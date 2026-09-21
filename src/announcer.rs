// SPDX-License-Identifier: MIT OR Apache-2.0
//! The rotation — asynchronous, with the acknowledgement as the only gate (SPEC-nettls §6.7).
//!
//! ```text
//! 1.  Create a new certificate, persist it
//! 2.  Publish the announcement
//! 3.  The peer stores it and acknowledges
//! 4.  Roll — AT ANY TIME after EVERYONE has acked
//! ```
//!
//! **There is no agreed point in time.** The peer accepts both `current` and
//! `next` from the moment the announcement is stored, so when the switch
//! happens is of no interest to it. That is what makes it impossible for a
//! stalled clock to topple a connection.
//!
//! ## The acknowledgement is not a courtesy
//!
//! If we roll before a peer has stored the new certificate, **its** handshake
//! fails in that very moment — exactly the breakage §6 exists to avoid. Hence:
//! no rotation until **every** registered peer has acked (§6.3b).
//!
//! The consequence is a coupling worth being honest about: if one peer is down,
//! we cannot rotate against anyone. That is accepted, because everything runs
//! on one machine in the same compose — one module down while the others run
//! **is** an error, and the coupling makes sure it becomes visible instead of
//! being left standing.
//!
//! ## No clock inside the module
//!
//! Every function takes `now` as a parameter. That is not just for
//! testability's sake: a state machine that reads the clock itself is a state
//! machine you cannot fast-forward, and then "what happens after 12 hours?"
//! becomes something you have to wait for instead of demonstrate.

use std::collections::BTreeSet;
use zeroize::Zeroize;

use crate::announcement::Announcement;
use crate::error::TlsError;

/// Seconds in a day.
pub const DAY_S: i64 = 86_400;

/// Nominal age at rotation: 7 days (§6.7c).
pub const NOMINAL_AGE_DAYS: i64 = 7;
/// Spread around the nominal age: ± 2 days.
pub const SPREAD_DAYS: i64 = 2;
/// Never more than one rotation per peer per 24 hours, regardless of trigger.
pub const MIN_BETWEEN_ROLLS_S: i64 = DAY_S;

/// Draws the time of the next rotation: `issued + 7 days ± 2 days`.
///
/// **Second resolution, not days.** Two modules provisioned in the same second
/// must not be able to land on the same day — and with day resolution they
/// would have had 5 possible values to collide on.
///
/// **CSPRNG**, not because the draw is secret, but because a *predictable*
/// rotation schedule is a schedule an attacker can plan against.
///
/// The spread is **symmetric**: it keeps the stated cadence honest — "roughly
/// every 7 days" is then true — and gives a better worst case, since an
/// *earlier* rotation gives **more** margin, not less.
pub fn draw_roll_time(issued: i64) -> Result<i64, TlsError> {
    let spenn = 2 * SPREAD_DAYS * DAY_S; // ±2 days = 4 days total
    let offset = tilfeldig_under(spenn as u64)? as i64 - SPREAD_DAYS * DAY_S;
    Ok(issued + NOMINAL_AGE_DAYS * DAY_S + offset)
}

/// A uniformly random number in `[0, tak)` from the OS CSPRNG.
///
/// Uses rejection instead of modulo: `x % tak` is biased when `tak` does not
/// divide `u64::MAX`, and even though the bias is negligible here, it is the
/// kind of detail that gets copied onward to a place where it is not.
fn tilfeldig_under(tak: u64) -> Result<u64, TlsError> {
    if tak == 0 {
        return Ok(0);
    }
    let grense = u64::MAX - (u64::MAX % tak);
    for _ in 0..64 {
        let b =
            krypto::random_bytes(8).map_err(|_| TlsError::Generate("CSPRNG unavailable".into()))?;
        let x = u64::from_le_bytes(b.try_into().expect("random_bytes(8) is 8 bytes"));
        if x < grense {
            return Ok(x % tak);
        }
    }
    Err(TlsError::Generate(
        "CSPRNG produced 64 rejected values in a row — something is wrong".into(),
    ))
}

/// Where the rotation stands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainState {
    /// Nothing in progress. The next attempt is scheduled for `attempt_at`.
    Idle {
        /// The time we are to start announcing.
        attempt_at: i64,
    },
    /// Announced. Waiting for acknowledgement from those who remain.
    Announced {
        /// Peers that have not yet acked.
        waiting_for: BTreeSet<String>,
        /// When the first announcement was published.
        first_announced: i64,
    },
}

/// The announcer's state machine for **one** instance.
#[derive(Debug, Clone)]
pub struct Schedule {
    state: ChainState,
    peers: BTreeSet<String>,
    /// When we last actually switched certificates. Enforces the rate limit.
    last_rolled: Option<i64>,
}

impl Schedule {
    /// New state machine. `attempt_at` is drawn with
    /// [`draw_roll_time`] from the certificate's issuance.
    pub fn new(peers: impl IntoIterator<Item = String>, attempt_at: i64) -> Self {
        Self {
            state: ChainState::Idle { attempt_at },
            peers: peers.into_iter().collect(),
            last_rolled: None,
        }
    }

    /// Register a peer. From now on it, too, must ack before we roll.
    pub fn add_peer(&mut self, name: impl Into<String>) {
        let name = name.into();
        if let ChainState::Announced { waiting_for, .. } = &mut self.state {
            waiting_for.insert(name.clone());
        }
        self.peers.insert(name);
    }

    /// Remove a peer.
    ///
    /// **Not an exceptional case.** If a module is decommissioned but stays in
    /// the registry, we wait forever for an acknowledgement from something that
    /// does not exist — and then the instance can never rotate again (§6.3b, M-34).
    pub fn remove_peer(&mut self, name: &str) {
        self.peers.remove(name);
        if let ChainState::Announced { waiting_for, .. } = &mut self.state {
            waiting_for.remove(name);
        }
    }

    /// Is it time to announce?
    pub fn should_announce(&self, now: i64) -> bool {
        matches!(self.state, ChainState::Idle { attempt_at } if now >= attempt_at)
    }

    /// Move to the announced state. The call site has built the announcement itself.
    pub fn announced(&mut self, now: i64) {
        if let ChainState::Idle { .. } = self.state {
            self.state = ChainState::Announced {
                waiting_for: self.peers.clone(),
                first_announced: now,
            };
        }
    }

    /// A peer has acked.
    pub fn acked(&mut self, peer: &str) {
        if let ChainState::Announced { waiting_for, .. } = &mut self.state {
            waiting_for.remove(peer);
        }
    }

    /// Peers we are still waiting for. An empty list means ready to roll.
    ///
    /// This exists so the alarm can **name** who is blocking. "The rotation
    /// failed" is useless when the cause is one specific peer — the operator
    /// then looks in the wrong place, and the coupling between two connections
    /// stays invisible (§6.3b, M-33).
    pub fn waiting_for(&self) -> Vec<&str> {
        match &self.state {
            ChainState::Announced { waiting_for, .. } => {
                waiting_for.iter().map(String::as_str).collect()
            }
            ChainState::Idle { .. } => Vec::new(),
        }
    }

    /// Can we switch certificates now?
    ///
    /// Requires **both** that everyone has acked **and** that the rate limit is
    /// respected. The rate limit stands regardless of what triggered the
    /// rotation: it caps any vector that amounts to forcing rotations (§6.7c, M-22).
    pub fn can_roll(&self, now: i64) -> bool {
        let alle_klare = matches!(&self.state, ChainState::Announced { waiting_for, .. } if waiting_for.is_empty());
        alle_klare && self.rate_limit_ok(now)
    }

    /// Has enough time passed since the previous actual rotation?
    pub fn rate_limit_ok(&self, now: i64) -> bool {
        match self.last_rolled {
            None => true,
            Some(t) => now - t >= MIN_BETWEEN_ROLLS_S,
        }
    }

    /// We have switched certificates. Schedules the next round.
    pub fn rolled(&mut self, now: i64) -> Result<(), TlsError> {
        self.last_rolled = Some(now);
        self.state = ChainState::Idle {
            attempt_at: draw_roll_time(now)?,
        };
        Ok(())
    }

    /// The state, for logging and status.
    pub fn state(&self) -> &ChainState {
        &self.state
    }

    /// When the pending announcement was first published, if we are waiting.
    pub fn first_announced(&self) -> Option<i64> {
        match self.state {
            ChainState::Announced {
                first_announced, ..
            } => Some(first_announced),
            ChainState::Idle { .. } => None,
        }
    }
}

impl Announcer {
    /// The file name the locked material is stored under.
    const LOCKED_FILE: &'static str = "material.locked";

    /// The previous generation's key, locked — when the announcer has a password.
    const PREVIOUS_LOCKED_FILE: &'static str = "previous-key.locked";
    /// The previous generation's key in cleartext — without a password, the
    /// same choice [`Announcer::save`] makes for the material itself.
    const PREVIOUS_CLEARTEXT_FILE: &'static str = "previous-key.json";

    /// Write the material — **locked if we have a password**.
    ///
    /// Without a password we fall back to `save_pem`, i.e. cleartext. That is
    /// not a shortcut: it is the mode 1 path, where the operator owns the file.
    /// But the choice is made in one place, not spread across the call sites.
    fn save(&self, m: &TlsMaterial, dir: &std::path::Path) -> Result<(), TlsError> {
        let Some(pw) = &self.password else {
            return m.save_pem(dir);
        };
        // `save_pem` to a temporary directory, read, lock, delete. The PEM form
        // is the one serialization `TlsMaterial` can be round-tripped through,
        // so we go via it — but it must never be left lying around.
        let tmp = dir.join(".tmp-material");
        std::fs::create_dir_all(&tmp).map_err(|e| TlsError::io(&tmp, e))?;
        let res = (|| -> Result<Vec<u8>, TlsError> {
            m.save_pem(&tmp)?;
            let cert = std::fs::read(tmp.join(crate::material::CERT_FILE))
                .map_err(|e| TlsError::io(&tmp, e))?;
            // Key PEM and the combined cleartext both stay in locked memory
            // until `lock` has produced the blob.
            let key = crate::secret::hold(
                std::fs::read(tmp.join(crate::material::KEY_FILE))
                    .map_err(|e| TlsError::io(&tmp, e))?,
            )?;
            let samlet = key.expose(|k| {
                let mut s = cert;
                s.extend_from_slice(b"\n");
                s.extend_from_slice(k);
                crate::secret::hold(s)
            })?;
            samlet.expose(|b| crate::lockbox::lock(pw, b))
        })();
        // Delete the cleartext staging area NO MATTER WHAT — also when the
        // locking failed. Otherwise an error in that last step would have left
        // the key in cleartext, and that is exactly the state we are trying to
        // avoid.
        let _ = std::fs::remove_dir_all(&tmp);
        let locked = res?;
        let path = dir.join(Self::LOCKED_FILE);
        Self::skriv_atomisk(&path, &locked)
    }

    /// Read the material back, locked or not.
    fn load(&self, dir: &std::path::Path) -> Result<TlsMaterial, TlsError> {
        let Some(pw) = &self.password else {
            return TlsMaterial::load(&CertSource::files(
                dir.join(crate::material::CERT_FILE),
                dir.join(crate::material::KEY_FILE),
            ));
        };
        let file = std::fs::read(dir.join(Self::LOCKED_FILE))
            .map_err(|e| TlsError::io(dir.join(Self::LOCKED_FILE), e))?;
        let out = crate::lockbox::unlock(pw, &file)?;
        out.expose(|b| {
            // Split on the raw bytes — no `String` copy of the key on the way.
            const MARKER: &[u8] = b"-----BEGIN PRIVATE KEY-----";
            let skille = b
                .windows(MARKER.len())
                .position(|w| w == MARKER)
                .ok_or_else(|| {
                    TlsError::Pem("no private key found in the locked material".into())
                })?;
            TlsMaterial::load(&CertSource::pem(b[..skille].to_vec(), b[skille..].to_vec()))
        })
    }

    /// The path the `previous` key is stored under. The name follows from whether we lock.
    ///
    /// Two names and not one, because cleartext content in a file called
    /// `.locked` is a lie — and because a name that does not match the setup
    /// then becomes a **visible** error instead of an attempt to guess the format.
    fn previous_path(&self) -> std::path::PathBuf {
        self.dir.join(if self.password.is_some() {
            Self::PREVIOUS_LOCKED_FILE
        } else {
            Self::PREVIOUS_CLEARTEXT_FILE
        })
    }

    /// Write atomically, with mode 0600.
    ///
    /// Every file this type owns goes through here: the previous generation's
    /// private key, the locked material of the current one, and the promise
    /// that survives a restart. A half-written file after a crash would look
    /// like a corrupt chain, and that is not a state we want to be able to end
    /// up in on a power failure. The mode matters for the same reason the rest
    /// of the crate sets it: `fs::write` would take whatever the umask says.
    fn skriv_atomisk(path: &std::path::Path, data: &[u8]) -> Result<(), TlsError> {
        use std::io::Write;
        let tmp = path.with_extension("tmp");
        let mut f = std::fs::File::create(&tmp).map_err(|e| TlsError::io(&tmp, e))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            f.set_permissions(std::fs::Permissions::from_mode(0o600))
                .map_err(|e| TlsError::io(&tmp, e))?;
        }
        f.write_all(data).map_err(|e| TlsError::io(&tmp, e))?;
        f.sync_all().map_err(|e| TlsError::io(&tmp, e))?;
        drop(f);
        std::fs::rename(&tmp, path).map_err(|e| TlsError::io(path, e))
    }

    /// Persist the **previous generation's key** — the one announcements are signed with.
    ///
    /// Only `previous` is stored here. `current` already lives on disk as
    /// material (`material.locked` / `cert.pem`+`key.pem`), and storing it in
    /// two places would have given two files that can drift apart after a crash
    /// in the middle of a switch. The two files therefore hold **disjoint** state.
    fn save_previous(
        &self,
        previous: Option<&(String, krypto::SecretBuf)>,
    ) -> Result<(), TlsError> {
        let path = self.previous_path();
        let Some((fp, pkcs8)) = previous else {
            // No previous yet (before the first rotation) — nothing to preserve.
            let _ = std::fs::remove_file(&path);
            return Ok(());
        };
        // The on-disk struct needs a `Vec<u8>` for serde; it is wiped the
        // moment the JSON exists.
        let json = {
            let mut on_disk = ForrigePaaDisk {
                fingerprint: fp.clone(),
                pkcs8: pkcs8.expose(|b| b.to_vec()),
            };
            let r = serde_json::to_vec(&on_disk);
            on_disk.pkcs8.zeroize();
            r
        }
        .map_err(|e| TlsError::Chain(format!("could not serialize the previous key: {e}")))?;

        // The cleartext goes into a SecretBuf: `from_vec` zeroizes the source,
        // and the buffer zeroizes itself when it goes out of scope. It contains
        // a private key, and must not be left lying around in memory.
        let secret = krypto::SecretBuf::from_vec(json)
            .map_err(|e| TlsError::Chain(format!("could not lock the previous key: {e}")))?;

        let out = match &self.password {
            Some(pw) => secret.expose(|b| crate::lockbox::lock(pw, b))?,
            None => secret.expose(|b| b.to_vec()),
        };
        Self::skriv_atomisk(&path, &out)
    }

    /// Restore the chain `(previous, current)` after a restart.
    ///
    /// **This must be called at startup.** `Announcer::new` receives the
    /// material the caller *has* — and after a rotation that is only generation
    /// 0, because the keys from generation 1 onwards are created and owned by
    /// the crate. Without this call the instance is left with `previous = None`,
    /// and the next double-signed announcement can be neither signed nor
    /// verified.
    ///
    /// Mirrors [`Announcer::restore_pending`]: explicit, fallible, and
    /// called by the consumer at startup.
    ///
    /// Returns `true` if a chain was restored, `false` if we have never
    /// rolled.
    ///
    /// # Fail-closed
    ///
    /// A chain that **exists but cannot be opened or parsed** is an error —
    /// not an absence. The two must not be treated alike: that would give a
    /// corrupt or tampered file exactly the silent state this call exists to
    /// prevent.
    fn restore_material(&self) -> Result<bool, TlsError> {
        let path = self.previous_path();
        let raa = match std::fs::read(&path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // If the OTHER form is there, the setup has changed under our
                // feet — a password added or removed. Then the chain is
                // unreadable, and that must be said out loud.
                let annen = self.dir.join(if self.password.is_some() {
                    Self::PREVIOUS_CLEARTEXT_FILE
                } else {
                    Self::PREVIOUS_LOCKED_FILE
                });
                if annen.exists() {
                    return Err(TlsError::Chain(format!(
                        "the previous key is stored as {} but the announcer is configured {}. \
                         The password setup has changed since the chain was saved; it cannot be \
                         read, and the pair must be approved anew by an operator",
                        annen.display(),
                        if self.password.is_some() {
                            "WITH a password"
                        } else {
                            "WITHOUT a password"
                        }
                    )));
                }
                return Ok(false);
            }
            Err(e) => return Err(TlsError::io(&path, e)),
        };

        let read_back: ForrigePaaDisk = match &self.password {
            Some(pw) => {
                let out = crate::lockbox::unlock(pw, &raa)?;
                out.expose(|b| serde_json::from_slice(b))
            }
            None => serde_json::from_slice(&raa),
        }
        .map_err(|e| {
            TlsError::Chain(format!(
                "the previous key in {} could not be parsed: {e}. The chain is broken, and the \
                 pair must be approved anew by an operator",
                path.display()
            ))
        })?;

        // `current` is derived from the material actually on disk — that is
        // the single truth about what we are running now.
        let material = self.load(&self.dir)?;
        let der = material.cert_chain()[0].as_ref().to_vec();
        let current_fp = krypto::hex::encode(&krypto::sha256(&der));
        let current_pkcs8 = crate::pkcs8::pkcs8_p256(material.key_der(), &der)?;

        if read_back.fingerprint == current_fp {
            return Err(TlsError::Chain(format!(
                "previous and current have the same fingerprint ({current_fp}). The state on \
                 disk is inconsistent, and the chain cannot be used"
            )));
        }

        *self
            .material
            .write()
            .map_err(|_| TlsError::Rustls("the material lock is poisoned".into()))? = OwnMaterial {
            // `hold` zeroizes the deserialized Vec as it moves it into the lock.
            previous: Some((read_back.fingerprint, crate::secret::hold(read_back.pkcs8)?)),
            current: (current_fp, current_pkcs8),
        };
        Ok(true)
    }
}

/// The previous generation's key, as it lies on disk.
#[derive(serde::Serialize, serde::Deserialize)]
struct ForrigePaaDisk {
    fingerprint: String,
    pkcs8: Vec<u8>,
}

/// Logs that the keys are stored in cleartext, once at setup.
fn tracing_advarsel() {
    // A silent cleartext storage is worse than a loud one: whoever reads the
    // code a year from now sees no difference between "deliberate choice" and
    // "forgotten".
    eprintln!(
        "nettls: NOTE — the Announcer is configured WITHOUT a password. The private keys are \
         stored in cleartext on disk. That is correct for mode 1 where the operator owns the \
         certificate, but for mode 2 the material must be locked."
    );
}

/// An announcement we have published and are awaiting acknowledgement for.
///
/// Not `Clone` since 0.8.3: it carries a private key (`SecretBuf`), and a key
/// is copied only deliberately, never by a derive. `Debug` redacts it.
#[derive(Debug)]
pub struct Pending {
    /// The announcement itself, republished until everyone has acked.
    pub announcement: Announcement,
    /// The new certificate as PEM.
    pub new_cert_pem: String,
    /// The new private key, PKCS#8.
    ///
    /// **Persisted together with the announcement, before it is published**
    /// (§6.9c): the announcement contains the new certificate, so the material
    /// *must* exist when it is created — and then it should live on disk, not
    /// in the memory of a process that has just promised something binding.
    ///
    /// In locked memory (0.8.3).
    pub new_pkcs8: krypto::SecretBuf,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peers() -> Vec<String> {
        vec!["service".into(), "portal".into()]
    }

    // --- the draw ------------------------------------------------------------ //

    #[test]
    fn time_lies_within_the_window() {
        for _ in 0..200 {
            let t = draw_roll_time(0).unwrap();
            assert!(
                (5 * DAY_S..=9 * DAY_S).contains(&t),
                "outside 5–9 days: {t}"
            );
        }
    }

    #[test]
    fn two_instances_provisioned_same_second_get_different_times() {
        // M-19. This is the whole reason the spread exists: `docker compose
        // up` provisions everything in the same second, and with a fixed
        // interval they would have been in lockstep forever.
        let mut sett = std::collections::BTreeSet::new();
        for _ in 0..50 {
            sett.insert(draw_roll_time(1_700_000_000).unwrap());
        }
        assert!(
            sett.len() > 40,
            "the spread is too narrow — only {} distinct out of 50",
            sett.len()
        );
    }

    #[test]
    fn spread_has_second_resolution() {
        // With day resolution there would only be 5 possible values.
        let verdier: BTreeSet<i64> = (0..50)
            .map(|_| draw_roll_time(0).unwrap() % DAY_S)
            .collect();
        assert!(verdier.len() > 20, "looks like day resolution: {verdier:?}");
    }

    // --- the gate: everyone must ack ------------------------------------------ //

    #[test]
    fn does_not_roll_until_everyone_has_acked() {
        let mut r = Schedule::new(peers(), 100);
        assert!(r.should_announce(100));
        r.announced(100);

        assert!(!r.can_roll(200));
        assert_eq!(r.waiting_for(), vec!["portal", "service"]);

        r.acked("service");
        assert!(!r.can_roll(200), "one left");
        assert_eq!(r.waiting_for(), vec!["portal"]);

        r.acked("portal");
        assert!(r.can_roll(200));
        assert!(r.waiting_for().is_empty());
    }

    #[test]
    fn the_blocker_can_be_named() {
        // M-33: "the rotation failed" is useless when the cause is one peer.
        let mut r = Schedule::new(peers(), 0);
        r.announced(0);
        r.acked("service");
        assert_eq!(r.waiting_for(), vec!["portal"]);
    }

    #[test]
    fn a_removed_peer_no_longer_blocks() {
        // M-34: without this a decommissioned module would block rotation forever.
        let mut r = Schedule::new(peers(), 0);
        r.announced(0);
        r.acked("service");
        assert!(!r.can_roll(100));
        r.remove_peer("portal");
        assert!(r.can_roll(100));
    }

    #[test]
    fn a_newly_added_peer_must_also_ack() {
        let mut r = Schedule::new(vec!["service".to_string()], 0);
        r.announced(0);
        r.acked("service");
        assert!(r.can_roll(100));
        r.add_peer("gateway");
        assert!(!r.can_roll(100), "the new one has not acked");
    }

    // --- rate limit ------------------------------------------------------------ //

    #[test]
    fn at_most_one_rotation_per_day() {
        // M-22. Caps the vector that amounts to forcing rotations.
        let mut r = Schedule::new(vec!["service".to_string()], 0);
        r.announced(0);
        r.acked("service");
        assert!(r.can_roll(0));
        r.rolled(0).unwrap();

        // Even with everything else in order, the rate limit blocks.
        r.state = ChainState::Announced {
            waiting_for: BTreeSet::new(),
            first_announced: 1,
        };
        assert!(!r.can_roll(DAY_S - 1));
        assert!(r.can_roll(DAY_S));
    }

    // --- the cycle -------------------------------------------------------------- //

    #[test]
    fn rolling_schedules_the_next_round() {
        let mut r = Schedule::new(vec!["service".to_string()], 0);
        r.announced(0);
        r.acked("service");
        r.rolled(1_000).unwrap();

        match r.state() {
            ChainState::Idle { attempt_at } => {
                assert!((1_000 + 5 * DAY_S..=1_000 + 9 * DAY_S).contains(attempt_at));
            }
            annet => panic!("expected Idle, got {annet:?}"),
        }
        assert!(!r.should_announce(1_001));
    }

    #[test]
    fn announced_is_idempotent() {
        // The announcement is republished until everyone has acked (§6.8a) —
        // and that must not reset who has already answered.
        let mut r = Schedule::new(peers(), 0);
        r.announced(0);
        r.acked("service");
        r.announced(500);
        assert_eq!(
            r.waiting_for(),
            vec!["portal"],
            "the service's answer must stand"
        );
        assert_eq!(r.first_announced(), Some(0), "the time must not move");
    }
}

// --------------------------------------------------------------------------- //
// Retries, alarm and countdown (§6.8a)
// --------------------------------------------------------------------------- //

/// The alarm fires 12 hours after the first failed attempt.
pub const ALARM_AFTER_S: i64 = 12 * 3600;

/// The retry cadence (§6.8a): tight at first, sparser afterwards.
///
/// Tight because the most common cause is trivial — the peer restarted, the
/// network flickered — and it should cost nothing. Sparser afterwards because a
/// problem that lasts for hours is not solved by more attempts.
pub fn interval_after(elapsed_s: i64) -> i64 {
    match elapsed_s {
        s if s < 15 * 60 => 60,
        s if s < 3600 => 5 * 60,
        _ => 3600,
    }
}

/// What the operator should see about a pending rotation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Status {
    /// Peers we are waiting for. Empty = all is well.
    pub waiting_for: Vec<String>,
    /// Has the alarm fired? (12 hours since the first attempt.)
    pub alarm: bool,
    /// Seconds until internal communication actually **stops** — that is,
    /// until the running certificate expires.
    ///
    /// This is the number the countdown shows. **Not** time until the next
    /// attempt, not time until the alarm: time until the app stops working.
    /// Anything else would give a smaller number than the one that matters,
    /// and a smaller number than the one that matters is worse than none (§6.8a).
    pub seconds_until_stop: i64,
}

impl Status {
    /// The countdown as `d days hh:mm:ss`.
    pub fn countdown(&self) -> String {
        let s = self.seconds_until_stop.max(0);
        let (d, r) = (s / DAY_S, s % DAY_S);
        format!(
            "{d} days {:02}:{:02}:{:02}",
            r / 3600,
            (r % 3600) / 60,
            r % 60
        )
    }

    /// The message the operator gets. Always names **who** is blocking.
    pub fn message(&self, own_name: &str) -> Option<String> {
        if self.waiting_for.is_empty() {
            return None;
        }
        Some(format!(
            "{}: rotation of {own_name} is blocked — waiting for acknowledgement from {}. \
             {} until internal communication stops.",
            if self.alarm { "ERROR" } else { "Waiting" },
            self.waiting_for.join(", "),
            self.countdown()
        ))
    }
}

impl Schedule {
    /// When should the announcement be republished?
    ///
    /// `None` when we are not waiting for anyone. The retries **continue after
    /// the alarm** — the alarm notifies a human, it does not end the attempt.
    /// If the peer comes back on its own, the rotation goes through without
    /// anyone having done anything (§6.8a, M-7e).
    pub fn next_retry(&self, now: i64) -> Option<i64> {
        let ChainState::Announced {
            waiting_for,
            first_announced,
        } = &self.state
        else {
            return None;
        };
        if waiting_for.is_empty() {
            return None;
        }
        let gaatt = now - first_announced;
        Some(now + interval_after(gaatt.max(0)))
    }

    /// Has the alarm fired?
    pub fn alarm(&self, now: i64) -> bool {
        match &self.state {
            ChainState::Announced {
                waiting_for,
                first_announced,
            } => !waiting_for.is_empty() && now - first_announced >= ALARM_AFTER_S,
            ChainState::Idle { .. } => false,
        }
    }

    /// The status the operator sees. `expires` is the running certificate's expiry.
    pub fn status(&self, now: i64, expires: i64) -> Status {
        Status {
            waiting_for: self.waiting_for().into_iter().map(str::to_string).collect(),
            alarm: self.alarm(now),
            seconds_until_stop: expires - now,
        }
    }
}

#[cfg(test)]
mod retry_tests {
    use super::*;

    fn r() -> Schedule {
        let mut r = Schedule::new(vec!["service".to_string(), "portal".to_string()], 0);
        r.announced(0);
        r
    }

    #[test]
    fn cadence_is_tight_at_first_and_sparser_afterwards() {
        assert_eq!(interval_after(0), 60);
        assert_eq!(interval_after(14 * 60), 60);
        assert_eq!(interval_after(15 * 60), 5 * 60);
        assert_eq!(interval_after(59 * 60), 5 * 60);
        assert_eq!(interval_after(3600), 3600);
        assert_eq!(interval_after(50 * 3600), 3600);
    }

    #[test]
    fn alarm_fires_after_twelve_hours_not_before() {
        let r = r();
        assert!(!r.alarm(0));
        assert!(!r.alarm(ALARM_AFTER_S - 1));
        assert!(r.alarm(ALARM_AFTER_S));
    }

    #[test]
    fn retries_continue_after_the_alarm() {
        // M-7e: the alarm notifies a human, it does not end the attempt.
        let r = r();
        let etter = ALARM_AFTER_S + 5 * 3600;
        assert!(r.alarm(etter));
        assert_eq!(
            r.next_retry(etter),
            Some(etter + 3600),
            "the attempts must continue at hourly cadence"
        );
    }

    #[test]
    fn a_peer_that_comes_back_resolves_it_without_an_operator() {
        // M-7e, second half.
        let mut r = r();
        assert!(r.alarm(ALARM_AFTER_S));
        r.acked("service");
        r.acked("portal");
        assert!(!r.alarm(ALARM_AFTER_S), "the alarm must clear on its own");
        assert!(r.next_retry(ALARM_AFTER_S).is_none());
        assert!(r.can_roll(ALARM_AFTER_S));
    }

    #[test]
    fn no_alarm_when_everyone_has_acked() {
        let mut r = r();
        r.acked("service");
        r.acked("portal");
        assert!(!r.alarm(ALARM_AFTER_S * 10));
    }

    #[test]
    fn countdown_runs_to_stop_not_to_next_attempt() {
        // M-7f: the number must be the time until the app stops working. A
        // smaller number than the one that matters is worse than none.
        let r = r();
        let expires = 30 * DAY_S;
        let now = 7 * DAY_S + ALARM_AFTER_S;
        let s = r.status(now, expires);
        assert_eq!(s.seconds_until_stop, expires - now);
        assert!(s.alarm);
        // 30 - 7 days - 12 hours = 22 days and 12 hours (§6.7c).
        assert_eq!(s.countdown(), "22 days 12:00:00");
    }

    #[test]
    fn message_always_names_who_is_blocking() {
        // M-33.
        let mut r = r();
        r.acked("service");
        let m = r
            .status(ALARM_AFTER_S, 30 * DAY_S)
            .message("gateway")
            .unwrap();
        assert!(m.contains("portal"), "{m}");
        assert!(m.contains("gateway"), "{m}");
        assert!(m.starts_with("ERROR"), "{m}");

        r.acked("portal");
        assert!(r
            .status(ALARM_AFTER_S, 30 * DAY_S)
            .message("gateway")
            .is_none());
    }

    #[test]
    fn guaranteed_worst_case_is_20_days_12_hours() {
        // §6.7c: rotation at 9 days (the latest), alarm 12 hours later.
        let r = r();
        let s = r.status(9 * DAY_S + ALARM_AFTER_S, 30 * DAY_S);
        assert_eq!(s.countdown(), "20 days 12:00:00");
    }
}

// --------------------------------------------------------------------------- //
// Mode (§6.2, §6.9b)
// --------------------------------------------------------------------------- //

/// Which trust mode a connection runs in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// **Pinning.** No rotation. The lifetime is the certificate's, and any
    /// change of trust requires a deliberate operator action.
    ///
    /// A fully valid choice internally too: an uploaded certificate with a
    /// 365-day lifetime gives 365 days without moving parts that can stall.
    Pinning,
    /// **Active rotation.** The app controls the lifetime — 30 days, rotation
    /// around day 7 — and switches on its own after advance notice.
    Rolling,
}

impl std::fmt::Display for Mode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Mode::Pinning => "pinning",
            Mode::Rolling => "rolling",
        })
    }
}

/// Warning threshold when a mode 1 certificate approaches expiry.
pub const MODE1_WARN_DAYS: i64 = 30;

/// Should the operator be warned that a mode 1 certificate needs handling?
///
/// **At 30 days remaining** — not at 5, and not the moment the certificate
/// falls. 30 days is enough to obtain a new one without it being urgent (§6.2, M-12).
pub fn mode1_should_warn(now: i64, expires: i64) -> bool {
    expires - now <= MODE1_WARN_DAYS * DAY_S
}

/// The result of comparing our mode with the peer's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ModeCheck {
    /// Both agree.
    Agree(Mode),
    /// Disagreement — an **active error** that names both sides.
    ///
    /// Traffic continues: the identity is fine, and it is only the rotation
    /// that cannot happen. But rotation is not attempted, and the operator is notified.
    Disagree {
        /// The mode we are configured with.
        ours: Mode,
        /// The mode the peer announces.
        theirs: Mode,
    },
}

/// Compare our configured mode with the one the peer **announces**.
///
/// Mode is **never negotiated** (§6.9b). A party that can *ask* for a mode can
/// ask for the weakest one — and then we have built a downgrade attack into
/// the protocol as a feature. We verify that the two agree. We never let them
/// agree on something weaker.
pub fn check_mode(ours: Mode, theirs: Mode) -> ModeCheck {
    if ours == theirs {
        ModeCheck::Agree(ours)
    } else {
        ModeCheck::Disagree { ours, theirs }
    }
}

impl ModeCheck {
    /// The message the operator gets on disagreement. Names **both** sides.
    pub fn message(&self, peer: &str) -> Option<String> {
        match self {
            ModeCheck::Agree(_) => None,
            ModeCheck::Disagree { ours, theirs } => Some(format!(
                "mode disagreement with {peer}: we stand in «{ours}», {peer} runs «{theirs}». \
                 Traffic continues, but rotation will not be attempted until both sides are set alike."
            )),
        }
    }

    /// Should rotation be attempted?
    pub fn can_roll(&self) -> bool {
        matches!(self, ModeCheck::Agree(Mode::Rolling))
    }
}

#[cfg(test)]
mod mode_tests {
    use super::*;

    #[test]
    fn agreement_on_rolling_allows_rotation() {
        let s = check_mode(Mode::Rolling, Mode::Rolling);
        assert!(s.can_roll());
        assert!(s.message("gateway").is_none());
    }

    #[test]
    fn agreement_on_pinning_gives_no_rotation_and_no_error() {
        let s = check_mode(Mode::Pinning, Mode::Pinning);
        assert!(!s.can_roll());
        assert!(s.message("gateway").is_none(), "agreement is not an error");
    }

    #[test]
    fn disagreement_names_both_sides() {
        // M-24. "Mode disagreement" without saying which ones is useless.
        let s = check_mode(Mode::Rolling, Mode::Pinning);
        assert!(!s.can_roll());
        let m = s.message("gateway").unwrap();
        assert!(m.contains("rolling"), "{m}");
        assert!(m.contains("pinning"), "{m}");
        assert!(m.contains("gateway"), "{m}");
        assert!(m.contains("Traffic continues"), "{m}");
    }

    #[test]
    fn mode_cannot_be_negotiated() {
        // M-25: the function does not accept a WISH, only two configured
        // values, and it never returns a third. There is no path to agreeing
        // on something weaker than what both sides are configured with.
        for (a, b) in [
            (Mode::Rolling, Mode::Pinning),
            (Mode::Pinning, Mode::Rolling),
        ] {
            match check_mode(a, b) {
                ModeCheck::Disagree { ours, theirs } => {
                    assert_eq!(ours, a);
                    assert_eq!(theirs, b);
                }
                ModeCheck::Agree(_) => panic!("should not have agreed"),
            }
        }
    }

    #[test]
    fn mode1_warns_at_thirty_days_not_before() {
        let expires = 365 * DAY_S;
        assert!(!mode1_should_warn(expires - 31 * DAY_S, expires));
        assert!(mode1_should_warn(expires - 30 * DAY_S, expires));
        assert!(
            mode1_should_warn(expires - 1, expires),
            "and still afterwards"
        );
    }

    #[test]
    fn mode_serializes_as_agreed() {
        // The value goes on the wire in /v1/tls/identity (§6.9b) and is part
        // of the contract — it must not be able to change through a Rust rename.
        // (0.7.0 switched the wire value rullerende→rolling BEFORE first
        // adoption — a deliberate, Roger-approved wire change, 2026-08-15.)
        assert_eq!(
            serde_json::to_string(&Mode::Rolling).unwrap(),
            "\"rolling\""
        );
        assert_eq!(
            serde_json::to_string(&Mode::Pinning).unwrap(),
            "\"pinning\""
        );
    }
}

// --------------------------------------------------------------------------- //
// The announcer: from state machine to actual rotation (§6.7, §6.9c)
// --------------------------------------------------------------------------- //

use std::sync::{Arc, RwLock};

use crate::material::TlsMaterial;
use crate::resolver::RotatingResolver;
use crate::{CertSource, SelfSignedParams};

/// The material an instance holds about **itself** during a rotation.
///
/// Up to three keys are in circulation at the same time (SPEC-nettls §6.3):
///
/// | | Why it exists |
/// |---|---|
/// | `current` | terminates TLS now |
/// | `previous` | **signs the next announcement** — without it we are back to one signature |
/// | `fresh` | announced, not yet taken into use |
///
/// **Exactly two are kept after a switch.** When `(previous, current)` becomes
/// `(current, new)`, the old `previous` is dropped: generation N-2 signs
/// nothing, and a key without a job is pure liability.
///
/// # Who owns the storage
///
/// **The crate.** Unlike the peer's state — which the consumer remembers
/// and puts back with [`Generations::restore`](crate::generations::Generations::restore)
/// — these are **your own private keys**, and they never leave the crate
/// (`SPEC-nettls` §6.11b: *"Do not store private keys. You do not get
/// them, and you are not supposed to have them"*). The consumer therefore
/// *cannot* preserve this chain, and must not be able to.
///
/// In practice this means:
///
/// - `current` lives on disk as material (`material.locked`, or
///   `cert.pem` + `key.pem` without a password).
/// - `previous` is stored by [`Announcer`] on every switch.
/// - [`Announcer::new`] restores both at startup, fail-closed (SPEC-nettls §6.11b). The
///   value given to `new` is only the **anchor** — the identity the consumer
///   shared at first boot. If a persisted chain exists, it overrides the
///   anchor; if it exists but cannot be read, construction fails loudly.
///
/// **0.8.3:** the keys are `krypto::SecretBuf` — locked memory, wiped on drop,
/// redacted in `Debug`. Build the anchor from
/// [`TlsMaterial::anchor_pkcs8`](crate::material::TlsMaterial::anchor_pkcs8),
/// which returns exactly this type.
pub struct OwnMaterial {
    /// The previous generation. `None` until the first rotation.
    pub previous: Option<(String, krypto::SecretBuf)>,
    /// Current: fingerprint (bare hex) and PKCS#8.
    pub current: (String, krypto::SecretBuf),
}

/// The announcer: binds [`Schedule`] to [`RotatingResolver`].
///
/// This layer is the reason `schedule.rs` alone was not enough. It was a
/// correct state machine with nothing to steer — it could say "we should roll
/// now", but nothing happened.
pub struct Announcer {
    name: String,
    dir: std::path::PathBuf,
    /// The password the key material is locked with at rest (§8.4).
    ///
    /// `None` means **cleartext on disk**. That is legitimate — mode 1 with an
    /// operator-uploaded certificate is a normal way of running, and there the
    /// operator owns the file — but it is a **choice**, and it must be visible as one.
    ///
    /// With §6 the stakes are higher than before: the rotation has up to three
    /// keys in circulation, and the `new/` directory holds an **unused** key
    /// from announcement to switch. It sits there waiting.
    password: Option<krypto::SecretString>,
    params: SelfSignedParams,
    resolver: Arc<RotatingResolver>,
    material: Arc<RwLock<OwnMaterial>>,
    schedule: Arc<RwLock<Schedule>>,
    /// The announcement awaiting acknowledgement, with its key material.
    pending: Arc<RwLock<Option<Pending>>>,
}

impl Announcer {
    /// Build the announcer — **load-or-init, fail-closed** (SPEC-nettls §6.11b).
    ///
    /// `anchor` is the identity the consumer *shares with* the crate at first
    /// boot: generation 0, the operator-approved material. It is only ever
    /// used as the starting point. From generation 1 onwards the keys are
    /// created and owned by the crate and never leave it — so if a persisted
    /// chain exists on disk, it **overrides** the anchor, and the anchor is
    /// just the identity from the first boot.
    ///
    /// Three outcomes, in order:
    ///
    /// 1. A chain exists on disk → it is loaded, validated and used.
    /// 2. A chain exists but cannot be opened or parsed → **error** (N-2): a
    ///    chain that exists but cannot be read is a fault, not an absence.
    /// 3. Nothing on disk → first boot; `anchor` becomes generation 0.
    ///
    /// A pending, announced-but-not-switched rotation (M-26) is restored the
    /// same way. It is therefore impossible to hold an `Announcer` in a
    /// silently wrong state: you either get a correct one, or an error you
    /// must handle. (This used to be two separate calls the consumer had to
    /// remember — the trap SPEC-nettls §6.11b exists to remove.)
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        name: impl Into<String>,
        dir: impl Into<std::path::PathBuf>,
        params: SelfSignedParams,
        resolver: Arc<RotatingResolver>,
        anchor: OwnMaterial,
        schedule: Schedule,
        password: Option<krypto::SecretString>,
    ) -> Result<Self, TlsError> {
        if password.is_none() {
            tracing_advarsel();
        }
        let s = Self {
            name: name.into(),
            dir: dir.into(),
            password,
            params,
            resolver,
            material: Arc::new(RwLock::new(anchor)),
            schedule: Arc::new(RwLock::new(schedule)),
            pending: Arc::new(RwLock::new(None)),
        };
        s.restore_material()?;
        s.restore_pending()?;
        Ok(s)
    }

    /// A read-only view of our own generation triple — fingerprints, never
    /// keys (SPEC-nettls §6.11b, decided 2026-08-13).
    ///
    /// `previous` is the retired generation we still sign announcements with;
    /// `current` is what we serve; `next` is an announced successor awaiting
    /// acknowledgement, if any. The crate tells what it knows — it never hands
    /// out private material.
    pub fn own_trio(&self) -> Result<OwnTrio, TlsError> {
        let m = self
            .material
            .read()
            .map_err(|_| TlsError::Rustls("the material lock is poisoned".into()))?;
        let p = self
            .pending
            .read()
            .map_err(|_| TlsError::Rustls("the pending lock is poisoned".into()))?;
        Ok(OwnTrio {
            previous_fingerprint: m.previous.as_ref().map(|(fp, _)| fp.clone()),
            current_fingerprint: m.current.0.clone(),
            next_fingerprint: p
                .as_ref()
                .map(|v| v.announcement.new_fingerprint().to_string()),
        })
    }

    /// Prepare a rotation: create a new certificate, **persist it**, and build
    /// the announcement.
    ///
    /// The order is normative (§6.9c): the material is written to disk
    /// **before** the announcement exists. The announcement contains the new
    /// certificate, so the material *must* exist when it is created — and then
    /// it should live on disk, not in the memory of a process that has just
    /// promised something binding.
    ///
    /// Idempotent: if an announcement is already out, the same one is returned.
    /// That is exactly the one that is republished until everyone has acked (§6.8a).
    pub fn prepare(&self, now: i64) -> Result<Announcement, TlsError> {
        if let Some(k) = self
            .pending
            .read()
            .ok()
            .and_then(|v| v.as_ref().map(|p| p.announcement.clone()))
        {
            return Ok(k);
        }

        let fresh = TlsMaterial::load(&CertSource::self_signed(self.params.clone()))?;
        let new_dir = self.dir.join("new");
        std::fs::create_dir_all(&new_dir).map_err(|e| TlsError::io(&new_dir, e))?;
        self.save(&fresh, &new_dir)?;

        let der = fresh.cert_chain()[0].as_ref().to_vec();
        let pem = String::from_utf8(crate::pem::encode("CERTIFICATE", &der))
            .map_err(|e| TlsError::Pem(e.to_string()))?;
        let new_pkcs8 = crate::pkcs8::pkcs8_p256(fresh.key_der(), &der)?;

        let m = self
            .material
            .read()
            .map_err(|_| TlsError::Rustls("the material lock is poisoned".into()))?;
        let k = Announcement::new(
            &self.name,
            m.previous.as_ref().map(|(fp, pk)| (fp.as_str(), pk)),
            (m.current.0.as_str(), &m.current.1),
            &pem,
            now,
        )?;
        drop(m);

        *self
            .pending
            .write()
            .map_err(|_| TlsError::Rustls("the pending lock is poisoned".into()))? =
            Some(Pending {
                announcement: k.clone(),
                new_cert_pem: pem,
                new_pkcs8,
            });
        self.schedule
            .write()
            .map_err(|_| TlsError::Rustls("the rotation lock is poisoned".into()))?
            .announced(now);
        Ok(k)
    }

    /// A peer has acked.
    pub fn acked(&self, peer: &str) -> Result<(), TlsError> {
        self.schedule
            .write()
            .map_err(|_| TlsError::Rustls("the rotation lock is poisoned".into()))?
            .acked(peer);
        Ok(())
    }

    /// Switch certificates — **only** if everyone has acked and the rate limit allows it.
    ///
    /// Returns the old fingerprint on a switch, `None` when we are not ready.
    /// Asking for a switch too early is not an error: it is the normal state
    /// while we are waiting.
    pub fn roll_if_ready(&self, now: i64) -> Result<Option<String>, TlsError> {
        self.roll_if_ready_gated(now, || true)
    }

    /// Like [`Announcer::roll_if_ready`], but asks the consumer at the last
    /// moment: *"is it safe for me to switch now?"* (SPEC-nettls §6.7e /
    /// §6.7e — the A4/A5 switch point, decided 2026-08-13).
    ///
    /// The receipt answers for the peer; `safe_now` answers for **us**. A
    /// party can have work that does not tolerate a swap right then — a gateway
    /// can hold a management session open under a lease, and a certificate switch
    /// mid-configuration is a self-inflicted interruption. The crate cannot
    /// know what such work is; it can ask.
    ///
    /// The gate is consulted **only** when everything else is ready (receipt
    /// in, pending material present), and **before** anything moves. A `false`
    /// postpones the switch with no side effects — ask again later. The chain
    /// and the serving still switch **together**, inside this call: there is
    /// no way to roll the chain without the resolver following.
    pub fn roll_if_ready_gated(
        &self,
        now: i64,
        safe_now: impl FnOnce() -> bool,
    ) -> Result<Option<String>, TlsError> {
        {
            let r = self
                .schedule
                .read()
                .map_err(|_| TlsError::Rustls("the rotation lock is poisoned".into()))?;
            if !r.can_roll(now) {
                return Ok(None);
            }
        }
        // Only the key is needed from `Pending`, and it is copied into a new
        // lock — the original stays until the switch has actually happened.
        let new_pkcs8 = {
            let g = self
                .pending
                .read()
                .map_err(|_| TlsError::Rustls("the pending lock is poisoned".into()))?;
            let Some(p) = g.as_ref() else {
                return Ok(None);
            };
            crate::secret::copy(&p.new_pkcs8)?
        };

        // The consumer's gate — last word before anything moves (SPEC-nettls §6.7e).
        if !safe_now() {
            return Ok(None);
        }

        // Move the material into place BEFORE the resolver switches, so a
        // crash in the middle leaves us with a certificate we actually have
        // the key to.
        let new_dir = self.dir.join("new");
        let fresh = self.load(&new_dir)?;
        self.save(&fresh, &self.dir)?;

        let old = self.resolver.swap(&fresh)?;

        {
            let mut m = self
                .material
                .write()
                .map_err(|_| TlsError::Rustls("the material lock is poisoned".into()))?;
            let new_fp = krypto::hex::encode(&krypto::sha256(fresh.cert_chain()[0].as_ref()));
            // Exactly two are kept: the old `previous` is dropped here.
            m.previous = Some(std::mem::replace(&mut m.current, (new_fp, new_pkcs8)));
        }

        // Preserve the new `previous` key. Without this it lives only in
        // memory, and a restart after more than one rotation leaves the
        // instance without the key the next announcement must be signed with
        // (SPEC-nettls §6.11, norm N-1).
        {
            let m = self
                .material
                .read()
                .map_err(|_| TlsError::Rustls("the material lock is poisoned".into()))?;
            self.save_previous(m.previous.as_ref())?;
        }

        *self
            .pending
            .write()
            .map_err(|_| TlsError::Rustls("the pending lock is poisoned".into()))? = None;
        self.schedule
            .write()
            .map_err(|_| TlsError::Rustls("the rotation lock is poisoned".into()))?
            .rolled(now)?;
        let _ = std::fs::remove_dir_all(&new_dir);
        Ok(Some(old))
    }

    /// Is it time to announce?
    pub fn should_announce(&self, now: i64) -> bool {
        self.schedule
            .read()
            .map(|r| r.should_announce(now))
            .unwrap_or(false)
    }

    /// The status the operator sees.
    pub fn status(&self, now: i64, expires: i64) -> Result<Status, TlsError> {
        Ok(self
            .schedule
            .read()
            .map_err(|_| TlsError::Rustls("the rotation lock is poisoned".into()))?
            .status(now, expires))
    }

    /// The pending announcement, if one exists.
    pub fn pending(&self) -> Option<Announcement> {
        self.pending
            .read()
            .ok()
            .and_then(|v| v.as_ref().map(|x| x.announcement.clone()))
    }
}

// --------------------------------------------------------------------------- //
// Clock exchange and time drift (§6.7b) — internal only
// --------------------------------------------------------------------------- //

/// Below this the deviation is normal and is not logged.
pub const DRIFT_NORMAL_S: i64 = 5;
/// Above this the operator is warned.
pub const DRIFT_WARNING_S: i64 = 30;
/// A jump larger than this warns even when the absolute value is within bounds.
pub const DRIFT_JUMP_S: i64 = 10;

/// How a clock deviation is to be handled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Drift {
    /// Below 5 s. Nothing.
    Normal,
    /// 5–30 s. Logged, visible in status, no alarm.
    Log,
    /// Above 30 s, or an abrupt jump. The operator is warned.
    Warning,
}

/// Tracks the clock deviation against **one** peer.
///
/// With asynchronous rotation the clock is no longer load-bearing (§6.7b) — it
/// cannot topple a connection. But it still matters: certificate validity is
/// absolute time, and a party with a wrong clock can reject a valid
/// certificate as "not yet valid".
///
/// **The deviation is tracked as a series, not as a single measurement.** An
/// NTP correction that moves the clock backwards can give a small momentary
/// deviation even though time has been skipped over — and an abrupt jump is
/// its own warning, regardless of whether the absolute value is within the
/// threshold.
#[derive(Debug, Clone, Default)]
pub struct ClockDrift {
    last: Option<i64>,
    /// The largest absolute deviation we have seen. For status.
    max: i64,
}

impl ClockDrift {
    /// New tracker.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register an observation: the peer's `sent_at` against our own clock.
    ///
    /// Internal transport time is milliseconds on a docker network, so we do
    /// not correct for it — the thresholds are far above it.
    pub fn observe(&mut self, their_sent_at: i64, our_now: i64) -> Drift {
        let deviation = their_sent_at - our_now;
        let sprang = self.last.map(|f| (deviation - f).abs()).unwrap_or(0);
        self.last = Some(deviation);
        self.max = self.max.max(deviation.abs());

        if deviation.abs() > DRIFT_WARNING_S || sprang > DRIFT_JUMP_S {
            Drift::Warning
        } else if deviation.abs() >= DRIFT_NORMAL_S {
            Drift::Log
        } else {
            Drift::Normal
        }
    }

    /// The last measured deviation in seconds (positive = the peer is ahead of us).
    pub fn last(&self) -> Option<i64> {
        self.last
    }

    /// The largest absolute deviation seen.
    pub fn max(&self) -> i64 {
        self.max
    }

    /// The message the operator gets, when there is something to say.
    pub fn message(&self, peer: &str) -> Option<String> {
        let s = self.last?;
        if s.abs() <= DRIFT_WARNING_S {
            return None;
        }
        Some(format!(
            "clock drift against {peer}: {s} seconds. Traffic continues as normal — \
             the clock is not load-bearing for the rotation (§6.7b) — but drift is rarely \
             the only thing that is wrong."
        ))
    }
}

#[cfg(test)]
mod clock_tests {
    use super::*;

    #[test]
    fn small_deviations_are_normal() {
        let mut k = ClockDrift::new();
        assert_eq!(k.observe(1000, 1000), Drift::Normal);
        assert_eq!(k.observe(1002, 1000), Drift::Normal);
    }

    #[test]
    fn medium_deviations_are_logged_without_alarm() {
        let mut k = ClockDrift::new();
        assert_eq!(k.observe(1005, 1000), Drift::Log);
        assert!(k.message("gateway").is_none(), "no warning below 30 s");
    }

    #[test]
    fn large_deviations_warn_and_name() {
        // M-15.
        let mut k = ClockDrift::new();
        assert_eq!(k.observe(1031, 1000), Drift::Warning);
        let m = k.message("gateway").unwrap();
        assert!(m.contains("gateway"), "{m}");
        assert!(m.contains("clock drift"), "{m}");
        assert!(m.contains("Traffic continues"), "{m}");
    }

    #[test]
    fn an_abrupt_jump_warns_even_within_the_threshold() {
        // M-18: this is the whole reason the deviation is tracked as a SERIES.
        // Both measurements are well below 30 s, but the clock has jumped.
        let mut k = ClockDrift::new();
        assert_eq!(k.observe(1000, 1000), Drift::Normal);
        assert_eq!(
            k.observe(1020, 1000),
            Drift::Warning,
            "a jump of 20 s must warn even though 20 < 30"
        );
    }

    #[test]
    fn drift_stops_neither_traffic_nor_rotation() {
        // M-16: the module has no way to stop anything — it returns an
        // assessment, not an action. That is the guarantee itself.
        let mut k = ClockDrift::new();
        let d = k.observe(9999, 1000);
        assert_eq!(d, Drift::Warning);
        // No `can_roll`/`stop` here: asking the module to stop something is impossible.
    }

    #[test]
    fn max_is_remembered() {
        let mut k = ClockDrift::new();
        k.observe(1040, 1000);
        k.observe(1001, 1000);
        assert_eq!(k.max(), 40);
        assert_eq!(k.last(), Some(1));
    }
}

// --------------------------------------------------------------------------- //
// The lifetime regimes (§6.2, §4)
// --------------------------------------------------------------------------- //

/// Lifetime of a certificate in **mode 2**: always 30 days.
///
/// Not adjustable. The rotation is the security mechanism, and a
/// lifetime the operator can tune would have made it a setting instead of a
/// guarantee.
pub const MODE2_LIFETIME_DAYS: u32 = 30;

/// Lower bound for a **user-facing** certificate: 47 days.
///
/// A public hard limit from around 2029. We adopt it today, and the floor
/// exists because frequent replacements give frequent browser warnings — and
/// warnings people have learned to click away do not work the day there is a
/// real MITM.
pub const MODE1_MIN_DAYS: u32 = 47;
/// Default for a user-facing certificate.
pub const MODE1_DEFAULT_DAYS: u32 = 90;
/// Absolute max for a user-facing certificate.
pub const MODE1_MAX_DAYS: u32 = 365;

/// Parameters for an **internal** certificate (mode 2): always 30 days.
pub fn mode2_params(
    common_name: impl Into<String>,
    sans: impl IntoIterator<Item = impl Into<String>>,
) -> SelfSignedParams {
    SelfSignedParams::new(common_name, sans).valid_days(MODE2_LIFETIME_DAYS)
}

/// Parameters for a **user-facing** certificate (mode 1), with validation.
///
/// `days = None` gives the default of 90.
pub fn mode1_params(
    common_name: impl Into<String>,
    sans: impl IntoIterator<Item = impl Into<String>>,
    days: Option<u32>,
) -> Result<SelfSignedParams, TlsError> {
    let d = days.unwrap_or(MODE1_DEFAULT_DAYS);
    if d < MODE1_MIN_DAYS {
        return Err(TlsError::Params(format!(
            "lifetime of {d} days is below the floor of {MODE1_MIN_DAYS} — frequent replacements \
             give frequent browser warnings, and warnings people have learned to click away do \
             not work the day there is a real MITM"
        )));
    }
    if d > MODE1_MAX_DAYS {
        return Err(TlsError::Params(format!(
            "lifetime of {d} days is above the ceiling of {MODE1_MAX_DAYS}"
        )));
    }
    Ok(SelfSignedParams::new(common_name, sans).valid_days(d))
}

#[cfg(test)]
mod lifetime_tests {
    use super::*;

    #[test]
    fn mode2_is_always_thirty_days() {
        // M-21. Not adjustable — the rotation IS the security mechanism, and a
        // lifetime the operator can tune would have made it a setting.
        assert_eq!(mode2_params("gateway", ["gateway"]).valid_days, 30);
    }

    #[test]
    fn mode1_default_is_ninety() {
        assert_eq!(
            mode1_params("portal", ["portal"], None).unwrap().valid_days,
            90
        );
    }

    #[test]
    fn mode1_floor_is_47() {
        assert!(mode1_params("portal", ["portal"], Some(46)).is_err());
        assert!(mode1_params("portal", ["portal"], Some(47)).is_ok());
    }

    #[test]
    fn mode1_ceiling_is_365() {
        assert!(mode1_params("portal", ["portal"], Some(365)).is_ok());
        assert!(mode1_params("portal", ["portal"], Some(366)).is_err());
    }

    #[test]
    fn error_message_explains_why_the_floor_exists() {
        // A limit without a rationale gets bypassed by the next person who meets it.
        let err = mode1_params("portal", ["portal"], Some(10)).unwrap_err();
        let t = format!("{err}");
        assert!(t.contains("click away"), "{t}");
    }
}

// --------------------------------------------------------------------------- //
// The promise must survive a restart (§6.9c, M-26)
// --------------------------------------------------------------------------- //

/// The file the pending announcement is persisted in.
pub const PENDING_FILE: &str = "pending-rotation.json";

#[derive(serde::Serialize, serde::Deserialize)]
struct PendingOnDisk {
    announcement: crate::announcement::AnnouncementJson,
    new_cert_pem: String,
    /// Peers that have not yet acked.
    waiting_for: Vec<String>,
    first_announced: i64,
}

impl Announcer {
    /// Write the pending announcement to disk.
    ///
    /// **The private key is not included.** It already lives in the `fresh/`
    /// directory from `prepare`, and writing it a second time would have given
    /// us two places to protect and one to forget.
    pub fn save_pending(&self) -> Result<(), TlsError> {
        let path = self.dir.join(PENDING_FILE);
        let v = self
            .pending
            .read()
            .map_err(|_| TlsError::Rustls("the pending lock is poisoned".into()))?;
        let Some(v) = v.as_ref() else {
            // Nothing to store: remove any old file so a restart does not
            // think a promise is lying there.
            let _ = std::fs::remove_file(&path);
            return Ok(());
        };
        let r = self
            .schedule
            .read()
            .map_err(|_| TlsError::Rustls("the rotation lock is poisoned".into()))?;
        let on_disk = PendingOnDisk {
            announcement: v.announcement.to_json(),
            new_cert_pem: v.new_cert_pem.clone(),
            waiting_for: r.waiting_for().into_iter().map(str::to_string).collect(),
            first_announced: r.first_announced().unwrap_or(0),
        };
        let text = serde_json::to_string_pretty(&on_disk)
            .map_err(|e| TlsError::Proof(format!("could not serialize: {e}")))?;
        Self::skriv_atomisk(&path, text.as_bytes())
    }

    /// Read a promise back after a restart.
    ///
    /// Without this, a restart between announcement and switch would forget
    /// that we had promised something binding — and the peer, which has acked
    /// and awaits the new certificate, would be left holding a promise nobody keeps.
    ///
    /// **The material is read from `fresh/`, not from the file.** The file
    /// carries only the announcement and who we are waiting for; the private
    /// key lies where it was written in `prepare`.
    fn restore_pending(&self) -> Result<bool, TlsError> {
        let path = self.dir.join(PENDING_FILE);
        let text = match std::fs::read_to_string(&path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(e) => return Err(TlsError::io(&path, e)),
        };
        let on_disk: PendingOnDisk = serde_json::from_str(&text)
            .map_err(|e| TlsError::Proof(format!("the pending file could not be parsed: {e}")))?;

        let k = Announcement::from_json(&on_disk.announcement)?;
        let new_dir = self.dir.join("new");
        let m = self.load(&new_dir).map_err(|e| {
            TlsError::Chain(format!(
                "the pending file promises a rotation, but the key material in «new/» is missing \
                 or damaged ({e}). The promise cannot be kept — this must be cleaned up by an \
                 operator."
            ))
        })?;
        let der = m.cert_chain()[0].as_ref().to_vec();
        let new_pkcs8 = crate::pkcs8::pkcs8_p256(m.key_der(), &der)?;

        *self
            .pending
            .write()
            .map_err(|_| TlsError::Rustls("the pending lock is poisoned".into()))? =
            Some(Pending {
                announcement: k,
                new_cert_pem: on_disk.new_cert_pem,
                new_pkcs8,
            });

        let mut r = self
            .schedule
            .write()
            .map_err(|_| TlsError::Rustls("the rotation lock is poisoned".into()))?;
        r.restore_announced(on_disk.waiting_for, on_disk.first_announced);
        Ok(true)
    }
}

impl Schedule {
    /// Set the state back to "announced" after a restart (§6.9c).
    ///
    /// Preserves **who we have already heard back from** and **when we first
    /// announced** — otherwise a restart would reset the 12-hour clock, and
    /// the alarm would never fire in a service that restarts often.
    pub fn restore_announced(&mut self, waiting_for: Vec<String>, first_announced: i64) {
        self.state = ChainState::Announced {
            waiting_for: waiting_for.into_iter().collect(),
            first_announced,
        };
    }
}

// --------------------------------------------------------------------------- //
// Falling to mode 1 on an identity deviation (§6.8b, M-8/M-27)
// --------------------------------------------------------------------------- //

/// Why a connection fell to mode 1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Deviation {
    /// The peer presented something that is neither `current` nor a stored `next`.
    UnknownCertificate {
        /// What we saw.
        observed: String,
    },
    /// A signature on an announcement did not hold.
    InvalidSignature(String),
    /// The peer presented a certificate it has **abandoned**.
    AbandonedCertificate {
        /// What we saw.
        observed: String,
    },
}

impl Deviation {
    /// The message the operator gets. Says what happened and what must be done.
    pub fn message(&self, peer: &str) -> String {
        let what = match self {
            Deviation::UnknownCertificate { observed } => format!(
                "presented a certificate we do not know ({}…)",
                &observed[..16.min(observed.len())]
            ),
            Deviation::InvalidSignature(d) => {
                format!("sent an announcement that did not hold: {d}")
            }
            Deviation::AbandonedCertificate { observed } => format!(
                "presented a certificate it has abandoned ({}…) — a rollback, or a replay",
                &observed[..16.min(observed.len())]
            ),
        };
        format!(
            "TRUST FAILURE against {peer}: the peer {what}. Traffic to {peer} is stopped, \
             and the connection now stands in mode 1 (pinning). An operator must approve the \
             identity anew before it can be used. This is NOT retried automatically — a retry \
             against an identity we cannot verify is just one more chance for whoever stands in \
             the middle."
        )
    }
}

/// The outcome of an identity deviation: **always** mode 1, never a retry.
///
/// The return type exists so the call site cannot choose anything else — the
/// newtype move: enforce the rule with the construction, not with someone
/// remembering it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FallToMode1 {
    /// What triggered the fall.
    pub deviation: Deviation,
}

impl FallToMode1 {
    /// Register a deviation. There is no other constructor, and no way back to
    /// mode 2 without an operator action.
    pub fn at(deviation: Deviation) -> Self {
        Self { deviation }
    }

    /// The mode the connection stands in afterwards. Always the same.
    pub fn mode(&self) -> Mode {
        Mode::Pinning
    }

    /// Should this be retried? Never.
    pub fn can_retry(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod restart_and_deviation_tests {
    use super::*;

    #[test]
    fn restore_preserves_who_has_acked() {
        // Without this a restart would reset who has answered, and a peer
        // would have to ack again for no reason.
        let mut r = Schedule::new(vec!["service".to_string(), "portal".to_string()], 0);
        r.restore_announced(vec!["portal".to_string()], 500);
        assert_eq!(r.waiting_for(), vec!["portal"]);
        assert_eq!(r.first_announced(), Some(500));
    }

    #[test]
    fn restore_preserves_the_alarm_clock() {
        // M-26, and the part that is easy to get wrong: restart often enough,
        // with the clock reset every time, and the alarm NEVER fires.
        let mut r = Schedule::new(vec!["service".to_string()], 0);
        r.restore_announced(vec!["service".to_string()], 0);
        assert!(
            r.alarm(ALARM_AFTER_S),
            "the alarm must fire based on the ORIGINAL time"
        );
    }

    #[test]
    fn deviation_always_gives_mode1_and_never_a_retry() {
        for a in [
            Deviation::UnknownCertificate {
                observed: "aa".repeat(32),
            },
            Deviation::InvalidSignature("prev did not hold".into()),
            Deviation::AbandonedCertificate {
                observed: "bb".repeat(32),
            },
        ] {
            let f = FallToMode1::at(a);
            assert_eq!(f.mode(), Mode::Pinning);
            assert!(!f.can_retry());
        }
    }

    #[test]
    fn message_says_what_happened_and_what_must_be_done() {
        let m = FallToMode1::at(Deviation::AbandonedCertificate {
            observed: "cc".repeat(32),
        })
        .deviation
        .message("gateway");
        assert!(m.contains("TRUST FAILURE"), "{m}");
        assert!(m.contains("gateway"), "{m}");
        assert!(m.contains("abandoned"), "{m}");
        assert!(m.contains("approve the identity anew"), "{m}");
        assert!(m.contains("NOT retried automatically"), "{m}");
    }
}

/// Our own generation triple, as a readable value — fingerprints only.
///
/// The consumer needs insight into what we hold (status, logging, operator
/// display); it never needs — and never gets — the private keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnTrio {
    /// The retired generation still used for signing. `None` before the first
    /// rotation.
    pub previous_fingerprint: Option<String>,
    /// What we serve right now.
    pub current_fingerprint: String,
    /// An announced successor awaiting acknowledgement, if any.
    pub next_fingerprint: Option<String>,
}
