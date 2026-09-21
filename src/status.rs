// SPDX-License-Identifier: MIT OR Apache-2.0
//! The status report — nettls' contribution to a consumer's "About" page.
//!
//! Every service in a deployment shows status for its parts, and the TLS part
//! is this crate's to describe. The crate therefore owns the **vocabulary**
//! (what the states are called), the **derivation** (what counts as a
//! warning) and the **one-line headline** — so every consumer shows the same
//! truth, and the thresholds live in ONE place. The consumer owns the
//! transport: it collects a [`Report`] and serves it wherever its status
//! surface lives.
//!
//! **Two views, two audiences (the instruction to consumers):**
//!
//! - [`Report::summary`] — the **general** view, safe for every logged-in
//!   user: component version, one traffic light, one headline. Serve this on
//!   the general About surface.
//! - [`Report`] itself — the **detailed** view: identity, rotation state,
//!   per-peer trust. Peer names, waiting lists and deviations are operations
//!   data — serve this **only on the admin surface**.
//!
//! Both serialize with serde; drop them straight into your status JSON. No
//! I/O, no clock: the caller passes `now` (Unix seconds), like the rest of
//! the crate's pure logic.

use serde::Serialize;

use crate::announcer::{mode1_should_warn, Status};
use crate::generations::Generations;
use crate::material::TlsMaterial;

/// One traffic light, derived by the crate's own rules — the consumer colours
/// the About row without interpreting anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Level {
    /// Everything is fine.
    Ok,
    /// Something needs attention soon (expiry approaching, rotation pending).
    Warn,
    /// Something needs an operator NOW (broken trust, alarm, expired cert).
    Alert,
}

/// The state of one peer, in the crate's vocabulary.
///
/// [`PeerReport::from_generations`] derives what the generation pair can
/// tell; `Broken` is the consumer's to set — only it sees the `Chain` error
/// from a failed restore/receive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PeerState {
    /// Trust is established and quiet.
    Ok,
    /// A next certificate is announced and awaiting the switch/approval.
    RotationPending,
    /// The continuity chain is broken — operator action required.
    Broken,
}

/// One peer's row in the detailed view (admin).
#[derive(Debug, Clone, Serialize)]
pub struct PeerReport {
    /// The consumer's name for the peer.
    pub name: String,
    /// Derived or consumer-set state.
    pub state: PeerState,
    /// The fingerprint we currently trust.
    pub current_fingerprint: String,
    /// The announced next fingerprint, when a rotation is in flight.
    pub next_fingerprint: Option<String>,
}

impl PeerReport {
    /// Derive a peer row from its generation pair. Bootstrap (nothing pinned
    /// beyond the operator's first approval) reads as `Ok` — approval already
    /// happened; a pending `next` reads as `RotationPending`.
    pub fn from_generations(name: impl Into<String>, g: &Generations) -> Self {
        let next = g.next().map(|n| n.fingerprint().to_string());
        PeerReport {
            name: name.into(),
            state: if next.is_some() {
                PeerState::RotationPending
            } else {
                PeerState::Ok
            },
            current_fingerprint: g.current().fingerprint().to_string(),
            next_fingerprint: next,
        }
    }

    /// The consumer saw a `Chain` error for this peer — only it can know.
    pub fn broken(name: impl Into<String>, last_known_fingerprint: impl Into<String>) -> Self {
        PeerReport {
            name: name.into(),
            state: PeerState::Broken,
            current_fingerprint: last_known_fingerprint.into(),
            next_fingerprint: None,
        }
    }
}

/// Our own identity, as the About page needs it.
#[derive(Debug, Clone, Serialize)]
pub struct IdentityReport {
    /// SHA-256 fingerprint of the serving certificate.
    pub fingerprint_sha256: String,
    /// Where the certificate came from (self-signed, loaded, …).
    pub origin: String,
    /// Unix seconds when the certificate expires (`None` = unparsable).
    pub not_after: Option<i64>,
    /// Whole days until expiry (negative = expired).
    pub days_until_expiry: i64,
    /// The crate's own expiry warning (same threshold as the rotation rule —
    /// owned HERE, never re-derived by a consumer).
    pub expiry_warning: bool,
}

/// The rotation machinery's contribution, when the service runs an announcer.
#[derive(Debug, Clone, Serialize)]
pub struct RotationReport {
    /// Peers we are waiting for. Empty = all is well.
    pub waiting_for: Vec<String>,
    /// Has the 12-hour alarm fired?
    pub alarm: bool,
    /// Seconds until internal communication actually stops (the countdown).
    pub seconds_until_stop: i64,
}

/// The detailed view — serve on the **admin** surface only.
#[derive(Debug, Clone, Serialize)]
pub struct Report {
    /// The crate version ([`crate::VERSION`]).
    pub version: &'static str,
    /// The derived traffic light.
    pub level: Level,
    /// The crate-authored one-liner (English, like every message the crate emits).
    pub headline: String,
    /// Our own identity.
    pub identity: IdentityReport,
    /// Rotation state, when an announcer runs.
    pub rotation: Option<RotationReport>,
    /// Per-peer trust.
    pub peers: Vec<PeerReport>,
}

/// The general view — safe for every logged-in user.
#[derive(Debug, Clone, Serialize)]
pub struct Summary {
    /// The crate version.
    pub version: &'static str,
    /// The derived traffic light.
    pub level: Level,
    /// The crate-authored one-liner.
    pub headline: String,
}

impl Report {
    /// Collect the report. `now` is Unix seconds (the caller owns the clock,
    /// as everywhere else in the crate); `announcer_status` is `None` for a
    /// service that runs plain pinning without the §6 announcer.
    pub fn collect(
        now: i64,
        material: &TlsMaterial,
        announcer_status: Option<&Status>,
        peers: Vec<PeerReport>,
    ) -> Report {
        let not_after = material.not_after();
        let days = material.days_until_expiry();
        let expiry_warning = not_after.map(|e| mode1_should_warn(now, e)).unwrap_or(true);
        let identity = IdentityReport {
            fingerprint_sha256: material.fingerprint_sha256(),
            origin: format!("{:?}", material.origin()),
            not_after,
            days_until_expiry: days,
            expiry_warning,
        };
        let rotation = announcer_status.map(|s| RotationReport {
            waiting_for: s.waiting_for.clone(),
            alarm: s.alarm,
            seconds_until_stop: s.seconds_until_stop,
        });

        let broken: Vec<&str> = peers
            .iter()
            .filter(|p| p.state == PeerState::Broken)
            .map(|p| p.name.as_str())
            .collect();
        let pending: Vec<&str> = peers
            .iter()
            .filter(|p| p.state == PeerState::RotationPending)
            .map(|p| p.name.as_str())
            .collect();
        let expired = days < 0;
        let alarm = rotation.as_ref().map(|r| r.alarm).unwrap_or(false);
        let stopping = rotation
            .as_ref()
            .map(|r| r.seconds_until_stop <= 0)
            .unwrap_or(false);
        let waiting = rotation
            .as_ref()
            .map(|r| !r.waiting_for.is_empty())
            .unwrap_or(false);

        let (level, headline) = if !broken.is_empty() {
            (
                Level::Alert,
                format!(
                    "trust chain broken to {} — operator action required",
                    broken.join(", ")
                ),
            )
        } else if expired || stopping {
            (
                Level::Alert,
                "certificate expired — communication stops".to_string(),
            )
        } else if alarm {
            (
                Level::Alert,
                format!(
                    "rotation alarm: still waiting for {}",
                    rotation
                        .as_ref()
                        .map(|r| r.waiting_for.join(", "))
                        .unwrap_or_default()
                ),
            )
        } else if expiry_warning {
            (Level::Warn, format!("certificate expires in {days} days"))
        } else if waiting || !pending.is_empty() {
            (Level::Warn, "rotation pending".to_string())
        } else {
            (Level::Ok, "TLS ok".to_string())
        };

        Report {
            version: crate::VERSION,
            level,
            headline,
            identity,
            rotation,
            peers,
        }
    }

    /// The general view — what every logged-in user may see.
    pub fn summary(&self) -> Summary {
        Summary {
            version: self.version,
            level: self.level,
            headline: self.headline.clone(),
        }
    }
}
