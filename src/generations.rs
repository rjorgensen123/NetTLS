// SPDX-License-Identifier: MIT OR Apache-2.0
//! The generation pair — the state §6 rests on.
//!
//! For each peer we keep:
//!
//! ```text
//! (previous, current)  [+ next, once it is announced and stored]
//! ```
//!
//! ## Two roles, and they do not overlap
//!
//! It is easy to assume that "the certificates we trust" is a single list. It
//! is not — the certificates have **two different jobs**, and which ones apply
//! is not the same:
//!
//! | Role | Which | Why |
//! |---|---|---|
//! | **Accepted in handshake** | `current` + `next` | The peer may switch at any moment (§6.7). We must accept both from the moment `next` is stored, or the connection breaks at the instant of the switch |
//! | **Verifies announcements** | `previous` + `current` | The two signatures on an announcement are made with exactly these (§6.5) |
//!
//! So `previous` is **not** accepted in a handshake once we have seen the
//! switch. It is kept to verify the next announcement, not to let anyone in.
//! Mixing the two would give a wider window than necessary — and the width of
//! the window is the whole reason a leaked old key stops having value.
//!
//! ## Promotion happens on observation
//!
//! `(previous, current)` becomes `(current, next)` when we **actually see**
//! the peer present the new certificate — not at a point in time, and not on
//! a message. The observation is the trigger, and it requires no coordination
//! between the parties at all. That is what makes the rotation asynchronous.

use crate::announcement::Announcement;
use crate::error::TlsError;
use krypto::sha256;

/// One certificate with its fingerprint.
#[derive(Clone, PartialEq, Eq)]
pub struct Generation {
    der: Vec<u8>,
    fp: String,
}

impl std::fmt::Debug for Generation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Everything here is public. The fingerprint is shortened because 64
        // hex chars in a log line is noise, not because it is sensitive.
        write!(f, "Generation({}…)", &self.fp[..16.min(self.fp.len())])
    }
}

impl Generation {
    /// From a DER-encoded certificate.
    pub fn from_der(der: impl Into<Vec<u8>>) -> Self {
        let der = der.into();
        let fp = krypto::hex::encode(&sha256(&der));
        Self { der, fp }
    }

    /// From PEM.
    pub fn from_pem(pem: &str) -> Result<Self, TlsError> {
        let fp = crate::announcement::fingerprint_from_pem(pem)?;
        let der = crate::announcement::der_from_pem(pem)?;
        Ok(Self { der, fp })
    }

    /// The certificate, DER-encoded.
    pub fn der(&self) -> &[u8] {
        &self.der
    }
    /// The fingerprint, 64 hex chars without prefix.
    pub fn fingerprint(&self) -> &str {
        &self.fp
    }
}

/// What happened when an announcement was received.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Received {
    /// New announcement stored. The peer's next identity is now known.
    Stored,
    /// We already had it. Idempotent — the peer republishes the same one until
    /// it gets an acknowledgement (§6.8a), and that must not be an error.
    Known,
}

/// The generation state for **one** peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Generations {
    previous: Option<Generation>,
    current: Generation,
    next: Option<Generation>,
}

impl Generations {
    /// The state right after the operator's approval (generation 0).
    ///
    /// No `previous`: that is exactly why the first announcement is
    /// single-signed (§6.3).
    pub fn from_approval(current: Generation) -> Self {
        Self {
            previous: None,
            current,
            next: None,
        }
    }

    /// Restore the state **the consumer itself has remembered** (§6.8).
    ///
    /// # Why this exists
    ///
    /// The API was asymmetric: the state could be read out — [`Self::current`],
    /// [`Self::previous`], [`Self::next`], [`Generation::der`] — but could
    /// only be rebuilt from a single anchor, via [`Self::from_approval`]. A
    /// service that had written everything down could not put it back.
    ///
    /// The consequence was that **every** restart looked like memory loss. The
    /// receiver then has only an anchor, and an announcement from a peer that
    /// has already rolled names a `previous` we do not know — which §6.3
    /// rightly rejects. The pair could thus not rotate again without the
    /// operator stepping in, even though only one process had restarted.
    ///
    /// # Who owns the storage
    ///
    /// **Not this crate.** `nettls` is a library and has no opinion on where
    /// the service stores anything, or how it protects it. The service
    /// remembers; the crate offers the way back.
    ///
    /// # What the caller vouches for
    ///
    /// This function **verifies nothing** — there is nothing to verify
    /// against. Whoever calls it thereby asserts that the contents come from
    /// the service's own, unmodified storage. Whoever can modify that storage
    /// chooses whom we trust, and that is why the integrity of the store is a
    /// security requirement on the consumer (SPEC-nettls §6.11b).
    ///
    /// The one thing enforced is the shape: `previous` and `next` cannot be
    /// the same certificate as `current`. Such a state cannot arise from a
    /// legal rotation, and it would have made [`Self::observed`] promote
    /// something that was already promoted.
    pub fn restore(
        previous: Option<Generation>,
        current: Generation,
        next: Option<Generation>,
    ) -> Result<Self, TlsError> {
        for (name, g) in [("previous", &previous), ("next", &next)] {
            if let Some(g) = g {
                if g.fingerprint() == current.fingerprint() {
                    return Err(TlsError::Params(format!(
                        "restored state has \"{name}\" equal to \"current\" ({}) — \
                         that cannot arise from a legal rotation",
                        current.fingerprint()
                    )));
                }
            }
        }
        if let (Some(f), Some(n)) = (&previous, &next) {
            if f.fingerprint() == n.fingerprint() {
                return Err(TlsError::Params(format!(
                    "restored state has \"previous\" equal to \"next\" ({}) — \
                     the peer cannot rotate back to a certificate it \
                     just left",
                    f.fingerprint()
                )));
            }
        }
        Ok(Self {
            previous,
            current,
            next,
        })
    }

    /// Receive an announcement: verify it against **our own** state, and store
    /// the new certificate.
    ///
    /// Verification uses `previous` and `current` — and that it is *our*
    /// `previous` that decides whether a single signature is accepted is the
    /// whole point (`Announcement::verify`).
    pub fn receive(&mut self, k: &Announcement) -> Result<Received, TlsError> {
        if let Some(n) = &self.next {
            if n.fingerprint() == k.new_fingerprint() {
                return Ok(Received::Known);
            }
        }
        k.verify(self.previous.as_ref().map(|g| g.der()), self.current.der())?;
        self.next = Some(Generation::from_pem(k.new_cert_pem())?);
        Ok(Received::Stored)
    }

    /// We have observed the peer present `fp` in a handshake.
    ///
    /// If it is `next`, the state is promoted. If it is `current`, nothing
    /// happens. If it is anything else, rejecting it is **not** this
    /// function's job — the handshake has already done that
    /// (`accepted_in_handshake`).
    pub fn observed(&mut self, fp: &str) -> bool {
        let Some(n) = &self.next else { return false };
        if n.fingerprint() != fp {
            return false;
        }
        let fresh = self.next.take().expect("checked above");
        self.previous = Some(std::mem::replace(&mut self.current, fresh));
        true
    }

    /// The certificates accepted in a **handshake**: `current` + `next`.
    ///
    /// Note that `previous` is not included. It is kept to verify the next
    /// announcement, not to let anyone in.
    pub fn accepted_in_handshake(&self) -> Vec<&Generation> {
        let mut out = vec![&self.current];
        if let Some(n) = &self.next {
            out.push(n);
        }
        out
    }

    /// The certificates that verify an **announcement**: `(previous, current)`.
    pub fn for_signing(&self) -> (Option<&Generation>, &Generation) {
        (self.previous.as_ref(), &self.current)
    }

    /// The running generation.
    pub fn current(&self) -> &Generation {
        &self.current
    }
    /// The previous generation, when it exists.
    pub fn previous(&self) -> Option<&Generation> {
        self.previous.as_ref()
    }
    /// Announced, not yet taken into use.
    pub fn next(&self) -> Option<&Generation> {
        self.next.as_ref()
    }

    /// Are we in bootstrap — that is, still without a previous generation?
    pub fn is_bootstrap(&self) -> bool {
        self.previous.is_none()
    }
}

#[cfg(test)]
mod tester {
    use super::*;
    use crate::material::TlsMaterial;
    use crate::{CertSource, SelfSignedParams};

    pub(super) struct Gen {
        pub(super) pem: String,
        pub(super) g: Generation,
        pub(super) pkcs8: krypto::SecretBuf,
    }

    pub(super) fn gen(name: &str) -> Gen {
        let m = TlsMaterial::load(&CertSource::self_signed(SelfSignedParams::new(
            name,
            [name],
        )))
        .expect("self-signed");
        let der = m.cert_chain()[0].as_ref().to_vec();
        let pkcs8 = crate::pkcs8::pkcs8_p256(m.key_der(), &der).expect("pkcs8");
        let pem = String::from_utf8(crate::pem::encode("CERTIFICATE", &der)).unwrap();
        Gen {
            pem,
            g: Generation::from_der(der),
            pkcs8,
        }
    }

    pub(super) fn kunngjor(
        a: &str,
        prev: Option<&Gen>,
        curr: &Gen,
        fresh: &Gen,
        t: i64,
    ) -> Announcement {
        Announcement::new(
            a,
            prev.map(|p| (p.g.fingerprint(), &p.pkcs8)),
            (curr.g.fingerprint(), &curr.pkcs8),
            &fresh.pem,
            t,
        )
        .unwrap()
    }

    #[test]
    fn bootstrap_has_no_previous_and_accepts_single_signature() {
        let c0 = gen("c0");
        let c1 = gen("c1");
        let mut g = Generations::from_approval(c0.g.clone());
        assert!(g.is_bootstrap());

        let k = kunngjor("gateway", None, &c0, &c1, 1);
        assert_eq!(g.receive(&k).unwrap(), Received::Stored);
        assert_eq!(g.next().unwrap().fingerprint(), c1.g.fingerprint());
    }

    #[test]
    fn the_two_roles_are_not_the_same() {
        // The core of the module: previous verifies announcements, but lets
        // no one into a handshake.
        let c0 = gen("c0");
        let c1 = gen("c1");
        let c2 = gen("c2");

        let mut g = Generations::from_approval(c0.g.clone());
        g.receive(&kunngjor("gateway", None, &c0, &c1, 1)).unwrap();
        assert!(g.observed(c1.g.fingerprint()));
        // Now: previous=c0, current=c1, next=None
        g.receive(&kunngjor("gateway", Some(&c0), &c1, &c2, 2))
            .unwrap();

        let hs: Vec<_> = g
            .accepted_in_handshake()
            .iter()
            .map(|x| x.fingerprint().to_string())
            .collect();
        assert!(hs.contains(&c1.g.fingerprint().to_string()), "current");
        assert!(hs.contains(&c2.g.fingerprint().to_string()), "next");
        assert!(
            !hs.contains(&c0.g.fingerprint().to_string()),
            "previous must NOT be accepted in a handshake — it is only for signatures"
        );

        let (previous, current) = g.for_signing();
        assert_eq!(previous.unwrap().fingerprint(), c0.g.fingerprint());
        assert_eq!(current.fingerprint(), c1.g.fingerprint());
    }

    #[test]
    fn promotion_happens_on_observation() {
        let c0 = gen("c0");
        let c1 = gen("c1");
        let mut g = Generations::from_approval(c0.g.clone());
        g.receive(&kunngjor("gateway", None, &c0, &c1, 1)).unwrap();

        // Before observation: nothing has moved.
        assert_eq!(g.current().fingerprint(), c0.g.fingerprint());
        assert!(g.previous().is_none());

        assert!(g.observed(c1.g.fingerprint()));
        assert_eq!(g.current().fingerprint(), c1.g.fingerprint());
        assert_eq!(g.previous().unwrap().fingerprint(), c0.g.fingerprint());
        assert!(g.next().is_none());
    }

    #[test]
    fn observing_something_else_does_not_promote() {
        let c0 = gen("c0");
        let c1 = gen("c1");
        let foreign = gen("foreign");
        let mut g = Generations::from_approval(c0.g.clone());
        g.receive(&kunngjor("gateway", None, &c0, &c1, 1)).unwrap();

        assert!(!g.observed(foreign.g.fingerprint()));
        assert!(!g.observed(c0.g.fingerprint()));
        assert_eq!(g.current().fingerprint(), c0.g.fingerprint());
        assert!(g.next().is_some(), "the announcement must still stand");
    }

    #[test]
    fn same_announcement_again_is_idempotent() {
        // The peer republishes the same one until it gets an acknowledgement
        // (§6.8a). That must not be an error.
        let c0 = gen("c0");
        let c1 = gen("c1");
        let mut g = Generations::from_approval(c0.g.clone());
        let k = kunngjor("gateway", None, &c0, &c1, 1);
        assert_eq!(g.receive(&k).unwrap(), Received::Stored);
        assert_eq!(g.receive(&k).unwrap(), Received::Known);
    }

    #[test]
    fn single_signature_rejected_after_first_rotation() {
        let c0 = gen("c0");
        let c1 = gen("c1");
        let c2 = gen("c2");
        let mut g = Generations::from_approval(c0.g.clone());
        g.receive(&kunngjor("gateway", None, &c0, &c1, 1)).unwrap();
        g.observed(c1.g.fingerprint());

        // A single-signed announcement now that we HAVE a previous → rejected.
        let k = kunngjor("gateway", None, &c1, &c2, 2);
        assert!(g.receive(&k).is_err());
        assert!(g.next().is_none(), "nothing must be stored");
    }

    #[test]
    fn three_rotations_carry_without_the_anchor() {
        // M-36: only at rotation 3 is the anchor out of every signature, and
        // the receiver's pair consists solely of certificates no one has
        // approved manually.
        let c: Vec<Gen> = (0..4).map(|i| gen(&format!("c{i}"))).collect();
        let mut g = Generations::from_approval(c[0].g.clone());

        g.receive(&kunngjor("gateway", None, &c[0], &c[1], 1))
            .unwrap();
        g.observed(c[1].g.fingerprint());

        g.receive(&kunngjor("gateway", Some(&c[0]), &c[1], &c[2], 2))
            .unwrap();
        g.observed(c[2].g.fingerprint());

        g.receive(&kunngjor("gateway", Some(&c[1]), &c[2], &c[3], 3))
            .unwrap();
        g.observed(c[3].g.fingerprint());

        assert_eq!(g.current().fingerprint(), c[3].g.fingerprint());
        assert_eq!(g.previous().unwrap().fingerprint(), c[2].g.fingerprint());
        // The anchor is out of the picture.
        for x in g.accepted_in_handshake() {
            assert_ne!(x.fingerprint(), c[0].g.fingerprint());
        }
    }
}

// --------------------------------------------------------------------------- //
// Wiring to actual TLS (§6.3, §6.7)
// --------------------------------------------------------------------------- //

use std::sync::{Arc, RwLock};

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{CertificateError, ClientConfig, DigitallySignedStruct, Error, SignatureScheme};

/// The client's trust in **one** peer, wired to actual TLS.
///
/// A **handle**: [`Clone`] shares the state, and a `ClientConfig` built here
/// reads the *live* state at every handshake. If you receive an announcement
/// after the config was built, the new certificate applies immediately —
/// without rebuilding the config and without restarting anything.
///
/// That is the precondition for the rotation being imperceptible: the peer
/// switches whenever it wants (§6.7), and we must accept it at that very
/// moment without having been told *when*.
#[derive(Clone)]
pub struct Trust {
    state: Arc<RwLock<Generations>>,
}

impl std::fmt::Debug for Trust {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.state.read() {
            Ok(g) => write!(f, "Trust({:?})", g.current()),
            Err(_) => f.write_str("Trust(<poisoned lock>)"),
        }
    }
}

impl Trust {
    /// From the operator's approval (generation 0).
    pub fn from_approval(current: Generation) -> Self {
        Self {
            state: Arc::new(RwLock::new(Generations::from_approval(current))),
        }
    }

    /// From an existing state (read from the locked file at startup).
    pub fn from_state(g: Generations) -> Self {
        Self {
            state: Arc::new(RwLock::new(g)),
        }
    }

    /// Receive an announcement. Takes effect on a live config.
    pub fn receive(&self, k: &Announcement) -> Result<Received, TlsError> {
        let mut g = self
            .state
            .write()
            .map_err(|_| TlsError::Chain("the trust lock is poisoned".into()))?;
        g.receive(k)
    }

    /// A snapshot of the state — for storage and status.
    pub fn state(&self) -> Result<Generations, TlsError> {
        self.state
            .read()
            .map(|g| g.clone())
            .map_err(|_| TlsError::Chain("the trust lock is poisoned".into()))
    }

    /// `ClientConfig` that accepts `current` + `next`.
    pub fn client_config(&self) -> Result<Arc<ClientConfig>, TlsError> {
        self.client_config_with_alpn(&[])
    }

    /// Like [`Trust::client_config`], but with ALPN.
    pub fn client_config_with_alpn(&self, alpn: &[Vec<u8>]) -> Result<Arc<ClientConfig>, TlsError> {
        self.client_config_with(alpn, &crate::transport::TransportPolicy::default())
    }

    /// Like [`Trust::client_config_with_alpn`], with an explicit
    /// [`TransportPolicy`](crate::transport::TransportPolicy) (0.8.3). Without
    /// one, the client offers the default: **AES-256-GCM only**.
    pub fn client_config_with(
        &self,
        alpn: &[Vec<u8>],
        transport: &crate::transport::TransportPolicy,
    ) -> Result<Arc<ClientConfig>, TlsError> {
        let provider = transport.provider();
        let verifier = GenerationVerifier {
            state: self.state.clone(),
            provider: provider.clone(),
        };
        let mut cfg = ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
            .map_err(|e| TlsError::Rustls(e.to_string()))?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(verifier))
            .with_no_client_auth();
        cfg.alpn_protocols = alpn.to_vec();
        // No session resumption: a resumed session skips certificate
        // verification, and a client could then have carried on under an
        // identity we just stopped accepting.
        cfg.resumption = crate::pin::no_resumption();
        Ok(Arc::new(cfg))
    }
}

#[derive(Debug)]
struct GenerationVerifier {
    state: Arc<RwLock<Generations>>,
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for GenerationVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        let fp = krypto::hex::encode(&sha256(end_entity.as_ref()));

        // One write-lock grab: we may have to promote, and taking a read lock
        // first and then a write lock would open a window where two handshakes
        // see different state.
        let mut g = match self.state.write() {
            Ok(g) => g,
            // A poisoned lock is a bug — but it must never turn into "accept
            // everything". Fail closed here too.
            Err(_) => {
                return Err(Error::InvalidCertificate(
                    CertificateError::ApplicationVerificationFailure,
                ))
            }
        };

        let godtatt = g
            .accepted_in_handshake()
            .iter()
            .any(|x| x.fingerprint() == fp);
        if !godtatt {
            // The fingerprints are deliberately left out of the error: the
            // client knows what it expected, and what it saw belongs in a log
            // call at the consumer — not in a TLS alert that goes out on the
            // wire.
            return Err(Error::InvalidCertificate(
                CertificateError::ApplicationVerificationFailure,
            ));
        }

        // **The observation is the promotion** (§6.7). If we see `next` on the
        // wire, the peer has switched — and then it is this moment, not a
        // point in time or a message, that moves the state.
        g.observed(&fp);

        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
mod restore_tests {
    use super::tester::{gen, kunngjor};
    use super::*;

    /// The core of §6.8: a restart WITH state must not look like memory
    /// loss — and (A8, decided 2026-08-14) a restart WITHOUT state is a
    /// fresh generation 0, not a dead end.
    ///
    /// The peer has rolled at least once, so it signs with `prev` + `curr`.
    /// A receiver holding only an anchor verifies what it CAN — `sig_curr`
    /// against the anchor — and accepts: the generation numbering is local to
    /// the receiver, and the operator just vouched for `curr`. A receiver
    /// that has remembered its `previous` verifies both signatures.
    #[test]
    fn restored_state_accepts_double_signed_announcement() {
        let (c0, c1, c2) = (gen("c0"), gen("c1"), gen("c2"));
        let k = kunngjor("gateway", Some(&c0), &c1, &c2, 1_700_000_000);

        // Without memory: only the anchor. A8: accepted — this is the late
        // joiner / re-anchored receiver, and `sig_curr` holds against the
        // anchor the operator approved.
        let mut glemt = Generations::from_approval(c1.g.clone());
        assert!(
            glemt.receive(&k).is_ok(),
            "a receiver with only an anchor must accept a double-signed \
             announcement whose curr matches the anchor (A8: numbering is \
             local to the receiver)"
        );

        // With memory: previous is back, and the same announcement goes in.
        let mut husket =
            Generations::restore(Some(c0.g.clone()), c1.g.clone(), None).expect("legal state");
        assert!(
            husket.receive(&k).is_ok(),
            "a receiver that HAS remembered its previous must accept exactly \
             the same announcement — otherwise every restart requires an operator"
        );
    }

    /// A pending `next` must survive too, not just `previous`.
    ///
    /// Without it, a restart between announcement and switch would forget that
    /// the peer had promised a new certificate — and the handshake would have
    /// rejected it at the very moment the peer actually switched.
    #[test]
    fn restored_next_accepted_in_handshake_and_promoted() {
        let (c0, c1, c2) = (gen("c0"), gen("c1"), gen("c2"));
        let mut g = Generations::restore(Some(c0.g.clone()), c1.g.clone(), Some(c2.g.clone()))
            .expect("legal state");

        let godtatt: Vec<&str> = g
            .accepted_in_handshake()
            .iter()
            .map(|x| x.fingerprint())
            .collect();
        assert!(
            godtatt.contains(&c1.g.fingerprint()),
            "current must be accepted"
        );
        assert!(
            godtatt.contains(&c2.g.fingerprint()),
            "a restored \"next\" must be accepted in handshake — otherwise the \
             connection fails exactly when the peer switches"
        );

        assert!(
            g.observed(c2.g.fingerprint()),
            "must promote on observation"
        );
        assert_eq!(g.current().fingerprint(), c2.g.fingerprint());
        assert_eq!(
            g.previous().map(|x| x.fingerprint()),
            Some(c1.g.fingerprint())
        );
    }

    /// The shape is enforced, even though the contents cannot be verified.
    #[test]
    fn impossible_states_are_rejected() {
        let (c0, c1) = (gen("c0"), gen("c1"));

        assert!(
            Generations::restore(Some(c1.g.clone()), c1.g.clone(), None).is_err(),
            "previous == current cannot arise from a legal rotation"
        );
        assert!(
            Generations::restore(None, c1.g.clone(), Some(c1.g.clone())).is_err(),
            "next == current would make observed() promote something that is \
             already promoted"
        );
        assert!(
            Generations::restore(Some(c0.g.clone()), c1.g.clone(), Some(c0.g.clone())).is_err(),
            "the peer cannot rotate back to the certificate it just left"
        );
        assert!(
            Generations::restore(Some(c0.g.clone()), c1.g.clone(), None).is_ok(),
            "the legal shape must still pass"
        );
    }
}
