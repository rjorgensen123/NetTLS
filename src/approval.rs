// SPDX-License-Identifier: MIT OR Apache-2.0
//! Recognitions — **one code path** for generation 0 and generation *n* (§6.3).
//!
//! A recognition is a signed claim that an identity has been accepted. There
//! are two kinds:
//!
//! | Generation | Signed by | Canonical prefix |
//! |---|---|---|
//! | **0** | the operator, via portal's Ed25519 key | `nettls-approve/v1` |
//! | **1..n** | previous + current certificate | `nettls-rotate/v2` |
//!
//! ## Why they share a code path
//!
//! The spec is explicit: *"the verification is one code path"* (§6.3, requirement M-9).
//! It is not tidiness — it is that an anchor verified somewhere other than the
//! rest of the chain is an anchor nobody looks at when something goes wrong. Two
//! verification paths mean two places to get it wrong, and one of them is never audited.
//!
//! [`Recognition`] is therefore one type with **one** `verify`. The call site
//! does not need to know which kind it is holding.
//!
//! ## What the operator's approval actually is
//!
//! Not an act of trust the app interprets, but a **signature** — made with the
//! approving party's Ed25519 key, which its peers already pin. The actor is
//! inside the signed string (§6.4): a signature that does not cover who acted
//! does not say who acted.

use serde::{Deserialize, Serialize};

use crate::announcement::Announcement;
use crate::canonical;
use crate::error::TlsError;
use crate::signature::from_hex;

/// Serialized operator approval (§6.4).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalJson {
    /// Always `"nettls-approve/v1"`.
    pub v: String,
    /// The peer being approved.
    pub peer: String,
    /// The fingerprint being approved (64 hex, no prefix).
    pub fingerprint: String,
    /// The operator's username — **inside** the signed string.
    pub approved_by: String,
    /// Timestamp, unix seconds UTC.
    pub timestamp: i64,
    /// Who signed. Today `"portal"`; later `"op:<name>"` if the operator gets
    /// their own key. The shape does not change — only the key (§6.4).
    pub key_id: String,
    /// Ed25519 signature, hex.
    pub sig: String,
}

/// Generation 0: the operator's approval, expressed as a signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Approval {
    peer: String,
    fingerprint: String,
    approved_by: String,
    timestamp: i64,
    key_id: String,
    sig: Vec<u8>,
}

impl Approval {
    /// Create and sign an approval.
    pub fn new(
        peer: &str,
        fingerprint: &str,
        approved_by: &str,
        timestamp: i64,
        key_id: &str,
        ed25519_seed: &krypto::SecretBuf,
    ) -> Result<Self, TlsError> {
        let message = canonical::approve_v1(peer, fingerprint, approved_by, timestamp)?;
        canonical::require_name(key_id, "key_id", 64)?;
        let sig = krypto::sign::ed25519_sign(ed25519_seed, &message)
            .map_err(|e| TlsError::Sign(format!("Ed25519 signing failed: {e}")))?
            .to_vec();
        Ok(Self {
            peer: peer.to_string(),
            fingerprint: fingerprint.to_string(),
            approved_by: approved_by.to_string(),
            timestamp,
            key_id: key_id.to_string(),
            sig,
        })
    }

    /// The canonical string this approval signs.
    pub fn canonical(&self) -> Result<Vec<u8>, TlsError> {
        canonical::approve_v1(
            &self.peer,
            &self.fingerprint,
            &self.approved_by,
            self.timestamp,
        )
    }

    /// Verify against the pinned key for `key_id`.
    ///
    /// `look_up_key` is the call site's key registry. That the lookup comes
    /// from outside is the point of the `key_id` mechanism: if the operator one
    /// day moves from portal-attested to their own key, the lookup changes — not
    /// the message shape and not this function (§6.4).
    pub fn verify(&self, look_up_key: &dyn Fn(&str) -> Option<Vec<u8>>) -> Result<(), TlsError> {
        let Some(pk) = look_up_key(&self.key_id) else {
            return Err(TlsError::Chain(format!(
                "the approval is signed with \"{}\", which does not exist in the key registry — \
                 we cannot verify the anchor, and then it is not an anchor",
                self.key_id
            )));
        };
        krypto::sign::ed25519_verify(&pk, &self.canonical()?, &self.sig)
            .map_err(|_| TlsError::ProofInvalid("the Ed25519 signature does not hold".into()))
    }

    /// The fingerprint that was approved.
    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }
    /// The peer the approval applies to.
    pub fn peer(&self) -> &str {
        &self.peer
    }
    /// Who approved.
    pub fn approved_by(&self) -> &str {
        &self.approved_by
    }
    /// The key that signed.
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// To serialized form.
    pub fn to_json(&self) -> ApprovalJson {
        ApprovalJson {
            v: canonical::APPROVE_V1.to_string(),
            peer: self.peer.clone(),
            fingerprint: self.fingerprint.clone(),
            approved_by: self.approved_by.clone(),
            timestamp: self.timestamp,
            key_id: self.key_id.clone(),
            sig: krypto::hex::encode(&self.sig),
        }
    }

    /// From serialized form. Fail-closed.
    pub fn from_json(j: &ApprovalJson) -> Result<Self, TlsError> {
        if j.v != canonical::APPROVE_V1 {
            return Err(TlsError::Proof(format!(
                "unknown message version \"{}\", expected \"{}\"",
                j.v,
                canonical::APPROVE_V1
            )));
        }
        canonical::require_component_name(&j.peer, "peer")?;
        canonical::require_fingerprint(&j.fingerprint, "fingerprint")?;
        canonical::require_name(&j.approved_by, "approved_by", 64)?;
        canonical::require_name(&j.key_id, "key_id", 64)?;
        Ok(Self {
            peer: j.peer.clone(),
            fingerprint: j.fingerprint.clone(),
            approved_by: j.approved_by.clone(),
            timestamp: j.timestamp,
            key_id: j.key_id.clone(),
            sig: from_hex(&j.sig)?,
        })
    }
}

/// What it takes to verify a recognition.
///
/// Gathers the two kinds' needs in one place, so `verify` has **one** signature
/// no matter which kind it receives.
pub struct Context<'a> {
    /// Key registry for `key_id` → Ed25519 public key (generation 0).
    pub keys: &'a dyn Fn(&str) -> Option<Vec<u8>>,
    /// The receiver's previous generation, if it exists (generation 1..n).
    pub previous_der: Option<&'a [u8]>,
    /// The receiver's current generation (generation 1..n).
    pub current_der: Option<&'a [u8]>,
}

/// A signed claim that an identity has been accepted — regardless of generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Recognition {
    /// Generation 0: the operator's approval.
    Operator(Approval),
    /// Generation 1..n: an announcement.
    Schedule(Box<Announcement>),
}

impl Recognition {
    /// **One code path** (M-9). The call site does not need to know which kind it has.
    pub fn verify(&self, k: &Context<'_>) -> Result<(), TlsError> {
        match self {
            Recognition::Operator(g) => g.verify(k.keys),
            Recognition::Schedule(r) => {
                let Some(current) = k.current_der else {
                    return Err(TlsError::Chain(
                        "an announcement cannot be verified without a current generation to \
                         verify it against"
                            .into(),
                    ));
                };
                r.verify(k.previous_der, current)
            }
        }
    }

    /// The fingerprint this recognition designates.
    pub fn fingerprint(&self) -> &str {
        match self {
            Recognition::Operator(g) => g.fingerprint(),
            Recognition::Schedule(r) => r.new_fingerprint(),
        }
    }

    /// Is this the anchor (generation 0)?
    pub fn is_anchor(&self) -> bool {
        matches!(self, Recognition::Operator(_))
    }
}

#[cfg(test)]
mod tester {
    use super::*;
    use crate::material::TlsMaterial;
    use crate::{CertSource, SelfSignedParams};
    use krypto::SecretBuf;

    const FP: &str = "aa00112233445566778899aabbccddeeff00112233445566778899aabbccddee";

    fn seed() -> SecretBuf {
        SecretBuf::from_vec(vec![5u8; 32]).unwrap()
    }

    fn register() -> impl Fn(&str) -> Option<Vec<u8>> {
        move |id: &str| {
            if id == "portal" {
                krypto::sign::ed25519_public(&seed())
                    .ok()
                    .map(|p| p.to_vec())
            } else {
                None
            }
        }
    }

    #[test]
    fn approval_verifies_against_pinned_key() {
        let g = Approval::new("gateway", FP, "operator", 100, "portal", &seed()).unwrap();
        let r = register();
        g.verify(&r).expect("must hold");
    }

    #[test]
    fn unknown_key_id_says_anchor_cannot_be_verified() {
        let g = Approval::new("gateway", FP, "operator", 100, "op:operator", &seed()).unwrap();
        let r = register();
        let err = g.verify(&r).unwrap_err();
        assert!(
            format!("{err}").contains("not an anchor"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn changed_actor_breaks_signature() {
        // `approved_by` lies INSIDE the signed string (§6.4): a signature that
        // does not cover who acted does not say who acted.
        let g = Approval::new("gateway", FP, "operator", 100, "portal", &seed()).unwrap();
        let mut j = g.to_json();
        j.approved_by = "en-annen".into();
        let tampered = Approval::from_json(&j).unwrap();
        let r = register();
        assert!(tampered.verify(&r).is_err());
    }

    #[test]
    fn changed_fingerprint_breaks_signature() {
        let g = Approval::new("gateway", FP, "operator", 100, "portal", &seed()).unwrap();
        let mut j = g.to_json();
        j.fingerprint = "bb".repeat(32);
        let tampered = Approval::from_json(&j).unwrap();
        let r = register();
        assert!(tampered.verify(&r).is_err());
    }

    #[test]
    fn json_round_trip() {
        let g = Approval::new(
            "gateway",
            FP,
            "bjørn-øyvind",
            1_700_000_000,
            "portal",
            &seed(),
        )
        .unwrap();
        let t = serde_json::to_string(&g.to_json()).unwrap();
        let inn: ApprovalJson = serde_json::from_str(&t).unwrap();
        assert_eq!(Approval::from_json(&inn).unwrap(), g);
    }

    #[test]
    fn unknown_version_rejected() {
        let g = Approval::new("gateway", FP, "operator", 100, "portal", &seed()).unwrap();
        let mut j = g.to_json();
        j.v = "nettls-approve/v2".into();
        assert!(Approval::from_json(&j).is_err());
    }

    // --- the ONE code path (M-9) ---------------------------------------------- //

    #[test]
    fn both_generations_verified_by_same_call() {
        // The requirement itself: the call site does not distinguish between
        // kinds. An anchor verified somewhere other than the rest of the chain
        // is an anchor nobody looks at when something goes wrong.
        let m0 =
            TlsMaterial::load(&CertSource::self_signed(SelfSignedParams::new("a", ["a"]))).unwrap();
        let der0 = m0.cert_chain()[0].as_ref().to_vec();
        let pkcs8 = crate::pkcs8::pkcs8_p256(m0.key_der(), &der0).unwrap();
        let fp0 = krypto::hex::encode(&krypto::sha256(&der0));

        let m1 =
            TlsMaterial::load(&CertSource::self_signed(SelfSignedParams::new("b", ["b"]))).unwrap();
        let pem1 = String::from_utf8(crate::pem::encode(
            "CERTIFICATE",
            m1.cert_chain()[0].as_ref(),
        ))
        .unwrap();

        let r = register();
        let recognitions = vec![
            Recognition::Operator(
                Approval::new("gateway", &fp0, "operator", 1, "portal", &seed()).unwrap(),
            ),
            Recognition::Schedule(Box::new(
                Announcement::new("gateway", None, (&fp0, &pkcs8), &pem1, 2).unwrap(),
            )),
        ];

        // ONE loop, one call, both kinds.
        for a in &recognitions {
            a.verify(&Context {
                keys: &r,
                previous_der: None,
                current_der: Some(&der0),
            })
            .unwrap_or_else(|e| panic!("recognition failed: {e}"));
        }

        assert!(recognitions[0].is_anchor());
        assert!(!recognitions[1].is_anchor());
        assert_eq!(recognitions[0].fingerprint(), fp0);
    }

    #[test]
    fn announcement_without_current_generation_rejected() {
        let m0 =
            TlsMaterial::load(&CertSource::self_signed(SelfSignedParams::new("a", ["a"]))).unwrap();
        let der0 = m0.cert_chain()[0].as_ref().to_vec();
        let pkcs8 = crate::pkcs8::pkcs8_p256(m0.key_der(), &der0).unwrap();
        let fp0 = krypto::hex::encode(&krypto::sha256(&der0));
        let m1 =
            TlsMaterial::load(&CertSource::self_signed(SelfSignedParams::new("b", ["b"]))).unwrap();
        let pem1 = String::from_utf8(crate::pem::encode(
            "CERTIFICATE",
            m1.cert_chain()[0].as_ref(),
        ))
        .unwrap();

        let a = Recognition::Schedule(Box::new(
            Announcement::new("gateway", None, (&fp0, &pkcs8), &pem1, 2).unwrap(),
        ));
        let r = register();
        assert!(a
            .verify(&Context {
                keys: &r,
                previous_der: None,
                current_der: None,
            })
            .is_err());
    }
}
