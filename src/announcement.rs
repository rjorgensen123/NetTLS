// SPDX-License-Identifier: MIT OR Apache-2.0
//! The announcement — "here is my next certificate" (SPEC-nettls §6.5).
//!
//! This is the message that makes the rotation **asynchronous**. The receiver
//! learns the counterpart's next identity *before* it is taken into use, and
//! thus never needs to know **when** the switch happens — it accepts both from
//! the moment the announcement is stored.
//!
//! ## Two signatures, and why
//!
//! The announcement is signed with the **previous** and the **current** key.
//! Forging it therefore requires *two consecutive* private keys. If an attacker
//! steals only the current one, he lacks the previous — and he cannot wait his
//! way to it either, for at the next generation he does own the "previous",
//! but lacks the new current one.
//!
//! By comparison, the model this replaced signed each proof with **only** the
//! outgoing key.
//! One stolen key was enough to sign one's way forward indefinitely, and it
//! looked like legitimate rotation.
//!
//! ## The exception: the very first rotation
//!
//! At rotation 1 only `cert0` exists. The anchor is the operator's approval
//! (generation 0), but it is signed with **portal's** Ed25519 key, which the
//! announcer does not have. The first announcement is therefore **single-signed** (§6.3).
//!
//! This is not a tolerance, but a rule with a precise condition: a single
//! signature is accepted **only** when the receiver itself does not yet have a
//! previous certificate. The condition is tied to the **receiver's state**, not
//! to a flag in the message — otherwise an attacker could have asked to be let
//! through by omitting `prev`.

use serde::{Deserialize, Serialize};

use crate::canonical;
use crate::error::TlsError;
use crate::signature::{from_hex, verify_p256};
use krypto::sha256;

/// The fingerprint of a PEM certificate: SHA-256 over DER, hex without prefix.
pub fn fingerprint_from_pem(pem: &str) -> Result<String, TlsError> {
    Ok(krypto::hex::encode(&sha256(&der_from_pem(pem)?)))
}

/// PEM → DER. Fail-closed on anything that is not exactly one CERTIFICATE block.
pub fn der_from_pem(pem: &str) -> Result<Vec<u8>, TlsError> {
    use rustls_pki_types::pem::PemObject;
    let mut found: Option<Vec<u8>> = None;
    for cert in rustls_pki_types::CertificateDer::pem_slice_iter(pem.as_bytes()) {
        let cert = cert.map_err(|e| TlsError::Pem(format!("invalid PEM: {e}")))?;
        if found.is_some() {
            return Err(TlsError::Pem(
                "the PEM contains multiple certificates — an announcement carries exactly one"
                    .into(),
            ));
        }
        found = Some(cert.as_ref().to_vec());
    }
    found.ok_or_else(|| TlsError::Pem("found no CERTIFICATE block in the PEM".into()))
}

/// Serialized form (§6.5). The field names are part of the contract.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnnouncementJson {
    /// Always `"nettls-rotate/v2"`.
    pub v: String,
    /// The service name of the announcer.
    pub announcer: String,
    /// The previous generation's fingerprint. `None` only at the first rotation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prev_fingerprint: Option<String>,
    /// The current generation's fingerprint.
    pub curr_fingerprint: String,
    /// The fingerprint of the new certificate.
    pub new_fingerprint: String,
    /// The new certificate, in its entirety.
    pub new_cert_pem: String,
    /// The sender's own clock, unix seconds UTC (§6.7b).
    pub sent_at: i64,
    /// Signature with the previous key, hex. `None` only at the first rotation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sig_prev: Option<String>,
    /// Signature with the current key, hex.
    pub sig_curr: String,
}

/// An announcement, fully verified or under construction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Announcement {
    announcer: String,
    prev_fp: Option<String>,
    curr_fp: String,
    new_fp: String,
    new_cert_pem: String,
    sent_at: i64,
    sig_prev: Option<Vec<u8>>,
    sig_curr: Vec<u8>,
}

impl Announcement {
    /// Builds and signs an announcement.
    ///
    /// `prev` is `None` at the very first rotation. If it is `Some`, both
    /// signatures **must** be made — it is not optional, and an announcement that
    /// could have been double-signed but is not, is a weakened announcement.
    pub fn new(
        announcer: &str,
        prev: Option<(&str, &krypto::SecretBuf)>,
        curr: (&str, &krypto::SecretBuf),
        new_cert_pem: &str,
        sent_at: i64,
    ) -> Result<Self, TlsError> {
        let new_fp = fingerprint_from_pem(new_cert_pem)?;
        let (curr_fp, curr_pkcs8) = curr;
        let prev_fp = prev.map(|(fp, _)| fp.to_string());

        let message =
            canonical::rotate_v2(announcer, prev_fp.as_deref(), curr_fp, &new_fp, sent_at)?;

        let sig_curr = crate::signature::sign_p256(curr_pkcs8, &message)?;
        let sig_prev = match prev {
            Some((_, pkcs8)) => Some(crate::signature::sign_p256(pkcs8, &message)?),
            None => None,
        };

        Ok(Self {
            announcer: announcer.to_string(),
            prev_fp,
            curr_fp: curr_fp.to_string(),
            new_fp,
            new_cert_pem: new_cert_pem.to_string(),
            sent_at,
            sig_prev,
            sig_curr,
        })
    }

    /// The canonical string this announcement signs.
    pub fn canonical(&self) -> Result<Vec<u8>, TlsError> {
        canonical::rotate_v2(
            &self.announcer,
            self.prev_fp.as_deref(),
            &self.curr_fp,
            &self.new_fp,
            self.sent_at,
        )
    }

    /// Verify the announcement against the receiver's **own** state.
    ///
    /// `prev_cert_der` is the receiver's previous generation, `curr_cert_der` the
    /// current one. That the condition for a single signature is tied to the
    /// *receiver's* state and not to a field in the message is the whole point:
    /// otherwise an attacker could have asked to be let through by omitting `prev`.
    ///
    /// The order is not accidental either. **The fingerprint is checked first**:
    /// if `new_cert_pem` was swapped in transit, that must be discovered before
    /// we use that key for anything at all.
    pub fn verify(
        &self,
        prev_cert_der: Option<&[u8]>,
        curr_cert_der: &[u8],
    ) -> Result<(), TlsError> {
        // 1. The certificate MUST hash to the stated fingerprint (§6.5).
        let actual = fingerprint_from_pem(&self.new_cert_pem)?;
        if actual != self.new_fp {
            return Err(TlsError::ProofInvalid(format!(
                "new_cert_pem hashes to {actual}, but the announcement says {} — \
                 the certificate was swapped in transit",
                self.new_fp
            )));
        }

        // 2. The announcement must apply to the identity we actually have.
        let actual_curr = krypto::hex::encode(&sha256(curr_cert_der));
        if actual_curr != self.curr_fp {
            return Err(TlsError::Chain(format!(
                "the announcement is issued by {}, but we know {actual_curr} as current — \
                 we have missed a rotation, or this is a different instance",
                self.curr_fp
            )));
        }

        let message = self.canonical()?;

        // 3. The current signature is ALWAYS required.
        verify_p256(curr_cert_der, &message, &self.sig_curr)?;

        // 4. The previous signature: required as soon as the receiver HAS a previous.
        match (prev_cert_der, &self.prev_fp, &self.sig_prev) {
            (Some(der), Some(fp), Some(sig)) => {
                let actual_prev = krypto::hex::encode(&sha256(der));
                if &actual_prev != fp {
                    return Err(TlsError::Chain(format!(
                        "the announcement states {fp} as previous, we have {actual_prev}"
                    )));
                }
                verify_p256(der, &message, sig)
            }
            // The receiver HAS a previous, but the announcement is single-signed.
            // This is the attempt to ask one's way through with fewer signatures.
            (Some(_), _, _) => Err(TlsError::ProofInvalid(
                "the announcement is single-signed, but we already have a previous certificate — \
                 two signatures are required from rotation 2 onwards (§6.3)"
                    .into(),
            )),
            // The receiver has NO previous: this is rotation 1 from OUR
            // perspective, and a single signature is the natural form.
            (None, None, None) => Ok(()),
            // The receiver holds only an anchor, but the announcement is
            // double-signed: the announcer is mid-life and does not know we
            // (re)anchored. A8 (decided 2026-08-14): the generation numbering
            // is LOCAL to the receiver — the chain belongs to the relation,
            // not the announcer. The operator's approval carries generation 0
            // exactly like a prev-signature carries generation n, so we
            // verify what we CAN verify — `sig_curr` against the anchor
            // (already done in step 3 above) — and the stated `prev`, which
            // we cannot check, is not grounds for rejection. Security equals
            // bootstrap: the operator just vouched for `curr`, an attacker
            // cannot induce the anchor-only state, and a replayed old
            // announcement fails the curr-vs-anchor check in step 2. This
            // also covers the late joiner: a fresh consumer meeting a
            // long-running announcer.
            (None, Some(_), Some(_)) => Ok(()),
            (None, _, _) => Err(TlsError::ProofInvalid(
                "prev_fingerprint and sig_prev must either both be present or both be absent"
                    .into(),
            )),
        }
    }

    /// To serialized form.
    pub fn to_json(&self) -> AnnouncementJson {
        AnnouncementJson {
            v: canonical::ROTATE_V2.to_string(),
            announcer: self.announcer.clone(),
            prev_fingerprint: self.prev_fp.clone(),
            curr_fingerprint: self.curr_fp.clone(),
            new_fingerprint: self.new_fp.clone(),
            new_cert_pem: self.new_cert_pem.clone(),
            sent_at: self.sent_at,
            sig_prev: self.sig_prev.as_deref().map(krypto::hex::encode),
            sig_curr: krypto::hex::encode(&self.sig_curr),
        }
    }

    /// From serialized form. **Fail-closed** on anything that does not add up.
    pub fn from_json(j: &AnnouncementJson) -> Result<Self, TlsError> {
        if j.v != canonical::ROTATE_V2 {
            return Err(TlsError::Proof(format!(
                "unknown message version \"{}\", expected \"{}\"",
                j.v,
                canonical::ROTATE_V2
            )));
        }
        // The fields are validated here, not at use: a value that cannot be part
        // of a canonical string must never get further than this.
        canonical::require_component_name(&j.announcer, "announcer")?;
        // DoS surface (D-item, 2026-08-11 review): the PEM comes straight off
        // the network. A P-256 leaf is ~1 KiB; 16 KiB is generous headroom,
        // and anything beyond it is not a certificate.
        if j.new_cert_pem.len() > MAX_CERT_PEM_LEN {
            return Err(TlsError::Params(format!(
                "new_cert_pem is {} bytes — above the cap of {MAX_CERT_PEM_LEN};                  that is not a certificate",
                j.new_cert_pem.len()
            )));
        }
        canonical::require_fingerprint(&j.curr_fingerprint, "curr_fingerprint")?;
        canonical::require_fingerprint(&j.new_fingerprint, "new_fingerprint")?;
        if let Some(p) = &j.prev_fingerprint {
            canonical::require_fingerprint(p, "prev_fingerprint")?;
        }
        // `prev_fingerprint` and `sig_prev` belong together: one without the other
        // is half an announcement, and we do not guess at what was meant.
        if j.prev_fingerprint.is_some() != j.sig_prev.is_some() {
            return Err(TlsError::Proof(
                "prev_fingerprint and sig_prev must either both be present or both be absent"
                    .into(),
            ));
        }
        Ok(Self {
            announcer: j.announcer.clone(),
            prev_fp: j.prev_fingerprint.clone(),
            curr_fp: j.curr_fingerprint.clone(),
            new_fp: j.new_fingerprint.clone(),
            new_cert_pem: j.new_cert_pem.clone(),
            sent_at: j.sent_at,
            sig_prev: j.sig_prev.as_deref().map(from_hex).transpose()?,
            sig_curr: from_hex(&j.sig_curr)?,
        })
    }

    /// The service name of the one who announced.
    pub fn announcer(&self) -> &str {
        &self.announcer
    }
    /// The fingerprint of the new certificate.
    pub fn new_fingerprint(&self) -> &str {
        &self.new_fp
    }
    /// The new certificate, in its entirety.
    pub fn new_cert_pem(&self) -> &str {
        &self.new_cert_pem
    }
    /// The sender's clock when the message was created.
    pub fn sent_at(&self) -> i64 {
        self.sent_at
    }
    /// Is this a first rotation (single-signed)?
    pub fn is_bootstrap(&self) -> bool {
        self.prev_fp.is_none()
    }
}

#[cfg(test)]
mod tester {
    use super::*;
    use crate::material::TlsMaterial;
    use crate::{CertSource, SelfSignedParams};

    struct Gen {
        pem: String,
        der: Vec<u8>,
        pkcs8: krypto::SecretBuf,
        fp: String,
    }

    fn generation(name: &str) -> Gen {
        let m = TlsMaterial::load(&CertSource::self_signed(SelfSignedParams::new(
            name,
            [name],
        )))
        .expect("self-signed");
        let der = m.cert_chain()[0].as_ref().to_vec();
        let pkcs8 = crate::pkcs8::pkcs8_p256(m.key_der(), &der).expect("pkcs8");
        let pem = String::from_utf8(crate::pem::encode("CERTIFICATE", &der)).unwrap();
        let fp = krypto::hex::encode(&sha256(&der));
        Gen {
            pem,
            der,
            pkcs8,
            fp,
        }
    }

    // --- bootstrap: rotation 1 ------------------------------------------------ //

    #[test]
    fn bootstrap_is_single_signed_and_accepted_without_previous() {
        let c0 = generation("c0");
        let c1 = generation("c1");
        let k = Announcement::new("gateway", None, (&c0.fp, &c0.pkcs8), &c1.pem, 100).unwrap();

        assert!(k.is_bootstrap());
        k.verify(None, &c0.der)
            .expect("rotation 1 must be accepted");
    }

    #[test]
    fn single_signature_rejected_when_receiver_has_a_previous() {
        // The emphasis is on HAS: it is the receiver's own state that decides,
        // not a field in the message. This is the attack the rule exists for —
        // asking one's way through with fewer signatures by omitting `prev`.
        let c0 = generation("c0");
        let c1 = generation("c1");
        let c2 = generation("c2");
        let k = Announcement::new("gateway", None, (&c1.fp, &c1.pkcs8), &c2.pem, 100).unwrap();

        let err = k.verify(Some(&c0.der), &c1.der).unwrap_err();
        assert!(
            format!("{err}").contains("single-signed"),
            "unexpected error: {err}"
        );
    }

    // --- steady state: two signatures ------------------------------------------ //

    #[test]
    fn double_signed_announcement_accepted() {
        let c0 = generation("c0");
        let c1 = generation("c1");
        let c2 = generation("c2");
        let k = Announcement::new(
            "gateway",
            Some((&c0.fp, &c0.pkcs8)),
            (&c1.fp, &c1.pkcs8),
            &c2.pem,
            100,
        )
        .unwrap();
        k.verify(Some(&c0.der), &c1.der).expect("must hold");
    }

    #[test]
    fn wrong_previous_signature_rejected() {
        let c0 = generation("c0");
        let foreign = generation("foreign");
        let c1 = generation("c1");
        let c2 = generation("c2");
        // Signed with a FOREIGN key as "previous", but states c0's fingerprint.
        let k = Announcement::new(
            "gateway",
            Some((&c0.fp, &foreign.pkcs8)),
            (&c1.fp, &c1.pkcs8),
            &c2.pem,
            100,
        )
        .unwrap();
        assert!(k.verify(Some(&c0.der), &c1.der).is_err());
    }

    #[test]
    fn wrong_current_signature_rejected() {
        let c0 = generation("c0");
        let foreign = generation("foreign");
        let c1 = generation("c1");
        let c2 = generation("c2");
        let k = Announcement::new(
            "gateway",
            Some((&c0.fp, &c0.pkcs8)),
            (&c1.fp, &foreign.pkcs8),
            &c2.pem,
            100,
        )
        .unwrap();
        assert!(k.verify(Some(&c0.der), &c1.der).is_err());
    }

    // --- the fingerprint is checked FIRST ------------------------------------- //

    #[test]
    fn swapped_certificate_rejected_even_with_valid_signatures() {
        let c0 = generation("c0");
        let c1 = generation("c1");
        let c2 = generation("c2");
        let evil = generation("evil");

        let k = Announcement::new(
            "gateway",
            Some((&c0.fp, &c0.pkcs8)),
            (&c1.fp, &c1.pkcs8),
            &c2.pem,
            100,
        )
        .unwrap();

        // Swap out the PEM but keep everything else — the signatures cover the
        // fingerprint, not the certificate, so they are still valid.
        let mut j = k.to_json();
        j.new_cert_pem = evil.pem.clone();
        let tampered = Announcement::from_json(&j).unwrap();

        let err = tampered.verify(Some(&c0.der), &c1.der).unwrap_err();
        assert!(
            format!("{err}").contains("swapped in transit"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn announcement_from_another_generation_rejected() {
        let c0 = generation("c0");
        let c1 = generation("c1");
        let c2 = generation("c2");
        let c3 = generation("c3");
        // Announced by c2, but the receiver is on c1.
        let k = Announcement::new(
            "gateway",
            Some((&c1.fp, &c1.pkcs8)),
            (&c2.fp, &c2.pkcs8),
            &c3.pem,
            100,
        )
        .unwrap();
        let err = k.verify(Some(&c0.der), &c1.der).unwrap_err();
        assert!(
            format!("{err}").contains("missed a rotation"),
            "unexpected error: {err}"
        );
    }

    // --- serialization ---------------------------------------------------------- //

    #[test]
    fn json_round_trip_preserves_everything() {
        let c0 = generation("c0");
        let c1 = generation("c1");
        let c2 = generation("c2");
        let k = Announcement::new(
            "gateway",
            Some((&c0.fp, &c0.pkcs8)),
            (&c1.fp, &c1.pkcs8),
            &c2.pem,
            1_700_000_000,
        )
        .unwrap();

        let text = serde_json::to_string(&k.to_json()).unwrap();
        let inn: AnnouncementJson = serde_json::from_str(&text).unwrap();
        assert_eq!(Announcement::from_json(&inn).unwrap(), k);
    }

    #[test]
    fn bootstrap_omits_prev_fields_in_json() {
        let c0 = generation("c0");
        let c1 = generation("c1");
        let k = Announcement::new("gateway", None, (&c0.fp, &c0.pkcs8), &c1.pem, 100).unwrap();
        let text = serde_json::to_string(&k.to_json()).unwrap();
        assert!(!text.contains("prev_fingerprint"), "{text}");
        assert!(!text.contains("sig_prev"), "{text}");
    }

    #[test]
    fn half_announcement_rejected() {
        // `prev_fingerprint` without `sig_prev` — we do not guess at what was meant.
        let c0 = generation("c0");
        let c1 = generation("c1");
        let c2 = generation("c2");
        let k = Announcement::new(
            "gateway",
            Some((&c0.fp, &c0.pkcs8)),
            (&c1.fp, &c1.pkcs8),
            &c2.pem,
            100,
        )
        .unwrap();
        let mut j = k.to_json();
        j.sig_prev = None;
        assert!(Announcement::from_json(&j).is_err());
    }

    #[test]
    fn unknown_version_rejected() {
        let c0 = generation("c0");
        let c1 = generation("c1");
        let k = Announcement::new("gateway", None, (&c0.fp, &c0.pkcs8), &c1.pem, 100).unwrap();
        let mut j = k.to_json();
        j.v = "nettls-rotate/v3".into();
        assert!(Announcement::from_json(&j).is_err());
    }

    #[test]
    fn pem_with_multiple_certificates_rejected() {
        let a = generation("a");
        let b = generation("b");
        let begge = format!("{}{}", a.pem, b.pem);
        assert!(fingerprint_from_pem(&begge).is_err());
        assert!(fingerprint_from_pem("not pem at all").is_err());
    }
}

// --------------------------------------------------------------------------- //
// The receipt (§6.6)
// --------------------------------------------------------------------------- //

/// Serialized receipt (§6.6).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiptJson {
    /// Always `"nettls-rotate-ack/v2"`.
    pub v: String,
    /// The one who acks.
    pub acker: String,
    /// The one who announced.
    pub announcer: String,
    /// The fingerprint being acked.
    pub new_fingerprint: String,
    /// The acker's own clock (§6.7b).
    pub sent_at: i64,
    /// Ed25519 signature, hex.
    pub sig: String,
}

/// "I have stored your next certificate."
///
/// Without it we do not roll (§6.8a): if A rolls before B has stored the new
/// one, B's handshake fails that very moment — exactly the breakage §6 exists to
/// avoid. The receipt is not a courtesy; it is the condition that makes the
/// asynchronous rotation safe.
///
/// **One** signature, with Ed25519 (§6.6b). Two signatures protect *continuity*,
/// and a receipt moves no identity — it confirms receipt. Its requirement is
/// authenticity, and one signature from a pinned key covers that fully.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Receipt {
    acker: String,
    announcer: String,
    new_fp: String,
    sent_at: i64,
    sig: Vec<u8>,
}

impl Receipt {
    /// Create and sign a receipt with the acker's Ed25519 seed.
    pub fn new(
        acker: &str,
        announcer: &str,
        new_fp: &str,
        sent_at: i64,
        ed25519_seed: &krypto::SecretBuf,
    ) -> Result<Self, TlsError> {
        let message = canonical::rotate_ack_v2(acker, announcer, new_fp, sent_at)?;
        let sig = krypto::sign::ed25519_sign(ed25519_seed, &message)
            .map_err(|e| TlsError::Sign(format!("Ed25519 signing failed: {e}")))?
            .to_vec();
        Ok(Self {
            acker: acker.to_string(),
            announcer: announcer.to_string(),
            new_fp: new_fp.to_string(),
            sent_at,
            sig,
        })
    }

    /// The canonical string this receipt signs.
    pub fn canonical(&self) -> Result<Vec<u8>, TlsError> {
        canonical::rotate_ack_v2(&self.acker, &self.announcer, &self.new_fp, self.sent_at)
    }

    /// Verify against the acker's **pinned** Ed25519 key, and against the
    /// fingerprint we actually announced.
    ///
    /// Both are required. A receipt that is genuine but applies to a *different*
    /// rotation is a replay — and it must not make us roll.
    pub fn verify(&self, pinned_pubkey: &[u8], forventet_new_fp: &str) -> Result<(), TlsError> {
        if self.new_fp != forventet_new_fp {
            return Err(TlsError::ProofInvalid(format!(
                "the receipt covers {}, but we announced {forventet_new_fp} — \
                 this is a receipt for a different rotation",
                self.new_fp
            )));
        }
        let message = self.canonical()?;
        krypto::sign::ed25519_verify(pinned_pubkey, &message, &self.sig)
            .map_err(|_| TlsError::ProofInvalid("the Ed25519 signature does not hold".into()))
    }

    /// To serialized form.
    pub fn to_json(&self) -> ReceiptJson {
        ReceiptJson {
            v: canonical::ROTATE_ACK_V2.to_string(),
            acker: self.acker.clone(),
            announcer: self.announcer.clone(),
            new_fingerprint: self.new_fp.clone(),
            sent_at: self.sent_at,
            sig: krypto::hex::encode(&self.sig),
        }
    }

    /// From serialized form. Fail-closed.
    pub fn from_json(j: &ReceiptJson) -> Result<Self, TlsError> {
        if j.v != canonical::ROTATE_ACK_V2 {
            return Err(TlsError::Proof(format!(
                "unknown message version \"{}\", expected \"{}\"",
                j.v,
                canonical::ROTATE_ACK_V2
            )));
        }
        canonical::require_component_name(&j.acker, "acker")?;
        canonical::require_component_name(&j.announcer, "announcer")?;
        canonical::require_fingerprint(&j.new_fingerprint, "new_fingerprint")?;
        Ok(Self {
            acker: j.acker.clone(),
            announcer: j.announcer.clone(),
            new_fp: j.new_fingerprint.clone(),
            sent_at: j.sent_at,
            sig: from_hex(&j.sig)?,
        })
    }

    /// Who acked.
    pub fn acker(&self) -> &str {
        &self.acker
    }
    /// The fingerprint that was acked.
    pub fn new_fingerprint(&self) -> &str {
        &self.new_fp
    }
    /// The acker's clock.
    pub fn sent_at(&self) -> i64 {
        self.sent_at
    }
}

#[cfg(test)]
mod receipt_tests {
    use super::*;
    use krypto::SecretBuf;

    const FP: &str = "aa00112233445566778899aabbccddeeff00112233445566778899aabbccddee";
    const ANNET_FP: &str = "bb00112233445566778899aabbccddeeff00112233445566778899aabbccddee";

    fn seed() -> SecretBuf {
        SecretBuf::from_vec(vec![3u8; 32]).unwrap()
    }

    fn public(s: &SecretBuf) -> Vec<u8> {
        krypto::sign::ed25519_public(s).unwrap().to_vec()
    }

    #[test]
    fn receipt_verifies_against_pinned_key() {
        let pk = public(&seed());
        let k = Receipt::new("service", "gateway", FP, 100, &seed()).unwrap();
        k.verify(&pk, FP).expect("must hold");
    }

    #[test]
    fn receipt_for_another_rotation_rejected() {
        // Replay: the receipt is genuine, but applies to something else. It
        // must not make us roll.
        let pk = public(&seed());
        let k = Receipt::new("service", "gateway", ANNET_FP, 100, &seed()).unwrap();
        let err = k.verify(&pk, FP).unwrap_err();
        assert!(
            format!("{err}").contains("a different rotation"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn receipt_from_wrong_sender_rejected() {
        let annen = public(&SecretBuf::from_vec(vec![9u8; 32]).unwrap());
        let k = Receipt::new("service", "gateway", FP, 100, &seed()).unwrap();
        assert!(k.verify(&annen, FP).is_err());
    }

    #[test]
    fn tampered_field_breaks_signature() {
        let pk = public(&seed());
        let k = Receipt::new("service", "gateway", FP, 100, &seed()).unwrap();
        let mut j = k.to_json();
        j.sent_at = 101;
        let tampered = Receipt::from_json(&j).unwrap();
        assert!(tampered.verify(&pk, FP).is_err());

        let mut j2 = k.to_json();
        j2.acker = "portal".into();
        let tuklet2 = Receipt::from_json(&j2).unwrap();
        assert!(tuklet2.verify(&pk, FP).is_err());
    }

    #[test]
    fn json_round_trip_preserves_everything() {
        let k = Receipt::new("service", "gateway", FP, 1_700_000_000, &seed()).unwrap();
        let text = serde_json::to_string(&k.to_json()).unwrap();
        let inn: ReceiptJson = serde_json::from_str(&text).unwrap();
        assert_eq!(Receipt::from_json(&inn).unwrap(), k);
    }

    #[test]
    fn unknown_version_rejected() {
        let k = Receipt::new("service", "gateway", FP, 100, &seed()).unwrap();
        let mut j = k.to_json();
        j.v = "nettls-rotate-ack/v1".into();
        assert!(Receipt::from_json(&j).is_err());
    }
}

// --------------------------------------------------------------------------- //
// The archive (§6.9) — audit trail, not a recovery mechanism
// --------------------------------------------------------------------------- //

/// The file the announcements are archived in, next to the certificate.
/// Upper bound for an incoming certificate PEM (D-item, 2026-08-11 review).
pub const MAX_CERT_PEM_LEN: usize = 16 * 1024;

/// The append-only archive of sent announcements, next to the material.
pub const ARCHIVE_FILE: &str = "announcements.jsonl";

/// Put an announcement in the archive, **append-only**.
///
/// # Why the archive exists now
///
/// In the model this replaced, the archive was a **recovery mechanism**: a client that had been
/// down read its way forward through the proofs. With §6 that job is gone —
/// the counterpart knows the next certificate before it is taken into use, so
/// there is nothing to catch up on.
///
/// What the archive does now is something else, and narrower: **an operator who
/// must decide whether a deviation is a bug or an attack must be able to see
/// what was actually announced and when.** Without that she is left with a
/// fingerprint she does not recognize and no history to hold it up against.
///
/// Append-only on purpose: a log that can be edited is not an audit trail.
/// We do not enforce it in the filesystem — that belongs in operations — but the
/// code here never writes anywhere but at the end.
pub fn archive(dir: &std::path::Path, k: &Announcement) -> Result<(), TlsError> {
    use std::io::Write;
    let line = serde_json::to_string(&k.to_json())
        .map_err(|e| TlsError::Proof(format!("could not serialize the announcement: {e}")))?;
    let path = dir.join(ARCHIVE_FILE);
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .map_err(|e| TlsError::io(&path, e))?;
    writeln!(f, "{line}").map_err(|e| TlsError::io(&path, e))?;
    Ok(())
}

/// Read the archive, oldest first.
///
/// **Skips lines that cannot be parsed**, and reports how many. An archive is an
/// audit trail: one broken line must not make the rest unreadable precisely when
/// someone needs to read it.
pub fn read_archive(dir: &std::path::Path) -> Result<(Vec<Announcement>, usize), TlsError> {
    let path = dir.join(ARCHIVE_FILE);
    let text = match std::fs::read_to_string(&path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok((Vec::new(), 0)),
        Err(e) => return Err(TlsError::io(&path, e)),
    };
    let mut out = Vec::new();
    let mut hoppet = 0usize;
    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        match serde_json::from_str::<AnnouncementJson>(line)
            .ok()
            .and_then(|j| Announcement::from_json(&j).ok())
        {
            Some(k) => out.push(k),
            None => hoppet += 1,
        }
    }
    Ok((out, hoppet))
}

#[cfg(test)]
mod arkiv_tester {
    use super::*;
    use crate::material::TlsMaterial;
    use crate::{CertSource, SelfSignedParams};

    fn announcement(n: &str) -> Announcement {
        let m = TlsMaterial::load(&CertSource::self_signed(SelfSignedParams::new(n, [n]))).unwrap();
        let der = m.cert_chain()[0].as_ref().to_vec();
        let pkcs8 = crate::pkcs8::pkcs8_p256(m.key_der(), &der).unwrap();
        let fp = krypto::hex::encode(&sha256(&der));
        let m2 = TlsMaterial::load(&CertSource::self_signed(SelfSignedParams::new(
            "fresh",
            ["fresh"],
        )))
        .unwrap();
        let pem = String::from_utf8(crate::pem::encode(
            "CERTIFICATE",
            m2.cert_chain()[0].as_ref(),
        ))
        .unwrap();
        Announcement::new("gateway", None, (&fp, &pkcs8), &pem, 1).unwrap()
    }

    fn tmpdir(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("nettls-arkiv-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn empty_archive_is_not_an_error() {
        let d = tmpdir("tom");
        let (v, hoppet) = read_archive(&d).unwrap();
        assert!(v.is_empty());
        assert_eq!(hoppet, 0);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn archive_preserves_order() {
        let d = tmpdir("rekke");
        let a = announcement("a");
        let b = announcement("b");
        archive(&d, &a).unwrap();
        archive(&d, &b).unwrap();
        let (v, _) = read_archive(&d).unwrap();
        assert_eq!(v.len(), 2);
        assert_eq!(v[0], a);
        assert_eq!(v[1], b);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn archiving_appends_and_does_not_overwrite() {
        let d = tmpdir("append");
        archive(&d, &announcement("a")).unwrap();
        archive(&d, &announcement("b")).unwrap();
        archive(&d, &announcement("c")).unwrap();
        assert_eq!(read_archive(&d).unwrap().0.len(), 3);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn one_corrupt_line_does_not_make_the_rest_unreadable() {
        // An audit trail must be readable WHEN someone needs it, and then "one
        // line is corrupt, hence everything is lost" is the worst conceivable answer.
        let d = tmpdir("korrupt");
        archive(&d, &announcement("a")).unwrap();
        {
            use std::io::Write;
            let mut f = std::fs::OpenOptions::new()
                .append(true)
                .open(d.join(ARCHIVE_FILE))
                .unwrap();
            writeln!(f, "{{ this is not valid json").unwrap();
        }
        archive(&d, &announcement("b")).unwrap();

        let (v, hoppet) = read_archive(&d).unwrap();
        assert_eq!(v.len(), 2, "the valid lines must be read");
        assert_eq!(hoppet, 1, "and the broken one must be counted");
        let _ = std::fs::remove_dir_all(&d);
    }
}

// --------------------------------------------------------------------------- //
// `GET /v1/tls/identity` — the entire response shape (§6.14)
// --------------------------------------------------------------------------- //

/// The response to `GET /v1/tls/identity`.
///
/// # Why the crate owns the whole shape, not just the announcement
///
/// `nettls` owns the communication, and thereby **the contract** (§6.14). If we
/// let each service assemble the rest of the response itself — mode here,
/// `sent_at` there — we would have three places that must be kept identical, and
/// that is exactly the drift §6.14 is meant to prevent. The hex-versus-base64
/// discrepancy arose in exactly that way: two sides each filling in their part
/// of a shape nobody owned.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityJson {
    /// The fingerprint being served right now, with the `sha256:` prefix.
    pub fingerprint: String,
    /// The certificate in its entirety.
    pub cert_pem: String,
    /// Expiry (ISO 8601), when it can be read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_after: Option<String>,
    /// The mode **this** instance is configured with (§6.9b).
    ///
    /// Announced, never negotiated. The client compares against its own and
    /// reports disagreement as an active error.
    pub mode: crate::announcer::Mode,
    /// The sender's own clock (§6.7b).
    pub sent_at: i64,
    /// Pending announcement, if a rotation has been prepared.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub announcement: Option<AnnouncementJson>,
}

impl IdentityJson {
    /// Build the response.
    ///
    /// `fingerprint` and `cert_pem` must be read **from what is actually being
    /// served**, not from a cached startup value. An advertised identity that
    /// lags one step behind what the server presents makes the client pin
    /// something it will never get to see — and then every single handshake
    /// fails. (That was not hypothetical: the first draft of the rotation did
    /// exactly that.)
    pub fn new(
        fingerprint: impl Into<String>,
        cert_pem: impl Into<String>,
        not_after: Option<String>,
        mode: crate::announcer::Mode,
        sent_at: i64,
        announcement: Option<&Announcement>,
    ) -> Self {
        Self {
            fingerprint: fingerprint.into(),
            cert_pem: cert_pem.into(),
            not_after,
            mode,
            sent_at,
            announcement: announcement.map(|k| k.to_json()),
        }
    }
}

#[cfg(test)]
mod identitet_tester {
    use super::*;
    use crate::announcer::Mode;

    const FP: &str = "aa00112233445566778899aabbccddeeff00112233445566778899aabbccddee";

    #[test]
    fn without_pending_rotation_announcement_is_omitted() {
        let i = IdentityJson::new(
            format!("sha256:{FP}"),
            "-----BEGIN CERTIFICATE-----\n",
            None,
            Mode::Rolling,
            100,
            None,
        );
        let t = serde_json::to_string(&i).unwrap();
        assert!(!t.contains("announcement"), "{t}");
        assert!(!t.contains("not_after"), "{t}");
    }

    #[test]
    fn mode_and_sent_at_are_always_present() {
        // Both are part of the contract: mode because the client must compare
        // (§6.9b), sent_at because drift must be measurable (§6.7b).
        let i = IdentityJson::new(
            format!("sha256:{FP}"),
            "x",
            None,
            Mode::Pinning,
            1_700_000_000,
            None,
        );
        let t = serde_json::to_string(&i).unwrap();
        assert!(t.contains("\"mode\":\"pinning\""), "{t}");
        assert!(t.contains("\"sent_at\":1700000000"), "{t}");
    }

    #[test]
    fn round_trip_preserves_everything() {
        let i = IdentityJson::new(
            format!("sha256:{FP}"),
            "cert",
            Some("2026-09-10T12:00:00Z".into()),
            Mode::Rolling,
            5,
            None,
        );
        let t = serde_json::to_string(&i).unwrap();
        let out: IdentityJson = serde_json::from_str(&t).unwrap();
        assert_eq!(out.fingerprint, i.fingerprint);
        assert_eq!(out.mode, Mode::Rolling);
        assert_eq!(out.not_after.as_deref(), Some("2026-09-10T12:00:00Z"));
    }
}
