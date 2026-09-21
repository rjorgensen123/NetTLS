// SPDX-License-Identifier: MIT OR Apache-2.0
//! Signing and verification for the §6 messages.
//!
//! Two signature types, because §6 has two kinds of senders:
//!
//! | Type | Key | Used for |
//! |---|---|---|
//! | **ECDSA P-256** | the certificate's key | the announcement (§6.5) — two signatures, from `prev` and `curr` |
//! | **Ed25519** | the service's signing key | the receipt (§6.6b), the operator approval (§6.4), the pair rotation (§8.5b) |
//!
//! The reason there are two and not one: the certificate lineage **rotates**,
//! and that rotation is exactly what the two signatures on the announcement
//! protect. The Ed25519 keys, by contrast, are stable, operator-distributed
//! identities the peer already pins — and a receipt moves no identity, so it
//! needs authenticity, not continuity.
//!
//! ## The primitives are `krypto`'s
//!
//! Since krypto 0.5 the actual cryptography lives in `krypto::sign` (Ed25519,
//! deterministic ECDSA P-256 — bit-compatible with what this crate produced
//! via `ring`) and `krypto::hex`. §8d.1 added them precisely so no consumer
//! carries its own signature layer — this crate was the consumer in question.
//! What remains here is the **TLS end** of the §6 domain: getting the P-256
//! key out of an X.509 certificate, and the §6 field rules. X.509 stays with
//! nettls by the boundary agreed with `krypto`.
//!
//! ## Serialization: **hex**, always
//!
//! Not base64. Not "whatever your library happens to give you". The choice is
//! normative (§6.5), and the reason is in the spec: Rust picked hex and Python
//! base64 last time, and the result was two legal choices and one unusable
//! protocol. The canonical form is `krypto::hex` — lowercase, fail-closed.

use crate::error::TlsError;

/// Hex → bytes for a §6 message field (a signature or a key).
///
/// The wire form is normative (§6.5): **lowercase**, even length — and a §6
/// field is never empty. The decoding itself is `krypto::hex::decode`
/// (canonical and fail-closed: uppercase, odd length or non-hex are errors,
/// never a guess). The empty-check is the one §6 rule added on top: an empty
/// signature field is a protocol error, not "zero bytes of signature".
pub fn from_hex(s: &str) -> Result<Vec<u8>, TlsError> {
    if s.is_empty() {
        return Err(TlsError::Proof("empty hex string".into()));
    }
    krypto::hex::decode(s).map_err(|e| TlsError::Proof(format!("invalid hex (§6.5): {e}")))
}

// --------------------------------------------------------------------------- //
// ECDSA P-256 — the certificate lineage
// --------------------------------------------------------------------------- //

/// Extracts the public P-256 key from a DER-encoded certificate.
///
/// Refuses everything but uncompressed P-256. A different key type is not an
/// "unexpected configuration" here — it means the certificate cannot take part
/// in §6 at all, and then it must say so at once.
pub fn p256_public_key(cert_der: &[u8]) -> Result<Vec<u8>, TlsError> {
    use x509_parser::prelude::FromDer;

    let (_rest, cert) = x509_parser::certificate::X509Certificate::from_der(cert_der)
        .map_err(|e| TlsError::Certificate(e.to_string()))?;
    let spki = cert.public_key();

    // 1.2.840.10045.2.1 = id-ecPublicKey.
    let alg = spki.algorithm.algorithm.to_id_string();
    if alg != "1.2.840.10045.2.1" {
        return Err(TlsError::ProofInvalid(format!(
            "the certificate has key type OID {alg}, not ECDSA (id-ecPublicKey) — \
             §6 signatures are defined for ECDSA P-256"
        )));
    }

    let point = spki.subject_public_key.data.as_ref();
    if point.len() != 65 || point[0] != 0x04 {
        return Err(TlsError::ProofInvalid(format!(
            "expected an uncompressed P-256 point (65 bytes, first byte 0x04), got {} bytes \
             starting with 0x{:02x}",
            point.len(),
            point.first().copied().unwrap_or(0)
        )));
    }
    Ok(point.to_vec())
}

/// Verifies an ECDSA P-256 signature against the **issuer's certificate**.
///
/// It is the certificate and not the fingerprint that must come in: a
/// fingerprint is a hash, and a public key cannot be derived from it. That is
/// the whole reason the announcement carries the certificate in full (§6.5).
pub fn verify_p256(cert_der: &[u8], message: &[u8], signature: &[u8]) -> Result<(), TlsError> {
    let key = p256_public_key(cert_der)?;
    krypto::sign::ecdsa_p256_verify(&key, message, signature).map_err(|_| {
        TlsError::ProofInvalid(
            "the ECDSA P-256 signature does not hold against the issuer's certificate".into(),
        )
    })
}

/// Signs a §6 message with a certificate's P-256 key (PKCS#8 DER form).
///
/// The signing itself is `krypto::sign::ecdsa_p256_sign` — deterministic
/// (RFC 6979) and ASN.1 DER, bit-compatible with what `ring` verified. This
/// function is the boundary where the certificate key, which must exist as
/// raw DER for rustls' sake, enters krypto's fence for the signing operation.
///
/// **0.8.3:** the key arrives as a `krypto::SecretBuf` — it has been in locked
/// memory since it was built (`TlsMaterial::anchor_pkcs8`), and is never
/// copied out of it here.
pub fn sign_p256(pkcs8: &krypto::SecretBuf, message: &[u8]) -> Result<Vec<u8>, TlsError> {
    krypto::sign::ecdsa_p256_sign(pkcs8, message)
        .map_err(|_| TlsError::Sign("the private key is not ECDSA P-256 in PKCS#8".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::material::TlsMaterial;
    use crate::{CertSource, SelfSignedParams};

    fn cert_and_pkcs8() -> (Vec<u8>, krypto::SecretBuf) {
        let m = TlsMaterial::load(&CertSource::self_signed(SelfSignedParams::new(
            "test",
            ["test"],
        )))
        .expect("self-signed");
        let der = m.cert_chain()[0].as_ref().to_vec();
        let pkcs8 = crate::pkcs8::pkcs8_p256(m.key_der(), &der).expect("pkcs8");
        (der, pkcs8)
    }

    // --- from_hex (§6.5 field rules over krypto::hex) ------------------------ //

    #[test]
    fn hex_roundtrip() {
        let b = vec![0x00, 0x0f, 0xa0, 0xff];
        assert_eq!(krypto::hex::encode(&b), "000fa0ff");
        assert_eq!(from_hex("000fa0ff").unwrap(), b);
    }

    #[test]
    fn hex_rejects_uppercase() {
        // Stricter than necessary for reading — but a protocol where `AB` and
        // `ab` both get in is a protocol where two implementations can produce
        // different bytes for the same value without anyone noticing.
        assert!(from_hex("000FA0FF").is_err());
    }

    #[test]
    fn hex_rejects_odd_empty_and_garbage() {
        assert!(from_hex("abc").is_err());
        assert!(from_hex("").is_err());
        assert!(from_hex("zz").is_err());
    }

    #[test]
    fn hex_does_not_panic_on_multibyte_utf8() {
        // Regression. An earlier in-house decoder indexed `&s[i..i + 2]` on a
        // `&str`, where `len()` counts BYTES — so the index could land in the
        // middle of a character and fell the thread with «byte index 2 is not
        // a char boundary».
        //
        // Reachable from outside: `sig_curr` and `sig` go straight from JSON
        // into here in `Announcement::from_json`, `Receipt::from_json` and
        // `Approval::from_json`. One peer, one field, one felled process.
        // krypto::hex::decode validates on bytes and cannot regress into this,
        // but the §6 entry point keeps the probe.
        for s in [
            "a\u{20AC}",
            "\u{20AC}a",
            "ab\u{20AC}\u{20AC}",
            "\u{e9}\u{e9}",
        ] {
            assert!(
                from_hex(s).is_err(),
                "{s:?} must give Err — and above all not panic"
            );
        }
    }

    // --- ECDSA P-256 -------------------------------------------------------- //

    #[test]
    fn p256_signs_and_verifies() {
        let (der, pkcs8) = cert_and_pkcs8();
        let sig = sign_p256(&pkcs8, b"hei").unwrap();
        verify_p256(&der, b"hei", &sig).expect("our own signature must hold");
    }

    #[test]
    fn p256_rejects_altered_message() {
        let (der, pkcs8) = cert_and_pkcs8();
        let sig = sign_p256(&pkcs8, b"hei").unwrap();
        assert!(verify_p256(&der, b"hej", &sig).is_err());
    }

    #[test]
    fn p256_rejects_other_key() {
        let (_der_a, pkcs8_a) = cert_and_pkcs8();
        let (der_b, _pkcs8_b) = cert_and_pkcs8();
        let sig = sign_p256(&pkcs8_a, b"hei").unwrap();
        assert!(
            verify_p256(&der_b, b"hei", &sig).is_err(),
            "a signature from one identity must not hold against another"
        );
    }

    #[test]
    fn p256_rejects_tampered_signature() {
        let (der, pkcs8) = cert_and_pkcs8();
        let mut sig = sign_p256(&pkcs8, b"hei").unwrap();
        let last = sig.len() - 1;
        sig[last] ^= 0x01;
        assert!(verify_p256(&der, b"hei", &sig).is_err());
    }

    // --- the two types must not be confusable ------------------------------- //

    #[test]
    fn an_ed25519_signature_does_not_hold_as_p256() {
        let (der, _) = cert_and_pkcs8();
        let seed = krypto::SecretBuf::from_vec(vec![7u8; 32]).unwrap();
        let sig = krypto::sign::ed25519_sign(&seed, b"hei").unwrap();
        assert!(
            verify_p256(&der, b"hei", &sig).is_err(),
            "the signature types must not be confusable"
        );
    }
}
