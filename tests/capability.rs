// SPDX-License-Identifier: MIT OR Apache-2.0
//! The signed AEAD support statement + the fallback rule: the best algorithm
//! is the default, fallback is an explicit AUTHENTICATED exception, and
//! falling back to nothing does not exist.

use krypto::Alg;
use nettls::capability::{alg_from_token, choose, SupportStatement};
use nettls::{CertSource, SelfSignedParams, TlsMaterial};

fn identity(name: &str) -> TlsMaterial {
    TlsMaterial::load(&CertSource::self_signed(SelfSignedParams::new(
        name,
        [name],
    )))
    .unwrap()
}

#[test]
fn statement_roundtrip_and_wrong_signer_rejected() {
    let python_side = identity("service");
    let pkcs8 = python_side.anchor_pkcs8().unwrap();
    let s = SupportStatement::signed("service", &[Alg::Aes256Gcm], 1_760_000_000, &pkcs8).unwrap();

    // Verified against the RIGHT pinned identity → the declared set.
    let cert = python_side.cert_chain()[0].as_ref().to_vec();
    assert_eq!(s.verify(&cert).unwrap(), vec![Alg::Aes256Gcm]);

    // An attacker cannot inject a downgrade: wrong signer → rejected.
    let attacker = identity("attacker");
    let wrong = attacker.cert_chain()[0].as_ref().to_vec();
    assert!(s.verify(&wrong).is_err());

    // Nor can the declared set be edited after signing.
    let mut tampered = s.clone();
    tampered.supported = vec!["aegis256".into(), "aes256gcm".into()];
    assert!(tampered.verify(&cert).is_err());
}

#[test]
fn choose_implements_the_decided_pattern() {
    // No statement → the requested algorithm stands (AEGIS default flow).
    assert_eq!(choose(Alg::Aegis256, None).unwrap(), Alg::Aegis256);
    // Verified statement without AEGIS → best declared (the Python bridge).
    assert_eq!(
        choose(Alg::Aegis256, Some(&[Alg::Aes256Gcm])).unwrap(),
        Alg::Aes256Gcm
    );
    // Statement WITH the requested one → no downgrade happens.
    assert_eq!(
        choose(Alg::Aegis256, Some(&[Alg::Aegis256, Alg::Aes256Gcm])).unwrap(),
        Alg::Aegis256
    );
    // Nothing acceptable → hard failure, never silently weaker.
    let err = choose(Alg::Aegis256, Some(&[])).unwrap_err();
    assert!(err.to_string().contains("never silently weaken"), "{err}");
}

#[test]
fn statement_is_fail_closed_on_form() {
    let m = identity("service");
    let pkcs8 = m.anchor_pkcs8().unwrap();
    // Empty support set is not a statement.
    assert!(SupportStatement::signed("service", &[], 1, &pkcs8).is_err());
    // Unknown tokens in a received statement are rejected at verify.
    let mut s =
        SupportStatement::signed("service", &[Alg::Aes256Gcm], 1_760_000_000, &pkcs8).unwrap();
    s.supported = vec!["rot13".into()];
    let cert = m.cert_chain()[0].as_ref().to_vec();
    assert!(s.verify(&cert).is_err());
    // Tokens are the cli's — one vocabulary.
    assert!(alg_from_token("aegis256").is_ok());
    assert!(alg_from_token("AEGIS256").is_err());
}
