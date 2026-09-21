// SPDX-License-Identifier: MIT OR Apache-2.0
//! Pinning: the format, and that a wrong value does not build a config that accepts everything.
//!
//! That the pinning actually **rejects the wrong server in a real handshake** is covered in
//! `smoke_tls.rs`. What is tested here is only that the config builds.

use nettls::{
    pinned_client_config, pinned_client_config_with_alpn, CertSource, SelfSignedParams, TlsMaterial,
};

fn en_fingerprint() -> String {
    TlsMaterial::load(&CertSource::self_signed(SelfSignedParams::default()))
        .unwrap()
        .fingerprint_sha256()
}

#[test]
fn accepts_canonical_form() {
    let fp = en_fingerprint();
    pinned_client_config(&fp).unwrap();
}

#[test]
fn accepts_openssl_format_with_colons_and_uppercase() {
    let fp = en_fingerprint();
    let openssl_stil: Vec<String> = fp
        .as_bytes()
        .chunks(2)
        .map(|c| String::from_utf8_lossy(c).to_uppercase())
        .collect();
    pinned_client_config(&openssl_stil.join(":")).unwrap();
    pinned_client_config(&format!("sha256:{}", openssl_stil.join(":"))).unwrap();
    pinned_client_config(&format!("  {fp}  ")).unwrap();
}

#[test]
fn rejects_everything_not_32_bytes() {
    for daarlig in [
        "",
        "abc",
        "not-hex-at-all",
        &"a".repeat(63),
        &"a".repeat(65),
    ] {
        let e = pinned_client_config(daarlig).unwrap_err();
        let s = e.to_string();
        assert!(s.contains("fingerprint"), "for {daarlig:?}: {s}");
        assert!(!s.is_empty());
    }
}

#[test]
fn rejects_invalid_hex_characters() {
    // Right length, wrong alphabet — this must NOT get through as "something".
    let e = pinned_client_config(&"z".repeat(64)).unwrap_err();
    assert!(e.to_string().contains("not hexadecimal"), "{e}");
}

#[test]
fn alpn_settes_gjennom() {
    let fp = en_fingerprint();
    let cfg = pinned_client_config_with_alpn(&fp, &[b"h2".to_vec(), b"http/1.1".to_vec()]).unwrap();
    assert_eq!(
        cfg.alpn_protocols,
        vec![b"h2".to_vec(), b"http/1.1".to_vec()]
    );

    let cfg = pinned_client_config(&fp).unwrap();
    assert!(
        cfg.alpn_protocols.is_empty(),
        "without ALPN the list must be empty"
    );
}
