// SPDX-License-Identifier: MIT OR Apache-2.0
//! Self-signed generation: SANs, fingerprints and parameter validation.

use nettls::{CertOrigin, CertSource, SelfSignedParams, TlsMaterial, MAX_VALID_DAYS};

fn params() -> SelfSignedParams {
    SelfSignedParams::new(
        "example portal",
        [
            "example.internal",
            "localhost",
            "10.0.0.5",
            "127.0.0.1",
            "::1",
        ],
    )
}

#[test]
fn san_contains_both_dns_names_and_ip_addresses() {
    let m = TlsMaterial::load(&CertSource::self_signed(params())).unwrap();
    let sans = m.sans();

    // rcgen itself distinguishes DNS SAN from IP SAN by whether the string
    // parses as an IP. Without an IP SAN, `https://<ip>:8080` fails with
    // ERR_CERT_COMMON_NAME_INVALID.
    assert!(
        sans.contains(&"example.internal".to_string()),
        "SANs: {sans:?}"
    );
    assert!(sans.contains(&"localhost".to_string()), "SANs: {sans:?}");
    assert!(
        sans.contains(&"10.0.0.5".to_string()),
        "IP SAN missing: {sans:?}"
    );
    assert!(
        sans.contains(&"127.0.0.1".to_string()),
        "IP SAN missing: {sans:?}"
    );
    assert!(
        sans.contains(&"::1".to_string()),
        "IPv6 SAN missing: {sans:?}"
    );
    assert_eq!(sans.len(), 5);
}

#[test]
fn common_name_ends_up_in_subject() {
    let m = TlsMaterial::load(&CertSource::self_signed(params())).unwrap();
    assert!(
        m.subject().contains("example portal"),
        "subject: {}",
        m.subject()
    );
}

#[test]
fn fingerprint_is_64_hex_digits_and_stable_for_same_cert() {
    let m = TlsMaterial::load(&CertSource::self_signed(params())).unwrap();
    let fp = m.fingerprint_sha256();

    assert_eq!(fp.len(), 64, "fingerprint: {fp}");
    assert!(fp
        .chars()
        .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    // Same material → same value, every time.
    assert_eq!(fp, m.fingerprint_sha256());
}

#[test]
fn fingerprint_changes_when_cert_changes() {
    let a = TlsMaterial::load(&CertSource::self_signed(params())).unwrap();
    let b = TlsMaterial::load(&CertSource::self_signed(params())).unwrap();
    assert_ne!(
        a.fingerprint_sha256(),
        b.fingerprint_sha256(),
        "two generations with the same parameters must yield different keys and thus different fingerprints"
    );
}

#[test]
fn validity_window_is_as_ordered() {
    let m = TlsMaterial::load(&CertSource::self_signed(params().valid_days(30))).unwrap();
    assert!(m.is_valid_now());
    let days_left = m.days_until_expiry();
    assert!(
        (28..=30).contains(&days_left),
        "days until expiry: {days_left}"
    );
    assert!(m.not_after().unwrap() > m.not_before().unwrap());
}

#[test]
fn origin_is_generated_for_pure_self_signed() {
    let m = TlsMaterial::load(&CertSource::self_signed(params())).unwrap();
    assert_eq!(m.origin(), CertOrigin::Generated);
}

#[test]
fn rejects_empty_san_list() {
    let p = SelfSignedParams {
        common_name: "x".into(),
        sans: vec![],
        valid_days: 365,
    };
    let e = TlsMaterial::load(&CertSource::self_signed(p)).unwrap_err();
    let s = e.to_string();
    assert!(
        s.contains("SAN"),
        "the error message must explain what is missing: {s}"
    );
}

#[test]
fn rejects_lifetime_outside_bounds() {
    for days_left in [0, MAX_VALID_DAYS + 1, 3650] {
        let p = SelfSignedParams::new("x", ["localhost"]).valid_days(days_left);
        let e = TlsMaterial::load(&CertSource::self_signed(p)).unwrap_err();
        assert!(
            e.to_string().contains("valid_days"),
            "days={days_left}: {e}"
        );
    }
}

#[test]
fn debug_never_leaks_the_key() {
    let m = TlsMaterial::load(&CertSource::self_signed(params())).unwrap();
    let dbg = format!("{m:?}");
    assert!(dbg.contains("[REDACTED]"), "{dbg}");
    assert!(!dbg.to_lowercase().contains("private key"), "{dbg}");

    // Same requirement for CertSource::pem, which actually carries the key.
    let src = CertSource::pem(b"cert".to_vec(), b"secret-key-bytes".to_vec());
    let dbg = format!("{src:?}");
    assert!(dbg.contains("[REDACTED]"), "{dbg}");
    assert!(!dbg.contains("secret-key-bytes"), "{dbg}");
}

// --------------------------------------------------------------------------- #
// SAN/CN-validering (sak L2-054)
//
// The minimum requirement in SPEC-nettls also covers configuration input. The
// crate previously accepted an empty string, 300 characters, spaces and `..`
// as SANs and wrote them straight into the certificate — the result was a
// certificate that silently matched nothing, where the operator met a cryptic
// browser error instead of a clear startup failure.
// --------------------------------------------------------------------------- #

fn gen(sans: &[&str]) -> Result<TlsMaterial, nettls::TlsError> {
    let p = SelfSignedParams::new("test", sans.iter().map(|s| s.to_string()));
    TlsMaterial::load(&CertSource::self_signed(p))
}

/// IP addresses MUST work. Without an IP SAN, `https://<ip>:8443` fails with
/// `ERR_CERT_COMMON_NAME_INVALID` — a validation that only accepted DNS names
/// would have broken a supported use case.
#[test]
fn ip_addresses_accepted_both_v4_and_v6() {
    for ip in ["127.0.0.1", "10.255.0.1", "::1", "2001:db8::1"] {
        assert!(gen(&[ip]).is_ok(), "IP SAN {ip} was rejected");
    }
    // And they must actually end up in the certificate, not just pass validation.
    let m = gen(&["10.0.0.5", "portal.example.no"]).expect("should have passed");
    assert!(
        m.sans().iter().any(|s| s == "10.0.0.5"),
        "IP missing from SAN: {:?}",
        m.sans()
    );
}

#[test]
fn valid_dns_names_are_accepted() {
    for name in [
        "localhost",
        "portal",
        "portal.example.no",
        "a-b.c-d.example.no",
        "*.example.no",        // a wildcard as the first part is legitimate and in use
        "example.no.",         // absolute name — one trailing dot is legal
        "xn--kvithval-64a.no", // punycode
    ] {
        assert!(gen(&[name]).is_ok(), "valid name {name:?} was rejected");
    }
}

#[test]
fn illegal_names_are_rejected_with_explanation() {
    let tilfeller: &[(&str, &str)] = &[
        ("", "empty"),
        ("foo bar", "illegal characters (space)"),
        ("..", "dots only"),
        ("a..b", "empty part between dots"),
        (".start", "leading dot"),
        ("-start.no", "hyphen first in the part"),
        ("slutt-.no", "hyphen last in the part"),
        ("ap*.example.no", "wildcard mid-part"),
        ("example.*.no", "wildcard that is not the first part"),
        ("æøå.no", "non-ASCII"),
    ];
    for (name, what) in tilfeller {
        let err = gen(&[name]).expect_err(&format!("{what}: {name:?} should have been rejected"));
        let message = err.to_string();
        // The error message must name what is wrong — otherwise the operator
        // is left with "invalid parameter" and a service that will not start.
        assert!(
            message.contains("SAN") || message.contains("common_name"),
            "message without a field name for {name:?}: {message}"
        );
    }
}

#[test]
fn too_long_names_are_rejected() {
    // One label above 63 characters.
    let lang_label = format!("{}.no", "a".repeat(64));
    assert!(
        gen(&[lang_label.as_str()]).is_err(),
        "a 64-character label should have been rejected"
    );
    // Above 253 characters in total (each label legal on its own).
    let mange = std::iter::repeat("abcdefgh")
        .take(40)
        .collect::<Vec<_>>()
        .join(".");
    assert!(mange.len() > 253);
    assert!(
        gen(&[mange.as_str()]).is_err(),
        "a name above 253 characters should have been rejected"
    );
}

/// CN is validated **more loosely** than SAN, and on purpose.
///
/// CN is a human-readable subject field, not a host name — modern browsers
/// ignore it. The crate's own default is `"nettls self-signed"`, with a space.
/// (The first attempt at this validation applied DNS rules to CN and toppled
/// seven existing tests in one second. The rule is strict where the name must
/// *match* something, and loose where it is only to be *read*.)
#[test]
fn readable_common_name_with_spaces_is_legal() {
    for cn in [
        "nettls self-signed",
        "example portal",
        "Example NetOps (internal)",
    ] {
        let p = SelfSignedParams::new(cn, vec!["localhost".to_string()]);
        assert!(
            TlsMaterial::load(&CertSource::self_signed(p)).is_ok(),
            "legal CN {cn:?} was rejected"
        );
    }
}

#[test]
fn invalid_common_name_is_rejected() {
    let ulovlige: &[(String, &str)] = &[
        ("".to_string(), "empty"),
        ("   ".to_string(), "spaces only"),
        ("a".repeat(65), "above X.509's limit of 64 characters"),
        ("portal\u{0}hidden".to_string(), "control character"),
        ("portal\nline2".to_string(), "newline"),
    ];
    for (cn, what) in ulovlige {
        let p = SelfSignedParams::new(cn.clone(), vec!["localhost".to_string()]);
        let err = TlsMaterial::load(&CertSource::self_signed(p))
            .expect_err(&format!("CN ({what}) should have been rejected: {cn:?}"));
        assert!(err.to_string().contains("common_name"), "{err}");
    }
}
