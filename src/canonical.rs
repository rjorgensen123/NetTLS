// SPDX-License-Identifier: MIT OR Apache-2.0
//! Canonical strings — what actually gets signed (SPEC-nettls §6).
//!
//! Four message forms, one function each. No I/O, no state, no keys: just
//! fields in and **bytes** out.
//!
//! ## Why this is its own module
//!
//! The contract between the Rust and Python implementations is not the
//! cryptographic core — it is **the entire path from object to bytes**. The
//! divergence we have already had (Rust picked hex, Python base64) sat
//! in the serialization, not in the signature. Gathering the byte
//! construction in one place means it can be tested against committed vectors
//! without anything else being built.
//!
//! ## The form, normative (§6.4, §6.5, §6.6, §8.5b)
//!
//! - **UTF-8**
//! - **LF** (`\n`) between lines — never CRLF
//! - **No trailing LF.** The last line ends where it ends.
//!
//! The last point is worth saying out loud: a trailing newline is invisible
//! in a text editor and changes the signature completely. The tests below
//! therefore compare **exact bytes**, not strings.

use crate::error::TlsError;

/// `nettls-approve/v1` — the operator approval (§6.4).
pub const APPROVE_V1: &str = "nettls-approve/v1";
/// `nettls-rotate/v2` — announcement of the next certificate (§6.5).
pub const ROTATE_V2: &str = "nettls-rotate/v2";
/// `nettls-rotate-ack/v2` — receipt confirming the announcement is stored (§6.6).
pub const ROTATE_ACK_V2: &str = "nettls-rotate-ack/v2";
/// `nettls-pairsecret/v1` — rotation of the pair secret (§8.5b).
pub const PAIRSECRET_V1: &str = "nettls-pairsecret/v1";

/// Canonical prefix for the signed AEAD support statement (additive, 0.8.2).
pub const ALGSUPPORT_V1: &str = "nettls-algsupport/v1";

/// A 64-character hex fingerprint, without a `sha256:` prefix.
///
/// Validated at construction and not at use: a value that ends up in a signed
/// string must never be able to carry a newline or an empty string into the
/// format. With a newline the field would become **two** lines, and an
/// attacker could thereby move content within the message without touching
/// the signature.
pub fn require_fingerprint(v: &str, field: &'static str) -> Result<(), TlsError> {
    if v.len() != 64 || !v.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(TlsError::Params(format!(
            "{field}: expected 64 hex characters without a «sha256:» prefix, got {} characters",
            v.len()
        )));
    }
    if v.bytes().any(|b| b.is_ascii_uppercase()) {
        return Err(TlsError::Params(format!(
            "{field}: fingerprints are written in lowercase"
        )));
    }
    Ok(())
}

/// A **component name** (`gateway`, `service`, `portal`) that goes into a signed
/// string — enforced exactly as SPEC-nettls §6.5 writes it: `[a-z0-9-]{1,32}`.
///
/// Stricter than [`require_name`], and on purpose (decided 2026-08-13): a
/// protocol where `Gateway` and `gateway` both get in is a protocol where two
/// implementations can produce different bytes for the same party. Usernames
/// (`approved_by`) are a different category and keep the looser rule.
pub fn require_component_name(v: &str, field: &'static str) -> Result<(), TlsError> {
    if v.is_empty() {
        return Err(TlsError::Params(format!("{field}: cannot be empty")));
    }
    if v.len() > 32 {
        return Err(TlsError::Params(format!(
            "{field}: too long (max 32 characters for a component name)"
        )));
    }
    if let Some(c) = v
        .chars()
        .find(|c| !matches!(c, 'a'..='z' | '0'..='9' | '-'))
    {
        return Err(TlsError::Params(format!(
            "{field}: the character {c:?} is outside [a-z0-9-] — component names are              lowercase ASCII, digits and hyphens (§6.5)"
        )));
    }
    Ok(())
}

/// A name field that goes into a signed string.
///
/// Refuses empty, too long, and anything that could break the line structure
/// — `\n`, `\r` and other control characters.
pub fn require_name(v: &str, field: &'static str, max: usize) -> Result<(), TlsError> {
    if v.is_empty() {
        return Err(TlsError::Params(format!("{field}: cannot be empty")));
    }
    if v.chars().count() > max {
        return Err(TlsError::Params(format!(
            "{field}: too long (max {max} characters)"
        )));
    }
    if let Some(c) = v.chars().find(|c| c.is_control()) {
        return Err(TlsError::Params(format!(
            "{field}: contains a control character (U+{:04X}) that would break the line structure",
            c as u32
        )));
    }
    Ok(())
}

/// Joins the lines into canonical form: LF between, **no** trailing LF.
fn assemble(lines: &[&str]) -> Vec<u8> {
    lines.join("\n").into_bytes()
}

/// The signed AEAD support statement (0.8.2) — the authenticated basis for
/// algorithm fallback. Only the party that does NOT support an algorithm can
/// authorize a downgrade, and only with its signature over this string.
///
/// ```text
/// nettls-algsupport/v1
/// <component>
/// <algs>            (comma-joined tokens in the FIXED order aegis256,xchacha20,aes256gcm)
/// <timestamp>
/// ```
///
/// The token list is validated fail-closed: unknown tokens, duplicates, an
/// empty list or a non-canonical order are rejected — two spellings of the
/// same support set must not exist.
pub fn algsupport_v1(component: &str, algs: &str, timestamp: i64) -> Result<Vec<u8>, TlsError> {
    require_component_name(component, "component")?;
    const ORDER: [&str; 3] = ["aegis256", "xchacha20", "aes256gcm"];
    if algs.is_empty() {
        return Err(TlsError::Params("algs: cannot be empty".into()));
    }
    let mut last_pos: Option<usize> = None;
    for token in algs.split(',') {
        let Some(pos) = ORDER.iter().position(|t| *t == token) else {
            return Err(TlsError::Params(format!(
                "algs: unknown token {token:?} — known: aegis256, xchacha20, aes256gcm"
            )));
        };
        if let Some(prev) = last_pos {
            if pos <= prev {
                return Err(TlsError::Params(format!(
                    "algs: token {token:?} out of canonical order (aegis256,xchacha20,aes256gcm) \
                     or duplicated — one spelling per support set"
                )));
            }
        }
        last_pos = Some(pos);
    }
    let t = timestamp.to_string();
    Ok(assemble(&[ALGSUPPORT_V1, component, algs, &t]))
}

/// **§6.4** — the operator approval, generation 0.
///
/// ```text
/// nettls-approve/v1
/// <peer>
/// <fingerprint>
/// <approved_by>
/// <timestamp>
/// ```
///
/// `approved_by` sits **inside** the string on purpose: a signature that does
/// not cover who acted does not say who acted.
pub fn approve_v1(
    peer: &str,
    fingerprint: &str,
    approved_by: &str,
    timestamp: i64,
) -> Result<Vec<u8>, TlsError> {
    require_component_name(peer, "peer")?;
    require_fingerprint(fingerprint, "fingerprint")?;
    require_name(approved_by, "approved_by", 64)?;
    let t = timestamp.to_string();
    Ok(assemble(&[APPROVE_V1, peer, fingerprint, approved_by, &t]))
}

/// **§6.5** — the announcement: "here is my next certificate".
///
/// ```text
/// nettls-rotate/v2
/// <announcer>
/// <prev_fp>
/// <curr_fp>
/// <new_fp>
/// <sent_at>
/// ```
///
/// Signed **twice**: with the `prev` key and with the `curr` key. Forging it
/// therefore requires two consecutive private keys.
///
/// `prev_fp` is `None` at the **first** rotation, where `cert0` is the only
/// key that exists (§6.3). It then serializes as `-`, so the line exists and
/// the format has a fixed line count — a field that vanished would make the
/// next line shift up and take on a different meaning.
pub fn rotate_v2(
    announcer: &str,
    prev_fp: Option<&str>,
    curr_fp: &str,
    new_fp: &str,
    sent_at: i64,
) -> Result<Vec<u8>, TlsError> {
    require_component_name(announcer, "announcer")?;
    if let Some(p) = prev_fp {
        require_fingerprint(p, "prev_fp")?;
    }
    require_fingerprint(curr_fp, "curr_fp")?;
    require_fingerprint(new_fp, "new_fp")?;
    let t = sent_at.to_string();
    Ok(assemble(&[
        ROTATE_V2,
        announcer,
        prev_fp.unwrap_or("-"),
        curr_fp,
        new_fp,
        &t,
    ]))
}

/// **§6.6** — the receipt: "I have stored your next certificate".
///
/// ```text
/// nettls-rotate-ack/v2
/// <acker>
/// <announcer>
/// <new_fp>
/// <sent_at>
/// ```
///
/// Signed **once**, with the acker's Ed25519 service key (§6.6b). Two
/// signatures protect continuity, and a receipt moves no identity — it
/// confirms storage. What it needs is authenticity.
pub fn rotate_ack_v2(
    acker: &str,
    announcer: &str,
    new_fp: &str,
    sent_at: i64,
) -> Result<Vec<u8>, TlsError> {
    require_component_name(acker, "acker")?;
    require_component_name(announcer, "announcer")?;
    require_fingerprint(new_fp, "new_fp")?;
    let t = sent_at.to_string();
    Ok(assemble(&[ROTATE_ACK_V2, acker, announcer, new_fp, &t]))
}

/// **§8.5b** — rotation of the pair secret.
///
/// ```text
/// nettls-pairsecret/v1
/// <a>
/// <b>
/// <sealed_a_sha256>
/// <sealed_b_sha256>
/// <sent_at>
/// ```
///
/// Signed by **both** parties. Neither portal nor one party alone can change
/// the secret — a 2-of-2 authorization with a blind custodian.
///
/// The party names are **not** sorted here: the order is `(a, b)` as the call
/// site gives it, and both sides must use the same. Sorting covertly would
/// let two implementations disagree without anyone seeing it.
pub fn pairsecret_v1(
    a: &str,
    b: &str,
    sealed_a_sha256: &str,
    sealed_b_sha256: &str,
    sent_at: i64,
) -> Result<Vec<u8>, TlsError> {
    require_component_name(a, "a")?;
    require_component_name(b, "b")?;
    require_fingerprint(sealed_a_sha256, "sealed_a_sha256")?;
    require_fingerprint(sealed_b_sha256, "sealed_b_sha256")?;
    let t = sent_at.to_string();
    Ok(assemble(&[
        PAIRSECRET_V1,
        a,
        b,
        sealed_a_sha256,
        sealed_b_sha256,
        &t,
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;

    const FP_A: &str = "aa00112233445566778899aabbccddeeff00112233445566778899aabbccddee";
    const FP_B: &str = "bb00112233445566778899aabbccddeeff00112233445566778899aabbccddee";
    const FP_C: &str = "cc00112233445566778899aabbccddeeff00112233445566778899aabbccddee";

    // --- exact bytes, not string equality ----------------------------------- //

    #[test]
    fn approve_yields_exactly_expected_bytes() {
        let out = approve_v1("gateway", FP_A, "operator", 1_700_000_000).unwrap();
        let expected = format!("nettls-approve/v1\ngateway\n{FP_A}\noperator\n1700000000");
        assert_eq!(out, expected.as_bytes());
        assert_ne!(*out.last().unwrap(), b'\n', "a trailing LF must NOT exist");
    }

    #[test]
    fn rotate_yields_exactly_expected_bytes() {
        let out = rotate_v2("gateway", Some(FP_A), FP_B, FP_C, 1_700_000_000).unwrap();
        let expected = format!("nettls-rotate/v2\ngateway\n{FP_A}\n{FP_B}\n{FP_C}\n1700000000");
        assert_eq!(out, expected.as_bytes());
    }

    #[test]
    fn first_rotation_serializes_prev_as_dash() {
        let out = rotate_v2("gateway", None, FP_B, FP_C, 1_700_000_000).unwrap();
        let expected = format!("nettls-rotate/v2\ngateway\n-\n{FP_B}\n{FP_C}\n1700000000");
        assert_eq!(out, expected.as_bytes());
        // The line count is the same as with prev — a vanished field would
        // make the next line shift up and mean something else.
        assert_eq!(
            out.iter().filter(|b| **b == b'\n').count(),
            rotate_v2("gateway", Some(FP_A), FP_B, FP_C, 1)
                .unwrap()
                .iter()
                .filter(|b| **b == b'\n')
                .count()
        );
    }

    #[test]
    fn ack_yields_exactly_expected_bytes() {
        let out = rotate_ack_v2("service", "gateway", FP_C, 1_700_000_000).unwrap();
        assert_eq!(
            out,
            format!("nettls-rotate-ack/v2\nservice\ngateway\n{FP_C}\n1700000000").as_bytes()
        );
    }

    #[test]
    fn pairsecret_yields_exactly_expected_bytes() {
        let out = pairsecret_v1("service", "gateway", FP_A, FP_B, 1_700_000_000).unwrap();
        assert_eq!(
            out,
            format!("nettls-pairsecret/v1\nservice\ngateway\n{FP_A}\n{FP_B}\n1700000000")
                .as_bytes()
        );
    }

    // --- CRLF and trailing LF ------------------------------------------------ //

    #[test]
    fn no_crlf_anywhere() {
        for out in [
            approve_v1("gateway", FP_A, "operator", 1).unwrap(),
            rotate_v2("gateway", Some(FP_A), FP_B, FP_C, 1).unwrap(),
            rotate_ack_v2("service", "gateway", FP_C, 1).unwrap(),
            pairsecret_v1("service", "gateway", FP_A, FP_B, 1).unwrap(),
        ] {
            assert!(
                !out.windows(2).any(|w| w == b"\r\n"),
                "CRLF in canonical form"
            );
            assert_ne!(*out.last().unwrap(), b'\n');
        }
    }

    // --- field validation: everything that could break the line structure --- //

    #[test]
    fn newline_in_a_field_is_rejected() {
        // Without this check «rog\ner» would become two lines, and an
        // attacker could move content within the message without touching the
        // signature.
        assert!(approve_v1("gateway", FP_A, "rog\ner", 1).is_err());
        assert!(approve_v1("net\rgw", FP_A, "operator", 1).is_err());
        assert!(rotate_v2("net\ngw", Some(FP_A), FP_B, FP_C, 1).is_err());
    }

    #[test]
    fn empty_name_is_rejected() {
        assert!(approve_v1("", FP_A, "operator", 1).is_err());
        assert!(approve_v1("gateway", FP_A, "", 1).is_err());
    }

    #[test]
    fn wrong_fingerprint_is_rejected() {
        assert!(approve_v1("gateway", "kort", "operator", 1).is_err());
        assert!(approve_v1("gateway", &format!("sha256:{FP_A}"), "operator", 1).is_err());
        assert!(approve_v1("gateway", &FP_A.to_uppercase(), "operator", 1).is_err());
        assert!(approve_v1("gateway", &"z".repeat(64), "operator", 1).is_err());
    }

    #[test]
    fn non_ascii_in_names_is_allowed() {
        // `approved_by` is a username. Norwegian characters must not be
        // blocked — but they must yield the same bytes on both sides, so the
        // weight is on UTF-8. (The value below deliberately probes non-ASCII.)
        let out = approve_v1("gateway", FP_A, "bjørn-øyvind", 1).unwrap();
        assert_eq!(
            out,
            format!("nettls-approve/v1\ngateway\n{FP_A}\nbjørn-øyvind\n1").as_bytes()
        );
    }

    #[test]
    fn negative_timestamp_serializes_as_signed_decimal() {
        let out = approve_v1("gateway", FP_A, "operator", -5).unwrap();
        assert!(out.ends_with(b"\n-5"));
    }
}
