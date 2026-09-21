// SPDX-License-Identifier: MIT OR Apache-2.0
//! SHA-256 fingerprint of the leaf certificate's DER — what clients pin.
//!
//! The model is the same as SSH host-key pinning: the identity is *exactly this
//! key*, not "something a CA has signed". That fits an internal setup without a CA, and it gives a
//! value the operator can read aloud and compare.
//!
//! The fingerprint is of the **DER**, not of the PEM text — the same value as
//! `openssl x509 -noout -fingerprint -sha256`.
//!
//! The primitives live in `krypto` (0.5): the hash is `krypto::sha256`, the
//! canonical serialization is `krypto::hex`, and authentication-decision
//! comparisons are `krypto::ct_eq`. What remains here is the one thing that is
//! *ours*: parsing a fingerprint the way an **operator** writes one.

use crate::error::TlsError;

/// Parses a fingerprint string the operator may have clipped from anywhere.
///
/// Deliberately tolerant on format: upper/lowercase, colons, spaces and a
/// leading `sha256:`/`SHA256:` are all allowed, because `openssl`, browsers and
/// our own `/status` write it differently. What is **not** tolerated is wrong
/// length or invalid characters — then it is a typo, and a typo in a pinning
/// value must never turn into "accepts everything".
///
/// This is deliberately NOT `krypto::hex::decode`: that one is the canonical
/// wire form (lowercase only, fail-closed), for values MACHINES exchange. This
/// one is for values HUMANS transcribe. The two must not be merged — loosening
/// the wire form is a protocol hole, and hardening the operator form is a
/// usability trap.
pub(crate) fn parse_fingerprint(s: &str) -> Result<[u8; 32], TlsError> {
    let trimmed = s.trim();
    let body = trimmed
        .strip_prefix("sha256:")
        .or_else(|| trimmed.strip_prefix("SHA256:"))
        .or_else(|| trimmed.strip_prefix("sha256-"))
        .unwrap_or(trimmed);

    let mut nibbles: Vec<u8> = Vec::with_capacity(64);
    for c in body.chars() {
        if c == ':' || c == ' ' || c == '-' || c == '\n' || c == '\r' || c == '\t' {
            continue;
        }
        match c.to_digit(16) {
            Some(d) => nibbles.push(d as u8),
            None => {
                return Err(TlsError::Fingerprint(format!(
                    "the character {c:?} is not hexadecimal (expected 64 hex digits, possibly with colons)"
                )))
            }
        }
    }
    if nibbles.len() != 64 {
        return Err(TlsError::Fingerprint(format!(
            "expected 64 hex digits (32 bytes), got {}",
            nibbles.len()
        )));
    }
    let mut out = [0u8; 32];
    for (i, pair) in nibbles.chunks_exact(2).enumerate() {
        out[i] = (pair[0] << 4) | pair[1];
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_canonical_form() {
        let raw = [0xdeu8; 32];
        let hex = krypto::hex::encode(&raw);
        assert_eq!(hex.len(), 64);
        assert_eq!(parse_fingerprint(&hex).unwrap(), raw);
    }

    #[test]
    fn tolerates_colons_uppercase_and_prefix() {
        let raw = [0xabu8; 32];
        let hex = krypto::hex::encode(&raw);
        let med_kolon: Vec<String> = hex
            .as_bytes()
            .chunks(2)
            .map(|c| String::from_utf8_lossy(c).to_uppercase())
            .collect();
        let pyntet = format!("SHA256:{}", med_kolon.join(":"));
        assert_eq!(parse_fingerprint(&pyntet).unwrap(), raw);
    }

    #[test]
    fn rejects_wrong_length_and_invalid_characters() {
        assert!(parse_fingerprint("abcd").is_err());
        assert!(parse_fingerprint(&"z".repeat(64)).is_err());
        assert!(parse_fingerprint("").is_err());
    }
}
