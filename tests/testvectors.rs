// SPDX-License-Identifier: MIT OR Apache-2.0
//! Test vectors — **normative** (SPEC-nettls §6.14).
//!
//! The vectors in `testvectors/canonical.json` are the answer key. Not the
//! Rust code, not the Python code: **the file**. If a vector fails, the
//! question is "which of the two is right according to the specification",
//! not "who must fall in line with whom".
//!
//! ## What they catch that a cross-test does not
//!
//! A cross-test shows that the two implementations agree **right now**. Two
//! implementations can agree and both be wrong. The vectors show that they
//! agree with **the contract** — and they cover the entire path from object
//! to bytes: field order, newlines, trailing newline, encoding.
//!
//! That is exactly where it broke last time: Rust picked hex, Python base64.
//! Both were legal. Neither was the contract, because the contract did not
//! say.
//!
//! The Ed25519 vectors include the **signature** too, not just the message —
//! Ed25519 is deterministic, so two implementations must produce identical
//! bytes. That is a far tighter probe than "does it verify?".
//!
//! The vector names, descriptions and JSON field names went English on
//! 2026-08-15 together with the wire keys (Roger's call: before first
//! adoption). The canonical BYTES and signatures are unchanged — only
//! versioned — they are data, not prose.

use std::collections::BTreeMap;

use nettls::canonical;

const VEKTORFIL: &str = "testvectors/canonical.json";

#[derive(serde::Serialize, serde::Deserialize, PartialEq, Eq, Debug)]
struct Vector {
    /// What the vector covers, in plain text.
    what: String,
    /// The canonical string as **hex** — not as text.
    ///
    /// Hex because a trailing newline, a CR or an invisible character would
    /// otherwise vanish in a JSON string read by eye. The point of the vector
    /// is exactly those bytes.
    canonical_hex: String,
    /// Ed25519 signature over the string, with the test seed. Only where meaningful.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ed25519_sig_hex: Option<String>,
}

/// The seed the vectors are signed with. Fixed, public, test vectors only.
const SEED: [u8; 32] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
];

/// The seed in the form `krypto::sign` takes it. The signing moved to krypto
/// in 0.8.0; Ed25519 is deterministic, so the vectors' signature bytes are
/// unchanged — which is precisely what this file proves.
fn seed() -> krypto::SecretBuf {
    krypto::SecretBuf::from_vec(SEED.to_vec()).unwrap()
}

const FP_A: &str = "aa00112233445566778899aabbccddeeff00112233445566778899aabbccddee";
const FP_B: &str = "bb00112233445566778899aabbccddeeff00112233445566778899aabbccddee";
const FP_C: &str = "cc00112233445566778899aabbccddeeff00112233445566778899aabbccddee";

/// All the vectors, built from the canonical module.
fn build() -> BTreeMap<String, Vector> {
    let mut v = BTreeMap::new();

    let mut add = |name: &str, what: &str, bytes: Vec<u8>| {
        v.insert(
            name.to_string(),
            Vector {
                what: what.to_string(),
                canonical_hex: krypto::hex::encode(&bytes),
                ed25519_sig_hex: Some(krypto::hex::encode(
                    &krypto::sign::ed25519_sign(&seed(), &bytes).unwrap(),
                )),
            },
        );
    };

    add(
        "approve-01-plain",
        "operator approval, ASCII username",
        canonical::approve_v1("gateway", FP_A, "operator", 1_700_000_000).unwrap(),
    );
    add(
        "approve-02-non-ascii",
        "operator approval with Norwegian characters — UTF-8 must give the same bytes on both sides",
        canonical::approve_v1("gateway", FP_A, "bjørn-øyvind", 1_700_000_000).unwrap(),
    );
    add(
        "approve-03-time-zero",
        "timestamp 0 — serialized as «0», not as an empty string",
        canonical::approve_v1("service", FP_B, "a", 0).unwrap(),
    );
    add(
        "approve-04-time-negative",
        "negative timestamp — signed decimal",
        canonical::approve_v1("service", FP_B, "a", -1).unwrap(),
    );
    add(
        "approve-05-max-lengths",
        "peer 32 chars, approved_by 64 chars — the limits must be equal on both sides",
        canonical::approve_v1(&"p".repeat(32), FP_C, &"u".repeat(64), 1).unwrap(),
    );

    add(
        "rotate-01-double-signed",
        "announcement in steady state — prev exists",
        canonical::rotate_v2("gateway", Some(FP_A), FP_B, FP_C, 1_700_000_000).unwrap(),
    );
    add(
        "rotate-02-bootstrap",
        "the first rotation — prev serialized as «-», not omitted",
        canonical::rotate_v2("gateway", None, FP_B, FP_C, 1_700_000_000).unwrap(),
    );

    add(
        "ack-01-plain",
        "receipt",
        canonical::rotate_ack_v2("service", "gateway", FP_C, 1_700_000_000).unwrap(),
    );

    add(
        "pairsecret-01-plain",
        "rotation of the pair secret — signed by both parties",
        canonical::pairsecret_v1("service", "gateway", FP_A, FP_B, 1_700_000_000).unwrap(),
    );

    add(
        "algsupport-01-python-bridge",
        "signed AEAD support statement — the Python bridge case: a party that only supports aes256gcm declares it (0.8.2)",
        canonical::algsupport_v1("service", "aes256gcm", 1_700_000_000).unwrap(),
    );

    v
}

#[test]
fn vectors_match_byte_for_byte() {
    let built = build();
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(VEKTORFIL);

    if std::env::var("WRITE_VECTORS").is_ok() {
        let json = serde_json::to_string_pretty(&built).unwrap();
        std::fs::write(&path, format!("{json}\n")).unwrap();
        eprintln!("wrote {} vectors to {}", built.len(), path.display());
        return;
    }

    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "could not read {} ({e}). First time? Run:\n    \
             WRITE_VECTORS=1 cargo test --test testvectors",
            path.display()
        )
    });
    let reference: BTreeMap<String, Vector> = serde_json::from_str(&text).unwrap();

    // No vector may vanish in silence. A deleted vector is a contract change,
    // and it must be visible in a diff.
    let missing: Vec<_> = reference
        .keys()
        .filter(|k| !built.contains_key(*k))
        .collect();
    assert!(
        missing.is_empty(),
        "vectors in the file that the code no longer produces: {missing:?} — \
         has a message form been removed without the contract changing?"
    );

    for (name, expected) in &reference {
        let actual = &built[name];
        assert_eq!(
            actual.canonical_hex, expected.canonical_hex,
            "\nvector «{name}» ({}) does not match.\n  reference: {}\n  actual:    {}\n",
            expected.what, expected.canonical_hex, actual.canonical_hex
        );
        assert_eq!(
            actual.ed25519_sig_hex, expected.ed25519_sig_hex,
            "\nthe Ed25519 signature for «{name}» does not match. Ed25519 is deterministic, \
             so this means either the message changed or the signing did.\n"
        );
    }

    // And new vectors must be committed, not merely exist in memory.
    let new_ones: Vec<_> = built
        .keys()
        .filter(|k| !reference.contains_key(*k))
        .collect();
    assert!(
        new_ones.is_empty(),
        "new vectors that are not committed: {new_ones:?} — run:\n    \
         WRITE_VECTORS=1 cargo test --test testvectors"
    );
}

#[test]
fn the_seeds_public_key_is_stable() {
    // The Python side needs this to verify the vectors' signatures. If it
    // changes, the seed changed — and then every signature vector is
    // invalid.
    let pk = krypto::sign::ed25519_public(&seed()).unwrap();
    assert_eq!(
        krypto::hex::encode(&pk),
        "79b5562e8fe654f94078b112e8a98ba7901f853ae695bed7e0e3910bad049664",
        "the test seed's public key has changed"
    );
}
