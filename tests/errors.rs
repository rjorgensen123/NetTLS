// SPDX-License-Identifier: MIT OR Apache-2.0
//! The error matrix, Rust side (SPEC-nettls §6.14b).
//!
//! Twin of `python/test_feil.py`, and they read **the same file**:
//! `testvectors/errors.json`.
//!
//! ## Why the corpus is shared and not two lists
//!
//! The vectors in `canonical.json` show that the two implementations agree on
//! **valid** values. An attacker does not live there. Two divergences had
//! already managed to arise without any test seeing them, because both sat in
//! the handling of the *invalid*:
//!
//! | Divergence | Rust | Python |
//! |---|---|---|
//! | Multi-byte UTF-8 in a hex field | **panic** | orderly error |
//! | C1 control character (U+0085) in a name | rejected | **accepted** |
//! | Broken PEM | wrapped error | **foreign exception type** |
//!
//! If the two lists differ, each side probes its own cases and the divergence
//! survives. One file, read by both, is the whole point.
//!
//! ## Two levels, and the difference is not pedantry
//!
//! - **`parse`** — `from_json` must reject. Everything that goes into the
//!   canonical string: names, fingerprints, hex, version.
//! - **`verify`** — `from_json` may accept, but `verify` **must** reject.
//!   `new_cert_pem` is not part of the signed string — only the fingerprint
//!   is — so a broken PEM is caught where the fingerprint is recomputed.
//!
//! A `parse` entry that is first stopped in `verify` would mean an invalid
//! value got to live as an object inside our program.
//!
//! ## Does a panic count as passing? No.
//!
//! A panic fails the test by itself in Rust. That is on purpose: it was
//! precisely a panic (`from_hex` on multi-byte UTF-8) that was the most severe
//! of the divergences, and it was reachable from `sig_curr` straight off the
//! network.
//!
//! The corpus vocabulary went fully English on 2026-08-15 together with the
//! wire keys (kinds `announcement`/`receipt`/`approval`, keys `name`/`field`/
//! `why`/`level`, levels `parse`/`verify`) — both suites read the same file and stay as they
//! are — data, not prose.

use nettls::announcement::{der_from_pem, Announcement, AnnouncementJson, Receipt, ReceiptJson};
use nettls::approval::{Approval, ApprovalJson};
use nettls::signature::from_hex;

const CORPUS_FILE: &str = "testvectors/errors.json";

fn corpus() -> serde_json::Value {
    let raa = std::fs::read_to_string(CORPUS_FILE)
        .unwrap_or_else(|e| panic!("could not read {CORPUS_FILE}: {e}"));
    serde_json::from_str(&raa).expect("the corpus must be valid JSON")
}

/// The outcome of reading **and** verifying one entry.
#[derive(Debug, PartialEq, Eq)]
enum Outcome {
    /// `from_json` (or serde) rejected.
    RejectedAtParsing,
    /// Parsed fine, but `verify` rejected.
    RejectedAtVerification,
    /// Made it all the way through.
    Accepted,
}

fn baseline(k: &serde_json::Value) -> &serde_json::Value {
    &k["_valid"]
}

fn prev_curr_der(k: &serde_json::Value) -> (Vec<u8>, Vec<u8>) {
    let g = baseline(k);
    (
        der_from_pem(g["prev_cert_pem"].as_str().unwrap()).expect("the baseline's prev PEM"),
        der_from_pem(g["curr_cert_pem"].as_str().unwrap()).expect("the baseline's curr PEM"),
    )
}

fn ed25519_pub(k: &serde_json::Value) -> Vec<u8> {
    from_hex(baseline(k)["ed25519_pub"].as_str().unwrap()).expect("the baseline's Ed25519 key")
}

fn try_announcement(k: &serde_json::Value, j: &serde_json::Value) -> Outcome {
    let Ok(kj) = serde_json::from_value::<AnnouncementJson>(j.clone()) else {
        return Outcome::RejectedAtParsing;
    };
    let Ok(obj) = Announcement::from_json(&kj) else {
        return Outcome::RejectedAtParsing;
    };
    let (prev, curr) = prev_curr_der(k);
    match obj.verify(Some(&prev), &curr) {
        Ok(()) => Outcome::Accepted,
        Err(_) => Outcome::RejectedAtVerification,
    }
}

fn try_receipt(k: &serde_json::Value, j: &serde_json::Value) -> Outcome {
    let Ok(kj) = serde_json::from_value::<ReceiptJson>(j.clone()) else {
        return Outcome::RejectedAtParsing;
    };
    let Ok(obj) = Receipt::from_json(&kj) else {
        return Outcome::RejectedAtParsing;
    };
    let pk = ed25519_pub(k);
    let fp = obj.new_fingerprint().to_string();
    match obj.verify(&pk, &fp) {
        Ok(()) => Outcome::Accepted,
        Err(_) => Outcome::RejectedAtVerification,
    }
}

fn try_approval(k: &serde_json::Value, j: &serde_json::Value) -> Outcome {
    let Ok(gj) = serde_json::from_value::<ApprovalJson>(j.clone()) else {
        return Outcome::RejectedAtParsing;
    };
    let Ok(obj) = Approval::from_json(&gj) else {
        return Outcome::RejectedAtParsing;
    };
    let pk = ed25519_pub(k);
    let lookup = move |id: &str| {
        if id == "portal" {
            Some(pk.clone())
        } else {
            None
        }
    };
    match obj.verify(&lookup) {
        Ok(()) => Outcome::Accepted,
        Err(_) => Outcome::RejectedAtVerification,
    }
}

// --------------------------------------------------------------------------- //
// Positive control — FIRST
// --------------------------------------------------------------------------- //

/// Without this, the whole corpus could pass for the wrong reason.
///
/// If the field names in the corpus file were wrong, **everything** would be
/// rejected — and a test that only demands rejection would look green while
/// probing nothing. Here the unmutated messages go all the way: parsed **and**
/// verified against real keys.
#[test]
fn the_baseline_is_accepted_and_verifies() {
    let k = corpus();
    let g = baseline(&k);
    for (kind, outcome) in [
        ("announcement", try_announcement(&k, &g["announcement"])),
        ("receipt", try_receipt(&k, &g["receipt"])),
        ("approval", try_approval(&k, &g["approval"])),
    ] {
        assert_eq!(
            outcome,
            Outcome::Accepted,
            "the baseline {kind} must go all the way through — otherwise the \
             error corpus probes nothing"
        );
    }
}

// --------------------------------------------------------------------------- //
// INCOMING Rust — the shared corpus
// --------------------------------------------------------------------------- //

fn run_kind(kind: &str, proev: fn(&serde_json::Value, &serde_json::Value) -> Outcome) {
    let k = corpus();
    let poster = k[kind]
        .as_array()
        .expect("the corpus must have a list here");
    assert!(!poster.is_empty(), "{kind}: an empty corpus probes nothing");

    for p in poster {
        let name = p["name"].as_str().unwrap();
        let field = p["field"].as_str().unwrap();
        let why = p["why"].as_str().unwrap();
        let level = p["level"].as_str().unwrap();

        let outcome = proev(&k, &p["json"]);

        match (level, &outcome) {
            ("parse", Outcome::RejectedAtParsing) => {}
            ("verify", Outcome::RejectedAtVerification) => {}

            ("parse", Outcome::Accepted) | ("verify", Outcome::Accepted) => {
                panic!("{kind}/{name}: ACCEPTED. Should have been rejected because {why} (field: {field})")
            }
            ("parse", Outcome::RejectedAtVerification) => panic!(
                "{kind}/{name}: slipped through the parser and was first stopped in \
                 verification. An invalid «{field}» thus got to live as an object \
                 inside the program — and verification was the only thing standing \
                 between it and a signed string."
            ),
            ("verify", Outcome::RejectedAtParsing) => panic!(
                "{kind}/{name}: rejected at PARSING, but is marked «verify». Either \
                 the marking is wrong, or something other than «{field}» failed first — \
                 and then the entry does not probe what it should."
            ),
            (other, _) => panic!("{kind}/{name}: unknown level «{other}» in the corpus"),
        }
    }
}

#[test]
fn incoming_announcement_is_rejected() {
    run_kind("announcement", try_announcement);
}

#[test]
fn incoming_receipt_is_rejected() {
    run_kind("receipt", try_receipt);
}

#[test]
fn incoming_approval_is_rejected() {
    run_kind("approval", try_approval);
}

// --------------------------------------------------------------------------- //
// OUTGOING Rust — the constructors must refuse to build anything invalid
// --------------------------------------------------------------------------- //

/// U+0085 NEL. Written as an escape on purpose: a raw control character is
/// invisible in an editor, and a constant nobody can see is a constant nobody
/// can review.
const NAME_WITH_NEL: &str = "gateway\u{0085}";
const NAME_WITH_LF: &str = "gateway\nfake";
const VALID_FP: &str = "abababababababababababababababababababababababababababababababab";

/// A name that cannot go into a canonical string must be stopped at the
/// source.
///
/// With a newline the field would become **two** lines, and an attacker could
/// thereby move content within the message without touching the signature.
#[test]
fn outgoing_names_are_rejected() {
    for (what, name) in [
        ("newline", NAME_WITH_LF),
        ("c1 control character", NAME_WITH_NEL),
        ("null byte", "gateway\u{0000}"),
        ("empty", ""),
        ("too long", "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"), // 33
        ("uppercase", "Gateway"),
        ("underscore", "gate_way"),
    ] {
        assert!(
            nettls::canonical::approve_v1(name, VALID_FP, "operator", 1).is_err(),
            "{what}: should have been rejected as a peer name"
        );
    }
}

#[test]
fn outgoing_fingerprints_are_rejected() {
    for (what, fp) in [
        ("uppercase", VALID_FP.to_uppercase()),
        ("too short", "abc".into()),
        ("too long", format!("{VALID_FP}ab")),
        ("with a «sha256:» prefix", format!("sha256:{VALID_FP}")),
        ("not hex", "g".repeat(64)),
        ("empty", String::new()),
    ] {
        assert!(
            nettls::canonical::approve_v1("gateway", &fp, "operator", 1).is_err(),
            "{what}: should have been rejected as a fingerprint"
        );
    }
}

/// `from_hex` is fail-closed. The multi-byte entry is the regression: the
/// form that indexed `&s[i..i + 2]` panicked instead of returning an error,
/// and was reachable from `sig_curr` straight off the network.
#[test]
fn outgoing_hex_is_rejected() {
    for (what, s) in [
        ("multi-byte UTF-8", "a\u{20AC}"),
        ("uppercase", "ABCD"),
        ("odd count", "abc"),
        ("empty", ""),
        ("not hex", "zzzz"),
    ] {
        assert!(
            from_hex(s).is_err(),
            "{what}: should have been rejected as hex"
        );
    }
}
