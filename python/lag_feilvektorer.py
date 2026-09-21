# SPDX-License-Identifier: MIT OR Apache-2.0
"""Generator for `testvectors/errors.json` — the normative error corpus.

Run:  python3 python/lag_feilvektorer.py

## Why the corpus exists

`testvectors/kanonisk.json` shows that the two implementations agree on
**valid** values. It says nothing about invalid ones — and that is where an
attacker actually lives. If Python is more lenient than Rust somewhere, you
attack Python; if Rust is more lenient, you attack Rust.

We have already had two such divergences, and the cross-test could see
**neither**:

- `from_hex` panicked in Rust on multi-byte UTF-8; Python gave an orderly error.
- `require_name` let C1 control characters through in Python; Rust rejected them.

Both sat in the handling of the *invalid*. Hence this corpus: one file, read by
both sides, where every entry **must** be rejected by both.

## Why the baseline is a real, valid message

Each entry is one mutation of a message that is otherwise fully valid — real
certificates, real signatures. Then the rejection can be attributed to exactly
that mutation. If the baseline were garbage, the entries would be rejected for
an entirely different reason than the one they are meant to probe, and the test
would pass for the wrong reason.

The `felt` value says which field was touched, so a test rejecting for the
wrong reason can be spotted by reading.

The corpus went fully English on 2026-08-15, together with the wire keys —
a deliberate, Roger-approved change made before first adoption. The corpus is
still normative: this generator's output IS the committed file, and both test
suites read the same file.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

HER = Path(__file__).resolve().parent
sys.path.insert(0, str(HER))

import nettls as n  # noqa: E402

UT = HER.parent / "testvectors" / "errors.json"

# Fixed seeds → the corpus is reproducible. The certificates below are
# self-signed and regenerated every time; that is fine, because nothing in the
# parse path looks at validity dates (pinning goes by fingerprint, §6.2).
SEED = bytes(range(32))


def _baseline() -> tuple[dict, dict, dict, dict]:
    """One valid announcement, receipt and approval — plus the certificates.

    The certificates must be in the file: without the `prev` and `curr` PEMs
    neither side can run verification, and corpus level «verify» would be
    unprobeable.
    """
    c0_pem, c0_key = n.self_signed("c0", ["c0"], days=30)
    c1_pem, c1_key = n.self_signed("c1", ["c1"], days=30)
    c2_pem, _ = n.self_signed("c2", ["c2"], days=30)

    k = n.Announcement.new(
        announcer="gateway",
        prev=(n.fingerprint_from_pem(c0_pem), c0_key),
        curr=(n.fingerprint_from_pem(c1_pem), c1_key),
        new_cert_pem=c2_pem,
        sent_at=1_700_000_000,
    )
    kv = n.Receipt.new("service", "gateway", k.new_fp, 1_700_000_001, SEED)
    g = n.Approval.new(
        "gateway", n.fingerprint_from_pem(c0_pem), "operator", 1_700_000_002, "portal", SEED
    )
    extra = {
        "prev_cert_pem": c0_pem,
        "curr_cert_pem": c1_pem,
        # The seed of the Ed25519 key that signed the receipt and the approval.
        # Hex, like all other key material in §6.
        "ed25519_seed": SEED.hex(),
        "ed25519_pub": n.ed25519_public_from_seed(SEED).hex(),
    }
    return k.to_json(), kv.to_json(), g.to_json(), extra


def _m(base: dict, field: str, value, why: str, name: str, level: str = "parse") -> dict:
    """One mutation. `value is ...` means "remove the field".

    `level` says **where** the entry must be stopped, and the two differ:

    - ``parse``  — `from_json` must reject. Covers everything that goes into
                   the canonical string: names, fingerprints, hex, version.
    - ``verify`` — `from_json` may accept, but verification **must** reject.
                      Covers `new_cert_pem`, which is not part of the signed
                      string: only the fingerprint is. A broken PEM is caught
                   where the fingerprint is recomputed and does not match.

    The distinction is not pedantry. Demanding rejection at the wrong level
    would either force validation where it does not belong, or — worse — let
    the test pass because something else entirely failed first.
    """
    j = json.loads(json.dumps(base))
    if value is ...:
        j.pop(field, None)
    else:
        j[field] = value
    return {"name": name, "field": field, "why": why, "level": level, "json": j}


# 64 hex characters, but not a fingerprint we have ever seen.
FOREIGN_FP = "0" * 64
HEX_WITH_MULTIBYTE = "a€"  # felled Rust before 2026-08-11
# Written as an ESCAPE on purpose: a raw U+0085 is invisible in an editor, and
# a constant nobody can see is a constant nobody can review.
NAME_WITH_NEL = "gateway\u0085"  # got through Python until 2026-08-11
NAME_WITH_LF = "gateway\nfake"


def announcement_errors(base: dict) -> list[dict]:
    return [
        _m(base, "v", "nettls-rotate/v1", "wrong message version", "wrong_version"),
        _m(base, "v", "", "empty message version", "empty_version"),
        _m(
            base,
            "announcer",
            NAME_WITH_LF,
            "a newline would split the field into two lines and move content "
            "within the canonical string without touching the signature",
            "announcer_newline",
        ),
        _m(
            base,
            "announcer",
            NAME_WITH_NEL,
            "U+0085 NEL is category Cc — Python let it through until 2026-08-11",
            "announcer_c1_control_char",
        ),
        _m(base, "announcer", "", "empty name", "announcer_empty"),
        _m(base, "announcer", "x" * 33, "the name is over the 32-char limit", "announcer_too_long"),
        _m(base, "announcer", "Gateway", "component names are [a-z0-9-] — uppercase rejected (§6.5)", "announcer_uppercase"),
        _m(base, "announcer", "gate_way", "component names are [a-z0-9-] — underscore rejected (§6.5)", "announcer_underscore"),
        _m(
            base,
            "curr_fingerprint",
            base["curr_fingerprint"].upper(),
            "fingerprints are written in lowercase (§6.5) — otherwise two "
            "implementations can produce different bytes for the same value",
            "curr_fp_uppercase",
        ),
        _m(base, "curr_fingerprint", "abc", "fingerprint too short", "curr_fp_too_short"),
        _m(
            base,
            "curr_fingerprint",
            "sha256:" + base["curr_fingerprint"],
            "the «sha256:» prefix does not belong in the field",
            "curr_fp_with_prefix",
        ),
        _m(base, "curr_fingerprint", "g" * 64, "64 chars, but not hex", "curr_fp_not_hex"),
        _m(base, "new_fingerprint", "abc", "fingerprint too short", "new_fp_too_short"),
        _m(
            base,
            "sig_curr",
            HEX_WITH_MULTIBYTE,
            "multi-byte UTF-8 in a hex field — felled Rust with a panic until "
            "2026-08-11, while Python gave an orderly error",
            "sig_curr_multibyte_utf8",
        ),
        _m(base, "sig_curr", "abc", "odd number of hex chars", "sig_curr_odd"),
        _m(base, "sig_curr", "", "empty signature", "sig_curr_empty"),
        _m(
            base,
            "sig_curr",
            base["sig_curr"].upper(),
            "hex in uppercase",
            "sig_curr_uppercase",
        ),
        _m(base, "sig_curr", "zz" * 32, "non-hex chars", "sig_curr_not_hex"),
        _m(
            base,
            "sig_prev",
            ...,
            "prev_fingerprint without sig_prev is half an announcement — we do "
            "not guess at what was meant",
            "half_announcement_missing_sig_prev",
        ),
        _m(
            base,
            "prev_fingerprint",
            ...,
            "sig_prev without prev_fingerprint is the same half announcement "
            "the other way",
            "half_announcement_missing_prev_fp",
        ),
        # --- level «verifiser» ----------------------------------------------- #
        # `new_cert_pem` is NOT part of the signed string — only the
        # fingerprint is. That is why these get through `from_json` in
        # both implementations, and must be stopped where the fingerprint is
        # recomputed from the PEM. That is the right place: a receiver that
        # stored a broken PEM would be left without a usable «next» at the
        # rotation.
        _m(
            base,
            "new_cert_pem",
            base["new_cert_pem"] + base["new_cert_pem"],
            "two certificates in the PEM — an announcement carries exactly one, "
            "otherwise it is unclear which one gets pinned",
            "two_certificates_in_pem",
            level="verify",
        ),
        _m(base, "new_cert_pem", "", "empty PEM", "empty_pem", level="verify"),
        _m(
            base,
            "new_cert_pem",
            "-----BEGIN CERTIFICATE-----\nxx\n-----END CERTIFICATE-----\n",
            "the PEM framing is there, but the content is not a certificate",
            "garbage_in_pem",
            level="verify",
        ),
        _m(
            base,
            "new_fingerprint",
            FOREIGN_FP,
            "valid FORM, but not the fingerprint of the certificate that comes "
            "with it — exactly the binding §6.5 exists to enforce",
            "new_fp_does_not_match_pem",
            level="verify",
        ),
    ]


def receipt_errors(base: dict) -> list[dict]:
    return [
        _m(base, "v", "nettls-rotate-ack/v1", "wrong message version", "ack_wrong_version"),
        _m(base, "acker", NAME_WITH_LF, "newline in a name", "ack_acker_newline"),
        _m(base, "acker", NAME_WITH_NEL, "C1 control character in a name", "ack_acker_c1"),
        _m(base, "announcer", "", "empty name", "ack_announcer_empty"),
        _m(base, "new_fingerprint", FOREIGN_FP[:10], "too short", "ack_fp_too_short"),
        _m(base, "sig", HEX_WITH_MULTIBYTE, "multi-byte UTF-8 in a hex field", "ack_sig_multibyte"),
        _m(base, "sig", "", "empty signature", "ack_sig_empty"),
        _m(base, "sig", base["sig"].upper(), "hex in uppercase", "ack_sig_uppercase"),
    ]


def approval_errors(base: dict) -> list[dict]:
    return [
        _m(base, "v", "nettls-approve/v2", "wrong message version", "ap_wrong_version"),
        _m(base, "peer", NAME_WITH_LF, "newline in a name", "ap_peer_newline"),
        _m(base, "peer", NAME_WITH_NEL, "C1 control character in a name", "ap_peer_c1"),
        _m(
            base,
            "approved_by",
            NAME_WITH_LF,
            "newline in «who approved» — the field sits inside the signature "
            "precisely to say who acted",
            "ap_approved_by_newline",
        ),
        _m(base, "approved_by", "", "empty name", "ap_approved_by_empty"),
        _m(base, "fingerprint", "abc", "fingerprint too short", "ap_fp_too_short"),
        _m(base, "key_id", NAME_WITH_LF, "newline in key_id", "ap_key_id_newline"),
        _m(base, "key_id", "", "empty key_id", "ap_key_id_empty"),
        _m(base, "sig", HEX_WITH_MULTIBYTE, "multi-byte UTF-8 in a hex field", "ap_sig_multibyte"),
        _m(base, "sig", "abc", "odd number of hex chars", "ap_sig_odd"),
    ]


def main() -> None:
    k, kv, g, extra = _baseline()
    corpus = {
        "_about": (
            "Normative error corpus (§6.14b). Every entry MUST be rejected by "
            "BOTH implementations — with an error, never a panic. The baseline "
            "is a valid message with real signatures; each entry is one mutation "
            "of it, so the rejection can be attributed to exactly that mutation."
        ),
        # POSITIVE CONTROL. Without it the whole corpus can pass for the wrong
        # reason: with wrong field names EVERYTHING would be rejected, and a
        # test that only demands rejection would look green while probing
        # nothing. These three are the unmutated messages, and they MUST be
        # accepted by both sides.
        "_valid": {"announcement": k, "receipt": kv, "approval": g, **extra},
        "announcement": announcement_errors(k),
        "receipt": receipt_errors(kv),
        "approval": approval_errors(g),
    }
    UT.write_text(json.dumps(corpus, indent=2, ensure_ascii=False) + "\n")
    n_entries = sum(len(v) for v in corpus.values() if isinstance(v, list))
    print(f"wrote {UT} — {n_entries} entries")


if __name__ == "__main__":
    main()
