# SPDX-License-Identifier: MIT OR Apache-2.0
"""The error matrix, Python side (SPEC-nettls §6.14b).

The cross-test and the vectors probe only **valid** values. An attacker does
not live there. Two divergences had already managed to arise without any test
seeing them, because both sat in the handling of the *invalid*:

| Divergence | Rust | Python |
|---|---|---|
| Multi-byte UTF-8 in a hex field | **panic** | orderly error |
| C1 control character (U+0085) in a name | rejected | **accepted** |

Hence this file, and its twin `tests/errors.rs`. Two directions per
implementation:

- **OUTGOING** — the constructor must refuse to *build* an invalid message, so
  we never send anything the peer has to guess about.
- **INCOMING** — the parser must reject a hostile message. With an **error**,
  never with a panic, and never by accepting it.

The two are unrelated: a hostile peer does not use our constructor. That is why
the corpus is built by hand, as JSON, the way an attacker would.

NOTE: the corpus keys and kind names (announcement/receipt/approval,
nivaa, name, field, hvorfor, levels parse/verifiser) mirror the frozen, shared
corpus file — data, not prose.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import nettls as n  # noqa: E402

CORPUS = json.loads((HERE.parent / "testvectors" / "errors.json").read_text())

BASELINE = CORPUS["_valid"]

READERS = {
    "announcement": n.Announcement.from_json,
    "receipt": n.Receipt.from_json,
    "approval": n.Approval.from_json,
}


def _entries(kind: str):
    return [pytest.param(p, id=p["name"]) for p in CORPUS[kind]]


def _verify_kind(kind: str, obj) -> None:
    """Run verification for the given kind, with the baseline's keys."""
    if kind == "announcement":
        obj.verify(
            n.der_from_pem(BASELINE["prev_cert_pem"]), n.der_from_pem(BASELINE["curr_cert_pem"])
        )
    elif kind == "receipt":
        obj.verify(n.from_hex(BASELINE["ed25519_pub"]), obj.new_fp)
    else:
        obj.verify(lambda kid: n.from_hex(BASELINE["ed25519_pub"]) if kid == "portal" else None)


# --------------------------------------------------------------------------- #
# Positive control — FIRST
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("kind", ["announcement", "receipt", "approval"])
def test_baseline_is_accepted_and_verifies(kind):
    """Without this, the whole corpus could pass for the wrong reason.

    If the field names in the corpus file were wrong, **everything** would be
    rejected — and a test that only demands rejection would look green while
    probing nothing at all.

    It goes all the way, not just through the parser: the message must both
    parse **and** verify against real keys. Otherwise the baseline could have
    been a message with valid form and a useless signature, and corpus level
    «verify» would pass without probing anything.
    """
    obj = READERS[kind](BASELINE[kind])
    _verify_kind(kind, obj)


# --------------------------------------------------------------------------- #
# INCOMING Python — the shared corpus
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("post", _entries("announcement"))
def test_incoming_announcement_is_rejected(post):
    _require_rejected("announcement", post)


@pytest.mark.parametrize("post", _entries("receipt"))
def test_incoming_receipt_is_rejected(post):
    _require_rejected("receipt", post)


@pytest.mark.parametrize("post", _entries("approval"))
def test_incoming_approval_is_rejected(post):
    _require_rejected("approval", post)


def _require_rejected(kind: str, post: dict) -> None:
    """Must raise ``NettlsError`` — at the **right level**, and never pass.

    The exception type is part of the contract: a `KeyError` or `TypeError`
    escaping means the field was never validated, it just happened to crash
    somewhere further in. Our caller catches `NettlsError` and nothing else.

    The level is part of the contract too. A `parse` entry first stopped in
    `verifiser` would mean an invalid value got to live as an object inside
    our program — and that *that* code was the only thing standing between it
    and a signed string.
    """
    load = READERS[kind]
    try:
        obj = load(post["json"])
    except n.NettlsError:
        if post["level"] == "verify":
            raise AssertionError(
                f"{post['name']}: rejected at PARSING, but is marked «verify». "
                f"Either the marking is wrong, or something other than "
                f"«{post['field']}» failed first — and then the entry does not "
                f"probe what it should."
            ) from None
        return
    except Exception as e:  # noqa: BLE001
        raise AssertionError(
            f"{post['name']}: rejected with {type(e).__name__} instead of "
            f"NettlsError — the field «{post['field']}» was never validated, "
            f"it just crashed further in. ({e})"
        ) from e

    if post["level"] == "parse":
        raise AssertionError(
            f"{post['name']}: ACCEPTED by the parser. Should have been rejected "
            f"because {post['why']} (field: {post['field']})"
        )

    # Level «verify»: it was allowed to become an object, but must be stopped here.
    try:
        _verify_kind(kind, obj)
    except n.NettlsError:
        return
    except Exception as e:  # noqa: BLE001
        raise AssertionError(
            f"{post['name']}: verification failed with {type(e).__name__} "
            f"instead of NettlsError ({e})"
        ) from e
    raise AssertionError(
        f"{post['name']}: ACCEPTED by verification. Should have been rejected "
        f"because {post['why']} (field: {post['field']})"
    )


# --------------------------------------------------------------------------- #
# OUTGOING Python — the constructors must refuse to build anything invalid
# --------------------------------------------------------------------------- #

LF = "gateway\nfake"
NEL = "gateway"  # U+0085 NEL, category Cc — invisible, hence as an escape
VALID_FP = "ab" * 32


@pytest.mark.parametrize(
    "name,field,verdi",
    [
        ("linjeskift", "peer", LF),
        ("c1_kontrolltegn", "peer", NEL),
        ("nullbyte", "peer", "gateway\x00"),
        ("tom", "peer", ""),
        ("for_langt", "peer", "x" * 33),
        ("uppercase", "peer", "Gateway"),
        ("underscore", "peer", "gate_way"),
    ],
)
def test_outgoing_names_are_rejected(name, field, verdi):
    """A name that cannot go into a canonical string is stopped at the source.

    With a newline the field would become **two** lines, and an attacker could
    thereby move content within the message without touching the signature.
    """
    with pytest.raises(n.NettlsError):
        n.approve_v1(verdi, VALID_FP, "operator", 1)


@pytest.mark.parametrize(
    "name,verdi",
    [
        ("store_bokstaver", VALID_FP.upper()),
        ("for_kort", "abc"),
        ("for_langt", "ab" * 33),
        ("med_prefiks", "sha256:" + VALID_FP),
        ("ikke_hex", "g" * 64),
        ("tom", ""),
    ],
)
def test_outgoing_fingerprints_are_rejected(name, verdi):
    with pytest.raises(n.NettlsError):
        n.approve_v1("gateway", verdi, "operator", 1)


@pytest.mark.parametrize(
    "name,verdi",
    [
        ("flerbyte_utf8", "a€"),
        ("store_bokstaver", "ABCD"),
        ("oddetall", "abc"),
        ("tom", ""),
        ("ikke_hex", "zzzz"),
    ],
)
def test_outgoing_hex_is_rejected(name, verdi):
    """`from_hex` is fail-closed. The multi-byte entry is the Rust-side regression.

    Python never had the panic — it indexes code points — but the entry is
    here anyway, so the two files probe the **same** corpus. An error matrix
    where the two sides test different cases is not an error matrix.
    """
    with pytest.raises(n.NettlsError):
        n.from_hex(verdi)


def test_outgoing_approval_rejects_invalid_key_id():
    with pytest.raises(n.NettlsError):
        n.Approval.new("gateway", VALID_FP, "operator", 1, LF, bytes(32))
