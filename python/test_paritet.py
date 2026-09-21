# SPDX-License-Identifier: MIT OR Apache-2.0
"""Parity test: does Python have a counterpart to everything Rust has? (§6.14c)

## The gap this closes

All the other tests compare **behaviour** — the vectors, the cross-test, the
error corpus, the ring. They all assume the function exists on *both* sides.
If it is missing in Python, there is nothing to compare, and **everything is
green**.

That is not hypothetical. Five findings on 2026-08-11 had exactly this shape:

| Missing in Python | Consequence |
|---|---|
| `Generations::restore` | every restart looked like memory loss |
| `Recognition` (M-9) | generation 0 verified by a different code path than the rest |
| `mode1_should_warn` (M-12) | no warning before a mode 1 certificate falls |
| `MODE2_LIFETIME_DAYS` (M-21) | the lifetime was a literal, not a requirement |
| `mode1_params` validation | a lifetime outside floor/ceiling was accepted |

None of them were **wrong logic**. They were absences. And an absence has no
behaviour to test.

They were found by reading the two files side by side. That does not scale,
and it does not run in CI.

## How it works

`TILORDNING` below is a **written-down decision** for every public element of
the crate: either the name of the Python counterpart, or one of the reasons it
does not exist. If someone adds something public in Rust without taking a
position, the build fails.

It is not the test that decides what should exist — it only requires that
someone took a position, and that the decision is written where others can
read it.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

HER = Path(__file__).resolve().parent
ROT = HER.parent
sys.path.insert(0, str(HER))

import nettls as n  # noqa: E402

# --------------------------------------------------------------------------- #
# The reasons something does NOT have a Python counterpart
# --------------------------------------------------------------------------- #

#: Storage. The one agreed exception: `nettls.py` stores nothing itself, and
#: trusts the consumer (§6.11b). Everything that is file handling goes here.
LAGRING = "storage — the consumer's responsibility (§6.11b)"

#: Rust-specific machinery meaningless in Python: rustls types, the crypto
#: provider, PEM encoding `cryptography` already does.
RUST_INTERN = "Rust-internal — no counterpart in Python"

#: The retired v1 model. Removed once every consumer has migrated to §6.
#: `#[doc(hidden)]` helpers that exist only for the cross-test and examples.
TESTHJELPER = "test helper, not part of the contract"

#: Internal Rust detail that Python solves differently, without the contract
#: differing. Requires an explanation per entry.
ANNEN_FORM = "solved differently in Python"

GRUNNER = {LAGRING, RUST_INTERN, TESTHJELPER, ANNEN_FORM}


# --------------------------------------------------------------------------- #
# The mapping — Rust name → Python name, or a reason
# --------------------------------------------------------------------------- #

TILORDNING: dict[str, str] = {
    # -- Canonical strings and signatures: the core of the contract ---------- #
    "APPROVE_V1": "APPROVE_V1",
    "ROTATE_V2": "ROTATE_V2",
    "ROTATE_ACK_V2": "ROTATE_ACK_V2",
    "PAIRSECRET_V1": "PAIRSECRET_V1",
    "approve_v1": "approve_v1",
    "rotate_v2": "rotate_v2",
    "rotate_ack_v2": "rotate_ack_v2",
    "pairsecret_v1": "pairsecret_v1",
    "require_fingerprint": "require_fingerprint",
    "require_name": "require_name",
    "require_component_name": "require_component_name",
    "MAX_CERT_PEM_LEN": "MAX_CERT_PEM_LEN",
    # Since 0.8.0 the crate carries no primitives of its own: hex encoding and
    # the Ed25519 functions are `krypto`'s (krypto::hex / krypto::sign), so the
    # Rust names vanished from THIS crate. The Python twin keeps its own
    # (`cryptography`-based) versions — parity on wire bytes is proven by the
    # test vectors and the cross-test, not by a name mapping.
    "from_hex": "from_hex",
    "sign_p256": "sign_p256",
    "verify_p256": "verify_p256",
    "fingerprint_from_pem": "fingerprint_from_pem",
    "der_from_pem": "der_from_pem",
    "cert_fingerprint_sha256": "fingerprint_from_der",
    # -- The messages -------------------------------------------------------- #
    "Announcement": "Announcement",
    "Receipt": "Receipt",
    "Approval": "Approval",
    "Recognition": "Recognition",
    "Context": "Context",
    "IdentityJson": "identity_json",
    # -- The generation state ------------------------------------------------ #
    "Generation": "Generation",
    "Generations": "Generations",
    # -- Schedule ---------------------------------------------------------- #
    "Schedule": "Schedule",
    "OwnTrio": ANNEN_FORM,  # Python's Announcer state is consumer-held and directly readable
    "Announcer": "Announcer",
    "ClockDrift": "ClockDrift",
    "Mode": "Mode",
    "check_mode": "Mode.check",
    "draw_roll_time": "draw_roll_time",
    "interval_after": "interval_after",
    "mode1_should_warn": "mode1_should_warn",
    "mode1_params": "mode1_lifetime",
    "mode2_params": "mode2_lifetime",
    # -- Constants ----------------------------------------------------------- #
    "DAY_S": "DAY_S",
    "NOMINAL_AGE_DAYS": "NOMINAL_AGE_DAYS",
    "SPREAD_DAYS": "SPREAD_DAYS",
    "MIN_BETWEEN_ROLLS_S": "MIN_BETWEEN_ROLLS_S",
    "ALARM_AFTER_S": "ALARM_AFTER_S",
    "DRIFT_NORMAL_S": "DRIFT_NORMAL_S",
    "DRIFT_WARNING_S": "DRIFT_WARNING_S",
    "DRIFT_JUMP_S": "DRIFT_JUMP_S",
    "MODE1_WARN_DAYS": "MODE1_WARN_DAYS",
    "MODE2_LIFETIME_DAYS": "MODE2_LIFETIME_DAYS",
    "MODE1_MIN_DAYS": "MODE1_MIN_DAYS",
    "MODE1_DEFAULT_DAYS": "MODE1_DEFAULT_DAYS",
    "MODE1_MAX_DAYS": "MODE1_MAX_DAYS",
    # -- Lock at rest and envelope ------------------------------------------- #
    "lock": "lock",
    "lock_with": ANNEN_FORM,  # Python has one AEAD (AES-GCM); the Alg choice is Rust-side (§6.0b)
    "seal_with": ANNEN_FORM,  # same
    "unlock": "unlock",
    "seal": "envelope_seal",
    "open": "envelope_open",
    "RecipientKey": "envelope_generate_key",
    "X25519_LEN": ANNEN_FORM,  # lengden sjekkes inline i `envelope_seal`/`envelope_open`
    # -- TLS setup ----------------------------------------------------------- #
    "SelfSignedParams": "self_signed",
    "pinned_client_config": "pinned_ssl_context",
    "TlsError": "NettlsError",
    # -- Storage: the agreed exception ---------------------------------------- #
    "TlsMaterial": LAGRING,
    "CertSource": LAGRING,
    "CertOrigin": LAGRING,
    "CERT_FILE": LAGRING,
    "KEY_FILE": LAGRING,
    "OwnMaterial": LAGRING,
    "Pending": LAGRING,
    "PENDING_FILE": LAGRING,
    "archive": LAGRING,
    "read_archive": LAGRING,
    "ARCHIVE_FILE": LAGRING,
    # -- Rust-internal -------------------------------------------------------- #
    "RotatingResolver": RUST_INTERN,  # rustls `ResolvesServerCert`
    "install_crypto_provider": RUST_INTERN,
    "provider": RUST_INTERN,
    "pinned_client_config_with_alpn": RUST_INTERN,  # ALPN is set directly on ctx
    # -- the channel's cipher (0.8.3, SPEC-nettls §6.0b): the policy is a rustls
    #    provider filter. Python's `ssl` speaks the default (AES-256-GCM) with
    #    OpenSSL's own suite list and can never speak our AEGIS suite — that is
    #    the point of the default, not a gap to fill. ------------------------- #
    "pinned_client_config_with": RUST_INTERN,
    "TransportCipher": RUST_INTERN,
    "TransportPolicy": RUST_INTERN,
    "CODEPOINT": RUST_INTERN,  # aegis: our private-use suite — Rust↔Rust only
    "suite": RUST_INTERN,  # aegis::suite()
    "p256_public_key": RUST_INTERN,  # `cryptography` does it internally
    "is_valid_san": ANNEN_FORM,  # `self_signed` validerer ved bygging
    "MAX_VALID_DAYS": ANNEN_FORM,  # dekkes av MODE1_MAX_DAYS
    # -- Types that exist only because Rust needs them ----------------------- #
    "AnnouncementJson": ANNEN_FORM,  # Python uses a dict directly
    "ReceiptJson": ANNEN_FORM,
    "ApprovalJson": ANNEN_FORM,
    "Received": ANNEN_FORM,  # Python returnerer "lagret"/"kjent"
    "Drift": ANNEN_FORM,  # Python returnerer "normal"/"logg"/"advarsel"
    "ModeCheck": ANNEN_FORM,  # Python returnerer None eller en message
    "ChainState": ANNEN_FORM,  # intern i Schedule
    "Status": ANNEN_FORM,  # Python har `countdown()`
    "Deviation": ANNEN_FORM,  # Python uses NettlsError
    "FallToMode1": ANNEN_FORM,
    "Trust": ANNEN_FORM,  # Python bygger SSLContext per forbindelse
    # -- the version anchor (0.8.2) -------------------------------------------- #
    "VERSION": ANNEN_FORM,  # Python: nettls.__version__ — guarded against the VERSION file
    # -- the status report (0.8.2): the About contribution. The consumer-facing
    #    JSON SHAPE is the contract (docs/API.md §status); the consumer builds
    #    the same shape — a twin helper can come with the issuance work. ------ #
    "Level": ANNEN_FORM,
    "PeerState": ANNEN_FORM,
    "PeerReport": ANNEN_FORM,
    "IdentityReport": ANNEN_FORM,
    "RotationReport": ANNEN_FORM,
    "Report": ANNEN_FORM,
    "Summary": ANNEN_FORM,
    # -- AEAD capability (0.8.2): Python HAS the surface (algsupport_v1,
    #    build/verify_support_statement, choose_alg, AEAD_TOKENS) — these map
    #    the Rust-side names that differ in form. ---------------------------- #
    "SupportStatement": "build_support_statement",  # dict + build/verify on the Python side
    "choose": "choose_alg",
    "alg_token": "AEAD_TOKENS",  # the token vocabulary is a tuple in Python
    "alg_from_token": "AEAD_TOKENS",
    "ALGSUPPORT_V1": "ALGSUPPORT_V1",
    "algsupport_v1": "algsupport_v1",
    # -- PEM building (0.8.1, wish #2): Python uses cryptography's own
    #    serialization — the PEM a consumer builds is byte-identical either way. #
    "encode": RUST_INTERN,
    # -- Test helpers --------------------------------------------------------- #
    "pkcs8_for_test": TESTHJELPER,
    "pem_encode_for_test": TESTHJELPER,
    "fingerprint_for_test": TESTHJELPER,
}


def rust_offentlig_flate() -> set[str]:
    """Everything that is `pub` at module level in the crate.

    Reads the source as text rather than asking `cargo doc --output-format
    json`, which requires nightly. The heuristic is deliberately strict: only
    `pub` at the far left, i.e. module level — `pub(crate)` and `pub` inside an
    `impl` are not matched, and must not be.
    """
    ut: set[str] = set()
    for fil in sorted((ROT / "src").glob("*.rs")):
        for m in re.finditer(
            r"^pub (?:fn|struct|enum|const|type) ([a-zA-Z_][a-zA-Z0-9_]*)",
            fil.read_text(),
            re.M,
        ):
            ut.add(m.group(1))
    return ut


def test_the_surface_was_actually_read():
    """Control: are we reading anything at all?

    Without it, a changed file structure or a broken expression would yield an
    empty set — and an empty comparison always passes.
    """
    flate = rust_offentlig_flate()
    assert len(flate) > 80, f"read only {len(flate)} elements — are we parsing right?"
    for kjerne in ("Announcement", "Generations", "from_hex", "lock", "seal"):
        assert kjerne in flate, f"«{kjerne}» is missing — the parser does not match"


@pytest.mark.parametrize("name", sorted(rust_offentlig_flate()))
def test_everything_in_rust_has_a_written_decision(name):
    """Every public element of the crate is either mirrored or justified.

    If this fails, the answer is **not** to add the name to the mapping to get
    green. The question is whether `nettls.py` should have had a counterpart —
    and if not, why. The reason remains for whoever reads the code in a year.
    """
    assert name in TILORDNING, (
        f"«{name}» is public in the crate, but is not in TILORDNING.\n"
        f"Take a position: either build a counterpart in nettls.py and list it "
        f"here, or list it with one of the reasons {sorted(GRUNNER)}.\n"
        f"Five gaps were found 2026-08-11 precisely because nothing required "
        f"anyone to take a position."
    )


@pytest.mark.parametrize(
    "rust_navn,py_navn",
    sorted((r, p) for r, p in TILORDNING.items() if p not in GRUNNER),
)
def test_the_mirrored_actually_exist_in_python(rust_navn, py_navn):
    """A mapping pointing at something that does not exist is worse than none."""
    obj = n
    for del_ in py_navn.split("."):
        assert hasattr(obj, del_), (
            f"TILORDNING says Rust's «{rust_navn}» is mirrored by «{py_navn}» "
            f"in nettls.py — but «{del_}» does not exist there"
        )
        obj = getattr(obj, del_)


def test_no_stale_entries():
    """If something is removed from Rust, the entry must be cleaned away.

    Otherwise the mapping grows into a list of things that once existed, and
    then it stops saying anything about the present.
    """
    flate = rust_offentlig_flate()
    foreldet = sorted(set(TILORDNING) - flate)
    assert not foreldet, (
        f"TILORDNING mentions {foreldet}, which is no longer public in the "
        f"crate. Clean the entry away."
    )


def test_everything_python_exports_is_known():
    """The other direction: does Python have something the crate does not?

    Not necessarily wrong — but it must be a deliberate addition, not
    something that has grown. Without this, Python could drift in its own
    direction without anything speaking up.
    """
    speilet = {p.split(".")[0] for p in TILORDNING.values() if p not in GRUNNER}
    # Additions that deliberately exist only in Python.
    kjente_tillegg = {
        "BAKDATERING_S",  # named in Python; inline constant in Rust
        "envelope_public",  # a derivation Rust does via RecipientKey
        "verify_support_statement",  # Rust: SupportStatement::verify (mapped via build_)
        "mode1_lifetime",
        "mode2_lifetime",
        # Since 0.8.0 the Rust side encodes via krypto::hex; the Python twin
        # (which has no krypto binding) keeps its own. Byte parity is proven
        # by the test vectors and the cross-test.
        "to_hex",
    }
    ukjent = sorted(set(n.__all__) - speilet - kjente_tillegg)
    assert not ukjent, (
        f"nettls.py exports {ukjent} without a counterpart in the crate and "
        f"without standing as a deliberate addition. Either it belongs in both, "
        f"or it must be justified here."
    )
