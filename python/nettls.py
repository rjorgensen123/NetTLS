# SPDX-License-Identifier: MIT OR Apache-2.0
"""nettls — the Python implementation of SPEC-nettls §6.

`nettls` owns the communication, and therefore **the contract**. The Rust side
is not "the original" and this file is not "a port" — both are implementations
of the same contract, which is §6 plus the test vectors in
`../testvectors/canonical.json`.

That has a practical consequence: when a vector fails, the question is *"which
of the two is right according to the specification"* — not *"Python must
conform to Rust"*. Last time, Rust had chosen hex and Python base64, and
neither was wrong until the spec said which one it should be.

## No app dependencies

The only dependency is ``cryptography``. No logging setup, no database, no
FastAPI, no ``PeerTrust`` types. That is what makes this file reusable — and
the requirement is recorded as M-10c.

## What is NOT here yet

Locking local state at rest (§8.4) requires argon2id, which does not exist in
``cryptography`` before v44. It arrives as its own item; the protocol below is
complete without it.
"""


from __future__ import annotations

def _crate_version() -> str:
    """The crate version, read from the one place that declares it.

    `Cargo.toml` is the single declaration. The Rust side derives from it through
    `env!("CARGO_PKG_VERSION")`; this side reads the same file. A derived value
    cannot drift from its source, which is why nothing guards the two against each
    other — there are not two of them.

    Returns "unknown" when the module is used away from the repository, which is a
    real case: someone copies this file out on its own. A missing manifest is not a
    reason to refuse to import.
    """
    import pathlib as _p
    import re as _re

    manifest = _p.Path(__file__).resolve().parent.parent / "Cargo.toml"
    try:
        lines = manifest.read_text(encoding="utf-8").splitlines()
    except OSError:
        return "unknown"
    in_package = False
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("["):
            # Only `[package]` declares the crate's own version; a `version =`
            # further down belongs to a dependency.
            if in_package:
                break
            in_package = stripped == "[package]"
            continue
        if in_package:
            m = _re.match(r'version\s*=\s*"([^"]+)"', stripped)
            if m:
                return m.group(1)
    return "unknown"


#: The twin follows the crate — derived from `Cargo.toml`, never written twice.
__version__ = _crate_version()

import hashlib
import json
import re
import ssl
import tempfile
import unicodedata
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.x509.oid import NameOID

__all__ = [
    "NettlsError",
    "APPROVE_V1",
    "ROTATE_V2",
    "ROTATE_ACK_V2",
    "PAIRSECRET_V1",
    "ALGSUPPORT_V1",
    "algsupport_v1",
    "build_support_statement",
    "verify_support_statement",
    "choose_alg",
    "to_hex",
    "from_hex",
    "fingerprint_from_der",
    "fingerprint_from_pem",
    "approve_v1",
    "rotate_v2",
    "rotate_ack_v2",
    "pairsecret_v1",
    "Announcement",
    "Receipt",
    "Approval",
    "Recognition",
    "Context",
    "Generation",
    "Generations",
    "Mode",
    "mode1_should_warn",
    "mode1_lifetime",
    "mode2_lifetime",
    "BAKDATERING_S",
    "Schedule",
    "Announcer",
    "ClockDrift",
    "pinned_ssl_context",
    "self_signed",
    "lock",
    "unlock",
    "envelope_seal",
    "envelope_open",
    "envelope_generate_key",
    "envelope_public",
]


class NettlsError(Exception):
    """Everything that goes wrong here. Fail-closed: we never guess."""


# --------------------------------------------------------------------------- #
# Canonical strings (§6.4, §6.5, §6.6, §8.5b)
# --------------------------------------------------------------------------- #

APPROVE_V1 = "nettls-approve/v1"
ROTATE_V2 = "nettls-rotate/v2"
ROTATE_ACK_V2 = "nettls-rotate-ack/v2"
PAIRSECRET_V1 = "nettls-pairsecret/v1"
ALGSUPPORT_V1 = "nettls-algsupport/v1"

#: Wire tokens for AEADs (krypto-cli's vocabulary) in the FIXED canonical/
#: preference order. Python's `cryptography` has no AEGIS — a Python party
#: typically declares ["aes256gcm"].
AEAD_TOKENS = ("aegis256", "xchacha20", "aes256gcm")


def _assemble(lines: list[str]) -> bytes:
    """LF between lines, **no** trailing LF.

    That last one is invisible in a text editor and changes the signature
    completely. That is why the tests compare exact bytes, not strings.
    """
    return "\n".join(lines).encode("utf-8")


def require_fingerprint(v: str, field: str) -> None:
    """64 lowercase hex characters, without a ``sha256:`` prefix.

    Validated at construction, not at use: a value that ends up inside a
    signed string must never be able to carry a line break into the format.
    With a line break the field would have become **two** lines, and an
    attacker could then have moved content within the message without
    touching the signature.
    """
    if len(v) != 64 or any(c not in "0123456789abcdef" for c in v):
        raise NettlsError(
            f"{field}: expected 64 lowercase hex characters without a "
            f"«sha256:» prefix, got {len(v)} characters"
        )


def _require_str(j: dict, field: str) -> str:
    """Fail-closed field access: present, and a string (§6.5).

    A ``KeyError`` or ``TypeError`` escaping would mean the field was never
    validated — it just happened to crash further in. Our caller catches
    ``NettlsError`` and nothing else (M-38/M-39).
    """
    v = j.get(field)
    if not isinstance(v, str):
        raise NettlsError(
            f"{field}: missing or not a string (got {type(v).__name__})"
        )
    return v


def _require_int(j: dict, field: str) -> int:
    """Fail-closed integer: present, an int — **never a silent conversion**.

    ``int(1.7) == 1`` truncates silently, and ``int("100")`` converts a type
    the contract does not allow. Both are rejected: what goes into a signed
    string must be exactly what was sent (§6.5). ``bool`` is rejected too —
    it is an ``int`` subclass in Python, and ``true`` is not a timestamp.
    """
    v = j.get(field)
    if not isinstance(v, int) or isinstance(v, bool):
        raise NettlsError(
            f"{field}: missing or not an integer (got {type(v).__name__}) — "
            f"floats and strings are never converted silently"
        )
    return v


#: Upper bound for an incoming certificate PEM (D-item, mirrors Rust).
MAX_CERT_PEM_LEN = 16 * 1024

_COMPONENT_NAME = re.compile(r"^[a-z0-9-]{1,32}$")


def require_component_name(v: str, field: str) -> None:
    """A component name (`gateway`, `service`, `portal`) — enforced exactly as
    SPEC-nettls §6.5 writes it: ``[a-z0-9-]{1,32}``.

    Stricter than :func:`require_name`, on purpose (decided 2026-08-13): a
    protocol where ``Gateway`` and ``gateway`` both get in is a protocol where two
    implementations can produce different bytes for the same party. Usernames
    (``approved_by``) are a different category and keep the looser rule.
    """
    if not v:
        raise NettlsError(f"{field}: cannot be empty")
    if len(v) > 32:
        raise NettlsError(f"{field}: too long (max 32 characters for a component name)")
    if not _COMPONENT_NAME.match(v):
        bad = next(c for c in v if not ("a" <= c <= "z" or "0" <= c <= "9" or c == "-"))
        raise NettlsError(
            f"{field}: the character {bad!r} is outside [a-z0-9-] — component names "
            f"are lowercase ASCII, digits and hyphens (§6.5)"
        )


def require_name(v: str, field: str, max_len: int) -> None:
    """A name field that goes into a signed string.

    Control characters are rejected as the **Unicode category ``Cc``**, not as
    a hand-picked selection. That is exactly what Rust's ``char::is_control()``
    does, and the two sides must reject the same things.

    The first version here checked ``ord(c) < 0x20 or ord(c) == 0x7F`` and
    thereby let the C1 range U+0080–U+009F through — among them U+0085 NEL,
    which *is* a line break in several contexts. Rust rejected them. A name
    Python accepted and Rust refused to read would have caused a one-sided
    interop stop — and no test could see it, because the cross-tests only try
    **valid** values.
    """
    if not v:
        raise NettlsError(f"{field}: cannot be empty")
    if len(v) > max_len:
        raise NettlsError(f"{field}: too long (max {max_len} characters)")
    for c in v:
        if unicodedata.category(c) == "Cc":
            raise NettlsError(
                f"{field}: contains a control character (U+{ord(c):04X}) that "
                f"would have broken the line structure"
            )


def approve_v1(peer: str, fingerprint: str, approved_by: str, timestamp: int) -> bytes:
    """§6.4 — the operator's approval, generation 0."""
    require_component_name(peer, "peer")
    require_fingerprint(fingerprint, "fingerprint")
    require_name(approved_by, "approved_by", 64)
    return _assemble([APPROVE_V1, peer, fingerprint, approved_by, str(timestamp)])


def rotate_v2(
    announcer: str,
    prev_fp: str | None,
    curr_fp: str,
    new_fp: str,
    sent_at: int,
) -> bytes:
    """§6.5 — the announcement: "here is my next certificate".

    ``prev_fp`` is ``None`` only at the **first** rotation and is then
    serialized as ``-``. So the field does not disappear: a field that
    disappeared would have made the next line move up and mean something else.
    """
    require_component_name(announcer, "announcer")
    if prev_fp is not None:
        require_fingerprint(prev_fp, "prev_fp")
    require_fingerprint(curr_fp, "curr_fp")
    require_fingerprint(new_fp, "new_fp")
    return _assemble(
        [ROTATE_V2, announcer, prev_fp or "-", curr_fp, new_fp, str(sent_at)]
    )


def rotate_ack_v2(acker: str, announcer: str, new_fp: str, sent_at: int) -> bytes:
    """§6.6 — the receipt: "I have stored your next certificate"."""
    require_component_name(acker, "acker")
    require_component_name(announcer, "announcer")
    require_fingerprint(new_fp, "new_fp")
    return _assemble([ROTATE_ACK_V2, acker, announcer, new_fp, str(sent_at)])


def pairsecret_v1(
    a: str, b: str, sealed_a_sha256: str, sealed_b_sha256: str, sent_at: int
) -> bytes:
    """§8.5b — rotation of the pair secret. Signed by **both** parties."""
    require_component_name(a, "a")
    require_component_name(b, "b")
    require_fingerprint(sealed_a_sha256, "sealed_a_sha256")
    require_fingerprint(sealed_b_sha256, "sealed_b_sha256")
    return _assemble(
        [PAIRSECRET_V1, a, b, sealed_a_sha256, sealed_b_sha256, str(sent_at)]
    )


# --------------------------------------------------------------------------- #
# Hex — the one legal serialization (§6.5)
# --------------------------------------------------------------------------- #

def algsupport_v1(component: str, algs: str, timestamp: int) -> bytes:
    """The signed AEAD support statement (0.8.2) — canonical bytes.

    Fail-closed on the token list: unknown tokens, duplicates, an empty list
    or a non-canonical order are rejected — two spellings of the same support
    set must not exist.
    """
    require_component_name(component, "component")
    if not algs:
        raise NettlsError("algs: cannot be empty")
    last = -1
    for token in algs.split(","):
        if token not in AEAD_TOKENS:
            raise NettlsError(
                f"algs: unknown token {token!r} — known: aegis256, xchacha20, aes256gcm"
            )
        pos = AEAD_TOKENS.index(token)
        if pos <= last:
            raise NettlsError(
                f"algs: token {token!r} out of canonical order or duplicated"
            )
        last = pos
    return _assemble([ALGSUPPORT_V1, component, algs, str(timestamp)])


def build_support_statement(
    component: str, supported: list[str], timestamp: int, private_key_pem: str
) -> dict:
    """Build and sign the statement with the party's TLS anchor (P-256).

    `supported` is wire tokens; normalized into canonical order. Returns the
    JSON-ready dict ({component, supported, timestamp, signature-hex}) — the
    same shape the Rust side serializes.
    """
    tokens = [t for t in AEAD_TOKENS if t in supported]
    if len(tokens) != len(supported):
        raise NettlsError(
            "a support statement may only declare known algorithms, once each"
        )
    if not tokens:
        raise NettlsError("a support statement must declare at least one algorithm")
    bytes_ = algsupport_v1(component, ",".join(tokens), timestamp)
    signature = sign_p256(private_key_pem, bytes_).hex()
    return {
        "component": component,
        "supported": tokens,
        "timestamp": timestamp,
        "signature": signature,
    }


def verify_support_statement(statement: dict, signer_cert_der: bytes) -> list[str]:
    """Verify against the signer's pinned certificate; return the declared tokens.

    Fail-closed the whole way — an unverifiable statement authorizes nothing.
    """
    bytes_ = algsupport_v1(
        statement["component"],
        ",".join(statement["supported"]),
        statement["timestamp"],
    )
    verify_p256(signer_cert_der, bytes_, bytes.fromhex(statement["signature"]))
    return list(statement["supported"])


def choose_alg(requested: str, verified_supported: list[str] | None) -> str:
    """The fallback rule (the decided pattern):

    no statement → the requested stands; a verified statement without it →
    the best declared by preference order; nothing acceptable → hard failure.
    Never silently weaker.
    """
    if verified_supported is None:
        return requested
    if requested in verified_supported:
        return requested
    for candidate in AEAD_TOKENS:
        if candidate in verified_supported:
            return candidate
    raise NettlsError(
        "AEAD negotiation failed (the connection must fail — never silently "
        f"weaken): requested {requested}; declared: {', '.join(verified_supported) or 'nothing'}"
    )



def to_hex(b: bytes) -> str:
    """Bytes → lowercase hex."""
    return b.hex()


def from_hex(s: str) -> bytes:
    """Hex → bytes. **Fail-closed.**

    Uppercase is rejected. Stricter than necessary just to *read*, but a
    protocol where both ``AB`` and ``ab`` go in is a protocol where two
    implementations can produce different bytes for the same value without
    anyone noticing.
    """
    if not s:
        raise NettlsError("empty hex string")
    if len(s) % 2:
        raise NettlsError(f"hex must have an even number of characters, got {len(s)}")
    if any(c.isupper() for c in s):
        raise NettlsError("hex is written in lowercase (§6.5)")
    if any(c.isspace() for c in s):
        # `bytes.fromhex` ignores whitespace; Rust rejects it. The two sides
        # must reject the same things (§6.14b).
        raise NettlsError("hex must not contain whitespace")
    try:
        return bytes.fromhex(s)
    except ValueError as e:
        raise NettlsError(f"invalid hex: {e}") from e


# --------------------------------------------------------------------------- #
# Fingerprints
# --------------------------------------------------------------------------- #


def fingerprint_from_der(der: bytes) -> str:
    """SHA-256 over the certificate's DER, hex without a prefix."""
    return hashlib.sha256(der).hexdigest()


def der_from_pem(pem: str) -> bytes:
    """PEM → DER. Fail-closed on anything that is not exactly one CERTIFICATE block."""
    blocks = [b for b in pem.split("-----BEGIN CERTIFICATE-----") if "END CERTIFICATE" in b]
    if not blocks:
        raise NettlsError("found no CERTIFICATE block in the PEM")
    if len(blocks) > 1:
        raise NettlsError(
            "the PEM contains multiple certificates — an announcement carries exactly one"
        )
    # `cryptography` raises `ValueError` on a broken PEM. It MUST be wrapped:
    # our caller catches `NettlsError` and nothing else, and a foreign
    # exception type from a hostile peer would have gone straight through the
    # error handling. The Rust side wraps it correspondingly in `TlsError::Pem`.
    try:
        cert = x509.load_pem_x509_certificate(pem.encode())
    except Exception as e:  # noqa: BLE001
        raise NettlsError(f"invalid PEM: {e}") from e
    return cert.public_bytes(serialization.Encoding.DER)


def fingerprint_from_pem(pem: str) -> str:
    """The fingerprint of a PEM certificate."""
    return fingerprint_from_der(der_from_pem(pem))


# --------------------------------------------------------------------------- #
# Signatures (§6.5, §6.6b)
# --------------------------------------------------------------------------- #


def verify_p256(cert_der: bytes, message: bytes, signature: bytes) -> None:
    """ECDSA P-256 against **the issuer's certificate**.

    The certificate, not the fingerprint, has to go in: a fingerprint is a
    hash, and a public key cannot be derived from it. That is the whole reason
    the announcement carries the certificate in full.
    """
    try:
        cert = x509.load_der_x509_certificate(cert_der)
    except Exception as e:  # noqa: BLE001 — foreign exception types must not escape
        raise NettlsError(f"invalid certificate DER: {e}") from e
    pk = cert.public_key()
    if not isinstance(pk, ec.EllipticCurvePublicKey) or not isinstance(
        pk.curve, ec.SECP256R1
    ):
        raise NettlsError(
            "the certificate is not ECDSA P-256 — §6 signatures are defined for P-256"
        )
    try:
        pk.verify(signature, message, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature as e:
        raise NettlsError(
            "the ECDSA P-256 signature does not hold against the issuer's certificate"
        ) from e


def sign_p256(private_key_pem: str, message: bytes) -> bytes:
    """Sign with a P-256 private key (PEM)."""
    try:
        k = serialization.load_pem_private_key(private_key_pem.encode(), password=None)
    except Exception as e:  # noqa: BLE001 — foreign exception types must not escape
        raise NettlsError(f"invalid private key PEM: {e}") from e
    if not isinstance(k, ec.EllipticCurvePrivateKey):
        raise NettlsError("the private key is not ECDSA")
    return k.sign(message, ec.ECDSA(hashes.SHA256()))


def verify_ed25519(pubkey: bytes, message: bytes, signature: bytes) -> None:
    """Ed25519 against a **raw** 32-byte public key.

    Raw and not DER, because that is the form the services already distribute.
    """
    if len(pubkey) != 32:
        raise NettlsError(
            f"Ed25519 public key must be 32 bytes, got {len(pubkey)}"
        )
    try:
        ed25519.Ed25519PublicKey.from_public_bytes(pubkey).verify(signature, message)
    except InvalidSignature as e:
        raise NettlsError("the Ed25519 signature does not hold") from e


def sign_ed25519(seed: bytes, message: bytes) -> bytes:
    """Sign with a raw 32-byte Ed25519 seed."""
    if len(seed) != 32:
        raise NettlsError(f"Ed25519 seed must be 32 bytes, got {len(seed)}")
    return ed25519.Ed25519PrivateKey.from_private_bytes(seed).sign(message)


def ed25519_public_from_seed(seed: bytes) -> bytes:
    """The public key belonging to an Ed25519 seed."""
    if len(seed) != 32:
        raise NettlsError(f"Ed25519 seed must be 32 bytes, got {len(seed)}")
    return (
        ed25519.Ed25519PrivateKey.from_private_bytes(seed)
        .public_key()
        .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    )


# --------------------------------------------------------------------------- #
# The announcement (§6.5)
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Announcement:
    """"Here is my next certificate."

    Two signatures, from **previous** and **current**. Forging it requires two
    consecutive private keys.

    ``prev_fp``/``sig_prev`` are ``None`` only at the **first** rotation,
    where ``cert0`` is the only key that exists (§6.3).
    """

    announcer: str
    prev_fp: str | None
    curr_fp: str
    new_fp: str
    new_cert_pem: str
    sent_at: int
    sig_prev: bytes | None
    sig_curr: bytes

    @staticmethod
    def new(
        announcer: str,
        prev: tuple[str, str] | None,
        curr: tuple[str, str],
        new_cert_pem: str,
        sent_at: int,
    ) -> Announcement:
        """Build and sign. ``prev``/``curr`` are ``(fingerprint, private_pem)``."""
        new_fp = fingerprint_from_pem(new_cert_pem)
        prev_fp = prev[0] if prev else None
        message = rotate_v2(announcer, prev_fp, curr[0], new_fp, sent_at)
        return Announcement(
            announcer=announcer,
            prev_fp=prev_fp,
            curr_fp=curr[0],
            new_fp=new_fp,
            new_cert_pem=new_cert_pem,
            sent_at=sent_at,
            sig_prev=sign_p256(prev[1], message) if prev else None,
            sig_curr=sign_p256(curr[1], message),
        )

    def canonical(self) -> bytes:
        return rotate_v2(
            self.announcer, self.prev_fp, self.curr_fp, self.new_fp, self.sent_at
        )

    def verify(self, prev_cert_der: bytes | None, curr_cert_der: bytes) -> None:
        """Verify against the receiver's **own** state.

        That the condition for a single signature is tied to the *receiver's*
        state and not to a field in the message is the whole point: otherwise
        an attacker could have asked to be let through by omitting ``prev``.

        The order is not arbitrary either. **The fingerprint is checked
        first**: if the certificate was swapped in transit, that must be
        discovered before we use that key for anything at all.
        """
        actual = fingerprint_from_pem(self.new_cert_pem)
        if actual != self.new_fp:
            raise NettlsError(
                f"new_cert_pem hashes to {actual}, but the announcement says "
                f"{self.new_fp} — the certificate was swapped in transit"
            )

        curr_actual = fingerprint_from_der(curr_cert_der)
        if curr_actual != self.curr_fp:
            raise NettlsError(
                f"the announcement is issued by {self.curr_fp}, but we know "
                f"{curr_actual} as current — we have missed a rotation, "
                f"or this is a different instance"
            )

        message = self.canonical()
        verify_p256(curr_cert_der, message, self.sig_curr)

        if prev_cert_der is not None:
            if self.prev_fp is None or self.sig_prev is None:
                raise NettlsError(
                    "the announcement is single-signed, but we already have a previous "
                    "certificate — two signatures are required from rotation 2 onward (§6.3)"
                )
            prev_actual = fingerprint_from_der(prev_cert_der)
            if prev_actual != self.prev_fp:
                raise NettlsError(
                    f"the announcement states {self.prev_fp} as previous, we have {prev_actual}"
                )
            verify_p256(prev_cert_der, message, self.sig_prev)
        elif self.prev_fp is not None:
            # The receiver holds only an anchor, but the announcement is
            # double-signed: the announcer is mid-life and does not know we
            # (re)anchored. A8 (decided 2026-08-14): generation numbering is
            # LOCAL to the receiver — we verify what we CAN (sig_curr against
            # the anchor, already done above), and the stated prev, which we
            # cannot check, is not grounds for rejection. Security equals
            # bootstrap; covers restart-with-loss AND the late joiner.
            pass

    def to_json(self) -> dict:
        d = {
            "v": ROTATE_V2,
            "announcer": self.announcer,
            "curr_fingerprint": self.curr_fp,
            "new_fingerprint": self.new_fp,
            "new_cert_pem": self.new_cert_pem,
            "sent_at": self.sent_at,
            "sig_curr": to_hex(self.sig_curr),
        }
        if self.prev_fp is not None:
            d["prev_fingerprint"] = self.prev_fp
        if self.sig_prev is not None:
            d["sig_prev"] = to_hex(self.sig_prev)
        return d

    @staticmethod
    def from_json(j: dict) -> Announcement:
        if j.get("v") != ROTATE_V2:
            raise NettlsError(
                f"unknown message version «{j.get('v')}», expected «{ROTATE_V2}»"
            )
        require_component_name(_require_str(j, "announcer"), "announcer")
        pem = _require_str(j, "new_cert_pem")
        if len(pem) > MAX_CERT_PEM_LEN:
            # DoS surface: the PEM comes straight off the network (D-item).
            raise NettlsError(
                f"new_cert_pem is {len(pem)} bytes — above the cap of "
                f"{MAX_CERT_PEM_LEN}; that is not a certificate"
            )
        require_fingerprint(_require_str(j, "curr_fingerprint"), "curr_fingerprint")
        require_fingerprint(_require_str(j, "new_fingerprint"), "new_fingerprint")
        prev_fp = j.get("prev_fingerprint")
        sig_prev = j.get("sig_prev")
        if prev_fp is not None:
            require_fingerprint(prev_fp, "prev_fingerprint")
        if (prev_fp is None) != (sig_prev is None):
            raise NettlsError(
                "prev_fingerprint and sig_prev must either both be present or both be absent"
            )
        return Announcement(
            announcer=j["announcer"],
            prev_fp=prev_fp,
            curr_fp=j["curr_fingerprint"],
            new_fp=j["new_fingerprint"],
            new_cert_pem=_require_str(j, "new_cert_pem"),
            sent_at=_require_int(j, "sent_at"),
            sig_prev=from_hex(sig_prev) if sig_prev else None,
            sig_curr=from_hex(_require_str(j, "sig_curr")),
        )

    @property
    def is_bootstrap(self) -> bool:
        return self.prev_fp is None


# --------------------------------------------------------------------------- #
# The receipt (§6.6)
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Receipt:
    """"I have stored your next certificate."

    **One** signature, with Ed25519 (§6.6b). Two signatures protect
    *continuity*, and a receipt moves no identity — it confirms reception.
    What it needs is authenticity.
    """

    acker: str
    announcer: str
    new_fp: str
    sent_at: int
    sig: bytes

    @staticmethod
    def new(
        acker: str, announcer: str, new_fp: str, sent_at: int, ed25519_seed: bytes
    ) -> Receipt:
        message = rotate_ack_v2(acker, announcer, new_fp, sent_at)
        return Receipt(acker, announcer, new_fp, sent_at, sign_ed25519(ed25519_seed, message))

    def canonical(self) -> bytes:
        return rotate_ack_v2(self.acker, self.announcer, self.new_fp, self.sent_at)

    def verify(self, pinned_pubkey: bytes, expected_new_fp: str) -> None:
        """Against the acker's pinned key **and** what we actually announced.

        Both have to go in. A receipt that is genuine but concerns a
        *different* rotation is a replay — and it must not make us roll.
        """
        if self.new_fp != expected_new_fp:
            raise NettlsError(
                f"the receipt concerns {self.new_fp}, but we announced "
                f"{expected_new_fp} — this is a receipt for a different rotation"
            )
        verify_ed25519(pinned_pubkey, self.canonical(), self.sig)

    def to_json(self) -> dict:
        return {
            "v": ROTATE_ACK_V2,
            "acker": self.acker,
            "announcer": self.announcer,
            "new_fingerprint": self.new_fp,
            "sent_at": self.sent_at,
            "sig": to_hex(self.sig),
        }

    @staticmethod
    def from_json(j: dict) -> Receipt:
        if j.get("v") != ROTATE_ACK_V2:
            raise NettlsError(
                f"unknown message version «{j.get('v')}», expected «{ROTATE_ACK_V2}»"
            )
        require_component_name(_require_str(j, "acker"), "acker")
        require_component_name(_require_str(j, "announcer"), "announcer")
        require_fingerprint(_require_str(j, "new_fingerprint"), "new_fingerprint")
        return Receipt(
            j["acker"],
            j["announcer"],
            j["new_fingerprint"],
            _require_int(j, "sent_at"),
            from_hex(_require_str(j, "sig")),
        )


# --------------------------------------------------------------------------- #
# Generation 0 (§6.4)
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Approval:
    """The operator's approval, expressed as a signature.

    Not an act of trust the app interprets, but a signature — and the actor is
    **inside** the signed string: a signature that does not cover who acted
    does not say who acted.
    """

    peer: str
    fingerprint: str
    approved_by: str
    timestamp: int
    key_id: str
    sig: bytes

    @staticmethod
    def new(
        peer: str,
        fingerprint: str,
        approved_by: str,
        timestamp: int,
        key_id: str,
        ed25519_seed: bytes,
    ) -> Approval:
        require_name(key_id, "key_id", 64)
        message = approve_v1(peer, fingerprint, approved_by, timestamp)
        return Approval(
            peer, fingerprint, approved_by, timestamp, key_id,
            sign_ed25519(ed25519_seed, message),
        )

    def canonical(self) -> bytes:
        return approve_v1(self.peer, self.fingerprint, self.approved_by, self.timestamp)

    def verify(self, lookup_key) -> None:
        """Against the pinned key for ``key_id``.

        That the lookup comes from outside is the point of ``key_id``: if the
        operator one day moves from portal-attested to their own key, the lookup
        changes — not the message form and not this function.
        """
        pk = lookup_key(self.key_id)
        if pk is None:
            raise NettlsError(
                f"the approval is signed with «{self.key_id}», which does not exist "
                f"in the key registry — we cannot verify the anchor, and then it "
                f"is not an anchor"
            )
        verify_ed25519(pk, self.canonical(), self.sig)

    def to_json(self) -> dict:
        return {
            "v": APPROVE_V1,
            "peer": self.peer,
            "fingerprint": self.fingerprint,
            "approved_by": self.approved_by,
            "timestamp": self.timestamp,
            "key_id": self.key_id,
            "sig": to_hex(self.sig),
        }

    @staticmethod
    def from_json(j: dict) -> Approval:
        if j.get("v") != APPROVE_V1:
            raise NettlsError(
                f"unknown message version «{j.get('v')}», expected «{APPROVE_V1}»"
            )
        require_component_name(_require_str(j, "peer"), "peer")
        require_fingerprint(_require_str(j, "fingerprint"), "fingerprint")
        require_name(_require_str(j, "approved_by"), "approved_by", 64)
        require_name(_require_str(j, "key_id"), "key_id", 64)
        return Approval(
            j["peer"], j["fingerprint"], j["approved_by"],
            _require_int(j, "timestamp"), j["key_id"], from_hex(_require_str(j, "sig")),
        )


# --------------------------------------------------------------------------- #
# The generation pair (§6.3)
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Generation:
    """One certificate with its fingerprint."""

    der: bytes
    fp: str

    @staticmethod
    def from_der(der: bytes) -> Generation:
        return Generation(der, fingerprint_from_der(der))

    @staticmethod
    def from_pem(pem: str) -> Generation:
        der = der_from_pem(pem)
        return Generation(der, fingerprint_from_der(der))

    @property
    def pem(self) -> str:
        return (
            x509.load_der_x509_certificate(self.der)
            .public_bytes(serialization.Encoding.PEM)
            .decode()
        )


class Generations:
    """``(previous, current)`` + ``next`` for **one** peer.

    ## Two roles, and they do not overlap

    | Role | Which |
    |---|---|
    | Accepted in the **handshake** | ``current`` + ``next`` |
    | Verifies **announcements** | ``previous`` + ``current`` |

    ``previous`` thus lets **no one in** after the switch is observed — it is
    kept to verify the next announcement. Merging the roles would have given a
    wider window than necessary, and the width of the window is the whole
    reason a leaked old key stops having value.
    """

    def __init__(self, current: Generation) -> None:
        self.previous: Generation | None = None
        self.current: Generation = current
        self.next: Generation | None = None

    @staticmethod
    def restore(
        previous: Generation | None,
        current: Generation,
        next: Generation | None,
    ) -> Generations:
        """Restore the state **the consumer itself has remembered** (§6.8).

        Without this the API was asymmetric: the state could be read out, but
        only rebuilt from a single anchor. A service that had written
        everything down thus could not put it back — and then **every**
        restart looked like memory loss. An announcement from a peer that has
        already rolled states a ``previous`` we do not know, and §6.3
        rightfully rejects it. The pair could thus not rotate again without an
        operator, even though only one process had restarted.

        **The storage is not owned by this module.** `nettls` is a library and
        has no opinion about where the service stores anything. The service
        remembers; the module offers the way back.

        **Nothing is verified** — there is nothing to verify against. The
        caller vouches that the content comes from the service's own,
        unaltered storage. Whoever can alter the storage chooses whom we
        trust.

        The one thing enforced is the shape: a state that cannot arise from a
        legal rotation is rejected.
        """
        for name, g in (("previous", previous), ("next", next)):
            if g is not None and g.fp == current.fp:
                raise NettlsError(
                    f"restored state has «{name}» equal to «current» "
                    f"({current.fp}) — that cannot arise from a legal rotation"
                )
        if previous is not None and next is not None and previous.fp == next.fp:
            raise NettlsError(
                f"restored state has «previous» equal to «next» ({previous.fp}) "
                f"— the peer cannot rotate back to a certificate it "
                f"just left"
            )
        g = Generations(current)
        g.previous = previous
        g.next = next
        return g

    def receive(self, k: Announcement) -> str:
        """Verify against **our own** state and store the new one.

        Returns ``"lagret"`` (stored) or ``"kjent"`` (known). Idempotent: the
        peer republishes the same one until it gets a receipt (§6.8a), and
        that must not be an error.
        """
        if self.next is not None and self.next.fp == k.new_fp:
            return "kjent"
        k.verify(self.previous.der if self.previous else None, self.current.der)
        self.next = Generation.from_pem(k.new_cert_pem)
        return "lagret"

    def observed(self, fp: str) -> bool:
        """**The observation is the promotion** (§6.7).

        Not a point in time, not a message. That is what makes the rotation
        require no coordination at all.
        """
        if self.next is None or self.next.fp != fp:
            return False
        self.previous, self.current, self.next = self.current, self.next, None
        return True

    def accepted_in_handshake(self) -> list[Generation]:
        out = [self.current]
        if self.next is not None:
            out.append(self.next)
        return out

    def for_signing(self) -> tuple[Generation | None, Generation]:
        return self.previous, self.current

    @property
    def is_bootstrap(self) -> bool:
        return self.previous is None


# --------------------------------------------------------------------------- #
# Recognition (§6.4, M-9) — one code path for generation 0 and 1..n
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Context:
    """Everything needed to verify a recognition, whatever its kind.

    Gathers both kinds' needs in one place, so ``verify`` has **one**
    signature.
    """

    #: ``key_id`` → Ed25519 public key. Used by generation 0.
    keys: object
    #: The receiver's previous generation, if it exists (generation 1..n).
    previous_der: bytes | None = None
    #: The receiver's current generation (generation 1..n).
    current_der: bytes | None = None


@dataclass(frozen=True)
class Recognition:
    """A signed claim that an identity is accepted — regardless of generation.

    ## Why this exists (M-9)

    The operator's approval **is** a signature, not an exception to the model.
    If the two kinds live as separate types, the call site has to choose which
    one it has — and a bootstrap case verified by a different code path than
    the rest is exactly where a weakness gets to live without anyone seeing
    it.

    Here there is **one** ``verify``. The call site does not need to know
    which kind it got.
    """

    kind: str  # "operator" | "schedule"
    approval: Approval | None = None
    announcement: Announcement | None = None

    @staticmethod
    def operator(g: Approval) -> Recognition:
        """Generation 0 — the operator's approval."""
        return Recognition("operator", approval=g)

    @staticmethod
    def schedule(k: Announcement) -> Recognition:
        """Generation 1..n — an announcement."""
        return Recognition("schedule", announcement=k)

    def verify(self, k: Context) -> None:
        """**One code path** (M-9). Fail-closed on missing context."""
        if self.kind == "operator":
            assert self.approval is not None
            self.approval.verify(k.keys)
            return
        assert self.announcement is not None
        if k.current_der is None:
            raise NettlsError(
                "cannot verify an announcement without the receiver's current "
                "generation — without it there is nothing to verify against"
            )
        self.announcement.verify(k.previous_der, k.current_der)


# --------------------------------------------------------------------------- #
# Mode (§6.2, §6.9b)
# --------------------------------------------------------------------------- #


class Mode:
    """The values that go on the wire in ``/v1/tls/identity``.

    Strings and not an enum, because they **are** the contract — a rename must
    not be able to change them.
    """

    PINNING = "pinning"
    ROLLING = "rolling"

    @staticmethod
    def check(ours: str, theirs: str) -> str | None:
        """Compare our configured mode with the one the peer **announces**.

        Mode is **never negotiated** (§6.9b). A party that can *request* a
        mode can request the weakest one — and then we have built a downgrade
        attack into the protocol as a feature.

        Returns ``None`` on agreement, otherwise a message naming both.
        """
        if ours == theirs:
            return None
        return (
            f"mode disagreement: we are set to «{ours}», the peer runs «{theirs}». "
            f"Traffic flows, but rotation is not attempted until both sides are set alike."
        )


# --------------------------------------------------------------------------- #
# TLS: pinned context and self-signing
# --------------------------------------------------------------------------- #


def pinned_ssl_context(accepted_pem: list[str]) -> ssl.SSLContext:
    """An ``SSLContext`` that trusts **exactly** these certificates.

    Used with ``current`` + stored ``next`` (§6.3) — the switch is then
    accepted the moment the peer makes it, without us having been told when.

    ``check_hostname`` is off: the certificates are self-signed and pinned on
    identity, not on name. The verification is not weaker for that — it is
    stricter, since only these exact certificates are accepted.
    """
    if not accepted_pem:
        raise NettlsError(
            "no certificates to pin — an empty list would have given a context that "
            "trusts nothing, and that must be an ERROR, not a silent state"
        )
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_REQUIRED
    # **Leaf as trust anchor.** Without this, OpenSSL refuses to use a
    # self-signed certificate without `basicConstraints: CA:TRUE` as an
    # anchor, and the pinning falls — not because the identity is wrong, but
    # because the verification is looking for a CA we never had.
    #
    # The alternative would have been to make every certificate a CA. That is
    # worse: it could then have signed other certificates. Here we instead say
    # what we actually mean — "trust exactly these leaves" — and that is
    # STRICTER than ordinary CA verification, not weaker.
    ctx.verify_flags |= ssl.VERIFY_X509_PARTIAL_CHAIN
    with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as f:
        f.write("\n".join(accepted_pem))
        path = f.name
    try:
        ctx.load_verify_locations(cafile=path)
    finally:
        Path(path).unlink(missing_ok=True)
    return ctx


_MAX_DNS_NAME = 253
_MAX_DNS_LABEL = 63
_MAX_COMMON_NAME = 64


def _validate_cn(cn: str) -> None:
    """CN is validated **loosely**, on purpose — it is a human-readable
    subject field, not a host name (mirrors material.rs)."""
    if not cn or not cn.strip():
        raise NettlsError(
            "common_name is empty — this is the text the operator sees in the "
            "certificate viewer"
        )
    if len(cn) > _MAX_COMMON_NAME:
        raise NettlsError(
            f"common_name is {len(cn)} characters — X.509 allows at most "
            f"{_MAX_COMMON_NAME}"
        )
    for c in cn:
        if unicodedata.category(c) == "Cc":
            raise NettlsError(
                f"common_name contains the control character {c!r} — it does "
                f"not belong in a subject"
            )


def _validate_dns_san(name: str) -> None:
    """DNS-SAN rules, mirroring material.rs — strict where the name must
    *match* something (M-36 / case L2-054)."""
    if not name:
        raise NettlsError("SAN: an empty string cannot match anything")
    if len(name) > _MAX_DNS_NAME:
        raise NettlsError(
            f"SAN {name!r} is {len(name)} characters — a DNS name can be at "
            f"most {_MAX_DNS_NAME}"
        )
    stripped = name[:-1] if name.endswith(".") else name
    labels = stripped.split(".")
    if all(lab == "" for lab in labels):
        raise NettlsError(f"SAN {name!r} consists only of dots")
    for i, lab in enumerate(labels):
        if lab == "":
            raise NettlsError(
                f"SAN {name!r} has an empty part between the dots — two dots "
                f"in a row, or a leading dot"
            )
        if len(lab) > _MAX_DNS_LABEL:
            raise NettlsError(
                f"SAN {name!r}: the part {lab!r} is {len(lab)} characters — at "
                f"most {_MAX_DNS_LABEL} between the dots"
            )
        if lab == "*":
            if i != 0:
                raise NettlsError(
                    f"SAN {name!r}: a wildcard is only legal as the first part "
                    f"(`*.example.no`)"
                )
            continue
        if lab.startswith("-") or lab.endswith("-"):
            raise NettlsError(
                f"SAN {name!r}: the part {lab!r} starts or ends with a hyphen"
            )
        for c in lab:
            if not (c.isascii() and (c.isalnum() or c == "-")):
                raise NettlsError(
                    f"SAN {name!r} contains the illegal character {c!r} — a DNS "
                    f"name can only have letters, digits, hyphens and dots. (If "
                    f"this is meant as an IP address, it must be written so that "
                    f"it parses as one.)"
                )


def self_signed(
    common_name: str, sans: list[str], days: int | None = None
) -> tuple[str, str]:
    """Self-signed ECDSA P-256 with SAN. Returns ``(cert_pem, key_pem)``.

    Default 30 days: the lifetime for **mode 2** (§6.2). It is not a
    convenience value — the rotation *is* the security mechanism, and a
    lifetime that is easy to turn up makes it a setting instead of a
    guarantee.
    """
    import datetime as _dt

    # Looked up at CALL time, not at definition time: the constant sits
    # further down in the file, and a default argument would have been bound
    # before it existed. The point is that there is only ONE source for the
    # lifetime.
    if days is None:
        days = MODE2_LIFETIME_DAYS
    if not (1 <= days <= 397):
        # 397 is MAX_VALID_DAYS on the Rust side (Safari/Chrome reject longer
        # lifetimes, self-signed included). The floor mirrors material.rs.
        raise NettlsError(
            f"valid_days = {days} is outside 1..=397 (Safari/Chrome reject "
            f"longer lifetimes, self-signed included)"
        )
    _validate_cn(common_name)

    # An empty SAN list gives a certificate that can never match any name —
    # useless, but produced in silence. Rust rejects it
    # (`tests/selfsigned.rs`), and the error must say WHAT is missing, not
    # just that something was.
    if not sans:
        raise NettlsError(
            "self_signed requires at least one SAN — a certificate without a SAN "
            "cannot match any name and will be rejected by every client"
        )

    k = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = _dt.datetime.now(_dt.timezone.utc)
    alt_names: list[x509.GeneralName] = []
    for s in sans:
        try:
            import ipaddress

            alt_names.append(x509.IPAddress(ipaddress.ip_address(s)))
        except ValueError:
            _validate_dns_san(s)
            alt_names.append(x509.DNSName(s))
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(k.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - _dt.timedelta(seconds=BAKDATERING_S))
        .not_valid_after(now + _dt.timedelta(days=days))
        .add_extension(x509.SubjectAlternativeName(alt_names), critical=False)
        .sign(k, hashes.SHA256())
    )
    return (
        cert.public_bytes(serialization.Encoding.PEM).decode(),
        k.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode(),
    )


# --------------------------------------------------------------------------- #
# `/v1/tls/identity` (§6.14)
# --------------------------------------------------------------------------- #


def identity_json(
    fingerprint: str,
    cert_pem: str,
    mode: str,
    sent_at: int,
    not_after: str | None = None,
    announcement: Announcement | None = None,
) -> dict:
    """The whole response form — the crate owns the contract, not just the announcement.

    If we let each service fill in its part, we would have had several places
    that must be kept identical. Hex-versus-base64 arose in exactly that way.
    """
    d: dict = {
        "fingerprint": fingerprint,
        "cert_pem": cert_pem,
        "mode": mode,
        "sent_at": sent_at,
    }
    if not_after is not None:
        d["not_after"] = not_after
    if announcement is not None:
        d["announcement"] = announcement.to_json()
    return d


def _load_vectors() -> dict:
    """The test vectors, when they are available next to the module."""
    path = Path(__file__).resolve().parent.parent / "testvectors" / "canonical.json"
    return json.loads(path.read_text())


# --------------------------------------------------------------------------- #
# Locking local state at rest (SPEC-nettls §6.11)
# --------------------------------------------------------------------------- #
#
# Bit-compatible with the Rust side's `nettls::lock` — same argon2id
# parameters, same HKDF and same FAFN blob as `krypto`. Not because the two
# sides read each other's files (each module locks its own), but because one
# format is one thing to keep right. Two formats would have been two, and one
# of them never gets reviewed.
#
# The property this buys:
#
#     A copy of the disk is worthless without at least one user's password —
#     because the key has never been on the machine.
#
# **No verification hash is stored.** If the password is wrong, the AEAD fails
# by itself. A stored hash would moreover have given an attacker with the disk
# an ORACLE OF THEIR OWN to test candidates against, alongside the ciphertext
# they would have had to attack anyway.

_LAAS_MAGIC = b"NETTLS\x01\x00"
_LAAS_SALT_LEN = 32
_LOCK_KEY_ID = b"nettls-local-st1"
_LOCK_INFO = b"nettls/local-state/v1"

# The FAFN header from `krypto::aead`:
#   magic "FAFN" (4) | format_ver (1) | alg_id (1) | key_id (16) | nonce (32)
_FAFN_MAGIC = b"FAFN"
_FAFN_VER = 1
_FAFN_ALG_AES256GCM = 3
_FAFN_KEY_ID_LEN = 16
_FAFN_NONCE_FIELD = 32
_FAFN_HEADER_LEN = 4 + 1 + 1 + _FAFN_KEY_ID_LEN + _FAFN_NONCE_FIELD  # 54
_AES_GCM_NONCE_LEN = 12

# `Preset::Interactive` in krypto: m = 64 MiB, t = 3, p = 2.
_ARGON2_M_KIB = 65_536
_ARGON2_T = 3
_ARGON2_P = 2


def _derive_argon2(password: str, salt: bytes) -> bytes:
    """argon2id as a **KDF**, not as a stored hash.

    Argon2 has two uses that must not be mixed: verification (the PHC string
    is stored) and key derivation (nothing is stored, only salt and
    parameters). Unlocking needs the latter.
    """
    try:
        from argon2.low_level import Type, hash_secret_raw
    except ImportError as e:  # pragma: no cover
        raise NettlsError(
            "argon2-cffi is missing — locking local state requires it "
            "(pip install argon2-cffi)"
        ) from e
    if len(salt) < 16:
        raise NettlsError(f"argon2 salt must be at least 16 bytes, got {len(salt)}")
    return hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=salt,
        time_cost=_ARGON2_T,
        memory_cost=_ARGON2_M_KIB,
        parallelism=_ARGON2_P,
        hash_len=32,
        type=Type.ID,
    )


def _hkdf_sha256(ikm: bytes, salt: bytes, info: bytes) -> bytes:
    """Same HKDF as `krypto::MasterKey::derive`."""
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=info).derive(ikm)


def _fafn_seal(key: bytes, key_id: bytes, plaintext: bytes) -> bytes:
    """FAFN blob with AES-256-GCM.

    **The header is associated data.** Tampering with `alg_id`, `key_id` or
    the nonce must produce an authentication failure, not a mis-decrypt —
    that is the whole point of the format, and it is the same rule the
    "key-id swap" test in `krypto` pins down.
    """
    import os

    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    if len(key_id) != _FAFN_KEY_ID_LEN:
        raise NettlsError(f"key_id must be {_FAFN_KEY_ID_LEN} bytes")
    nonce_field = bytearray(_FAFN_NONCE_FIELD)
    nonce_field[:_AES_GCM_NONCE_LEN] = os.urandom(_AES_GCM_NONCE_LEN)
    header = (
        _FAFN_MAGIC
        + bytes([_FAFN_VER, _FAFN_ALG_AES256GCM])
        + key_id
        + bytes(nonce_field)
    )
    ct = AESGCM(key).encrypt(
        bytes(nonce_field[:_AES_GCM_NONCE_LEN]), plaintext, header
    )
    return header + ct


def _fafn_open(key: bytes, blob: bytes) -> bytes:
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    if len(blob) < _FAFN_HEADER_LEN:
        raise NettlsError("blob shorter than the header")
    header, body = blob[:_FAFN_HEADER_LEN], blob[_FAFN_HEADER_LEN:]
    if header[:4] != _FAFN_MAGIC:
        raise NettlsError("wrong magic (not FAFN)")
    if header[4] != _FAFN_VER:
        raise NettlsError(f"unsupported format_ver {header[4]}")
    if header[5] != _FAFN_ALG_AES256GCM:
        raise NettlsError(
            f"alg_id {header[5]} — the Python side only supports AES-256-GCM (3), "
            f"the interop bridge in krypto"
        )
    nonce = header[6 + _FAFN_KEY_ID_LEN : 6 + _FAFN_KEY_ID_LEN + _AES_GCM_NONCE_LEN]
    try:
        return AESGCM(key).decrypt(nonce, body, header)
    except InvalidTag as e:
        raise NettlsError("authentication failed — wrong key, or the blob was altered") from e


def lock(password: str, plaintext: bytes) -> bytes:
    """Lock content with a password. Fresh salt every time."""
    import os

    salt = os.urandom(_LAAS_SALT_LEN)
    ikm = _derive_argon2(password, salt)
    key = _hkdf_sha256(ikm, salt, _LOCK_INFO)
    return _LAAS_MAGIC + salt + _fafn_seal(key, _LOCK_KEY_ID, plaintext)


def unlock(password: str, data: bytes) -> bytes:
    """Unlock. **A wrong password gives an authentication failure**, not an empty answer."""
    if len(data) < len(_LAAS_MAGIC) + _LAAS_SALT_LEN:
        raise NettlsError("the locked file is too short to contain header and salt")
    if data[: len(_LAAS_MAGIC)] != _LAAS_MAGIC:
        raise NettlsError(
            "unknown file format — this is not a locked nettls state file. "
            "(A wrong FORMAT, not a wrong password: look for the right file, not "
            "the right password.)"
        )
    salt = data[len(_LAAS_MAGIC) : len(_LAAS_MAGIC) + _LAAS_SALT_LEN]
    blob = data[len(_LAAS_MAGIC) + _LAAS_SALT_LEN :]
    ikm = _derive_argon2(password, salt)
    key = _hkdf_sha256(ikm, salt, _LOCK_INFO)
    try:
        return _fafn_open(key, blob)
    except NettlsError as e:
        raise NettlsError(
            "could not unlock the local state — wrong password, or the file "
            "was altered. (We store no verification hash, so this is the AEAD "
            "speaking up.)"
        ) from e


# --------------------------------------------------------------------------- #
# The rotation (§6.7, §6.7c, §6.8a)
# --------------------------------------------------------------------------- #

DAY_S = 86_400
NOMINAL_AGE_DAYS = 7
SPREAD_DAYS = 2
MIN_BETWEEN_ROLLS_S = DAY_S
ALARM_AFTER_S = 12 * 3600


def draw_roll_time(issued_at: int) -> int:
    """``issued_at + 7 days ± 2 days``, with **second resolution** from a CSPRNG.

    Seconds and not days: two modules provisioned in the same second must not
    be able to land on the same day, and with day resolution they would have
    had 5 possible values to collide on.

    CSPRNG not because the draw is secret, but because a **predictable**
    rotation schedule is a schedule an attacker can plan against.
    """
    import secrets

    span = 2 * SPREAD_DAYS * DAY_S
    offset = secrets.randbelow(span) - SPREAD_DAYS * DAY_S
    return issued_at + NOMINAL_AGE_DAYS * DAY_S + offset


def interval_after(elapsed_s: int) -> int:
    """The retry cadence (§6.8a): tight at the start, sparser afterwards."""
    if elapsed_s < 15 * 60:
        return 60
    if elapsed_s < 3600:
        return 5 * 60
    return 3600


class Schedule:
    """The announcer's state machine.

    **No clock inside the class** — everything takes ``now`` as a parameter. A
    state machine that reads the clock itself cannot be fast-forwarded, and
    then "what happens after 12 hours?" becomes something you have to wait for
    instead of something you can show.
    """

    def __init__(self, peers: list[str], attempt_at: int) -> None:
        self.peers = set(peers)
        self._forsoek_ved = attempt_at
        self._waiting_for: set[str] | None = None
        self._first_announced: int | None = None
        self._last_rolled: int | None = None

    def should_announce(self, now: int) -> bool:
        return self._waiting_for is None and now >= self._forsoek_ved

    def announced(self, now: int) -> None:
        """Idempotent: the announcement is republished until everyone has acked."""
        if self._waiting_for is None:
            self._waiting_for = set(self.peers)
            self._first_announced = now

    def acked(self, peer: str) -> None:
        if self._waiting_for is not None:
            self._waiting_for.discard(peer)

    def waiting_for(self) -> list[str]:
        """So the alarm can **name** who is blocking (M-33)."""
        return sorted(self._waiting_for) if self._waiting_for else []

    def add_peer(self, name: str) -> None:
        self.peers.add(name)
        if self._waiting_for is not None:
            self._waiting_for.add(name)

    def remove_peer(self, name: str) -> None:
        """**Not an exceptional case** (M-34).

        If a module is decommissioned but stays in the registry, we wait
        forever for a receipt from something that does not exist.
        """
        self.peers.discard(name)
        if self._waiting_for is not None:
            self._waiting_for.discard(name)

    def rate_limit_ok(self, now: int) -> bool:
        return (
            self._last_rolled is None
            or now - self._last_rolled >= MIN_BETWEEN_ROLLS_S
        )

    def can_roll(self, now: int) -> bool:
        return (
            self._waiting_for is not None
            and not self._waiting_for
            and self.rate_limit_ok(now)
        )

    def rolled(self, now: int) -> None:
        self._last_rolled = now
        self._waiting_for = None
        self._first_announced = None
        self._forsoek_ved = draw_roll_time(now)

    def alarm(self, now: int) -> bool:
        return (
            self._waiting_for is not None
            and bool(self._waiting_for)
            and self._first_announced is not None
            and now - self._first_announced >= ALARM_AFTER_S
        )

    def next_retry(self, now: int) -> int | None:
        """The retries **continue after the alarm** (M-7e).

        The alarm notifies a human; it does not end the attempt. If the peer
        comes back on its own, the rotation goes through without anyone having
        done anything.
        """
        if not self._waiting_for or self._first_announced is None:
            return None
        return now + interval_after(max(0, now - self._first_announced))

    def restore_announced(self, waiting_for: list[str], first_announced: int) -> None:
        """After a restart (§6.9c).

        Preserves **when we first announced** — otherwise a restart would have
        reset the 12-hour clock, and the alarm would never have gone off in a
        service that restarts often.
        """
        self._waiting_for = set(waiting_for)
        self._first_announced = first_announced

    def countdown(self, now: int, expires_at: int) -> str:
        """Time until **stop** — not until the next attempt.

        A smaller number than the true one is worse than no countdown.
        """
        s = max(0, expires_at - now)
        d, r = divmod(s, DAY_S)
        t, r = divmod(r, 3600)
        m, sec = divmod(r, 60)
        return f"{d} days {t:02d}:{m:02d}:{sec:02d}"


class Announcer:
    """Binds [`Schedule`] to what is actually served.

    ``switch_to`` is a callback from the call site — the module knows nothing
    about how the certificate is put into use, only **when** it is allowed.
    """

    def __init__(
        self,
        name: str,
        params: tuple[str, list[str]],
        current: tuple[str, str, str],
        schedule: Schedule,
        switch_to,
        lifetime_days: int = 30,
    ) -> None:
        self.name = name
        self._cn, self._sans = params
        # (fingerprint, cert_pem, key_pem)
        self.previous: tuple[str, str, str] | None = None
        self.current = current
        self.schedule = schedule
        self._switch_to = switch_to
        self._lifetime = lifetime_days
        self._pending_state: tuple[Announcement, str, str] | None = None

    def prepare(self, now: int, store) -> Announcement:
        """Create a new certificate and build the announcement.

        Idempotent: if an announcement is already out, the same one is
        returned. It is precisely that one which is republished until everyone
        has acked (§6.8a).

        ## `store` (save) is required, and that is the whole point (M-26)

        The Rust crate writes the material to disk itself, **before** the
        announcement exists. This module stores nothing — but the ordering is
        just as normative, so it is enforced through the call instead:

        `store(state)` is called with the **new** state before the
        announcement is returned. If it raises, no announcement exists, and we
        have not promised anything we cannot keep.

        Without this the failure mode would have been: publish, the peer
        acknowledges, the process dies — and the private key of an
        already-acked fingerprint exists nowhere. That is the one case that
        cannot be repaired without an operator, and it is too easy to get
        wrong if the ordering only lives in a document.

        The callback must **commit** before it returns. If it returns while
        the write still sits in an open transaction, the guarantee is gone.
        """
        if self._pending_state is not None:
            return self._pending_state[0]
        cert, key = self_signed(self._cn, self._sans, self._lifetime)
        k = Announcement.new(
            self.name,
            (self.previous[0], self.previous[2]) if self.previous else None,
            (self.current[0], self.current[2]),
            cert,
            now,
        )
        pending = (k, cert, key)

        # Save BEFORE any of this becomes visible externally. If it fails, we
        # roll back to the state we had — the key is discarded, and no one has
        # heard of it.
        store(self._state_with(pending, now))

        self._pending_state = pending
        self.schedule.announced(now)
        return k

    # -- state: the consumer remembers, the module does not (§6.11b) ------ #

    def _material(self, m: tuple[str, str, str] | None) -> dict | None:
        if m is None:
            return None
        return {"fp": m[0], "cert_pem": m[1], "key_pem": m[2]}

    def _state_with(self, pending, now: int | None) -> dict:
        return {
            "name": self.name,
            "cn": self._cn,
            "sans": list(self._sans),
            "lifetime_days": self._lifetime,
            "previous": self._material(self.previous),
            "current": self._material(self.current),
            "pending": (
                {
                    "announcement": pending[0].to_json(),
                    "cert_pem": pending[1],
                    "key_pem": pending[2],
                }
                if pending
                else None
            ),
            "schedule": {
                "peers": sorted(self.schedule.peers),
                "waiting_for": sorted(self.schedule.waiting_for()),
                "first_announced": (
                    now if now is not None else self.schedule._first_announced
                ),
            },
        }

    def state(self) -> dict:
        """Everything the consumer must store to survive a restart.

        **Contains private keys in plaintext.** That is deliberate: the
        consumer owns the storage and must be able to encrypt it itself
        (§6.11b). Never write it to a log, and encrypt it at rest.
        """
        return self._state_with(self._pending_state, None)

    @staticmethod
    def restore(state: dict, switch_to) -> Announcer:
        """Rebuild from what the consumer has remembered.

        The counterpart of [`state`]. Without this, a service could write
        everything down and still not come back — the same asymmetry
        [`Generations.restore`] exists to fix.
        """

        def mat(d):
            return None if d is None else (d["fp"], d["cert_pem"], d["key_pem"])

        r = Schedule(state["schedule"]["peers"], 0)
        v = state.get("pending")
        k = Announcer(
            state["name"],
            (state["cn"], list(state["sans"])),
            mat(state["current"]),
            r,
            switch_to,
            state.get("lifetime_days", 30),
        )
        k.previous = mat(state.get("previous"))
        if v is not None:
            k._pending_state = (
                Announcement.from_json(v["announcement"]),
                v["cert_pem"],
                v["key_pem"],
            )
            # The promise is binding: the peer may already have acked, and is
            # then waiting for precisely this certificate (§6.9c).
            r.restore_announced(
                state["schedule"]["waiting_for"],
                state["schedule"]["first_announced"] or 0,
            )
        return k

    def acked(self, peer: str) -> None:
        self.schedule.acked(peer)

    def roll_if_ready(self, now: int) -> str | None:
        """Switch **only** if everyone has acked and the rate limit allows it.

        Asking for a switch too early is not an error — it is the normal state
        while we wait.
        """
        if not self.schedule.can_roll(now) or self._pending_state is None:
            return None
        k, cert, key = self._pending_state
        old = self.current[0]
        self._switch_to(cert, key)
        # Exactly two are kept: generation N-2 is released here.
        self.previous = self.current
        self.current = (k.new_fp, cert, key)
        self._pending_state = None
        self.schedule.rolled(now)
        return old

    @property
    def pending(self) -> Announcement | None:
        return self._pending_state[0] if self._pending_state else None


# --------------------------------------------------------------------------- #
# ClockDrift (§6.7b)
# --------------------------------------------------------------------------- #

# --------------------------------------------------------------------------- #
# Lifetimes and warnings (§6.2, M-11, M-12, M-21)
# --------------------------------------------------------------------------- #

#: The lifetime of an **internal** certificate (mode 2). Always 30 days (M-21).
#:
#: Not adjustable, and that is the point: **the rotation IS the security
#: mechanism.** A lifetime the operator can tune would have made it a setting
#: instead of a guarantee.
MODE2_LIFETIME_DAYS = 30

#: Lower bound for a **user-facing** certificate: 47 days.
#:
#: A public hard limit from around 2029, adopted today. The floor exists
#: because frequent switches produce frequent browser warnings — and warnings
#: people have learned to click away do not work on the day it is a real MITM.
MODE1_MIN_DAYS = 47
#: Default for a user-facing certificate.
MODE1_DEFAULT_DAYS = 90
#: Absolute max for a user-facing certificate.
MODE1_MAX_DAYS = 365

#: Warning when a mode 1 certificate approaches expiry.
MODE1_WARN_DAYS = 30

#: How far back a newly issued certificate is dated, for clock skew.
#:
#: **Must match the Rust side** (`material.rs`, `p.not_before = now - 1 hour`).
#: Python had 5 minutes until 2026-08-11 — a 12× tighter tolerance than the
#: crate. A Python-issued certificate would then have been rejected as "not
#: yet valid" by a peer whose clock ran 10 minutes behind, while a Rust-issued
#: one passed fine. Neither the cross-test nor the ring test could see it: the
#: one checks signatures and format, the other runs all nodes on the same
#: clock.
BAKDATERING_S = 3600


def mode1_should_warn(now: int, expires_at: int) -> bool:
    """Should the operator be warned that a mode 1 certificate needs handling? (M-12)

    **At 30 days left** — not at 5, and not when the certificate falls. 30
    days is enough to obtain a new one without it being urgent.
    """
    return expires_at - now <= MODE1_WARN_DAYS * DAY_S


def mode2_lifetime() -> int:
    """The lifetime of an internal certificate. Always 30 days (M-21)."""
    return MODE2_LIFETIME_DAYS


def mode1_lifetime(days: int | None = None) -> int:
    """Validated lifetime for a **user-facing** certificate (mode 1).

    ``days = None`` gives the default of 90. Outside the floor or ceiling is
    an error, not an adjustment — the limits are there for reasons, not out of
    habit.
    """
    d = MODE1_DEFAULT_DAYS if days is None else days
    if d < MODE1_MIN_DAYS:
        raise NettlsError(
            f"lifetime of {d} days is below the floor of {MODE1_MIN_DAYS} — frequent "
            f"switches produce frequent browser warnings, and warnings people have "
            f"learned to click away do not work on the day it is a real MITM"
        )
    if d > MODE1_MAX_DAYS:
        raise NettlsError(f"lifetime of {d} days is above the ceiling of {MODE1_MAX_DAYS}")
    return d


DRIFT_NORMAL_S = 5
DRIFT_WARNING_S = 30
DRIFT_JUMP_S = 10


class ClockDrift:
    """Tracks the offset against **one** peer as a **series**, not a single measurement.

    A backward NTP correction can produce a small instantaneous offset even
    though time has jumped — and an abrupt jump is its own warning, regardless
    of whether the absolute value is within the threshold.
    """

    def __init__(self) -> None:
        self.last: int | None = None
        self.max = 0

    def observe(self, their_sent_at: int, our_now: int) -> str:
        """Returns ``"normal"``, ``"logg"`` (log) or ``"advarsel"`` (warning)."""
        drift = their_sent_at - our_now
        jump = abs(drift - self.last) if self.last is not None else 0
        self.last = drift
        self.max = max(self.max, abs(drift))
        if abs(drift) > DRIFT_WARNING_S or jump > DRIFT_JUMP_S:
            return "advarsel"
        if abs(drift) >= DRIFT_NORMAL_S:
            return "logg"
        return "normal"

    def message(self, peer: str) -> str | None:
        if self.last is None or abs(self.last) <= DRIFT_WARNING_S:
            return None
        return (
            f"clock drift against {peer}: {self.last} seconds. Traffic flows as "
            f"normal — the clock is not load-bearing for the rotation (§6.7b) — but "
            f"drift is rarely the only thing that is wrong."
        )


# --------------------------------------------------------------------------- #
# Sealed envelopes (§8.5)
# --------------------------------------------------------------------------- #

_ENV_MAGIC = b"NETENV\x01\x00"
_ENV_KEY_ID = b"nettls-envelope1"
_ENV_INFO = b"nettls/envelope/v1"
_X25519_LEN = 32


def envelope_generate_key() -> tuple[bytes, bytes]:
    """New X25519 pair. Returns ``(private, public)``."""
    from cryptography.hazmat.primitives.asymmetric import x25519

    sk = x25519.X25519PrivateKey.generate()
    return (
        sk.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        ),
        sk.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        ),
    )


def envelope_public(private_key: bytes) -> bytes:
    from cryptography.hazmat.primitives.asymmetric import x25519

    return (
        x25519.X25519PrivateKey.from_private_bytes(private_key)
        .public_key()
        .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    )


def _env_derive(shared: bytes, ephemeral_pub: bytes, recipient_pub: bytes) -> bytes:
    """Bound to **both** public keys.

    Without that binding, an attacker could have swapped out the ephemeral
    sender key and made the recipient derive a different key than the one that
    was actually used — the classic mistake in home-grown sealed-box variants.
    """
    return _hkdf_sha256(shared + ephemeral_pub + recipient_pub, ephemeral_pub, _ENV_INFO)


def envelope_seal(recipient_public: bytes, plaintext: bytes) -> bytes:
    """Seal to the recipient's public key.

    The sender needs **no** key of its own: the ephemeral one is drawn here
    and discarded. That is why portal can create an envelope without being able
    to open it.
    """
    from cryptography.hazmat.primitives.asymmetric import x25519

    if len(recipient_public) != _X25519_LEN:
        raise NettlsError(
            f"X25519 public key must be {_X25519_LEN} bytes, "
            f"got {len(recipient_public)}"
        )
    eph = x25519.X25519PrivateKey.generate()
    eph_pub = eph.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    shared = eph.exchange(x25519.X25519PublicKey.from_public_bytes(recipient_public))
    key = _env_derive(shared, eph_pub, recipient_public)
    return _ENV_MAGIC + eph_pub + _fafn_seal(key, _ENV_KEY_ID, plaintext)


def envelope_open(private_key: bytes, envelope: bytes) -> bytes:
    """Open. **Only** the recipient can."""
    from cryptography.hazmat.primitives.asymmetric import x25519

    if len(envelope) < len(_ENV_MAGIC) + _X25519_LEN:
        raise NettlsError("the envelope is too short")
    if envelope[: len(_ENV_MAGIC)] != _ENV_MAGIC:
        raise NettlsError(
            "unknown format — this is not a nettls envelope. "
            "(Wrong FORMAT, not wrong key.)"
        )
    eph_pub = envelope[len(_ENV_MAGIC) : len(_ENV_MAGIC) + _X25519_LEN]
    blob = envelope[len(_ENV_MAGIC) + _X25519_LEN :]
    sk = x25519.X25519PrivateKey.from_private_bytes(private_key)
    my_pub = sk.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    shared = sk.exchange(x25519.X25519PublicKey.from_public_bytes(eph_pub))
    key = _env_derive(shared, eph_pub, my_pub)
    try:
        return _fafn_open(key, blob)
    except NettlsError as e:
        raise NettlsError(
            "could not open the envelope — it is not sealed to this "
            "key, or it was altered"
        ) from e
