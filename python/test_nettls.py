# SPDX-License-Identifier: MIT OR Apache-2.0
"""Konformanstest for Python-siden av SPEC-nettls §6.

The most important test here is `test_vectors_match_byte_for_byte`. The vectors
in `../testvectors/canonical.json` are **normative** — they are the verdict, not
byproduct of the Rust code. If one fails, the question is "who is right
according to the spec", not "Python must fall in line with Rust".

The Ed25519 signatures are in the vectors because Ed25519 is **deterministic**:
Python must produce identical bytes, not merely bytes that verify. That is a
far tighter probe.

Run:  python3 -m pytest nettls/python/ -q
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

import nettls as n  # noqa: E402

VECTORS = json.loads(
    (Path(__file__).resolve().parent.parent / "testvectors" / "canonical.json").read_text()
)

# The same seed the Rust side uses for the vectors.
SEED = bytes(range(1, 33))

FP_A = "aa00112233445566778899aabbccddeeff00112233445566778899aabbccddee"
FP_B = "bb00112233445566778899aabbccddeeff00112233445566778899aabbccddee"
FP_C = "cc00112233445566778899aabbccddeeff00112233445566778899aabbccddee"


def build_vectors() -> dict[str, bytes]:
    """The same set, built from the Python side."""
    return {
        "approve-01-plain": n.approve_v1("gateway", FP_A, "operator", 1_700_000_000),
        "approve-02-non-ascii": n.approve_v1(
            "gateway", FP_A, "bjørn-øyvind", 1_700_000_000
        ),
        "approve-03-time-zero": n.approve_v1("service", FP_B, "a", 0),
        "approve-04-time-negative": n.approve_v1("service", FP_B, "a", -1),
        "approve-05-max-lengths": n.approve_v1("p" * 32, FP_C, "u" * 64, 1),
        "rotate-01-double-signed": n.rotate_v2(
            "gateway", FP_A, FP_B, FP_C, 1_700_000_000
        ),
        "rotate-02-bootstrap": n.rotate_v2("gateway", None, FP_B, FP_C, 1_700_000_000),
        "ack-01-plain": n.rotate_ack_v2("service", "gateway", FP_C, 1_700_000_000),
        "pairsecret-01-plain": n.pairsecret_v1(
            "service", "gateway", FP_A, FP_B, 1_700_000_000
        ),
        "algsupport-01-python-bridge": n.algsupport_v1(
            "service", "aes256gcm", 1_700_000_000
        ),
    }


# --------------------------------------------------------------------------- #
# The vectors — the proof that the two implementations agree with the CONTRACT
# --------------------------------------------------------------------------- #


def test_seed_public_key_is_stable():
    # Change this, and every signature vector is invalid.
    assert (
        n.to_hex(n.ed25519_public_from_seed(SEED))
        == "79b5562e8fe654f94078b112e8a98ba7901f853ae695bed7e0e3910bad049664"
    )


@pytest.mark.parametrize("name", sorted(VECTORS))
def test_vectors_match_byte_for_byte(name):
    expected = VECTORS[name]
    actual = build_vectors()[name]
    assert n.to_hex(actual) == expected["canonical_hex"], (
        f"\nvector «{name}» ({expected['what']}) does not match.\n"
        f"  expected:   {expected['canonical_hex']}\n"
        f"  actual: {n.to_hex(actual)}\n"
    )


@pytest.mark.parametrize("name", sorted(VECTORS))
def test_ed25519_signatures_are_identical(name):
    # Ed25519 is deterministic, so this is byte equality and not merely
    # "does it verify?". A much tighter probe.
    expected = VECTORS[name]
    if "ed25519_sig_hex" not in expected:
        pytest.skip("vektoren har ingen signatur")
    sig = n.sign_ed25519(SEED, bytes.fromhex(expected["canonical_hex"]))
    assert n.to_hex(sig) == expected["ed25519_sig_hex"]


def test_no_vector_is_missing_on_the_python_side():
    # A vector Rust produces but Python does not is a hole in the contract.
    missing = set(VECTORS) - set(build_vectors())
    assert not missing, f"Python does not build: {sorted(missing)}"


# --------------------------------------------------------------------------- #
# The form: LF, no trailing newline, prev as «-»
# --------------------------------------------------------------------------- #


def test_no_trailing_newline_anywhere():
    for b in build_vectors().values():
        assert not b.endswith(b"\n"), b
        assert b"\r\n" not in b


def test_bootstrap_serializes_prev_as_dash():
    med = n.rotate_v2("gateway", FP_A, FP_B, FP_C, 1)
    uten = n.rotate_v2("gateway", None, FP_B, FP_C, 1)
    assert b"\n-\n" in uten
    # Same line count: a vanished field would have made the next line
    # rykke opp og bety noe annet.
    assert med.count(b"\n") == uten.count(b"\n")


# --------------------------------------------------------------------------- #
# Feltvalidering
# --------------------------------------------------------------------------- #


def test_newline_in_a_field_is_rejected():
    # Without this the field would become TWO lines, and an attacker could move
    # content in the message without touching the signature.
    with pytest.raises(n.NettlsError):
        n.approve_v1("gateway", FP_A, "rog\ner", 1)
    with pytest.raises(n.NettlsError):
        n.approve_v1("net\rgw", FP_A, "operator", 1)


def test_wrong_fingerprint_is_rejected():
    for d in ["kort", f"sha256:{FP_A}", FP_A.upper(), "z" * 64]:
        with pytest.raises(n.NettlsError):
            n.approve_v1("gateway", d, "operator", 1)


def test_hex_rejects_uppercase_and_garbage():
    assert n.from_hex("000fa0ff") == bytes([0, 0x0F, 0xA0, 0xFF])
    for d in ["000FA0FF", "abc", "", "zz"]:
        with pytest.raises(n.NettlsError):
            n.from_hex(d)


# --------------------------------------------------------------------------- #
# Announcement and receipt
# --------------------------------------------------------------------------- #


def gen(name: str):
    cert, key = n.self_signed(name, [name])
    return cert, key, n.fingerprint_from_pem(cert), n.der_from_pem(cert)


def test_bootstrap_accepted_without_previous():
    c0, k0, fp0, der0 = gen("c0")
    c1, _, _, _ = gen("c1")
    k = n.Announcement.new("gateway", None, (fp0, k0), c1, 100)
    assert k.is_bootstrap
    k.verify(None, der0)


def test_single_signature_rejected_when_receiver_has_previous():
    # The attack the rule exists for: asking through with fewer signatures by
    # omitting `prev`. The condition is tied to the RECEIVER's state.
    _, _, _, der0 = gen("c0")
    c1, k1, fp1, der1 = gen("c1")
    c2, _, _, _ = gen("c2")
    k = n.Announcement.new("gateway", None, (fp1, k1), c2, 100)
    with pytest.raises(n.NettlsError, match="single-signed"):
        k.verify(der0, der1)


def test_double_signed_accepted():
    c0, k0, fp0, der0 = gen("c0")
    c1, k1, fp1, der1 = gen("c1")
    c2, _, _, _ = gen("c2")
    k = n.Announcement.new("gateway", (fp0, k0), (fp1, k1), c2, 100)
    k.verify(der0, der1)


def test_swapped_certificate_rejected_even_with_valid_signatures():
    # The signatures cover the FINGERPRINT, not the certificate — so they are
    # still valid. The fingerprint must therefore be checked FIRST.
    c0, k0, fp0, der0 = gen("c0")
    c1, k1, fp1, der1 = gen("c1")
    c2, _, _, _ = gen("c2")
    ondt, _, _, _ = gen("ondt")
    k = n.Announcement.new("gateway", (fp0, k0), (fp1, k1), c2, 100)
    j = k.to_json()
    j["new_cert_pem"] = ondt
    tuklet = n.Announcement.from_json(j)
    with pytest.raises(n.NettlsError, match="swapped in transit"):
        tuklet.verify(der0, der1)


def test_json_roundtrip_preserves_everything():
    c0, k0, fp0, _ = gen("c0")
    c1, k1, fp1, _ = gen("c1")
    c2, _, _, _ = gen("c2")
    k = n.Announcement.new("gateway", (fp0, k0), (fp1, k1), c2, 1_700_000_000)
    assert n.Announcement.from_json(json.loads(json.dumps(k.to_json()))) == k


def test_half_announcement_is_rejected():
    c0, k0, fp0, _ = gen("c0")
    c1, k1, fp1, _ = gen("c1")
    c2, _, _, _ = gen("c2")
    j = n.Announcement.new("gateway", (fp0, k0), (fp1, k1), c2, 1).to_json()
    del j["sig_prev"]
    with pytest.raises(n.NettlsError):
        n.Announcement.from_json(j)


def test_receipt_rejects_replay():
    pk = n.ed25519_public_from_seed(SEED)
    k = n.Receipt.new("service", "gateway", FP_B, 100, SEED)
    k.verify(pk, FP_B)
    with pytest.raises(n.NettlsError, match="a different rotation"):
        k.verify(pk, FP_A)


# --------------------------------------------------------------------------- #
# Generation 0
# --------------------------------------------------------------------------- #


def test_approval_verifies_and_rejects_tampering():
    reg = lambda i: n.ed25519_public_from_seed(SEED) if i == "portal" else None  # noqa: E731
    g = n.Approval.new("gateway", FP_A, "operator", 100, "portal", SEED)
    g.verify(reg)

    j = g.to_json()
    j["approved_by"] = "someone-else"
    with pytest.raises(n.NettlsError):
        n.Approval.from_json(j).verify(reg)


def test_unknown_key_id_says_anchor_cannot_be_verified():
    reg = lambda i: None  # noqa: E731
    g = n.Approval.new("gateway", FP_A, "operator", 100, "op:operator", SEED)
    with pytest.raises(n.NettlsError, match="is not an anchor"):
        g.verify(reg)


# --------------------------------------------------------------------------- #
# Generasjonsparet
# --------------------------------------------------------------------------- #


def test_the_two_roles_are_not_the_same():
    c0, k0, fp0, der0 = gen("c0")
    c1, k1, fp1, der1 = gen("c1")
    c2, _, fp2, _ = gen("c2")

    g = n.Generations(n.Generation.from_der(der0))
    g.receive(n.Announcement.new("gateway", None, (fp0, k0), c1, 1))
    assert g.observed(fp1)
    g.receive(n.Announcement.new("gateway", (fp0, k0), (fp1, k1), c2, 2))

    hs = [x.fp for x in g.accepted_in_handshake()]
    assert fp1 in hs and fp2 in hs
    assert fp0 not in hs, "previous must NOT be accepted in a handshake"
    assert g.for_signing()[0].fp == fp0


def test_receive_is_idempotent():
    c0, k0, fp0, der0 = gen("c0")
    c1, _, _, _ = gen("c1")
    g = n.Generations(n.Generation.from_der(der0))
    k = n.Announcement.new("gateway", None, (fp0, k0), c1, 1)
    assert g.receive(k) == "lagret"
    assert g.receive(k) == "kjent"


# --------------------------------------------------------------------------- #
# Mode
# --------------------------------------------------------------------------- #


def test_mode_is_never_negotiated():
    assert n.Mode.check(n.Mode.ROLLING, n.Mode.ROLLING) is None
    m = n.Mode.check(n.Mode.ROLLING, n.Mode.PINNING)
    assert m and "rolling" in m and "pinning" in m


def test_empty_pin_list_is_an_error():
    # An empty list would give a context that trusts nothing — that must be
    # an ERROR, not a silent state.
    with pytest.raises(n.NettlsError):
        n.pinned_ssl_context([])


# --------------------------------------------------------------------------- #
# Locking at rest (§8.4)
# --------------------------------------------------------------------------- #


def test_lock_roundtrip():
    f = n.lock("secret-password", b"peer registry + keys")
    assert n.unlock("secret-password", f) == b"peer registry + keys"


def test_wrong_password_gives_authentication_failure():
    # No stored verification hash — the AEAD speaks up by itself.
    f = n.lock("secret-password", b"x")
    with pytest.raises(n.NettlsError, match="wrong password"):
        n.unlock("hemmeliG", f)


def test_no_phc_hash_in_the_file():
    # A stored hash would give an attacker with the disk a SEPARATE oracle to
    # test candidates against, alongside the ciphertext he had to attack
    # anyway.
    f = n.lock("secret-password", b"x")
    assert b"$argon2" not in f
    assert f[:8] == b"NETTLS\x01\x00"
    assert f[8 + 32 : 8 + 32 + 4] == b"FAFN", "the FAFN blob must start right after the salt"


def test_altered_ciphertext_and_salt_rejected():
    f = bytearray(n.lock("secret-password", b"something important"))
    f[-1] ^= 1
    with pytest.raises(n.NettlsError):
        n.unlock("secret-password", bytes(f))

    f2 = bytearray(n.lock("secret-password", b"something important"))
    f2[8] ^= 1  # first salt byte
    with pytest.raises(n.NettlsError):
        n.unlock("secret-password", bytes(f2))


def test_wrong_format_says_it_is_the_format():
    # "Wrong password" would send the operator hunting for a password when she
    # would hunt for the right file.
    with pytest.raises(n.NettlsError, match="unknown file format"):
        n.unlock("x", b"this is quite definitely not a locked file at all")


def test_same_content_gives_different_ciphertext():
    assert n.lock("secret-password", b"x") != n.lock("secret-password", b"x")


# --------------------------------------------------------------------------- #
# Sealed envelope (§8.5) — the sender as a blind courier
# --------------------------------------------------------------------------- #


def test_envelope_roundtrip():
    private_key, public = n.envelope_generate_key()
    k = n.envelope_seal(public, b"something only the recipient may see")
    assert n.envelope_open(private_key, k) == b"something only the recipient may see"


def test_sender_cannot_open_own_envelope():
    """The whole point: portal seals, and cannot get back in.

    The ephemeral key sealing draws is discarded in the same call. There is no
    `envelope_seal` variant that gives the sender anything to open with — and
    that is a property of the API, not a rule someone must remember to follow.
    """
    _, public = n.envelope_generate_key()
    k = n.envelope_seal(public, b"device-password")

    # Alt en avsender sitter igjen med er konvolutten og mottakerens OFFENTLIGE
    # key. Neither part opens it.
    with pytest.raises(n.NettlsError):
        n.envelope_open(public, k)


def test_wrong_recipient_does_not_get_in():
    _, public = n.envelope_generate_key()
    annen_privat, _ = n.envelope_generate_key()
    k = n.envelope_seal(public, b"x")
    with pytest.raises(n.NettlsError, match="not sealed to this"):
        n.envelope_open(annen_privat, k)


def test_tampered_envelope_is_rejected():
    """Both the ciphertext and the ephemeral key are protected.

    Den last er den interessante: kan en angriper bytte den efemere delen uten
    unnoticed, the binding to both public keys falls away — it
    klassiske feilen i hjemmesnekrede sealed-box-varianter.
    """
    private_key, public = n.envelope_generate_key()

    k = bytearray(n.envelope_seal(public, b"something important"))
    k[-1] ^= 1  # chifferteksten
    with pytest.raises(n.NettlsError):
        n.envelope_open(private_key, bytes(k))

    k2 = bytearray(n.envelope_seal(public, b"something important"))
    k2[8] ^= 1  # first byte of the ephemeral public key
    with pytest.raises(n.NettlsError):
        n.envelope_open(private_key, bytes(k2))


def test_envelope_wrong_format_says_it_is_the_format():
    private_key, _ = n.envelope_generate_key()
    with pytest.raises(n.NettlsError, match="not a nettls envelope"):
        n.envelope_open(private_key, b"NETTLS\x01\x00 this is a locked file, not an envelope")
    with pytest.raises(n.NettlsError, match="too short"):
        n.envelope_open(private_key, b"kort")


def test_wrong_key_length_rejected_with_the_length():
    with pytest.raises(n.NettlsError, match="32 bytes"):
        n.envelope_seal(b"for kort", b"x")


def test_same_plaintext_gives_different_envelopes():
    # A fresh ephemeral key per sealing — two equal device passwords must not be
    # gjenkjennelige som like for den som ser konvoluttene passere.
    _, public = n.envelope_generate_key()
    assert n.envelope_seal(public, b"x") != n.envelope_seal(public, b"x")


def test_public_part_derives_stably():
    private_key, public = n.envelope_generate_key()
    assert n.envelope_public(private_key) == public


# --------------------------------------------------------------------------- #
# Gjenoppretting av husket state (§6.8)
# --------------------------------------------------------------------------- #


def _gen(name):
    pem, key = n.self_signed(name, [name], days=30)
    return pem, key, n.Generation.from_pem(pem)


def test_restored_state_accepts_double_signed_announcement():
    """The core of §6.8 — and A8 (decided 2026-08-14).

    The peer has rolled, so it signs with prev+curr. A receiver holding only
    an anchor verifies what it CAN — sig_curr against the anchor — and
    accepts: the generation numbering is local to the receiver. A receiver
    that has remembered its previous verifies both signatures.
    """
    p0, k0, g0 = _gen("c0")
    p1, k1, g1 = _gen("c1")
    p2, _, _ = _gen("c2")
    k = n.Announcement.new("gateway", (g0.fp, k0), (g1.fp, k1), p2, 1_700_000_000)

    glemt = n.Generations(g1)
    assert glemt.receive(k) == "lagret", (
        "A8: an anchor-only receiver accepts a double-signed announcement "
        "whose curr matches the anchor"
    )

    husket = n.Generations.restore(g0, g1, None)
    assert husket.receive(k) == "lagret"


def test_restored_next_accepted_in_handshake_and_promoted():
    """A pending «next» must survive too — not just «previous».

    Without it, a restart between announcement and swap would forget that the
    peer had promised a new certificate, and the handshake would reject it
    exactly when the peer
    actually switched.
    """
    _, _, g0 = _gen("c0")
    _, _, g1 = _gen("c1")
    _, _, g2 = _gen("c2")
    g = n.Generations.restore(g0, g1, g2)

    fps = [x.fp for x in g.accepted_in_handshake()]
    assert g1.fp in fps and g2.fp in fps

    assert g.observed(g2.fp)
    assert g.current.fp == g2.fp
    assert g.previous.fp == g1.fp


def test_restore_rejects_impossible_states():
    _, _, g0 = _gen("c0")
    _, _, g1 = _gen("c1")
    for previous, current, next in [
        (g1, g1, None),   # previous == current
        (None, g1, g1),   # next == current
        (g0, g1, g0),     # tilbake til det den nettopp forlot
    ]:
        with pytest.raises(n.NettlsError):
            n.Generations.restore(previous, current, next)
    assert n.Generations.restore(g0, g1, None) is not None


# --------------------------------------------------------------------------- #
# Levetider og varsling (M-11, M-12, M-21)
# --------------------------------------------------------------------------- #


def test_mode2_lifetime_is_always_thirty_days():
    """M-21. Not tunable — the rotation IS the security mechanism.

    A lifetime the operator can tweak would make it a setting in
    stedet for en garanti.
    """
    assert n.mode2_lifetime() == 30
    assert n.MODE2_LIFETIME_DAYS == 30


def test_self_signed_uses_same_lifetime_as_constant():
    """Én kilde til sannheten. To ville drevet fra hverandre."""
    import datetime

    pem, _ = n.self_signed("x", ["x"])
    from cryptography import x509

    c = x509.load_pem_x509_certificate(pem.encode())
    spenn = c.not_valid_after_utc - c.not_valid_before_utc
    # The span is the lifetime PLUS the backdating for clock skew.
    assert spenn == datetime.timedelta(
        days=n.MODE2_LIFETIME_DAYS, seconds=n.BAKDATERING_S
    )


def test_backdating_matches_rust():
    """The clock-skew tolerance must be the same in both implementations.

    Python hadde 5 minutter mot Rust sin ene time — en 12× strammere toleranse.
    A Python-issued certificate would be rejected as "not yet valid" by a
    peer whose clock ran 10 minutes behind. No cross-test could see it:
    signatures and format were identical, and the ring test runs all nodes on
    samme klokke.
    """
    assert n.BAKDATERING_S == 3600, (
        "must match `p.not_before = now - Duration::hours(1)` in material.rs"
    )


def test_mode1_warns_at_thirty_days_left():
    """M-12: ikke ved 5, og ikke i det sertifikatet faller."""
    expires_at = 1_000 * n.DAY_S
    assert not n.mode1_should_warn(expires_at - 31 * n.DAY_S, expires_at)
    assert n.mode1_should_warn(expires_at - 30 * n.DAY_S, expires_at)
    assert n.mode1_should_warn(expires_at - 1 * n.DAY_S, expires_at)
    # Also after expiry — that is when it is most urgent.
    assert n.mode1_should_warn(expires_at + n.DAY_S, expires_at)


def test_mode1_lifetime_has_floor_and_ceiling():
    assert n.mode1_lifetime() == n.MODE1_DEFAULT_DAYS == 90
    assert n.mode1_lifetime(47) == 47
    assert n.mode1_lifetime(365) == 365
    with pytest.raises(n.NettlsError, match="below the floor"):
        n.mode1_lifetime(46)
    with pytest.raises(n.NettlsError, match="above the ceiling"):
        n.mode1_lifetime(366)


# --------------------------------------------------------------------------- #
# SAN: hostnavn, IP-adresser, og blandingen (paritet med tests/selfsigned.rs)
# --------------------------------------------------------------------------- #


def _sans(pem: str):
    """(dns-name, ip-adresser) fra sertifikatets SAN."""
    from cryptography import x509

    c = x509.load_pem_x509_certificate(pem.encode())
    ext = c.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    return (
        ext.get_values_for_type(x509.DNSName),
        [str(i) for i in ext.get_values_for_type(x509.IPAddress)],
    )


def test_san_separates_ip_from_hostname():
    """An IP must go in as `iPAddress`, not as `dNSName`.

    Put an IP in as a DNS name, and every verification against that address fails —
    klienten leter etter en IP i IP-feltet og finner ingenting. Feilen er
    unpleasant because the certificate looks right when you read it.
    """
    pem, _ = n.self_signed("node", ["localhost", "127.0.0.1", "node.intern", "::1"])
    dns, ip = _sans(pem)
    assert dns == ["localhost", "node.intern"]
    assert ip == ["127.0.0.1", "::1"]


def test_san_hostnames_only():
    pem, _ = n.self_signed("a", ["a.intern", "alias.intern"])
    dns, ip = _sans(pem)
    assert dns == ["a.intern", "alias.intern"]
    assert ip == []


def test_san_ip_only():
    pem, _ = n.self_signed("a", ["10.0.0.1"])
    dns, ip = _sans(pem)
    assert dns == []
    assert ip == ["10.0.0.1"]


def test_empty_san_list_is_rejected():
    """Parity with Rust. A certificate without SANs can match no name.

    Python godtok det fram til 2026-08-11 og produserte et ubrukelig
    sertifikat i stillhet.
    """
    with pytest.raises(n.NettlsError, match="at least one SAN"):
        n.self_signed("x", [])


def test_common_name_is_not_enough():
    """CN alone does not count — modern clients look only at SAN.

    Derfor er tom SAN en feil selv om CN er satt.
    """
    pem, _ = n.self_signed("bare-cn", ["bare-cn"])
    dns, _ = _sans(pem)
    assert dns == ["bare-cn"], "the name must be in SAN, not just in CN"


# --------------------------------------------------------------------------- #
# Varsling ved blokkert schedule (M-7c, M-7d, M-7e)
# --------------------------------------------------------------------------- #


def test_alarm_fires_after_twelve_hours_not_before():
    r = n.Schedule(["service"], 0)
    r.announced(1000)
    assert not r.alarm(1000), "no alarm at the moment we announce"
    assert not r.alarm(1000 + n.ALARM_AFTER_S - 1), "not one second too early"
    assert r.alarm(1000 + n.ALARM_AFTER_S), "M-7c: 12 hours after the first attempt"


def test_receipt_stops_the_alarm():
    """A peer that comes back on its own resolves it without an operator (M-7d)."""
    r = n.Schedule(["service"], 0)
    r.announced(1000)
    assert r.alarm(1000 + n.ALARM_AFTER_S)
    r.acked("service")
    assert not r.alarm(1000 + n.ALARM_AFTER_S), "the receipt must silence the alarm"


def test_retries_continue_after_the_alarm():
    """M-7d: the alarm does not stop the retries."""
    r = n.Schedule(["service"], 0)
    r.announced(0)
    for gaatt in (0, 15 * 60, 3600, 24 * 3600):
        assert r.next_retry(gaatt) is not None, (
            f"the retries must continue even {gaatt}s in — also after the alarm"
        )


def test_retry_cadence_is_dense_at_the_start():
    assert n.interval_after(0) == 60
    assert n.interval_after(15 * 60 - 1) == 60
    assert n.interval_after(15 * 60) == 5 * 60
    assert n.interval_after(3600 - 1) == 5 * 60
    assert n.interval_after(3600) == 3600


def test_countdown_is_active_not_a_one_off_warning():
    """M-7e: the operator must see a clock counting down.

    A one-off warning vanishes in a log. A countdown stays, and it is the
    difference between "someone saw it" and "someone did something".
    """
    r = n.Schedule(["service"], 0)
    r.announced(0)
    expires_at = 30 * n.DAY_S
    a = r.countdown(0, expires_at)
    b = r.countdown(10 * n.DAY_S, expires_at)
    assert a and b and a != b, "the text must change as time passes"


def test_twin_version_is_derived_from_the_manifest():
    """The twin reads its version from Cargo.toml, the one place it is declared.

    Nothing here guards two values against each other — there is only one. What
    is worth checking is that the derivation actually works: a broken parse would
    quietly report "unknown" and nobody would notice until a bug report arrived
    with no version in it.
    """
    import pathlib
    import re

    import nettls as twin

    manifest = pathlib.Path(__file__).resolve().parent.parent / "Cargo.toml"
    declared = re.search(r'^version\s*=\s*"([^"]+)"', manifest.read_text(), re.M).group(1)
    assert twin.__version__ == declared
    assert twin.__version__ != "unknown"


def test_support_statement_roundtrip_and_fallback_rule():
    """The signed AEAD support statement (0.8.2): only the non-supporting
    party can authorize a downgrade, and only with its signature; nothing
    acceptable → hard failure (never silently weaker)."""
    key_pem, cert_der = _p256_identity()
    st = n.build_support_statement("service", ["aes256gcm"], 1_700_000_000, key_pem)
    assert n.verify_support_statement(st, cert_der) == ["aes256gcm"]

    # Tampering with the declared set breaks the signature.
    st2 = dict(st, supported=["aegis256", "aes256gcm"])
    try:
        n.verify_support_statement(st2, cert_der)
        raise AssertionError("a tampered statement must not verify")
    except n.NettlsError:
        pass

    # The fallback rule.
    assert n.choose_alg("aegis256", None) == "aegis256"
    assert n.choose_alg("aegis256", ["aes256gcm"]) == "aes256gcm"
    assert n.choose_alg("aegis256", ["aegis256", "aes256gcm"]) == "aegis256"
    try:
        n.choose_alg("aegis256", [])
        raise AssertionError("no acceptable algorithm must fail hard")
    except n.NettlsError as e:
        assert "never silently" in str(e)


def _p256_identity():
    """A throwaway P-256 identity (key PEM + self-signed cert DER) for tests."""
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "statement-test")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    return key_pem, cert.public_bytes(serialization.Encoding.DER)
