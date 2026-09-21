# SPDX-License-Identifier: MIT OR Apache-2.0
"""Cross-test Rust ↔ Python (SPEC-nettls §6.14, requirement M-10).

The vectors show that both agree with **the contract**. This one shows that
they agree with **each other** on fresh data — and the two catch different
things:

| | Catches |
|---|---|
| The test vectors | Errors both implementations **share** — neither matches the answer key |
| The cross-test | Errors where they **disagree** — a signature from one does not hold at the other |

The test builds a small Rust binary that produces messages, and verifies them
here. Then it turns around: Python signs, Rust verifies.

Skipped if `cargo` is not available.

NOTE: the corpus kind names (announcement/kvittering/approval) are frozen
corpus vocabulary and stay as they are.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

import nettls as n  # noqa: E402

ROT = Path(__file__).resolve().parent.parent

pytestmark = pytest.mark.skipif(
    shutil.which("cargo") is None, reason="cargo missing — kryss-test hoppes over"
)

# A small Rust binary that does exactly two things: produces a set of messages
# as JSON, and verifies a set it receives. Nothing else — the smaller it is,
# jo mindre er sjansen for at testen beviser noe om seg selv i stedet for om
# kontrakten.
BRO = r'''
use std::io::Read;
fn main() {
    let mut inn = String::new();
    std::io::stdin().read_to_string(&mut inn).unwrap();
    let v: serde_json::Value = serde_json::from_str(&inn).unwrap();
    match v["op"].as_str().unwrap() {
        // Rust signs → Python verifies
        "produser" => {
            let c0 = nettls::TlsMaterial::load(&nettls::CertSource::self_signed(
                nettls::SelfSignedParams::new("c0", ["c0"]))).unwrap();
            let c1 = nettls::TlsMaterial::load(&nettls::CertSource::self_signed(
                nettls::SelfSignedParams::new("c1", ["c1"]))).unwrap();
            let c2 = nettls::TlsMaterial::load(&nettls::CertSource::self_signed(
                nettls::SelfSignedParams::new("c2", ["c2"]))).unwrap();
            let pem = |m: &nettls::TlsMaterial| -> String {
                let der = m.cert_chain()[0].as_ref().to_vec();
                let mut s = String::from("-----BEGIN CERTIFICATE-----\n");
                use base64ct::{Base64, Encoding};
                let b = Base64::encode_string(&der);
                for c in b.as_bytes().chunks(64) { s.push_str(std::str::from_utf8(c).unwrap()); s.push('\n'); }
                s.push_str("-----END CERTIFICATE-----\n"); s
            };
            let fp = |m: &nettls::TlsMaterial| m.fingerprint_sha256().replace("sha256:", "");
            let pk = |m: &nettls::TlsMaterial| nettls::pkcs8_for_test(m).unwrap();
            let k = nettls::announcement::Announcement::new(
                "gateway", Some((&fp(&c0), &pk(&c0))), (&fp(&c1), &pk(&c1)), &pem(&c2), 1700000000,
            ).unwrap();
            let seed = krypto::SecretBuf::from_vec(vec![3u8; 32]).unwrap();
            let kv = nettls::announcement::Receipt::new(
                "service", "gateway", k.new_fingerprint(), 1700000001, &seed).unwrap();
            let g = nettls::approval::Approval::new(
                "gateway", &fp(&c0), "operator", 1700000002, "portal", &seed).unwrap();
            println!("{}", serde_json::json!({
                "announcement": k.to_json(),
                "receipt": kv.to_json(),
                "approval": g.to_json(),
                "prev_cert_pem": pem(&c0),
                "curr_cert_pem": pem(&c1),
                "ed25519_pub": krypto::hex::encode(
                    &krypto::sign::ed25519_public(&seed).unwrap()),
            }));
        }
        // Python signs → Rust verifies
        "verify" => {
            let kj: nettls::announcement::AnnouncementJson =
                serde_json::from_value(v["announcement"].clone()).unwrap();
            let k = nettls::announcement::Announcement::from_json(&kj).unwrap();
            let der = |s: &str| nettls::announcement::der_from_pem(s).unwrap();
            let prev = v["prev_cert_pem"].as_str().map(der);
            let curr = der(v["curr_cert_pem"].as_str().unwrap());
            k.verify(prev.as_deref(), &curr).unwrap();

            let kvj: nettls::announcement::ReceiptJson =
                serde_json::from_value(v["receipt"].clone()).unwrap();
            let kv = nettls::announcement::Receipt::from_json(&kvj).unwrap();
            let pub_ = nettls::signature::from_hex(v["ed25519_pub"].as_str().unwrap()).unwrap();
            kv.verify(&pub_, k.new_fingerprint()).unwrap();

            let gj: nettls::approval::ApprovalJson =
                serde_json::from_value(v["approval"].clone()).unwrap();
            let g = nettls::approval::Approval::from_json(&gj).unwrap();
            g.verify(&|id: &str| if id == "portal" { Some(pub_.clone()) } else { None }).unwrap();

            println!("OK");
        }
        // Lock in Rust → unlock in Python
        "lock" => {
            let pw = krypto::SecretString::from_string(v["password"].as_str().unwrap().to_string()).unwrap();
            let ut = nettls::lockbox::lock_with(&pw, v["plaintext"].as_str().unwrap().as_bytes(), krypto::Alg::Aes256Gcm).unwrap();
            println!("{}", serde_json::json!({"file": krypto::hex::encode(&ut)}));
        }
        // Lock in Python → unlock in Rust
        "unlock" => {
            let pw = krypto::SecretString::from_string(v["password"].as_str().unwrap().to_string()).unwrap();
            let fil = nettls::signature::from_hex(v["file"].as_str().unwrap()).unwrap();
            let ut = nettls::lockbox::unlock(&pw, &fil).unwrap();
            let s = ut.expose(|b| String::from_utf8_lossy(b).into_owned());
            println!("{s}");
        }
        // Seal in Rust → open in Python. Python owns the key pair and sends
        // only the PUBLIC part here — as in practice, where the sender seals
        // to a public key it was handed as a file.
        "envelope_seal" => {
            let mott = nettls::signature::from_hex(v["mottaker_off"].as_str().unwrap()).unwrap();
            let k = nettls::envelope::seal_with(&mott, v["plaintext"].as_str().unwrap().as_bytes(), krypto::Alg::Aes256Gcm).unwrap();
            println!("{}", serde_json::json!({"envelope": krypto::hex::encode(&k)}));
        }
        // Seal in Python → open in Rust. The private key is sent in here
        // because the bridge is stateless between calls; in production it
        // lives as a file at the recipient (§8.7).
        "envelope_open" => {
            let private_key = nettls::signature::from_hex(v["private_key"].as_str().unwrap()).unwrap();
            let n = nettls::envelope::RecipientKey::from_bytes(krypto::SecretBuf::from_vec(private_key).unwrap()).unwrap();
            let k = nettls::signature::from_hex(v["envelope"].as_str().unwrap()).unwrap();
            let ut = nettls::envelope::open(&n, &k).unwrap();
            let s = ut.expose(|b| String::from_utf8_lossy(b).into_owned());
            // The public part comes along: then we get confirmation that the
            // two stacks (krypto vs `cryptography`) derive the SAME
            // public key from the same private bytes.
            println!("{}", serde_json::json!({
                "plaintext": s,
                "public": krypto::hex::encode(&n.public().unwrap()),
            }));
        }
        // The error matrix across the bridge: Rust passes its verdict on each
        // entry, and Python compares with its own. Not "did both reject?" —
        // but did they reject at the SAME LEVEL. A party stopping something at
        // parsing while the other first catches it at verification does not
        // agree with the other; it just happens not to be vulnerable yet.
        "dom" => {
            let g = &v["gyldig"];
            let prev = nettls::announcement::der_from_pem(g["prev_cert_pem"].as_str().unwrap()).unwrap();
            let curr = nettls::announcement::der_from_pem(g["curr_cert_pem"].as_str().unwrap()).unwrap();
            let pk = nettls::signature::from_hex(g["ed25519_pub"].as_str().unwrap()).unwrap();
            let mut ut = serde_json::Map::new();
            for (kind, poster) in v["poster"].as_object().unwrap() {
                let mut dommer = serde_json::Map::new();
                for (name, j) in poster.as_object().unwrap() {
                    let d = match kind.as_str() {
                        "announcement" => (|| {
                            let kj: nettls::announcement::AnnouncementJson =
                                serde_json::from_value(j.clone()).map_err(|_| ())?;
                            let o = nettls::announcement::Announcement::from_json(&kj).map_err(|_| ())?;
                            Ok(o.verify(Some(&prev), &curr).is_ok())
                        })(),
                        "receipt" => (|| {
                            let kj: nettls::announcement::ReceiptJson =
                                serde_json::from_value(j.clone()).map_err(|_| ())?;
                            let o = nettls::announcement::Receipt::from_json(&kj).map_err(|_| ())?;
                            let fp = o.new_fingerprint().to_string();
                            Ok(o.verify(&pk, &fp).is_ok())
                        })(),
                        _ => (|| {
                            let gj: nettls::approval::ApprovalJson =
                                serde_json::from_value(j.clone()).map_err(|_| ())?;
                            let o = nettls::approval::Approval::from_json(&gj).map_err(|_| ())?;
                            let f = |id: &str| if id == "portal" { Some(pk.clone()) } else { None };
                            Ok(o.verify(&f).is_ok())
                        })(),
                    };
                    let dom = match d {
                        Err(()) => "avvist_ved_parsing",
                        Ok(false) => "avvist_ved_verifisering",
                        Ok(true) => "godtatt",
                    };
                    dommer.insert(name.clone(), serde_json::json!(dom));
                }
                ut.insert(kind.clone(), serde_json::Value::Object(dommer));
            }
            println!("{}", serde_json::Value::Object(ut));
        }
        annet => panic!("ukjent op: {annet}"),
    }
}
'''


def _krypto_dep() -> str:
    """Path dep where the sibling directory exists, otherwise registry.

    Mirrors exactly what CI does with `nettls`'s own manifest (the `sed` that
    fjerner path-en). Uten dette bygget broen mot
    `{ROT}/../krypto`, which only exists on a developer machine — in CI only
    `nettls` is checked out, and the cross-test failed with «No such file or
    directory» after everything else had passed.

    **And the choice must follow nettls's own**, not merely be available: if
    the crate uses path-krypto while the bridge uses registry-krypto, two
    DIFFERENT krypto crates end up in the same graph. `krypto::SecretString`
    from one is then not the same type as from the other, and the bridge does
    not compile.
    """
    sosken = ROT.parent / "krypto"
    if sosken.exists():
        return f'krypto = {{ path = "{sosken}" }}'
    # CI (no sibling): follow nettls's OWN dependency line, read from its
    # manifest. BOTH the version and the registry are read rather than written
    # down here, and both for the same reason.
    #
    # A hardcoded version drifts the first time nettls bumps its krypto
    # dependency, and then TWO incompatible krypto crates land in the graph —
    # that has happened: the bridge said 0.5 while nettls 0.8.2 required 0.6, a
    # failure only CI could see.
    #
    # A hardcoded registry is the same mistake one level down, and it has also
    # happened. A CI that resolves krypto from a public registry strips
    # `registry = ...` from the manifest; a bridge that puts it back fails to
    # PARSE — «registry index was not found in any configuration» — before a
    # single test runs.
    manifest = (ROT / "Cargo.toml").read_text()
    line = re.search(r"^krypto\s*=.*$", manifest, re.M)
    if not line:
        raise AssertionError("could not find nettls's krypto dependency in Cargo.toml")
    version = re.search(r'version\s*=\s*"([^"]+)"', line.group(0))
    if not version:
        raise AssertionError("could not read nettls's krypto version from Cargo.toml")
    parts = [f'version = "{version.group(1)}"']
    registry = re.search(r'registry\s*=\s*"([^"]+)"', line.group(0))
    if registry:
        parts.append(f'registry = "{registry.group(1)}"')
    return "krypto = { " + ", ".join(parts) + " }"


def _bridge_dir() -> Path:
    """Builds the bridge binary in a temporary crate depending on nettls."""
    d = Path(tempfile.mkdtemp(prefix="nettls-kryss-"))
    (d / "src").mkdir()
    (d / "src" / "main.rs").write_text(BRO)
    (d / "Cargo.toml").write_text(
        f"""[package]
name = "kryssbro"
version = "0.0.0"
edition = "2021"

[dependencies]
nettls = {{ path = "{ROT}" }}
serde_json = "1"
{_krypto_dep()}
base64ct = {{ version = "1", features = ["alloc"] }}
"""
    )
    return d


def _run(d: Path, inn: dict) -> str:
    r = subprocess.run(
        ["cargo", "run", "-q", "--manifest-path", str(d / "Cargo.toml")],
        input=json.dumps(inn),
        capture_output=True,
        text=True,
        timeout=600,
    )
    if r.returncode != 0:
        raise AssertionError(f"bridge feilet:\n{r.stderr[-3000:]}")
    return r.stdout.strip()


@pytest.fixture(scope="module")
def bridge():
    d = _bridge_dir()
    yield d
    shutil.rmtree(d, ignore_errors=True)


def test_rust_signs_python_verifies(bridge):
    ut = json.loads(_run(bridge, {"op": "produser"}))

    k = n.Announcement.from_json(ut["announcement"])
    k.verify(n.der_from_pem(ut["prev_cert_pem"]), n.der_from_pem(ut["curr_cert_pem"]))

    kv = n.Receipt.from_json(ut["receipt"])
    kv.verify(n.from_hex(ut["ed25519_pub"]), k.new_fp)

    g = n.Approval.from_json(ut["approval"])
    g.verify(lambda i: n.from_hex(ut["ed25519_pub"]) if i == "portal" else None)


def test_python_signs_rust_verifies(bridge):
    seed = bytes([3] * 32)
    c0, k0 = n.self_signed("c0", ["c0"])
    c1, k1 = n.self_signed("c1", ["c1"])
    c2, _ = n.self_signed("c2", ["c2"])
    fp0, fp1 = n.fingerprint_from_pem(c0), n.fingerprint_from_pem(c1)

    k = n.Announcement.new("gateway", (fp0, k0), (fp1, k1), c2, 1_700_000_000)
    kv = n.Receipt.new("service", "gateway", k.new_fp, 1_700_000_001, seed)
    g = n.Approval.new("gateway", fp0, "operator", 1_700_000_002, "portal", seed)

    reply = _run(
        bridge,
        {
            "op": "verify",
            "announcement": k.to_json(),
            "receipt": kv.to_json(),
            "approval": g.to_json(),
            "prev_cert_pem": c0,
            "curr_cert_pem": c1,
            "ed25519_pub": n.to_hex(n.ed25519_public_from_seed(seed)),
        },
    )
    assert reply == "OK", reply


def test_rust_locks_python_unlocks(bridge):
    """The lock at rest is bit-compatible both ways (§8.4).

    Not because the two sides read each other's files — each module locks its
    own — but because one format is one thing to keep correct. Two formats
    would have been two, and
    det ene blir aldri revidert.
    """
    ut = json.loads(_run(bridge, {"op": "lock", "password": "secret-pw", "plaintext": "state"}))
    assert n.unlock("secret-pw", n.from_hex(ut["file"])) == b"state"

    with pytest.raises(n.NettlsError):
        n.unlock("wrong-password", n.from_hex(ut["file"]))


def test_python_locks_rust_unlocks(bridge):
    fil = n.lock("secret-pw", b"state from python")
    reply = _run(bridge, {"op": "unlock", "password": "secret-pw", "file": n.to_hex(fil)})
    assert reply == "state from python", reply


# ── The sealed envelope (§8.5) ────────────────────────────────────────────── #
#
# This edge is the ONLY one that is purely one-way in operation: the sender
# seals, and the recipient opens. If the two sides drift apart here, it is
# not caught by a
# handshake and not by a signature that fails to verify — the envelope is only
# simply impossible to open, at one of the parties, at the moment a module is
# to be unlocked. Exactly the same class of error as hex-vs-base64, at a worse
# time.
#
# The stacks are NOT the same either: Rust uses `x25519-dalek` (ring has only
# ephemeral X25519), Python uses `cryptography`. That both say "X25519" is no
# proof that they agree on the HKDF `info`, on the AAD, or on which public
# keys are bound into the derivation.


def test_rust_seals_python_opens(bridge):
    """Rust seals to a key Python owns. Only the public part goes out."""
    private_key, public = n.envelope_generate_key()
    ut = json.loads(
        _run(
            bridge,
            {
                "op": "envelope_seal",
                "mottaker_off": n.to_hex(public),
                "plaintext": "device password from portal",
            },
        )
    )
    konv = n.from_hex(ut["envelope"])
    assert n.envelope_open(private_key, konv) == b"device password from portal"

    # A different recipient must not get in. Without this the test would have
    # passed even if the key binding were gone and everyone could open
    # everything.
    annen, _ = n.envelope_generate_key()
    with pytest.raises(n.NettlsError):
        n.envelope_open(annen, konv)


def test_python_seals_rust_opens(bridge):
    """The other way — and at the same time: do the two stacks derive the same public key?"""
    private_key, public = n.envelope_generate_key()
    konv = n.envelope_seal(public, b"state from python")
    ut = json.loads(
        _run(
            bridge,
            {"op": "envelope_open", "private_key": n.to_hex(private_key), "envelope": n.to_hex(konv)},
        )
    )
    assert ut["plaintext"] == "state from python", ut

    # Same private bytes → same public key in both stacks. If this
    # feil, ville hver side forseglet til «sin egen» oppfatning av mottakeren.
    assert n.from_hex(ut["public"]) == public


# ── The error matrix across (§6.14b) ──────────────────────────────────────── #
#
# `python/test_feil.py` og `tests/feil.rs` leser samme korpus, men hver for seg,
# i hver sin prosess. Denne feller de to dommene mot hverandre — og krever at de
# are equal AT LEVEL, not merely that both ended in "no".
#
# The level is not a detail. If Rust stops something at parsing while Python
# catches it at verification, they disagree: Python has then let an invalid
# value gets to become an object in the program, and verification is the only
# thing standing
# between it and a signed string. That is a difference in attack surface, not in
# stil.


def _python_dom(kind: str, j: dict, gyldig: dict) -> str:
    lesere = {
        "announcement": n.Announcement.from_json,
        "receipt": n.Receipt.from_json,
        "approval": n.Approval.from_json,
    }
    try:
        o = lesere[kind](j)
    except n.NettlsError:
        return "avvist_ved_parsing"
    try:
        if kind == "announcement":
            o.verify(
                n.der_from_pem(gyldig["prev_cert_pem"]),
                n.der_from_pem(gyldig["curr_cert_pem"]),
            )
        elif kind == "receipt":
            o.verify(n.from_hex(gyldig["ed25519_pub"]), o.new_fp)
        else:
            o.verify(
                lambda kid: n.from_hex(gyldig["ed25519_pub"]) if kid == "portal" else None
            )
    except n.NettlsError:
        return "avvist_ved_verifisering"
    return "godtatt"


def test_both_pass_same_verdict_over_entire_error_corpus(bridge):
    """Python ↔ Rust: 40 hostile messages, same verdict at the same level."""
    korpus = json.loads((ROT / "testvectors" / "errors.json").read_text())
    gyldig = korpus["_valid"]

    poster = {
        kind: {p["name"]: p["json"] for p in korpus[kind]}
        for kind in ("announcement", "receipt", "approval")
    }
    rust = json.loads(_run(bridge, {"op": "dom", "gyldig": gyldig, "poster": poster}))

    mismatches = []
    for kind, ps in poster.items():
        for name, j in ps.items():
            py = _python_dom(kind, j, gyldig)
            ru = rust[kind][name]
            if py != ru:
                mismatches.append(f"  {kind}/{name}: python={py} rust={ru}")
    assert not mismatches, "the two sides disagree on hostile messages:\n" + "\n".join(mismatches)

    # Positive control: without it everything above could have been
    # "rejected at parsing" on both sides for a trivial reason, and the test
    # would have looked green.
    for kind in ("announcement", "receipt", "approval"):
        assert _python_dom(kind, gyldig[kind], gyldig) == "godtatt", (
            f"the baseline {kind} does not pass — then the corpus probes nothing"
        )
