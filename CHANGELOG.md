# Changelog — nettls

Every notable change to this crate is recorded here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project follows [Semantic Versioning](https://semver.org/).

> **Note:** the API can change between minor versions. Every entry in `docs/API.md` is
> marked with the version it applies from, so a reader sees what holds for their version
> without guessing.

## [0.9.0] — 2026-09-21 (the repository starts over)

### Note — the history starts here, on purpose

The repository this crate lived in was cleaned out and started fresh at this version. The
earlier commits were written while a larger private system was being built, and they describe
it: sibling services, internal documents, decisions that belong to that system rather than to
this crate. 128 of them also carried an author identity that is no longer the right one, and
their messages were largely in a language this crate stopped using at 0.7.0. Carrying them
along would have mixed design for other things into a crate meant to stand on its own.

What each release changed is in this file. The code is what it was — the tree at 0.9.0 is the
tree that was there at 0.8.6, minus nothing. Only the commit history was left behind, and the
untouched original is archived where the people who need it can reach it.

### Added — the crate declares itself to a registry

`keywords` and `categories` in the manifest, and `repository` now points somewhere the outside
world can actually reach.

### Fixed — the description promised something removed in 0.8.2

It advertised "sliding pinning (a continuity chain with rotation proofs)". The rotation proofs
went with the §5 model, and the words appear nowhere else in the crate — not in the code, not in
the docs, not in the README, which has described the §6 protocol correctly all along. The
description is the first thing a reader sees on a registry, and it was the last place still
saying the old thing.

## [0.8.6] — 2026-09-21 (prepared for release outside this project)

No functional change. Not one public signature moved; the whole round is about what a reader
outside meets when they open the crate.

### Changed — the crate no longer names what it was built for

Doc comments, test data and test names identified the services around this crate, the internal
documents that held a rule, and the deployment it ran in. None of that reaches someone who has
never seen any of it, so the names are out and the meaning stays: a sender seals, a recipient
opens, a consuming service keeps the state. Test fixtures use role names — `gateway`, `service`,
`portal`, `operator` — and both vector files are regenerated rather than edited, because the
names sit inside the signed canonical bytes.

What is *not* removed is where the crate came from. It was built for an application where two
services both needed HTTPS and an operator's device password passed through both, and it has run
there ever since. That belongs in the README, and it is there.

### Added — `SECURITY.md`, `CONTRIBUTING.md`, and SPDX identifiers

A security policy that says what a report must contain, that an AI-assisted finding must be
checked by a person before it is sent, and that a flaw in rustls, rcgen, x509-parser or `krypto`
belongs upstream — but say that it exists. Contribution terms: reports are what is wanted, code
is accepted only under the crate's own licence. And `SPDX-License-Identifier: MIT OR Apache-2.0`
as the first line of all 46 source files.

### Changed — the README says why the licence is dual, and what the design came from

The dual licence is about patents, not about what other crates do: MIT is silent on them,
Apache-2.0 grants one explicitly. And RFC 8061 — confidentiality in the data plane — moves from a
footnote to the reason the crate looks the way it does: endpoints that keep traffic confidential
without a certificate authority between them.

The promise of an API freeze at 1.0 is gone from every file. There is no such plan. What makes
the API safe to build on is that each entry in `docs/API.md` carries the version it applies from.

### Fixed — the README described a crate that no longer existed

Four errors, all of them things nothing was checking. The dependency list named `rustls-pemfile`
(out since 0.8.1), said `krypto 0.6`, and omitted `aegis` and `zeroize` — both direct
dependencies since 0.8.3. The module table was missing four public modules: `capability`,
`status`, `pem` and `error`. And two test counts were wrong.

`docs/API.md` had drifted on none of this, because a test fails the build when a public name is
missing from it. The README was guarded by nothing. The test counts are now gone rather than
corrected — a number in a README is a claim nobody maintains.

### Fixed — three error messages named something that no longer exists

`TlsError::Proof`, `ProofInvalid` and `Sign` are used across the whole §6 surface —
announcements, approvals, support statements, envelopes, the lockbox, hex parsing. Their
messages still described the retired §5 rotation proof, so a failure to open a sealed envelope
reported that *the rotation proof does not hold*. The variant names are part of the API and stay;
the text now says what actually happened: a signed value could not be parsed, a signature or
sealed value does not hold, a signature could not be produced.

Their doc comments went the same way, along with eight references to §5 sections in other modules
and an error string telling the caller that *rotation proofs* require ECDSA P-256 when what
requires it is signing. Nothing tested any of this text, which is precisely why it could rot.

### Fixed — docs/API.md documented two names that never existed

The doc guard fails the build when a public name is missing from the API contract. It does not
look the other way, so the contract could name something the code does not have — and it did:
`pinning_pending` and `pinning_broken`, in the enrollment rule. The states are called
`PeerState::RotationPending` and `PeerState::Broken`.

Checked in both directions now. Of the 169 names the contract mentions, the seven that are not in
this crate are krypto's two Ed25519 constants (labelled as krypto's) and the five §5 items in the
removed-history section, which is where they belong.

### Changed — the code is English throughout

The crate declared its language English at 0.7.0 and 147 identifiers stayed Norwegian anyway:
`feil`, `hemmelig`, `forste`, `andre`, `hva`, `svar`, `koble_til`, `slaa_opp`, `forrige_sti`,
`Vektor`, `linje`, `laast` and more. All local variables and private helpers — no public name
changed. Four comments and one assertion message were half-translated and are now whole.

### Changed — the version is declared in one place

`Cargo.toml` is now the only file that writes it down. The `VERSION` file is gone, and the Python
twin reads the manifest instead of carrying a copy.

It used to stand in three places held in step by two tests. That worked, and it is still three
places to edit and two tests to explain — a guard against drift is an admission that drift is
possible. A derived value has nothing to drift from. The Rust side was already derived
(`env!("CARGO_PKG_VERSION")`); now the Python side is too, and the test that compared them is
replaced by one that checks the derivation actually resolves rather than quietly reporting
"unknown".

`nettls::VERSION` and `nettls.__version__` are unchanged as names. Only where they get their
value changed.

### Changed — requires krypto 0.7

The path dependency points at a sibling checkout that moved to 0.7.0. `registry = "gitea"` stays:
resolving from the private registry is what lets a release be tried before it goes anywhere else.

### Changed — the changelog starts at 0.7.0

Everything before it is gone from this file and archived, untouched, outside the crate. It
described which internal case drove a release and which sibling service needed it. Every design
reason in those entries already lives in the doc comments — checked before cutting, not assumed.

## [0.8.5] — 2026-09-20 (security fix: a rustls advisory out of the lockfile)

### Fixed — RUSTSEC-2026-0285

`Cargo.lock` stood at **rustls 0.23.43**, which is affected by *"TLS 1.3 handshake messages
incorrectly accepted across encryption level boundaries"*
([RUSTSEC-2026-0285](https://rustsec.org/advisories/RUSTSEC-2026-0285)). Raised to
**0.23.45**, and `rustls-webpki` followed from 0.103.13 to 0.103.15.

This crate's own CI runs `cargo deny`, and the step was **red**: `advisories FAILED`.
It now reads `advisories ok, bans ok, licenses ok, sources ok`.

The consumers had already raised their own lockfiles on 2026-09-15 (L2-115); this crate's
was the one left behind. No code change, no surface change — the lockfile only.

## [0.8.4] — 2026-09-04 (documentation only)

### Fixed — README and docs/Home brought up to date with 0.8.3

No code change. 0.8.3 shipped with a README that still carried §5 leftovers (the module table
listed `chain` + `rotation`, removed in 0.8.2; a "sliding pinning" status; "holds the proof"),
the claim "no cipher filtering" (untrue from 0.8.3), and adoption status for other services
(which belongs to those services, not to this crate). Roger: "I would rather have things
correct" — hence a release of its own. `transport` and `aegis` are in the module table; Home no
longer mentions "the rotation proof".

## [0.8.3] — 2026-09-04 (the code round after the spec round)

### Added — `aegis`: AEGIS-256 in the TLS channel as a **deliberate deviation**, built to be replaced (L2-076)

The premise in the case was wrong, and I am the one who wrote it: PR rustls#2737 made the IV
length variable, but never raised the ceiling — `Iv::MAX_LEN` is 16 both in 0.24.0-dev.1 and on
git main (read in the source 2026-09-04), AEGIS-256 needs 32, and nobody upstream is working on
it. Roger 2026-09-04: this crate only talks to itself in this channel, so we build our own suite
and write down exactly what we do and why — in the spec, in the code, and here:

| Deviation | What we do |
|---|---|
| Nonce | rustls' 12-byte TLS 1.3 nonce (`iv XOR seq`), left-aligned and zero-extended to 32 — unique per key because the TLS nonce is |
| Code point | `0xFF06` (TLS private use), an echo of `0x1306` — a non-standard suite has no business sitting on the IANA point |
| Hash pairing | SHA-384 HKDF, reused from ring's `TLS13_AES_256_GCM_SHA384`; the standard pairs SHA-512, but ring's hash types are private in rustls, and we are not adding primitive glue of our own |

The AEAD itself is untouched: the `aegis` crate (the same primitive `krypto` uses at rest,
vector-verified), 256-bit key, 128-bit tag, record AAD exactly as rustls computes it. TLS 1.3
only. `aegis` is a new direct dependency (it was already in the tree via `krypto`). Offered
**only** when the consumer lists `TransportCipher::Aegis256`; the default in transport is
AES-256-GCM. Foreign parties (Python/OpenSSL, browsers) skip an unknown suite — the fallback rule
realised by TLS itself.

**The way out:** the day rustls ships AEGIS suites or a 32-byte IV, `aegis.rs` is *replaced*
(out with the extension and the private code point, in with `0x1306` and SHA-512);
`TransportCipher::Aegis256` survives as the consumer's name. The unit test
`the_deviation_still_has_its_reason` fails the moment rustls changes the nonce length, so the
switch is announced by the build rather than by memory. Nine handshake tests over loopback
(`tests/aegis.rs` + `tests/transport.rs`), including 64 KiB across several records.

### Added — `transport`: the TLS channel's cipher is the consumer's choice (SPEC-nettls §6.0b)

`TransportCipher { Aes256Gcm, ChaCha20Poly1305 }` and `TransportPolicy` (the consumer's list, in
the consumer's order; empty or repeated → `Params`). All four config builders gained a
`*_with(alpn, &TransportPolicy)` variant (`TlsMaterial::server_config_with`,
`RotatingResolver::server_config_with`, `pinned_client_config_with`, `Trust::client_config_with`);
the old builders use `TransportPolicy::default()`.

**The default is AES-256-GCM alone (Roger 2026-09-04)** — the one AEAD every party speaks
(rustls, OpenSSL/Python, every browser since 2014). Up to and including 0.8.2 the configs offered
ring's whole list (nine suites, AES-128 among them); that is gone. One choice covers both
protocol versions (the TLS 1.3 suite plus the TLS 1.2 ECDHE pair with the same AEAD), so TLS 1.2
for older browsers does not open the door to a weaker AEAD. No suite in common → a hard handshake
failure, never a silent fallback. Servers set `ignore_client_order` — the consumer's order wins,
not the peer's (rule 3; rustls' default is the opposite, and the handshake test caught it).

The process-global provider (`install_crypto_provider`, for *other* libraries in the process) is
still ring's full default. Five handshake tests over loopback in `tests/transport.rs`.

### Changed — private keys in memory as `krypto::SecretBuf` (SPEC-nettls §8, "outstanding" → built)

Every private key the crate *holds* now sits in locked memory (mlock, zeroed on drop,
`[REDACTED]` in `Debug`, readable only through `expose`): the generation trio in
`OwnMaterial`/`Pending`, the anchor from `TlsMaterial::anchor_pkcs8`, PEM read from and written to
disk, and the plaintext on its way into the lockbox. Short-lived buffers that cannot be a
`SecretBuf` (PEM the consumer passes in via `CertSource::pem`, the DER intermediate in the PKCS#8
construction, rustls' own `PrivateKeyDer`) are `zeroize::Zeroizing` — guaranteed zeroing, no
lock. `pem::wipe` (the best-effort loop under `forbid(unsafe_code)`) is removed; `zeroize` is a
new direct dependency (already in the tree via rustls-pki-types). The boundary is written down in
`src/secret.rs` and the API file: rustls/ring keep their own copy of the key for as long as a
`ServerConfig` lives, and rcgen holds the key pair during generation — neither can be locked from
here. If `mlock` fails, that is a hard error, never a silent fallback to ordinary memory.

**API changes (0.x — the consumers follow in their own rounds and build `OwnMaterial` themselves):**

| Before | Now |
|---|---|
| `TlsMaterial::anchor_pkcs8() -> Result<Vec<u8>, _>` | `-> Result<krypto::SecretBuf, _>` |
| `OwnMaterial { previous: Option<(String, Vec<u8>)>, current: (String, Vec<u8>) }` | `(String, krypto::SecretBuf)` for both |
| `Pending { new_pkcs8: Vec<u8> }`, `Clone` | `new_pkcs8: krypto::SecretBuf`, **not** `Clone` |
| `Announcement::new(_, Option<(&str, &[u8])>, (&str, &[u8]), …)` | `&krypto::SecretBuf` instead of `&[u8]` |
| `signature::sign_p256(pkcs8: &[u8], _)` | `pkcs8: &krypto::SecretBuf` |
| `SupportStatement::signed(_, _, _, anchor_pkcs8: &[u8])` | `&krypto::SecretBuf` |
| `pem::wipe` (crate-internal) | removed |

The wire format is unchanged; every normative vector, the error corpus and the Python cross-test
are green.

### Removed — `KRYSSJEKK.md`

The working document from 2026-08-11 (a cross-check of target picture → spec → code, against the
archived `SPEC-nettls-v1`) is out of the repository and kept outside it. The crate is to stand on
its own and does not carry scaffolding.

### Fixed — comment references to documents that no longer exist

`SIKKERHETSMODELL §8.x` (the document is dissolved) now points at whatever owns the rule today
(`SPEC-nettls` §6.3/§6.11/§6.11b); `SPEC-nettls §6.17.3` (the section is gone — the anchor norm
lives in §6.11b) and `SPEC-nettls-v1` (superseded by v2) are corrected. No code change.

### Changed — the krypto lock followed to 0.6.2

`Cargo.lock` stood at krypto 0.6.0; 0.6.1/0.6.2 are published (cleanup plus optional process
hardening), no API break.

## [0.8.2] — 2026-08-27 (the module round)

### Added — `pub const VERSION`

Mirrors `Cargo.toml` — the anchor that says which feature set is active (the mapping from version
to capabilities lives in this file).

### Documented — docs/API.md IS the contract (Roger 2026-08-26)

One API file: `docs/API.md` is the normative, reimplementable contract (enforced by a doc-guard
test); a verbatim copy is kept outside the crate. What was unique to the old spec contract has
moved in: the wire-format table (FROZEN), the enrollment rule (CONTRACT), the error-model
principles (never empty messages; Chain = the best-explained error), the stability section and
the normative top-level rules (input/output plus the feedback contract). The bindings to
consumers live in SPEC-nettls.

### Removed — the entire §5 model (`chain` + `rotation`) (BREAKING; Roger's decision)

"We are building completely clean now and breaking what we must — the consumers are taken right
after and corrected there; there is no backwards compatibility to consider, the application is in
its build phase." Out: `TrustChain`, `RotationProof`, `PROOF_VERSION`, `ROTATION_PROOF_FILE`,
`TlsMaterial::{sign_successor, sign_rotation, verify_successor}` and the `rotation.proof` file.
The §5 model signed with ONE key (one stolen key = a rotation that looks legitimate forever) and
had been superseded by §6 since 0.3.0. **Survived:** `cert_fingerprint_sha256` (the
observe-without-trusting path) — moved to `material`; the PKCS#8 helpers behind `anchor_pkcs8` —
moved to an internal module. The §5.5 health check (an unspecified alerting check in the §5
cadence) fell away with the model — §6 has `Status` and the deviation diagnostics.

### Added — `capability`: the signed AEAD support statement (Roger's request)

The decided pattern, now built: **the best algorithm (AEGIS-256) is the default, a fallback is an
explicit AUTHENTICATED exception, and a fallback to nothing does not exist.** A new canonical
prefix `nettls-algsupport/v1` (additive; fixed token order, fail-closed on unknown tokens,
duplicates or wrong order) · `SupportStatement` (build and sign with the party's P-256 anchor /
verify against a pinned certificate — only the party that does NOT support something can
authorise the downgrade, and only with a signature) · `choose` (the rule: with no statement the
requested one stands; a verified statement without it → the best declared one by preference
order; nothing acceptable → **a new `TlsError::Negotiation`, a hard error — never silently
weaker**). lockbox and envelope already defaulted to AEGIS-256 with a `_with` choice per call
(the 0.8 round). The Python twin carries the same surface (`algsupport_v1`,
`build/verify_support_statement`, `choose_alg`); byte parity is proven by a new normative vector
`algsupport-01-python-bridge`.

### Added — the `status` module: the About contribution (Roger's request)

An application's About page shows the status of every part — the TLS part is this crate's to
describe. The crate owns the vocabulary, the derivation (the thresholds live in ONE place —
`expiry_warning` reuses the rotation rule's threshold) and the headline; the consumer owns the
transport. **Two views, two audiences (the instruction to consumers, written into the
contract):** `Report::summary()` (version + traffic light + headline) for everyone logged in on
the general About page; the whole `Report` (identity, rotation state, per-peer trust) ONLY on the
admin surface — peer names, waiting lists and deviations are operational data. All
serde-serialisable; no I/O, the caller owns the clock.

### Added — a version anchor in the Python twin

`nettls.__version__` (guarded against the `VERSION` file by a test, as on the Rust side); the
parity map cleaned of the §5 entries.

### Maintenance

The krypto dependency followed to 0.6 (`krypto = "0.6"`).

## [0.8.1] — 2026-08-16

**Wishes #2, #3 and #4 from `ØNSKER-byggeklosser.md` — all realised**, plus the base64
consequence of wish #1 (local variants go when `krypto` has the building block).

### Added
- **`nettls::pem::encode(label, der)` is PUBLIC** (wish #2): PEM is the TLS domain, so building it
  belongs here. RFC 7468 form (64-character lines), the intermediate buffer is wiped (the DER may
  be a private key). Consumers that built PEM by hand switch to this.
- **`TlsMaterial::anchor_pkcs8()`** (wish #4): the ONE documented place where the key CROSSES from
  the TLS domain into the §6 domain (the Announcer anchor). A consumer had been using the hidden
  test helper for this in production — the function did the right thing, the name and visibility
  lied. Not a general key export.

### Changed
- **`rustls-pemfile` is OUT** (wish #3 — an unmaintained advisory): PEM reading now goes through
  `rustls-pki-types`' built-in `pem` module (the same underlying types; no wire change).
  *(The wish text assumed a "pem" feature — the module is built in.)*
- **The internal base64 encoder is gone** (`pem.rs`, ~40 lines): the body is built with
  `krypto::base64` (0.5.1). Requires `krypto = "0.5.1"`.
- `pkcs8_for_test` and `pem_encode_for_test` are **deprecated** (they point at the real APIs; to
  be removed in a later y-bump).

## [0.8.0] — 2026-08-15

**The migration to krypto 0.5 — the crate no longer carries primitives of its own.** krypto 0.5
was built precisely to take over what this crate had been pulling in itself: signatures, key
agreement, hex, SHA-256, constant-time comparison and CSPRNG bytes. Roger's direction for the
round: "no history, nothing to take into account — we remove our home-made functions that krypto
can now solve." The wire format, the canonical strings and **every test vector are unchanged byte
for byte** (`testvectors/canonical.json` passed without regeneration — krypto's Ed25519 and P-256
are bit-compatible with what `ring` produced).

### ⚠ Security — AEGIS blobs from krypto ≤ 0.4.4 must be regenerated

krypto 0.5.0 fixed a key/nonce swap in the AEGIS-256 layer. `lock()` and `seal()` default to
AEGIS-256, so **lockbox files and envelopes written with krypto ≤ 0.4.4 give an `Auth` error
under 0.8.0 and have to be made again** (lock or seal the content afresh). Nothing is in
production; the crate itself has no frozen sealed vectors. Blobs sealed with `Alg::Aes256Gcm`
(the interop bridge) are unaffected.

### Removed — the primitives, replaced by krypto

| Gone from `nettls` | Use instead |
|---|---|
| `signature::to_hex` | `krypto::hex::encode` |
| `signature::sign_ed25519` | `krypto::sign::ed25519_sign` (seed as a `SecretBuf`) |
| `signature::verify_ed25519` | `krypto::sign::ed25519_verify` |
| `signature::ed25519_public_from_seed` | `krypto::sign::ed25519_public` |
| `signature::ED25519_PUBKEY_LEN` / `ED25519_SEED_LEN` | `krypto::sign::ED25519_PUBLIC_LEN` / `ED25519_SEED_LEN` |
| *(internal: fingerprint hex/sha256/ct_eq, the rotation's `hex_to_bytes`, x25519-dalek and ring calls)* | `krypto::{hex, sha256, ct_eq, exchange, random_bytes}` |

The dependencies **`ring` and `x25519-dalek` are removed** from the manifest (both are still
present transitively: ring through the rustls/rcgen provider, x25519-dalek through krypto). The
provider trap is unchanged — krypto does not touch rustls' `CryptoProvider`.

### Changed — breaking

- **`Approval::new` and `Receipt::new` take the seed as `&krypto::SecretBuf`** (was `&[u8]`) —
  correcting a breach of invariant #1: a private key crossed the API boundary as raw bytes.
- **`RecipientKey::from_bytes` takes a `krypto::SecretBuf`** (was `&[u8]`) and **consumes** it —
  same reason, same pattern as `krypto::MasterKey::from_bytes`.
- `signature::from_hex` is now the §6.5 field rule (non-empty) over `krypto::hex::decode` — the
  same fail-closed semantics as before (lowercase, even length, never a panic on UTF-8), proven by
  the error corpus (`testvectors/errors.json`) passing unchanged.
- The rotation proof's signature field is parsed by the same rule — **uppercase is now rejected**
  there too (the field is machine-written in lowercase; the tolerance was an inconsistency, not a
  feature).
- Requires `krypto = "0.5"` (was `0.4.4`).

### Added

- **Non-contributory X25519 is rejected**: `envelope::seal*` against a low-order recipient point
  (all-zero, for instance) now gives an error instead of an envelope with a predictable key — a
  free property from `krypto::exchange::x25519_shared`.

### Unchanged

- This crate's own formats and domain: the NETENV envelope, the NETTLS lockbox file, rotation
  proofs, the §6 messages, X.509 parsing (`p256_public_key`), the operator-tolerant
  `parse_fingerprint`. The boundary is §8d.1: krypto owns the primitives, the consumer owns its
  formats.
- The whole §6.14 contract: test vectors, error corpus and the Rust ↔ Python cross-tests — 209
  cargo tests plus 312 pytest green with no vector changes.

### Known wait

- ~~CI builds against **registry** krypto and stays red until krypto 0.5.0 is published.~~
  **Resolved the same day:** krypto 0.5.0 and nettls 0.8.0 were both published 2026-08-15. The
  blocker was never the token — cargo ≥ 1.74 requires `global-credential-providers =
  ["cargo:token"]` in `~/.cargo/config.toml`, and the line was missing. Publish-verify compiled
  against registry krypto, the same path CI takes.

## [0.7.0] — 2026-08-15

**The 0.7 wave: the §6.17 and §6.19 API decisions are realised.** One migration
for consumers, with the changed behaviour listed below. Wire format, canonical
strings and all test vectors are byte-for-byte unchanged.

### Changed — `Announcer::new` is load-or-init, fail-closed (SPEC-nettls §6.17.3)

**Breaking.** `Announcer::new(…, anchor, …) -> Result<Self, TlsError>`:

- The material parameter is now named what it is: `anchor` — the identity the
  consumer shares with the crate at first boot, generation 0. From generation 1
  the keys are created and owned by the crate; a persisted chain on disk
  therefore **overrides** the anchor.
- `new` restores the chain **and** any pending announced-but-not-switched
  rotation itself, fail-closed: state that exists but cannot be read fails
  construction loudly (a fault, not an absence). It is no longer possible to
  hold an `Announcer` in a silently wrong state.
- `restore_material()` and `restore_pending()` are absorbed into `new` and are
  no longer public. There is no startup call to forget — the trap the external
  reference implementation walked into is gone.

### Changed — an anchor-only receiver accepts a double-signed announcement (A8, decided 2026-08-14)

Generation numbering is **local to the receiver**: the chain belongs to the
relation, not the announcer. A receiver holding only an anchor (fresh
approval — first boot, restart-with-loss, or a late joiner meeting a
long-running announcer) verifies what it *can* — `sig_curr` against the
anchor the operator just vouched for — and a stated `prev` it cannot check is
not grounds for rejection. From generation 1 (the receiver's own counting)
the two-signature rule applies as before. Security equals bootstrap; the
anchor-only state cannot be induced by an attacker; replay fails the
curr-vs-anchor check. The ring test that documented the old blocking as a
strict xfail flipped to unexpectedly-green on this change — as designed — and
is rewritten as the positive `test_rotation_after_restart_resumes`.

### Changed — component names are enforced exactly as §6.5 writes them

New `require_component_name` (both languages): `announcer`, `acker`, `peer`
and the pair-rotation party names must match `[a-z0-9-]{1,32}` — enforced at
**parse level**, not just at signing. Previously the generic name rule let
uppercase and underscores through, so two implementations could produce
different bytes for the same party. Usernames (`approved_by`) keep the looser
rule (no control characters, 1–64) — a different category on purpose. The
error corpus gained `announcer_uppercase` and `announcer_underscore`, read by
both sides.

### Changed — the AEAD choice is lifted out; the default at rest is now AEGIS-256 (SPEC-nettls §6.0b)

`lockbox::lock` and `envelope::seal` now default to **AEGIS-256** — at rest
there is no cross-reading (whoever writes, reads), so a Rust-owned store uses
the default. New `lock_with`/`seal_with` take an explicit
`krypto::Alg` for the per-recipient, static choice; `Alg::Aes256Gcm` remains
the documented interop bridge toward Python. Unlocking/opening reads the
algorithm from the FAFN header; a reader without the algorithm fails hard,
never silently (the A1 rule). Existing locked state written by earlier
versions (AES-GCM) still opens — the header decides.

### Added — `Announcer::roll_if_ready_gated` (SPEC-nettls §6.7e / §6.18.1 — the A4/A5 switch point)

The receipt answers for the peer; the gate answers for **us**. `roll_if_ready_gated(now,
safe_now)` consults the consumer at the last moment, only when everything else is ready, and a
`false` postpones the switch with no side effects. The chain and the serving still switch
**together**, inside the call — there is no way to roll the chain without the resolver
following. `roll_if_ready` is unchanged and delegates with an always-open gate.

(The Python twin already gives the consumer the last word by construction: the switch there
happens through the consumer-supplied `bytt_til` callback.)

### Added — `Announcer::own_trio()` (SPEC-nettls §6.17.3 pt. 3)

A read-only view of our own generation triple — `previous_fingerprint`,
`current_fingerprint`, `next_fingerprint` (`OwnTrio`). Fingerprints only,
never keys: the crate tells what it knows; the consumer needs insight for
status, logging and operator display.

### Note — the changelog starts here, on purpose

Releases before this one are not in this file. They were written while the crate
was being built inside a larger private system, and they describe it: sibling
services, internal documents, case numbers from a tracker nobody outside can
reach. Most of it is noise to someone reading the crate, and the part that is not
noise is already somewhere better.

Dropping them lost no design reason. Those reasons live in the doc comments,
where a reader meets them next to the thing they explain — why certificates are
ECDSA P-256 and why that is also the more compatible choice, why the lifetime is
capped at 397 days, why an IP address has to be in the SAN list, why permissions
are set on the temp file before the rename, why the crypto provider is installed
idempotently and why the fence against a second one is a test rather than a CI
step. All of it is in `src/`, stated more fully there than it ever was here.

This release is where the crate as it exists now begins.
