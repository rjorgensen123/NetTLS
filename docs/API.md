# API — the contract

Every public type and function in `nettls`, grouped by module — precise enough to reimplement
the crate from. To get started, or to understand the order things are done in, read
**[Usage](Usage.md)** first. What the crate is and is not, is in **[Home](Home.md)**.

**The authoritative source is `src/` + `CHANGELOG.md`; on divergence the code wins.** The
version (the `VERSION` constant, derived from `Cargo.toml`) is the anchor for the active feature
set — the mapping version → capabilities lives in `CHANGELOG.md`. Every public name must
appear in this file (enforced by a doc-guard test).

Everything returns `Result<_, TlsError>` where something can fail. The crate does not panic on
input.

Two normative rules bind whoever *changes* the surface:

- **Verify input and output.** All input is validated (type, length, range, character set —
  fail-closed; unknown values are rejected, never silently skipped), and output never carries
  key material. An uncovered case → update this document.
- **The feedback contract.** What the crate answers — success, errors and status — lives HERE:
  `Result` with [`TlsError`](#error--tlserror) (never empty error messages — every variant
  carries enough context for the operator to see WHAT is wrong), plus the announcer's
  [`Status`](#status--for-alerting) for alerting. No error path carries key material. An answer
  not written here is a gap in the contract and should be reported — not interpreted.

## The wire format — all-English, FROZEN

The wire went English in 0.7.0 while it was still free (no service spoke the
§6 wire yet); the signed canonical bytes were unchanged. **The table below is frozen — changing
it is breaking regardless of semver:**

| What | Value |
|---|---|
| Canonical prefixes | `nettls-approve/v1` · `nettls-rotate/v2` · `nettls-rotate-ack/v2` · `nettls-pairsecret/v1` · `nettls-algsupport/v1` *(additive, 0.8.2)* |
| Canonical form | UTF-8, LF between lines, **no** trailing LF; `prev` serializes as `-` when absent |
| JSON field names | all English: `approved_by`, `timestamp`, `mode`, `announcement`, … |
| Mode values | `"pinning"` and `"rolling"` |
| File names on disk | `cert.pem` · `key.pem` · `pending-rotation.json` · `announcements.jsonl` |
| Blob magics | `NETTLS\x01\x00` (lockbox) · `NETENV\x01\x00` (envelope) · FAFN (krypto) |
| KDF labels | `nettls/local-state/v1` + `nettls-local-st1` · `nettls/envelope/v1` + `nettls-envelope1` |
| Test vectors | `testvectors/canonical.json` + `errors.json` — `canonical_hex` values byte-identical since 0.6 |

*(The Norwegian ⇄ English wire migration table lives in `CHANGELOG.md` under `[0.7.0]`.)*

---

## Root — what you meet first

```rust
pub fn install_crypto_provider() -> bool;   // idempotent; true if THIS call installed it
pub fn provider() -> Arc<rustls::crypto::CryptoProvider>;
```

Re-exported from the root: `TlsMaterial`, `CertSource`, `SelfSignedParams`, `CertOrigin`,
`is_valid_san`, `CERT_FILE`, `KEY_FILE`, `MAX_VALID_DAYS`, `RotatingResolver`, `TlsError`,
`pinned_client_config`, `pinned_client_config_with_alpn`, `pinned_client_config_with`,
`cert_fingerprint_sha256`, `TransportCipher`, `TransportPolicy` *(0.8.3)*.

`pub use rustls` — so you do not have to list rustls as a dependency just for the types (and
risk a line of your own with the wrong features).

**Tests only** (`#[doc(hidden)]`): `fingerprint_for_test` — plus `pkcs8_for_test` and
`pem_encode_for_test`, both **deprecated since 0.8.1**: the real APIs are
`TlsMaterial::anchor_pkcs8()` (wish #4) and `pem::encode` (wish #2).

**`pem` — building PEM** *(public since 0.8.1, wish #2)*:

```rust
pub fn encode(label: &str, der: &[u8]) -> Vec<u8>;   // RFC 7468, 64-char lines
```

PEM is TLS domain, so building it lives here. The base64 body is `krypto::base64` (canonical);
the intermediate is zeroized — the DER may be a private key. The returned buffer is the caller's
to protect; `save_pem` holds a key's PEM in a `SecretBuf` until it is on disk (0.8.3). Reading PEM goes through
`rustls-pki-types`' built-in `pem` module (0.8.1 — `rustls-pemfile` is out; it was flagged
unmaintained).

---

## `material` — the certificate

| | |
|---|---|
| `CERT_FILE` · `KEY_FILE` | the file names `auto`/`save_pem` use (`cert.pem`, `key.pem`) |
| `MAX_VALID_DAYS` | 397 — browsers reject longer |
| `is_valid_san(name) -> bool` | is this a valid SAN? (syntax only, never DNS lookups) |

### `CertOrigin`

Where the certificate came from. **Log this.**

`Files` · `Pem` · `Generated` · `Reused` · `ReusedExpired` · `Ephemeral`

> `Ephemeral` means the directory was not writable → a new fingerprint on every restart →
> everyone who pinned you loses you. `ReusedExpired` means an expired certificate was kept
> deliberately — regeneration must be an operator action, or every pinned pairing breaks
> silently. Both deserve loud log lines.

### `SelfSignedParams`

```rust
pub struct SelfSignedParams { pub common_name: String, pub sans: Vec<String>, pub valid_days: u32 }

impl SelfSignedParams {
    pub fn new(common_name: impl Into<String>, sans: impl IntoIterator<Item = impl Into<String>>) -> Self;
    pub fn valid_days(self, days: u32) -> Self;
}
```
Has `Default`. Strings that parse as IP addresses become IP SANs, the rest DNS SANs.

### `CertSource`

```rust
impl CertSource {
    pub fn files(cert_path: impl Into<PathBuf>, key_path: impl Into<PathBuf>) -> Self;
    pub fn pem(cert_pem: impl Into<Vec<u8>>, key_pem: impl Into<Vec<u8>>) -> Self;
    pub fn self_signed(params: SelfSignedParams) -> Self;
    pub fn auto(dir: impl Into<PathBuf>, params: SelfSignedParams) -> Self;
}
```
`Debug` is redacted — it never reveals key material.

### `TlsMaterial`

```rust
impl TlsMaterial {
    pub fn load(src: &CertSource) -> Result<Self, TlsError>;

    // facts
    pub fn fingerprint_sha256(&self) -> String;      // hex of the leaf DER — what clients pin
    pub fn not_after(&self) -> Option<i64>;          // unix
    pub fn not_before(&self) -> Option<i64>;
    pub fn days_until_expiry(&self) -> i64;          // negative when expired
    pub fn is_valid_now(&self) -> bool;
    pub fn sans(&self) -> &[String];
    pub fn subject(&self) -> &str;
    pub fn origin(&self) -> CertOrigin;
    pub fn cert_chain(&self) -> &[CertificateDer<'static>];

    // use
    pub fn certified_key(&self) -> Result<Arc<rustls::sign::CertifiedKey>, TlsError>;
    pub fn server_config(&self) -> Result<Arc<ServerConfig>, TlsError>;   // TLS 1.3+1.2, ALPN h2+http/1.1
    pub fn server_config_with_alpn(&self, alpn: &[Vec<u8>]) -> Result<Arc<ServerConfig>, TlsError>;
    pub fn server_config_with(&self, alpn: &[Vec<u8>], transport: &TransportPolicy)
        -> Result<Arc<ServerConfig>, TlsError>;                           // 0.8.3 — see `transport`
    pub fn save_pem(&self, dir: &Path) -> Result<(), TlsError>;           // atomic; key.pem 0600
    pub fn anchor_pkcs8(&self) -> Result<krypto::SecretBuf, TlsError>;    // 0.8.1, wish #4 — see below
}
```

**`anchor_pkcs8` (0.8.1)** is the ONE documented place the key crosses from the TLS domain into
the §6 domain: it feeds `Announcer::new`'s anchor, so announcements are signed with the same
identity the server serves. It is not a general key export — the output is PKCS#8 for the anchor
construction, nothing else. **Since 0.8.3 it is a `krypto::SecretBuf`** (was `Vec<u8>`): locked
memory, wiped on drop, `[REDACTED]` in `Debug`, readable only through `expose`.

**Private keys in memory (0.8.3).** Every key the crate *holds* — the generation triple in
`OwnMaterial`/`Pending`, the anchor above, PEM read from or written to disk — is a `SecretBuf`.
Short-lived buffers that cannot be (PEM handed in via `CertSource::pem`, DER intermediates) are
`zeroize::Zeroizing` — guaranteed wipe, no lock. **The honest limit:** `TlsMaterial` keeps the
key as rustls' `PrivateKeyDer` (wrapped in `Zeroizing`, ordinary heap), and rustls/ring hold
their own parsed copy for as long as a `ServerConfig` lives; rcgen holds the fresh key pair
during generation. Neither can be locked from here. `SecretBuf::from_vec` failing (`mlock`,
`RLIMIT_MEMLOCK`) is a hard error — never a silent fallback to ordinary memory.

---

### `cert_fingerprint_sha256`

```rust
pub fn cert_fingerprint_sha256(cert_der: &[u8]) -> String;
```

The SHA-256 fingerprint of a certificate in DER — the same value as
`TlsMaterial::fingerprint_sha256`, but for a certificate you have merely **seen**. The way into
"observing is not trusting": connect unverified only to *read* the peer's identity and show it
to the operator (the certificate is sent in cleartext in every handshake anyway). *(Lived in the
retired `rotation` module before 0.8.2.)*

## `provider` · `pin` · `resolver`

```rust
// provider
pub fn provider() -> Arc<CryptoProvider>;
pub fn install_crypto_provider() -> bool;

// pin — static pinning; against a ROTATING peer, use generations::Trust instead
pub fn pinned_client_config(fingerprint_sha256: &str) -> Result<Arc<ClientConfig>, TlsError>;
pub fn pinned_client_config_with_alpn(fingerprint_sha256: &str, alpn: &[Vec<u8>]) -> Result<Arc<ClientConfig>, TlsError>;
pub fn pinned_client_config_with(fingerprint_sha256: &str, alpn: &[Vec<u8>], transport: &TransportPolicy)
    -> Result<Arc<ClientConfig>, TlsError>;                                   // 0.8.3
```

### `transport` — the channel's cipher is the consumer's choice *(new in 0.8.3)*

The same principle as the at-rest cipher menu — the crate offers, the consumer chooses —
applied to the TLS channel itself. Every config builder has a `*_with`
variant taking a `TransportPolicy`; the builders without one use `TransportPolicy::default()`.

```rust
#[non_exhaustive]
pub enum TransportCipher { Aes256Gcm, ChaCha20Poly1305, Aegis256 }   // wire names: TLS has ChaCha20, not XChaCha20
impl TransportCipher { pub fn token(self) -> &'static str; }   // "aes256gcm" · "chacha20poly1305" · "aegis256"

pub struct TransportPolicy { .. }                             // Default = AES-256-GCM only
impl TransportPolicy {
    pub fn only(cipher: TransportCipher) -> Self;
    pub fn new(ciphers: &[TransportCipher]) -> Result<Self, TlsError>;   // consumer's order; empty/repeated → Params
    pub fn ciphers(&self) -> &[TransportCipher];
}
```

- **Default: AES-256-GCM only** (decided 2026-09-04) — the one AEAD every party in the
  party speaks: rustls, OpenSSL/Python, every browser since 2014. Up to 0.8.2 the configs
  offered ring's full list (nine suites, AES-128 included); that list is gone.
- **The consumer's list, in the consumer's order.** rustls picks the first suite in *our* list
  the peer also offers; the server's list decides. Nothing outside the list is ever used.
- **No common suite → hard handshake failure** (`NoCipherSuitesInCommon` server-side, an alert
  client-side). No fallback, no renegotiation on the peer's word. Widening a server policy
  never breaks a default client: keep `Aes256Gcm` in the list.
- One choice covers **both protocol versions** — the TLS 1.3 suite and the TLS 1.2 ECDHE pair
  with the same AEAD — so keeping TLS 1.2 for older browsers does not reopen a weaker AEAD.
- AEGIS-256 in the transport is the third choice, built as a deliberate deviation — see
  `aegis` below. The process-global provider (`install_crypto_provider`, for *other*
  libraries in the process) is ring's full default and is not touched by a policy.

### `aegis` — AEGIS-256 in the channel: a deliberate deviation, built to be replaced *(0.8.3)*

```rust
pub const CODEPOINT: u16 = 0xFF06;        // TLS private use — NOT the IANA TLS_AEGIS_256_SHA512 (0x1306)
pub fn suite() -> SupportedCipherSuite;   // what TransportCipher::Aegis256 puts in the list
```

Offered only when a consumer lists `TransportCipher::Aegis256`; **never the default**. Two nettls
ends speak it; a foreign peer (Python/OpenSSL, a browser) skips it as an unknown suite — the
fallback rule realised by TLS itself: list `[Aegis256, Aes256Gcm]` and a Rust peer lands on AEGIS,
everyone else on AES-256-GCM, with no negotiation code of ours.

**Why it deviates (decided 2026-09-04):** rustls gives every TLS 1.3 AEAD a 12-byte nonce
(`NONCE_LEN`; 16 in 0.24-dev and on git-main, checked against the source), AEGIS-256 needs 32,
and nobody upstream is working on it. So this suite, written down as what it is:

| Deviation | What we do |
|---|---|
| nonce | rustls' 12-byte TLS 1.3 nonce (`iv XOR seq`), left-aligned, zero-padded to 32 — unique per key because the TLS nonce is |
| code point | `0xFF06` (private use), echoing `0x1306` — a non-standard suite does not squat on the IANA point |
| hash pairing | SHA-384 HKDF, reusing ring's `TLS13_AES_256_GCM_SHA384` providers; the standard pairs SHA-512, but ring's hash types are private to rustls and we add no primitive glue |

The AEAD is the `aegis` crate (the primitive krypto uses at rest, vector-verified), 256-bit key,
128-bit tag, record AAD exactly as rustls computes it. TLS 1.3 only. Nothing cryptographic is
implemented here — the file is the seam between rustls' record layer and the primitive.

**The exit:** when rustls ships AEGIS suites or a 32-byte IV, `aegis.rs` is *replaced* — drop the
padding and the private point, use `0x1306` with SHA-512 — and `TransportCipher::Aegis256` stays
as the consumer's name. The unit test `the_deviation_still_has_its_reason` fails the moment
rustls widens the nonce, so the exit is announced by the build.

### `RotatingResolver` — change certificates without a restart

```rust
impl RotatingResolver {
    pub fn new(material: &TlsMaterial) -> Result<Self, TlsError>;
    pub fn swap(&self, material: &TlsMaterial) -> Result<String, TlsError>;  // → the old fingerprint
    pub fn fingerprint_sha256(&self) -> String;                              // what is served NOW
    pub fn server_config(&self) -> Result<Arc<ServerConfig>, TlsError>;
    pub fn server_config_with_alpn(&self, alpn: &[Vec<u8>]) -> Result<Arc<ServerConfig>, TlsError>;
    pub fn server_config_with(&self, alpn: &[Vec<u8>], transport: &TransportPolicy)
        -> Result<Arc<ServerConfig>, TlsError>;                           // 0.8.3 — see `transport`
}
```
Implements `ResolvesServerCert`. **Build the config once** — it is live, and `swap` takes effect
on it. `Clone` shares state. `swap` validates before switching: a rejected certificate never
replaces one that works.

---

## `generations` — which certificates apply

```rust
pub struct Generation;
impl Generation {
    pub fn from_der(der: impl Into<Vec<u8>>) -> Self;
    pub fn from_pem(pem: &str) -> Result<Self, TlsError>;
    pub fn der(&self) -> &[u8];
    pub fn fingerprint(&self) -> &str;
}

pub enum Received { Stored, Known }   // Known = idempotent re-receipt, not an error
```

### `Generations` — the state for ONE peer

```rust
impl Generations {
    pub fn from_approval(current: Generation) -> Self;
    pub fn restore(previous: Option<Generation>, current: Generation, next: Option<Generation>)
        -> Result<Self, TlsError>;   // your own storage back in; shape-checked, nothing verified
    pub fn receive(&mut self, k: &Announcement) -> Result<Received, TlsError>;
    pub fn observed(&mut self, fp: &str) -> bool;                    // promotion ON OBSERVATION
    pub fn accepted_in_handshake(&self) -> Vec<&Generation>;         // current + next — NEVER previous
    pub fn for_signing(&self) -> (Option<&Generation>, &Generation); // (previous, current)
    pub fn current(&self) -> &Generation;
    pub fn previous(&self) -> Option<&Generation>;
    pub fn next(&self) -> Option<&Generation>;
    pub fn is_bootstrap(&self) -> bool;
}
```

The two roles do not overlap: `previous` verifies announcements but lets no one into a
handshake.

### `Trust` — the thread-safe wrapper, wired to TLS

```rust
impl Trust {
    pub fn from_approval(current: Generation) -> Self;
    pub fn from_state(g: Generations) -> Self;
    pub fn receive(&self, k: &Announcement) -> Result<Received, TlsError>;   // &self, not &mut
    pub fn state(&self) -> Result<Generations, TlsError>;                    // snapshot for storage
    pub fn client_config(&self) -> Result<Arc<ClientConfig>, TlsError>;      // LIVE — build once
    pub fn client_config_with_alpn(&self, alpn: &[Vec<u8>]) -> Result<Arc<ClientConfig>, TlsError>;
    pub fn client_config_with(&self, alpn: &[Vec<u8>], transport: &TransportPolicy)
        -> Result<Arc<ClientConfig>, TlsError>;                           // 0.8.3 — see `transport`
}
```

---

## `announcement` — "here is my next certificate"

```rust
pub fn fingerprint_from_pem(pem: &str) -> Result<String, TlsError>;
pub fn der_from_pem(pem: &str) -> Result<Vec<u8>, TlsError>;   // exactly ONE CERTIFICATE block

pub const MAX_CERT_PEM_LEN: usize = 16 * 1024;      // DoS cap on incoming PEM
pub const ARCHIVE_FILE: &str = "announcements.jsonl";
pub fn archive(dir: &Path, k: &Announcement) -> Result<(), TlsError>;             // append-only audit
pub fn read_archive(dir: &Path) -> Result<(Vec<Announcement>, usize), TlsError>;  // → (read, skipped)
```

### `Announcement`

```rust
impl Announcement {
    pub fn new(
        announcer: &str,
        prev: Option<(&str, &krypto::SecretBuf)>,   // (fingerprint, PKCS#8) — None at the very first rotation
        curr: (&str, &krypto::SecretBuf),           // (fingerprint, PKCS#8) — SecretBuf since 0.8.3
        new_cert_pem: &str,
        sent_at: i64,
    ) -> Result<Self, TlsError>;

    pub fn canonical(&self) -> Result<Vec<u8>, TlsError>;
    pub fn verify(&self, prev_cert_der: Option<&[u8]>, curr_cert_der: &[u8]) -> Result<(), TlsError>;
    pub fn to_json(&self) -> AnnouncementJson;
    pub fn from_json(j: &AnnouncementJson) -> Result<Self, TlsError>;   // fail-closed

    pub fn announcer(&self) -> &str;
    pub fn new_fingerprint(&self) -> &str;
    pub fn new_cert_pem(&self) -> &str;
    pub fn sent_at(&self) -> i64;
    pub fn is_bootstrap(&self) -> bool;
}
```

> If `prev` is available, both signatures **must** be made. An announcement that could have been
> double-signed but is not, is a weakened announcement.
>
> `verify` checks against the **receiver's own** state: a single signature is accepted only when
> the receiver has no previous — and (A8) a receiver holding **only an anchor** accepts a
> double-signed announcement whose `curr` matches the anchor: generation numbering is local to
> the receiver.

`AnnouncementJson` (serialized form; the field names are contract): `v` · `announcer` ·
`prev_fingerprint` · `curr_fingerprint` · `new_fingerprint` · `new_cert_pem` · `sent_at` ·
`sig_prev` · `sig_curr`

### `Receipt` — the gate

```rust
impl Receipt {
    pub fn new(acker: &str, announcer: &str, new_fp: &str, sent_at: i64, ed25519_seed: &krypto::SecretBuf)
        -> Result<Self, TlsError>;
    pub fn canonical(&self) -> Result<Vec<u8>, TlsError>;
    pub fn verify(&self, pinned_pubkey: &[u8], expected_new_fp: &str) -> Result<(), TlsError>;
    pub fn to_json(&self) -> ReceiptJson;
    pub fn from_json(j: &ReceiptJson) -> Result<Self, TlsError>;
    pub fn acker(&self) -> &str;
    pub fn new_fingerprint(&self) -> &str;
    pub fn sent_at(&self) -> i64;
}
```

`ReceiptJson`: `v` · `acker` · `announcer` · `new_fingerprint` · `sent_at` · `sig`

`verify` requires **both** the pinned key and the expected fingerprint: a genuine receipt for a
*different* rotation is a replay and must not make you roll.

### `IdentityJson` — what a service publishes

Fields: `fingerprint` (with `sha256:` prefix) · `cert_pem` · `not_after` · `mode` · `sent_at` ·
`announcement` *(field names ARE the wire names — the wire went fully English in 0.7.0; old⇄new table in CHANGELOG, note removed in a later version)*

```rust
impl IdentityJson {
    pub fn new(fingerprint: impl Into<String>, cert_pem: impl Into<String>,
               not_after: Option<String>, mode: Mode, sent_at: i64,
               announcement: Option<&Announcement>) -> Self;
}
```

Read `fingerprint`/`cert_pem` **from what is actually served** (the resolver), never from a
cached startup value.

---

## `approval` — the operator's approval

```rust
impl Approval {
    pub fn new(peer: &str, fingerprint: &str, approved_by: &str, timestamp: i64,
               key_id: &str, ed25519_seed: &krypto::SecretBuf) -> Result<Self, TlsError>;
    pub fn canonical(&self) -> Result<Vec<u8>, TlsError>;
    pub fn verify(&self, look_up_key: &dyn Fn(&str) -> Option<Vec<u8>>) -> Result<(), TlsError>;
    pub fn fingerprint(&self) -> &str;
    pub fn peer(&self) -> &str;
    pub fn approved_by(&self) -> &str;
    pub fn key_id(&self) -> &str;
    pub fn to_json(&self) -> ApprovalJson;
    pub fn from_json(j: &ApprovalJson) -> Result<Self, TlsError>;
}

pub struct Context<'a> {
    pub keys: &'a dyn Fn(&str) -> Option<Vec<u8>>,      // key_id → Ed25519 pubkey
    pub previous_der: Option<&'a [u8]>,                 // the receiver's previous generation
    pub current_der: Option<&'a [u8]>,                  // the receiver's current generation
}

pub enum Recognition { Operator(Approval), Schedule(Box<Announcement>) }
impl Recognition {
    pub fn verify(&self, k: &Context<'_>) -> Result<(), TlsError>;   // ONE code path for gen 0 and n
    pub fn fingerprint(&self) -> &str;
    pub fn is_anchor(&self) -> bool;    // operator approval = the root
}
```

`ApprovalJson`: `v` · `peer` · `fingerprint` · `approved_by` · `timestamp` · `key_id` · `sig`
*(field names ARE the wire names — see the transition table in CHANGELOG)*

---

## `announcer` — the rhythm and the state machine

### Constants

| Group | Names |
|---|---|
| Time | `DAY_S` · `NOMINAL_AGE_DAYS` (7) · `SPREAD_DAYS` (±2) · `MIN_BETWEEN_ROLLS_S` · `ALARM_AFTER_S` (12 h) |
| Lifetime | `MODE2_LIFETIME_DAYS` (30) · `MODE1_MIN_DAYS` (47) · `MODE1_DEFAULT_DAYS` (90) · `MODE1_MAX_DAYS` (365) · `MODE1_WARN_DAYS` (30) |
| Clock drift | `DRIFT_NORMAL_S` (5) · `DRIFT_WARNING_S` (30) · `DRIFT_JUMP_S` (10) |
| File | `PENDING_FILE` (`pending-rotation.json`) |

### Mode

```rust
pub enum Mode { Pinning, Rolling }     // wire values: "pinning" / "rolling"
pub enum ModeCheck { Agree(Mode), Disagree { ours: Mode, theirs: Mode } }

pub fn check_mode(ours: Mode, theirs: Mode) -> ModeCheck;  // compares, NEVER negotiates
impl ModeCheck { pub fn message(&self, peer: &str) -> Option<String>; pub fn can_roll(&self) -> bool; }

pub fn mode2_params(common_name, sans) -> SelfSignedParams;                        // always 30 days
pub fn mode1_params(common_name, sans, days: Option<u32>) -> Result<SelfSignedParams, TlsError>;
pub fn mode1_should_warn(now: i64, expires: i64) -> bool;                          // at 30 days left
```

### `Schedule` — the state machine (pure logic, no I/O)

```rust
pub enum ChainState { Idle { attempt_at: i64 }, Announced { waiting_for: BTreeSet<String>, first_announced: i64 } }

impl Schedule {
    pub fn new(peers: impl IntoIterator<Item = String>, attempt_at: i64) -> Self;
    pub fn add_peer(&mut self, name: impl Into<String>);
    pub fn remove_peer(&mut self, name: &str);
    pub fn should_announce(&self, now: i64) -> bool;
    pub fn announced(&mut self, now: i64);
    pub fn acked(&mut self, peer: &str);
    pub fn waiting_for(&self) -> Vec<&str>;      // empty = ready to roll
    pub fn can_roll(&self, now: i64) -> bool;
    pub fn rate_limit_ok(&self, now: i64) -> bool;
    pub fn rolled(&mut self, now: i64) -> Result<(), TlsError>;
    pub fn state(&self) -> &ChainState;
    pub fn first_announced(&self) -> Option<i64>;
    pub fn status(&self, now: i64, expires: i64) -> Status;
    pub fn restore_announced(&mut self, waiting_for: Vec<String>, first_announced: i64);  // after restart
}

pub fn draw_roll_time(issued: i64) -> Result<i64, TlsError>;   // issued + 7 d ± 2 d (CSPRNG)
pub fn interval_after(elapsed_s: i64) -> i64;                  // retry cadence: tight, then sparser
```

### `Status` — for alerting

```rust
pub struct Status { pub waiting_for: Vec<String>, pub alarm: bool, pub seconds_until_stop: i64 }
impl Status {
    pub fn countdown(&self) -> String;                          // "d days hh:mm:ss"
    pub fn message(&self, own_peer_name: &str) -> Option<String>; // always names WHO is blocking
    pub fn next_retry(&self, now: i64) -> Option<i64>;
    pub fn alarm(&self, now: i64) -> bool;
}
```

`seconds_until_stop` counts to the moment communication actually **stops** (certificate expiry)
— not to the next retry, not to the alarm.

### `Announcer` — the one that binds it together

```rust
pub struct OwnMaterial {                       // keys as SecretBuf since 0.8.3 (were Vec<u8>)
    pub previous: Option<(String, krypto::SecretBuf)>,   // (fingerprint, PKCS#8)
    pub current: (String, krypto::SecretBuf),            // build from TlsMaterial::anchor_pkcs8()
}
pub struct Pending {                           // Debug (redacted) — NOT Clone since 0.8.3
    pub announcement: Announcement, pub new_cert_pem: String, pub new_pkcs8: krypto::SecretBuf }
pub struct OwnTrio {                           // fingerprints only — never keys
    pub previous_fingerprint: Option<String>,
    pub current_fingerprint: String,
    pub next_fingerprint: Option<String>,
}

impl Announcer {
    pub fn new(name, dir, params: SelfSignedParams, resolver: Arc<RotatingResolver>,
               anchor: OwnMaterial, schedule: Schedule,
               password: Option<krypto::SecretString>) -> Result<Self, TlsError>;
        // load-or-init, fail-closed: disk state overrides the anchor; unreadable state = error

    pub fn own_trio(&self) -> Result<OwnTrio, TlsError>;
    pub fn prepare(&self, now: i64) -> Result<Announcement, TlsError>;   // create + persist + announce; idempotent
    pub fn acked(&self, peer: &str) -> Result<(), TlsError>;             // verify the Receipt FIRST
    pub fn roll_if_ready(&self, now: i64) -> Result<Option<String>, TlsError>;
    pub fn roll_if_ready_gated(&self, now: i64, safe_now: impl FnOnce() -> bool)
        -> Result<Option<String>, TlsError>;   // the consumer's last word; chain+serving switch together
    pub fn should_announce(&self, now: i64) -> bool;
    pub fn status(&self, now: i64, expires: i64) -> Result<Status, TlsError>;
    pub fn pending(&self) -> Option<Announcement>;
    pub fn save_pending(&self) -> Result<(), TlsError>;   // the private key is NOT included
}
```

`password: None` means **key material in cleartext on disk**. Legitimate (mode 1 with an
operator-uploaded certificate), but it is a choice, and it must be visible as one.

### Deviation and downgrade

```rust
pub enum Deviation {
    UnknownCertificate { observed: String },
    InvalidSignature(String),
    AbandonedCertificate { observed: String },
}
impl Deviation { pub fn message(&self, peer: &str) -> String; }

pub struct FallToMode1 { pub deviation: Deviation }
impl FallToMode1 {
    pub fn at(deviation: Deviation) -> Self;   // the only constructor — no way back without an operator
    pub fn mode(&self) -> Mode;            // always Pinning
    pub fn can_retry(&self) -> bool;       // always false
}
```

### `ClockDrift` — diagnostics

```rust
pub enum Drift { Normal, Log, Warning }
impl ClockDrift {
    pub fn new() -> Self;                  // + Default
    pub fn observe(&mut self, their_sent_at: i64, our_now: i64) -> Drift;
    pub fn last(&self) -> Option<i64>;     // positive = the peer is ahead
    pub fn max(&self) -> i64;
    pub fn message(&self, peer: &str) -> Option<String>;
}
```
Pure diagnostics — clock drift steers nothing.

---

## `capability` — the signed AEAD support statement *(new in 0.8.2)*

The decided pattern: **the best algorithm (AEGIS-256) is the default; fallback is an explicit,
authenticated exception; falling back to nothing does not exist.** `lockbox`/`envelope` already
default to AEGIS-256 with `_with` variants for an explicit per-call choice — this module is the
authenticated basis for choosing.

```rust
pub const ALGSUPPORT_V1: &str = "nettls-algsupport/v1";        // in `canonical`
pub fn algsupport_v1(component: &str, algs: &str, timestamp: i64) -> Result<Vec<u8>, TlsError>;  // in `canonical`

pub fn alg_token(alg: Alg) -> &'static str;                    // krypto-cli's vocabulary
pub fn alg_from_token(token: &str) -> Result<Alg, TlsError>;   // fail-closed

pub struct SupportStatement { component, supported: Vec<String>, timestamp, signature }
impl SupportStatement {
    pub fn signed(component, supported: &[Alg], timestamp, anchor_pkcs8: &krypto::SecretBuf) -> Result<Self, TlsError>;
    pub fn verify(&self, signer_cert_der: &[u8]) -> Result<Vec<Alg>, TlsError>;
}

pub fn choose(requested: Alg, verified_supported: Option<&[Alg]>) -> Result<Alg, TlsError>;
```

- **Only the party that does NOT support an algorithm can authorize a downgrade** — with its
  P-256 anchor signature over the canonical statement (fixed token order; unknown tokens,
  duplicates and reordering are rejected — one spelling per support set).
- **`choose` is the rule:** no statement → the requested stands; a verified statement without
  it → the best the peer declared, by the fixed preference order (aegis256 · xchacha20 ·
  aes256gcm); nothing acceptable → `TlsError::Negotiation` — **the connection fails, never
  silently weaker**. An unverifiable statement authorizes nothing.
- The Python twin carries the same surface (`algsupport_v1`,
  `build_support_statement`/`verify_support_statement`, `choose_alg`) — a Python party
  typically declares `["aes256gcm"]`. Byte parity is proven by the `algsupport-01` vector.

## `status` — the About contribution *(new in 0.8.2)*

Every service shows status for its parts; the TLS part is this crate's to describe. The crate
owns the **vocabulary**, the **derivation** (what counts as a warning — thresholds live in ONE
place) and the **headline**; the consumer owns the transport.

```rust
pub enum Level { Ok, Warn, Alert }                       // the traffic light, crate-derived
pub enum PeerState { Ok, RotationPending, Broken }

pub struct PeerReport { pub name, pub state, pub current_fingerprint, pub next_fingerprint }
impl PeerReport {
    pub fn from_generations(name, g: &Generations) -> Self;  // derives Ok/RotationPending
    pub fn broken(name, last_known_fingerprint) -> Self;     // only the consumer sees Chain errors
}

pub struct IdentityReport { fingerprint_sha256, origin, not_after, days_until_expiry, expiry_warning }
pub struct RotationReport { waiting_for, alarm, seconds_until_stop }

pub struct Report { version, level, headline, identity, rotation: Option<RotationReport>, peers }
impl Report {
    pub fn collect(now: i64, material: &TlsMaterial,
                   announcer_status: Option<&Status>, peers: Vec<PeerReport>) -> Report;
    pub fn summary(&self) -> Summary;
}

pub struct Summary { version, level, headline }
```

**The instruction to consumers — two views, two audiences:**

| View | Audience | Serve it on |
|---|---|---|
| `Report::summary()` — version, traffic light, headline; nothing else | every logged-in user | the general About surface |
| `Report` — identity, rotation state, per-peer trust | admin only (peer names, waiting lists and deviations are operations data) | the admin surface |

Everything serializes with serde — drop it straight into your status JSON. No I/O, no clock:
you pass `now` (Unix seconds). The `expiry_warning` flag and the `level` are the crate's own
rules — never re-derive them.

---

## `signature` — the §6 rules over krypto's primitives

Since 0.8.0 the primitives live in `krypto` (0.5): encoding is `krypto::hex::encode`, Ed25519 is
`krypto::sign::ed25519_*` (seeds as `krypto::SecretBuf`, constants `ED25519_SEED_LEN`/
`ED25519_PUBLIC_LEN` are krypto's). What remains here is the §6 domain:

```rust
pub fn from_hex(s: &str) -> Result<Vec<u8>, TlsError>;    // §6.5 field: non-empty + krypto::hex::decode
                                                          // (lowercase, fail-closed; never panics on UTF-8)

pub fn p256_public_key(cert_der: &[u8]) -> Result<Vec<u8>, TlsError>;             // X.509 → SEC1 point
pub fn sign_p256(pkcs8: &krypto::SecretBuf, message: &[u8]) -> Result<Vec<u8>, TlsError>;  // → krypto::sign; key never leaves the lock (0.8.3)
pub fn verify_p256(cert_der: &[u8], message: &[u8], signature: &[u8]) -> Result<(), TlsError>;
```

## `canonical` — what actually gets signed

Domain separators: `APPROVE_V1` · `ROTATE_V2` · `ROTATE_ACK_V2` · `PAIRSECRET_V1`

Builders: `approve_v1(..)` · `rotate_v2(..)` · `rotate_ack_v2(..)` · `pairsecret_v1(..)`

Validation: `require_fingerprint(v, field)` · `require_component_name(v, field)` (strict:
`[a-z0-9-]{1,32}`) · `require_name(v, field, max)` (usernames: looser, but no control chars)

> Use these if you verify outside the crate. Building the string yourself is a fine way to get a
> signature that looks right and is not.

## `envelope` — seal to one recipient

```rust
pub const X25519_LEN: usize = 32;

impl RecipientKey {                       // Debug: [REDACTED]; the key lives in a SecretBuf
    pub fn from_bytes(b: krypto::SecretBuf) -> Result<Self, TlsError>;   // consumes — the secret-types rule
    pub fn generate() -> Result<(Self, Vec<u8>), TlsError>;   // (private, public)
    pub fn public(&self) -> Result<Vec<u8>, TlsError>;
}

pub fn seal(recipient_public: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, TlsError>;   // AEGIS-256
pub fn seal_with(recipient_public: &[u8], plaintext: &[u8], alg: krypto::Alg) -> Result<Vec<u8>, TlsError>;
pub fn open(key: &RecipientKey, envelope: &[u8]) -> Result<krypto::SecretBuf, TlsError>;
```

Whoever seals holds no key and cannot open. `seal_with(_, _, Alg::Aes256Gcm)` is the interop
bridge for a recipient without AEGIS (Python); `open` reads the algorithm from the header.
The key exchange is `krypto::exchange` (0.8.0) — a low-order recipient point is **rejected at
sealing** (non-contributory result), it no longer yields an envelope.

## `lockbox` — lock with a password

```rust
pub fn lock(password: &krypto::SecretString, plaintext: &[u8]) -> Result<Vec<u8>, TlsError>;      // AEGIS-256
pub fn lock_with(password, plaintext, alg: krypto::Alg) -> Result<Vec<u8>, TlsError>;
pub fn unlock(password: &krypto::SecretString, file: &[u8]) -> Result<krypto::SecretBuf, TlsError>;
```

argon2id + FAFN. No verification hash is stored — a wrong password is an AEAD authentication
failure, and an unknown format is reported as **wrong format**, not a wrong password.

---

## `error` — `TlsError`

```rust
#[non_exhaustive]
pub enum TlsError {
    Io { path: Option<PathBuf>, detail: String },
    Pem(String),
    KeyMismatch(String),                                    // the classic upload mistake
    NotValidNow { not_before: i64, not_after: i64, now: i64 },
    Certificate(String),
    Generate(String),
    Rustls(String),
    Params(String),          // invalid consumer input (empty SAN list, valid_days out of range, …)
    Fingerprint(String),
    Proof(String),           // could not be PARSED — fail-closed
    ProofInvalid(String),    // parses fine but does NOT hold (signature, wrong identity, replay)
    Chain(String),           // the continuity chain is broken — the system's best-explained error
    Sign(String),
    Negotiation(String),     // no authenticated common AEAD — hard failure (0.8.2)
}
```

| Variant | When |
|---|---|
| `Io` | file/directory |
| `Pem` | the PEM could not be read |
| `KeyMismatch` | the key does not belong to the certificate |
| `NotValidNow` | outside the validity window |
| `Certificate` | the certificate could not be parsed |
| `Generate` | generation failed |
| `Rustls` | rustls rejected the config |
| `Params` | invalid parameters in |
| `Fingerprint` | the fingerprint has the wrong shape |
| `Proof` | the proof/message could not be parsed |
| `ProofInvalid` | parsed fine but does not hold |
| `Chain` | the chain does not connect |
| `Sign` | signing failed |
| `Negotiation` | no *authenticated* common AEAD — the connection must fail, never silently weaken *(0.8.2)* |

The `Proof` / `ProofInvalid` split is worth noting: the first is a shape error, the second is a
signature that does not hold. Only the second is a security finding. `#[non_exhaustive]` — new
variants may appear.

**Never empty error messages** — every variant carries enough context for the operator to see
*what* is wrong. **No variant ever carries key material** (a `TlsError` gets logged, and a
logged private key is a compromised private key). The `Chain` message names the state and
**both** fingerprints — its consequence is that communication stands still until an operator
re-approves, so it must be the system's best-explained error.

---

## The enrollment rule — trust over an unverified connection (CONTRACT)

Before a peer is approved (`PeerState::RotationPending`), or when the chain is broken
(`PeerState::Broken`),
three principles apply for every consumer of this crate:

1. **Observing an identity is not trusting it.** A certificate is public — connecting
   unverified *only to read the peer's certificate/fingerprint* gives an attacker nothing new.
   The connection may be used to **look**, never to **transfer**.
2. **The order layer is protected independently of TLS.** Every request is verified with
   Ed25519 signatures against pinned keys — an attacker on an unverified connection loses you
   confidentiality, not integrity. Unverified mode is *uncomfortable*, not *dangerous*.
3. **The fingerprint is verified out of band.** A service logs its own fingerprint at startup
   and exposes it on its health surface; the surface asking for approval SHALL urge the
   operator to compare against the peer's own startup log. Without that comparison the
   approval is effectively TOFU.

**The contract for unverified mode:**

| Allowed | **Not allowed** |
|---|---|
| fetching and showing the peer's certificate/fingerprint | credential deposits — secrets must **never** cross an unverified connection |
| health checks | any mutating operation against devices/data |
| the operator's approval of a fingerprint | anything carrying customer data or configuration |

---

## Stability

**Safe to build on:** the wire format (the frozen table
at the top — changing it is breaking regardless of semver) · the `TlsError` branches
(`#[non_exhaustive]`) · the `CertSource`/`TlsMaterial` surface · the pinning model (full
signature verification, constant time, resumption off) · the §6 message forms and verification
orders · the generation pair's two roles · the `Announcer::new` contract (load-or-init,
fail-closed) · the switch point (chain + serving together, consumer's port) · the algorithm
layers (AEGIS-256 default, AES-256-GCM as the bridge, algorithm from the header, hard failure).

**Deliberate non-mechanisms** *(decided 2026-08-27)*: the Ed25519 **request-signing keys do
not rotate on a schedule** — §6 rotates certificates; the signing keys are static, and their
replacement is *regeneration per service + a new operator approval* (the gen 0 path). The
trust model leans on the gen 0/init step by design. And the crate has **no CA/issuer role**:
it offers certificate functions (self-signed issuance, pinning, §6 rotation) — it never issues
on anyone's behalf.

**In motion:**

- **AEGIS-256 in the TLS transport is a deliberate deviation, not a wait (0.8.3).** Checked
  against the source 2026-09-04: rustls 0.23 has a 12-byte nonce, 0.24.0-dev.1 *and* git-main
  cap `Iv::MAX_LEN` at 16 (PR#2737 made the IV variable-length, never 32), and nobody upstream
  is working on it. So `aegis` ships our own suite — private code point, zero-padded nonce,
  SHA-384 pairing, all written down — as a consumer choice (`TransportCipher::Aegis256`),
  never the default. The default transport is AES-256-GCM. The exit (rustls ships AEGIS or a
  32-byte IV) is caught by the build.
- ~~Guaranteed zeroing of PEM buffers belongs in `krypto::SecretBuf`; `pem::wipe` is a
  documented, bounded compromise under `forbid(unsafe_code)`.~~ **Done in 0.8.3:** private keys
  the crate holds are `SecretBuf`; `pem::wipe` is gone (`zeroize` covers the short-lived
  rest). What remains outside the fence is rustls'/ring's own copy — see *Private keys in
  memory* under `TlsMaterial`.

**Breaking 0.x shifts that have happened** *(precedent)*: 0.3.0 deprecated the §5 model; 0.6.x
absorbed the recovery calls into `Announcer::new`; **0.7.0 switched the whole API surface to
English** (see the migration table in `CHANGELOG.md`) without touching the wire format;
**0.8.0 removed the crate's own primitives in favour of krypto** (hex/Ed25519 out of the
surface, seeds as `SecretBuf`) — still without touching the wire format; **0.8.2 removed the
retired §5 model entirely** (`chain` + `rotation`: `TrustChain`, `RotationProof`,
`PROOF_VERSION`, `ROTATION_PROOF_FILE`, the `sign_successor`/`sign_rotation`/
`verify_successor` methods and the `rotation.proof` file) — the whole app is in its build
phase, nothing to migrate (`cert_fingerprint_sha256` survived; it moved to `material`).
Recorded here, and every entry above carries the version it applies from.

---

## Further

- **[Home](Home.md)** — what nettls is, and what it is not
- **[Usage](Usage.md)** — the order, the traps, and what you do yourself
