# nettls — shared TLS building block

*(Directory `nettls/`. No codename — the crate has had a functional name from day one.)*

> **This repository is a mirror.** Development happens elsewhere and is pushed here;
> every sync overwrites what is here, so a pull request cannot be merged and a commit
> made here is lost. Issues are read — see [CONTRIBUTING.md](CONTRIBUTING.md) for the
> form a change has to arrive in, and [SECURITY.md](SECURITY.md) for vulnerabilities.

A standalone TLS building block — it grew out of building a real application, but
is fully self-contained (its only sibling dependency is the `krypto` crate). One place for
your TLS setup: a crypto provider without traps, self-signed
certificates with SANs, PEM in and out, SHA-256 fingerprints, fingerprint pinning on the client
side — and the **§6 announcement protocol**: asynchronous certificate rotation with two-signature
continuity, signed receipts, generation pairs and an operator anchor.

- **Type:** Rust crate (library)
- **Lifetime:** Long-lived — semver from day one, and every entry in the API contract carries
  the version it applies from, so the crate can change without a reader having to guess
- **License:** MIT/Apache-2.0 dual
- **Dependencies:** rustls 0.23 (ring provider), rcgen 0.14, rustls-pki-types, x509-parser,
  serde/serde_json, time, aegis, zeroize, krypto 0.7. **No `axum`, no async runtime, no logging** —
  the crate returns `ServerConfig`/`ClientConfig` and facts; the consumer binds and logs.
  **No direct `ring` or `x25519-dalek`** since 0.8.0 — every primitive is krypto's.
- **In use:** already carrying traffic in more than one application.
- **Python twin:** a protocol twin lives in [`python/nettls.py`](python/nettls.py).
- **Docs:** [`docs/`](docs/) — **authoritative for the crate** (externally validated: a third
  party built against this repo alone). The complete, machine-verified contract is
  [`docs/API.md`](docs/API.md) — every public name, enforced by a doc-guard test; guide:
  [`docs/Usage.md`](docs/Usage.md); overview: [`docs/Home.md`](docs/Home.md).
- **Changes:** [`CHANGELOG.md`](CHANGELOG.md) · **Version:** declared once, in [`Cargo.toml`](Cargo.toml)


## Why does the crate exist?

Data had to move safely between two modules in two separate applications. The quick answer
would have been an SSH tunnel, or something similar bolted on from the outside. The alternative
was to do it once, properly, and then never think about it again. This crate is that one time —
and the application it was written for has been running on it since.

A separate crate rather than folding it into `krypto`: `krypto` is data-at-rest; TLS is
data-in-transit with a completely different rate of change. And
no existing crate covers self-signed + SAN + fingerprint pinning + the provider trap in one
place.

**Where the shape comes from.** Part of the motivation was plain certificate handling. The rest
is [RFC 8061](https://www.rfc-editor.org/rfc/rfc8061.html) — confidentiality in the data plane.
That work asks how two endpoints keep the traffic between them confidential *without* a
certificate authority in the middle: they establish who the other is directly, and the channel
rests on that alone. Nearly everything distinctive here follows from taking that seriously —
self-signed certificates instead of a CA chain, a fingerprint as the identity rather than a
signature from a third party, and the §6 rotation protocol so that identity can change without
the recognition breaking. Secure transport is the subject, not a feature.

**The cryptography is not this crate's.** Every primitive — AEAD, key derivation, signatures,
key exchange, constant-time comparison — lives in [`krypto`](https://crates.io/crates/krypto),
and since 0.8.0 nothing here reaches a primitive directly. That was a decision, not an accident
of layering: writing the same handful of primitives a second time, in a crate whose subject is
transport, is how two implementations of the same thing end up disagreeing about it. What stays
here is the TLS end — X.509, PEM, fingerprints, and the rotation protocol.

## The provider trap — the crate's most important job

`rustls` fails closed if **zero or more than one** crypto provider is compiled in:
*"no process-level CryptoProvider available"*. Cargo features are additive, so
`rustls = { version = "0.23", features = ["ring"] }` gives you ring **in addition to**
aws-lc-rs, not instead of it — rustls' own defaults pull in aws-lc-rs via `aws_lc_rs` +
`prefer-post-quantum`. Several crates do the same through the back door; `axum-server`'s
`tls-rustls` is defined as `["tls-rustls-no-provider", "rustls/aws-lc-rs"]`. **The failure
only shows up at the first handshake** — that is, potentially not until production. This is
what stranded the July 2026 attempt.

The crate solves it three ways at once:

1. `default-features = false` on everything that touches rustls (see the comment at the top of
   `Cargo.toml`).
2. `install_crypto_provider()` — idempotent, explicit, called first in `main()`.
3. Every config is built with `builder_with_provider(...)`, **never** `builder()`. That keeps
   the crate's own code correct even if the dependency tree one day pulls in a second provider.

The fence also exists as a **test**: `no_other_crypto_provider_in_cargo_lock` fails if
`aws-lc-sys`/`aws-lc-rs` appears in `Cargo.lock`.

**Consuming services must follow the same rules in their own manifests** — the crate cannot
force it through for them. Use `axum-server` with `tls-rustls-no-provider`, never `tls-rustls`,
and `tokio-rustls` with `default-features = false`.

## The API in one glance

The complete, machine-verified contract is [`docs/API.md`](docs/API.md). The shape of it:

| Module | What it gives you |
|---|---|
| `provider` | `install_crypto_provider()` · `provider()` — one engine, explicit, once |
| `material` | `CertSource` (files/pem/self_signed/auto) → `TlsMaterial` → `server_config()` + facts (`fingerprint_sha256`, `origin`, `days_until_expiry`, …) |
| `pin` | `pinned_client_config()` — static fingerprint pinning, full handshake-signature verification |
| `resolver` | `RotatingResolver` — swap the served certificate without a restart |
| `announcement` | `Announcement` (two-signature "here is my next certificate"), `Receipt` (signed ack), `IdentityJson`, append-only archive |
| `approval` | `Approval` (the operator's approval as an Ed25519 signature), `Recognition` — one verification path for generation 0 and n |
| `generations` | `Generations` (previous/current/next — two non-overlapping roles), `Trust` (live client config) |
| `announcer` | `Schedule` (state machine), `Announcer` (binds it all: prepare → acked → `roll_if_ready_gated`), `Mode`/`check_mode`, `Status`, `ClockDrift`, `FallToMode1` |
| `lockbox` | `lock`/`unlock` local state with a password (argon2id + FAFN; AEGIS-256 default) |
| `envelope` | sealed X25519 envelopes — the carrier never sees the contents |
| `canonical` + `signature` | the normative byte forms and the two signature types (ECDSA P-256, Ed25519) |
| `pem` | `encode(label, der)` — PEM out in RFC 7468 form; reading goes through `rustls-pki-types` |
| `capability` | `SupportStatement`/`choose` — the signed AEAD support statement: a fallback is an authenticated exception, never a silent one |
| `transport` | `TransportPolicy`/`TransportCipher` — the channel's cipher is the consumer's choice; AES-256-GCM alone by default (0.8.3) |
| `aegis` | AEGIS-256 as a TLS 1.3 record AEAD — our own suite, a documented deviation built to be replaced (0.8.3) |
| `status` | `Report`/`Summary` — the About contribution: two views for two audiences, no I/O, the caller owns the clock |
| `error` | `TlsError` — one error type, `#[non_exhaustive]`, never carrying key material |

### Use in a service

```rust
nettls::install_crypto_provider();                       // first thing in main()

let params = nettls::SelfSignedParams::new(
    "my service",
    ["service.internal", "localhost", "10.0.0.5", "127.0.0.1"],
);
let m = nettls::TlsMaterial::load(&nettls::CertSource::auto("/tls", params))?;

tracing::info!(fingerprint = %m.fingerprint_sha256(), origin = ?m.origin(),
               days_left = m.days_until_expiry(), "TLS ready");
let config = m.server_config()?;                          // Arc<rustls::ServerConfig>
```

### Rotation in one glance (§6)

```rust
// One-time setup: resolver + announcer (load-or-init, fail-closed).
let resolver = Arc::new(nettls::RotatingResolver::new(&material)?);
let config = resolver.server_config()?;                   // bind ONCE — it follows the swaps
let announcer = nettls::announcer::Announcer::new(
    "my-service", "/tls", nettls::announcer::mode2_params("my-service", ["my-service"]),
    resolver, anchor, schedule, Some(password))?;

// The rhythm is yours — the crate never acts on its own:
let ann = announcer.prepare(now)?;                        // create + persist + announce
announcer.acked("peer")?;                                 // a receipt came in (verified!)
announcer.roll_if_ready_gated(now, || device_idle())?;    // switch — chain and serving together
```

## Choices that are made, and are not to be "improved" casually

| Choice | Why |
|---|---|
| **ring**, not aws-lc-rs | Build time (~2.5 min saved) and fewer C dependencies. aws-lc-rs is verified viable if we ever need FIPS or post-quantum hybrid. |
| **ECDSA P-256** on self-generated certs | rcgen with ring **cannot** make RSA. And ECDSA gives *better* backwards compatibility: Win7/IE11 has ECDHE_ECDSA+GCM, not ECDHE_RSA+GCM. Ed25519 is supported by no mainstream browser. |
| **TLS 1.3 + TLS 1.2** | Without `tls12`, everything that is not TLS 1.3 is locked out. Looks like cleanup, is a compatibility regression. |
| **`auto` reuses the stored cert** | A new cert per boot = a new fingerprint = a new browser warning every time. Warnings the operator learns to click away don't work the day there is a real MITM. Expired stored certs are reused too (`ReusedExpired`) — regeneration must be deliberate, or every pinned pairing breaks silently. |
| **Max 397 days lifetime** | Safari and Chrome reject longer, self-signed included. |
| **No HSTS helpers** | `Strict-Transport-Security` set once while running self-signed locks the operator out of the app in that browser permanently. Do not add it here. |
| **Pinning without a CA chain and without a name check** | Deliberate — the same model as SSH host-key pinning. The handshake **signature** is verified in full; that is what makes pinning safe. |
| **A window of exactly two generations** | A rotation is not atomic across two services; with one fingerprint the connection would break mid-transition. With three or more, the trust surface would grow with every rotation, and an old leaked key would keep its value. |
| **Two signatures on the announcement** | Forging it requires two *consecutive* private keys. The §5 model's single signature let one stolen key sign itself forward indefinitely — that is why §5 is deprecated. |
| **The receipt gates the switch** | If A rolls before B has stored the new cert, B's handshake breaks at that instant. No receipt, no roll. |
| **Mode is announced, never negotiated** | A party that can *ask* for a mode can ask for the weakest one. `check_mode` compares; it never converges. |
| **Rotation cadence (7 d) vs. lifetime (30 d)** | Two numbers on purpose: if rotation fails there are 23 days to fix it — the app does not fall over. |
| **AEGIS-256 at rest, AES-256-GCM as the interop bridge** | The menu is krypto's, the choice is per store (§6.0b). Readers take the algorithm from the FAFN header and fail hard, never silently. |
| **The TLS channel's cipher is the consumer's choice** | `TransportPolicy` (0.8.3): default **AES-256-GCM only** — what every peer speaks. ChaCha20-Poly1305 and AEGIS-256 on request, in the consumer's order; no common suite is a hard failure, never a fallback. AEGIS in the channel is *our own suite*, a documented deviation from the standard (rustls has no 32-byte IV) built to be replaced — see `src/aegis.rs`. |
| **Session resumption OFF on the client side** | A resumed TLS 1.3 session does not resend the certificate — the pinning verifier would not run, and "pinned" would mean "checked once". The server side is untouched (useful for browsers; no pinning to undermine there). |

## What the crate does not do

Certificate administration (`/admin/tls/*`), the approval surface in the startup ceremony, the
rotation *job* (what runs every 7 days), CSR generation and the always-works port belong to the
consuming service, not here. The crate provides the building blocks, not the flow. It also logs nothing: `tls_rotated`, `tls_chain_check` and
`tls_static_pinning` are the consumer's responsibility.

## Test

```sh
cargo test                     # unit, integration and doctests; real TLS handshakes included
cargo clippy --all-targets -- -D warnings
python -m pytest python/ -q    # the Python twin — use the CI-pinned venv (python/krav-ci.txt)
python python/ringnode.py      # the ring: N nodes rotating against each other (see examples/ringnode.rs)
```

## Author

**Roger Jorgensen** — rogerj@gmail.com

Design, architecture and structure; the security model and what it means to fail closed; the
contracts the crate presents outwards; and the decisions about what it does and deliberately
does not do. 

The code is written by Claude AI (Opus and Fable).

Reviewed independently by DeepSeek, Qwen, Gemini and Fable.

## License

MIT **or** Apache-2.0, at the recipient's choice.
See [`LICENSE-MIT`](LICENSE-MIT) and [`LICENSE-APACHE`](LICENSE-APACHE).

Both permit the same use. They differ on patents, and that is the reason for offering both:
MIT is silent on them, Apache-2.0 grants one explicitly and withdraws it from anyone who sues
over it (§3). Organisations differ on which of the two their own rules already accept — and for
a crate that carries traffic the question comes up more often than elsewhere. Offering both
means you take the one you are already cleared for, without having to ask.

### Contributions

**Reports are what is wanted here — not patches.** If something behaves differently from what
the documentation says, or a guarantee does not hold, say so and show how to see it. That is
the most useful thing anyone outside can send. The crate is deliberately narrow, with one
canonical way of doing each thing, so a fix has to fit that canon — and it is quicker and safer
for the fix to be made here than for a patch to be reviewed and reshaped into it.

Code is not refused. It is simply not what is being asked for, and it is not prioritised.
**If you do send it, it is accepted only under the same terms as the crate.** By submitting
code for inclusion you license it as MIT **or** Apache-2.0, at the recipient's choice, with no
additional conditions. Code offered on other terms cannot be merged — not as a judgement on it,
but because the choice this crate gives its users only holds if it holds for every line in it.
A single file on other terms breaks that promise for everyone downstream.

[CONTRIBUTING.md](CONTRIBUTING.md) says how to file a report. [SECURITY.md](SECURITY.md) covers
anything security-related, which does not belong in an issue.
