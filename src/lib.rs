// SPDX-License-Identifier: MIT OR Apache-2.0
//! `nettls` — a shared TLS building block for services that have to agree on one
//! way of doing it.
//!
//! It was not written in the abstract. It was built for an application where two
//! services both needed HTTPS and an operator's **device password** passed
//! through both, and it has run there ever since. Rather than duplicate the
//! rustls setup — and duplicate its pitfalls — it lives here, in one place, with
//! tests.
//!
//! ## Why a separate crate and not `krypto`?
//!
//! `krypto` is data-at-rest. TLS is
//! data-in-transit and has a completely different rate of change (rustls
//! upgrades, provider choice, certificate life cycle). And no existing crate
//! covers the combination self-signed + SAN + fingerprint pinning + the
//! provider trap in one place.
//!
//! ## The provider trap — this crate's most important job
//!
//! `rustls` fails closed if **zero or more than one** crypto provider is
//! compiled in: "no process-level CryptoProvider available". Cargo features
//! are additive, so `rustls = { version = "0.23", features = ["ring"] }` gives
//! you ring *in addition to* aws-lc-rs, not instead of it. Several crates pull
//! in aws-lc-rs through the back door — `axum-server`'s `tls-rustls` feature is
//! defined as `["tls-rustls-no-provider", "rustls/aws-lc-rs"]`. The failure
//! only shows up at the **first handshake** — that is, potentially not until
//! production.
//!
//! The crate solves this in two ways at once: [`install_crypto_provider`] sets
//! the process default explicitly and idempotently, and all configs are built
//! with `builder_with_provider(...)` — never `builder()` — so the crate's own
//! code is correct no matter what the dependency tree gets up to. See
//! `Cargo.toml` for the rules consuming services must follow in their own
//! manifests.
//!
//! ## Typical use in a service
//!
//! ```no_run
//! # fn main() -> Result<(), nettls::TlsError> {
//! nettls::install_crypto_provider(); // first thing in main()
//!
//! let params = nettls::SelfSignedParams::new(
//!     "example portal",
//!     ["example.internal", "localhost", "10.0.0.5", "127.0.0.1"],
//! );
//! let material = nettls::TlsMaterial::load(&nettls::CertSource::auto("/tls", params))?;
//!
//! // The fingerprint is what clients pin — log it at startup.
//! println!("TLS fingerprint: {}", material.fingerprint_sha256());
//! let config = material.server_config()?; // Arc<rustls::ServerConfig>
//! # let _ = config; Ok(()) }
//! ```
//!
//! And on the client side, against a service with a known fingerprint:
//!
//! ```no_run
//! # fn main() -> Result<(), nettls::TlsError> {
//! let client = nettls::pinned_client_config(
//!     "3b1f…64 hex digits…a9",
//! )?;
//! # let _ = client; Ok(()) }
//! ```
//!
//! ## Rotation without a CA — the §6 protocol
//!
//! Static pinning is right facing the outside, but internally it would reject
//! every single rotation — and the rotation *is* the security mechanism: a key
//! that leaks after its window is already out of use. The crate's answer is
//! the announced, receipted, operator-approved rotation protocol:
//!
//! - [`announcement::Announcement`] — *"here is my next certificate"*, signed
//!   under §6 rules ([`signature`], [`canonical`]).
//! - [`generations::Trust`] — the peer's state (previous/current/next) with
//!   distinct roles, read live at every handshake.
//! - [`announcer::Announcer`] — the state machine that binds announcement,
//!   receipt, approval and the switch point together.
//! - [`RotatingResolver`] swaps the server's certificate **without a restart**,
//!   so the rotation does not cost an outage.
//!
//! The root is the operator's approval of the first certificate — there is
//! no CA, and an announcement we cannot verify does not extend trust. In that
//! case the connection is broken, because the alternative is TOFU through the
//! back door. *(The earlier §5 "sliding pinning" model — `TrustChain` +
//! `RotationProof`, one-key proofs — was removed in 0.8.2; see `CHANGELOG.md`.)*
//!
//! ## What the crate does NOT do
//!
//! - **No `axum` dependency, no runtime.** It returns
//!   `rustls::ServerConfig`/`ClientConfig`; the consumer does its own binding.
//!   That is why a service built on axum, one built on something else, and one
//!   not yet written can all use it.
//! - **No logging.** The crate emits nothing; it returns facts
//!   ([`TlsMaterial::origin`], [`TlsMaterial::days_until_expiry`],
//!   [`TlsMaterial::fingerprint_sha256`]) that the consumer logs wherever it
//!   wants.
//! - **No HSTS helpers.** Deliberately: `Strict-Transport-Security` set once
//!   while we are running self-signed locks the operator out of the app in that
//!   browser until browser data is cleared (L2-014 ch. 8.2). Do not "improve"
//!   this.
//! - **No cipher *negotiation* of its own.** The channel's cipher is the
//!   consumer's choice ([`transport`], 0.8.3): the default is AES-256-GCM
//!   alone, and TLS itself picks the first suite in the consumer's list the
//!   peer also speaks. No common suite is a hard failure — never a fallback.
//!   *(Up to 0.8.2 the configs offered ring's full list of nine suites.)*

#![forbid(unsafe_code)]
#![warn(missing_docs)]

/// The crate version, for consumers that surface component versions — the
/// anchor that says which feature set is active (the mapping version →
/// capabilities lives in `CHANGELOG.md`). Mirrors `Cargo.toml`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub mod aegis; // 0.8.3: AEGIS-256 in the channel — a deliberate, documented deviation (L2-076)
pub mod announcement;
pub mod announcer;
pub mod approval;
pub mod canonical;
pub mod capability;
pub mod envelope;
pub mod error;
pub mod generations;
pub mod lockbox;
pub mod material;
pub mod pin;
pub mod provider;
pub mod resolver;
pub mod signature;
pub mod status;
pub mod transport; // 0.8.3: the TLS channel's cipher — the consumer's choice (§6.0b)

mod fingerprint;
pub mod pem; // pub since 0.8.1 (wish #2): PEM building is TLS domain and lives here
mod pkcs8;
mod secret; // 0.8.3: private keys in memory — SecretBuf, and the honest limit

pub use error::TlsError;
pub use material::{
    cert_fingerprint_sha256, is_valid_san, CertOrigin, CertSource, SelfSignedParams, TlsMaterial,
    CERT_FILE, KEY_FILE, MAX_VALID_DAYS,
};
pub use pin::{pinned_client_config, pinned_client_config_with, pinned_client_config_with_alpn};
pub use provider::{install_crypto_provider, provider};
pub use resolver::RotatingResolver;
pub use transport::{TransportCipher, TransportPolicy};

/// Re-export, so consumers can name rustls types without listing `rustls`
/// themselves — and thus without risking a line of their own with wrong features.
/// PKCS#8 from key material — **only for the cross-test** against the Python side.
///
/// Lives here and not in `signature` because it is not part of §6: it exists
/// solely so the bridge in `python/test_krysstest.py` can sign with the same
/// material it serves. A general signing oracle on TLS key material is a
/// surface we do not want.
#[doc(hidden)]
#[deprecated(
    since = "0.8.1",
    note = "use TlsMaterial::anchor_pkcs8() — the proper anchor API (wish #4)"
)]
pub fn pkcs8_for_test(m: &TlsMaterial) -> Result<krypto::SecretBuf, TlsError> {
    m.anchor_pkcs8()
}

/// PEM encoding — **only for examples and tests** (the ring node).
#[doc(hidden)]
#[deprecated(
    since = "0.8.1",
    note = "use nettls::pem::encode — public since 0.8.1 (wish #2)"
)]
pub fn pem_encode_for_test(label: &str, der: &[u8]) -> Vec<u8> {
    pem::encode(label, der)
}

/// SHA-256 over DER as hex — **only for examples and tests**.
#[doc(hidden)]
pub fn fingerprint_for_test(der: &[u8]) -> String {
    krypto::hex::encode(&krypto::sha256(der))
}

pub use rustls;
