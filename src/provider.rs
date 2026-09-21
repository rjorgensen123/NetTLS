// SPDX-License-Identifier: MIT OR Apache-2.0
//! Crypto provider: one choice, explicit, once.
//!
//! See the long comment in `Cargo.toml` for why this is the crate's reason to
//! exist. In short: rustls fails closed if zero or more than one provider is
//! compiled in, and the failure only surfaces at the **first handshake** —
//! that is, potentially not until production. By installing the provider
//! explicitly and building all configs with [`builder_with_provider`], the
//! code is correct no matter what the dependency tree gets up to.
//!
//! [`builder_with_provider`]: rustls::ServerConfig::builder_with_provider

use std::sync::{Arc, OnceLock};

use rustls::crypto::CryptoProvider;

static PROVIDER: OnceLock<Arc<CryptoProvider>> = OnceLock::new();

/// The provider this crate uses: **ring**.
///
/// The choice is ring and not aws-lc-rs for build-time reasons (aws-lc-sys
/// takes ~2.5 minutes extra) and for fewer C dependencies — not because
/// aws-lc-rs is impossible. Should we one day need FIPS or post-quantum hybrid
/// (X25519MLKEM768), aws-lc-rs is the way, and it is verified viable in our
/// build environment (L2-014 ch. 2.3).
///
/// The same `Arc` is returned every time, so repeated calls are free.
pub fn provider() -> Arc<CryptoProvider> {
    PROVIDER
        .get_or_init(|| Arc::new(rustls::crypto::ring::default_provider()))
        .clone()
}

/// Installs ring as the process-global default provider. **Idempotent.**
///
/// Call it first in `main()`. It can safely be called multiple times and from
/// multiple threads: `CryptoProvider::install_default` can only succeed once
/// per process, and "already installed" is deliberately swallowed here — it is
/// not an error, it is the expected state on call number two.
///
/// The function returns `bool`: `true` if *this* call installed the provider,
/// `false` if one already existed. The return value is pure information
/// (useful in a log); no consumer needs to react to it.
///
/// Note that the crate's own `server_config`/`pinned_client_config` do not
/// depend on this having been called — they use [`provider()`] explicitly. The
/// process-global installation is there for everything *else* in the process
/// that might call `rustls::ServerConfig::builder()` without a provider.
pub fn install_crypto_provider() -> bool {
    // `get_default().is_none()` first, to avoid building a provider we do not
    // need; `install_default` is authoritative in a race between threads
    // anyway, and if we lose that race the outcome is exactly what we would
    // have had.
    if CryptoProvider::get_default().is_some() {
        return false;
    }
    CryptoProvider::install_default(rustls::crypto::ring::default_provider()).is_ok()
}
