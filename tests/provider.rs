// SPDX-License-Identifier: MIT OR Apache-2.0
//! Provider-installasjonen — cratens hele eksistensberettigelse.

use nettls::{install_crypto_provider, provider};

#[test]
fn install_is_idempotent() {
    // `CryptoProvider::install_default` can succeed only ONCE per process.
    // A second call must not panic, not return an error upwards, and not
    // leave the process without a provider — "already installed" is the
    // expected state, not an error condition.
    let first = install_crypto_provider();
    let second = install_crypto_provider();
    let tredje = install_crypto_provider();

    assert!(first, "the first call must install");
    assert!(!second, "the second call must see it is already done");
    assert!(!tredje);

    assert!(
        rustls::crypto::CryptoProvider::get_default().is_some(),
        "the process must have a default provider after the calls"
    );
}

#[test]
fn provider_gives_ring_suites_and_same_arc_every_time() {
    let a = provider();
    let b = provider();
    assert!(
        std::sync::Arc::ptr_eq(&a, &b),
        "provider() must not build a new one every time"
    );

    // Nine suites, all AEAD, all ECDHE — ring's whole set. If that count changes
    // on an upgrade, it deserves a look, not a panic.
    assert_eq!(
        a.cipher_suites.len(),
        9,
        "unexpected suite list: {:?}",
        a.cipher_suites
    );

    // Sanity: that we actually got ring and not aws-lc-rs. The ring provider
    // lacks X25519MLKEM768 (the post-quantum hybrid aws-lc-rs brings).
    let grupper: Vec<String> = a
        .kx_groups
        .iter()
        .map(|g| format!("{:?}", g.name()))
        .collect();
    assert!(
        grupper.iter().any(|g| g.contains("X25519")),
        "kx-grupper: {grupper:?}"
    );
    assert!(
        !grupper.iter().any(|g| g.contains("MLKEM")),
        "MLKEM suggests aws-lc-rs has sneaked in: {grupper:?}"
    );
}

/// Gjerdet mot at provider-fella sniker seg tilbake.
///
/// Case L2-014 ch. 2.2.7 proposes this as a CI check. It lives here as a
/// **test** instead, so it follows the crate and runs for everyone who builds
/// it — not just in one CI configuration someone can forget to copy.
///
/// If it fires: a dependency was added without `default-features = false`, or
/// an existing dependency got new defaults. The production symptom would have
/// been a panic at the **first handshake** — «no process-level CryptoProvider
/// available» — i.e. possibly only after rollout.
#[test]
fn no_other_crypto_provider_in_cargo_lock() {
    let lock = include_str!("../Cargo.lock");
    for forbudt in ["aws-lc-sys", "aws-lc-rs"] {
        assert!(
            !lock.contains(&format!("name = \"{forbudt}\"")),
            "{forbudt} exists in Cargo.lock — then TWO crypto providers are compiled in, and \
             rustls fail-closes at the first handshake. See the comment at the top of \
             Cargo.toml: every new dependency touching rustls MUST have default-features = false."
        );
    }
    // Positive control: the test must not be able to go green because the file was empty.
    assert!(
        lock.contains("name = \"rustls\""),
        "Cargo.lock does not look as expected"
    );
    assert!(lock.contains("name = \"ring\""));
}
