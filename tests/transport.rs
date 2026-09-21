// SPDX-License-Identifier: MIT OR Apache-2.0
//! The TLS channel's cipher is the consumer's choice (SPEC-nettls §6.0b) —
//! proven with real handshakes over loopback, not by inspecting lists.
//!
//! - the default is AES-256-GCM only, on both sides;
//! - a peer outside the policy is refused — hard, no fallback;
//! - the consumer's order decides when both sides offer several.

use std::sync::Arc;

use nettls::{
    install_crypto_provider, pinned_client_config_with, CertSource, SelfSignedParams, TlsMaterial,
    TransportCipher, TransportPolicy,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};

const GREETING: &[u8] = b"cipher agreed";

fn material() -> TlsMaterial {
    TlsMaterial::load(&CertSource::self_signed(SelfSignedParams::new(
        "nettls transport",
        ["localhost"],
    )))
    .unwrap()
}

/// One-shot server with the given policy. Returns the port.
async fn start_server(m: &TlsMaterial, policy: &TransportPolicy) -> u16 {
    let config = m.server_config_with(&[], policy).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let acceptor = TlsAcceptor::from(config);
    tokio::spawn(async move {
        if let Ok((tcp, _)) = listener.accept().await {
            if let Ok(mut tls) = acceptor.accept(tcp).await {
                let _ = tls.write_all(GREETING).await;
                let _ = tls.shutdown().await;
            }
        }
    });
    port
}

/// Connects pinned, with the given policy. Returns the negotiated suite's name.
async fn connect(port: u16, fp: &str, policy: &TransportPolicy) -> Result<String, String> {
    let config = pinned_client_config_with(fp, &[], policy).map_err(|e| e.to_string())?;
    let connector = TlsConnector::from(config);
    let tcp = TcpStream::connect(("127.0.0.1", port))
        .await
        .map_err(|e| e.to_string())?;
    let name = nettls::rustls::pki_types::ServerName::try_from("localhost").unwrap();
    let mut tls = connector
        .connect(name, tcp)
        .await
        .map_err(|e| e.to_string())?;
    let suite = format!(
        "{:?}",
        tls.get_ref()
            .1
            .negotiated_cipher_suite()
            .expect("a completed handshake has a suite")
            .suite()
    );
    let mut buf = Vec::new();
    tls.read_to_end(&mut buf).await.map_err(|e| e.to_string())?;
    assert_eq!(buf, GREETING);
    Ok(suite)
}

fn chacha() -> TransportPolicy {
    TransportPolicy::only(TransportCipher::ChaCha20Poly1305)
}

#[tokio::test]
async fn default_is_aes_256_gcm_on_both_sides() {
    install_crypto_provider();
    let m = material();
    let fp = m.fingerprint_sha256();
    let port = start_server(&m, &TransportPolicy::default()).await;
    let suite = connect(port, &fp, &TransportPolicy::default())
        .await
        .expect("default against default must connect");
    assert_eq!(suite, "TLS13_AES_256_GCM_SHA384", "{suite}");
}

#[tokio::test]
async fn a_peer_outside_the_policy_is_refused_hard() {
    install_crypto_provider();
    let m = material();
    let fp = m.fingerprint_sha256();

    // Server: the default (AES-256-GCM). Client: ChaCha20 only. No common
    // suite → the handshake fails. Nothing falls back to anything.
    let port = start_server(&m, &TransportPolicy::default()).await;
    let err = connect(port, &fp, &chacha())
        .await
        .expect_err("no common cipher must be a hard failure");
    assert!(
        err.to_lowercase().contains("handshake") || err.to_lowercase().contains("alert"),
        "expected a handshake failure, got: {err}"
    );
}

#[tokio::test]
async fn the_consumers_order_decides() {
    install_crypto_provider();
    let m = material();
    let fp = m.fingerprint_sha256();

    // Both sides offer both; the SERVER's order is what rustls honours, and
    // the server's order is the consumer's list, verbatim.
    let both_chacha_first = TransportPolicy::new(&[
        TransportCipher::ChaCha20Poly1305,
        TransportCipher::Aes256Gcm,
    ])
    .unwrap();
    let both_aes_first = TransportPolicy::new(&[
        TransportCipher::Aes256Gcm,
        TransportCipher::ChaCha20Poly1305,
    ])
    .unwrap();

    let port = start_server(&m, &both_chacha_first).await;
    let suite = connect(port, &fp, &both_aes_first).await.unwrap();
    assert_eq!(suite, "TLS13_CHACHA20_POLY1305_SHA256", "{suite}");

    let port = start_server(&m, &both_aes_first).await;
    let suite = connect(port, &fp, &both_chacha_first).await.unwrap();
    assert_eq!(suite, "TLS13_AES_256_GCM_SHA384", "{suite}");
}

#[tokio::test]
async fn a_widened_server_still_meets_a_default_client() {
    install_crypto_provider();
    let m = material();
    let fp = m.fingerprint_sha256();
    // A consumer that widens its server policy keeps working against every
    // peer that stayed on the default — AES-256-GCM is always in the list.
    let wide = TransportPolicy::new(&[
        TransportCipher::ChaCha20Poly1305,
        TransportCipher::Aes256Gcm,
    ])
    .unwrap();
    let port = start_server(&m, &wide).await;
    let suite = connect(port, &fp, &TransportPolicy::default())
        .await
        .unwrap();
    assert_eq!(suite, "TLS13_AES_256_GCM_SHA384", "{suite}");
}

#[test]
fn the_server_config_carries_only_the_policy_suites() {
    install_crypto_provider();
    let m = material();
    let cfg = m.server_config().unwrap();
    let suites: Vec<String> = cfg
        .crypto_provider()
        .cipher_suites
        .iter()
        .map(|s| format!("{:?}", s.suite()))
        .collect();
    assert_eq!(suites.len(), 3, "{suites:?}");
    assert!(
        suites.iter().all(|s| s.contains("AES_256_GCM")),
        "{suites:?}"
    );
    // And the process-global provider (for OTHER libraries) is untouched.
    let _ = Arc::clone(&nettls::provider());
    assert!(nettls::provider().cipher_suites.len() > 3);
}
