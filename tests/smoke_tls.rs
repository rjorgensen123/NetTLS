// SPDX-License-Identifier: MIT OR Apache-2.0
//! Smoke test: a **real** TLS server and a **real** TLS client over a real
//! TCP socket on loopback.
//!
//! This is the test that proves the thing actually works. The unit tests prove
//! that we compute the right fingerprint; this one proves that rustls actually
//! lets the pinned server through and actually shuts out another — including
//! that the handshake signature is validated, that protocol versions are
//! negotiated, and that
//! bare finnes én crypto-provider i prosessen.

use std::sync::Arc;

use nettls::{
    install_crypto_provider, pinned_client_config, CertSource, SelfSignedParams, TlsMaterial,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};

const GREETING: &[u8] = b"hello from nettls";

fn params() -> SelfSignedParams {
    SelfSignedParams::new("nettls smoke", ["localhost", "127.0.0.1"])
}

/// Starts a TLS server on a random loopback port. Returns the port.
/// The server accepts one connection, sends [`GREETING`] and hangs up.
async fn start_server(config: Arc<nettls::rustls::ServerConfig>) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let acceptor = TlsAcceptor::from(config);

    tokio::spawn(async move {
        // One attempt is enough; a rejected client yields an error we ignore
        // on purpose here — it is the client side the test checks.
        if let Ok((tcp, _)) = listener.accept().await {
            if let Ok(mut tls) = acceptor.accept(tcp).await {
                let _ = tls.write_all(GREETING).await;
                let _ = tls.shutdown().await;
            }
        }
    });

    port
}

/// Connects with pinning and reads the reply.
async fn connect_to(port: u16, pinned_fingerprint: &str) -> Result<Vec<u8>, String> {
    let config = pinned_client_config(pinned_fingerprint).map_err(|e| e.to_string())?;
    let connector = TlsConnector::from(config);

    let tcp = TcpStream::connect(("127.0.0.1", port))
        .await
        .map_err(|e| e.to_string())?;
    // The host name is there because rustls requires one — it is NOT checked
    // (pinning, not name validation). We deliberately use a name that is NOT
    // in the SAN list, to prove exactly that.
    let name = nettls::rustls::pki_types::ServerName::try_from("name-not-in-san")
        .map_err(|e| e.to_string())?;

    let mut tls = connector
        .connect(name, tcp)
        .await
        .map_err(|e| e.to_string())?;
    let mut buf = Vec::new();
    tls.read_to_end(&mut buf).await.map_err(|e| e.to_string())?;
    Ok(buf)
}

#[tokio::test]
async fn right_fingerprint_gets_through_wrong_fingerprint_rejected() {
    install_crypto_provider();

    // ── Server A: the one we pin ───────────────────────────────────────────
    let server_a = TlsMaterial::load(&CertSource::self_signed(params())).unwrap();
    let fp_a = server_a.fingerprint_sha256();

    // ── Server B: a different server, i.e. "the MITM" ─────────────────────
    let server_b = TlsMaterial::load(&CertSource::self_signed(params())).unwrap();
    let fp_b = server_b.fingerprint_sha256();
    assert_ne!(fp_a, fp_b);

    // 1) Pinned on A, connecting to A → must get through.
    let port_a = start_server(server_a.server_config().unwrap()).await;
    let reply = connect_to(port_a, &fp_a)
        .await
        .expect("pinning on the right fingerprint must get through");
    assert_eq!(reply, GREETING, "got wrong data over the pinned connection");

    // 2) Pinned on A, but the server is B → must be rejected.
    let port_b = start_server(server_b.server_config().unwrap()).await;
    let err = connect_to(port_b, &fp_a).await.expect_err(
        "pinning on the WRONG fingerprint must be rejected — otherwise pinning is worthless",
    );
    assert!(
        err.to_lowercase().contains("certificate")
            || err.to_lowercase().contains("cert")
            || err.contains("invalid"),
        "expected a certificate error, got: {err}"
    );
    eprintln!("pin rejection gave (as expected): {err}");

    // 3) And to rule out that B was simply broken: B gets through when we pin
    //    B. (A new server, since the previous one accepted one connection.)
    let port_b2 = start_server(server_b.server_config().unwrap()).await;
    let reply = connect_to(port_b2, &fp_b)
        .await
        .expect("B must work when B is pinned");
    assert_eq!(reply, GREETING);
}

#[tokio::test]
async fn handshake_uses_tls13_and_alpn_negotiates() {
    install_crypto_provider();

    let material = TlsMaterial::load(&CertSource::self_signed(params())).unwrap();
    let fp = material.fingerprint_sha256();
    let server_cfg = material.server_config().unwrap(); // ALPN: h2, http/1.1

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let acceptor = TlsAcceptor::from(server_cfg);
    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let mut tls = acceptor.accept(tcp).await.unwrap();
        let (_, conn) = tls.get_ref();
        let versjon = conn.protocol_version();
        let suite = conn.negotiated_cipher_suite().map(|s| s.suite());
        let alpn = conn.alpn_protocol().map(|p| p.to_vec());
        let _ = tls.write_all(GREETING).await;
        let _ = tls.shutdown().await;
        (versjon, suite, alpn)
    });

    let config =
        nettls::pinned_client_config_with_alpn(&fp, &[b"h2".to_vec(), b"http/1.1".to_vec()])
            .unwrap();
    let connector = TlsConnector::from(config);
    let tcp = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let name = nettls::rustls::pki_types::ServerName::try_from("localhost").unwrap();
    let mut tls = connector.connect(name, tcp).await.unwrap();
    let mut buf = Vec::new();
    tls.read_to_end(&mut buf).await.unwrap();
    assert_eq!(buf, GREETING);

    let (versjon, suite, alpn) = server.await.unwrap();
    eprintln!("forhandlet: {versjon:?} / {suite:?} / ALPN {alpn:?}");
    assert_eq!(
        versjon,
        Some(nettls::rustls::ProtocolVersion::TLSv1_3),
        "two modern parties must land on TLS 1.3"
    );
    assert_eq!(
        alpn.as_deref(),
        Some(&b"h2"[..]),
        "ALPN must negotiate to h2"
    );
}

#[tokio::test]
async fn cert_lastet_fra_disk_virker_i_et_ekte_handshake() {
    install_crypto_provider();

    // The whole round: generate → save → load back → server → pinned client.
    // This is exactly the `auto` flow a service gets at restart.
    let dir = std::env::temp_dir().join(format!(
        "nettls-smoke-disk-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));

    let first = TlsMaterial::load(&CertSource::auto(&dir, params())).unwrap();
    let etter_restart = TlsMaterial::load(&CertSource::auto(&dir, params())).unwrap();
    assert_eq!(
        first.fingerprint_sha256(),
        etter_restart.fingerprint_sha256(),
        "the fingerprint must survive a restart, otherwise pinning does not work in practice"
    );

    let port = start_server(etter_restart.server_config().unwrap()).await;
    let reply = connect_to(port, &first.fingerprint_sha256()).await.unwrap();
    assert_eq!(reply, GREETING);

    let _ = std::fs::remove_dir_all(&dir);
}
