// SPDX-License-Identifier: MIT OR Apache-2.0
//! AEGIS-256 in the TLS channel — our own suite, spoken by two nettls ends,
//! never forced on anyone: proven with real handshakes over loopback.
//!
//! The deviation itself (nonce padding, private code point, SHA-384 pairing)
//! and its exit condition are documented and unit-tested in `src/aegis.rs`.

use nettls::{
    install_crypto_provider, pinned_client_config_with, CertSource, SelfSignedParams, TlsMaterial,
    TransportCipher, TransportPolicy,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tokio_rustls::{TlsAcceptor, TlsConnector};

const HELLO: &[u8] = b"hello over aegis";
const REPLY: &[u8] = b"aegis says hi back";

fn material() -> TlsMaterial {
    TlsMaterial::load(&CertSource::self_signed(SelfSignedParams::new(
        "nettls aegis",
        ["localhost"],
    )))
    .unwrap()
}

fn aegis_only() -> TransportPolicy {
    TransportPolicy::only(TransportCipher::Aegis256)
}

fn aegis_then_aes() -> TransportPolicy {
    TransportPolicy::new(&[TransportCipher::Aegis256, TransportCipher::Aes256Gcm]).unwrap()
}

/// One-shot server: reads HELLO from the client, answers REPLY. Returns the
/// port and a handle yielding what the server read (so the client→server
/// direction is proven too, not only server→client).
async fn start_server(m: &TlsMaterial, policy: &TransportPolicy) -> (u16, JoinHandle<Vec<u8>>) {
    let config = m.server_config_with(&[], policy).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let acceptor = TlsAcceptor::from(config);
    let handle = tokio::spawn(async move {
        let mut got = Vec::new();
        if let Ok((tcp, _)) = listener.accept().await {
            if let Ok(mut tls) = acceptor.accept(tcp).await {
                let mut buf = vec![0u8; HELLO.len()];
                if tls.read_exact(&mut buf).await.is_ok() {
                    got = buf;
                }
                let _ = tls.write_all(REPLY).await;
                let _ = tls.shutdown().await;
            }
        }
        got
    });
    (port, handle)
}

/// Connects pinned, sends HELLO, reads the reply. Returns the negotiated suite.
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
    tls.write_all(HELLO).await.map_err(|e| e.to_string())?;
    let mut buf = Vec::new();
    tls.read_to_end(&mut buf).await.map_err(|e| e.to_string())?;
    assert_eq!(buf, REPLY, "server reply must survive the record layer");
    Ok(suite)
}

fn our_codepoint() -> String {
    format!(
        "{:?}",
        nettls::rustls::CipherSuite::Unknown(nettls::aegis::CODEPOINT)
    )
}

#[tokio::test]
async fn two_nettls_ends_speak_aegis_in_both_directions() {
    install_crypto_provider();
    let m = material();
    let fp = m.fingerprint_sha256();
    let (port, server) = start_server(&m, &aegis_only()).await;
    let suite = connect(port, &fp, &aegis_only())
        .await
        .expect("AEGIS against AEGIS must connect");
    assert_eq!(suite, our_codepoint(), "{suite}");
    assert_eq!(
        server.await.unwrap(),
        HELLO,
        "client→server data must arrive intact"
    );
}

#[tokio::test]
async fn aegis_is_never_forced_on_a_default_peer() {
    install_crypto_provider();
    let m = material();
    let fp = m.fingerprint_sha256();

    // A server that prefers AEGIS but keeps AES-256-GCM in its list meets a
    // default client on AES — the fallback rule, realised by TLS itself.
    let (port, server) = start_server(&m, &aegis_then_aes()).await;
    let suite = connect(port, &fp, &TransportPolicy::default())
        .await
        .unwrap();
    assert_eq!(suite, "TLS13_AES_256_GCM_SHA384", "{suite}");
    assert_eq!(server.await.unwrap(), HELLO);

    // And a Rust peer that also lists AEGIS gets AEGIS — the server's order.
    let (port, server) = start_server(&m, &aegis_then_aes()).await;
    let suite = connect(port, &fp, &aegis_then_aes()).await.unwrap();
    assert_eq!(suite, our_codepoint(), "{suite}");
    assert_eq!(server.await.unwrap(), HELLO);
}

#[tokio::test]
async fn an_aegis_only_client_against_a_default_server_fails_hard() {
    install_crypto_provider();
    let m = material();
    let fp = m.fingerprint_sha256();
    // The default server offers AES-256-GCM only; the client insists on AEGIS.
    // No common suite → hard failure, no silent downgrade (rule 1 and 5).
    let (port, _server) = start_server(&m, &TransportPolicy::default()).await;
    let err = connect(port, &fp, &aegis_only())
        .await
        .expect_err("no common suite must fail the handshake");
    assert!(
        err.to_lowercase().contains("handshake") || err.to_lowercase().contains("alert"),
        "expected a handshake failure, got: {err}"
    );
}

#[tokio::test]
async fn larger_than_one_record_survives() {
    install_crypto_provider();
    let m = material();
    let fp = m.fingerprint_sha256();
    // 64 KiB crosses the 16 KiB record boundary several times — every record
    // gets its own sequence number, and therefore its own padded nonce.
    let big = vec![0x5Au8; 64 * 1024];
    let config = m.server_config_with(&[], &aegis_only()).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let acceptor = TlsAcceptor::from(config);
    let payload = big.clone();
    tokio::spawn(async move {
        if let Ok((tcp, _)) = listener.accept().await {
            if let Ok(mut tls) = acceptor.accept(tcp).await {
                let _ = tls.write_all(&payload).await;
                let _ = tls.shutdown().await;
            }
        }
    });
    let config = pinned_client_config_with(&fp, &[], &aegis_only()).unwrap();
    let tcp = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let name = nettls::rustls::pki_types::ServerName::try_from("localhost").unwrap();
    let mut tls = TlsConnector::from(config).connect(name, tcp).await.unwrap();
    let mut got = Vec::new();
    tls.read_to_end(&mut got).await.unwrap();
    assert_eq!(got, big);
}
