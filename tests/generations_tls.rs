// SPDX-License-Identifier: MIT OR Apache-2.0
//! **M-6** — the §6 model against a live server that swaps certificates while
//! running.
//!
//! This is the test that was missing when phase 3.1 was wrongly ticked off as
//! done. The unit tests showed the state machine was correct; they could not
//! show it was *connected to anything*. Here the traffic runs over a real TCP
//! socket, with a real rustls handshake, and the server swaps certificates
//! between two connections.
//!
//! What the test actually has to prove:
//!
//! 1. An announced successor is accepted **without** the client being told
//!    when the swap happens (§6.7 — asynchronous rotation).
//! 2. `previous` is **not** accepted in a handshake after promotion, even
//!    though it is still used to verify announcements (§6.3, the two roles).
//! 3. A certificate that is neither `current` nor `next` is rejected
//!    (§6.8b).

use std::sync::Arc;

use nettls::announcement::Announcement;
use nettls::generations::{Generation, Trust};
use nettls::{CertSource, SelfSignedParams, TlsMaterial};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// One generation: material, PEM, fingerprint and signing key.
struct Gen {
    material: TlsMaterial,
    pem: String,
    fp: String,
    pkcs8: krypto::SecretBuf,
}

impl Gen {
    /// A second locked copy of the key — `SecretBuf` is not `Clone` by design.
    fn key(&self) -> krypto::SecretBuf {
        self.pkcs8
            .expose(|b| krypto::SecretBuf::from_vec(b.to_vec()))
            .expect("mlock")
    }
}

fn generation() -> Gen {
    let material = TlsMaterial::load(&CertSource::self_signed(SelfSignedParams::new(
        "localhost",
        ["localhost"],
    )))
    .expect("self-signed");
    let der = material.cert_chain()[0].as_ref().to_vec();
    let pem = pem_of(&der);
    let fp = material.fingerprint_sha256();
    let pkcs8 = pkcs8_of(&material, &der);
    Gen {
        material,
        pem,
        fp,
        pkcs8,
    }
}

fn pem_of(der: &[u8]) -> String {
    use std::fmt::Write;
    let b64 = base64_std(der);
    let mut s = String::from("-----BEGIN CERTIFICATE-----\n");
    for line in b64.as_bytes().chunks(64) {
        let _ = writeln!(s, "{}", std::str::from_utf8(line).unwrap());
    }
    s.push_str("-----END CERTIFICATE-----\n");
    s
}

fn base64_std(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for b in data.chunks(3) {
        let n = ((b[0] as u32) << 16)
            | ((*b.get(1).unwrap_or(&0) as u32) << 8)
            | (*b.get(2).unwrap_or(&0) as u32);
        out.push(T[(n >> 18) as usize & 63] as char);
        out.push(T[(n >> 12) as usize & 63] as char);
        out.push(if b.len() > 1 {
            T[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if b.len() > 2 {
            T[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

/// Extracts PKCS#8 from the material via `save_pem` + `load`, since the
/// internal conversion is not public.
fn pkcs8_of(m: &TlsMaterial, _der: &[u8]) -> krypto::SecretBuf {
    let dir = std::env::temp_dir().join(format!(
        "nettls-m6-{}-{}",
        std::process::id(),
        m.fingerprint_sha256()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    m.save_pem(&dir).unwrap();
    let key_pem = std::fs::read_to_string(dir.join(nettls::KEY_FILE)).unwrap();
    let _ = std::fs::remove_dir_all(&dir);

    use rustls_pki_types::pem::PemObject;
    let n = rustls_pki_types::PrivatePkcs8KeyDer::from_pem_slice(key_pem.as_bytes())
        .expect("pkcs8 key");
    krypto::SecretBuf::from_vec(n.secret_pkcs8_der().to_vec()).expect("mlock")
}

/// A server that presents exactly one certificate, and can be restarted with
/// a different one on the same port.
async fn server(port: u16, cfg: Arc<rustls::ServerConfig>) -> tokio::task::JoinHandle<()> {
    let lytter = TcpListener::bind(("127.0.0.1", port)).await.expect("bind");
    tokio::spawn(async move {
        let akseptor = tokio_rustls::TlsAcceptor::from(cfg);
        while let Ok((tcp, _)) = lytter.accept().await {
            let akseptor = akseptor.clone();
            tokio::spawn(async move {
                if let Ok(mut s) = akseptor.accept(tcp).await {
                    let _ = s.write_all(b"hei").await;
                    let _ = s.shutdown().await;
                }
            });
        }
    })
}

/// Ett handshake. `Ok(())` betyr at klienten godtok serverens sertifikat.
async fn connect_to(trust: &Trust, port: u16) -> Result<(), String> {
    let cfg = trust.client_config().map_err(|e| e.to_string())?;
    let kobler = tokio_rustls::TlsConnector::from(cfg);
    let tcp = TcpStream::connect(("127.0.0.1", port))
        .await
        .map_err(|e| e.to_string())?;
    let name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
    let mut s = kobler.connect(name, tcp).await.map_err(|e| e.to_string())?;
    let mut buf = [0u8; 3];
    s.read_exact(&mut buf).await.map_err(|e| e.to_string())?;
    assert_eq!(&buf, b"hei");
    Ok(())
}

fn ledig_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

#[tokio::test(flavor = "multi_thread")]
async fn announced_successor_accepted_without_client_knowing_when() {
    nettls::install_crypto_provider();

    let c0 = generation();
    let c1 = generation();
    let port = ledig_port();

    // The operator has approved c0.
    let trust = Trust::from_approval(Generation::from_der(
        c0.material.cert_chain()[0].as_ref().to_vec(),
    ));

    // Server on c0. Sanity: the pin works NOW — without this the rest could
    // have "passed" against a dead server.
    let s0 = server(port, c0.cfg()).await;
    connect_to(&trust, port)
        .await
        .expect("cannot be assessed: c0 does not get through to begin with");

    // The announcement: c0 appoints c1. First rotation → single-signed (§6.3).
    let k = Announcement::new("gateway", None, (&c0.fp_bar(), &c0.pkcs8), &c1.pem, 1).unwrap();
    trust
        .receive(&k)
        .expect("the announcement must be accepted");

    // The server swaps. The client has NOT been told when.
    s0.abort();
    tokio::time::sleep(std::time::Duration::from_millis(80)).await;
    let s1 = server(port, c1.cfg()).await;

    connect_to(&trust, port)
        .await
        .expect("M-6 BROKEN: the announced successor was not accepted");

    // And the observation must have promoted the state (§6.7).
    let g = trust.state().unwrap();
    assert_eq!(
        g.current().fingerprint(),
        c1.fp_bar(),
        "promotion did not happen on observation"
    );
    assert_eq!(g.previous().unwrap().fingerprint(), c0.fp_bar());
    assert!(g.next().is_none());

    s1.abort();
}

#[tokio::test(flavor = "multi_thread")]
async fn previous_generation_does_not_get_in_after_promotion() {
    // The two roles (§6.3): `previous` verifies announcements, but must not
    // be usable for connecting. Mix them, and the window would become wider
    // than necessary — and the window's width is the whole reason a leaked
    // old key stops having value.
    nettls::install_crypto_provider();

    let c0 = generation();
    let c1 = generation();
    let port = ledig_port();

    let trust = Trust::from_approval(Generation::from_der(
        c0.material.cert_chain()[0].as_ref().to_vec(),
    ));
    let k = Announcement::new("gateway", None, (&c0.fp_bar(), &c0.pkcs8), &c1.pem, 1).unwrap();
    trust.receive(&k).unwrap();

    // Promote by actually seeing c1.
    let s1 = server(port, c1.cfg()).await;
    connect_to(&trust, port).await.expect("c1 must pass");
    s1.abort();
    tokio::time::sleep(std::time::Duration::from_millis(80)).await;

    // We now stand at (previous=c0, current=c1). c0 must NO LONGER get in.
    let s0 = server(port, c0.cfg()).await;
    let r = connect_to(&trust, port).await;
    assert!(
        r.is_err(),
        "the previous generation got into a handshake — the two roles are mixed"
    );
    s0.abort();
}

#[tokio::test(flavor = "multi_thread")]
async fn unknown_certificate_is_rejected() {
    nettls::install_crypto_provider();

    let c0 = generation();
    let foreign = generation();
    let port = ledig_port();

    let trust = Trust::from_approval(Generation::from_der(
        c0.material.cert_chain()[0].as_ref().to_vec(),
    ));

    let s = server(port, foreign.cfg()).await;
    let r = connect_to(&trust, port).await;
    assert!(r.is_err(), "an unknown certificate was accepted (§6.8b)");
    s.abort();
}

impl Gen {
    /// Server configuration for this generation.
    fn cfg(&self) -> Arc<rustls::ServerConfig> {
        self.material.server_config().expect("server config")
    }

    /// The fingerprint without a `sha256:` prefix, as §6 uses it.
    fn fp_bar(&self) -> String {
        self.fp
            .strip_prefix("sha256:")
            .unwrap_or(&self.fp)
            .to_string()
    }
}

/// Keeps `Arc` in use (keeps the import honest if the tests change).
#[allow(dead_code)]
fn _bruk_arc(_: Arc<()>) {}

// --------------------------------------------------------------------------- //
// 3.6 — the announcer actually drives a rotation, end to end
// --------------------------------------------------------------------------- //

/// The whole cycle over real TCP: announce → the client stores → receipt →
/// swap → the client connects to the new one **without having been told
/// when**.
///
/// And the actual gate: **the server does not swap before the receipt is in.**
/// Roll before the peer has stored the new one, and the peer's handshake
/// fails that very moment — exactly the break §6 exists to avoid.
#[tokio::test(flavor = "multi_thread")]
async fn announcer_rolls_only_when_receipt_is_in() {
    use nettls::announcer::{Announcer, OwnMaterial, Schedule};
    use nettls::RotatingResolver;

    nettls::install_crypto_provider();

    let c0 = generation();
    let port = ledig_port();
    let dir = std::env::temp_dir().join(format!("nettls-36-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    c0.material.save_pem(&dir).unwrap();

    let resolver = Arc::new(RotatingResolver::new(&c0.material).unwrap());
    let announcer = Announcer::new(
        "gateway",
        &dir,
        SelfSignedParams::new("localhost", ["localhost"]),
        resolver.clone(),
        OwnMaterial {
            previous: None,
            current: (c0.fp_bar(), c0.key()),
        },
        Schedule::new(vec!["service".to_string()], 0),
        None,
    )
    .unwrap();

    // A server that reads the resolver live — it swaps when the resolver does.
    let lytter = TcpListener::bind(("127.0.0.1", port)).await.unwrap();
    let r = resolver.clone();
    let srv = tokio::spawn(async move {
        while let Ok((tcp, _)) = lytter.accept().await {
            let cfg = r.server_config().unwrap();
            tokio::spawn(async move {
                let akseptor = tokio_rustls::TlsAcceptor::from(cfg);
                if let Ok(mut s) = akseptor.accept(tcp).await {
                    let _ = s.write_all(b"hei").await;
                    let _ = s.shutdown().await;
                }
            });
        }
    });

    let trust = Trust::from_approval(Generation::from_der(
        c0.material.cert_chain()[0].as_ref().to_vec(),
    ));
    connect_to(&trust, port).await.expect("c0 must pass");

    // Announce.
    assert!(announcer.should_announce(100));
    let k = announcer.prepare(100).expect("announcement");
    let nytt_fp = k.new_fingerprint().to_string();

    // Without a receipt NOTHING may happen — the gate in §6.8a.
    assert!(
        announcer.roll_if_ready(200).unwrap().is_none(),
        "rolled without a receipt — the gate in §6.8a does not hold"
    );
    connect_to(&trust, port).await.expect("must still be c0");

    // The client stores and acknowledges.
    trust.receive(&k).expect("the client stores the new one");
    announcer.acked("service").unwrap();

    // Now we roll.
    let old = announcer
        .roll_if_ready(200)
        .unwrap()
        .expect("should have rolled now");
    assert!(old.contains(&c0.fp_bar()), "old fp: {old}");

    // The client connects to the new one without being told when the swap happened.
    connect_to(&trust, port)
        .await
        .expect("the announced successor was not accepted after the swap");
    assert_eq!(trust.state().unwrap().current().fingerprint(), nytt_fp);

    // And the rate limit blocks an immediate new round (M-22).
    assert!(!announcer.should_announce(201));

    srv.abort();
    let _ = std::fs::remove_dir_all(&dir);
}

/// **M-26** — an announced-and-acked promise survives a restart.
///
/// Not "the fields are preserved", but what actually matters: a **new**
/// `Announcer` built from disk keeps the promise the previous one gave. The
/// peer has acked and awaits the new certificate; forget it, and the peer is
/// left holding a promise
/// ingen holder.
#[tokio::test(flavor = "multi_thread")]
async fn loftet_overlever_en_restart() {
    use nettls::announcer::{Announcer, OwnMaterial, Schedule};
    use nettls::RotatingResolver;

    nettls::install_crypto_provider();

    let c0 = generation();
    let port = ledig_port();
    let dir = std::env::temp_dir().join(format!("nettls-m26-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    c0.material.save_pem(&dir).unwrap();

    let resolver = Arc::new(RotatingResolver::new(&c0.material).unwrap());
    let params = SelfSignedParams::new("localhost", ["localhost"]);

    // --- "before restart" ------------------------------------------------- //
    let k = {
        let kg = Announcer::new(
            "gateway",
            &dir,
            params.clone(),
            resolver.clone(),
            OwnMaterial {
                previous: None,
                current: (c0.fp_bar(), c0.key()),
            },
            Schedule::new(vec!["service".to_string()], 0),
            None,
        )
        .unwrap();
        let k = kg.prepare(100).unwrap();
        kg.acked("service").unwrap();
        kg.save_pending().unwrap();
        k
    }; // kg is dropped — the process "dies"

    // --- "after restart": everything is rebuilt from disk ------------------ //
    let kg2 = Announcer::new(
        "gateway",
        &dir,
        params,
        resolver.clone(),
        OwnMaterial {
            previous: None,
            current: (c0.fp_bar(), c0.key()),
        },
        Schedule::new(vec!["service".to_string()], 0),
        None,
    )
    .unwrap();
    // `new` restores the promise itself (§6.17.3): the pending next must be
    // visible in the trio without any extra call.
    assert!(
        kg2.own_trio().unwrap().next_fingerprint.is_some(),
        "M-26 BROKEN: the promise was not read back"
    );
    assert_eq!(
        kg2.pending().unwrap().new_fingerprint(),
        k.new_fingerprint(),
        "the restored promise covers a different certificate"
    );

    // The receipt from before the restart must still count — the peer must
    // not have to ack again for no reason.
    let lytter = TcpListener::bind(("127.0.0.1", port)).await.unwrap();
    let r = resolver.clone();
    let srv = tokio::spawn(async move {
        while let Ok((tcp, _)) = lytter.accept().await {
            let cfg = r.server_config().unwrap();
            tokio::spawn(async move {
                let a = tokio_rustls::TlsAcceptor::from(cfg);
                if let Ok(mut s) = a.accept(tcp).await {
                    let _ = s.write_all(b"hei").await;
                    let _ = s.shutdown().await;
                }
            });
        }
    });

    let old = kg2
        .roll_if_ready(200)
        .unwrap()
        .expect("M-26 BROKEN: the receipt from before the restart did not count");
    assert!(old.contains(&c0.fp_bar()));

    // And the client that stored the announcement before the restart gets through afterwards.
    let trust = Trust::from_approval(Generation::from_der(
        c0.material.cert_chain()[0].as_ref().to_vec(),
    ));
    trust.receive(&k).unwrap();
    connect_to(&trust, port)
        .await
        .expect("the client does not reach the certificate promised before the restart");

    srv.abort();
    let _ = std::fs::remove_dir_all(&dir);
}

/// **M-28/M-29** — the keys are locked at rest when a password is set.
///
/// This was the cross-check finding: `lockbox` existed as a primitive, the
/// requirement was noted as covered, and the `Announcer` still wrote `key.pem`
/// in cleartext. A primitive without a coupling is not a requirement
/// fulfilled.
#[tokio::test(flavor = "multi_thread")]
async fn keys_are_locked_when_password_is_set() {
    use nettls::announcer::{Announcer, OwnMaterial, Schedule};
    use nettls::RotatingResolver;

    nettls::install_crypto_provider();

    let c0 = generation();
    let dir = std::env::temp_dir().join(format!("nettls-m28-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    let pw = krypto::SecretString::from_string("secret".into()).unwrap();
    let kg = Announcer::new(
        "gateway",
        &dir,
        SelfSignedParams::new("localhost", ["localhost"]),
        Arc::new(RotatingResolver::new(&c0.material).unwrap()),
        OwnMaterial {
            previous: None,
            current: (c0.fp_bar(), c0.key()),
        },
        Schedule::new(vec!["service".to_string()], 0),
        Some(pw),
    )
    .unwrap();

    kg.prepare(100).unwrap();

    // No cleartext key anywhere under the directory.
    let mut found_locked = false;
    for e in walk(&dir) {
        let name = e.file_name().unwrap().to_string_lossy().to_string();
        assert_ne!(
            name,
            nettls::KEY_FILE,
            "M-28 BROKEN: cleartext key on disk: {}",
            e.display()
        );
        if name == "material.locked" {
            found_locked = true;
            let b = std::fs::read(&e).unwrap();
            assert_eq!(&b[..8], b"NETTLS\x01\x00", "err filformat");
            assert!(
                !String::from_utf8_lossy(&b).contains("PRIVATE KEY"),
                "M-28 BROKEN: the key is readable in the «locked» file"
            );
            // Written through the crate's atomic writer, which sets the mode.
            // `fs::write` would have taken whatever the umask says — typically
            // 0644, so world-readable key material at rest.
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mode = std::fs::metadata(&e).unwrap().permissions().mode() & 0o777;
                assert_eq!(
                    mode, 0o600,
                    "the locked material must not be readable by others"
                );
            }
        }
    }
    assert!(found_locked, "found no locked material file");

    // And the material can be read back — locking that cannot be unlocked is
    // not locking, it is loss.
    kg.acked("service").unwrap();
    assert!(kg.roll_if_ready(200).unwrap().is_some(), "could not roll");

    let _ = std::fs::remove_dir_all(&dir);
}

fn walk(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    let Ok(rd) = std::fs::read_dir(dir) else {
        return out;
    };
    for e in rd.flatten() {
        let p = e.path();
        if p.is_dir() {
            out.extend(walk(&p));
        } else {
            out.push(p);
        }
    }
    out
}

/// **§6.17.1** — the `previous` key survives a restart after **two** rotations.
///
/// Reported by the reference implementation: a node that had rotated more than
/// once could, after a restart, neither sign nor verify the next announcement.
/// It was left with `current` but `previous = None`, because the previous key
/// bare levde i minnet.
///
/// The test does not check that a field is preserved, but what actually
/// matters: that a **new** `Announcer` built from disk can still produce a
/// **double-signed** announcement. If `previous` is gone, it becomes
/// single-signed — and then we are back to one key, which is the whole reason
/// §6 exists.
#[tokio::test(flavor = "multi_thread")]
async fn previous_key_survives_restart_after_two_rotations() {
    use nettls::announcer::{Announcer, OwnMaterial, Schedule, DAY_S};
    use nettls::RotatingResolver;

    nettls::install_crypto_provider();

    let c0 = generation();
    let dir = std::env::temp_dir().join(format!("nettls-617-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    c0.material.save_pem(&dir).unwrap();

    let resolver = Arc::new(RotatingResolver::new(&c0.material).unwrap());
    let params = SelfSignedParams::new("localhost", ["localhost"]);
    let t1 = 100;
    let t2 = t1 + DAY_S + 1;
    let t3 = t2 + DAY_S + 1;

    let bygg = |material| {
        Announcer::new(
            "gateway",
            &dir,
            params.clone(),
            resolver.clone(),
            material,
            Schedule::new(vec!["service".to_string()], 0),
            None,
        )
    };
    let gen0 = || OwnMaterial {
        previous: None,
        current: (c0.fp_bar(), c0.key()),
    };

    // --- "before restart": rotate twice ------------------------------------ //
    {
        let kg = bygg(gen0()).unwrap();
        for t in [t1, t2] {
            kg.prepare(t).unwrap();
            kg.acked("service").unwrap();
            kg.roll_if_ready(t)
                .unwrap()
                .unwrap_or_else(|| panic!("the rotation at {t} did not happen"));
        }
    } // kg is dropped — the process "dies"

    // --- «etter restart» --------------------------------------------------- //
    // The consumer can only supply generation 0: the keys from gen 1 onwards
    // are made and owned by the crate, and never leave it. `new` restores the
    // chain itself (§6.17.3) — the trio must show a previous straight away.
    let kg2 = bygg(gen0()).unwrap();
    assert!(
        kg2.own_trio().unwrap().previous_fingerprint.is_some(),
        "§6.17.1 BROKEN: the chain was not read back from disk"
    );

    let k = kg2.prepare(t3).unwrap();
    assert!(
        !k.is_bootstrap(),
        "§6.17.1 BROKEN: the announcement is single-signed — the previous key \
         did not survive the restart, and we are back to one key"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// The A4/A5 switch point (SPEC-nettls §6.7e): the consumer's gate has the last
/// word, and a `false` postpones with **no side effects**.
#[tokio::test(flavor = "multi_thread")]
async fn the_gate_postpones_the_switch_without_side_effects() {
    use nettls::announcer::{Announcer, OwnMaterial, Schedule};
    use nettls::RotatingResolver;

    nettls::install_crypto_provider();
    let c0 = generation();
    let dir = std::env::temp_dir().join(format!("nettls-gate-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    c0.material.save_pem(&dir).unwrap();

    let resolver = std::sync::Arc::new(RotatingResolver::new(&c0.material).unwrap());
    let kg = Announcer::new(
        "gateway",
        &dir,
        SelfSignedParams::new("localhost", ["localhost"]),
        resolver.clone(),
        OwnMaterial {
            previous: None,
            current: (c0.fp_bar(), c0.key()),
        },
        Schedule::new(vec!["service".to_string()], 0),
        None,
    )
    .unwrap();

    kg.prepare(100).unwrap();
    kg.acked("service").unwrap();

    // Everything is ready — but the consumer says "not now".
    let before = resolver.fingerprint_sha256();
    assert!(
        kg.roll_if_ready_gated(100, || false).unwrap().is_none(),
        "a false gate must postpone the switch"
    );
    assert_eq!(
        resolver.fingerprint_sha256(),
        before,
        "the resolver must be untouched after a postponed switch"
    );
    assert!(
        kg.own_trio().unwrap().next_fingerprint.is_some(),
        "the pending promise must survive a postponed switch"
    );

    // Same call, gate open: the chain and the serving switch together.
    let old = kg
        .roll_if_ready_gated(100, || true)
        .unwrap()
        .expect("with an open gate the switch must happen");
    assert_eq!(old, before, "swap must return the fingerprint we served");
    assert_ne!(resolver.fingerprint_sha256(), before);
    assert!(kg.own_trio().unwrap().previous_fingerprint.is_some());

    let _ = std::fs::remove_dir_all(&dir);
}
