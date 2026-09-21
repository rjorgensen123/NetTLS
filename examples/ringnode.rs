// SPDX-License-Identifier: MIT OR Apache-2.0
//! A ring node in Rust (SPEC-nettls §6.15).
//!
//! The counterpart of `python/ringnode.py`, and it speaks **exactly the same
//! protocol**: one JSON line in, one out, over TLS. The node does not know
//! which language its neighbours are written in — and that is the whole point
//! of the ring.
//!
//! Blocking I/O on purpose: a thread per connection is more than enough for
//! three nodes, and it keeps the test free of async machinery that could hide
//! a bug in what is actually being tested.
//!
//! ```text
//! cargo run --example ringnode -- <name> <port> <neighbour-port> <ed25519-seed-hex>
//! ```

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};

use nettls::announcement::{Announcement, Receipt};
use nettls::announcer::{Mode, Schedule};
use nettls::generations::{Generation, Trust};
use nettls::{CertSource, SelfSignedParams, TlsMaterial};
use serde_json::{json, Value};

struct Node {
    name: String,
    port: u16,
    neighbour_port: u16,
    /// The successor's name. Without it the marker path cannot PIN — it
    /// would fall back to an unverified configuration.
    neighbour_name: Mutex<Option<String>>,
    seed: krypto::SecretBuf,
    /// Our own material: (fingerprint, cert_pem, pkcs8).
    current: Mutex<(String, String, Arc<krypto::SecretBuf>)>,
    previous: Mutex<Option<(String, String, Arc<krypto::SecretBuf>)>>,
    /// Announced, not yet taken into use.
    pending: Mutex<Option<(Announcement, String, Arc<krypto::SecretBuf>)>>,
    schedule: Mutex<Schedule>,
    peers: Mutex<HashMap<String, Trust>>,
    peer_keys: Mutex<HashMap<String, Vec<u8>>>,
    rotations: Mutex<u32>,
    /// Who must ack OUR rotations. `Schedule` has no getter for the set, and
    /// the consumer is the one who remembers anyway.
    ackers: Mutex<Vec<String>>,
}

fn make_material(name: &str) -> (String, String, Arc<krypto::SecretBuf>) {
    let m = TlsMaterial::load(&CertSource::self_signed(
        SelfSignedParams::new(name, ["localhost", "127.0.0.1"]).valid_days(30),
    ))
    .expect("selvsignert");
    let der = m.cert_chain()[0].as_ref().to_vec();
    let pem = String::from_utf8(nettls::pem::encode("CERTIFICATE", &der)).unwrap();
    let fp = m.fingerprint_sha256().replace("sha256:", "");
    let pkcs8 = Arc::new(m.anchor_pkcs8().expect("pkcs8"));
    (fp, pem, pkcs8)
}

impl Node {
    fn new(name: &str, port: u16, neighbour_port: u16, seed: Vec<u8>) -> Self {
        let m = make_material(name);
        Self {
            name: name.to_string(),
            port,
            neighbour_port,
            neighbour_name: Mutex::new(None),
            seed: krypto::SecretBuf::from_vec(seed).expect("seed"),
            current: Mutex::new(m),
            previous: Mutex::new(None),
            pending: Mutex::new(None),
            schedule: Mutex::new(Schedule::new(Vec::<String>::new(), 0)),
            peers: Mutex::new(HashMap::new()),
            peer_keys: Mutex::new(HashMap::new()),
            rotations: Mutex::new(0),
            ackers: Mutex::new(Vec::new()),
        }
    }

    /// Server configuration built **per connection**, from the live material.
    /// A cached config would have served the old certificate after a rotation
    /// — i.e. exactly the divergence between what we advertise and what we
    /// present.
    fn server_config(&self) -> Arc<rustls::ServerConfig> {
        let (_, cert, key) = self.current.lock().unwrap().clone();
        let key_pem =
            String::from_utf8(key.expose(|k| nettls::pem::encode("PRIVATE KEY", k))).unwrap();
        TlsMaterial::load(&CertSource::pem(cert.into_bytes(), key_pem.into_bytes()))
            .expect("material")
            .server_config()
            .expect("server config")
    }

    fn handter(&self, m: &Value) -> Value {
        match m["op"].as_str().unwrap_or("") {
            "identity" => {
                let (fp, cert, _) = self.current.lock().unwrap().clone();
                let mut out = json!({
                    "fingerprint": format!("sha256:{fp}"),
                    "cert_pem": cert,
                    "mode": Mode::Rolling,
                    "sent_at": now(),
                });
                if let Some((k, _, _)) = self.pending.lock().unwrap().as_ref() {
                    out["announcement"] = serde_json::to_value(k.to_json()).unwrap();
                }
                out
            }
            "ack" => {
                let kj: nettls::announcement::ReceiptJson =
                    serde_json::from_value(m["receipt"].clone()).unwrap();
                let kv = Receipt::from_json(&kj).unwrap();
                // `.get`, not indexing: a receipt from an unknown acker is a
                // NORMAL hostile/misrouted message and must be an error reply,
                // not a panic (mirrors the Python node).
                let Some(pk) = self.peer_keys.lock().unwrap().get(kv.acker()).cloned() else {
                    return json!({"error": format!(
                        "receipt from unknown acker {:?} — no pinned Ed25519 key", kv.acker()
                    )});
                };
                let expected = self
                    .pending
                    .lock()
                    .unwrap()
                    .as_ref()
                    .map(|(k, _, _)| k.new_fingerprint().to_string())
                    .unwrap_or_else(|| kv.new_fingerprint().to_string());
                match kv.verify(&pk, &expected) {
                    Ok(()) => {
                        self.schedule.lock().unwrap().acked(kv.acker());
                        json!({"ok": true})
                    }
                    Err(e) => json!({"error": e.to_string()}),
                }
            }
            "marker" => {
                let hopp = m["skip"].as_i64().unwrap_or(0);
                if hopp <= 0 {
                    return json!({"marker": m["marker"]});
                }
                // **Pinned, like all other traffic.** Without the neighbour's
                // name the marker fell back to an unverified configuration: it
                // proved connectivity, not pinning, and promotion never
                // happened on this path.
                let nb = self.neighbour_name.lock().unwrap().clone();
                match self.talk(
                    self.neighbour_port,
                    &json!({"op":"marker","marker":m["marker"],"skip":hopp-1}),
                    nb.as_deref(),
                ) {
                    Ok(reply) => json!({"marker": reply["marker"]}),
                    Err(e) => json!({"error": format!("the neighbour did not answer: {e}")}),
                }
            }
            annet => json!({"error": format!("unknown op: {annet}")}),
        }
    }

    /// One request to a neighbour. If the neighbour is known, `current` + `next` are pinned.
    fn talk(&self, port: u16, message: &Value, neighbour: Option<&str>) -> Result<Value, String> {
        nettls::install_crypto_provider();
        // `Trust` gives a config that accepts `current` + `next` and that
        // **promotes by itself** when it sees the swap in the handshake (§6.7).
        // That is why
        // trenger noden ingen manuell observasjons-logikk.
        let cfg = match neighbour.and_then(|nb| self.peers.lock().unwrap().get(nb).cloned()) {
            Some(t) => t.client_config().map_err(|e| e.to_string())?,
            None => unverified_config(),
        };

        let name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
        let mut konn = rustls::ClientConnection::new(cfg, name).map_err(|e| e.to_string())?;
        let mut tcp = TcpStream::connect(("127.0.0.1", port)).map_err(|e| e.to_string())?;
        // A timeout so a hang becomes a READABLE error instead of a test that
        // stands for ten minutes without saying why.
        let _ = tcp.set_read_timeout(Some(std::time::Duration::from_secs(20)));
        let _ = tcp.set_write_timeout(Some(std::time::Duration::from_secs(20)));
        let mut s = rustls::Stream::new(&mut konn, &mut tcp);

        s.write_all(format!("{message}\n").as_bytes())
            .map_err(|e| e.to_string())?;
        s.flush().map_err(|e| e.to_string())?;

        let mut line = String::new();
        BufReader::new(&mut s)
            .read_line(&mut line)
            .map_err(|e| e.to_string())?;
        serde_json::from_str(&line).map_err(|e| e.to_string())
    }
}

fn unverified_config() -> Arc<rustls::ClientConfig> {
    #[derive(Debug)]
    struct Alt(Arc<rustls::crypto::CryptoProvider>);
    impl rustls::client::danger::ServerCertVerifier for Alt {
        fn verify_server_cert(
            &self,
            _: &rustls::pki_types::CertificateDer<'_>,
            _: &[rustls::pki_types::CertificateDer<'_>],
            _: &rustls::pki_types::ServerName<'_>,
            _: &[u8],
            _: rustls::pki_types::UnixTime,
        ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        }
        fn verify_tls12_signature(
            &self,
            m: &[u8],
            c: &rustls::pki_types::CertificateDer<'_>,
            d: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls12_signature(
                m,
                c,
                d,
                &self.0.signature_verification_algorithms,
            )
        }
        fn verify_tls13_signature(
            &self,
            m: &[u8],
            c: &rustls::pki_types::CertificateDer<'_>,
            d: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls13_signature(
                m,
                c,
                d,
                &self.0.signature_verification_algorithms,
            )
        }
        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            self.0.signature_verification_algorithms.supported_schemes()
        }
    }
    let p = nettls::provider();
    Arc::new(
        rustls::ClientConfig::builder_with_provider(p.clone())
            .with_safe_default_protocol_versions()
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(Alt(p)))
            .with_no_client_auth(),
    )
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// A snapshot of the trust in one peer, as a comparable value.
///
/// Used to establish that a rejected message did not get to change anything.
/// Without it, "rejected" would only mean the call returned an error — not
/// that the state stood untouched.
fn state_of(node: &Arc<Node>, name: &str) -> Option<(String, Option<String>, Option<String>)> {
    let mp = node.peers.lock().unwrap();
    let g = mp.get(name)?.state().ok()?;
    Some((
        g.current().fingerprint().to_string(),
        g.previous().map(|x| x.fingerprint().to_string()),
        g.next().map(|x| x.fingerprint().to_string()),
    ))
}

fn control(node: &Arc<Node>, m: &Value) -> Value {
    match m["op"].as_str().unwrap_or("") {
        "approve" => {
            let port = m["port"].as_u64().unwrap() as u16;
            let reply = match node.talk(port, &json!({"op":"identity"}), None) {
                Ok(v) => v,
                Err(e) => return json!({"error": format!("the neighbour did not answer: {e}")}),
            };
            let g = Generation::from_pem(reply["cert_pem"].as_str().unwrap()).unwrap();
            let fp = g.fingerprint().to_string();
            let name = m["name"].as_str().unwrap().to_string();
            let _ = &name;
            node.peers
                .lock()
                .unwrap()
                .insert(name.clone(), Trust::from_approval(g));
            // If this is the successor in the ring, remember the name — the
            // marker path needs it to be able to pin.
            if port == node.neighbour_port {
                *node.neighbour_name.lock().unwrap() = Some(name.clone());
            }
            node.peer_keys.lock().unwrap().insert(
                name.clone(),
                nettls::signature::from_hex(m["ed25519_pub"].as_str().unwrap()).unwrap(),
            );
            json!({"ok": true, "fp": fp})
        }
        "require_ack_from" => {
            // Who must ack OUR rotation is whoever **pins us** — not whoever
            // we pin. The two edges differ, and mixing them makes you wait
            // forever for a receipt that was never meant to come.
            let name = m["name"].as_str().unwrap().to_string();
            node.schedule.lock().unwrap().add_peer(name.clone());
            node.ackers.lock().unwrap().push(name);
            json!({"ok": true})
        }
        "know_key" => {
            // Only the pinned Ed25519 key — no trust in a certificate.
            node.peer_keys.lock().unwrap().insert(
                m["name"].as_str().unwrap().to_string(),
                nettls::signature::from_hex(m["ed25519_pub"].as_str().unwrap()).unwrap(),
            );
            json!({"ok": true})
        }
        "prepare" => {
            let naa_ = m["now"].as_i64().unwrap();
            if let Some((k, _, _)) = node.pending.lock().unwrap().as_ref() {
                return json!({"ok": true, "new_fp": k.new_fingerprint()});
            }
            let (fp_ny, pem_ny, pk_ny) = make_material(&node.name);
            let (fp_k, _, pk_k) = node.current.lock().unwrap().clone();
            let previous = node.previous.lock().unwrap().clone();
            let k = Announcement::new(
                &node.name,
                previous.as_ref().map(|(f, _, p)| (f.as_str(), p.as_ref())),
                (fp_k.as_str(), pk_k.as_ref()),
                &pem_ny,
                naa_,
            )
            .unwrap();
            let _ = fp_ny;
            *node.pending.lock().unwrap() = Some((k.clone(), pem_ny, pk_ny));
            node.schedule.lock().unwrap().announced(naa_);
            json!({"ok": true, "new_fp": k.new_fingerprint()})
        }
        "fetch_and_ack" => {
            let name = m["name"].as_str().unwrap();
            let port = m["port"].as_u64().unwrap() as u16;
            let reply = match node.talk(port, &json!({"op":"identity"}), Some(name)) {
                Ok(v) => v,
                Err(e) => return json!({"error": format!("the neighbour did not answer: {e}")}),
            };
            if reply.get("announcement").is_none() {
                return json!({"ok": true, "no_announcement": true});
            }
            // NOT `.unwrap()`. An announcement that does not verify is a
            // NORMAL §6.8 state — it must be reported, not fell the thread.
            // With a panic here the control thread died, and the orchestrator
            // stood waiting until the deadline ran out: the symptom became a
            // timeout instead of the error message that actually explained
            // what was wrong.
            let kj: nettls::announcement::AnnouncementJson =
                match serde_json::from_value(reply["announcement"].clone()) {
                    Ok(v) => v,
                    Err(e) => return json!({"error": format!("invalid announcement: {e}")}),
                };
            let k = match Announcement::from_json(&kj) {
                Ok(v) => v,
                Err(e) => return json!({"error": e.to_string()}),
            };
            if let Some(t) = node.peers.lock().unwrap().get(name) {
                if let Err(e) = t.receive(&k) {
                    return json!({"error": e.to_string()});
                }
            }
            let kv = Receipt::new(
                &node.name,
                name,
                k.new_fingerprint(),
                m["now"].as_i64().unwrap(),
                &node.seed,
            )
            .unwrap();
            node.talk(
                port,
                &json!({"op":"ack","receipt": kv.to_json()}),
                Some(name),
            )
            .unwrap();
            json!({"ok": true, "acked_on": k.new_fingerprint()})
        }
        "roll" => {
            let naa_ = m["now"].as_i64().unwrap();
            if !node.schedule.lock().unwrap().can_roll(naa_) {
                return json!({"ok": true, "rolled": false});
            }
            let Some((k, pem, pk)) = node.pending.lock().unwrap().take() else {
                return json!({"ok": true, "rolled": false});
            };
            let old = {
                let mut kj = node.current.lock().unwrap();
                let old = kj.0.clone();
                // Exactly two are kept: generation N-2 is dropped here.
                *node.previous.lock().unwrap() = Some(kj.clone());
                *kj = (k.new_fingerprint().to_string(), pem, pk);
                old
            };
            *node.rotations.lock().unwrap() += 1;
            node.schedule.lock().unwrap().rolled(naa_).unwrap();
            json!({"ok": true, "rolled": true, "old": old})
        }
        // The consumer's MEMORY (§6.11b). `nettls` saves its own material
        // even in Rust, but the ring node mirrors a consuming service here:
        // EVERYTHING goes out, and everything can be put back. Then the test
        // probes the same property in both languages.
        "export" => {
            let hex = krypto::hex::encode;
            let mat = |m: &(String, String, Arc<krypto::SecretBuf>)| json!({"fp": m.0, "cert_pem": m.1, "pkcs8": m.2.expose(hex)});
            let kj = node.current.lock().unwrap().clone();
            let fo = node.previous.lock().unwrap().clone();
            let ve = node.pending.lock().unwrap().clone();
            let r = node.schedule.lock().unwrap();

            let mut peers = serde_json::Map::new();
            for (name, t) in node.peers.lock().unwrap().iter() {
                let g = t.state().unwrap();
                peers.insert(
                    name.clone(),
                    json!({
                        "previous": g.previous().map(|x| hex(x.der())),
                        "current": hex(g.current().der()),
                        "next": g.next().map(|x| hex(x.der())),
                    }),
                );
            }
            let keys: HashMap<String, String> = node
                .peer_keys
                .lock()
                .unwrap()
                .iter()
                .map(|(k, v)| (k.clone(), hex(v)))
                .collect();

            json!({"ok": true, "state": {
                "current": mat(&kj),
                "previous": fo.as_ref().map(mat),
                "pending": ve.as_ref().map(|(k, pem, pk)| json!({
                    "announcement": k.to_json(),
                    "cert_pem": pem,
                    "pkcs8": pk.expose(hex),
                })),
                "peers": peers,
                "keys": keys,
                "rotations": *node.rotations.lock().unwrap(),
                "ackers": node.ackers.lock().unwrap().clone(),
                "waiting_for": r.waiting_for(),
                "first_announced": r.first_announced(),
            }})
        }
        "import" => {
            let t = &m["state"];
            let ub = |v: &Value| nettls::signature::from_hex(v.as_str().unwrap()).unwrap();
            // Private keys go straight into locked memory (0.8.3).
            let ubk = |v: &Value| Arc::new(krypto::SecretBuf::from_vec(ub(v)).unwrap());
            let mat = |v: &Value| {
                (
                    v["fp"].as_str().unwrap().to_string(),
                    v["cert_pem"].as_str().unwrap().to_string(),
                    ubk(&v["pkcs8"]),
                )
            };

            *node.current.lock().unwrap() = mat(&t["current"]);
            *node.previous.lock().unwrap() = t["previous"].as_object().map(|_| mat(&t["previous"]));

            // The PENDING key pair must be included. Without it a restart
            // between announcement and swap would lose a key the peer has
            // already acked (M-26).
            *node.pending.lock().unwrap() = t["pending"].as_object().map(|v| {
                let kj: nettls::announcement::AnnouncementJson =
                    serde_json::from_value(v["announcement"].clone()).unwrap();
                (
                    Announcement::from_json(&kj).unwrap(),
                    v["cert_pem"].as_str().unwrap().to_string(),
                    ubk(&v["pkcs8"]),
                )
            });

            // The peers' generations — the link that keeps a restart from
            // looking like memory loss.
            let mut mp = HashMap::new();
            for (name, d) in t["peers"].as_object().unwrap() {
                let g = nettls::generations::Generations::restore(
                    d["previous"]
                        .as_str()
                        .map(|h| Generation::from_der(nettls::signature::from_hex(h).unwrap())),
                    Generation::from_der(ub(&d["current"])),
                    d["next"]
                        .as_str()
                        .map(|h| Generation::from_der(nettls::signature::from_hex(h).unwrap())),
                )
                .unwrap();
                mp.insert(name.clone(), Trust::from_state(g));
            }
            *node.peers.lock().unwrap() = mp;

            *node.peer_keys.lock().unwrap() = t["keys"]
                .as_object()
                .unwrap()
                .iter()
                .map(|(k, v)| (k.clone(), ub(v)))
                .collect();

            let ackers: Vec<String> = t["ackers"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_str().unwrap().to_string())
                .collect();
            let mut r = Schedule::new(ackers.clone(), 0);
            if node.pending.lock().unwrap().is_some() {
                // The promise is binding: the peer may already have acked.
                r.restore_announced(
                    t["waiting_for"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|v| v.as_str().unwrap().to_string())
                        .collect(),
                    t["first_announced"].as_i64().unwrap_or(0),
                );
            }
            *node.schedule.lock().unwrap() = r;
            *node.ackers.lock().unwrap() = ackers;
            *node.rotations.lock().unwrap() = t["rotations"].as_u64().unwrap() as u32;

            let fp = node.current.lock().unwrap().0.clone();
            json!({"ok": true, "fp": fp})
        }
        // A hostile announcement fed straight into the receive path (§6.15b).
        //
        // Two things must hold, and the second is the important one: the
        // message must be rejected, AND the state must be unchanged afterwards.
        // A receiver that rejects, but manages to write half the message into
        // `Generations` first, has not rejected it — it has merely refrained
        // from saying yes.
        "inject" => {
            let name = m["name"].as_str().unwrap();
            let before = state_of(node, name);
            let err = (|| -> Result<(), String> {
                let kj: nettls::announcement::AnnouncementJson =
                    serde_json::from_value(m["announcement"].clone())
                        .map_err(|e| format!("serde: {e}"))?;
                let k = Announcement::from_json(&kj).map_err(|e| e.to_string())?;
                let mp = node.peers.lock().unwrap();
                let t = mp.get(name).ok_or("ukjent peer")?;
                t.receive(&k).map(|_| ()).map_err(|e| e.to_string())
            })()
            .err();
            let after_state = state_of(node, name);
            json!({
                "ok": true,
                "rejected": err.is_some(),
                // NOT "error": the control channel reads that field as a
                // protocol failure. Here a rejection is exactly what should
                // happen.
                "rejected_reason": err,
                "unchanged": before == after_state,
            })
        }
        "marker" => {
            // NOT `.unwrap()`. A neighbour that does not answer — because it
            // was killed, is restarting, or pins us on a certificate we no
            // longer have — is a COMPLETELY NORMAL §6.8 state, and must be
            // reported as an
            // err.
            //
            // With `.unwrap()` the control thread panicked instead, and no
            // reply was ever written to stdout: the orchestrator stood waiting
            // forever. A hanging test does not say what is wrong; it only says
            // something is. The Python node returned an error in the same
            // situation — yet another asymmetry between the two.
            let nb = node.neighbour_name.lock().unwrap().clone();
            match node.talk(
                node.neighbour_port,
                &json!({"op":"marker","marker":m["marker"],"skip":m["skip"]}),
                nb.as_deref(),
            ) {
                Ok(reply) => json!({"ok": true, "marker": reply["marker"]}),
                Err(e) => json!({"error": format!("the neighbour did not answer: {e}")}),
            }
        }
        "status" => {
            let mp: HashMap<String, Value> = node
                .peers
                .lock()
                .unwrap()
                .iter()
                .map(|(k, v)| {
                    let g = v.state().unwrap();
                    (
                        k.clone(),
                        json!({
                            "current": g.current().fingerprint(),
                            "previous": g.previous().map(|x| x.fingerprint().to_string()),
                            "next": g.next().map(|x| x.fingerprint().to_string()),
                        }),
                    )
                })
                .collect();
            json!({
                "ok": true,
                "fp": node.current.lock().unwrap().0,
                "rotations": *node.rotations.lock().unwrap(),
                "peers": mp,
            })
        }
        "stop" => {
            println!("{}", json!({"ok": true}));
            std::process::exit(0);
        }
        annet => json!({"error": format!("ukjent control_op: {annet}")}),
    }
}

fn main() {
    nettls::install_crypto_provider();
    let a: Vec<String> = std::env::args().collect();
    let node = Arc::new(Node::new(
        &a[1],
        a[2].parse().unwrap(),
        a[3].parse().unwrap(),
        nettls::signature::from_hex(&a[4]).unwrap(),
    ));

    // Control on stdin.
    {
        let node = node.clone();
        std::thread::spawn(move || {
            let inn = std::io::stdin();
            for line in inn.lock().lines() {
                let Ok(line) = line else { break };
                if line.trim().is_empty() {
                    continue;
                }
                let m: Value = serde_json::from_str(&line).unwrap();
                println!("{}", control(&node, &m));
                let _ = std::io::stdout().flush();
            }
        });
    }

    let listener = TcpListener::bind(("127.0.0.1", node.port)).unwrap();
    println!(
        "{}",
        json!({"ready": node.name, "fp": node.current.lock().unwrap().0})
    );
    let _ = std::io::stdout().flush();

    for tcp in listener.incoming() {
        let Ok(mut tcp) = tcp else { continue };
        let node = node.clone();
        std::thread::spawn(move || {
            let cfg = node.server_config();
            let Ok(mut konn) = rustls::ServerConnection::new(cfg) else {
                return;
            };
            let mut s = rustls::Stream::new(&mut konn, &mut tcp);
            let mut line = String::new();
            if BufReader::new(&mut s).read_line(&mut line).is_err() || line.is_empty() {
                return;
            }
            let Ok(m) = serde_json::from_str::<Value>(&line) else {
                return;
            };
            let reply = node.handter(&m);
            let _ = s.write_all(format!("{reply}\n").as_bytes());
            let _ = s.flush();
        });
    }
}
