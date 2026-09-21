// SPDX-License-Identifier: MIT OR Apache-2.0
//! PEM to and from disk, and the `CertSource::auto` behaviour.

use std::fs;
use std::path::PathBuf;

use nettls::{CertOrigin, CertSource, SelfSignedParams, TlsMaterial, CERT_FILE, KEY_FILE};

/// Enkel temp-katalog uten dependency. Ryddes i `Drop`.
struct TempDir(PathBuf);

impl TempDir {
    fn new(name: &str) -> Self {
        let mut p = std::env::temp_dir();
        let unik = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        p.push(format!("nettls-test-{name}-{unik}"));
        fs::create_dir_all(&p).unwrap();
        TempDir(p)
    }
    fn path(&self) -> &std::path::Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn params() -> SelfSignedParams {
    SelfSignedParams::new("nettls test", ["localhost", "127.0.0.1"])
}

#[test]
fn save_pem_and_load_back_from_file_gives_same_fingerprint() {
    let dir = TempDir::new("save");
    let generert = TlsMaterial::load(&CertSource::self_signed(params())).unwrap();
    generert.save_pem(dir.path()).unwrap();

    let cert_path = dir.path().join(CERT_FILE);
    let key_path = dir.path().join(KEY_FILE);
    assert!(cert_path.is_file() && key_path.is_file());

    let lastet = TlsMaterial::load(&CertSource::files(&cert_path, &key_path)).unwrap();
    assert_eq!(generert.fingerprint_sha256(), lastet.fingerprint_sha256());
    assert_eq!(lastet.origin(), CertOrigin::Files);
    assert_eq!(lastet.sans(), generert.sans());
    // The material must still be usable for an actual ServerConfig.
    lastet.server_config().unwrap();
}

#[cfg(unix)]
#[test]
fn key_file_is_0600_and_cert_file_0644() {
    use std::os::unix::fs::PermissionsExt;
    let dir = TempDir::new("perm");
    TlsMaterial::load(&CertSource::self_signed(params()))
        .unwrap()
        .save_pem(dir.path())
        .unwrap();

    let key_mode = fs::metadata(dir.path().join(KEY_FILE))
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    let cert_mode = fs::metadata(dir.path().join(CERT_FILE))
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(key_mode, 0o600, "key.pem must not be readable by others");
    assert_eq!(cert_mode, 0o644);
}

#[test]
fn load_from_pem_in_memory() {
    let dir = TempDir::new("mem");
    let generert = TlsMaterial::load(&CertSource::self_signed(params())).unwrap();
    generert.save_pem(dir.path()).unwrap();

    let cert_pem = fs::read(dir.path().join(CERT_FILE)).unwrap();
    let key_pem = fs::read(dir.path().join(KEY_FILE)).unwrap();
    let lastet = TlsMaterial::load(&CertSource::pem(cert_pem, key_pem)).unwrap();

    assert_eq!(lastet.fingerprint_sha256(), generert.fingerprint_sha256());
    assert_eq!(lastet.origin(), CertOrigin::Pem);
}

#[test]
fn auto_generates_first_time_and_reuses_thereafter() {
    let dir = TempDir::new("auto");

    let first = TlsMaterial::load(&CertSource::auto(dir.path(), params())).unwrap();
    assert_eq!(first.origin(), CertOrigin::Generated);
    assert!(dir.path().join(CERT_FILE).is_file());

    let second = TlsMaterial::load(&CertSource::auto(dir.path(), params())).unwrap();
    assert_eq!(second.origin(), CertOrigin::Reused);
    assert_eq!(
        first.fingerprint_sha256(),
        second.fingerprint_sha256(),
        "auto must reuse the cert — otherwise the operator gets a new browser warning at every restart"
    );
}

#[test]
fn auto_regenerates_when_stored_cert_is_corrupt() {
    let dir = TempDir::new("korrupt");
    let first = TlsMaterial::load(&CertSource::auto(dir.path(), params())).unwrap();

    fs::write(dir.path().join(CERT_FILE), b"this is not PEM\n").unwrap();

    let second = TlsMaterial::load(&CertSource::auto(dir.path(), params())).unwrap();
    assert_eq!(second.origin(), CertOrigin::Generated);
    assert_ne!(first.fingerprint_sha256(), second.fingerprint_sha256());
    // And the new material is actually written back.
    let tredje = TlsMaterial::load(&CertSource::auto(dir.path(), params())).unwrap();
    assert_eq!(tredje.origin(), CertOrigin::Reused);
    assert_eq!(tredje.fingerprint_sha256(), second.fingerprint_sha256());
}

#[test]
fn auto_regenerates_when_key_does_not_belong_to_cert() {
    let dir = TempDir::new("mismatch");
    let first = TlsMaterial::load(&CertSource::auto(dir.path(), params())).unwrap();

    // Swap in the key from a COMPLETELY different certificate.
    let annen = TempDir::new("mismatch-kilde");
    TlsMaterial::load(&CertSource::self_signed(params()))
        .unwrap()
        .save_pem(annen.path())
        .unwrap();
    fs::copy(annen.path().join(KEY_FILE), dir.path().join(KEY_FILE)).unwrap();

    let second = TlsMaterial::load(&CertSource::auto(dir.path(), params())).unwrap();
    assert_eq!(second.origin(), CertOrigin::Generated);
    assert_ne!(first.fingerprint_sha256(), second.fingerprint_sha256());
}

#[test]
fn files_gives_understandable_error_on_mismatched_key() {
    let a = TempDir::new("par-a");
    let b = TempDir::new("par-b");
    TlsMaterial::load(&CertSource::self_signed(params()))
        .unwrap()
        .save_pem(a.path())
        .unwrap();
    TlsMaterial::load(&CertSource::self_signed(params()))
        .unwrap()
        .save_pem(b.path())
        .unwrap();

    let e = TlsMaterial::load(&CertSource::files(
        a.path().join(CERT_FILE),
        b.path().join(KEY_FILE),
    ))
    .unwrap_err();
    let s = e.to_string();
    assert!(
        s.contains("do not belong together"),
        "the error message must say WHAT is wrong: {s}"
    );
    assert!(!s.is_empty());
}

#[test]
fn files_gives_understandable_error_on_missing_file_and_empty_pem() {
    let dir = TempDir::new("mangler");
    let e = TlsMaterial::load(&CertSource::files(
        dir.path().join("does-not-exist.pem"),
        dir.path().join("nor-this-one.pem"),
    ))
    .unwrap_err();
    assert!(e.to_string().contains("does-not-exist.pem"), "{e}");

    let e = TlsMaterial::load(&CertSource::pem(b"".to_vec(), b"".to_vec())).unwrap_err();
    assert!(e.to_string().contains("CERTIFICATE"), "{e}");
}

#[test]
fn auto_without_writable_dir_gives_ephemeral_but_works() {
    // /proc is mounted such that create_dir_all fails; should a platform
    // allow it anyway, we skip instead of failing falsely.
    let umulig = std::path::Path::new("/proc/nettls-cannot-write-here");
    if fs::create_dir_all(umulig).is_ok() {
        let _ = fs::remove_dir_all(umulig);
        eprintln!("hopper over: katalogen lot seg actual opprette");
        return;
    }

    let m = TlsMaterial::load(&CertSource::auto(umulig, params())).unwrap();
    assert_eq!(
        m.origin(),
        CertOrigin::Ephemeral,
        "the service must come up with TLS, but the consumer must learn that the fingerprint \
         does not survive a restart"
    );
    m.server_config().unwrap();
}
