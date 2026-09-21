// SPDX-License-Identifier: MIT OR Apache-2.0
//! Minimal PEM encoding (DER → PEM) and safe writing to disk.
//!
//! We *read* PEM with `rustls-pki-types` (its `pem` feature — 0.8.1, wish #3);
//! writing lives here. The base64 body is `krypto::base64` (0.8.1, wish #1's
//! consequence: own variants go away once krypto has the building block).
//!
//! The module also owns the one rule that matters when private keys hit disk:
//! **write atomically, and set the permissions before the file becomes visible
//! under its final name.** Otherwise there is a window where `key.pem` is
//! readable by everyone.

use std::fs;
use std::io::Write;
use std::path::Path;

use zeroize::Zeroize;

use crate::error::TlsError;

/// Encodes DER as a PEM block with the given label, 64 chars per line (RFC 7468).
///
/// **Public since 0.8.1 (wish #2):** PEM is TLS domain, so building it lives
/// here — consumers that used to build PEM by hand use this instead. The
/// base64 body is the canonical `krypto::base64`. The intermediate is
/// zeroized: the DER may be a private key. (The returned buffer is the
/// caller's to protect — for a key, `save_pem` holds it in a `SecretBuf`.)
pub fn encode(label: &str, der: &[u8]) -> Vec<u8> {
    let mut b64 = krypto::base64::encode(der).into_bytes();

    let mut out = Vec::with_capacity(b64.len() + b64.len() / 64 + 2 * label.len() + 32);
    out.extend_from_slice(b"-----BEGIN ");
    out.extend_from_slice(label.as_bytes());
    out.extend_from_slice(b"-----\n");
    for line in b64.chunks(64) {
        out.extend_from_slice(line);
        out.push(b'\n');
    }
    out.extend_from_slice(b"-----END ");
    out.extend_from_slice(label.as_bytes());
    out.extend_from_slice(b"-----\n");

    b64.zeroize();
    out
}

/// Writes `bytes` to `path` atomically: `.tmp` → `fsync` → `rename`.
///
/// `mode` is set on the temp file **before** `rename`, so the file never exists
/// under its final name with permissions that are too open. On non-unix `mode`
/// is ignored (the crate is built for Linux containers; the parameter exists so
/// the code compiles everywhere).
pub(crate) fn write_atomic(path: &Path, bytes: &[u8], mode: u32) -> Result<(), TlsError> {
    let tmp = path.with_extension("tmp");
    // Clean up any leftover from an interrupted earlier write.
    let _ = fs::remove_file(&tmp);

    let mut f = fs::File::create(&tmp).map_err(|e| TlsError::io(&tmp, e))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        f.set_permissions(fs::Permissions::from_mode(mode))
            .map_err(|e| TlsError::io(&tmp, e))?;
    }
    #[cfg(not(unix))]
    let _ = mode;

    f.write_all(bytes).map_err(|e| TlsError::io(&tmp, e))?;
    f.sync_all().map_err(|e| TlsError::io(&tmp, e))?;
    drop(f);

    fs::rename(&tmp, path).map_err(|e| TlsError::io(path, e))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // (The base64 vectors live in krypto::base64 now — the body is its output;
    // the readback test below proves the whole PEM block end-to-end.)

    #[test]
    fn pem_can_be_read_back_by_pki_types() {
        use rustls_pki_types::pem::PemObject;
        // 200 bytes of "DER" → several lines → covers the line wrapping.
        let der: Vec<u8> = (0..200u32).map(|i| (i * 7 % 251) as u8).collect();
        let pem = encode("CERTIFICATE", &der);
        let certs: Vec<_> = rustls_pki_types::CertificateDer::pem_slice_iter(&pem)
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(certs.len(), 1);
        assert_eq!(certs[0].as_ref(), &der[..]);
    }
}
