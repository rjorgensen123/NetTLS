// SPDX-License-Identifier: MIT OR Apache-2.0
//! PKCS#8-building for P-256 keys — internal helpers behind
//! [`TlsMaterial::anchor_pkcs8`](crate::material::TlsMaterial::anchor_pkcs8):
//! the documented crossing TLS domain → §6 anchor. Lived in the retired §5
//! module (`rotation.rs`, removed 0.8.2); the helpers are §6's too, so they
//! moved here rather than dying with it.

use krypto::SecretBuf;
use rustls::pki_types::PrivateKeyDer;
use zeroize::{Zeroize, Zeroizing};

use crate::error::TlsError;
use crate::secret;
use crate::signature::p256_public_key as ec_p256_public_key;

/// Produces the key as PKCS#8, the form `krypto::sign::ecdsa_p256_sign` wants
/// it in — in locked memory (0.8.3, see `secret.rs`).
///
/// - `Pkcs8` (what `nettls` itself generates, and what `save_pem`/`load`
///   preserves) is passed straight through.
/// - `Sec1` (`-----BEGIN EC PRIVATE KEY-----`, i.e. what `openssl ecparam`
///   emits) gets wrapped: we extract the 32-byte private scalar and combine it
///   with the public point from the certificate. Without this, a perfectly
///   ordinary operator-supplied EC key could not rotate, and the failure would
///   have been incomprehensible.
/// - Everything else (RSA) → an explanatory error.
pub(crate) fn pkcs8_p256(
    key: &PrivateKeyDer<'static>,
    cert_der: &[u8],
) -> Result<SecretBuf, TlsError> {
    match key {
        PrivateKeyDer::Pkcs8(k) => secret::hold(k.secret_pkcs8_der().to_vec()),
        PrivateKeyDer::Sec1(k) => {
            let mut scalar = sec1_private_scalar(k.secret_sec1_der())?;
            let point = ec_p256_public_key(cert_der)?;
            let out = pkcs8_from_parts(&scalar, &point);
            scalar.zeroize();
            secret::hold(out)
        }
        _ => Err(TlsError::Sign(
            "the private key is not an EC key (probably RSA) — signing requires ECDSA \
             P-256, which is what `nettls` generates itself. An RSA certificate can still be \
             served and pinned statically, it just cannot rotate."
                .to_string(),
        )),
    }
}

/// Extracts the private scalar from a SEC1 `ECPrivateKey`.
///
/// ```text
/// ECPrivateKey ::= SEQUENCE {
///     version        INTEGER { ecPrivkeyVer1(1) },
///     privateKey     OCTET STRING,          ← 32 byte for P-256
///     parameters [0] ECParameters OPTIONAL,
///     publicKey  [1] BIT STRING OPTIONAL }
/// ```
///
/// We read only the first two fields, and we read them **strictly**: anything
/// that deviates from the form above is an error, not something to guess past.
fn sec1_private_scalar(der: &[u8]) -> Result<[u8; 32], TlsError> {
    let err = || {
        TlsError::Sign(
            "the EC private key (SEC1) does not have the expected form SEQUENCE { INTEGER 1, \
             OCTET STRING (32 bytes), … } for P-256"
                .to_string(),
        )
    };
    // SEQUENCE header: tag 0x30, then short or long length form.
    let mut i = 0usize;
    if der.first() != Some(&0x30) {
        return Err(err());
    }
    i += 1;
    let len_byte = *der.get(i).ok_or_else(err)?;
    i += 1;
    if len_byte & 0x80 != 0 {
        let n = (len_byte & 0x7f) as usize;
        if n == 0 || n > 4 {
            return Err(err());
        }
        i += n;
    }
    // version INTEGER 1
    if der.get(i..i + 3) != Some(&[0x02, 0x01, 0x01][..]) {
        return Err(err());
    }
    i += 3;
    // privateKey OCTET STRING (32)
    if der.get(i..i + 2) != Some(&[0x04, 0x20][..]) {
        return Err(err());
    }
    i += 2;
    let raw = der.get(i..i + 32).ok_or_else(err)?;
    let mut out = [0u8; 32];
    out.copy_from_slice(raw);
    Ok(out)
}

/// Builds a PKCS#8 v2 (`id-ecPublicKey` / `prime256v1`) around scalar + point.
///
/// Every intermediate that carries the scalar is `Zeroizing`: wiped when it
/// goes out of scope, whichever path returns.
fn pkcs8_from_parts(scalar: &[u8; 32], point: &[u8]) -> Vec<u8> {
    // ECPrivateKey with publicKey [1]:
    //   SEQUENCE { INTEGER 1, OCTET STRING (32), [1] { BIT STRING (0x04||X||Y) } }
    let mut ec = Zeroizing::new(Vec::new());
    ec.extend_from_slice(&[0x02, 0x01, 0x01]); // version 1
    ec.push(0x04);
    ec.push(0x20);
    ec.extend_from_slice(scalar);
    // [1] EXPLICIT BIT STRING
    let mut bit = vec![0x03, (point.len() + 1) as u8, 0x00];
    bit.extend_from_slice(point);
    ec.push(0xa1);
    ec.push(bit.len() as u8);
    ec.extend_from_slice(&bit);
    let mut ec_seq = Zeroizing::new(vec![0x30, ec.len() as u8]);
    ec_seq.extend_from_slice(&ec);

    // AlgorithmIdentifier { id-ecPublicKey, prime256v1 }
    const ALG: [u8; 21] = [
        0x30, 0x13, // SEQUENCE
        0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, // 1.2.840.10045.2.1
        0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, // 1.2.840.10045.3.1.7
    ];

    let mut inner = Zeroizing::new(Vec::new());
    inner.extend_from_slice(&[0x02, 0x01, 0x00]); // version 0
    inner.extend_from_slice(&ALG);
    inner.push(0x04); // privateKey OCTET STRING
    inner.push(ec_seq.len() as u8);
    inner.extend_from_slice(&ec_seq);

    let mut out = vec![0x30];
    if inner.len() < 128 {
        out.push(inner.len() as u8);
    } else {
        out.push(0x81);
        out.push(inner.len() as u8);
    }
    out.extend_from_slice(&inner);
    out
}
