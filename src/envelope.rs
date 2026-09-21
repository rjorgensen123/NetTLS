// SPDX-License-Identifier: MIT OR Apache-2.0
//! Sealed envelopes — the carrier as a **blind courier**.
//!
//! The pair secret that unlocks a connection does not sit in cleartext at the
//! party that carries it. It sits as an envelope encrypted to the recipient's
//! public key. The carrier stores and delivers opaque blobs, and can **never**
//! read them — not in memory either.
//!
//! That gives a split which is the whole point:
//!
//! | Party | Has | Can |
//! |---|---|---|
//! | The recipient | `sk` (private key, outside the locked file) | open an envelope — but has none |
//! | portal | the envelopes, in the safe | deliver them — but never read them |
//! | The operator | the password that opens the safe | trigger the delivery |
//!
//! **The recipient has a key that opens nothing. portal has an envelope it
//! cannot read.** Neither is anything alone, and it takes a human to bring
//! them together.
//!
//! ## The transport does not need to be encrypted
//!
//! The payload is already encrypted to the recipient. An eavesdropper gets a
//! blob he cannot open, and a MITM cannot swap it without the seal breaking.
//! That is **better** than sending it over TLS, not merely as good: the
//! security does not depend on the channel. And that is what removes the
//! chicken-and-egg at startup — delivery can happen to a module that cannot
//! yet terminate TLS.
//!
//! ## The construction
//!
//! Ephemeral X25519 + HKDF + AEAD, i.e. the classic sealed-box form. No crypto
//! of our own: since krypto 0.5 every primitive is `krypto`'s — the key
//! exchange is `krypto::exchange` (which also **rejects a non-contributory
//! result**: a low-order peer point that would force an all-zero shared secret
//! is an error, not an envelope), the derivation is krypto's HKDF, and the
//! AEAD is the same FAFN blob used everywhere else. The `NETENV` container
//! format — magic, layout, and the binding of both public keys into the
//! derivation — is this crate's, by the boundary agreed with `krypto`: krypto
//! owns primitives, the consumer owns its formats.
//!
//! The sender's ephemeral public key sits in front of the blob and is
//! **part of the key derivation**. Without that binding an attacker could
//! swap the sender key and make the recipient derive a different key than the
//! one that was used — a classic mistake in home-grown sealed-box variants.

use krypto::{exchange, Alg, SecretBuf};

use crate::error::TlsError;

/// Magic + version, so a blob we do not understand is rejected as **wrong
/// format** and not as a wrong key.
const MAGIC: &[u8; 8] = b"NETENV\x01\x00";
/// The length of an X25519 key, public and private alike.
pub const X25519_LEN: usize = 32;
/// The `key_id` in the FAFN header.
const KEY_ID: [u8; 16] = *b"nettls-envelope1";
/// HKDF info. Purpose separation: the key from here must never be able to
/// collide with a key derived for anything else.
const INFO: &[u8] = b"nettls/envelope/v1";

/// An X25519 key pair for a recipient.
///
/// The private part sits **outside** the locked file (§8.7) — it must be
/// readable while the module is still locked. Alone it opens nothing: without
/// the envelope from portal the module gets no further.
pub struct RecipientKey {
    privat: SecretBuf,
}

impl std::fmt::Debug for RecipientKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RecipientKey([REDACTED])")
    }
}

impl RecipientKey {
    /// From the 32 raw key bytes. **Consumes** the buffer — the key lives on
    /// only inside the fence (the secret-types rule (secrets cross APIs only as krypto types): a private key never crosses an API
    /// boundary as `&[u8]`).
    pub fn from_bytes(b: SecretBuf) -> Result<Self, TlsError> {
        if b.len() != X25519_LEN {
            return Err(TlsError::Params(format!(
                "an X25519 private key must be {X25519_LEN} bytes, got {}",
                b.len()
            )));
        }
        Ok(Self { privat: b })
    }

    /// Draws a new pair. Returns `(key, public part)`.
    pub fn generate() -> Result<(Self, Vec<u8>), TlsError> {
        let (privat, public) = exchange::x25519_keypair()
            .map_err(|e| TlsError::Generate(format!("key generation failed: {e}")))?;
        Ok((Self { privat }, public.to_vec()))
    }

    /// The public part — distributed as a file, same pattern as the Ed25519
    /// keys.
    pub fn public(&self) -> Result<Vec<u8>, TlsError> {
        exchange::x25519_public(&self.privat)
            .map(|p| p.to_vec())
            .map_err(|e| TlsError::Generate(format!("invalid X25519 private key: {e}")))
    }
}

/// Seals `plaintext` to the recipient's public key — with the
/// default AEAD, **AEGIS-256** (SPEC-nettls §6.0b).
///
/// The choice is **per recipient, static** (the layer table in §6.0b): a Rust
/// recipient gets the default; a recipient without AEGIS (Python) gets the
/// interop bridge via [`seal_with`] and `Alg::Aes256Gcm`. Opening reads the
/// algorithm from the FAFN header; a recipient without the algorithm fails
/// hard, never silently.
///
/// The sender needs **no** key of its own: the ephemeral one is drawn here and
/// discarded afterwards. That is why portal can make an envelope it cannot
/// open.
pub fn seal(recipient_public: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, TlsError> {
    seal_with(recipient_public, plaintext, Alg::Aegis256)
}

/// Like [`seal`], but with an explicit AEAD choice for the recipient.
pub fn seal_with(recipient_public: &[u8], plaintext: &[u8], alg: Alg) -> Result<Vec<u8>, TlsError> {
    if recipient_public.len() != X25519_LEN {
        return Err(TlsError::Params(format!(
            "an X25519 public key must be {X25519_LEN} bytes, got {}",
            recipient_public.len()
        )));
    }
    // "Ephemeral" is a LIFETIME property here — the secret half is dropped at
    // the end of this function, having existed only inside a SecretBuf.
    let (ephemeral, ephemeral_pub) = exchange::x25519_keypair()
        .map_err(|e| TlsError::Generate(format!("key generation failed: {e}")))?;

    // Rejects a non-contributory result (low-order recipient point) with an
    // error — an envelope whose key an attacker could predict is never made.
    let shared = exchange::x25519_shared(&ephemeral, recipient_public).map_err(|_| {
        TlsError::Params(
            "the recipient's X25519 public key is invalid (it would force a predictable \
             shared secret) — no envelope is made for it"
                .into(),
        )
    })?;

    let blob = seal_inner(&shared, &ephemeral_pub, recipient_public, plaintext, alg)?;

    let mut out = Vec::with_capacity(MAGIC.len() + X25519_LEN + blob.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&ephemeral_pub);
    out.extend_from_slice(&blob);
    Ok(out)
}

/// Opens an envelope. **Only** the recipient can.
pub fn open(key: &RecipientKey, envelope: &[u8]) -> Result<SecretBuf, TlsError> {
    if envelope.len() < MAGIC.len() + X25519_LEN {
        return Err(TlsError::Pem("the envelope is too short".into()));
    }
    if &envelope[..MAGIC.len()] != MAGIC {
        return Err(TlsError::Pem(
            "unknown format — this is not a nettls envelope. (Wrong FORMAT, not a wrong key.)"
                .into(),
        ));
    }
    let ephemeral_pub = &envelope[MAGIC.len()..MAGIC.len() + X25519_LEN];
    let blob = &envelope[MAGIC.len() + X25519_LEN..];

    let my_pub = key.public()?;
    let shared = exchange::x25519_shared(&key.privat, ephemeral_pub).map_err(|_| {
        TlsError::ProofInvalid(
            "the ephemeral key in the envelope is invalid — the envelope is malformed or \
             manipulated"
                .into(),
        )
    })?;

    let dk = derive(&shared, ephemeral_pub, &my_pub)?;
    krypto::open(&dk, blob).map_err(|_| {
        TlsError::ProofInvalid(
            "could not open the envelope — it is not sealed to this key, \
             or it was altered"
                .into(),
        )
    })
}

fn seal_inner(
    shared: &SecretBuf,
    ephemeral_pub: &[u8],
    recipient_pub: &[u8],
    plaintext: &[u8],
    alg: Alg,
) -> Result<Vec<u8>, TlsError> {
    let dk = derive(shared, ephemeral_pub, recipient_pub)?;
    let pt = SecretBuf::from_vec(plaintext.to_vec())
        .map_err(|e| TlsError::Generate(format!("could not hold the plaintext: {e}")))?;
    krypto::seal(&dk, &KEY_ID, &pt, alg)
        .map_err(|e| TlsError::Generate(format!("sealing failed: {e}")))
}

/// Derives the AEAD key from the shared secret, **bound to both public
/// keys**.
///
/// The binding is not decoration. Without it an attacker could swap the
/// ephemeral sender key in the envelope and make the recipient derive a
/// different key than the one actually used — the classic mistake in
/// home-grown sealed-box variants.
///
/// The shared secret is key *material*, not a key — krypto's HKDF
/// (`MasterKey::derive`) stands between it and the AEAD, exactly as
/// `krypto::exchange` requires.
fn derive(
    shared: &SecretBuf,
    ephemeral_pub: &[u8],
    recipient_pub: &[u8],
) -> Result<krypto::DerivedKey, TlsError> {
    let ikm = shared.expose(|s| {
        let mut v = Vec::with_capacity(s.len() + 2 * X25519_LEN);
        v.extend_from_slice(s);
        v.extend_from_slice(ephemeral_pub);
        v.extend_from_slice(recipient_pub);
        v
    });

    let mk = krypto::MasterKey::from_bytes(
        SecretBuf::from_vec(ikm).map_err(|e| TlsError::Generate(e.to_string()))?,
    )
    .map_err(|e| TlsError::Generate(format!("could not build the key root: {e}")))?;
    mk.derive(INFO, ephemeral_pub)
        .map_err(|e| TlsError::Generate(format!("key derivation failed: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret(bytes: [u8; 32]) -> SecretBuf {
        SecretBuf::from_vec(bytes.to_vec()).unwrap()
    }

    #[test]
    fn roundtrip() {
        let (n, off) = RecipientKey::generate().unwrap();
        let k = seal(&off, b"par-hemmeligheten").unwrap();
        let out = open(&n, &k).unwrap();
        out.expose(|b| assert_eq!(b, b"par-hemmeligheten"));
    }

    #[test]
    fn the_courier_cannot_read_what_he_carries() {
        // The whole point: whoever SEALS has no key and cannot open.
        let (recipient, off) = RecipientKey::generate().unwrap();
        let (kurer, _) = RecipientKey::generate().unwrap();
        let k = seal(&off, b"secret").unwrap();
        assert!(
            open(&kurer, &k).is_err(),
            "the courier could open the envelope he carries"
        );
        open(&recipient, &k).expect("the recipient must be able to");
    }

    #[test]
    fn wrong_recipient_cannot_open() {
        let (_a, off_a) = RecipientKey::generate().unwrap();
        let (b, _off_b) = RecipientKey::generate().unwrap();
        let k = seal(&off_a, b"secret").unwrap();
        assert!(open(&b, &k).is_err());
    }

    #[test]
    fn swapped_sender_key_is_rejected() {
        // The binding in `derive`: swap the ephemeral key and it breaks.
        let (n, off) = RecipientKey::generate().unwrap();
        let (_annen, annen_off) = RecipientKey::generate().unwrap();
        let mut k = seal(&off, b"secret").unwrap();
        k[MAGIC.len()..MAGIC.len() + X25519_LEN].copy_from_slice(&annen_off);
        assert!(open(&n, &k).is_err());
    }

    #[test]
    fn altered_ciphertext_is_rejected() {
        let (n, off) = RecipientKey::generate().unwrap();
        let mut k = seal(&off, b"secret").unwrap();
        let last = k.len() - 1;
        k[last] ^= 0x01;
        assert!(open(&n, &k).is_err());
    }

    #[test]
    fn same_plaintext_gives_different_envelopes() {
        // An ephemeral key per sealing.
        let (_n, off) = RecipientKey::generate().unwrap();
        assert_ne!(seal(&off, b"x").unwrap(), seal(&off, b"x").unwrap());
    }

    #[test]
    fn low_order_recipient_key_is_rejected_at_sealing() {
        // New with krypto 0.5: `x25519_shared` rejects a non-contributory
        // result. The all-zero point is the canonical low-order case — an
        // envelope "sealed" to it would have a predictable key, so it must
        // never be made.
        assert!(seal(&[0u8; 32], b"x").is_err());
    }

    #[test]
    fn wrong_format_says_it_is_the_format() {
        let (n, _) = RecipientKey::generate().unwrap();
        let err = open(&n, b"this is quite definitely not an envelope at all").unwrap_err();
        assert!(format!("{err}").contains("unknown format"), "{err}");
    }

    #[test]
    fn wrong_key_lengths_are_rejected() {
        assert!(seal(&[0u8; 31], b"x").is_err());
        assert!(RecipientKey::from_bytes(SecretBuf::from_vec(vec![0u8; 16]).unwrap()).is_err());
    }

    #[test]
    fn the_key_is_redacted_in_debug() {
        // What matters is that no key bytes come out — not what the redaction
        // looks like. (The first draft checked that the string contained no
        // «[», which `[REDACTED]` obviously does.)
        let n = RecipientKey::from_bytes(secret([0xABu8; 32])).unwrap();
        let d = format!("{n:?}");
        assert!(d.contains("REDACTED"), "{d}");
        assert!(!d.contains("171"), "key bytes in Debug: {d}");
        assert!(!d.to_lowercase().contains("ab"), "key bytes in Debug: {d}");
    }

    #[test]
    fn public_key_is_stable_for_same_private() {
        let n = RecipientKey::from_bytes(secret([7u8; 32])).unwrap();
        assert_eq!(n.public().unwrap(), n.public().unwrap());
    }
}
