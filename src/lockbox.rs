// SPDX-License-Identifier: MIT OR Apache-2.0
//! Lock and unlock local state at rest (SPEC-nettls §6.11).
//!
//! A module comes up **locked**. It cannot read its own peer registry, its
//! generation pairs or its TLS keys until it has been given the password —
//! and the password arrives only once a human has logged in (§8.1).
//!
//! The property this buys, stated precisely:
//!
//! > **A copy of the disk is worthless without at least one user's password**
//! > — because the key has never been on the machine.
//!
//! ## No verification hash
//!
//! We store **no** argon2 hash next to the ciphertext. If the password is
//! wrong, the AEAD authentication fails on its own. A stored hash would also
//! have given an attacker with the disk a **separate oracle** to test
//! candidates against, alongside the ciphertext he had to attack anyway
//! (§8.4).
//!
//! ## Not a new blob format
//!
//! The crypto is `krypto`'s: argon2id as the KDF, and the FAFN blob with the
//! AEAD. Inventing a second format would mean two things to
//! keep correct — and one of them is always the one that never gets reviewed.
//!
//! The salt sits in cleartext in front of the blob. It is no secret: its job
//! is to make precomputed tables useless, and it does that just as well in
//! plain sight.

use krypto::{Alg, SecretBuf, SecretString};

use crate::error::TlsError;

/// Magic + version in front of the salt, so a file we do not understand is
/// rejected as **wrong format** instead of as a wrong password.
///
/// The difference is not cosmetic: "wrong password" sends the operator off to
/// hunt for a password, while "wrong format" sends her to the right place.
const MAGIC: &[u8; 8] = b"NETTLS\x01\x00";
/// The salt length. 16 is the minimum in `krypto`; we use 32.
const SALT_LEN: usize = 32;
/// The `key_id` in the FAFN header. Fixed — we have one key per file, derived
/// from the password, and no key rotation at this layer.
const KEY_ID: [u8; 16] = *b"nettls-local-st1";

/// Locks content with a password — with the default AEAD,
/// **AEGIS-256** (SPEC-nettls §6.0b: at rest there is no cross-reading —
/// whoever writes, reads — so a Rust-owned store uses the best we have).
///
/// The salt is drawn fresh every time, so two lockings of the same content
/// with the same password yield different ciphertext.
pub fn lock(password: &SecretString, plaintext: &[u8]) -> Result<Vec<u8>, TlsError> {
    lock_with(password, plaintext, Alg::Aegis256)
}

/// Like [`lock`], but with an explicit AEAD choice (SPEC-nettls §6.0b: the
/// algorithm menu is krypto's; the choice is the consumer's).
///
/// `Alg::Aes256Gcm` is the documented interop bridge — the one AEAD the
/// Python side also has. Unlocking reads the algorithm from the FAFN header,
/// so [`unlock`] opens either; a reader without the algorithm fails hard,
/// never silently (the A1 rule: no fallback below the floor, never to
/// nothing).
pub fn lock_with(password: &SecretString, plaintext: &[u8], alg: Alg) -> Result<Vec<u8>, TlsError> {
    // `random_bytes` and not `SecretBuf::random`: the salt is stored in
    // cleartext right in front of the blob — it is public by design.
    let salt = krypto::random_bytes(SALT_LEN)
        .map_err(|_| TlsError::Generate("CSPRNG unavailable".into()))?;

    let blob = seal(password, &salt, plaintext, alg)?;

    let mut out = Vec::with_capacity(MAGIC.len() + SALT_LEN + blob.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&salt);
    out.extend_from_slice(&blob);
    Ok(out)
}

/// Unlocks. **A wrong password gives an authentication failure**, not an empty result.
pub fn unlock(password: &SecretString, file: &[u8]) -> Result<SecretBuf, TlsError> {
    if file.len() < MAGIC.len() + SALT_LEN {
        return Err(TlsError::Pem(
            "the locked file is too short to contain header and salt".into(),
        ));
    }
    if &file[..MAGIC.len()] != MAGIC {
        return Err(TlsError::Pem(
            "unknown file format — this is not a locked nettls state file. \
             (A wrong FORMAT, not a wrong password: look for the right file, not the right password.)"
                .into(),
        ));
    }
    let salt = &file[MAGIC.len()..MAGIC.len() + SALT_LEN];
    let blob = &file[MAGIC.len() + SALT_LEN..];

    let key = derive(password, salt)?;
    let dk = krypto::MasterKey::from_bytes(key)
        .and_then(|mk| mk.derive(b"nettls/local-state/v1", salt))
        .map_err(|e| TlsError::Generate(format!("key derivation failed: {e}")))?;

    krypto::open(&dk, blob).map_err(|_| {
        TlsError::ProofInvalid(
            "could not unlock the local state — wrong password, or the file was altered. \
             (We store no verification hash, so this is the AEAD speaking up.)"
                .into(),
        )
    })
}

fn seal(
    password: &SecretString,
    salt: &[u8],
    plaintext: &[u8],
    alg: Alg,
) -> Result<Vec<u8>, TlsError> {
    let key = derive(password, salt)?;
    let dk = krypto::MasterKey::from_bytes(key)
        .and_then(|mk| mk.derive(b"nettls/local-state/v1", salt))
        .map_err(|e| TlsError::Generate(format!("key derivation failed: {e}")))?;
    let pt = SecretBuf::from_vec(plaintext.to_vec())
        .map_err(|e| TlsError::Generate(format!("could not hold the plaintext: {e}")))?;
    krypto::seal(&dk, &KEY_ID, &pt, alg)
        .map_err(|e| TlsError::Generate(format!("sealing failed: {e}")))
}

fn derive(password: &SecretString, salt: &[u8]) -> Result<SecretBuf, TlsError> {
    krypto::password::derive_key(password, salt, krypto::password::Preset::Interactive)
        .map_err(|e| TlsError::Generate(format!("argon2 derivation failed: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pw(s: &str) -> SecretString {
        SecretString::from_string(s.to_string()).expect("valid")
    }

    #[test]
    fn roundtrip() {
        let file = lock(&pw("secret"), b"peer registry + keys").unwrap();
        let out = unlock(&pw("secret"), &file).unwrap();
        out.expose(|b| assert_eq!(b, b"peer registry + keys"));
    }

    #[test]
    fn wrong_password_gives_authentication_failure() {
        // O-7: no stored verification hash — the AEAD speaks up.
        let file = lock(&pw("secret"), b"x").unwrap();
        let err = unlock(&pw("secreT"), &file).unwrap_err();
        assert!(format!("{err}").contains("no verification hash"), "{err}");
    }

    #[test]
    fn no_verification_hash_in_the_file() {
        // The requirement itself: the file must contain magic + salt + FAFN
        // blob, and nothing usable as an oracle.
        let file = lock(&pw("secret"), b"x").unwrap();
        assert_eq!(&file[..MAGIC.len()], MAGIC);
        // The FAFN blob starts right after the salt.
        assert_eq!(&file[MAGIC.len() + SALT_LEN..][..4], b"FAFN");
        // No PHC string anywhere.
        assert!(
            !String::from_utf8_lossy(&file).contains("$argon2"),
            "a PHC hash has sneaked into the file"
        );
    }

    #[test]
    fn altered_ciphertext_is_rejected() {
        let mut file = lock(&pw("secret"), b"noe viktig").unwrap();
        let last = file.len() - 1;
        file[last] ^= 0x01;
        assert!(unlock(&pw("secret"), &file).is_err());
    }

    #[test]
    fn altered_salt_is_rejected() {
        let mut file = lock(&pw("secret"), b"noe viktig").unwrap();
        file[MAGIC.len()] ^= 0x01;
        assert!(unlock(&pw("secret"), &file).is_err());
    }

    #[test]
    fn wrong_format_says_it_is_the_format() {
        // "Wrong password" would have sent the operator hunting for a password.
        let err = unlock(
            &pw("x"),
            b"this is quite definitely not a locked state file",
        )
        .unwrap_err();
        assert!(format!("{err}").contains("unknown file format"), "{err}");
    }

    #[test]
    fn too_short_file_is_rejected() {
        assert!(unlock(&pw("x"), b"kort").is_err());
    }

    #[test]
    fn same_content_gives_different_ciphertext() {
        // Fresh salt every time.
        let a = lock(&pw("secret"), b"x").unwrap();
        let b = lock(&pw("secret"), b"x").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn empty_content_is_allowed() {
        let file = lock(&pw("secret"), b"").unwrap();
        let out = unlock(&pw("secret"), &file).unwrap();
        out.expose(|b| assert!(b.is_empty()));
    }
}
