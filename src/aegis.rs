// SPDX-License-Identifier: MIT OR Apache-2.0
//! AEGIS-256 in the TLS channel — **a deliberate deviation, built to be replaced.**
//!
//! # What this is
//!
//! A TLS 1.3 cipher suite with AEGIS-256 as the record AEAD, offered when a
//! consumer puts [`TransportCipher::Aegis256`] in its [`TransportPolicy`]. It is
//! **not** `TLS_AEGIS_256_SHA512` (IANA `0x13,0x06`, draft-irtf-cfrg-aegis-aead)
//! and must not claim to be. Only two nettls ends can speak it; every other
//! party (Python/OpenSSL, browsers) never sees it offered unless the consumer
//! asks, and skips it as an unknown suite if it does.
//!
//! # Why it deviates (decided 2026-09-04, Roger)
//!
//! rustls hands every TLS 1.3 AEAD a **12-byte** IV (`Iv`/`Nonce`, `NONCE_LEN`
//! = 12 in 0.23; `Iv::MAX_LEN` = 16 in 0.24.0-dev.1 *and* on git-main — checked
//! against the source, not the changelog). AEGIS-256 needs a **32-byte** nonce.
//! Nobody upstream is working on a wider IV, and we will not build against a
//! fork. So instead of waiting (the plan until 2026-09-04) we do three things
//! the standard suite would not, and write each one down:
//!
//! | Deviation | What we do | Why it is safe here |
//! |---|---|---|
//! | **Nonce** | the 12-byte TLS 1.3 nonce (`iv XOR seq`), left-aligned, zero-padded to 32 bytes | AEGIS-256 needs a nonce that is *unique per key*; the TLS nonce already is. Padding preserves uniqueness. |
//! | **Code point** | `0xFF06` — TLS private use (`0xFF,0x00`–`0xFF,0xFF`), echoing `0x1306` | a non-standard suite must not squat on the IANA code point; foreign peers skip unknown suites (standard TLS) |
//! | **Hash pairing** | SHA-384 HKDF, reusing ring's `TLS13_AES_256_GCM_SHA384` providers | the standard pairs SHA-512; ring's hash/HMAC types are private to rustls, and we add no primitive glue of our own. SHA-384 is what the transcript and key schedule of our other suites already use |
//!
//! The AEAD itself is untouched: the `aegis` crate (by a co-author of the
//! draft, verified against its vectors — the same primitive krypto uses at
//! rest), 256-bit key, 128-bit tag, TLS 1.3 record AAD exactly as rustls
//! computes it (`make_tls13_aad`). Nothing cryptographic is implemented here;
//! this file is the *seam* between rustls' record layer and the primitive.
//!
//! # The exit
//!
//! The day rustls ships AEGIS suites, or a release carries a 32-byte IV
//! (`Iv::MAX_LEN >= 32`), this file is **replaced**, not extended: drop the
//! nonce padding, drop the private code point, use `0x1306` with SHA-512, keep
//! [`TransportCipher::Aegis256`] as the consumer's name for it. The test
//! `the_deviation_still_has_its_reason` fails the moment rustls widens the
//! nonce, so the exit is not something to remember — it is something the build
//! tells you. The tracking case is **L2-076**.
//!
//! [`TransportCipher::Aegis256`]: crate::transport::TransportCipher::Aegis256
//! [`TransportPolicy`]: crate::transport::TransportPolicy

use std::sync::OnceLock;

use aegis::aegis256::Aegis256;
use rustls::crypto::cipher::{
    make_tls13_aad, AeadKey, InboundOpaqueMessage, InboundPlainMessage, Iv, MessageDecrypter,
    MessageEncrypter, Nonce, OutboundOpaqueMessage, OutboundPlainMessage, PrefixedPayload,
    Tls13AeadAlgorithm, UnsupportedOperationError, NONCE_LEN,
};
use rustls::crypto::ring::cipher_suite::TLS13_AES_256_GCM_SHA384;
use rustls::crypto::CipherSuiteCommon;
use rustls::{
    CipherSuite, ConnectionTrafficSecrets, ContentType, Error, ProtocolVersion,
    SupportedCipherSuite, Tls13CipherSuite,
};
use zeroize::Zeroizing;

/// The private-use code point this suite is offered under. **Not** the IANA
/// `TLS_AEGIS_256_SHA512` (`0x1306`) — see the module docs for why.
pub const CODEPOINT: u16 = 0xFF06;

/// AEGIS-256 tag length in the record: 128 bits, as the draft's TLS profile.
const TAG_LEN: usize = 16;

/// Key length: AEGIS-256 takes a 256-bit key.
const KEY_LEN: usize = 32;

/// Our suite, as rustls sees it. Built once; the reference lives for the
/// process (rustls wants `&'static`).
pub fn suite() -> SupportedCipherSuite {
    static SUITE: OnceLock<SupportedCipherSuite> = OnceLock::new();
    *SUITE.get_or_init(|| {
        let base = TLS13_AES_256_GCM_SHA384
            .tls13()
            .expect("TLS13_AES_256_GCM_SHA384 is a TLS 1.3 suite");
        let s: &'static Tls13CipherSuite = Box::leak(Box::new(Tls13CipherSuite {
            common: CipherSuiteCommon {
                suite: CipherSuite::Unknown(CODEPOINT),
                // SHA-384, borrowed from ring's AES-256-GCM suite — deviation
                // no. 3 in the module docs.
                hash_provider: base.common.hash_provider,
                // Well under any bound the draft states for AEGIS-256; rustls
                // triggers a TLS 1.3 key update when a key has encrypted this
                // many records.
                confidentiality_limit: 1 << 48,
            },
            hkdf_provider: base.hkdf_provider,
            aead_alg: &Aegis256Aead,
            quic: None,
        }));
        SupportedCipherSuite::Tls13(s)
    })
}

/// The 32-byte AEGIS-256 nonce from rustls' 12-byte TLS 1.3 nonce — deviation
/// no. 1: left-aligned, zero-padded. Unique per key because the TLS nonce is.
fn nonce32(iv: &Iv, seq: u64) -> [u8; 32] {
    let tls = Nonce::new(iv, seq).0;
    let mut out = [0u8; 32];
    out[..NONCE_LEN].copy_from_slice(&tls);
    out
}

fn key32(key: AeadKey) -> Zeroizing<[u8; KEY_LEN]> {
    let mut k = Zeroizing::new([0u8; KEY_LEN]);
    // rustls guarantees `key_len()` bytes; anything else is a rustls bug, and
    // a panic here is the honest response (ring's provider unwraps the same way).
    k.copy_from_slice(key.as_ref());
    k
}

struct Aegis256Aead;

impl Tls13AeadAlgorithm for Aegis256Aead {
    fn encrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageEncrypter> {
        Box::new(Encrypter {
            key: key32(key),
            iv,
        })
    }

    fn decrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageDecrypter> {
        Box::new(Decrypter {
            key: key32(key),
            iv,
        })
    }

    fn key_len(&self) -> usize {
        KEY_LEN
    }

    fn extract_keys(
        &self,
        _key: AeadKey,
        _iv: Iv,
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        // Key export (kTLS offload) is not a thing for this suite.
        Err(UnsupportedOperationError)
    }

    fn fips(&self) -> bool {
        false
    }
}

struct Encrypter {
    key: Zeroizing<[u8; KEY_LEN]>,
    iv: Iv,
}

struct Decrypter {
    key: Zeroizing<[u8; KEY_LEN]>,
    iv: Iv,
}

impl MessageEncrypter for Encrypter {
    fn encrypt(
        &mut self,
        msg: OutboundPlainMessage<'_>,
        seq: u64,
    ) -> Result<OutboundOpaqueMessage, Error> {
        let total_len = self.encrypted_payload_len(msg.payload.len());
        let mut payload = PrefixedPayload::with_capacity(total_len);
        payload.extend_from_chunks(&msg.payload);
        // TLS 1.3 inner plaintext: content || type (no padding).
        payload.extend_from_slice(&[u8::from(msg.typ)]);

        let aad = make_tls13_aad(total_len);
        let cipher = Aegis256::<TAG_LEN>::new(&self.key, &nonce32(&self.iv, seq));
        let tag = cipher.encrypt_in_place(payload.as_mut(), &aad);
        payload.extend_from_slice(&tag);

        Ok(OutboundOpaqueMessage::new(
            ContentType::ApplicationData,
            // All TLS 1.3 application data records carry the legacy version
            // 0x0303 (RFC 8446 §5.1) — same as ring's suites.
            ProtocolVersion::TLSv1_2,
            payload,
        ))
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len + 1 + TAG_LEN
    }
}

impl MessageDecrypter for Decrypter {
    fn decrypt<'a>(
        &mut self,
        mut msg: InboundOpaqueMessage<'a>,
        seq: u64,
    ) -> Result<InboundPlainMessage<'a>, Error> {
        let payload = &mut msg.payload;
        let len = payload.len();
        if len < TAG_LEN {
            return Err(Error::DecryptError);
        }
        let aad = make_tls13_aad(len);
        let (ct, tag) = payload.split_at_mut(len - TAG_LEN);
        let tag: [u8; TAG_LEN] = tag.try_into().map_err(|_| Error::DecryptError)?;
        let cipher = Aegis256::<TAG_LEN>::new(&self.key, &nonce32(&self.iv, seq));
        cipher
            .decrypt_in_place(ct, &tag, &aad)
            .map_err(|_| Error::DecryptError)?;
        payload.truncate(len - TAG_LEN);
        msg.into_tls13_unpadded_message()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::crypto::cipher::OutboundChunks;

    fn pair() -> (Box<dyn MessageEncrypter>, Box<dyn MessageDecrypter>) {
        let key = [7u8; KEY_LEN];
        (
            Aegis256Aead.encrypter(AeadKey::from(key), Iv::new([3u8; NONCE_LEN])),
            Aegis256Aead.decrypter(AeadKey::from(key), Iv::new([3u8; NONCE_LEN])),
        )
    }

    fn encrypt(enc: &mut dyn MessageEncrypter, plain: &[u8], seq: u64) -> Vec<u8> {
        let chunks = [plain];
        let msg = OutboundPlainMessage {
            typ: ContentType::ApplicationData,
            version: ProtocolVersion::TLSv1_3,
            payload: OutboundChunks::new(&chunks),
        };
        // `encode` prepends the 5-byte record header; the record body follows.
        enc.encrypt(msg, seq).unwrap().encode()[5..].to_vec()
    }

    fn decrypt(
        dec: &mut dyn MessageDecrypter,
        body: &mut [u8],
        seq: u64,
    ) -> Result<Vec<u8>, Error> {
        let msg =
            InboundOpaqueMessage::new(ContentType::ApplicationData, ProtocolVersion::TLSv1_2, body);
        dec.decrypt(msg, seq).map(|m| m.payload.to_vec())
    }

    #[test]
    fn record_roundtrip() {
        let (mut enc, mut dec) = pair();
        let plain = b"the seam, not the primitive";
        let mut body = encrypt(&mut *enc, plain, 0);
        assert_eq!(body.len(), plain.len() + 1 + TAG_LEN);
        let out = decrypt(&mut *dec, &mut body, 0).unwrap();
        assert_eq!(out, plain);
    }

    #[test]
    fn tampering_and_wrong_sequence_are_refused() {
        let (mut enc, mut dec) = pair();
        let mut body = encrypt(&mut *enc, b"payload", 5);
        // Wrong sequence number → wrong nonce → authentication fails.
        assert!(decrypt(&mut *dec, &mut body.clone(), 6).is_err());
        // One flipped bit in the ciphertext.
        body[0] ^= 1;
        assert!(decrypt(&mut *dec, &mut body, 5).is_err());
        // Too short to even carry a tag.
        let mut short = vec![0u8; TAG_LEN - 1];
        assert!(decrypt(&mut *dec, &mut short, 5).is_err());
    }

    #[test]
    fn nonce_is_the_tls_nonce_zero_padded() {
        let iv = Iv::new([0xAA; NONCE_LEN]);
        let n = nonce32(&iv, 1);
        assert_eq!(&n[..NONCE_LEN], &Nonce::new(&iv, 1).0);
        assert!(n[NONCE_LEN..].iter().all(|b| *b == 0));
        assert_ne!(nonce32(&iv, 1), nonce32(&iv, 2));
    }

    #[test]
    fn the_suite_is_ours_and_tls13_only() {
        let s = suite();
        assert_eq!(s.suite(), CipherSuite::Unknown(CODEPOINT));
        assert!(s.tls13().is_some());
        assert_eq!(s.tls13().unwrap().aead_alg.key_len(), KEY_LEN);
    }

    /// **The exit condition, checked by the build.** rustls 0.23 fixes the
    /// TLS 1.3 nonce at 12 bytes. When a rustls we build against widens it,
    /// this fails — and that is the signal to replace this file with the
    /// standard suite (L2-076), not to fix the test.
    #[test]
    fn the_deviation_still_has_its_reason() {
        assert_eq!(
            NONCE_LEN, 12,
            "rustls has changed its TLS 1.3 nonce length — revisit aegis.rs: can the \
             standard TLS_AEGIS_256_SHA512 (0x1306, 32-byte IV, SHA-512) replace this deviation? (L2-076)"
        );
    }
}
