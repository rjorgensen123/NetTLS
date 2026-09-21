// SPDX-License-Identifier: MIT OR Apache-2.0
//! The TLS channel's cipher — the consumer's choice, never negotiated away.
//!
//! SPEC-nettls §6.0b: the algorithm choice applies "to everything, the traffic
//! too". This module is where it reaches the transport. Three things are fixed
//! by the spec's rules and enforced here:
//!
//! 1. **A default that needs no thought.** A consumer that says nothing gets
//!    [`TransportPolicy::default`]: **AES-256-GCM only** — the one AEAD every
//!    party speaks (rustls, OpenSSL/Python, every browser).
//!    Decided 2026-09-04: AEGIS-256 is *available* in the transport as a
//!    consumer choice, but not the default — see `aegis.rs` for why.
//! 2. **The consumer's list, in the consumer's order.** rustls picks the first
//!    suite in *our* list the peer also offers. Nothing outside the list is
//!    ever used; a peer that shares no suite gets a hard handshake failure
//!    (`NoCipherSuitesInCommon` on the server side, an alert on the client).
//!    There is no silent fallback and no renegotiation on the peer's word.
//! 3. **Minimal.** The policy is a filter over the ring provider's suites:
//!    a few dozen lines, and the default path costs one `Vec` per config.
//!
//! One choice per cipher covers both protocol versions: TLS 1.3's suite and
//! the TLS 1.2 ECDHE suites with the same AEAD, so keeping TLS 1.2 for older
//! browsers (L2-014) does not reopen the door to a weaker AEAD.

use std::sync::Arc;

use rustls::crypto::ring::cipher_suite as ring;
use rustls::crypto::CryptoProvider;
use rustls::SupportedCipherSuite;

use crate::error::TlsError;

/// An AEAD for the TLS channel.
///
/// Names follow the wire, not krypto's at-rest menu: TLS has ChaCha20-Poly1305
/// (12-byte nonce), not XChaCha20 — the token is honest about which one runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum TransportCipher {
    /// AES-256-GCM — `TLS13_AES_256_GCM_SHA384` and the TLS 1.2 ECDHE
    /// equivalents. **The default.** Spoken by every party.
    Aes256Gcm,
    /// ChaCha20-Poly1305 — `TLS13_CHACHA20_POLY1305_SHA256` and the TLS 1.2
    /// ECDHE equivalents. For peers without AES hardware.
    ChaCha20Poly1305,
    /// AEGIS-256 — **our own TLS 1.3 suite, a deliberate deviation** from the
    /// standard `TLS_AEGIS_256_SHA512` (private code point, zero-padded nonce,
    /// SHA-384 pairing). Only two nettls ends can speak it; a foreign peer
    /// skips it as unknown. TLS 1.3 only. Everything about why, and about the
    /// exit, is in [`crate::aegis`]. Not the default (decided 2026-09-04).
    Aegis256,
}

impl TransportCipher {
    /// The token for logs and status — stable, lowercase.
    pub fn token(self) -> &'static str {
        match self {
            Self::Aes256Gcm => "aes256gcm",
            Self::ChaCha20Poly1305 => "chacha20poly1305",
            Self::Aegis256 => "aegis256",
        }
    }

    /// The rustls suites this choice enables: TLS 1.3 first, then the TLS 1.2
    /// ECDHE pair (ECDSA before RSA — our own certificates are ECDSA). AEGIS
    /// has no TLS 1.2 form.
    fn suites(self) -> Vec<SupportedCipherSuite> {
        match self {
            Self::Aes256Gcm => vec![
                ring::TLS13_AES_256_GCM_SHA384,
                ring::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                ring::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            ],
            Self::ChaCha20Poly1305 => vec![
                ring::TLS13_CHACHA20_POLY1305_SHA256,
                ring::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
                ring::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            ],
            Self::Aegis256 => vec![crate::aegis::suite()],
        }
    }
}

/// Which ciphers a TLS config offers, in order of preference.
///
/// Built once, passed to the `*_with` config builders
/// ([`TlsMaterial::server_config_with`], [`RotatingResolver::server_config_with`],
/// [`pinned_client_config_with`], [`Trust::client_config_with`]). The builders
/// without a policy use [`TransportPolicy::default`].
///
/// [`TlsMaterial::server_config_with`]: crate::material::TlsMaterial::server_config_with
/// [`RotatingResolver::server_config_with`]: crate::resolver::RotatingResolver::server_config_with
/// [`pinned_client_config_with`]: crate::pin::pinned_client_config_with
/// [`Trust::client_config_with`]: crate::generations::Trust::client_config_with
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportPolicy {
    ciphers: Vec<TransportCipher>,
}

impl Default for TransportPolicy {
    /// **AES-256-GCM only.** The choice that needs no thought and works
    /// against every peer we have.
    fn default() -> Self {
        Self::only(TransportCipher::Aes256Gcm)
    }
}

impl TransportPolicy {
    /// Exactly one cipher.
    pub fn only(cipher: TransportCipher) -> Self {
        Self {
            ciphers: vec![cipher],
        }
    }

    /// The consumer's list, in the consumer's order. Empty lists and repeated
    /// entries are rejected — a policy says exactly what it means, once.
    pub fn new(ciphers: &[TransportCipher]) -> Result<Self, TlsError> {
        if ciphers.is_empty() {
            return Err(TlsError::Params(
                "a transport policy must name at least one cipher — there is no \"no encryption\""
                    .into(),
            ));
        }
        for (i, c) in ciphers.iter().enumerate() {
            if ciphers[..i].contains(c) {
                return Err(TlsError::Params(format!(
                    "a transport policy names each cipher once — {} is repeated",
                    c.token()
                )));
            }
        }
        Ok(Self {
            ciphers: ciphers.to_vec(),
        })
    }

    /// The ciphers, in preference order.
    pub fn ciphers(&self) -> &[TransportCipher] {
        &self.ciphers
    }

    /// The ring provider narrowed to this policy's suites, in this order.
    /// Everything else in the provider (key exchange, signature verification,
    /// randomness, key loading) is ring's unchanged.
    pub(crate) fn provider(&self) -> Arc<CryptoProvider> {
        let base = crate::provider::provider();
        let cipher_suites = self
            .ciphers
            .iter()
            .flat_map(|c| c.suites())
            .collect::<Vec<_>>();
        Arc::new(CryptoProvider {
            cipher_suites,
            ..(*base).clone()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_aes256_only() {
        let p = TransportPolicy::default();
        assert_eq!(p.ciphers(), &[TransportCipher::Aes256Gcm]);
        let suites = p.provider().cipher_suites.clone();
        assert_eq!(suites.len(), 3);
        for s in suites {
            let name = format!("{:?}", s.suite());
            assert!(name.contains("AES_256_GCM"), "{name}");
        }
    }

    #[test]
    fn order_is_the_consumers_order() {
        let p = TransportPolicy::new(&[
            TransportCipher::ChaCha20Poly1305,
            TransportCipher::Aes256Gcm,
        ])
        .unwrap();
        let suites = p.provider().cipher_suites.clone();
        assert_eq!(suites.len(), 6);
        assert!(format!("{:?}", suites[0].suite()).contains("CHACHA20"));
        assert!(format!("{:?}", suites[3].suite()).contains("AES_256_GCM"));
    }

    #[test]
    fn empty_and_repeated_are_rejected() {
        assert!(TransportPolicy::new(&[]).is_err());
        assert!(
            TransportPolicy::new(&[TransportCipher::Aes256Gcm, TransportCipher::Aes256Gcm])
                .is_err()
        );
    }

    #[test]
    fn nothing_outside_the_policy_is_offered() {
        // Neither policy carries AES-128 — the ring default does.
        let all = crate::provider::provider().cipher_suites.len();
        let p = TransportPolicy::new(&[
            TransportCipher::Aes256Gcm,
            TransportCipher::ChaCha20Poly1305,
        ])
        .unwrap();
        let ours = p.provider().cipher_suites.clone();
        assert!(ours.len() < all);
        assert!(ours
            .iter()
            .all(|s| !format!("{:?}", s.suite()).contains("AES_128")));
    }
}
