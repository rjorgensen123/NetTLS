// SPDX-License-Identifier: MIT OR Apache-2.0
//! Client side: fingerprint pinning instead of a CA chain.
//!
//! # What this module deliberately does NOT do
//!
//! [`pinned_client_config`] builds a `ClientConfig` that does **not** build any
//! CA chain and does **not** check the hostname against the SAN. It accepts
//! exactly one certificate: the one whose SHA-256 over the DER matches the
//! pinned value.
//!
//! That is not a shortcut — it is the right model for an internal setup
//! without a CA, and it is identical to SSH host-key pinning: the identity is
//! *exactly this key*. A CA
//! chain would have required a CA we do not have, and a name check would have
//! been meaningless when the peer is designated by fingerprint anyway.
//!
//! # What it still does — and what makes it safe
//!
//! The handshake signature is **verified in full** against the provider, for
//! both TLS 1.2 and TLS 1.3. Without that the pinning would be worthless:
//! anyone could replay a copied certificate they do not hold the private key
//! for. The comparison of the fingerprint itself is constant-time.
//!
//! # Consequence for the consumer
//!
//! Since the hostname is not checked, it does not matter which `ServerName`
//! you give `TlsConnector::connect` — but rustls requires that you give *one*.
//! Use the service name (e.g. `"gateway"`), so the SNI in the handshake is
//! something that makes sense in a packet capture.
//!
//! **If the server changes certificate, the pinned value must be updated.**
//! That is the price of pinning, and it is intentional: a silent swap should
//! stop the traffic, not pass.

use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{CertificateError, ClientConfig, DigitallySignedStruct, Error, SignatureScheme};

use crate::error::TlsError;
use crate::fingerprint::parse_fingerprint;
use krypto::{ct_eq, sha256};

/// `ClientConfig` that only accepts the server with this SHA-256 fingerprint.
///
/// `fingerprint_sha256` is the value [`crate::TlsMaterial::fingerprint_sha256`]
/// gives. The format is tolerant (colons, uppercase and a `sha256:` prefix are
/// fine), but the length is not — a typo yields an error, never a config that
/// accepts more than it should.
///
/// No ALPN is set. If you need that, use
/// [`pinned_client_config_with_alpn`].
pub fn pinned_client_config(fingerprint_sha256: &str) -> Result<Arc<ClientConfig>, TlsError> {
    pinned_client_config_with_alpn(fingerprint_sha256, &[])
}

/// Like [`pinned_client_config`], but with an ALPN list.
pub fn pinned_client_config_with_alpn(
    fingerprint_sha256: &str,
    alpn: &[Vec<u8>],
) -> Result<Arc<ClientConfig>, TlsError> {
    pinned_client_config_with(
        fingerprint_sha256,
        alpn,
        &crate::transport::TransportPolicy::default(),
    )
}

/// Like [`pinned_client_config_with_alpn`], with an explicit
/// [`TransportPolicy`](crate::transport::TransportPolicy) (0.8.3). Without one,
/// the client offers the default: **AES-256-GCM only**.
pub fn pinned_client_config_with(
    fingerprint_sha256: &str,
    alpn: &[Vec<u8>],
    transport: &crate::transport::TransportPolicy,
) -> Result<Arc<ClientConfig>, TlsError> {
    let expected = parse_fingerprint(fingerprint_sha256)?;
    let provider = transport.provider();
    let verifier = PinnedServerCertVerifier {
        expected,
        provider: provider.clone(),
    };

    let mut cfg = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .map_err(|e| TlsError::Rustls(e.to_string()))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth();
    cfg.alpn_protocols = alpn.to_vec();
    cfg.resumption = no_resumption();
    Ok(Arc::new(cfg))
}

/// **Session resumption is turned off on the client side — deliberately.**
///
/// Discovered 2026-08-10, during the work on rolling pinning: if the client
/// resumes an earlier session (TLS 1.3 PSK), the server does **not** send the
/// certificate again, and then our verifier does not run either. The pinning
/// then becomes a check performed on the *first* connection and thereafter
/// implied on all later ones — until the ticket expires.
///
/// That is not a hole in itself (whoever resumes must prove they hold the
/// secret from an already authenticated session), but it breaks two things we
/// depend on:
///
/// 1. **The rotation must bite immediately.** With resumption, a client that
///    has not yet seen the new identity could keep connecting on the old one —
///    directly contrary to the fact that the key's lifetime *is* the security
///    mechanism.
/// 2. **"Pinned" must mean checked at every handshake**, without exception. An
///    invariant with an exception is not an invariant, it is a footnote.
///
/// The price is one extra round trip on an internal network with very few new
/// connections — and our clients keep their connections open anyway. The
/// server side ([`crate::TlsMaterial::server_config`]) we leave alone: there,
/// resumption is useful for the browsers, and there is no pinning there to
/// undermine.
pub(crate) fn no_resumption() -> rustls::client::Resumption {
    rustls::client::Resumption::disabled()
}

/// The verifier behind [`pinned_client_config`].
struct PinnedServerCertVerifier {
    expected: [u8; 32],
    provider: Arc<CryptoProvider>,
}

impl std::fmt::Debug for PinnedServerCertVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PinnedServerCertVerifier")
            .field("expected", &krypto::hex::encode(&self.expected))
            .finish()
    }
}

impl ServerCertVerifier for PinnedServerCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        // Intermediate certificates are ignored: we pin the leaf, there is no
        // chain to build, and a chain we do not trust must not be able to
        // influence anything.
        let actual = sha256(end_entity.as_ref());
        if ct_eq(&actual, &self.expected) {
            Ok(ServerCertVerified::assertion())
        } else {
            // The error does not contain the fingerprints. The client already
            // knows what it expected, and what it got belongs in a log call at
            // the consumer, not in a TLS alert that goes out on the wire.
            Err(Error::InvalidCertificate(
                CertificateError::ApplicationVerificationFailure,
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        // This is not a formality: without signature verification, anyone
        // could replay a copied certificate without holding the private key,
        // and the pinning would be worthless.
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}
