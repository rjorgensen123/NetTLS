// SPDX-License-Identifier: MIT OR Apache-2.0
//! Error model.
//!
//! The principle from First Preview applies: **never empty error messages**.
//! Every variant carries enough context for the operator to see *what* is
//! wrong — "the key does not belong to the certificate", "the certificate
//! expired 2026-03-01" — not just that something failed.
//!
//! No variant contains key material. That is an invariant, not a coincidence:
//! `TlsError` gets logged, and a logged private key is a compromised private
//! key.

use std::fmt;
use std::path::PathBuf;

/// Error from `nettls`. `#[non_exhaustive]` — new variants may appear.
#[derive(Debug)]
#[non_exhaustive]
pub enum TlsError {
    /// File I/O failed. `path` is included when we know which file it concerned.
    Io {
        /// The file the operation concerned, if known.
        path: Option<PathBuf>,
        /// What went wrong.
        detail: String,
    },
    /// The PEM could not be parsed (empty file, wrong block type, truncated base64 …).
    Pem(String),
    /// The private key does not belong to the certificate, or the provider does
    /// not support it. This is the classic upload error.
    KeyMismatch(String),
    /// The certificate is expired or not yet valid (unix time).
    NotValidNow {
        /// `notBefore` from the certificate.
        not_before: i64,
        /// `notAfter` from the certificate.
        not_after: i64,
        /// The point in time we compared against.
        now: i64,
    },
    /// The certificate could not be parsed as X.509.
    Certificate(String),
    /// Generating a self-signed certificate failed (rcgen).
    Generate(String),
    /// rustls rejected the configuration.
    Rustls(String),
    /// Invalid parameters from the consumer (empty SAN list, `valid_days` outside
    /// 1..=397, …).
    Params(String),
    /// The fingerprint string could not be parsed as 32 bytes of hexadecimal.
    Fingerprint(String),
    /// A signed or serialized value could not be **parsed**: an unknown version
    /// prefix, the wrong number of lines, invalid hex, a field that does not
    /// resolve. Covers announcements, receipts, approvals, support statements and
    /// the raw hex forms.
    ///
    /// **Fail-closed** — a value we cannot read is a value we do not trust. The
    /// distinction from [`TlsError::ProofInvalid`] is deliberate: this one never
    /// got as far as checking a signature.
    Proof(String),
    /// A value parsed cleanly but **does not hold**: a signature that does not
    /// verify against the key it should, a sealed blob that does not authenticate,
    /// or a statement issued for a different party than the one being checked.
    ///
    /// The difference from [`TlsError::Proof`] is where it failed. That one could
    /// not read the value; this one read it and found it untrue.
    ProofInvalid(String),
    /// **The continuity chain is broken**: the issuer is not among the
    /// fingerprints we currently trust. The message names the state
    /// and includes both fingerprints — this is the failure that should be the
    /// best explained in the entire system, because its consequence is that
    /// communication stays down until an operator approves anew.
    Chain(String),
    /// Could not produce a signature — typically because the key is not
    /// ECDSA P-256.
    Sign(String),
    /// AEAD negotiation failed: no *authenticated* common algorithm. The
    /// connection must fail — never silently weaken. Fallback happens only to
    /// an algorithm the peer has SIGNED that it supports.
    Negotiation(String),
}

impl fmt::Display for TlsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TlsError::Io { path: Some(p), detail } => {
                write!(f, "file I/O failed for {}: {detail}", p.display())
            }
            TlsError::Io { path: None, detail } => write!(f, "file I/O failed: {detail}"),
            TlsError::Pem(s) => write!(f, "the PEM could not be parsed: {s}"),
            TlsError::KeyMismatch(s) => write!(f, "key and certificate do not belong together: {s}"),
            TlsError::NotValidNow { not_before, not_after, now } => write!(
                f,
                "the certificate is not valid now (notBefore={not_before}, notAfter={not_after}, now={now}, unix time)"
            ),
            TlsError::Certificate(s) => write!(f, "the certificate could not be parsed: {s}"),
            TlsError::Generate(s) => write!(f, "could not generate self-signed certificate: {s}"),
            TlsError::Rustls(s) => write!(f, "rustls rejected the configuration: {s}"),
            TlsError::Params(s) => write!(f, "invalid parameters: {s}"),
            TlsError::Fingerprint(s) => write!(f, "invalid SHA-256 fingerprint: {s}"),
            TlsError::Proof(s) => write!(f, "a signed value could not be parsed: {s}"),
            TlsError::ProofInvalid(s) => write!(f, "a signature or sealed value does not hold: {s}"),
            TlsError::Chain(s) => write!(f, "{s}"),
            TlsError::Sign(s) => write!(f, "could not sign: {s}"),
            TlsError::Negotiation(s) => write!(
                f,
                "AEAD negotiation failed (the connection must fail — never silently weaken): {s}"
            ),
        }
    }
}

impl std::error::Error for TlsError {}

impl TlsError {
    pub(crate) fn io(path: impl Into<PathBuf>, e: std::io::Error) -> Self {
        TlsError::Io {
            path: Some(path.into()),
            detail: e.to_string(),
        }
    }
}
