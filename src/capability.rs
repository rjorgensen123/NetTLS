// SPDX-License-Identifier: MIT OR Apache-2.0
//! AEAD capability — the signed support statement and the fallback rule.
//!
//! The decided pattern: **the best algorithm (AEGIS-256) is the
//! default; fallback is an explicit, authenticated exception; falling back to
//! nothing does not exist.** Concretely:
//!
//! - A party that does NOT support the requested algorithm answers with a
//!   **signed** [`SupportStatement`] declaring what it actually supports.
//!   Only the non-supporting party can trigger a downgrade — the signature is
//!   what stops an attacker from downgrading anyone at will.
//! - [`choose`] implements the rule: use the requested algorithm, or fall
//!   back to the best algorithm the peer has *signed* that it supports —
//!   otherwise **fail hard** ([`TlsError::Negotiation`]). Never silently
//!   weaker, never a downgrade on unauthenticated grounds.
//!
//! The crate is I/O-free here as everywhere: consumers exchange the statement
//! (as JSON — it serializes with serde); this module builds, signs, verifies
//! and decides. Signing uses the party's TLS anchor (ECDSA P-256), like every
//! §6 message.

use krypto::Alg;
use serde::{Deserialize, Serialize};

use crate::canonical::{self, algsupport_v1};
use crate::error::TlsError;
use crate::signature::{sign_p256, verify_p256};

/// The fixed preference order — also the canonical token order on the wire.
const PREFERENCE: [Alg; 3] = [Alg::Aegis256, Alg::XChaCha20Poly1305, Alg::Aes256Gcm];

/// The wire token for an algorithm (same tokens as krypto's cli).
pub fn alg_token(alg: Alg) -> &'static str {
    match alg {
        Alg::Aegis256 => "aegis256",
        Alg::XChaCha20Poly1305 => "xchacha20",
        Alg::Aes256Gcm => "aes256gcm",
        // `Alg` is #[non_exhaustive]: a future algorithm must get a token HERE
        // before it can be declared — no token, no negotiation.
        _ => "unknown",
    }
}

/// Parse a wire token — fail-closed on anything unknown.
pub fn alg_from_token(token: &str) -> Result<Alg, TlsError> {
    match token {
        "aegis256" => Ok(Alg::Aegis256),
        "xchacha20" => Ok(Alg::XChaCha20Poly1305),
        "aes256gcm" => Ok(Alg::Aes256Gcm),
        other => Err(TlsError::Params(format!(
            "unknown AEAD token {other:?} — known: aegis256, xchacha20, aes256gcm"
        ))),
    }
}

/// The signed support statement: "this is what I actually support".
///
/// Serialize it as JSON and send it however your surfaces talk; the receiver
/// calls [`SupportStatement::verify`] against the signer's pinned certificate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SupportStatement {
    /// Who declares (component name, validated like every §6 name).
    pub component: String,
    /// The supported algorithms, as wire tokens in canonical order.
    pub supported: Vec<String>,
    /// Unix seconds when the statement was made.
    pub timestamp: i64,
    /// Hex ECDSA P-256 signature over the canonical bytes.
    pub signature: String,
}

impl SupportStatement {
    /// Build and sign a statement with the declarer's TLS anchor (PKCS#8,
    /// from [`TlsMaterial::anchor_pkcs8`](crate::material::TlsMaterial::anchor_pkcs8)).
    /// The supported set is normalized into canonical order.
    pub fn signed(
        component: &str,
        supported: &[Alg],
        timestamp: i64,
        anchor_pkcs8: &krypto::SecretBuf,
    ) -> Result<SupportStatement, TlsError> {
        if supported.is_empty() {
            return Err(TlsError::Params(
                "a support statement must declare at least one algorithm".into(),
            ));
        }
        let tokens: Vec<String> = PREFERENCE
            .iter()
            .filter(|a| supported.contains(a))
            .map(|a| alg_token(*a).to_string())
            .collect();
        if tokens.len() != supported.len() {
            return Err(TlsError::Params(
                "a support statement may only declare known algorithms, once each".into(),
            ));
        }
        let csv = tokens.join(",");
        let bytes = algsupport_v1(component, &csv, timestamp)?;
        let signature = krypto::hex::encode(&sign_p256(anchor_pkcs8, &bytes)?);
        Ok(SupportStatement {
            component: component.to_string(),
            supported: tokens,
            timestamp,
            signature,
        })
    }

    /// Verify against the signer's certificate (DER — the pinned identity you
    /// already trust for this peer) and return the declared algorithms.
    ///
    /// Fail-closed the whole way: unknown tokens, non-canonical order and a
    /// bad signature all reject — an unverifiable statement authorizes
    /// nothing ([`TlsError::ProofInvalid`]).
    pub fn verify(&self, signer_cert_der: &[u8]) -> Result<Vec<Alg>, TlsError> {
        let csv = self.supported.join(",");
        let bytes = algsupport_v1(&self.component, &csv, self.timestamp)?;
        let sig = canonical_hex(&self.signature)?;
        verify_p256(signer_cert_der, &bytes, &sig)
            .map_err(|e| TlsError::ProofInvalid(format!("support statement: {e}")))?;
        self.supported
            .iter()
            .map(|t| alg_from_token(t))
            .collect::<Result<Vec<Alg>, TlsError>>()
    }
}

fn canonical_hex(s: &str) -> Result<Vec<u8>, TlsError> {
    crate::signature::from_hex(s)
}

/// The fallback rule (the decided pattern, verbatim):
///
/// - No statement → the requested algorithm stands. (A peer that cannot open
///   it answers with a signed statement; only then may anything change.)
/// - A verified statement listing the requested algorithm → the requested one.
/// - A verified statement without it → the best algorithm the peer declared,
///   by the fixed preference order.
/// - Nothing acceptable → **hard failure** ([`TlsError::Negotiation`]). Never
///   silently weaker.
pub fn choose(requested: Alg, verified_supported: Option<&[Alg]>) -> Result<Alg, TlsError> {
    let Some(supported) = verified_supported else {
        return Ok(requested);
    };
    if supported.contains(&requested) {
        return Ok(requested);
    }
    for candidate in PREFERENCE {
        if supported.contains(&candidate) {
            return Ok(candidate);
        }
    }
    Err(TlsError::Negotiation(format!(
        "the peer's signed statement declares no acceptable algorithm \
         (requested {}; declared: {})",
        alg_token(requested),
        supported
            .iter()
            .map(|a| alg_token(*a))
            .collect::<Vec<_>>()
            .join(", ")
    )))
}

// Keep the canonical module linked for rustdoc readers.
#[allow(unused_imports)]
use canonical::ALGSUPPORT_V1 as _DOC_ANCHOR;
