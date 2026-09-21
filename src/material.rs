// SPDX-License-Identifier: MIT OR Apache-2.0
//! Certificate + key: where it comes from, and what we can say about it.

use std::fmt;
use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::ServerConfig;
use x509_parser::prelude::FromDer;
use zeroize::Zeroizing;

use crate::error::TlsError;
use crate::pem;
use crate::provider::provider;
use crate::secret;
use crate::transport::TransportPolicy;
use krypto::sha256;

/// The file names `CertSource::auto` and [`TlsMaterial::save_pem`] use.
pub const CERT_FILE: &str = "cert.pem";
/// The file name for the private key.
pub const KEY_FILE: &str = "key.pem";

/// Upper bound on the lifetime of self-generated certificates.
///
/// Safari and Chrome reject certificates with a lifetime longer than 398
/// days — self-signed included. We cap it at 397 for margin. If the consumer
/// asks for more, that is an error we should report at generation time, not a
/// surprise in the browser months later.
pub const MAX_VALID_DAYS: u32 = 397;

/// Where the material came from. Pure information for the consumer — in
/// particular [`CertOrigin::Ephemeral`], which the consumer **should log as a
/// warning**.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CertOrigin {
    /// Loaded from PEM files on disk.
    Files,
    /// Loaded from PEM bytes the consumer had in memory (e.g. an upload).
    Pem,
    /// Freshly generated self-signed, written to the `auto` directory. The
    /// fingerprint survives a restart.
    Generated,
    /// Valid certificate found in the `auto` directory and reused. No new
    /// browser warning for the operator.
    Reused,
    /// **Expired (or not yet valid) certificate found in the `auto`
    /// directory — and deliberately KEPT.** The service comes up and works;
    /// clients will complain about the date.
    ///
    /// Roger (2026-08-10): "if an operator chooses to run the whole app on our
    /// dummy certs, approves them, and they expire, then it must be possible
    /// to override that with a glowing WARNING both here and there — it must
    /// not be possible to overlook, but the app must work if an operator
    /// chooses it."
    ///
    /// We therefore do **not** replace the certificate automatically: a new
    /// certificate has a new fingerprint, and that would silently break every
    /// pinned pairing — the operator would see an inexplicable 502 instead of
    /// a date error she can act on. Regeneration must be a **deliberate
    /// action**. The consumer **MUST** log this very clearly.
    ReusedExpired,
    /// Freshly generated self-signed that could **not** be saved (the
    /// directory was missing or not writable). The fingerprint **changes on
    /// every restart** — pinning does not work across restarts, and the
    /// operator gets a new browser warning every time. The consumer should
    /// log this clearly.
    Ephemeral,
}

/// Parameters for a self-generated certificate.
#[derive(Debug, Clone)]
pub struct SelfSignedParams {
    /// CN in the subject. Cosmetic for modern browsers (they read the SAN,
    /// not the CN), but it is what the operator sees in the certificate viewer.
    pub common_name: String,
    /// SAN list: DNS names **and** IP addresses. Strings that parse as an
    /// IP address automatically become IP SANs, the rest become DNS SANs.
    ///
    /// **Without an IP SAN, `https://<ip>:8080` fails** with
    /// `ERR_CERT_COMMON_NAME_INVALID`, which is considerably harder for the
    /// operator to click past than an ordinary self-signed warning. Include
    /// everything the operators actually type into the address bar.
    pub sans: Vec<String>,
    /// Lifetime in days. Must be `1..=`[`MAX_VALID_DAYS`].
    pub valid_days: u32,
}

impl Default for SelfSignedParams {
    fn default() -> Self {
        Self {
            common_name: "nettls self-signed".to_string(),
            sans: vec!["localhost".to_string(), "127.0.0.1".to_string()],
            valid_days: 365,
        }
    }
}

impl SelfSignedParams {
    /// Builds parameters with CN and SAN list; lifetime 365 days.
    pub fn new(
        common_name: impl Into<String>,
        sans: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        Self {
            common_name: common_name.into(),
            sans: sans.into_iter().map(Into::into).collect(),
            valid_days: 365,
        }
    }

    /// Sets the lifetime.
    pub fn valid_days(mut self, days: u32) -> Self {
        self.valid_days = days;
        self
    }
}

#[derive(Clone)]
enum Kind {
    Files {
        cert_path: PathBuf,
        key_path: PathBuf,
    },
    Pem {
        cert_pem: Vec<u8>,
        /// The consumer's bytes, as handed in — wiped on drop. The locked
        /// copy is what `load` builds from it (see `secret.rs`).
        key_pem: Zeroizing<Vec<u8>>,
    },
    SelfSigned(SelfSignedParams),
    Auto {
        dir: PathBuf,
        params: SelfSignedParams,
    },
}

/// Where the certificate comes from.
///
/// Construct with [`CertSource::files`], [`CertSource::pem`],
/// [`CertSource::self_signed`] or [`CertSource::auto`], and pass to
/// [`TlsMaterial::load`].
#[derive(Clone)]
pub struct CertSource {
    kind: Kind,
}

impl fmt::Debug for CertSource {
    /// Deliberately redacted: the `Pem` variant carries the private key, and
    /// a `{:?}` in a log line is enough to leak it (the redaction rule (never secret contents in Debug/Display)).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.kind {
            Kind::Files {
                cert_path,
                key_path,
            } => f
                .debug_struct("CertSource::Files")
                .field("cert_path", cert_path)
                .field("key_path", key_path)
                .finish(),
            Kind::Pem { cert_pem, key_pem } => f
                .debug_struct("CertSource::Pem")
                .field("cert_pem", &format_args!("[{} bytes]", cert_pem.len()))
                .field(
                    "key_pem",
                    &format_args!("[REDACTED], len={}", key_pem.len()),
                )
                .finish(),
            Kind::SelfSigned(p) => f.debug_tuple("CertSource::SelfSigned").field(p).finish(),
            Kind::Auto { dir, params } => f
                .debug_struct("CertSource::Auto")
                .field("dir", dir)
                .field("params", params)
                .finish(),
        }
    }
}

impl CertSource {
    /// Read cert chain and private key from two PEM files.
    ///
    /// The leaf certificate must come **first** in the chain file. rustls does
    /// not build the chain itself — with the intermediate missing, some
    /// clients fail and others don't, which is the classic "works on my
    /// machine" trap.
    pub fn files(cert_path: impl Into<PathBuf>, key_path: impl Into<PathBuf>) -> Self {
        Self {
            kind: Kind::Files {
                cert_path: cert_path.into(),
                key_path: key_path.into(),
            },
        }
    }

    /// Same as [`CertSource::files`], but from PEM the consumer has in
    /// memory — e.g. a certificate the operator just uploaded.
    ///
    /// Validate **before** anything is written to disk: `TlsMaterial::load`
    /// does the whole validation in memory, and [`TlsMaterial::save_pem`] is
    /// called only once it has passed. A rejected certificate must never be
    /// able to replace a working one.
    pub fn pem(cert_pem: impl Into<Vec<u8>>, key_pem: impl Into<Vec<u8>>) -> Self {
        Self {
            kind: Kind::Pem {
                cert_pem: cert_pem.into(),
                key_pem: Zeroizing::new(key_pem.into()),
            },
        }
    }

    /// Generate a new self-signed certificate in memory. Writes nothing.
    ///
    /// The fingerprint changes on every generation. For a service that gets
    /// restarted, you almost always want [`CertSource::auto`] instead.
    pub fn self_signed(params: SelfSignedParams) -> Self {
        Self {
            kind: Kind::SelfSigned(params),
        }
    }

    /// Load from `dir` if a **valid** certificate exists there; otherwise
    /// generate a self-signed one and save it in `dir`.
    ///
    /// This is the variant services should use. The point is that the
    /// fingerprint is stable across restarts: without that, the operator gets
    /// a new browser warning every time, and warnings you learn to stop
    /// reading don't work the day there is a real MITM.
    ///
    /// "Valid" means: both files exist, the PEM parses, the key belongs to the
    /// certificate, and the certificate is within its validity window **now**.
    /// If any of this does not hold, a new one is generated — a service that
    /// does not start because a self-generated certificate expired is a worse
    /// outcome than a new certificate.
    ///
    /// If the directory is not writable, the certificate is generated in
    /// memory and [`TlsMaterial::origin`] becomes [`CertOrigin::Ephemeral`].
    /// The consumer **should log a warning** in that case.
    pub fn auto(dir: impl Into<PathBuf>, params: SelfSignedParams) -> Self {
        Self {
            kind: Kind::Auto {
                dir: dir.into(),
                params,
            },
        }
    }
}

/// A validated certificate with its private key.
///
/// The construction is the validation itself: a `TlsMaterial` that exists has
/// a non-empty chain, a key the provider accepts, and a key that provably
/// belongs to the leaf certificate.
pub struct TlsMaterial {
    chain: Vec<CertificateDer<'static>>,
    /// rustls' type, because rustls needs it — wiped on drop, but ordinary
    /// heap. The honest limit is written down in `secret.rs`.
    key: Zeroizing<PrivateKeyDer<'static>>,
    origin: CertOrigin,
    fingerprint: String,
    not_before: i64,
    not_after: i64,
    sans: Vec<String>,
    subject: String,
}

impl fmt::Debug for TlsMaterial {
    /// The key is **never** included. Everything else here is public
    /// information any TLS client gets to see in the handshake anyway.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsMaterial")
            .field("origin", &self.origin)
            .field("subject", &self.subject)
            .field("sans", &self.sans)
            .field("fingerprint_sha256", &self.fingerprint)
            .field("not_after", &self.not_after)
            .field("chain_len", &self.chain.len())
            .field("key", &"[REDACTED]")
            .finish()
    }
}

impl TlsMaterial {
    /// Fetches, validates and (for `auto`) possibly generates and saves.
    pub fn load(src: &CertSource) -> Result<Self, TlsError> {
        match &src.kind {
            Kind::Files {
                cert_path,
                key_path,
            } => {
                let cert_pem = fs::read(cert_path).map_err(|e| TlsError::io(cert_path, e))?;
                // Straight into locked memory; `from_vec` zeroizes the read buffer.
                let key_pem =
                    secret::hold(fs::read(key_path).map_err(|e| TlsError::io(key_path, e))?)?;
                key_pem.expose(|k| Self::from_pem(&cert_pem, k, CertOrigin::Files))
            }
            Kind::Pem { cert_pem, key_pem } => Self::from_pem(cert_pem, key_pem, CertOrigin::Pem),
            Kind::SelfSigned(params) => {
                let (chain, key) = generate(params)?;
                Self::from_der(chain, key, CertOrigin::Generated)
            }
            Kind::Auto { dir, params } => Self::load_auto(dir, params),
        }
    }

    fn load_auto(dir: &Path, params: &SelfSignedParams) -> Result<Self, TlsError> {
        let cert_path = dir.join(CERT_FILE);
        let key_path = dir.join(KEY_FILE);

        if cert_path.is_file() && key_path.is_file() {
            // Failure here is not fatal: we fall back to generating. But we do
            // not swallow the error silently — it comes out as `Ephemeral`/
            // `Generated` which the consumer can log, and the files are only
            // overwritten once the new material has been validated.
            match Self::load(&CertSource::files(&cert_path, &key_path)) {
                Ok(mut m) => {
                    // Valid → reuse. Expired → reuse ANYWAY, but mark it.
                    //
                    // We deliberately do NOT replace the certificate automatically on
                    // expiry: a new certificate has a new fingerprint, and would have
                    // silently broken every pinned pairing. The operator would then see
                    // an inexplicable 502 instead of a date error she can act on.
                    // Regenerating is a deliberate action — see `CertOrigin::ReusedExpired`.
                    m.origin = if m.is_valid_now() {
                        CertOrigin::Reused
                    } else {
                        CertOrigin::ReusedExpired
                    };
                    return Ok(m);
                }
                // Corrupt, unreadable, or a key that does not match → we have no
                // usable material at all, and generate new.
                Err(_) => { /* falls through to the generation below */ }
            }
        }

        let (chain, key) = generate(params)?;
        let mut m = Self::from_der(chain, key, CertOrigin::Generated)?;
        if m.save_pem(dir).is_err() {
            // The directory does not exist or is read-only. The service must
            // still come up with TLS — but the consumer has to know that the
            // fingerprint does not survive a restart.
            m.origin = CertOrigin::Ephemeral;
        }
        Ok(m)
    }

    fn from_pem(cert_pem: &[u8], key_pem: &[u8], origin: CertOrigin) -> Result<Self, TlsError> {
        use rustls_pki_types::pem::PemObject;
        let chain: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(cert_pem)
            .collect::<Result<_, _>>()
            .map_err(|e| TlsError::Pem(format!("could not read CERTIFICATE blocks: {e}")))?;
        if chain.is_empty() {
            return Err(TlsError::Pem(
                "found no CERTIFICATE block — is this a PEM file, and is the leaf certificate first?"
                    .to_string(),
            ));
        }

        let key = PrivateKeyDer::from_pem_slice(key_pem).map_err(|e| {
            TlsError::Pem(format!(
                "could not read private key (expected PRIVATE KEY, RSA PRIVATE KEY or EC PRIVATE KEY): {e}"
            ))
        })?;

        Self::from_der(chain, key, origin)
    }

    fn from_der(
        chain: Vec<CertificateDer<'static>>,
        key: PrivateKeyDer<'static>,
        origin: CertOrigin,
    ) -> Result<Self, TlsError> {
        // This call IS the cross-check "does the key belong to the
        // certificate" — and at the same time "does the provider support the
        // key type". A wrong pair gives `InconsistentKeys(KeyMismatch)`. No
        // separate check needed.
        rustls::sign::CertifiedKey::from_der(chain.clone(), key.clone_key(), &provider())
            .map_err(|e| TlsError::KeyMismatch(e.to_string()))?;

        let leaf = &chain[0];
        let fingerprint = krypto::hex::encode(&sha256(leaf.as_ref()));
        let (not_before, not_after, sans, subject) = inspect(leaf)?;

        Ok(Self {
            chain,
            key: Zeroizing::new(key),
            origin,
            fingerprint,
            not_before,
            not_after,
            sans,
            subject,
        })
    }

    /// SHA-256 of the leaf certificate's DER, lowercase hexadecimal without
    /// separators. **This is the value clients pin.**
    ///
    /// Same value as `openssl x509 -noout -fingerprint -sha256` (without the
    /// colons).
    pub fn fingerprint_sha256(&self) -> String {
        self.fingerprint.clone()
    }

    /// `notAfter` as unix time — for expiry warnings and `/status`.
    ///
    /// Returns `Option` because the API must tolerate one day meeting a
    /// certificate we cannot get a sensible time out of; in practice it is
    /// always `Some` for anything that made it through [`TlsMaterial::load`].
    pub fn not_after(&self) -> Option<i64> {
        Some(self.not_after)
    }

    /// `notBefore` as unix time.
    pub fn not_before(&self) -> Option<i64> {
        Some(self.not_before)
    }

    /// Days until expiry, negative if already expired.
    ///
    /// The consumer should `warn!` below 30 days and `error!` below 7 (L2-014
    /// ch. 4.5) — the crate does not log by itself.
    pub fn days_until_expiry(&self) -> i64 {
        (self.not_after - now_unix()) / 86_400
    }

    /// Is the certificate within its validity window right now?
    pub fn is_valid_now(&self) -> bool {
        let now = now_unix();
        now >= self.not_before && now <= self.not_after
    }

    /// The SAN list, as it appears in the certificate (DNS names and IPs as
    /// text).
    pub fn sans(&self) -> &[String] {
        &self.sans
    }

    /// The subject DN as text — what the operator sees in the browser's
    /// certificate viewer.
    pub fn subject(&self) -> &str {
        &self.subject
    }

    /// Where the material came from. See in particular [`CertOrigin::Ephemeral`].
    pub fn origin(&self) -> CertOrigin {
        self.origin
    }

    /// The cert chain in DER, leaf first.
    pub fn cert_chain(&self) -> &[CertificateDer<'static>] {
        &self.chain
    }

    /// Chain + key as rustls' `CertifiedKey`.
    ///
    /// Used by [`crate::RotatingResolver`] to swap certificates without a
    /// restart. The call is also the cross-check "does the key belong to the
    /// certificate" — the same one as in [`TlsMaterial::load`], repeated here
    /// because a swap must never be able to install something inconsistent.
    pub fn certified_key(&self) -> Result<Arc<rustls::sign::CertifiedKey>, TlsError> {
        rustls::sign::CertifiedKey::from_der(self.chain.clone(), self.key.clone_key(), &provider())
            .map(Arc::new)
            .map_err(|e| TlsError::KeyMismatch(e.to_string()))
    }

    /// The identity anchor as PKCS#8 — for [`Announcer::new`]'s anchor
    /// (`crate::announcer::Announcer`). **Public since 0.8.1 (wish #4).**
    ///
    /// This is the ONE documented place the key CROSSES from the TLS domain
    /// into the §6 domain: the announcer signs announcements with the same
    /// identity the server serves. The first consumer to adopt §6 used the
    /// hidden test helper for this in production — the function did
    /// the right thing; the name and visibility lied. Now the crossing has a
    /// name. It is still not a general key-export: the output is PKCS#8 for
    /// the anchor construction, nothing else.
    ///
    /// **0.8.3:** the key is returned in locked memory (`krypto::SecretBuf`),
    /// never as a `Vec<u8>`. It is `Debug`-redacted, wiped on drop, and read
    /// only through `expose` — the secret-types rule applied to our own
    /// crossing.
    pub fn anchor_pkcs8(&self) -> Result<krypto::SecretBuf, TlsError> {
        let der = self.cert_chain()[0].as_ref().to_vec();
        crate::pkcs8::pkcs8_p256(self.key_der(), &der)
    }

    /// The private key in DER. **Crate-internal only** — the key must not
    /// leave `TlsMaterial`; it is meant to be used in here (the secret-types rule (secrets cross APIs only as krypto types)).
    pub(crate) fn key_der(&self) -> &PrivateKeyDer<'static> {
        &self.key
    }

    /// `ServerConfig` with TLS 1.3 + TLS 1.2, ALPN `h2, http/1.1`, and the
    /// default transport policy (**AES-256-GCM only** — [`TransportPolicy`]).
    ///
    /// **The cipher is the consumer's choice, not rustls' list** (SPEC-nettls
    /// §6.0b, decided 2026-09-04). The default offers one AEAD, the one every
    /// peer speaks — browsers included, since 2014. To offer
    /// more, or something else, use [`TlsMaterial::server_config_with`]. Up to
    /// 0.8.2 this was ring's full list (nine suites, AES-128 included).
    ///
    /// TLS 1.2 is included deliberately: without it, everything that is not
    /// TLS 1.3 drops off, including older browsers we have promised to keep.
    /// The policy covers both versions with the same AEAD.
    ///
    /// [`TransportPolicy`]: crate::transport::TransportPolicy
    pub fn server_config(&self) -> Result<Arc<ServerConfig>, TlsError> {
        self.server_config_with_alpn(&[b"h2".to_vec(), b"http/1.1".to_vec()])
    }

    /// Like [`TlsMaterial::server_config`], but with a custom ALPN list.
    ///
    /// Pass an empty list to turn ALPN off. To serve HTTP/1.1 without h2, use
    /// `&[b"http/1.1".to_vec()]` — but always keep `http/1.1` in the list if
    /// browsers are to reach the service.
    pub fn server_config_with_alpn(&self, alpn: &[Vec<u8>]) -> Result<Arc<ServerConfig>, TlsError> {
        self.server_config_with(alpn, &TransportPolicy::default())
    }

    /// Like [`TlsMaterial::server_config_with_alpn`], with an explicit
    /// [`TransportPolicy`](crate::transport::TransportPolicy) (0.8.3).
    pub fn server_config_with(
        &self,
        alpn: &[Vec<u8>],
        transport: &TransportPolicy,
    ) -> Result<Arc<ServerConfig>, TlsError> {
        // `builder_with_provider`, NEVER `builder()`: that keeps the provider
        // choice local and explicit instead of depending on process-global
        // state that a transitive dependency may have broken.
        let mut cfg = ServerConfig::builder_with_provider(transport.provider())
            .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
            .map_err(|e| TlsError::Rustls(e.to_string()))?
            .with_no_client_auth()
            .with_single_cert(self.chain.clone(), self.key.clone_key())
            .map_err(|e| TlsError::Rustls(e.to_string()))?;
        cfg.alpn_protocols = alpn.to_vec();
        // The consumer's order decides, not the peer's (SPEC-nettls §6.0b,
        // rule 3). rustls' default is to honour the CLIENT's preference.
        cfg.ignore_client_order = true;
        Ok(Arc::new(cfg))
    }

    /// Writes `cert.pem` (0644) and `key.pem` (0600) to `dir`, atomically.
    ///
    /// The directory is created if missing. The key file gets its permissions
    /// set **before** it becomes visible under its final name.
    pub fn save_pem(&self, dir: &Path) -> Result<(), TlsError> {
        fs::create_dir_all(dir).map_err(|e| TlsError::io(dir, e))?;

        let mut cert_pem = Vec::new();
        for c in &self.chain {
            cert_pem.extend_from_slice(&pem::encode("CERTIFICATE", c.as_ref()));
        }
        pem::write_atomic(&dir.join(CERT_FILE), &cert_pem, 0o644)?;

        let (label, der) = match &*self.key {
            PrivateKeyDer::Pkcs8(k) => ("PRIVATE KEY", k.secret_pkcs8_der()),
            PrivateKeyDer::Pkcs1(k) => ("RSA PRIVATE KEY", k.secret_pkcs1_der()),
            PrivateKeyDer::Sec1(k) => ("EC PRIVATE KEY", k.secret_sec1_der()),
            // `PrivateKeyDer` is #[non_exhaustive]; an unknown variant must
            // give an honest error, not a half-written key file.
            _ => {
                return Err(TlsError::Pem(
                    "unknown private key format — cannot be written as PEM".to_string(),
                ))
            }
        };
        // The PEM form of the key lives in locked memory until it is on disk.
        let key_pem = secret::hold(pem::encode(label, der))?;
        key_pem.expose(|k| pem::write_atomic(&dir.join(KEY_FILE), k, 0o600))
    }
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Extracts the validity window, SAN list and subject from the leaf DER.
fn inspect(leaf: &CertificateDer<'_>) -> Result<(i64, i64, Vec<String>, String), TlsError> {
    let (_rest, cert) = x509_parser::certificate::X509Certificate::from_der(leaf.as_ref())
        .map_err(|e| TlsError::Certificate(e.to_string()))?;

    let not_before = cert.validity().not_before.timestamp();
    let not_after = cert.validity().not_after.timestamp();
    let subject = cert.subject().to_string();

    let mut sans = Vec::new();
    if let Ok(Some(ext)) = cert.subject_alternative_name() {
        for name in &ext.value.general_names {
            use x509_parser::extensions::GeneralName;
            match name {
                GeneralName::DNSName(s) => sans.push((*s).to_string()),
                GeneralName::IPAddress(b) => sans.push(format_ip(b)),
                other => sans.push(format!("{other}")),
            }
        }
    }

    Ok((not_before, not_after, sans, subject))
}

fn format_ip(bytes: &[u8]) -> String {
    match bytes.len() {
        4 => {
            let mut a = [0u8; 4];
            a.copy_from_slice(bytes);
            IpAddr::from(a).to_string()
        }
        16 => {
            let mut a = [0u8; 16];
            a.copy_from_slice(bytes);
            IpAddr::from(a).to_string()
        }
        n => format!("<IP SAN with {n} bytes>"),
    }
}

/// Generates a self-signed ECDSA P-256 certificate.
fn generate(
    params: &SelfSignedParams,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), TlsError> {
    if params.sans.is_empty() {
        return Err(TlsError::Params(
            "the SAN list is empty — modern browsers ignore the CN and require SANs, so such a \
             certificate would be rejected. Include every name and every IP the operators use."
                .to_string(),
        ));
    }
    if params.valid_days == 0 || params.valid_days > MAX_VALID_DAYS {
        return Err(TlsError::Params(format!(
            "valid_days = {} is outside 1..={MAX_VALID_DAYS} (Safari/Chrome reject longer \
             lifetimes, self-signed included)",
            params.valid_days
        )));
    }
    // The minimum requirement in SPEC-nettls also applies to configuration input,
    // not just data from the network. Without this, an empty string, 300 characters,
    // spaces and `..` went straight into the certificate — and the result was a
    // certificate that silently matched nothing, where the operator met a cryptic
    // browser error instead of a clear startup error (case L2-054).
    validate_common_name(&params.common_name)?;
    for san in &params.sans {
        validate_san_name(san, "SAN")?;
    }

    let mut p = rcgen::CertificateParams::new(params.sans.clone())
        .map_err(|e| TlsError::Generate(e.to_string()))?;
    p.distinguished_name
        .push(rcgen::DnType::CommonName, params.common_name.clone());

    let now = time::OffsetDateTime::now_utc();
    // One hour backwards: clock skew between container and client must not
    // give "certificate is not yet valid" right after generation.
    p.not_before = now - time::Duration::hours(1);
    p.not_after = now + time::Duration::days(i64::from(params.valid_days));

    // ECDSA P-256 and not RSA — partly because rcgen with the ring backend
    // *cannot* make RSA (`KeyGenerationUnavailable`), partly because ECDSA
    // gives BETTER backwards compatibility: Win7/IE11 has ECDHE_ECDSA+GCM,
    // but not ECDHE_RSA+GCM. Ed25519 would have been tempting, but is not
    // supported by any mainstream browser.
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
        .map_err(|e| TlsError::Generate(e.to_string()))?;
    let cert = p
        .self_signed(&key)
        .map_err(|e| TlsError::Generate(e.to_string()))?;

    let chain = vec![cert.der().clone()];
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
    Ok((chain, key_der))
}

/// Maximum total length of a DNS name in a certificate (RFC 1035).
const MAX_DNS_NAME: usize = 253;
/// Maximum length of a single label between the dots (RFC 1035).
const MAX_DNS_LABEL: usize = 63;

/// Is this a name that can appear as a SAN in a certificate?
///
/// Exists for consumers that **auto-detect** names themselves (the container's
/// hostname, the machine's IPs) and need to discard an unusable find silently.
/// The asymmetry is the point: a name the *operator* supplied must fail loudly
/// at startup, while our own best-effort guess must never be able to stop a
/// service from starting. Without this, the consumer would have to duplicate
/// the rules, and two copies of a rule is one copy that sooner or later drifts.
///
/// Validates one name that is to go into a certificate — SAN or CN.
///
/// **IP addresses are accepted without further checks.** They are not a
/// special case we tolerate, but a supported and necessary usage: without an
/// IP SAN, `https://<ip>:8443` fails with `ERR_CERT_COMMON_NAME_INVALID`, and
/// that is considerably harder for the operator to get past than an ordinary
/// self-signed warning. A validation that only accepted DNS names would break
/// something that works today.
///
/// For everything else, RFC 1035/1123 applies: 1–253 characters in total,
/// labels of 1–63 characters with `a-z 0-9 -`, and no hyphen first or last in
/// a label. A wildcard is accepted as the **first** label (`*.example.no`)
/// because that is legitimate and in use; `*` anywhere else is meaningless in
/// a certificate name.
///
/// We check **syntax, not existence** — no DNS lookups. A service that must
/// resolve names in order to start is a service that does not start when name
/// resolution is down.
pub fn is_valid_san(name: &str) -> bool {
    validate_san_name(name, "SAN").is_ok()
}

fn validate_san_name(name: &str, field: &str) -> Result<(), TlsError> {
    if name.is_empty() {
        return Err(TlsError::Params(format!(
            "{field} is an empty string — a name must have content to be able to match anything"
        )));
    }
    // IPs (both `127.0.0.1` and `::1`) are already fully validated by the parser itself.
    if name.parse::<std::net::IpAddr>().is_ok() {
        return Ok(());
    }
    if name.len() > MAX_DNS_NAME {
        return Err(TlsError::Params(format!(
            "{field} {name:?} is {} characters — a DNS name can be at most {MAX_DNS_NAME}",
            name.len()
        )));
    }
    // A single trailing dot (absolute name, "example.no.") is legal in DNS,
    // but yields an empty last label. We strip it before the label check
    // instead of rejecting a name that is formally correct.
    let body = name.strip_suffix('.').unwrap_or(name);
    if body.is_empty() {
        return Err(TlsError::Params(format!(
            "{field} {name:?} consists only of dots"
        )));
    }
    for (i, label) in body.split('.').enumerate() {
        if label.is_empty() {
            return Err(TlsError::Params(format!(
                "{field} {name:?} has an empty part between the dots — two dots in a row, \
                 or a leading dot"
            )));
        }
        if label.len() > MAX_DNS_LABEL {
            return Err(TlsError::Params(format!(
                "{field} {name:?}: the part {label:?} is {} characters — at most {MAX_DNS_LABEL} \
                 between the dots",
                label.len()
            )));
        }
        // Wildcard: only as the entire first label. `*.example.no` is valid
        // and in use; `ap*.example.no` and `example.*.no` are not.
        if label == "*" {
            if i == 0 {
                continue;
            }
            return Err(TlsError::Params(format!(
                "{field} {name:?}: a wildcard is only legal as the first part (`*.example.no`)"
            )));
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(TlsError::Params(format!(
                "{field} {name:?}: the part {label:?} starts or ends with a hyphen"
            )));
        }
        if let Some(c) = label
            .chars()
            .find(|c| !(c.is_ascii_alphanumeric() || *c == '-'))
        {
            return Err(TlsError::Params(format!(
                "{field} {name:?} contains the illegal character {c:?} — a DNS name can only \
                 have letters, digits, hyphens and dots. (If this is meant as an \
                 IP address, it must be written so that it parses as one.)"
            )));
        }
    }
    Ok(())
}

/// Maximum length of the CN in X.509 (`ub-common-name`, RFC 5280).
const MAX_COMMON_NAME: usize = 64;

/// Validates the CN — which is something **other** than a SAN.
///
/// The CN is a human-readable subject field, not a hostname. Modern browsers
/// read the SAN and ignore the CN completely; what the CN does is be the text
/// the operator sees in the certificate viewer. The crate's own default is
/// therefore `"nettls self-signed"` — with a space, and fully legal.
///
/// (The first attempt validated the CN with DNS rules. That toppled seven
/// existing tests immediately, and rightly so: `"example portal"` is a
/// perfectly fine CN. The rule is strict where the name has to *match*
/// something, and loose where it only has to be *read*.)
///
/// We therefore only require that it is something sensible: not empty, within
/// X.509's length limit, and without control characters — the latter because
/// they do not belong in a subject and can do ugly things in a terminal that
/// displays the certificate.
fn validate_common_name(cn: &str) -> Result<(), TlsError> {
    if cn.trim().is_empty() {
        return Err(TlsError::Params(
            "common_name is empty — this is the text the operator sees in the certificate viewer"
                .to_string(),
        ));
    }
    if cn.chars().count() > MAX_COMMON_NAME {
        return Err(TlsError::Params(format!(
            "common_name is {} characters — X.509 allows at most {MAX_COMMON_NAME}",
            cn.chars().count()
        )));
    }
    if let Some(c) = cn.chars().find(|c| c.is_control()) {
        return Err(TlsError::Params(format!(
            "common_name contains the control character {c:?} — it does not belong in a subject, \
             and can distort the display wherever the certificate is shown"
        )));
    }
    Ok(())
}

/// The SHA-256 fingerprint of a certificate in DER — the same value as
/// [`TlsMaterial::fingerprint_sha256`], but for a certificate we have merely
/// seen.
///
/// Used when we connect **unverified just to read** the peer's identity and
/// show it to the operator (observing an identity is not trusting it —
/// the certificate is sent in cleartext in every handshake anyway).
pub fn cert_fingerprint_sha256(cert_der: &[u8]) -> String {
    krypto::hex::encode(&sha256(cert_der))
}
