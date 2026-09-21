// SPDX-License-Identifier: MIT OR Apache-2.0
//! `cert_fingerprint_sha256` — the way into "observing is not trusting": we
//! connect unverified only to *read* the peer's identity and show it to the
//! operator. (Salvaged from the retired §5 test suite; the function moved to
//! `material` when `rotation` was removed in 0.8.2.)

use nettls::{CertSource, SelfSignedParams, TlsMaterial};

#[test]
fn fingerprint_of_seen_certificate_is_same_value() {
    let m = TlsMaterial::load(&CertSource::self_signed(SelfSignedParams::new(
        "observed-peer",
        ["observed-peer"],
    )))
    .unwrap();
    let der = m.cert_chain()[0].as_ref().to_vec();
    assert_eq!(
        nettls::cert_fingerprint_sha256(&der),
        m.fingerprint_sha256()
    );
}
