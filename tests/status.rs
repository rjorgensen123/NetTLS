// SPDX-License-Identifier: MIT OR Apache-2.0
//! The status report — nettls' About contribution: one truth, two views
//! (Summary for every user, Report for the admin surface), levels and
//! headlines owned by the crate.

use nettls::announcer::Status;
use nettls::generations::{Generation, Generations};
use nettls::status::{Level, PeerReport, PeerState, Report};
use nettls::{CertSource, SelfSignedParams, TlsMaterial};

fn material(valid_days: u32) -> TlsMaterial {
    TlsMaterial::load(&CertSource::self_signed(
        SelfSignedParams::new("status-test", ["status-test"]).valid_days(valid_days),
    ))
    .unwrap()
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

#[test]
fn quiet_state_is_ok_and_summary_is_safe_for_users() {
    let m = material(365);
    let r = Report::collect(now(), &m, None, vec![]);
    assert_eq!(r.level, Level::Ok);
    assert_eq!(r.headline, "TLS ok");
    assert_eq!(r.version, nettls::VERSION);

    let s = r.summary();
    let json = serde_json::to_value(&s).unwrap();
    // The general view carries exactly version, level and headline — no peer
    // names, no fingerprints, no operations detail.
    let obj = json.as_object().unwrap();
    assert_eq!(obj.len(), 3);
    assert!(
        obj.contains_key("version") && obj.contains_key("level") && obj.contains_key("headline")
    );
}

#[test]
fn broken_peer_is_alert_and_named_in_the_headline() {
    let m = material(365);
    let peers = vec![PeerReport::broken("service", "aa".repeat(32))];
    let r = Report::collect(now(), &m, None, peers);
    assert_eq!(r.level, Level::Alert);
    assert!(r.headline.contains("service"), "{}", r.headline);
    assert!(r.headline.contains("operator action required"));
}

#[test]
fn expiry_warning_is_warn_with_days_in_the_headline() {
    // The crate's own threshold (mode1_should_warn) fires well inside 5 days.
    let m = material(3);
    let r = Report::collect(now(), &m, None, vec![]);
    assert_eq!(r.level, Level::Warn);
    assert!(r.headline.contains("expires in"), "{}", r.headline);
    assert!(r.identity.expiry_warning);
}

#[test]
fn rotation_alarm_beats_warn_and_pending_reads_from_generations() {
    let m = material(365);
    let status = Status {
        waiting_for: vec!["gateway".into()],
        alarm: true,
        seconds_until_stop: 86_400,
    };
    let r = Report::collect(now(), &m, Some(&status), vec![]);
    assert_eq!(r.level, Level::Alert);
    assert!(r.headline.contains("gateway"), "{}", r.headline);

    // A peer with an announced next reads as RotationPending.
    let g = Generations::from_approval(Generation::from_der(m.cert_chain()[0].as_ref().to_vec()));
    let p = PeerReport::from_generations("gateway", &g);
    assert_eq!(p.state, PeerState::Ok); // bootstrap: nothing pending
    assert_eq!(p.current_fingerprint, m.fingerprint_sha256());
}
