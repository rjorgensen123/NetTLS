// SPDX-License-Identifier: MIT OR Apache-2.0
//! Version guard.
//!
//! `Cargo.toml` is the only place the version is written. The crate's `VERSION`
//! constant and the Python twin's `__version__` both derive from it, so there is
//! nothing here comparing them against each other — a derived value cannot drift
//! from its source, and a test that asserts it does not is a test that asserts
//! nothing. Until 0.8.6 the version stood in three files kept in step by tests;
//! now it stands in one.
//!
//! What can still drift is the changelog. A version can be cut without anyone
//! writing down what changed in it, and that is what this file catches.

#[test]
fn changelog_has_an_entry_for_the_current_version() {
    let changelog = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/CHANGELOG.md"))
        .expect("CHANGELOG.md must exist");
    let heading = format!("## [{}]", env!("CARGO_PKG_VERSION"));
    assert!(
        changelog.contains(&heading),
        "CHANGELOG.md has no «{heading}» entry — a cut version without a changelog entry \
         is a version nobody can migrate to"
    );
}

/// 0.8.2: the `VERSION` constant must mirror Cargo.toml (the anchor that says
/// which feature set is active).
#[test]
fn version_constant_mirrors_cargo_toml() {
    assert_eq!(nettls::VERSION, env!("CARGO_PKG_VERSION"));
}
