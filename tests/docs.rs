// SPDX-License-Identifier: MIT OR Apache-2.0
//! Doc guard (0.8.2): every public name in the crate
//! must appear in the shipped contract (`docs/API.md`). A surface change that
//! skips the docs fails `cargo test` — the same fence `tests/version.rs` puts
//! around VERSION/CHANGELOG.

use std::collections::BTreeSet;
use std::fs;

fn read(rel: &str) -> String {
    fs::read_to_string(format!("{}/{rel}", env!("CARGO_MANIFEST_DIR")))
        .unwrap_or_else(|e| panic!("cannot read {rel}: {e}"))
}

fn ident_prefix(s: &str) -> String {
    s.chars()
        .take_while(|c| c.is_alphanumeric() || *c == '_')
        .collect()
}

/// Every root re-export/const/module, and every `pub fn/const/struct/enum/
/// trait/type` in every source file (impl methods included — they are the
/// surface too).
fn pub_names() -> BTreeSet<String> {
    let mut names = BTreeSet::new();

    let lib = read("src/lib.rs");
    let mut rest = lib.as_str();
    while let Some(i) = rest.find("pub use ") {
        rest = &rest[i + 8..];
        let (Some(open), Some(close)) = (rest.find('{'), rest.find('}')) else {
            break;
        };
        if open < close {
            for n in rest[open + 1..close].split(',') {
                let n = n.trim();
                if !n.is_empty() && n.chars().all(|c| c.is_alphanumeric() || c == '_') {
                    names.insert(n.to_string());
                }
            }
        }
        rest = &rest[close..];
    }

    let dir = format!("{}/src", env!("CARGO_MANIFEST_DIR"));
    for entry in fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        let t = fs::read_to_string(&path).unwrap();
        for line in t.lines() {
            let l = line.trim_start();
            let l = l.strip_prefix("pub async ").unwrap_or(l);
            for p in [
                "pub fn ",
                "pub const ",
                "pub struct ",
                "pub enum ",
                "pub trait ",
                "pub type ",
                "pub mod ",
            ] {
                if let Some(r) = l.strip_prefix(p) {
                    let name = ident_prefix(r);
                    if !name.is_empty() {
                        names.insert(name);
                    }
                }
            }
        }
    }
    names
}

#[test]
fn every_public_name_is_in_the_contract_docs() {
    let names = pub_names();
    assert!(
        names.len() >= 180,
        "the extractor found suspiciously few names ({}) — is it broken?",
        names.len()
    );
    let text = read("docs/API.md");
    let missing: Vec<&String> = names
        .iter()
        .filter(|n| !text.contains(n.as_str()))
        .collect();
    assert!(
        missing.is_empty(),
        "docs/API.md does not mention these public names: {missing:?} — \
         the contract must follow the surface"
    );
}
