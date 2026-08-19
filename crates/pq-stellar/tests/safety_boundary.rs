//! Enforces the safety boundary inherited from `pq-core`.
//!
//! `pq-core` documents that `SigningKey::from_bytes` is trusted-input only: the
//! underlying `ml-dsa` `from_expanded` does not validate its input and its own
//! documentation states it can panic on a malformed or maliciously constructed
//! expanded signing key. This crate is the layer that would expose that to
//! network-supplied bytes, so it must never decode a signing key.
//!
//! Documenting that is not enough — a later refactor would quietly break it.
//! This test reads the crate's own source and fails if the boundary is crossed.

use std::fs;
use std::path::Path;

fn sources() -> Vec<(String, String)> {
    fn walk(dir: &Path, out: &mut Vec<(String, String)>) {
        for e in fs::read_dir(dir).unwrap().flatten() {
            let p = e.path();
            if p.is_dir() {
                walk(&p, out);
            } else if p.extension().is_some_and(|x| x == "rs") {
                out.push((
                    p.strip_prefix(env!("CARGO_MANIFEST_DIR")).unwrap().display().to_string(),
                    fs::read_to_string(&p).unwrap(),
                ));
            }
        }
    }
    let mut out = Vec::new();
    walk(&Path::new(env!("CARGO_MANIFEST_DIR")).join("src"), &mut out);
    assert!(!out.is_empty(), "found no sources to scan");
    out
}

/// No path in this crate may decode a signing key from bytes.
#[test]
fn no_signing_key_decode_path() {
    let mut violations = Vec::new();

    for (path, src) in sources() {
        for (n, line) in src.lines().enumerate() {
            // Ignore doc comments and comments -- the module docs discuss this
            // boundary by name, which is intended.
            let code = line.split("//").next().unwrap_or("");
            if code.trim().is_empty() {
                continue;
            }
            let mentions_signing_key = code.contains("SigningKey");
            let decodes = code.contains("from_bytes") || code.contains("from_expanded");
            if mentions_signing_key && decodes {
                violations.push(format!("{path}:{}: {}", n + 1, line.trim()));
            }
            // The deprecated, panicking constructor must never appear at all.
            if code.contains("from_expanded") {
                violations.push(format!("{path}:{}: from_expanded is forbidden here: {}", n + 1, line.trim()));
            }
        }
    }

    assert!(
        violations.is_empty(),
        "pq-stellar must never decode a signing key from bytes -- \
         `ml-dsa`'s from_expanded can panic on malicious input and this crate \
         is the layer exposed to network-supplied data. Use `PqKeypair::from_seed`, \
         or accept an already-constructed `&S::SigningKey`.\n\nViolations:\n  {}",
        violations.join("\n  ")
    );
}

/// Signing keys must only ever be borrowed from a caller who already holds one.
#[test]
fn signing_keys_are_only_borrowed() {
    for (path, src) in sources() {
        for (n, line) in src.lines().enumerate() {
            let code = line.split("//").next().unwrap_or("");
            if let Some(idx) = code.find("S::SigningKey") {
                let before = &code[..idx];
                assert!(
                    before.ends_with('&') || before.ends_with("type SigningKey = ")
                        || code.contains("type SigningKey"),
                    "{path}:{}: signing keys must be borrowed (&S::SigningKey), \
                     never taken by value or constructed here: {}",
                    n + 1,
                    line.trim()
                );
            }
        }
    }
}

/// The verifying-key path -- the one that does consume untrusted bytes -- is
/// the validated one, and must remain available.
#[test]
fn verifying_key_decode_is_the_untrusted_path() {
    use pq_core::{PqEncode, PqScheme};
    // Garbage of the right length must be handled without panicking, and
    // garbage of the wrong length must be rejected.
    type S = pq_core::schemes::mldsa65::Scheme;
    type Vk = <S as PqScheme>::VerifyingKey;
    let wrong_len = vec![0xABu8; 10];
    assert!(Vk::from_bytes(&wrong_len).is_err());
    let right_len_garbage = vec![0xABu8; <S as PqScheme>::VERIFYING_KEY_LEN];
    // Either decodes to a key that verifies nothing, or is rejected. Must not panic.
    let _ = Vk::from_bytes(&right_len_garbage);
}
