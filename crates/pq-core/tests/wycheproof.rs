//! Wycheproof adversarial vectors (C2SP/wycheproof, testvectors_v1).
//!
//! These are the cases a plausible-but-wrong verifier accepts: malformed hint
//! encodings, infinity-norm violations on the response vector, zero public
//! keys, wrong lengths, and over-long context strings. Every one must be
//! rejected.

use pq_core::traits::{PqEncode, PqVerifier};
use serde_json::Value;
use std::collections::BTreeMap;

fn load(name: &str) -> Value {
    let path = format!("{}/tests/vectors/wycheproof/{name}", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_str(&std::fs::read_to_string(&path).expect(&path)).unwrap()
}

/// Returns (passed, per-flag counts) or panics on the first disagreement.
fn run<V: PqVerifier>(file: &str) -> (usize, BTreeMap<String, usize>) {
    let doc = load(file);
    let mut n = 0usize;
    let mut by_flag: BTreeMap<String, usize> = BTreeMap::new();

    for g in doc["testGroups"].as_array().unwrap() {
        let pk_hex = g["publicKey"].as_str().unwrap();
        let pk_bytes = hex::decode(pk_hex).unwrap();
        // A group whose public key is itself invalid (wrong length) must be
        // rejected at decode; its tests are then vacuously rejected.
        let vk = V::from_bytes(&pk_bytes);

        for t in g["tests"].as_array().unwrap() {
            let tc = t["tcId"].as_u64().unwrap();
            let expect_valid = t["result"].as_str().unwrap() == "valid";
            let msg = hex::decode(t["msg"].as_str().unwrap_or("")).unwrap();
            let sig = hex::decode(t["sig"].as_str().unwrap_or("")).unwrap();
            let ctx = hex::decode(t.get("ctx").and_then(|v| v.as_str()).unwrap_or("")).unwrap();
            let comment = t["comment"].as_str().unwrap_or("");

            let got = match &vk {
                Ok(k) => k.verify(&msg, &ctx, &sig).is_ok(),
                Err(_) => false,
            };

            assert_eq!(
                got, expect_valid,
                "{file} tc {tc} ({comment}): expected valid={expect_valid}, got {got} \
                 -- flags {:?}",
                t["flags"]
            );

            for f in t["flags"].as_array().map(|a| a.as_slice()).unwrap_or(&[]) {
                *by_flag.entry(f.as_str().unwrap_or("?").to_string()).or_default() += 1;
            }
            n += 1;
        }
    }
    (n, by_flag)
}

#[test]
fn wycheproof_mldsa44() {
    use pq_core::schemes::mldsa44::VerifyingKey;
    let (n, flags) = run::<VerifyingKey>("mldsa_44_verify_test.json");
    println!("Wycheproof ML-DSA-44: {n} cases passed");
    for (f, c) in &flags {
        println!("   {f:<28} {c}");
    }
    assert!(n > 0);
}

#[test]
fn wycheproof_mldsa65() {
    use pq_core::schemes::mldsa65::VerifyingKey;
    let (n, flags) = run::<VerifyingKey>("mldsa_65_verify_test.json");
    println!("Wycheproof ML-DSA-65: {n} cases passed");
    for (f, c) in &flags {
        println!("   {f:<28} {c}");
    }
    assert!(n > 0);
}

/// The context limit is a property of the FIPS external interface, not of any
/// one implementation. Verify we enforce it rather than truncating.
#[test]
fn context_over_255_is_rejected() {
    use pq_core::schemes::mldsa65::{Keypair, VerifyingKey};
    use pq_core::traits::{PqKeypair, PqSigner};
    use pq_core::PqError;

    let kp = Keypair::from_seed(&[7u8; 32]).unwrap();
    let mut sig = vec![0u8; 3309];
    let long_ctx = vec![0xAAu8; 256];

    assert!(matches!(
        kp.signing_key().sign_into(b"m", &long_ctx, &mut sig),
        Err(PqError::ContextTooLong { actual: 256 })
    ));

    let mut vk_bytes = vec![0u8; 1952];
    kp.verifying_key().write_to(&mut vk_bytes).unwrap();
    let vk = VerifyingKey::from_bytes(&vk_bytes).unwrap();
    assert!(matches!(
        vk.verify(b"m", &long_ctx, &sig),
        Err(PqError::ContextTooLong { actual: 256 })
    ));

    // 255 is the boundary and must be accepted.
    let ok_ctx = vec![0xAAu8; 255];
    let n = kp.signing_key().sign_into(b"m", &ok_ctx, &mut sig).unwrap();
    assert_eq!(n, 3309);
    assert!(vk.verify(b"m", &ok_ctx, &sig).is_ok());
    // ...and the signature must not verify under a different context.
    assert!(vk.verify(b"m", &[], &sig).is_err());
}
