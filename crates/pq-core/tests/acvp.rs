//! NIST ACVP conformance vectors (FIPS 204).
//!
//! Source: usnistgov/ACVP-Server, gen-val/json-files/ML-DSA-{sigVer,keyGen}-FIPS204.
//!
//! We exercise the **external / pure** sigVer groups, because that is the
//! interface `PqVerifier::verify` exposes (FIPS 204 Algorithm 3). The
//! internal-interface groups cannot be replayed through an external API by
//! construction and are counted as skipped rather than silently ignored.

use pq_core::traits::{PqEncode, PqKeypair, PqVerifier};
use serde_json::Value;

fn load(name: &str) -> Value {
    let path = format!("{}/tests/vectors/acvp/{name}", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_str(&std::fs::read_to_string(&path).expect(&path)).unwrap()
}

fn hx(v: &Value, k: &str) -> Vec<u8> {
    hex::decode(v.get(k).and_then(|x| x.as_str()).unwrap_or("")).unwrap()
}

/// Run every external/pure sigVer case for one parameter set.
fn sig_ver<V: PqVerifier>(param_set: &str) -> (usize, usize) {
    let doc = load("ML-DSA-sigVer-FIPS204.json");
    let (mut run, mut skipped) = (0usize, 0usize);

    for g in doc["testGroups"].as_array().unwrap() {
        if g["parameterSet"].as_str() != Some(param_set) {
            continue;
        }
        let external = g["signatureInterface"].as_str() == Some("external");
        let pure = g["preHash"].as_str() == Some("pure");
        if !(external && pure) {
            skipped += g["tests"].as_array().unwrap().len();
            continue;
        }

        for t in g["tests"].as_array().unwrap() {
            let tc = t["tcId"].as_u64().unwrap();
            let expected = t["testPassed"].as_bool().unwrap();
            let reason = t["reason"].as_str().unwrap_or("");

            let vk = V::from_bytes(&hx(t, "pk"))
                .unwrap_or_else(|e| panic!("tc {tc}: public key rejected: {e}"));
            let got = vk
                .verify(&hx(t, "message"), &hx(t, "context"), &hx(t, "signature"))
                .is_ok();

            assert_eq!(
                got, expected,
                "{param_set} tc {tc}: expected testPassed={expected}, got {got} \
                 (ACVP reason: {reason:?}) -- ACCEPTING A BAD SIGNATURE OR \
                 REJECTING A GOOD ONE IS A BLOCKING DEFECT"
            );
            run += 1;
        }
    }
    (run, skipped)
}

#[test]
fn acvp_sigver_mldsa44() {
    use pq_core::schemes::mldsa44::VerifyingKey;
    let (run, skipped) = sig_ver::<VerifyingKey>("ML-DSA-44");
    println!("ACVP sigVer ML-DSA-44: {run} external/pure cases passed, {skipped} internal-interface cases skipped");
    assert!(run > 0, "no ACVP cases ran -- vectors missing?");
}

#[test]
fn acvp_sigver_mldsa65() {
    use pq_core::schemes::mldsa65::VerifyingKey;
    let (run, skipped) = sig_ver::<VerifyingKey>("ML-DSA-65");
    println!("ACVP sigVer ML-DSA-65: {run} external/pure cases passed, {skipped} internal-interface cases skipped");
    assert!(run > 0, "no ACVP cases ran -- vectors missing?");
}

/// Seed -> (pk, sk) derivation must match NIST byte-for-byte.
fn key_gen<K: PqKeypair>(param_set: &str, vk_len: usize, sk_len: usize) -> usize {
    let doc = load("ML-DSA-keyGen-FIPS204.json");
    let mut run = 0usize;
    for g in doc["testGroups"].as_array().unwrap() {
        if g["parameterSet"].as_str() != Some(param_set) {
            continue;
        }
        for t in g["tests"].as_array().unwrap() {
            let tc = t["tcId"].as_u64().unwrap();
            let kp = K::from_seed(&hx(t, "seed")).unwrap();

            let mut vk = vec![0u8; vk_len];
            kp.verifying_key().write_to(&mut vk).unwrap();
            assert_eq!(hex::encode(&vk), hex::encode(hx(t, "pk")), "{param_set} tc {tc}: pk mismatch");

            let mut sk = vec![0u8; sk_len];
            kp.signing_key().write_to(&mut sk).unwrap();
            assert_eq!(hex::encode(&sk), hex::encode(hx(t, "sk")), "{param_set} tc {tc}: sk mismatch");
            run += 1;
        }
    }
    run
}

#[test]
fn acvp_keygen_mldsa44() {
    use pq_core::schemes::mldsa44::Keypair;
    let n = key_gen::<Keypair>("ML-DSA-44", 1312, 2560);
    println!("ACVP keyGen ML-DSA-44: {n} cases matched pk and sk byte-for-byte");
    assert!(n > 0);
}

#[test]
fn acvp_keygen_mldsa65() {
    use pq_core::schemes::mldsa65::Keypair;
    let n = key_gen::<Keypair>("ML-DSA-65", 1952, 4032);
    println!("ACVP keyGen ML-DSA-65: {n} cases matched pk and sk byte-for-byte");
    assert!(n > 0);
}
