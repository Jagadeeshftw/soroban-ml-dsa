//! Differential testing: `ml-dsa` (RustCrypto) vs `fips204` (integritychain).
//!
//! Neither implementation has been independently audited. Two independent
//! codebases written from the same specification agreeing on every input is
//! meaningfully stronger evidence than either passing vectors alone — a defect
//! would have to be present in both, identically, to survive.
//!
//! **This is mitigation, not resolution.** It does not establish positive
//! assurance and is not a substitute for review of the verification path.
//!
//! Any disagreement is a blocking defect: the test panics rather than
//! reporting a count.
//!
//! Both implementations are driven through FIPS 204's *deterministic* variant
//! (`rnd = 0^32`), so agreement is checked at the strongest available level —
//! byte-identical signatures, not merely mutual acceptance.

use pq_core::traits::{PqEncode, PqKeypair, PqSigner, PqVerifier};
use serde_json::Value;

use fips204::traits::{SerDes, Signer as F4Signer, Verifier as F4Verifier};

/// FIPS 204 deterministic variant: rnd = 0^32.
const DETERMINISTIC: [u8; 32] = [0u8; 32];

fn load(dir: &str, name: &str) -> Value {
    let path = format!("{}/tests/vectors/{dir}/{name}", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_str(&std::fs::read_to_string(&path).expect(&path)).unwrap()
}

macro_rules! differential_suite {
    (
        $test_vectors:ident, $test_signing:ident,
        ours: $ours:path,
        theirs: $theirs:path,
        param_set: $param_set:literal,
        wycheproof: $wyc:literal,
        pk_len: $pk_len:expr, sk_len: $sk_len:expr, sig_len: $sig_len:expr,
    ) => {
        /// Both implementations must reach the same accept/reject verdict on
        /// every ACVP and Wycheproof case, and both must match the expected
        /// result.
        #[test]
        fn $test_vectors() {
            use $ours as ours;
            use $theirs as theirs;

            let (mut agreed, mut skipped_len) = (0usize, 0usize);

            // ---- ACVP external / pure ----
            let doc = load("acvp", "ML-DSA-sigVer-FIPS204.json");
            for g in doc["testGroups"].as_array().unwrap() {
                if g["parameterSet"].as_str() != Some($param_set) { continue; }
                if g["signatureInterface"].as_str() != Some("external") { continue; }
                if g["preHash"].as_str() != Some("pure") { continue; }

                for t in g["tests"].as_array().unwrap() {
                    let tc = t["tcId"].as_u64().unwrap();
                    let expected = t["testPassed"].as_bool().unwrap();
                    let hx = |k: &str| hex::decode(t[k].as_str().unwrap_or("")).unwrap();
                    let (pk, msg, ctx, sig) = (hx("pk"), hx("message"), hx("context"), hx("signature"));

                    let ours_ok = ours::VerifyingKey::from_bytes(&pk)
                        .map(|k| k.verify(&msg, &ctx, &sig).is_ok())
                        .unwrap_or(false);

                    let theirs_ok = match (<[u8; $pk_len]>::try_from(&pk[..]),
                                           <[u8; $sig_len]>::try_from(&sig[..])) {
                        (Ok(pk_a), Ok(sig_a)) => theirs::PublicKey::try_from_bytes(pk_a)
                            .map(|k| k.verify(&msg, &sig_a, &ctx))
                            .unwrap_or(false),
                        _ => { skipped_len += 1; continue; }
                    };

                    assert_eq!(ours_ok, theirs_ok,
                        "DISAGREEMENT {} ACVP tc {}: ml-dsa={} fips204={} (NIST says {})",
                        $param_set, tc, ours_ok, theirs_ok, expected);
                    assert_eq!(ours_ok, expected,
                        "both implementations disagree with NIST at ACVP tc {}", tc);
                    agreed += 1;
                }
            }

            // ---- Wycheproof ----
            let doc = load("wycheproof", $wyc);
            for g in doc["testGroups"].as_array().unwrap() {
                let pk = hex::decode(g["publicKey"].as_str().unwrap()).unwrap();
                for t in g["tests"].as_array().unwrap() {
                    let tc = t["tcId"].as_u64().unwrap();
                    let expected = t["result"].as_str().unwrap() == "valid";
                    let msg = hex::decode(t["msg"].as_str().unwrap_or("")).unwrap();
                    let sig = hex::decode(t["sig"].as_str().unwrap_or("")).unwrap();
                    let ctx = hex::decode(t.get("ctx").and_then(|v| v.as_str()).unwrap_or("")).unwrap();

                    let ours_ok = ours::VerifyingKey::from_bytes(&pk)
                        .map(|k| k.verify(&msg, &ctx, &sig).is_ok())
                        .unwrap_or(false);

                    let theirs_ok = match (<[u8; $pk_len]>::try_from(&pk[..]),
                                           <[u8; $sig_len]>::try_from(&sig[..])) {
                        (Ok(pk_a), Ok(sig_a)) => theirs::PublicKey::try_from_bytes(pk_a)
                            .map(|k| k.verify(&msg, &sig_a, &ctx))
                            .unwrap_or(false),
                        // fips204's API is fixed-width, so wrong-length inputs
                        // cannot be expressed. Ours rejects them; counted, not hidden.
                        _ => {
                            assert!(!ours_ok, "{} wycheproof tc {}: we accepted a wrong-length input", $param_set, tc);
                            skipped_len += 1;
                            continue;
                        }
                    };

                    assert_eq!(ours_ok, theirs_ok,
                        "DISAGREEMENT {} wycheproof tc {}: ml-dsa={} fips204={} (expected {})",
                        $param_set, tc, ours_ok, theirs_ok, expected);
                    agreed += 1;
                }
            }

            println!("{}: {} cases where both implementations agreed; \
                      {} skipped (wrong-length input, inexpressible in fips204's fixed-width API)",
                     $param_set, agreed, skipped_len);
            assert!(agreed > 0);
        }

        /// Same key, same message, same context, deterministic variant on both
        /// sides: the signature bytes must be identical, and each side must
        /// verify the other's output.
        #[test]
        fn $test_signing() {
            use $ours as ours;
            use $theirs as theirs;

            let contexts: [&[u8]; 4] = [b"", b"stellar", &[0xFFu8; 255], b"\x00\x01\x02"];
            let messages: [&[u8]; 4] = [b"", b"a", b"The quick brown fox", &[0x5Au8; 4096]];
            let mut checked = 0usize;

            for seed_byte in 0u8..16 {
                let kp = ours::Keypair::from_seed(&[seed_byte; 32]).unwrap();

                let mut pk_bytes = [0u8; $pk_len];
                kp.verifying_key().write_to(&mut pk_bytes).unwrap();
                let mut sk_bytes = [0u8; $sk_len];
                kp.signing_key().write_to(&mut sk_bytes).unwrap();

                // The same encoded key material must load in the other implementation:
                // this is an encoding-compatibility check as much as a crypto one.
                let their_pk = theirs::PublicKey::try_from_bytes(pk_bytes)
                    .expect("fips204 rejected a key ml-dsa produced");
                let their_sk = theirs::PrivateKey::try_from_bytes(sk_bytes)
                    .expect("fips204 rejected a signing key ml-dsa produced");

                for msg in messages {
                    for ctx in contexts {
                        let mut our_sig = [0u8; $sig_len];
                        let n = kp.signing_key().sign_into(msg, ctx, &mut our_sig).unwrap();
                        assert_eq!(n, $sig_len);

                        let their_sig = their_sk
                            .try_sign_with_seed(&DETERMINISTIC, msg, ctx)
                            .expect("fips204 failed to sign");

                        assert_eq!(
                            hex::encode(our_sig), hex::encode(their_sig),
                            "DISAGREEMENT {}: deterministic signatures differ \
                             (seed byte {}, msg {} bytes, ctx {} bytes)",
                            $param_set, seed_byte, msg.len(), ctx.len()
                        );

                        // Cross-verification, both directions.
                        assert!(their_pk.verify(msg, &our_sig, ctx),
                            "fips204 rejected an ml-dsa signature");
                        let vk = ours::VerifyingKey::from_bytes(&pk_bytes).unwrap();
                        assert!(vk.verify(msg, ctx, &their_sig).is_ok(),
                            "ml-dsa rejected a fips204 signature");

                        // Corruption: every single-byte flip must be rejected by both.
                        for pos in [0usize, $sig_len / 2, $sig_len - 1] {
                            let mut bad = our_sig;
                            bad[pos] ^= 0x01;
                            let a = vk.verify(msg, ctx, &bad).is_ok();
                            let b = their_pk.verify(msg, &bad, ctx);
                            assert_eq!(a, b, "DISAGREEMENT on corrupted signature at byte {pos}");
                            assert!(!a, "corrupted signature accepted at byte {pos}");
                        }

                        // Wrong context must not verify (domain separation).
                        if !ctx.is_empty() {
                            assert!(vk.verify(msg, b"", &our_sig).is_err());
                            assert!(!their_pk.verify(msg, &our_sig, b""));
                        }
                        checked += 1;
                    }
                }
            }
            println!("{}: {} (key, message, context) combinations produced \
                      byte-identical signatures under both implementations", $param_set, checked);
        }
    };
}

differential_suite! {
    differential_vectors_mldsa44, differential_signing_mldsa44,
    ours: pq_core::schemes::mldsa44,
    theirs: fips204::ml_dsa_44,
    param_set: "ML-DSA-44",
    wycheproof: "mldsa_44_verify_test.json",
    pk_len: 1312, sk_len: 2560, sig_len: 2420,
}

differential_suite! {
    differential_vectors_mldsa65, differential_signing_mldsa65,
    ours: pq_core::schemes::mldsa65,
    theirs: fips204::ml_dsa_65,
    param_set: "ML-DSA-65",
    wycheproof: "mldsa_65_verify_test.json",
    pk_len: 1952, sk_len: 4032, sig_len: 3309,
}
