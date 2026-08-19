#![no_std]
//! Benchmark and verifier contract.
//!
//! Exposes in-contract ML-DSA verification alongside the native host-function
//! baselines, so guest-side and host-side cost are measured through the same
//! path with the same VM instantiation overhead. All ML-DSA logic comes from
//! `pq-core`; nothing scheme-specific is inlined.

use soroban_sdk::{contract, contractimpl, Bytes, BytesN, Env};

use pq_core::schemes::{mldsa44, mldsa65};
use pq_core::{PqEncode, PqVerifier};

#[contract]
pub struct Verifier;

#[contractimpl]
impl Verifier {
    /// Fixed VM instantiation + dispatch cost. Subtract to isolate real work.
    pub fn noop(_env: Env) -> bool {
        true
    }

    /// Full in-contract ML-DSA-65 verification.
    pub fn verify65(_env: Env, pk: Bytes, msg: Bytes, sig: Bytes) -> bool {
        let mut pk_b = [0u8; 1952];
        if pk.len() != 1952 { return false; }
        pk.copy_into_slice(&mut pk_b);
        let mut sig_b = [0u8; 3309];
        if sig.len() != 3309 { return false; }
        sig.copy_into_slice(&mut sig_b);
        let mut m = [0u8; 8192];
        let n = msg.len() as usize;
        if n > 8192 { return false; }
        msg.copy_into_slice(&mut m[..n]);

        match mldsa65::VerifyingKey::from_bytes(&pk_b) {
            Ok(vk) => vk.verify(&m[..n], &[], &sig_b).is_ok(),
            Err(_) => false,
        }
    }

    /// Full in-contract ML-DSA-44 verification.
    pub fn verify44(_env: Env, pk: Bytes, msg: Bytes, sig: Bytes) -> bool {
        let mut pk_b = [0u8; 1312];
        if pk.len() != 1312 { return false; }
        pk.copy_into_slice(&mut pk_b);
        let mut sig_b = [0u8; 2420];
        if sig.len() != 2420 { return false; }
        sig.copy_into_slice(&mut sig_b);
        let mut m = [0u8; 8192];
        let n = msg.len() as usize;
        if n > 8192 { return false; }
        msg.copy_into_slice(&mut m[..n]);

        match mldsa44::VerifyingKey::from_bytes(&pk_b) {
            Ok(vk) => vk.verify(&m[..n], &[], &sig_b).is_ok(),
            Err(_) => false,
        }
    }

    /// Verifying-key decode only: isolates ExpandA, mirroring CAP-0087's
    /// `MlDsa65DecodeVerifyingKey` cost type.
    pub fn decode65(_env: Env, pk: Bytes) -> bool {
        let mut pk_b = [0u8; 1952];
        if pk.len() != 1952 { return false; }
        pk.copy_into_slice(&mut pk_b);
        mldsa65::VerifyingKey::from_bytes(&pk_b).is_ok()
    }

    pub fn decode44(_env: Env, pk: Bytes) -> bool {
        let mut pk_b = [0u8; 1312];
        if pk.len() != 1312 { return false; }
        pk.copy_into_slice(&mut pk_b);
        mldsa44::VerifyingKey::from_bytes(&pk_b).is_ok()
    }

    /// Ed25519 via the existing host function.
    pub fn ed25519(env: Env, pk: BytesN<32>, msg: Bytes, sig: BytesN<64>) -> bool {
        env.crypto().ed25519_verify(&pk, &msg, &sig);
        true
    }

    /// ECDSA secp256r1 via the existing host function (CAP-0051).
    ///
    /// Hashes in-contract because the host function takes a `Hash<32>`; that
    /// also matches how the scheme is used in practice.
    pub fn secp256r1(env: Env, pk: BytesN<65>, msg: Bytes, sig: BytesN<64>) -> bool {
        let digest = env.crypto().sha256(&msg);
        env.crypto().secp256r1_verify(&pk, &digest, &sig);
        true
    }
}
