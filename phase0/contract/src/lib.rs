#![no_std]
use soroban_sdk::{contract, contractimpl, Bytes, Env};
use ml_dsa::{MlDsa44, MlDsa65, EncodedVerifyingKey, VerifyingKey, Signature};
use ml_dsa::signature::Verifier;

#[contract]
pub struct PqProbe;

#[contractimpl]
impl PqProbe {
    /// Full in-contract ML-DSA-65 verification.
    pub fn verify(_env: Env, pk: Bytes, msg: Bytes, sig: Bytes) -> bool {
        let mut pk_a = [0u8; 1952];
        if pk.len() != 1952 { return false; }
        pk.copy_into_slice(&mut pk_a);

        let mut sig_a = [0u8; 3309];
        if sig.len() != 3309 { return false; }
        sig.copy_into_slice(&mut sig_a);

        let mut msg_a = [0u8; 256];
        let mlen = msg.len() as usize;
        if mlen > 256 { return false; }
        msg.copy_into_slice(&mut msg_a[..mlen]);

        let enc = EncodedVerifyingKey::<MlDsa65>::from(pk_a);
        let vk = VerifyingKey::<MlDsa65>::decode(&enc);
        let s = match Signature::<MlDsa65>::try_from(&sig_a[..]) { Ok(s) => s, Err(_) => return false };
        vk.verify(&msg_a[..mlen], &s).is_ok()
    }

    /// Key decode / matrix expansion only (isolates the ExpandA cost).
    pub fn decode_only(_env: Env, pk: Bytes) -> bool {
        let mut pk_a = [0u8; 1952];
        if pk.len() != 1952 { return false; }
        pk.copy_into_slice(&mut pk_a);
        let enc = EncodedVerifyingKey::<MlDsa65>::from(pk_a);
        let _vk = VerifyingKey::<MlDsa65>::decode(&enc);
        true
    }

    /// No-op: measures fixed VM instantiation + dispatch overhead.
    pub fn noop(_env: Env) -> bool { true }

    /// Full in-contract ML-DSA-44 verification.
    pub fn verify44(_env: Env, pk: Bytes, msg: Bytes, sig: Bytes) -> bool {
        let mut pk_a = [0u8; 1312];
        if pk.len() != 1312 { return false; }
        pk.copy_into_slice(&mut pk_a);
        let mut sig_a = [0u8; 2420];
        if sig.len() != 2420 { return false; }
        sig.copy_into_slice(&mut sig_a);
        let mut msg_a = [0u8; 256];
        let mlen = msg.len() as usize;
        if mlen > 256 { return false; }
        msg.copy_into_slice(&mut msg_a[..mlen]);
        let enc = EncodedVerifyingKey::<MlDsa44>::from(pk_a);
        let vk = VerifyingKey::<MlDsa44>::decode(&enc);
        let s = match Signature::<MlDsa44>::try_from(&sig_a[..]) { Ok(s) => s, Err(_) => return false };
        vk.verify(&msg_a[..mlen], &s).is_ok()
    }

    /// Ed25519 baseline via the existing host function.
    pub fn ed25519(env: Env, pk: Bytes, msg: Bytes, sig: Bytes) -> bool {
        let pk32: soroban_sdk::BytesN<32> = pk.try_into().unwrap();
        let sig64: soroban_sdk::BytesN<64> = sig.try_into().unwrap();
        env.crypto().ed25519_verify(&pk32, &msg, &sig64);
        true
    }
}
