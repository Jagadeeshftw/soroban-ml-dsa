#![no_std]
use soroban_sdk::auth::{Context, CustomAccountInterface};
use soroban_sdk::crypto::Hash;
use soroban_sdk::{contract, contracterror, contractimpl, contracttype, Bytes, Env, Vec};
use ml_dsa::{MlDsa65, EncodedVerifyingKey, VerifyingKey, Signature};
use ml_dsa::signature::Verifier;

#[contracttype]
#[derive(Clone)]
pub enum DataKey { PubKey }

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum Error {
    NotInited = 1,
    BadPubKeyLen = 2,
    BadSigLen = 3,
    SigVerifyFailed = 4,
}

#[contract]
pub struct PqAccount;

#[contractimpl]
impl PqAccount {
    /// Store the ML-DSA-65 verifying key (1952 bytes) that guards this account.
    pub fn init(env: Env, pubkey: Bytes) -> Result<(), Error> {
        if pubkey.len() != 1952 { return Err(Error::BadPubKeyLen); }
        env.storage().instance().set(&DataKey::PubKey, &pubkey);
        Ok(())
    }

    /// A protected entry point: requires this account to authorize.
    pub fn protected(env: Env) -> u32 {
        env.current_contract_address().require_auth();
        42
    }
}

#[contractimpl]
impl CustomAccountInterface for PqAccount {
    type Signature = Bytes;
    type Error = Error;

    fn __check_auth(
        env: Env,
        signature_payload: Hash<32>,
        signature: Bytes,
        _auth_contexts: Vec<Context>,
    ) -> Result<(), Error> {
        let pk: Bytes = env.storage().instance()
            .get(&DataKey::PubKey).ok_or(Error::NotInited)?;

        let mut pk_a = [0u8; 1952];
        if pk.len() != 1952 { return Err(Error::BadPubKeyLen); }
        pk.copy_into_slice(&mut pk_a);

        let mut sig_a = [0u8; 3309];
        if signature.len() != 3309 { return Err(Error::BadSigLen); }
        signature.copy_into_slice(&mut sig_a);

        let mut msg = [0u8; 32];
        signature_payload.to_bytes().copy_into_slice(&mut msg);

        let enc = EncodedVerifyingKey::<MlDsa65>::from(pk_a);
        let vk = VerifyingKey::<MlDsa65>::decode(&enc);
        let s = Signature::<MlDsa65>::try_from(&sig_a[..]).map_err(|_| Error::BadSigLen)?;
        vk.verify(&msg, &s).map_err(|_| Error::SigVerifyFailed)
    }
}
