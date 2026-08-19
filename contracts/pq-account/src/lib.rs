#![no_std]
//! Soroban custom account authorising via a post-quantum signature.
//!
//! The verification logic lives in `pq-core`, which is also what the
//! client-side `pq-stellar` adapter uses. Contract and client therefore share
//! one implementation — a signature the client produces is verified by exactly
//! the code the client signed against, and a divergence would have to be a
//! divergence in `pq-core` itself.
//!
//! Parameter set is ML-DSA-65. Switching to ML-DSA-44 means changing the two
//! `use` lines and the two size constants; the logic below is unchanged,
//! because it is written against the `pq-core` traits rather than the scheme.

use soroban_sdk::auth::{Context, CustomAccountInterface};
use soroban_sdk::crypto::Hash;
use soroban_sdk::{contract, contracterror, contractimpl, contracttype, Bytes, Env, Vec};

use pq_core::schemes::mldsa65::{Scheme, VerifyingKey};
use pq_core::{PqEncode, PqScheme, PqVerifier};

const VK_LEN: usize = <Scheme as PqScheme>::VERIFYING_KEY_LEN; // 1952
const SIG_LEN: usize = <Scheme as PqScheme>::SIGNATURE_LEN; // 3309

/// Domain-separation context, bound into every signature this account accepts.
///
/// The client must pass the identical value. It prevents a signature produced
/// for some other contract using the same key from being replayed here.
const CONTEXT: &[u8] = b"pq-account-v1";

#[contracttype]
#[derive(Clone)]
pub enum DataKey {
    PubKey,
}

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
    /// Store the verifying key that guards this account.
    pub fn init(env: Env, pubkey: Bytes) -> Result<(), Error> {
        if pubkey.len() as usize != VK_LEN {
            return Err(Error::BadPubKeyLen);
        }
        // Reject a key that will not decode, rather than discovering it at the
        // first authorization attempt when the account is already unusable.
        let mut buf = [0u8; VK_LEN];
        pubkey.copy_into_slice(&mut buf);
        VerifyingKey::from_bytes(&buf).map_err(|_| Error::BadPubKeyLen)?;

        env.storage().instance().set(&DataKey::PubKey, &pubkey);
        Ok(())
    }

    /// A protected entry point requiring this account to authorize.
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
        let stored: Bytes = env
            .storage()
            .instance()
            .get(&DataKey::PubKey)
            .ok_or(Error::NotInited)?;

        if stored.len() as usize != VK_LEN {
            return Err(Error::BadPubKeyLen);
        }
        if signature.len() as usize != SIG_LEN {
            return Err(Error::BadSigLen);
        }

        let mut vk_buf = [0u8; VK_LEN];
        stored.copy_into_slice(&mut vk_buf);
        let mut sig_buf = [0u8; SIG_LEN];
        signature.copy_into_slice(&mut sig_buf);
        let mut msg = [0u8; 32];
        signature_payload.to_bytes().copy_into_slice(&mut msg);

        // Note the decode path used here is the *verifying* key path, which is
        // validated. `pq-core` documents that the signing-key decode can panic
        // on malicious input; nothing on this path touches it.
        let vk = VerifyingKey::from_bytes(&vk_buf).map_err(|_| Error::BadPubKeyLen)?;
        vk.verify(&msg, CONTEXT, &sig_buf)
            .map_err(|_| Error::SigVerifyFailed)
    }
}
