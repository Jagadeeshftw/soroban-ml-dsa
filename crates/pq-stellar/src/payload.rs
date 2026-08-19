//! Soroban authorization signature payload.
//!
//! This is the part of the integration that is easy to get subtly wrong, so it
//! lives in one place with the derivation spelled out.
//!
//! When a contract account is invoked, the Soroban host computes a 32-byte
//! `signature_payload` and passes it to `__check_auth`. The signer must produce
//! a signature over *exactly* those bytes. The payload is
//!
//! ```text
//! SHA-256( XDR( HashIdPreimage::SorobanAuthorization {
//!     network_id,                    // SHA-256 of the network passphrase
//!     nonce,                         // replay protection, unique per account
//!     signature_expiration_ledger,   // ledger after which the signature is dead
//!     invocation,                    // the full call tree being authorized
//! }))
//! ```
//!
//! Everything an attacker could otherwise vary is already bound in by the host:
//! the network (so a testnet signature cannot be replayed on mainnet), the nonce
//! (so a signature cannot be replayed at all), the expiry, and the entire
//! invocation tree including arguments (so "transfer 1 XLM" cannot be swapped
//! for "transfer 1000 XLM"). A custom account's job is to verify the signature
//! over these bytes and not to undo any of that.

use sha2::{Digest, Sha256};
use stellar_xdr::{
    Hash, HashIdPreimage, HashIdPreimageSorobanAuthorization, Limits, SorobanAuthorizedInvocation,
    WriteXdr,
};

use crate::error::StellarError;

/// Derive a network id from its passphrase.
///
/// `"Test SDF Network ; September 2015"` for testnet,
/// `"Public Global Stellar Network ; September 2015"` for mainnet.
#[must_use]
pub fn network_id(passphrase: &str) -> [u8; 32] {
    Sha256::digest(passphrase.as_bytes()).into()
}

/// Testnet passphrase.
pub const TESTNET_PASSPHRASE: &str = "Test SDF Network ; September 2015";
/// Mainnet passphrase.
pub const MAINNET_PASSPHRASE: &str = "Public Global Stellar Network ; September 2015";

/// The inputs the host binds into a Soroban authorization signature.
#[derive(Debug, Clone)]
pub struct AuthorizationPayload {
    pub network_id: [u8; 32],
    pub nonce: i64,
    pub signature_expiration_ledger: u32,
    pub invocation: SorobanAuthorizedInvocation,
}

impl AuthorizationPayload {
    /// Compute the 32 bytes the signer must sign.
    ///
    /// Must match what the host computes byte-for-byte; a mismatch shows up as
    /// an authorization failure with no further diagnostic, so this is worth
    /// testing against a real network rather than only against itself.
    pub fn signature_payload(&self) -> Result<[u8; 32], StellarError> {
        let preimage = HashIdPreimage::SorobanAuthorization(HashIdPreimageSorobanAuthorization {
            network_id: Hash(self.network_id),
            nonce: self.nonce,
            signature_expiration_ledger: self.signature_expiration_ledger,
            invocation: self.invocation.clone(),
        });
        let bytes = preimage
            .to_xdr(Limits::none())
            .map_err(|_| StellarError::Xdr("failed to encode HashIdPreimage"))?;
        Ok(Sha256::digest(&bytes).into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn network_ids_are_the_known_constants() {
        // These are fixed by the passphrases and are worth pinning: a wrong
        // network id produces signatures that fail with no useful error.
        assert_eq!(
            hex::encode(network_id(TESTNET_PASSPHRASE)),
            "cee0302d59844d32bdca915c8203dd44b33fbb7edc19051ea37abedf28ecd472"
        );
        assert_eq!(
            hex::encode(network_id(MAINNET_PASSPHRASE)),
            "7ac33997544e3175d266bd022439b22cdb16508c01163f26e5cb2a3e1045a979"
        );
    }
}
