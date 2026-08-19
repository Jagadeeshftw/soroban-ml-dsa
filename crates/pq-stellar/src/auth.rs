//! Building Soroban authorization entries signed with a post-quantum scheme.
//!
//! Everything here is generic over [`PqScheme`]. Nothing in this module names
//! ML-DSA, and adding SLH-DSA or Falcon requires no change to it — which is the
//! property the `pq-core` trait layer exists to provide.

use pq_core::{PqEncode, PqScheme, PqSigner, PqVerifier};
use stellar_xdr::{
    ScAddress, ScBytes, ScVal, SorobanAddressCredentials, SorobanAuthorizationEntry,
    SorobanCredentials,
};

use crate::error::StellarError;
use crate::payload::AuthorizationPayload;

/// Sign a Soroban authorization payload with a post-quantum signing key.
///
/// `context` is the FIPS domain-separation string. Pass `&[]` unless the
/// account contract expects a specific one — and if it does, the contract and
/// the signer must agree exactly, or verification fails.
pub fn sign_authorization<S: PqScheme>(
    signing_key: &S::SigningKey,
    payload: &AuthorizationPayload,
    context: &[u8],
) -> Result<Vec<u8>, StellarError> {
    let msg = payload.signature_payload()?;
    let mut sig = vec![0u8; S::SIGNATURE_LEN];
    let n = signing_key.sign_into(&msg, context, &mut sig)?;
    sig.truncate(n);
    Ok(sig)
}

/// Build a complete authorization entry for a post-quantum contract account.
///
/// The resulting entry goes in the `auth` field of an `InvokeHostFunctionOp`.
/// The signature is carried as `ScVal::Bytes`, which is what a contract
/// declaring `type Signature = Bytes` in its `CustomAccountInterface`
/// receives.
pub fn build_auth_entry<S: PqScheme>(
    account: ScAddress,
    signing_key: &S::SigningKey,
    payload: AuthorizationPayload,
    context: &[u8],
) -> Result<SorobanAuthorizationEntry, StellarError> {
    let sig = sign_authorization::<S>(signing_key, &payload, context)?;
    Ok(SorobanAuthorizationEntry {
        credentials: SorobanCredentials::Address(SorobanAddressCredentials {
            address: account,
            nonce: payload.nonce,
            signature_expiration_ledger: payload.signature_expiration_ledger,
            signature: bytes_to_scval(&sig)?,
        }),
        root_invocation: payload.invocation,
    })
}

/// Encode a verifying key for storage in a contract's instance state.
///
/// The account contract reads this back as `Bytes` and passes it to
/// [`PqVerifier::from_bytes`].
pub fn encode_verifying_key<S: PqScheme>(vk: &S::VerifyingKey) -> Result<ScVal, StellarError> {
    let mut buf = vec![0u8; S::VERIFYING_KEY_LEN];
    let n = vk.write_to(&mut buf)?;
    buf.truncate(n);
    bytes_to_scval(&buf)
}

/// Verify a signature against a Soroban authorization payload off-chain.
///
/// Useful for checking a signature before paying to submit it, and for testing
/// an account contract's expectations without a network round-trip.
pub fn verify_authorization<S: PqScheme>(
    verifying_key: &S::VerifyingKey,
    payload: &AuthorizationPayload,
    context: &[u8],
    signature: &[u8],
) -> Result<(), StellarError> {
    let msg = payload.signature_payload()?;
    verifying_key.verify(&msg, context, signature)?;
    Ok(())
}

fn bytes_to_scval(b: &[u8]) -> Result<ScVal, StellarError> {
    Ok(ScVal::Bytes(ScBytes(
        b.to_vec()
            .try_into()
            .map_err(|_| StellarError::Encoding("byte string exceeds XDR limit"))?,
    )))
}

/// Stable on-chain discriminant for a scheme.
///
/// A contract account supporting more than one scheme needs to record which
/// one a stored key belongs to. Deriving this from [`PqScheme::NAME`] keeps the
/// mapping in one place rather than scattered across contract code.
///
/// Values are explicit and must never be renumbered — they may be persisted in
/// ledger state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum SchemeId {
    MlDsa44 = 1,
    MlDsa65 = 2,
    MlDsa87 = 3,
    SlhDsaSha2_128s = 4,
    Falcon512 = 5,
}

impl SchemeId {
    /// Resolve the discriminant for a scheme, by its `PqScheme::NAME`.
    #[must_use]
    pub fn of<S: PqScheme>() -> Option<Self> {
        Self::from_name(S::NAME)
    }

    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        Some(match name {
            "ML-DSA-44" => Self::MlDsa44,
            "ML-DSA-65" => Self::MlDsa65,
            "ML-DSA-87" => Self::MlDsa87,
            "SLH-DSA-SHA2-128s" => Self::SlhDsaSha2_128s,
            "FN-DSA-512" | "Falcon-512" => Self::Falcon512,
            _ => return None,
        })
    }
}
