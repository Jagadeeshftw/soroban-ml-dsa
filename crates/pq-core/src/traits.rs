//! The scheme-agnostic trait layer.
//!
//! Nothing here mentions ML-DSA, and nothing here mentions any chain. Adding a
//! new scheme means adding a module under [`crate::schemes`]; it must not
//! require editing this file. See `schemes/slhdsa_sketch.rs` for a
//! compile-checked demonstration that a structurally different scheme
//! (hash-based, far larger signatures, different seed shape) fits unchanged.
//!
//! ## Why slice-based encoding
//!
//! Signature and key sizes vary by three orders of magnitude across the
//! standardised post-quantum schemes — 2,420 bytes for ML-DSA-44 up to 49,856
//! for SLH-DSA-256f. Returning owned arrays would force either `alloc` or
//! const-generic sizes threaded through every caller. Writing into a
//! caller-provided slice and returning the byte count keeps the layer
//! `no_std`, allocation-free, and size-agnostic.

use crate::error::PqError;

/// Static description of a signature scheme and its parameter set.
///
/// Ties the three key types together so a caller can be generic over
/// "the scheme" rather than over three independent type parameters.
pub trait PqScheme {
    /// Algorithm identifier, e.g. `"ML-DSA-65"`. Stable; suitable for
    /// serialising into an on-chain discriminant.
    const NAME: &'static str;
    /// NIST post-quantum security category (1, 2, 3, or 5).
    const SECURITY_CATEGORY: u8;
    /// Encoded verifying (public) key length in bytes.
    const VERIFYING_KEY_LEN: usize;
    /// Encoded signing (secret) key length in bytes.
    const SIGNING_KEY_LEN: usize;
    /// Encoded signature length in bytes.
    ///
    /// Fixed for ML-DSA and SLH-DSA. A scheme with variable-length signatures
    /// (Falcon, whose signatures are compressed) should report its maximum
    /// here and rely on the byte count returned by
    /// [`PqSigner::sign_into`] for the actual length.
    const SIGNATURE_LEN: usize;
    /// Seed length accepted by [`PqKeypair::from_seed`].
    const SEED_LEN: usize;

    type VerifyingKey: PqVerifier;
    type SigningKey: PqSigner;
    type Keypair: PqKeypair<SigningKey = Self::SigningKey, VerifyingKey = Self::VerifyingKey>;
}

/// A value that can be encoded to, and decoded from, its canonical byte form.
pub trait PqEncode: Sized {
    /// Length of this value's canonical encoding.
    fn encoded_len(&self) -> usize;

    /// Write the canonical encoding into `out`, returning bytes written.
    ///
    /// Fails with [`PqError::BufferTooSmall`] rather than truncating.
    fn write_to(&self, out: &mut [u8]) -> Result<usize, PqError>;

    /// Decode from the canonical byte form.
    ///
    /// Rejects wrong lengths and structurally invalid encodings.
    fn from_bytes(bytes: &[u8]) -> Result<Self, PqError>;
}

/// The public half: verifies signatures.
pub trait PqVerifier: PqEncode {
    /// Verify `signature` over `message` under domain-separation string `context`.
    ///
    /// Implements the *external* interface of the scheme's *pure* variant —
    /// for FIPS 204 that is `ML-DSA.Verify` (Algorithm 3), which prefixes
    /// `0x00 || len(ctx) || ctx` to the message. Pass an empty `context` for
    /// the common default.
    ///
    /// Returns `Ok(())` only on success. Every cryptographic failure returns
    /// [`PqError::VerificationFailed`]; callers must not branch on anything
    /// finer.
    fn verify(&self, message: &[u8], context: &[u8], signature: &[u8]) -> Result<(), PqError>;
}

/// The secret half: produces signatures.
pub trait PqSigner: PqEncode {
    /// Sign `message` under `context`, writing the signature into `out` and
    /// returning the number of bytes written.
    ///
    /// Deterministic where the scheme offers a deterministic variant, so the
    /// same inputs always produce the same signature. This keeps test vectors
    /// reproducible and removes any dependence on an RNG at signing time —
    /// which matters because this layer must build with no entropy source
    /// available.
    fn sign_into(&self, message: &[u8], context: &[u8], out: &mut [u8]) -> Result<usize, PqError>;

    /// Derive the matching verifying key.
    fn verifying_key(&self) -> impl PqVerifier;
}

/// A signing/verifying key pair derived from a seed.
pub trait PqKeypair: Sized {
    type SigningKey: PqSigner;
    type VerifyingKey: PqVerifier;

    /// Deterministically derive a key pair from `seed`.
    ///
    /// Seed length is scheme-defined ([`PqScheme::SEED_LEN`]); a wrong length
    /// is [`PqError::InvalidLength`], never silently padded or truncated.
    fn from_seed(seed: &[u8]) -> Result<Self, PqError>;

    fn signing_key(&self) -> &Self::SigningKey;
    fn verifying_key(&self) -> &Self::VerifyingKey;
}

/// Shared precondition for the FIPS external interfaces.
#[inline]
pub(crate) fn check_context(context: &[u8]) -> Result<(), PqError> {
    if context.len() > crate::error::MAX_CONTEXT_LEN {
        return Err(PqError::ContextTooLong { actual: context.len() });
    }
    Ok(())
}

#[inline]
pub(crate) fn check_len(actual: usize, expected: usize) -> Result<(), PqError> {
    if actual != expected {
        return Err(PqError::InvalidLength { expected, actual });
    }
    Ok(())
}
