//! **Not an implementation.** A compile-checked demonstration that the trait
//! layer accommodates a structurally different scheme without modification.
//!
//! SLH-DSA (FIPS 205) is the hardest case among the standardised schemes for a
//! trait layer designed around ML-DSA, because it differs on every axis that
//! could have been accidentally baked in:
//!
//! | | ML-DSA-65 | SLH-DSA-SHA2-128s |
//! |---|---|---|
//! | family | module-lattice | stateless hash-based |
//! | signature | 3,309 B | **7,856 B** (and 49,856 B for 256f) |
//! | verifying key | 1,952 B | **32 B** |
//! | signing key | 4,032 B | 64 B |
//! | seed | 32 B (`xi`) | **48 B** (`SK.seed ‖ SK.prf ‖ PK.seed`) |
//! | security category | 3 | 1 |
//!
//! Everything below type-checks against the unmodified traits in
//! [`crate::traits`]. Nothing in that module was changed to make it fit, and
//! no chain adapter would need to change either: adapters are written against
//! [`PqVerifier`], never against a concrete scheme.
//!
//! Falcon / FN-DSA is the easier case and is not sketched here, but note the
//! one place the traits already accommodate it: [`PqSigner::sign_into`]
//! returns the number of bytes written rather than assuming
//! [`PqScheme::SIGNATURE_LEN`], because Falcon signatures are compressed and
//! variable-length.
//!
//! To make this real: drop in a FIPS 205 implementation, delete the
//! `unimplemented!()` bodies, and remove `#[allow(dead_code)]`. No other file
//! in this crate changes.

#![allow(dead_code, unused_variables)]

use crate::error::PqError;
use crate::traits::{PqEncode, PqKeypair, PqScheme, PqSigner, PqVerifier};

/// SLH-DSA-SHA2-128s parameter set.
#[derive(Debug)]
pub struct Scheme;

#[derive(Debug)]
pub struct VerifyingKey([u8; 32]);
#[derive(Debug)]
pub struct SigningKey([u8; 64]);
#[derive(Debug)]
pub struct Keypair {
    signing: SigningKey,
    verifying: VerifyingKey,
}

impl PqScheme for Scheme {
    const NAME: &'static str = "SLH-DSA-SHA2-128s";
    const SECURITY_CATEGORY: u8 = 1;
    const VERIFYING_KEY_LEN: usize = 32;
    const SIGNING_KEY_LEN: usize = 64;
    // Two orders of magnitude larger than ML-DSA-65. The slice-based encoding
    // in `PqEncode` is what makes this a non-event for the trait layer.
    const SIGNATURE_LEN: usize = 7856;
    // 3n rather than ML-DSA's 32 -- `from_seed` takes a slice, so this needs
    // no trait change.
    const SEED_LEN: usize = 48;

    type VerifyingKey = VerifyingKey;
    type SigningKey = SigningKey;
    type Keypair = Keypair;
}

impl PqEncode for VerifyingKey {
    fn encoded_len(&self) -> usize { 32 }
    fn write_to(&self, out: &mut [u8]) -> Result<usize, PqError> { unimplemented!("FIPS 205") }
    fn from_bytes(bytes: &[u8]) -> Result<Self, PqError> { unimplemented!("FIPS 205") }
}

impl PqVerifier for VerifyingKey {
    /// FIPS 205 `slh_verify` takes the same `(message, context, signature)`
    /// shape as FIPS 204 `ML-DSA.Verify`, including the 0–255 byte context and
    /// the `0x00 ‖ len(ctx) ‖ ctx` prefix. The signature is identical.
    fn verify(&self, message: &[u8], context: &[u8], signature: &[u8]) -> Result<(), PqError> {
        unimplemented!("FIPS 205")
    }
}

impl PqEncode for SigningKey {
    fn encoded_len(&self) -> usize { 64 }
    fn write_to(&self, out: &mut [u8]) -> Result<usize, PqError> { unimplemented!("FIPS 205") }
    fn from_bytes(bytes: &[u8]) -> Result<Self, PqError> { unimplemented!("FIPS 205") }
}

impl PqSigner for SigningKey {
    fn sign_into(&self, message: &[u8], context: &[u8], out: &mut [u8]) -> Result<usize, PqError> {
        unimplemented!("FIPS 205")
    }
    fn verifying_key(&self) -> impl PqVerifier { VerifyingKey([0u8; 32]) }
}

impl PqKeypair for Keypair {
    type SigningKey = SigningKey;
    type VerifyingKey = VerifyingKey;
    fn from_seed(seed: &[u8]) -> Result<Self, PqError> { unimplemented!("FIPS 205") }
    fn signing_key(&self) -> &SigningKey { &self.signing }
    fn verifying_key(&self) -> &VerifyingKey { &self.verifying }
}

/// Compile-time proof of the design constraint: this function is generic over
/// *any* scheme and is instantiated below for both a real ML-DSA parameter set
/// and the SLH-DSA sketch. It is the shape a chain adapter takes.
#[allow(dead_code)]
fn adapter_shaped_function<S: PqScheme>(vk_bytes: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    match S::VerifyingKey::from_bytes(vk_bytes) {
        Ok(vk) => vk.verify(msg, &[], sig).is_ok(),
        Err(_) => false,
    }
}

#[allow(dead_code)]
fn _instantiations_typecheck() {
    let _ = adapter_shaped_function::<crate::schemes::mldsa65::Scheme>;
    let _ = adapter_shaped_function::<crate::schemes::mldsa44::Scheme>;
    // Same generic function, a hash-based scheme with a 7,856-byte signature
    // and a 48-byte seed. No trait-layer change was required to admit it.
    let _ = adapter_shaped_function::<Scheme>;
}
