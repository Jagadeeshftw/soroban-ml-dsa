//! ML-DSA (FIPS 204) binding.
//!
//! Both parameter sets are generated from one macro, so the two code paths
//! cannot drift. The only per-set inputs are the `ml-dsa` parameter type, the
//! FIPS 204 encoded sizes, and the NIST security category.
//!
//! The underlying implementation is [`ml_dsa`] 0.1.1, which is **unaudited**.
//! See the crate README.

/// Generates a complete `PqScheme` implementation for one ML-DSA parameter set.
macro_rules! impl_mldsa {
    (
        module:   $module:ident,
        params:   $params:ty,
        name:     $name:literal,
        category: $category:literal,
        vk_len:   $vk_len:literal,
        sk_len:   $sk_len:literal,
        sig_len:  $sig_len:literal,
    ) => {
        pub mod $module {
            use crate::error::PqError;
            use crate::traits::{
                check_context, check_len, PqEncode, PqKeypair, PqScheme, PqSigner, PqVerifier,
            };
            use ml_dsa::{
                EncodedSignature, EncodedVerifyingKey, ExpandedSigningKey, ExpandedSigningKeyBytes,
                Seed, Signature,
            };

            /// Marker type carrying the parameter set's constants.
            #[derive(Debug, Clone, Copy)]
            pub struct Scheme;

            /// FIPS 204 verifying (public) key.
            #[derive(Clone)]
            pub struct VerifyingKey(ml_dsa::VerifyingKey<$params>);

            impl core::fmt::Debug for VerifyingKey {
                fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                    write!(f, "VerifyingKey<{}>", $name)
                }
            }

            /// FIPS 204 signing (secret) key, held in expanded form.
            #[derive(Clone)]
            pub struct SigningKey(ExpandedSigningKey<$params>);

            // Deliberately opaque: never render secret key material.
            impl core::fmt::Debug for SigningKey {
                fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                    write!(f, "SigningKey<{}>(redacted)", $name)
                }
            }

            /// A signing/verifying pair derived from a 32-byte seed.
            #[derive(Clone, Debug)]
            pub struct Keypair {
                signing: SigningKey,
                verifying: VerifyingKey,
            }

            impl PqScheme for Scheme {
                const NAME: &'static str = $name;
                const SECURITY_CATEGORY: u8 = $category;
                const VERIFYING_KEY_LEN: usize = $vk_len;
                const SIGNING_KEY_LEN: usize = $sk_len;
                const SIGNATURE_LEN: usize = $sig_len;
                const SEED_LEN: usize = 32;

                type VerifyingKey = VerifyingKey;
                type SigningKey = SigningKey;
                type Keypair = Keypair;
            }

            // ---------------------------------------------------------------
            // VerifyingKey
            // ---------------------------------------------------------------

            impl PqEncode for VerifyingKey {
                fn encoded_len(&self) -> usize {
                    $vk_len
                }

                fn write_to(&self, out: &mut [u8]) -> Result<usize, PqError> {
                    if out.len() < $vk_len {
                        return Err(PqError::BufferTooSmall { needed: $vk_len, actual: out.len() });
                    }
                    out[..$vk_len].copy_from_slice(self.0.encode().as_slice());
                    Ok($vk_len)
                }

                fn from_bytes(bytes: &[u8]) -> Result<Self, PqError> {
                    check_len(bytes.len(), $vk_len)?;
                    let enc = EncodedVerifyingKey::<$params>::try_from(bytes)
                        .map_err(|_| PqError::MalformedEncoding)?;
                    Ok(Self(ml_dsa::VerifyingKey::<$params>::decode(&enc)))
                }
            }

            impl PqVerifier for VerifyingKey {
                fn verify(
                    &self,
                    message: &[u8],
                    context: &[u8],
                    signature: &[u8],
                ) -> Result<(), PqError> {
                    check_context(context)?;
                    check_len(signature.len(), $sig_len)?;

                    // A signature that fails to decode is structurally
                    // malformed (bad hint vector, or ||z||_inf out of range).
                    // FIPS 204 requires rejecting it; we fold that into the
                    // same failure the caller sees for a bad signature so no
                    // extra information is exposed.
                    let enc = match EncodedSignature::<$params>::try_from(signature) {
                        Ok(e) => e,
                        Err(_) => return Err(PqError::VerificationFailed),
                    };
                    let sig = match Signature::<$params>::decode(&enc) {
                        Some(s) => s,
                        None => return Err(PqError::VerificationFailed),
                    };

                    if self.0.verify_with_context(message, context, &sig) {
                        Ok(())
                    } else {
                        Err(PqError::VerificationFailed)
                    }
                }
            }

            // ---------------------------------------------------------------
            // SigningKey
            // ---------------------------------------------------------------

            impl PqEncode for SigningKey {
                fn encoded_len(&self) -> usize {
                    $sk_len
                }

                /// Encodes to the FIPS 204 **expanded** secret-key format
                /// (`sk`, the form NIST's ACVP keyGen vectors specify).
                ///
                /// `ml-dsa` deprecates this encoding in favour of the 32-byte
                /// seed. We retain it because it is the form the standard's own
                /// test vectors use and the form other implementations
                /// interoperate on; see the crate README for the maintenance
                /// risk this creates.
                fn write_to(&self, out: &mut [u8]) -> Result<usize, PqError> {
                    if out.len() < $sk_len {
                        return Err(PqError::BufferTooSmall { needed: $sk_len, actual: out.len() });
                    }
                    #[allow(deprecated)]
                    out[..$sk_len].copy_from_slice(self.0.to_expanded().as_slice());
                    Ok($sk_len)
                }

                /// Decode a FIPS 204 expanded secret key.
                ///
                /// # Panics
                ///
                /// **Trusted input only.** The underlying
                /// `ExpandedSigningKey::from_expanded` does not validate its
                /// input and its own documentation states it "can potentially
                /// panic if keys are malformed or maliciously generated". This
                /// crate is `no_std` and cannot catch that.
                ///
                /// Use [`PqKeypair::from_seed`] for anything reaching this from
                /// outside your trust boundary. Note that the *verification*
                /// path — the one that actually consumes attacker-controlled
                /// bytes — does not touch this API and is unaffected.
                fn from_bytes(bytes: &[u8]) -> Result<Self, PqError> {
                    check_len(bytes.len(), $sk_len)?;
                    let enc = ExpandedSigningKeyBytes::<$params>::try_from(bytes)
                        .map_err(|_| PqError::MalformedEncoding)?;
                    #[allow(deprecated)]
                    Ok(Self(ExpandedSigningKey::<$params>::from_expanded(&enc)))
                }
            }

            impl PqSigner for SigningKey {
                fn sign_into(
                    &self,
                    message: &[u8],
                    context: &[u8],
                    out: &mut [u8],
                ) -> Result<usize, PqError> {
                    check_context(context)?;
                    if out.len() < $sig_len {
                        return Err(PqError::BufferTooSmall {
                            needed: $sig_len,
                            actual: out.len(),
                        });
                    }
                    let sig = self
                        .0
                        .sign_deterministic(message, context)
                        .map_err(|_| PqError::SigningFailed)?;
                    out[..$sig_len].copy_from_slice(sig.encode().as_slice());
                    Ok($sig_len)
                }

                fn verifying_key(&self) -> impl PqVerifier {
                    VerifyingKey(self.0.verifying_key())
                }
            }

            // ---------------------------------------------------------------
            // Keypair
            // ---------------------------------------------------------------

            #[cfg(test)]
            mod size_guard {
                use super::*;
                /// The declared FIPS 204 constants must match what the
                /// underlying crate actually produces. If `ml-dsa` ever changes
                /// an encoding, this fails rather than silently shipping a
                /// wrong `SIGNATURE_LEN` to a chain adapter.
                #[test]
                fn declared_sizes_match_implementation() {
                    let kp = Keypair::from_seed(&[1u8; 32]).unwrap();
                    assert_eq!(kp.verifying_key().encoded_len(), Scheme::VERIFYING_KEY_LEN);
                    assert_eq!(kp.signing_key().encoded_len(), Scheme::SIGNING_KEY_LEN);
                    let mut sig = [0u8; $sig_len];
                    let n = kp.signing_key().sign_into(b"x", b"", &mut sig).unwrap();
                    assert_eq!(n, Scheme::SIGNATURE_LEN);
                    assert_eq!(Scheme::SEED_LEN, 32);
                }
            }

            impl PqKeypair for Keypair {
                type SigningKey = SigningKey;
                type VerifyingKey = VerifyingKey;

                fn from_seed(seed: &[u8]) -> Result<Self, PqError> {
                    check_len(seed.len(), 32)?;
                    let mut s = [0u8; 32];
                    s.copy_from_slice(seed);
                    let expanded = ExpandedSigningKey::<$params>::from_seed(&Seed::from(s));
                    let verifying = VerifyingKey(expanded.verifying_key());
                    Ok(Self { signing: SigningKey(expanded), verifying })
                }

                fn signing_key(&self) -> &SigningKey {
                    &self.signing
                }

                fn verifying_key(&self) -> &VerifyingKey {
                    &self.verifying
                }
            }
        }
    };
}

impl_mldsa! {
    module:   mldsa44,
    params:   ml_dsa::MlDsa44,
    name:     "ML-DSA-44",
    category: 2,
    vk_len:   1312,
    sk_len:   2560,
    sig_len:  2420,
}

impl_mldsa! {
    module:   mldsa65,
    params:   ml_dsa::MlDsa65,
    name:     "ML-DSA-65",
    category: 3,
    vk_len:   1952,
    sk_len:   4032,
    sig_len:  3309,
}
