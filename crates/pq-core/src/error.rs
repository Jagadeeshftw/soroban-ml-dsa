/// Errors surfaced by the `pq-core` trait layer.
///
/// Deliberately coarse. A verifier must not leak *why* a signature failed
/// beyond what an attacker can already determine by construction, so every
/// cryptographic rejection collapses into [`PqError::VerificationFailed`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PqError {
    /// An encoded key, signature, or seed had the wrong length.
    InvalidLength { expected: usize, actual: usize },
    /// A buffer passed for output was too small.
    BufferTooSmall { needed: usize, actual: usize },
    /// A structurally malformed encoding (bad hint vector, out-of-range
    /// response vector, non-canonical packing).
    MalformedEncoding,
    /// The context string exceeded the 255-byte limit the FIPS external
    /// interfaces impose.
    ContextTooLong { actual: usize },
    /// The signature did not verify.
    VerificationFailed,
    /// Signing failed. For deterministic schemes this indicates malformed key
    /// material rather than a transient condition.
    SigningFailed,
}

impl core::fmt::Display for PqError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidLength { expected, actual } =>
                write!(f, "invalid length: expected {expected}, got {actual}"),
            Self::BufferTooSmall { needed, actual } =>
                write!(f, "buffer too small: need {needed}, got {actual}"),
            Self::MalformedEncoding => f.write_str("malformed encoding"),
            Self::ContextTooLong { actual } =>
                write!(f, "context too long: {actual} bytes, maximum 255"),
            Self::VerificationFailed => f.write_str("signature verification failed"),
            Self::SigningFailed => f.write_str("signing failed"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for PqError {}

/// Maximum context-string length, fixed by the FIPS 204 / FIPS 205 external
/// interfaces. Shared across schemes.
pub const MAX_CONTEXT_LEN: usize = 255;
