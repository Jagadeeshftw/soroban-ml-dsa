use core::fmt;

/// Errors from the Stellar adapter layer.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum StellarError {
    /// A `pq-core` operation failed.
    Pq(pq_core::PqError),
    /// XDR encoding failed.
    Xdr(&'static str),
    /// A signature or key did not fit the on-chain representation.
    Encoding(&'static str),
}

impl fmt::Display for StellarError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pq(e) => write!(f, "post-quantum operation failed: {e}"),
            Self::Xdr(m) => write!(f, "XDR error: {m}"),
            Self::Encoding(m) => write!(f, "encoding error: {m}"),
        }
    }
}

impl std::error::Error for StellarError {}

impl From<pq_core::PqError> for StellarError {
    fn from(e: pq_core::PqError) -> Self {
        Self::Pq(e)
    }
}
