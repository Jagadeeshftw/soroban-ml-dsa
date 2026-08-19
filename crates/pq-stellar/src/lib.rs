//! # pq-stellar
//!
//! Stellar/Soroban adapter for [`pq_core`]: signature payload construction, XDR
//! encoding, and authorization entries for post-quantum contract accounts.
//!
//! ## Direction of dependency
//!
//! `pq-stellar` depends on `pq-core`. Never the reverse. `pq-core` contains no
//! Stellar types and must not acquire any.
//!
//! Everything in [`auth`] is generic over [`pq_core::PqScheme`]. No function in
//! this crate names a concrete scheme, so adding SLH-DSA or Falcon requires no
//! change here.
//!
//! ## ⚠️ Safety boundary inherited from `pq-core`
//!
//! `pq-core` documents that `SigningKey::from_bytes` is trusted-input only: the
//! underlying `ml-dsa` `from_expanded` does not validate its input and can
//! panic on a malformed or maliciously constructed expanded signing key.
//!
//! **This crate never calls it.** Signing keys enter only as
//! `&S::SigningKey` values the caller already holds, and this crate constructs
//! signing keys from nothing. The only decoding path exposed here is
//! [`pq_core::PqVerifier::from_bytes`] — the verifying-key path, which is
//! validated and is exercised by the full Wycheproof suite.
//!
//! That property is enforced by a test (`no_signing_key_decode_path`), not just
//! documented, because it is the sort of thing a later refactor would quietly
//! break.
//!
//! ## ⚠️ No audited implementation exists
//!
//! See the `pq-core` README. Differential testing and conformance vectors are
//! mitigation, not resolution. Testnet only.

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]

pub mod auth;
pub mod error;
pub mod payload;

pub use error::StellarError;
pub use payload::{network_id, AuthorizationPayload, MAINNET_PASSPHRASE, TESTNET_PASSPHRASE};

// Re-exported so downstream code can depend on one crate.
pub use pq_core;
