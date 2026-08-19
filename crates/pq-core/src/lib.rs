//! # pq-core
//!
//! Scheme-agnostic post-quantum signature traits, with ML-DSA-44 and ML-DSA-65
//! (FIPS 204) behind them.
//!
//! This crate is **chain-agnostic by construction**. It has no dependency on
//! Stellar, Soroban, or any other chain, and it must stay that way: chain
//! adapters depend on `pq-core`, never the reverse.
//!
//! ## ⚠️ No audited implementation exists
//!
//! ML-DSA here is [`ml_dsa`] 0.1.1, which states it has never been
//! independently audited. The main alternative, `fips204`, carries the same
//! warning. **There is currently no audited pure-Rust ML-DSA implementation.**
//!
//! This crate's response is differential testing against `fips204` plus NIST
//! ACVP and Wycheproof conformance vectors. That is **mitigation, not
//! resolution** — it lowers the chance a defect goes unnoticed; it does not
//! establish positive assurance. Do not use this in front of real value.
//!
//! ## Layout
//!
//! - [`traits`] — the scheme-agnostic layer. Adding a scheme must not require
//!   editing it.
//! - [`schemes`] — concrete implementations, plus a compile-checked SLH-DSA
//!   sketch demonstrating that constraint holds.

#![no_std]
#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]

#[cfg(any(test, feature = "std"))]
extern crate std;

pub mod error;
pub mod schemes;
pub mod traits;

pub use error::{PqError, MAX_CONTEXT_LEN};
pub use traits::{PqEncode, PqKeypair, PqScheme, PqSigner, PqVerifier};
