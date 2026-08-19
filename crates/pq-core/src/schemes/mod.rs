//! Concrete scheme implementations.
//!
//! Adding a scheme means adding a module here. It must not require editing
//! `crate::traits`. See [`slhdsa_sketch`] for a compile-checked demonstration.

mod mldsa;

pub use mldsa::{mldsa44, mldsa65};

pub mod slhdsa_sketch;
