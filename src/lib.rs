//! A Rust implementation of Static **[ICE-FROST]**: **I**dentifiable **C**heating **E**ntity **F**lexible **R**ound-**O**ptimised **S**chnorr **T**hreshold signatures.

#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(missing_debug_implementations)]
#![deny(missing_docs)]
#![deny(unsafe_code)]
#![warn(future_incompatible)]
#![allow(clippy::type_complexity)]
#![feature(generic_const_exprs)]

#[cfg(any(test, feature = "std"))]
#[macro_use]
extern crate std;

#[cfg(not(feature = "std"))]
extern crate alloc;

mod error;
pub use error::{Error, FrostResult};

/// A module defining the different key types used by an ICE-FROST instance.
pub mod keys;
/// A module defining the [`ThresholdParameters`] type used by an ICE-FROST instance.
pub mod parameters;

mod ciphersuite;
pub use ciphersuite::CipherSuite;

pub(crate) mod utils;

/// A module defining the logic of an ICE-FROST instance's distributed key generation session.
///
/// This module is also used in the context of key resharing, between two (potentially disjoint)
/// groups of participants.
pub mod dkg;
/// A module defining the logic of an ICE-FROST signing session.
pub mod sign;

/// This module provides a concrete implementation of an ICE-FROST CipherSuite over Secp256k1,
/// with SHA-256 as underlying base hash function.
/// It is made available for testing and benchmarking purposes.
pub mod testing {
    use super::*;

    use ark_secp256k1::Projective as G;

    use sha2::Sha256;
    use utils::{String, ToOwned};

    use zeroize::Zeroize;

    #[derive(Debug, Copy, Clone, PartialEq, Eq, Default, Zeroize)]
    /// An example instance of ICE-FROST over Secp256k1 with SHA-256 as underlying hasher.
    pub struct Secp256k1Sha256;

    impl CipherSuite for Secp256k1Sha256 {
        type G = G;

        type HashOutput = [u8; 32];

        type InnerHasher = Sha256;

        // SHA-256 targets 128 bits of security
        const HASH_SEC_PARAM: usize = 128;

        fn context_string() -> String {
            "ICE-FROST_SECP256K1_SHA256".to_owned()
        }
    }
}
