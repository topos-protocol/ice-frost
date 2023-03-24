//! A Rust implementation of Static **[ICE-FROST]**: **I**dentifiable **C**heating **E**ntity **F**lexible **R**ound-**O**ptimised **S**chnorr **T**hreshold signatures.

#![no_std]
#![warn(future_incompatible)]
// #![deny(missing_docs)]
#![allow(non_snake_case)]
// TODO: remove once do_keygen() is refactored
#![allow(clippy::type_complexity)]
#![feature(generic_const_exprs)]

#[cfg(any(test, feature = "std"))]
#[macro_use]
extern crate std;

#[cfg(not(feature = "std"))]
extern crate alloc;

mod error;
pub use error::{Error, FrostResult};

pub mod keys;
pub mod parameters;

mod ciphersuite;
pub use ciphersuite::CipherSuite;

pub mod utils;

pub mod dkg;
pub mod sign;

/// This module provides a concrete implementation of a FROST CipherSuite over Secp256k1,
/// with SHA-256 as underlying base hash function.
/// It is made available for testing and benchmarking purposes.
pub mod testing {
    use super::*;

    use ark_secp256k1::Projective as G;

    use sha2::Sha256;
    use utils::{String, ToOwned};

    use zeroize::Zeroize;

    #[derive(Debug, Copy, Clone, PartialEq, Eq, Default, Zeroize)]
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
