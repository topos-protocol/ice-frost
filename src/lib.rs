//! A Rust implementation of Static **[ICE-FROST]**: **I**dentifiable **C**heating **E**ntity **F**lexible **R**ound-**O**ptimised **S**chnorr **T**hreshold signatures.

#![no_std]
#![warn(future_incompatible)]
// #![deny(missing_docs)]
#![allow(non_snake_case)]
// TODO: remove once do_keygen() is refactored
#![allow(clippy::type_complexity)]

#[cfg(any(test, feature = "std"))]
#[macro_use]
extern crate std;

#[cfg(not(feature = "std"))]
extern crate alloc;

pub mod error;
pub mod keys;
pub mod parameters;

pub mod utils;

pub mod dkg;
pub mod sign;
