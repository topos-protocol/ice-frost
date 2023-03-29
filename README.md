
# ICE-FROST

[![codecov](https://codecov.io/gh/topos-network/ice_frost/branch/main/graph/badge.svg?token=CP8FGXD8VP)](https://codecov.io/gh/topos-network/ice_frost)
![example workflow](https://github.com/topos-network/ice_frost/actions/workflows/ci.yml/badge.svg)

A modular Rust implementation of [ICE-FROST: Identifiable Cheating Entity Flexible Round-Optimised Schnorr Threshold signatures](https://eprint.iacr.org/2021/1658) supporting static group keys.

## Usage

Please see the documentation for usage examples.

## Modular Backend

This library has a modular backend supporting

- arbitrary curves defined with the arkworks library suite;
- arbitrary hash functions for the internal random oracles of the ICE-FROST ciphersuite.

It provides by default an example instantiation over the Secp256k1 curve with SHA-256, to be used in tests and benchmarks.

## MSRV

This crate requires the `generic_const_exprs` unstable feature, and thus needs to be compiled with the `nightly` toolchain.

## Note on `no_std` usage

This crate can be made `no_std` compliant, by relying on the `alloc` crate instead.

## WARNING

This codebase is under development and is at an academic proof-of-concept prototype level.
In particular, this implementation has not received careful code review yet, and hence is NOT ready for production use.

## License

Licensed under either of

- Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.
