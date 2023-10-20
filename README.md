# ICE-FROST

[![codecov](https://codecov.io/gh/topos-protocol/ice-frost/branch/main/graph/badge.svg?token=CP8FGXD8VP)](https://codecov.io/gh/topos-protocol/ice-frost)
![example workflow](https://github.com/topos-protocol/ice-frost/actions/workflows/ci.yml/badge.svg)

A modular Rust implementation of [ICE-FROST: Identifiable Cheating Entity Flexible Round-Optimised Schnorr Threshold signatures](https://eprint.iacr.org/2021/1658) supporting static group keys.

## Usage

Please see the documentation for usage examples.

## Modular Backend

This library has a modular backend supporting

- arbitrary curves defined with the arkworks library suite;
- arbitrary hash functions for the internal random oracles of the ICE-FROST ciphersuite;
- an arbitrary AEAD for the secret shares encryption part of the DKG / Key resharing phase.

Note however that two parameters are not modular, at least in the current version:

- the hash function targeted security parameter: this crate assumes 128 bits of collision security for the ciphersuite's internal hashers. One **MUST** provide
  a hasher with _at least_ 128 bits of collision security when instantiating an ICE-FROST ciphersuite.
- the secret share encryption mechanism: this part of the distributed key generation currently relies on the ciphersuite's AEAD but with a fixed HKDF instantiated from SHA-256.

This library also provides by default an example instantiation over the Secp256k1 curve with SHA-256, to be used in tests and benchmarks.

## Note on `no_std` usage

This crate can be made `no_std` compliant, by relying on the `alloc` crate instead.

## Features

- `std`: activated by-default, allowing use of the Rust standard library
- `asm`: deactivated by-default, allowing x86-64 assembly optimization for finite field operations. This feature also activates the `std` one.

## WARNING

This codebase is under development and is at an academic proof-of-concept prototype level.
In particular, this implementation has not received careful code review yet, and hence is NOT ready for production use.

## License

Licensed under either of

- Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.
