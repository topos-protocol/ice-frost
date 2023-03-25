
# ICE-FROST

[![codecov](https://codecov.io/gh/topos-network/ice_frost/branch/master/graph/badge.svg?token=CA3D4JVOEJ)](https://codecov.io/gh/topos-network/ice_frost)
![example workflow](https://github.com/topos-network/ice_frost/actions/workflows/ci.yml/badge.svg)

A modular Rust implementation of [ICE-FROST: Identifiable Cheating Entity Flexible Round-Optimised Schnorr Threshold signatures](https://eprint.iacr.org/2021/1658) supporting static group keys.

# TODO

- [x] Update backend
- [x] Modularize keygen
- [x] Modularize signing
- [x] Bring back to_bytes() / from_bytes() method
- [ ] Update doc
- [ ] Update readme
- [ ] Update license

## Usage

Please see the documentation for usage examples.

## MSRV

This crate requires the `generic_const_exprs` unstable feature, and thus needs to be compiled with the `nightly` toolchain.

## Note on `no_std` usage

This crate can be made `no_std` compliant, by relying on the `alloc` crate instead.

## WARNING

This codebase is under development and is at an academic proof-of-concept prototype level.
In particular, this implementation has not received careful code review yet, and hence is NOT ready for production use.

## License

This project is licensed under the BSD-3-Clause.
