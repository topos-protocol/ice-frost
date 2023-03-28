//!
// -*- mode: rust; -*-
//
// This file is part of ice-frost.
// Copyright (c) 2017-2019 isis lovecruft
// Copyright (c) 2021-2023 Toposware Inc.
// See LICENSE for licensing information.
//
// Authors:
// - isis agora lovecruft <isis@patternsinthevoid.net>
// - Toposware developers <dev@toposware.com>

//! This library provides a Rust implementation of the Static **[ICE-FROST]**:
//! **I**dentifiable **C**heating **E**ntity **F**lexible **R**ound-**O**ptimised **S**chnorr **T**hreshold
//! signature scheme, detailed in <https://eprint.iacr.org/2021/1658>.
//!
//! The ICE-FROST signature scheme extends the original FROST t-out-of-n threshold signature scheme, by adding
//! new properties to the distributed key generation phase: it is made robust, meaning that adversaries under
//! a targeted threshold cannot interrupt a key sharing / resharing session; and static, meaning that the public
//! group verifying key, to be used to attest correctness of the generated ICE-FROST signatures, is invariant
//! when proceeding to individual signing keys resharing to a (possibly) different group of participants.
//!
//! # Usage
//!
//! Alice, Bob, and Carol would like to set up a threshold signing scheme where
//! at least two of them need to sign on a given message to produce a valid
//! signature.
//!
//! For this, they need to define a [`CipherSuite`] to be used in the DKG and signing sessions.
//! This CipherSuite is used to parameterize ICE-FROST over an arbitrary curve backend, with
//! an arbitrary underlying hasher instantiating all random oracles.
//! The following example creates an ICE-FROST CipherSuite over the Secp256k1 curve,
//! with SHA-256 as internal hash function.
//!
//! ```rust
//! use ice_frost::CipherSuite;
//! use sha2::Sha256;
//! use zeroize::Zeroize;
//! use ark_secp256k1::Projective as G;
//!
//! #[derive(Debug, Copy, Clone, PartialEq, Eq, Default, Zeroize)]
//! pub struct Secp256k1Sha256;
//!
//! impl CipherSuite for Secp256k1Sha256 {
//!     type G = G;
//!
//!     type HashOutput = [u8; 32];
//!
//!     type InnerHasher = Sha256;
//!
//!     // SHA-256 targets 128 bits of security
//!     const HASH_SEC_PARAM: usize = 128;
//!
//!     fn context_string() -> String {
//!         "ICE-FROST_SECP256K1_SHA256".to_owned()
//!     }
//! }
//! ```
//!
//! We will use the `Secp256k1Sha256` as CipherSuite for all the following examples.
//!
//! Following the [`CipherSuite`] definition, Alice, Bob, and Carol need to define their
//! ICE-FROST session parameters as follows.
//!
//! ```rust
//! # use ice_frost::testing::Secp256k1Sha256;
//! use ice_frost::parameters::ThresholdParameters;
//!
//! let params = ThresholdParameters::<Secp256k1Sha256>::new(3,2);
//! ```
//!
//! ## Distributed Key Generation
//!
//! Alice, Bob, and Carol each generate their secret polynomial coefficients
//! (which make up each individual's personal secret key) and commitments to
//! them, as well as a zero-knowledge proof of their personal secret key.  Out
//! of scope, they each need to agree upon their *participant index* which is
//! some non-zero integer unique to each of them (these are the `1`, `2`, and
//! `3` in the following examples).
//!
//! ```rust
//! # use ice_frost::parameters::ThresholdParameters;
//! # use ice_frost::FrostResult;
//! # use ice_frost::dkg::Participant;
//! # use ice_frost::CipherSuite;
//! # use rand::rngs::OsRng;
//! # use ark_secp256k1::Projective as G;
//! # use sha2::Sha256;
//! # use ice_frost::testing::Secp256k1Sha256;
//! #
//! # fn do_test() -> FrostResult<Secp256k1Sha256, ()> {
//! # let params = ThresholdParameters::new(3,2);
//! # let mut rng = OsRng;
//!
//! // All ICE-FROST methods requiring a source of entropy should use a cryptographic pseudorandom
//! // generator to prevent any risk of private information retrieval.
//! let (alice, alice_coefficients, alice_dh_sk) = Participant::new_dealer(&params, 1, &mut rng)?;
//! let (bob, bob_coefficients, bob_dh_sk) = Participant::new_dealer(&params, 2, &mut rng)?;
//! let (carol, carol_coefficients, carol_dh_sk) = Participant::new_dealer(&params, 3, &mut rng)?;
//! # Ok(()) } fn main() { assert!(do_test().is_ok()); }
//! ```
//!
//! They send these values to each of the other participants (also out of scope
//! for this library), or otherwise publish them publicly somewhere.
//!
//! Note that they should only send the `alice`, `bob`, and `carol` structs, *not*
//! the `alice_coefficients`, etc., as the latter are their personal signing keys.
//!
//! Alice can then start the first round of the distributed key generation protocol:
//!
//! ```rust
//! use ice_frost::dkg::DistributedKeyGeneration;
//! # use ice_frost::parameters::ThresholdParameters;
//! # use ice_frost::dkg::Participant;
//! # use ice_frost::CipherSuite;
//! # use ice_frost::FrostResult;
//! # use rand::rngs::OsRng;
//! # use ark_secp256k1::Projective as G;
//! # use sha2::Sha256;
//! # use ice_frost::testing::Secp256k1Sha256;
//! #
//! # fn do_test() -> FrostResult<Secp256k1Sha256, ()> {
//! # let params = ThresholdParameters::new(3,2);
//! # let mut rng = OsRng;
//! #
//! # let (alice, alice_coefficients, alice_dh_sk) = Participant::new_dealer(&params, 1, &mut rng)?;
//! # let (bob, bob_coefficients, bob_dh_sk) = Participant::new_dealer(&params, 2, &mut rng)?;
//! # let (carol, carol_coefficients, carol_dh_sk) = Participant::new_dealer(&params, 3, &mut rng)?;
//!
//! let participants: Vec<Participant<Secp256k1Sha256>> = vec!(alice.clone(), bob.clone(), carol.clone());
//! let (alice_state, participant_lists) =
//!     DistributedKeyGeneration::<_, Secp256k1Sha256>::new_initial(
//!         &params,
//!         &alice_dh_sk,
//!         &alice.index,
//!         &alice_coefficients,
//!         &participants,
//!         &mut rng,
//!     )?;
//! # Ok(()) } fn main() { assert!(do_test().is_ok()); }
//! ```
//!
//! Alice then collects their secret shares which they send to the other participants:
//!
//! ```rust
//! # use ice_frost::dkg::DistributedKeyGeneration;
//! # use ice_frost::parameters::ThresholdParameters;
//! # use ice_frost::dkg::Participant;
//! # use ice_frost::CipherSuite;
//! # use ice_frost::FrostResult;
//! # use rand::rngs::OsRng;
//! # use ark_secp256k1::Projective as G;
//! # use sha2::Sha256;
//! # use zeroize::Zeroize;
//! # use ice_frost::testing::Secp256k1Sha256;
//! #
//! # fn do_test() -> FrostResult<Secp256k1Sha256, ()> {
//! # let params = ThresholdParameters::new(3,2);
//! # let mut rng = OsRng;
//! #
//! # let (alice, alice_coefficients, alice_dh_sk) = Participant::new_dealer(&params, 1, &mut rng)?;
//! # let (bob, bob_coefficients, bob_dh_sk) = Participant::new_dealer(&params, 2, &mut rng)?;
//! # let (carol, carol_coefficients, carol_dh_sk) = Participant::new_dealer(&params, 3, &mut rng)?;
//! #
//! # let participants: Vec<Participant<Secp256k1Sha256>> = vec!(alice.clone(), bob.clone(), carol.clone());
//! # let (alice_state, participant_lists) = DistributedKeyGeneration::<_, Secp256k1Sha256>::new_initial(&params, &alice_dh_sk, &alice.index, &alice_coefficients,
//! #                                                      &participants, &mut rng)?;
//! let alice_their_encrypted_secret_shares = alice_state.their_encrypted_secret_shares()?;;
//! # Ok(()) } fn main() { assert!(do_test().is_ok()); }
//! ```
//!
//! Bob and Carol each do the same:
//!
//! ```rust
//! # use ice_frost::dkg::DistributedKeyGeneration;
//! # use ice_frost::parameters::ThresholdParameters;
//! # use ice_frost::dkg::Participant;
//! # use ice_frost::CipherSuite;
//! # use ice_frost::FrostResult;
//! # use rand::rngs::OsRng;
//! # use ark_secp256k1::Projective as G;
//! # use sha2::Sha256;
//! # use zeroize::Zeroize;
//! # use ice_frost::testing::Secp256k1Sha256;
//! #
//! # fn do_test() -> FrostResult<Secp256k1Sha256, ()> {
//! # let params = ThresholdParameters::new(3,2);
//! # let mut rng = OsRng;
//! #
//! # let (alice, alice_coefficients, alice_dh_sk) = Participant::new_dealer(&params, 1, &mut rng)?;
//! # let (bob, bob_coefficients, bob_dh_sk) = Participant::new_dealer(&params, 2, &mut rng)?;
//! # let (carol, carol_coefficients, carol_dh_sk) = Participant::new_dealer(&params, 3, &mut rng)?;
//! #
//! # let participants: Vec<Participant<Secp256k1Sha256>> = vec!(alice.clone(), bob.clone(), carol.clone());
//! let (bob_state, participant_lists) =
//!     DistributedKeyGeneration::<_, Secp256k1Sha256>::new_initial(
//!         &params,
//!         &bob_dh_sk,
//!         &bob.index,
//!         &bob_coefficients,
//!         &participants,
//!         &mut rng,
//!     )?;
//! # Ok(()) }
//! # fn do_test2() -> FrostResult<Secp256k1Sha256, ()> {
//! # let params = ThresholdParameters::new(3,2);
//! # let mut rng = OsRng;
//! #
//! # let (alice, alice_coefficients, alice_dh_sk) = Participant::new_dealer(&params, 1, &mut rng)?;
//! # let (bob, bob_coefficients, bob_dh_sk) = Participant::new_dealer(&params, 2, &mut rng)?;
//! # let (carol, carol_coefficients, carol_dh_sk) = Participant::new_dealer(&params, 3, &mut rng)?;
//! #
//! # let participants: Vec<Participant<Secp256k1Sha256>> = vec!(alice.clone(), bob.clone(), carol.clone());
//! # let (bob_state, participant_lists) = DistributedKeyGeneration::<_, Secp256k1Sha256>::new_initial(&params, &bob_dh_sk, &bob.index, &bob_coefficients,
//! #                                                    &participants, &mut rng)?;
//!
//! let bob_their_encrypted_secret_shares = bob_state.their_encrypted_secret_shares()?;;
//!
//! // send_to_alice(bob_their_encrypted_secret_shares[0]);
//! // send_to_carol(bob_their_encrypted_secret_shares[1]);
//! # Ok(()) } fn main() { assert!(do_test().is_ok()); assert!(do_test2().is_ok()); }
//! ```
//!
//! and
//!
//! ```rust
//! # use ice_frost::dkg::DistributedKeyGeneration;
//! # use ice_frost::parameters::ThresholdParameters;
//! # use ice_frost::dkg::Participant;
//! # use ice_frost::CipherSuite;
//! # use ice_frost::FrostResult;
//! # use rand::rngs::OsRng;
//! # use ark_secp256k1::Projective as G;
//! # use sha2::Sha256;
//! # use zeroize::Zeroize;
//! # use ice_frost::testing::Secp256k1Sha256;
//! #
//! # fn do_test() -> FrostResult<Secp256k1Sha256, ()> {
//! # let params = ThresholdParameters::new(3,2);
//! # let mut rng = OsRng;
//! #
//! # let (alice, alice_coefficients, alice_dh_sk) = Participant::new_dealer(&params, 1, &mut rng)?;
//! # let (bob, bob_coefficients, bob_dh_sk) = Participant::new_dealer(&params, 2, &mut rng)?;
//! # let (carol, carol_coefficients, carol_dh_sk) = Participant::new_dealer(&params, 3, &mut rng)?;
//! #
//! # let participants: Vec<Participant<Secp256k1Sha256>> = vec!(alice.clone(), bob.clone(), carol.clone());
//! let (carol_state, participant_lists) =
//!     DistributedKeyGeneration::<_, Secp256k1Sha256>::new_initial(
//!         &params,
//!         &carol_dh_sk,
//!         &carol.index,
//!         &carol_coefficients,
//!         &participants,
//!         &mut rng,
//!     )?;
//! # Ok(()) }
//! # fn do_test2() -> FrostResult<Secp256k1Sha256, ()> {
//! # let params = ThresholdParameters::new(3,2);
//! # let mut rng = OsRng;
//! #
//! # let (alice, alice_coefficients, alice_dh_sk) = Participant::new_dealer(&params, 1, &mut rng)?;
//! # let (bob, bob_coefficients, bob_dh_sk) = Participant::new_dealer(&params, 2, &mut rng)?;
//! # let (carol, carol_coefficients, carol_dh_sk) = Participant::new_dealer(&params, 3, &mut rng)?;
//! #
//! # let participants: Vec<Participant<Secp256k1Sha256>> = vec!(alice.clone(), bob.clone(), carol.clone());
//! # let (carol_state, participant_lists) = DistributedKeyGeneration::<_, Secp256k1Sha256>::new_initial(&params, &carol_dh_sk, &carol.index, &carol_coefficients,
//! #                                                      &participants, &mut rng)?;
//!
//! let carol_their_encrypted_secret_shares = carol_state.their_encrypted_secret_shares()?;;
//!
//! // send_to_alice(carol_their_encrypted_secret_shares[0]);
//! // send_to_bob(carol_their_encrypted_secret_shares[1]);
//! # Ok(()) } fn main() { assert!(do_test().is_ok()); assert!(do_test2().is_ok()); }
//! ```
//!
//! Each participant now has a vector of secret shares given to them by the other participants:
//!
//! ```rust
//! # use ice_frost::dkg::DistributedKeyGeneration;
//! # use ice_frost::parameters::ThresholdParameters;
//! # use ice_frost::dkg::Participant;
//! # use ice_frost::CipherSuite;
//! # use ice_frost::FrostResult;
//! # use rand::rngs::OsRng;
//! # use ark_secp256k1::Projective as G;
//! # use sha2::Sha256;
//! # use zeroize::Zeroize;
//! # use ice_frost::testing::Secp256k1Sha256;
//! #
//! # fn do_test() -> FrostResult<Secp256k1Sha256, ()> {
//! # let params = ThresholdParameters::new(3,2);
//! # let mut rng = OsRng;
//! #
//! # let (alice, alice_coefficients, alice_dh_sk) = Participant::new_dealer(&params, 1, &mut rng)?;
//! # let (bob, bob_coefficients, bob_dh_sk) = Participant::new_dealer(&params, 2, &mut rng)?;
//! # let (carol, carol_coefficients, carol_dh_sk) = Participant::new_dealer(&params, 3, &mut rng)?;
//! #
//! # let participants: Vec<Participant<Secp256k1Sha256>> = vec!(alice.clone(), bob.clone(), carol.clone());
//! # let (alice_state, participant_lists) = DistributedKeyGeneration::<_, Secp256k1Sha256>::new_initial(&params, &alice_dh_sk, &alice.index, &alice_coefficients,
//! #                                                      &participants, &mut rng)?;
//! # let alice_their_encrypted_secret_shares = alice_state.their_encrypted_secret_shares()?;;
//! #
//! # let (bob_state, participant_lists) = DistributedKeyGeneration::<_, Secp256k1Sha256>::new_initial(&params, &bob_dh_sk, &bob.index, &bob_coefficients,
//! #                                                    &participants, &mut rng)?;
//! # let bob_their_encrypted_secret_shares = bob_state.their_encrypted_secret_shares()?;;
//! #
//! # let (carol_state, participant_lists) = DistributedKeyGeneration::<_, Secp256k1Sha256>::new_initial(&params, &carol_dh_sk, &carol.index, &carol_coefficients,
//! #                                                      &participants, &mut rng)?;
//! # let carol_their_encrypted_secret_shares = carol_state.their_encrypted_secret_shares()?;;
//! let alice_my_encrypted_secret_shares = vec!(alice_their_encrypted_secret_shares[0].clone(),
//!                                   bob_their_encrypted_secret_shares[0].clone(),
//!                                   carol_their_encrypted_secret_shares[0].clone());
//! let bob_my_encrypted_secret_shares = vec!(alice_their_encrypted_secret_shares[1].clone(),
//!                                 bob_their_encrypted_secret_shares[1].clone(),
//!                                 carol_their_encrypted_secret_shares[1].clone());
//! let carol_my_encrypted_secret_shares = vec!(alice_their_encrypted_secret_shares[2].clone(),
//!                                   bob_their_encrypted_secret_shares[2].clone(),
//!                                   carol_their_encrypted_secret_shares[2].clone());
//! # Ok(()) } fn main() { assert!(do_test().is_ok()); }
//! ```
//!
//! The participants then use these secret shares from the other participants to advance to
//! the second round of the distributed key generation protocol.
//!
//! ```rust
//! # use ice_frost::dkg::DistributedKeyGeneration;
//! # use ice_frost::parameters::ThresholdParameters;
//! # use ice_frost::dkg::Participant;
//! # use ice_frost::CipherSuite;
//! # use ice_frost::FrostResult;
//! # use rand::rngs::OsRng;
//! # use ark_secp256k1::Projective as G;
//! # use sha2::Sha256;
//! # use zeroize::Zeroize;
//! # use ice_frost::testing::Secp256k1Sha256;
//! #
//! # fn do_test() -> FrostResult<Secp256k1Sha256, ()> {
//! # let params = ThresholdParameters::new(3,2);
//! # let mut rng = OsRng;
//! #
//! # let (alice, alice_coefficients, alice_dh_sk) = Participant::new_dealer(&params, 1, &mut rng)?;
//! # let (bob, bob_coefficients, bob_dh_sk) = Participant::new_dealer(&params, 2, &mut rng)?;
//! # let (carol, carol_coefficients, carol_dh_sk) = Participant::new_dealer(&params, 3, &mut rng)?;
//! #
//! # let participants: Vec<Participant<Secp256k1Sha256>> = vec!(alice.clone(), bob.clone(), carol.clone());
//! # let (alice_state, participant_lists) = DistributedKeyGeneration::<_, Secp256k1Sha256>::new_initial(&params, &alice_dh_sk, &alice.index, &alice_coefficients,
//! #                                                      &participants, &mut rng)?;
//! # let alice_their_encrypted_secret_shares = alice_state.their_encrypted_secret_shares()?;;
//! #
//! # let (bob_state, participant_lists) = DistributedKeyGeneration::<_, Secp256k1Sha256>::new_initial(&params, &bob_dh_sk, &bob.index, &bob_coefficients,
//! #                                                    &participants, &mut rng)?;
//! # let bob_their_encrypted_secret_shares = bob_state.their_encrypted_secret_shares()?;;
//! #
//! # let (carol_state, participant_lists) = DistributedKeyGeneration::<_, Secp256k1Sha256>::new_initial(&params, &carol_dh_sk, &carol.index, &carol_coefficients,
//! #                                                      &participants, &mut rng)?;
//! # let carol_their_encrypted_secret_shares = carol_state.their_encrypted_secret_shares()?;;
//! # let alice_my_encrypted_secret_shares = vec!(alice_their_encrypted_secret_shares[0].clone(),
//! #                                   bob_their_encrypted_secret_shares[0].clone(),
//! #                                   carol_their_encrypted_secret_shares[0].clone());
//! # let bob_my_encrypted_secret_shares = vec!(alice_their_encrypted_secret_shares[1].clone(),
//! #                                 bob_their_encrypted_secret_shares[1].clone(),
//! #                                 carol_their_encrypted_secret_shares[1].clone());
//! # let carol_my_encrypted_secret_shares = vec!(alice_their_encrypted_secret_shares[2].clone(),
//! #                                   bob_their_encrypted_secret_shares[2].clone(),
//! #                                   carol_their_encrypted_secret_shares[2].clone());
//! #
//! let alice_state = alice_state.to_round_two(alice_my_encrypted_secret_shares, &mut rng)?;
//! let bob_state = bob_state.to_round_two(bob_my_encrypted_secret_shares, &mut rng)?;
//! let carol_state = carol_state.to_round_two(carol_my_encrypted_secret_shares, &mut rng)?;
//! # Ok(()) } fn main() { assert!(do_test().is_ok()); }
//! ```
//!
//! Each participant can now derive their long-lived, personal signing keys and the group's
//! public key.  They should all derive the same group public key.  They
//! also derive their [`IndividualVerifyingKey`](crate::keys::IndividualVerifyingKey)s
//! from their [`IndividualSigningKey`](crate::keys::IndividualSigningKey)s.
//!
//! ```rust
//! # use ice_frost::dkg::DistributedKeyGeneration;
//! # use ice_frost::parameters::ThresholdParameters;
//! # use ice_frost::dkg::Participant;
//! # use ice_frost::CipherSuite;
//! # use ice_frost::FrostResult;
//! # use rand::rngs::OsRng;
//! # use ark_secp256k1::Projective as G;
//! # use sha2::Sha256;
//! # use zeroize::Zeroize;
//! # use ice_frost::testing::Secp256k1Sha256;
//! #
//! # fn do_test() -> FrostResult<Secp256k1Sha256, ()> {
//! # let params = ThresholdParameters::new(3,2);
//! # let mut rng = OsRng;
//! #
//! # let (alice, alice_coefficients, alice_dh_sk) = Participant::new_dealer(&params, 1, &mut rng)?;
//! # let (bob, bob_coefficients, bob_dh_sk) = Participant::new_dealer(&params, 2, &mut rng)?;
//! # let (carol, carol_coefficients, carol_dh_sk) = Participant::new_dealer(&params, 3, &mut rng)?;
//! #
//! # let participants: Vec<Participant<Secp256k1Sha256>> = vec!(alice.clone(), bob.clone(), carol.clone());
//! # let (alice_state, participant_lists) = DistributedKeyGeneration::<_, Secp256k1Sha256>::new_initial(&params, &alice_dh_sk, &alice.index, &alice_coefficients,
//! #                                                      &participants, &mut rng)?;
//! # let alice_their_encrypted_secret_shares = alice_state.their_encrypted_secret_shares()?;;
//! #
//! # let (bob_state, participant_lists) = DistributedKeyGeneration::<_, Secp256k1Sha256>::new_initial(&params, &bob_dh_sk, &bob.index, &bob_coefficients,
//! #                                                    &participants, &mut rng)?;
//! # let bob_their_encrypted_secret_shares = bob_state.their_encrypted_secret_shares()?;;
//! #
//! # let (carol_state, participant_lists) = DistributedKeyGeneration::<_, Secp256k1Sha256>::new_initial(&params, &carol_dh_sk, &carol.index, &carol_coefficients,
//! #                                                      &participants, &mut rng)?;
//! # let carol_their_encrypted_secret_shares = carol_state.their_encrypted_secret_shares()?;;
//! # let alice_my_encrypted_secret_shares = vec!(alice_their_encrypted_secret_shares[0].clone(),
//! #                                   bob_their_encrypted_secret_shares[0].clone(),
//! #                                   carol_their_encrypted_secret_shares[0].clone());
//! # let bob_my_encrypted_secret_shares = vec!(alice_their_encrypted_secret_shares[1].clone(),
//! #                                 bob_their_encrypted_secret_shares[1].clone(),
//! #                                 carol_their_encrypted_secret_shares[1].clone());
//! # let carol_my_encrypted_secret_shares = vec!(alice_their_encrypted_secret_shares[2].clone(),
//! #                                   bob_their_encrypted_secret_shares[2].clone(),
//! #                                   carol_their_encrypted_secret_shares[2].clone());
//! #
//! # let alice_state = alice_state.to_round_two(alice_my_encrypted_secret_shares, &mut rng)?;
//! # let bob_state = bob_state.to_round_two(bob_my_encrypted_secret_shares, &mut rng)?;
//! # let carol_state = carol_state.to_round_two(carol_my_encrypted_secret_shares, &mut rng)?;
//! #
//! let (alice_group_key, alice_secret_key) = alice_state.finish()?;
//! let (bob_group_key, bob_secret_key) = bob_state.finish()?;
//! let (carol_group_key, carol_secret_key) = carol_state.finish()?;
//!
//! assert!(alice_group_key == bob_group_key);
//! assert!(carol_group_key == bob_group_key);
//!
//! let alice_public_key = alice_secret_key.to_public();
//! let bob_public_key = bob_secret_key.to_public();
//! let carol_public_key = carol_secret_key.to_public();
//! # Ok(()) } fn main() { assert!(do_test().is_ok()); }
//! ```
//!
//! ## Distributed Key Resharing
//!
//! Alice, Bob, and Carol perform between them their distributed key generation
//! and end up with their long-lived, personal secret keys and the group's public
//! key. They now want to allow a different set of people, namely Alexis, Barbara,
//! Claire and David, to sign with respect to the same group's public key.
//!
//! ```rust
//! # use ice_frost::dkg::DistributedKeyGeneration;
//! # use ice_frost::parameters::ThresholdParameters;
//! # use ice_frost::dkg::Participant;
//! # use ice_frost::CipherSuite;
//! # use ice_frost::FrostResult;
//! # use rand::rngs::OsRng;
//! # use ark_secp256k1::Projective as G;
//! # use sha2::Sha256;
//! # use zeroize::Zeroize;
//! # use ice_frost::testing::Secp256k1Sha256;
//! #
//! # fn do_test() -> FrostResult<Secp256k1Sha256, ()> {
//! # let params = ThresholdParameters::new(3,2);
//! # let mut rng = OsRng;
//! #
//! # let (alice, alice_coefficients, alice_dh_sk) = Participant::new_dealer(&params, 1, &mut rng)?;
//! # let (bob, bob_coefficients, bob_dh_sk) = Participant::new_dealer(&params, 2, &mut rng)?;
//! # let (carol, carol_coefficients, carol_dh_sk) = Participant::new_dealer(&params, 3, &mut rng)?;
//!
//! // Perform regular 2-out-of-3 DKG...
//! #
//! # let participants: Vec<Participant<Secp256k1Sha256>> = vec!(alice.clone(), bob.clone(), carol.clone());
//! # let (alice_state, participant_lists) = DistributedKeyGeneration::<_, Secp256k1Sha256>::new_initial(&params, &alice_dh_sk, &alice.index, &alice_coefficients,
//! #                                                      &participants, &mut rng)?;
//! # let alice_their_encrypted_secret_shares = alice_state.their_encrypted_secret_shares()?;;
//! #
//! # let (bob_state, participant_lists) = DistributedKeyGeneration::<_, Secp256k1Sha256>::new_initial(&params, &bob_dh_sk, &bob.index, &bob_coefficients,
//! #                                                    &participants, &mut rng)?;
//! # let bob_their_encrypted_secret_shares = bob_state.their_encrypted_secret_shares()?;;
//! #
//! # let (carol_state, participant_lists) = DistributedKeyGeneration::<_, Secp256k1Sha256>::new_initial(&params, &carol_dh_sk, &carol.index, &carol_coefficients,
//! #                                                      &participants, &mut rng)?;
//! # let carol_their_encrypted_secret_shares = carol_state.their_encrypted_secret_shares()?;;
//! # let alice_my_encrypted_secret_shares = vec!(alice_their_encrypted_secret_shares[0].clone(),
//! #                                   bob_their_encrypted_secret_shares[0].clone(),
//! #                                   carol_their_encrypted_secret_shares[0].clone());
//! # let bob_my_encrypted_secret_shares = vec!(alice_their_encrypted_secret_shares[1].clone(),
//! #                                 bob_their_encrypted_secret_shares[1].clone(),
//! #                                 carol_their_encrypted_secret_shares[1].clone());
//! # let carol_my_encrypted_secret_shares = vec!(alice_their_encrypted_secret_shares[2].clone(),
//! #                                   bob_their_encrypted_secret_shares[2].clone(),
//! #                                   carol_their_encrypted_secret_shares[2].clone());
//! #
//! # let alice_state = alice_state.to_round_two(alice_my_encrypted_secret_shares, &mut rng)?;
//! # let bob_state = bob_state.to_round_two(bob_my_encrypted_secret_shares, &mut rng)?;
//! # let carol_state = carol_state.to_round_two(carol_my_encrypted_secret_shares, &mut rng)?;
//!
//! let (alice_group_key, alice_secret_key) = alice_state.finish()?;
//! let (bob_group_key, bob_secret_key) = bob_state.finish()?;
//! let (carol_group_key, carol_secret_key) = carol_state.finish()?;
//!
//! # assert!(alice_group_key == bob_group_key);
//! # assert!(carol_group_key == bob_group_key);
//! #
//! // Instantiate new configuration parameters and create a new set of signers
//! let new_params = ThresholdParameters::new(4,3);
//!
//! let (alexis, alexis_dh_sk) = Participant::new_signer(&new_params, 1, &mut rng)?;
//! let (barbara, barbara_dh_sk) = Participant::new_signer(&new_params, 2, &mut rng)?;
//! let (claire, claire_dh_sk) = Participant::new_signer(&new_params, 3, &mut rng)?;
//! let (david, david_dh_sk) = Participant::new_signer(&new_params, 4, &mut rng)?;
//!
//! let signers: Vec<Participant<Secp256k1Sha256>> =
//!     vec!(alexis.clone(), barbara.clone(), claire.clone(), david.clone());
//!
//! let (alice_as_dealer, alice_encrypted_shares, participant_lists) =
//!     Participant::reshare(&new_params, alice_secret_key, &signers, &mut rng)?;
//!
//! let (bob_as_dealer, bob_encrypted_shares, participant_lists) =
//!     Participant::reshare(&new_params, bob_secret_key, &signers, &mut rng)?;
//!
//! let (carol_as_dealer, carol_encrypted_shares, participant_lists) =
//!     Participant::reshare(&new_params, carol_secret_key, &signers, &mut rng)?;
//! # Ok(()) } fn main() { assert!(do_test().is_ok()); }
//! ```
//!
//! Alexis, Barbara, Claire and David, can now instantiate their distributed key
//! generation protocol with respect to the previous set of dealers.
//!
//! ```rust
//! # use ice_frost::dkg::DistributedKeyGeneration;
//! # use ice_frost::parameters::ThresholdParameters;
//! # use ice_frost::dkg::Participant;
//! # use ice_frost::CipherSuite;
//! # use ice_frost::FrostResult;
//! # use rand::rngs::OsRng;
//! # use ark_secp256k1::Projective as G;
//! # use sha2::Sha256;
//! # use zeroize::Zeroize;
//! # use ice_frost::testing::Secp256k1Sha256;
//! #
//! # fn do_test() -> FrostResult<Secp256k1Sha256, ()> {
//! # let params = ThresholdParameters::new(3,2);
//! # let mut rng = OsRng;
//! #
//! # let (alice, alice_coefficients, alice_dh_sk) = Participant::new_dealer(&params, 1, &mut rng)?;
//! # let (bob, bob_coefficients, bob_dh_sk) = Participant::new_dealer(&params, 2, &mut rng)?;
//! # let (carol, carol_coefficients, carol_dh_sk) = Participant::new_dealer(&params, 3, &mut rng)?;
//! #
//! # let participants: Vec<Participant<Secp256k1Sha256>> = vec!(alice.clone(), bob.clone(), carol.clone());
//! # let (alice_state, participant_lists) = DistributedKeyGeneration::<_, Secp256k1Sha256>::new_initial(&params, &alice_dh_sk, &alice.index, &alice_coefficients,
//! #                                                      &participants, &mut rng)?;
//! # let alice_their_encrypted_secret_shares = alice_state.their_encrypted_secret_shares()?;;
//! #
//! # let (bob_state, participant_lists) = DistributedKeyGeneration::<_, Secp256k1Sha256>::new_initial(&params, &bob_dh_sk, &bob.index, &bob_coefficients,
//! #                                                    &participants, &mut rng)?;
//! # let bob_their_encrypted_secret_shares = bob_state.their_encrypted_secret_shares()?;;
//! #
//! # let (carol_state, participant_lists) = DistributedKeyGeneration::<_, Secp256k1Sha256>::new_initial(&params, &carol_dh_sk, &carol.index, &carol_coefficients,
//! #                                                      &participants, &mut rng)?;
//! # let carol_their_encrypted_secret_shares = carol_state.their_encrypted_secret_shares()?;;
//! # let alice_my_encrypted_secret_shares = vec!(alice_their_encrypted_secret_shares[0].clone(),
//! #                                   bob_their_encrypted_secret_shares[0].clone(),
//! #                                   carol_their_encrypted_secret_shares[0].clone());
//! # let bob_my_encrypted_secret_shares = vec!(alice_their_encrypted_secret_shares[1].clone(),
//! #                                 bob_their_encrypted_secret_shares[1].clone(),
//! #                                 carol_their_encrypted_secret_shares[1].clone());
//! # let carol_my_encrypted_secret_shares = vec!(alice_their_encrypted_secret_shares[2].clone(),
//! #                                   bob_their_encrypted_secret_shares[2].clone(),
//! #                                   carol_their_encrypted_secret_shares[2].clone());
//! #
//! # let alice_state = alice_state.to_round_two(alice_my_encrypted_secret_shares, &mut rng)?;
//! # let bob_state = bob_state.to_round_two(bob_my_encrypted_secret_shares, &mut rng)?;
//! # let carol_state = carol_state.to_round_two(carol_my_encrypted_secret_shares, &mut rng)?;
//! #
//! # let (alice_group_key, alice_secret_key) = alice_state.finish()?;
//! # let (bob_group_key, bob_secret_key) = bob_state.finish()?;
//! # let (carol_group_key, carol_secret_key) = carol_state.finish()?;
//! #
//! # assert!(alice_group_key == bob_group_key);
//! # assert!(carol_group_key == bob_group_key);
//! #
//! # // Instantiate new configuration parameters and create a set of signers
//! # let new_params = ThresholdParameters::new(4,3);
//! #
//! # let (alexis, alexis_dh_sk) = Participant::new_signer(&new_params, 1, &mut rng)?;
//! # let (barbara, barbara_dh_sk) = Participant::new_signer(&new_params, 2, &mut rng)?;
//! # let (claire, claire_dh_sk) = Participant::new_signer(&new_params, 3, &mut rng)?;
//! # let (david, david_dh_sk) = Participant::new_signer(&new_params, 4, &mut rng)?;
//! #
//! # let signers: Vec<Participant<Secp256k1Sha256>> = vec!(alexis.clone(), barbara.clone(), claire.clone(), david.clone());
//! # let (alice_as_dealer, alice_encrypted_shares, participant_lists) =
//! #     Participant::reshare(&new_params, alice_secret_key, &signers, &mut rng)?;
//! # let (bob_as_dealer, bob_encrypted_shares, participant_lists) =
//! #     Participant::reshare(&new_params, bob_secret_key, &signers, &mut rng)?;
//! # let (carol_as_dealer, carol_encrypted_shares, participant_lists) =
//! #     Participant::reshare(&new_params, carol_secret_key, &signers, &mut rng)?;
//! #
//! let dealers: Vec<Participant<Secp256k1Sha256>> =
//!     vec!(alice_as_dealer.clone(), bob_as_dealer.clone(), carol_as_dealer.clone());
//!
//! let (alexis_state, participant_lists) =
//!     DistributedKeyGeneration::<_, Secp256k1Sha256>::new(
//!         &params,
//!         &alexis_dh_sk,
//!         &alexis.index,
//!         &dealers,
//!         &mut rng,
//!     )?;
//!
//! let (barbara_state, participant_lists) =
//!     DistributedKeyGeneration::<_, Secp256k1Sha256>::new(
//!         &params,
//!         &barbara_dh_sk,
//!         &barbara.index,
//!         &dealers,
//!         &mut rng,
//!     )?;
//!
//! let (claire_state, participant_lists) =
//!     DistributedKeyGeneration::<_, Secp256k1Sha256>::new(
//!         &params,
//!         &claire_dh_sk,
//!         &claire.index,
//!         &dealers,
//!         &mut rng,
//!     )?;
//!
//! let (david_state, participant_lists) =
//!     DistributedKeyGeneration::<_, Secp256k1Sha256>::new(
//!         &params,
//!         &david_dh_sk,
//!         &david.index,
//!         &dealers,
//!         &mut rng,
//!     )?;
//! #
//! # Ok(()) } fn main() { assert!(do_test().is_ok()); }
//! ```
//!
//! Alexis, Barbara, Claire and David, can then use the encrypted secret
//! shares of the previous dealers to proceed to the Round 2 of the
//! distributed key resharing protocol.
//!
//! ```rust
//! # use ice_frost::dkg::DistributedKeyGeneration;
//! # use ice_frost::parameters::ThresholdParameters;
//! # use ice_frost::dkg::Participant;
//! # use ice_frost::CipherSuite;
//! # use ice_frost::FrostResult;
//! # use rand::rngs::OsRng;
//! # use ark_secp256k1::Projective as G;
//! # use sha2::Sha256;
//! # use zeroize::Zeroize;
//! # use ice_frost::testing::Secp256k1Sha256;
//! #
//! # fn do_test() -> FrostResult<Secp256k1Sha256, ()> {
//! # let params = ThresholdParameters::new(3,2);
//! # let mut rng = OsRng;
//! #
//! # let (alice, alice_coefficients, alice_dh_sk) = Participant::new_dealer(&params, 1, &mut rng)?;
//! # let (bob, bob_coefficients, bob_dh_sk) = Participant::new_dealer(&params, 2, &mut rng)?;
//! # let (carol, carol_coefficients, carol_dh_sk) = Participant::new_dealer(&params, 3, &mut rng)?;
//! #
//! # let participants: Vec<Participant<Secp256k1Sha256>> = vec!(alice.clone(), bob.clone(), carol.clone());
//! # let (alice_state, participant_lists) = DistributedKeyGeneration::<_, Secp256k1Sha256>::new_initial(&params, &alice_dh_sk, &alice.index, &alice_coefficients,
//! #                                                      &participants, &mut rng)?;
//! # let alice_their_encrypted_secret_shares = alice_state.their_encrypted_secret_shares()?;;
//! #
//! # let (bob_state, participant_lists) = DistributedKeyGeneration::<_, Secp256k1Sha256>::new_initial(&params, &bob_dh_sk, &bob.index, &bob_coefficients,
//! #                                                    &participants, &mut rng)?;
//! # let bob_their_encrypted_secret_shares = bob_state.their_encrypted_secret_shares()?;;
//! #
//! # let (carol_state, participant_lists) = DistributedKeyGeneration::<_, Secp256k1Sha256>::new_initial(&params, &carol_dh_sk, &carol.index, &carol_coefficients,
//! #                                                      &participants, &mut rng)?;
//! # let carol_their_encrypted_secret_shares = carol_state.their_encrypted_secret_shares()?;;
//! # let alice_my_encrypted_secret_shares = vec!(alice_their_encrypted_secret_shares[0].clone(),
//! #                                   bob_their_encrypted_secret_shares[0].clone(),
//! #                                   carol_their_encrypted_secret_shares[0].clone());
//! # let bob_my_encrypted_secret_shares = vec!(alice_their_encrypted_secret_shares[1].clone(),
//! #                                 bob_their_encrypted_secret_shares[1].clone(),
//! #                                 carol_their_encrypted_secret_shares[1].clone());
//! # let carol_my_encrypted_secret_shares = vec!(alice_their_encrypted_secret_shares[2].clone(),
//! #                                   bob_their_encrypted_secret_shares[2].clone(),
//! #                                   carol_their_encrypted_secret_shares[2].clone());
//! #
//! # let alice_state = alice_state.to_round_two(alice_my_encrypted_secret_shares, &mut rng)?;
//! # let bob_state = bob_state.to_round_two(bob_my_encrypted_secret_shares, &mut rng)?;
//! # let carol_state = carol_state.to_round_two(carol_my_encrypted_secret_shares, &mut rng)?;
//! #
//! # let (alice_group_key, alice_secret_key) = alice_state.finish()?;
//! # let (bob_group_key, bob_secret_key) = bob_state.finish()?;
//! # let (carol_group_key, carol_secret_key) = carol_state.finish()?;
//! #
//! # assert!(alice_group_key == bob_group_key);
//! # assert!(carol_group_key == bob_group_key);
//! #
//! # // Instantiate new configuration parameters and create a set of signers
//! # let new_params = ThresholdParameters::new(4,3);
//! #
//! # let (alexis, alexis_dh_sk) = Participant::new_signer(&new_params, 1, &mut rng)?;
//! # let (barbara, barbara_dh_sk) = Participant::new_signer(&new_params, 2, &mut rng)?;
//! # let (claire, claire_dh_sk) = Participant::new_signer(&new_params, 3, &mut rng)?;
//! # let (david, david_dh_sk) = Participant::new_signer(&new_params, 4, &mut rng)?;
//! #
//! # let signers: Vec<Participant<Secp256k1Sha256>> = vec!(alexis.clone(), barbara.clone(), claire.clone(), david.clone());
//! # let (alice_as_dealer, alice_encrypted_shares, participant_lists) =
//! #     Participant::reshare(&new_params, alice_secret_key, &signers, &mut rng)?;
//! # let (bob_as_dealer, bob_encrypted_shares, participant_lists) =
//! #     Participant::reshare(&new_params, bob_secret_key, &signers, &mut rng)?;
//! # let (carol_as_dealer, carol_encrypted_shares, participant_lists) =
//! #     Participant::reshare(&new_params, carol_secret_key, &signers, &mut rng)?;
//! #
//! # let dealers: Vec<Participant<Secp256k1Sha256>> =
//! #     vec!(alice_as_dealer.clone(), bob_as_dealer.clone(), carol_as_dealer.clone());
//! # let (alexis_state, participant_lists) = DistributedKeyGeneration::<_, Secp256k1Sha256>::new(&params, &alexis_dh_sk, &alexis.index,
//! #                                                    &dealers, &mut rng)?;
//! #
//! # let (barbara_state, participant_lists) = DistributedKeyGeneration::<_, Secp256k1Sha256>::new(&params, &barbara_dh_sk, &barbara.index,
//! #                                                    &dealers, &mut rng)?;
//! #
//! # let (claire_state, participant_lists) = DistributedKeyGeneration::<_, Secp256k1Sha256>::new(&params, &claire_dh_sk, &claire.index,
//! #                                                      &dealers, &mut rng)?;
//! #
//! # let (david_state, participant_lists) = DistributedKeyGeneration::<_, Secp256k1Sha256>::new(&params, &david_dh_sk, &david.index,
//! #                                                      &dealers, &mut rng)?;
//! #
//! # let alexis_my_encrypted_secret_shares = vec!(alice_encrypted_shares[0].clone(),
//! #                                   bob_encrypted_shares[0].clone(),
//! #                                   carol_encrypted_shares[0].clone());
//! # let barbara_my_encrypted_secret_shares = vec!(alice_encrypted_shares[1].clone(),
//! #                                   bob_encrypted_shares[1].clone(),
//! #                                   carol_encrypted_shares[1].clone());
//! # let claire_my_encrypted_secret_shares = vec!(alice_encrypted_shares[2].clone(),
//! #                                   bob_encrypted_shares[2].clone(),
//! #                                   carol_encrypted_shares[2].clone());
//! # let david_my_encrypted_secret_shares = vec!(alice_encrypted_shares[3].clone(),
//! #                                   bob_encrypted_shares[3].clone(),
//! #                                   carol_encrypted_shares[3].clone());
//! #
//! let alexis_state = alexis_state.to_round_two(alexis_my_encrypted_secret_shares, &mut rng)?;
//! let barbara_state = barbara_state.to_round_two(barbara_my_encrypted_secret_shares, &mut rng)?;
//! let claire_state = claire_state.to_round_two(claire_my_encrypted_secret_shares, &mut rng)?;
//! let david_state = david_state.to_round_two(david_my_encrypted_secret_shares, &mut rng)?;
//! # Ok(()) } fn main() { assert!(do_test().is_ok()); }
//! ```
//!
//! Alexis, Barbara, Claire and David, can now use the encrypted secret
//! shares of the previous dealers to recompute the group's public key
//! and obtain their own long-lived, personal secret keys.
//!
//! ```rust
//! # use ice_frost::dkg::DistributedKeyGeneration;
//! # use ice_frost::parameters::ThresholdParameters;
//! # use ice_frost::dkg::Participant;
//! # use ice_frost::CipherSuite;
//! # use ice_frost::FrostResult;
//! # use rand::rngs::OsRng;
//! # use ark_secp256k1::Projective as G;
//! # use sha2::Sha256;
//! # use zeroize::Zeroize;
//! # use ice_frost::testing::Secp256k1Sha256;
//! #
//! # fn do_test() -> FrostResult<Secp256k1Sha256, ()> {
//! # let params = ThresholdParameters::new(3,2);
//! # let mut rng = OsRng;
//! #
//! # let (alice, alice_coefficients, alice_dh_sk) = Participant::new_dealer(&params, 1, &mut rng)?;
//! # let (bob, bob_coefficients, bob_dh_sk) = Participant::new_dealer(&params, 2, &mut rng)?;
//! # let (carol, carol_coefficients, carol_dh_sk) = Participant::new_dealer(&params, 3, &mut rng)?;
//! #
//! # let participants: Vec<Participant<Secp256k1Sha256>> = vec!(alice.clone(), bob.clone(), carol.clone());
//! # let (alice_state, participant_lists) = DistributedKeyGeneration::<_, Secp256k1Sha256>::new_initial(&params, &alice_dh_sk, &alice.index, &alice_coefficients,
//! #                                                      &participants, &mut rng)?;
//! # let alice_their_encrypted_secret_shares = alice_state.their_encrypted_secret_shares()?;;
//! #
//! # let (bob_state, participant_lists) = DistributedKeyGeneration::<_, Secp256k1Sha256>::new_initial(&params, &bob_dh_sk, &bob.index, &bob_coefficients,
//! #                                                    &participants, &mut rng)?;
//! # let bob_their_encrypted_secret_shares = bob_state.their_encrypted_secret_shares()?;;
//! #
//! # let (carol_state, participant_lists) = DistributedKeyGeneration::<_, Secp256k1Sha256>::new_initial(&params, &carol_dh_sk, &carol.index, &carol_coefficients,
//! #                                                      &participants, &mut rng)?;
//! # let carol_their_encrypted_secret_shares = carol_state.their_encrypted_secret_shares()?;;
//! # let alice_my_encrypted_secret_shares = vec!(alice_their_encrypted_secret_shares[0].clone(),
//! #                                   bob_their_encrypted_secret_shares[0].clone(),
//! #                                   carol_their_encrypted_secret_shares[0].clone());
//! # let bob_my_encrypted_secret_shares = vec!(alice_their_encrypted_secret_shares[1].clone(),
//! #                                 bob_their_encrypted_secret_shares[1].clone(),
//! #                                 carol_their_encrypted_secret_shares[1].clone());
//! # let carol_my_encrypted_secret_shares = vec!(alice_their_encrypted_secret_shares[2].clone(),
//! #                                   bob_their_encrypted_secret_shares[2].clone(),
//! #                                   carol_their_encrypted_secret_shares[2].clone());
//! #
//! # let alice_state = alice_state.to_round_two(alice_my_encrypted_secret_shares, &mut rng)?;
//! # let bob_state = bob_state.to_round_two(bob_my_encrypted_secret_shares, &mut rng)?;
//! # let carol_state = carol_state.to_round_two(carol_my_encrypted_secret_shares, &mut rng)?;
//! #
//! # let (alice_group_key, alice_secret_key) = alice_state.finish()?;
//! # let (bob_group_key, bob_secret_key) = bob_state.finish()?;
//! # let (carol_group_key, carol_secret_key) = carol_state.finish()?;
//! #
//! # assert!(alice_group_key == bob_group_key);
//! # assert!(carol_group_key == bob_group_key);
//! #
//! # let new_params = ThresholdParameters::new(4,3);
//! #
//! # let (alexis, alexis_dh_sk) = Participant::new_signer(&new_params, 1, &mut rng)?;
//! # let (barbara, barbara_dh_sk) = Participant::new_signer(&new_params, 2, &mut rng)?;
//! # let (claire, claire_dh_sk) = Participant::new_signer(&new_params, 3, &mut rng)?;
//! # let (david, david_dh_sk) = Participant::new_signer(&new_params, 4, &mut rng)?;
//! #
//! # let signers: Vec<Participant<Secp256k1Sha256>> = vec!(alexis.clone(), barbara.clone(), claire.clone(), david.clone());
//! # let (alice_as_dealer, alice_encrypted_shares, participant_lists) =
//! #     Participant::reshare(&new_params, alice_secret_key, &signers, &mut rng)?;
//! # let (bob_as_dealer, bob_encrypted_shares, participant_lists) =
//! #     Participant::reshare(&new_params, bob_secret_key, &signers, &mut rng)?;
//! # let (carol_as_dealer, carol_encrypted_shares, participant_lists) =
//! #     Participant::reshare(&new_params, carol_secret_key, &signers, &mut rng)?;
//! #
//! # let dealers: Vec<Participant<Secp256k1Sha256>> = vec!(alice_as_dealer.clone(), bob_as_dealer.clone(), carol_as_dealer.clone());
//! # let (alexis_state, participant_lists) = DistributedKeyGeneration::<_, Secp256k1Sha256>::new(&params, &alexis_dh_sk, &alexis.index,
//! #                                                    &dealers, &mut rng)?;
//! #
//! # let (barbara_state, participant_lists) = DistributedKeyGeneration::<_, Secp256k1Sha256>::new(&params, &barbara_dh_sk, &barbara.index,
//! #                                                    &dealers, &mut rng)?;
//! #
//! # let (claire_state, participant_lists) = DistributedKeyGeneration::<_, Secp256k1Sha256>::new(&params, &claire_dh_sk, &claire.index,
//! #                                                      &dealers, &mut rng)?;
//! #
//! # let (david_state, participant_lists) = DistributedKeyGeneration::<_, Secp256k1Sha256>::new(&params, &david_dh_sk, &david.index,
//! #                                                      &dealers, &mut rng)?;
//! #
//! # let alexis_my_encrypted_secret_shares = vec!(alice_encrypted_shares[0].clone(),
//! #                                   bob_encrypted_shares[0].clone(),
//! #                                   carol_encrypted_shares[0].clone());
//! # let barbara_my_encrypted_secret_shares = vec!(alice_encrypted_shares[1].clone(),
//! #                                   bob_encrypted_shares[1].clone(),
//! #                                   carol_encrypted_shares[1].clone());
//! # let claire_my_encrypted_secret_shares = vec!(alice_encrypted_shares[2].clone(),
//! #                                   bob_encrypted_shares[2].clone(),
//! #                                   carol_encrypted_shares[2].clone());
//! # let david_my_encrypted_secret_shares = vec!(alice_encrypted_shares[3].clone(),
//! #                                   bob_encrypted_shares[3].clone(),
//! #                                   carol_encrypted_shares[3].clone());
//! #
//! # let alexis_state = alexis_state.to_round_two(alexis_my_encrypted_secret_shares, &mut rng)?;
//! # let barbara_state = barbara_state.to_round_two(barbara_my_encrypted_secret_shares, &mut rng)?;
//! # let claire_state = claire_state.to_round_two(claire_my_encrypted_secret_shares, &mut rng)?;
//! # let david_state = david_state.to_round_two(david_my_encrypted_secret_shares, &mut rng)?;
//! #
//! let (alexis_group_key, alexis_secret_key) = alexis_state.finish()?;
//! let (barbara_group_key, barbara_secret_key) = barbara_state.finish()?;
//! let (claire_group_key, claire_secret_key) = claire_state.finish()?;
//! let (david_group_key, david_secret_key) = david_state.finish()?;
//!
//! assert!(alexis_group_key == alice_group_key);
//! assert!(barbara_group_key == alice_group_key);
//! assert!(claire_group_key == alice_group_key);
//! assert!(david_group_key == alice_group_key);
//! # Ok(()) } fn main() { assert!(do_test().is_ok()); }
//! ```
//!
//! ## Precomputation and Partial Signatures
//!
//! After running their DKG, or after receiving secret shares from a previous set of signers,
//! Alice, Bob, and Carol can now create partial threshold signatures over an agreed upon
//! message with their respective secret keys, which they can then give to an untrusted
//! [`SignatureAggregator`](crate::sign::SignatureAggregator) (which can be one of the participants) to create a
//! 2-out-of-3 threshold signature.  To do this, they each pre-compute (using
//! `generate_commitment_share_lists` and publish a list of commitment shares.
//!
//! ```rust
//! use ice_frost::sign::generate_commitment_share_lists;
//! # use ice_frost::CipherSuite;
//! # use ice_frost::FrostResult;
//! # use ice_frost::dkg::DistributedKeyGeneration;
//! # use ice_frost::parameters::ThresholdParameters;
//! # use ice_frost::dkg::Participant;
//! # use ice_frost::testing::Secp256k1Sha256;
//! use ice_frost::sign::SignatureAggregator;
//!
//! use rand::rngs::OsRng;
//! # fn do_test() -> FrostResult<Secp256k1Sha256, ()> {
//! # let params = ThresholdParameters::new(3,2);
//! # let mut rng = OsRng;
//! #
//! # let (alice, alice_coefficients, alice_dh_sk) = Participant::new_dealer(&params, 1, &mut rng)?;
//! # let (bob, bob_coefficients, bob_dh_sk) = Participant::new_dealer(&params, 2, &mut rng)?;
//! # let (carol, carol_coefficients, carol_dh_sk) = Participant::new_dealer(&params, 3, &mut rng)?;
//! #
//! # let participants: Vec<Participant<Secp256k1Sha256>> = vec!(alice.clone(), bob.clone(), carol.clone());
//! # let (alice_state, participant_lists) = DistributedKeyGeneration::<_, Secp256k1Sha256>::new_initial(&params, &alice_dh_sk, &alice.index, &alice_coefficients,
//! #                                                      &participants, &mut rng)?;
//! # let alice_their_encrypted_secret_shares = alice_state.their_encrypted_secret_shares()?;;
//! #
//! # let (bob_state, participant_lists) = DistributedKeyGeneration::<_, Secp256k1Sha256>::new_initial(&params, &bob_dh_sk, &bob.index, &bob_coefficients,
//! #                                                    &participants, &mut rng)?;
//! # let bob_their_encrypted_secret_shares = bob_state.their_encrypted_secret_shares()?;;
//! #
//! # let (carol_state, participant_lists) = DistributedKeyGeneration::<_, Secp256k1Sha256>::new_initial(&params, &carol_dh_sk, &carol.index, &carol_coefficients,
//! #                                                      &participants, &mut rng)?;
//! # let carol_their_encrypted_secret_shares = carol_state.their_encrypted_secret_shares()?;;
//! # let alice_my_encrypted_secret_shares = vec!(alice_their_encrypted_secret_shares[0].clone(),
//! #                                   bob_their_encrypted_secret_shares[0].clone(),
//! #                                   carol_their_encrypted_secret_shares[0].clone());
//! # let bob_my_encrypted_secret_shares = vec!(alice_their_encrypted_secret_shares[1].clone(),
//! #                                 bob_their_encrypted_secret_shares[1].clone(),
//! #                                 carol_their_encrypted_secret_shares[1].clone());
//! # let carol_my_encrypted_secret_shares = vec!(alice_their_encrypted_secret_shares[2].clone(),
//! #                                   bob_their_encrypted_secret_shares[2].clone(),
//! #                                   carol_their_encrypted_secret_shares[2].clone());
//! #
//! # let alice_state = alice_state.to_round_two(alice_my_encrypted_secret_shares, &mut rng)?;
//! # let bob_state = bob_state.to_round_two(bob_my_encrypted_secret_shares, &mut rng)?;
//! # let carol_state = carol_state.to_round_two(carol_my_encrypted_secret_shares, &mut rng)?;
//! #
//! # let (alice_group_key, alice_secret_key) = alice_state.finish()?;
//! # let (bob_group_key, bob_secret_key) = bob_state.finish()?;
//! # let (carol_group_key, carol_secret_key) = carol_state.finish()?;
//! #
//! # let alice_public_key = alice_secret_key.to_public();
//! # let bob_public_key = bob_secret_key.to_public();
//! # let carol_public_key = carol_secret_key.to_public();
//!
//! let (alice_public_comshares, mut alice_secret_comshares) =
//!     generate_commitment_share_lists::<Secp256k1Sha256>(&mut OsRng, &alice_secret_key, 1);
//! let (bob_public_comshares, mut bob_secret_comshares) =
//!     generate_commitment_share_lists::<Secp256k1Sha256>(&mut OsRng, &bob_secret_key, 1);
//! let (carol_public_comshares, mut carol_secret_comshares) =
//!     generate_commitment_share_lists::<Secp256k1Sha256>(&mut OsRng, &carol_secret_key, 1);
//!
//! let message = b"This is a test of the tsunami alert system. This is only a test.";
//!
//! // The aggregator can be anyone who knows the group key, not necessarily Bob or a group participant
//! let mut aggregator =
//!     SignatureAggregator::new(
//!         params,
//!         bob_group_key.clone(),
//!         &message[..],
//!     );
//! # Ok(()) }
//! # fn main() { assert!(do_test().is_ok()); }
//! ```
//!
//! The aggregator takes note of each expected signer for this run of the protocol.  For this run,
//! we'll have Alice and Carol sign.
//!
//! ```rust
//! # use ice_frost::sign::generate_commitment_share_lists;
//! # use ice_frost::CipherSuite;
//! # use ice_frost::FrostResult;
//! # use ice_frost::dkg::DistributedKeyGeneration;
//! # use ice_frost::keys::IndividualVerifyingKey;
//! # use ice_frost::parameters::ThresholdParameters;
//! # use ice_frost::dkg::Participant;
//! # use ice_frost::testing::Secp256k1Sha256;
//! # use ice_frost::sign::SignatureAggregator;
//! #
//! # use rand::rngs::OsRng;
//! #
//! # fn do_test() -> FrostResult<Secp256k1Sha256, ()> {
//! # let params = ThresholdParameters::new(3,2);
//! # let mut rng = OsRng;
//! #
//! # let (alice, alice_coefficients, alice_dh_sk) = Participant::new_dealer(&params, 1, &mut rng)?;
//! # let (bob, bob_coefficients, bob_dh_sk) = Participant::new_dealer(&params, 2, &mut rng)?;
//! # let (carol, carol_coefficients, carol_dh_sk) = Participant::new_dealer(&params, 3, &mut rng)?;
//! #
//! # let participants: Vec<Participant<Secp256k1Sha256>> = vec!(alice.clone(), bob.clone(), carol.clone());
//! # let (alice_state, participant_lists) = DistributedKeyGeneration::<_, Secp256k1Sha256>::new_initial(&params, &alice_dh_sk, &alice.index, &alice_coefficients,
//! #                                                      &participants, &mut rng)?;
//! # let alice_their_encrypted_secret_shares = alice_state.their_encrypted_secret_shares()?;;
//! #
//! # let (bob_state, participant_lists) = DistributedKeyGeneration::<_, Secp256k1Sha256>::new_initial(&params, &bob_dh_sk, &bob.index, &bob_coefficients,
//! #                                                    &participants, &mut rng)?;
//! # let bob_their_encrypted_secret_shares = bob_state.their_encrypted_secret_shares()?;;
//! #
//! # let (carol_state, participant_lists) = DistributedKeyGeneration::<_, Secp256k1Sha256>::new_initial(&params, &carol_dh_sk, &carol.index, &carol_coefficients,
//! #                                                      &participants, &mut rng)?;
//! # let carol_their_encrypted_secret_shares = carol_state.their_encrypted_secret_shares()?;;
//! # let alice_my_encrypted_secret_shares = vec!(alice_their_encrypted_secret_shares[0].clone(),
//! #                                   bob_their_encrypted_secret_shares[0].clone(),
//! #                                   carol_their_encrypted_secret_shares[0].clone());
//! # let bob_my_encrypted_secret_shares = vec!(alice_their_encrypted_secret_shares[1].clone(),
//! #                                 bob_their_encrypted_secret_shares[1].clone(),
//! #                                 carol_their_encrypted_secret_shares[1].clone());
//! # let carol_my_encrypted_secret_shares = vec!(alice_their_encrypted_secret_shares[2].clone(),
//! #                                   bob_their_encrypted_secret_shares[2].clone(),
//! #                                   carol_their_encrypted_secret_shares[2].clone());
//! #
//! # let alice_state = alice_state.to_round_two(alice_my_encrypted_secret_shares, &mut rng)?;
//! # let bob_state = bob_state.to_round_two(bob_my_encrypted_secret_shares, &mut rng)?;
//! # let carol_state = carol_state.to_round_two(carol_my_encrypted_secret_shares, &mut rng)?;
//! #
//! # let (alice_group_key, alice_secret_key) = alice_state.finish()?;
//! # let (bob_group_key, bob_secret_key) = bob_state.finish()?;
//! # let (carol_group_key, carol_secret_key) = carol_state.finish()?;
//! #
//! # let alice_public_key = alice_secret_key.to_public();
//! # let bob_public_key = bob_secret_key.to_public();
//! # let carol_public_key = carol_secret_key.to_public();
//! #
//! # let (alice_public_comshares, mut alice_secret_comshares) =
//! #     generate_commitment_share_lists::<Secp256k1Sha256>(&mut OsRng, &alice_secret_key, 1);
//! # let (bob_public_comshares, mut bob_secret_comshares) =
//! #     generate_commitment_share_lists::<Secp256k1Sha256>(&mut OsRng, &bob_secret_key, 1);
//! # let (carol_public_comshares, mut carol_secret_comshares) =
//! #     generate_commitment_share_lists::<Secp256k1Sha256>(&mut OsRng, &carol_secret_key, 1);
//! #
//! # let message = b"This is a test of the tsunami alert system. This is only a test.";
//! #
//! # let mut aggregator = SignatureAggregator::new(params, bob_group_key.clone(), &message[..]);
//! #
//! aggregator.include_signer(1, alice_public_comshares.commitments[0], alice_public_key);
//! aggregator.include_signer(3, carol_public_comshares.commitments[0], carol_public_key);
//! # Ok(()) }
//! # fn main() { assert!(do_test().is_ok()); }
//! ```
//!
//! The aggregator should then publicly announce which participants are expected to be signers.
//!
//! ```rust
//! # use ice_frost::sign::generate_commitment_share_lists;
//! # use ice_frost::CipherSuite;
//! # use ice_frost::FrostResult;
//! # use ice_frost::dkg::DistributedKeyGeneration;
//! # use ice_frost::keys::IndividualVerifyingKey;
//! # use ice_frost::parameters::ThresholdParameters;
//! # use ice_frost::dkg::Participant;
//! # use ice_frost::testing::Secp256k1Sha256;
//! # use ice_frost::sign::SignatureAggregator;
//! #
//! # use rand::rngs::OsRng;
//! #
//! # fn do_test() -> FrostResult<Secp256k1Sha256, ()> {
//! # let params = ThresholdParameters::new(3,2);
//! # let mut rng = OsRng;
//! #
//! # let (alice, alice_coefficients, alice_dh_sk) = Participant::new_dealer(&params, 1, &mut rng)?;
//! # let (bob, bob_coefficients, bob_dh_sk) = Participant::new_dealer(&params, 2, &mut rng)?;
//! # let (carol, carol_coefficients, carol_dh_sk) = Participant::new_dealer(&params, 3, &mut rng)?;
//! #
//! # let participants: Vec<Participant<Secp256k1Sha256>> = vec!(alice.clone(), bob.clone(), carol.clone());
//! # let (alice_state, participant_lists) = DistributedKeyGeneration::<_, Secp256k1Sha256>::new_initial(&params, &alice_dh_sk, &alice.index, &alice_coefficients,
//! #                                                      &participants, &mut rng)?;
//! # let alice_their_encrypted_secret_shares = alice_state.their_encrypted_secret_shares()?;;
//! #
//! # let (bob_state, participant_lists) = DistributedKeyGeneration::<_, Secp256k1Sha256>::new_initial(&params, &bob_dh_sk, &bob.index, &bob_coefficients,
//! #                                                    &participants, &mut rng)?;
//! # let bob_their_encrypted_secret_shares = bob_state.their_encrypted_secret_shares()?;;
//! #
//! # let (carol_state, participant_lists) = DistributedKeyGeneration::<_, Secp256k1Sha256>::new_initial(&params, &carol_dh_sk, &carol.index, &carol_coefficients,
//! #                                                      &participants, &mut rng)?;
//! # let carol_their_encrypted_secret_shares = carol_state.their_encrypted_secret_shares()?;;
//! # let alice_my_encrypted_secret_shares = vec!(alice_their_encrypted_secret_shares[0].clone(),
//! #                                   bob_their_encrypted_secret_shares[0].clone(),
//! #                                   carol_their_encrypted_secret_shares[0].clone());
//! # let bob_my_encrypted_secret_shares = vec!(alice_their_encrypted_secret_shares[1].clone(),
//! #                                 bob_their_encrypted_secret_shares[1].clone(),
//! #                                 carol_their_encrypted_secret_shares[1].clone());
//! # let carol_my_encrypted_secret_shares = vec!(alice_their_encrypted_secret_shares[2].clone(),
//! #                                   bob_their_encrypted_secret_shares[2].clone(),
//! #                                   carol_their_encrypted_secret_shares[2].clone());
//! #
//! # let alice_state = alice_state.to_round_two(alice_my_encrypted_secret_shares, &mut rng)?;
//! # let bob_state = bob_state.to_round_two(bob_my_encrypted_secret_shares, &mut rng)?;
//! # let carol_state = carol_state.to_round_two(carol_my_encrypted_secret_shares, &mut rng)?;
//! #
//! # let (alice_group_key, alice_secret_key) = alice_state.finish()?;
//! # let (bob_group_key, bob_secret_key) = bob_state.finish()?;
//! # let (carol_group_key, carol_secret_key) = carol_state.finish()?;
//! #
//! # let alice_public_key = alice_secret_key.to_public();
//! # let bob_public_key = bob_secret_key.to_public();
//! # let carol_public_key = carol_secret_key.to_public();
//! #
//! # let (alice_public_comshares, mut alice_secret_comshares) =
//! #     generate_commitment_share_lists::<Secp256k1Sha256>(&mut OsRng, &alice_secret_key, 1);
//! # let (bob_public_comshares, mut bob_secret_comshares) =
//! #     generate_commitment_share_lists::<Secp256k1Sha256>(&mut OsRng, &bob_secret_key, 1);
//! # let (carol_public_comshares, mut carol_secret_comshares) =
//! #     generate_commitment_share_lists::<Secp256k1Sha256>(&mut OsRng, &carol_secret_key, 1);
//! #
//! # let message = b"This is a test of the tsunami alert system. This is only a test.";
//! #
//! # let mut aggregator = SignatureAggregator::new(params, bob_group_key.clone(), &message[..]);
//! #
//! # aggregator.include_signer(1, alice_public_comshares.commitments[0], alice_public_key);
//! # aggregator.include_signer(3, carol_public_comshares.commitments[0], carol_public_key);
//! let signers = aggregator.get_signers();
//! # Ok(()) }
//! # fn main() { assert!(do_test().is_ok()); }
//! ```
//!
//! Alice and Carol each then compute their partial signatures, and send these to the signature aggregator.
//!
//! ```rust
//! # use ice_frost::sign::generate_commitment_share_lists;
//! # use ice_frost::CipherSuite;
//! # use ice_frost::FrostResult;
//! # use ice_frost::dkg::DistributedKeyGeneration;
//! # use ice_frost::parameters::ThresholdParameters;
//! # use ice_frost::dkg::Participant;
//! # use ice_frost::testing::Secp256k1Sha256;
//! # use ice_frost::sign::SignatureAggregator;
//! #
//! # use rand::rngs::OsRng;
//! #
//! # fn do_test() -> FrostResult<Secp256k1Sha256, ()> {
//! # let params = ThresholdParameters::new(3,2);
//! # let mut rng = OsRng;
//! #
//! # let (alice, alice_coefficients, alice_dh_sk) = Participant::new_dealer(&params, 1, &mut rng)?;
//! # let (bob, bob_coefficients, bob_dh_sk) = Participant::new_dealer(&params, 2, &mut rng)?;
//! # let (carol, carol_coefficients, carol_dh_sk) = Participant::new_dealer(&params, 3, &mut rng)?;
//! #
//! # let participants: Vec<Participant<Secp256k1Sha256>> = vec!(alice.clone(), bob.clone(), carol.clone());
//! # let (alice_state, participant_lists) = DistributedKeyGeneration::<_, Secp256k1Sha256>::new_initial(&params, &alice_dh_sk, &alice.index, &alice_coefficients,
//! #                                                      &participants, &mut rng)?;
//! # let alice_their_encrypted_secret_shares = alice_state.their_encrypted_secret_shares()?;
//! #
//! # let (bob_state, participant_lists) = DistributedKeyGeneration::<_, Secp256k1Sha256>::new_initial(&params, &bob_dh_sk, &bob.index, &bob_coefficients,
//! #                                                    &participants, &mut rng)?;
//! # let bob_their_encrypted_secret_shares = bob_state.their_encrypted_secret_shares()?;
//! #
//! # let (carol_state, participant_lists) = DistributedKeyGeneration::<_, Secp256k1Sha256>::new_initial(&params, &carol_dh_sk, &carol.index, &carol_coefficients,
//! #                                                      &participants, &mut rng)?;
//! # let carol_their_encrypted_secret_shares = carol_state.their_encrypted_secret_shares()?;
//! # let alice_my_encrypted_secret_shares = vec!(alice_their_encrypted_secret_shares[0].clone(),
//! #                                   bob_their_encrypted_secret_shares[0].clone(),
//! #                                   carol_their_encrypted_secret_shares[0].clone());
//! # let bob_my_encrypted_secret_shares = vec!(alice_their_encrypted_secret_shares[1].clone(),
//! #                                 bob_their_encrypted_secret_shares[1].clone(),
//! #                                 carol_their_encrypted_secret_shares[1].clone());
//! # let carol_my_encrypted_secret_shares = vec!(alice_their_encrypted_secret_shares[2].clone(),
//! #                                   bob_their_encrypted_secret_shares[2].clone(),
//! #                                   carol_their_encrypted_secret_shares[2].clone());
//! #
//! # let alice_state = alice_state.to_round_two(alice_my_encrypted_secret_shares, &mut rng)?;
//! # let bob_state = bob_state.to_round_two(bob_my_encrypted_secret_shares, &mut rng)?;
//! # let carol_state = carol_state.to_round_two(carol_my_encrypted_secret_shares, &mut rng)?;
//! #
//! # let (alice_group_key, alice_secret_key) = alice_state.finish()?;
//! # let (bob_group_key, bob_secret_key) = bob_state.finish()?;
//! # let (carol_group_key, carol_secret_key) = carol_state.finish()?;
//! #
//! # let alice_public_key = alice_secret_key.to_public();
//! # let bob_public_key = bob_secret_key.to_public();
//! # let carol_public_key = carol_secret_key.to_public();
//! #
//! # let (alice_public_comshares, mut alice_secret_comshares) =
//! #     generate_commitment_share_lists::<Secp256k1Sha256>(&mut OsRng, &alice_secret_key, 1);
//! # let (bob_public_comshares, mut bob_secret_comshares) =
//! #     generate_commitment_share_lists::<Secp256k1Sha256>(&mut OsRng, &bob_secret_key, 1);
//! # let (carol_public_comshares, mut carol_secret_comshares) =
//! #     generate_commitment_share_lists::<Secp256k1Sha256>(&mut OsRng, &carol_secret_key, 1);
//! #
//! # let message = b"This is a test of the tsunami alert system. This is only a test.";
//! #
//! # let mut aggregator = SignatureAggregator::new(params, bob_group_key.clone(), &message[..]);
//! #
//! # aggregator.include_signer(1, alice_public_comshares.commitments[0], (&alice_secret_key).into());
//! # aggregator.include_signer(3, carol_public_comshares.commitments[0], (&carol_secret_key).into());
//! #
//! # let signers = aggregator.get_signers();
//! # let message_hash = Secp256k1Sha256::h4(&message[..]).unwrap();
//!
//! let alice_partial = alice_secret_key.sign(&message_hash, &alice_group_key,
//!                                           &mut alice_secret_comshares, 0, signers)?;
//! let carol_partial = carol_secret_key.sign(&message_hash, &carol_group_key,
//!                                           &mut carol_secret_comshares, 0, signers)?;
//!
//! aggregator.include_partial_signature(alice_partial);
//! aggregator.include_partial_signature(carol_partial);
//! # Ok(()) }
//! # fn main() { assert!(do_test().is_ok()); }
//! ```
//!
//! ## Signature Aggregation
//!
//! Once all the expected signers have sent their partial signatures, the
//! aggregator attempts to finalize its state, ensuring that there are no errors
//! thus far in the partial signatures, before finally attempting to complete
//! the aggregation of the partial signatures into a threshold signature.
//!
//! ```rust,ignore
//! let aggregator = aggregator.finalize()?;
//! ```
//!
//! If the aggregator could not finalize the state, then the `.finalize()` method
//! will return a list of participant indices from which finalization failed.
//! Note that a failure to complete is **guaranteed to be the fault of the aggregator**,
//! e.g. not collecting all the expected partial signatures, accepting two partial
//! signatures from the same participant, etc.
//!
//! And the same for the actual aggregation, if there was an error then list of
//! misbehaving participant indices is returned.
//! Unlike the `.finalize()` step, however, a failure of final aggregation is guaranteed
//! to be caused by the returned list of misbehaving participants, specifically that
//! their partial signature was invalid.
//!
//! ```rust,ignore
//! let threshold_signature = aggregator.aggregate()?;
//! ```
//!
//! Anyone with the group public key can then verify the threshold signature
//! in the same way they would for a standard Schnorr signature.
//!
//! ```rust,ignore
//! let verified = threshold_signature.verify(alice_group_key, &message_hash)?;
//! ```

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
/// A module defining the [`ThresholdParameters`](crate::parameters::ThresholdParameters) type used by an ICE-FROST instance.
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
