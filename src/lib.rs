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
//! **NOTE**: This library assumes that participants can exchange messages on a public communication channel,
//! with each message being authentified (i.e. digitally signed) by its sender.
//!
//! # Usage
//!
//! Alice, Bob, and Carol would like to set up a threshold signing scheme where
//! at least two of them need to sign on a given message to produce a valid
//! signature.
//!
//! For this, they need to define a [`CipherSuite`] to be used in the DKG and signing sessions.
//! This [`CipherSuite`] is used to parameterize ICE-FROST over an arbitrary curve backend, with
//! an arbitrary underlying hasher instantiating all random oracles.
//! The following example creates an ICE-FROST [`CipherSuite`] over the Secp256k1 curve,
//! with SHA-256 as internal hash function, and AES-GCM with a 128-bit key and 96-bit nonce
//! as internal block cipher.
//!
//! ```rust
//! use ice_frost::CipherSuite;
//! use sha2::Sha256;
//! use zeroize::Zeroize;
//! use aes_gcm::Aes128Gcm;
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
//!     type Cipher = Aes128Gcm;
//!
//!     fn context_string() -> String {
//!         "ICE-FROST_SECP256K1_SHA256".to_owned()
//!     }
//! }
//! ```
//!
//! We will use the `Secp256k1Sha256` as [`CipherSuite`] for all the following examples.
//!
//! Following the [`CipherSuite`] definition, Alice, Bob, and Carol need to define their
//! ICE-FROST session parameters as follows.
//!
//! ```rust
//! # use ice_frost::testing::Secp256k1Sha256;
//! use ice_frost::parameters::ThresholdParameters;
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
//! # let params = ThresholdParameters::new(3,2)?;
//! # let mut rng = OsRng;
//! #
//! // All ICE-FROST methods requiring a source of entropy should use a cryptographic pseudorandom
//! // generator to prevent any risk of private information retrieval.
//! let (alice, alice_coefficients, alice_dh_sk) = Participant::new_dealer(params, 1, &mut rng)?;
//! let (bob, bob_coefficients, bob_dh_sk) = Participant::new_dealer(params, 2, &mut rng)?;
//! let (carol, carol_coefficients, carol_dh_sk) = Participant::new_dealer(params, 3, &mut rng)?;
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
//! # let params = ThresholdParameters::new(3,2)?;
//! # let mut rng = OsRng;
//! #
//! # let (alice, alice_coefficients, alice_dh_sk) = Participant::new_dealer(params, 1, &mut rng)?;
//! # let (bob, bob_coefficients, bob_dh_sk) = Participant::new_dealer(params, 2, &mut rng)?;
//! # let (carol, carol_coefficients, carol_dh_sk) = Participant::new_dealer(params, 3, &mut rng)?;
//!
//! let participants: Vec<Participant<Secp256k1Sha256>> =
//!     vec![alice.clone(), bob.clone(), carol.clone()];
//! let (alice_state, participant_lists) =
//!     DistributedKeyGeneration::<_, Secp256k1Sha256>::bootstrap(
//!         params,
//!         &alice_dh_sk,
//!         alice.index,
//!         &alice_coefficients,
//!         &participants,
//!         &mut rng,
//!     )?;
//! # Ok(()) } fn main() { assert!(do_test().is_ok()); }
//! ```
//!
//! The `participant_lists` output along `alice_state` contains a list of honest participants to continue the DKG
//! with, and a list of malicious ones whose NIZK proofs could not be verified. The logic for malicious participant
//! handling is explained in more details [here](#malicious-participants-and-complaints-handling).
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
//! # let params = ThresholdParameters::new(3,2)?;
//! # let mut rng = OsRng;
//! #
//! # let (alice, alice_coefficients, alice_dh_sk) = Participant::new_dealer(params, 1, &mut rng)?;
//! # let (bob, bob_coefficients, bob_dh_sk) = Participant::new_dealer(params, 2, &mut rng)?;
//! # let (carol, carol_coefficients, carol_dh_sk) = Participant::new_dealer(params, 3, &mut rng)?;
//! #
//! # let participants: Vec<Participant<Secp256k1Sha256>> = vec![alice.clone(), bob.clone(), carol.clone()];
//! # let (alice_state, participant_lists) = DistributedKeyGeneration::<_, Secp256k1Sha256>::bootstrap(params, &alice_dh_sk, alice.index, &alice_coefficients,
//! #                                                      &participants, &mut rng)?;
//! let alice_their_encrypted_secret_shares = alice_state.their_encrypted_secret_shares()?;
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
//! # let params = ThresholdParameters::new(3,2)?;
//! # let mut rng = OsRng;
//! #
//! # let (alice, alice_coefficients, alice_dh_sk) = Participant::new_dealer(params, 1, &mut rng)?;
//! # let (bob, bob_coefficients, bob_dh_sk) = Participant::new_dealer(params, 2, &mut rng)?;
//! # let (carol, carol_coefficients, carol_dh_sk) = Participant::new_dealer(params, 3, &mut rng)?;
//! #
//! # let participants: Vec<Participant<Secp256k1Sha256>> = vec![alice.clone(), bob.clone(), carol.clone()];
//! let (bob_state, participant_lists) =
//!     DistributedKeyGeneration::<_, Secp256k1Sha256>::bootstrap(
//!         params,
//!         &bob_dh_sk,
//!         bob.index,
//!         &bob_coefficients,
//!         &participants,
//!         &mut rng,
//!     )?;
//! # Ok(()) }
//! # fn do_test2() -> FrostResult<Secp256k1Sha256, ()> {
//! # let params = ThresholdParameters::new(3,2)?;
//! # let mut rng = OsRng;
//! #
//! # let (alice, alice_coefficients, alice_dh_sk) = Participant::new_dealer(params, 1, &mut rng)?;
//! # let (bob, bob_coefficients, bob_dh_sk) = Participant::new_dealer(params, 2, &mut rng)?;
//! # let (carol, carol_coefficients, carol_dh_sk) = Participant::new_dealer(params, 3, &mut rng)?;
//! #
//! # let participants: Vec<Participant<Secp256k1Sha256>> = vec![alice.clone(), bob.clone(), carol.clone()];
//! # let (bob_state, participant_lists) = DistributedKeyGeneration::<_, Secp256k1Sha256>::bootstrap(params, &bob_dh_sk, bob.index, &bob_coefficients,
//! #                                                    &participants, &mut rng)?;
//!
//! let bob_their_encrypted_secret_shares = bob_state.their_encrypted_secret_shares()?;
//!
//! // send_to_alice(bob_their_encrypted_secret_shares.get(&alice.index).unwrap());
//! // send_to_carol(bob_their_encrypted_secret_shares.get(&bob.index).unwrap());
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
//! # let params = ThresholdParameters::new(3,2)?;
//! # let mut rng = OsRng;
//! #
//! # let (alice, alice_coefficients, alice_dh_sk) = Participant::new_dealer(params, 1, &mut rng)?;
//! # let (bob, bob_coefficients, bob_dh_sk) = Participant::new_dealer(params, 2, &mut rng)?;
//! # let (carol, carol_coefficients, carol_dh_sk) = Participant::new_dealer(params, 3, &mut rng)?;
//! #
//! # let participants: Vec<Participant<Secp256k1Sha256>> = vec![alice.clone(), bob.clone(), carol.clone()];
//! let (carol_state, participant_lists) =
//!     DistributedKeyGeneration::<_, Secp256k1Sha256>::bootstrap(
//!         params,
//!         &carol_dh_sk,
//!         carol.index,
//!         &carol_coefficients,
//!         &participants,
//!         &mut rng,
//!     )?;
//! # Ok(()) }
//! # fn do_test2() -> FrostResult<Secp256k1Sha256, ()> {
//! # let params = ThresholdParameters::new(3,2)?;
//! # let mut rng = OsRng;
//! #
//! # let (alice, alice_coefficients, alice_dh_sk) = Participant::new_dealer(params, 1, &mut rng)?;
//! # let (bob, bob_coefficients, bob_dh_sk) = Participant::new_dealer(params, 2, &mut rng)?;
//! # let (carol, carol_coefficients, carol_dh_sk) = Participant::new_dealer(params, 3, &mut rng)?;
//! #
//! # let participants: Vec<Participant<Secp256k1Sha256>> = vec![alice.clone(), bob.clone(), carol.clone()];
//! # let (carol_state, participant_lists) = DistributedKeyGeneration::<_, Secp256k1Sha256>::bootstrap(params, &carol_dh_sk, carol.index, &carol_coefficients,
//! #                                                      &participants, &mut rng)?;
//!
//! let carol_their_encrypted_secret_shares = carol_state.their_encrypted_secret_shares()?;
//!
//! // send_to_alice(carol_their_encrypted_secret_shares.get(&alice.index).unwrap());
//! // send_to_bob(carol_their_encrypted_secret_shares.get(&bob.index).unwrap());
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
//! # let params = ThresholdParameters::new(3,2)?;
//! # let mut rng = OsRng;
//! #
//! # let (alice, alice_coefficients, alice_dh_sk) = Participant::new_dealer(params, 1, &mut rng)?;
//! # let (bob, bob_coefficients, bob_dh_sk) = Participant::new_dealer(params, 2, &mut rng)?;
//! # let (carol, carol_coefficients, carol_dh_sk) = Participant::new_dealer(params, 3, &mut rng)?;
//! #
//! # let participants: Vec<Participant<Secp256k1Sha256>> = vec![alice.clone(), bob.clone(), carol.clone()];
//! # let (alice_state, participant_lists) = DistributedKeyGeneration::<_, Secp256k1Sha256>::bootstrap(params, &alice_dh_sk, alice.index, &alice_coefficients,
//! #                                                      &participants, &mut rng)?;
//! # let alice_their_encrypted_secret_shares = alice_state.their_encrypted_secret_shares()?;
//! #
//! # let (bob_state, participant_lists) = DistributedKeyGeneration::<_, Secp256k1Sha256>::bootstrap(params, &bob_dh_sk, bob.index, &bob_coefficients,
//! #                                                    &participants, &mut rng)?;
//! # let bob_their_encrypted_secret_shares = bob_state.their_encrypted_secret_shares()?;
//! #
//! # let (carol_state, participant_lists) = DistributedKeyGeneration::<_, Secp256k1Sha256>::bootstrap(params, &carol_dh_sk, carol.index, &carol_coefficients,
//! #                                                      &participants, &mut rng)?;
//! # let carol_their_encrypted_secret_shares = carol_state.their_encrypted_secret_shares()?;
//! let alice_my_encrypted_secret_shares = vec![
//!     alice_their_encrypted_secret_shares.get(&alice.index).unwrap().clone(),
//!     bob_their_encrypted_secret_shares.get(&alice.index).unwrap().clone(),
//!     carol_their_encrypted_secret_shares.get(&alice.index).unwrap().clone(),
//! ];
//! let bob_my_encrypted_secret_shares = vec![
//!     alice_their_encrypted_secret_shares.get(&bob.index).unwrap().clone(),
//!     bob_their_encrypted_secret_shares.get(&bob.index).unwrap().clone(),
//!     carol_their_encrypted_secret_shares.get(&bob.index).unwrap().clone(),
//! ];
//! let carol_my_encrypted_secret_shares = vec![
//!     alice_their_encrypted_secret_shares.get(&carol.index).unwrap().clone(),
//!     bob_their_encrypted_secret_shares.get(&carol.index).unwrap().clone(),
//!     carol_their_encrypted_secret_shares.get(&carol.index).unwrap().clone(),
//! ];
//! # Ok(()) } fn main() { assert!(do_test().is_ok()); }
//! ```
//!
//! The participants then use these secret shares from the other participants to advance to
//! the second round of the distributed key generation protocol.
//!
//! Note that this library doesn't enforce that the indices in the encrypted secret shares
//! are valid (i.e. within the bounds defined by the parameters of this key generation session).
//! It is the responsibility of implementors to pre-check those before proceeding to `round_two`,
//! otherwise they will abort without succeeding in generating a group key.
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
//! # let params = ThresholdParameters::new(3,2)?;
//! # let mut rng = OsRng;
//! #
//! # let (alice, alice_coefficients, alice_dh_sk) = Participant::new_dealer(params, 1, &mut rng)?;
//! # let (bob, bob_coefficients, bob_dh_sk) = Participant::new_dealer(params, 2, &mut rng)?;
//! # let (carol, carol_coefficients, carol_dh_sk) = Participant::new_dealer(params, 3, &mut rng)?;
//! #
//! # let participants: Vec<Participant<Secp256k1Sha256>> = vec![alice.clone(), bob.clone(), carol.clone()];
//! # let (alice_state, participant_lists) = DistributedKeyGeneration::<_, Secp256k1Sha256>::bootstrap(params, &alice_dh_sk, alice.index, &alice_coefficients,
//! #                                                      &participants, &mut rng)?;
//! # let alice_their_encrypted_secret_shares = alice_state.their_encrypted_secret_shares()?;
//! #
//! # let (bob_state, participant_lists) = DistributedKeyGeneration::<_, Secp256k1Sha256>::bootstrap(params, &bob_dh_sk, bob.index, &bob_coefficients,
//! #                                                    &participants, &mut rng)?;
//! # let bob_their_encrypted_secret_shares = bob_state.their_encrypted_secret_shares()?;
//! #
//! # let (carol_state, participant_lists) = DistributedKeyGeneration::<_, Secp256k1Sha256>::bootstrap(params, &carol_dh_sk, carol.index, &carol_coefficients,
//! #                                                      &participants, &mut rng)?;
//! # let carol_their_encrypted_secret_shares = carol_state.their_encrypted_secret_shares()?;
//! # let alice_my_encrypted_secret_shares = vec![alice_their_encrypted_secret_shares.get(&alice.index).unwrap().clone(),
//! #                                   bob_their_encrypted_secret_shares.get(&alice.index).unwrap().clone(),
//! #                                   carol_their_encrypted_secret_shares.get(&alice.index).unwrap().clone()];
//! # let bob_my_encrypted_secret_shares = vec![alice_their_encrypted_secret_shares.get(&bob.index).unwrap().clone(),
//! #                                 bob_their_encrypted_secret_shares.get(&bob.index).unwrap().clone(),
//! #                                 carol_their_encrypted_secret_shares.get(&bob.index).unwrap().clone()];
//! # let carol_my_encrypted_secret_shares = vec![alice_their_encrypted_secret_shares.get(&carol.index).unwrap().clone(),
//! #                                   bob_their_encrypted_secret_shares.get(&carol.index).unwrap().clone(),
//! #                                   carol_their_encrypted_secret_shares.get(&carol.index).unwrap().clone()];
//! #
//! let (alice_state, alice_complaints) =
//!     alice_state.to_round_two(&alice_my_encrypted_secret_shares, &mut rng)?;
//! let (bob_state, bob_complaints) =
//!     bob_state.to_round_two(&bob_my_encrypted_secret_shares, &mut rng)?;
//! let (carol_state, carol_complaints) =
//!     carol_state.to_round_two(&carol_my_encrypted_secret_shares, &mut rng)?;
//!
//! // Everything should have run smoothly.
//! assert!(alice_complaints.is_empty());
//! assert!(bob_complaints.is_empty());
//! assert!(carol_complaints.is_empty());
//! # Ok(()) } fn main() { assert!(do_test().is_ok()); }
//! ```
//!
//! Participants may have generated local complaints for secret shares that were destined to them and incorrectly generated.
//! The logic for complaint handling is explained in more details [here](#malicious-participants-and-complaints-handling).
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
//! # let params = ThresholdParameters::new(3,2)?;
//! # let mut rng = OsRng;
//! #
//! # let (alice, alice_coefficients, alice_dh_sk) = Participant::new_dealer(params, 1, &mut rng)?;
//! # let (bob, bob_coefficients, bob_dh_sk) = Participant::new_dealer(params, 2, &mut rng)?;
//! # let (carol, carol_coefficients, carol_dh_sk) = Participant::new_dealer(params, 3, &mut rng)?;
//! #
//! # let participants: Vec<Participant<Secp256k1Sha256>> = vec![alice.clone(), bob.clone(), carol.clone()];
//! # let (alice_state, participant_lists) = DistributedKeyGeneration::<_, Secp256k1Sha256>::bootstrap(params, &alice_dh_sk, alice.index, &alice_coefficients,
//! #                                                      &participants, &mut rng)?;
//! # let alice_their_encrypted_secret_shares = alice_state.their_encrypted_secret_shares()?;
//! #
//! # let (bob_state, participant_lists) = DistributedKeyGeneration::<_, Secp256k1Sha256>::bootstrap(params, &bob_dh_sk, bob.index, &bob_coefficients,
//! #                                                    &participants, &mut rng)?;
//! # let bob_their_encrypted_secret_shares = bob_state.their_encrypted_secret_shares()?;
//! #
//! # let (carol_state, participant_lists) = DistributedKeyGeneration::<_, Secp256k1Sha256>::bootstrap(params, &carol_dh_sk, carol.index, &carol_coefficients,
//! #                                                      &participants, &mut rng)?;
//! # let carol_their_encrypted_secret_shares = carol_state.their_encrypted_secret_shares()?;
//! # let alice_my_encrypted_secret_shares = vec![alice_their_encrypted_secret_shares.get(&alice.index).unwrap().clone(),
//! #                                   bob_their_encrypted_secret_shares.get(&alice.index).unwrap().clone(),
//! #                                   carol_their_encrypted_secret_shares.get(&alice.index).unwrap().clone()];
//! # let bob_my_encrypted_secret_shares = vec![alice_their_encrypted_secret_shares.get(&bob.index).unwrap().clone(),
//! #                                 bob_their_encrypted_secret_shares.get(&bob.index).unwrap().clone(),
//! #                                 carol_their_encrypted_secret_shares.get(&bob.index).unwrap().clone()];
//! # let carol_my_encrypted_secret_shares = vec![alice_their_encrypted_secret_shares.get(&carol.index).unwrap().clone(),
//! #                                   bob_their_encrypted_secret_shares.get(&carol.index).unwrap().clone(),
//! #                                   carol_their_encrypted_secret_shares.get(&carol.index).unwrap().clone()];
//! #
//! # let (alice_state, _) = alice_state.to_round_two(&alice_my_encrypted_secret_shares, &mut rng)?;
//! # let (bob_state, _) = bob_state.to_round_two(&bob_my_encrypted_secret_shares, &mut rng)?;
//! # let (carol_state, _) = carol_state.to_round_two(&carol_my_encrypted_secret_shares, &mut rng)?;
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
//! Anybody can compute the [`IndividualVerifyingKey`](crate::keys::IndividualVerifyingKey) of a given participant and assert its correctness against the
//! list of available commitments. Note that this list should only contain commitments from the honest remaining participants
//! at the end of the DKG session. See [here](#malicious-participants-and-complaints-handling) for an example in case of adversarial presence.
//!
//! ```rust
//! # use ice_frost::dkg::DistributedKeyGeneration;
//! # use ice_frost::parameters::ThresholdParameters;
//! # use ice_frost::keys::IndividualVerifyingKey;
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
//! # let params = ThresholdParameters::new(3,2)?;
//! # let mut rng = OsRng;
//! #
//! let (alice, alice_coefficients, alice_dh_sk) = Participant::new_dealer(params, 1, &mut rng)?;
//! let (bob, bob_coefficients, bob_dh_sk) = Participant::new_dealer(params, 2, &mut rng)?;
//! let (carol, carol_coefficients, carol_dh_sk) = Participant::new_dealer(params, 3, &mut rng)?;
//! #
//! # let participants: Vec<Participant<Secp256k1Sha256>> = vec![alice.clone(), bob.clone(), carol.clone()];
//! # let (alice_state, participant_lists) = DistributedKeyGeneration::<_, Secp256k1Sha256>::bootstrap(params, &alice_dh_sk, alice.index, &alice_coefficients,
//! #                                                      &participants, &mut rng)?;
//! # let alice_their_encrypted_secret_shares = alice_state.their_encrypted_secret_shares()?;
//! #
//! # let (bob_state, participant_lists) = DistributedKeyGeneration::<_, Secp256k1Sha256>::bootstrap(params, &bob_dh_sk, bob.index, &bob_coefficients,
//! #                                                    &participants, &mut rng)?;
//! # let bob_their_encrypted_secret_shares = bob_state.their_encrypted_secret_shares()?;
//! #
//! # let (carol_state, participant_lists) = DistributedKeyGeneration::<_, Secp256k1Sha256>::bootstrap(params, &carol_dh_sk, carol.index, &carol_coefficients,
//! #                                                      &participants, &mut rng)?;
//! # let carol_their_encrypted_secret_shares = carol_state.their_encrypted_secret_shares()?;
//! # let alice_my_encrypted_secret_shares = vec![alice_their_encrypted_secret_shares.get(&alice.index).unwrap().clone(),
//! #                                   bob_their_encrypted_secret_shares.get(&alice.index).unwrap().clone(),
//! #                                   carol_their_encrypted_secret_shares.get(&alice.index).unwrap().clone()];
//! # let bob_my_encrypted_secret_shares = vec![alice_their_encrypted_secret_shares.get(&bob.index).unwrap().clone(),
//! #                                 bob_their_encrypted_secret_shares.get(&bob.index).unwrap().clone(),
//! #                                 carol_their_encrypted_secret_shares.get(&bob.index).unwrap().clone()];
//! # let carol_my_encrypted_secret_shares = vec![alice_their_encrypted_secret_shares.get(&carol.index).unwrap().clone(),
//! #                                   bob_their_encrypted_secret_shares.get(&carol.index).unwrap().clone(),
//! #                                   carol_their_encrypted_secret_shares.get(&carol.index).unwrap().clone()];
//! #
//! # let (alice_state, _) = alice_state.to_round_two(&alice_my_encrypted_secret_shares, &mut rng)?;
//! # let (bob_state, _) = bob_state.to_round_two(&bob_my_encrypted_secret_shares, &mut rng)?;
//! # let (carol_state, _) = carol_state.to_round_two(&carol_my_encrypted_secret_shares, &mut rng)?;
//! #
//!
//! // Proceed to DKG...
//!
//! let (alice_group_key, alice_secret_key) = alice_state.finish()?;
//! let (bob_group_key, bob_secret_key) = bob_state.finish()?;
//! let (carol_group_key, carol_secret_key) = carol_state.finish()?;
//!
//! let alice_public_key = alice_secret_key.to_public();
//! let bob_public_key = bob_secret_key.to_public();
//! let carol_public_key = carol_secret_key.to_public();
//!
//! // Commitments do not need to be ordered.
//! let all_commitments = [
//!     bob.commitments.unwrap(),
//!     carol.commitments.unwrap(),
//!     alice.commitments.unwrap()
//! ];
//!
//! assert_eq!(
//!     IndividualVerifyingKey::generate_from_commitments(alice.index, &all_commitments).unwrap(),
//!     alice_public_key
//! );
//! assert_eq!(
//!     IndividualVerifyingKey::generate_from_commitments(bob.index, &all_commitments).unwrap(),
//!     bob_public_key
//! );
//! assert_eq!(
//!     IndividualVerifyingKey::generate_from_commitments(carol.index, &all_commitments).unwrap(),
//!     carol_public_key
//! );
//!
//! assert!(alice_public_key.verify(&all_commitments).is_ok());
//! assert!(bob_public_key.verify(&all_commitments).is_ok());
//! assert!(carol_public_key.verify(&all_commitments).is_ok());
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
//! # let params = ThresholdParameters::new(3,2)?;
//! # let mut rng = OsRng;
//! #
//! # let (alice, alice_coefficients, alice_dh_sk) = Participant::new_dealer(params, 1, &mut rng)?;
//! # let (bob, bob_coefficients, bob_dh_sk) = Participant::new_dealer(params, 2, &mut rng)?;
//! # let (carol, carol_coefficients, carol_dh_sk) = Participant::new_dealer(params, 3, &mut rng)?;
//!
//! // Perform regular 2-out-of-3 DKG...
//! #
//! # let participants: Vec<Participant<Secp256k1Sha256>> = vec![alice.clone(), bob.clone(), carol.clone()];
//! # let (alice_state, participant_lists) = DistributedKeyGeneration::<_, Secp256k1Sha256>::bootstrap(params, &alice_dh_sk, alice.index, &alice_coefficients,
//! #                                                      &participants, &mut rng)?;
//! # let alice_their_encrypted_secret_shares = alice_state.their_encrypted_secret_shares()?;
//! #
//! # let (bob_state, participant_lists) = DistributedKeyGeneration::<_, Secp256k1Sha256>::bootstrap(params, &bob_dh_sk, bob.index, &bob_coefficients,
//! #                                                    &participants, &mut rng)?;
//! # let bob_their_encrypted_secret_shares = bob_state.their_encrypted_secret_shares()?;
//! #
//! # let (carol_state, participant_lists) = DistributedKeyGeneration::<_, Secp256k1Sha256>::bootstrap(params, &carol_dh_sk, carol.index, &carol_coefficients,
//! #                                                      &participants, &mut rng)?;
//! # let carol_their_encrypted_secret_shares = carol_state.their_encrypted_secret_shares()?;
//! # let alice_my_encrypted_secret_shares = vec![alice_their_encrypted_secret_shares.get(&alice.index).unwrap().clone(),
//! #                                   bob_their_encrypted_secret_shares.get(&alice.index).unwrap().clone(),
//! #                                   carol_their_encrypted_secret_shares.get(&alice.index).unwrap().clone()];
//! # let bob_my_encrypted_secret_shares = vec![alice_their_encrypted_secret_shares.get(&bob.index).unwrap().clone(),
//! #                                 bob_their_encrypted_secret_shares.get(&bob.index).unwrap().clone(),
//! #                                 carol_their_encrypted_secret_shares.get(&bob.index).unwrap().clone()];
//! # let carol_my_encrypted_secret_shares = vec![alice_their_encrypted_secret_shares.get(&carol.index).unwrap().clone(),
//! #                                   bob_their_encrypted_secret_shares.get(&carol.index).unwrap().clone(),
//! #                                   carol_their_encrypted_secret_shares.get(&carol.index).unwrap().clone()];
//! #
//! # let (alice_state, _) = alice_state.to_round_two(&alice_my_encrypted_secret_shares, &mut rng)?;
//! # let (bob_state, _) = bob_state.to_round_two(&bob_my_encrypted_secret_shares, &mut rng)?;
//! # let (carol_state, _) = carol_state.to_round_two(&carol_my_encrypted_secret_shares, &mut rng)?;
//!
//! let (alice_group_key, alice_secret_key) = alice_state.finish()?;
//! let (bob_group_key, bob_secret_key) = bob_state.finish()?;
//! let (carol_group_key, carol_secret_key) = carol_state.finish()?;
//!
//! # assert!(alice_group_key == bob_group_key);
//! # assert!(carol_group_key == bob_group_key);
//! #
//! // Instantiate new configuration parameters and create a new set of signers
//! let new_params = ThresholdParameters::new(4, 3)?;
//!
//! let (alexis, alexis_dh_sk) = Participant::new_signer(new_params, 1, &mut rng)?;
//! let (barbara, barbara_dh_sk) = Participant::new_signer(new_params, 2, &mut rng)?;
//! let (claire, claire_dh_sk) = Participant::new_signer(new_params, 3, &mut rng)?;
//! let (david, david_dh_sk) = Participant::new_signer(new_params, 4, &mut rng)?;
//!
//! let signers: Vec<Participant<Secp256k1Sha256>> =
//!     vec![alexis.clone(), barbara.clone(), claire.clone(), david.clone()];
//!
//! let (alice_as_dealer, alice_encrypted_shares, participant_lists) =
//!     Participant::reshare(new_params, &alice_secret_key, &signers, &mut rng)?;
//!
//! let (bob_as_dealer, bob_encrypted_shares, participant_lists) =
//!     Participant::reshare(new_params, &bob_secret_key, &signers, &mut rng)?;
//!
//! let (carol_as_dealer, carol_encrypted_shares, participant_lists) =
//!     Participant::reshare(new_params, &carol_secret_key, &signers, &mut rng)?;
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
//! # let params = ThresholdParameters::new(3,2)?;
//! # let mut rng = OsRng;
//! #
//! # let (alice, alice_coefficients, alice_dh_sk) = Participant::new_dealer(params, 1, &mut rng)?;
//! # let (bob, bob_coefficients, bob_dh_sk) = Participant::new_dealer(params, 2, &mut rng)?;
//! # let (carol, carol_coefficients, carol_dh_sk) = Participant::new_dealer(params, 3, &mut rng)?;
//! #
//! # let participants: Vec<Participant<Secp256k1Sha256>> = vec![alice.clone(), bob.clone(), carol.clone()];
//! # let (alice_state, participant_lists) = DistributedKeyGeneration::<_, Secp256k1Sha256>::bootstrap(params, &alice_dh_sk, alice.index, &alice_coefficients,
//! #                                                      &participants, &mut rng)?;
//! # let alice_their_encrypted_secret_shares = alice_state.their_encrypted_secret_shares()?;
//! #
//! # let (bob_state, participant_lists) = DistributedKeyGeneration::<_, Secp256k1Sha256>::bootstrap(params, &bob_dh_sk, bob.index, &bob_coefficients,
//! #                                                    &participants, &mut rng)?;
//! # let bob_their_encrypted_secret_shares = bob_state.their_encrypted_secret_shares()?;
//! #
//! # let (carol_state, participant_lists) = DistributedKeyGeneration::<_, Secp256k1Sha256>::bootstrap(params, &carol_dh_sk, carol.index, &carol_coefficients,
//! #                                                      &participants, &mut rng)?;
//! # let carol_their_encrypted_secret_shares = carol_state.their_encrypted_secret_shares()?;
//! # let alice_my_encrypted_secret_shares = vec![alice_their_encrypted_secret_shares.get(&alice.index).unwrap().clone(),
//! #                                   bob_their_encrypted_secret_shares.get(&alice.index).unwrap().clone(),
//! #                                   carol_their_encrypted_secret_shares.get(&alice.index).unwrap().clone()];
//! # let bob_my_encrypted_secret_shares = vec![alice_their_encrypted_secret_shares.get(&bob.index).unwrap().clone(),
//! #                                 bob_their_encrypted_secret_shares.get(&bob.index).unwrap().clone(),
//! #                                 carol_their_encrypted_secret_shares.get(&bob.index).unwrap().clone()];
//! # let carol_my_encrypted_secret_shares = vec![alice_their_encrypted_secret_shares.get(&carol.index).unwrap().clone(),
//! #                                   bob_their_encrypted_secret_shares.get(&carol.index).unwrap().clone(),
//! #                                   carol_their_encrypted_secret_shares.get(&carol.index).unwrap().clone()];
//! #
//! # let (alice_state, _) = alice_state.to_round_two(&alice_my_encrypted_secret_shares, &mut rng)?;
//! # let (bob_state, _) = bob_state.to_round_two(&bob_my_encrypted_secret_shares, &mut rng)?;
//! # let (carol_state, _) = carol_state.to_round_two(&carol_my_encrypted_secret_shares, &mut rng)?;
//! #
//! # let (alice_group_key, alice_secret_key) = alice_state.finish()?;
//! # let (bob_group_key, bob_secret_key) = bob_state.finish()?;
//! # let (carol_group_key, carol_secret_key) = carol_state.finish()?;
//! #
//! # assert!(alice_group_key == bob_group_key);
//! # assert!(carol_group_key == bob_group_key);
//! #
//! # // Instantiate new configuration parameters and create a set of signers
//! # let new_params = ThresholdParameters::new(4, 3)?;
//! #
//! # let (alexis, alexis_dh_sk) = Participant::new_signer(new_params, 1, &mut rng)?;
//! # let (barbara, barbara_dh_sk) = Participant::new_signer(new_params, 2, &mut rng)?;
//! # let (claire, claire_dh_sk) = Participant::new_signer(new_params, 3, &mut rng)?;
//! # let (david, david_dh_sk) = Participant::new_signer(new_params, 4, &mut rng)?;
//! #
//! # let signers: Vec<Participant<Secp256k1Sha256>> = vec![alexis.clone(), barbara.clone(), claire.clone(), david.clone()];
//! # let (alice_as_dealer, alice_encrypted_shares, participant_lists) =
//! #     Participant::reshare(new_params, &alice_secret_key, &signers, &mut rng)?;
//! # let (bob_as_dealer, bob_encrypted_shares, participant_lists) =
//! #     Participant::reshare(new_params, &bob_secret_key, &signers, &mut rng)?;
//! # let (carol_as_dealer, carol_encrypted_shares, participant_lists) =
//! #     Participant::reshare(new_params, &carol_secret_key, &signers, &mut rng)?;
//! #
//! let dealers: Vec<Participant<Secp256k1Sha256>> =
//!     vec![alice_as_dealer.clone(), bob_as_dealer.clone(), carol_as_dealer.clone()];
//!
//! let (alexis_state, participant_lists) =
//!     DistributedKeyGeneration::<_, Secp256k1Sha256>::new(
//!         params,
//!         &alexis_dh_sk,
//!         alexis.index,
//!         &dealers,
//!         &mut rng,
//!     )?;
//!
//! let (barbara_state, participant_lists) =
//!     DistributedKeyGeneration::<_, Secp256k1Sha256>::new(
//!         params,
//!         &barbara_dh_sk,
//!         barbara.index,
//!         &dealers,
//!         &mut rng,
//!     )?;
//!
//! let (claire_state, participant_lists) =
//!     DistributedKeyGeneration::<_, Secp256k1Sha256>::new(
//!         params,
//!         &claire_dh_sk,
//!         claire.index,
//!         &dealers,
//!         &mut rng,
//!     )?;
//!
//! let (david_state, participant_lists) =
//!     DistributedKeyGeneration::<_, Secp256k1Sha256>::new(
//!         params,
//!         &david_dh_sk,
//!         david.index,
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
//! # let params = ThresholdParameters::new(3,2)?;
//! # let mut rng = OsRng;
//! #
//! # let (alice, alice_coefficients, alice_dh_sk) = Participant::new_dealer(params, 1, &mut rng)?;
//! # let (bob, bob_coefficients, bob_dh_sk) = Participant::new_dealer(params, 2, &mut rng)?;
//! # let (carol, carol_coefficients, carol_dh_sk) = Participant::new_dealer(params, 3, &mut rng)?;
//! #
//! # let participants: Vec<Participant<Secp256k1Sha256>> = vec![alice.clone(), bob.clone(), carol.clone()];
//! # let (alice_state, participant_lists) = DistributedKeyGeneration::<_, Secp256k1Sha256>::bootstrap(params, &alice_dh_sk, alice.index, &alice_coefficients,
//! #                                                      &participants, &mut rng)?;
//! # let alice_their_encrypted_secret_shares = alice_state.their_encrypted_secret_shares()?;
//! #
//! # let (bob_state, participant_lists) = DistributedKeyGeneration::<_, Secp256k1Sha256>::bootstrap(params, &bob_dh_sk, bob.index, &bob_coefficients,
//! #                                                    &participants, &mut rng)?;
//! # let bob_their_encrypted_secret_shares = bob_state.their_encrypted_secret_shares()?;
//! #
//! # let (carol_state, participant_lists) = DistributedKeyGeneration::<_, Secp256k1Sha256>::bootstrap(params, &carol_dh_sk, carol.index, &carol_coefficients,
//! #                                                      &participants, &mut rng)?;
//! # let carol_their_encrypted_secret_shares = carol_state.their_encrypted_secret_shares()?;
//! # let alice_my_encrypted_secret_shares = vec![alice_their_encrypted_secret_shares.get(&alice.index).unwrap().clone(),
//! #                                   bob_their_encrypted_secret_shares.get(&alice.index).unwrap().clone(),
//! #                                   carol_their_encrypted_secret_shares.get(&alice.index).unwrap().clone()];
//! # let bob_my_encrypted_secret_shares = vec![alice_their_encrypted_secret_shares.get(&bob.index).unwrap().clone(),
//! #                                 bob_their_encrypted_secret_shares.get(&bob.index).unwrap().clone(),
//! #                                 carol_their_encrypted_secret_shares.get(&bob.index).unwrap().clone()];
//! # let carol_my_encrypted_secret_shares = vec![alice_their_encrypted_secret_shares.get(&carol.index).unwrap().clone(),
//! #                                   bob_their_encrypted_secret_shares.get(&carol.index).unwrap().clone(),
//! #                                   carol_their_encrypted_secret_shares.get(&carol.index).unwrap().clone()];
//! #
//! # let (alice_state, _) = alice_state.to_round_two(&alice_my_encrypted_secret_shares, &mut rng)?;
//! # let (bob_state, _) = bob_state.to_round_two(&bob_my_encrypted_secret_shares, &mut rng)?;
//! # let (carol_state, _) = carol_state.to_round_two(&carol_my_encrypted_secret_shares, &mut rng)?;
//! #
//! # let (alice_group_key, alice_secret_key) = alice_state.finish()?;
//! # let (bob_group_key, bob_secret_key) = bob_state.finish()?;
//! # let (carol_group_key, carol_secret_key) = carol_state.finish()?;
//! #
//! # assert!(alice_group_key == bob_group_key);
//! # assert!(carol_group_key == bob_group_key);
//! #
//! # // Instantiate new configuration parameters and create a set of signers
//! # let new_params = ThresholdParameters::new(4, 3)?;
//! #
//! # let (alexis, alexis_dh_sk) = Participant::new_signer(new_params, 1, &mut rng)?;
//! # let (barbara, barbara_dh_sk) = Participant::new_signer(new_params, 2, &mut rng)?;
//! # let (claire, claire_dh_sk) = Participant::new_signer(new_params, 3, &mut rng)?;
//! # let (david, david_dh_sk) = Participant::new_signer(new_params, 4, &mut rng)?;
//! #
//! # let signers: Vec<Participant<Secp256k1Sha256>> = vec![alexis.clone(), barbara.clone(), claire.clone(), david.clone()];
//! # let (alice_as_dealer, alice_encrypted_shares, participant_lists) =
//! #     Participant::reshare(new_params, &alice_secret_key, &signers, &mut rng)?;
//! # let (bob_as_dealer, bob_encrypted_shares, participant_lists) =
//! #     Participant::reshare(new_params, &bob_secret_key, &signers, &mut rng)?;
//! # let (carol_as_dealer, carol_encrypted_shares, participant_lists) =
//! #     Participant::reshare(new_params, &carol_secret_key, &signers, &mut rng)?;
//! #
//! # let dealers: Vec<Participant<Secp256k1Sha256>> =
//! #     vec![alice_as_dealer.clone(), bob_as_dealer.clone(), carol_as_dealer.clone()];
//! # let (alexis_state, participant_lists) = DistributedKeyGeneration::<_, Secp256k1Sha256>::new(params, &alexis_dh_sk, alexis.index,
//! #                                                    &dealers, &mut rng)?;
//! #
//! # let (barbara_state, participant_lists) = DistributedKeyGeneration::<_, Secp256k1Sha256>::new(params, &barbara_dh_sk, barbara.index,
//! #                                                    &dealers, &mut rng)?;
//! #
//! # let (claire_state, participant_lists) = DistributedKeyGeneration::<_, Secp256k1Sha256>::new(params, &claire_dh_sk, claire.index,
//! #                                                      &dealers, &mut rng)?;
//! #
//! # let (david_state, participant_lists) = DistributedKeyGeneration::<_, Secp256k1Sha256>::new(params, &david_dh_sk, david.index,
//! #                                                      &dealers, &mut rng)?;
//! #
//! # let alexis_my_encrypted_secret_shares = vec![alice_encrypted_shares.get(&alexis.index).unwrap().clone(),
//! #                                   bob_encrypted_shares.get(&alexis.index).unwrap().clone(),
//! #                                   carol_encrypted_shares.get(&alexis.index).unwrap().clone()];
//! # let barbara_my_encrypted_secret_shares = vec![alice_encrypted_shares.get(&barbara.index).unwrap().clone(),
//! #                                   bob_encrypted_shares.get(&barbara.index).unwrap().clone(),
//! #                                   carol_encrypted_shares.get(&barbara.index).unwrap().clone()];
//! # let claire_my_encrypted_secret_shares = vec![alice_encrypted_shares.get(&claire.index).unwrap().clone(),
//! #                                   bob_encrypted_shares.get(&claire.index).unwrap().clone(),
//! #                                   carol_encrypted_shares.get(&claire.index).unwrap().clone()];
//! # let david_my_encrypted_secret_shares = vec![alice_encrypted_shares.get(&david.index).unwrap().clone(),
//! #                                   bob_encrypted_shares.get(&david.index).unwrap().clone(),
//! #                                   carol_encrypted_shares.get(&david.index).unwrap().clone()];
//! #
//! let (alexis_state, alexis_complaints) =
//!     alexis_state.to_round_two(&alexis_my_encrypted_secret_shares, &mut rng)?;
//! let (barbara_state, barbara_complaints) =
//!     barbara_state.to_round_two(&barbara_my_encrypted_secret_shares, &mut rng)?;
//! let (claire_state, claire_complaints) =
//!     claire_state.to_round_two(&claire_my_encrypted_secret_shares, &mut rng)?;
//! let (david_state, david_complaints) =
//!     david_state.to_round_two(&david_my_encrypted_secret_shares, &mut rng)?;
//!
//! // Everything should have run smoothly.
//! assert!(alexis_complaints.is_empty());
//! assert!(barbara_complaints.is_empty());
//! assert!(claire_complaints.is_empty());
//! assert!(david_complaints.is_empty());
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
//! # let params = ThresholdParameters::new(3,2)?;
//! # let mut rng = OsRng;
//! #
//! # let (alice, alice_coefficients, alice_dh_sk) = Participant::new_dealer(params, 1, &mut rng)?;
//! # let (bob, bob_coefficients, bob_dh_sk) = Participant::new_dealer(params, 2, &mut rng)?;
//! # let (carol, carol_coefficients, carol_dh_sk) = Participant::new_dealer(params, 3, &mut rng)?;
//! #
//! # let participants: Vec<Participant<Secp256k1Sha256>> = vec![alice.clone(), bob.clone(), carol.clone()];
//! # let (alice_state, participant_lists) = DistributedKeyGeneration::<_, Secp256k1Sha256>::bootstrap(params, &alice_dh_sk, alice.index, &alice_coefficients,
//! #                                                      &participants, &mut rng)?;
//! # let alice_their_encrypted_secret_shares = alice_state.their_encrypted_secret_shares()?;
//! #
//! # let (bob_state, participant_lists) = DistributedKeyGeneration::<_, Secp256k1Sha256>::bootstrap(params, &bob_dh_sk, bob.index, &bob_coefficients,
//! #                                                    &participants, &mut rng)?;
//! # let bob_their_encrypted_secret_shares = bob_state.their_encrypted_secret_shares()?;
//! #
//! # let (carol_state, participant_lists) = DistributedKeyGeneration::<_, Secp256k1Sha256>::bootstrap(params, &carol_dh_sk, carol.index, &carol_coefficients,
//! #                                                      &participants, &mut rng)?;
//! # let carol_their_encrypted_secret_shares = carol_state.their_encrypted_secret_shares()?;
//! # let alice_my_encrypted_secret_shares = vec![alice_their_encrypted_secret_shares.get(&alice.index).unwrap().clone(),
//! #                                   bob_their_encrypted_secret_shares.get(&alice.index).unwrap().clone(),
//! #                                   carol_their_encrypted_secret_shares.get(&alice.index).unwrap().clone()];
//! # let bob_my_encrypted_secret_shares = vec![alice_their_encrypted_secret_shares.get(&bob.index).unwrap().clone(),
//! #                                 bob_their_encrypted_secret_shares.get(&bob.index).unwrap().clone(),
//! #                                 carol_their_encrypted_secret_shares.get(&bob.index).unwrap().clone()];
//! # let carol_my_encrypted_secret_shares = vec![alice_their_encrypted_secret_shares.get(&carol.index).unwrap().clone(),
//! #                                   bob_their_encrypted_secret_shares.get(&carol.index).unwrap().clone(),
//! #                                   carol_their_encrypted_secret_shares.get(&carol.index).unwrap().clone()];
//! #
//! # let (alice_state, _) = alice_state.to_round_two(&alice_my_encrypted_secret_shares, &mut rng)?;
//! # let (bob_state, _) = bob_state.to_round_two(&bob_my_encrypted_secret_shares, &mut rng)?;
//! # let (carol_state, _) = carol_state.to_round_two(&carol_my_encrypted_secret_shares, &mut rng)?;
//! #
//! # let (alice_group_key, alice_secret_key) = alice_state.finish()?;
//! # let (bob_group_key, bob_secret_key) = bob_state.finish()?;
//! # let (carol_group_key, carol_secret_key) = carol_state.finish()?;
//! #
//! # assert!(alice_group_key == bob_group_key);
//! # assert!(carol_group_key == bob_group_key);
//! #
//! # let new_params = ThresholdParameters::new(4, 3)?;
//! #
//! # let (alexis, alexis_dh_sk) = Participant::new_signer(new_params, 1, &mut rng)?;
//! # let (barbara, barbara_dh_sk) = Participant::new_signer(new_params, 2, &mut rng)?;
//! # let (claire, claire_dh_sk) = Participant::new_signer(new_params, 3, &mut rng)?;
//! # let (david, david_dh_sk) = Participant::new_signer(new_params, 4, &mut rng)?;
//! #
//! # let signers: Vec<Participant<Secp256k1Sha256>> = vec![alexis.clone(), barbara.clone(), claire.clone(), david.clone()];
//! # let (alice_as_dealer, alice_encrypted_shares, participant_lists) =
//! #     Participant::reshare(new_params, &alice_secret_key, &signers, &mut rng)?;
//! # let (bob_as_dealer, bob_encrypted_shares, participant_lists) =
//! #     Participant::reshare(new_params, &bob_secret_key, &signers, &mut rng)?;
//! # let (carol_as_dealer, carol_encrypted_shares, participant_lists) =
//! #     Participant::reshare(new_params, &carol_secret_key, &signers, &mut rng)?;
//! #
//! # let dealers: Vec<Participant<Secp256k1Sha256>> = vec![alice_as_dealer.clone(), bob_as_dealer.clone(), carol_as_dealer.clone()];
//! # let (alexis_state, participant_lists) = DistributedKeyGeneration::<_, Secp256k1Sha256>::new(params, &alexis_dh_sk, alexis.index,
//! #                                                    &dealers, &mut rng)?;
//! #
//! # let (barbara_state, participant_lists) = DistributedKeyGeneration::<_, Secp256k1Sha256>::new(params, &barbara_dh_sk, barbara.index,
//! #                                                    &dealers, &mut rng)?;
//! #
//! # let (claire_state, participant_lists) = DistributedKeyGeneration::<_, Secp256k1Sha256>::new(params, &claire_dh_sk, claire.index,
//! #                                                      &dealers, &mut rng)?;
//! #
//! # let (david_state, participant_lists) = DistributedKeyGeneration::<_, Secp256k1Sha256>::new(params, &david_dh_sk, david.index,
//! #                                                      &dealers, &mut rng)?;
//! #
//! # let alexis_my_encrypted_secret_shares = vec![alice_encrypted_shares.get(&alexis.index).unwrap().clone(),
//! #                                   bob_encrypted_shares.get(&alexis.index).unwrap().clone(),
//! #                                   carol_encrypted_shares.get(&alexis.index).unwrap().clone()];
//! # let barbara_my_encrypted_secret_shares = vec![alice_encrypted_shares.get(&barbara.index).unwrap().clone(),
//! #                                   bob_encrypted_shares.get(&barbara.index).unwrap().clone(),
//! #                                   carol_encrypted_shares.get(&barbara.index).unwrap().clone()];
//! # let claire_my_encrypted_secret_shares = vec![alice_encrypted_shares.get(&claire.index).unwrap().clone(),
//! #                                   bob_encrypted_shares.get(&claire.index).unwrap().clone(),
//! #                                   carol_encrypted_shares.get(&claire.index).unwrap().clone()];
//! # let david_my_encrypted_secret_shares = vec![alice_encrypted_shares.get(&david.index).unwrap().clone(),
//! #                                   bob_encrypted_shares.get(&david.index).unwrap().clone(),
//! #                                   carol_encrypted_shares.get(&david.index).unwrap().clone()];
//! #
//! # let (alexis_state, _) = alexis_state.to_round_two(&alexis_my_encrypted_secret_shares, &mut rng)?;
//! # let (barbara_state, _) = barbara_state.to_round_two(&barbara_my_encrypted_secret_shares, &mut rng)?;
//! # let (claire_state, _) = claire_state.to_round_two(&claire_my_encrypted_secret_shares, &mut rng)?;
//! # let (david_state, _) = david_state.to_round_two(&david_my_encrypted_secret_shares, &mut rng)?;
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
//! ## Malicious participants and complaints handling
//!
//! ICE-FROST Distributed Key Generation and Resharing processes are robust, meaning that they can terminate
//! successfully even in presence of malicious adversaries, as long as there remain at least t honest participants
//! within a t-out-of-n initial session.
//!
//! During the initial phase of the DKG, invalid NIZK proofs of DH public keys, or invalid NIZK proofs of secret key
//! (if any) would result in adversaries being flagged and added to the `misbehaving_participants` list.
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
//! # let params = ThresholdParameters::new(3,2)?;
//! # let mut rng = OsRng;
//! #
//! let (alice, alice_coefficients, alice_dh_sk) = Participant::new_dealer(params, 1, &mut rng)?;
//! let (mut bob, bob_coefficients, bob_dh_sk) = Participant::new_dealer(params, 2, &mut rng)?;
//! // Let's change Bob's dh_public_key so that his NIZK proof becomes invalid.
//! bob.dh_public_key = alice.dh_public_key.clone();
//! let (carol, carol_coefficients, carol_dh_sk) = Participant::new_dealer(params, 3, &mut rng)?;
//!
//! let participants: Vec<Participant<Secp256k1Sha256>> =
//!     vec![alice.clone(), bob.clone(), carol.clone()];
//! let (alice_state, participant_lists) =
//!     DistributedKeyGeneration::<_, Secp256k1Sha256>::bootstrap(
//!         params, &alice_dh_sk, alice.index, &alice_coefficients, &participants, &mut rng
//!     )?;
//! assert!(participant_lists.valid_participants == vec![alice.clone(), carol.clone()]);
//! assert!(participant_lists.misbehaving_participants.is_some());
//! assert!(participant_lists.misbehaving_participants.unwrap() == vec![bob.index]);
//!
//! // Ignore Bob as he would be discarded anyway.
//!
//! let (carol_state, participant_lists) =
//!     DistributedKeyGeneration::<_, Secp256k1Sha256>::bootstrap(
//!         params, &carol_dh_sk, carol.index, &carol_coefficients, &participants, &mut rng
//!     )?;
//! assert!(participant_lists.valid_participants == vec![alice, carol]);
//! assert!(participant_lists.misbehaving_participants.is_some());
//! assert!(participant_lists.misbehaving_participants.unwrap() == vec![bob.index]);
//!
//! # Ok(()) }
//! # fn main() { assert!(do_test().is_ok()); }
//! ```
//!
//! Upon detected misbehaviour, the remaining honest participants must discard possibly incoming shares
//! from malicious participants before proceeding to the secound round of the DKG.
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
//! # let params = ThresholdParameters::new(3,2)?;
//! # let mut rng = OsRng;
//! #
//! # let (alice, alice_coefficients, alice_dh_sk) = Participant::new_dealer(params, 1, &mut rng)?;
//! # let (mut bob, bob_coefficients, bob_dh_sk) = Participant::new_dealer(params, 2, &mut rng)?;
//! # // Let's change Bob's dh_public_key so that his NIZK proof becomes invalid.
//! # bob.dh_public_key = alice.dh_public_key.clone();
//! # let (carol, carol_coefficients, carol_dh_sk) = Participant::new_dealer(params, 3, &mut rng)?;
//! #
//! # let participants: Vec<Participant<Secp256k1Sha256>> = vec![alice.clone(), bob.clone(), carol.clone()];
//! # let (alice_state, participant_lists) = DistributedKeyGeneration::<_, Secp256k1Sha256>::bootstrap(
//! #       params, &alice_dh_sk, alice.index, &alice_coefficients, &participants, &mut rng)?;
//! # let alice_their_encrypted_secret_shares = alice_state.their_encrypted_secret_shares()?;
//! #
//! # let (carol_state, participant_lists) = DistributedKeyGeneration::<_, Secp256k1Sha256>::bootstrap(
//! #       params, &carol_dh_sk, carol.index, &carol_coefficients, &participants, &mut rng)?;
//! # let carol_their_encrypted_secret_shares = carol_state.their_encrypted_secret_shares()?;
//! #
//! // Alice and Carol will ignore encrypted shares they may have received from Bob.
//! let alice_my_encrypted_secret_shares = vec![
//!     alice_their_encrypted_secret_shares.get(&alice.index).unwrap().clone(),
//!     carol_their_encrypted_secret_shares.get(&alice.index).unwrap().clone()
//! ];
//! let carol_my_encrypted_secret_shares = vec![
//!     alice_their_encrypted_secret_shares.get(&carol.index).unwrap().clone(),
//!     carol_their_encrypted_secret_shares.get(&carol.index).unwrap().clone()
//! ];
//!
//! let (alice_state, _) = alice_state.to_round_two(&alice_my_encrypted_secret_shares, &mut rng)?;
//! let (carol_state, _) = carol_state.to_round_two(&carol_my_encrypted_secret_shares, &mut rng)?;
//!
//! # Ok(()) }
//! # fn main() { assert!(do_test().is_ok()); }
//! ```
//!
//! During the second phase of the DKG, invalid encrypted secret shares would result in adversaries being flagged
//! by generating a complaint. Those complaints would then be publicly shared with every other participant, who would
//! process them in order to settle on who is to blame between the plaintiff and the defendant.
//!
//! Note that this process of complaint verification is *necessary* for honest parties to proceed to the end of the DKG.
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
//! # let params = ThresholdParameters::new(3,2)?;
//! # let mut rng = OsRng;
//! // Alice, Bob and Carol run the first round of the DKG without trouble...
//! #
//! # let (alice, alice_coefficients, alice_dh_sk) = Participant::new_dealer(params, 1, &mut rng)?;
//! # let (bob, bob_coefficients, bob_dh_sk) = Participant::new_dealer(params, 2, &mut rng)?;
//! # let (carol, carol_coefficients, carol_dh_sk) = Participant::new_dealer(params, 3, &mut rng)?;
//! #
//! # let participants: Vec<Participant<Secp256k1Sha256>> = vec![alice.clone(), bob.clone(), carol.clone()];
//! # let (alice_state, participant_lists) = DistributedKeyGeneration::<_, Secp256k1Sha256>::bootstrap(
//! #       params, &alice_dh_sk, alice.index, &alice_coefficients, &participants, &mut rng)?;
//! # let alice_their_encrypted_secret_shares = alice_state.their_encrypted_secret_shares()?;
//! #
//! # let (bob_state, participant_lists) = DistributedKeyGeneration::<_, Secp256k1Sha256>::bootstrap(
//! #       params, &bob_dh_sk, bob.index, &bob_coefficients, &participants, &mut rng)?;
//! # let mut bob_their_encrypted_secret_shares = bob_state.their_encrypted_secret_shares()?.clone();
//! # bob_their_encrypted_secret_shares.get_mut(&alice.index).unwrap().nonce = [0; 12].into();
//! #
//! # let (carol_state, participant_lists) = DistributedKeyGeneration::<_, Secp256k1Sha256>::bootstrap(
//! #       params, &carol_dh_sk, carol.index, &carol_coefficients, &participants, &mut rng)?;
//! # let carol_their_encrypted_secret_shares = carol_state.their_encrypted_secret_shares()?;
//! #
//!
//! // Bob will send an invalid share to Alice.
//! let invalid_share = bob_their_encrypted_secret_shares.get(&alice.index).unwrap();
//!
//! let alice_my_encrypted_secret_shares = vec![
//!     alice_their_encrypted_secret_shares.get(&alice.index).unwrap().clone(),
//!     invalid_share.clone(),
//!     carol_their_encrypted_secret_shares.get(&alice.index).unwrap().clone()];
//!
//! // Ignore Bob as he would be discarded anyway.
//!
//! let carol_my_encrypted_secret_shares = vec![
//!     alice_their_encrypted_secret_shares.get(&carol.index).unwrap().clone(),
//!     bob_their_encrypted_secret_shares.get(&carol.index).unwrap().clone(),
//!     carol_their_encrypted_secret_shares.get(&carol.index).unwrap().clone()
//! ];
//!
//! let (mut alice_state, alice_complaints) =
//!     alice_state.to_round_two(&alice_my_encrypted_secret_shares, &mut rng)?;
//! let (mut carol_state, carol_complaints) =
//!     carol_state.to_round_two(&carol_my_encrypted_secret_shares, &mut rng)?;
//!
//! assert!(alice_complaints.len() == 1);
//! assert!(carol_complaints.is_empty());
//!
//! # Ok(()) }
//! # fn main() { assert!(do_test().is_ok()); }
//! ```
//!
//! Alice shares her complaint with all other participants. Everyone will process the received complaints,
//! update their internal state accordingly, and then conclude with this DKG. The complaint handling is done
//! through the `blame` method which will determine whom of the plaintiff or the defendant is malicious.
//!
//! Note that one can process several complaints against the same participant, in which case the subsequent
//! complaint settlements won't update the state (as this participant will have already been removed, if malicious).
//!
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
//! # let params = ThresholdParameters::new(3,2)?;
//! # let mut rng = OsRng;
//! // Alice, Bob and Carol run the first round of the DKG without trouble...
//! #
//! # let (alice, alice_coefficients, alice_dh_sk) = Participant::new_dealer(params, 1, &mut rng)?;
//! # let (bob, bob_coefficients, bob_dh_sk) = Participant::new_dealer(params, 2, &mut rng)?;
//! # let (carol, carol_coefficients, carol_dh_sk) = Participant::new_dealer(params, 3, &mut rng)?;
//! #
//! # let participants: Vec<Participant<Secp256k1Sha256>> = vec![alice.clone(), bob.clone(), carol.clone()];
//! # let (alice_state, participant_lists) = DistributedKeyGeneration::<_, Secp256k1Sha256>::bootstrap(
//! #       params, &alice_dh_sk, alice.index, &alice_coefficients, &participants, &mut rng)?;
//! # let alice_their_encrypted_secret_shares = alice_state.their_encrypted_secret_shares()?;
//! #
//! # let (bob_state, participant_lists) = DistributedKeyGeneration::<_, Secp256k1Sha256>::bootstrap(
//! #       params, &bob_dh_sk, bob.index, &bob_coefficients, &participants, &mut rng)?;
//! # let mut bob_their_encrypted_secret_shares = bob_state.their_encrypted_secret_shares()?.clone();
//! # bob_their_encrypted_secret_shares.get_mut(&alice.index).unwrap().nonce = [0; 12].into();
//! #
//! # let (carol_state, participant_lists) = DistributedKeyGeneration::<_, Secp256k1Sha256>::bootstrap(
//! #       params, &carol_dh_sk, carol.index, &carol_coefficients, &participants, &mut rng)?;
//! # let carol_their_encrypted_secret_shares = carol_state.their_encrypted_secret_shares()?;
//! #
//! # // Bob will send an invalid share to Alice.
//! # let invalid_share = bob_their_encrypted_secret_shares.get(&alice.index).unwrap();
//! #
//! # let alice_my_encrypted_secret_shares = vec![
//! #     alice_their_encrypted_secret_shares.get(&alice.index).unwrap().clone(),
//! #     invalid_share.clone(),
//! #     carol_their_encrypted_secret_shares.get(&alice.index).unwrap().clone()];
//! #
//! # // Ignore Bob as he would be discarded anyway.
//! #
//! # let carol_my_encrypted_secret_shares = vec![
//! #     alice_their_encrypted_secret_shares.get(&carol.index).unwrap().clone(),
//! #     bob_their_encrypted_secret_shares.get(&carol.index).unwrap().clone(),
//! #     carol_their_encrypted_secret_shares.get(&carol.index).unwrap().clone()
//! # ];
//! #
//! # let (mut alice_state, alice_complaints) = alice_state.to_round_two(&alice_my_encrypted_secret_shares, &mut rng)?;
//! # let (mut carol_state, carol_complaints) = carol_state.to_round_two(&carol_my_encrypted_secret_shares, &mut rng)?;
//! #
//! let all_complaints = &[alice_complaints, carol_complaints].concat();
//! let rejected_keys = alice_state.blame(&all_complaints);
//! assert!(rejected_keys.len() == 1);
//! assert!(rejected_keys[0] == bob.dh_public_key);
//! carol_state.blame(&all_complaints);
//! assert!(rejected_keys.len() == 1);
//! assert!(rejected_keys[0] == bob.dh_public_key);
//!
//! // Alice and Carol can now finish correctly their DKG.
//! let (alice_group_key, alice_secret_key) = alice_state.finish()?;
//! let (carol_group_key, carol_secret_key) = carol_state.finish()?;
//!
//! assert!(alice_group_key == carol_group_key);
//!
//! # Ok(()) }
//! # fn main() { assert!(do_test().is_ok()); }
//! ```
//!
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
//! # let params = ThresholdParameters::new(3,2)?;
//! # let mut rng = OsRng;
//! #
//! # let (alice, alice_coefficients, alice_dh_sk) = Participant::new_dealer(params, 1, &mut rng)?;
//! # let (bob, bob_coefficients, bob_dh_sk) = Participant::new_dealer(params, 2, &mut rng)?;
//! # let (carol, carol_coefficients, carol_dh_sk) = Participant::new_dealer(params, 3, &mut rng)?;
//! #
//! # let participants: Vec<Participant<Secp256k1Sha256>> = vec![alice.clone(), bob.clone(), carol.clone()];
//! # let (alice_state, participant_lists) = DistributedKeyGeneration::<_, Secp256k1Sha256>::bootstrap(params, &alice_dh_sk, alice.index, &alice_coefficients,
//! #                                                      &participants, &mut rng)?;
//! # let alice_their_encrypted_secret_shares = alice_state.their_encrypted_secret_shares()?;
//! #
//! # let (bob_state, participant_lists) = DistributedKeyGeneration::<_, Secp256k1Sha256>::bootstrap(params, &bob_dh_sk, bob.index, &bob_coefficients,
//! #                                                    &participants, &mut rng)?;
//! # let bob_their_encrypted_secret_shares = bob_state.their_encrypted_secret_shares()?;
//! #
//! # let (carol_state, participant_lists) = DistributedKeyGeneration::<_, Secp256k1Sha256>::bootstrap(params, &carol_dh_sk, carol.index, &carol_coefficients,
//! #                                                      &participants, &mut rng)?;
//! # let carol_their_encrypted_secret_shares = carol_state.their_encrypted_secret_shares()?;
//! # let alice_my_encrypted_secret_shares = vec![alice_their_encrypted_secret_shares.get(&alice.index).unwrap().clone(),
//! #                                   bob_their_encrypted_secret_shares.get(&alice.index).unwrap().clone(),
//! #                                   carol_their_encrypted_secret_shares.get(&alice.index).unwrap().clone()];
//! # let bob_my_encrypted_secret_shares = vec![alice_their_encrypted_secret_shares.get(&bob.index).unwrap().clone(),
//! #                                 bob_their_encrypted_secret_shares.get(&bob.index).unwrap().clone(),
//! #                                 carol_their_encrypted_secret_shares.get(&bob.index).unwrap().clone()];
//! # let carol_my_encrypted_secret_shares = vec![alice_their_encrypted_secret_shares.get(&carol.index).unwrap().clone(),
//! #                                   bob_their_encrypted_secret_shares.get(&carol.index).unwrap().clone(),
//! #                                   carol_their_encrypted_secret_shares.get(&carol.index).unwrap().clone()];
//! #
//! # let (alice_state, _) = alice_state.to_round_two(&alice_my_encrypted_secret_shares, &mut rng)?;
//! # let (bob_state, _) = bob_state.to_round_two(&bob_my_encrypted_secret_shares, &mut rng)?;
//! # let (carol_state, _) = carol_state.to_round_two(&carol_my_encrypted_secret_shares, &mut rng)?;
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
//!     generate_commitment_share_lists::<Secp256k1Sha256>(&mut rng, &alice_secret_key, 1)?;
//! let (bob_public_comshares, mut bob_secret_comshares) =
//!     generate_commitment_share_lists::<Secp256k1Sha256>(&mut rng, &bob_secret_key, 1)?;
//! let (carol_public_comshares, mut carol_secret_comshares) =
//!     generate_commitment_share_lists::<Secp256k1Sha256>(&mut rng, &carol_secret_key, 1)?;
//!
//! let message = b"This is a test of the tsunami alert system. This is only a test.";
//!
//! // The aggregator can be anyone who knows the group key,
//! // not necessarily Bob or a group participant.
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
//! The aggregator takes note of each expected signer for this run of the protocol.
//! For this run, we'll have Alice and Carol sign.
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
//! # let params = ThresholdParameters::new(3,2)?;
//! # let mut rng = OsRng;
//! #
//! # let (alice, alice_coefficients, alice_dh_sk) = Participant::new_dealer(params, 1, &mut rng)?;
//! # let (bob, bob_coefficients, bob_dh_sk) = Participant::new_dealer(params, 2, &mut rng)?;
//! # let (carol, carol_coefficients, carol_dh_sk) = Participant::new_dealer(params, 3, &mut rng)?;
//! #
//! # let participants: Vec<Participant<Secp256k1Sha256>> = vec![alice.clone(), bob.clone(), carol.clone()];
//! # let (alice_state, participant_lists) = DistributedKeyGeneration::<_, Secp256k1Sha256>::bootstrap(params, &alice_dh_sk, alice.index, &alice_coefficients,
//! #                                                      &participants, &mut rng)?;
//! # let alice_their_encrypted_secret_shares = alice_state.their_encrypted_secret_shares()?;
//! #
//! # let (bob_state, participant_lists) = DistributedKeyGeneration::<_, Secp256k1Sha256>::bootstrap(params, &bob_dh_sk, bob.index, &bob_coefficients,
//! #                                                    &participants, &mut rng)?;
//! # let bob_their_encrypted_secret_shares = bob_state.their_encrypted_secret_shares()?;
//! #
//! # let (carol_state, participant_lists) = DistributedKeyGeneration::<_, Secp256k1Sha256>::bootstrap(params, &carol_dh_sk, carol.index, &carol_coefficients,
//! #                                                      &participants, &mut rng)?;
//! # let carol_their_encrypted_secret_shares = carol_state.their_encrypted_secret_shares()?;
//! # let alice_my_encrypted_secret_shares = vec![alice_their_encrypted_secret_shares.get(&alice.index).unwrap().clone(),
//! #                                   bob_their_encrypted_secret_shares.get(&alice.index).unwrap().clone(),
//! #                                   carol_their_encrypted_secret_shares.get(&alice.index).unwrap().clone()];
//! # let bob_my_encrypted_secret_shares = vec![alice_their_encrypted_secret_shares.get(&bob.index).unwrap().clone(),
//! #                                 bob_their_encrypted_secret_shares.get(&bob.index).unwrap().clone(),
//! #                                 carol_their_encrypted_secret_shares.get(&bob.index).unwrap().clone()];
//! # let carol_my_encrypted_secret_shares = vec![alice_their_encrypted_secret_shares.get(&carol.index).unwrap().clone(),
//! #                                   bob_their_encrypted_secret_shares.get(&carol.index).unwrap().clone(),
//! #                                   carol_their_encrypted_secret_shares.get(&carol.index).unwrap().clone()];
//! #
//! # let (alice_state, _) = alice_state.to_round_two(&alice_my_encrypted_secret_shares, &mut rng)?;
//! # let (bob_state, _) = bob_state.to_round_two(&bob_my_encrypted_secret_shares, &mut rng)?;
//! # let (carol_state, _) = carol_state.to_round_two(&carol_my_encrypted_secret_shares, &mut rng)?;
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
//! #     generate_commitment_share_lists::<Secp256k1Sha256>(&mut rng, &alice_secret_key, 1)?;
//! # let (bob_public_comshares, mut bob_secret_comshares) =
//! #     generate_commitment_share_lists::<Secp256k1Sha256>(&mut rng, &bob_secret_key, 1)?;
//! # let (carol_public_comshares, mut carol_secret_comshares) =
//! #     generate_commitment_share_lists::<Secp256k1Sha256>(&mut rng, &carol_secret_key, 1)?;
//! #
//! # let message = b"This is a test of the tsunami alert system. This is only a test.";
//! #
//! # let mut aggregator = SignatureAggregator::new(params, bob_group_key.clone(), &message[..]);
//! #
//! aggregator.include_signer(1, alice_public_comshares.commitments[0], &alice_public_key);
//! aggregator.include_signer(3, carol_public_comshares.commitments[0], &carol_public_key);
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
//! # let params = ThresholdParameters::new(3,2)?;
//! # let mut rng = OsRng;
//! #
//! # let (alice, alice_coefficients, alice_dh_sk) = Participant::new_dealer(params, 1, &mut rng)?;
//! # let (bob, bob_coefficients, bob_dh_sk) = Participant::new_dealer(params, 2, &mut rng)?;
//! # let (carol, carol_coefficients, carol_dh_sk) = Participant::new_dealer(params, 3, &mut rng)?;
//! #
//! # let participants: Vec<Participant<Secp256k1Sha256>> = vec![alice.clone(), bob.clone(), carol.clone()];
//! # let (alice_state, participant_lists) = DistributedKeyGeneration::<_, Secp256k1Sha256>::bootstrap(params, &alice_dh_sk, alice.index, &alice_coefficients,
//! #                                                      &participants, &mut rng)?;
//! # let alice_their_encrypted_secret_shares = alice_state.their_encrypted_secret_shares()?;
//! #
//! # let (bob_state, participant_lists) = DistributedKeyGeneration::<_, Secp256k1Sha256>::bootstrap(params, &bob_dh_sk, bob.index, &bob_coefficients,
//! #                                                    &participants, &mut rng)?;
//! # let bob_their_encrypted_secret_shares = bob_state.their_encrypted_secret_shares()?;
//! #
//! # let (carol_state, participant_lists) = DistributedKeyGeneration::<_, Secp256k1Sha256>::bootstrap(params, &carol_dh_sk, carol.index, &carol_coefficients,
//! #                                                      &participants, &mut rng)?;
//! # let carol_their_encrypted_secret_shares = carol_state.their_encrypted_secret_shares()?;
//! # let alice_my_encrypted_secret_shares = vec![alice_their_encrypted_secret_shares.get(&alice.index).unwrap().clone(),
//! #                                   bob_their_encrypted_secret_shares.get(&alice.index).unwrap().clone(),
//! #                                   carol_their_encrypted_secret_shares.get(&alice.index).unwrap().clone()];
//! # let bob_my_encrypted_secret_shares = vec![alice_their_encrypted_secret_shares.get(&bob.index).unwrap().clone(),
//! #                                 bob_their_encrypted_secret_shares.get(&bob.index).unwrap().clone(),
//! #                                 carol_their_encrypted_secret_shares.get(&bob.index).unwrap().clone()];
//! # let carol_my_encrypted_secret_shares = vec![alice_their_encrypted_secret_shares.get(&carol.index).unwrap().clone(),
//! #                                   bob_their_encrypted_secret_shares.get(&carol.index).unwrap().clone(),
//! #                                   carol_their_encrypted_secret_shares.get(&carol.index).unwrap().clone()];
//! #
//! # let (alice_state, _) = alice_state.to_round_two(&alice_my_encrypted_secret_shares, &mut rng)?;
//! # let (bob_state, _) = bob_state.to_round_two(&bob_my_encrypted_secret_shares, &mut rng)?;
//! # let (carol_state, _) = carol_state.to_round_two(&carol_my_encrypted_secret_shares, &mut rng)?;
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
//! #     generate_commitment_share_lists::<Secp256k1Sha256>(&mut rng, &alice_secret_key, 1)?;
//! # let (bob_public_comshares, mut bob_secret_comshares) =
//! #     generate_commitment_share_lists::<Secp256k1Sha256>(&mut rng, &bob_secret_key, 1)?;
//! # let (carol_public_comshares, mut carol_secret_comshares) =
//! #     generate_commitment_share_lists::<Secp256k1Sha256>(&mut rng, &carol_secret_key, 1)?;
//! #
//! # let message = b"This is a test of the tsunami alert system. This is only a test.";
//! #
//! # let mut aggregator = SignatureAggregator::new(params, bob_group_key.clone(), &message[..]);
//! #
//! # aggregator.include_signer(1, alice_public_comshares.commitments[0], &alice_public_key);
//! # aggregator.include_signer(3, carol_public_comshares.commitments[0], &carol_public_key);
//! let signers = aggregator.signers();
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
//! # let params = ThresholdParameters::new(3,2)?;
//! # let mut rng = OsRng;
//! #
//! # let (alice, alice_coefficients, alice_dh_sk) = Participant::new_dealer(params, 1, &mut rng)?;
//! # let (bob, bob_coefficients, bob_dh_sk) = Participant::new_dealer(params, 2, &mut rng)?;
//! # let (carol, carol_coefficients, carol_dh_sk) = Participant::new_dealer(params, 3, &mut rng)?;
//! #
//! # let participants: Vec<Participant<Secp256k1Sha256>> = vec![alice.clone(), bob.clone(), carol.clone()];
//! # let (alice_state, participant_lists) = DistributedKeyGeneration::<_, Secp256k1Sha256>::bootstrap(params, &alice_dh_sk, alice.index, &alice_coefficients,
//! #                                                      &participants, &mut rng)?;
//! # let alice_their_encrypted_secret_shares = alice_state.their_encrypted_secret_shares()?;
//! #
//! # let (bob_state, participant_lists) = DistributedKeyGeneration::<_, Secp256k1Sha256>::bootstrap(params, &bob_dh_sk, bob.index, &bob_coefficients,
//! #                                                    &participants, &mut rng)?;
//! # let bob_their_encrypted_secret_shares = bob_state.their_encrypted_secret_shares()?;
//! #
//! # let (carol_state, participant_lists) = DistributedKeyGeneration::<_, Secp256k1Sha256>::bootstrap(params, &carol_dh_sk, carol.index, &carol_coefficients,
//! #                                                      &participants, &mut rng)?;
//! # let carol_their_encrypted_secret_shares = carol_state.their_encrypted_secret_shares()?;
//! # let alice_my_encrypted_secret_shares = vec![alice_their_encrypted_secret_shares.get(&alice.index).unwrap().clone(),
//! #                                   bob_their_encrypted_secret_shares.get(&alice.index).unwrap().clone(),
//! #                                   carol_their_encrypted_secret_shares.get(&alice.index).unwrap().clone()];
//! # let bob_my_encrypted_secret_shares = vec![alice_their_encrypted_secret_shares.get(&bob.index).unwrap().clone(),
//! #                                 bob_their_encrypted_secret_shares.get(&bob.index).unwrap().clone(),
//! #                                 carol_their_encrypted_secret_shares.get(&bob.index).unwrap().clone()];
//! # let carol_my_encrypted_secret_shares = vec![alice_their_encrypted_secret_shares.get(&carol.index).unwrap().clone(),
//! #                                   bob_their_encrypted_secret_shares.get(&carol.index).unwrap().clone(),
//! #                                   carol_their_encrypted_secret_shares.get(&carol.index).unwrap().clone()];
//! #
//! # let (alice_state, _) = alice_state.to_round_two(&alice_my_encrypted_secret_shares, &mut rng)?;
//! # let (bob_state, _) = bob_state.to_round_two(&bob_my_encrypted_secret_shares, &mut rng)?;
//! # let (carol_state, _) = carol_state.to_round_two(&carol_my_encrypted_secret_shares, &mut rng)?;
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
//! #     generate_commitment_share_lists::<Secp256k1Sha256>(&mut rng, &alice_secret_key, 1)?;
//! # let (bob_public_comshares, mut bob_secret_comshares) =
//! #     generate_commitment_share_lists::<Secp256k1Sha256>(&mut rng, &bob_secret_key, 1)?;
//! # let (carol_public_comshares, mut carol_secret_comshares) =
//! #     generate_commitment_share_lists::<Secp256k1Sha256>(&mut rng, &carol_secret_key, 1)?;
//! #
//! # let message = b"This is a test of the tsunami alert system. This is only a test.";
//! #
//! # let mut aggregator = SignatureAggregator::new(params, bob_group_key.clone(), &message[..]);
//! #
//! # aggregator.include_signer(1, alice_public_comshares.commitments[0], &alice_public_key);
//! # aggregator.include_signer(3, carol_public_comshares.commitments[0], &carol_public_key);
//! #
//! # let signers = aggregator.signers();
//! # let message_hash = Secp256k1Sha256::h4(&message[..]);
//!
//! let alice_partial = alice_secret_key.sign(
//!     &message_hash,
//!     &alice_group_key,
//!     &mut alice_secret_comshares,
//!     0,
//!     signers
//! )?;
//! let carol_partial = carol_secret_key.sign(
//!     &message_hash,
//!     &carol_group_key,
//!     &mut carol_secret_comshares,
//!     0,
//!     signers
//! )?;
//!
//! aggregator.include_partial_signature(&alice_partial);
//! aggregator.include_partial_signature(&carol_partial);
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

#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(missing_debug_implementations)]
#![deny(missing_docs)]
#![deny(unsafe_code)]
#![warn(future_incompatible)]
#![allow(clippy::type_complexity)]

#[cfg(feature = "std")]
#[macro_use]
extern crate std;

#[cfg(not(feature = "std"))]
#[macro_use]
extern crate alloc;

pub(crate) const HASH_SEC_PARAM: usize = 128;

mod error;
pub use error::{Error, FrostResult};

/// A module defining traits for implementing convenient encoding and decoding to/from bytes.
mod serialization;
pub use serialization::{FromBytes, ToBytes};

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

/// This module provides a concrete implementation of an ICE-FROST [`CipherSuite`] over Secp256k1,
/// with SHA-256 as underlying base hash function.
/// It is made available for testing and benchmarking purposes.
pub mod testing {
    use super::{utils, CipherSuite};

    use aes_gcm::Aes128Gcm;
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

        type Cipher = Aes128Gcm;

        fn context_string() -> String {
            "ICE-FROST_SECP256K1_SHA256".to_owned()
        }
    }
}
