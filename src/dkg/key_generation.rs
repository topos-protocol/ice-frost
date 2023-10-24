//! The static and robust ICE-FROST Distributed Key generation (DKG) protocol.
//!
//! This implementation uses the [typestate] design pattern (also called session
//! types) behind the scenes to enforce that more programming errors are discoverable
//! at compile-time.  Additionally, secrets generated for commitment openings, secret keys,
//! nonces in zero-knowledge proofs, etc., are zeroed-out in memory when they are dropped
//! out of scope.
//!
//! # Details
//!
//! ## Round One
//!
//! * Step #1: Every participant \\(P\_i\\) samples \\(t\\) random values \\((a\_{i0}, \\dots, a\_{i(t-1)})\\)
//!            uniformly in \\(\mathbb{Z}\_q\\), and uses these values as coefficients to define a
//!            polynomial \\(f\_i\(x\) = \sum\_{j=0}^{t-1} a\_{ij} x^{j}\\) of degree \\( t-1 \\) over
//!            \\(\mathbb{Z}\_q\\).
//!
//! These step numbers are given as written in the paper. They are executed in a different order to
//! save one scalar multiplication.
//!
//! * Step #3: Every participant \\(P\_i\\) computes a public commitment
//!            \\(C\_i = \[\phi\_{i0}, \\dots, \phi\_{i(t-1)}\]\\), where \\(\phi\_{ij} = g^{a\_{ij}}\\),
//!            \\(0 \le j \le t-1\\).
//!
//! * Step #2: Every \\(P\_i\\) computes a proof of knowledge to the corresponding secret key
//!            \\(a\_{i0}\\) by calculating a pseudo-Schnorr signature \\(\sigma\_i = \(s, r\)\\).
//!
//! * Step #4: Every participant \\(P\_i\\) broadcasts \\(\(C\_i\\), \\(\sigma\_i\)\\) to all other participants.
//!
//! * Step #5: Upon receiving \\((C\_l, \sigma\_l)\\) from participants \\(1 \le l \le n\\), \\(l \ne i\\),
//!            participant \\(P\_i\\) verifies \\(\sigma\_l = (s\_l, r\_l)\\), by checking:
//!            \\(s\_l \stackrel{?}{=} \mathcal{H}(l, \Phi, \phi\_{l0}, g^{r\_l} \cdot \phi\_{l0}^{-s\_i})\\).
//!            If any participants' proofs cannot be verified, return their participant indices.
//!
//! ## Round Two
//!
//! * Step #1: Each \\(P\_i\\) securely sends to each other participant \\(P\_l\\) a secret share
//!            \\((l, f\_i(l))\\) using their secret polynomial \\(f\_i(l)\\) and keeps \\((i, f\_i(i))\\)
//!            for themselves.
//!
//! * Step #2: Each \\(P\_i\\) verifies their shares by calculating:
//!            \\(g^{f\_l(i)} \stackrel{?}{=} \prod\_{k=0}^{n-1} \\)\\(\phi\_{lk}^{i^{k} \mod q}\\),
//!            aborting if the check fails.
//!
//! * Step #3: Each \\(P\_i\\) calculates their secret signing key as the product of all the secret
//!            polynomial evaluations (including their own):
//!            \\(a\_i = g^{f\_i(i)} \cdot \prod\_{l=0}^{n-1} g^{f\_l(i)}\\), as well as calculating
//!            the group public key in similar fashion from the commitments from round one:
//!            \\(A = C\_i \cdot \prod\_{l=0}^{n-1} C_l\\).
//!
//! # Examples
//!
//! ```rust
//! use ice_frost::dkg::DistributedKeyGeneration;
//! use ice_frost::parameters::ThresholdParameters;
//! use ice_frost::FrostResult;
//! use ice_frost::testing::Secp256k1Sha256;
//! use ice_frost::dkg::Participant;
//! use rand::rngs::OsRng;
//!
//! # fn do_test() -> FrostResult<Secp256k1Sha256, ()> {
//! // Set up key shares for a threshold signature scheme which needs at least
//! // 2-out-of-3 signers.
//! let params = ThresholdParameters::new(3,2);
//! let mut rng = OsRng;
//!
//! // Alice, Bob, and Carol each generate their secret polynomial coefficients
//! // and commitments to them, as well as a zero-knowledge proof of a secret key.
//! let (alice, alice_coeffs, alice_dh_sk) = Participant::new_dealer(params, 1, &mut rng)?;
//! let (bob, bob_coeffs, bob_dh_sk) = Participant::new_dealer(params, 2, &mut rng)?;
//! let (carol, carol_coeffs, carol_dh_sk) = Participant::new_dealer(params, 3, &mut rng)?;
//!
//! // They send these values to each of the other participants (out of scope
//! // for this library), or otherwise publish them somewhere.
//! //
//! // alice.send_to(bob);
//! // alice.send_to(carol);
//! // bob.send_to(alice);
//! // bob.send_to(carol);
//! // carol.send_to(alice);
//! // carol.send_to(bob);
//! //
//! // NOTE: They should only send the `alice`, `bob`, and `carol` structs, *not*
//! //       the `alice_coefficients`, etc.
//! //
//!
//! // Alice enters round one of the distributed key generation protocol.
//! let participants: Vec<Participant<Secp256k1Sha256>> = vec![alice.clone(), bob.clone(), carol.clone()];
//! let (alice_state, participant_lists) =
//!     DistributedKeyGeneration::<_, Secp256k1Sha256>::bootstrap(
//!         params,
//!         &alice_dh_sk,
//!         alice.index,
//!         &alice_coeffs,
//!         &participants,
//!         &mut rng,
//!     )
//!     ?;
//!
//! // Alice then collects the secret shares which they send to the other participants:
//! let alice_their_encrypted_secret_shares = alice_state.their_encrypted_secret_shares()?;
//! // keep_to_self(alice_their_encrypted_secret_shares[0]);
//! // send_to_bob(alice_their_encrypted_secret_shares[1]);
//! // send_to_carol(alice_their_encrypted_secret_shares[2]);
//!
//! // Bob enters round one of the distributed key generation protocol.
//! let (bob_state, participant_lists) =
//!     DistributedKeyGeneration::<_, Secp256k1Sha256>::bootstrap(
//!         params,
//!         &bob_dh_sk,
//!         bob.index,
//!         &bob_coeffs,
//!         &participants,
//!         &mut rng,
//!     )
//!     ?;
//!
//! // Bob then collects the secret shares which they send to the other participants:
//! let bob_their_encrypted_secret_shares = bob_state.their_encrypted_secret_shares()?;
//! // send_to_alice(bob_their_encrypted_secret_shares[0]);
//! // keep_to_self(bob_their_encrypted_secret_shares[1]);
//! // send_to_carol(bob_their_encrypted_secret_shares[2]);
//!
//! // Carol enters round one of the distributed key generation protocol.
//! let (carol_state, participant_lists) =
//!     DistributedKeyGeneration::<_, Secp256k1Sha256>::bootstrap(
//!         params,
//!         &carol_dh_sk,
//!         carol.index,
//!         &carol_coeffs,
//!         &participants,
//!         &mut rng,
//!     )
//!     ?;
//!
//! // Carol then collects the secret shares which they send to the other participants:
//! let carol_their_encrypted_secret_shares = carol_state.their_encrypted_secret_shares()?;
//! // send_to_alice(carol_their_encrypted_secret_shares[0]);
//! // send_to_bob(carol_their_encrypted_secret_shares[1]);
//! // keep_to_self(carol_their_encrypted_secret_shares[2]);
//!
//! // Each participant now has a vector of secret shares given to them by the other participants:
//! let alice_my_encrypted_secret_shares = vec![
//!     alice_their_encrypted_secret_shares[0].clone(),
//!     bob_their_encrypted_secret_shares[0].clone(),
//!     carol_their_encrypted_secret_shares[0].clone(),
//! ];
//! let bob_my_encrypted_secret_shares = vec![
//!     alice_their_encrypted_secret_shares[1].clone(),
//!     bob_their_encrypted_secret_shares[1].clone(),
//!     carol_their_encrypted_secret_shares[1].clone(),
//! ];
//! let carol_my_encrypted_secret_shares = vec![
//!     alice_their_encrypted_secret_shares[2].clone(),
//!     bob_their_encrypted_secret_shares[2].clone(),
//!     carol_their_encrypted_secret_shares[2].clone(),
//! ];
//!
//! // The participants then use these secret shares from the other participants to advance to
//! // round two of the distributed key generation protocol.
//! let alice_state = alice_state.to_round_two(&alice_my_encrypted_secret_shares, &mut rng)?;
//! let bob_state = bob_state.to_round_two(&bob_my_encrypted_secret_shares, &mut rng)?;
//! let carol_state = carol_state.to_round_two(&carol_my_encrypted_secret_shares, &mut rng)?;
//!
//! // Each participant can now derive their long-lived secret keys and the group's
//! // public key.
//! let (alice_group_key, alice_secret_key) = alice_state.finish()?;
//! let (bob_group_key, bob_secret_key) = bob_state.finish()?;
//! let (carol_group_key, carol_secret_key) = carol_state.finish()?;
//!
//! // They should all derive the same group public key.
//! assert!(alice_group_key == bob_group_key);
//! assert!(carol_group_key == bob_group_key);
//!
//! // Alice, Bob, and Carol can now create partial threshold signatures over an agreed upon
//! // message with their respective secret keys, which they can then give to a
//! // [`SignatureAggregator`] to create a 2-out-of-3 threshold signature.
//! # Ok(())}
//! # fn main() { assert!(do_test().is_ok()); }
//! ```
//!
//! ## Resharing
//!
//! ICE-FROST allows for secret shares redistribution to a new set of participants,
//! while keeping the same group's public key. The new set of participants can be intersecting,
//! partly or fully, the former set of participants, or be fully disjoint from it. In the case
//! where both sets are equal, we talk of secret share refreshing instead of resharing.
//!
//! # Examples
//!
//! ```rust
//! use ice_frost::dkg::DistributedKeyGeneration;
//! use ice_frost::parameters::ThresholdParameters;
//! use ice_frost::FrostResult;
//! use ice_frost::testing::Secp256k1Sha256;
//! use ice_frost::dkg::Participant;
//! use rand::rngs::OsRng;
//!
//! # fn do_test() -> FrostResult<Secp256k1Sha256, ()> {
//! // Set up key shares for a threshold signature scheme which needs at least
//! // 2-out-of-3 signers.
//! let params = ThresholdParameters::new(3,2);
//! let mut rng = OsRng;
//!
//! // Alice, Bob, and Carol each generate their secret polynomial coefficients
//! // and commitments to them, as well as a zero-knowledge proof of a secret key.
//! let (alice, alice_coeffs, alice_dh_sk) = Participant::new_dealer(params, 1, &mut rng)?;
//! let (bob, bob_coeffs, bob_dh_sk) = Participant::new_dealer(params, 2, &mut rng)?;
//! let (carol, carol_coeffs, carol_dh_sk) = Participant::new_dealer(params, 3, &mut rng)?;
//!
//! // They send these values to each of the other participants (out of scope
//! // for this library), or otherwise publish them somewhere.
//! //
//! // alice.send_to(bob);
//! // alice.send_to(carol);
//! // bob.send_to(alice);
//! // bob.send_to(carol);
//! // carol.send_to(alice);
//! // carol.send_to(bob);
//! //
//! // NOTE: They should only send the `alice`, `bob`, and `carol` structs, *not*
//! //       the `alice_coefficients`, etc.
//!
//! // Alice enters round one of the distributed key generation protocol.
//! let participants: Vec<Participant<Secp256k1Sha256>> = vec![alice.clone(), bob.clone(), carol.clone()];
//! let (alice_state, participant_lists) =
//!     DistributedKeyGeneration::<_, Secp256k1Sha256>::bootstrap(
//!         params,
//!         &alice_dh_sk,
//!         alice.index,
//!         &alice_coeffs,
//!         &participants,
//!         &mut rng,
//!     )
//!     ?;
//!
//! // Alice then collects the secret shares which they send to the other participants:
//! let alice_their_encrypted_secret_shares = alice_state.their_encrypted_secret_shares()?;
//! // keep_to_self(alice_their_encrypted_secret_shares[0]);
//! // send_to_bob(alice_their_encrypted_secret_shares[1]);
//! // send_to_carol(alice_their_encrypted_secret_shares[2]);
//!
//! // Bob enters round one of the distributed key generation protocol.
//! let (bob_state, participant_lists) =
//!     DistributedKeyGeneration::<_, Secp256k1Sha256>::bootstrap(
//!         params,
//!         &bob_dh_sk,
//!         bob.index,
//!         &bob_coeffs,
//!         &participants,
//!         &mut rng,
//!     )
//!     ?;
//!
//! // Bob then collects the secret shares which they send to the other participants:
//! let bob_their_encrypted_secret_shares = bob_state.their_encrypted_secret_shares()?;
//! // send_to_alice(bob_their_encrypted_secret_shares[0]);
//! // keep_to_self(bob_their_encrypted_secret_shares[1]);
//! // send_to_carol(bob_their_encrypted_secret_shares[2]);
//!
//! // Carol enters round one of the distributed key generation protocol.
//! let (carol_state, participant_lists) =
//!     DistributedKeyGeneration::<_, Secp256k1Sha256>::bootstrap(
//!         params,
//!         &carol_dh_sk,
//!         carol.index,
//!         &carol_coeffs,
//!         &participants,
//!         &mut rng,
//!     )
//!     ?;
//!
//! // Carol then collects the secret shares which they send to the other participants:
//! let carol_their_encrypted_secret_shares = carol_state.their_encrypted_secret_shares()?;
//! // send_to_alice(carol_their_encrypted_secret_shares[0]);
//! // send_to_bob(carol_their_encrypted_secret_shares[1]);
//! // keep_to_self(carol_their_encrypted_secret_shares[2]);
//!
//! // Each participant now has a vector of secret shares given to them by the other participants:
//! let alice_my_encrypted_secret_shares = vec![
//!     alice_their_encrypted_secret_shares[0].clone(),
//!     bob_their_encrypted_secret_shares[0].clone(),
//!     carol_their_encrypted_secret_shares[0].clone(),
//! ];
//! let bob_my_encrypted_secret_shares = vec![
//!     alice_their_encrypted_secret_shares[1].clone(),
//!     bob_their_encrypted_secret_shares[1].clone(),
//!     carol_their_encrypted_secret_shares[1].clone(),
//! ];
//! let carol_my_encrypted_secret_shares = vec![
//!     alice_their_encrypted_secret_shares[2].clone(),
//!     bob_their_encrypted_secret_shares[2].clone(),
//!     carol_their_encrypted_secret_shares[2].clone(),
//! ];
//!
//! // The participants then use these secret shares from the other participants to advance to
//! // round two of the distributed key generation protocol.
//! let alice_state = alice_state.to_round_two(&alice_my_encrypted_secret_shares, &mut rng)?;
//! let bob_state = bob_state.to_round_two(&bob_my_encrypted_secret_shares, &mut rng)?;
//! let carol_state = carol_state.to_round_two(&carol_my_encrypted_secret_shares, &mut rng)?;
//!
//! // Each participant can now derive their long-lived secret keys and the group's
//! // public key.
//! let (alice_group_key, alice_secret_key) = alice_state.finish()?;
//! let (bob_group_key, bob_secret_key) = bob_state.finish()?;
//! let (carol_group_key, carol_secret_key) = carol_state.finish()?;
//!
//! // They should all derive the same group public key.
//! assert!(alice_group_key == bob_group_key);
//! assert!(carol_group_key == bob_group_key);
//!
//! // Instantiate another configuration of threshold signature.
//! let new_params = ThresholdParameters::new(4,3);
//!
//! // Alexis, Barbara, Claire and David each generate their Diffie-Hellman
//! // private key, as well as a zero-knowledge proof to it.
//! let (alexis, alexis_dh_sk) = Participant::new_signer(new_params, 1, &mut rng)?;
//! let (barbara, barbara_dh_sk) = Participant::new_signer(new_params, 2, &mut rng)?;
//! let (claire, claire_dh_sk) = Participant::new_signer(new_params, 3, &mut rng)?;
//! let (david, david_dh_sk) = Participant::new_signer(new_params, 4, &mut rng)?;
//!
//! // They send these values to each of the other and previous participants
//! // (out of scope for this library), or otherwise publish them somewhere.
//! //
//! // alexis.send_to(barbara);
//! // alexis.send_to(claire);
//! // alexis.send_to(david);
//! // alexis.send_to(alice);
//! // alexis.send_to(bob);
//! // alexis.send_to(carol);
//! // barbara.send_to(alexis);
//! // barbara.send_to(claire);
//! // barbara.send_to(david);
//! // barbara.send_to(alice);
//! // barbara.send_to(bob);
//! // barbara.send_to(carol);
//! // claire.send_to(alexis);
//! // claire.send_to(barbara);
//! // claire.send_to(david);
//! // claire.send_to(alice);
//! // claire.send_to(bob);
//! // claire.send_to(carol);
//! // david.send_to(alexis);
//! // david.send_to(barbara);
//! // david.send_to(claire);
//! // david.send_to(alice);
//! // david.send_to(bob);
//! // david.send_to(carol);
//! //
//! // NOTE: They should only send the `alexis`, `barbara`, `claire` and `david` structs,
//! //       *not* the `alexis_dh_sk`, etc.
//! //
//! // Everybody verifies the zero-knowledge proofs of Diffie-Hellman private keys of
//! // the other participants.
//!
//! // Alice, Bob and Carol compute new secret shares of their long-lived secret signing key,
//! // encrypted for Alexis, Barbara, Claire and David respectively.
//!
//! let signers: Vec<Participant<Secp256k1Sha256>> =
//!     vec![alexis.clone(), barbara.clone(), claire.clone(), david.clone()];
//! let (alice_as_dealer, alice_encrypted_shares, participant_lists) =
//!     Participant::reshare(new_params, &alice_secret_key, &signers, &mut rng)?;
//!
//! let (bob_as_dealer, bob_encrypted_shares, participant_lists) =
//!     Participant::reshare(new_params, &bob_secret_key, &signers, &mut rng)?;
//!
//! let (carol_as_dealer, carol_encrypted_shares, participant_lists) =
//!     Participant::reshare(new_params, &carol_secret_key, &signers, &mut rng)?;
//!
//! // NOTE: They use the *new* configuration parameters (3-out-of-4) when resharing.
//!
//! // Alexis, Barbara, Claire and Carol instantiate their DKG session with the set of dealers
//! // who will compute their shares. They don't need to provide any coefficients.
//! let dealers: Vec<Participant<Secp256k1Sha256>> =
//!     vec![alice_as_dealer.clone(), bob_as_dealer.clone(), carol_as_dealer.clone()];
//! let (alexis_state, participant_lists) =
//!     DistributedKeyGeneration::<_, Secp256k1Sha256>::new(
//!         params,
//!         &alexis_dh_sk,
//!         alexis.index,
//!         &dealers,
//!         &mut rng,
//!     )
//!     ?;
//!
//! let (barbara_state, participant_lists) =
//!     DistributedKeyGeneration::<_, Secp256k1Sha256>::new(
//!         params,
//!         &barbara_dh_sk,
//!         barbara.index,
//!         &dealers,
//!         &mut rng,
//!     )
//!     ?;
//!
//! let (claire_state, participant_lists) =
//!     DistributedKeyGeneration::<_, Secp256k1Sha256>::new(
//!         params,
//!         &claire_dh_sk,
//!         claire.index,
//!         &dealers,
//!         &mut rng,
//!     )
//!     ?;
//!
//! let (david_state, participant_lists) =
//!     DistributedKeyGeneration::<_, Secp256k1Sha256>::new(
//!         params,
//!         &david_dh_sk,
//!         david.index,
//!         &dealers,
//!         &mut rng,
//!     )
//!     ?;
//!
//! // NOTE: They use the *old* configuration parameters (2-out-of-3) when instantiating their DKG.
//! //       If some participants of the previous set (i.e. dealers here) have been discarded
//! //       during their own DKG, signers need to update the *old* configuration parameters to
//! //       take the number of total participants into account.
//! //       For instance, if in a 201-out-of-300 setting, 37 participants had been discarded for
//! //       misconduct, when new signers would refer to this previous set as dealers, they should
//! //       set `params` to a 201-out-of-263 setting.
//!
//! let alexis_my_encrypted_secret_shares = vec![
//!     alice_encrypted_shares[0].clone(),
//!     bob_encrypted_shares[0].clone(),
//!     carol_encrypted_shares[0].clone(),
//! ];
//! let barbara_my_encrypted_secret_shares = vec![
//!     alice_encrypted_shares[1].clone(),
//!     bob_encrypted_shares[1].clone(),
//!     carol_encrypted_shares[1].clone()
//! ];
//! let claire_my_encrypted_secret_shares = vec![
//!     alice_encrypted_shares[2].clone(),
//!     bob_encrypted_shares[2].clone(),
//!     carol_encrypted_shares[2].clone()
//! ];
//! let david_my_encrypted_secret_shares = vec![
//!     alice_encrypted_shares[3].clone(),
//!     bob_encrypted_shares[3].clone(),
//!     carol_encrypted_shares[3].clone()
//! ];
//!
//! // Alexis, Barbara, Claire and David can now finish the resharing DKG with the received
//! // encrypted shares from Alice, Bob and Carol. This process is identical to the initial
//! // DKG ran by Alice, Bob and Carol. The final group key of the 3-out-of-4 threshold scheme
//! // configuration will be identical to the one of the 2-out-of-3 original one.
//!
//! let alexis_state = alexis_state.to_round_two(&alexis_my_encrypted_secret_shares, &mut rng)?;
//! let barbara_state = barbara_state.to_round_two(&barbara_my_encrypted_secret_shares, &mut rng)?;
//! let claire_state = claire_state.to_round_two(&claire_my_encrypted_secret_shares, &mut rng)?;
//! let david_state = david_state.to_round_two(&david_my_encrypted_secret_shares, &mut rng)?;
//!
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
//! [typestate]: http://cliffle.com/blog/rust-typestate/

use ark_ec::Group;
use ark_ff::{Field, Zero};
use ark_serialize::CanonicalDeserialize;
use ark_serialize::CanonicalSerialize;

use core::ops::DerefMut;
use core::ops::{Deref, Mul};
use rand::CryptoRng;
use rand::RngCore;

use zeroize::Zeroize;

use crate::ciphersuite::CipherSuite;
use crate::dkg::{
    round_types::{DkgState, RoundOne, RoundTwo},
    secret_share::{
        decrypt_share, encrypt_share, Coefficients, EncryptedSecretShare, SecretShare,
        VerifiableSecretSharingCommitment,
    },
    Complaint, Participant,
};
use crate::keys::{
    DiffieHellmanPrivateKey, DiffieHellmanPublicKey, GroupVerifyingKey, IndividualSigningKey,
};
use crate::parameters::ThresholdParameters;
use crate::FromBytes;
use crate::ToBytes;
use crate::{Error, FrostResult};

use crate::utils::calculate_lagrange_coefficients;
use crate::utils::{BTreeMap, Box, Scalar, ToString, Vec};

/// State machine structures for holding intermediate values during a
/// distributed key generation protocol run, to prevent misuse.
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct DistributedKeyGeneration<S: DkgState, C: CipherSuite> {
    state: BoxedState<C>,
    data: S,
}

impl<S: DkgState, C: CipherSuite> ToBytes<C> for DistributedKeyGeneration<S, C> {}
impl<S: DkgState, C: CipherSuite> FromBytes<C> for DistributedKeyGeneration<S, C> {}

/// Shared state which occurs across all rounds of a threshold signing protocol run.
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
struct ActualState<C: CipherSuite> {
    /// The parameters for this instantiation of a threshold signature.
    parameters: ThresholdParameters<C>,
    /// The index of the participant.
    index: u32,
    /// The DH private key for deriving a symmetric key to encrypt and decrypt
    /// secret shares.
    dh_private_key: DiffieHellmanPrivateKey<C>,
    /// The DH public key for deriving a symmetric key to encrypt and decrypt
    /// secret shares.
    dh_public_key: DiffieHellmanPublicKey<C>,
    /// A vector of tuples containing the index of each participant and that
    /// respective participant's commitments to their private polynomial
    /// coefficients.
    their_commitments: Option<Vec<VerifiableSecretSharingCommitment<C>>>,
    /// A vector of ECPoints containing the index of each participant and that
    /// respective participant's DH public key.
    their_dh_public_keys: BTreeMap<u32, DiffieHellmanPublicKey<C>>,
    /// The encrypted secret shares this participant has calculated for all the other participants.
    their_encrypted_secret_shares: Option<Vec<EncryptedSecretShare<C>>>,
    /// The secret shares this participant has received from all the other participants.
    my_secret_shares: Option<Vec<SecretShare<C>>>,
}

#[derive(Clone, Debug)]
struct BoxedState<C: CipherSuite>(Box<ActualState<C>>);

impl<C: CipherSuite> Deref for BoxedState<C> {
    type Target = ActualState<C>;
    fn deref(&self) -> &ActualState<C> {
        &self.0
    }
}

impl<C: CipherSuite> DerefMut for BoxedState<C> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<C: CipherSuite> BoxedState<C> {
    fn new(state: ActualState<C>) -> Self {
        Self(Box::new(state))
    }
}

// Required trait to implement `CanonicalDeserialize` below.
impl<C: CipherSuite> ark_serialize::Valid for BoxedState<C> {
    fn check(&self) -> Result<(), ark_serialize::SerializationError> {
        self.0.check()
    }
}

impl<C: CipherSuite> CanonicalSerialize for BoxedState<C> {
    fn serialize_with_mode<W: ark_serialize::Write>(
        &self,
        writer: W,
        compress: ark_serialize::Compress,
    ) -> Result<(), ark_serialize::SerializationError> {
        self.0.serialize_with_mode(writer, compress)
    }

    fn serialized_size(&self, compress: ark_serialize::Compress) -> usize {
        self.0.serialized_size(compress)
    }
}

impl<C: CipherSuite> CanonicalDeserialize for BoxedState<C> {
    fn deserialize_with_mode<R: ark_serialize::Read>(
        reader: R,
        compress: ark_serialize::Compress,
        validate: ark_serialize::Validate,
    ) -> Result<Self, ark_serialize::SerializationError> {
        ActualState::<C>::deserialize_with_mode(reader, compress, validate).map(Self::new)
    }
}

/// Output of the first round of the Distributed Key Generation.
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct DKGParticipantList<C: CipherSuite> {
    /// List of the valid participants to be used in RoundTwo
    pub valid_participants: Vec<Participant<C>>,
    /// List of the invalid participants that have been removed
    pub misbehaving_participants: Option<Vec<u32>>,
}

impl<C: CipherSuite> DistributedKeyGeneration<RoundOne, C> {
    /// Bootstrap the very first ICE-FROST DKG session for a group of participants. This assumes that no
    /// prior DKG has been performed, from which previous participants would reshare their secrets. If a
    /// prior ICE-FROST DKG has been ran successfully, participants from a new set should run the `new`
    /// method instead.
    ///
    /// The `bootstrap` method checks the zero-knowledge proofs of knowledge of signing keys and
    /// Diffie-Hellman private keys of all the other participants.
    ///
    /// # Inputs
    ///
    /// * The protocol instance [`ThresholdParameters`].
    /// * This participant's [`DiffieHellmanPrivateKey`].
    /// * This participant's `index`.
    /// * This participant's secret `coefficients` making up their long-lived secret key.
    /// * The list of `participants` for this ICE-FROST session.
    /// * A cryptographically secure pseudo-random generator.
    ///
    /// # Returns
    ///
    /// An updated state machine for the distributed key generation protocol if
    /// all of the zero-knowledge proofs verified successfully, otherwise a
    /// vector of participants whose proofs were incorrect.
    pub fn bootstrap(
        parameters: ThresholdParameters<C>,
        dh_private_key: &DiffieHellmanPrivateKey<C>,
        my_index: u32,
        my_coefficients: &Coefficients<C>,
        participants: &[Participant<C>],
        mut rng: impl RngCore + CryptoRng,
    ) -> FrostResult<C, (Self, DKGParticipantList<C>)> {
        Self::new_state_internal(
            parameters,
            dh_private_key,
            my_index,
            Some(my_coefficients),
            participants,
            true,
            true,
            &mut rng,
        )
    }

    /// Initiate a new DKG session beween participants, where an ICE-FROST group
    /// key already exists. If no ICE-FROST group key exists yet, the `bootstrap`
    /// should be called instead.
    ///
    /// This method will check the zero-knowledge proofs of
    /// knowledge of secret keys of all the other participants.
    ///
    /// # Inputs
    ///
    /// * The protocol new instance [`ThresholdParameters`]. These parameters can
    ///   be different from the previous ICE-FROST session using the same group key.
    /// * This participant's [`DiffieHellmanPrivateKey`].
    /// * This participant's `index`.
    /// * The list of `dealers`. These are the participants of the previous ICE-FROST
    ///   session from which the individual secret shares are being redistributed.
    /// * A cryptographically secure pseudo-random generator.
    ///
    /// # Returns
    ///
    /// An updated state machine for the distributed key generation protocol if
    /// all of the zero-knowledge proofs verified successfully, otherwise a
    /// vector of participants whose zero-knowledge proofs were incorrect.
    pub fn new(
        parameters: ThresholdParameters<C>,
        dh_private_key: &DiffieHellmanPrivateKey<C>,
        my_index: u32,
        dealers: &[Participant<C>],
        mut rng: impl RngCore + CryptoRng,
    ) -> FrostResult<C, (Self, DKGParticipantList<C>)> {
        Self::new_state_internal(
            parameters,
            dh_private_key,
            my_index,
            None,
            dealers,
            false,
            true,
            &mut rng,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new_state_internal(
        parameters: ThresholdParameters<C>,
        dh_private_key: &DiffieHellmanPrivateKey<C>,
        my_index: u32,
        my_coefficients: Option<&Coefficients<C>>,
        participants: &[Participant<C>],
        from_dealer: bool,
        from_signer: bool,
        mut rng: impl RngCore + CryptoRng,
    ) -> FrostResult<C, (Self, DKGParticipantList<C>)> {
        let mut their_commitments: Vec<VerifiableSecretSharingCommitment<C>> =
            Vec::with_capacity(parameters.t as usize);
        let mut their_dh_public_keys: BTreeMap<u32, DiffieHellmanPublicKey<C>> = BTreeMap::new();
        let mut valid_participants: Vec<Participant<C>> = Vec::with_capacity(parameters.n as usize);
        let mut misbehaving_participants: Vec<u32> = Vec::new();

        let dh_public_key = DiffieHellmanPublicKey::new(C::G::generator().mul(dh_private_key.0));

        // Bail if we didn't get enough participants.
        if participants.len() != parameters.n as usize {
            return Err(Error::InvalidNumberOfParticipants(
                participants.len(),
                parameters.n,
            ));
        }

        // Check the public keys and the DH keys of the participants.
        for p in participants {
            // Always check the DH keys of the participants
            match p.proof_of_dh_private_key.verify(p.index, &p.dh_public_key) {
                Ok(()) => {
                    // Signers additionally check the public keys of the signers
                    if from_signer {
                        let Some(public_key) = p.public_key() else {
                            misbehaving_participants.push(p.index);
                            continue;
                        };

                        match p
                            .proof_of_secret_key
                            .as_ref()
                            .expect("Dealers always have a proof of secret key.")
                            .verify(p.index, public_key)
                        {
                            Ok(()) => {
                                valid_participants.push(p.clone());
                                their_commitments.push(p.commitments.as_ref().expect("Dealers always have commitments to their secret polynomial evaluations.").clone());
                                their_dh_public_keys.insert(p.index, p.dh_public_key.clone());
                            }
                            Err(_) => misbehaving_participants.push(p.index),
                        }
                    } else {
                        valid_participants.push(p.clone());
                        their_dh_public_keys.insert(p.index, p.dh_public_key.clone());
                    }
                }
                Err(_) => misbehaving_participants.push(p.index),
            }
        }

        // If too many participants were misbehaving, return an error along their indices.
        if valid_participants.len() < parameters.t as usize {
            return Err(Error::TooManyInvalidParticipants(misbehaving_participants));
        }

        if !from_dealer && from_signer {
            let state = ActualState {
                parameters,
                index: my_index,
                dh_private_key: dh_private_key.clone(),
                dh_public_key,
                their_commitments: Some(their_commitments),
                their_dh_public_keys,
                their_encrypted_secret_shares: None,
                my_secret_shares: None,
            };

            return Ok((
                DistributedKeyGeneration::<RoundOne, C> {
                    state: BoxedState::new(state),
                    data: RoundOne {},
                },
                DKGParticipantList {
                    valid_participants,
                    misbehaving_participants: if misbehaving_participants.is_empty() {
                        None
                    } else {
                        Some(misbehaving_participants)
                    },
                },
            ));
        }

        // We pre-calculate the secret shares from Round 2 - Step 1 here since
        // it doesn't require additional online activity.
        // ICE-FROST also requires to encrypt them into `their_encrypted_secret_shares`.
        //
        // Round 2
        // Step 1: Each P_i securely sends to each other participant P_l a secret share
        //         (l, f_i(l)) and keeps (i, f_i(i)) for themselves.
        let mut their_encrypted_secret_shares: Vec<EncryptedSecretShare<C>> =
            Vec::with_capacity(parameters.n as usize - 1);

        for p in participants {
            let share = SecretShare::<C>::evaluate_polynomial(
                my_index,
                p.index,
                my_coefficients.expect(
                    "Dealers always have coefficients to generate/redistribute secret shares.",
                ),
            );

            let dh_key = p.dh_public_key.key * dh_private_key.0;
            let mut dh_key_bytes = Vec::with_capacity(dh_key.compressed_size());
            dh_key
                .serialize_compressed(&mut dh_key_bytes)
                .map_err(|_| Error::CompressionError)?;

            their_encrypted_secret_shares.push(encrypt_share(&share, &dh_key_bytes[..], &mut rng)?);
        }

        let state = ActualState {
            parameters,
            index: my_index,
            dh_private_key: dh_private_key.clone(),
            dh_public_key,
            their_commitments: if from_signer {
                Some(their_commitments)
            } else {
                None
            },
            their_dh_public_keys,
            their_encrypted_secret_shares: Some(their_encrypted_secret_shares),
            my_secret_shares: None,
        };

        Ok((
            DistributedKeyGeneration::<RoundOne, C> {
                state: BoxedState::new(state),
                data: RoundOne {},
            },
            DKGParticipantList {
                valid_participants,
                misbehaving_participants: if misbehaving_participants.is_empty() {
                    None
                } else {
                    Some(misbehaving_participants)
                },
            },
        ))
    }

    /// Retrieve an encrypted secret share for each other participant, to be given to them
    /// at the end of [`DistributedKeyGeneration::<RoundOne, C>`] .
    pub fn their_encrypted_secret_shares(&self) -> FrostResult<C, &Vec<EncryptedSecretShare<C>>> {
        self.state
            .their_encrypted_secret_shares
            .as_ref()
            .ok_or(Error::NoEncryptedShares)
    }

    /// Progress to round two of the Dkg protocol once we have sent each encrypted share
    /// from [`DistributedKeyGeneration::<RoundOne, C>::their_encrypted_secret_shares()`] to its
    /// respective other participant, and collected our shares from the other
    /// participants in turn.
    pub fn to_round_two(
        mut self,
        my_encrypted_secret_shares: &[EncryptedSecretShare<C>],
        mut rng: impl RngCore + CryptoRng,
    ) -> FrostResult<C, DistributedKeyGeneration<RoundTwo, C>> {
        // Sanity check
        assert_eq!(self.data, RoundOne {});

        // Zero out the other participants encrypted secret shares from memory.
        if self.state.their_encrypted_secret_shares.is_some() {
            self.state.their_encrypted_secret_shares = None;
        }

        let mut complaints: Vec<Complaint<C>> = Vec::new();

        if my_encrypted_secret_shares.len() != self.state.parameters.n as usize {
            return Err(Error::MissingShares);
        }

        let mut my_secret_shares: Vec<SecretShare<C>> = Vec::new();

        // Step 2.1: Each P_i decrypts their shares with
        //           key k_il = pk_l^sk_i
        for encrypted_share in my_encrypted_secret_shares {
            if let Some(pk) = self
                .state
                .their_dh_public_keys
                .get(&encrypted_share.sender_index)
            {
                let dh_shared_key = **pk * self.state.dh_private_key.0;
                let mut dh_key_bytes = Vec::with_capacity(dh_shared_key.compressed_size());
                dh_shared_key
                    .serialize_compressed(&mut dh_key_bytes)
                    .map_err(|_| Error::CompressionError)?;

                // Step 2.2: Each share is verified by calculating:
                //           g^{f_l(i)} ?= \Prod_{k=0}^{t-1} \phi_{lk}^{i^{k} mod q},
                //           creating a complaint if the check fails.
                let decrypted_share = decrypt_share(encrypted_share, &dh_key_bytes);

                for commitment in self.state.their_commitments.as_ref().expect(
                    "Dealers always have commitments to their secret polynomial evaluations.",
                ) {
                    if commitment.index == encrypted_share.sender_index {
                        // If the decrypted share is incorrect, P_i builds a complaint.

                        if decrypted_share.is_err()
                            || decrypted_share
                                .as_ref()
                                .expect("This cannot fail.")
                                .verify(commitment)
                                .is_err()
                        {
                            complaints.push(Complaint::<C>::new(
                                encrypted_share.receiver_index,
                                encrypted_share.sender_index,
                                pk,
                                &self.state.dh_private_key.0,
                                &self.state.dh_public_key.key,
                                &dh_shared_key,
                                &mut rng,
                            )?);
                            break;
                        }
                    }
                }
                if let Ok(share) = decrypted_share {
                    my_secret_shares.push(share);
                }
            } else {
                return Err(Error::Custom("to_round_two() was called with encrypted secret shares containing invalid indices".to_string()));
            }
        }

        if !complaints.is_empty() {
            return Err(Error::Complaint(complaints));
        }

        self.state.my_secret_shares = Some(my_secret_shares);

        Ok(DistributedKeyGeneration::<RoundTwo, C> {
            state: self.state,
            data: RoundTwo {},
        })
    }
}

impl<C: CipherSuite> DistributedKeyGeneration<RoundTwo, C> {
    /// Calculate this threshold signing protocol participant's long-lived
    /// secret signing keyshare and the group's public verification key.
    ///
    /// # Example
    ///
    /// [```ignore
    /// let (group_key, secret_key) = state.finish()?;
    /// [```
    pub fn finish(mut self) -> FrostResult<C, (GroupVerifyingKey<C>, IndividualSigningKey<C>)> {
        let secret_key = self.calculate_signing_key()?;
        let group_key = self.calculate_group_key()?;

        self.state.my_secret_shares.zeroize();

        Ok((group_key, secret_key))
    }

    /// Calculate this threshold signing participant's long-lived secret signing
    /// key by interpolating all of the polynomial evaluations from the other
    /// participants.
    pub(crate) fn calculate_signing_key(&self) -> FrostResult<C, IndividualSigningKey<C>> {
        let my_secret_shares = self.state.my_secret_shares.as_ref().ok_or_else(|| {
            Error::Custom("Could not retrieve participant's secret shares".to_string())
        })?;

        let mut index_vector = Vec::with_capacity(my_secret_shares.len());

        for share in my_secret_shares {
            index_vector.push(share.sender_index);
        }

        let mut key = Scalar::<C>::ZERO;

        for share in my_secret_shares {
            let coeff =
                match calculate_lagrange_coefficients::<C>(share.sender_index, &index_vector) {
                    Ok(s) => s,
                    Err(error) => return Err(Error::Custom(error.to_string())),
                };
            key += share.polynomial_evaluation * coeff;
        }

        Ok(IndividualSigningKey {
            index: self.state.index,
            key,
        })
    }

    /// Calculate the group public key used for verifying threshold signatures.
    ///
    /// # Returns
    ///
    /// A [`GroupVerifyingKey`] for the set of participants.
    pub(crate) fn calculate_group_key(&self) -> FrostResult<C, GroupVerifyingKey<C>> {
        let commitments = self
            .state
            .their_commitments
            .as_ref()
            .ok_or(Error::InvalidGroupKey)?;
        let mut index_vector = Vec::with_capacity(commitments.len());

        for commitment in commitments {
            index_vector.push(commitment.index);
        }

        let mut group_key = <C as CipherSuite>::G::zero();

        // The group key is the interpolation at 0 of all index 0 of the dealers' commitments.
        for commitment in commitments {
            let coeff = calculate_lagrange_coefficients::<C>(commitment.index, &index_vector)?;

            group_key += commitment
                .public_key()
                .expect("We should always be able to retrieve a public key from a commitment.")
                .mul(coeff);
        }

        Ok(GroupVerifyingKey::new(group_key))
    }

    /// Every participant can verify a complaint and determine who is the malicious
    /// party. The relevant encrypted share is assumed to exist and publicly retrievable
    /// by any participant.
    pub fn blame(
        &self,
        encrypted_share: &EncryptedSecretShare<C>,
        complaint: &Complaint<C>,
    ) -> u32 {
        let mut pk_maker = <C as CipherSuite>::G::zero();
        let mut pk_accused = <C as CipherSuite>::G::zero();
        let mut commitment_accused = VerifiableSecretSharingCommitment {
            index: 0,
            points: Vec::new(),
        };

        for commitment in self
            .state
            .their_commitments
            .as_ref()
            .expect("Dealers always have commitments to their secret polynomial evaluations.")
        {
            if commitment.index == complaint.accused_index {
                commitment_accused = commitment.clone();
            }
        }

        if commitment_accused.points.is_empty() {
            return complaint.maker_index;
        }

        for (index, pk) in &self.state.their_dh_public_keys {
            if index == &complaint.maker_index {
                pk_maker = **pk;
            } else if index == &complaint.accused_index {
                pk_accused = **pk;
            }
        }

        if pk_maker == <C as CipherSuite>::G::zero() || pk_accused == <C as CipherSuite>::G::zero()
        {
            return complaint.maker_index;
        }

        if complaint.verify(&pk_maker, &pk_accused).is_err() {
            return complaint.maker_index;
        }

        let mut dh_key_bytes = Vec::with_capacity(complaint.dh_shared_key.compressed_size());
        if complaint
            .dh_shared_key
            .serialize_compressed(&mut dh_key_bytes)
            .is_err()
        {
            return complaint.maker_index;
        };

        let share_res = decrypt_share(encrypted_share, &dh_key_bytes[..]);

        match share_res {
            Err(_) => complaint.accused_index,
            Ok(share) => match share.verify(&commitment_accused) {
                Ok(()) => complaint.maker_index,
                Err(_) => complaint.accused_index,
            },
        }
    }
}

#[cfg(test)]
mod test {
    use core::ops::Mul;

    use super::*;
    use crate::dkg::{ComplaintProof, NizkPokOfSecretKey};
    use crate::keys::IndividualVerifyingKey;
    use crate::testing::Secp256k1Sha256;
    use crate::{FromBytes, ToBytes};

    use ark_ec::Group;
    use ark_ff::UniformRand;
    use ark_secp256k1::{Fr, Projective};

    use rand::rngs::OsRng;
    use rand::Rng;

    #[test]
    fn nizk_of_secret_key() {
        let params = ThresholdParameters::new(3, 2);
        let rng = OsRng;

        let (p, _, _) = Participant::<Secp256k1Sha256>::new_dealer(params, 1, rng).unwrap();
        let result = p
            .proof_of_secret_key
            .as_ref()
            .unwrap()
            .verify(p.index, p.public_key().unwrap());

        assert!(result.is_ok());
    }

    #[test]
    fn secret_share_from_one_coefficients() {
        let mut coeffs: Vec<Fr> = Vec::with_capacity(5);

        for _ in 0..5 {
            coeffs.push(Fr::ONE);
        }

        let coefficients = Coefficients::<Secp256k1Sha256>(coeffs);
        let share = SecretShare::<Secp256k1Sha256>::evaluate_polynomial(1, 1, &coefficients);

        assert!(share.polynomial_evaluation == Fr::from(5u8));

        let mut commitments = VerifiableSecretSharingCommitment {
            index: 1,
            points: Vec::new(),
        };

        for i in 0..5 {
            commitments
                .points
                .push(Projective::generator() * coefficients.0[i]);
        }

        assert!(share.verify(&commitments).is_ok());
    }

    #[test]
    fn secret_share_participant_index_zero() {
        let mut coeffs: Vec<Fr> = Vec::with_capacity(5);

        for _ in 0..5 {
            coeffs.push(Fr::ONE);
        }

        let coefficients = Coefficients::<Secp256k1Sha256>(coeffs);
        let share = SecretShare::evaluate_polynomial(1, 0, &coefficients);

        assert!(share.polynomial_evaluation == Fr::ONE);

        let mut commitments = VerifiableSecretSharingCommitment {
            index: 1,
            points: Vec::new(),
        };

        for i in 0..5 {
            commitments
                .points
                .push(Projective::generator() * coefficients.0[i]);
        }

        assert!(share.verify(&commitments).is_ok());
    }

    #[test]
    fn single_party_keygen() {
        let params = ThresholdParameters::new(1, 1);
        let rng = OsRng;

        let (p1, p1coeffs, p1_dh_sk) =
            Participant::<Secp256k1Sha256>::new_dealer(params, 1, rng).unwrap();

        p1.proof_of_secret_key
            .as_ref()
            .unwrap()
            .verify(p1.index, p1.public_key().unwrap())
            .unwrap();

        let participants: Vec<Participant<Secp256k1Sha256>> = vec![p1.clone()];
        let (p1_state, _participant_lists) =
            DistributedKeyGeneration::<RoundOne, Secp256k1Sha256>::bootstrap(
                params,
                &p1_dh_sk,
                p1.index,
                &p1coeffs,
                &participants,
                rng,
            )
            .unwrap();
        let p1_my_encrypted_secret_shares =
            p1_state.their_encrypted_secret_shares().unwrap().clone();
        let p1_state = p1_state
            .to_round_two(&p1_my_encrypted_secret_shares, rng)
            .unwrap();
        let result = p1_state.finish();

        assert!(result.is_ok());

        let (p1_group_key, p1_secret_key) = result.unwrap();

        assert!(p1_group_key.key == Projective::generator().mul(p1_secret_key.key));
    }

    #[test]
    fn keygen_3_out_of_5() {
        let params = ThresholdParameters::<Secp256k1Sha256>::new(5, 3);
        let rng = OsRng;

        let (p1, p1coeffs, p1_dh_sk) =
            Participant::<Secp256k1Sha256>::new_dealer(params, 1, rng).unwrap();
        let (p2, p2coeffs, p2_dh_sk) =
            Participant::<Secp256k1Sha256>::new_dealer(params, 2, rng).unwrap();
        let (p3, p3coeffs, p3_dh_sk) =
            Participant::<Secp256k1Sha256>::new_dealer(params, 3, rng).unwrap();
        let (p4, p4coeffs, p4_dh_sk) =
            Participant::<Secp256k1Sha256>::new_dealer(params, 4, rng).unwrap();
        let (p5, p5coeffs, p5_dh_sk) =
            Participant::<Secp256k1Sha256>::new_dealer(params, 5, rng).unwrap();

        p1.proof_of_secret_key
            .as_ref()
            .unwrap()
            .verify(p1.index, p1.public_key().unwrap())
            .unwrap();
        p2.proof_of_secret_key
            .as_ref()
            .unwrap()
            .verify(p2.index, p2.public_key().unwrap())
            .unwrap();
        p3.proof_of_secret_key
            .as_ref()
            .unwrap()
            .verify(p3.index, p3.public_key().unwrap())
            .unwrap();
        p4.proof_of_secret_key
            .as_ref()
            .unwrap()
            .verify(p4.index, p4.public_key().unwrap())
            .unwrap();
        p5.proof_of_secret_key
            .as_ref()
            .unwrap()
            .verify(p5.index, p5.public_key().unwrap())
            .unwrap();

        let participants: Vec<Participant<Secp256k1Sha256>> =
            vec![p1.clone(), p2.clone(), p3.clone(), p4.clone(), p5.clone()];
        let (p1_state, _participant_lists) =
            DistributedKeyGeneration::<RoundOne, Secp256k1Sha256>::bootstrap(
                params,
                &p1_dh_sk,
                p1.index,
                &p1coeffs,
                &participants,
                rng,
            )
            .unwrap();
        let p1_their_encrypted_secret_shares = p1_state.their_encrypted_secret_shares().unwrap();

        let (p2_state, _participant_lists) =
            DistributedKeyGeneration::<RoundOne, Secp256k1Sha256>::bootstrap(
                params,
                &p2_dh_sk,
                p2.index,
                &p2coeffs,
                &participants,
                rng,
            )
            .unwrap();
        let p2_their_encrypted_secret_shares = p2_state.their_encrypted_secret_shares().unwrap();

        let (p3_state, _participant_lists) =
            DistributedKeyGeneration::<RoundOne, Secp256k1Sha256>::bootstrap(
                params,
                &p3_dh_sk,
                p3.index,
                &p3coeffs,
                &participants,
                rng,
            )
            .unwrap();
        let p3_their_encrypted_secret_shares = p3_state.their_encrypted_secret_shares().unwrap();

        let (p4_state, _participant_lists) =
            DistributedKeyGeneration::<RoundOne, Secp256k1Sha256>::bootstrap(
                params,
                &p4_dh_sk,
                p4.index,
                &p4coeffs,
                &participants,
                rng,
            )
            .unwrap();
        let p4_their_encrypted_secret_shares = p4_state.their_encrypted_secret_shares().unwrap();

        let (p5_state, _participant_lists) =
            DistributedKeyGeneration::<RoundOne, Secp256k1Sha256>::bootstrap(
                params,
                &p5_dh_sk,
                p5.index,
                &p5coeffs,
                &participants,
                rng,
            )
            .unwrap();
        let p5_their_encrypted_secret_shares = p5_state.their_encrypted_secret_shares().unwrap();

        let p1_my_encrypted_secret_shares = vec![
            p1_their_encrypted_secret_shares[0].clone(),
            p2_their_encrypted_secret_shares[0].clone(),
            p3_their_encrypted_secret_shares[0].clone(),
            p4_their_encrypted_secret_shares[0].clone(),
            p5_their_encrypted_secret_shares[0].clone(),
        ];

        let p2_my_encrypted_secret_shares = vec![
            p1_their_encrypted_secret_shares[1].clone(),
            p2_their_encrypted_secret_shares[1].clone(),
            p3_their_encrypted_secret_shares[1].clone(),
            p4_their_encrypted_secret_shares[1].clone(),
            p5_their_encrypted_secret_shares[1].clone(),
        ];

        let p3_my_encrypted_secret_shares = vec![
            p1_their_encrypted_secret_shares[2].clone(),
            p2_their_encrypted_secret_shares[2].clone(),
            p3_their_encrypted_secret_shares[2].clone(),
            p4_their_encrypted_secret_shares[2].clone(),
            p5_their_encrypted_secret_shares[2].clone(),
        ];

        let p4_my_encrypted_secret_shares = vec![
            p1_their_encrypted_secret_shares[3].clone(),
            p2_their_encrypted_secret_shares[3].clone(),
            p3_their_encrypted_secret_shares[3].clone(),
            p4_their_encrypted_secret_shares[3].clone(),
            p5_their_encrypted_secret_shares[3].clone(),
        ];

        let p5_my_encrypted_secret_shares = vec![
            p1_their_encrypted_secret_shares[4].clone(),
            p2_their_encrypted_secret_shares[4].clone(),
            p3_their_encrypted_secret_shares[4].clone(),
            p4_their_encrypted_secret_shares[4].clone(),
            p5_their_encrypted_secret_shares[4].clone(),
        ];

        let p1_state = p1_state
            .to_round_two(&p1_my_encrypted_secret_shares, rng)
            .unwrap();
        let p2_state = p2_state
            .to_round_two(&p2_my_encrypted_secret_shares, rng)
            .unwrap();
        let p3_state = p3_state
            .to_round_two(&p3_my_encrypted_secret_shares, rng)
            .unwrap();
        let p4_state = p4_state
            .to_round_two(&p4_my_encrypted_secret_shares, rng)
            .unwrap();
        let p5_state = p5_state
            .to_round_two(&p5_my_encrypted_secret_shares, rng)
            .unwrap();

        let (p1_group_key, p1_secret_key) = p1_state.finish().unwrap();
        let (p2_group_key, p2_secret_key) = p2_state.finish().unwrap();
        let (p3_group_key, p3_secret_key) = p3_state.finish().unwrap();
        let (p4_group_key, p4_secret_key) = p4_state.finish().unwrap();
        let (p5_group_key, p5_secret_key) = p5_state.finish().unwrap();

        assert!(p1_group_key == p2_group_key);
        assert!(p2_group_key == p3_group_key);
        assert!(p3_group_key == p4_group_key);
        assert!(p4_group_key == p5_group_key);

        let mut group_secret_key = Fr::ZERO;
        let indices = [1, 2, 3, 4, 5];

        group_secret_key += calculate_lagrange_coefficients::<Secp256k1Sha256>(1, &indices)
            .unwrap()
            * p1_secret_key.key;
        group_secret_key += calculate_lagrange_coefficients::<Secp256k1Sha256>(2, &indices)
            .unwrap()
            * p2_secret_key.key;
        group_secret_key += calculate_lagrange_coefficients::<Secp256k1Sha256>(3, &indices)
            .unwrap()
            * p3_secret_key.key;
        group_secret_key += calculate_lagrange_coefficients::<Secp256k1Sha256>(4, &indices)
            .unwrap()
            * p4_secret_key.key;
        group_secret_key += calculate_lagrange_coefficients::<Secp256k1Sha256>(5, &indices)
            .unwrap()
            * p5_secret_key.key;

        let group_key = GroupVerifyingKey::new(Projective::generator().mul(group_secret_key));

        assert!(p5_group_key == group_key);
    }

    #[test]
    fn keygen_2_out_of_3() {
        fn do_test() -> FrostResult<Secp256k1Sha256, ()> {
            let params = ThresholdParameters::new(3, 2);
            let rng = OsRng;

            let (p1, p1coeffs, p1_dh_sk) =
                Participant::<Secp256k1Sha256>::new_dealer(params, 1, rng).unwrap();
            let (p2, p2coeffs, p2_dh_sk) =
                Participant::<Secp256k1Sha256>::new_dealer(params, 2, rng).unwrap();
            let (p3, p3coeffs, p3_dh_sk) =
                Participant::<Secp256k1Sha256>::new_dealer(params, 3, rng).unwrap();

            p1.proof_of_secret_key
                .as_ref()
                .unwrap()
                .verify(p1.index, p1.public_key().unwrap())?;
            p2.proof_of_secret_key
                .as_ref()
                .unwrap()
                .verify(p2.index, p2.public_key().unwrap())?;
            p3.proof_of_secret_key
                .as_ref()
                .unwrap()
                .verify(p3.index, p3.public_key().unwrap())?;

            let participants: Vec<Participant<Secp256k1Sha256>> =
                vec![p1.clone(), p2.clone(), p3.clone()];
            let (p1_state, _participant_lists) =
                DistributedKeyGeneration::<RoundOne, Secp256k1Sha256>::bootstrap(
                    params,
                    &p1_dh_sk,
                    p1.index,
                    &p1coeffs,
                    &participants,
                    rng,
                )?;
            let p1_their_encrypted_secret_shares = p1_state.their_encrypted_secret_shares()?;

            let (p2_state, _participant_lists) =
                DistributedKeyGeneration::<RoundOne, Secp256k1Sha256>::bootstrap(
                    params,
                    &p2_dh_sk,
                    p2.index,
                    &p2coeffs,
                    &participants,
                    rng,
                )?;
            let p2_their_encrypted_secret_shares = p2_state.their_encrypted_secret_shares()?;

            let (p3_state, _participant_lists) =
                DistributedKeyGeneration::<RoundOne, Secp256k1Sha256>::bootstrap(
                    params,
                    &p3_dh_sk,
                    p3.index,
                    &p3coeffs,
                    &participants,
                    rng,
                )?;
            let p3_their_encrypted_secret_shares = p3_state.their_encrypted_secret_shares()?;

            let p1_my_encrypted_secret_shares = vec![
                p1_their_encrypted_secret_shares[0].clone(),
                p2_their_encrypted_secret_shares[0].clone(),
                p3_their_encrypted_secret_shares[0].clone(),
            ];
            let p2_my_encrypted_secret_shares = vec![
                p1_their_encrypted_secret_shares[1].clone(),
                p2_their_encrypted_secret_shares[1].clone(),
                p3_their_encrypted_secret_shares[1].clone(),
            ];
            let p3_my_encrypted_secret_shares = vec![
                p1_their_encrypted_secret_shares[2].clone(),
                p2_their_encrypted_secret_shares[2].clone(),
                p3_their_encrypted_secret_shares[2].clone(),
            ];

            let p1_state = p1_state.to_round_two(&p1_my_encrypted_secret_shares, rng)?;
            let p2_state = p2_state.to_round_two(&p2_my_encrypted_secret_shares, rng)?;
            let p3_state = p3_state.to_round_two(&p3_my_encrypted_secret_shares, rng)?;

            let (p1_group_key, _p1_secret_key) = p1_state.finish()?;
            let (p2_group_key, _p2_secret_key) = p2_state.finish()?;
            let (p3_group_key, _p3_secret_key) = p3_state.finish()?;

            assert!(p1_group_key == p2_group_key);
            assert!(p2_group_key == p3_group_key);

            Ok(())
        }
        assert!(do_test().is_ok());
    }

    #[test]
    fn keygen_static_2_out_of_3_with_common_participants() {
        fn do_test() -> FrostResult<Secp256k1Sha256, ()> {
            let params = ThresholdParameters::new(3, 2);
            let rng = OsRng;

            let (dealer1, dealer1coeffs, dealer1_dh_sk) =
                Participant::<Secp256k1Sha256>::new_dealer(params, 1, rng).unwrap();
            let (dealer2, dealer2coeffs, dealer2_dh_sk) =
                Participant::<Secp256k1Sha256>::new_dealer(params, 2, rng).unwrap();
            let (dealer3, dealer3coeffs, dealer3_dh_sk) =
                Participant::<Secp256k1Sha256>::new_dealer(params, 3, rng).unwrap();

            dealer1
                .proof_of_secret_key
                .as_ref()
                .unwrap()
                .verify(dealer1.index, dealer1.public_key().unwrap())?;
            dealer2
                .proof_of_secret_key
                .as_ref()
                .unwrap()
                .verify(dealer2.index, dealer2.public_key().unwrap())?;
            dealer3
                .proof_of_secret_key
                .as_ref()
                .unwrap()
                .verify(dealer3.index, dealer3.public_key().unwrap())?;

            let dealers: Vec<Participant<Secp256k1Sha256>> =
                vec![dealer1.clone(), dealer2.clone(), dealer3.clone()];
            let (dealer1_state, _participant_lists) =
                DistributedKeyGeneration::<RoundOne, Secp256k1Sha256>::bootstrap(
                    params,
                    &dealer1_dh_sk,
                    dealer1.index,
                    &dealer1coeffs,
                    &dealers,
                    rng,
                )?;
            let dealer1_their_encrypted_secret_shares =
                dealer1_state.their_encrypted_secret_shares()?;

            let (dealer2_state, _participant_lists) =
                DistributedKeyGeneration::<RoundOne, Secp256k1Sha256>::bootstrap(
                    params,
                    &dealer2_dh_sk,
                    dealer2.index,
                    &dealer2coeffs,
                    &dealers,
                    rng,
                )?;
            let dealer2_their_encrypted_secret_shares =
                dealer2_state.their_encrypted_secret_shares()?;

            let (dealer3_state, _participant_lists) =
                DistributedKeyGeneration::<RoundOne, Secp256k1Sha256>::bootstrap(
                    params,
                    &dealer3_dh_sk,
                    dealer3.index,
                    &dealer3coeffs,
                    &dealers,
                    rng,
                )?;
            let dealer3_their_encrypted_secret_shares =
                dealer3_state.their_encrypted_secret_shares()?;

            let dealer1_my_encrypted_secret_shares = vec![
                dealer1_their_encrypted_secret_shares[0].clone(),
                dealer2_their_encrypted_secret_shares[0].clone(),
                dealer3_their_encrypted_secret_shares[0].clone(),
            ];
            let dealer2_my_encrypted_secret_shares = vec![
                dealer1_their_encrypted_secret_shares[1].clone(),
                dealer2_their_encrypted_secret_shares[1].clone(),
                dealer3_their_encrypted_secret_shares[1].clone(),
            ];
            let dealer3_my_encrypted_secret_shares = vec![
                dealer1_their_encrypted_secret_shares[2].clone(),
                dealer2_their_encrypted_secret_shares[2].clone(),
                dealer3_their_encrypted_secret_shares[2].clone(),
            ];

            let dealer1_state =
                dealer1_state.to_round_two(&dealer1_my_encrypted_secret_shares, rng)?;
            let dealer2_state =
                dealer2_state.to_round_two(&dealer2_my_encrypted_secret_shares, rng)?;
            let dealer3_state =
                dealer3_state.to_round_two(&dealer3_my_encrypted_secret_shares, rng)?;

            let (dealer1_group_key, dealer1_secret_key) = dealer1_state.finish()?;
            let (dealer2_group_key, dealer2_secret_key) = dealer2_state.finish()?;
            let (dealer3_group_key, dealer3_secret_key) = dealer3_state.finish()?;

            assert!(dealer1_group_key == dealer2_group_key);
            assert!(dealer2_group_key == dealer3_group_key);

            let (signer1, signer1_dh_sk) = Participant::new_signer(params, 1, rng).unwrap();
            let (signer2, signer2_dh_sk) = Participant::new_signer(params, 2, rng).unwrap();
            // Dealer 3 is also a participant of the next set of signers
            let (signer3, signer3_dh_sk) = (dealer3, dealer3_dh_sk);

            let signers: Vec<Participant<Secp256k1Sha256>> =
                vec![signer1.clone(), signer2.clone(), signer3.clone()];

            let (dealer1_for_signers, dealer1_encrypted_shares_for_signers, _participant_lists) =
                Participant::reshare(params, &dealer1_secret_key, &signers, rng)?;
            let (dealer2_for_signers, dealer2_encrypted_shares_for_signers, _participant_lists) =
                Participant::reshare(params, &dealer2_secret_key, &signers, rng)?;
            let (dealer3_for_signers, dealer3_encrypted_shares_for_signers, _participant_lists) =
                Participant::reshare(params, &dealer3_secret_key, &signers, rng)?;

            let dealers: Vec<Participant<Secp256k1Sha256>> = vec![
                dealer1_for_signers,
                dealer2_for_signers,
                dealer3_for_signers,
            ];
            let (signer1_state, _participant_lists) =
                DistributedKeyGeneration::<RoundOne, Secp256k1Sha256>::new(
                    params,
                    &signer1_dh_sk,
                    signer1.index,
                    &dealers,
                    rng,
                )?;

            let (signer2_state, _participant_lists) =
                DistributedKeyGeneration::<RoundOne, Secp256k1Sha256>::new(
                    params,
                    &signer2_dh_sk,
                    signer2.index,
                    &dealers,
                    rng,
                )?;

            let (signer3_state, _participant_lists) =
                DistributedKeyGeneration::<RoundOne, Secp256k1Sha256>::new(
                    params,
                    &signer3_dh_sk,
                    signer3.index,
                    &dealers,
                    rng,
                )?;

            let signer1_my_encrypted_secret_shares = vec![
                dealer1_encrypted_shares_for_signers[0].clone(),
                dealer2_encrypted_shares_for_signers[0].clone(),
                dealer3_encrypted_shares_for_signers[0].clone(),
            ];
            let signer2_my_encrypted_secret_shares = vec![
                dealer1_encrypted_shares_for_signers[1].clone(),
                dealer2_encrypted_shares_for_signers[1].clone(),
                dealer3_encrypted_shares_for_signers[1].clone(),
            ];
            let signer3_my_encrypted_secret_shares = vec![
                dealer1_encrypted_shares_for_signers[2].clone(),
                dealer2_encrypted_shares_for_signers[2].clone(),
                dealer3_encrypted_shares_for_signers[2].clone(),
            ];

            let signer1_state =
                signer1_state.to_round_two(&signer1_my_encrypted_secret_shares, rng)?;
            let signer2_state =
                signer2_state.to_round_two(&signer2_my_encrypted_secret_shares, rng)?;
            let signer3_state =
                signer3_state.to_round_two(&signer3_my_encrypted_secret_shares, rng)?;

            let (signer1_group_key, _signer1_secret_key) = signer1_state.finish()?;
            let (signer2_group_key, _signer2_secret_key) = signer2_state.finish()?;
            let (signer3_group_key, _signer3_secret_key) = signer3_state.finish()?;

            assert!(signer1_group_key == signer2_group_key);
            assert!(signer2_group_key == signer3_group_key);

            assert!(signer1_group_key == dealer1_group_key);

            Ok(())
        }
        assert!(do_test().is_ok());
    }

    #[test]
    fn keygen_static_2_out_of_3_into_3_out_of_5() {
        fn do_test() -> FrostResult<Secp256k1Sha256, ()> {
            let params_dealers = ThresholdParameters::new(3, 2);
            let rng = OsRng;

            let (dealer1, dealer1coeffs, dealer1_dh_sk) =
                Participant::<Secp256k1Sha256>::new_dealer(params_dealers, 1, rng).unwrap();
            let (dealer2, dealer2coeffs, dealer2_dh_sk) =
                Participant::<Secp256k1Sha256>::new_dealer(params_dealers, 2, rng).unwrap();
            let (dealer3, dealer3coeffs, dealer3_dh_sk) =
                Participant::<Secp256k1Sha256>::new_dealer(params_dealers, 3, rng).unwrap();

            dealer1
                .proof_of_secret_key
                .as_ref()
                .unwrap()
                .verify(dealer1.index, dealer1.public_key().unwrap())?;
            dealer2
                .proof_of_secret_key
                .as_ref()
                .unwrap()
                .verify(dealer2.index, dealer2.public_key().unwrap())?;
            dealer3
                .proof_of_secret_key
                .as_ref()
                .unwrap()
                .verify(dealer3.index, dealer3.public_key().unwrap())?;

            let dealers: Vec<Participant<Secp256k1Sha256>> =
                vec![dealer1.clone(), dealer2.clone(), dealer3.clone()];
            let (dealer1_state, _participant_lists) =
                DistributedKeyGeneration::<RoundOne, Secp256k1Sha256>::bootstrap(
                    params_dealers,
                    &dealer1_dh_sk,
                    dealer1.index,
                    &dealer1coeffs,
                    &dealers,
                    rng,
                )?;
            let dealer1_their_encrypted_secret_shares =
                dealer1_state.their_encrypted_secret_shares()?;

            let (dealer2_state, _participant_lists) =
                DistributedKeyGeneration::<RoundOne, Secp256k1Sha256>::bootstrap(
                    params_dealers,
                    &dealer2_dh_sk,
                    dealer2.index,
                    &dealer2coeffs,
                    &dealers,
                    rng,
                )?;
            let dealer2_their_encrypted_secret_shares =
                dealer2_state.their_encrypted_secret_shares()?;

            let (dealer3_state, _participant_lists) =
                DistributedKeyGeneration::<RoundOne, Secp256k1Sha256>::bootstrap(
                    params_dealers,
                    &dealer3_dh_sk,
                    dealer3.index,
                    &dealer3coeffs,
                    &dealers,
                    rng,
                )?;
            let dealer3_their_encrypted_secret_shares =
                dealer3_state.their_encrypted_secret_shares()?;

            let dealer1_my_encrypted_secret_shares = vec![
                dealer1_their_encrypted_secret_shares[0].clone(),
                dealer2_their_encrypted_secret_shares[0].clone(),
                dealer3_their_encrypted_secret_shares[0].clone(),
            ];
            let dealer2_my_encrypted_secret_shares = vec![
                dealer1_their_encrypted_secret_shares[1].clone(),
                dealer2_their_encrypted_secret_shares[1].clone(),
                dealer3_their_encrypted_secret_shares[1].clone(),
            ];
            let dealer3_my_encrypted_secret_shares = vec![
                dealer1_their_encrypted_secret_shares[2].clone(),
                dealer2_their_encrypted_secret_shares[2].clone(),
                dealer3_their_encrypted_secret_shares[2].clone(),
            ];

            let dealer1_state =
                dealer1_state.to_round_two(&dealer1_my_encrypted_secret_shares, rng)?;
            let dealer2_state =
                dealer2_state.to_round_two(&dealer2_my_encrypted_secret_shares, rng)?;
            let dealer3_state =
                dealer3_state.to_round_two(&dealer3_my_encrypted_secret_shares, rng)?;

            let (dealer1_group_key, dealer1_secret_key) = dealer1_state.finish()?;
            let (dealer2_group_key, dealer2_secret_key) = dealer2_state.finish()?;
            let (dealer3_group_key, dealer3_secret_key) = dealer3_state.finish()?;

            assert!(dealer1_group_key == dealer2_group_key);
            assert!(dealer2_group_key == dealer3_group_key);

            let params_signers = ThresholdParameters::<Secp256k1Sha256>::new(5, 3);
            let (signer1, signer1_dh_sk) = Participant::new_signer(params_signers, 1, rng).unwrap();
            let (signer2, signer2_dh_sk) = Participant::new_signer(params_signers, 2, rng).unwrap();
            let (signer3, signer3_dh_sk) = Participant::new_signer(params_signers, 3, rng).unwrap();
            let (signer4, signer4_dh_sk) = Participant::new_signer(params_signers, 4, rng).unwrap();
            let (signer5, signer5_dh_sk) = Participant::new_signer(params_signers, 5, rng).unwrap();

            let signers: Vec<Participant<Secp256k1Sha256>> = vec![
                signer1.clone(),
                signer2.clone(),
                signer3.clone(),
                signer4.clone(),
                signer5.clone(),
            ];

            let (dealer1_for_signers, dealer1_encrypted_shares_for_signers, _participant_lists) =
                Participant::reshare(params_signers, &dealer1_secret_key, &signers, rng)?;
            let (dealer2_for_signers, dealer2_encrypted_shares_for_signers, _participant_lists) =
                Participant::reshare(params_signers, &dealer2_secret_key, &signers, rng)?;
            let (dealer3_for_signers, dealer3_encrypted_shares_for_signers, _participant_lists) =
                Participant::reshare(params_signers, &dealer3_secret_key, &signers, rng)?;

            let dealers: Vec<Participant<Secp256k1Sha256>> = vec![
                dealer1_for_signers,
                dealer2_for_signers,
                dealer3_for_signers,
            ];
            let (signer1_state, _participant_lists) =
                DistributedKeyGeneration::<RoundOne, Secp256k1Sha256>::new(
                    params_dealers,
                    &signer1_dh_sk,
                    signer1.index,
                    &dealers,
                    rng,
                )?;

            let (signer2_state, _participant_lists) =
                DistributedKeyGeneration::<RoundOne, Secp256k1Sha256>::new(
                    params_dealers,
                    &signer2_dh_sk,
                    signer2.index,
                    &dealers,
                    rng,
                )?;

            let (signer3_state, _participant_lists) =
                DistributedKeyGeneration::<RoundOne, Secp256k1Sha256>::new(
                    params_dealers,
                    &signer3_dh_sk,
                    signer3.index,
                    &dealers,
                    rng,
                )?;

            let (signer4_state, _participant_lists) =
                DistributedKeyGeneration::<RoundOne, Secp256k1Sha256>::new(
                    params_dealers,
                    &signer4_dh_sk,
                    signer4.index,
                    &dealers,
                    rng,
                )?;

            let (signer5_state, _participant_lists) =
                DistributedKeyGeneration::<RoundOne, Secp256k1Sha256>::new(
                    params_dealers,
                    &signer5_dh_sk,
                    signer5.index,
                    &dealers,
                    rng,
                )?;

            let signer1_my_encrypted_secret_shares = vec![
                dealer1_encrypted_shares_for_signers[0].clone(),
                dealer2_encrypted_shares_for_signers[0].clone(),
                dealer3_encrypted_shares_for_signers[0].clone(),
            ];
            let signer2_my_encrypted_secret_shares = vec![
                dealer1_encrypted_shares_for_signers[1].clone(),
                dealer2_encrypted_shares_for_signers[1].clone(),
                dealer3_encrypted_shares_for_signers[1].clone(),
            ];
            let signer3_my_encrypted_secret_shares = vec![
                dealer1_encrypted_shares_for_signers[2].clone(),
                dealer2_encrypted_shares_for_signers[2].clone(),
                dealer3_encrypted_shares_for_signers[2].clone(),
            ];
            let signer4_my_encrypted_secret_shares = vec![
                dealer1_encrypted_shares_for_signers[3].clone(),
                dealer2_encrypted_shares_for_signers[3].clone(),
                dealer3_encrypted_shares_for_signers[3].clone(),
            ];
            let signer5_my_encrypted_secret_shares = vec![
                dealer1_encrypted_shares_for_signers[4].clone(),
                dealer2_encrypted_shares_for_signers[4].clone(),
                dealer3_encrypted_shares_for_signers[4].clone(),
            ];

            let signer1_state =
                signer1_state.to_round_two(&signer1_my_encrypted_secret_shares, rng)?;
            let signer2_state =
                signer2_state.to_round_two(&signer2_my_encrypted_secret_shares, rng)?;
            let signer3_state =
                signer3_state.to_round_two(&signer3_my_encrypted_secret_shares, rng)?;
            let signer4_state =
                signer4_state.to_round_two(&signer4_my_encrypted_secret_shares, rng)?;
            let signer5_state =
                signer5_state.to_round_two(&signer5_my_encrypted_secret_shares, rng)?;

            let (signer1_group_key, _signer1_secret_key) = signer1_state.finish()?;
            let (signer2_group_key, _signer2_secret_key) = signer2_state.finish()?;
            let (signer3_group_key, _signer3_secret_key) = signer3_state.finish()?;
            let (signer4_group_key, _signer4_secret_key) = signer4_state.finish()?;
            let (signer5_group_key, _signer5_secret_key) = signer5_state.finish()?;

            assert!(signer1_group_key == signer2_group_key);
            assert!(signer2_group_key == signer3_group_key);
            assert!(signer3_group_key == signer4_group_key);
            assert!(signer4_group_key == signer5_group_key);

            assert!(signer1_group_key == dealer1_group_key);

            Ok(())
        }
        assert!(do_test().is_ok());
    }

    #[test]
    fn encrypt_and_decrypt() {
        let mut rng = OsRng;

        let original_share = SecretShare::<Secp256k1Sha256> {
            sender_index: 1,
            receiver_index: 2,
            polynomial_evaluation: Fr::rand(&mut rng),
        };

        let mut key = [0u8; 32];
        rng.fill(&mut key);

        let encrypted_share = encrypt_share(&original_share, &key, rng).unwrap();
        let decrypted_share = decrypt_share::<Secp256k1Sha256>(&encrypted_share, &key);

        assert!(decrypted_share.is_ok());
        assert!(
            original_share.polynomial_evaluation == decrypted_share.unwrap().polynomial_evaluation
        );
    }

    #[test]
    fn keygen_2_out_of_3_with_random_keys() {
        fn do_test() -> FrostResult<Secp256k1Sha256, ()> {
            let params = ThresholdParameters::new(3, 2);
            let rng = OsRng;

            let (p1, p1coeffs, dh_sk1) =
                Participant::<Secp256k1Sha256>::new_dealer(params, 1, rng).unwrap();
            let (p2, p2coeffs, dh_sk2) =
                Participant::<Secp256k1Sha256>::new_dealer(params, 2, rng).unwrap();
            let (p3, p3coeffs, dh_sk3) =
                Participant::<Secp256k1Sha256>::new_dealer(params, 3, rng).unwrap();

            p1.proof_of_secret_key
                .as_ref()
                .unwrap()
                .verify(p1.index, p1.public_key().unwrap())?;
            p2.proof_of_secret_key
                .as_ref()
                .unwrap()
                .verify(p2.index, p2.public_key().unwrap())?;
            p3.proof_of_secret_key
                .as_ref()
                .unwrap()
                .verify(p3.index, p3.public_key().unwrap())?;

            let participants: Vec<Participant<Secp256k1Sha256>> =
                vec![p1.clone(), p2.clone(), p3.clone()];
            let (p1_state, _participant_lists) =
                DistributedKeyGeneration::<RoundOne, Secp256k1Sha256>::bootstrap(
                    params,
                    &dh_sk1,
                    p1.index,
                    &p1coeffs,
                    &participants,
                    rng,
                )?;
            let p1_their_encrypted_secret_shares = p1_state.their_encrypted_secret_shares()?;

            let (p2_state, _participant_lists) =
                DistributedKeyGeneration::<RoundOne, Secp256k1Sha256>::bootstrap(
                    params,
                    &dh_sk2,
                    p2.index,
                    &p2coeffs,
                    &participants,
                    rng,
                )?;
            let p2_their_encrypted_secret_shares = p2_state.their_encrypted_secret_shares()?;

            let (p3_state, _participant_lists) =
                DistributedKeyGeneration::<RoundOne, Secp256k1Sha256>::bootstrap(
                    params,
                    &dh_sk3,
                    p3.index,
                    &p3coeffs,
                    &participants,
                    rng,
                )?;
            let p3_their_encrypted_secret_shares = p3_state.their_encrypted_secret_shares()?;

            let p1_my_encrypted_secret_shares = vec![
                p1_their_encrypted_secret_shares[0].clone(),
                p2_their_encrypted_secret_shares[0].clone(),
                p3_their_encrypted_secret_shares[0].clone(),
            ];
            let p2_my_encrypted_secret_shares = vec![
                p1_their_encrypted_secret_shares[1].clone(),
                p2_their_encrypted_secret_shares[1].clone(),
                p3_their_encrypted_secret_shares[1].clone(),
            ];
            let p3_my_encrypted_secret_shares = vec![
                p1_their_encrypted_secret_shares[2].clone(),
                p2_their_encrypted_secret_shares[2].clone(),
                p3_their_encrypted_secret_shares[2].clone(),
            ];

            let p1_state = p1_state.to_round_two(&p1_my_encrypted_secret_shares, rng)?;
            let p2_state = p2_state.to_round_two(&p2_my_encrypted_secret_shares, rng)?;
            let p3_state = p3_state.to_round_two(&p3_my_encrypted_secret_shares, rng)?;

            let (p1_group_key, _p1_secret_key) = p1_state.finish()?;
            let (p2_group_key, _p2_secret_key) = p2_state.finish()?;
            let (p3_group_key, _p3_secret_key) = p3_state.finish()?;

            assert!(p1_group_key == p2_group_key);
            assert!(p2_group_key == p3_group_key);

            Ok(())
        }
        assert!(do_test().is_ok());
    }

    #[test]
    fn keygen_verify_complaint() {
        fn do_test() -> FrostResult<Secp256k1Sha256, ()> {
            let params = ThresholdParameters::new(3, 2);
            let rng = OsRng;

            let (p1, p1coeffs, dh_sk1) =
                Participant::<Secp256k1Sha256>::new_dealer(params, 1, rng).unwrap();
            let (p2, p2coeffs, dh_sk2) =
                Participant::<Secp256k1Sha256>::new_dealer(params, 2, rng).unwrap();
            let (p3, p3coeffs, dh_sk3) =
                Participant::<Secp256k1Sha256>::new_dealer(params, 3, rng).unwrap();

            p1.proof_of_secret_key
                .as_ref()
                .unwrap()
                .verify(p1.index, p1.public_key().unwrap())?;
            p2.proof_of_secret_key
                .as_ref()
                .unwrap()
                .verify(p2.index, p2.public_key().unwrap())?;
            p3.proof_of_secret_key
                .as_ref()
                .unwrap()
                .verify(p3.index, p3.public_key().unwrap())?;

            let participants: Vec<Participant<Secp256k1Sha256>> =
                vec![p1.clone(), p2.clone(), p3.clone()];
            let (p1_state, _participant_lists) =
                DistributedKeyGeneration::<RoundOne, Secp256k1Sha256>::bootstrap(
                    params,
                    &dh_sk1,
                    p1.index,
                    &p1coeffs,
                    &participants,
                    rng,
                )?;
            let p1_their_encrypted_secret_shares = p1_state.their_encrypted_secret_shares()?;

            let (p2_state, _participant_lists) =
                DistributedKeyGeneration::<RoundOne, Secp256k1Sha256>::bootstrap(
                    params,
                    &dh_sk2,
                    p2.index,
                    &p2coeffs,
                    &participants,
                    rng,
                )?;
            let p2_their_encrypted_secret_shares = p2_state.their_encrypted_secret_shares()?;

            let (p3_state, _participant_lists) =
                DistributedKeyGeneration::<RoundOne, Secp256k1Sha256>::bootstrap(
                    params,
                    &dh_sk3,
                    p3.index,
                    &p3coeffs,
                    &participants,
                    rng,
                )?;
            let p3_their_encrypted_secret_shares = p3_state.their_encrypted_secret_shares()?;

            let mut complaint: Complaint<Secp256k1Sha256>;

            // Wrong decryption from nonce
            {
                let mut wrong_encrypted_secret_share = p1_their_encrypted_secret_shares[1].clone();
                wrong_encrypted_secret_share.nonce = [42; 12].into();
                let p1_my_encrypted_secret_shares = vec![
                    p1_their_encrypted_secret_shares[0].clone(),
                    p2_their_encrypted_secret_shares[0].clone(),
                    p3_their_encrypted_secret_shares[0].clone(),
                ];
                // Wrong share inserted here!
                let p2_my_encrypted_secret_shares = vec![
                    wrong_encrypted_secret_share.clone(),
                    p2_their_encrypted_secret_shares[1].clone(),
                    p3_their_encrypted_secret_shares[1].clone(),
                ];
                let p3_my_encrypted_secret_shares = vec![
                    p1_their_encrypted_secret_shares[2].clone(),
                    p2_their_encrypted_secret_shares[2].clone(),
                    p3_their_encrypted_secret_shares[2].clone(),
                ];

                let p1_state = p1_state
                    .clone()
                    .to_round_two(&p1_my_encrypted_secret_shares, rng)?;
                let p3_state = p3_state
                    .clone()
                    .to_round_two(&p3_my_encrypted_secret_shares, rng)?;

                let complaints = p2_state
                    .clone()
                    .to_round_two(&p2_my_encrypted_secret_shares, rng);
                assert!(complaints.is_err());
                let complaints = complaints.unwrap_err();
                if let Error::Complaint(complaints) = complaints {
                    assert!(complaints.len() == 1);

                    let bad_index = p3_state.blame(&wrong_encrypted_secret_share, &complaints[0]);
                    assert!(bad_index == 1);

                    let (p1_group_key, _p1_secret_key) = p1_state.finish()?;
                    let (p3_group_key, _p3_secret_key) = p3_state.finish()?;

                    assert!(p1_group_key == p3_group_key);

                    // Copy for next test and change dh_key
                    complaint = complaints[0].clone();
                    complaint.dh_shared_key.double_in_place();
                } else {
                    return Err(Error::Custom("Unexpected error".to_string()));
                }
            }

            // Wrong decryption of polynomial evaluation
            {
                let mut wrong_encrypted_secret_share = p1_their_encrypted_secret_shares[1].clone();
                wrong_encrypted_secret_share.encrypted_polynomial_evaluation = vec![42; 32];
                let p1_my_encrypted_secret_shares = vec![
                    p1_their_encrypted_secret_shares[0].clone(),
                    p2_their_encrypted_secret_shares[0].clone(),
                    p3_their_encrypted_secret_shares[0].clone(),
                ];
                // Wrong share inserted here!
                let p2_my_encrypted_secret_shares = vec![
                    wrong_encrypted_secret_share.clone(),
                    p2_their_encrypted_secret_shares[1].clone(),
                    p3_their_encrypted_secret_shares[1].clone(),
                ];
                let p3_my_encrypted_secret_shares = vec![
                    p1_their_encrypted_secret_shares[2].clone(),
                    p2_their_encrypted_secret_shares[2].clone(),
                    p3_their_encrypted_secret_shares[2].clone(),
                ];

                let p1_state = p1_state
                    .clone()
                    .to_round_two(&p1_my_encrypted_secret_shares, rng)?;
                let p3_state = p3_state
                    .clone()
                    .to_round_two(&p3_my_encrypted_secret_shares, rng)?;

                let complaints = p2_state
                    .clone()
                    .to_round_two(&p2_my_encrypted_secret_shares, rng);
                assert!(complaints.is_err());
                let complaints = complaints.unwrap_err();
                if let Error::Complaint(complaints) = complaints {
                    assert!(complaints.len() == 1);

                    let bad_index = p3_state.blame(&wrong_encrypted_secret_share, &complaints[0]);
                    assert!(bad_index == 1);

                    let (p1_group_key, _p1_secret_key) = p1_state.finish()?;
                    let (p3_group_key, _p3_secret_key) = p3_state.finish()?;

                    assert!(p1_group_key == p3_group_key);
                } else {
                    return Err(Error::Custom("Unexpected error".to_string()));
                }
            }

            // Wrong encrypted share
            {
                let dh_key = p1.dh_public_key.key * dh_sk1.0;
                let mut dh_key_bytes = Vec::with_capacity(dh_key.compressed_size());
                dh_key.serialize_compressed(&mut dh_key_bytes).unwrap();
                let wrong_encrypted_secret_share = encrypt_share(
                    &SecretShare::<Secp256k1Sha256> {
                        sender_index: 1,
                        receiver_index: 2,
                        polynomial_evaluation: Fr::from(42u32),
                    },
                    &dh_key_bytes[..],
                    rng,
                )
                .unwrap();
                let p1_my_encrypted_secret_shares = vec![
                    p1_their_encrypted_secret_shares[0].clone(),
                    p2_their_encrypted_secret_shares[0].clone(),
                    p3_their_encrypted_secret_shares[0].clone(),
                ];
                // Wrong share inserted here!
                let p2_my_encrypted_secret_shares = vec![
                    wrong_encrypted_secret_share.clone(),
                    p2_their_encrypted_secret_shares[1].clone(),
                    p3_their_encrypted_secret_shares[1].clone(),
                ];
                let p3_my_encrypted_secret_shares = vec![
                    p1_their_encrypted_secret_shares[2].clone(),
                    p2_their_encrypted_secret_shares[2].clone(),
                    p3_their_encrypted_secret_shares[2].clone(),
                ];

                let p1_state = p1_state
                    .clone()
                    .to_round_two(&p1_my_encrypted_secret_shares, rng)?;
                let p3_state = p3_state
                    .clone()
                    .to_round_two(&p3_my_encrypted_secret_shares, rng)?;

                let complaints = p2_state
                    .clone()
                    .to_round_two(&p2_my_encrypted_secret_shares, rng);
                assert!(complaints.is_err());
                let complaints = complaints.unwrap_err();
                if let Error::Complaint(complaints) = complaints {
                    assert!(complaints.len() == 1);

                    let bad_index = p3_state.blame(&wrong_encrypted_secret_share, &complaints[0]);
                    assert!(bad_index == 1);

                    let (p1_group_key, _p1_secret_key) = p1_state.finish()?;
                    let (p3_group_key, _p3_secret_key) = p3_state.finish()?;

                    assert!(p1_group_key == p3_group_key);
                } else {
                    return Err(Error::Custom("Unexpected error".to_string()));
                }
            }

            // Wrong complaint leads to blaming the complaint maker
            {
                let _p1_my_encrypted_secret_shares = vec![
                    p1_their_encrypted_secret_shares[0].clone(),
                    p2_their_encrypted_secret_shares[0].clone(),
                    p3_their_encrypted_secret_shares[0].clone(),
                ];
                let _p2_my_encrypted_secret_shares = vec![
                    p1_their_encrypted_secret_shares[0].clone(),
                    p2_their_encrypted_secret_shares[1].clone(),
                    p3_their_encrypted_secret_shares[1].clone(),
                ];
                let p3_my_encrypted_secret_shares = vec![
                    p1_their_encrypted_secret_shares[2].clone(),
                    p2_their_encrypted_secret_shares[2].clone(),
                    p3_their_encrypted_secret_shares[2].clone(),
                ];

                let p3_state = p3_state
                    .clone()
                    .to_round_two(&p3_my_encrypted_secret_shares, rng)?;

                let bad_index = p3_state.blame(&p1_their_encrypted_secret_shares[0], &complaint);
                assert!(bad_index == 2);
            }

            Ok(())
        }
        assert!(do_test().is_ok());
    }

    #[test]
    fn test_serialization() {
        fn do_test() -> FrostResult<Secp256k1Sha256, ()> {
            let params = ThresholdParameters::new(3, 2);
            let rng = OsRng;

            let (p1, p1coeffs, p1_dh_sk) = Participant::new_dealer(params, 1, rng).unwrap();
            let (p2, p2coeffs, p2_dh_sk) = Participant::new_dealer(params, 2, rng).unwrap();
            let (p3, p3coeffs, p3_dh_sk) = Participant::new_dealer(params, 3, rng).unwrap();

            p1.proof_of_secret_key
                .as_ref()
                .unwrap()
                .verify(p1.index, p1.public_key().unwrap())?;
            p2.proof_of_secret_key
                .as_ref()
                .unwrap()
                .verify(p2.index, p2.public_key().unwrap())?;
            p3.proof_of_secret_key
                .as_ref()
                .unwrap()
                .verify(p3.index, p3.public_key().unwrap())?;

            let participants: Vec<Participant<Secp256k1Sha256>> =
                vec![p1.clone(), p2.clone(), p3.clone()];
            let (p1_state, _participant_lists) =
                DistributedKeyGeneration::<RoundOne, Secp256k1Sha256>::bootstrap(
                    params,
                    &p1_dh_sk,
                    p1.index,
                    &p1coeffs,
                    &participants,
                    rng,
                )?;
            let p1_their_encrypted_secret_shares = p1_state.their_encrypted_secret_shares()?;

            let (p2_state, _participant_lists) =
                DistributedKeyGeneration::<RoundOne, Secp256k1Sha256>::bootstrap(
                    params,
                    &p2_dh_sk,
                    p2.index,
                    &p2coeffs,
                    &participants,
                    rng,
                )?;
            let p2_their_encrypted_secret_shares = p2_state.their_encrypted_secret_shares()?;

            let (p3_state, _participant_lists) =
                DistributedKeyGeneration::<RoundOne, Secp256k1Sha256>::bootstrap(
                    params,
                    &p3_dh_sk,
                    p3.index,
                    &p3coeffs,
                    &participants,
                    rng,
                )?;
            let p3_their_encrypted_secret_shares = p3_state.their_encrypted_secret_shares()?;

            {
                let p1_my_encrypted_secret_shares = vec![
                    p1_their_encrypted_secret_shares[0].clone(),
                    p2_their_encrypted_secret_shares[0].clone(),
                    p3_their_encrypted_secret_shares[0].clone(),
                ];
                let p2_my_encrypted_secret_shares = vec![
                    p1_their_encrypted_secret_shares[1].clone(),
                    p2_their_encrypted_secret_shares[1].clone(),
                    p3_their_encrypted_secret_shares[1].clone(),
                ];
                let p3_my_encrypted_secret_shares = vec![
                    p1_their_encrypted_secret_shares[2].clone(),
                    p2_their_encrypted_secret_shares[2].clone(),
                    p3_their_encrypted_secret_shares[2].clone(),
                ];

                // Check serialization

                let bytes = p1.to_bytes()?;
                assert_eq!(p1, Participant::from_bytes(&bytes)?);

                let bytes = p1coeffs.to_bytes()?;
                let p1coeffs_deserialized = Coefficients::from_bytes(&bytes)?;
                assert_eq!(p1coeffs.0.len(), p1coeffs_deserialized.0.len());
                for i in 0..p1coeffs.0.len() {
                    assert_eq!(p1coeffs.0[i], p1coeffs_deserialized.0[i]);
                }

                let bytes = p1_dh_sk.to_bytes()?;
                assert_eq!(p1_dh_sk, DiffieHellmanPrivateKey::from_bytes(&bytes)?);

                let bytes = p1.proof_of_secret_key.as_ref().unwrap().to_bytes()?;
                assert_eq!(
                    p1.proof_of_secret_key.unwrap(),
                    NizkPokOfSecretKey::from_bytes(&bytes)?
                );

                let bytes = p1_state.their_encrypted_secret_shares()?[0].to_bytes()?;
                assert_eq!(
                    p1_state.their_encrypted_secret_shares()?[0],
                    EncryptedSecretShare::from_bytes(&bytes)?
                );

                let bytes = p1_state.to_bytes()?;
                assert_eq!(
                    *p1_state.state,
                    *DistributedKeyGeneration::<RoundOne, Secp256k1Sha256>::from_bytes(&bytes)?
                        .state
                );

                // Continue KeyGen

                let p1_state = p1_state
                    .clone()
                    .to_round_two(&p1_my_encrypted_secret_shares, rng)?;
                let p2_state = p2_state
                    .clone()
                    .to_round_two(&p2_my_encrypted_secret_shares, rng)?;
                let p3_state = p3_state
                    .clone()
                    .to_round_two(&p3_my_encrypted_secret_shares, rng)?;

                let (p1_group_key, _p1_secret_key) = p1_state.clone().finish()?;
                let (p2_group_key, _p2_secret_key) = p2_state.finish()?;
                let (p3_group_key, _p3_secret_key) = p3_state.finish()?;

                assert!(p1_group_key.key == p2_group_key.key);
                assert!(p2_group_key.key == p3_group_key.key);

                // Check serialization
                let bytes = p1_group_key.to_bytes()?;
                assert_eq!(p1_group_key, GroupVerifyingKey::from_bytes(&bytes)?);

                let bytes = p1_state.to_bytes()?;
                assert_eq!(
                    *p1_state.state,
                    *DistributedKeyGeneration::<RoundTwo, Secp256k1Sha256>::from_bytes(&bytes)?
                        .state
                );
            }

            {
                let wrong_encrypted_secret_share =
                    EncryptedSecretShare::new(1, 2, [0; 12].into(), vec![0]);

                let p1_my_encrypted_secret_shares = vec![
                    p1_their_encrypted_secret_shares[0].clone(),
                    p2_their_encrypted_secret_shares[0].clone(),
                    p3_their_encrypted_secret_shares[0].clone(),
                ];
                let p2_my_encrypted_secret_shares = vec![
                    wrong_encrypted_secret_share.clone(),
                    p2_their_encrypted_secret_shares[1].clone(),
                    p3_their_encrypted_secret_shares[1].clone(),
                ];
                let p3_my_encrypted_secret_shares = vec![
                    p1_their_encrypted_secret_shares[2].clone(),
                    p2_their_encrypted_secret_shares[2].clone(),
                    p3_their_encrypted_secret_shares[2].clone(),
                ];

                let p1_state = p1_state.to_round_two(&p1_my_encrypted_secret_shares, rng)?;
                let p3_state = p3_state.to_round_two(&p3_my_encrypted_secret_shares, rng)?;

                let complaints = p2_state.to_round_two(&p2_my_encrypted_secret_shares, rng);
                assert!(complaints.is_err());
                let complaints = complaints.unwrap_err();
                if let Error::Complaint(complaints) = complaints {
                    assert!(complaints.len() == 1);

                    let bad_index = p3_state.blame(&wrong_encrypted_secret_share, &complaints[0]);

                    assert!(bad_index == 1);

                    let (p1_group_key, _p1_secret_key) = p1_state.finish()?;
                    let (p3_group_key, _p3_secret_key) = p3_state.finish()?;

                    assert!(p1_group_key == p3_group_key);

                    // Check serialization

                    let bytes = complaints[0].proof.to_bytes()?;
                    assert_eq!(complaints[0].proof, ComplaintProof::from_bytes(&bytes)?);

                    let bytes = complaints[0].to_bytes()?;
                    assert_eq!(complaints[0], Complaint::from_bytes(&bytes)?);

                    Ok(())
                } else {
                    Err(Error::Custom("Unexpected error".to_string()))
                }
            }
        }

        println!("{:?}", do_test());

        assert!(do_test().is_ok());
    }

    #[test]
    fn individual_public_key_share() {
        fn do_test() -> FrostResult<Secp256k1Sha256, ()> {
            let params = ThresholdParameters::new(3, 2);
            let rng = OsRng;

            let (p1, p1coeffs, p1_dh_sk) =
                Participant::<Secp256k1Sha256>::new_dealer(params, 1, rng).unwrap();
            let (p2, p2coeffs, p2_dh_sk) =
                Participant::<Secp256k1Sha256>::new_dealer(params, 2, rng).unwrap();
            let (p3, p3coeffs, p3_dh_sk) =
                Participant::<Secp256k1Sha256>::new_dealer(params, 3, rng).unwrap();

            p1.proof_of_secret_key
                .as_ref()
                .unwrap()
                .verify(p1.index, p1.public_key().unwrap())?;
            p2.proof_of_secret_key
                .as_ref()
                .unwrap()
                .verify(p2.index, p2.public_key().unwrap())?;
            p3.proof_of_secret_key
                .as_ref()
                .unwrap()
                .verify(p3.index, p3.public_key().unwrap())?;

            let participants: Vec<Participant<Secp256k1Sha256>> =
                vec![p1.clone(), p2.clone(), p3.clone()];
            let (p1_state, _participant_lists) =
                DistributedKeyGeneration::<RoundOne, Secp256k1Sha256>::bootstrap(
                    params,
                    &p1_dh_sk,
                    p1.index,
                    &p1coeffs,
                    &participants,
                    rng,
                )?;
            let p1_their_encrypted_secret_shares = p1_state.their_encrypted_secret_shares()?;

            let (p2_state, _participant_lists) =
                DistributedKeyGeneration::<RoundOne, Secp256k1Sha256>::bootstrap(
                    params,
                    &p2_dh_sk,
                    p2.index,
                    &p2coeffs,
                    &participants,
                    rng,
                )?;
            let p2_their_encrypted_secret_shares = p2_state.their_encrypted_secret_shares()?;

            let (p3_state, _participant_lists) =
                DistributedKeyGeneration::<RoundOne, Secp256k1Sha256>::bootstrap(
                    params,
                    &p3_dh_sk,
                    p3.index,
                    &p3coeffs,
                    &participants,
                    rng,
                )?;
            let p3_their_encrypted_secret_shares = p3_state.their_encrypted_secret_shares()?;

            let p1_my_encrypted_secret_shares = vec![
                p1_their_encrypted_secret_shares[0].clone(),
                p2_their_encrypted_secret_shares[0].clone(),
                p3_their_encrypted_secret_shares[0].clone(),
            ];
            let p2_my_encrypted_secret_shares = vec![
                p1_their_encrypted_secret_shares[1].clone(),
                p2_their_encrypted_secret_shares[1].clone(),
                p3_their_encrypted_secret_shares[1].clone(),
            ];
            let p3_my_encrypted_secret_shares = vec![
                p1_their_encrypted_secret_shares[2].clone(),
                p2_their_encrypted_secret_shares[2].clone(),
                p3_their_encrypted_secret_shares[2].clone(),
            ];

            let p1_state = p1_state.to_round_two(&p1_my_encrypted_secret_shares, rng)?;
            let p2_state = p2_state.to_round_two(&p2_my_encrypted_secret_shares, rng)?;
            let p3_state = p3_state.to_round_two(&p3_my_encrypted_secret_shares, rng)?;

            let (p1_group_key, p1_secret_key) = p1_state.finish()?;
            let (p2_group_key, p2_secret_key) = p2_state.finish()?;
            let (p3_group_key, p3_secret_key) = p3_state.finish()?;

            assert!(p1_group_key == p2_group_key);
            assert!(p2_group_key == p3_group_key);

            // Check the validity of each IndividualVerifyingKey

            let p1_public_key = p1_secret_key.to_public();
            let p2_public_key = p2_secret_key.to_public();
            let p3_public_key = p3_secret_key.to_public();

            // The order does not matter
            let commitments = [
                p2.commitments.unwrap(),
                p3.commitments.unwrap(),
                p1.commitments.unwrap(),
            ];

            assert!(p1_public_key.verify(&commitments).is_ok());
            assert!(p2_public_key.verify(&commitments).is_ok());
            assert!(p3_public_key.verify(&commitments).is_ok());

            assert!(p1_public_key.verify(&commitments[1..]).is_err());

            // Check that the generated IndividualVerifyingKey from other participants match
            let p1_recovered_public_key =
                IndividualVerifyingKey::generate_from_commitments(1, &commitments)?;
            let p2_recovered_public_key =
                IndividualVerifyingKey::generate_from_commitments(2, &commitments)?;
            let p3_recovered_public_key =
                IndividualVerifyingKey::generate_from_commitments(3, &commitments)?;

            assert_eq!(p1_public_key, p1_recovered_public_key);
            assert_eq!(p2_public_key, p2_recovered_public_key);
            assert_eq!(p3_public_key, p3_recovered_public_key);

            Ok(())
        }
        assert!(do_test().is_ok());
    }
}
