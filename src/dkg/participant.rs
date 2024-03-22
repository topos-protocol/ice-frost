//! The participant module, defining ICE-FROST Distributed Key Generation
//! participants creation and individual secret share redistribution.

use ark_ec::Group;
use ark_ff::UniformRand;
use ark_serialize::CanonicalDeserialize;
use ark_serialize::CanonicalSerialize;

use core::cmp::Ordering;
use core::ops::Mul;
use rand::CryptoRng;
use rand::RngCore;

use crate::ciphersuite::CipherSuite;
use crate::dkg::{
    secret_share::{Coefficients, EncryptedSecretShare, VerifiableSecretSharingCommitment},
    NizkPokOfSecretKey,
};
use crate::keys::{DiffieHellmanPrivateKey, DiffieHellmanPublicKey, IndividualSigningKey};
use crate::parameters::ThresholdParameters;
use crate::serialization::impl_serialization_traits;
use crate::{Error, FrostResult};

use crate::utils::{BTreeMap, Scalar, Vec};

use super::DKGParticipantList;
use super::DistributedKeyGeneration;

/// A participant in a threshold signing.
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct Participant<C: CipherSuite> {
    /// The index of this participant, to keep the participants in order.
    pub index: u32,
    /// The public key used to derive symmetric keys for encrypting and
    /// decrypting shares via DH.
    pub dh_public_key: DiffieHellmanPublicKey<C>,
    /// A vector of Pedersen commitments to the coefficients of this
    /// participant's private polynomial.
    pub commitments: Option<VerifiableSecretSharingCommitment<C>>,
    /// The zero-knowledge proof of knowledge of the secret key (a.k.a. the
    /// first coefficient in the private polynomial).  It is constructed as a
    /// Schnorr signature using \\( a_{i0} \\) as the signing key.
    pub proof_of_secret_key: Option<NizkPokOfSecretKey<C>>,
    /// The zero-knowledge proof of knowledge of the DH private key.
    /// It is computed similarly to the proof_of_secret_key.
    pub proof_of_dh_private_key: NizkPokOfSecretKey<C>,
}

impl_serialization_traits!(Participant<CipherSuite>);

impl<C: CipherSuite> Participant<C> {
    /// Construct a new dealer for the distributed key generation protocol,
    /// who will generate shares for a group of participants. Dealers are regular
    /// signers with the additional ability to redistribute their secret shares,
    /// either to the same set of participants (called key refreshing), or to
    /// another set of participants.
    ///
    /// In case of resharing/refreshing of the secret participant shares once the
    /// DKG session has completed, a dealer can call the `reshare` method to distribute
    /// shares of their secret key to a new set of participants.
    ///
    /// # Inputs
    ///
    /// * The protocol instance [`ThresholdParameters`],
    /// * This participant's `index`,
    /// * A cryptographically secure pseudo-random generator.
    ///
    /// # Usage
    ///
    /// After a new participant is constructed, the [`participant.index`],
    /// [`participant.commitments`], [`participant.proof_of_secret_key`] and
    /// [`participant.proof_of_dh_private_key`] should be sent to every
    /// other participant in the protocol.
    ///
    /// # Returns
    ///
    /// A distributed key generation protocol [`Participant`] and that
    /// dealer's secret polynomial `coefficients` along the dealer's
    /// Diffie-Hellman private key for secret shares encryption which
    /// must be kept private.
    pub fn new_dealer(
        parameters: ThresholdParameters<C>,
        index: u32,
        mut rng: impl RngCore + CryptoRng,
    ) -> FrostResult<C, (Self, Coefficients<C>, DiffieHellmanPrivateKey<C>)> {
        let (dealer, coeff_option, dh_private_key) =
            Self::new_internal(parameters, false, index, None, &mut rng)?;
        Ok((
            dealer,
            coeff_option.expect("We always have at least an empty vector"),
            dh_private_key,
        ))
    }

    /// Construct a new signer for the distributed key generation protocol.
    ///
    /// A signer only combines shares from a previous set of dealers and
    /// computes a private signing key from it. In particular, signers do
    /// not have the ability to redistribute secret share to other participants.
    ///
    /// # Inputs
    ///
    /// * The protocol instance [`ThresholdParameters`],
    /// * This participant's `index`,
    /// * A cryptographically secure pseudo-random generator.
    ///
    /// # Usage
    ///
    /// After a new participant is constructed, the `participant.index`
    /// and [`participant.proof_of_dh_private_key`] should be sent to every
    /// other participant in the protocol.
    ///
    /// # Returns
    ///
    /// A distributed key generation protocol [`Participant`] along the
    /// signers's Diffie-Hellman private key for secret shares encryption
    /// which must be kept private.
    pub fn new_signer(
        parameters: ThresholdParameters<C>,
        index: u32,
        mut rng: impl RngCore + CryptoRng,
    ) -> FrostResult<C, (Self, DiffieHellmanPrivateKey<C>)> {
        let (signer, _coeff_option, dh_private_key) =
            Self::new_internal(parameters, true, index, None, &mut rng)?;
        Ok((signer, dh_private_key))
    }

    fn new_internal(
        parameters: ThresholdParameters<C>,
        is_signer: bool,
        index: u32,
        secret_key: Option<Scalar<C>>,
        mut rng: impl RngCore + CryptoRng,
    ) -> FrostResult<C, (Self, Option<Coefficients<C>>, DiffieHellmanPrivateKey<C>)> {
        if index == 0 {
            return Err(Error::IndexIsZero);
        }

        // Step 1: Every participant P_i samples t random values (a_{i0}, ..., a_{i(t-1)})
        //         uniformly in ZZ_q, and uses these values as coefficients to define a
        //         polynomial f_i(x) = \sum_{j=0}^{t-1} a_{ij} x^{j} of degree t-1 over
        //         ZZ_q.
        let t = parameters.t as usize;

        // Every participant samples a random pair of keys (dh_private_key, dh_public_key)
        // and generates a proof of knowledge of dh_private_key.
        // This will be used for secret shares encryption and for complaint generation.
        let dh_private_key = DiffieHellmanPrivateKey(Scalar::<C>::rand(&mut rng));
        let dh_public_key = DiffieHellmanPublicKey::new(C::G::generator().mul(dh_private_key.0));

        // Compute a proof of knowledge of dh_secret_key
        let proof_of_dh_private_key =
            NizkPokOfSecretKey::<C>::prove(index, &dh_private_key.0, &dh_public_key, &mut rng)?;

        if is_signer {
            // Signers don't need coefficients, commitments or proofs of secret key.
            Ok((
                Participant {
                    index,
                    dh_public_key,
                    commitments: None,
                    proof_of_secret_key: None,
                    proof_of_dh_private_key,
                },
                None,
                dh_private_key,
            ))
        } else {
            let mut coefficients: Vec<Scalar<C>> = Vec::with_capacity(t);
            let mut commitments = VerifiableSecretSharingCommitment {
                index,
                points: Vec::with_capacity(t),
            };

            match secret_key {
                Some(sk) => coefficients.push(sk),
                None => coefficients.push(Scalar::<C>::rand(&mut rng)),
            }

            for _ in 1..t {
                coefficients.push(Scalar::<C>::rand(&mut rng));
            }

            let coefficients = Coefficients(coefficients);

            // Step 3: Every dealer computes a public commitment
            //         C_i = [\phi_{i0}, ..., \phi_{i(t-1)}], where \phi_{ij} = g^{a_{ij}},
            //         0 ≤ j ≤ t-1.
            for j in 0..t {
                commitments
                    .points
                    .push(C::G::generator() * coefficients.0[j]);
            }

            // The steps are out of order, in order to save one scalar multiplication.

            // Step 2: Every dealer computes a proof of knowledge to the corresponding secret
            //         a_{i0} by calculating a Schnorr signature \alpha_i = (s, group_commitment).
            let proof_of_secret_key: NizkPokOfSecretKey<C> = NizkPokOfSecretKey::prove(
                index,
                &coefficients.0[0],
                commitments
                    .public_key()
                    .expect("We should always be able to retrieve a public key."),
                rng,
            )?;

            Ok((
                Participant {
                    index,
                    dh_public_key,
                    commitments: Some(commitments),
                    proof_of_secret_key: Some(proof_of_secret_key),
                    proof_of_dh_private_key,
                },
                Some(coefficients),
                dh_private_key,
            ))
        }
    }

    /// Reshare this dealer's secret key to a new set of participants.
    ///
    /// # Inputs
    ///
    /// * The *new* protocol instance [`ThresholdParameters`],
    /// * This participant's `secret_key`,
    /// * A reference to the list of new participants,
    ///
    /// # Usage
    ///
    /// After a new participant is constructed, the `participant.index`,
    /// `participant.commitments`, `participant.proof_of_secret_key` and
    /// `participant.proof_of_dh_private_key` should be sent to every other
    /// participant in the protocol along with their dedicated secret share.
    ///
    /// # Returns
    ///
    /// A distributed key generation protocol [`Participant`], a
    /// [`Vec<EncryptedSecretShare::<C>>`] to be sent to each participant
    /// of the new set accordingly.
    /// It also returns a list of the valid / misbehaving participants
    /// of the new set for handling outside of this crate.
    pub fn reshare(
        parameters: ThresholdParameters<C>,
        secret_key: &IndividualSigningKey<C>,
        signers: &[Participant<C>],
        mut rng: impl RngCore + CryptoRng,
    ) -> FrostResult<
        C,
        (
            Self,
            BTreeMap<u32, EncryptedSecretShare<C>>,
            DKGParticipantList<C>,
        ),
    > {
        let (dealer, coeff_option, dh_private_key) = Self::new_internal(
            parameters,
            false,
            secret_key.index,
            Some(secret_key.key),
            &mut rng,
        )?;

        let coefficients = coeff_option.expect("We always have at least an empty vector");

        let (participant_state, participant_lists) = DistributedKeyGeneration::new_state_internal(
            parameters,
            &dh_private_key,
            secret_key.index,
            Some(&coefficients),
            signers,
            true,
            false,
            &mut rng,
        )?;

        let encrypted_shares = participant_state.their_encrypted_secret_shares()?.clone();

        Ok((dealer, encrypted_shares, participant_lists))
    }

    /// Retrieve \\( \alpha_{i0} * B \\), where \\( B \\) is the prime-order basepoint.
    ///
    /// This is used to pass into the final call to [`DistributedKeyGeneration::<RoundTwo, C>::finish()`] .
    pub fn public_key(&self) -> Option<&C::G> {
        self.commitments.as_ref().map(|c| c.public_key())?
    }
}

impl<C: CipherSuite> PartialOrd for Participant<C> {
    fn partial_cmp(&self, other: &Participant<C>) -> Option<Ordering> {
        match self.index.cmp(&other.index) {
            Ordering::Less => Some(Ordering::Less),
            Ordering::Equal => None, // Participants cannot have the same index.
            Ordering::Greater => Some(Ordering::Greater),
        }
    }
}

impl<C: CipherSuite> PartialEq for Participant<C> {
    fn eq(&self, other: &Participant<C>) -> bool {
        self.index == other.index
    }
}
#[cfg(test)]
mod test {
    use super::*;
    use crate::testing::Secp256k1Sha256;

    use rand::rngs::OsRng;

    #[test]
    fn index_zero_is_invalid() {
        let params = ThresholdParameters::new(3, 2).unwrap();
        let rng = OsRng;

        let result = Participant::<Secp256k1Sha256>::new_dealer(params, 0, rng);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), Error::IndexIsZero);
    }
}
