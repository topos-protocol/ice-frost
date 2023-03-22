use ark_ec::CurveGroup;
use ark_ff::{Field, UniformRand};
use ark_serialize::CanonicalDeserialize;
use ark_serialize::CanonicalSerialize;

use core::cmp::Ordering;
use rand::CryptoRng;
use rand::RngCore;

use zeroize::Zeroize;

use crate::dkg::{
    rounds::{DkgState, RoundOne, RoundTwo},
    secret_share::{
        decrypt_share, encrypt_share, Coefficients, EncryptedSecretShare, SecretShare,
        VerifiableSecretSharingCommitment,
    },
    Complaint, NizkPokOfSecretKey,
};
use crate::error::Error;
use crate::keys::{
    DiffieHellmanPrivateKey, DiffieHellmanPublicKey, GroupKey, IndividualSigningKey,
};
use crate::parameters::ThresholdParameters;

use crate::utils::calculate_lagrange_coefficients;
use crate::utils::{Box, ToString, Vec};

/// A participant in a threshold signing.
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct Participant<G: CurveGroup> {
    /// The index of this participant, to keep the participants in order.
    pub index: u32,
    /// The public key used to derive symmetric keys for encrypting and
    /// decrypting shares via DH.
    pub dh_public_key: DiffieHellmanPublicKey<G>,
    /// A vector of Pedersen commitments to the coefficients of this
    /// participant's private polynomial.
    pub commitments: Option<VerifiableSecretSharingCommitment<G>>,
    /// The zero-knowledge proof of knowledge of the secret key (a.k.a. the
    /// first coefficient in the private polynomial).  It is constructed as a
    /// Schnorr signature using \\( a_{i0} \\) as the signing key.
    pub proof_of_secret_key: Option<NizkPokOfSecretKey<G>>,
    /// The zero-knowledge proof of knowledge of the DH private key.
    /// It is computed similarly to the proof_of_secret_key.
    pub proof_of_dh_private_key: NizkPokOfSecretKey<G>,
}

impl<G: CurveGroup> Participant<G> {
    /// Construct a new dealer for the distributed key generation protocol,
    /// who will generate shares for a group of signers (can be the group of dealers).
    ///
    /// In case of resharing/refreshing of the secret participant shares once the
    /// Dkg has completed, a dealer can call the `reshare` method to distribute
    /// shares of her secret key to a new set of participants.
    ///
    /// # Inputs
    ///
    /// * The protocol instance [`ThresholdParameters`],
    /// * This participant's `index`,
    /// * A context string to prevent replay attacks.
    ///
    /// # Usage
    ///
    /// After a new participant is constructed, the `participant.index`,
    /// `participant.commitments`, `participant.proof_of_secret_key` and
    /// `participant.proof_of_dh_private_key` should be sent to every
    /// other participant in the protocol.
    ///
    /// # Returns
    ///
    /// A distributed key generation protocol [`Participant`] and that
    /// dealer's secret polynomial `Coefficients` along the dealer's
    /// Diffie-Hellman private key for secret shares encryption which
    /// must be kept private.
    pub fn new_dealer(
        parameters: &ThresholdParameters<G>,
        index: u32,
        context_string: &str,
        mut rng: impl RngCore + CryptoRng,
    ) -> (Self, Coefficients<G>, DiffieHellmanPrivateKey<G>) {
        let (dealer, coeff_option, dh_private_key) =
            Self::new_internal(parameters, false, index, None, context_string, &mut rng);
        (dealer, coeff_option.unwrap(), dh_private_key)
    }

    /// Construct a new signer for the distributed key generation protocol.
    ///
    /// A signer only combines shares from a previous set of dealers and
    /// computes a private signing key from it.
    ///
    /// # Inputs
    ///
    /// * The protocol instance [`ThresholdParameters`],
    /// * This participant's `index`,
    /// * A context string to prevent replay attacks.
    ///
    /// # Usage
    ///
    /// After a new participant is constructed, the `participant.index`
    /// and `participant.proof_of_dh_private_key` should be sent to every
    /// other participant in the protocol.
    ///
    /// # Returns
    ///
    /// A distributed key generation protocol [`Participant`] along the
    /// signers's Diffie-Hellman private key for secret shares encryption
    /// which must be kept private,
    pub fn new_signer(
        parameters: &ThresholdParameters<G>,
        index: u32,
        context_string: &str,
        mut rng: impl RngCore + CryptoRng,
    ) -> (Self, DiffieHellmanPrivateKey<G>) {
        let (signer, _coeff_option, dh_private_key) =
            Self::new_internal(parameters, true, index, None, context_string, &mut rng);
        (signer, dh_private_key)
    }

    fn new_internal(
        parameters: &ThresholdParameters<G>,
        is_signer: bool,
        index: u32,
        secret_key: Option<G::ScalarField>,
        context_string: &str,
        mut rng: impl RngCore + CryptoRng,
    ) -> (Self, Option<Coefficients<G>>, DiffieHellmanPrivateKey<G>) {
        // Step 1: Every participant P_i samples t random values (a_{i0}, ..., a_{i(t-1)})
        //         uniformly in ZZ_q, and uses these values as coefficients to define a
        //         polynomial f_i(x) = \sum_{j=0}^{t-1} a_{ij} x^{j} of degree t-1 over
        //         ZZ_q.
        let t: usize = parameters.t as usize;

        // RICE-FROST: Every participant samples a random pair of keys (dh_private_key, dh_public_key)
        // and generates a proof of knowledge of dh_private_key. This will be used for secret shares
        // encryption and for complaint generation.

        let dh_private_key = DiffieHellmanPrivateKey(G::ScalarField::rand(&mut rng));
        let dh_public_key = DiffieHellmanPublicKey(G::generator().mul(dh_private_key.0));

        // Compute a proof of knowledge of dh_secret_key
        // TODO: error
        let proof_of_dh_private_key = NizkPokOfSecretKey::<G>::prove(
            index,
            &dh_private_key.0,
            &dh_public_key,
            context_string,
            &mut rng,
        )
        .unwrap();

        if is_signer {
            // Signers don't need coefficients, commitments or proofs of secret key.
            (
                Participant {
                    index,
                    dh_public_key,
                    commitments: None,
                    proof_of_secret_key: None,
                    proof_of_dh_private_key,
                },
                None,
                dh_private_key,
            )
        } else {
            let mut coefficients: Vec<G::ScalarField> = Vec::with_capacity(t);
            let mut commitments = VerifiableSecretSharingCommitment {
                index,
                points: Vec::with_capacity(t),
            };

            match secret_key {
                Some(sk) => coefficients.push(sk),
                None => coefficients.push(G::ScalarField::rand(&mut rng)),
            }

            for _ in 1..t {
                coefficients.push(G::ScalarField::rand(&mut rng));
            }

            let coefficients = Coefficients(coefficients);

            // Step 3: Every dealer computes a public commitment
            //         C_i = [\phi_{i0}, ..., \phi_{i(t-1)}], where \phi_{ij} = g^{a_{ij}},
            //         0 ≤ j ≤ t-1.
            for j in 0..t {
                commitments.points.push(G::generator() * coefficients.0[j]);
            }

            // The steps are out of order, in order to save one scalar multiplication.

            // Step 2: Every dealer computes a proof of knowledge to the corresponding secret
            //         a_{i0} by calculating a Schnorr signature \alpha_i = (s, R).  (In
            //         the FROST paper: \alpha_i = (\mu_i, c_i), but we stick with Schnorr's
            //         original notation here.)
            // TODO: error
            let proof_of_secret_key: NizkPokOfSecretKey<G> = NizkPokOfSecretKey::prove(
                index,
                &coefficients.0[0],
                commitments.public_key().unwrap(),
                context_string,
                rng,
            )
            .unwrap();

            (
                Participant {
                    index,
                    dh_public_key,
                    commitments: Some(commitments),
                    proof_of_secret_key: Some(proof_of_secret_key),
                    proof_of_dh_private_key,
                },
                Some(coefficients),
                dh_private_key,
            )
        }
    }

    /// Reshare this dealer's secret key to a new set of participants.
    ///
    /// # Inputs
    ///
    /// * The *new* protocol instance [`ThresholdParameters`],
    /// * This participant's `secret_key`,
    /// * A reference to the list of new participants,
    /// * A context string to prevent replay attacks.
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
    /// `Vec<EncryptedSecretShare::<G>>` to be sent to each participant
    /// of the new set accordingly.
    /// It also returns a list of the valid / misbehaving participants
    /// of the new set for handling outside of this crate.
    pub fn reshare(
        parameters: &ThresholdParameters<G>,
        secret_key: IndividualSigningKey<G>,
        signers: &[Participant<G>],
        context_string: &str,
        mut rng: impl RngCore + CryptoRng,
    ) -> Result<(Self, Vec<EncryptedSecretShare<G>>, DKGParticipantList<G>), Error<G>> {
        let (dealer, coeff_option, dh_private_key) = Self::new_internal(
            parameters,
            false,
            secret_key.index,
            Some(secret_key.key),
            context_string,
            &mut rng,
        );

        // Unwrapping cannot panic here
        let coefficients = coeff_option.unwrap();

        let (participant_state, participant_lists) = DistributedKeyGeneration::new_state_internal(
            parameters,
            &dh_private_key,
            &secret_key.index,
            Some(&coefficients),
            signers,
            context_string,
            true,
            false,
            &mut rng,
        )?;

        // Unwrapping cannot panic here
        let encrypted_shares = participant_state
            .their_encrypted_secret_shares()
            .unwrap()
            .clone();

        Ok((dealer, encrypted_shares, participant_lists))
    }

    /// Serialize this `Participant` to a vector of bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error<G>> {
        let mut bytes = Vec::new();

        self.serialize_compressed(&mut bytes)
            .map_err(|_| Error::SerialisationError)?;

        Ok(bytes)
    }

    /// Attempt to deserialize a `Participant` from a vector of bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error<G>> {
        Self::deserialize_compressed(bytes).map_err(|_| Error::DeserialisationError)
    }

    /// Retrieve \\( \alpha_{i0} * B \\), where \\( B \\) is the Ristretto basepoint.
    ///
    /// This is used to pass into the final call to `DistributedKeyGeneration::<RoundTwo>.finish()`.
    pub fn public_key(&self) -> Option<&G> {
        if self.commitments.is_some() {
            return self.commitments.as_ref().unwrap().public_key();
        }

        None
    }
}

impl<G: CurveGroup> PartialOrd for Participant<G> {
    fn partial_cmp(&self, other: &Participant<G>) -> Option<Ordering> {
        match self.index.cmp(&other.index) {
            Ordering::Less => Some(Ordering::Less),
            Ordering::Equal => None, // Participants cannot have the same index.
            Ordering::Greater => Some(Ordering::Greater),
        }
    }
}

impl<G: CurveGroup> PartialEq for Participant<G> {
    fn eq(&self, other: &Participant<G>) -> bool {
        self.index == other.index
    }
}

/// State machine structures for holding intermediate values during a
/// distributed key generation protocol run, to prevent misuse.
#[derive(Clone, Debug)]
pub struct DistributedKeyGeneration<S: DkgState, G: CurveGroup> {
    state: Box<ActualState<G>>,
    data: S,
}

/// Shared state which occurs across all rounds of a threshold signing protocol run.
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
struct ActualState<G: CurveGroup> {
    /// The parameters for this instantiation of a threshold signature.
    parameters: ThresholdParameters<G>,
    /// The index of the participant.
    index: u32,
    /// The DH private key for deriving a symmetric key to encrypt and decrypt
    /// secret shares.
    dh_private_key: DiffieHellmanPrivateKey<G>,
    /// The DH public key for deriving a symmetric key to encrypt and decrypt
    /// secret shares.
    dh_public_key: DiffieHellmanPublicKey<G>,
    /// A vector of tuples containing the index of each participant and that
    /// respective participant's commitments to their private polynomial
    /// coefficients.
    their_commitments: Option<Vec<VerifiableSecretSharingCommitment<G>>>,
    /// A vector of ECPoints containing the index of each participant and that
    /// respective participant's DH public key.
    their_dh_public_keys: Vec<(u32, DiffieHellmanPublicKey<G>)>,
    /// The encrypted secret shares this participant has calculated for all the other participants.
    their_encrypted_secret_shares: Option<Vec<EncryptedSecretShare<G>>>,
    /// The secret shares this participant has received from all the other participants.
    my_secret_shares: Option<Vec<SecretShare<G>>>,
}

/// Output of the first round of the Distributed Key Generation.
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct DKGParticipantList<G: CurveGroup> {
    /// List of the valid participants to be used in RoundTwo
    pub valid_participants: Vec<Participant<G>>,
    /// List of the invalid participants that have been removed
    pub misbehaving_participants: Option<Vec<u32>>,
}

impl<G: CurveGroup> DistributedKeyGeneration<RoundOne, G> {
    /// Check the zero-knowledge proofs of knowledge of secret keys of all the
    /// other participants. When no group key has been computed by a group of
    /// participants yet, this method should be called rather than
    /// `DistributedKeyGeneration<RoundOne, G>::new()`.
    ///
    /// # Note
    ///
    /// The `participants` will be sorted by their indices.
    ///
    /// # Returns
    ///
    /// An updated state machine for the distributed key generation protocol if
    /// all of the zero-knowledge proofs verified successfully, otherwise a
    /// vector of participants whose zero-knowledge proofs were incorrect.
    pub fn new_initial(
        parameters: &ThresholdParameters<G>,
        dh_private_key: &DiffieHellmanPrivateKey<G>,
        my_index: &u32,
        my_coefficients: &Coefficients<G>,
        participants: &[Participant<G>],
        context_string: &str,
        mut rng: impl RngCore + CryptoRng,
    ) -> Result<(Self, DKGParticipantList<G>), Error<G>> {
        Self::new_state_internal(
            parameters,
            dh_private_key,
            my_index,
            Some(my_coefficients),
            participants,
            context_string,
            true,
            true,
            &mut rng,
        )
    }

    /// Check the zero-knowledge proofs of knowledge of secret keys of all the
    /// other participants. When a group key already exists and dealers have
    /// distributed secret shares to a new set, participants of this new set
    /// should call this method.
    ///
    /// # Note
    ///
    /// The `participants` will be sorted by their indices.
    ///
    /// # Returns
    ///
    /// An updated state machine for the distributed key generation protocol if
    /// all of the zero-knowledge proofs verified successfully, otherwise a
    /// vector of participants whose zero-knowledge proofs were incorrect.
    pub fn new(
        parameters: &ThresholdParameters<G>,
        dh_private_key: &DiffieHellmanPrivateKey<G>,
        my_index: &u32,
        dealers: &[Participant<G>],
        context_string: &str,
        mut rng: impl RngCore + CryptoRng,
    ) -> Result<(Self, DKGParticipantList<G>), Error<G>> {
        Self::new_state_internal(
            parameters,
            dh_private_key,
            my_index,
            None,
            dealers,
            context_string,
            false,
            true,
            &mut rng,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn new_state_internal(
        parameters: &ThresholdParameters<G>,
        dh_private_key: &DiffieHellmanPrivateKey<G>,
        my_index: &u32,
        my_coefficients: Option<&Coefficients<G>>,
        participants: &[Participant<G>],
        context_string: &str,
        from_dealer: bool,
        from_signer: bool,
        mut rng: impl RngCore + CryptoRng,
    ) -> Result<(Self, DKGParticipantList<G>), Error<G>> {
        let mut their_commitments: Vec<VerifiableSecretSharingCommitment<G>> =
            Vec::with_capacity(parameters.t as usize);
        let mut their_dh_public_keys: Vec<(u32, DiffieHellmanPublicKey<G>)> =
            Vec::with_capacity(parameters.t as usize);
        let mut valid_participants: Vec<Participant<G>> = Vec::with_capacity(parameters.n as usize);
        let mut misbehaving_participants: Vec<u32> = Vec::new();

        let dh_public_key = DiffieHellmanPublicKey(G::generator().mul(dh_private_key.0));

        // Bail if we didn't get enough participants.
        if participants.len() != parameters.n as usize {
            return Err(Error::InvalidNumberOfParticipants(
                participants.len(),
                parameters.n,
            ));
        }

        // Check the public keys and the DH keys of the participants.
        for p in participants.iter() {
            // Always check the DH keys of the participants
            match p
                .proof_of_dh_private_key
                .verify(p.index, &p.dh_public_key, context_string)
            {
                Ok(_) => {
                    // Signers additionally check the public keys of the signers
                    if from_signer {
                        let public_key = match p.public_key() {
                            Some(key) => key,
                            None => {
                                misbehaving_participants.push(p.index);
                                continue;
                            }
                        };
                        match p.proof_of_secret_key.as_ref().unwrap().verify(
                            p.index,
                            public_key,
                            context_string,
                        ) {
                            Ok(_) => {
                                valid_participants.push(p.clone());
                                their_commitments.push(p.commitments.as_ref().unwrap().clone());
                                their_dh_public_keys.push((p.index, p.dh_public_key.clone()));
                            }
                            Err(_) => misbehaving_participants.push(p.index),
                        }
                    } else {
                        valid_participants.push(p.clone());
                        their_dh_public_keys.push((p.index, p.dh_public_key.clone()));
                    }
                }
                Err(_) => misbehaving_participants.push(p.index),
            }
        }

        // [DIFFERENT_TO_PAPER] If too many participants were misbehaving, return an error along their indices.
        if valid_participants.len() < parameters.t as usize {
            return Err(Error::TooManyInvalidParticipants(misbehaving_participants));
        }

        if !from_dealer && from_signer {
            let state = ActualState {
                parameters: *parameters,
                index: *my_index,
                dh_private_key: dh_private_key.clone(),
                dh_public_key,
                their_commitments: Some(their_commitments),
                their_dh_public_keys,
                their_encrypted_secret_shares: None,
                my_secret_shares: None,
            };

            return Ok((
                DistributedKeyGeneration::<RoundOne, G> {
                    state: Box::new(state),
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

        // [DIFFERENT_TO_PAPER] We pre-calculate the secret shares from Round 2
        // Step 1 here since it doesn't require additional online activity.
        // RICE-FROST: We also encrypt them into their_encrypted_secret_shares.
        //
        // Round 2
        // Step 1: Each P_i securely sends to each other participant P_l a secret share
        //         (l, f_i(l)) and keeps (i, f_i(i)) for themselves.
        let mut their_encrypted_secret_shares: Vec<EncryptedSecretShare<G>> =
            Vec::with_capacity(parameters.n as usize - 1);

        for p in participants.iter() {
            let share =
                SecretShare::<G>::evaluate_polynomial(my_index, &p.index, my_coefficients.unwrap());

            let dh_key = p.dh_public_key.0 * dh_private_key.0;
            let mut dh_key_bytes = Vec::new();
            dh_key
                .serialize_compressed(&mut dh_key_bytes)
                .map_err(|_| Error::PointCompressionError)?;

            their_encrypted_secret_shares.push(encrypt_share(&share, &dh_key_bytes[..], &mut rng));
        }

        let state = ActualState {
            parameters: *parameters,
            index: *my_index,
            dh_private_key: dh_private_key.clone(),
            dh_public_key,
            their_commitments: if !from_signer {
                None
            } else {
                Some(their_commitments)
            },
            their_dh_public_keys,
            their_encrypted_secret_shares: Some(their_encrypted_secret_shares),
            my_secret_shares: None,
        };

        Ok((
            DistributedKeyGeneration::<RoundOne, G> {
                state: Box::new(state),
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
    /// at the end of `DistributedKeyGeneration::<RoundOne, G>`.
    pub fn their_encrypted_secret_shares(&self) -> Result<&Vec<EncryptedSecretShare<G>>, Error<G>> {
        self.state
            .their_encrypted_secret_shares
            .as_ref()
            .ok_or(Error::NoEncryptedShares)
    }

    /// Progress to round two of the Dkg protocol once we have sent each encrypted share
    /// from `DistributedKeyGeneration::<RoundOne, G>.their_encrypted_secret_shares()` to its
    /// respective other participant, and collected our shares from the other
    /// participants in turn.
    #[allow(clippy::wrong_self_convention)]
    pub fn to_round_two(
        mut self,
        my_encrypted_secret_shares: Vec<EncryptedSecretShare<G>>,
        mut rng: impl RngCore + CryptoRng,
    ) -> Result<DistributedKeyGeneration<RoundTwo, G>, Error<G>> {
        // Sanity check
        assert_eq!(self.data, RoundOne {});

        // Zero out the other participants encrypted secret shares from memory.
        if self.state.their_encrypted_secret_shares.is_some() {
            self.state.their_encrypted_secret_shares = None;
        }

        // RICE-FROST

        let mut complaints: Vec<Complaint<G>> = Vec::new();

        if my_encrypted_secret_shares.len() != self.state.parameters.n as usize {
            return Err(Error::MissingShares);
        }

        let mut my_secret_shares: Vec<SecretShare<G>> = Vec::new();

        // Step 2.1: Each P_i decrypts their shares with
        //           key k_il = pk_l^sk_i
        for encrypted_share in my_encrypted_secret_shares.iter() {
            for pk in self.state.their_dh_public_keys.iter() {
                if pk.0 == encrypted_share.sender_index {
                    let dh_shared_key = *pk.1 * self.state.dh_private_key.0;
                    let mut dh_key_bytes = Vec::new();
                    dh_shared_key
                        .serialize_compressed(&mut dh_key_bytes)
                        .map_err(|_| Error::PointCompressionError)?;

                    // Step 2.2: Each share is verified by calculating:
                    //           g^{f_l(i)} ?= \Prod_{k=0}^{t-1} \phi_{lk}^{i^{k} mod q},
                    //           creating a complaint if the check fails.
                    let decrypted_share = decrypt_share(encrypted_share, &dh_key_bytes);
                    let decrypted_share_ref = &decrypted_share;

                    for commitment in self.state.their_commitments.as_ref().unwrap().iter() {
                        if commitment.index == encrypted_share.sender_index {
                            // If the decrypted share is incorrect, P_i builds
                            // a complaint

                            if decrypted_share.is_err()
                                || decrypted_share_ref
                                    .as_ref()
                                    .unwrap()
                                    .verify(commitment)
                                    .is_err()
                            {
                                complaints.push(Complaint::<G>::new(
                                    encrypted_share.receiver_index,
                                    encrypted_share.sender_index,
                                    &pk.1,
                                    &self.state.dh_private_key.0,
                                    &self.state.dh_public_key.0,
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
                }
            }
        }

        if !complaints.is_empty() {
            return Err(Error::Complaint(complaints));
        }

        self.state.my_secret_shares = Some(my_secret_shares);

        Ok(DistributedKeyGeneration::<RoundTwo, G> {
            state: self.state,
            data: RoundTwo {},
        })
    }
}

impl<G: CurveGroup> DistributedKeyGeneration<RoundTwo, G> {
    /// Calculate this threshold signing protocol participant's long-lived
    /// secret signing keyshare and the group's public verification key.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let (group_key, secret_key) = state.finish()?;
    /// ```
    pub fn finish(mut self) -> Result<(GroupKey<G>, IndividualSigningKey<G>), Error<G>> {
        let secret_key = self.calculate_signing_key()?;
        let group_key = self.calculate_group_key()?;

        self.state.my_secret_shares.zeroize();

        Ok((group_key, secret_key))
    }

    /// Calculate this threshold signing participant's long-lived secret signing
    /// key by interpolating all of the polynomial evaluations from the other
    /// participants.
    pub(crate) fn calculate_signing_key(&self) -> Result<IndividualSigningKey<G>, Error<G>> {
        let my_secret_shares = self.state.my_secret_shares.as_ref().ok_or_else(|| {
            Error::Custom("Could not retrieve participant's secret shares".to_string())
        })?;

        let mut index_vector: Vec<u32> = Vec::new();

        for share in my_secret_shares.iter() {
            index_vector.push(share.sender_index);
        }

        let mut key = G::ScalarField::ZERO;

        for share in my_secret_shares.iter() {
            let coeff =
                match calculate_lagrange_coefficients::<G>(share.sender_index, &index_vector) {
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
    /// A [`GroupKey`] for the set of participants.
    ///
    /// my_commitment is needed for now, but won't be when the distinction
    /// dealers/signers is implemented.
    pub(crate) fn calculate_group_key(&self) -> Result<GroupKey<G>, Error<G>> {
        let mut index_vector: Vec<u32> = Vec::new();

        for commitment in self.state.their_commitments.as_ref().unwrap().iter() {
            index_vector.push(commitment.index);
        }

        let mut group_key = G::zero();

        // The group key is the interpolation at 0 of all index 0 of the dealers' commitments.
        for commitment in self.state.their_commitments.as_ref().unwrap().iter() {
            let coeff = match calculate_lagrange_coefficients::<G>(commitment.index, &index_vector)
            {
                Ok(s) => s,
                Err(error) => return Err(Error::Custom(error.to_string())),
            };

            group_key += commitment.public_key().unwrap().mul(coeff);
        }

        Ok(GroupKey(group_key))
    }

    /// Every participant can verify a complaint and determine who is the malicious
    /// party. The relevant encrypted share is assumed to exist and publicly retrievable
    /// by any participant.
    pub fn blame(
        &self,
        encrypted_share: &EncryptedSecretShare<G>,
        complaint: &Complaint<G>,
    ) -> u32 {
        let mut pk_maker = G::zero();
        let mut pk_accused = G::zero();
        let mut commitment_accused = VerifiableSecretSharingCommitment {
            index: 0,
            points: Vec::new(),
        };

        for commitment in self.state.their_commitments.as_ref().unwrap().iter() {
            if commitment.index == complaint.accused_index {
                commitment_accused = commitment.clone();
            }
        }

        if commitment_accused.points.is_empty() {
            return complaint.maker_index;
        }

        for (index, pk) in self.state.their_dh_public_keys.iter() {
            if index == &complaint.maker_index {
                pk_maker = **pk;
            } else if index == &complaint.accused_index {
                pk_accused = **pk;
            }
        }

        if pk_maker == G::zero() || pk_accused == G::zero() {
            return complaint.maker_index;
        }

        if complaint.verify(&pk_maker, &pk_accused).is_err() {
            return complaint.maker_index;
        }

        let mut dh_key_bytes = Vec::new();
        if complaint
            .dh_shared_key
            .serialize_compressed(&mut dh_key_bytes)
            .is_err()
        {
            return complaint.maker_index;
        };

        let share = decrypt_share(encrypted_share, &dh_key_bytes[..]);
        if share.is_err() {
            return complaint.accused_index;
        }
        match share.unwrap().verify(&commitment_accused) {
            Ok(()) => complaint.maker_index,
            Err(_) => complaint.accused_index,
        }
    }
}

#[cfg(test)]
mod test {
    use core::ops::Mul;

    use super::*;
    use crate::keys::IndividualVerifyingKey;

    use ark_bn254::{Fr, G1Projective};
    use ark_ec::Group;

    use rand::rngs::OsRng;
    use rand::Rng;

    #[test]
    fn nizk_of_secret_key() {
        let params = ThresholdParameters::new(3, 2);
        let mut rng = OsRng;

        let (p, _, _) = Participant::<G1Projective>::new_dealer(&params, 0, "Φ", &mut rng);
        let result =
            p.proof_of_secret_key
                .as_ref()
                .unwrap()
                .verify(p.index, p.public_key().unwrap(), "Φ");

        assert!(result.is_ok());
    }

    #[test]
    fn secret_share_from_one_coefficients() {
        let mut coeffs: Vec<Fr> = Vec::new();

        for _ in 0..5 {
            coeffs.push(Fr::ONE);
        }

        let coefficients = Coefficients::<G1Projective>(coeffs);
        let share = SecretShare::<G1Projective>::evaluate_polynomial(&1, &1, &coefficients);

        assert!(share.polynomial_evaluation == Fr::from(5u8));

        let mut commitments = VerifiableSecretSharingCommitment {
            index: 1,
            points: Vec::new(),
        };

        for i in 0..5 {
            commitments
                .points
                .push(G1Projective::generator() * coefficients.0[i]);
        }

        assert!(share.verify(&commitments).is_ok());
    }

    #[test]
    fn secret_share_participant_index_zero() {
        let mut coeffs: Vec<Fr> = Vec::new();

        for _ in 0..5 {
            coeffs.push(Fr::ONE);
        }

        let coefficients = Coefficients(coeffs);
        let share = SecretShare::evaluate_polynomial(&1, &0, &coefficients);

        assert!(share.polynomial_evaluation == Fr::ONE);

        let mut commitments = VerifiableSecretSharingCommitment {
            index: 1,
            points: Vec::new(),
        };

        for i in 0..5 {
            commitments
                .points
                .push(G1Projective::generator() * coefficients.0[i]);
        }

        assert!(share.verify(&commitments).is_ok());
    }

    #[test]
    fn single_party_keygen() {
        let params = ThresholdParameters::new(1, 1);
        let mut rng = OsRng;

        let (p1, p1coeffs, p1_dh_sk) =
            Participant::<G1Projective>::new_dealer(&params, 1, "Φ", &mut rng);

        p1.proof_of_secret_key
            .as_ref()
            .unwrap()
            .verify(p1.index, p1.public_key().unwrap(), "Φ")
            .unwrap();

        let participants: Vec<Participant<G1Projective>> = vec![p1.clone()];
        let (p1_state, _participant_lists) =
            DistributedKeyGeneration::<RoundOne, G1Projective>::new_initial(
                &params,
                &p1_dh_sk,
                &p1.index,
                &p1coeffs,
                &participants,
                "Φ",
                &mut rng,
            )
            .unwrap();
        let p1_my_encrypted_secret_shares =
            p1_state.their_encrypted_secret_shares().unwrap().clone();
        let p1_state = p1_state
            .to_round_two(p1_my_encrypted_secret_shares, &mut rng)
            .unwrap();
        let result = p1_state.finish();

        assert!(result.is_ok());

        let (p1_group_key, p1_secret_key) = result.unwrap();

        assert!(
            p1_group_key.0.into_affine()
                == G1Projective::generator()
                    .mul(p1_secret_key.key)
                    .into_affine()
        );
    }

    #[test]
    fn keygen_3_out_of_5() {
        let params = ThresholdParameters::<G1Projective>::new(5, 3);
        let mut rng = OsRng;

        let (p1, p1coeffs, p1_dh_sk) =
            Participant::<G1Projective>::new_dealer(&params, 1, "Φ", &mut rng);
        let (p2, p2coeffs, p2_dh_sk) =
            Participant::<G1Projective>::new_dealer(&params, 2, "Φ", &mut rng);
        let (p3, p3coeffs, p3_dh_sk) =
            Participant::<G1Projective>::new_dealer(&params, 3, "Φ", &mut rng);
        let (p4, p4coeffs, p4_dh_sk) =
            Participant::<G1Projective>::new_dealer(&params, 4, "Φ", &mut rng);
        let (p5, p5coeffs, p5_dh_sk) =
            Participant::<G1Projective>::new_dealer(&params, 5, "Φ", &mut rng);

        p1.proof_of_secret_key
            .as_ref()
            .unwrap()
            .verify(p1.index, p1.public_key().unwrap(), "Φ")
            .unwrap();
        p2.proof_of_secret_key
            .as_ref()
            .unwrap()
            .verify(p2.index, p2.public_key().unwrap(), "Φ")
            .unwrap();
        p3.proof_of_secret_key
            .as_ref()
            .unwrap()
            .verify(p3.index, p3.public_key().unwrap(), "Φ")
            .unwrap();
        p4.proof_of_secret_key
            .as_ref()
            .unwrap()
            .verify(p4.index, p4.public_key().unwrap(), "Φ")
            .unwrap();
        p5.proof_of_secret_key
            .as_ref()
            .unwrap()
            .verify(p5.index, p5.public_key().unwrap(), "Φ")
            .unwrap();

        let participants: Vec<Participant<G1Projective>> =
            vec![p1.clone(), p2.clone(), p3.clone(), p4.clone(), p5.clone()];
        let (p1_state, _participant_lists) =
            DistributedKeyGeneration::<RoundOne, G1Projective>::new_initial(
                &params,
                &p1_dh_sk,
                &p1.index,
                &p1coeffs,
                &participants,
                "Φ",
                &mut rng,
            )
            .unwrap();
        let p1_their_encrypted_secret_shares = p1_state.their_encrypted_secret_shares().unwrap();

        let (p2_state, _participant_lists) =
            DistributedKeyGeneration::<RoundOne, G1Projective>::new_initial(
                &params,
                &p2_dh_sk,
                &p2.index,
                &p2coeffs,
                &participants,
                "Φ",
                &mut rng,
            )
            .unwrap();
        let p2_their_encrypted_secret_shares = p2_state.their_encrypted_secret_shares().unwrap();

        let (p3_state, _participant_lists) =
            DistributedKeyGeneration::<RoundOne, G1Projective>::new_initial(
                &params,
                &p3_dh_sk,
                &p3.index,
                &p3coeffs,
                &participants,
                "Φ",
                &mut rng,
            )
            .unwrap();
        let p3_their_encrypted_secret_shares = p3_state.their_encrypted_secret_shares().unwrap();

        let (p4_state, _participant_lists) =
            DistributedKeyGeneration::<RoundOne, G1Projective>::new_initial(
                &params,
                &p4_dh_sk,
                &p4.index,
                &p4coeffs,
                &participants,
                "Φ",
                &mut rng,
            )
            .unwrap();
        let p4_their_encrypted_secret_shares = p4_state.their_encrypted_secret_shares().unwrap();

        let (p5_state, _participant_lists) =
            DistributedKeyGeneration::<RoundOne, G1Projective>::new_initial(
                &params,
                &p5_dh_sk,
                &p5.index,
                &p5coeffs,
                &participants,
                "Φ",
                &mut rng,
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
            .to_round_two(p1_my_encrypted_secret_shares, &mut rng)
            .unwrap();
        let p2_state = p2_state
            .to_round_two(p2_my_encrypted_secret_shares, &mut rng)
            .unwrap();
        let p3_state = p3_state
            .to_round_two(p3_my_encrypted_secret_shares, &mut rng)
            .unwrap();
        let p4_state = p4_state
            .to_round_two(p4_my_encrypted_secret_shares, &mut rng)
            .unwrap();
        let p5_state = p5_state
            .to_round_two(p5_my_encrypted_secret_shares, &mut rng)
            .unwrap();

        let (p1_group_key, p1_secret_key) = p1_state.finish().unwrap();
        let (p2_group_key, p2_secret_key) = p2_state.finish().unwrap();
        let (p3_group_key, p3_secret_key) = p3_state.finish().unwrap();
        let (p4_group_key, p4_secret_key) = p4_state.finish().unwrap();
        let (p5_group_key, p5_secret_key) = p5_state.finish().unwrap();

        assert!(p1_group_key.0.into_affine() == p2_group_key.0.into_affine());
        assert!(p2_group_key.0.into_affine() == p3_group_key.0.into_affine());
        assert!(p3_group_key.0.into_affine() == p4_group_key.0.into_affine());
        assert!(p4_group_key.0.into_affine() == p5_group_key.0.into_affine());

        let mut group_secret_key = Fr::ZERO;
        let indices = [1, 2, 3, 4, 5];

        group_secret_key += calculate_lagrange_coefficients::<G1Projective>(1, &indices).unwrap()
            * p1_secret_key.key;
        group_secret_key += calculate_lagrange_coefficients::<G1Projective>(2, &indices).unwrap()
            * p2_secret_key.key;
        group_secret_key += calculate_lagrange_coefficients::<G1Projective>(3, &indices).unwrap()
            * p3_secret_key.key;
        group_secret_key += calculate_lagrange_coefficients::<G1Projective>(4, &indices).unwrap()
            * p4_secret_key.key;
        group_secret_key += calculate_lagrange_coefficients::<G1Projective>(5, &indices).unwrap()
            * p5_secret_key.key;

        let group_key = G1Projective::generator().mul(group_secret_key);

        assert!(p5_group_key.0.into_affine() == group_key.into_affine())
    }

    #[test]
    fn keygen_2_out_of_3() {
        fn do_test() -> Result<(), ()> {
            let params = ThresholdParameters::new(3, 2);
            let mut rng = OsRng;

            let (p1, p1coeffs, p1_dh_sk) =
                Participant::<G1Projective>::new_dealer(&params, 1, "Φ", &mut rng);
            let (p2, p2coeffs, p2_dh_sk) =
                Participant::<G1Projective>::new_dealer(&params, 2, "Φ", &mut rng);
            let (p3, p3coeffs, p3_dh_sk) =
                Participant::<G1Projective>::new_dealer(&params, 3, "Φ", &mut rng);

            p1.proof_of_secret_key
                .as_ref()
                .unwrap()
                .verify(p1.index, p1.public_key().unwrap(), "Φ")
                .or(Err(()))?;
            p2.proof_of_secret_key
                .as_ref()
                .unwrap()
                .verify(p2.index, p2.public_key().unwrap(), "Φ")
                .or(Err(()))?;
            p3.proof_of_secret_key
                .as_ref()
                .unwrap()
                .verify(p3.index, p3.public_key().unwrap(), "Φ")
                .or(Err(()))?;

            let participants: Vec<Participant<G1Projective>> =
                vec![p1.clone(), p2.clone(), p3.clone()];
            let (p1_state, _participant_lists) =
                DistributedKeyGeneration::<RoundOne, G1Projective>::new_initial(
                    &params,
                    &p1_dh_sk,
                    &p1.index,
                    &p1coeffs,
                    &participants,
                    "Φ",
                    &mut rng,
                )
                .or(Err(()))?;
            let p1_their_encrypted_secret_shares =
                p1_state.their_encrypted_secret_shares().or(Err(()))?;

            let (p2_state, _participant_lists) =
                DistributedKeyGeneration::<RoundOne, G1Projective>::new_initial(
                    &params,
                    &p2_dh_sk,
                    &p2.index,
                    &p2coeffs,
                    &participants,
                    "Φ",
                    &mut rng,
                )
                .or(Err(()))?;
            let p2_their_encrypted_secret_shares =
                p2_state.their_encrypted_secret_shares().or(Err(()))?;

            let (p3_state, _participant_lists) =
                DistributedKeyGeneration::<RoundOne, G1Projective>::new_initial(
                    &params,
                    &p3_dh_sk,
                    &p3.index,
                    &p3coeffs,
                    &participants,
                    "Φ",
                    &mut rng,
                )
                .or(Err(()))?;
            let p3_their_encrypted_secret_shares =
                p3_state.their_encrypted_secret_shares().or(Err(()))?;

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

            let p1_state = p1_state
                .to_round_two(p1_my_encrypted_secret_shares, &mut rng)
                .or(Err(()))?;
            let p2_state = p2_state
                .to_round_two(p2_my_encrypted_secret_shares, &mut rng)
                .or(Err(()))?;
            let p3_state = p3_state
                .to_round_two(p3_my_encrypted_secret_shares, &mut rng)
                .or(Err(()))?;

            let (p1_group_key, _p1_secret_key) = p1_state.finish().or(Err(()))?;
            let (p2_group_key, _p2_secret_key) = p2_state.finish().or(Err(()))?;
            let (p3_group_key, _p3_secret_key) = p3_state.finish().or(Err(()))?;

            assert!(p1_group_key.0.into_affine() == p2_group_key.0.into_affine());
            assert!(p2_group_key.0.into_affine() == p3_group_key.0.into_affine());

            Ok(())
        }
        assert!(do_test().is_ok());
    }

    #[test]
    fn keygen_static_2_out_of_3_with_common_participants() {
        fn do_test() -> Result<(), ()> {
            let params = ThresholdParameters::new(3, 2);
            let mut rng = OsRng;

            let (dealer1, dealer1coeffs, dealer1_dh_sk) =
                Participant::<G1Projective>::new_dealer(&params, 1, "Φ", &mut rng);
            let (dealer2, dealer2coeffs, dealer2_dh_sk) =
                Participant::<G1Projective>::new_dealer(&params, 2, "Φ", &mut rng);
            let (dealer3, dealer3coeffs, dealer3_dh_sk) =
                Participant::<G1Projective>::new_dealer(&params, 3, "Φ", &mut rng);

            dealer1
                .proof_of_secret_key
                .as_ref()
                .unwrap()
                .verify(dealer1.index, dealer1.public_key().unwrap(), "Φ")
                .or(Err(()))?;
            dealer2
                .proof_of_secret_key
                .as_ref()
                .unwrap()
                .verify(dealer2.index, dealer2.public_key().unwrap(), "Φ")
                .or(Err(()))?;
            dealer3
                .proof_of_secret_key
                .as_ref()
                .unwrap()
                .verify(dealer3.index, dealer3.public_key().unwrap(), "Φ")
                .or(Err(()))?;

            let dealers: Vec<Participant<G1Projective>> =
                vec![dealer1.clone(), dealer2.clone(), dealer3.clone()];
            let (dealer1_state, _participant_lists) =
                DistributedKeyGeneration::<RoundOne, G1Projective>::new_initial(
                    &params,
                    &dealer1_dh_sk,
                    &dealer1.index,
                    &dealer1coeffs,
                    &dealers,
                    "Φ",
                    &mut rng,
                )
                .or(Err(()))?;
            let dealer1_their_encrypted_secret_shares =
                dealer1_state.their_encrypted_secret_shares().or(Err(()))?;

            let (dealer2_state, _participant_lists) =
                DistributedKeyGeneration::<RoundOne, G1Projective>::new_initial(
                    &params,
                    &dealer2_dh_sk,
                    &dealer2.index,
                    &dealer2coeffs,
                    &dealers,
                    "Φ",
                    &mut rng,
                )
                .or(Err(()))?;
            let dealer2_their_encrypted_secret_shares =
                dealer2_state.their_encrypted_secret_shares().or(Err(()))?;

            let (dealer3_state, _participant_lists) =
                DistributedKeyGeneration::<RoundOne, G1Projective>::new_initial(
                    &params,
                    &dealer3_dh_sk,
                    &dealer3.index,
                    &dealer3coeffs,
                    &dealers,
                    "Φ",
                    &mut rng,
                )
                .or(Err(()))?;
            let dealer3_their_encrypted_secret_shares =
                dealer3_state.their_encrypted_secret_shares().or(Err(()))?;

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

            let dealer1_state = dealer1_state
                .to_round_two(dealer1_my_encrypted_secret_shares, &mut rng)
                .or(Err(()))?;
            let dealer2_state = dealer2_state
                .to_round_two(dealer2_my_encrypted_secret_shares, &mut rng)
                .or(Err(()))?;
            let dealer3_state = dealer3_state
                .to_round_two(dealer3_my_encrypted_secret_shares, &mut rng)
                .or(Err(()))?;

            let (dealer1_group_key, dealer1_secret_key) = dealer1_state.finish().or(Err(()))?;
            let (dealer2_group_key, dealer2_secret_key) = dealer2_state.finish().or(Err(()))?;
            let (dealer3_group_key, dealer3_secret_key) = dealer3_state.finish().or(Err(()))?;

            assert!(dealer1_group_key.0.into_affine() == dealer2_group_key.0.into_affine());
            assert!(dealer2_group_key.0.into_affine() == dealer3_group_key.0.into_affine());

            let (signer1, signer1_dh_sk) = Participant::new_signer(&params, 1, "Φ", &mut rng);
            let (signer2, signer2_dh_sk) = Participant::new_signer(&params, 2, "Φ", &mut rng);
            // Dealer 3 is also a participant of the next set of signers
            let (signer3, signer3_dh_sk) = (dealer3.clone(), dealer3_dh_sk);

            let signers: Vec<Participant<G1Projective>> =
                vec![signer1.clone(), signer2.clone(), signer3.clone()];

            let (dealer1_for_signers, dealer1_encrypted_shares_for_signers, _participant_lists) =
                Participant::reshare(&params, dealer1_secret_key, &signers, "Φ", &mut rng)
                    .map_err(|_| ())?;
            let (dealer2_for_signers, dealer2_encrypted_shares_for_signers, _participant_lists) =
                Participant::reshare(&params, dealer2_secret_key, &signers, "Φ", &mut rng)
                    .map_err(|_| ())?;
            let (dealer3_for_signers, dealer3_encrypted_shares_for_signers, _participant_lists) =
                Participant::reshare(&params, dealer3_secret_key, &signers, "Φ", &mut rng)
                    .map_err(|_| ())?;

            let dealers: Vec<Participant<G1Projective>> = vec![
                dealer1_for_signers,
                dealer2_for_signers,
                dealer3_for_signers,
            ];
            let (signer1_state, _participant_lists) =
                DistributedKeyGeneration::<RoundOne, G1Projective>::new(
                    &params,
                    &signer1_dh_sk,
                    &signer1.index,
                    &dealers,
                    "Φ",
                    &mut rng,
                )
                .or(Err(()))?;

            let (signer2_state, _participant_lists) =
                DistributedKeyGeneration::<RoundOne, G1Projective>::new(
                    &params,
                    &signer2_dh_sk,
                    &signer2.index,
                    &dealers,
                    "Φ",
                    &mut rng,
                )
                .or(Err(()))?;

            let (signer3_state, _participant_lists) =
                DistributedKeyGeneration::<RoundOne, G1Projective>::new(
                    &params,
                    &signer3_dh_sk,
                    &signer3.index,
                    &dealers,
                    "Φ",
                    &mut rng,
                )
                .or(Err(()))?;

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

            let signer1_state = signer1_state
                .to_round_two(signer1_my_encrypted_secret_shares, &mut rng)
                .or(Err(()))?;
            let signer2_state = signer2_state
                .to_round_two(signer2_my_encrypted_secret_shares, &mut rng)
                .or(Err(()))?;
            let signer3_state = signer3_state
                .to_round_two(signer3_my_encrypted_secret_shares, &mut rng)
                .or(Err(()))?;

            let (signer1_group_key, _signer1_secret_key) = signer1_state.finish().or(Err(()))?;
            let (signer2_group_key, _signer2_secret_key) = signer2_state.finish().or(Err(()))?;
            let (signer3_group_key, _signer3_secret_key) = signer3_state.finish().or(Err(()))?;

            assert!(signer1_group_key.0.into_affine() == signer2_group_key.0.into_affine());
            assert!(signer2_group_key.0.into_affine() == signer3_group_key.0.into_affine());

            assert!(signer1_group_key.0.into_affine() == dealer1_group_key.0.into_affine());

            Ok(())
        }
        assert!(do_test().is_ok());
    }

    #[test]
    fn keygen_static_2_out_of_3_into_3_out_of_5() {
        fn do_test() -> Result<(), ()> {
            let params_dealers = ThresholdParameters::new(3, 2);
            let mut rng = OsRng;

            let (dealer1, dealer1coeffs, dealer1_dh_sk) =
                Participant::<G1Projective>::new_dealer(&params_dealers, 1, "Φ", &mut rng);
            let (dealer2, dealer2coeffs, dealer2_dh_sk) =
                Participant::<G1Projective>::new_dealer(&params_dealers, 2, "Φ", &mut rng);
            let (dealer3, dealer3coeffs, dealer3_dh_sk) =
                Participant::<G1Projective>::new_dealer(&params_dealers, 3, "Φ", &mut rng);

            dealer1
                .proof_of_secret_key
                .as_ref()
                .unwrap()
                .verify(dealer1.index, dealer1.public_key().unwrap(), "Φ")
                .or(Err(()))?;
            dealer2
                .proof_of_secret_key
                .as_ref()
                .unwrap()
                .verify(dealer2.index, dealer2.public_key().unwrap(), "Φ")
                .or(Err(()))?;
            dealer3
                .proof_of_secret_key
                .as_ref()
                .unwrap()
                .verify(dealer3.index, dealer3.public_key().unwrap(), "Φ")
                .or(Err(()))?;

            let dealers: Vec<Participant<G1Projective>> =
                vec![dealer1.clone(), dealer2.clone(), dealer3.clone()];
            let (dealer1_state, _participant_lists) =
                DistributedKeyGeneration::<RoundOne, G1Projective>::new_initial(
                    &params_dealers,
                    &dealer1_dh_sk,
                    &dealer1.index,
                    &dealer1coeffs,
                    &dealers,
                    "Φ",
                    &mut rng,
                )
                .or(Err(()))?;
            let dealer1_their_encrypted_secret_shares =
                dealer1_state.their_encrypted_secret_shares().or(Err(()))?;

            let (dealer2_state, _participant_lists) =
                DistributedKeyGeneration::<RoundOne, G1Projective>::new_initial(
                    &params_dealers,
                    &dealer2_dh_sk,
                    &dealer2.index,
                    &dealer2coeffs,
                    &dealers,
                    "Φ",
                    &mut rng,
                )
                .or(Err(()))?;
            let dealer2_their_encrypted_secret_shares =
                dealer2_state.their_encrypted_secret_shares().or(Err(()))?;

            let (dealer3_state, _participant_lists) =
                DistributedKeyGeneration::<RoundOne, G1Projective>::new_initial(
                    &params_dealers,
                    &dealer3_dh_sk,
                    &dealer3.index,
                    &dealer3coeffs,
                    &dealers,
                    "Φ",
                    &mut rng,
                )
                .or(Err(()))?;
            let dealer3_their_encrypted_secret_shares =
                dealer3_state.their_encrypted_secret_shares().or(Err(()))?;

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

            let dealer1_state = dealer1_state
                .to_round_two(dealer1_my_encrypted_secret_shares, &mut rng)
                .or(Err(()))?;
            let dealer2_state = dealer2_state
                .to_round_two(dealer2_my_encrypted_secret_shares, &mut rng)
                .or(Err(()))?;
            let dealer3_state = dealer3_state
                .to_round_two(dealer3_my_encrypted_secret_shares, &mut rng)
                .or(Err(()))?;

            let (dealer1_group_key, dealer1_secret_key) = dealer1_state.finish().or(Err(()))?;
            let (dealer2_group_key, dealer2_secret_key) = dealer2_state.finish().or(Err(()))?;
            let (dealer3_group_key, dealer3_secret_key) = dealer3_state.finish().or(Err(()))?;

            assert!(dealer1_group_key.0.into_affine() == dealer2_group_key.0.into_affine());
            assert!(dealer2_group_key.0.into_affine() == dealer3_group_key.0.into_affine());

            let params_signers = ThresholdParameters::<G1Projective>::new(5, 3);
            let (signer1, signer1_dh_sk) =
                Participant::new_signer(&params_signers, 1, "Φ", &mut rng);
            let (signer2, signer2_dh_sk) =
                Participant::new_signer(&params_signers, 2, "Φ", &mut rng);
            let (signer3, signer3_dh_sk) =
                Participant::new_signer(&params_signers, 3, "Φ", &mut rng);
            let (signer4, signer4_dh_sk) =
                Participant::new_signer(&params_signers, 4, "Φ", &mut rng);
            let (signer5, signer5_dh_sk) =
                Participant::new_signer(&params_signers, 5, "Φ", &mut rng);

            let signers: Vec<Participant<G1Projective>> = vec![
                signer1.clone(),
                signer2.clone(),
                signer3.clone(),
                signer4.clone(),
                signer5.clone(),
            ];

            let (dealer1_for_signers, dealer1_encrypted_shares_for_signers, _participant_lists) =
                Participant::reshare(&params_signers, dealer1_secret_key, &signers, "Φ", &mut rng)
                    .map_err(|_| ())?;
            let (dealer2_for_signers, dealer2_encrypted_shares_for_signers, _participant_lists) =
                Participant::reshare(&params_signers, dealer2_secret_key, &signers, "Φ", &mut rng)
                    .map_err(|_| ())?;
            let (dealer3_for_signers, dealer3_encrypted_shares_for_signers, _participant_lists) =
                Participant::reshare(&params_signers, dealer3_secret_key, &signers, "Φ", &mut rng)
                    .map_err(|_| ())?;

            let dealers: Vec<Participant<G1Projective>> = vec![
                dealer1_for_signers,
                dealer2_for_signers,
                dealer3_for_signers,
            ];
            let (signer1_state, _participant_lists) =
                DistributedKeyGeneration::<RoundOne, G1Projective>::new(
                    &params_dealers,
                    &signer1_dh_sk,
                    &signer1.index,
                    &dealers,
                    "Φ",
                    &mut rng,
                )
                .or(Err(()))?;

            let (signer2_state, _participant_lists) =
                DistributedKeyGeneration::<RoundOne, G1Projective>::new(
                    &params_dealers,
                    &signer2_dh_sk,
                    &signer2.index,
                    &dealers,
                    "Φ",
                    &mut rng,
                )
                .or(Err(()))?;

            let (signer3_state, _participant_lists) =
                DistributedKeyGeneration::<RoundOne, G1Projective>::new(
                    &params_dealers,
                    &signer3_dh_sk,
                    &signer3.index,
                    &dealers,
                    "Φ",
                    &mut rng,
                )
                .or(Err(()))?;

            let (signer4_state, _participant_lists) =
                DistributedKeyGeneration::<RoundOne, G1Projective>::new(
                    &params_dealers,
                    &signer4_dh_sk,
                    &signer4.index,
                    &dealers,
                    "Φ",
                    &mut rng,
                )
                .or(Err(()))?;

            let (signer5_state, _participant_lists) =
                DistributedKeyGeneration::<RoundOne, G1Projective>::new(
                    &params_dealers,
                    &signer5_dh_sk,
                    &signer5.index,
                    &dealers,
                    "Φ",
                    &mut rng,
                )
                .or(Err(()))?;

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

            let signer1_state = signer1_state
                .to_round_two(signer1_my_encrypted_secret_shares, &mut rng)
                .or(Err(()))?;
            let signer2_state = signer2_state
                .to_round_two(signer2_my_encrypted_secret_shares, &mut rng)
                .or(Err(()))?;
            let signer3_state = signer3_state
                .to_round_two(signer3_my_encrypted_secret_shares, &mut rng)
                .or(Err(()))?;
            let signer4_state = signer4_state
                .to_round_two(signer4_my_encrypted_secret_shares, &mut rng)
                .or(Err(()))?;
            let signer5_state = signer5_state
                .to_round_two(signer5_my_encrypted_secret_shares, &mut rng)
                .or(Err(()))?;

            let (signer1_group_key, _signer1_secret_key) = signer1_state.finish().or(Err(()))?;
            let (signer2_group_key, _signer2_secret_key) = signer2_state.finish().or(Err(()))?;
            let (signer3_group_key, _signer3_secret_key) = signer3_state.finish().or(Err(()))?;
            let (signer4_group_key, _signer4_secret_key) = signer4_state.finish().or(Err(()))?;
            let (signer5_group_key, _signer5_secret_key) = signer5_state.finish().or(Err(()))?;

            assert!(signer1_group_key.0.into_affine() == signer2_group_key.0.into_affine());
            assert!(signer2_group_key.0.into_affine() == signer3_group_key.0.into_affine());
            assert!(signer3_group_key.0.into_affine() == signer4_group_key.0.into_affine());
            assert!(signer4_group_key.0.into_affine() == signer5_group_key.0.into_affine());

            assert!(signer1_group_key.0.into_affine() == dealer1_group_key.0.into_affine());

            Ok(())
        }
        assert!(do_test().is_ok());
    }

    #[test]
    fn encrypt_and_decrypt() {
        let mut rng: OsRng = OsRng;

        let original_share = SecretShare::<G1Projective> {
            sender_index: 1,
            receiver_index: 2,
            polynomial_evaluation: Fr::rand(&mut rng),
        };

        let mut key = [0u8; 32];
        rng.fill(&mut key);

        let encrypted_share = encrypt_share(&original_share, &key, &mut rng);
        let decrypted_share = decrypt_share::<G1Projective>(&encrypted_share, &key);

        assert!(decrypted_share.is_ok());
        assert!(
            original_share.polynomial_evaluation == decrypted_share.unwrap().polynomial_evaluation
        );
    }

    #[test]
    fn keygen_2_out_of_3_with_random_keys() {
        fn do_test() -> Result<(), ()> {
            let params = ThresholdParameters::new(3, 2);
            let mut rng: OsRng = OsRng;

            let (p1, p1coeffs, dh_sk1) =
                Participant::<G1Projective>::new_dealer(&params, 1, "Φ", &mut rng);
            let (p2, p2coeffs, dh_sk2) =
                Participant::<G1Projective>::new_dealer(&params, 2, "Φ", &mut rng);
            let (p3, p3coeffs, dh_sk3) =
                Participant::<G1Projective>::new_dealer(&params, 3, "Φ", &mut rng);

            p1.proof_of_secret_key
                .as_ref()
                .unwrap()
                .verify(p1.index, p1.public_key().unwrap(), "Φ")
                .or(Err(()))?;
            p2.proof_of_secret_key
                .as_ref()
                .unwrap()
                .verify(p2.index, p2.public_key().unwrap(), "Φ")
                .or(Err(()))?;
            p3.proof_of_secret_key
                .as_ref()
                .unwrap()
                .verify(p3.index, p3.public_key().unwrap(), "Φ")
                .or(Err(()))?;

            let participants: Vec<Participant<G1Projective>> =
                vec![p1.clone(), p2.clone(), p3.clone()];
            let (p1_state, _participant_lists) =
                DistributedKeyGeneration::<RoundOne, G1Projective>::new_initial(
                    &params,
                    &dh_sk1,
                    &p1.index,
                    &p1coeffs,
                    &participants,
                    "Φ",
                    &mut rng,
                )
                .or(Err(()))?;
            let p1_their_encrypted_secret_shares =
                p1_state.their_encrypted_secret_shares().or(Err(()))?;

            let (p2_state, _participant_lists) =
                DistributedKeyGeneration::<RoundOne, G1Projective>::new_initial(
                    &params,
                    &dh_sk2,
                    &p2.index,
                    &p2coeffs,
                    &participants,
                    "Φ",
                    &mut rng,
                )
                .or(Err(()))?;
            let p2_their_encrypted_secret_shares =
                p2_state.their_encrypted_secret_shares().or(Err(()))?;

            let (p3_state, _participant_lists) =
                DistributedKeyGeneration::<RoundOne, G1Projective>::new_initial(
                    &params,
                    &dh_sk3,
                    &p3.index,
                    &p3coeffs,
                    &participants,
                    "Φ",
                    &mut rng,
                )
                .or(Err(()))?;
            let p3_their_encrypted_secret_shares =
                p3_state.their_encrypted_secret_shares().or(Err(()))?;

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

            let p1_state = p1_state
                .to_round_two(p1_my_encrypted_secret_shares, &mut rng)
                .or(Err(()))?;
            let p2_state = p2_state
                .to_round_two(p2_my_encrypted_secret_shares, &mut rng)
                .or(Err(()))?;
            let p3_state = p3_state
                .to_round_two(p3_my_encrypted_secret_shares, &mut rng)
                .or(Err(()))?;

            let (p1_group_key, _p1_secret_key) = p1_state.finish().or(Err(()))?;
            let (p2_group_key, _p2_secret_key) = p2_state.finish().or(Err(()))?;
            let (p3_group_key, _p3_secret_key) = p3_state.finish().or(Err(()))?;

            assert!(p1_group_key.0.into_affine() == p2_group_key.0.into_affine());
            assert!(p2_group_key.0.into_affine() == p3_group_key.0.into_affine());

            Ok(())
        }
        assert!(do_test().is_ok());
    }

    #[test]
    fn keygen_verify_complaint() {
        fn do_test() -> Result<(), ()> {
            let params = ThresholdParameters::new(3, 2);
            let mut rng: OsRng = OsRng;

            let (p1, p1coeffs, dh_sk1) =
                Participant::<G1Projective>::new_dealer(&params, 1, "Φ", &mut rng);
            let (p2, p2coeffs, dh_sk2) =
                Participant::<G1Projective>::new_dealer(&params, 2, "Φ", &mut rng);
            let (p3, p3coeffs, dh_sk3) =
                Participant::<G1Projective>::new_dealer(&params, 3, "Φ", &mut rng);

            p1.proof_of_secret_key
                .as_ref()
                .unwrap()
                .verify(p1.index, p1.public_key().unwrap(), "Φ")
                .or(Err(()))?;
            p2.proof_of_secret_key
                .as_ref()
                .unwrap()
                .verify(p2.index, p2.public_key().unwrap(), "Φ")
                .or(Err(()))?;
            p3.proof_of_secret_key
                .as_ref()
                .unwrap()
                .verify(p3.index, p3.public_key().unwrap(), "Φ")
                .or(Err(()))?;

            let participants: Vec<Participant<G1Projective>> =
                vec![p1.clone(), p2.clone(), p3.clone()];
            let (p1_state, _participant_lists) =
                DistributedKeyGeneration::<RoundOne, G1Projective>::new_initial(
                    &params,
                    &dh_sk1,
                    &p1.index,
                    &p1coeffs,
                    &participants,
                    "Φ",
                    &mut rng,
                )
                .or(Err(()))?;
            let p1_their_encrypted_secret_shares =
                p1_state.their_encrypted_secret_shares().or(Err(()))?;

            let (p2_state, _participant_lists) =
                DistributedKeyGeneration::<RoundOne, G1Projective>::new_initial(
                    &params,
                    &dh_sk2,
                    &p2.index,
                    &p2coeffs,
                    &participants,
                    "Φ",
                    &mut rng,
                )
                .or(Err(()))?;
            let p2_their_encrypted_secret_shares =
                p2_state.their_encrypted_secret_shares().or(Err(()))?;

            let (p3_state, _participant_lists) =
                DistributedKeyGeneration::<RoundOne, G1Projective>::new_initial(
                    &params,
                    &dh_sk3,
                    &p3.index,
                    &p3coeffs,
                    &participants,
                    "Φ",
                    &mut rng,
                )
                .or(Err(()))?;
            let p3_their_encrypted_secret_shares =
                p3_state.their_encrypted_secret_shares().or(Err(()))?;

            let mut complaint: Complaint<G1Projective>;

            // Wrong decryption from nonce
            {
                let mut wrong_encrypted_secret_share = p1_their_encrypted_secret_shares[1].clone();
                wrong_encrypted_secret_share.nonce = [42; 16];
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
                    .to_round_two(p1_my_encrypted_secret_shares, &mut rng)
                    .or(Err(()))?;
                let p3_state = p3_state
                    .clone()
                    .to_round_two(p3_my_encrypted_secret_shares, &mut rng)
                    .or(Err(()))?;

                let complaints = p2_state
                    .clone()
                    .to_round_two(p2_my_encrypted_secret_shares, &mut rng);
                assert!(complaints.is_err());
                let complaints = complaints.unwrap_err();
                if let Error::Complaint(complaints) = complaints {
                    assert!(complaints.len() == 1);

                    let bad_index = p3_state.blame(&wrong_encrypted_secret_share, &complaints[0]);
                    assert!(bad_index == 1);

                    let (p1_group_key, _p1_secret_key) = p1_state.finish().or(Err(()))?;
                    let (p3_group_key, _p3_secret_key) = p3_state.finish().or(Err(()))?;

                    assert!(p1_group_key.0.into_affine() == p3_group_key.0.into_affine());

                    // Copy for next test and change dh_key
                    complaint = complaints[0].clone();
                    complaint.dh_shared_key.double_in_place();
                } else {
                    return Err(());
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
                    .to_round_two(p1_my_encrypted_secret_shares, &mut rng)
                    .or(Err(()))?;
                let p3_state = p3_state
                    .clone()
                    .to_round_two(p3_my_encrypted_secret_shares, &mut rng)
                    .or(Err(()))?;

                let complaints = p2_state
                    .clone()
                    .to_round_two(p2_my_encrypted_secret_shares, &mut rng);
                assert!(complaints.is_err());
                let complaints = complaints.unwrap_err();
                if let Error::Complaint(complaints) = complaints {
                    assert!(complaints.len() == 1);

                    let bad_index = p3_state.blame(&wrong_encrypted_secret_share, &complaints[0]);
                    assert!(bad_index == 1);

                    let (p1_group_key, _p1_secret_key) = p1_state.finish().or(Err(()))?;
                    let (p3_group_key, _p3_secret_key) = p3_state.finish().or(Err(()))?;

                    assert!(p1_group_key.0.into_affine() == p3_group_key.0.into_affine());
                } else {
                    return Err(());
                }
            }

            // Wrong encrypted share
            {
                let dh_key = p1.dh_public_key.0 * dh_sk1.0;
                let mut dh_key_bytes = Vec::new();
                dh_key.serialize_compressed(&mut dh_key_bytes).unwrap();
                let wrong_encrypted_secret_share = encrypt_share(
                    &SecretShare::<G1Projective> {
                        sender_index: 1,
                        receiver_index: 2,
                        polynomial_evaluation: Fr::from(42u32),
                    },
                    &dh_key_bytes[..],
                    &mut rng,
                );
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
                    .to_round_two(p1_my_encrypted_secret_shares, &mut rng)
                    .or(Err(()))?;
                let p3_state = p3_state
                    .clone()
                    .to_round_two(p3_my_encrypted_secret_shares, &mut rng)
                    .or(Err(()))?;

                let complaints = p2_state
                    .clone()
                    .to_round_two(p2_my_encrypted_secret_shares, &mut rng);
                assert!(complaints.is_err());
                let complaints = complaints.unwrap_err();
                if let Error::Complaint(complaints) = complaints {
                    assert!(complaints.len() == 1);

                    let bad_index = p3_state.blame(&wrong_encrypted_secret_share, &complaints[0]);
                    assert!(bad_index == 1);

                    let (p1_group_key, _p1_secret_key) = p1_state.finish().or(Err(()))?;
                    let (p3_group_key, _p3_secret_key) = p3_state.finish().or(Err(()))?;

                    assert!(p1_group_key.0.into_affine() == p3_group_key.0.into_affine());
                } else {
                    return Err(());
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
                    .to_round_two(p3_my_encrypted_secret_shares, &mut rng)
                    .or(Err(()))?;

                let bad_index = p3_state.blame(&p1_their_encrypted_secret_shares[0], &complaint);
                assert!(bad_index == 2);
            }

            Ok(())
        }
        assert!(do_test().is_ok());
    }

    // TODO: check serialisation

    #[test]
    fn individual_public_key_share() {
        fn do_test() -> Result<(), ()> {
            let params = ThresholdParameters::new(3, 2);
            let mut rng: OsRng = OsRng;

            let (p1, p1coeffs, p1_dh_sk) =
                Participant::<G1Projective>::new_dealer(&params, 1, "Φ", &mut rng);
            let (p2, p2coeffs, p2_dh_sk) =
                Participant::<G1Projective>::new_dealer(&params, 2, "Φ", &mut rng);
            let (p3, p3coeffs, p3_dh_sk) =
                Participant::<G1Projective>::new_dealer(&params, 3, "Φ", &mut rng);

            p1.proof_of_secret_key
                .as_ref()
                .unwrap()
                .verify(p1.index, p1.public_key().unwrap(), "Φ")
                .or(Err(()))?;
            p2.proof_of_secret_key
                .as_ref()
                .unwrap()
                .verify(p2.index, p2.public_key().unwrap(), "Φ")
                .or(Err(()))?;
            p3.proof_of_secret_key
                .as_ref()
                .unwrap()
                .verify(p3.index, p3.public_key().unwrap(), "Φ")
                .or(Err(()))?;

            let participants: Vec<Participant<G1Projective>> =
                vec![p1.clone(), p2.clone(), p3.clone()];
            let (p1_state, _participant_lists) =
                DistributedKeyGeneration::<RoundOne, G1Projective>::new_initial(
                    &params,
                    &p1_dh_sk,
                    &p1.index,
                    &p1coeffs,
                    &participants,
                    "Φ",
                    &mut rng,
                )
                .or(Err(()))?;
            let p1_their_encrypted_secret_shares =
                p1_state.their_encrypted_secret_shares().or(Err(()))?;

            let (p2_state, _participant_lists) =
                DistributedKeyGeneration::<RoundOne, G1Projective>::new_initial(
                    &params,
                    &p2_dh_sk,
                    &p2.index,
                    &p2coeffs,
                    &participants,
                    "Φ",
                    &mut rng,
                )
                .or(Err(()))?;
            let p2_their_encrypted_secret_shares =
                p2_state.their_encrypted_secret_shares().or(Err(()))?;

            let (p3_state, _participant_lists) =
                DistributedKeyGeneration::<RoundOne, G1Projective>::new_initial(
                    &params,
                    &p3_dh_sk,
                    &p3.index,
                    &p3coeffs,
                    &participants,
                    "Φ",
                    &mut rng,
                )
                .or(Err(()))?;
            let p3_their_encrypted_secret_shares =
                p3_state.their_encrypted_secret_shares().or(Err(()))?;

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

            let p1_state = p1_state
                .to_round_two(p1_my_encrypted_secret_shares, &mut rng)
                .or(Err(()))?;
            let p2_state = p2_state
                .to_round_two(p2_my_encrypted_secret_shares, &mut rng)
                .or(Err(()))?;
            let p3_state = p3_state
                .to_round_two(p3_my_encrypted_secret_shares, &mut rng)
                .or(Err(()))?;

            let (p1_group_key, p1_secret_key) = p1_state.finish().or(Err(()))?;
            let (p2_group_key, p2_secret_key) = p2_state.finish().or(Err(()))?;
            let (p3_group_key, p3_secret_key) = p3_state.finish().or(Err(()))?;

            assert!(p1_group_key.0.into_affine() == p2_group_key.0.into_affine());
            assert!(p2_group_key.0.into_affine() == p3_group_key.0.into_affine());

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
                IndividualVerifyingKey::generate_from_commitments(1, &commitments);
            let p2_recovered_public_key =
                IndividualVerifyingKey::generate_from_commitments(2, &commitments);
            let p3_recovered_public_key =
                IndividualVerifyingKey::generate_from_commitments(3, &commitments);

            assert_eq!(p1_public_key, p1_recovered_public_key);
            assert_eq!(p2_public_key, p2_recovered_public_key);
            assert_eq!(p3_public_key, p3_recovered_public_key);

            Ok(())
        }
        assert!(do_test().is_ok());
    }
}
