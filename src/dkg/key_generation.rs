use ark_ec::Group;
use ark_ff::{Field, Zero};
use ark_serialize::CanonicalDeserialize;
use ark_serialize::CanonicalSerialize;

use core::ops::Mul;
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
    DiffieHellmanPrivateKey, DiffieHellmanPublicKey, GroupKey, IndividualSigningKey,
};
use crate::parameters::ThresholdParameters;
use crate::{Error, FrostResult};

use crate::utils::calculate_lagrange_coefficients;
use crate::utils::{Box, ToString, Vec};

/// State machine structures for holding intermediate values during a
/// distributed key generation protocol run, to prevent misuse.
#[derive(Clone, Debug)]
pub struct DistributedKeyGeneration<S: DkgState, C: CipherSuite> {
    state: Box<ActualState<C>>,
    data: S,
}

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
    their_dh_public_keys: Vec<(u32, DiffieHellmanPublicKey<C>)>,
    /// The encrypted secret shares this participant has calculated for all the other participants.
    their_encrypted_secret_shares: Option<Vec<EncryptedSecretShare<C>>>,
    /// The secret shares this participant has received from all the other participants.
    my_secret_shares: Option<Vec<SecretShare<C>>>,
}

/// Output of the first round of the Distributed Key Generation.
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct DKGParticipantList<C: CipherSuite> {
    /// List of the valid participants to be used in RoundTwo
    pub valid_participants: Vec<Participant<C>>,
    /// List of the invalid participants that have been removed
    pub misbehaving_participants: Option<Vec<u32>>,
}

impl<C: CipherSuite> DistributedKeyGeneration<RoundOne, C>
where
    [(); C::HASH_SEC_PARAM]:,
{
    /// Serialize this [`DistributedKeyGeneration<RoundOne, _>`] to a vector of bytes.
    pub fn to_bytes(&self) -> FrostResult<C, Vec<u8>> {
        let mut bytes = Vec::new();

        self.state
            .serialize_compressed(&mut bytes)
            .map_err(|_| Error::SerializationError)?;

        self.data
            .serialize_compressed(&mut bytes)
            .map_err(|_| Error::SerializationError)?;

        Ok(bytes)
    }

    /// Attempt to deserialize a [`DistributedKeyGeneration<RoundOne, _>`] from a vector of bytes.
    pub fn from_bytes(bytes: &[u8]) -> FrostResult<C, Self> {
        let state = Box::new(
            ActualState::deserialize_compressed(bytes).map_err(|_| Error::DeserializationError)?,
        );

        let data =
            RoundOne::deserialize_compressed(bytes).map_err(|_| Error::DeserializationError)?;

        Ok(Self { state, data })
    }

    /// Check the zero-knowledge proofs of knowledge of secret keys of all the
    /// other participants. When no group key has been computed by a group of
    /// participants yet, this method should be called rather than
    /// [`DistributedKeyGeneration<RoundOne, C>::new()`] .
    ///
    /// # Note
    ///
    /// The [`participants`] will be sorted by their indices.
    ///
    /// # Returns
    ///
    /// An updated state machine for the distributed key generation protocol if
    /// all of the zero-knowledge proofs verified successfully, otherwise a
    /// vector of participants whose zero-knowledge proofs were incorrect.
    pub fn new_initial(
        parameters: &ThresholdParameters<C>,
        dh_private_key: &DiffieHellmanPrivateKey<C>,
        my_index: &u32,
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

    /// Check the zero-knowledge proofs of knowledge of secret keys of all the
    /// other participants. When a group key already exists and dealers have
    /// distributed secret shares to a new set, participants of this new set
    /// should call this method.
    ///
    /// # Note
    ///
    /// The [`participants`] will be sorted by their indices.
    ///
    /// # Returns
    ///
    /// An updated state machine for the distributed key generation protocol if
    /// all of the zero-knowledge proofs verified successfully, otherwise a
    /// vector of participants whose zero-knowledge proofs were incorrect.
    pub fn new(
        parameters: &ThresholdParameters<C>,
        dh_private_key: &DiffieHellmanPrivateKey<C>,
        my_index: &u32,
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
        parameters: &ThresholdParameters<C>,
        dh_private_key: &DiffieHellmanPrivateKey<C>,
        my_index: &u32,
        my_coefficients: Option<&Coefficients<C>>,
        participants: &[Participant<C>],
        from_dealer: bool,
        from_signer: bool,
        mut rng: impl RngCore + CryptoRng,
    ) -> FrostResult<C, (Self, DKGParticipantList<C>)> {
        let mut their_commitments: Vec<VerifiableSecretSharingCommitment<C>> =
            Vec::with_capacity(parameters.t as usize);
        let mut their_dh_public_keys: Vec<(u32, DiffieHellmanPublicKey<C>)> =
            Vec::with_capacity(parameters.t as usize);
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
        for p in participants.iter() {
            // Always check the DH keys of the participants
            match p.proof_of_dh_private_key.verify(p.index, &p.dh_public_key) {
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
                        match p
                            .proof_of_secret_key
                            .as_ref()
                            .unwrap()
                            .verify(p.index, public_key)
                        {
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
                DistributedKeyGeneration::<RoundOne, C> {
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
        let mut their_encrypted_secret_shares: Vec<EncryptedSecretShare<C>> =
            Vec::with_capacity(parameters.n as usize - 1);

        for p in participants.iter() {
            let share =
                SecretShare::<C>::evaluate_polynomial(my_index, &p.index, my_coefficients.unwrap());

            let dh_key = p.dh_public_key.key * dh_private_key.0;
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
            DistributedKeyGeneration::<RoundOne, C> {
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
    /// at the end of [`DistributedKeyGeneration::<RoundOne, C>`] .
    pub fn their_encrypted_secret_shares(&self) -> FrostResult<C, &Vec<EncryptedSecretShare<C>>> {
        self.state
            .their_encrypted_secret_shares
            .as_ref()
            .ok_or(Error::NoEncryptedShares)
    }

    /// Progress to round two of the Dkg protocol once we have sent each encrypted share
    /// from [`DistributedKeyGeneration::<RoundOne, C>.their_encrypted_secret_shares()`] to its
    /// respective other participant, and collected our shares from the other
    /// participants in turn.
    pub fn to_round_two(
        mut self,
        my_encrypted_secret_shares: Vec<EncryptedSecretShare<C>>,
        mut rng: impl RngCore + CryptoRng,
    ) -> FrostResult<C, DistributedKeyGeneration<RoundTwo, C>> {
        // Sanity check
        assert_eq!(self.data, RoundOne {});

        // Zero out the other participants encrypted secret shares from memory.
        if self.state.their_encrypted_secret_shares.is_some() {
            self.state.their_encrypted_secret_shares = None;
        }

        // RICE-FROST

        let mut complaints: Vec<Complaint<C>> = Vec::new();

        if my_encrypted_secret_shares.len() != self.state.parameters.n as usize {
            return Err(Error::MissingShares);
        }

        let mut my_secret_shares: Vec<SecretShare<C>> = Vec::new();

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
                                complaints.push(Complaint::<C>::new(
                                    encrypted_share.receiver_index,
                                    encrypted_share.sender_index,
                                    &pk.1,
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
                }
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
    /// Serialize this [`DistributedKeyGeneration<RoundTwo, _>`] to a vector of bytes.
    pub fn to_bytes(&self) -> FrostResult<C, Vec<u8>> {
        let mut bytes = Vec::new();

        self.state
            .serialize_compressed(&mut bytes)
            .map_err(|_| Error::SerializationError)?;

        self.data
            .serialize_compressed(&mut bytes)
            .map_err(|_| Error::SerializationError)?;

        Ok(bytes)
    }

    /// Attempt to deserialize a [`DistributedKeyGeneration<RoundTwo, _>`] from a vector of bytes.
    pub fn from_bytes(bytes: &[u8]) -> FrostResult<C, Self> {
        let state = Box::new(
            ActualState::deserialize_compressed(bytes).map_err(|_| Error::DeserializationError)?,
        );

        let data =
            RoundTwo::deserialize_compressed(bytes).map_err(|_| Error::DeserializationError)?;

        Ok(Self { state, data })
    }

    /// Calculate this threshold signing protocol participant's long-lived
    /// secret signing keyshare and the group's public verification key.
    ///
    /// # Example
    ///
    /// [```ignore
    /// let (group_key, secret_key) = state.finish()?;
    /// [```
    pub fn finish(mut self) -> FrostResult<C, (GroupKey<C>, IndividualSigningKey<C>)> {
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

        let mut index_vector: Vec<u32> = Vec::new();

        for share in my_secret_shares.iter() {
            index_vector.push(share.sender_index);
        }

        let mut key = <C::G as Group>::ScalarField::ZERO;

        for share in my_secret_shares.iter() {
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
    /// A [`GroupKey`] for the set of participants.
    ///
    /// my_commitment is needed for now, but won't be when the distinction
    /// dealers/signers is implemented.
    pub(crate) fn calculate_group_key(&self) -> FrostResult<C, GroupKey<C>> {
        let mut index_vector: Vec<u32> = Vec::new();

        for commitment in self.state.their_commitments.as_ref().unwrap().iter() {
            index_vector.push(commitment.index);
        }

        let mut group_key = <C as CipherSuite>::G::zero();

        // The group key is the interpolation at 0 of all index 0 of the dealers' commitments.
        for commitment in self.state.their_commitments.as_ref().unwrap().iter() {
            let coeff = match calculate_lagrange_coefficients::<C>(commitment.index, &index_vector)
            {
                Ok(s) => s,
                Err(error) => return Err(Error::Custom(error.to_string())),
            };

            group_key += commitment.public_key().unwrap().mul(coeff);
        }

        Ok(GroupKey::new(group_key))
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

        if pk_maker == <C as CipherSuite>::G::zero() || pk_accused == <C as CipherSuite>::G::zero()
        {
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
    use crate::dkg::{ComplaintProof, NizkPokOfSecretKey};
    use crate::keys::IndividualVerifyingKey;
    use crate::testing::Secp256k1Sha256;

    use ark_ec::Group;
    use ark_ff::UniformRand;
    use ark_secp256k1::{Fr, Projective};

    use rand::rngs::OsRng;
    use rand::Rng;

    #[test]
    fn nizk_of_secret_key() {
        let params = ThresholdParameters::new(3, 2);
        let rng = OsRng;

        let (p, _, _) = Participant::<Secp256k1Sha256>::new_dealer(&params, 0, rng);
        let result = p
            .proof_of_secret_key
            .as_ref()
            .unwrap()
            .verify(p.index, p.public_key().unwrap());

        assert!(result.is_ok());
    }

    #[test]
    fn secret_share_from_one_coefficients() {
        let mut coeffs: Vec<Fr> = Vec::new();

        for _ in 0..5 {
            coeffs.push(Fr::ONE);
        }

        let coefficients = Coefficients::<Secp256k1Sha256>(coeffs);
        let share = SecretShare::<Secp256k1Sha256>::evaluate_polynomial(&1, &1, &coefficients);

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
        let mut coeffs: Vec<Fr> = Vec::new();

        for _ in 0..5 {
            coeffs.push(Fr::ONE);
        }

        let coefficients = Coefficients::<Secp256k1Sha256>(coeffs);
        let share = SecretShare::evaluate_polynomial(&1, &0, &coefficients);

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

        let (p1, p1coeffs, p1_dh_sk) = Participant::<Secp256k1Sha256>::new_dealer(&params, 1, rng);

        p1.proof_of_secret_key
            .as_ref()
            .unwrap()
            .verify(p1.index, p1.public_key().unwrap())
            .unwrap();

        let participants: Vec<Participant<Secp256k1Sha256>> = vec![p1.clone()];
        let (p1_state, _participant_lists) =
            DistributedKeyGeneration::<RoundOne, Secp256k1Sha256>::new_initial(
                &params,
                &p1_dh_sk,
                &p1.index,
                &p1coeffs,
                &participants,
                rng,
            )
            .unwrap();
        let p1_my_encrypted_secret_shares =
            p1_state.their_encrypted_secret_shares().unwrap().clone();
        let p1_state = p1_state
            .to_round_two(p1_my_encrypted_secret_shares, rng)
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

        let (p1, p1coeffs, p1_dh_sk) = Participant::<Secp256k1Sha256>::new_dealer(&params, 1, rng);
        let (p2, p2coeffs, p2_dh_sk) = Participant::<Secp256k1Sha256>::new_dealer(&params, 2, rng);
        let (p3, p3coeffs, p3_dh_sk) = Participant::<Secp256k1Sha256>::new_dealer(&params, 3, rng);
        let (p4, p4coeffs, p4_dh_sk) = Participant::<Secp256k1Sha256>::new_dealer(&params, 4, rng);
        let (p5, p5coeffs, p5_dh_sk) = Participant::<Secp256k1Sha256>::new_dealer(&params, 5, rng);

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
            DistributedKeyGeneration::<RoundOne, Secp256k1Sha256>::new_initial(
                &params,
                &p1_dh_sk,
                &p1.index,
                &p1coeffs,
                &participants,
                rng,
            )
            .unwrap();
        let p1_their_encrypted_secret_shares = p1_state.their_encrypted_secret_shares().unwrap();

        let (p2_state, _participant_lists) =
            DistributedKeyGeneration::<RoundOne, Secp256k1Sha256>::new_initial(
                &params,
                &p2_dh_sk,
                &p2.index,
                &p2coeffs,
                &participants,
                rng,
            )
            .unwrap();
        let p2_their_encrypted_secret_shares = p2_state.their_encrypted_secret_shares().unwrap();

        let (p3_state, _participant_lists) =
            DistributedKeyGeneration::<RoundOne, Secp256k1Sha256>::new_initial(
                &params,
                &p3_dh_sk,
                &p3.index,
                &p3coeffs,
                &participants,
                rng,
            )
            .unwrap();
        let p3_their_encrypted_secret_shares = p3_state.their_encrypted_secret_shares().unwrap();

        let (p4_state, _participant_lists) =
            DistributedKeyGeneration::<RoundOne, Secp256k1Sha256>::new_initial(
                &params,
                &p4_dh_sk,
                &p4.index,
                &p4coeffs,
                &participants,
                rng,
            )
            .unwrap();
        let p4_their_encrypted_secret_shares = p4_state.their_encrypted_secret_shares().unwrap();

        let (p5_state, _participant_lists) =
            DistributedKeyGeneration::<RoundOne, Secp256k1Sha256>::new_initial(
                &params,
                &p5_dh_sk,
                &p5.index,
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
            .to_round_two(p1_my_encrypted_secret_shares, rng)
            .unwrap();
        let p2_state = p2_state
            .to_round_two(p2_my_encrypted_secret_shares, rng)
            .unwrap();
        let p3_state = p3_state
            .to_round_two(p3_my_encrypted_secret_shares, rng)
            .unwrap();
        let p4_state = p4_state
            .to_round_two(p4_my_encrypted_secret_shares, rng)
            .unwrap();
        let p5_state = p5_state
            .to_round_two(p5_my_encrypted_secret_shares, rng)
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

        let group_key = GroupKey::new(Projective::generator().mul(group_secret_key));

        assert!(p5_group_key == group_key)
    }

    #[test]
    fn keygen_2_out_of_3() {
        fn do_test() -> FrostResult<Secp256k1Sha256, ()> {
            let params = ThresholdParameters::new(3, 2);
            let rng = OsRng;

            let (p1, p1coeffs, p1_dh_sk) =
                Participant::<Secp256k1Sha256>::new_dealer(&params, 1, rng);
            let (p2, p2coeffs, p2_dh_sk) =
                Participant::<Secp256k1Sha256>::new_dealer(&params, 2, rng);
            let (p3, p3coeffs, p3_dh_sk) =
                Participant::<Secp256k1Sha256>::new_dealer(&params, 3, rng);

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
                DistributedKeyGeneration::<RoundOne, Secp256k1Sha256>::new_initial(
                    &params,
                    &p1_dh_sk,
                    &p1.index,
                    &p1coeffs,
                    &participants,
                    rng,
                )?;
            let p1_their_encrypted_secret_shares = p1_state.their_encrypted_secret_shares()?;

            let (p2_state, _participant_lists) =
                DistributedKeyGeneration::<RoundOne, Secp256k1Sha256>::new_initial(
                    &params,
                    &p2_dh_sk,
                    &p2.index,
                    &p2coeffs,
                    &participants,
                    rng,
                )?;
            let p2_their_encrypted_secret_shares = p2_state.their_encrypted_secret_shares()?;

            let (p3_state, _participant_lists) =
                DistributedKeyGeneration::<RoundOne, Secp256k1Sha256>::new_initial(
                    &params,
                    &p3_dh_sk,
                    &p3.index,
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

            let p1_state = p1_state.to_round_two(p1_my_encrypted_secret_shares, rng)?;
            let p2_state = p2_state.to_round_two(p2_my_encrypted_secret_shares, rng)?;
            let p3_state = p3_state.to_round_two(p3_my_encrypted_secret_shares, rng)?;

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
                Participant::<Secp256k1Sha256>::new_dealer(&params, 1, rng);
            let (dealer2, dealer2coeffs, dealer2_dh_sk) =
                Participant::<Secp256k1Sha256>::new_dealer(&params, 2, rng);
            let (dealer3, dealer3coeffs, dealer3_dh_sk) =
                Participant::<Secp256k1Sha256>::new_dealer(&params, 3, rng);

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
                DistributedKeyGeneration::<RoundOne, Secp256k1Sha256>::new_initial(
                    &params,
                    &dealer1_dh_sk,
                    &dealer1.index,
                    &dealer1coeffs,
                    &dealers,
                    rng,
                )?;
            let dealer1_their_encrypted_secret_shares =
                dealer1_state.their_encrypted_secret_shares()?;

            let (dealer2_state, _participant_lists) =
                DistributedKeyGeneration::<RoundOne, Secp256k1Sha256>::new_initial(
                    &params,
                    &dealer2_dh_sk,
                    &dealer2.index,
                    &dealer2coeffs,
                    &dealers,
                    rng,
                )?;
            let dealer2_their_encrypted_secret_shares =
                dealer2_state.their_encrypted_secret_shares()?;

            let (dealer3_state, _participant_lists) =
                DistributedKeyGeneration::<RoundOne, Secp256k1Sha256>::new_initial(
                    &params,
                    &dealer3_dh_sk,
                    &dealer3.index,
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
                dealer1_state.to_round_two(dealer1_my_encrypted_secret_shares, rng)?;
            let dealer2_state =
                dealer2_state.to_round_two(dealer2_my_encrypted_secret_shares, rng)?;
            let dealer3_state =
                dealer3_state.to_round_two(dealer3_my_encrypted_secret_shares, rng)?;

            let (dealer1_group_key, dealer1_secret_key) = dealer1_state.finish()?;
            let (dealer2_group_key, dealer2_secret_key) = dealer2_state.finish()?;
            let (dealer3_group_key, dealer3_secret_key) = dealer3_state.finish()?;

            assert!(dealer1_group_key == dealer2_group_key);
            assert!(dealer2_group_key == dealer3_group_key);

            let (signer1, signer1_dh_sk) = Participant::new_signer(&params, 1, rng);
            let (signer2, signer2_dh_sk) = Participant::new_signer(&params, 2, rng);
            // Dealer 3 is also a participant of the next set of signers
            let (signer3, signer3_dh_sk) = (dealer3, dealer3_dh_sk);

            let signers: Vec<Participant<Secp256k1Sha256>> =
                vec![signer1.clone(), signer2.clone(), signer3.clone()];

            let (dealer1_for_signers, dealer1_encrypted_shares_for_signers, _participant_lists) =
                Participant::reshare(&params, dealer1_secret_key, &signers, rng)?;
            let (dealer2_for_signers, dealer2_encrypted_shares_for_signers, _participant_lists) =
                Participant::reshare(&params, dealer2_secret_key, &signers, rng)?;
            let (dealer3_for_signers, dealer3_encrypted_shares_for_signers, _participant_lists) =
                Participant::reshare(&params, dealer3_secret_key, &signers, rng)?;

            let dealers: Vec<Participant<Secp256k1Sha256>> = vec![
                dealer1_for_signers,
                dealer2_for_signers,
                dealer3_for_signers,
            ];
            let (signer1_state, _participant_lists) =
                DistributedKeyGeneration::<RoundOne, Secp256k1Sha256>::new(
                    &params,
                    &signer1_dh_sk,
                    &signer1.index,
                    &dealers,
                    rng,
                )?;

            let (signer2_state, _participant_lists) =
                DistributedKeyGeneration::<RoundOne, Secp256k1Sha256>::new(
                    &params,
                    &signer2_dh_sk,
                    &signer2.index,
                    &dealers,
                    rng,
                )?;

            let (signer3_state, _participant_lists) =
                DistributedKeyGeneration::<RoundOne, Secp256k1Sha256>::new(
                    &params,
                    &signer3_dh_sk,
                    &signer3.index,
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
                signer1_state.to_round_two(signer1_my_encrypted_secret_shares, rng)?;
            let signer2_state =
                signer2_state.to_round_two(signer2_my_encrypted_secret_shares, rng)?;
            let signer3_state =
                signer3_state.to_round_two(signer3_my_encrypted_secret_shares, rng)?;

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
                Participant::<Secp256k1Sha256>::new_dealer(&params_dealers, 1, rng);
            let (dealer2, dealer2coeffs, dealer2_dh_sk) =
                Participant::<Secp256k1Sha256>::new_dealer(&params_dealers, 2, rng);
            let (dealer3, dealer3coeffs, dealer3_dh_sk) =
                Participant::<Secp256k1Sha256>::new_dealer(&params_dealers, 3, rng);

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
                DistributedKeyGeneration::<RoundOne, Secp256k1Sha256>::new_initial(
                    &params_dealers,
                    &dealer1_dh_sk,
                    &dealer1.index,
                    &dealer1coeffs,
                    &dealers,
                    rng,
                )?;
            let dealer1_their_encrypted_secret_shares =
                dealer1_state.their_encrypted_secret_shares()?;

            let (dealer2_state, _participant_lists) =
                DistributedKeyGeneration::<RoundOne, Secp256k1Sha256>::new_initial(
                    &params_dealers,
                    &dealer2_dh_sk,
                    &dealer2.index,
                    &dealer2coeffs,
                    &dealers,
                    rng,
                )?;
            let dealer2_their_encrypted_secret_shares =
                dealer2_state.their_encrypted_secret_shares()?;

            let (dealer3_state, _participant_lists) =
                DistributedKeyGeneration::<RoundOne, Secp256k1Sha256>::new_initial(
                    &params_dealers,
                    &dealer3_dh_sk,
                    &dealer3.index,
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
                dealer1_state.to_round_two(dealer1_my_encrypted_secret_shares, rng)?;
            let dealer2_state =
                dealer2_state.to_round_two(dealer2_my_encrypted_secret_shares, rng)?;
            let dealer3_state =
                dealer3_state.to_round_two(dealer3_my_encrypted_secret_shares, rng)?;

            let (dealer1_group_key, dealer1_secret_key) = dealer1_state.finish()?;
            let (dealer2_group_key, dealer2_secret_key) = dealer2_state.finish()?;
            let (dealer3_group_key, dealer3_secret_key) = dealer3_state.finish()?;

            assert!(dealer1_group_key == dealer2_group_key);
            assert!(dealer2_group_key == dealer3_group_key);

            let params_signers = ThresholdParameters::<Secp256k1Sha256>::new(5, 3);
            let (signer1, signer1_dh_sk) = Participant::new_signer(&params_signers, 1, rng);
            let (signer2, signer2_dh_sk) = Participant::new_signer(&params_signers, 2, rng);
            let (signer3, signer3_dh_sk) = Participant::new_signer(&params_signers, 3, rng);
            let (signer4, signer4_dh_sk) = Participant::new_signer(&params_signers, 4, rng);
            let (signer5, signer5_dh_sk) = Participant::new_signer(&params_signers, 5, rng);

            let signers: Vec<Participant<Secp256k1Sha256>> = vec![
                signer1.clone(),
                signer2.clone(),
                signer3.clone(),
                signer4.clone(),
                signer5.clone(),
            ];

            let (dealer1_for_signers, dealer1_encrypted_shares_for_signers, _participant_lists) =
                Participant::reshare(&params_signers, dealer1_secret_key, &signers, rng)?;
            let (dealer2_for_signers, dealer2_encrypted_shares_for_signers, _participant_lists) =
                Participant::reshare(&params_signers, dealer2_secret_key, &signers, rng)?;
            let (dealer3_for_signers, dealer3_encrypted_shares_for_signers, _participant_lists) =
                Participant::reshare(&params_signers, dealer3_secret_key, &signers, rng)?;

            let dealers: Vec<Participant<Secp256k1Sha256>> = vec![
                dealer1_for_signers,
                dealer2_for_signers,
                dealer3_for_signers,
            ];
            let (signer1_state, _participant_lists) =
                DistributedKeyGeneration::<RoundOne, Secp256k1Sha256>::new(
                    &params_dealers,
                    &signer1_dh_sk,
                    &signer1.index,
                    &dealers,
                    rng,
                )?;

            let (signer2_state, _participant_lists) =
                DistributedKeyGeneration::<RoundOne, Secp256k1Sha256>::new(
                    &params_dealers,
                    &signer2_dh_sk,
                    &signer2.index,
                    &dealers,
                    rng,
                )?;

            let (signer3_state, _participant_lists) =
                DistributedKeyGeneration::<RoundOne, Secp256k1Sha256>::new(
                    &params_dealers,
                    &signer3_dh_sk,
                    &signer3.index,
                    &dealers,
                    rng,
                )?;

            let (signer4_state, _participant_lists) =
                DistributedKeyGeneration::<RoundOne, Secp256k1Sha256>::new(
                    &params_dealers,
                    &signer4_dh_sk,
                    &signer4.index,
                    &dealers,
                    rng,
                )?;

            let (signer5_state, _participant_lists) =
                DistributedKeyGeneration::<RoundOne, Secp256k1Sha256>::new(
                    &params_dealers,
                    &signer5_dh_sk,
                    &signer5.index,
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
                signer1_state.to_round_two(signer1_my_encrypted_secret_shares, rng)?;
            let signer2_state =
                signer2_state.to_round_two(signer2_my_encrypted_secret_shares, rng)?;
            let signer3_state =
                signer3_state.to_round_two(signer3_my_encrypted_secret_shares, rng)?;
            let signer4_state =
                signer4_state.to_round_two(signer4_my_encrypted_secret_shares, rng)?;
            let signer5_state =
                signer5_state.to_round_two(signer5_my_encrypted_secret_shares, rng)?;

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

        let encrypted_share = encrypt_share(&original_share, &key, rng);
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
                Participant::<Secp256k1Sha256>::new_dealer(&params, 1, rng);
            let (p2, p2coeffs, dh_sk2) =
                Participant::<Secp256k1Sha256>::new_dealer(&params, 2, rng);
            let (p3, p3coeffs, dh_sk3) =
                Participant::<Secp256k1Sha256>::new_dealer(&params, 3, rng);

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
                DistributedKeyGeneration::<RoundOne, Secp256k1Sha256>::new_initial(
                    &params,
                    &dh_sk1,
                    &p1.index,
                    &p1coeffs,
                    &participants,
                    rng,
                )?;
            let p1_their_encrypted_secret_shares = p1_state.their_encrypted_secret_shares()?;

            let (p2_state, _participant_lists) =
                DistributedKeyGeneration::<RoundOne, Secp256k1Sha256>::new_initial(
                    &params,
                    &dh_sk2,
                    &p2.index,
                    &p2coeffs,
                    &participants,
                    rng,
                )?;
            let p2_their_encrypted_secret_shares = p2_state.their_encrypted_secret_shares()?;

            let (p3_state, _participant_lists) =
                DistributedKeyGeneration::<RoundOne, Secp256k1Sha256>::new_initial(
                    &params,
                    &dh_sk3,
                    &p3.index,
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

            let p1_state = p1_state.to_round_two(p1_my_encrypted_secret_shares, rng)?;
            let p2_state = p2_state.to_round_two(p2_my_encrypted_secret_shares, rng)?;
            let p3_state = p3_state.to_round_two(p3_my_encrypted_secret_shares, rng)?;

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
                Participant::<Secp256k1Sha256>::new_dealer(&params, 1, rng);
            let (p2, p2coeffs, dh_sk2) =
                Participant::<Secp256k1Sha256>::new_dealer(&params, 2, rng);
            let (p3, p3coeffs, dh_sk3) =
                Participant::<Secp256k1Sha256>::new_dealer(&params, 3, rng);

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
                DistributedKeyGeneration::<RoundOne, Secp256k1Sha256>::new_initial(
                    &params,
                    &dh_sk1,
                    &p1.index,
                    &p1coeffs,
                    &participants,
                    rng,
                )?;
            let p1_their_encrypted_secret_shares = p1_state.their_encrypted_secret_shares()?;

            let (p2_state, _participant_lists) =
                DistributedKeyGeneration::<RoundOne, Secp256k1Sha256>::new_initial(
                    &params,
                    &dh_sk2,
                    &p2.index,
                    &p2coeffs,
                    &participants,
                    rng,
                )?;
            let p2_their_encrypted_secret_shares = p2_state.their_encrypted_secret_shares()?;

            let (p3_state, _participant_lists) =
                DistributedKeyGeneration::<RoundOne, Secp256k1Sha256>::new_initial(
                    &params,
                    &dh_sk3,
                    &p3.index,
                    &p3coeffs,
                    &participants,
                    rng,
                )?;
            let p3_their_encrypted_secret_shares = p3_state.their_encrypted_secret_shares()?;

            let mut complaint: Complaint<Secp256k1Sha256>;

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
                    .to_round_two(p1_my_encrypted_secret_shares, rng)?;
                let p3_state = p3_state
                    .clone()
                    .to_round_two(p3_my_encrypted_secret_shares, rng)?;

                let complaints = p2_state
                    .clone()
                    .to_round_two(p2_my_encrypted_secret_shares, rng);
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
                    .to_round_two(p1_my_encrypted_secret_shares, rng)?;
                let p3_state = p3_state
                    .clone()
                    .to_round_two(p3_my_encrypted_secret_shares, rng)?;

                let complaints = p2_state
                    .clone()
                    .to_round_two(p2_my_encrypted_secret_shares, rng);
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
                let mut dh_key_bytes = Vec::new();
                dh_key.serialize_compressed(&mut dh_key_bytes).unwrap();
                let wrong_encrypted_secret_share = encrypt_share(
                    &SecretShare::<Secp256k1Sha256> {
                        sender_index: 1,
                        receiver_index: 2,
                        polynomial_evaluation: Fr::from(42u32),
                    },
                    &dh_key_bytes[..],
                    rng,
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
                    .to_round_two(p1_my_encrypted_secret_shares, rng)?;
                let p3_state = p3_state
                    .clone()
                    .to_round_two(p3_my_encrypted_secret_shares, rng)?;

                let complaints = p2_state
                    .clone()
                    .to_round_two(p2_my_encrypted_secret_shares, rng);
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
                    .to_round_two(p3_my_encrypted_secret_shares, rng)?;

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

            let (p1, p1coeffs, p1_dh_sk) = Participant::new_dealer(&params, 1, rng);
            let (p2, p2coeffs, p2_dh_sk) = Participant::new_dealer(&params, 2, rng);
            let (p3, p3coeffs, p3_dh_sk) = Participant::new_dealer(&params, 3, rng);

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
                DistributedKeyGeneration::<RoundOne, Secp256k1Sha256>::new_initial(
                    &params,
                    &p1_dh_sk,
                    &p1.index,
                    &p1coeffs,
                    &participants,
                    rng,
                )?;
            let p1_their_encrypted_secret_shares = p1_state.their_encrypted_secret_shares()?;

            let (p2_state, _participant_lists) =
                DistributedKeyGeneration::<RoundOne, Secp256k1Sha256>::new_initial(
                    &params,
                    &p2_dh_sk,
                    &p2.index,
                    &p2coeffs,
                    &participants,
                    rng,
                )?;
            let p2_their_encrypted_secret_shares = p2_state.their_encrypted_secret_shares()?;

            let (p3_state, _participant_lists) =
                DistributedKeyGeneration::<RoundOne, Secp256k1Sha256>::new_initial(
                    &params,
                    &p3_dh_sk,
                    &p3.index,
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

                // Check serialisation

                let bytes = p1.to_bytes()?;
                assert_eq!(p1, Participant::from_bytes(&bytes)?);

                let bytes = p1coeffs.to_bytes()?;
                let p1coeffs_deserialised = Coefficients::from_bytes(&bytes)?;
                assert_eq!(p1coeffs.0.len(), p1coeffs_deserialised.0.len());
                for i in 0..p1coeffs.0.len() {
                    assert_eq!(p1coeffs.0[i], p1coeffs_deserialised.0[i]);
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
                    .to_round_two(p1_my_encrypted_secret_shares, rng)?;
                let p2_state = p2_state
                    .clone()
                    .to_round_two(p2_my_encrypted_secret_shares, rng)?;
                let p3_state = p3_state
                    .clone()
                    .to_round_two(p3_my_encrypted_secret_shares, rng)?;

                let (p1_group_key, _p1_secret_key) = p1_state.clone().finish()?;
                let (p2_group_key, _p2_secret_key) = p2_state.finish()?;
                let (p3_group_key, _p3_secret_key) = p3_state.finish()?;

                assert!(p1_group_key.key == p2_group_key.key);
                assert!(p2_group_key.key == p3_group_key.key);

                // Check serialisation
                let bytes = p1_group_key.to_bytes()?;
                assert_eq!(p1_group_key, GroupKey::from_bytes(&bytes)?);

                let bytes = p1_state.to_bytes()?;
                assert_eq!(
                    *p1_state.state,
                    *DistributedKeyGeneration::<RoundTwo, Secp256k1Sha256>::from_bytes(&bytes)?
                        .state
                );
            }

            {
                let wrong_encrypted_secret_share =
                    EncryptedSecretShare::new(1, 2, [0; 16], vec![0]);

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

                let p1_state = p1_state.to_round_two(p1_my_encrypted_secret_shares, rng)?;
                let p3_state = p3_state.to_round_two(p3_my_encrypted_secret_shares, rng)?;

                let complaints = p2_state.to_round_two(p2_my_encrypted_secret_shares, rng);
                assert!(complaints.is_err());
                let complaints = complaints.unwrap_err();
                if let Error::Complaint(complaints) = complaints {
                    assert!(complaints.len() == 1);

                    let bad_index = p3_state.blame(&wrong_encrypted_secret_share, &complaints[0]);

                    assert!(bad_index == 1);

                    let (p1_group_key, _p1_secret_key) = p1_state.finish()?;
                    let (p3_group_key, _p3_secret_key) = p3_state.finish()?;

                    assert!(p1_group_key == p3_group_key);

                    // Check serialisation

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
                Participant::<Secp256k1Sha256>::new_dealer(&params, 1, rng);
            let (p2, p2coeffs, p2_dh_sk) =
                Participant::<Secp256k1Sha256>::new_dealer(&params, 2, rng);
            let (p3, p3coeffs, p3_dh_sk) =
                Participant::<Secp256k1Sha256>::new_dealer(&params, 3, rng);

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
                DistributedKeyGeneration::<RoundOne, Secp256k1Sha256>::new_initial(
                    &params,
                    &p1_dh_sk,
                    &p1.index,
                    &p1coeffs,
                    &participants,
                    rng,
                )?;
            let p1_their_encrypted_secret_shares = p1_state.their_encrypted_secret_shares()?;

            let (p2_state, _participant_lists) =
                DistributedKeyGeneration::<RoundOne, Secp256k1Sha256>::new_initial(
                    &params,
                    &p2_dh_sk,
                    &p2.index,
                    &p2coeffs,
                    &participants,
                    rng,
                )?;
            let p2_their_encrypted_secret_shares = p2_state.their_encrypted_secret_shares()?;

            let (p3_state, _participant_lists) =
                DistributedKeyGeneration::<RoundOne, Secp256k1Sha256>::new_initial(
                    &params,
                    &p3_dh_sk,
                    &p3.index,
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

            let p1_state = p1_state.to_round_two(p1_my_encrypted_secret_shares, rng)?;
            let p2_state = p2_state.to_round_two(p2_my_encrypted_secret_shares, rng)?;
            let p3_state = p3_state.to_round_two(p3_my_encrypted_secret_shares, rng)?;

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
