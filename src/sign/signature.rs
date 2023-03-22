//! FROST signatures and their creation.

use ark_ec::CurveGroup;
use ark_ff::Field;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use core::cmp::Ordering;
use core::ops::{Deref, DerefMut};

use crate::error::Error;
use crate::utils::{
    calculate_lagrange_coefficients, compute_challenge, hash_to_bytes, hash_to_field,
};
use crate::utils::{BTreeMap, Box, ToString, Vec};

use crate::keys::{GroupKey, IndividualSigningKey, IndividualVerifyingKey};
use crate::parameters::ThresholdParameters;

use super::precomputation::SecretCommitmentShareList;

/// An individual signer in the threshold signature scheme.
#[derive(Clone, Copy, Debug, Eq, CanonicalDeserialize, CanonicalSerialize)]
pub struct Signer<G: CurveGroup> {
    /// The participant index of this signer.
    pub participant_index: u32,
    /// One of the commitments that were published by each signing participant
    /// in the pre-computation phase.
    pub published_commitment_share: (G, G),
}

impl<G: CurveGroup> Ord for Signer<G> {
    fn cmp(&self, other: &Signer<G>) -> Ordering {
        self.partial_cmp(other).unwrap()
    }
}

impl<G: CurveGroup> PartialOrd for Signer<G> {
    fn partial_cmp(&self, other: &Signer<G>) -> Option<Ordering> {
        match self.participant_index.cmp(&other.participant_index) {
            Ordering::Less => Some(Ordering::Less),
            // WARNING: Participants cannot have identical indices, so dedup() MUST be called.
            Ordering::Equal => Some(Ordering::Equal),
            Ordering::Greater => Some(Ordering::Greater),
        }
    }
}

impl<G: CurveGroup> PartialEq for Signer<G> {
    fn eq(&self, other: &Signer<G>) -> bool {
        self.participant_index == other.participant_index
    }
}

/// A partially-constructed threshold signature, made by each participant in the
/// signing protocol during the first phase of a signature creation.
#[derive(Debug, Eq, PartialEq, CanonicalDeserialize, CanonicalSerialize)]
pub struct PartialThresholdSignature<G: CurveGroup> {
    pub(crate) index: u32,
    pub(crate) z: G::ScalarField,
}

impl<G: CurveGroup> PartialThresholdSignature<G> {
    /// Serialize this `PartialThresholdSignature` to a vector of bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error<G>> {
        let mut bytes = Vec::new();

        self.serialize_compressed(&mut bytes)
            .map_err(|_| Error::SerialisationError)?;

        Ok(bytes)
    }

    /// Attempt to deserialize a `PartialThresholdSignature` from a vector of bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error<G>> {
        Self::deserialize_compressed(bytes).map_err(|_| Error::DeserialisationError)
    }
}

/// A complete, aggregated threshold signature.
#[derive(Debug, Eq, PartialEq, CanonicalDeserialize, CanonicalSerialize)]
pub struct ThresholdSignature<G: CurveGroup> {
    pub(crate) R: G,
    pub(crate) z: G::ScalarField,
}

impl<G: CurveGroup> ThresholdSignature<G> {
    /// Serialize this `ThresholdSignature` to a vector of bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error<G>> {
        let mut bytes = Vec::new();

        self.serialize_compressed(&mut bytes)
            .map_err(|_| Error::SerialisationError)?;

        Ok(bytes)
    }

    /// Attempt to deserialize a `ThresholdSignature` from a vector of bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error<G>> {
        Self::deserialize_compressed(bytes).map_err(|_| Error::DeserialisationError)
    }
}

/// A struct for storing signers' R values with the signer's participant index.
#[derive(Debug, Default, CanonicalDeserialize, CanonicalSerialize)]
struct SignerRs<G: CurveGroup>(pub(crate) BTreeMap<u32, G>);

impl<G: CurveGroup> SignerRs<G> {
    pub fn new() -> Self {
        Self(BTreeMap::new())
    }
}

impl<G: CurveGroup> Deref for SignerRs<G> {
    type Target = BTreeMap<u32, G>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<G: CurveGroup> DerefMut for SignerRs<G> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

/// A type for storing signers' partial threshold signatures along with the
/// respective signer participant index.
#[derive(Debug, Default, CanonicalDeserialize, CanonicalSerialize)]
pub(crate) struct PartialThresholdSignatures<G: CurveGroup>(
    pub(crate) BTreeMap<u32, G::ScalarField>,
);

impl<G: CurveGroup> PartialThresholdSignatures<G> {
    pub fn new() -> Self {
        Self(BTreeMap::new())
    }
}

impl<G: CurveGroup> Deref for PartialThresholdSignatures<G> {
    type Target = BTreeMap<u32, G::ScalarField>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<G: CurveGroup> DerefMut for PartialThresholdSignatures<G> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

/// A type for storing signers' individual public keys along with the respective
/// signer participant index.
#[derive(Debug, Default, CanonicalDeserialize, CanonicalSerialize)]
pub(crate) struct IndividualPublicKeys<G: CurveGroup>(pub(crate) BTreeMap<u32, G>);

impl<G: CurveGroup> IndividualPublicKeys<G> {
    pub fn new() -> Self {
        Self(BTreeMap::new())
    }
}

impl<G: CurveGroup> Deref for IndividualPublicKeys<G> {
    type Target = BTreeMap<u32, G>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<G: CurveGroup> DerefMut for IndividualPublicKeys<G> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

fn compute_binding_factors_and_group_commitment<G: CurveGroup>(
    message_hash: &[u8],
    signers: &[Signer<G>],
) -> (BTreeMap<u32, G::ScalarField>, SignerRs<G>) {
    let mut binding_factors: BTreeMap<u32, G::ScalarField> = BTreeMap::new();
    let mut Rs = SignerRs::<G>::new();

    let context_string = "FROST-Sha256";
    let mut message = message_hash.to_vec();

    // [DIFFERENT_TO_PAPER] We add the set of participants (in the paper
    // B = <(i, D_{ij}, E_(ij))> i \E S) here to avoid rehashing them over and
    // over again.
    for signer in signers.iter() {
        let hiding = signer.published_commitment_share.0;
        let binding = signer.published_commitment_share.1;

        message.extend(&signer.participant_index.to_be_bytes());
        // TODO Error instead
        hiding.serialize_compressed(&mut message).unwrap();
        binding.serialize_compressed(&mut message).unwrap();
    }

    for signer in signers.iter() {
        let hiding = signer.published_commitment_share.0;
        let binding = signer.published_commitment_share.1;

        let mut message_prime = message.clone();

        message_prime.extend(&signer.participant_index.to_be_bytes());
        // TODO Error instead
        hiding.serialize_compressed(&mut message_prime).unwrap();
        binding.serialize_compressed(&mut message_prime).unwrap();

        let binding_factor = hash_to_field::<G>(context_string.as_bytes(), &message_prime).unwrap(); // This is rho in the paper.

        Rs.insert(
            signer.participant_index,
            hiding + binding.mul(binding_factor),
        );
        binding_factors.insert(signer.participant_index, binding_factor);
    }
    (binding_factors, Rs)
}

impl<G: CurveGroup> IndividualSigningKey<G> {
    /// Compute an individual signer's [`PartialThresholdSignature`] contribution to
    /// a [`ThresholdSignature`] on a `message`.
    ///
    /// # Inputs
    ///
    /// * The `message_hash` to be signed by every individual signer, this should be
    ///   the `Sha256` digest of the message, optionally along with some application-specific
    ///   context string, and can be calculated with the helper function
    ///   [`compute_challenge`].
    /// * The public [`GroupKey`] for this group of signing participants,
    /// * This signer's [`SecretCommitmentShareList`] being used in this instantiation and
    /// * The index of the particular `CommitmentShare` being used, and
    /// * The list of all the currently participating [`Signer`]s (including ourself).
    ///
    /// # Warning
    ///
    /// The secret share `index` here **must** be the same secret share
    /// corresponding to its public commitment which is passed to
    /// `SignatureAggregrator.include_signer()`.
    ///
    /// # Returns
    ///
    /// A Result whose `Ok` value contains a [`PartialThresholdSignature`], which
    /// should be sent to the [`SignatureAggregator`].  Otherwise, its `Err` value contains
    /// a string describing the error which occurred.
    pub fn sign(
        &self,
        message_hash: &[u8],
        group_key: &GroupKey<G>,
        my_secret_commitment_share_list: &mut SecretCommitmentShareList<G>,
        my_commitment_share_index: usize,
        signers: &[Signer<G>],
    ) -> Result<PartialThresholdSignature<G>, Error<G>> {
        if my_commitment_share_index + 1 > my_secret_commitment_share_list.commitments.len() {
            return Err(Error::MissingCommitmentShares);
        }

        let (binding_factors, Rs) =
            compute_binding_factors_and_group_commitment(message_hash, signers);
        let R: G = Rs.values().sum();
        let challenge =
            compute_challenge(message_hash, group_key, &R).map_err(|_| Error::InvalidChallenge)?;
        let my_binding_factor = binding_factors
            .get(&self.index)
            .ok_or(Error::InvalidBindingFactor)?;
        let all_participant_indices: Vec<u32> =
            signers.iter().map(|x| x.participant_index).collect();
        let lambda: G::ScalarField =
            calculate_lagrange_coefficients::<G>(self.index, &all_participant_indices)
                .map_err(|e| Error::Custom(e.to_string()))?;
        let my_commitment_share =
            my_secret_commitment_share_list.commitments[my_commitment_share_index].clone();
        let z = my_commitment_share.hiding.secret
            + (my_commitment_share.binding.secret * my_binding_factor)
            + (lambda * self.key * challenge);

        // Zero out our secrets from memory to prevent nonce reuse.
        my_secret_commitment_share_list.drop_share(my_commitment_share);

        Ok(PartialThresholdSignature {
            index: self.index,
            z,
        })
    }
}

/// A signature aggregator, in any of various states.
pub trait Aggregator {}

/// The internal state of a signature aggregator.
#[derive(Debug, CanonicalDeserialize, CanonicalSerialize)]
pub(crate) struct AggregatorState<G: CurveGroup> {
    /// The protocol instance parameters.
    pub(crate) parameters: ThresholdParameters<G>,
    /// The set of signing participants for this round.
    pub(crate) signers: Vec<Signer<G>>,
    /// The signer's public keys for verifying their [`PartialThresholdSignature`].
    pub(crate) public_keys: IndividualPublicKeys<G>,
    /// The partial signatures from individual participants which have been
    /// collected thus far.
    pub(crate) partial_signatures: PartialThresholdSignatures<G>,
    /// The group public key for all the participants.
    pub(crate) group_key: GroupKey<G>,
}

/// A signature aggregator is an untrusted party who coalesces all of the
/// participating signers' published commitment shares and their
/// [`PartialThresholdSignature`] and creates the final [`ThresholdSignature`].
/// The signature aggregator may even be one of the \\(t\\) participants in this
/// signing operation.
#[derive(Debug)]
pub struct SignatureAggregator<A: Aggregator, G: CurveGroup> {
    /// The aggregator's actual state, shared across types.
    pub(crate) state: Box<AggregatorState<G>>,
    /// The aggregator's additional state.
    pub(crate) aggregator: A,
}

/// The initial state for a [`SignatureAggregator`], which may include invalid
/// or non-sensical data.
#[derive(Debug)]
pub struct Initial<'sa> {
    /// An optional context string for computing the message hash.
    pub(crate) context: &'sa [u8],
    /// The message to be signed.
    pub(crate) message: &'sa [u8],
}

impl Aggregator for Initial<'_> {}

/// The finalized state for a [`SignatureAggregator`], which has thoroughly
/// validated its data.
///
/// # Guarantees
///
/// * There are no duplicate signing attempts from the same individual signer.
/// * All expected signers have contributed a partial signature.
/// * All expected signers have a public key.
///
/// This leaves only one remaining failure mode for the actual aggregation of
/// the partial signatures:
///
/// * Any signer could have contributed a malformed partial signature.
#[derive(Debug)]
pub struct Finalized {
    /// The hashed context and message for signing.
    pub(crate) message_hash: Vec<u8>,
}

impl Aggregator for Finalized {}

impl<G: CurveGroup> SignatureAggregator<Initial<'_>, G> {
    /// Construct a new signature aggregator from some protocol instantiation
    /// `parameters` and a `message` to be signed.
    ///
    /// # Inputs
    ///
    /// * The [`ThresholdParameters`] for this threshold signing operation,
    /// * The public [`GroupKey`] for the intended sets of signers,
    /// * An optional `context` string for computing the message hash,
    /// * The `message` to be signed.
    ///
    /// # Notes
    ///
    /// The `context` and the `message` string should be given to the aggregator
    /// so that all signers can query them before deciding whether or not to
    /// sign.
    ///
    /// # Returns
    ///
    /// A new [`SignatureAggregator`].
    pub fn new<'sa>(
        parameters: ThresholdParameters<G>,
        group_key: GroupKey<G>,
        context: &'sa [u8],
        message: &'sa [u8],
    ) -> SignatureAggregator<Initial<'sa>, G> {
        let signers: Vec<Signer<G>> = Vec::with_capacity(parameters.t as usize);
        let public_keys = IndividualPublicKeys::<G>::new();
        let partial_signatures = PartialThresholdSignatures::<G>::new();
        let state = AggregatorState {
            parameters,
            signers,
            public_keys,
            partial_signatures,
            group_key,
        };

        SignatureAggregator {
            state: Box::new(state),
            aggregator: Initial { context, message },
        }
    }

    /// Include a signer in the protocol.
    ///
    /// # Warning
    ///
    /// If this method is called for a specific participant, then that
    /// participant MUST provide a partial signature to give to
    /// [`SignatureAggregator.include_partial_signature`], otherwise the signing
    /// procedure will fail.
    ///
    /// # Panics
    ///
    /// If the `signer.participant_index` doesn't match the `public_key.index`.
    pub fn include_signer(
        &mut self,
        participant_index: u32,
        published_commitment_share: (G, G),
        public_key: IndividualVerifyingKey<G>,
    ) {
        assert_eq!(participant_index, public_key.index,
                   "Tried to add signer with participant index {}, but public key is for participant with index {}",
                   participant_index, public_key.index);

        self.state.signers.push(Signer {
            participant_index,
            published_commitment_share,
        });
        self.state
            .public_keys
            .insert(public_key.index, public_key.share);
    }

    /// Get the list of partipating signers.
    ///
    /// # Returns
    ///
    /// A `&Vec<Signer>` of the participating signers in this round.
    pub fn get_signers(&'_ mut self) -> &'_ Vec<Signer<G>> {
        self.state.signers.sort();
        self.state.signers.dedup();

        // Sanity check
        assert!(self.state.signers.len() <= self.state.parameters.n as usize);

        &self.state.signers
    }

    /// Helper function to get the remaining signers who were expected to sign,
    /// but have not yet contributed their [`PartialThresholdSignature`]s.
    ///
    /// This can be used by an honest aggregator who wishes to ensure that the
    /// aggregation procedure is ready to be run, or who wishes to be able to
    /// remind/poll individual signers for their [`PartialThresholdSignature`]
    /// contribution.
    ///
    /// # Returns
    ///
    /// A sorted `Vec` of unique [`Signer`]s who have yet to contribute their
    /// partial signatures.
    pub fn get_remaining_signers(&self) -> Vec<Signer<G>> {
        let mut remaining_signers: Vec<Signer<G>> = Vec::new();

        for signer in self.state.signers.iter() {
            if self
                .state
                .partial_signatures
                .get(&signer.participant_index)
                .is_none()
            {
                remaining_signers.push(*signer);
            }
        }
        remaining_signers.sort();
        remaining_signers.dedup();
        remaining_signers
    }

    /// Add a [`PartialThresholdSignature`] to be included in the aggregation.
    pub fn include_partial_signature(&mut self, partial_signature: PartialThresholdSignature<G>) {
        self.state
            .partial_signatures
            .insert(partial_signature.index, partial_signature.z);
    }

    /// Ensure that this signature aggregator is in a proper state to run the aggregation protocol.
    ///
    /// # Returns
    ///
    /// A Result whose Ok() value is a finalized aggregator, otherwise a
    /// `BTreeMap<u32, &'static str>` containing the participant indices of the misbehaving
    /// signers and a description of their misbehaviour.
    ///
    /// If the `BTreeMap` contains a key for `0`, this indicates that
    /// the aggregator did not have \(( t' \)) partial signers
    /// s.t. \(( t \le t' \le n \)).
    pub fn finalize(
        mut self,
    ) -> Result<SignatureAggregator<Finalized, G>, BTreeMap<u32, &'static str>> {
        let mut misbehaving_participants: BTreeMap<u32, &'static str> = BTreeMap::new();
        let remaining_signers = self.get_remaining_signers();

        // [DIFFERENT_TO_PAPER] We're reporting missing partial signatures which
        // could possibly be the fault of the aggregator, but here we explicitly
        // make it the aggregator's fault and problem.
        if !remaining_signers.is_empty() {
            // We call the aggregator "participant 0" for the sake of error messages.
            misbehaving_participants.insert(0, "Missing remaining signer(s)");

            for signer in remaining_signers.iter() {
                misbehaving_participants
                    .insert(signer.participant_index, "Missing partial signature");
            }
        }

        // Ensure that our new state is ordered and deduplicated.
        self.state.signers = self.get_signers().clone();

        for signer in self.state.signers.iter() {
            if self
                .state
                .public_keys
                .get(&signer.participant_index)
                .is_none()
            {
                misbehaving_participants.insert(signer.participant_index, "Missing public key");
            }
        }

        if !misbehaving_participants.is_empty() {
            return Err(misbehaving_participants);
        }

        let message_hash =
            hash_to_bytes::<G>(self.aggregator.context, self.aggregator.message).unwrap();

        Ok(SignatureAggregator {
            state: self.state,
            aggregator: Finalized { message_hash },
        })
    }
}

impl<G: CurveGroup> SignatureAggregator<Finalized, G> {
    /// Aggregate a set of previously-collected partial signatures.
    ///
    /// # Returns
    ///
    /// A Result whose Ok() value is a [`ThresholdSignature`], otherwise a
    /// `BTreeMap<u32, &'static str>` containing the participant indices of the misbehaving
    /// signers and a description of their misbehaviour.
    pub fn aggregate(&self) -> Result<ThresholdSignature<G>, BTreeMap<u32, &'static str>> {
        let mut misbehaving_participants: BTreeMap<u32, &'static str> = BTreeMap::new();

        let (_, Rs) = compute_binding_factors_and_group_commitment(
            &self.aggregator.message_hash,
            &self.state.signers,
        );
        let R: G = Rs.values().sum();
        let c = compute_challenge(&self.aggregator.message_hash, &self.state.group_key, &R)
            .expect("Could not compute a challenge");
        let all_participant_indices: Vec<u32> = self
            .state
            .signers
            .iter()
            .map(|x| x.participant_index)
            .collect();
        let mut z = G::ScalarField::ZERO;

        // We first combine all partial signatures together, to remove the need for individual
        // signature verification in case the final group signature is valid.
        for signer in self.state.signers.iter() {
            // This unwrap() cannot fail, because SignatureAggregator<Initial>.finalize()
            // checks that we have partial signature for every expected signer.
            let partial_sig = self
                .state
                .partial_signatures
                .get(&signer.participant_index)
                .unwrap();

            z += partial_sig;
        }

        let signature = ThresholdSignature { z, R };

        // Verify the obtained signature, listing malicious participants
        // if the verification failed.
        match signature.verify(&self.state.group_key, &self.aggregator.message_hash) {
            Ok(()) => Ok(signature),
            Err(_) => {
                for signer in self.state.signers.iter() {
                    // This unwrap() cannot fail, since the attempted division by zero in
                    // the calculation of the Lagrange interpolation cannot happen,
                    // because we use the typestate pattern,
                    // i.e. SignatureAggregator<Initial>.finalize(), to ensure that
                    // there are no duplicate signers, which is the only thing that
                    // would cause a denominator of zero.
                    let lambda = calculate_lagrange_coefficients::<G>(
                        signer.participant_index,
                        &all_participant_indices,
                    )
                    .unwrap();

                    // This cannot fail, and has already been performed previously.
                    let partial_sig = self
                        .state
                        .partial_signatures
                        .get(&signer.participant_index)
                        .unwrap();

                    // Again, this unwrap() cannot fail, because of the checks in finalize().
                    let Y_i = self
                        .state
                        .public_keys
                        .get(&signer.participant_index)
                        .unwrap();

                    let check = G::generator() * partial_sig;

                    // Again, this unwrap() cannot fail, because we check the
                    // participant indexes against the expected ones in finalize().
                    let R_i = Rs.get(&signer.participant_index).unwrap();

                    if check != *R_i + (Y_i.mul(c * lambda)) {
                        misbehaving_participants
                            .insert(signer.participant_index, "Incorrect partial signature");
                    }
                }
                Err(misbehaving_participants)
            }
        }
    }
}

impl<G: CurveGroup> ThresholdSignature<G> {
    /// Verify this [`ThresholdSignature`].
    ///
    /// # Returns
    ///
    /// A `Result` whose `Ok` value is an empty tuple if the threshold signature
    /// was successfully verified, otherwise a vector of the participant indices
    /// of any misbehaving participants.
    pub fn verify(&self, group_key: &GroupKey<G>, message_hash: &[u8]) -> Result<(), Error<G>> {
        let c_prime = compute_challenge(message_hash, group_key, &self.R)
            .map_err(|_| Error::InvalidChallenge)?;
        let R_prime: G = G::msm(
            &[G::generator().into(), (-group_key.0).into()],
            &[self.z, c_prime],
        )
        .map_err(|_| Error::InvalidSignature)?;

        match self.R == R_prime {
            true => Ok(()),
            false => Err(Error::InvalidSignature),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use crate::dkg::Participant;
    use crate::dkg::{DistributedKeyGeneration, RoundOne};
    use crate::sign::generate_commitment_share_lists;

    use ark_bn254::{Fr, G1Projective};

    use ark_ff::{UniformRand, Zero};
    use rand::rngs::OsRng;

    #[test]
    fn signing_and_verification_single_party() {
        let params = ThresholdParameters::<G1Projective>::new(1, 1);
        let mut rng = OsRng;

        let (p1, p1coeffs, p1_dh_sk) = Participant::new_dealer(&params, 1, "Φ", &mut rng);

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

        let (group_key, p1_sk) = result.unwrap();

        let context = b"CONTEXT STRING STOLEN FROM DALEK TEST SUITE";
        let message = b"This is a test of the tsunami alert system. This is only a test.";
        let (p1_public_comshares, mut p1_secret_comshares) =
            generate_commitment_share_lists(&mut OsRng, 1, 1);

        let mut aggregator =
            SignatureAggregator::new(params, group_key, &context[..], &message[..]);

        aggregator.include_signer(1, p1_public_comshares.commitments[0], (&p1_sk).into());

        let signers = aggregator.get_signers();
        let message_hash = hash_to_bytes::<G1Projective>(&context[..], &message[..]).unwrap();

        let p1_partial = p1_sk
            .sign(
                &message_hash,
                &group_key,
                &mut p1_secret_comshares,
                0,
                signers,
            )
            .unwrap();

        aggregator.include_partial_signature(p1_partial);

        let aggregator = aggregator.finalize().unwrap();
        let signing_result = aggregator.aggregate();

        assert!(signing_result.is_ok());

        let threshold_signature = signing_result.unwrap();
        let verification_result = threshold_signature.verify(&group_key, &message_hash);

        println!("{:?}", verification_result);

        assert!(verification_result.is_ok());
    }

    #[test]
    fn signing_and_verification_1_out_of_1() {
        let params = ThresholdParameters::<G1Projective>::new(1, 1);
        let mut rng = OsRng;

        let (p1, p1coeffs, p1_dh_sk) = Participant::new_dealer(&params, 1, "Φ", &mut rng);

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

        let (group_key, p1_sk) = p1_state.finish().unwrap();

        let context = b"CONTEXT STRING STOLEN FROM DALEK TEST SUITE";
        let message = b"This is a test of the tsunami alert system. This is only a test.";
        let (p1_public_comshares, mut p1_secret_comshares) =
            generate_commitment_share_lists(&mut OsRng, 1, 1);

        let mut aggregator =
            SignatureAggregator::new(params, group_key, &context[..], &message[..]);

        aggregator.include_signer(1, p1_public_comshares.commitments[0], (&p1_sk).into());

        let signers = aggregator.get_signers();
        let message_hash = hash_to_bytes::<G1Projective>(&context[..], &message[..]).unwrap();

        let p1_partial = p1_sk
            .sign(
                &message_hash,
                &group_key,
                &mut p1_secret_comshares,
                0,
                signers,
            )
            .unwrap();

        aggregator.include_partial_signature(p1_partial);

        let aggregator = aggregator.finalize().unwrap();
        let threshold_signature = aggregator.aggregate().unwrap();
        let verification_result = threshold_signature.verify(&group_key, &message_hash);

        assert!(verification_result.is_ok());
    }

    #[test]
    fn signing_and_verification_1_out_of_2() {
        let params = ThresholdParameters::<G1Projective>::new(2, 1);
        let mut rng = OsRng;

        let (p1, p1coeffs, p1_dh_sk) = Participant::new_dealer(&params, 1, "Φ", &mut rng);
        let (p2, p2coeffs, p2_dh_sk) = Participant::new_dealer(&params, 2, "Φ", &mut rng);

        let participants: Vec<Participant<G1Projective>> = vec![p1.clone(), p2.clone()];
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

        let p1_my_encrypted_secret_shares = vec![
            p1_their_encrypted_secret_shares[0].clone(),
            p2_their_encrypted_secret_shares[0].clone(),
        ];
        let p2_my_encrypted_secret_shares = vec![
            p1_their_encrypted_secret_shares[1].clone(),
            p2_their_encrypted_secret_shares[1].clone(),
        ];

        let p1_state = p1_state
            .to_round_two(p1_my_encrypted_secret_shares, &mut rng)
            .unwrap();
        let p2_state = p2_state
            .to_round_two(p2_my_encrypted_secret_shares, &mut rng)
            .unwrap();

        let (group_key, p1_sk) = p1_state.finish().unwrap();
        let (_, _p2_sk) = p2_state.finish().unwrap();

        let context = b"CONTEXT STRING STOLEN FROM DALEK TEST SUITE";
        let message = b"This is a test of the tsunami alert system. This is only a test.";
        let (p1_public_comshares, mut p1_secret_comshares) =
            generate_commitment_share_lists(&mut OsRng, 1, 1);

        let mut aggregator =
            SignatureAggregator::new(params, group_key, &context[..], &message[..]);

        aggregator.include_signer(1, p1_public_comshares.commitments[0], (&p1_sk).into());

        let signers = aggregator.get_signers();
        let message_hash = hash_to_bytes::<G1Projective>(&context[..], &message[..]).unwrap();

        let p1_partial = p1_sk
            .sign(
                &message_hash,
                &group_key,
                &mut p1_secret_comshares,
                0,
                signers,
            )
            .unwrap();

        aggregator.include_partial_signature(p1_partial);

        let aggregator = aggregator.finalize().unwrap();
        let threshold_signature = aggregator.aggregate().unwrap();
        let verification_result = threshold_signature.verify(&group_key, &message_hash);

        assert!(verification_result.is_ok());
    }

    #[test]
    fn signing_and_verification_3_out_of_5() {
        let params = ThresholdParameters::<G1Projective>::new(5, 3);
        let mut rng = OsRng;

        let (p1, p1coeffs, p1_dh_sk) = Participant::new_dealer(&params, 1, "Φ", &mut rng);
        let (p2, p2coeffs, p2_dh_sk) = Participant::new_dealer(&params, 2, "Φ", &mut rng);
        let (p3, p3coeffs, p3_dh_sk) = Participant::new_dealer(&params, 3, "Φ", &mut rng);
        let (p4, p4coeffs, p4_dh_sk) = Participant::new_dealer(&params, 4, "Φ", &mut rng);
        let (p5, p5coeffs, p5_dh_sk) = Participant::new_dealer(&params, 5, "Φ", &mut rng);

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

        let (group_key, p1_sk) = p1_state.finish().unwrap();
        let (_, _) = p2_state.finish().unwrap();
        let (_, p3_sk) = p3_state.finish().unwrap();
        let (_, p4_sk) = p4_state.finish().unwrap();
        let (_, _) = p5_state.finish().unwrap();

        let context = b"CONTEXT STRING STOLEN FROM DALEK TEST SUITE";
        let message = b"This is a test of the tsunami alert system. This is only a test.";
        let (p1_public_comshares, mut p1_secret_comshares) =
            generate_commitment_share_lists(&mut OsRng, 1, 1);
        let (p3_public_comshares, mut p3_secret_comshares) =
            generate_commitment_share_lists(&mut OsRng, 3, 1);
        let (p4_public_comshares, mut p4_secret_comshares) =
            generate_commitment_share_lists(&mut OsRng, 4, 1);

        let mut aggregator =
            SignatureAggregator::new(params, group_key, &context[..], &message[..]);

        aggregator.include_signer(1, p1_public_comshares.commitments[0], (&p1_sk).into());
        aggregator.include_signer(3, p3_public_comshares.commitments[0], (&p3_sk).into());
        aggregator.include_signer(4, p4_public_comshares.commitments[0], (&p4_sk).into());

        let signers = aggregator.get_signers();
        let message_hash = hash_to_bytes::<G1Projective>(&context[..], &message[..]).unwrap();

        let p1_partial = p1_sk
            .sign(
                &message_hash,
                &group_key,
                &mut p1_secret_comshares,
                0,
                signers,
            )
            .unwrap();
        let p3_partial = p3_sk
            .sign(
                &message_hash,
                &group_key,
                &mut p3_secret_comshares,
                0,
                signers,
            )
            .unwrap();
        let p4_partial = p4_sk
            .sign(
                &message_hash,
                &group_key,
                &mut p4_secret_comshares,
                0,
                signers,
            )
            .unwrap();

        aggregator.include_partial_signature(p1_partial);
        aggregator.include_partial_signature(p3_partial);
        aggregator.include_partial_signature(p4_partial);

        let aggregator = aggregator.finalize().unwrap();
        let threshold_signature = aggregator.aggregate().unwrap();
        let verification_result = threshold_signature.verify(&group_key, &message_hash);

        assert!(verification_result.is_ok());
    }

    #[test]
    fn signing_and_verification_2_out_of_3() {
        // TODO: refactor to generic function to use in all tests
        fn do_keygen() -> Result<
            (
                ThresholdParameters<G1Projective>,
                IndividualSigningKey<G1Projective>,
                IndividualSigningKey<G1Projective>,
                IndividualSigningKey<G1Projective>,
                GroupKey<G1Projective>,
            ),
            (),
        > {
            let params = ThresholdParameters::<G1Projective>::new(3, 2);
            let mut rng = OsRng;

            let (p1, p1coeffs, p1_dh_sk) = Participant::new_dealer(&params, 1, "Φ", &mut rng);
            let (p2, p2coeffs, p2_dh_sk) = Participant::new_dealer(&params, 2, "Φ", &mut rng);
            let (p3, p3coeffs, p3_dh_sk) = Participant::new_dealer(&params, 3, "Φ", &mut rng);

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

            Ok((
                params,
                p1_secret_key,
                p2_secret_key,
                p3_secret_key,
                p1_group_key,
            ))
        }
        let keygen_protocol = do_keygen();

        assert!(keygen_protocol.is_ok());

        let (params, p1_sk, p2_sk, _p3_sk, group_key) = keygen_protocol.unwrap();

        let context = b"CONTEXT STRING STOLEN FROM DALEK TEST SUITE";
        let message = b"This is a test of the tsunami alert system. This is only a test.";
        let (p1_public_comshares, mut p1_secret_comshares) =
            generate_commitment_share_lists(&mut OsRng, 1, 1);
        let (p2_public_comshares, mut p2_secret_comshares) =
            generate_commitment_share_lists(&mut OsRng, 2, 1);

        let mut aggregator =
            SignatureAggregator::new(params, group_key, &context[..], &message[..]);

        aggregator.include_signer(1, p1_public_comshares.commitments[0], (&p1_sk).into());
        aggregator.include_signer(2, p2_public_comshares.commitments[0], (&p2_sk).into());

        let signers = aggregator.get_signers();
        let message_hash = hash_to_bytes::<G1Projective>(&context[..], &message[..]).unwrap();

        let p1_partial = p1_sk
            .sign(
                &message_hash,
                &group_key,
                &mut p1_secret_comshares,
                0,
                signers,
            )
            .unwrap();
        let p2_partial = p2_sk
            .sign(
                &message_hash,
                &group_key,
                &mut p2_secret_comshares,
                0,
                signers,
            )
            .unwrap();

        aggregator.include_partial_signature(p1_partial);
        aggregator.include_partial_signature(p2_partial);

        let aggregator = aggregator.finalize().unwrap();
        let signing_result = aggregator.aggregate();

        assert!(signing_result.is_ok());

        let threshold_signature = signing_result.unwrap();
        let verification_result = threshold_signature.verify(&group_key, &message_hash);

        println!("{:?}", verification_result);

        assert!(verification_result.is_ok());
    }

    #[test]
    fn signing_and_verification_static_2_out_of_3() {
        #[allow(clippy::type_complexity)]
        fn do_keygen() -> Result<
            (
                ThresholdParameters<G1Projective>,
                IndividualSigningKey<G1Projective>,
                IndividualSigningKey<G1Projective>,
                IndividualSigningKey<G1Projective>,
                IndividualSigningKey<G1Projective>,
                IndividualSigningKey<G1Projective>,
                IndividualSigningKey<G1Projective>,
                GroupKey<G1Projective>,
            ),
            (),
        > {
            let params = ThresholdParameters::<G1Projective>::new(3, 2);
            let mut rng = OsRng;

            let (dealer1, dealer1coeffs, dealer1_dh_sk) =
                Participant::new_dealer(&params, 1, "Φ", &mut rng);
            let (dealer2, dealer2coeffs, dealer2_dh_sk) =
                Participant::new_dealer(&params, 2, "Φ", &mut rng);
            let (dealer3, dealer3coeffs, dealer3_dh_sk) =
                Participant::new_dealer(&params, 3, "Φ", &mut rng);

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
            let (signer3, signer3_dh_sk) = Participant::new_signer(&params, 3, "Φ", &mut rng);

            let signers: Vec<Participant<G1Projective>> =
                vec![signer1.clone(), signer2.clone(), signer3.clone()];

            let (dealer1_for_signers, dealer1_encrypted_shares_for_signers, _participant_lists) =
                Participant::reshare(&params, dealer1_secret_key.clone(), &signers, "Φ", &mut rng)
                    .map_err(|_| ())?;
            let (dealer2_for_signers, dealer2_encrypted_shares_for_signers, _participant_lists) =
                Participant::reshare(&params, dealer2_secret_key.clone(), &signers, "Φ", &mut rng)
                    .map_err(|_| ())?;
            let (dealer3_for_signers, dealer3_encrypted_shares_for_signers, _participant_lists) =
                Participant::reshare(&params, dealer3_secret_key.clone(), &signers, "Φ", &mut rng)
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

            let (signer1_group_key, signer1_secret_key) = signer1_state.finish().or(Err(()))?;
            let (signer2_group_key, signer2_secret_key) = signer2_state.finish().or(Err(()))?;
            let (signer3_group_key, signer3_secret_key) = signer3_state.finish().or(Err(()))?;

            assert!(signer1_group_key.0.into_affine() == signer2_group_key.0.into_affine());
            assert!(signer2_group_key.0.into_affine() == signer3_group_key.0.into_affine());

            assert!(signer1_group_key.0.into_affine() == dealer1_group_key.0.into_affine());

            Ok((
                params,
                dealer1_secret_key,
                dealer2_secret_key,
                dealer3_secret_key,
                signer1_secret_key,
                signer2_secret_key,
                signer3_secret_key,
                dealer1_group_key,
            ))
        }
        let keygen_protocol = do_keygen();

        assert!(keygen_protocol.is_ok());

        let (params, d1_sk, d2_sk, _d3_sk, s1_sk, s2_sk, _s3_sk, group_key) =
            keygen_protocol.unwrap();

        let context = b"CONTEXT STRING STOLEN FROM DALEK TEST SUITE";
        let message = b"This is a test of the tsunami alert system. This is only a test.";
        let (d1_public_comshares, mut d1_secret_comshares) =
            generate_commitment_share_lists(&mut OsRng, 1, 1);
        let (d2_public_comshares, mut d2_secret_comshares) =
            generate_commitment_share_lists(&mut OsRng, 2, 1);

        let mut aggregator =
            SignatureAggregator::new(params, group_key, &context[..], &message[..]);

        aggregator.include_signer(1, d1_public_comshares.commitments[0], (&d1_sk).into());
        aggregator.include_signer(2, d2_public_comshares.commitments[0], (&d2_sk).into());

        let signers = aggregator.get_signers();
        let message_hash = hash_to_bytes::<G1Projective>(&context[..], &message[..]).unwrap();

        let d1_partial = d1_sk
            .sign(
                &message_hash,
                &group_key,
                &mut d1_secret_comshares,
                0,
                signers,
            )
            .unwrap();
        let d2_partial = d2_sk
            .sign(
                &message_hash,
                &group_key,
                &mut d2_secret_comshares,
                0,
                signers,
            )
            .unwrap();

        aggregator.include_partial_signature(d1_partial);
        aggregator.include_partial_signature(d2_partial);

        let aggregator = aggregator.finalize().unwrap();
        let signing_result = aggregator.aggregate();

        assert!(signing_result.is_ok());

        let threshold_signature = signing_result.unwrap();
        let verification_result = threshold_signature.verify(&group_key, &message_hash);

        println!("Dealer's signing session: {:?}", verification_result);

        let context = b"CONTEXT STRING STOLEN FROM DALEK TEST SUITE";
        let message = b"This is a test of the tsunami alert system. This is only a test.";
        let (s1_public_comshares, mut s1_secret_comshares) =
            generate_commitment_share_lists(&mut OsRng, 1, 1);
        let (s2_public_comshares, mut s2_secret_comshares) =
            generate_commitment_share_lists(&mut OsRng, 2, 1);

        let mut aggregator =
            SignatureAggregator::new(params, group_key, &context[..], &message[..]);

        aggregator.include_signer(1, s1_public_comshares.commitments[0], (&s1_sk).into());
        aggregator.include_signer(2, s2_public_comshares.commitments[0], (&s2_sk).into());

        let signers = aggregator.get_signers();
        let message_hash = hash_to_bytes::<G1Projective>(&context[..], &message[..]).unwrap();

        let s1_partial = s1_sk
            .sign(
                &message_hash,
                &group_key,
                &mut s1_secret_comshares,
                0,
                signers,
            )
            .unwrap();
        let s2_partial = s2_sk
            .sign(
                &message_hash,
                &group_key,
                &mut s2_secret_comshares,
                0,
                signers,
            )
            .unwrap();

        aggregator.include_partial_signature(s1_partial);
        aggregator.include_partial_signature(s2_partial);

        let aggregator = aggregator.finalize().unwrap();
        let signing_result = aggregator.aggregate();

        assert!(signing_result.is_ok());

        let threshold_signature = signing_result.unwrap();
        let verification_result = threshold_signature.verify(&group_key, &message_hash);

        println!("Signers's signing session: {:?}", verification_result);

        assert!(verification_result.is_ok());
    }

    #[test]
    fn signing_and_verification_static_2_out_of_3_into_3_out_of_5() {
        #[allow(clippy::type_complexity)]
        fn do_keygen() -> Result<
            (
                ThresholdParameters<G1Projective>,
                ThresholdParameters<G1Projective>,
                IndividualSigningKey<G1Projective>,
                IndividualSigningKey<G1Projective>,
                IndividualSigningKey<G1Projective>,
                IndividualSigningKey<G1Projective>,
                IndividualSigningKey<G1Projective>,
                IndividualSigningKey<G1Projective>,
                IndividualSigningKey<G1Projective>,
                IndividualSigningKey<G1Projective>,
                GroupKey<G1Projective>,
            ),
            (),
        > {
            let params_dealers = ThresholdParameters::<G1Projective>::new(3, 2);
            let mut rng = OsRng;

            let (dealer1, dealer1coeffs, dealer1_dh_sk) =
                Participant::new_dealer(&params_dealers, 1, "Φ", &mut rng);
            let (dealer2, dealer2coeffs, dealer2_dh_sk) =
                Participant::new_dealer(&params_dealers, 2, "Φ", &mut rng);
            let (dealer3, dealer3coeffs, dealer3_dh_sk) =
                Participant::new_dealer(&params_dealers, 3, "Φ", &mut rng);

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
                Participant::reshare(
                    &params_signers,
                    dealer1_secret_key.clone(),
                    &signers,
                    "Φ",
                    &mut rng,
                )
                .map_err(|_| ())?;
            let (dealer2_for_signers, dealer2_encrypted_shares_for_signers, _participant_lists) =
                Participant::reshare(
                    &params_signers,
                    dealer2_secret_key.clone(),
                    &signers,
                    "Φ",
                    &mut rng,
                )
                .map_err(|_| ())?;
            let (dealer3_for_signers, dealer3_encrypted_shares_for_signers, _participant_lists) =
                Participant::reshare(
                    &params_signers,
                    dealer3_secret_key.clone(),
                    &signers,
                    "Φ",
                    &mut rng,
                )
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

            let (signer1_group_key, signer1_secret_key) = signer1_state.finish().or(Err(()))?;
            let (signer2_group_key, signer2_secret_key) = signer2_state.finish().or(Err(()))?;
            let (signer3_group_key, signer3_secret_key) = signer3_state.finish().or(Err(()))?;
            let (signer4_group_key, signer4_secret_key) = signer4_state.finish().or(Err(()))?;
            let (signer5_group_key, signer5_secret_key) = signer5_state.finish().or(Err(()))?;

            assert!(signer1_group_key.0.into_affine() == signer2_group_key.0.into_affine());
            assert!(signer2_group_key.0.into_affine() == signer3_group_key.0.into_affine());
            assert!(signer3_group_key.0.into_affine() == signer4_group_key.0.into_affine());
            assert!(signer4_group_key.0.into_affine() == signer5_group_key.0.into_affine());

            assert!(signer1_group_key.0.into_affine() == dealer1_group_key.0.into_affine());

            Ok((
                params_dealers,
                params_signers,
                dealer1_secret_key,
                dealer2_secret_key,
                dealer3_secret_key,
                signer1_secret_key,
                signer2_secret_key,
                signer3_secret_key,
                signer4_secret_key,
                signer5_secret_key,
                dealer1_group_key,
            ))
        }
        let keygen_protocol = do_keygen();

        assert!(keygen_protocol.is_ok());

        let (
            d_params,
            s_params,
            d1_sk,
            d2_sk,
            _d3_sk,
            s1_sk,
            s2_sk,
            s3_sk,
            _s4_sk,
            _s5_sk,
            group_key,
        ) = keygen_protocol.unwrap();

        let context = b"CONTEXT STRING STOLEN FROM DALEK TEST SUITE";
        let message = b"This is a test of the tsunami alert system. This is only a test.";
        let (d1_public_comshares, mut d1_secret_comshares) =
            generate_commitment_share_lists(&mut OsRng, 1, 1);
        let (d2_public_comshares, mut d2_secret_comshares) =
            generate_commitment_share_lists(&mut OsRng, 2, 1);

        let mut aggregator =
            SignatureAggregator::new(d_params, group_key, &context[..], &message[..]);

        aggregator.include_signer(1, d1_public_comshares.commitments[0], (&d1_sk).into());
        aggregator.include_signer(2, d2_public_comshares.commitments[0], (&d2_sk).into());

        let signers = aggregator.get_signers();
        let message_hash = hash_to_bytes::<G1Projective>(&context[..], &message[..]).unwrap();

        let d1_partial = d1_sk
            .sign(
                &message_hash,
                &group_key,
                &mut d1_secret_comshares,
                0,
                signers,
            )
            .unwrap();
        let d2_partial = d2_sk
            .sign(
                &message_hash,
                &group_key,
                &mut d2_secret_comshares,
                0,
                signers,
            )
            .unwrap();

        aggregator.include_partial_signature(d1_partial);
        aggregator.include_partial_signature(d2_partial);

        let aggregator = aggregator.finalize().unwrap();
        let signing_result = aggregator.aggregate();

        assert!(signing_result.is_ok());

        let threshold_signature = signing_result.unwrap();
        let verification_result = threshold_signature.verify(&group_key, &message_hash);

        println!("Dealer's signing session: {:?}", verification_result);

        let context = b"CONTEXT STRING STOLEN FROM DALEK TEST SUITE";
        let message = b"This is a test of the tsunami alert system. This is only a test.";
        let (s1_public_comshares, mut s1_secret_comshares) =
            generate_commitment_share_lists(&mut OsRng, 1, 1);
        let (s2_public_comshares, mut s2_secret_comshares) =
            generate_commitment_share_lists(&mut OsRng, 2, 1);
        let (s3_public_comshares, mut s3_secret_comshares) =
            generate_commitment_share_lists(&mut OsRng, 3, 1);

        let mut aggregator =
            SignatureAggregator::new(s_params, group_key, &context[..], &message[..]);

        aggregator.include_signer(1, s1_public_comshares.commitments[0], (&s1_sk).into());
        aggregator.include_signer(2, s2_public_comshares.commitments[0], (&s2_sk).into());
        aggregator.include_signer(3, s3_public_comshares.commitments[0], (&s3_sk).into());

        let signers = aggregator.get_signers();
        let message_hash = hash_to_bytes::<G1Projective>(&context[..], &message[..]).unwrap();

        let s1_partial = s1_sk
            .sign(
                &message_hash,
                &group_key,
                &mut s1_secret_comshares,
                0,
                signers,
            )
            .unwrap();
        let s2_partial = s2_sk
            .sign(
                &message_hash,
                &group_key,
                &mut s2_secret_comshares,
                0,
                signers,
            )
            .unwrap();
        let s3_partial = s3_sk
            .sign(
                &message_hash,
                &group_key,
                &mut s3_secret_comshares,
                0,
                signers,
            )
            .unwrap();

        aggregator.include_partial_signature(s1_partial);
        aggregator.include_partial_signature(s2_partial);
        aggregator.include_partial_signature(s3_partial);

        let aggregator = aggregator.finalize().unwrap();
        let signing_result = aggregator.aggregate();

        assert!(signing_result.is_ok());

        let threshold_signature = signing_result.unwrap();
        let verification_result = threshold_signature.verify(&group_key, &message_hash);

        println!("Signers's signing session: {:?}", verification_result);

        assert!(verification_result.is_ok());
    }

    #[test]
    fn aggregator_get_signers() {
        let params = ThresholdParameters::<G1Projective>::new(3, 2);
        let context = b"CONTEXT STRING STOLEN FROM DALEK TEST SUITE";
        let message = b"This is a test of the tsunami alert system. This is only a test.";

        let (p1_public_comshares, _) = generate_commitment_share_lists(&mut OsRng, 1, 1);
        let (p2_public_comshares, _) = generate_commitment_share_lists(&mut OsRng, 2, 1);

        let mut aggregator = SignatureAggregator::new(
            params,
            GroupKey(G1Projective::zero()),
            &context[..],
            &message[..],
        );

        let p1_sk = IndividualSigningKey {
            index: 1,
            key: Fr::rand(&mut OsRng),
        };
        let p2_sk = IndividualSigningKey {
            index: 2,
            key: Fr::rand(&mut OsRng),
        };

        aggregator.include_signer(2, p2_public_comshares.commitments[0], (&p2_sk).into());
        aggregator.include_signer(1, p1_public_comshares.commitments[0], (&p1_sk).into());
        aggregator.include_signer(2, p2_public_comshares.commitments[0], (&p2_sk).into());

        let signers = aggregator.get_signers();

        // The signers should be deduplicated.
        assert!(signers.len() == 2);

        // The indices should match and be in sorted order.
        assert!(signers[0].participant_index == 1);
        assert!(signers[1].participant_index == 2);

        // Participant 1 should have the correct precomputed shares.
        assert!(signers[0].published_commitment_share.0 == p1_public_comshares.commitments[0].0);
        assert!(signers[0].published_commitment_share.1 == p1_public_comshares.commitments[0].1);

        // Same for participant 2.
        assert!(signers[1].published_commitment_share.0 == p2_public_comshares.commitments[0].0);
        assert!(signers[1].published_commitment_share.1 == p2_public_comshares.commitments[0].1);
    }

    // TODO: check serialisation
}
