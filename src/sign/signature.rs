//! The signature module defining an ICE-FROST signing
//! session, from individual partial signature creation to
//! their public aggregation.

use crate::ciphersuite::CipherSuite;
use crate::serialization::impl_serialization_traits;

use ark_ec::{Group, VariableBaseMSM};
use ark_ff::{Field, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use core::cmp::Ordering;
use core::ops::{Add, Deref, DerefMut, Mul};

use crate::utils::calculate_lagrange_coefficients;
use crate::utils::{BTreeMap, Box, Scalar, Vec};
use crate::{Error, FrostResult};

use crate::keys::{GroupVerifyingKey, IndividualSigningKey, IndividualVerifyingKey};
use crate::parameters::ThresholdParameters;

use super::precomputation::SecretCommitmentShareList;

/// An individual signer in the threshold signature scheme.
#[derive(Clone, Copy, Debug, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Signer<C: CipherSuite> {
    /// The participant index of this signer.
    pub participant_index: u32,
    /// One of the commitments that were published by each signing participant
    /// in the pre-computation phase.
    pub published_commitment_share: (C::G, C::G),
}

impl<C: CipherSuite> Ord for Signer<C> {
    fn cmp(&self, other: &Signer<C>) -> Ordering {
        match self.participant_index.cmp(&other.participant_index) {
            Ordering::Less => Ordering::Less,
            // WARNING: Distinct participants cannot have identical indices, so `dedup()` MUST be called.
            Ordering::Equal => Ordering::Equal,
            Ordering::Greater => Ordering::Greater,
        }
    }
}

impl<C: CipherSuite> PartialOrd for Signer<C> {
    fn partial_cmp(&self, other: &Signer<C>) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<C: CipherSuite> PartialEq for Signer<C> {
    fn eq(&self, other: &Signer<C>) -> bool {
        self.participant_index == other.participant_index
    }
}

/// A partially-constructed threshold signature, made by each participant in the
/// signing protocol during the first phase of a signature creation.
#[derive(Debug, Eq, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct PartialThresholdSignature<C: CipherSuite> {
    pub(crate) index: u32,
    pub(crate) z: Scalar<C>,
}

impl_serialization_traits!(PartialThresholdSignature<CipherSuite>);

/// A complete, aggregated threshold signature.
#[derive(Debug, Eq, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct ThresholdSignature<C: CipherSuite> {
    pub(crate) group_commitment: C::G,
    pub(crate) z: Scalar<C>,
}

impl_serialization_traits!(ThresholdSignature<CipherSuite>);

/// A struct for storing signers' binding factors with their index.
#[derive(Debug, Default, CanonicalSerialize, CanonicalDeserialize)]
struct BindingFactors<C: CipherSuite>(pub(crate) BTreeMap<u32, Scalar<C>>);

impl<C: CipherSuite> BindingFactors<C> {
    pub const fn new() -> Self {
        Self(BTreeMap::new())
    }
}

impl<C: CipherSuite> Deref for BindingFactors<C> {
    type Target = BTreeMap<u32, Scalar<C>>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<C: CipherSuite> DerefMut for BindingFactors<C> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

/// A type for storing signers' partial threshold signatures along with the
/// respective signer participant index.
#[derive(Debug, Default, CanonicalSerialize, CanonicalDeserialize)]
pub(crate) struct PartialThresholdSignatures<C: CipherSuite>(pub(crate) BTreeMap<u32, Scalar<C>>);

impl<C: CipherSuite> PartialThresholdSignatures<C> {
    pub const fn new() -> Self {
        Self(BTreeMap::new())
    }
}

impl<C: CipherSuite> Deref for PartialThresholdSignatures<C> {
    type Target = BTreeMap<u32, Scalar<C>>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<C: CipherSuite> DerefMut for PartialThresholdSignatures<C> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

/// A type for storing signers' individual public keys along with the respective
/// signer participant index.
#[derive(Debug, Default, CanonicalSerialize, CanonicalDeserialize)]
pub(crate) struct IndividualPublicKeys<C: CipherSuite>(pub(crate) BTreeMap<u32, C::G>);

impl<C: CipherSuite> IndividualPublicKeys<C> {
    pub const fn new() -> Self {
        Self(BTreeMap::new())
    }
}

impl<C: CipherSuite> Deref for IndividualPublicKeys<C> {
    type Target = BTreeMap<u32, C::G>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<C: CipherSuite> DerefMut for IndividualPublicKeys<C> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

fn encode_group_commitment_list<C: CipherSuite>(
    commitment_list: &[(u32, C::G, C::G)],
) -> FrostResult<C, Vec<u8>> {
    let mut encoded_group_commitment =
        Vec::with_capacity(commitment_list.len() * 2 * commitment_list[0].1.compressed_size());
    for (identifier, hiding_nonce_commitment, binding_nonce_commitment) in commitment_list {
        // RFC Note: identifier should be a ScalarField element that we serialize
        encoded_group_commitment.extend(&identifier.to_le_bytes()[..]);
        hiding_nonce_commitment
            .serialize_compressed(&mut encoded_group_commitment)
            .map_err(|_| Error::SerializationError)?;
        binding_nonce_commitment
            .serialize_compressed(&mut encoded_group_commitment)
            .map_err(|_| Error::SerializationError)?;
    }

    Ok(encoded_group_commitment)
}

fn compute_binding_factors<C: CipherSuite>(
    message: &[u8],
    signers: &[Signer<C>],
) -> FrostResult<C, BindingFactors<C>> {
    let mut binding_factor_list = BindingFactors::new();

    let mut msg_hash = C::h4(message).as_ref().to_vec();

    let mut commitment_list = Vec::with_capacity(signers.len());
    for signer in signers {
        let hiding = signer.published_commitment_share.0;
        let binding = signer.published_commitment_share.1;

        commitment_list.push((signer.participant_index, hiding, binding));
    }

    let encoded_comm_hash = C::h5(&encode_group_commitment_list::<C>(&commitment_list)?);
    // [`extend`] operates in place, hence msg_hash is now equal to [`rho_input_prefix`] .
    msg_hash.extend(encoded_comm_hash.as_ref());

    for (identifier, _, _) in &commitment_list {
        let mut rho_input = msg_hash.clone();
        // RFC Note: identifier should be a ScalarField element that we serialize
        rho_input.extend(&identifier.to_le_bytes()[..]);
        let binding_factor = C::h1(&rho_input);
        binding_factor_list.insert(*identifier, binding_factor);
    }

    Ok(binding_factor_list)
}

fn binding_factor_for_participant<C: CipherSuite>(
    participant_index: u32,
    binding_factor_list: &BTreeMap<u32, Scalar<C>>,
) -> FrostResult<C, Scalar<C>> {
    binding_factor_list
        .get(&participant_index)
        .ok_or(Error::InvalidBindingFactor)
        .copied()
}

fn commitment_for_participant<C: CipherSuite>(
    participant_index: u32,
    message: &[u8],
    signers: &[Signer<C>],
) -> FrostResult<C, C::G> {
    let mut msg_hash = C::h4(message).as_ref().to_vec();

    let mut commitment_list = Vec::with_capacity(signers.len());
    let (mut participant_hiding, mut participant_binding) = (C::G::zero(), C::G::zero());
    for signer in signers {
        let hiding = signer.published_commitment_share.0;
        let binding = signer.published_commitment_share.1;

        commitment_list.push((signer.participant_index, hiding, binding));

        if participant_index == signer.participant_index {
            (participant_hiding, participant_binding) = signer.published_commitment_share;
        }
    }

    let encoded_comm_hash = C::h5(&encode_group_commitment_list::<C>(&commitment_list)?);
    // [`extend`] operates in place, hence msg_hash is now equal to [`rho_input_prefix`] .
    msg_hash.extend(encoded_comm_hash.as_ref());

    let mut rho_input = msg_hash.clone();
    // RFC Note: identifier should be a ScalarField element that we serialize
    rho_input.extend(&participant_index.to_le_bytes()[..]);
    let binding_factor = C::h1(&rho_input);

    Ok(participant_hiding + participant_binding.mul(binding_factor))
}

fn compute_group_commitment<C: CipherSuite>(
    signers: &[Signer<C>],
    binding_factor_list: &BTreeMap<u32, Scalar<C>>,
) -> FrostResult<C, C::G> {
    let mut group_commitment = C::G::zero();

    for signer in signers {
        let hiding_nonce_commitment = signer.published_commitment_share.0;
        let binding_nonce_commitment = signer.published_commitment_share.1;

        let binding_factor =
            binding_factor_for_participant::<C>(signer.participant_index, binding_factor_list)?;
        group_commitment +=
            hiding_nonce_commitment.add(binding_nonce_commitment.mul(binding_factor));
    }

    Ok(group_commitment)
}

pub(crate) fn compute_challenge<C: CipherSuite>(
    group_commitment: &C::G,
    group_key: &GroupVerifyingKey<C>,
    message_hash: &[u8],
) -> FrostResult<C, Scalar<C>> {
    let mut challenge_input = Vec::with_capacity(
        group_commitment.compressed_size() + group_key.compressed_size() + message_hash.len(),
    );
    group_commitment
        .serialize_compressed(&mut challenge_input)
        .map_err(|_| Error::CompressionError)?;
    group_key
        .serialize_compressed(&mut challenge_input)
        .map_err(|_| Error::CompressionError)?;
    challenge_input.extend(message_hash);

    Ok(C::h2(&challenge_input))
}

impl<C: CipherSuite> IndividualSigningKey<C> {
    /// Compute an individual signer's [`PartialThresholdSignature`] contribution to
    /// a [`ThresholdSignature`] on a `message`.
    ///
    /// # Inputs
    ///
    /// * The `message_hash` to be signed by every individual signer. This can be computed
    ///   with the `h4` hasher of this instantiation's [`CipherSuite`].
    /// * The public [`GroupVerifyingKey`] for this group of signing participants,
    /// * This signer's [`SecretCommitmentShareList`] being used in this instantiation and
    /// * The index of the particular `CommitmentShare` being used, and
    /// * The list of all the currently participating [`Signer`]s (including ourself).
    ///
    /// # Warning
    ///
    /// The secret share `index` here **must** be the same secret share
    /// corresponding to its public commitment which is passed to
    /// [`SignatureAggregrator.include_signer()`] .
    ///
    /// # Returns
    ///
    /// A Result whose [`Ok`] value contains a [`PartialThresholdSignature`], which
    /// should be sent to the [`SignatureAggregator`].
    pub fn sign(
        &self,
        message_hash: &[u8],
        group_key: &GroupVerifyingKey<C>,
        my_secret_commitment_share_list: &mut SecretCommitmentShareList<C>,
        my_commitment_share_index: usize,
        signers: &[Signer<C>],
    ) -> FrostResult<C, PartialThresholdSignature<C>> {
        if my_commitment_share_index + 1 > my_secret_commitment_share_list.commitments.len() {
            return Err(Error::MissingCommitmentShares);
        }

        let binding_factor_list = compute_binding_factors(message_hash, signers)?;
        let binding_factor = binding_factor_for_participant::<C>(self.index, &binding_factor_list)?;

        let group_commitment = compute_group_commitment(signers, &binding_factor_list)?;

        let all_participant_indices: Vec<u32> =
            signers.iter().map(|x| x.participant_index).collect();
        let lambda: Scalar<C> =
            calculate_lagrange_coefficients::<C>(self.index, &all_participant_indices)?;

        let my_commitment_share =
            my_secret_commitment_share_list.commitments[my_commitment_share_index].clone();

        let challenge = compute_challenge::<C>(&group_commitment, group_key, message_hash)?;

        let z = my_commitment_share.hiding.secret
            + (my_commitment_share.binding.secret * binding_factor)
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
#[derive(Debug, CanonicalSerialize, CanonicalDeserialize)]
pub(crate) struct AggregatorState<C: CipherSuite> {
    /// The protocol instance parameters.
    pub(crate) parameters: ThresholdParameters<C>,
    /// The set of signing participants for this round.
    signers: Vec<Signer<C>>,
    /// The signer's public keys for verifying their [`PartialThresholdSignature`].
    pub(crate) public_keys: IndividualPublicKeys<C>,
    /// The partial signatures from individual participants which have been
    /// collected thus far.
    pub(crate) partial_signatures: PartialThresholdSignatures<C>,
    /// The group public key for all the participants.
    pub(crate) group_key: GroupVerifyingKey<C>,
}

/// A signature aggregator is an untrusted party who coalesces all of the
/// participating signers' published commitment shares and their
/// [`PartialThresholdSignature`] and creates the final [`ThresholdSignature`].
/// The signature aggregator may even be one of the \\(t\\) participants in this
/// signing operation.
#[derive(Debug)]
pub struct SignatureAggregator<C: CipherSuite, A: Aggregator> {
    /// The aggregator's actual state, shared across types.
    state: Box<AggregatorState<C>>,
    /// The aggregator's additional state.
    pub(crate) aggregator: A,
}

impl<C, A> SignatureAggregator<C, A>
where
    C: CipherSuite,
    A: Aggregator,
{
    /// Get the list of participating [`Signer`]s.
    ///
    /// # Returns
    ///
    /// A reference to the internal list of [`Signer`]s.
    pub fn signers(&self) -> &[Signer<C>] {
        &self.state.signers
    }
}

/// The initial state for a [`SignatureAggregator`], which may include invalid
/// or non-sensical data.
#[derive(Debug)]
pub struct Initial<'sa> {
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
pub struct Finalized<C: CipherSuite> {
    /// The hashed context and message for signing.
    pub(crate) message_hash: C::HashOutput,
}

impl<C: CipherSuite> Aggregator for Finalized<C> {}

impl<C: CipherSuite> SignatureAggregator<C, Initial<'_>> {
    /// Construct a new signature aggregator from some protocol instantiation
    /// `parameters` and a `message` to be signed.
    ///
    /// # Inputs
    ///
    /// * The [`ThresholdParameters`] for this threshold signing operation,
    /// * The public [`GroupVerifyingKey`] for the intended sets of signers,
    /// * The `message` to be signed.
    ///
    /// # Notes
    ///
    /// The `message` string should be given to the aggregator so that all
    /// signers can query it before deciding whether or not to sign.
    ///
    /// # Returns
    ///
    /// A new [`SignatureAggregator`].
    pub fn new(
        parameters: ThresholdParameters<C>,
        group_key: GroupVerifyingKey<C>,
        message: &[u8],
    ) -> SignatureAggregator<C, Initial<'_>> {
        let signers: Vec<Signer<C>> = Vec::with_capacity(parameters.t as usize);
        let public_keys = IndividualPublicKeys::<C>::new();
        let partial_signatures = PartialThresholdSignatures::<C>::new();
        let state = AggregatorState {
            parameters,
            signers,
            public_keys,
            partial_signatures,
            group_key,
        };

        SignatureAggregator {
            state: Box::new(state),
            aggregator: Initial { message },
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
    /// # Errors if the [`signer.participant_index`] does not match the
    /// [`public_key.index`] .
    pub fn include_signer(
        &mut self,
        participant_index: u32,
        published_commitment_share: (C::G, C::G),
        public_key: &IndividualVerifyingKey<C>,
    ) -> FrostResult<C, ()> {
        if participant_index != public_key.index {
            return Err(Error::IndexMismatch(participant_index, public_key.index));
        }

        self.state.signers.push(Signer {
            participant_index,
            published_commitment_share,
        });

        // Deduplicate partipating [`Signer`]s and check that there are no
        // more signers than participants as set in the [`ThresholdParameters`].
        self.state.signers.sort();
        self.state.signers.dedup();
        if self.state.signers.len() > self.state.parameters.n as usize {
            return Err(Error::TooManySigners(
                self.state.signers.len(),
                self.state.parameters.n,
            ));
        }

        self.state
            .public_keys
            .insert(public_key.index, public_key.share);
        Ok(())
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
    /// A sorted [`Vec`] of unique [`Signer`]s who have yet to contribute their
    /// partial signatures.
    #[must_use]
    pub fn remaining_signers(&self) -> Vec<Signer<C>> {
        let mut remaining_signers = Vec::with_capacity(self.signers().len());

        for signer in self.signers() {
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
    pub fn include_partial_signature(&mut self, partial_signature: &PartialThresholdSignature<C>) {
        self.state
            .partial_signatures
            .insert(partial_signature.index, partial_signature.z);
    }

    /// Ensure that this signature aggregator is in a proper state to run the aggregation protocol.
    ///
    /// # Returns
    ///
    /// A Result whose Ok() value is a finalized aggregator, otherwise a
    /// [`BTreeMap<u32, &'static str>`] containing the participant indices of the misbehaving
    /// signers and a description of their misbehaviour.
    ///
    /// If the [`BTreeMap`] contains a key for [`0`, this indicates that
    /// the aggregator did not have \(( t' \)) partial signers
    /// s.t. \(( t \le t' \le n \)).
    pub fn finalize(self) -> FrostResult<C, SignatureAggregator<C, Finalized<C>>> {
        let mut misbehaving_participants = Vec::new();
        let remaining_signers = self.remaining_signers();

        // We're reporting missing partial signatures which
        // could possibly be the fault of the aggregator, but here we explicitly
        // make it the aggregator's fault and problem.
        if !remaining_signers.is_empty() {
            // We call the aggregator "participant 0" for the sake of error messages.
            misbehaving_participants.push(0);

            for signer in &remaining_signers {
                misbehaving_participants.push(signer.participant_index);
            }
        }

        for signer in self.signers() {
            if self
                .state
                .public_keys
                .get(&signer.participant_index)
                .is_none()
            {
                misbehaving_participants.push(signer.participant_index);
            }
        }

        if !misbehaving_participants.is_empty() {
            return Err(Error::MisbehavingParticipants(misbehaving_participants));
        }

        let message_hash = C::h4(self.aggregator.message);

        Ok(SignatureAggregator {
            state: self.state,
            aggregator: Finalized { message_hash },
        })
    }
}

impl<C: CipherSuite> SignatureAggregator<C, Finalized<C>> {
    /// Aggregate a set of previously-collected partial signatures.
    ///
    /// # Returns
    ///
    /// A Result whose Ok() value is a [`ThresholdSignature`], otherwise a
    /// [`BTreeMap<u32, &'static str>`] containing the participant indices of the misbehaving
    /// signers and a description of their misbehaviour.
    pub fn aggregate(&self) -> FrostResult<C, ThresholdSignature<C>> {
        let binding_factor_list =
            compute_binding_factors(self.aggregator.message_hash.as_ref(), self.signers())?;
        let group_commitment = compute_group_commitment(self.signers(), &binding_factor_list)?;
        let challenge = compute_challenge::<C>(
            &group_commitment,
            &self.state.group_key,
            self.aggregator.message_hash.as_ref(),
        )?;

        let all_participant_indices: Vec<u32> = self
            .state
            .signers
            .iter()
            .map(|x| x.participant_index)
            .collect();

        let mut z = Scalar::<C>::ZERO;

        // We first combine all partial signatures together, to remove the need for individual
        // signature verification in case the final group signature is valid.
        for signer in self.signers() {
            let partial_sig = self
                .state
                .partial_signatures
                .get(&signer.participant_index)
                .expect("The SignatureAggregator ensured no partial signature was missing when calling finalize().");

            z += partial_sig;
        }

        let signature = ThresholdSignature {
            group_commitment,
            z,
        };

        // Verify the obtained signature, listing malicious participants
        // if the verification failed.
        if let Ok(()) =
            signature.verify(&self.state.group_key, self.aggregator.message_hash.as_ref())
        {
            Ok(signature)
        } else {
            let mut misbehaving_participants = Vec::new();
            for signer in self.signers() {
                // This cannot error, since the attempted division by zero in
                // the calculation of the Lagrange interpolation cannot happen,
                // because we use the typestate pattern,
                // i.e. [`SignatureAggregator<Initial>::finalize()`], to ensure that
                // there are no duplicate signers, which is the only thing that
                // would cause a denominator of zero.
                let lambda = calculate_lagrange_coefficients::<C>(
                    signer.participant_index,
                    &all_participant_indices,
                )?;

                let partial_sig = self
                    .state
                    .partial_signatures
                    .get(&signer.participant_index)
                    .expect("This has already been performed before.");

                let pk_i = self
                    .state
                    .public_keys
                    .get(&signer.participant_index)
                    .expect("This has already been checked when calling finalize().");

                let check = C::G::generator() * partial_sig;

                let participant_commitment = commitment_for_participant(
                    signer.participant_index,
                    self.aggregator.message_hash.as_ref(),
                    self.signers(),
                )?;

                if check != participant_commitment + (pk_i.mul(challenge * lambda)) {
                    misbehaving_participants.push(signer.participant_index);
                }
            }
            Err(Error::MisbehavingParticipants(misbehaving_participants))
        }
    }
}

impl<C: CipherSuite> ThresholdSignature<C> {
    /// Verify this [`ThresholdSignature`].
    ///
    /// # Returns
    ///
    /// A [`FrostResult`] whose [`Ok`] value indicates that the signature was computed correctly.
    pub fn verify(
        &self,
        group_key: &GroupVerifyingKey<C>,
        message_hash: &[u8],
    ) -> FrostResult<C, ()> {
        let challenge = compute_challenge::<C>(&self.group_commitment, group_key, message_hash)?;

        let retrieved_commitment: C::G = <C as CipherSuite>::G::msm(
            &[C::G::generator().into(), (-group_key.key).into()],
            &[self.z, challenge],
        )
        .map_err(|_| Error::InvalidSignature)?;

        if self.group_commitment == retrieved_commitment {
            Ok(())
        } else {
            Err(Error::InvalidSignature)
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use crate::dkg::test::do_keygen;
    use crate::dkg::Participant;
    use crate::dkg::{DistributedKeyGeneration, RoundOne};
    use crate::sign::{generate_commitment_share_lists, PublicCommitmentShareList};
    use crate::testing::Secp256k1Sha256;
    use crate::{FromBytes, ToBytes};

    use ark_secp256k1::{Fr, Projective};

    use ark_ff::UniformRand;
    use rand::rngs::OsRng;

    #[test]
    fn signing_and_verification_single_party() {
        let (params, signing_keys, group_key, _, _) = do_keygen(1, 1, None, None).unwrap();
        let p1_sk = signing_keys[0].clone();

        let message = b"This is a test of the tsunami alert system. This is only a test.";
        let (p1_public_comshares, mut p1_secret_comshares) =
            generate_commitment_share_lists(&mut OsRng, &p1_sk, 1).unwrap();

        let mut aggregator = SignatureAggregator::new(params, group_key, &message[..]);

        aggregator
            .include_signer(1, p1_public_comshares.commitments[0], &p1_sk.to_public())
            .unwrap();

        let message_hash = Secp256k1Sha256::h4(&message[..]);

        let p1_partial = p1_sk
            .sign(
                &message_hash,
                &group_key,
                &mut p1_secret_comshares,
                0,
                aggregator.signers(),
            )
            .unwrap();

        aggregator.include_partial_signature(&p1_partial);

        let aggregator = aggregator.finalize().unwrap();
        let signing_result = aggregator.aggregate();

        assert!(signing_result.is_ok());

        let threshold_signature = signing_result.unwrap();
        let verification_result1 = threshold_signature.verify(&group_key, &message_hash);
        let verification_result2 = group_key.verify_signature(&threshold_signature, &message_hash);

        assert!(verification_result1.is_ok());
        assert!(verification_result2.is_ok());
    }

    #[test]
    fn signing_and_verification_1_out_of_1() {
        let (params, signing_keys, group_key, _, _) = do_keygen(1, 1, None, None).unwrap();
        let p1_sk = signing_keys[0].clone();

        let message = b"This is a test of the tsunami alert system. This is only a test.";
        let (p1_public_comshares, mut p1_secret_comshares) =
            generate_commitment_share_lists(&mut OsRng, &p1_sk, 1).unwrap();

        let mut aggregator = SignatureAggregator::new(params, group_key, &message[..]);

        aggregator
            .include_signer(1, p1_public_comshares.commitments[0], &p1_sk.to_public())
            .unwrap();

        let message_hash = Secp256k1Sha256::h4(&message[..]);

        let p1_partial = p1_sk
            .sign(
                &message_hash,
                &group_key,
                &mut p1_secret_comshares,
                0,
                aggregator.signers(),
            )
            .unwrap();

        aggregator.include_partial_signature(&p1_partial);

        let aggregator = aggregator.finalize().unwrap();
        let threshold_signature = aggregator.aggregate().unwrap();
        let verification_result1 = threshold_signature.verify(&group_key, &message_hash);
        let verification_result2 = group_key.verify_signature(&threshold_signature, &message_hash);

        assert!(verification_result1.is_ok());
        assert!(verification_result2.is_ok());
    }

    #[test]
    fn signing_and_verification_1_out_of_2() {
        let (params, signing_keys, group_key, _, _) = do_keygen(2, 1, None, None).unwrap();
        let p1_sk = signing_keys[0].clone();

        let message = b"This is a test of the tsunami alert system. This is only a test.";
        let (p1_public_comshares, mut p1_secret_comshares) =
            generate_commitment_share_lists(&mut OsRng, &p1_sk, 1).unwrap();

        let mut aggregator = SignatureAggregator::new(params, group_key, &message[..]);

        aggregator
            .include_signer(1, p1_public_comshares.commitments[0], &p1_sk.to_public())
            .unwrap();

        let message_hash = Secp256k1Sha256::h4(&message[..]);

        let p1_partial = p1_sk
            .sign(
                &message_hash,
                &group_key,
                &mut p1_secret_comshares,
                0,
                aggregator.signers(),
            )
            .unwrap();

        aggregator.include_partial_signature(&p1_partial);

        let aggregator = aggregator.finalize().unwrap();
        let threshold_signature = aggregator.aggregate().unwrap();
        let verification_result1 = threshold_signature.verify(&group_key, &message_hash);
        let verification_result2 = group_key.verify_signature(&threshold_signature, &message_hash);

        assert!(verification_result1.is_ok());
        assert!(verification_result2.is_ok());
    }

    #[test]
    fn signing_and_verification_3_out_of_5() {
        let (params, signing_keys, group_key, _, _) = do_keygen(5, 3, None, None).unwrap();
        let p1_sk = signing_keys[0].clone();
        let p3_sk = signing_keys[2].clone();
        let p4_sk = signing_keys[3].clone();

        let message = b"This is a test of the tsunami alert system. This is only a test.";
        let (p1_public_comshares, mut p1_secret_comshares) =
            generate_commitment_share_lists(&mut OsRng, &p1_sk, 1).unwrap();
        let (p3_public_comshares, mut p3_secret_comshares) =
            generate_commitment_share_lists(&mut OsRng, &p3_sk, 1).unwrap();
        let (p4_public_comshares, mut p4_secret_comshares) =
            generate_commitment_share_lists(&mut OsRng, &p4_sk, 1).unwrap();

        let mut aggregator = SignatureAggregator::new(params, group_key, &message[..]);

        aggregator
            .include_signer(1, p1_public_comshares.commitments[0], &p1_sk.to_public())
            .unwrap();
        aggregator
            .include_signer(3, p3_public_comshares.commitments[0], &p3_sk.to_public())
            .unwrap();
        aggregator
            .include_signer(4, p4_public_comshares.commitments[0], &p4_sk.to_public())
            .unwrap();

        let message_hash = Secp256k1Sha256::h4(&message[..]);

        let p1_partial = p1_sk
            .sign(
                &message_hash,
                &group_key,
                &mut p1_secret_comshares,
                0,
                aggregator.signers(),
            )
            .unwrap();
        let p3_partial = p3_sk
            .sign(
                &message_hash,
                &group_key,
                &mut p3_secret_comshares,
                0,
                aggregator.signers(),
            )
            .unwrap();
        let p4_partial = p4_sk
            .sign(
                &message_hash,
                &group_key,
                &mut p4_secret_comshares,
                0,
                aggregator.signers(),
            )
            .unwrap();

        aggregator.include_partial_signature(&p1_partial);
        aggregator.include_partial_signature(&p3_partial);
        aggregator.include_partial_signature(&p4_partial);

        let aggregator = aggregator.finalize().unwrap();
        let threshold_signature = aggregator.aggregate().unwrap();
        let verification_result1 = threshold_signature.verify(&group_key, &message_hash);
        let verification_result2 = group_key.verify_signature(&threshold_signature, &message_hash);

        assert!(verification_result1.is_ok());
        assert!(verification_result2.is_ok());
    }

    #[test]
    fn signing_and_verification_2_out_of_3() {
        let (params, signing_keys, group_key, _, _) = do_keygen(3, 2, None, None).unwrap();
        let p1_sk = signing_keys[0].clone();
        let p2_sk = signing_keys[1].clone();

        let message = b"This is a test of the tsunami alert system. This is only a test.";
        let (p1_public_comshares, mut p1_secret_comshares) =
            generate_commitment_share_lists(&mut OsRng, &p1_sk, 1).unwrap();
        let (p2_public_comshares, mut p2_secret_comshares) =
            generate_commitment_share_lists(&mut OsRng, &p2_sk, 1).unwrap();

        let mut aggregator = SignatureAggregator::new(params, group_key, &message[..]);

        aggregator
            .include_signer(1, p1_public_comshares.commitments[0], &p1_sk.to_public())
            .unwrap();
        aggregator
            .include_signer(2, p2_public_comshares.commitments[0], &p2_sk.to_public())
            .unwrap();

        let message_hash = Secp256k1Sha256::h4(&message[..]);

        let p1_partial = p1_sk
            .sign(
                &message_hash,
                &group_key,
                &mut p1_secret_comshares,
                0,
                aggregator.signers(),
            )
            .unwrap();
        let p2_partial = p2_sk
            .sign(
                &message_hash,
                &group_key,
                &mut p2_secret_comshares,
                0,
                aggregator.signers(),
            )
            .unwrap();

        aggregator.include_partial_signature(&p1_partial);
        aggregator.include_partial_signature(&p2_partial);

        let aggregator = aggregator.finalize().unwrap();
        let signing_result = aggregator.aggregate();

        assert!(signing_result.is_ok());

        let threshold_signature = signing_result.unwrap();
        let verification_result = threshold_signature.verify(&group_key, &message_hash);

        assert!(verification_result.is_ok());
    }

    #[test]
    fn signing_and_verification_static_2_out_of_3() {
        if let (params, dealers_signing_keys, group_key, _, Some(signers_signing_keys)) =
            do_keygen(3, 2, Some(3), Some(2)).unwrap()
        {
            let d1_sk = dealers_signing_keys[0].clone();
            let d2_sk = dealers_signing_keys[1].clone();

            let s1_sk = signers_signing_keys[0].clone();
            let s2_sk = signers_signing_keys[1].clone();

            let message = b"This is a test of the tsunami alert system. This is only a test.";
            let (d1_public_comshares, mut d1_secret_comshares) =
                generate_commitment_share_lists(&mut OsRng, &d1_sk, 1).unwrap();
            let (d2_public_comshares, mut d2_secret_comshares) =
                generate_commitment_share_lists(&mut OsRng, &d2_sk, 1).unwrap();

            let mut aggregator = SignatureAggregator::new(params, group_key, &message[..]);

            aggregator
                .include_signer(1, d1_public_comshares.commitments[0], &d1_sk.to_public())
                .unwrap();
            aggregator
                .include_signer(2, d2_public_comshares.commitments[0], &d2_sk.to_public())
                .unwrap();

            let message_hash = Secp256k1Sha256::h4(&message[..]);

            let d1_partial = d1_sk
                .sign(
                    &message_hash,
                    &group_key,
                    &mut d1_secret_comshares,
                    0,
                    aggregator.signers(),
                )
                .unwrap();
            let d2_partial = d2_sk
                .sign(
                    &message_hash,
                    &group_key,
                    &mut d2_secret_comshares,
                    0,
                    aggregator.signers(),
                )
                .unwrap();

            aggregator.include_partial_signature(&d1_partial);
            aggregator.include_partial_signature(&d2_partial);

            let aggregator = aggregator.finalize().unwrap();
            let signing_result = aggregator.aggregate();

            assert!(signing_result.is_ok());

            let threshold_signature = signing_result.unwrap();
            let verification_result = threshold_signature.verify(&group_key, &message_hash);

            assert!(verification_result.is_ok());

            let message = b"This is a test of the tsunami alert system. This is only a test.";
            let (s1_public_comshares, mut s1_secret_comshares) =
                generate_commitment_share_lists(&mut OsRng, &s1_sk, 1).unwrap();
            let (s2_public_comshares, mut s2_secret_comshares) =
                generate_commitment_share_lists(&mut OsRng, &s2_sk, 1).unwrap();

            let mut aggregator = SignatureAggregator::new(params, group_key, &message[..]);

            aggregator
                .include_signer(1, s1_public_comshares.commitments[0], &s1_sk.to_public())
                .unwrap();
            aggregator
                .include_signer(2, s2_public_comshares.commitments[0], &s2_sk.to_public())
                .unwrap();

            let message_hash = Secp256k1Sha256::h4(&message[..]);

            let s1_partial = s1_sk
                .sign(
                    &message_hash,
                    &group_key,
                    &mut s1_secret_comshares,
                    0,
                    aggregator.signers(),
                )
                .unwrap();
            let s2_partial = s2_sk
                .sign(
                    &message_hash,
                    &group_key,
                    &mut s2_secret_comshares,
                    0,
                    aggregator.signers(),
                )
                .unwrap();

            aggregator.include_partial_signature(&s1_partial);
            aggregator.include_partial_signature(&s2_partial);

            let aggregator = aggregator.finalize().unwrap();
            let signing_result = aggregator.aggregate();

            assert!(signing_result.is_ok());

            let threshold_signature = signing_result.unwrap();
            let verification_result = threshold_signature.verify(&group_key, &message_hash);

            assert!(verification_result.is_ok());
        } else {
            panic!("Invalid DKG")
        }
    }

    #[test]
    fn signing_and_verification_static_2_out_of_3_into_3_out_of_5() {
        if let (
            d_params,
            dealers_signing_keys,
            group_key,
            Some(s_params),
            Some(signers_signing_keys),
        ) = do_keygen(3, 2, Some(5), Some(3)).unwrap()
        {
            let d1_sk = dealers_signing_keys[0].clone();
            let d2_sk = dealers_signing_keys[1].clone();

            let s1_sk = signers_signing_keys[0].clone();
            let s2_sk = signers_signing_keys[1].clone();
            let s3_sk = signers_signing_keys[2].clone();

            let message = b"This is a test of the tsunami alert system. This is only a test.";
            let (d1_public_comshares, mut d1_secret_comshares) =
                generate_commitment_share_lists(&mut OsRng, &d1_sk, 1).unwrap();
            let (d2_public_comshares, mut d2_secret_comshares) =
                generate_commitment_share_lists(&mut OsRng, &d2_sk, 1).unwrap();

            let mut aggregator = SignatureAggregator::new(d_params, group_key, &message[..]);

            aggregator
                .include_signer(1, d1_public_comshares.commitments[0], &d1_sk.to_public())
                .unwrap();
            aggregator
                .include_signer(2, d2_public_comshares.commitments[0], &d2_sk.to_public())
                .unwrap();

            let message_hash = Secp256k1Sha256::h4(&message[..]);

            let d1_partial = d1_sk
                .sign(
                    &message_hash,
                    &group_key,
                    &mut d1_secret_comshares,
                    0,
                    aggregator.signers(),
                )
                .unwrap();
            let d2_partial = d2_sk
                .sign(
                    &message_hash,
                    &group_key,
                    &mut d2_secret_comshares,
                    0,
                    aggregator.signers(),
                )
                .unwrap();

            aggregator.include_partial_signature(&d1_partial);
            aggregator.include_partial_signature(&d2_partial);

            let aggregator = aggregator.finalize().unwrap();
            let signing_result = aggregator.aggregate();

            assert!(signing_result.is_ok());

            let threshold_signature = signing_result.unwrap();
            let verification_result = threshold_signature.verify(&group_key, &message_hash);

            assert!(verification_result.is_ok());

            let message = b"This is a test of the tsunami alert system. This is only a test.";
            let (s1_public_comshares, mut s1_secret_comshares) =
                generate_commitment_share_lists(&mut OsRng, &s1_sk, 1).unwrap();
            let (s2_public_comshares, mut s2_secret_comshares) =
                generate_commitment_share_lists(&mut OsRng, &s2_sk, 1).unwrap();
            let (s3_public_comshares, mut s3_secret_comshares) =
                generate_commitment_share_lists(&mut OsRng, &s3_sk, 1).unwrap();

            let mut aggregator = SignatureAggregator::new(s_params, group_key, &message[..]);

            aggregator
                .include_signer(1, s1_public_comshares.commitments[0], &s1_sk.to_public())
                .unwrap();
            aggregator
                .include_signer(2, s2_public_comshares.commitments[0], &s2_sk.to_public())
                .unwrap();
            aggregator
                .include_signer(3, s3_public_comshares.commitments[0], &s3_sk.to_public())
                .unwrap();

            let message_hash = Secp256k1Sha256::h4(&message[..]);

            let s1_partial = s1_sk
                .sign(
                    &message_hash,
                    &group_key,
                    &mut s1_secret_comshares,
                    0,
                    aggregator.signers(),
                )
                .unwrap();
            let s2_partial = s2_sk
                .sign(
                    &message_hash,
                    &group_key,
                    &mut s2_secret_comshares,
                    0,
                    aggregator.signers(),
                )
                .unwrap();
            let s3_partial = s3_sk
                .sign(
                    &message_hash,
                    &group_key,
                    &mut s3_secret_comshares,
                    0,
                    aggregator.signers(),
                )
                .unwrap();

            aggregator.include_partial_signature(&s1_partial);
            aggregator.include_partial_signature(&s2_partial);
            aggregator.include_partial_signature(&s3_partial);

            let aggregator = aggregator.finalize().unwrap();
            let signing_result = aggregator.aggregate();

            assert!(signing_result.is_ok());

            let threshold_signature = signing_result.unwrap();
            let verification_result = threshold_signature.verify(&group_key, &message_hash);

            assert!(verification_result.is_ok());
        } else {
            panic!("Invalid DKG")
        }
    }

    #[test]
    fn aggregator_get_signers() {
        let params = ThresholdParameters::<Secp256k1Sha256>::new(3, 2).unwrap();
        let message = b"This is a test of the tsunami alert system. This is only a test.";

        let p1_sk = IndividualSigningKey {
            index: 1,
            key: Fr::rand(&mut OsRng),
        };
        let p2_sk = IndividualSigningKey {
            index: 2,
            key: Fr::rand(&mut OsRng),
        };

        let (p1_public_comshares, _) =
            generate_commitment_share_lists::<Secp256k1Sha256>(&mut OsRng, &p1_sk, 1).unwrap();
        let (p2_public_comshares, _) =
            generate_commitment_share_lists::<Secp256k1Sha256>(&mut OsRng, &p2_sk, 1).unwrap();

        let mut aggregator = SignatureAggregator::new(
            params,
            GroupVerifyingKey::new(Projective::zero()),
            &message[..],
        );

        aggregator
            .include_signer(2, p2_public_comshares.commitments[0], &p2_sk.to_public())
            .unwrap();
        aggregator
            .include_signer(1, p1_public_comshares.commitments[0], &p1_sk.to_public())
            .unwrap();
        aggregator
            .include_signer(2, p2_public_comshares.commitments[0], &p2_sk.to_public())
            .unwrap();

        let signers = aggregator.signers();

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

    #[test]
    fn signature_from_incomplete_set() {
        let params = ThresholdParameters::new(5, 3).unwrap();
        let rng = OsRng;

        // p1 will be malicious on the first round of the DKG
        let (mut p1, p1coeffs, dh_sk1) =
            Participant::<Secp256k1Sha256>::new_dealer(params, 1, rng).unwrap();
        p1.dh_public_key.key = p1.dh_public_key.double();

        let (p2, p2coeffs, dh_sk2) =
            Participant::<Secp256k1Sha256>::new_dealer(params, 2, rng).unwrap();
        let (p3, p3coeffs, dh_sk3) =
            Participant::<Secp256k1Sha256>::new_dealer(params, 3, rng).unwrap();
        let (p4, p4coeffs, dh_sk4) =
            Participant::<Secp256k1Sha256>::new_dealer(params, 4, rng).unwrap();
        let (p5, p5coeffs, dh_sk5) =
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
        let (_p1_state, _participant_lists) =
            DistributedKeyGeneration::<RoundOne, Secp256k1Sha256>::bootstrap(
                params,
                &dh_sk1,
                p1.index,
                &p1coeffs,
                &participants,
                rng,
            )
            .unwrap();

        let (p2_state, p2_participant_lists) =
            DistributedKeyGeneration::<RoundOne, Secp256k1Sha256>::bootstrap(
                params,
                &dh_sk2,
                p2.index,
                &p2coeffs,
                &participants,
                rng,
            )
            .unwrap();
        let p2_their_encrypted_secret_shares = p2_state.their_encrypted_secret_shares().unwrap();

        let (p3_state, p3_participant_lists) =
            DistributedKeyGeneration::<RoundOne, Secp256k1Sha256>::bootstrap(
                params,
                &dh_sk3,
                p3.index,
                &p3coeffs,
                &participants,
                rng,
            )
            .unwrap();
        let p3_their_encrypted_secret_shares = p3_state.their_encrypted_secret_shares().unwrap();

        let (p4_state, p4_participant_lists) =
            DistributedKeyGeneration::<RoundOne, Secp256k1Sha256>::bootstrap(
                params,
                &dh_sk4,
                p4.index,
                &p4coeffs,
                &participants,
                rng,
            )
            .unwrap();
        let p4_their_encrypted_secret_shares = p4_state.their_encrypted_secret_shares().unwrap();

        let (p5_state, p5_participant_lists) =
            DistributedKeyGeneration::<RoundOne, Secp256k1Sha256>::bootstrap(
                params,
                &dh_sk5,
                p5.index,
                &p5coeffs,
                &participants,
                rng,
            )
            .unwrap();
        let p5_their_encrypted_secret_shares = p5_state.their_encrypted_secret_shares().unwrap();

        // Participants all identified p1 as malicious
        assert!(p2_participant_lists.misbehaving_participants.is_some());
        assert!(p3_participant_lists.misbehaving_participants.is_some());
        assert!(p4_participant_lists.misbehaving_participants.is_some());
        assert!(p5_participant_lists.misbehaving_participants.is_some());

        assert!(p2_participant_lists.misbehaving_participants.unwrap() == vec![1]);
        assert!(p3_participant_lists.misbehaving_participants.unwrap() == vec![1]);
        assert!(p4_participant_lists.misbehaving_participants.unwrap() == vec![1]);
        assert!(p5_participant_lists.misbehaving_participants.unwrap() == vec![1]);

        // Wrong share inserted here!
        let mut wrong_encrypted_secret_share_from_p4_to_p2 =
            p4_their_encrypted_secret_shares.get(&2).unwrap().clone();
        wrong_encrypted_secret_share_from_p4_to_p2.nonce = [42; 12].into();
        let p2_my_encrypted_secret_shares = vec![
            p2_their_encrypted_secret_shares.get(&2).unwrap().clone(),
            p3_their_encrypted_secret_shares.get(&2).unwrap().clone(),
            wrong_encrypted_secret_share_from_p4_to_p2.clone(),
            p5_their_encrypted_secret_shares.get(&2).unwrap().clone(),
        ];

        let p3_my_encrypted_secret_shares = vec![
            p2_their_encrypted_secret_shares.get(&3).unwrap().clone(),
            p3_their_encrypted_secret_shares.get(&3).unwrap().clone(),
            p4_their_encrypted_secret_shares.get(&3).unwrap().clone(),
            p5_their_encrypted_secret_shares.get(&3).unwrap().clone(),
        ];
        let p4_my_encrypted_secret_shares = vec![
            p2_their_encrypted_secret_shares.get(&4).unwrap().clone(),
            p3_their_encrypted_secret_shares.get(&4).unwrap().clone(),
            p4_their_encrypted_secret_shares.get(&4).unwrap().clone(),
            p5_their_encrypted_secret_shares.get(&4).unwrap().clone(),
        ];

        // Wrong shares inserted here!
        let mut wrong_encrypted_secret_share_from_p4_to_p5 =
            p4_their_encrypted_secret_shares.get(&5).unwrap().clone();
        wrong_encrypted_secret_share_from_p4_to_p5.nonce = [42; 12].into();
        let p5_my_encrypted_secret_shares = vec![
            p2_their_encrypted_secret_shares.get(&5).unwrap().clone(),
            p3_their_encrypted_secret_shares.get(&5).unwrap().clone(),
            wrong_encrypted_secret_share_from_p4_to_p5.clone(),
            p5_their_encrypted_secret_shares.get(&5).unwrap().clone(),
        ];

        let (mut p2_state, p2_complaints) = p2_state
            .clone()
            .to_round_two(&p2_my_encrypted_secret_shares, rng)
            .unwrap();
        assert!(p2_complaints.len() == 1);

        let (mut p3_state, complaints) = p3_state
            .clone()
            .to_round_two(&p3_my_encrypted_secret_shares, rng)
            .unwrap();
        assert!(complaints.is_empty());

        let (p4_state, complaints) = p4_state
            .clone()
            .to_round_two(&p4_my_encrypted_secret_shares, rng)
            .unwrap();
        assert!(complaints.is_empty());

        let (mut p5_state, p5_complaints) = p5_state
            .clone()
            .to_round_two(&p5_my_encrypted_secret_shares, rng)
            .unwrap();
        assert!(p5_complaints.len() == 1);

        let all_complaints = &[p2_complaints, p5_complaints].concat();

        let bad_indices = p2_state.blame(all_complaints);
        assert!(bad_indices.len() == 1); // both complaints led to the same conclusion
        assert!(bad_indices[0] == p4.dh_public_key);
        let bad_indices = p3_state.blame(all_complaints);
        assert!(bad_indices.len() == 1); // both complaints led to the same conclusion
        assert!(bad_indices[0] == p4.dh_public_key);
        let bad_indices = p5_state.blame(all_complaints);
        assert!(bad_indices.len() == 1); // both complaints led to the same conclusion
        assert!(bad_indices[0] == p4.dh_public_key);

        // Everyone can finish the DKG.
        // However, only honest participants will be able to generate
        // publicly verifiable individual private/public keys.
        let (p2_group_key, p2_secret_key) = p2_state.finish().unwrap();
        let (p3_group_key, p3_secret_key) = p3_state.finish().unwrap();
        let (p4_group_key, _p4_secret_key) = p4_state.finish().unwrap();
        let (p5_group_key, p5_secret_key) = p5_state.finish().unwrap();

        assert!(p2_group_key == p3_group_key);
        assert!(p3_group_key == p5_group_key);

        assert!(p4_group_key != p2_group_key);

        let group_key = p5_group_key;

        // Check the validity of all honest participants `IndividualVerifyingKey`.

        let p2_public_key = p2_secret_key.to_public();
        let p3_public_key = p3_secret_key.to_public();
        let p5_public_key = p5_secret_key.to_public();

        // The order does not matter, but we must *only* use commitments from remaining (honest) participants.
        let commitments = [
            p2.commitments.unwrap(),
            p5.commitments.unwrap(),
            p3.commitments.unwrap(),
        ];

        assert!(p2_public_key.verify(&commitments).is_ok());
        assert!(p3_public_key.verify(&commitments).is_ok());
        assert!(p5_public_key.verify(&commitments).is_ok());

        assert!(p2_public_key.verify(&commitments[1..]).is_err());

        // Check that the generated `IndividualVerifyingKey` from other participants match.
        let p2_recovered_public_key =
            IndividualVerifyingKey::generate_from_commitments(2, &commitments).unwrap();
        let p3_recovered_public_key =
            IndividualVerifyingKey::generate_from_commitments(3, &commitments).unwrap();
        let p5_recovered_public_key =
            IndividualVerifyingKey::generate_from_commitments(5, &commitments).unwrap();

        assert_eq!(p2_public_key, p2_recovered_public_key);
        assert_eq!(p3_public_key, p3_recovered_public_key);
        assert_eq!(p5_public_key, p5_recovered_public_key);

        // We still have enough signers to generate a valid signature.

        let message = b"This is a test of the tsunami alert system. This is only a test.";
        let (p2_public_comshares, mut p2_secret_comshares) =
            generate_commitment_share_lists(&mut OsRng, &p2_secret_key, 1).unwrap();
        let (p3_public_comshares, mut p3_secret_comshares) =
            generate_commitment_share_lists(&mut OsRng, &p3_secret_key, 1).unwrap();
        let (p5_public_comshares, mut p5_secret_comshares) =
            generate_commitment_share_lists(&mut OsRng, &p5_secret_key, 1).unwrap();

        let mut aggregator = SignatureAggregator::new(params, group_key, &message[..]);

        aggregator
            .include_signer(
                2,
                p2_public_comshares.commitments[0],
                &p2_secret_key.to_public(),
            )
            .unwrap();
        aggregator
            .include_signer(
                3,
                p3_public_comshares.commitments[0],
                &p3_secret_key.to_public(),
            )
            .unwrap();
        aggregator
            .include_signer(
                5,
                p5_public_comshares.commitments[0],
                &p5_secret_key.to_public(),
            )
            .unwrap();

        let message_hash = Secp256k1Sha256::h4(&message[..]);

        let p2_partial = p2_secret_key
            .sign(
                &message_hash,
                &group_key,
                &mut p2_secret_comshares,
                0,
                aggregator.signers(),
            )
            .unwrap();
        let p3_partial = p3_secret_key
            .sign(
                &message_hash,
                &group_key,
                &mut p3_secret_comshares,
                0,
                aggregator.signers(),
            )
            .unwrap();
        let p5_partial = p5_secret_key
            .sign(
                &message_hash,
                &group_key,
                &mut p5_secret_comshares,
                0,
                aggregator.signers(),
            )
            .unwrap();

        aggregator.include_partial_signature(&p2_partial);
        aggregator.include_partial_signature(&p3_partial);
        aggregator.include_partial_signature(&p5_partial);

        let aggregator = aggregator.finalize().unwrap();
        let threshold_signature = aggregator.aggregate().unwrap();
        let verification_result1 = threshold_signature.verify(&group_key, &message_hash);
        let verification_result2 = group_key.verify_signature(&threshold_signature, &message_hash);

        assert!(verification_result1.is_ok());
        assert!(verification_result2.is_ok());
    }

    #[test]
    fn test_serialization() {
        let (params, dealers_signing_keys, group_key, _, _) = do_keygen(3, 2, None, None).unwrap();

        let p1_sk = dealers_signing_keys[0].clone();
        let p2_sk = dealers_signing_keys[1].clone();

        let message = b"This is a test of the tsunami alert system. This is only a test.";
        let (p1_public_comshares, mut p1_secret_comshares) =
            generate_commitment_share_lists(&mut OsRng, &p1_sk, 1).unwrap();
        let (p2_public_comshares, mut p2_secret_comshares) =
            generate_commitment_share_lists(&mut OsRng, &p2_sk, 1).unwrap();

        let mut aggregator = SignatureAggregator::new(params, group_key, &message[..]);

        aggregator
            .include_signer(1, p1_public_comshares.commitments[0], &p1_sk.to_public())
            .unwrap();
        aggregator
            .include_signer(2, p2_public_comshares.commitments[0], &p2_sk.to_public())
            .unwrap();

        let message_hash = Secp256k1Sha256::h4(&message[..]);

        let p1_partial = p1_sk
            .sign(
                &message_hash,
                &group_key,
                &mut p1_secret_comshares,
                0,
                aggregator.signers(),
            )
            .unwrap();
        let p2_partial = p2_sk
            .sign(
                &message_hash,
                &group_key,
                &mut p2_secret_comshares,
                0,
                aggregator.signers(),
            )
            .unwrap();

        // Check serialization

        let bytes = p1_secret_comshares.to_bytes().unwrap();
        assert_eq!(
            p1_secret_comshares,
            SecretCommitmentShareList::from_bytes(&bytes).unwrap()
        );

        let bytes = p1_public_comshares.to_bytes().unwrap();
        assert_eq!(
            p1_public_comshares,
            PublicCommitmentShareList::from_bytes(&bytes).unwrap()
        );

        let bytes = p1_partial.to_bytes().unwrap();
        assert_eq!(
            p1_partial,
            PartialThresholdSignature::from_bytes(&bytes).unwrap()
        );

        // Continue signature

        aggregator.include_partial_signature(&p1_partial);
        aggregator.include_partial_signature(&p2_partial);

        let aggregator = aggregator.finalize().unwrap();
        let signing_result = aggregator.aggregate();

        assert!(signing_result.is_ok());

        let threshold_signature = signing_result.unwrap();
        let verification_result1 = threshold_signature.verify(&group_key, &message_hash);
        let verification_result2 = group_key.verify_signature(&threshold_signature, &message_hash);

        assert!(verification_result1.is_ok());
        assert!(verification_result2.is_ok());

        // Check serialization

        let bytes = threshold_signature.to_bytes().unwrap();
        assert_eq!(
            threshold_signature,
            ThresholdSignature::from_bytes(&bytes).unwrap()
        );
    }
}
