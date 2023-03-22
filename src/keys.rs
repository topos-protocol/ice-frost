use core::ops::Deref;

use crate::dkg::secret_share::VerifiableSecretSharingCommitment;
use crate::error::Error;
use crate::utils::calculate_lagrange_coefficients;
use crate::utils::{ToString, Vec};

use ark_ec::CurveGroup;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use zeroize::Zeroize;

/// A Diffie-Hellman private key wrapper type around a PrimeField.
#[derive(Clone, Debug, Eq, PartialEq, CanonicalSerialize, CanonicalDeserialize, Zeroize)]
pub struct DiffieHellmanPrivateKey<G: CurveGroup>(pub(crate) G::ScalarField);

impl<G: CurveGroup> DiffieHellmanPrivateKey<G> {
    /// Serialize this `DiffieHellmanPrivateKey` to a vector of bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error<G>> {
        let mut bytes = Vec::new();

        self.serialize_compressed(&mut bytes)
            .map_err(|_| Error::SerialisationError)?;

        Ok(bytes)
    }

    /// Attempt to deserialize a `DiffieHellmanPrivateKey` from a vector of bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error<G>> {
        Self::deserialize_compressed(bytes).map_err(|_| Error::DeserialisationError)
    }
}

impl<G: CurveGroup> Drop for DiffieHellmanPrivateKey<G> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// A Diffie-Hellman public key wrapper type around a CurveGroup.
#[derive(Clone, Debug, Eq, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct DiffieHellmanPublicKey<G: CurveGroup>(pub(crate) G);

impl<G: CurveGroup> DiffieHellmanPublicKey<G> {
    /// Serialize this `DiffieHellmanPublicKey` to a vector of bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error<G>> {
        let mut bytes = Vec::new();

        self.serialize_compressed(&mut bytes)
            .map_err(|_| Error::SerialisationError)?;

        Ok(bytes)
    }

    /// Attempt to deserialize a `DiffieHellmanPublicKey` from a vector of bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error<G>> {
        Self::deserialize_compressed(bytes).map_err(|_| Error::DeserialisationError)
    }
}

impl<G: CurveGroup> Deref for DiffieHellmanPublicKey<G> {
    type Target = G;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// A public verification share for a participant.
///
/// Any participant can recalculate the public verification share, which is the
/// public half of a [`IndividualSigningKey`], of any other participant in the protocol.
#[derive(Clone, Debug, Eq, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct IndividualVerifyingKey<G: CurveGroup> {
    /// The participant index to which this key belongs.
    pub index: u32,
    /// The public verification share.
    pub share: G,
}

impl<G: CurveGroup> IndividualVerifyingKey<G> {
    /// Serialize this `IndividualVerifyingKey` to a vector of bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error<G>> {
        let mut bytes = Vec::new();

        self.serialize_compressed(&mut bytes)
            .map_err(|_| Error::SerialisationError)?;

        Ok(bytes)
    }

    /// Attempt to deserialize a `IndividualVerifyingKey` from a vector of bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error<G>> {
        Self::deserialize_compressed(bytes).map_err(|_| Error::DeserialisationError)
    }

    /// Any participant can compute the public verification share of any other participant.
    ///
    /// This is done by re-computing each [`IndividualVerifyingKey`] as \\(Y\_i\\) s.t.:
    ///
    /// \\[
    /// Y\_i = \prod\_{j=1}^{n} \prod\_{k=0}^{t-1} \phi\_{jk}^{i^{k} \mod q}
    /// \\]
    ///
    /// for each [`Participant`] index \\(i\\).
    ///
    /// # Inputs
    ///
    /// * A vector of `commitments` regarding the secret polynomial
    ///   [`Coefficients`] that this [`IndividualVerifyingKey`] was generated with.
    ///
    /// # Returns
    ///
    /// A `Result` with either an empty `Ok` or `Err` value, depending on
    /// whether or not the verification was successful.
    pub fn verify(
        &self,
        commitments: &[VerifiableSecretSharingCommitment<G>],
    ) -> Result<(), Error<G>> {
        let mut rhs: G = G::zero();
        let term: G::ScalarField = self.index.into();

        let mut index_vector: Vec<u32> = Vec::new();
        for commitment in commitments.iter() {
            index_vector.push(commitment.index);
        }

        for commitment in commitments.iter() {
            let mut tmp: G = G::zero();
            for (index, com) in commitment.points.iter().rev().enumerate() {
                tmp += com;

                if index != (commitment.points.len() - 1) {
                    tmp *= term;
                }
            }

            let coeff = match calculate_lagrange_coefficients::<G>(commitment.index, &index_vector)
            {
                Ok(s) => s,
                Err(error) => return Err(Error::Custom(error.to_string())),
            };

            rhs += tmp.mul(coeff);
        }

        match self.share.into_affine() == rhs.into_affine() {
            true => Ok(()),
            false => Err(Error::ShareVerificationError),
        }
    }

    /// Any participant can compute the public verification share of any other participant.
    ///
    /// This is done by re-computing each [`IndividualVerifyingKey`] as \\(Y\_i\\) s.t.:
    ///
    /// \\[
    /// Y\_i = \prod\_{j=1}^{n} \prod\_{k=0}^{t-1} \phi\_{jk}^{i^{k} \mod q}
    /// \\]
    ///
    /// for each [`Participant`] index \\(i\\).
    ///
    /// # Inputs
    ///
    /// * A `participant_index` and
    /// * A vector of `commitments` regarding the secret polynomial
    ///   [`Coefficients`] that the [`IndividualVerifyingKey`] will be generated from.
    ///
    /// # Returns
    ///
    /// An `IndividualVerifyingKey`.
    pub fn generate_from_commitments(
        participant_index: u32,
        commitments: &[VerifiableSecretSharingCommitment<G>],
    ) -> Self {
        let mut share: G = G::zero();
        let term: G::ScalarField = participant_index.into();

        let mut index_vector: Vec<u32> = Vec::new();
        for commitment in commitments.iter() {
            index_vector.push(commitment.index);
        }

        for commitment in commitments.iter() {
            let mut tmp: G = G::zero();
            for (index, com) in commitment.points.iter().rev().enumerate() {
                tmp += com;

                if index != (commitment.points.len() - 1) {
                    tmp *= term;
                }
            }

            let coeff =
                calculate_lagrange_coefficients::<G>(commitment.index, &index_vector).unwrap();
            share += tmp * coeff;
        }

        IndividualVerifyingKey {
            index: participant_index,
            share,
        }
    }
}

/// A secret key, used by one participant in a threshold signature scheme, to sign a message.
#[derive(Clone, Debug, Eq, PartialEq, CanonicalSerialize, CanonicalDeserialize, Zeroize)]
pub struct IndividualSigningKey<G: CurveGroup> {
    /// The participant index to which this key belongs.
    pub(crate) index: u32,
    /// The participant's long-lived secret share of the group signing key.
    pub(crate) key: G::ScalarField,
}

impl<G: CurveGroup> IndividualSigningKey<G> {
    /// Serialize this `IndividualSigningKey` to a vector of bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error<G>> {
        let mut bytes = Vec::new();

        self.serialize_compressed(&mut bytes)
            .map_err(|_| Error::SerialisationError)?;

        Ok(bytes)
    }

    /// Attempt to deserialize a `IndividualSigningKey` from a vector of bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error<G>> {
        Self::deserialize_compressed(bytes).map_err(|_| Error::DeserialisationError)
    }
}

impl<G: CurveGroup> Drop for IndividualSigningKey<G> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl<G: CurveGroup> IndividualSigningKey<G> {
    /// Derive the corresponding public key for this secret key.
    pub fn to_public(&self) -> IndividualVerifyingKey<G> {
        let share = G::generator() * self.key;

        IndividualVerifyingKey {
            index: self.index,
            share,
        }
    }
}

impl<G: CurveGroup> From<&IndividualSigningKey<G>> for IndividualVerifyingKey<G> {
    fn from(source: &IndividualSigningKey<G>) -> IndividualVerifyingKey<G> {
        source.to_public()
    }
}

/// A public key, used to verify a signature made by a threshold of a group of participants.
#[derive(Clone, Copy, Debug, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct GroupKey<G: CurveGroup>(pub(crate) G);

impl<G: CurveGroup> PartialEq for GroupKey<G> {
    fn eq(&self, other: &Self) -> bool {
        self.0.into_affine() == other.0.into_affine()
    }
}

impl<G: CurveGroup> GroupKey<G> {
    /// Serialize this `GroupKey` to a vector of bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error<G>> {
        let mut bytes = Vec::new();

        self.serialize_compressed(&mut bytes)
            .map_err(|_| Error::SerialisationError)?;

        Ok(bytes)
    }

    /// Attempt to deserialize a `GroupKey` from a vector of bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error<G>> {
        Self::deserialize_compressed(bytes).map_err(|_| Error::DeserialisationError)
    }
}
