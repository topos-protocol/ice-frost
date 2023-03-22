//! Precomputation for one-round signing.

use crate::error::Error;
use crate::utils::Vec;

use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_serialize::CanonicalDeserialize;
use ark_serialize::CanonicalSerialize;

use rand::CryptoRng;
use rand::Rng;
use zeroize::Zeroize;

#[derive(Debug, CanonicalSerialize, CanonicalDeserialize, Zeroize)]
pub(crate) struct NoncePair<F: PrimeField>(pub(crate) F, pub(crate) F);

impl<F: PrimeField> Drop for NoncePair<F> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl<F: PrimeField> NoncePair<F> {
    pub fn new(mut csprng: impl CryptoRng + Rng) -> Self {
        NoncePair(F::rand(&mut csprng), F::rand(&mut csprng))
    }
}

impl<G: CurveGroup> From<NoncePair<G::ScalarField>> for CommitmentShare<G> {
    fn from(other: NoncePair<G::ScalarField>) -> Self {
        let x = G::generator().mul(other.0);
        let y = G::generator().mul(other.1);

        Self {
            hiding: Commitment {
                secret: other.0,
                commit: x,
            },
            binding: Commitment {
                secret: other.1,
                commit: y,
            },
        }
    }
}

/// A pair of a secret and a commitment to it.
#[derive(Clone, Debug, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub(crate) struct Commitment<G: CurveGroup> {
    /// The secret.
    pub(crate) secret: G::ScalarField,
    /// The commitment.
    pub(crate) commit: G,
}

impl<G: CurveGroup> Zeroize for Commitment<G> {
    fn zeroize(&mut self) {
        self.secret.zeroize();
        // We set the commitment to the identity point, as the Group trait
        // does not implement Zeroize.
        // Safely zeroizing of the secret component is what actually matters.
        self.commit = G::zero();
    }
}

impl<G: CurveGroup> Drop for Commitment<G> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Test equality in constant-time.
impl<G: CurveGroup> PartialEq for Commitment<G> {
    fn eq(&self, other: &Self) -> bool {
        self.secret.eq(&other.secret) & self.commit.into_affine().eq(&other.commit.into_affine())
    }
}

/// A precomputed commitment share.
#[derive(Clone, Debug, Eq, CanonicalSerialize, CanonicalDeserialize, Zeroize)]
pub struct CommitmentShare<G: CurveGroup> {
    /// The hiding commitment.
    ///
    /// This is \\((d\_{ij}, D\_{ij})\\) in the paper.
    pub(crate) hiding: Commitment<G>,
    /// The binding commitment.
    ///
    /// This is \\((e\_{ij}, E\_{ij})\\) in the paper.
    pub(crate) binding: Commitment<G>,
}

impl<G: CurveGroup> CommitmentShare<G> {
    /// Serialize this `CommitmentShare` to a vector of bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error<G>> {
        let mut bytes = Vec::new();

        self.serialize_compressed(&mut bytes)
            .map_err(|_| Error::SerialisationError)?;

        Ok(bytes)
    }

    /// Attempt to deserialize a `CommitmentShare` from a vector of bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error<G>> {
        Self::deserialize_compressed(bytes).map_err(|_| Error::DeserialisationError)
    }
}

impl<G: CurveGroup> Drop for CommitmentShare<G> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Test equality in constant-time.
impl<G: CurveGroup> PartialEq for CommitmentShare<G> {
    fn eq(&self, other: &Self) -> bool {
        self.hiding.eq(&other.hiding) & self.binding.eq(&other.binding)
    }
}

impl<G: CurveGroup> CommitmentShare<G> {
    /// Publish the public commitments in this [`CommitmentShare`].
    pub fn publish(&self) -> (G, G) {
        (self.hiding.commit, self.binding.commit)
    }
}

/// A secret commitment share list, containing the revealed secrets for the
/// hiding and binding commitments.
#[derive(Clone, Debug, Eq, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct SecretCommitmentShareList<G: CurveGroup> {
    /// The secret commitment shares.
    pub commitments: Vec<CommitmentShare<G>>,
}

impl<G: CurveGroup> SecretCommitmentShareList<G> {
    /// Serialize this `SecretCommitmentShareList` to a vector of bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error<G>> {
        let mut bytes = Vec::new();

        self.serialize_compressed(&mut bytes)
            .map_err(|_| Error::SerialisationError)?;

        Ok(bytes)
    }

    /// Attempt to deserialize a `SecretCommitmentShareList` from a vector of bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error<G>> {
        Self::deserialize_compressed(bytes).map_err(|_| Error::DeserialisationError)
    }
}

/// A public commitment share list, containing only the hiding and binding
/// commitments, *not* their committed-to secret values.
///
/// This should be published somewhere before the signing protocol takes place
/// for the other signing participants to obtain.
#[derive(Debug, Eq, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct PublicCommitmentShareList<G: CurveGroup> {
    /// The participant's index.
    pub participant_index: u32,
    /// The published commitments.
    pub commitments: Vec<(G, G)>,
}

impl<G: CurveGroup> PublicCommitmentShareList<G> {
    /// Serialize this `PublicCommitmentShareList` to a vector of bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error<G>> {
        let mut bytes = Vec::new();

        self.serialize_compressed(&mut bytes)
            .map_err(|_| Error::SerialisationError)?;

        Ok(bytes)
    }

    /// Attempt to deserialize a `PublicCommitmentShareList` from a vector of bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error<G>> {
        Self::deserialize_compressed(bytes).map_err(|_| Error::DeserialisationError)
    }
}

/// Pre-compute a list of [`CommitmentShare`]s for single-round threshold signing.
///
/// # Inputs
///
/// * `participant_index` is the index of the threshold signing
///   participant who is publishing this share.
/// * `number_of_shares` denotes the number of commitments published at a time.
///
/// # Returns
///
/// A tuple of ([`PublicCommitmentShareList`], [`SecretCommitmentShareList`]).
pub fn generate_commitment_share_lists<G: CurveGroup>(
    mut csprng: impl CryptoRng + Rng,
    participant_index: u32,
    number_of_shares: usize,
) -> (PublicCommitmentShareList<G>, SecretCommitmentShareList<G>) {
    let mut commitments: Vec<CommitmentShare<G>> = Vec::with_capacity(number_of_shares);

    for _ in 0..number_of_shares {
        commitments.push(CommitmentShare::from(NoncePair::new(&mut csprng)));
    }

    let mut published: Vec<(G, G)> = Vec::with_capacity(number_of_shares);

    for commitment in commitments.iter() {
        published.push(commitment.publish());
    }

    (
        PublicCommitmentShareList {
            participant_index,
            commitments: published,
        },
        SecretCommitmentShareList { commitments },
    )
}

impl<G: CurveGroup> SecretCommitmentShareList<G> {
    /// Drop a used [`CommitmentShare`] from our secret commitment share list
    /// and ensure that it is wiped from memory.
    pub fn drop_share(&mut self, share: CommitmentShare<G>) {
        let mut index = -1;

        // This is not constant-time in that the number of commitment shares in
        // the list may be discovered via side channel, as well as the index of
        // share to be deleted, as well as whether or not the share was in the
        // list, but none of this should give any adversary any advantage.
        for (i, s) in self.commitments.iter().enumerate() {
            if s.eq(&share) {
                index = i as isize;
            }
        }
        if index >= 0 {
            drop(self.commitments.remove(index as usize));
        }
        drop(share);
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use ark_bn254::{Fr, G1Projective};
    use ark_ec::Group;
    use ark_ff::UniformRand;
    use rand::rngs::OsRng;

    use core::ops::Mul;

    #[test]
    fn secret_pair() {
        let _secret_pair = NoncePair::<Fr>::new(&mut OsRng);
    }

    #[test]
    fn secret_pair_into_commitment_share() {
        let _commitment_share: CommitmentShare<G1Projective> = NoncePair::new(&mut OsRng).into();
    }

    #[test]
    fn test_serialisation() {
        let mut rng = OsRng;

        for _ in 0..100 {
            let secret = Fr::rand(&mut rng);
            let commit = G1Projective::generator().mul(secret);
            let commitment = Commitment { secret, commit };
            let mut bytes = Vec::new();

            commitment.serialize_compressed(&mut bytes).unwrap();
            assert_eq!(
                commitment,
                Commitment::deserialize_compressed(&bytes[..]).unwrap()
            );
        }

        for _ in 0..100 {
            let secret = Fr::rand(&mut rng);
            let commit = G1Projective::generator().mul(secret);
            let binding = Commitment { secret, commit };
            let hiding = binding.clone();
            let commitment_share = CommitmentShare { binding, hiding };
            let mut bytes = Vec::new();

            commitment_share.serialize_compressed(&mut bytes).unwrap();
            assert_eq!(
                commitment_share,
                CommitmentShare::deserialize_compressed(&bytes[..]).unwrap()
            );
        }

        // invalid encodings
        let bytes = [255u8; 64];
        assert!(Commitment::<G1Projective>::deserialize_compressed(&bytes[..]).is_err());

        let bytes = [255u8; 128];
        assert!(CommitmentShare::<G1Projective>::deserialize_compressed(&bytes[..]).is_err());
    }

    #[test]
    fn commitment_share_list_generate() {
        let (public_share_list, secret_share_list) =
            generate_commitment_share_lists::<G1Projective>(&mut OsRng, 0, 5);

        assert_eq!(
            public_share_list.commitments[0].0.into_affine(),
            (G1Projective::generator().mul(secret_share_list.commitments[0].hiding.secret))
                .into_affine()
        );
    }

    #[test]
    fn drop_used_commitment_shares() {
        let (_public_share_list, mut secret_share_list) =
            generate_commitment_share_lists(&mut OsRng, 3, 8);

        assert!(secret_share_list.commitments.len() == 8);

        let used_share: CommitmentShare<G1Projective> = secret_share_list.commitments[0].clone();

        secret_share_list.drop_share(used_share);

        assert!(secret_share_list.commitments.len() == 7);
    }
}
