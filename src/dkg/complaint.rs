use crate::error::Error;
use crate::utils::Vec;

use rand::{CryptoRng, RngCore};
use sha2::Sha256;

use ark_ec::CurveGroup;
use ark_ff::field_hashers::{DefaultFieldHasher, HashToField};
use ark_ff::UniformRand;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

/// A complaint generated when a participant receives a bad share.
#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Complaint<G: CurveGroup> {
    /// The index of the complaint maker.
    pub maker_index: u32,
    /// The index of the alleged misbehaving participant.
    pub accused_index: u32,
    /// The shared DH private key.
    pub dh_shared_key: G,
    /// The complaint proof.
    pub proof: ComplaintProof<G>,
}

impl<G: CurveGroup> Complaint<G> {
    pub(crate) fn new(
        my_index: u32,
        accused_index: u32,
        accused_pk: &G,
        dh_skey: &G::ScalarField,
        dh_pkey: &G,
        dh_shared_key: &G,
        mut rng: impl RngCore + CryptoRng,
    ) -> Result<Self, Error<G>> {
        let r = G::ScalarField::rand(&mut rng);

        let a1 = G::generator().mul(r);
        let a2 = accused_pk.mul(r);

        let hasher = <DefaultFieldHasher<Sha256, 128> as HashToField<G::ScalarField>>::new(
            "Complaint Context".as_bytes(),
        );

        let mut message = my_index.to_le_bytes().to_vec();
        message.extend(&accused_index.to_le_bytes());
        dh_pkey
            .serialize_compressed(&mut message)
            .map_err(|_| Error::PointCompressionError)?;
        accused_pk
            .serialize_compressed(&mut message)
            .map_err(|_| Error::PointCompressionError)?;
        dh_shared_key
            .serialize_compressed(&mut message)
            .map_err(|_| Error::PointCompressionError)?;
        a1.serialize_compressed(&mut message)
            .map_err(|_| Error::PointCompressionError)?;
        a2.serialize_compressed(&mut message)
            .map_err(|_| Error::PointCompressionError)?;

        let h: G::ScalarField = hasher.hash_to_field(&message[..], 1)[0];
        Ok(Self {
            maker_index: my_index,
            accused_index,
            dh_shared_key: *dh_shared_key,
            proof: ComplaintProof {
                a1,
                a2,
                z: r + h * dh_skey,
            },
        })
    }

    /// A complaint is valid if:
    /// --  a1 + h.pk_i = z.g
    /// --  a2 + h.k_il = z.pk_l
    pub fn verify(&self, pk_i: &G, pk_l: &G) -> Result<(), Error<G>> {
        let hasher = <DefaultFieldHasher<Sha256, 128> as HashToField<G::ScalarField>>::new(
            "Complaint Context".as_bytes(),
        );

        let mut message = self.maker_index.to_le_bytes().to_vec();
        message.extend(&self.accused_index.to_le_bytes());
        pk_i.serialize_compressed(&mut message)
            .map_err(|_| Error::PointCompressionError)?;
        pk_l.serialize_compressed(&mut message)
            .map_err(|_| Error::PointCompressionError)?;
        self.dh_shared_key
            .serialize_compressed(&mut message)
            .map_err(|_| Error::PointCompressionError)?;
        self.proof
            .a1
            .serialize_compressed(&mut message)
            .map_err(|_| Error::PointCompressionError)?;
        self.proof
            .a2
            .serialize_compressed(&mut message)
            .map_err(|_| Error::PointCompressionError)?;

        let h: G::ScalarField = hasher.hash_to_field(&message[..], 1)[0];

        if self.proof.a1 + pk_i.mul(h) != G::generator() * self.proof.z {
            return Err(Error::ComplaintVerificationError);
        }

        if self.proof.a2 + self.dh_shared_key * h != pk_l.mul(self.proof.z) {
            return Err(Error::ComplaintVerificationError);
        }

        Ok(())
    }

    /// Serialize this `Complaint` to a vector of bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error<G>> {
        let mut bytes = Vec::new();

        self.serialize_compressed(&mut bytes)
            .map_err(|_| Error::SerialisationError)?;

        Ok(bytes)
    }

    /// Attempt to deserialize a `Complaint` from a vector of bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error<G>> {
        Self::deserialize_compressed(bytes).map_err(|_| Error::DeserialisationError)
    }
}

/// A proof that a generated complaint is valid.
#[derive(Clone, Copy, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct ComplaintProof<G: CurveGroup> {
    /// a1 = g^r.
    pub a1: G,
    /// a2 = pk_l^r.
    pub a2: G,
    /// z = r + H(pk_i, pk_l, k_il).sh_i
    pub z: G::ScalarField,
}

impl<G: CurveGroup> ComplaintProof<G> {
    /// Serialize this `ComplaintProof` to a vector of bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error<G>> {
        let mut bytes = Vec::new();

        self.serialize_compressed(&mut bytes)
            .map_err(|_| Error::SerialisationError)?;

        Ok(bytes)
    }

    /// Attempt to deserialize a `ComplaintProof` from a vector of bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error<G>> {
        Self::deserialize_compressed(bytes).map_err(|_| Error::DeserialisationError)
    }
}
