use crate::utils::Vec;
use crate::{Error, FrostResult};

use core::ops::Mul;

use rand::{CryptoRng, RngCore};
use sha2::Sha256;

use crate::ciphersuite::CipherSuite;

use ark_ec::Group;
use ark_ff::field_hashers::{DefaultFieldHasher, HashToField};
use ark_ff::UniformRand;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

/// A complaint generated when a participant receives a bad share.
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Complaint<C: CipherSuite> {
    /// The index of the complaint maker.
    pub maker_index: u32,
    /// The index of the alleged misbehaving participant.
    pub accused_index: u32,
    /// The shared DH private key.
    pub dh_shared_key: <C as CipherSuite>::G,
    /// The complaint proof.
    pub proof: ComplaintProof<C>,
}

impl<C: CipherSuite> Complaint<C> {
    pub(crate) fn new(
        my_index: u32,
        accused_index: u32,
        accused_pk: &C::G,
        dh_skey: &<C::G as Group>::ScalarField,
        dh_pkey: &C::G,
        dh_shared_key: &C::G,
        mut rng: impl RngCore + CryptoRng,
    ) -> FrostResult<C, Self> {
        let r = <C::G as Group>::ScalarField::rand(&mut rng);

        let a1 = C::G::generator().mul(r);
        let a2 = accused_pk.mul(r);

        let hasher = <DefaultFieldHasher<Sha256, 128> as HashToField<
            <C::G as Group>::ScalarField,
        >>::new("Complaint Context".as_bytes());

        let mut message = my_index.to_le_bytes().to_vec();
        message.extend(&accused_index.to_le_bytes());
        dh_pkey
            .serialize_compressed(&mut message)
            .map_err(|_| Error::CompressionError)?;
        accused_pk
            .serialize_compressed(&mut message)
            .map_err(|_| Error::CompressionError)?;
        dh_shared_key
            .serialize_compressed(&mut message)
            .map_err(|_| Error::CompressionError)?;
        a1.serialize_compressed(&mut message)
            .map_err(|_| Error::CompressionError)?;
        a2.serialize_compressed(&mut message)
            .map_err(|_| Error::CompressionError)?;

        let h: <C::G as Group>::ScalarField = hasher.hash_to_field(&message[..], 1)[0];
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
    pub fn verify(&self, pk_i: &C::G, pk_l: &C::G) -> FrostResult<C, ()> {
        let hasher = <DefaultFieldHasher<Sha256, 128> as HashToField<
            <C::G as Group>::ScalarField,
        >>::new("Complaint Context".as_bytes());

        let mut message = self.maker_index.to_le_bytes().to_vec();
        message.extend(&self.accused_index.to_le_bytes());
        pk_i.serialize_compressed(&mut message)
            .map_err(|_| Error::CompressionError)?;
        pk_l.serialize_compressed(&mut message)
            .map_err(|_| Error::CompressionError)?;
        self.dh_shared_key
            .serialize_compressed(&mut message)
            .map_err(|_| Error::CompressionError)?;
        self.proof
            .a1
            .serialize_compressed(&mut message)
            .map_err(|_| Error::CompressionError)?;
        self.proof
            .a2
            .serialize_compressed(&mut message)
            .map_err(|_| Error::CompressionError)?;

        let h: <C::G as Group>::ScalarField = hasher.hash_to_field(&message[..], 1)[0];

        if self.proof.a1 + pk_i.mul(h) != C::G::generator() * self.proof.z {
            return Err(Error::ComplaintVerificationError);
        }

        if self.proof.a2 + self.dh_shared_key * h != pk_l.mul(self.proof.z) {
            return Err(Error::ComplaintVerificationError);
        }

        Ok(())
    }

    /// Serialize this [`Complaint`] to a vector of bytes.
    pub fn to_bytes(&self) -> FrostResult<C, Vec<u8>> {
        let mut bytes = Vec::new();

        self.serialize_compressed(&mut bytes)
            .map_err(|_| Error::SerializationError)?;

        Ok(bytes)
    }

    /// Attempt to deserialize a [`Complaint`] from a vector of bytes.
    pub fn from_bytes(bytes: &[u8]) -> FrostResult<C, Self> {
        Self::deserialize_compressed(bytes).map_err(|_| Error::DeserializationError)
    }
}

/// A proof that a generated complaint is valid.
#[derive(Clone, Copy, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct ComplaintProof<C: CipherSuite> {
    /// a1 = g^r.
    pub a1: <C as CipherSuite>::G,
    /// a2 = pk_l^r.
    pub a2: <C as CipherSuite>::G,
    /// z = r + H(pk_i, pk_l, k_il).sh_i
    pub z: <C::G as Group>::ScalarField,
}

impl<C: CipherSuite> ComplaintProof<C> {
    /// Serialize this [`ComplaintProof`] to a vector of bytes.
    pub fn to_bytes(&self) -> FrostResult<C, Vec<u8>> {
        let mut bytes = Vec::new();

        self.serialize_compressed(&mut bytes)
            .map_err(|_| Error::SerializationError)?;

        Ok(bytes)
    }

    /// Attempt to deserialize a [`ComplaintProof`] from a vector of bytes.
    pub fn from_bytes(bytes: &[u8]) -> FrostResult<C, Self> {
        Self::deserialize_compressed(bytes).map_err(|_| Error::DeserializationError)
    }
}
