//! The complaint module for handling disputes during an ICE-FROST
//! Distributed Key Generation session.

use crate::serialization::impl_serialization_traits;
use crate::utils::{Scalar, Vec};
use crate::{Error, FrostResult};

use core::ops::Mul;

use rand::{CryptoRng, RngCore};
use sha2::Sha256;

use crate::ciphersuite::CipherSuite;

use ark_ec::Group;
use ark_ff::field_hashers::{DefaultFieldHasher, HashToField};
use ark_ff::UniformRand;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use super::EncryptedSecretShare;

/// A complaint generated when a participant receives an invalid share.
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Complaint<C: CipherSuite> {
    /// The shared Diffie-Hellman secret key.
    pub dh_shared_key: <C as CipherSuite>::G,
    /// The encrypted share against which this complaint is made.
    pub encrypted_share: EncryptedSecretShare<C>,
    /// The complaint proof.
    pub proof: ComplaintProof<C>,
}

impl_serialization_traits!(Complaint<CipherSuite>);

impl<C: CipherSuite> Complaint<C> {
    pub(crate) fn new(
        accused_pk: &C::G,
        dh_skey: &Scalar<C>,
        dh_shared_key: &C::G,
        encrypted_share: &EncryptedSecretShare<C>,
        mut rng: impl RngCore + CryptoRng,
    ) -> FrostResult<C, Self> {
        let r = Scalar::<C>::rand(&mut rng);

        let a1 = C::G::generator().mul(r);
        let a2 = accused_pk.mul(r);

        let hasher = <DefaultFieldHasher<Sha256, 128> as HashToField<Scalar<C>>>::new(
            "Complaint Context".as_bytes(),
        );

        let dh_pkey = C::G::generator() * dh_skey;

        // We are hashing 5 group elements + the encrypted share.
        let mut message = Vec::with_capacity(
            dh_shared_key.compressed_size() * 5 + encrypted_share.compressed_size(),
        );
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
        encrypted_share
            .serialize_compressed(&mut message)
            .map_err(|_| Error::CompressionError)?;

        let h: Scalar<C> = hasher.hash_to_field(&message[..], 1)[0];

        Ok(Self {
            dh_shared_key: *dh_shared_key,
            encrypted_share: encrypted_share.clone(),
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
        let hasher = <DefaultFieldHasher<Sha256, 128> as HashToField<Scalar<C>>>::new(
            "Complaint Context".as_bytes(),
        );

        // We are hashing 5 group elements + the encrypted share.
        let mut message = Vec::with_capacity(
            self.dh_shared_key.compressed_size() * 5 + self.encrypted_share.compressed_size(),
        );
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
        self.encrypted_share
            .serialize_compressed(&mut message)
            .map_err(|_| Error::CompressionError)?;

        let h: Scalar<C> = hasher.hash_to_field(&message[..], 1)[0];

        if self.proof.a1 + pk_i.mul(h) != C::G::generator() * self.proof.z {
            return Err(Error::ComplaintVerificationError);
        }

        if self.proof.a2 + self.dh_shared_key * h != pk_l.mul(self.proof.z) {
            return Err(Error::ComplaintVerificationError);
        }

        Ok(())
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
    pub z: Scalar<C>,
}

impl_serialization_traits!(ComplaintProof<CipherSuite>);
