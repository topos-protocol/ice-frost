use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{
    field_hashers::{DefaultFieldHasher, HashToField},
    UniformRand,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use crate::error::Error;
use crate::utils::Vec;

use sha2::Sha256;

use rand::CryptoRng;
use rand::Rng;

/// A proof of knowledge of a secret key, created by making a Schnorr signature
/// with the secret key.
///
/// This proof is created by making a pseudo-Schnorr signature,
/// \\( \sigma\_i = (s\_i, r\_i) \\) using \\( a\_{i0} \\) (from
/// `ice_frost::keygen::DistributedKeyGeneration::<RoundOne>::compute_share`)
/// as the secret key, such that \\( k \stackrel{\\$}{\leftarrow} \mathbb{Z}\_q \\),
/// \\( M\_i = g^k \\), \\( s\_i = \mathcal{H}(i, \phi, g^{a\_{i0}}, M\_i) \\),
/// \\( r\_i = k + a\_{i0} \cdot s\_i \\).
///
/// Verification is done by calculating \\(M'\_i = g^r + A\_i^{-s}\\),
/// where \\(A\_i = g^{a_i}\\), and using it to compute
/// \\(s'\_i = \mathcal{H}(i, \phi, A\_i, M'\_i)\\), then finally
/// \\(s\_i \stackrel{?}{=} s'\_i\\).
#[derive(Clone, Debug, Eq, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct NizkPokOfSecretKey<G: CurveGroup> {
    /// The scalar portion of the Schnorr signature encoding the context.
    s: G::ScalarField,
    /// The scalar portion of the Schnorr signature which is the actual signature.
    r: G::ScalarField,
}

impl<G: CurveGroup> NizkPokOfSecretKey<G> {
    /// Serialize this `NizkPokOfSecretKey` to a vector of bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error<G>> {
        let mut bytes = Vec::new();

        self.serialize_compressed(&mut bytes)
            .map_err(|_| Error::SerialisationError)?;

        Ok(bytes)
    }

    /// Attempt to deserialize a `NizkPokOfSecretKey` from a vector of bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error<G>> {
        Self::deserialize_compressed(bytes).map_err(|_| Error::DeserialisationError)
    }

    /// Prove knowledge of a secret key.
    pub fn prove(
        index: u32,
        secret_key: &G::ScalarField,
        public_key: &G,
        context_string: &str,
        mut csprng: impl Rng + CryptoRng,
    ) -> Result<Self, Error<G>> {
        let k = G::ScalarField::rand(&mut csprng);
        let M: G = G::generator() * k;

        let h = <DefaultFieldHasher<Sha256, 128> as HashToField<G::ScalarField>>::new(
            context_string.as_bytes(),
        );

        let mut message = index.to_le_bytes().to_vec();
        public_key
            .serialize_compressed(&mut message)
            .map_err(|_| Error::PointCompressionError)?;
        M.serialize_compressed(&mut message)
            .map_err(|_| Error::PointCompressionError)?;

        let s: G::ScalarField = h.hash_to_field(&message[..], 1)[0];
        let r = k + (*secret_key * s);

        Ok(NizkPokOfSecretKey { s, r })
    }

    /// Verify that the prover does indeed know the secret key.
    pub fn verify(&self, index: u32, public_key: &G, context_string: &str) -> Result<(), Error<G>> {
        let M_prime: G = G::msm(
            &[G::Affine::generator(), public_key.into_affine()],
            &[self.r, -self.s],
        )
        .map_err(|_| Error::InvalidMSMParameters)?;

        let h = <DefaultFieldHasher<Sha256, 128> as HashToField<G::ScalarField>>::new(
            context_string.as_bytes(),
        );

        let mut message = index.to_le_bytes().to_vec();
        public_key
            .serialize_compressed(&mut message)
            .map_err(|_| Error::PointCompressionError)?;
        M_prime
            .serialize_compressed(&mut message)
            .map_err(|_| Error::PointCompressionError)?;

        let s_prime: G::ScalarField = h.hash_to_field(&message[..], 1)[0];

        if self.s == s_prime {
            return Ok(());
        }

        Err(Error::InvalidProofOfKnowledge)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use ark_bn254::{Fr, G1Projective};
    use ark_ec::Group;
    use core::ops::Mul;
    use rand::{rngs::OsRng, RngCore};
    use std::string::ToString;

    #[test]
    fn test_serialization() {
        let mut rng = OsRng;

        for _ in 0..100 {
            let nizk = NizkPokOfSecretKey::<G1Projective> {
                s: Fr::rand(&mut rng),
                r: Fr::rand(&mut rng),
            };
            let mut bytes = Vec::new();
            nizk.serialize_compressed(&mut bytes).unwrap();
            assert_eq!(
                nizk,
                NizkPokOfSecretKey::deserialize_compressed(&bytes[..]).unwrap()
            );
        }
    }

    #[test]
    fn test_nizkpok() {
        let mut rng = OsRng;

        let index = rng.next_u32();
        let sk = Fr::rand(&mut rng);
        let pk = G1Projective::generator().mul(sk);
        let context = "This is a context string".to_string();

        let nizk = NizkPokOfSecretKey::<G1Projective>::prove(index, &sk, &pk, &context, &mut rng);
        assert!(nizk.is_ok());
        let nizk = nizk.unwrap();
        assert!(nizk.verify(index, &pk, &context).is_ok());
    }
}
