use ark_ec::{AffineRepr, CurveGroup, Group, VariableBaseMSM};
use ark_ff::UniformRand;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use crate::ciphersuite::CipherSuite;
use crate::utils::Vec;
use crate::{Error, FrostResult};

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
pub struct NizkPokOfSecretKey<C: CipherSuite> {
    /// The scalar portion of the Schnorr signature encoding the context.
    s: <C::G as Group>::ScalarField,
    /// The scalar portion of the Schnorr signature which is the actual signature.
    r: <C::G as Group>::ScalarField,
}

impl<C: CipherSuite> NizkPokOfSecretKey<C>
where
    [(); C::HASH_SEC_PARAM]:,
{
    /// Serialize this `NizkPokOfSecretKey` to a vector of bytes.
    pub fn to_bytes(&self) -> FrostResult<C, Vec<u8>> {
        let mut bytes = Vec::new();

        self.serialize_compressed(&mut bytes)
            .map_err(|_| Error::SerialisationError)?;

        Ok(bytes)
    }

    /// Attempt to deserialize a `NizkPokOfSecretKey` from a vector of bytes.
    pub fn from_bytes(bytes: &[u8]) -> FrostResult<C, Self> {
        Self::deserialize_compressed(bytes).map_err(|_| Error::DeserialisationError)
    }

    /// Prove knowledge of a secret key.
    pub fn prove(
        index: u32,
        secret_key: &<C::G as Group>::ScalarField,
        public_key: &C::G,
        mut csprng: impl Rng + CryptoRng,
    ) -> FrostResult<C, Self> {
        let k = <C::G as Group>::ScalarField::rand(&mut csprng);
        let M: C::G = C::G::generator() * k;

        let mut message = index.to_le_bytes().to_vec();
        public_key
            .serialize_compressed(&mut message)
            .map_err(|_| Error::PointCompressionError)?;
        M.serialize_compressed(&mut message)
            .map_err(|_| Error::PointCompressionError)?;

        let s = C::h0(&message)?;
        let r = k + (*secret_key * s);

        Ok(NizkPokOfSecretKey { s, r })
    }

    /// Verify that the prover does indeed know the secret key.
    pub fn verify(&self, index: u32, public_key: &C::G) -> FrostResult<C, ()> {
        let M_prime: C::G = <C as CipherSuite>::G::msm(
            &[
                <C::G as CurveGroup>::Affine::generator(),
                public_key.into_affine(),
            ],
            &[self.r, -self.s],
        )
        .map_err(|_| Error::InvalidMSMParameters)?;

        let mut message = index.to_le_bytes().to_vec();
        public_key
            .serialize_compressed(&mut message)
            .map_err(|_| Error::PointCompressionError)?;
        M_prime
            .serialize_compressed(&mut message)
            .map_err(|_| Error::PointCompressionError)?;

        let s_prime = C::h0(&message)?;

        if self.s == s_prime {
            return Ok(());
        }

        Err(Error::InvalidProofOfKnowledge)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::testing::Secp256k1Sha256;

    use ark_ec::Group;
    use ark_secp256k1::{Fr, Projective};
    use core::ops::Mul;
    use rand::{rngs::OsRng, RngCore};

    #[test]
    fn test_serialization() {
        let mut rng = OsRng;

        for _ in 0..100 {
            let nizk = NizkPokOfSecretKey::<Secp256k1Sha256> {
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
        let pk = Projective::generator().mul(sk);

        let nizk = NizkPokOfSecretKey::<Secp256k1Sha256>::prove(index, &sk, &pk, rng);
        assert!(nizk.is_ok());
        let nizk = nizk.unwrap();
        assert!(nizk.verify(index, &pk).is_ok());
    }
}
