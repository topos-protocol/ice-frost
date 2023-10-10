//! The parameters module for defining the threshold parameters to be used within an ICE-FROST session.

use core::marker::PhantomData;

use crate::ciphersuite::CipherSuite;
use crate::utils::Vec;
use crate::{Error, FrostResult};

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

/// The configuration parameters for conducting the process of creating a
/// threshold signature.
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct ThresholdParameters<C: CipherSuite> {
    /// The number of participants in the scheme.
    pub n: u32,
    /// The threshold required for a successful signature.
    pub t: u32,
    _phantom: PhantomData<C>,
}

impl<C: CipherSuite> ThresholdParameters<C> {
    /// Initialize a new set of threshold parameters.
    ///
    /// Will panic if one of the following condition is met:
    ///  - n equals 0
    ///  - t equals 0
    ///  - n < t
    pub fn new(n: u32, t: u32) -> Self {
        assert!(n > 0);
        assert!(t > 0);
        assert!(n >= t);

        Self {
            n,
            t,
            _phantom: PhantomData,
        }
    }

    /// Serialize this [`ThresholdParameters`] to a vector of bytes.
    pub fn to_bytes(&self) -> FrostResult<C, Vec<u8>> {
        let mut bytes = Vec::with_capacity(self.compressed_size());

        self.serialize_compressed(&mut bytes)
            .map_err(|_| Error::SerializationError)?;

        Ok(bytes)
    }

    /// Attempt to deserialize a [`ThresholdParameters`] from a vector of bytes.
    pub fn from_bytes(bytes: &[u8]) -> FrostResult<C, Self> {
        Self::deserialize_compressed(bytes).map_err(|_| Error::DeserializationError)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::testing::Secp256k1Sha256;
    use rand::{rngs::OsRng, RngCore};

    #[test]
    fn test_serialisation() {
        let mut rng = OsRng;

        for _ in 0..100 {
            let n = rng.next_u32();
            let t = core::cmp::min(n, rng.next_u32());
            let params = ThresholdParameters::<Secp256k1Sha256>::new(n, t);
            let bytes = params.to_bytes().unwrap();
            assert!(ThresholdParameters::<Secp256k1Sha256>::from_bytes(&bytes).is_ok());
            assert_eq!(params, ThresholdParameters::from_bytes(&bytes).unwrap());
        }
    }
}
