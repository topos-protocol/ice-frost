//! The parameters module for defining the threshold parameters to be used within an ICE-FROST session.

use core::marker::PhantomData;

use crate::ciphersuite::CipherSuite;
use crate::serialization::impl_serialization_traits;
use crate::utils::Vec;

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

impl_serialization_traits!(ThresholdParameters<CipherSuite>);

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
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::testing::Secp256k1Sha256;
    use crate::{FromBytes, ToBytes};
    use rand::{rngs::OsRng, RngCore};

    #[test]
    fn test_serialization() {
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
