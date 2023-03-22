//! Configurable parameters for an instance of an ICE-FROST signing protocol.

use crate::utils::Vec;

use ark_ec::CurveGroup;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use crate::error::Error;
use core::marker::PhantomData;

/// The configuration parameters for conducting the process of creating a
/// threshold signature.
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct ThresholdParameters<G: CurveGroup> {
    /// The number of participants in the scheme.
    pub n: u32,
    /// The threshold required for a successful signature.
    pub t: u32,
    _phantom: PhantomData<G>,
}

impl<G: CurveGroup> ThresholdParameters<G> {
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

    /// Serialize this `ThresholdParameters` to a vector of bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error<G>> {
        let mut bytes = Vec::new();

        self.serialize_compressed(&mut bytes)
            .map_err(|_| Error::SerialisationError)?;

        Ok(bytes)
    }

    /// Attempt to deserialize a `ThresholdParameters` from a vector of bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error<G>> {
        Self::deserialize_compressed(bytes).map_err(|_| Error::DeserialisationError)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use ark_bn254::G1Projective;
    use rand::{rngs::OsRng, RngCore};

    #[test]
    fn test_serialisation() {
        let mut rng = OsRng;

        for _ in 0..100 {
            let n = rng.next_u32();
            let t = core::cmp::min(n, rng.next_u32());
            let params = ThresholdParameters::<G1Projective>::new(n, t);
            let bytes = params.to_bytes().unwrap();
            assert!(ThresholdParameters::<G1Projective>::from_bytes(&bytes).is_ok());
            assert_eq!(params, ThresholdParameters::from_bytes(&bytes).unwrap());
        }
    }
}
