use core::fmt::Debug;
use core::marker::{Send, Sync};

use zeroize::Zeroize;

use ark_ec::{CurveGroup, Group};

use crate::utils::String;
use crate::FrostResult;
use digest::{Digest, DynDigest};

pub trait CipherSuite: Copy + Clone + PartialEq + Eq + Debug + Send + Sync + Zeroize {
    type G: CurveGroup;

    /// A byte array of fixed length.
    type HashOutput: AsRef<[u8]> + AsMut<[u8]> + Default;

    type InnerHasher: Default + Clone + Digest + DynDigest;

    /// The security parameter of the underlying hash function `InnerHasher` to be used
    /// to instantiate the provided hash methods.
    const HASH_SEC_PARAM: usize;

    //////////////////////////////////////////////////////////////////////////////////////////////

    // Required methods

    /// A method returning this CipherSuite's custom context string, to be used in the different
    /// hash functions invoked in the ICE-FROST protocol.
    fn context_string() -> String;

    ///////////////////////////////////////////////////////////////////////////////////////////////

    // Provided methods`

    /// `h1` hash for this CipherSuite.
    ///
    /// The context string for `h1` is this CipherSuite's CONTEXT_STRING,
    /// concatenated with "rho".
    fn h1(m: &[u8]) -> FrostResult<Self, <Self::G as Group>::ScalarField>
    where
        [(); Self::HASH_SEC_PARAM]:,
    {
        crate::utils::hash_to_field::<Self>((Self::context_string() + "rho").as_bytes(), m)
    }

    /// `h2` hash for this CipherSuite.
    ///
    /// The context string for `h2` is this CipherSuite's CONTEXT_STRING,
    /// concatenated with "challenge".
    fn h2(m: &[u8]) -> FrostResult<Self, <Self::G as Group>::ScalarField>
    where
        [(); Self::HASH_SEC_PARAM]:,
    {
        crate::utils::hash_to_field::<Self>((Self::context_string() + "challenge").as_bytes(), m)
    }

    /// `h3` hash for this CipherSuite.
    ///
    /// The context string for `h3` is this CipherSuite's CONTEXT_STRING,
    /// concatenated with "nonce".
    fn h3(m: &[u8]) -> FrostResult<Self, <Self::G as Group>::ScalarField>
    where
        [(); Self::HASH_SEC_PARAM]:,
    {
        crate::utils::hash_to_field::<Self>((Self::context_string() + "nonce").as_bytes(), m)
    }

    /// `h4` hash for this CipherSuite.
    ///
    /// The context string for `h4` is this CipherSuite's CONTEXT_STRING,
    /// concatenated with "message".
    fn h4(m: &[u8]) -> FrostResult<Self, Self::HashOutput> {
        crate::utils::hash_to_array::<Self>((Self::context_string() + "message").as_bytes(), m)
    }

    /// `h5` hash for this CipherSuite.
    ///
    /// The context string for `h5` is this CipherSuite's CONTEXT_STRING,
    /// concatenated with "commitment".
    fn h5(m: &[u8]) -> FrostResult<Self, Self::HashOutput> {
        crate::utils::hash_to_array::<Self>((Self::context_string() + "commitment").as_bytes(), m)
    }
}
