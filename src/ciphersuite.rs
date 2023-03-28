use core::fmt::Debug;
use core::marker::{Send, Sync};

use zeroize::Zeroize;

use ark_ec::{CurveGroup, Group};

use crate::utils::String;
use crate::FrostResult;
use digest::{Digest, DynDigest};

/// A trait defining the prime-order group of operation and cryptographic hash function details
/// of this ICE-FROST protocol instantiation.
pub trait CipherSuite: Copy + Clone + PartialEq + Eq + Debug + Send + Sync + Zeroize {
    /// The prime-order group on which this ICE-FROST [`CipherSuite`] operates.
    type G: CurveGroup;

    /// A byte array of a given length for this [`CipherSuite`]'s binary hashers.
    type HashOutput: AsRef<[u8]> + AsMut<[u8]> + Default;

    /// The underlying hasher used to construct all random oracles of this [`CipherSuite`] .
    type InnerHasher: Default + Clone + Digest + DynDigest;

    /// The security parameter of this [`CipherSuite`]'s `InnerHasher` .
    const HASH_SEC_PARAM: usize;

    //////////////////////////////////////////////////////////////////////////////////////////////

    // Required methods

    /// A method returning this [`CipherSuite`]'s custom context string, to be used in the different
    /// random oracles invoked in the ICE-FROST protocol.
    fn context_string() -> String;

    ///////////////////////////////////////////////////////////////////////////////////////////////

    // Provided methods`

    /// `h0` hash for this [`CipherSuite`] .
    ///
    /// This oracle is not part of the FROST IETF specification, and is
    /// aimed at being used during the distributed key generation phase.
    ///
    /// The context string for `h0` is this [`CipherSuite`]'s `CONTEXT_STRING`,
    /// concatenated with "nizkpok".
    ///
    /// It is used to compute the Non-Interactive Zero-Knowledge proofs
    /// of Knowledge of the participants' private keys.
    fn h0(m: &[u8]) -> FrostResult<Self, <Self::G as Group>::ScalarField>
    where
        [(); Self::HASH_SEC_PARAM]:,
    {
        crate::utils::hash_to_field::<Self>((Self::context_string() + "nizkpok").as_bytes(), m)
    }

    /// `h1` hash for this [`CipherSuite`] .
    ///
    /// The context string for `h1` is this [`CipherSuite`]'s `CONTEXT_STRING`,
    /// concatenated with "rho".
    ///
    /// It is used to compute the binding factor during an ICE-FROST signing session.
    fn h1(m: &[u8]) -> FrostResult<Self, <Self::G as Group>::ScalarField>
    where
        [(); Self::HASH_SEC_PARAM]:,
    {
        crate::utils::hash_to_field::<Self>((Self::context_string() + "rho").as_bytes(), m)
    }

    /// `h2` hash for this [`CipherSuite`] .
    ///
    /// The context string for `h2` is this [`CipherSuite`]'s `CONTEXT_STRING`,
    /// concatenated with "challenge".
    ///
    /// It is used to compute the binding factor during an ICE-FROST signing session.
    fn h2(m: &[u8]) -> FrostResult<Self, <Self::G as Group>::ScalarField>
    where
        [(); Self::HASH_SEC_PARAM]:,
    {
        crate::utils::hash_to_field::<Self>((Self::context_string() + "challenge").as_bytes(), m)
    }

    /// `h3` hash for this [`CipherSuite`] .
    ///
    /// The context string for `h3` is this [`CipherSuite`]'s `CONTEXT_STRING`,
    /// concatenated with "nonce".
    ///
    /// It is used to precompute the nonces to be shared during ICE-FROST signing sessions.
    fn h3(m: &[u8]) -> FrostResult<Self, <Self::G as Group>::ScalarField>
    where
        [(); Self::HASH_SEC_PARAM]:,
    {
        crate::utils::hash_to_field::<Self>((Self::context_string() + "nonce").as_bytes(), m)
    }

    /// `h4` hash for this [`CipherSuite`] .
    ///
    /// The context string for `h4` is this [`CipherSuite`]'s `CONTEXT_STRING`,
    /// concatenated with "message".
    ///
    /// It is used to hash the message to sign during an ICE-FROST signing session.
    ///
    /// Signers of an ICE-FROST session should use this method to hash the original message
    /// before proceeding to computing their individual partial signatures.
    fn h4(m: &[u8]) -> FrostResult<Self, Self::HashOutput> {
        crate::utils::hash_to_array::<Self>((Self::context_string() + "message").as_bytes(), m)
    }

    /// `h5` hash for this [`CipherSuite`] .
    ///
    /// The context string for `h5` is this [`CipherSuite`]'s `CONTEXT_STRING`,
    /// concatenated with "commitment".
    ///
    /// It is used to hash the group commitment during an ICE-FROST signing session.
    fn h5(m: &[u8]) -> FrostResult<Self, Self::HashOutput> {
        crate::utils::hash_to_array::<Self>((Self::context_string() + "commitment").as_bytes(), m)
    }
}
