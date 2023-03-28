//! Utility module.

use ark_ff::field_hashers::{DefaultFieldHasher, HashToField};

#[cfg(not(feature = "std"))]
pub use alloc::{
    borrow::ToOwned,
    boxed::Box,
    collections::btree_map::BTreeMap,
    string::{String, ToString},
    vec::{self, Vec},
};

#[cfg(feature = "std")]
pub use std::{
    borrow::ToOwned,
    boxed::Box,
    collections::btree_map::BTreeMap,
    string::{String, ToString},
    vec::{self, Vec},
};

use crate::ciphersuite::CipherSuite;

use crate::{Error, FrostResult};
use ark_ec::Group;
use ark_ff::Field;

use digest::Digest;

// Convenient type alias to reduce verbosity when needing to access the
// internal ScalarField type of a `CipherSuite`.
pub(crate) type Scalar<C> = <<C as CipherSuite>::G as Group>::ScalarField;

/// Interpolate a polynomial with Lagrange method.
pub(crate) fn calculate_lagrange_coefficients<C: CipherSuite>(
    my_index: u32,
    all_indices: &[u32],
) -> FrostResult<C, Scalar<C>> {
    let mut numerator = Scalar::<C>::ONE;
    let mut denominator = Scalar::<C>::ONE;

    let my_index_field = Scalar::<C>::from(my_index);

    for &j in all_indices.iter() {
        if j == my_index {
            continue;
        }
        let s = Scalar::<C>::from(j);

        numerator *= s;
        denominator *= s - my_index_field;
    }

    if denominator == Scalar::<C>::ZERO {
        return Err(Error::Custom("Duplicate shares provided".to_string()));
    }

    Ok(numerator * denominator.inverse().unwrap())
}

pub fn hash_to_field<C: CipherSuite>(
    context_string: &[u8],
    message_to_hash: &[u8],
) -> FrostResult<C, Scalar<C>>
where
    [(); C::HASH_SEC_PARAM]:,
{
    let h =
        <DefaultFieldHasher<C::InnerHasher, { C::HASH_SEC_PARAM }> as HashToField<Scalar<C>>>::new(
            context_string,
        );

    Ok(h.hash_to_field(message_to_hash, 1)[0])
}

pub fn hash_to_array<C: CipherSuite>(
    context_string: &[u8],
    message_to_hash: &[u8],
) -> FrostResult<C, C::HashOutput> {
    let mut h = C::InnerHasher::new();
    h.update(context_string);
    h.update(message_to_hash);

    let mut output = C::HashOutput::default();
    output.as_mut().copy_from_slice(h.finalize().as_slice());

    Ok(output)
}
