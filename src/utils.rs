//! Utility module.

use ark_ff::field_hashers::{DefaultFieldHasher, HashToField};

#[cfg(not(feature = "std"))]
pub use alloc::{
    borrow::ToOwned,
    boxed::Box,
    collections::btree_map::BTreeMap,
    string::{String, ToString},
    vec::Vec,
};

#[cfg(feature = "std")]
pub use std::{
    borrow::ToOwned,
    boxed::Box,
    collections::btree_map::BTreeMap,
    string::{String, ToString},
    vec::Vec,
};

use crate::{ciphersuite::CipherSuite, HASH_SEC_PARAM};

use crate::{Error, FrostResult};
use ark_ec::Group;
use ark_ff::Field;

use digest::Digest;

// Convenient type alias to reduce verbosity when needing to access the
// internal ScalarField type of a `CipherSuite`.
pub(crate) type Scalar<C> = <<C as CipherSuite>::G as Group>::ScalarField;

/// Interpolate a polynomial with Lagrange method.
///
/// This will error if one of the following conditions is met:
/// * `my_index` is 0;
/// * `all_indices` contains 0;
/// * `all_indices` does not contain `my_index`;
/// * `all_indices` contains duplicate indices.
pub(crate) fn calculate_lagrange_coefficients<C: CipherSuite>(
    my_index: u32,
    all_indices: &[u32],
) -> FrostResult<C, Scalar<C>> {
    let mut sorted_indices = all_indices.to_vec();
    sorted_indices.sort_unstable();
    sorted_indices.dedup();
    if sorted_indices.len() != all_indices.len() {
        return Err(Error::Custom("Duplicate indices provided".to_string()));
    }

    // Also handles the case where `my_index` is 0.
    if sorted_indices.contains(&0) {
        return Err(Error::IndexIsZero);
    }

    let mut numerator = Scalar::<C>::ONE;
    let mut denominator = Scalar::<C>::ONE;

    let my_index_field = Scalar::<C>::from(my_index);

    for j in sorted_indices {
        if j == my_index {
            continue;
        }
        let s = Scalar::<C>::from(j);

        numerator *= s;
        denominator *= s - my_index_field;
    }

    Ok(numerator
        * denominator
            .inverse()
            .ok_or_else(|| Error::Custom("Duplicate indices provided".to_string()))?)
}

pub fn hash_to_field<C: CipherSuite>(context_string: &[u8], message_to_hash: &[u8]) -> Scalar<C> {
    let h = <DefaultFieldHasher<C::InnerHasher, { HASH_SEC_PARAM }> as HashToField<Scalar<C>>>::new(
        context_string,
    );

    h.hash_to_field(message_to_hash, 1)[0]
}

pub fn hash_to_array<C: CipherSuite>(
    context_string: &[u8],
    message_to_hash: &[u8],
) -> C::HashOutput {
    let mut h = C::InnerHasher::new();
    h.update(context_string);
    h.update(message_to_hash);

    let mut output = C::HashOutput::default();
    output.as_mut().copy_from_slice(h.finalize().as_slice());

    output
}

#[cfg(test)]
mod test {
    use super::*;

    use crate::testing::Secp256k1Sha256;

    #[test]
    fn invalid_lagrange_interpolation() {
        // Participant index is zero
        {
            let index = 0u32;
            let all_indices: Vec<u32> = (0..100u32).collect();
            assert!(
                calculate_lagrange_coefficients::<Secp256k1Sha256>(index, &all_indices).is_err()
            );
        }

        // Participants list contains zero
        {
            let index = 2u32;
            let all_indices: Vec<u32> = (0..100u32).collect();
            assert!(
                calculate_lagrange_coefficients::<Secp256k1Sha256>(index, &all_indices).is_err()
            );
        }

        // Participants list does not contain participant index
        {
            let index = 101u32;
            let all_indices: Vec<u32> = (0..100u32).collect();
            assert!(
                calculate_lagrange_coefficients::<Secp256k1Sha256>(index, &all_indices).is_err()
            );
        }

        // Participants list contains duplicated indices
        {
            let index = 4u32;
            let mut all_indices: Vec<u32> = (1..100u32).collect();
            all_indices[63] = 12;
            assert!(
                calculate_lagrange_coefficients::<Secp256k1Sha256>(index, &all_indices).is_err()
            );
        }
    }
}
