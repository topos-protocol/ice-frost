use ark_ff::field_hashers::{DefaultFieldHasher, HashToField};
use ark_serialize::CanonicalSerialize;

#[cfg(not(feature = "std"))]
pub use alloc::{
    boxed::Box,
    collections::btree_map::BTreeMap,
    string::{String, ToString},
    vec::{self, Vec},
};

#[cfg(feature = "std")]
pub use std::{
    boxed::Box,
    collections::btree_map::BTreeMap,
    string::{String, ToString},
    vec::{self, Vec},
};

use crate::error::Error;
use ark_ec::CurveGroup;
use ark_ff::Field;

use sha2::Sha256;

/// Interpolate a polynomial with Lagrange method.
pub(crate) fn calculate_lagrange_coefficients<G: CurveGroup>(
    my_index: u32,
    all_indices: &[u32],
) -> Result<G::ScalarField, Error<G>> {
    let mut numerator = G::ScalarField::ONE;
    let mut denominator = G::ScalarField::ONE;

    let my_index_field = G::ScalarField::from(my_index);

    for &j in all_indices.iter() {
        if j == my_index {
            continue;
        }
        let s = G::ScalarField::from(j);

        numerator *= s;
        denominator *= s - my_index_field;
    }

    if denominator == G::ScalarField::ZERO {
        return Err(Error::Custom("Duplicate shares provided".to_string()));
    }

    Ok(numerator * denominator.inverse().unwrap())
}

pub fn hash_to_field<G: CurveGroup>(
    context_string: &[u8],
    message_to_hash: &[u8],
) -> Result<G::ScalarField, Error<G>> {
    let h = <DefaultFieldHasher<Sha256, 128> as HashToField<G::ScalarField>>::new(context_string);

    Ok(h.hash_to_field(message_to_hash, 1)[0])
}

pub fn hash_to_bytes<G: CurveGroup>(
    context_string: &[u8],
    message_to_hash: &[u8],
) -> Result<Vec<u8>, Error<G>> {
    let h = <DefaultFieldHasher<Sha256, 128> as HashToField<G::ScalarField>>::new(context_string);

    let output: G::ScalarField = h.hash_to_field(message_to_hash, 1)[0];
    let mut output_bytes = Vec::new();
    output
        .serialize_compressed(&mut output_bytes)
        .map_err(|_| Error::PointCompressionError)?;

    Ok(output_bytes)
}

pub fn compute_challenge<G: CurveGroup>(
    message_hash: &[u8],
    group_key: &crate::keys::GroupKey<G>,
    R: &G,
) -> Result<G::ScalarField, Error<G>> {
    let mut message = message_hash.to_vec();
    R.serialize_compressed(&mut message)
        .map_err(|_| Error::PointCompressionError)?;
    group_key
        .serialize_compressed(&mut message)
        .map_err(|_| Error::PointCompressionError)?;

    hash_to_field("FROST Challenge SHA256".as_bytes(), &message)
}
