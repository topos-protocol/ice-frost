//! The round module for defining the two rounds of an ICE-FROST
//! Distributed Key Generation session, using the [typestate](http://cliffle.com/blog/rust-typestate/)
//! pattern internally.

use crate::utils::Vec;

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

/// Every participant in the distributed key generation has sent a vector of
/// commitments and a zero-knowledge proof of a secret key to every other
/// participant in the protocol.  During round one, each participant checks the
/// zero-knowledge proofs of secret keys of all other participants.
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct RoundOne {}

/// During round two each participant verifies their secret shares they received
/// from each other participant.
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct RoundTwo {}

/// Module to implement trait sealing so that [`DkgState`] cannot be
/// implemented for externally declared types.
mod private {
    pub trait Sealed {}

    impl Sealed for super::RoundOne {}
    impl Sealed for super::RoundTwo {}
}

/// Marker trait to designate valid rounds in the distributed key generation
/// protocol's state machine.  It is implemented using the [sealed trait design
/// pattern][sealed] pattern to prevent external types from implementing further
/// valid states.
///
/// [sealed]: https://rust-lang.github.io/api-guidelines/future-proofing.html#sealed-traits-protect-against-downstream-implementations-c-sealed
pub trait DkgState: private::Sealed + CanonicalDeserialize + CanonicalSerialize {}

impl DkgState for RoundOne {}
impl DkgState for RoundTwo {}
