//! The error module for error handling during ICE-FROST sessions.

use crate::ciphersuite::CipherSuite;

use crate::dkg::Complaint;
use crate::utils::{String, Vec};

/// Errors that may happen during Key Generation/Resharing
/// or Signing phases of ICE-FROST.
#[derive(Debug, PartialEq, Eq)]
pub enum Error<C: CipherSuite> {
    /// Serialization error
    SerializationError,
    /// Deserialization error
    DeserializationError,
    /// Point compression error
    CompressionError,
    /// Point decompression error
    DecompressionError,
    /// Encrypted secret share decryption failure
    DecryptionError,
    /// Secret share encryption failure
    EncryptionError,
    /// Secret share verification failure
    ShareVerificationError,
    /// Complaint verification failure
    ComplaintVerificationError,
    /// The index of a participant is zero
    IndexIsZero,
    /// The index of a signer does not match the index in the public key
    IndexMismatch(u32, u32),
    /// GroupVerifyingKey generation failure
    InvalidGroupKey,
    /// Invalid NiZK proof of knowledge
    InvalidProofOfKnowledge,
    /// Inconsistent commitment length with threshold parameter.
    InvalidCommitmentLength,
    /// The participant is missing some others' secret shares
    MissingShares,
    /// Could not retrieve the participant's encrypted shares
    NoEncryptedShares,
    /// At least one complaint has been issued during `to_round_two()` execution
    Complaint(Vec<Complaint<C>>),
    /// Not all participants have been included
    InvalidNumberOfParticipants(usize, u32),
    /// The provided slices for the MSM don't match in length
    InvalidMSMParameters,
    /// Too many invalid participants, with their indices
    TooManyInvalidParticipants(Vec<u32>),
    /// Too many unique signers given the [`crate::parameters::ThresholdParameters`].
    TooManySigners(usize, u32),
    /// The participant is missing commitment shares
    MissingCommitmentShares,
    /// Invalid binding factor
    InvalidBindingFactor,
    /// Invalid challenge
    InvalidChallenge,
    /// Invalid signature
    InvalidSignature,
    /// Misbehaving participants
    MisbehavingParticipants(Vec<u32>),
    /// A valid [`ThresholdParams`] requires non-zero participants, non-zero
    /// threshold and more participants than the threshold.
    InvalidThresholdParams,
    /// Custom error
    Custom(String),
}

impl<C: CipherSuite> core::fmt::Display for Error<C> {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            Error::SerializationError => write!(f, "An error happened while serializing."),
            Error::DeserializationError => write!(f, "An error happened while deserializing."),
            Error::CompressionError => write!(f, "An error happened while compressing a point."),
            Error::DecompressionError => {
                write!(f, "An error happened while decompressing a point.")
            }
            Error::DecryptionError => write!(f, "Could not decrypt encrypted share."),
            Error::EncryptionError => write!(f, "Could not encrypt secret share."),
            Error::ShareVerificationError => write!(f, "The secret share is not correct."),
            Error::ComplaintVerificationError => write!(f, "The complaint is not correct."),
            Error::IndexIsZero => write!(f, "The indexs of a participant cannot be 0."),
            Error::IndexMismatch(participant_idx, pubkey_idx) => write!(
                f,
                "Index mismatch between participant index ({}) and the public key index ({}).",
                participant_idx, pubkey_idx
            ),
            Error::InvalidGroupKey => write!(
                f,
                "Could not generate a valid group key with the given commitments."
            ),
            Error::TooManySigners(signers, n_param) => {
                write!(
                    f,
                    "Too many signers ({}) given the DKG instance parameters (total participants set to {}).",
                    signers, n_param
                )
            }
            Error::InvalidProofOfKnowledge => write!(
                f,
                "The NiZK proof of knowledge of the secret key is not correct."
            ),
            Error::InvalidCommitmentLength => write!(
                f,
                "The length of this commitment does not correspond to the threshold parameter."
            ),
            Error::MissingShares => write!(f, "Some shares are missing."),
            Error::NoEncryptedShares => write!(f, "Could not retrieve encrypted shares."),
            Error::Complaint(complaints) => write!(f, "{:?}", complaints),
            Error::InvalidMSMParameters => write!(
                f,
                "The provided slices of points and scalars do not match in length."
            ),
            Error::InvalidNumberOfParticipants(nb, n_params) => write!(
                f,
                "The number of participants {} does not match Dkg instance parameters {}.",
                nb, n_params
            ),
            Error::TooManyInvalidParticipants(indices) => write!(
                f,
                "Too many invalid participants to continue the Dkg: {:?}",
                indices
            ),
            Error::MissingCommitmentShares => write!(
                f,
                "The participant is missing commitment shares for signing."
            ),
            Error::InvalidBindingFactor => {
                write!(f, "Could not compute the participant binding factor.")
            }
            Error::InvalidChallenge => write!(f, "Could not compute the signature challenge."),
            Error::InvalidSignature => write!(f, "The threshold signature is not correct."),
            Error::MisbehavingParticipants(indices) => write!(
                f,
                "These participants provided invalid partial signatures: {:?}",
                indices
            ),
            Error::InvalidThresholdParams => write!(f, "Invalid threshold parameters"),
            Error::Custom(string) => write!(f, "{:?}", string),
        }
    }
}

/// Type alias for a Result returning an ICE-FROST-related error on failure.
pub type FrostResult<C, T> = Result<T, Error<C>>;
