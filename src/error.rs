use crate::ciphersuite::CipherSuite;

use crate::dkg::Complaint;
use crate::utils::{String, Vec};

/// Errors that may happen during Key Generation
#[derive(Debug, PartialEq, Eq)]
pub enum Error<C: CipherSuite> {
    /// Serialisation error
    SerialisationError,
    /// Deserialisation error
    DeserialisationError,
    /// Point compression error
    PointCompressionError,
    /// Point decompression error
    PointDecompressionError,
    /// Encrypted secret share decryption failure
    DecryptionError,
    /// Secret share verification failure
    ShareVerificationError,
    /// Complaint verification failure
    ComplaintVerificationError,
    /// GroupKey generation failure
    InvalidGroupKey,
    /// Invalid NiZK proof of knowledge
    InvalidProofOfKnowledge,
    /// The participant is missing some others' secret shares
    MissingShares,
    /// Could not retrieve the participant's encrypted shares
    NoEncryptedShares,
    // /// At least one complaint has been issued during to_round_two() execution
    Complaint(Vec<Complaint<C>>),
    /// Not all participants have been included
    InvalidNumberOfParticipants(usize, u32),
    /// The provided slices for the MSM don't match in lenth
    InvalidMSMParameters,
    /// Too many invalid participants, with their indices
    TooManyInvalidParticipants(Vec<u32>),
    /// The participant is missing commitment shares
    MissingCommitmentShares,
    /// Invalid binding factor
    InvalidBindingFactor,
    /// Invalid challenge
    InvalidChallenge,
    /// Invalid signature
    InvalidSignature,
    /// Misbehaving Participants
    MisbehavingParticipants(Vec<u32>),
    /// Custom error
    Custom(String),
}

impl<C: CipherSuite> core::fmt::Display for Error<C> {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            Error::SerialisationError => {
                write!(f, "An error happened while serialising.")
            }
            Error::DeserialisationError => {
                write!(f, "An error happened while deserialising.")
            }
            Error::PointCompressionError => {
                write!(f, "An error happened while compressing a point.")
            }
            Error::PointDecompressionError => {
                write!(f, "An error happened while decompressing a point.")
            }
            Error::DecryptionError => {
                write!(f, "Could not decrypt encrypted share.")
            }
            Error::ShareVerificationError => {
                write!(f, "The secret share is not correct.")
            }
            Error::ComplaintVerificationError => {
                write!(f, "The complaint is not correct.")
            }
            Error::InvalidGroupKey => {
                write!(
                    f,
                    "Could not generate a valid group key with the given commitments."
                )
            }
            Error::InvalidProofOfKnowledge => {
                write!(
                    f,
                    "The NiZK proof of knowledge of the secret key is not correct."
                )
            }
            Error::MissingShares => {
                write!(f, "Some shares are missing.")
            }
            Error::NoEncryptedShares => {
                write!(f, "Could not retrieve encrypted shares.")
            }
            Error::Complaint(complaints) => {
                write!(f, "{:?}", complaints)
            }
            Error::InvalidMSMParameters => {
                write!(
                    f,
                    "The provided slices of points and scalars do not match in length."
                )
            }
            Error::InvalidNumberOfParticipants(nb, n_params) => {
                write!(
                    f,
                    "The number of participants {} does not match Dkg instance parameters {}.",
                    nb, n_params
                )
            }
            Error::TooManyInvalidParticipants(indices) => {
                write!(
                    f,
                    "Too many invalid participants to continue the Dkg: {:?}",
                    indices
                )
            }
            Error::MissingCommitmentShares => {
                write!(
                    f,
                    "The participant is missing commitment shares for signing."
                )
            }
            Error::InvalidBindingFactor => {
                write!(f, "Could not compute the participant binding factor.")
            }
            Error::InvalidChallenge => {
                write!(f, "Could not compute the signature challenge.")
            }
            Error::InvalidSignature => {
                write!(f, "The threshold signature is not correct.")
            }
            Error::MisbehavingParticipants(indices) => {
                write!(
                    f,
                    "These participants provided invalid partial signatures: {:?}",
                    indices
                )
            }
            Error::Custom(string) => {
                write!(f, "{:?}", string)
            }
        }
    }
}

pub type FrostResult<C, T> = Result<T, Error<C>>;
