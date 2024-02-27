//! The secret sharing module for defining individual secret shares
//! and their public commitments, along with their encrypted versions
//! post Diffie-Hellman key exchange.
//!
//! This module currently only supports AES128-GCM with HKDF instantiated
//! from SHA-256.

use core::fmt::Debug;
use core::marker::PhantomData;

use crate::parameters::ThresholdParameters;
use crate::serialization::impl_serialization_traits;
use crate::utils::{Scalar, ToString, Vec};
use crate::{Error, FrostResult};

use crate::ciphersuite::CipherSuite;

use ark_ec::{CurveGroup, Group};
use ark_ff::{Field, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use rand::{CryptoRng, RngCore};

use aead::{Aead, AeadCore, Key, KeyInit, KeySizeUser, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;

use zeroize::Zeroize;

/// A struct for holding a shard of the shared secret, in order to ensure that
/// the shard is overwritten with zeroes when it falls out of scope.
#[derive(Debug, Clone, CanonicalSerialize, CanonicalDeserialize, Zeroize)]
pub struct Coefficients<C: CipherSuite>(pub(crate) Vec<Scalar<C>>);

impl_serialization_traits!(Coefficients<CipherSuite>);

impl<C: CipherSuite> Drop for Coefficients<C> {
    fn drop(&mut self) {
        self.0.iter_mut().zeroize();
    }
}

/// A secret share calculated by evaluating a polynomial with secret
/// coefficients for some indeterminant.
#[derive(Clone, Debug, Eq, PartialEq, CanonicalSerialize, CanonicalDeserialize, Zeroize)]
pub struct SecretShare<C: CipherSuite> {
    /// The index of the share maker.
    pub sender_index: u32,
    /// The participant index that this secret share was calculated for.
    pub receiver_index: u32,
    /// The final evaluation of the polynomial for the participant-respective
    /// indeterminant.
    pub(crate) polynomial_evaluation: Scalar<C>,
}

impl_serialization_traits!(SecretShare<CipherSuite>);

impl<C: CipherSuite> Drop for SecretShare<C> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl<C: CipherSuite> SecretShare<C> {
    /// Evaluate the polynomial, `f(x)` for the secret coefficients at the value of `x` .
    pub(crate) fn evaluate_polynomial(
        sender_index: u32,
        receiver_index: u32,
        coefficients: &Coefficients<C>,
    ) -> SecretShare<C> {
        let term: Scalar<C> = (receiver_index).into();
        let mut sum = Scalar::<C>::ZERO;

        // Evaluate using Horner's method.
        for (receiver_index, coefficient) in coefficients.0.iter().rev().enumerate() {
            // The secret is the constant term in the polynomial
            sum += coefficient;

            if receiver_index != (coefficients.0.len() - 1) {
                sum *= term;
            }
        }
        SecretShare {
            sender_index,
            receiver_index,
            polynomial_evaluation: sum,
        }
    }

    /// Verify that this secret share was correctly computed w.r.t. some secret
    /// polynomial coefficients attested to by some `commitment` .
    pub(crate) fn verify(
        &self,
        commitment: &VerifiableSecretSharingCommitment<C>,
    ) -> FrostResult<C, ()> {
        let lhs = C::G::generator() * self.polynomial_evaluation;
        let term: Scalar<C> = self.receiver_index.into();

        let rhs = commitment.evaluate_hiding(&term);

        if lhs.into_affine() == rhs.into_affine() {
            Ok(())
        } else {
            Err(Error::ShareVerificationError)
        }
    }
}

/// A secret share encrypted with a participant's public key
#[derive(Clone, Zeroize)]
pub struct EncryptedSecretShare<C: CipherSuite> {
    /// The index of the share maker.
    pub sender_index: u32,
    /// The participant index that this secret share was calculated for.
    pub receiver_index: u32,
    /// The nonce to be used for decryption of this encrypted share.
    pub nonce: Nonce<C::Cipher>,
    /// The encrypted polynomial evaluation.
    pub(crate) encrypted_polynomial_evaluation: Vec<u8>,
    #[zeroize(skip)]
    _phantom: PhantomData<C>,
}

impl<C: CipherSuite> PartialEq for EncryptedSecretShare<C> {
    fn eq(&self, other: &Self) -> bool {
        self.sender_index == other.sender_index
            && self.receiver_index == other.receiver_index
            && self.nonce.as_slice() == other.nonce.as_slice()
            && self.encrypted_polynomial_evaluation == other.encrypted_polynomial_evaluation
    }
}

impl<C: CipherSuite> Eq for EncryptedSecretShare<C> {}

impl<C: CipherSuite> Debug for EncryptedSecretShare<C> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "EncryptedSecretShare {{ sender_index: {}, receiver_index: {}, nonce: {:?}, encrypted_polynomial_evaluation: {:?} }}",
            self.sender_index,
            self.receiver_index,
            self.nonce,
            self.encrypted_polynomial_evaluation
        )
    }
}

// Required trait to implement `CanonicalDeserialize` below.
impl<C: CipherSuite> ark_serialize::Valid for EncryptedSecretShare<C> {
    fn check(&self) -> Result<(), ark_serialize::SerializationError> {
        self.sender_index.check()?;
        self.receiver_index.check()?;
        // Collecting is not ideal for this and the `serialize_with_mode` / `deserialize_with_mode`
        // implementation below, but is necessary, at least until the `GenericArray` dependency of
        // the aead trait gets bumped to 1.0.
        self.nonce.to_vec().check()?;
        self.encrypted_polynomial_evaluation.check()
    }
}

impl<C: CipherSuite> CanonicalSerialize for EncryptedSecretShare<C> {
    fn serialize_with_mode<W: ark_serialize::Write>(
        &self,
        mut writer: W,
        compress: ark_serialize::Compress,
    ) -> Result<(), ark_serialize::SerializationError> {
        self.sender_index
            .serialize_with_mode(&mut writer, compress)?;
        self.receiver_index
            .serialize_with_mode(&mut writer, compress)?;
        self.nonce
            .to_vec()
            .serialize_with_mode(&mut writer, compress)?;
        self.encrypted_polynomial_evaluation
            .serialize_with_mode(&mut writer, compress)
    }

    fn serialized_size(&self, compress: ark_serialize::Compress) -> usize {
        self.sender_index.serialized_size(compress)
            + self.receiver_index.serialized_size(compress)
            + self.nonce.serialized_size(compress)
            + self
                .encrypted_polynomial_evaluation
                .serialized_size(compress)
    }
}

impl<C: CipherSuite> CanonicalDeserialize for EncryptedSecretShare<C> {
    fn deserialize_with_mode<R: ark_serialize::Read>(
        mut reader: R,
        compress: ark_serialize::Compress,
        validate: ark_serialize::Validate,
    ) -> Result<Self, ark_serialize::SerializationError> {
        let sender_index = u32::deserialize_with_mode(&mut reader, compress, validate)?;
        let receiver_index = u32::deserialize_with_mode(&mut reader, compress, validate)?;
        let nonce_vec = Vec::<u8>::deserialize_with_mode(&mut reader, compress, validate)?;
        let nonce = Nonce::<C::Cipher>::from_exact_iter(nonce_vec)
            .ok_or(ark_serialize::SerializationError::InvalidData)?;
        let encrypted_polynomial_evaluation =
            Vec::<u8>::deserialize_with_mode(&mut reader, compress, validate)?;

        Ok(EncryptedSecretShare::<C>::new(
            sender_index,
            receiver_index,
            nonce,
            encrypted_polynomial_evaluation,
        ))
    }
}

impl_serialization_traits!(EncryptedSecretShare<CipherSuite>);

impl<C: CipherSuite> Drop for EncryptedSecretShare<C> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl<C: CipherSuite> EncryptedSecretShare<C> {
    /// Constructs a new [`EncryptedSecretShare`] from the provided inputs.
    #[must_use]
    pub fn new(
        sender_index: u32,
        receiver_index: u32,
        nonce: Nonce<C::Cipher>,
        encrypted_polynomial_evaluation: Vec<u8>,
    ) -> Self {
        Self {
            sender_index,
            receiver_index,
            nonce,
            encrypted_polynomial_evaluation,
            _phantom: PhantomData,
        }
    }
}

/// A commitment to a participant's secret polynomial coefficients for Feldman's
/// verifiable secret sharing scheme.
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct VerifiableSecretSharingCommitment<C: CipherSuite> {
    /// The index of this participant.
    pub index: u32,
    /// The commitments to the participant's secret coefficients.
    pub points: Vec<C::G>,
}

impl_serialization_traits!(VerifiableSecretSharingCommitment<CipherSuite>);

impl<C: CipherSuite> VerifiableSecretSharingCommitment<C> {
    /// Retrieve \\( \alpha_{i0} * B \\), where \\( B \\) is the prime-order basepoint.
    pub fn public_key(&self) -> Option<&C::G> {
        if !self.points.is_empty() {
            return Some(&self.points[0]);
        }

        None
    }

    /// Evaluate g^P(i) without knowing the secret coefficients of the polynomial
    pub fn evaluate_hiding(&self, term: &Scalar<C>) -> C::G {
        let mut sum = <C as CipherSuite>::G::zero();

        // Evaluate using Horner's method.
        for (k, coefficient) in self.points.iter().rev().enumerate() {
            // The secret is the constant term in the polynomial
            sum += coefficient;

            if k != (self.points.len() - 1) {
                sum *= term;
            }
        }

        sum
    }

    /// Enforces that the number of points of this commitment
    /// matches the [`Ciphersuite`]'s threshold parameter `t`.
    pub fn check_degree(&self, parameters: ThresholdParameters<C>) -> FrostResult<C, ()> {
        if self.points.len() != parameters.t as usize {
            return Err(Error::InvalidCommitmentLength);
        }

        Ok(())
    }
}

/// Encrypt a `SecretShare` given an initial slice of bytes.
///
/// This will perform an HMAC-based Extract-and-Expand Key Derivation Function (HKDF)
/// expansion over the Initial Key Material passed as input. The obtained Output Key
/// Material will then be passed to this `Ciphersuite`'s cipher along with a random
/// nonce to encrypt the private polynomial evaluation corresponding to this secret share.
pub(crate) fn encrypt_share<C: CipherSuite>(
    share: &SecretShare<C>,
    initial_key_bytes: &[u8],
    rng: impl RngCore + CryptoRng,
) -> FrostResult<C, EncryptedSecretShare<C>> {
    let hkdf = Hkdf::<Sha256>::new(None, initial_key_bytes);
    let mut final_aead_key = vec![0u8; <C::Cipher as KeySizeUser>::key_size()];
    hkdf.expand(&[], &mut final_aead_key)
        .map_err(|_| Error::Custom("KDF expansion failed unexpectedly".to_string()))?;

    let key = Key::<C::Cipher>::from_slice(&final_aead_key); // This cannot panic.
    let cipher = C::Cipher::new(key);

    let nonce = C::Cipher::generate_nonce(rng);

    let mut share_bytes = Vec::with_capacity(share.polynomial_evaluation.compressed_size());
    share
        .polynomial_evaluation
        .serialize_compressed(&mut share_bytes)
        .map_err(|_| Error::CompressionError)?;

    let encrypted_polynomial_evaluation = cipher
        .encrypt(&nonce, share_bytes.as_ref())
        .map_err(|_| Error::EncryptionError)?;

    Ok(EncryptedSecretShare::<C> {
        sender_index: share.sender_index,
        receiver_index: share.receiver_index,
        nonce,
        encrypted_polynomial_evaluation,
        _phantom: PhantomData,
    })
}

/// Decrypt an `EncryptedSecretShare` given an initial slice of bytes.
///
/// This will perform an HMAC-based Extract-and-Expand Key Derivation Function (HKDF)
/// expansion over the Initial Key Material passed as input. The obtained Output Key
/// Material will then be passed to this `Ciphersuite`'s cipher along with the associated
/// nonce used to obtain this `EncryptedSecretShare` to decrypt it.
pub(crate) fn decrypt_share<C: CipherSuite>(
    encrypted_share: &EncryptedSecretShare<C>,
    initial_key_bytes: &[u8],
) -> FrostResult<C, SecretShare<C>> {
    let hkdf = Hkdf::<Sha256>::new(None, initial_key_bytes);
    let mut final_aead_key = vec![0u8; <C::Cipher as KeySizeUser>::key_size()];
    hkdf.expand(&[], &mut final_aead_key)
        .map_err(|_| Error::Custom("KDF expansion failed unexpectedly".to_string()))?;

    let key = Key::<C::Cipher>::from_slice(&final_aead_key); // This cannot panic.
    let cipher = C::Cipher::new(key);

    let bytes = cipher
        .decrypt(
            &encrypted_share.nonce,
            encrypted_share.encrypted_polynomial_evaluation.as_ref(),
        )
        .map_err(|_| Error::DecryptionError)?;

    let evaluation =
        Scalar::<C>::deserialize_compressed(&bytes[..]).map_err(|_| Error::DecompressionError)?;

    Ok(SecretShare {
        sender_index: encrypted_share.sender_index,
        receiver_index: encrypted_share.receiver_index,
        polynomial_evaluation: evaluation,
    })
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::testing::Secp256k1Sha256;

    use ark_ff::UniformRand;
    use ark_secp256k1::Fr;
    use rand::rngs::OsRng;

    #[test]
    fn test_serialization() {
        let mut rng = OsRng;

        for _ in 0..100 {
            let secret_share = SecretShare::<Secp256k1Sha256> {
                sender_index: rng.next_u32(),
                receiver_index: rng.next_u32(),
                polynomial_evaluation: Fr::rand(&mut rng),
            };
            let mut bytes = Vec::with_capacity(secret_share.compressed_size());
            secret_share.serialize_compressed(&mut bytes).unwrap();
            assert_eq!(
                secret_share,
                SecretShare::deserialize_compressed(&bytes[..]).unwrap()
            );
        }

        for _ in 0..100 {
            let mut nonce = [0u8; 12];
            let mut encrypted_polynomial_evaluation = vec![0u8; 12];
            rng.fill_bytes(&mut nonce);
            rng.fill_bytes(&mut encrypted_polynomial_evaluation);
            let encrypted_secret_share = EncryptedSecretShare::<Secp256k1Sha256>::new(
                rng.next_u32(),
                rng.next_u32(),
                nonce.into(),
                encrypted_polynomial_evaluation,
            );
            let mut bytes = Vec::with_capacity(encrypted_secret_share.compressed_size());
            encrypted_secret_share
                .serialize_compressed(&mut bytes)
                .unwrap();
            assert_eq!(
                encrypted_secret_share,
                EncryptedSecretShare::deserialize_compressed(&bytes[..]).unwrap(),
            );
        }
    }
}
