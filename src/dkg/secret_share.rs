//! The secret sharing module for defining individual secret shares
//! and their public commitments, along with their encrypted versions
//! post Diffie-Hellman key exchange.
//!
//! This module currently only supports AES128-CTR with HKDF instantiated
//! from SHA-256.

use core::marker::PhantomData;

use crate::serialization::impl_serialization_traits;
use crate::utils::{Scalar, ToString, Vec};
use crate::{Error, FrostResult};

use crate::ciphersuite::CipherSuite;

use ark_ec::{CurveGroup, Group};
use ark_ff::{Field, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use rand::{CryptoRng, RngCore};

use aes::cipher::{generic_array::GenericArray, FromBlockCipher, NewBlockCipher, StreamCipher};
use aes::{Aes128, Aes128Ctr};
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
        let mut rhs: C::G = <C as CipherSuite>::G::zero();

        for (index, com) in commitment.points.iter().rev().enumerate() {
            rhs += com;

            if index != (commitment.points.len() - 1) {
                rhs *= term;
            }
        }

        if lhs.into_affine() == rhs.into_affine() {
            Ok(())
        } else {
            Err(Error::ShareVerificationError)
        }
    }
}

/// A secret share encrypted with a participant's public key
#[derive(Clone, Debug, Eq, PartialEq, CanonicalSerialize, CanonicalDeserialize, Zeroize)]
pub struct EncryptedSecretShare<C: CipherSuite> {
    /// The index of the share maker.
    pub sender_index: u32,
    /// The participant index that this secret share was calculated for.
    pub receiver_index: u32,
    /// The nonce to be used for decryption with AES-CTR mode.
    pub nonce: [u8; 16],
    /// The encrypted polynomial evaluation.
    pub(crate) encrypted_polynomial_evaluation: Vec<u8>,
    #[zeroize(skip)]
    _phantom: PhantomData<C>,
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
        nonce: [u8; 16],
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
}

pub(crate) fn encrypt_share<C: CipherSuite>(
    share: &SecretShare<C>,
    aes_key: &[u8],
    mut rng: impl RngCore + CryptoRng,
) -> FrostResult<C, EncryptedSecretShare<C>> {
    let hkdf = Hkdf::<Sha256>::new(None, aes_key);
    let mut final_aes_key = [0u8; 16];
    hkdf.expand(&[], &mut final_aes_key)
        .map_err(|_| Error::Custom("KDF expansion failed unexpectedly".to_string()))?;

    let mut nonce_array = [0u8; 16];
    rng.fill_bytes(&mut nonce_array);

    let final_aes_key = GenericArray::from_slice(&final_aes_key);
    let nonce = GenericArray::from_slice(&nonce_array);
    let cipher = Aes128::new(final_aes_key);
    let mut cipher = Aes128Ctr::from_block_cipher(cipher, nonce);

    let mut share_bytes = Vec::with_capacity(share.polynomial_evaluation.compressed_size());
    share
        .polynomial_evaluation
        .serialize_compressed(&mut share_bytes)
        .map_err(|_| Error::CompressionError)?;
    cipher.apply_keystream(&mut share_bytes);

    Ok(EncryptedSecretShare::<C> {
        sender_index: share.sender_index,
        receiver_index: share.receiver_index,
        nonce: nonce_array,
        encrypted_polynomial_evaluation: share_bytes,
        _phantom: PhantomData,
    })
}

pub(crate) fn decrypt_share<C: CipherSuite>(
    encrypted_share: &EncryptedSecretShare<C>,
    aes_key: &[u8],
) -> FrostResult<C, SecretShare<C>> {
    let hkdf = Hkdf::<Sha256>::new(None, aes_key);
    let mut final_aes_key = [0u8; 16];
    hkdf.expand(&[], &mut final_aes_key)
        .expect("KDF expansion failed unexpectedly");

    let final_aes_key = GenericArray::from_slice(&final_aes_key);

    let nonce = GenericArray::from_slice(&encrypted_share.nonce);
    let cipher = Aes128::new(final_aes_key);
    let mut cipher = Aes128Ctr::from_block_cipher(cipher, nonce);

    let mut bytes = encrypted_share.encrypted_polynomial_evaluation.clone();
    cipher.apply_keystream(&mut bytes);

    let evaluation =
        Scalar::<C>::deserialize_compressed(&bytes[..]).map_err(|_| Error::DecryptionError)?;

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
    use rand::{rngs::OsRng, RngCore};

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
            let mut nonce = [0u8; 16];
            let mut encrypted_polynomial_evaluation = vec![0u8; 16];
            rng.fill_bytes(&mut nonce);
            rng.fill_bytes(&mut encrypted_polynomial_evaluation);
            let encrypted_secret_share = EncryptedSecretShare::<Secp256k1Sha256>::new(
                rng.next_u32(),
                rng.next_u32(),
                nonce,
                encrypted_polynomial_evaluation,
            );
            let mut bytes = Vec::with_capacity(encrypted_secret_share.compressed_size());
            encrypted_secret_share
                .serialize_compressed(&mut bytes)
                .unwrap();
            assert_eq!(
                encrypted_secret_share,
                EncryptedSecretShare::deserialize_compressed(&bytes[..]).unwrap()
            );
        }
    }
}
