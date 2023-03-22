use core::marker::PhantomData;

use crate::error::Error;
use crate::utils::Vec;

use ark_ec::CurveGroup;
use ark_ff::Field;
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
pub struct Coefficients<G: CurveGroup>(pub(crate) Vec<G::ScalarField>);

impl<G: CurveGroup> Coefficients<G> {
    /// Serialize this `Coefficients` to a vector of bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error<G>> {
        let mut bytes = Vec::new();

        self.serialize_compressed(&mut bytes)
            .map_err(|_| Error::SerialisationError)?;

        Ok(bytes)
    }

    /// Attempt to deserialize a `Coefficients` from a vector of bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error<G>> {
        Self::deserialize_compressed(bytes).map_err(|_| Error::DeserialisationError)
    }
}

impl<G: CurveGroup> Drop for Coefficients<G> {
    fn drop(&mut self) {
        self.0.iter_mut().zeroize();
    }
}

/// A secret share calculated by evaluating a polynomial with secret
/// coefficients for some indeterminant.
#[derive(Clone, Debug, Eq, PartialEq, CanonicalSerialize, CanonicalDeserialize, Zeroize)]
pub struct SecretShare<G: CurveGroup> {
    /// The index of the share maker.
    pub sender_index: u32,
    /// The participant index that this secret share was calculated for.
    pub receiver_index: u32,
    /// The final evaluation of the polynomial for the participant-respective
    /// indeterminant.
    pub(crate) polynomial_evaluation: G::ScalarField,
}

impl<G: CurveGroup> Drop for SecretShare<G> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl<G: CurveGroup> SecretShare<G> {
    /// Serialize this `SecretShare` to a vector of bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error<G>> {
        let mut bytes = Vec::new();

        self.serialize_compressed(&mut bytes)
            .map_err(|_| Error::SerialisationError)?;

        Ok(bytes)
    }

    /// Attempt to deserialize a `SecretShare` from a vector of bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error<G>> {
        Self::deserialize_compressed(bytes).map_err(|_| Error::DeserialisationError)
    }

    /// Evaluate the polynomial, `f(x)` for the secret coefficients at the value of `x`.
    pub(crate) fn evaluate_polynomial(
        sender_index: &u32,
        receiver_index: &u32,
        coefficients: &Coefficients<G>,
    ) -> SecretShare<G> {
        let term: G::ScalarField = (*receiver_index).into();
        let mut sum = G::ScalarField::ZERO;

        // Evaluate using Horner's method.
        for (receiver_index, coefficient) in coefficients.0.iter().rev().enumerate() {
            // The secret is the constant term in the polynomial
            sum += coefficient;

            if receiver_index != (coefficients.0.len() - 1) {
                sum *= term;
            }
        }
        SecretShare {
            sender_index: *sender_index,
            receiver_index: *receiver_index,
            polynomial_evaluation: sum,
        }
    }

    /// Verify that this secret share was correctly computed w.r.t. some secret
    /// polynomial coefficients attested to by some `commitment`.
    pub(crate) fn verify(
        &self,
        commitment: &VerifiableSecretSharingCommitment<G>,
    ) -> Result<(), Error<G>> {
        let lhs = G::generator() * self.polynomial_evaluation;
        let term: G::ScalarField = self.receiver_index.into();
        let mut rhs: G = G::zero();

        for (index, com) in commitment.points.iter().rev().enumerate() {
            rhs += com;

            if index != (commitment.points.len() - 1) {
                rhs *= term;
            }
        }

        match lhs.into_affine() == rhs.into_affine() {
            true => Ok(()),
            false => Err(Error::ShareVerificationError),
        }
    }
}

/// A secret share encrypted with a participant's public key
#[derive(Clone, Debug, Eq, PartialEq, CanonicalSerialize, CanonicalDeserialize, Zeroize)]
pub struct EncryptedSecretShare<G: CurveGroup> {
    /// The index of the share maker.
    pub sender_index: u32,
    /// The participant index that this secret share was calculated for.
    pub receiver_index: u32,
    /// The nonce to be used for decryption with AES-CTR mode.
    pub nonce: [u8; 16],
    /// The encrypted polynomial evaluation.
    pub(crate) encrypted_polynomial_evaluation: Vec<u8>,
    #[zeroize(skip)]
    _phantom: PhantomData<G>,
}

impl<G: CurveGroup> Drop for EncryptedSecretShare<G> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl<G: CurveGroup> EncryptedSecretShare<G> {
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

    /// Serialize this `EncryptedSecretShare` to a vector of bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error<G>> {
        let mut bytes = Vec::new();

        self.serialize_compressed(&mut bytes)
            .map_err(|_| Error::SerialisationError)?;

        Ok(bytes)
    }

    /// Attempt to deserialize a `EncryptedSecretShare` from a vector of bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error<G>> {
        Self::deserialize_compressed(bytes).map_err(|_| Error::DeserialisationError)
    }
}

/// A commitment to a participant's secret polynomial coefficients for Feldman's
/// verifiable secret sharing scheme.
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct VerifiableSecretSharingCommitment<G: CurveGroup> {
    /// The index of this participant.
    pub index: u32,
    /// The commitments to the participant's secret coefficients.
    pub points: Vec<G>,
}

impl<G: CurveGroup> VerifiableSecretSharingCommitment<G> {
    /// Serialize this `VerifiableSecretSharingCommitment` to a vector of bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error<G>> {
        let mut bytes = Vec::new();

        self.serialize_compressed(&mut bytes)
            .map_err(|_| Error::SerialisationError)?;

        Ok(bytes)
    }

    /// Attempt to deserialize a `VerifiableSecretSharingCommitment` from a vector of bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error<G>> {
        Self::deserialize_compressed(bytes).map_err(|_| Error::DeserialisationError)
    }

    /// Retrieve \\( \alpha_{i0} * B \\), where \\( B \\) is the Ristretto basepoint.
    pub fn public_key(&self) -> Option<&G> {
        if !self.points.is_empty() {
            return Some(&self.points[0]);
        }
        None
    }

    /// Evaluate g^P(i) without knowing the secret coefficients of the polynomial
    pub fn evaluate_hiding(&self, term: &G::ScalarField) -> G {
        let mut sum = G::zero();

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

pub(crate) fn encrypt_share<G: CurveGroup>(
    share: &SecretShare<G>,
    aes_key: &[u8],
    mut rng: impl RngCore + CryptoRng,
) -> EncryptedSecretShare<G> {
    let hkdf = Hkdf::<Sha256>::new(None, aes_key);
    let mut final_aes_key = [0u8; 16];
    hkdf.expand(&[], &mut final_aes_key)
        .expect("KDF expansion failed unexpectedly");

    let mut nonce_array = [0u8; 16];
    rng.fill_bytes(&mut nonce_array);

    let final_aes_key = GenericArray::from_slice(&final_aes_key);
    let nonce = GenericArray::from_slice(&nonce_array);
    let cipher = Aes128::new(final_aes_key);
    let mut cipher = Aes128Ctr::from_block_cipher(cipher, nonce);

    let mut share_bytes = Vec::new();
    // TODO: replace by error
    share
        .polynomial_evaluation
        .serialize_compressed(&mut share_bytes)
        .unwrap();
    cipher.apply_keystream(&mut share_bytes);

    EncryptedSecretShare::<G> {
        sender_index: share.sender_index,
        receiver_index: share.receiver_index,
        nonce: nonce_array,
        encrypted_polynomial_evaluation: share_bytes,
        _phantom: PhantomData,
    }
}

pub(crate) fn decrypt_share<G: CurveGroup>(
    encrypted_share: &EncryptedSecretShare<G>,
    aes_key: &[u8],
) -> Result<SecretShare<G>, Error<G>> {
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
        G::ScalarField::deserialize_compressed(&bytes[..]).map_err(|_| Error::DecryptionError)?;

    Ok(SecretShare {
        sender_index: encrypted_share.sender_index,
        receiver_index: encrypted_share.receiver_index,
        polynomial_evaluation: evaluation,
    })
}

#[cfg(test)]
mod test {
    use super::*;
    use ark_bn254::{Fr, G1Projective};
    use ark_ff::UniformRand;
    use rand::{rngs::OsRng, RngCore};

    #[test]
    fn test_serialization() {
        let mut rng = OsRng;

        for _ in 0..100 {
            let secret_share = SecretShare::<G1Projective> {
                sender_index: rng.next_u32(),
                receiver_index: rng.next_u32(),
                polynomial_evaluation: Fr::rand(&mut rng),
            };
            let mut bytes = Vec::new();
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
            let encrypted_secret_share = EncryptedSecretShare::<G1Projective>::new(
                rng.next_u32(),
                rng.next_u32(),
                nonce,
                encrypted_polynomial_evaluation,
            );
            let mut bytes = Vec::new();
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
