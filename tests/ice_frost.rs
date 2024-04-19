//! Integration tests for ICE-FROST.

use ark_ec::Group;
use ark_ff::UniformRand;
use ice_frost::keys::{DiffieHellmanPrivateKey, GroupVerifyingKey, IndividualSigningKey};
use rand::rngs::OsRng;

use ice_frost::CipherSuite;

use ice_frost::dkg::{DistributedKeyGeneration, EncryptedSecretShare, Participant, RoundOne};
use ice_frost::parameters::ThresholdParameters;
use ice_frost::sign::{
    generate_commitment_share_lists, PublicCommitmentShareList, SecretCommitmentShareList,
};

use ice_frost::sign::SignatureAggregator;

use ice_frost::testing::Secp256k1Sha256;

type ParticipantDKG = Participant<Secp256k1Sha256>;
type Dkg<T> = DistributedKeyGeneration<T, Secp256k1Sha256>;

type PublicCommShareList = PublicCommitmentShareList<Secp256k1Sha256>;
type SecretCommShareList = SecretCommitmentShareList<Secp256k1Sha256>;

#[test]
fn signing_and_verification_3_out_of_5() {
    let params = ThresholdParameters::new(5, 3).unwrap();
    let rng = OsRng;

    let (p1, p1coeffs, p1_dh_sk) = ParticipantDKG::new_dealer(params, 1, rng).unwrap();
    let (p2, p2coeffs, p2_dh_sk) = ParticipantDKG::new_dealer(params, 2, rng).unwrap();
    let (p3, p3coeffs, p3_dh_sk) = ParticipantDKG::new_dealer(params, 3, rng).unwrap();
    let (p4, p4coeffs, p4_dh_sk) = ParticipantDKG::new_dealer(params, 4, rng).unwrap();
    let (p5, p5coeffs, p5_dh_sk) = ParticipantDKG::new_dealer(params, 5, rng).unwrap();

    let participants: Vec<ParticipantDKG> =
        vec![p1.clone(), p2.clone(), p3.clone(), p4.clone(), p5.clone()];
    let (p1_state, _participant_lists) =
        Dkg::<_>::bootstrap(params, &p1_dh_sk, p1.index, &p1coeffs, &participants, rng).unwrap();
    let p1_their_encrypted_secret_shares = p1_state.their_encrypted_secret_shares().unwrap();

    let (p2_state, _participant_lists) =
        Dkg::<_>::bootstrap(params, &p2_dh_sk, p2.index, &p2coeffs, &participants, rng).unwrap();
    let p2_their_encrypted_secret_shares = p2_state.their_encrypted_secret_shares().unwrap();

    let (p3_state, _participant_lists) =
        Dkg::<_>::bootstrap(params, &p3_dh_sk, p3.index, &p3coeffs, &participants, rng).unwrap();
    let p3_their_encrypted_secret_shares = p3_state.their_encrypted_secret_shares().unwrap();

    let (p4_state, _participant_lists) =
        Dkg::<_>::bootstrap(params, &p4_dh_sk, p4.index, &p4coeffs, &participants, rng).unwrap();
    let p4_their_encrypted_secret_shares = p4_state.their_encrypted_secret_shares().unwrap();

    let (p5_state, _participant_lists) =
        Dkg::<_>::bootstrap(params, &p5_dh_sk, p5.index, &p5coeffs, &participants, rng).unwrap();
    let p5_their_encrypted_secret_shares = p5_state.their_encrypted_secret_shares().unwrap();

    let p1_my_encrypted_secret_shares = vec![
        p1_their_encrypted_secret_shares
            .get(&1)
            .unwrap()
            .clone()
            .clone(),
        p2_their_encrypted_secret_shares
            .get(&1)
            .unwrap()
            .clone()
            .clone(),
        p3_their_encrypted_secret_shares
            .get(&1)
            .unwrap()
            .clone()
            .clone(),
        p4_their_encrypted_secret_shares
            .get(&1)
            .unwrap()
            .clone()
            .clone(),
        p5_their_encrypted_secret_shares
            .get(&1)
            .unwrap()
            .clone()
            .clone(),
    ];

    let p2_my_encrypted_secret_shares = vec![
        p1_their_encrypted_secret_shares
            .get(&2)
            .unwrap()
            .clone()
            .clone(),
        p2_their_encrypted_secret_shares
            .get(&2)
            .unwrap()
            .clone()
            .clone(),
        p3_their_encrypted_secret_shares
            .get(&2)
            .unwrap()
            .clone()
            .clone(),
        p4_their_encrypted_secret_shares
            .get(&2)
            .unwrap()
            .clone()
            .clone(),
        p5_their_encrypted_secret_shares
            .get(&2)
            .unwrap()
            .clone()
            .clone(),
    ];

    let p3_my_encrypted_secret_shares = vec![
        p1_their_encrypted_secret_shares
            .get(&3)
            .unwrap()
            .clone()
            .clone(),
        p2_their_encrypted_secret_shares
            .get(&3)
            .unwrap()
            .clone()
            .clone(),
        p3_their_encrypted_secret_shares
            .get(&3)
            .unwrap()
            .clone()
            .clone(),
        p4_their_encrypted_secret_shares
            .get(&3)
            .unwrap()
            .clone()
            .clone(),
        p5_their_encrypted_secret_shares
            .get(&3)
            .unwrap()
            .clone()
            .clone(),
    ];

    let p4_my_encrypted_secret_shares = vec![
        p1_their_encrypted_secret_shares
            .get(&4)
            .unwrap()
            .clone()
            .clone(),
        p2_their_encrypted_secret_shares
            .get(&4)
            .unwrap()
            .clone()
            .clone(),
        p3_their_encrypted_secret_shares
            .get(&4)
            .unwrap()
            .clone()
            .clone(),
        p4_their_encrypted_secret_shares
            .get(&4)
            .unwrap()
            .clone()
            .clone(),
        p5_their_encrypted_secret_shares
            .get(&4)
            .unwrap()
            .clone()
            .clone(),
    ];

    let p5_my_encrypted_secret_shares = vec![
        p1_their_encrypted_secret_shares
            .get(&5)
            .unwrap()
            .clone()
            .clone(),
        p2_their_encrypted_secret_shares
            .get(&5)
            .unwrap()
            .clone()
            .clone(),
        p3_their_encrypted_secret_shares
            .get(&5)
            .unwrap()
            .clone()
            .clone(),
        p4_their_encrypted_secret_shares
            .get(&5)
            .unwrap()
            .clone()
            .clone(),
        p5_their_encrypted_secret_shares
            .get(&5)
            .unwrap()
            .clone()
            .clone(),
    ];

    let (p1_state, complaints) = p1_state
        .to_round_two(&p1_my_encrypted_secret_shares, rng)
        .unwrap();
    assert!(complaints.is_empty());
    let (p2_state, complaints) = p2_state
        .to_round_two(&p2_my_encrypted_secret_shares, rng)
        .unwrap();
    assert!(complaints.is_empty());
    let (p3_state, complaints) = p3_state
        .to_round_two(&p3_my_encrypted_secret_shares, rng)
        .unwrap();
    assert!(complaints.is_empty());
    let (p4_state, complaints) = p4_state
        .to_round_two(&p4_my_encrypted_secret_shares, rng)
        .unwrap();
    assert!(complaints.is_empty());
    let (p5_state, complaints) = p5_state
        .to_round_two(&p5_my_encrypted_secret_shares, rng)
        .unwrap();
    assert!(complaints.is_empty());

    let (group_key, p1_sk) = p1_state.finish().unwrap();
    let (_, _) = p2_state.finish().unwrap();
    let (_, p3_sk) = p3_state.finish().unwrap();
    let (_, p4_sk) = p4_state.finish().unwrap();
    let (_, _) = p5_state.finish().unwrap();

    let message = b"This is a test of the tsunami alert system. This is only a test.";
    let (p1_public_comshares, mut p1_secret_comshares) =
        generate_commitment_share_lists(&mut OsRng, &p1_sk, 1).unwrap();
    let (p3_public_comshares, mut p3_secret_comshares) =
        generate_commitment_share_lists(&mut OsRng, &p3_sk, 1).unwrap();
    let (p4_public_comshares, mut p4_secret_comshares) =
        generate_commitment_share_lists(&mut OsRng, &p4_sk, 1).unwrap();

    let mut aggregator = SignatureAggregator::new(params, group_key, &message[..]);

    aggregator
        .include_signer(1, p1_public_comshares.commitments[0], &p1_sk.to_public())
        .unwrap();
    aggregator
        .include_signer(3, p3_public_comshares.commitments[0], &p3_sk.to_public())
        .unwrap();
    aggregator
        .include_signer(4, p4_public_comshares.commitments[0], &p4_sk.to_public())
        .unwrap();

    let message_hash = Secp256k1Sha256::h4(&message[..]);
    let signers = aggregator.signers();
    let p1_partial = p1_sk
        .sign(
            &message_hash,
            &group_key,
            &mut p1_secret_comshares,
            0,
            signers,
        )
        .unwrap();
    let p3_partial = p3_sk
        .sign(
            &message_hash,
            &group_key,
            &mut p3_secret_comshares,
            0,
            signers,
        )
        .unwrap();
    let p4_partial = p4_sk
        .sign(
            &message_hash,
            &group_key,
            &mut p4_secret_comshares,
            0,
            signers,
        )
        .unwrap();

    aggregator.include_partial_signature(&p1_partial);
    aggregator.include_partial_signature(&p3_partial);
    aggregator.include_partial_signature(&p4_partial);

    let aggregator = aggregator.finalize().unwrap();
    let threshold_signature = aggregator.aggregate().unwrap();
    let verification_result1 = threshold_signature.verify(&group_key, &message_hash);
    let verification_result2 = group_key.verify_signature(&threshold_signature, &message_hash);

    assert!(verification_result1.is_ok());
    assert!(verification_result2.is_ok());
}

#[test]
fn resharing_from_non_frost_key() {
    type SchnorrSecretKey = <<Secp256k1Sha256 as CipherSuite>::G as Group>::ScalarField;
    type SchnorrPublicKey = <Secp256k1Sha256 as CipherSuite>::G;

    // A single party outside of any ICE-FROST scenario, who owns a keypair to perform
    // Schnorr signatures.
    let mut rng = OsRng;
    let single_party_sk: SchnorrSecretKey = SchnorrSecretKey::rand(&mut rng);
    let single_party_pk: SchnorrPublicKey =
        <<Secp256k1Sha256 as CipherSuite>::G>::generator() * single_party_sk;

    // Converts this party's keys into ICE-FROST format, simulating a 1-out-of-1 setup.
    let simulated_parameters = ThresholdParameters::new(1, 1).unwrap();
    let frost_sk = IndividualSigningKey::from_single_key(single_party_sk);
    let frost_pk = GroupVerifyingKey::new(single_party_pk);

    // Start a resharing phase from this single party to a set of new participants.
    const NUMBER_OF_PARTICIPANTS: u32 = 5;
    const THRESHOLD_OF_PARTICIPANTS: u32 = 3;

    let threshold_parameters =
        ThresholdParameters::new(NUMBER_OF_PARTICIPANTS, THRESHOLD_OF_PARTICIPANTS).unwrap();

    let mut signers = Vec::<Participant<Secp256k1Sha256>>::new();
    let mut signers_dh_secret_keys = Vec::<DiffieHellmanPrivateKey<Secp256k1Sha256>>::new();

    for i in 1..=NUMBER_OF_PARTICIPANTS {
        let (p, dh_sk) =
            Participant::<Secp256k1Sha256>::new_signer(threshold_parameters, i, rng).unwrap();

        signers.push(p);
        signers_dh_secret_keys.push(dh_sk);
    }

    let mut signers_encrypted_secret_shares: Vec<Vec<EncryptedSecretShare<Secp256k1Sha256>>> =
        (0..NUMBER_OF_PARTICIPANTS).map(|_| Vec::new()).collect();

    let mut signers_states_1 = Vec::<Dkg<_>>::new();
    let mut signers_states_2 = Vec::<Dkg<_>>::new();

    let (single_dealer, dealer_encrypted_shares_for_signers, _participant_lists) =
        Participant::reshare(threshold_parameters, &frost_sk, &signers, rng).unwrap();

    for i in 0..NUMBER_OF_PARTICIPANTS as usize {
        let (signer_state, _participant_lists) =
            DistributedKeyGeneration::<RoundOne, Secp256k1Sha256>::new(
                simulated_parameters,
                &signers_dh_secret_keys[i],
                signers[i].index,
                &[single_dealer.clone()],
                rng,
            )
            .unwrap();
        signers_states_1.push(signer_state);
    }

    for (i, shares) in signers_encrypted_secret_shares.iter_mut().enumerate() {
        let share_for_signer = dealer_encrypted_shares_for_signers
            .get(&(i as u32 + 1))
            .unwrap()
            .clone();
        *shares = vec![share_for_signer];
    }

    for i in 0..NUMBER_OF_PARTICIPANTS as usize {
        let (si_state, complaints) = signers_states_1[i]
            .clone()
            .to_round_two(&signers_encrypted_secret_shares[i], rng)
            .unwrap();
        assert!(complaints.is_empty());

        signers_states_2.push(si_state);
    }

    let mut signers_secret_keys = Vec::<IndividualSigningKey<Secp256k1Sha256>>::new();

    for signers_state in &signers_states_2 {
        let (si_group_key, si_sk) = signers_state.clone().finish().unwrap();
        signers_secret_keys.push(si_sk);

        // Assert that each signer's individual group key matches the converted
        // single's party public key.
        assert!(si_group_key == frost_pk);
    }

    let message = b"This is a test of the tsunami alert system. This is only a test.";

    let mut signers_public_comshares =
        Vec::<PublicCommShareList>::with_capacity(NUMBER_OF_PARTICIPANTS as usize);
    let mut signers_secret_comshares =
        Vec::<SecretCommShareList>::with_capacity(NUMBER_OF_PARTICIPANTS as usize);

    for i in 0..THRESHOLD_OF_PARTICIPANTS {
        let (pi_public_comshares, pi_secret_comshares) =
            generate_commitment_share_lists(&mut OsRng, &signers_secret_keys[i as usize], 1)
                .unwrap();
        signers_public_comshares.push(pi_public_comshares);
        signers_secret_comshares.push(pi_secret_comshares);
    }

    let mut aggregator = SignatureAggregator::new(threshold_parameters, frost_pk, &message[..]);

    for i in 0..THRESHOLD_OF_PARTICIPANTS {
        aggregator
            .include_signer(
                signers[i as usize].index,
                signers_public_comshares[i as usize].commitments[0],
                &signers_secret_keys[i as usize].to_public(),
            )
            .unwrap();
    }

    let message_hash = Secp256k1Sha256::h4(&message[..]);

    for i in 0..THRESHOLD_OF_PARTICIPANTS {
        let pi_partial_signature = signers_secret_keys[i as usize]
            .sign(
                &message_hash,
                &frost_pk,
                &mut signers_secret_comshares[i as usize],
                0,
                aggregator.signers(),
            )
            .unwrap();
        aggregator.include_partial_signature(&pi_partial_signature);
    }

    let aggregator = aggregator.finalize().unwrap();

    let threshold_signature = aggregator.aggregate().unwrap();

    assert!(threshold_signature.verify(&frost_pk, &message_hash).is_ok());
}
