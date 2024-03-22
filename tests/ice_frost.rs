//! Integration tests for ICE-FROST.

use rand::rngs::OsRng;

use ice_frost::CipherSuite;

use ice_frost::dkg::{DistributedKeyGeneration, Participant};
use ice_frost::parameters::ThresholdParameters;
use ice_frost::sign::generate_commitment_share_lists;

use ice_frost::sign::SignatureAggregator;

use ice_frost::testing::Secp256k1Sha256;

type ParticipantDKG = Participant<Secp256k1Sha256>;
type Dkg<T> = DistributedKeyGeneration<T, Secp256k1Sha256>;

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

    aggregator.include_signer(1, p1_public_comshares.commitments[0], &p1_sk.to_public());
    aggregator.include_signer(3, p3_public_comshares.commitments[0], &p3_sk.to_public());
    aggregator.include_signer(4, p4_public_comshares.commitments[0], &p4_sk.to_public());

    let signers = aggregator.get_signers();
    let message_hash = Secp256k1Sha256::h4(&message[..]);

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
