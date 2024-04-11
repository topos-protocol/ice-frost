//! Benchmarks for ICE-FROST signing sessions.

#[macro_use]
extern crate criterion;

use std::collections::BTreeMap;

use criterion::Criterion;

use rand::rngs::OsRng;

use ice_frost::dkg::{Coefficients, DistributedKeyGeneration, EncryptedSecretShare, Participant};
use ice_frost::keys::{DiffieHellmanPrivateKey, IndividualSigningKey};
use ice_frost::parameters::ThresholdParameters;
use ice_frost::sign::{
    generate_commitment_share_lists, PublicCommitmentShareList, SecretCommitmentShareList,
    SignatureAggregator,
};
use ice_frost::testing::Secp256k1Sha256;
use ice_frost::CipherSuite;

type ParticipantDKG = Participant<Secp256k1Sha256>;
type Coeff = Coefficients<Secp256k1Sha256>;
type Dkg<T> = DistributedKeyGeneration<T, Secp256k1Sha256>;
type DHSkey = DiffieHellmanPrivateKey<Secp256k1Sha256>;
type Skey = IndividualSigningKey<Secp256k1Sha256>;

type PublicCommShareList = PublicCommitmentShareList<Secp256k1Sha256>;
type SecretCommShareList = SecretCommitmentShareList<Secp256k1Sha256>;

const NUMBER_OF_PARTICIPANTS: u32 = 5;
const THRESHOLD_OF_PARTICIPANTS: u32 = 3;

fn criterion_benchmark(c: &mut Criterion) {
    let params =
        ThresholdParameters::new(NUMBER_OF_PARTICIPANTS, THRESHOLD_OF_PARTICIPANTS).unwrap();
    let rng = OsRng;

    let mut participants = Vec::<ParticipantDKG>::with_capacity(NUMBER_OF_PARTICIPANTS as usize);
    let mut coefficients = Vec::<Coeff>::with_capacity(NUMBER_OF_PARTICIPANTS as usize);
    let mut dh_secret_keys = Vec::<DHSkey>::with_capacity(NUMBER_OF_PARTICIPANTS as usize);

    for i in 1..NUMBER_OF_PARTICIPANTS + 1 {
        let (p, c, dh_sk) = ParticipantDKG::new_dealer(params, i, rng).unwrap();
        participants.push(p);
        coefficients.push(c);
        dh_secret_keys.push(dh_sk);
    }

    let mut participants_encrypted_secret_shares: Vec<
        BTreeMap<u32, EncryptedSecretShare<Secp256k1Sha256>>,
    > = (0..NUMBER_OF_PARTICIPANTS)
        .map(|_| BTreeMap::new())
        .collect();

    let mut participants_states_1 = Vec::<Dkg<_>>::with_capacity(NUMBER_OF_PARTICIPANTS as usize);
    let mut participants_states_2 = Vec::<Dkg<_>>::with_capacity(NUMBER_OF_PARTICIPANTS as usize);

    for i in 0..NUMBER_OF_PARTICIPANTS {
        let (pi_state, _participant_lists) = Dkg::<_>::bootstrap(
            params,
            &dh_secret_keys[i as usize],
            participants[i as usize].index,
            &coefficients[i as usize],
            &participants,
            rng,
        )
        .unwrap();
        let pi_their_encrypted_secret_shares = pi_state.their_encrypted_secret_shares().unwrap();
        participants_encrypted_secret_shares[i as usize] = pi_their_encrypted_secret_shares.clone();
        participants_states_1.push(pi_state);
    }

    let mut p1_my_encrypted_secret_shares =
        Vec::<EncryptedSecretShare<Secp256k1Sha256>>::with_capacity(
            NUMBER_OF_PARTICIPANTS as usize,
        );
    for j in 0..NUMBER_OF_PARTICIPANTS {
        p1_my_encrypted_secret_shares.push(
            participants_encrypted_secret_shares[j as usize]
                .get(&1)
                .unwrap()
                .clone(),
        );
    }
    participants_states_2.push(
        participants_states_1[0]
            .clone()
            .to_round_two(&p1_my_encrypted_secret_shares, rng)
            .unwrap()
            .0,
    );

    for i in 2..NUMBER_OF_PARTICIPANTS + 1 {
        let mut pi_my_encrypted_secret_shares =
            Vec::<EncryptedSecretShare<Secp256k1Sha256>>::with_capacity(
                NUMBER_OF_PARTICIPANTS as usize,
            );
        for j in 0..NUMBER_OF_PARTICIPANTS {
            pi_my_encrypted_secret_shares.push(
                participants_encrypted_secret_shares[j as usize]
                    .get(&i)
                    .unwrap()
                    .clone(),
            );
        }

        participants_states_2.push(
            participants_states_1[(i - 1) as usize]
                .clone()
                .to_round_two(&pi_my_encrypted_secret_shares, rng)
                .unwrap()
                .0,
        );
    }

    let mut participants_secret_keys =
        Vec::<Skey>::with_capacity(THRESHOLD_OF_PARTICIPANTS as usize);
    let (group_key, p1_sk) = participants_states_2[0].clone().finish().unwrap();
    participants_secret_keys.push(p1_sk);

    for i in 2..THRESHOLD_OF_PARTICIPANTS + 1 {
        let (_, pi_sk) = participants_states_2[(i - 1) as usize]
            .clone()
            .finish()
            .unwrap();
        participants_secret_keys.push(pi_sk);
    }
    for i in (THRESHOLD_OF_PARTICIPANTS + 2)..NUMBER_OF_PARTICIPANTS + 1 {
        let (_, _) = participants_states_2[(i - 1) as usize]
            .clone()
            .finish()
            .unwrap();
    }

    let message = b"This is a test of the tsunami alert system. This is only a test.";

    let mut participants_public_comshares =
        Vec::<PublicCommShareList>::with_capacity(NUMBER_OF_PARTICIPANTS as usize);
    let mut participants_secret_comshares =
        Vec::<SecretCommShareList>::with_capacity(NUMBER_OF_PARTICIPANTS as usize);
    let (p1_public_comshares, p1_secret_comshares) =
        generate_commitment_share_lists(&mut OsRng, &participants_secret_keys[0], 1).unwrap();
    participants_public_comshares.push(p1_public_comshares);
    participants_secret_comshares.push(p1_secret_comshares.clone());

    for i in 1..THRESHOLD_OF_PARTICIPANTS + 1 {
        let (pi_public_comshares, pi_secret_comshares) = generate_commitment_share_lists(
            &mut OsRng,
            &participants_secret_keys[(i - 1) as usize],
            1,
        )
        .unwrap();
        participants_public_comshares.push(pi_public_comshares);
        participants_secret_comshares.push(pi_secret_comshares);
    }

    let mut aggregator = SignatureAggregator::new(params, group_key, &message[..]);

    for i in 1..THRESHOLD_OF_PARTICIPANTS + 1 {
        aggregator
            .include_signer(
                i,
                participants_public_comshares[(i - 1) as usize].commitments[0],
                &participants_secret_keys[(i - 1) as usize].to_public(),
            )
            .unwrap();
    }

    let signers = aggregator.signers().to_vec();
    let message_hash = Secp256k1Sha256::h4(&message[..]);
    let message_hash_copy = message_hash;

    let p1_sk = participants_secret_keys[0].clone();

    for i in 1..THRESHOLD_OF_PARTICIPANTS + 1 {
        let pi_partial_signature = participants_secret_keys[(i - 1) as usize]
            .sign(
                &message_hash,
                &group_key,
                &mut participants_secret_comshares[(i - 1) as usize],
                0,
                &signers,
            )
            .unwrap();
        aggregator.include_partial_signature(&pi_partial_signature);
    }

    c.bench_function("Partial signature creation", move |b| {
        b.iter(|| {
            p1_sk.sign(
                &message_hash,
                &group_key,
                &mut p1_secret_comshares.clone(),
                0,
                &signers,
            )
        });
    });

    let aggregator = aggregator.finalize().unwrap();

    let threshold_signature = aggregator.aggregate().unwrap();

    c.bench_function("Signature aggregation", move |b| {
        b.iter(|| aggregator.aggregate());
    });

    c.bench_function("Signature verification", move |b| {
        b.iter(|| threshold_signature.verify(&group_key, &message_hash_copy));
    });
}

criterion_group!(
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = criterion_benchmark);
criterion_main!(benches);
