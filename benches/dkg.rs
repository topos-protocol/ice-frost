//! Benchmarks for ICE-FROST distributed key generation with static resharing.

#[macro_use]
extern crate criterion;

use std::collections::BTreeMap;

use criterion::Criterion;

use rand::rngs::OsRng;

use ice_frost::dkg::{Coefficients, DistributedKeyGeneration, EncryptedSecretShare, Participant};
use ice_frost::keys::DiffieHellmanPrivateKey;
use ice_frost::parameters::ThresholdParameters;
use ice_frost::testing::Secp256k1Sha256;

type ParticipantDKG = Participant<Secp256k1Sha256>;
type Dkg<T> = DistributedKeyGeneration<T, Secp256k1Sha256>;
type DHSkey = DiffieHellmanPrivateKey<Secp256k1Sha256>;
type Coeff = Coefficients<Secp256k1Sha256>;

const NUMBER_OF_PARTICIPANTS: u32 = 5;
const THRESHOLD_OF_PARTICIPANTS: u32 = 3;

fn criterion_benchmark(c: &mut Criterion) {
    let params =
        ThresholdParameters::new(NUMBER_OF_PARTICIPANTS, THRESHOLD_OF_PARTICIPANTS).unwrap();
    let rng = OsRng;

    c.bench_function("Participant creation (dealer)", move |b| {
        b.iter(|| ParticipantDKG::new_dealer(params, 1, rng))
    });

    c.bench_function("Participant creation (signer)", move |b| {
        b.iter(|| ParticipantDKG::new_signer(params, 1, rng))
    });

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

    let p1_dh_sk = dh_secret_keys[0].clone();
    let p1 = participants[0].clone();
    let coefficient = coefficients[0].clone();

    let participants_copy = participants.clone();

    c.bench_function("Round One (dealer)", move |b| {
        b.iter(|| {
            Dkg::<_>::bootstrap(
                params,
                &p1_dh_sk,
                p1.index,
                &coefficient,
                &participants_copy,
                rng,
            )
        });
    });

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

    let p1_state = participants_states_1[0].clone();

    // Needed for benchmarking below.
    let p1_my_encrypted_secret_shares_copy = p1_my_encrypted_secret_shares.clone();

    c.bench_function("Round Two", move |b| {
        b.iter(|| {
            p1_state
                .clone()
                .to_round_two(&p1_my_encrypted_secret_shares_copy, rng)
        });
    });

    let p1_state = participants_states_1[0]
        .clone()
        .to_round_two(&p1_my_encrypted_secret_shares, rng)
        .unwrap()
        .0;

    c.bench_function("Finish", move |b| {
        b.iter(|| p1_state.clone().finish());
    });

    let (_group_key, p1_sk) = participants_states_2[0].clone().finish().unwrap();

    let mut signers = Vec::<ParticipantDKG>::with_capacity(NUMBER_OF_PARTICIPANTS as usize);
    let (s1, s1_dh_sk) = ParticipantDKG::new_signer(params, 1, rng).unwrap();
    signers.push(s1.clone());

    for i in 2..NUMBER_OF_PARTICIPANTS + 1 {
        let (s, _) = ParticipantDKG::new_signer(params, i, rng).unwrap();
        signers.push(s);
    }

    c.bench_function("Reshare", move |b| {
        b.iter(|| ParticipantDKG::reshare(params, &p1_sk, &signers, rng));
    });

    let dealers = participants.clone();

    c.bench_function("Round One (signer)", move |b| {
        b.iter(|| Dkg::<_>::new(params, &s1_dh_sk, s1.index, &dealers, rng));
    });
}

criterion_group!(
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = criterion_benchmark);
criterion_main!(benches);
