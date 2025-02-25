use criterion::{BatchSize, Criterion, black_box, criterion_group, criterion_main};
use ff_ext::FromUniformBytes;
use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::Goldilocks;
use poseidon::{challenger::DefaultChallenger, digest::Digest, poseidon_hash::PoseidonHash};
use rand::rng;

fn random_ceno_goldy() -> Goldilocks {
    Goldilocks::random(&mut rng())
}

fn random_ceno_hash() -> Digest<Goldilocks> {
    Digest(vec![Goldilocks::random(&mut rng()); 4].try_into().unwrap())
}

fn ceno_hash_single(a: Goldilocks) {
    let _result = black_box(PoseidonHash::<Goldilocks>::hash_or_noop(&[a]));
}

fn ceno_hash_2_to_1(left: &Digest<Goldilocks>, right: &Digest<Goldilocks>) {
    let _result = black_box(PoseidonHash::<Goldilocks>::two_to_one(left, right));
}

fn ceno_hash_many_to_1(values: &[Goldilocks]) {
    let _result = black_box(PoseidonHash::<Goldilocks>::hash_or_noop(values));
}

pub fn hashing_benchmark(c: &mut Criterion) {
    c.bench_function("ceno hash single", |bencher| {
        bencher.iter_batched(random_ceno_goldy, ceno_hash_single, BatchSize::SmallInput)
    });

    c.bench_function("ceno hash 2 to 1", |bencher| {
        bencher.iter_batched(
            || (random_ceno_hash(), random_ceno_hash()),
            |(left, right)| ceno_hash_2_to_1(&left, &right),
            BatchSize::SmallInput,
        )
    });

    c.bench_function("ceno hash 60 to 1", |bencher| {
        bencher.iter_batched(
            || {
                (0..60)
                    .map(|_| Goldilocks::random(&mut rng()))
                    .collect::<Vec<_>>()
            },
            |values| ceno_hash_many_to_1(values.as_slice()),
            BatchSize::SmallInput,
        )
    });
}

use p3_symmetric::Permutation;

// bench permutation
pub fn permutation_benchmark(c: &mut Criterion) {
    let mut plonky_permutation = PoseidonPermutation::new(core::iter::repeat(GoldilocksField(0)));
    let ceno_challenger = DefaultChallenger::<Goldilocks, _>::new_poseidon_default();

    c.bench_function("plonky permute", |bencher| {
        bencher.iter(|| plonky_permutation.permute())
    });

    c.bench_function("ceno permute", |bencher| {
        bencher.iter(|| {
            let mut state = [Goldilocks::ZERO; 8];
            ceno_challenger.permutation.permute_mut(&mut state);
        })
    });
}

criterion_group!(benches, permutation_benchmark, hashing_benchmark);
criterion_main!(benches);
