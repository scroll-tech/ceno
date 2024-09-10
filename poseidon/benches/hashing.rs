use ark_std::test_rng;
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use ff::Field;
use goldilocks::Goldilocks;
use plonky2::{
    field::{goldilocks_field::GoldilocksField, types::Sample},
    hash::{hash_types::HashOut, poseidon::PoseidonHash as PlonkyPoseidonHash},
    plonk::config::Hasher,
};
use plonky2::hash::hashing::PlonkyPermutation;
use plonky2::hash::poseidon::PoseidonPermutation;
use poseidon::{digest::Digest, poseidon_hash::PoseidonHash};

fn random_plonky_2_goldy() -> GoldilocksField {
    GoldilocksField::rand()
}

fn random_ceno_goldy() -> Goldilocks {
    Goldilocks::random(&mut test_rng())
}

fn plonky_hash_single(a: GoldilocksField) {
    let result = black_box(PlonkyPoseidonHash::hash_or_noop(&[a]));
}

fn ceno_hash_single(a: Goldilocks) {
    let result = black_box(PoseidonHash::hash_or_noop(&[a]));
}

fn plonky_hash_2_to_1(left: HashOut<GoldilocksField>, right: HashOut<GoldilocksField>) {
    let result = black_box(PlonkyPoseidonHash::two_to_one(left, right));
}

fn ceno_hash_2_to_1(left: &Digest<Goldilocks>, right: &Digest<Goldilocks>) {
    let result = black_box(PoseidonHash::two_to_one(left, right));
}

fn plonky_hash_60_to_1(values: &[GoldilocksField]) {
    let result = black_box(PlonkyPoseidonHash::hash_or_noop(values));
}

fn ceno_hash_60_to_1(values: &[Goldilocks]) {
    let result = black_box(PoseidonHash::hash_or_noop(values));
}

pub fn hashing_benchmark(c: &mut Criterion) {
    let p_a = black_box(random_plonky_2_goldy());
    c.bench_function("plonky hash single", |bencher| {
        bencher.iter(|| plonky_hash_single(p_a))
    });

    let left = HashOut::<GoldilocksField>::rand();
    let right = HashOut::<GoldilocksField>::rand();
    c.bench_function("plonky hash 2 to 1", |bencher| {
        bencher.iter(|| plonky_hash_2_to_1(left, right))
    });

    let sixty_elems = GoldilocksField::rand_vec(60);
    c.bench_function("plonky hash 60 to 1", |bencher| {
        bencher.iter(|| plonky_hash_60_to_1(sixty_elems.as_slice()))
    });

    let c_a = black_box(random_ceno_goldy());
    c.bench_function("ceno hash single", |bencher| {
        bencher.iter(|| ceno_hash_single(c_a))
    });

    let left = Digest(
        vec![Goldilocks::random(&mut test_rng()); 4]
            .try_into()
            .unwrap(),
    );
    let right = Digest(
        vec![Goldilocks::random(&mut test_rng()); 4]
            .try_into()
            .unwrap(),
    );
    c.bench_function("ceno hash 2 to 1", |bencher| {
        bencher.iter(|| ceno_hash_2_to_1(&left, &right))
    });

    let values = (0..60)
        .map(|_| Goldilocks::random(&mut test_rng()))
        .collect::<Vec<_>>();
    c.bench_function("ceno hash 60 to 1", |bencher| {
        bencher.iter(|| ceno_hash_60_to_1(values.as_slice()))
    });
}


// bench permutation
pub fn permutation_benchmark(c: &mut Criterion) {
    let mut plonky_permutation = PoseidonPermutation::new(core::iter::repeat(GoldilocksField(0)));
    let mut ceno_permutation = poseidon::poseidon_permutation::PoseidonPermutation::new(core::iter::repeat(Goldilocks::ZERO));

    c.bench_function("plonky permute", |bencher| {
        bencher.iter(|| black_box(plonky_permutation.permute()))
    });

    c.bench_function("ceno permute", |bencher| {
        bencher.iter(|| black_box(ceno_permutation.permute()))
    });
}

criterion_group!(benches, permutation_benchmark, hashing_benchmark);
criterion_main!(benches);
