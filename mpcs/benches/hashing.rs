use ark_std::test_rng;
use criterion::{Criterion, criterion_group, criterion_main};
use ff::Field;
use goldilocks::{Goldilocks, GoldilocksExt2};
use mpcs::util::merkle_tree::{Hasher, KeccakHasher, PoseidonHasher};

fn random_ceno_goldy() -> Goldilocks {
    Goldilocks::random(&mut test_rng())
}

pub fn criterion_benchmark_poseidon(c: &mut Criterion) {
    criterion_benchmark::<PoseidonHasher>(c, "poseidon");
}

pub fn criterion_benchmark_keccak(c: &mut Criterion) {
    criterion_benchmark::<KeccakHasher>(c, "keccak");
}

pub fn criterion_benchmark<H: Hasher<GoldilocksExt2>>(c: &mut Criterion, id: &str) {
    let mut group = c.benchmark_group(format!("hashing_{}", id,));
    let left: H::Digest = H::Digest::try_from(vec![random_ceno_goldy(); 4]).unwrap();
    let right: H::Digest = H::Digest::try_from(vec![random_ceno_goldy(); 4]).unwrap();
    group.bench_function("hash 2 to 1", |bencher| {
        bencher.iter(|| H::hash_two_digests(&left, &right))
    });

    let values = (0..60).map(|_| random_ceno_goldy()).collect::<Vec<_>>();
    group.bench_function("hash 60 to 1", |bencher| {
        bencher.iter(|| H::hash_slice_base(&values))
    });
}

criterion_group!(
    benches,
    criterion_benchmark_keccak,
    criterion_benchmark_poseidon
);
criterion_main!(benches);
