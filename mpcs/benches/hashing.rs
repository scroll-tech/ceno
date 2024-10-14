use ark_std::test_rng;
use criterion::{criterion_group, criterion_main, Criterion};
use ff::Field;
use goldilocks::Goldilocks;
use mpcs::util::hash::{hash_two_digests, Digest};
use poseidon::poseidon_hash::PoseidonHash;

pub fn criterion_benchmark(c: &mut Criterion) {
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
        bencher.iter(|| hash_two_digests(&left, &right))
    });

    let values = (0..60)
        .map(|_| Goldilocks::random(&mut test_rng()))
        .collect::<Vec<_>>();
    c.bench_function("ceno hash 60 to 1", |bencher| {
        bencher.iter(|| {
            PoseidonHash::hash_or_noop(&values);
        })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
