use ark_std::test_rng;
use criterion::{Criterion, criterion_group, criterion_main};
use ff::Field;
use goldilocks::Goldilocks;
use mpcs::util::hash::{Digest, hash_two_digests};
use poseidon::poseidon_hash::PoseidonHash;

fn random_ceno_goldy() -> Goldilocks {
    Goldilocks::random(&mut test_rng())
}
pub fn criterion_benchmark(c: &mut Criterion) {
    let left = Digest(vec![random_ceno_goldy(); 4].try_into().unwrap());
    let right = Digest(vec![random_ceno_goldy(); 4].try_into().unwrap());
    c.bench_function("ceno hash 2 to 1", |bencher| {
        bencher.iter(|| hash_two_digests(&left, &right))
    });

    let values = (0..60).map(|_| random_ceno_goldy()).collect::<Vec<_>>();
    c.bench_function("ceno hash 60 to 1", |bencher| {
        bencher.iter(|| PoseidonHash::hash_or_noop(&values))
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
