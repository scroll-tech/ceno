use ark_std::test_rng;
use criterion::{Criterion, criterion_group, criterion_main};

use ff_ext::FromUniformBytes;
use p3::goldilocks::Goldilocks;
use poseidon::poseidon_hash::PoseidonHash;

fn random_ceno_goldy() -> Goldilocks {
    Goldilocks::random(&mut test_rng())
}
pub fn criterion_benchmark(c: &mut Criterion) {
    let values = (0..60).map(|_| random_ceno_goldy()).collect::<Vec<_>>();
    c.bench_function("ceno hash 60 to 1", |bencher| {
        bencher.iter(|| PoseidonHash::hash_or_noop(&values))
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
