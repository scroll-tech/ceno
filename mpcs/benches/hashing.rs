use ark_std::test_rng;
use criterion::{Criterion, criterion_group, criterion_main};
use ff::Field;
use goldilocks::Goldilocks;
use mpcs::util::hash::{Digest, DIGEST_WIDTH, hash_two_digests, new_hasher};

fn random_ceno_goldy() -> Goldilocks {
    Goldilocks::random(&mut test_rng())
}
pub fn criterion_benchmark(c: &mut Criterion) {
    let hasher = new_hasher();
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
        bencher.iter(|| hash_two_digests(&left, &right, &hasher))
    });

    let mut hasher = new_hasher();
    let values = (0..60)
        .map(|_| Goldilocks::random(&mut test_rng()))
        .collect::<Vec<_>>();
    c.bench_function("ceno hash 60 to 1", |bencher| {
        bencher.iter(|| {
            hasher.update(values.as_slice());
            let result = &hasher.squeeze_vec()[0..DIGEST_WIDTH];
        })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);