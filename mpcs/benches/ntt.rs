use criterion::*;
use plonky2::field::{
    goldilocks_field::GoldilocksField, polynomial::PolynomialCoeffs, types::Sample,
};

fn bench_ntt_internal(c: &mut Criterion) {
    const NUM_SAMPLES: usize = 10;
    let group_name = "plonky2-ntt";
    let mut group = c.benchmark_group(group_name);
    group.sample_size(NUM_SAMPLES);

    for num_vars in 15..24 {
        group.bench_function(format!("{}", num_vars), |b| {
            let coeffs = (0..(1 << num_vars))
                .map(|_| GoldilocksField::rand())
                .collect::<Vec<GoldilocksField>>();
            b.iter_batched(
                || coeffs.clone(),
                |coeffs| {
                    let coeffs = PolynomialCoeffs::new(coeffs);
                    coeffs.lde(3);
                },
                BatchSize::LargeInput,
            );
        });
    }
}

fn bench_ntt(c: &mut Criterion) {
    bench_ntt_internal(c);
}

criterion_group!(benches, bench_ntt);
criterion_main!(benches);
