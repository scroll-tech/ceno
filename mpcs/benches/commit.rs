use ark_std::rand::thread_rng;
use criterion::*;
use ff::Field;
use goldilocks::Goldilocks;
use mpcs::{
    encode_rs_basecode, interpolate_over_boolean_hypercube,
    util::plonky2_util::reverse_index_bits_in_place,
};

fn bench_interpolate_over_hypercube_internal(c: &mut Criterion) {
    const NUM_SAMPLES: usize = 10;
    let mut rng = thread_rng();
    let group_name = "interpolate-over-hypercube";
    let mut group = c.benchmark_group(group_name);
    group.sample_size(NUM_SAMPLES);

    for num_vars in 15..24 {
        group.bench_function(format!("{}", num_vars), |b| {
            let leaves = (0..(1 << num_vars))
                .map(|_| Goldilocks::random(&mut rng))
                .collect::<Vec<Goldilocks>>();
            b.iter_batched(
                || leaves.clone(),
                |leaves| {
                    interpolate_over_boolean_hypercube(&leaves);
                },
                BatchSize::LargeInput,
            );
        });
    }
}

fn bench_encode_internal(c: &mut Criterion) {
    const NUM_SAMPLES: usize = 10;
    let mut rng = thread_rng();
    let group_name = "basefold-encode";
    let mut group = c.benchmark_group(group_name);
    group.sample_size(NUM_SAMPLES);

    for num_vars in 15..24 {
        group.bench_function(format!("{}", num_vars), |b| {
            let coeffs = (0..(1 << num_vars))
                .map(|_| Goldilocks::random(&mut rng))
                .collect::<Vec<Goldilocks>>();
            b.iter_batched(
                || coeffs.clone(),
                |coeffs| {
                    encode_rs_basecode(&coeffs, 1 << 3, 1 << 7);
                },
                BatchSize::LargeInput,
            );
        });
    }
}

fn bench_reverse_index_bits_in_place_internal(c: &mut Criterion) {
    const NUM_SAMPLES: usize = 10;
    let mut rng = thread_rng();
    let group_name = "reverse-index-bits-in-place";
    let mut group = c.benchmark_group(group_name);
    group.sample_size(NUM_SAMPLES);

    for num_vars in 15..24 {
        group.bench_function(format!("{}", num_vars), |b| {
            let coeffs = (0..(1 << num_vars))
                .map(|_| Goldilocks::random(&mut rng))
                .collect::<Vec<Goldilocks>>();
            b.iter_batched(
                || coeffs.clone(),
                |mut coeffs| {
                    reverse_index_bits_in_place(&mut coeffs);
                },
                BatchSize::LargeInput,
            );
        });
    }
}

fn bench_commit(c: &mut Criterion) {
    bench_reverse_index_bits_in_place_internal(c);
    bench_encode_internal(c);
    bench_interpolate_over_hypercube_internal(c);
}

criterion_group!(benches, bench_commit);
criterion_main!(benches);
