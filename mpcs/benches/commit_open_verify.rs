use std::time::Duration;

use criterion::*;
use goldilocks::GoldilocksExt2;

use mpcs::{util::transcript::PoseidonTranscript, Basefold, BasefoldDefaultParams};

#[cfg(feature = "benchmark")]
use mpcs::test_util::{run_batch_commit_open_verify, run_commit_open_verify};

#[cfg(not(feature = "benchmark"))]
fn run_commit_open_verify<E, Pcs, T>(_: bool, _: usize, _: usize) {
    panic!("Benchmark feature is not enabled");
}

#[cfg(not(feature = "benchmark"))]
fn run_batch_commit_open_verify<E, Pcs, T>(_: bool, _: usize, _: usize) {
    panic!("Benchmark feature is not enabled");
}

type PcsGoldilocks = Basefold<GoldilocksExt2, BasefoldDefaultParams>;

const NUM_SAMPLES: usize = 10;

fn bench_commit_open_verify_goldilocks_base(c: &mut Criterion) {
    let mut group = c.benchmark_group("commit_open_verify_goldilocks_base");
    group.sample_size(NUM_SAMPLES);
    // Challenge is over extension field, poly over the base field
    for num_vars in 10..=20 {
        group.bench_function(
            BenchmarkId::new("run_commit_open_verify", format!("{}", num_vars)),
            |b| {
                b.iter(|| {
                    run_commit_open_verify::<
                        GoldilocksExt2,
                        PcsGoldilocks,
                        PoseidonTranscript<GoldilocksExt2>,
                    >(true, num_vars, num_vars + 1);
                })
            },
        );
    }
}

fn bench_commit_open_verify_goldilocks_2(c: &mut Criterion) {
    // Both challenge and poly are over extension field
    let mut group = c.benchmark_group("commit_open_verify_goldilocks_base");
    group.sample_size(NUM_SAMPLES);
    // Challenge is over extension field, poly over the base field
    for num_vars in 10..=20 {
        group.bench_function(
            BenchmarkId::new("run_commit_open_verify", format!("{}", num_vars)),
            |b| {
                b.iter(|| {
                    run_commit_open_verify::<
                        GoldilocksExt2,
                        PcsGoldilocks,
                        PoseidonTranscript<GoldilocksExt2>,
                    >(false, num_vars, num_vars + 1);
                })
            },
        );
    }
}

fn bench_batch_commit_open_verify_goldilocks_base(c: &mut Criterion) {
    let mut group = c.benchmark_group("commit_batch_open_verify_goldilocks_base");
    group.sample_size(NUM_SAMPLES);
    // Challenge is over extension field, poly over the base field
    for num_vars in 10..=20 {
        group.bench_function(
            BenchmarkId::new("run_commit_open_verify", format!("{}", num_vars)),
            |b| {
                b.iter(|| {
                    run_batch_commit_open_verify::<
                        GoldilocksExt2,
                        PcsGoldilocks,
                        PoseidonTranscript<GoldilocksExt2>,
                    >(true, num_vars, num_vars + 1);
                })
            },
        );
    }
}

fn bench_batch_commit_open_verify_goldilocks_2(c: &mut Criterion) {
    let mut group = c.benchmark_group("commit_batch_open_verify_goldilocks_base");
    group.sample_size(NUM_SAMPLES);
    // Challenge is over extension field, poly over the base field
    for num_vars in 10..=20 {
        group.bench_function(
            BenchmarkId::new("run_batch_commit_open_verify", format!("{}", num_vars)),
            |b| {
                b.iter(|| {
                    run_batch_commit_open_verify::<
                        GoldilocksExt2,
                        PcsGoldilocks,
                        PoseidonTranscript<GoldilocksExt2>,
                    >(false, num_vars, num_vars + 1);
                })
            },
        );
    }
}

criterion_group! {
  name = bench_basefold;
  config = Criterion::default().warm_up_time(Duration::from_millis(3000));
  targets = bench_commit_open_verify_goldilocks_base, bench_commit_open_verify_goldilocks_2, bench_batch_commit_open_verify_goldilocks_base, bench_batch_commit_open_verify_goldilocks_2
}

criterion_main!(bench_basefold);
