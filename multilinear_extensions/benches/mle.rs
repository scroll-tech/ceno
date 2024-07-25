use ark_std::rand::{thread_rng, Rng};
use criterion::*;
use ff::Field;
use goldilocks::GoldilocksExt2;
use multilinear_extensions::{
    mle::DenseMultilinearExtension,
    virtual_poly::{build_eq_x_r, build_eq_x_r_sequential},
};

fn fix_var(c: &mut Criterion) {
    let mut rng = thread_rng();

    const NUM_SAMPLES: usize = 10;
    for nv in 16..24 {
        let mut group = c.benchmark_group("mle");
        group.sample_size(NUM_SAMPLES);

        for i in 0..nv {
            group.bench_function(
                BenchmarkId::new("fix_var", format!("({},{})", nv, nv - i)),
                |b| {
                    b.iter_with_setup(
                        || {
                            let mut v =
                                DenseMultilinearExtension::<GoldilocksExt2>::random(nv, &mut rng);
                            let r = GoldilocksExt2::random(&mut rng);
                            for _ in 0..i {
                                v.fix_variables_in_place(&[r]);
                            }
                            (v, r)
                        },
                        |(mut v, r)| v.fix_variables_in_place(&[r]),
                    );
                },
            );
        }
        group.finish();
    }
}

fn fix_var_par(c: &mut Criterion) {
    let mut rng = thread_rng();

    const NUM_SAMPLES: usize = 10;
    for nv in 16..24 {
        let mut group = c.benchmark_group("mle");
        group.sample_size(NUM_SAMPLES);

        for i in 0..nv {
            group.bench_function(
                BenchmarkId::new("fix_var_par", format!("({},{})", nv, nv - i)),
                |b| {
                    b.iter_with_setup(
                        || {
                            let mut v =
                                DenseMultilinearExtension::<GoldilocksExt2>::random(nv, &mut rng);
                            let r = GoldilocksExt2::random(&mut rng);
                            for _ in 0..i {
                                v.fix_variables_in_place(&[r]);
                            }
                            (v, r)
                        },
                        |(mut v, r)| v.fix_variables_in_place_parallel(&[r]),
                    );
                },
            );
        }
        group.finish();
    }
}

fn bench_build_eq_internal(c: &mut Criterion, use_par: bool) {
    const NUM_SAMPLES: usize = 10;
    let mut rng = thread_rng();
    let group_name = if use_par {
        "build_eq_par"
    } else {
        "build_eq_seq"
    };
    let mut group = c.benchmark_group(group_name);
    group.sample_size(NUM_SAMPLES);

    for num_vars in 15..24 {
        group.bench_function(format!("{}", num_vars), |b| {
            b.iter_batched(
                || {
                    (0..num_vars)
                        .map(|_| GoldilocksExt2::random(&mut rng))
                        .collect::<Vec<GoldilocksExt2>>()
                },
                |r| {
                    if use_par {
                        build_eq_x_r(&r)
                    } else {
                        build_eq_x_r_sequential(&r)
                    }
                },
                BatchSize::SmallInput,
            );
        });
    }
}

fn bench_build_eq(c: &mut Criterion) {
    bench_build_eq_internal(c, false);
    bench_build_eq_internal(c, true);
}

criterion_group!(benches, bench_build_eq, fix_var, fix_var_par,);
criterion_main!(benches);
