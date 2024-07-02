use ark_std::rand::thread_rng;
use criterion::*;
use ff::Field;
use goldilocks::GoldilocksExt2;
use multilinear_extensions::mle::DenseMultilinearExtension;

fn fix_var(c: &mut Criterion) {
    let mut rng = thread_rng();

    const NUM_SAMPLES: usize = 10;
    for nv in 12..20 {
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
    for nv in 12..20 {
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

criterion_group!(benches, fix_var, fix_var_par,);
criterion_main!(benches);
