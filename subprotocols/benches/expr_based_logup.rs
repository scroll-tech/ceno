use std::{array, time::Duration};

use ark_std::test_rng;
use criterion::*;
use ff::Field;
use goldilocks::GoldilocksExt2;
use itertools::Itertools;
use subprotocols::{
    expression::{Constant, Expression, Witness},
    sumcheck::SumcheckProverState,
    test_utils::{random_point, random_poly},
    zerocheck::ZerocheckProverState,
};
use transcript::BasicTranscript as Transcript;

criterion_group!(benches, zerocheck_fn, sumcheck_fn);
criterion_main!(benches);

const NUM_SAMPLES: usize = 10;
const NV: [usize; 2] = [25, 26];

fn sumcheck_fn(c: &mut Criterion) {
    type E = GoldilocksExt2;

    for nv in NV {
        // expand more input size once runtime is acceptable
        let mut group = c.benchmark_group(format!("logup_sumcheck_nv_{}", nv));
        group.sample_size(NUM_SAMPLES);

        // Benchmark the proving time
        group.bench_function(
            BenchmarkId::new("prove_sumcheck", format!("sumcheck_nv_{}", nv)),
            |b| {
                b.iter_custom(|iters| {
                    let mut time = Duration::new(0, 0);
                    for _ in 0..iters {
                        let mut rng = test_rng();
                        // Initialize logup expression.
                        let eq = Expression::Wit(Witness::EqPoly(0));
                        let beta = Expression::Const(Constant::Challenge(0));
                        let [d0, d1, n0, n1] =
                            array::from_fn(|i| Expression::Wit(Witness::ExtPoly(i)));
                        let expr = eq * (d0.clone() * d1.clone() + beta * (d0 * n1 + d1 * n0));

                        // Randomly generate point and witness.
                        let point = random_point(&mut rng, nv);

                        let d0 = random_poly(&mut rng, nv);
                        let d1 = random_poly(&mut rng, nv);
                        let n0 = random_poly(&mut rng, nv);
                        let n1 = random_poly(&mut rng, nv);
                        let mut ext_mles = [d0.clone(), d1.clone(), n0.clone(), n1.clone()];

                        let challenges = vec![E::random(&mut rng)];

                        let ext_mle_refs =
                            ext_mles.iter_mut().map(|v| v.as_mut_slice()).collect_vec();

                        let mut prover_transcript = Transcript::new(b"test");
                        let prover = SumcheckProverState::new(
                            expr,
                            &[&point],
                            ext_mle_refs,
                            vec![],
                            &challenges,
                            &mut prover_transcript,
                        );

                        let instant = std::time::Instant::now();
                        let _ = black_box(prover.prove());
                        let elapsed = instant.elapsed();
                        time += elapsed;
                    }

                    time
                });
            },
        );

        group.finish();
    }
}

fn zerocheck_fn(c: &mut Criterion) {
    type E = GoldilocksExt2;

    for nv in NV {
        // expand more input size once runtime is acceptable
        let mut group = c.benchmark_group(format!("logup_sumcheck_nv_{}", nv));
        group.sample_size(NUM_SAMPLES);

        // Benchmark the proving time
        group.bench_function(
            BenchmarkId::new("prove_sumcheck", format!("sumcheck_nv_{}", nv)),
            |b| {
                b.iter_custom(|iters| {
                    let mut time = Duration::new(0, 0);
                    for _ in 0..iters {
                        // Initialize logup expression.
                        let mut rng = test_rng();
                        let beta = Expression::Const(Constant::Challenge(0));
                        let [d0, d1, n0, n1] =
                            array::from_fn(|i| Expression::Wit(Witness::ExtPoly(i)));
                        let expr = d0.clone() * d1.clone() + beta * (d0 * n1 + d1 * n0);

                        // Randomly generate point and witness.
                        let point = random_point(&mut rng, nv);

                        let d0 = random_poly(&mut rng, nv);
                        let d1 = random_poly(&mut rng, nv);
                        let n0 = random_poly(&mut rng, nv);
                        let n1 = random_poly(&mut rng, nv);
                        let mut ext_mles = [d0.clone(), d1.clone(), n0.clone(), n1.clone()];

                        let challenges = vec![E::random(&mut rng)];

                        let ext_mle_refs =
                            ext_mles.iter_mut().map(|v| v.as_mut_slice()).collect_vec();

                        let mut prover_transcript = Transcript::new(b"test");
                        let prover = ZerocheckProverState::new(
                            vec![expr],
                            &[&point],
                            ext_mle_refs,
                            vec![],
                            &challenges,
                            &mut prover_transcript,
                        );

                        let instant = std::time::Instant::now();
                        let _ = black_box(prover.prove());
                        let elapsed = instant.elapsed();
                        time += elapsed;
                    }

                    time
                });
            },
        );

        group.finish();
    }
}
