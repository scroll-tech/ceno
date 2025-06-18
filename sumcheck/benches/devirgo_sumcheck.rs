#![allow(clippy::manual_memcpy)]
#![allow(clippy::needless_range_loop)]

use std::{sync::Arc, time::Duration};

use criterion::*;
use either::Either;
use ff_ext::{ExtensionField, GoldilocksExt2};
use itertools::Itertools;
use p3::field::FieldAlgebra;
use rand::thread_rng;
use sumcheck::structs::IOPProverState;

use multilinear_extensions::{
    mle::MultilinearExtension, monomial::Term, op_mle, util::max_usable_threads,
    virtual_poly::VirtualPolynomial, virtual_polys::VirtualPolynomials,
};
use transcript::BasicTranscript as Transcript;

criterion_group!(benches, sumcheck_fn, devirgo_sumcheck_fn,);
criterion_main!(benches);

const NUM_SAMPLES: usize = 10;
const NUM_DEGREE: usize = 3;
const NV: [usize; 2] = [25, 26];

/// transpose 2d vector without clone
pub fn transpose<T>(v: Vec<Vec<T>>) -> Vec<Vec<T>> {
    assert!(!v.is_empty());
    let len = v[0].len();
    let mut iters: Vec<_> = v.into_iter().map(|n| n.into_iter()).collect();
    (0..len)
        .map(|_| {
            iters
                .iter_mut()
                .map(|n| n.next().unwrap())
                .collect::<Vec<T>>()
        })
        .collect()
}

fn prepare_input<'a, E: ExtensionField>(nv: usize) -> (E, Vec<MultilinearExtension<'a, E>>) {
    let mut rng = thread_rng();
    let fs = (0..NUM_DEGREE)
        .map(|_| MultilinearExtension::<E>::random(nv, &mut rng))
        .collect_vec();

    let asserted_sum = fs
        .iter()
        .fold(vec![E::ONE; 1 << nv], |mut acc, f| {
            op_mle!(f, |f| {
                (0..f.len()).zip(acc.iter_mut()).for_each(|(i, acc)| {
                    *acc *= f[i];
                });
                acc
            })
        })
        .iter()
        .cloned()
        .sum::<E>();

    (asserted_sum, fs)
}

fn sumcheck_fn(c: &mut Criterion) {
    type E = GoldilocksExt2;

    for nv in NV {
        // expand more input size once runtime is acceptable
        let mut group = c.benchmark_group(format!("sumcheck_nv_{}", nv));
        group.sample_size(NUM_SAMPLES);

        // Benchmark the proving time
        group.bench_function(
            BenchmarkId::new("prove_sumcheck", format!("sumcheck_nv_{}", nv)),
            |b| {
                b.iter_custom(|iters| {
                    let mut time = Duration::new(0, 0);
                    for _ in 0..iters {
                        let mut prover_transcript = Transcript::new(b"test");
                        let (_, fs) = { prepare_input(nv) };
                        let fs = fs.into_iter().map(Arc::new).collect_vec();

                        let virtual_poly_v1 = VirtualPolynomial::new_from_product(fs, E::ONE);
                        let instant = std::time::Instant::now();
                        #[allow(deprecated)]
                        let (_sumcheck_proof_v1, _) = IOPProverState::<E>::prove_parallel(
                            virtual_poly_v1,
                            &mut prover_transcript,
                        );
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

fn devirgo_sumcheck_fn(c: &mut Criterion) {
    type E = GoldilocksExt2;

    let threads = max_usable_threads();
    for nv in NV {
        // expand more input size once runtime is acceptable
        let mut group = c.benchmark_group(format!("devirgo_nv_{}", nv));
        group.sample_size(NUM_SAMPLES);

        // Benchmark the proving time
        group.bench_function(
            BenchmarkId::new("prove_sumcheck", format!("devirgo_nv_{}", nv)),
            |b| {
                b.iter_custom(|iters| {
                    let mut time = Duration::new(0, 0);
                    for _ in 0..iters {
                        let mut prover_transcript = Transcript::new(b"test");
                        let (_, fs) = { prepare_input(nv) };

                        let virtual_poly_v2 = VirtualPolynomials::new_from_monimials(
                            threads,
                            nv,
                            vec![Term {
                                scalar: Either::Right(E::ONE),
                                product: fs.iter().map(Either::Left).collect_vec(),
                            }],
                        );
                        let instant = std::time::Instant::now();
                        let (_sumcheck_proof_v2, _) =
                            IOPProverState::<E>::prove(virtual_poly_v2, &mut prover_transcript);
                        let elapsed = instant.elapsed();
                        time += elapsed;
                    }
                    time
                });
            },
        );

        // Benchmark the proving time ext
        group.bench_function(
            BenchmarkId::new("prove_sumcheck_ext", format!("devirgo_nv_{}", nv)),
            |b| {
                b.iter_custom(|iters| {
                    let mut time = Duration::new(0, 0);
                    for _ in 0..iters {
                        let mut prover_transcript = Transcript::new(b"test");
                        let (_, fs) = { prepare_input(nv) };
                        let fs = fs
                            .into_iter()
                            .map(|mle: MultilinearExtension<'_, E>| {
                                MultilinearExtension::from_evaluation_vec_smart(
                                    mle.num_vars(),
                                    mle.get_base_field_vec()
                                        .iter()
                                        .map(E::from_ref_base)
                                        .collect_vec(),
                                )
                            })
                            .collect_vec();

                        let virtual_poly_v2 = VirtualPolynomials::new_from_monimials(
                            threads,
                            nv,
                            vec![Term {
                                scalar: Either::Right(E::ONE),
                                product: fs.iter().map(Either::Left).collect_vec(),
                            }],
                        );
                        let instant = std::time::Instant::now();
                        let (_sumcheck_proof_v2, _) =
                            IOPProverState::<E>::prove(virtual_poly_v2, &mut prover_transcript);
                        let elapsed = instant.elapsed();
                        time += elapsed;
                    }
                    time
                });
            },
        );

        // Benchmark the proving time
        group.bench_function(
            BenchmarkId::new("prove_sumcheck_ext_in_place", format!("devirgo_nv_{}", nv)),
            |b| {
                b.iter_custom(|iters| {
                    let mut time = Duration::new(0, 0);
                    for _ in 0..iters {
                        let mut prover_transcript = Transcript::new(b"test");
                        let (_, fs) = { prepare_input(nv) };
                        let mut fs = fs
                            .into_iter()
                            .map(|mle: MultilinearExtension<'_, E>| {
                                MultilinearExtension::from_evaluation_vec_smart(
                                    mle.num_vars(),
                                    mle.get_base_field_vec()
                                        .iter()
                                        .map(E::from_ref_base)
                                        .collect_vec(),
                                )
                            })
                            .collect_vec();

                        let virtual_poly_v2 = VirtualPolynomials::new_from_monimials(
                            threads,
                            nv,
                            vec![Term {
                                scalar: Either::Right(E::ONE),
                                product: fs.iter_mut().map(Either::Right).collect_vec(),
                            }],
                        );
                        let instant = std::time::Instant::now();
                        let (_sumcheck_proof_v2, _) =
                            IOPProverState::<E>::prove(virtual_poly_v2, &mut prover_transcript);
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
