#![allow(clippy::manual_memcpy)]
#![allow(clippy::needless_range_loop)]

use std::time::Duration;

use ark_std::test_rng;
use criterion::*;
use ff_ext::{ExtensionField, GoldilocksExt2};
use itertools::Itertools;
use p3::field::PrimeCharacteristicRing;
use sumcheck::structs::IOPProverState;

use multilinear_extensions::{
    mle::DenseMultilinearExtension,
    op_mle,
    util::max_usable_threads,
    virtual_poly::{ArcMultilinearExtension, VirtualPolynomial},
    virtual_polys::VirtualPolynomials,
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

fn prepare_input<'a, E: ExtensionField>(nv: usize) -> (E, Vec<ArcMultilinearExtension<'a, E>>) {
    let mut rng = test_rng();
    let fs = (0..NUM_DEGREE)
        .map(|_| {
            let mle: ArcMultilinearExtension<'a, E> =
                DenseMultilinearExtension::<E>::random(nv, &mut rng).into();
            mle
        })
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

                        let mut virtual_poly_v1 = VirtualPolynomial::new(nv);
                        virtual_poly_v1.add_mle_list(fs.to_vec(), E::ONE);

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

                        let mut virtual_poly_v2 = VirtualPolynomials::new(threads, nv);
                        virtual_poly_v2.add_mle_list(fs.iter().collect_vec(), E::ONE);

                        let instant = std::time::Instant::now();
                        let (_sumcheck_proof_v2, _) = IOPProverState::<E>::prove_batch_polys(
                            virtual_poly_v2,
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
