#![allow(clippy::manual_memcpy)]
#![allow(clippy::needless_range_loop)]

use std::{array, time::Duration};

use ark_std::test_rng;
use criterion::*;
use ff::Field;
use ff_ext::ExtensionField;
use itertools::Itertools;
use sumcheck::{structs::IOPProverStateV2 as IOPProverState, util::ceil_log2};

use goldilocks::GoldilocksExt2;
use multilinear_extensions::{
    mle::DenseMultilinearExtension,
    op_mle,
    util::max_usable_threads,
    virtual_poly::build_eq_x_r_vec,
    virtual_poly_v2::{ArcMultilinearExtension, VirtualPolynomialV2 as VirtualPolynomial},
};
use transcript::BasicTranscript as Transcript;

criterion_group!(benches, sumcheck_fn, devirgo_sumcheck_fn,);
criterion_main!(benches);

const NUM_SAMPLES: usize = 10;
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

fn prepare_input<'a, E: ExtensionField + Field>(
    nv: usize,
) -> (E, VirtualPolynomial<'a, E>, Vec<VirtualPolynomial<'a, E>>) {
    let mut rng = test_rng();
    let max_thread_id = max_usable_threads();
    let size_log2 = ceil_log2(max_thread_id);
    let point = (0..nv).map(|_| E::random(&mut rng)).collect::<Vec<_>>();
    // generate logup constraint sigma = f0 * f1 + beta * (f0 * f3 + f1 * f2)
    let fs: [ArcMultilinearExtension<'a, E>; 4] = array::from_fn(|_| {
        let eval = (0..1 << nv).map(|_| E::random(&mut rng)).collect_vec();
        DenseMultilinearExtension::from_evaluations_ext_vec(nv, eval).into()
    });
    let eq = build_eq_x_r_vec(&point);
    let eq = DenseMultilinearExtension::from_evaluations_ext_vec(nv, eq).into();
    let polys = [vec![eq], fs.to_vec()].concat();
    let beta = E::random(&mut rng);

    let mut virtual_poly_v1 = VirtualPolynomial::new(nv);
    virtual_poly_v1.add_mle_list(
        vec![polys[0].clone(), polys[1].clone(), polys[2].clone()],
        E::ONE,
    );
    virtual_poly_v1.add_mle_list(
        vec![polys[0].clone(), polys[1].clone(), polys[4].clone()],
        beta,
    );
    virtual_poly_v1.add_mle_list(
        vec![polys[0].clone(), polys[2].clone(), polys[3].clone()],
        beta,
    );

    // devirgo version
    let virtual_poly_v2: Vec<Vec<ArcMultilinearExtension<'a, E>>> = transpose(
        polys
            .iter()
            .map(|f| match &f.evaluations() {
                multilinear_extensions::mle::FieldType::Base(evaluations) => evaluations
                    .chunks((1 << nv) >> size_log2)
                    .map(|chunk| {
                        let mle: ArcMultilinearExtension<'a, E> =
                            DenseMultilinearExtension::<E>::from_evaluations_vec(
                                nv - size_log2,
                                chunk.to_vec(),
                            )
                            .into();
                        mle
                    })
                    .collect_vec(),
                multilinear_extensions::mle::FieldType::Ext(evaluations) => evaluations
                    .chunks((1 << nv) >> size_log2)
                    .map(|chunk| {
                        let mle: ArcMultilinearExtension<'a, E> =
                            DenseMultilinearExtension::<E>::from_evaluations_ext_vec(
                                nv - size_log2,
                                chunk.to_vec(),
                            )
                            .into();
                        mle
                    })
                    .collect_vec(),
                _ => unreachable!(),
            })
            .collect(),
    );
    let virtual_poly_v2: Vec<VirtualPolynomial<E>> = virtual_poly_v2
        .into_iter()
        .map(|polys| {
            let mut virtual_poly = VirtualPolynomial::new(nv);
            virtual_poly.add_mle_list(
                vec![polys[0].clone(), polys[1].clone(), polys[2].clone()],
                E::ONE,
            );
            virtual_poly.add_mle_list(
                vec![polys[0].clone(), polys[1].clone(), polys[4].clone()],
                beta,
            );
            virtual_poly.add_mle_list(
                vec![polys[0].clone(), polys[2].clone(), polys[3].clone()],
                beta,
            );
            virtual_poly
        })
        .collect();

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
        .sum::<E>();

    (asserted_sum, virtual_poly_v1, virtual_poly_v2)
}

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
                        let mut prover_transcript = Transcript::<E>::new(b"test");
                        let (_, virtual_poly, _) = { prepare_input(nv) };

                        let instant = std::time::Instant::now();
                        #[allow(deprecated)]
                        let (_sumcheck_proof_v1, _) = IOPProverState::<E>::prove_parallel(
                            virtual_poly.clone(),
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
        let mut group = c.benchmark_group(format!("logup_devirgo_nv_{}", nv));
        group.sample_size(NUM_SAMPLES);

        // Benchmark the proving time
        group.bench_function(
            BenchmarkId::new("prove_sumcheck", format!("devirgo_nv_{}", nv)),
            |b| {
                b.iter_custom(|iters| {
                    let mut time = Duration::new(0, 0);
                    for _ in 0..iters {
                        let mut prover_transcript = Transcript::<E>::new(b"test");
                        let (_, _, virtual_poly_splitted) = { prepare_input(nv) };

                        let instant = std::time::Instant::now();
                        let (_sumcheck_proof_v2, _) = IOPProverState::<E>::prove_batch_polys(
                            threads,
                            virtual_poly_splitted,
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
