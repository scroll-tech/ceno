#![allow(clippy::manual_memcpy)]
#![allow(clippy::needless_range_loop)]

use std::array;

use ark_std::test_rng;
use const_env::from_env;
use criterion::*;
use ff_ext::ExtensionField;
use itertools::Itertools;
use sumcheck::{structs::IOPProverStateV2 as IOPProverState, util::ceil_log2};

use goldilocks::GoldilocksExt2;
use multilinear_extensions::{
    mle::DenseMultilinearExtension,
    op_mle,
    virtual_poly_v2::{ArcMultilinearExtension, VirtualPolynomialV2 as VirtualPolynomial},
};
use transcript::Transcript;

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

fn prepare_input<'a, E: ExtensionField>(
    max_thread_id: usize,
    nv: usize,
) -> (E, VirtualPolynomial<'a, E>, Vec<VirtualPolynomial<'a, E>>) {
    let mut rng = test_rng();
    let size_log2 = ceil_log2(max_thread_id);
    let fs: [ArcMultilinearExtension<'a, E>; NUM_DEGREE] = array::from_fn(|_| {
        let mle: ArcMultilinearExtension<'a, E> =
            DenseMultilinearExtension::<E>::random(nv, &mut rng).into();
        mle
    });

    let mut virtual_poly_v1 = VirtualPolynomial::new(nv);
    virtual_poly_v1.add_mle_list(fs.to_vec(), E::ONE);

    // devirgo version
    let virtual_poly_v2: Vec<Vec<ArcMultilinearExtension<'a, E>>> = transpose(
        fs.iter()
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
                _ => unreachable!(),
            })
            .collect(),
    );
    let virtual_poly_v2: Vec<VirtualPolynomial<E>> = virtual_poly_v2
        .into_iter()
        .map(|fs| {
            let mut virtual_polynomial = VirtualPolynomial::new(fs[0].num_vars());
            virtual_polynomial.add_mle_list(fs, E::ONE);
            virtual_polynomial
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

#[from_env]
const RAYON_NUM_THREADS: usize = 8;

fn sumcheck_fn(c: &mut Criterion) {
    type E = GoldilocksExt2;

    for nv in NV.into_iter() {
        // expand more input size once runtime is acceptable
        let mut group = c.benchmark_group(format!("sumcheck_nv_{}", nv));
        group.sample_size(NUM_SAMPLES);

        // Benchmark the proving time
        group.bench_function(
            BenchmarkId::new("prove_sumcheck", format!("sumcheck_nv_{}", nv)),
            |b| {
                b.iter_with_setup(
                    || {
                        let prover_transcript = Transcript::<E>::new(b"test");
                        let (asserted_sum, virtual_poly, virtual_poly_splitted) =
                            { prepare_input(RAYON_NUM_THREADS, nv) };
                        (
                            prover_transcript,
                            asserted_sum,
                            virtual_poly,
                            virtual_poly_splitted,
                        )
                    },
                    |(
                        mut prover_transcript,
                        _asserted_sum,
                        virtual_poly,
                        _virtual_poly_splitted,
                    )| {
                        #[allow(deprecated)]
                        let (_sumcheck_proof_v1, _) = IOPProverState::<E>::prove_parallel(
                            virtual_poly.clone(),
                            &mut prover_transcript,
                        );
                    },
                );
            },
        );

        group.finish();
    }
}

fn devirgo_sumcheck_fn(c: &mut Criterion) {
    type E = GoldilocksExt2;

    for nv in NV.into_iter() {
        // expand more input size once runtime is acceptable
        let mut group = c.benchmark_group(format!("devirgo_nv_{}", nv));
        group.sample_size(NUM_SAMPLES);

        // Benchmark the proving time
        group.bench_function(
            BenchmarkId::new("prove_sumcheck", format!("devirgo_nv_{}", nv)),
            |b| {
                b.iter_with_setup(
                    || {
                        let prover_transcript = Transcript::<E>::new(b"test");
                        let (asserted_sum, virtual_poly, virtual_poly_splitted) =
                            { prepare_input(RAYON_NUM_THREADS, nv) };
                        (
                            prover_transcript,
                            asserted_sum,
                            virtual_poly,
                            virtual_poly_splitted,
                        )
                    },
                    |(
                        mut prover_transcript,
                        _asserted_sum,
                        _virtual_poly,
                        virtual_poly_splitted,
                    )| {
                        let (_sumcheck_proof_v2, _) = IOPProverState::<E>::prove_batch_polys(
                            RAYON_NUM_THREADS,
                            virtual_poly_splitted,
                            &mut prover_transcript,
                        );
                    },
                );
            },
        );

        group.finish();
    }
}
