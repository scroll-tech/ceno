#![allow(clippy::manual_memcpy)]
#![allow(clippy::needless_range_loop)]

use std::sync::Arc;

use ark_std::test_rng;
use const_env::from_env;
use criterion::*;
use ff_ext::{ExtensionField, ff::Field};
use itertools::Itertools;
use sumcheck::{structs::IOPProverState, util::ceil_log2};

use goldilocks::GoldilocksExt2;
use multilinear_extensions::{
    commutative_op_mle_pair,
    mle::{ArcDenseMultilinearExtension, DenseMultilinearExtension, MultilinearExtension},
    virtual_poly::VirtualPolynomial,
};
use transcript::Transcript;

criterion_group!(benches, sumcheck_fn, devirgo_sumcheck_fn,);
criterion_main!(benches);

const NUM_SAMPLES: usize = 10;

fn prepare_input<E: ExtensionField>(
    max_thread_id: usize,
    nv: usize,
) -> (E, VirtualPolynomial<E>, Vec<VirtualPolynomial<E>>) {
    let mut rng = test_rng();
    let size_log2 = ceil_log2(max_thread_id);
    let f1: Arc<DenseMultilinearExtension<E>> =
        DenseMultilinearExtension::<E>::random(nv, &mut rng).into();
    let g1: Arc<DenseMultilinearExtension<E>> =
        DenseMultilinearExtension::<E>::random(nv, &mut rng).into();

    let mut virtual_poly_1 = VirtualPolynomial::new_from_mle(f1.clone(), E::BaseField::ONE);
    virtual_poly_1.mul_by_mle(g1.clone(), <E as ff_ext::ExtensionField>::BaseField::ONE);

    let mut virtual_poly_f1: Vec<VirtualPolynomial<E>> = match &f1.evaluations {
        multilinear_extensions::mle::FieldType::Base(evaluations) => evaluations
            .chunks((1 << nv) >> size_log2)
            .map(|chunk| {
                DenseMultilinearExtension::<E>::from_evaluations_vec(nv - size_log2, chunk.to_vec())
                    .into()
            })
            .map(|mle| VirtualPolynomial::new_from_mle(mle, E::BaseField::ONE))
            .collect_vec(),
        _ => unreachable!(),
    };

    let poly_g1: Vec<ArcDenseMultilinearExtension<E>> = match &g1.evaluations {
        multilinear_extensions::mle::FieldType::Base(evaluations) => evaluations
            .chunks((1 << nv) >> size_log2)
            .map(|chunk| {
                DenseMultilinearExtension::<E>::from_evaluations_vec(nv - size_log2, chunk.to_vec())
                    .into()
            })
            .collect_vec(),
        _ => unreachable!(),
    };

    let asserted_sum = commutative_op_mle_pair!(|f1, g1| {
        (0..f1.len())
            .map(|i| f1[i] * g1[i])
            .fold(E::ZERO, |acc, item| acc + item)
    });

    virtual_poly_f1
        .iter_mut()
        .zip(poly_g1.iter())
        .for_each(|(f1, g1)| f1.mul_by_mle(g1.clone(), E::BaseField::ONE));
    (asserted_sum, virtual_poly_1, virtual_poly_f1)
}

#[from_env]
const RAYON_NUM_THREADS: usize = 8;

fn sumcheck_fn(c: &mut Criterion) {
    type E = GoldilocksExt2;

    for nv in [13, 14, 15, 16].into_iter() {
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

    for nv in [13, 14, 15, 16].into_iter() {
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
