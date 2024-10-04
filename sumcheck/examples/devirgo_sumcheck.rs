use std::sync::Arc;

use ark_std::test_rng;
use const_env::from_env;
use ff_ext::{ff::Field, ExtensionField};
use goldilocks::GoldilocksExt2;
use itertools::Itertools;
use multilinear_extensions::{
    commutative_op_mle_pair,
    mle::{ArcDenseMultilinearExtension, DenseMultilinearExtension, MultilinearExtension},
    virtual_poly::VirtualPolynomial,
};
use sumcheck::{
    structs::{IOPProverState, IOPVerifierState},
    util::ceil_log2,
};
use transcript::Transcript;

type E = GoldilocksExt2;

fn prepare_input<E: ExtensionField>(
    max_thread_id: usize,
) -> (E, VirtualPolynomial<E>, Vec<VirtualPolynomial<E>>) {
    let nv = 10;
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
    (
        asserted_sum,
        virtual_poly_1,
        virtual_poly_f1.try_into().unwrap(),
    )
}

#[from_env]
const RAYON_NUM_THREADS: usize = 8;

fn main() {
    let mut prover_transcript_v1 = Transcript::<E>::new(b"test");
    let mut prover_transcript_v2 = Transcript::<E>::new(b"test");

    let (asserted_sum, virtual_poly, virtual_poly_splitted) = prepare_input(RAYON_NUM_THREADS);
    let (sumcheck_proof_v2, _) = IOPProverState::<E>::prove_batch_polys(
        RAYON_NUM_THREADS,
        virtual_poly_splitted.clone(),
        &mut prover_transcript_v2,
    );
    println!("v2 finish");

    let mut transcript = Transcript::new(b"test");
    let poly_info = virtual_poly.aux_info.clone();
    let subclaim = IOPVerifierState::<E>::verify(
        asserted_sum,
        &sumcheck_proof_v2,
        &poly_info,
        &mut transcript,
    );
    assert!(
        virtual_poly.evaluate(
            subclaim
                .point
                .iter()
                .map(|c| c.elements)
                .collect::<Vec<_>>()
                .as_ref()
        ) == subclaim.expected_evaluation,
        "wrong subclaim"
    );

    let (sumcheck_proof_v1, _) =
        IOPProverState::<E>::prove_parallel(virtual_poly.clone(), &mut prover_transcript_v1);

    println!("v1 finish");
    assert!(sumcheck_proof_v2 == sumcheck_proof_v1);
}
