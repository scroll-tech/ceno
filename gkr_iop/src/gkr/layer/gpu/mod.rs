use crate::{
    cpu::{CpuBackend, CpuProver},
    gkr::{
        booleanhypercube::BooleanHypercube,
        layer::{
            Layer, LayerWitness,
            hal::{SumcheckLayerProver, ZerocheckLayerProver},
            zerocheck_layer::RotationPoints,
        },
    },
    gpu::{GpuBackend, GpuProver},
};
use either::Either;
use ff_ext::ExtensionField;
use itertools::{Itertools, chain};
use mpcs::PolynomialCommitmentScheme;
use multilinear_extensions::{
    Expression,
    mle::{MultilinearExtension, Point},
    monomial::Term,
};
use rayon::{
    iter::{IndexedParallelIterator, IntoParallelRefIterator, ParallelIterator},
    slice::ParallelSlice,
};
use std::sync::Arc;
use sumcheck::{
    macros::{entered_span, exit_span},
    structs::IOPProof,
    util::get_challenge_pows,
};
use transcript::{BasicTranscript, Transcript};

use crate::{
    gkr::layer::{
        ROTATION_OPENING_COUNT,
        hal::LinearLayerProver,
        sumcheck_layer::{LayerProof, SumcheckLayerProof},
    },
    hal::ProverBackend,
};

use crate::gpu::{MultilinearExtensionGpu, gpu_prover::*};

pub mod utils;
use crate::selector::SelectorContext;
use utils::*;

impl<E: ExtensionField, PCS: PolynomialCommitmentScheme<E>> LinearLayerProver<GpuBackend<E, PCS>>
    for GpuProver<GpuBackend<E, PCS>>
{
    fn prove(
        layer: &Layer<E>,
        wit: LayerWitness<GpuBackend<E, PCS>>,
        out_point: &multilinear_extensions::mle::Point<E>,
        transcript: &mut impl transcript::Transcript<E>,
    ) -> crate::gkr::layer::sumcheck_layer::LayerProof<E> {
        let span = entered_span!("LinearLayerProver", profiling_2 = true);
        let cpu_wits: Vec<Arc<MultilinearExtension<'_, E>>> = wit
            .0
            .into_iter()
            .map(|gpu_mle| Arc::new(gpu_mle.inner_to_mle()))
            .collect();
        let cpu_wit = LayerWitness::<CpuBackend<E, PCS>>(cpu_wits);
        let res = <CpuProver<CpuBackend<E, PCS>> as LinearLayerProver<CpuBackend<E, PCS>>>::prove(
            layer, cpu_wit, out_point, transcript,
        );
        exit_span!(span);
        res
    }
}

impl<E: ExtensionField, PCS: PolynomialCommitmentScheme<E>> SumcheckLayerProver<GpuBackend<E, PCS>>
    for GpuProver<GpuBackend<E, PCS>>
{
    fn prove(
        layer: &Layer<E>,
        num_threads: usize,
        max_num_variables: usize,
        wit: LayerWitness<'_, GpuBackend<E, PCS>>,
        challenges: &[<GpuBackend<E, PCS> as ProverBackend>::E],
        transcript: &mut impl Transcript<<GpuBackend<E, PCS> as ProverBackend>::E>,
    ) -> LayerProof<<GpuBackend<E, PCS> as ProverBackend>::E> {
        let span = entered_span!("SumcheckLayerProver", profiling_2 = true);
        let cpu_wits: Vec<Arc<MultilinearExtension<'_, E>>> = wit
            .0
            .into_iter()
            .map(|gpu_mle| Arc::new(gpu_mle.inner_to_mle()))
            .collect();
        let cpu_wit = LayerWitness::<CpuBackend<E, PCS>>(cpu_wits);
        let res = <CpuProver<CpuBackend<E, PCS>> as SumcheckLayerProver<CpuBackend<E, PCS>>>::prove(
            layer,
            num_threads,
            max_num_variables,
            cpu_wit,
            challenges,
            transcript,
        );
        exit_span!(span);
        res
    }
}

impl<E: ExtensionField, PCS: PolynomialCommitmentScheme<E>> ZerocheckLayerProver<GpuBackend<E, PCS>>
    for GpuProver<GpuBackend<E, PCS>>
{
    fn prove(
        layer: &Layer<<GpuBackend<E, PCS> as ProverBackend>::E>,
        _num_threads: usize,
        max_num_variables: usize,
        wit: LayerWitness<GpuBackend<E, PCS>>,
        out_points: &[Point<<GpuBackend<E, PCS> as ProverBackend>::E>],
        pub_io_evals: &[<GpuBackend<E, PCS> as ProverBackend>::E],
        challenges: &[<GpuBackend<E, PCS> as ProverBackend>::E],
        transcript: &mut impl Transcript<<GpuBackend<E, PCS> as ProverBackend>::E>,
        selector_ctxs: &[SelectorContext],
    ) -> (
        LayerProof<<GpuBackend<E, PCS> as ProverBackend>::E>,
        Point<<GpuBackend<E, PCS> as ProverBackend>::E>,
    ) {
        let span = entered_span!("ZerocheckLayerProver", profiling_2 = true);
        let num_threads = 1; // VP builder for GPU: do not use _num_threads

        assert_eq!(challenges.len(), 2);
        assert_eq!(
            layer.out_sel_and_eval_exprs.len(),
            out_points.len(),
            "out eval length {} != with distinct out_point {}",
            layer.out_sel_and_eval_exprs.len(),
            out_points.len(),
        );

        let (_, raw_rotation_exprs) = &layer.rotation_exprs;
        let (rotation_proof, rotation_left, rotation_right, rotation_point) =
            if let Some(rotation_sumcheck_expression) =
                layer.rotation_sumcheck_expression_monomial_terms.as_ref()
            {
                // 1st sumcheck: process rotation_exprs
                let rt = out_points.first().unwrap();
                let (
                    proof,
                    RotationPoints {
                        left,
                        right,
                        origin,
                    },
                ) = prove_rotation_gpu(
                    num_threads,
                    max_num_variables,
                    layer.rotation_cyclic_subgroup_size,
                    layer.rotation_cyclic_group_log2,
                    &wit,
                    raw_rotation_exprs,
                    rotation_sumcheck_expression.clone(),
                    rt,
                    challenges,
                    transcript,
                );
                (Some(proof), Some(left), Some(right), Some(origin))
            } else {
                (None, None, None, None)
            };

        // 2th sumcheck: batch rotation with other constrains
        let main_sumcheck_challenges = chain!(
            challenges.iter().copied(),
            get_challenge_pows(
                layer.exprs.len() + raw_rotation_exprs.len() * ROTATION_OPENING_COUNT,
                transcript,
            )
        )
        .collect_vec();

        let span_eq = entered_span!("build eqs", profiling_2 = true);
        let cuda_hal = get_cuda_hal().unwrap();
        let eqs_gpu = layer
            .out_sel_and_eval_exprs
            .iter()
            .zip(out_points.iter())
            .zip(selector_ctxs.iter())
            .map(|(((sel_type, _), point), selector_ctx)| {
                build_eq_x_r_with_sel_gpu(&cuda_hal, point, selector_ctx, sel_type)
            })
            // for rotation left point
            .chain(
                rotation_left
                    .iter()
                    .map(|rotation_left| build_eq_x_r_gpu(&cuda_hal, rotation_left)),
            )
            // for rotation right point
            .chain(
                rotation_right
                    .iter()
                    .map(|rotation_right| build_eq_x_r_gpu(&cuda_hal, rotation_right)),
            )
            // for rotation point
            .chain(
                rotation_point
                    .iter()
                    .map(|rotation_point| build_eq_x_r_gpu(&cuda_hal, rotation_point)),
            )
            .collect::<Vec<_>>();
        // `wit` := witin ++ fixed ++ pubio
        let all_witins_gpu = wit
            .iter()
            .take(layer.n_witin + layer.n_fixed + layer.n_instance)
            .map(|mle| mle.as_ref())
            .chain(
                // some non-selector structural witin
                wit.iter()
                    .skip(layer.n_witin + layer.n_fixed + layer.n_instance)
                    .take(
                        layer.n_structural_witin
                            - layer.out_sel_and_eval_exprs.len()
                            - layer
                                .rotation_exprs
                                .0
                                .as_ref()
                                .map(|_| ROTATION_OPENING_COUNT)
                                .unwrap_or(0),
                    )
                    .map(|mle| mle.as_ref()),
            )
            .chain(eqs_gpu.iter())
            .collect_vec();
        assert_eq!(
            all_witins_gpu.len(),
            layer.n_witin + layer.n_structural_witin + layer.n_fixed + layer.n_instance,
            "all_witins.len() {} != layer.n_witin {} + layer.n_structural_witin {} + layer.n_fixed {} + layer.n_instance {}",
            all_witins_gpu.len(),
            layer.n_witin,
            layer.n_structural_witin,
            layer.n_fixed,
            layer.n_instance,
        );
        exit_span!(span_eq);

        // Calculate max_num_var and max_degree from the extracted relationships
        let (term_coefficients, mle_indices_per_term, mle_size_info) =
            extract_mle_relationships_from_monomial_terms(
                &layer
                    .main_sumcheck_expression_monomial_terms
                    .clone()
                    .unwrap(),
                &all_witins_gpu,
                &pub_io_evals.iter().map(|v| Either::Right(*v)).collect_vec(),
                &main_sumcheck_challenges,
            );
        let max_num_var = max_num_variables;
        let max_degree = mle_indices_per_term
            .iter()
            .map(|indices| indices.len())
            .max()
            .unwrap_or(0);

        // Convert types for GPU function Call
        let basic_tr: &mut BasicTranscript<BB31Ext> =
            unsafe { &mut *(transcript as *mut _ as *mut BasicTranscript<BB31Ext>) };
        let term_coefficients_gl64: Vec<BB31Ext> =
            unsafe { std::mem::transmute(term_coefficients) };
        let all_witins_gpu_gl64: Vec<&MultilinearExtensionGpu<BB31Ext>> =
            unsafe { std::mem::transmute(all_witins_gpu) };
        let all_witins_gpu_type_gl64 = all_witins_gpu_gl64.iter().map(|mle| &mle.mle).collect_vec();
        let (proof_gpu, evals_gpu, challenges_gpu) = cuda_hal
            .sumcheck
            .prove_generic_sumcheck_gpu(
                &cuda_hal,
                all_witins_gpu_type_gl64,
                &mle_size_info,
                &term_coefficients_gl64,
                &mle_indices_per_term,
                max_num_var,
                max_degree,
                basic_tr,
            )
            .unwrap();
        let evals_gpu = evals_gpu.into_iter().flatten().collect_vec();
        let row_challenges = challenges_gpu.iter().map(|c| c.elements).collect_vec();

        // convert back to E: ExtensionField
        let proof_gpu_e =
            unsafe { std::mem::transmute::<IOPProof<BB31Ext>, IOPProof<E>>(proof_gpu) };
        let evals_gpu_e = unsafe { std::mem::transmute::<Vec<BB31Ext>, Vec<E>>(evals_gpu) };
        let row_challenges_e =
            unsafe { std::mem::transmute::<Vec<BB31Ext>, Vec<E>>(row_challenges) };

        exit_span!(span);
        (
            LayerProof {
                main: SumcheckLayerProof {
                    proof: proof_gpu_e,
                    evals: evals_gpu_e,
                },
                rotation: rotation_proof,
            },
            row_challenges_e,
        )
    }
}

/// This is to prove the following n rotation arguments:
/// For the i-th argument, we check rotated(rotation_expr[i].0) == rotation_expr[i].1
/// This is proved through the following arguments:
///     0 = \sum_{b = 0}^{N - 1} sel(b) * \sum_i alpha^i * (rotated_rotation_expr[i].0(b) - rotation_expr[i].1(b))
/// With the randomness rx, we check: (currently we only support cycle with length 32)
///     rotated_rotation_expr[i].0(rx) == (1 - rx_4) * rotation_expr[i].1(0, rx_0, rx_1, ..., rx_3, rx_5, ...)
///                                     + rx_4 * rotation_expr[i].1(1, rx_0, 1 - rx_1, ..., rx_3, rx_5, ...)
#[allow(clippy::too_many_arguments)]
pub(crate) fn prove_rotation_gpu<E: ExtensionField, PCS: PolynomialCommitmentScheme<E>>(
    _num_threads: usize,
    max_num_variables: usize,
    rotation_cyclic_subgroup_size: usize,
    rotation_cyclic_group_log2: usize,
    wit: &LayerWitness<GpuBackend<E, PCS>>,
    raw_rotation_exprs: &[(Expression<E>, Expression<E>)],
    rotation_sumcheck_expression: Vec<Term<Expression<E>, Expression<E>>>,
    rt: &Point<E>,
    global_challenges: &[E],
    transcript: &mut impl Transcript<E>,
) -> (SumcheckLayerProof<E>, RotationPoints<E>) {
    let bh = BooleanHypercube::new(rotation_cyclic_group_log2);
    let cuda_hal = get_cuda_hal().unwrap();

    // rotated_mles is non-deterministic input, rotated from existing witness polynomial
    // we will reduce it to zero check, and finally reduce to committed polynomial opening
    let span = entered_span!("rotate_witin_selector", profiling_3 = true);
    let rotated_mles_gpu = build_rotation_mles_gpu(
        &cuda_hal,
        raw_rotation_exprs,
        wit,
        &bh,
        rotation_cyclic_group_log2,
    );
    let selector_gpu = build_rotation_selector_gpu(
        &cuda_hal,
        wit,
        rt,
        &bh,
        rotation_cyclic_subgroup_size,
        rotation_cyclic_group_log2,
    );
    let rotation_challenges = chain!(
        global_challenges.iter().copied(),
        get_challenge_pows(raw_rotation_exprs.len(), transcript)
    )
    .collect_vec();
    exit_span!(span);

    let span = entered_span!("rotation IOPProverState::prove", profiling_3 = true);
    // gpu mles
    let mle_gpu_ref: Vec<&MultilinearExtensionGpu<E>> = rotated_mles_gpu
        .iter()
        .zip_eq(raw_rotation_exprs)
        .flat_map(|(mle, (_, expr))| match expr {
            Expression::WitIn(wit_id) => {
                vec![mle, wit[*wit_id as usize].as_ref()]
            }
            _ => panic!(""),
        })
        .chain(std::iter::once(&selector_gpu))
        .collect_vec();
    // Calculate max_num_var and max_degree from the extracted relationships
    let (term_coefficients, mle_indices_per_term, mle_size_info) =
        extract_mle_relationships_from_monomial_terms(
            &rotation_sumcheck_expression,
            &mle_gpu_ref,
            &[],
            &rotation_challenges,
        );
    let max_num_var = max_num_variables;
    let max_degree = mle_indices_per_term
        .iter()
        .map(|indices| indices.len())
        .max()
        .unwrap_or(0);

    // Convert types for GPU function call
    let basic_tr: &mut BasicTranscript<BB31Ext> =
        unsafe { &mut *(transcript as *mut _ as *mut BasicTranscript<BB31Ext>) };
    let term_coefficients_gl64: Vec<BB31Ext> = unsafe { std::mem::transmute(term_coefficients) };
    let all_witins_gpu_gl64: Vec<&MultilinearExtensionGpu<BB31Ext>> =
        unsafe { std::mem::transmute(mle_gpu_ref) };
    let all_witins_gpu_type_gl64 = all_witins_gpu_gl64.iter().map(|mle| &mle.mle).collect_vec();
    // gpu prover
    let (proof_gpu, evals_gpu, challenges_gpu) = cuda_hal
        .sumcheck
        .prove_generic_sumcheck_gpu(
            &cuda_hal,
            all_witins_gpu_type_gl64,
            &mle_size_info,
            &term_coefficients_gl64,
            &mle_indices_per_term,
            max_num_var,
            max_degree,
            basic_tr,
        )
        .unwrap();
    let evals_gpu = evals_gpu.into_iter().flatten().collect_vec();
    let row_challenges = challenges_gpu.iter().map(|c| c.elements).collect_vec();

    let proof_gpu_e = unsafe { std::mem::transmute::<IOPProof<BB31Ext>, IOPProof<E>>(proof_gpu) };
    let mut evals_gpu_e = unsafe { std::mem::transmute::<Vec<BB31Ext>, Vec<E>>(evals_gpu) };
    let row_challenges_e = unsafe { std::mem::transmute::<Vec<BB31Ext>, Vec<E>>(row_challenges) };
    // skip selector/eq as verifier can derive itself
    evals_gpu_e.truncate(raw_rotation_exprs.len() * 2);
    exit_span!(span);

    let span = entered_span!("rotation derived left/right eval", profiling_3 = true);
    let bh = BooleanHypercube::new(rotation_cyclic_group_log2);
    let (left_point, right_point) = bh.get_rotation_points(&row_challenges_e);
    let evals = evals_gpu_e
        .par_chunks_exact(2)
        .zip_eq(raw_rotation_exprs.par_iter())
        .flat_map(|(evals, (rotated_expr, _))| {
            let [rotated_eval, target_eval] = evals else {
                unreachable!()
            };
            let left_eval = match rotated_expr {
                Expression::WitIn(source_wit_id) => {
                    wit[*source_wit_id as usize].evaluate(&left_point)
                }
                _ => unreachable!(),
            };
            let right_eval =
                bh.get_rotation_right_eval_from_left(*rotated_eval, left_eval, &row_challenges_e);
            #[cfg(debug_assertions)]
            {
                use multilinear_extensions::Expression;

                let expected_right_eval = match rotated_expr {
                    Expression::WitIn(source_wit_id) => {
                        wit[*source_wit_id as usize].evaluate(&right_point)
                    }
                    _ => unreachable!(),
                };
                assert_eq!(
                    expected_right_eval, right_eval,
                    "rotation right eval mismatch: expected {expected_right_eval}, got {right_eval}"
                );
            }
            [left_eval, right_eval, *target_eval]
        })
        .collect::<Vec<E>>();
    exit_span!(span);

    (
        SumcheckLayerProof {
            proof: proof_gpu_e,
            evals,
        },
        RotationPoints {
            left: left_point,
            right: right_point,
            origin: row_challenges_e,
        },
    )
}
