use crate::{
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
use multilinear_extensions::{Expression, mle::Point, monomial::Term};
use rayon::{
    iter::{IndexedParallelIterator, IntoParallelRefIterator, ParallelIterator},
    slice::ParallelSlice,
};
use sumcheck::{
    macros::{entered_span, exit_span},
    structs::IOPProof,
    util::get_challenge_pows,
};
use transcript::{BasicTranscript, Transcript};

use crate::{
    gkr::layer::{
        hal::LinearLayerProver,
        sumcheck_layer::{LayerProof, SumcheckLayerProof},
    },
    hal::ProverBackend,
};
use ceno_gpu::common::sumcheck::CommonTermPlan;

use crate::gpu::{MultilinearExtensionGpu, gpu_prover::*};

pub mod utils;
use crate::selector::{SelectorContext, SelectorType};
use utils::*;

impl<E: ExtensionField, PCS: PolynomialCommitmentScheme<E>> LinearLayerProver<GpuBackend<E, PCS>>
    for GpuProver<GpuBackend<E, PCS>>
{
    fn prove(
        _layer: &Layer<E>,
        _wit: LayerWitness<GpuBackend<E, PCS>>,
        _out_point: &multilinear_extensions::mle::Point<E>,
        _transcript: &mut impl transcript::Transcript<E>,
    ) -> crate::gkr::layer::sumcheck_layer::LayerProof<E> {
        panic!("LinearLayerProver is not implemented for GPU");
    }
}

impl<E: ExtensionField, PCS: PolynomialCommitmentScheme<E>> SumcheckLayerProver<GpuBackend<E, PCS>>
    for GpuProver<GpuBackend<E, PCS>>
{
    fn prove(
        _layer: &Layer<E>,
        _num_threads: usize,
        _max_num_variables: usize,
        _wit: LayerWitness<'_, GpuBackend<E, PCS>>,
        _challenges: &[<GpuBackend<E, PCS> as ProverBackend>::E],
        _transcript: &mut impl Transcript<<GpuBackend<E, PCS> as ProverBackend>::E>,
    ) -> LayerProof<<GpuBackend<E, PCS> as ProverBackend>::E> {
        panic!("SumcheckLayerProver is not implemented for GPU");
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
        let stream = crate::gpu::get_thread_stream();
        let span = entered_span!("ZerocheckLayerProver", profiling_2 = true);
        let _num_threads = 1; // VP builder for GPU: do not use host thread parallelism

        assert_eq!(challenges.len(), 2);
        assert_eq!(
            layer.out_sel_and_eval_exprs.len(),
            out_points.len(),
            "out eval length {} != with distinct out_point {}",
            layer.out_sel_and_eval_exprs.len(),
            out_points.len(),
        );

        // Main sumcheck batches smaller selector-group sumchecks.
        // Per group g (from `out_sel_and_eval_exprs`):
        //   p_g(x) = sel_g(x) * Σ_j (α_{2+offset(g,j)} * expr_{g,j}(x)),
        //   S_g = Σ_{x in {0,1}^n} p_g(x).
        // The batched polynomial is p(x) = Σ_g p_g(x), so Σ_x p(x) = Σ_g S_g.
        let main_sumcheck_challenges = chain!(
            challenges.iter().copied(),
            get_challenge_pows(layer.exprs.len(), transcript)
        )
        .collect_vec();

        let span_eq = entered_span!("build eqs", profiling_2 = true);
        let cuda_hal = get_cuda_hal().unwrap();
        let selector_eq_pairs = layer
            .out_sel_and_eval_exprs
            .iter()
            .zip(out_points.iter())
            .zip(selector_ctxs.iter())
            .filter_map(|(((sel_type, _), point), selector_ctx)| {
                let eq = build_eq_x_r_with_sel_gpu(&cuda_hal, point, selector_ctx, sel_type);
                let selector_expr = match sel_type {
                    SelectorType::Whole(expr)
                    | SelectorType::Prefix(expr)
                    | SelectorType::OrderedSparse {
                        expression: expr, ..
                    }
                    | SelectorType::QuarkBinaryTreeLessThan(expr) => expr,
                    SelectorType::None => return None,
                };
                let Expression::StructuralWitIn(wit_id, _) = selector_expr else {
                    panic!("selector expression must be StructuralWitIn");
                };
                let wit_id = *wit_id as usize;
                assert!(
                    wit_id < layer.n_structural_witin,
                    "selector wit id out of range"
                );
                Some((wit_id, eq))
            })
            .collect::<Vec<_>>();

        let mut selector_eq_by_wit_id: Vec<Option<MultilinearExtensionGpu<'static, E>>> =
            vec![None; layer.n_structural_witin];
        for (wit_id, eq) in selector_eq_pairs {
            if selector_eq_by_wit_id[wit_id].is_none() {
                selector_eq_by_wit_id[wit_id] = Some(eq);
            }
        }

        // `wit` := witin ++ fixed ++ structural
        // selector structural witins are replaced by computed eq MLEs in-place by witness id.
        let base_wit_count = layer.n_witin + layer.n_fixed;
        let all_witins_gpu = wit
            .iter()
            .take(base_wit_count)
            .map(|mle| mle.as_ref())
            .chain(
                selector_eq_by_wit_id
                    .iter_mut()
                    .zip(
                        wit.iter()
                            .skip(base_wit_count)
                            .take(layer.n_structural_witin),
                    )
                    .map(|(selector_eq, mle)| {
                        if let Some(eq) = selector_eq.as_mut() {
                            eq
                        } else {
                            mle.as_ref()
                        }
                    }),
            )
            .collect_vec();
        assert_eq!(
            all_witins_gpu.len(),
            layer.n_witin + layer.n_structural_witin + layer.n_fixed,
            "all_witins.len() {} != layer.n_witin {} + layer.n_structural_witin {} + layer.n_fixed {}",
            all_witins_gpu.len(),
            layer.n_witin,
            layer.n_structural_witin,
            layer.n_fixed,
        );
        exit_span!(span_eq);

        let plan = layer.main_sumcheck_expression_common_factored.as_ref();
        let residual_terms = layer
            .main_sumcheck_expression_monomial_terms_excluded_shared
            .as_ref();
        // Calculate max_num_var and max_degree from the extracted relationships
        let monomial_terms = match (plan, residual_terms) {
            (Some(_), Some(residual)) => residual.clone(),
            (Some(_), None) => panic!("common factoring plan present without residual monomials"),
            (None, Some(terms)) => terms.clone(),
            (None, None) => layer
                .main_sumcheck_expression_monomial_terms
                .clone()
                .expect("main sumcheck monomial terms must exist"),
        };
        let (term_coefficients, mle_indices_per_term, mle_size_info) =
            extract_mle_relationships_from_monomial_terms(
                &monomial_terms,
                &all_witins_gpu,
                &pub_io_evals.iter().map(|v| Either::Right(*v)).collect_vec(),
                &main_sumcheck_challenges,
            );
        if let Some(plan) = plan {
            for group in &plan.groups {
                for &term_idx in &group.term_indices {
                    debug_assert!(
                        term_idx < mle_indices_per_term.len(),
                        "factored term {} missing residual monomial (len={})",
                        term_idx,
                        mle_indices_per_term.len()
                    );
                }
            }
        }
        let common_term_plan_host: Option<CommonTermPlan> =
            plan.map(|plan| encode_common_term_plan(plan, all_witins_gpu.len()));
        let max_num_var = max_num_variables;
        let max_degree = if let Some(plan) = plan {
            plan.groups
                .iter()
                .flat_map(|group| {
                    group.term_indices.iter().map(|term_idx| {
                        let shared_len = group.shared_len;
                        let residual_len = mle_indices_per_term
                            .get(*term_idx)
                            .map(|v| v.len())
                            .unwrap_or(0);
                        shared_len + residual_len
                    })
                })
                .max()
                .unwrap_or_else(|| {
                    mle_indices_per_term
                        .iter()
                        .map(|indices| indices.len())
                        .max()
                        .unwrap_or(0)
                })
        } else {
            mle_indices_per_term
                .iter()
                .map(|indices| indices.len())
                .max()
                .unwrap_or(0)
        };

        // Convert types for GPU function Call
        let basic_tr: &mut BasicTranscript<BB31Ext> =
            unsafe { &mut *(transcript as *mut _ as *mut BasicTranscript<BB31Ext>) };
        let term_coefficients_gl64: Vec<BB31Ext> =
            unsafe { std::mem::transmute(term_coefficients) };
        let all_witins_gpu_gl64: Vec<&MultilinearExtensionGpu<BB31Ext>> =
            unsafe { std::mem::transmute(all_witins_gpu) };
        let all_witins_gpu_type_gl64 = all_witins_gpu_gl64.iter().map(|mle| &mle.mle).collect_vec();
        let (proof_gpu, evals_gpu, challenges_gpu) = cuda_hal
            .prove_generic_sumcheck_gpu(
                all_witins_gpu_type_gl64,
                &mle_size_info,
                &term_coefficients_gl64,
                &mle_indices_per_term,
                max_num_var,
                max_degree,
                common_term_plan_host.as_ref(),
                basic_tr,
                stream.as_ref(),
            )
            .unwrap();
        let evals_gpu = evals_gpu.into_iter().flatten().collect();
        let row_challenges = challenges_gpu.iter().map(|c| c.elements).collect();

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
#[tracing::instrument(skip_all, name = "prove_rotation_gpu", level = "info")]
pub fn prove_rotation_gpu<E: ExtensionField, PCS: PolynomialCommitmentScheme<E>>(
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
    let stream = crate::gpu::get_thread_stream();
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
        .prove_generic_sumcheck_gpu(
            all_witins_gpu_type_gl64,
            &mle_size_info,
            &term_coefficients_gl64,
            &mle_indices_per_term,
            max_num_var,
            max_degree,
            None,
            basic_tr,
            stream.as_ref(),
        )
        .unwrap();
    let evals_gpu = evals_gpu.into_iter().flatten().collect();
    let row_challenges = challenges_gpu.iter().map(|c| c.elements).collect();

    let proof_gpu_e = unsafe { std::mem::transmute::<IOPProof<BB31Ext>, IOPProof<E>>(proof_gpu) };
    let mut evals_gpu_e = unsafe { std::mem::transmute::<Vec<BB31Ext>, Vec<E>>(evals_gpu) };
    let row_challenges_e = unsafe { std::mem::transmute::<Vec<BB31Ext>, Vec<E>>(row_challenges) };
    // skip selector/eq as verifier can derive itself
    evals_gpu_e.truncate(raw_rotation_exprs.len() * 2);
    exit_span!(span);

    let span = entered_span!("rotation derived left/right eval", profiling_3 = true);
    let bh = BooleanHypercube::new(rotation_cyclic_group_log2);
    let (left_point, right_point) = bh.get_rotation_points(&row_challenges_e);
    // Capture parent thread's CUDA stream so Rayon workers can reuse it.
    // TODO: GPU batch evaluation and its batch version
    let parent_stream = crate::gpu::get_thread_stream();
    let evals = evals_gpu_e
        .par_chunks_exact(2)
        .zip_eq(raw_rotation_exprs.par_iter())
        .flat_map(|(evals, (rotated_expr, _))| {
            // Propagate parent thread's CUDA stream to Rayon worker
            let _guard = parent_stream
                .as_ref()
                .map(|s| crate::gpu::bind_thread_stream(s.clone()));
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
