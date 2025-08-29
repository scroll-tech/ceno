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
    utils::{rotation_next_base_mle, rotation_selector},
};
use either::Either;
use ff_ext::ExtensionField;
use itertools::{Itertools, chain};
use mpcs::PolynomialCommitmentScheme;
use multilinear_extensions::{
    Expression,
    mle::{MultilinearExtension, Point},
    monomial::Term,
    virtual_poly::build_eq_x_r_vec,
    virtual_polys::VirtualPolynomialsBuilder,
    utils::eval_by_expr_with_instance,
};
use rayon::{
    iter::{
        IndexedParallelIterator, IntoParallelRefIterator, ParallelIterator,
    },
    slice::ParallelSlice,
};
use sumcheck::{
    macros::{entered_span, exit_span},
    structs::{IOPProof, IOPProverState},
    util::get_challenge_pows,
};
use std::sync::Arc;
use transcript::{BasicTranscript, Transcript};



use crate::{
    gkr::layer::{
        ROTATION_OPENING_COUNT,
        hal::LinearLayerProver,
        sumcheck_layer::{LayerProof, SumcheckLayerProof},
    },
    hal::ProverBackend,
};

use crate::gpu::gpu_prover::*;

impl<E: ExtensionField, PCS: PolynomialCommitmentScheme<E>> LinearLayerProver<GpuBackend<E, PCS>>
    for GpuProver<GpuBackend<E, PCS>>
{
    fn prove(
        layer: &Layer<E>,
        wit: LayerWitness<GpuBackend<E, PCS>>,
        out_point: &multilinear_extensions::mle::Point<E>,
        transcript: &mut impl transcript::Transcript<E>,
    ) -> crate::gkr::layer::sumcheck_layer::LayerProof<E> {
        let cpu_wits: Vec<Arc<MultilinearExtension<'_, E>>> = wit.0
            .into_iter()
            .map(|gpu_mle| Arc::new(gpu_mle.inner_to_mle()))
            .collect();
        let cpu_wit = LayerWitness::<CpuBackend<E, PCS>>(cpu_wits);
        <CpuProver<CpuBackend<E, PCS>> as LinearLayerProver<CpuBackend<E, PCS>>>::prove(
            layer, cpu_wit, out_point, transcript,
        )
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
        let cpu_wits: Vec<Arc<MultilinearExtension<'_, E>>> = wit.0
            .into_iter()
            .map(|gpu_mle| Arc::new(gpu_mle.inner_to_mle()))
            .collect();
        let cpu_wit = LayerWitness::<CpuBackend<E, PCS>>(cpu_wits);
        <CpuProver<CpuBackend<E, PCS>> as SumcheckLayerProver<CpuBackend<E, PCS>>>::prove(
            layer,
            num_threads,
            max_num_variables,
            cpu_wit,
            challenges,
            transcript,
        )
    }
}

pub fn extract_mle_relationships_from_monomial_terms<'a, E: ExtensionField>(
    monomial_terms: &[Term<Expression<E>, Expression<E>>],
    all_mles: &Vec<Either<&'a MultilinearExtension<'a, E>, &'a mut MultilinearExtension<'a, E>>>,
    // all_mles: &[Either<&GpuPolynomial, &mut GpuPolynomial>],
    public_io_evals: &[E],
    challenges: &[E],
) -> (Vec<E>, Vec<Vec<usize>>, Vec<(usize, usize)>) {
    let mut term_coefficients = Vec::new();
    let mut mle_indices_per_term = Vec::new();
    let mut mle_size_info = Vec::new();
    
    for term in monomial_terms {
        // scalar - convert Either<E::BaseField, E> to E
        let scalar_either = eval_by_expr_with_instance(
            &[], &[], &[], public_io_evals, challenges, &term.scalar
        );
        let scalar = match scalar_either {
            Either::Left(base_field_val) => E::from(base_field_val),
            Either::Right(ext_field_val) => ext_field_val,
        };
        term_coefficients.push(scalar);
        
        // MLE indices
        let mut indices = Vec::new();
        for expr in &term.product {
            match expr {
                Expression::WitIn(witin_id) => {
                    indices.push(*witin_id as usize);
                }
                _ => panic!("Unsupported expression in product: {:?}", expr),
            }
        }
        
        // MLE size - get this before moving indices
        let first_idx = indices.first().copied();
        mle_indices_per_term.push(indices);
        
        if let Some(first_idx) = first_idx {
            let num_vars = all_mles[first_idx].num_vars();
            mle_size_info.push((num_vars, num_vars));
        }
    }
    
    (term_coefficients, mle_indices_per_term, mle_size_info)
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
        num_instances: usize,
    ) -> (
        LayerProof<<GpuBackend<E, PCS> as ProverBackend>::E>,
        Point<<GpuBackend<E, PCS> as ProverBackend>::E>,
    ) {
        let num_threads = 1; // VP builder for GPU: do not use _num_threads
        println!("  [GPU] ZerocheckLayerProver::prove()");

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
                println!("  [GPU] call prove_rotation_gpu() with rotation_cyclic_group_log2 = {}", layer.rotation_cyclic_group_log2);
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
        let span = entered_span!("build_out_points_eq", profiling_4 = true);
        let main_sumcheck_challenges = chain!(
            challenges.iter().copied(),
            get_challenge_pows(
                layer.exprs.len() + raw_rotation_exprs.len() * ROTATION_OPENING_COUNT,
                transcript,
            )
        )
        .collect_vec();
        // zero check eq || rotation eq
        let mut eqs = layer
            .out_sel_and_eval_exprs
            .par_iter()
            .zip(out_points.par_iter())
            .filter_map(|((sel_type, _), point)| sel_type.compute(point, num_instances))
            // for rotation left point
            .chain(rotation_left.par_iter().map(|rotation_left| {
                MultilinearExtension::from_evaluations_ext_vec(
                    rotation_left.len(),
                    build_eq_x_r_vec(rotation_left),
                )
            }))
            // for rotation right point
            .chain(rotation_right.par_iter().map(|rotation_right| {
                MultilinearExtension::from_evaluations_ext_vec(
                    rotation_right.len(),
                    build_eq_x_r_vec(rotation_right),
                )
            }))
            // for rotation point
            .chain(rotation_point.par_iter().map(|rotation_point| {
                MultilinearExtension::from_evaluations_ext_vec(
                    rotation_point.len(),
                    build_eq_x_r_vec(rotation_point),
                )
            }))
            .collect::<Vec<_>>();
        exit_span!(span);
        println!("eqs.len() = {}", eqs.len());

        // `wit` := witin ++ fixed
        // we concat eq in between `wit` := witin ++ eqs ++ fixed
        let mut eqs_cpu = eqs.clone();
        let mut all_witins = wit
            .iter()
            .take(layer.n_witin)
            .map(|mle| Either::Left(mle.inner_to_mle()))
            .chain(eqs_cpu.iter_mut().map(Either::Right))
            .chain(
                // fixed, start after `n_witin`
                wit.iter()
                    .skip(layer.n_witin + layer.n_structural_witin)
                    .map(|mle| Either::Left(mle.inner_to_mle())),
            )
            .collect_vec();
        assert_eq!(
            all_witins.len(),
            layer.n_witin + layer.n_structural_witin + layer.n_fixed,
            "all_witins.len() {} != layer.n_witin {} + layer.n_structural_witin {} + layer.n_fixed {}",
            all_witins.len(),
            layer.n_witin,
            layer.n_structural_witin,
            layer.n_fixed,
        );
        let all_witins_ref: Vec<Either<&MultilinearExtension<'_, E>, &mut MultilinearExtension<'_, E>>> = 
            all_witins.iter_mut().map(|either| {
                match either {
                    Either::Left(mle) => Either::Left(&*mle),  // &mut T -> &T
                    Either::Right(mle_mut) => Either::Right(&mut **mle_mut), // &mut &mut T -> &mut T
                }
            }).collect_vec();
        let (term_coefficients, mle_indices_per_term, mle_size_info) = extract_mle_relationships_from_monomial_terms(
            &layer
                .main_sumcheck_expression_monomial_terms
                .clone()
                .unwrap(),
            &all_witins_ref,
            pub_io_evals,
            &main_sumcheck_challenges,
        );

        // cpu
        let span = entered_span!("IOPProverState::prove", profiling_4 = true);
        
        let builder =
            VirtualPolynomialsBuilder::new_with_mles(num_threads, max_num_variables, all_witins_ref);
        let vps = builder.to_virtual_polys_with_monomial_terms(
            &layer
                .main_sumcheck_expression_monomial_terms
                .clone()
                .unwrap(),
            pub_io_evals,
            &main_sumcheck_challenges,
        );
        let mut transcript_cpu = transcript.clone();
        let (_proof, prover_state) = IOPProverState::prove(vps, &mut transcript_cpu);
        let evals = prover_state.get_mle_flatten_final_evaluations();

        // gpu
        type EGL64 = ff_ext::GoldilocksExt2;
        let device = CUDA_DEVICE
            .as_ref()
            .map_err(|e| format!("Device not available: {:?}", e))
            .unwrap();
        device.bind_to_thread().unwrap();
        let hal_arc = CUDA_HAL
            .as_ref()
            .map_err(|e| format!("HAL not available: {:?}", e))
            .unwrap();
        let cuda_hal = hal_arc.lock().unwrap();

        println!("all_witins_gpu begin");
        // Reconstruct the GPU-specific types for CUDA operations
        let mut all_witins_gpu = wit
            .iter()
            .take(layer.n_witin)
            .map(|mle| Either::Left(mle.inner_to_mle()))
            .chain(eqs.iter_mut().map(Either::Right))
            .chain(
                // fixed, start after `n_witin`
                wit.iter()
                    .skip(layer.n_witin + layer.n_structural_witin)
                    .map(|mle| Either::Left(mle.inner_to_mle())),
            )
            .collect_vec();
        let all_witins_ref: Vec<Either<&MultilinearExtension<'_, E>, &mut MultilinearExtension<'_, E>>> = 
            all_witins_gpu.iter_mut().map(|either| {
                match either {
                    Either::Left(mle) => Either::Left(&*mle),  // &mut T -> &T
                    Either::Right(mle_mut) => Either::Right(&mut **mle_mut), // &mut &mut T -> &mut T
                }
            }).collect_vec();
        let all_witins_gpu_gl64: Vec<Either<&MultilinearExtension<EGL64>, &mut MultilinearExtension<EGL64>>> = unsafe { std::mem::transmute(all_witins_ref) };

        // Calculate max_num_var and max_degree from the extracted relationships
        let max_num_var = max_num_variables;
        let max_degree = mle_indices_per_term.iter()
            .map(|indices| indices.len())
            .max()
            .unwrap_or(0);

        // transcript >>> BasicTranscript<GL64^2>
        let basic_tr: &mut BasicTranscript<EGL64> =
            unsafe { &mut *(transcript as *mut _ as *mut BasicTranscript<EGL64>) };
        // Convert types for GPU function call
        let term_coefficients_gl64: Vec<EGL64> = unsafe { std::mem::transmute(term_coefficients) };
        let (proof_gpu, evals_gpu, challenges_gpu) = cuda_hal.sumcheck.prove_generic_sumcheck_mles(&cuda_hal, all_witins_gpu_gl64, &mle_size_info, &term_coefficients_gl64, &mle_indices_per_term, max_num_var, max_degree, basic_tr).unwrap();
        let evals_gpu = evals_gpu.into_iter().flatten().collect_vec();
        let row_challenges = challenges_gpu.iter().map(|c| c.elements).collect_vec();

        let proof_gpu_e = unsafe { std::mem::transmute::<IOPProof<EGL64>, IOPProof<E>>(proof_gpu) };
        let evals_gpu_e = unsafe { std::mem::transmute::<Vec<EGL64>, Vec<E>>(evals_gpu) };
        let row_challenges_e = unsafe { std::mem::transmute::<Vec<EGL64>, Vec<E>>(row_challenges) };
        // assert_eq!(evals_gpu_e, evals);
        for i in 0..evals_gpu_e.len() {
            assert_eq!(evals_gpu_e[i], evals[i], "evals_gpu_e[{}] = {} != evals[{}] = {}", i, evals_gpu_e[i], i, evals[i]);
        }

        exit_span!(span);
        
        // (
        //     LayerProof {
        //         main: SumcheckLayerProof { proof, evals },
        //         rotation: rotation_proof,
        //     },
        //     prover_state.collect_raw_challenges(),
        // )
        (
            LayerProof {
                main: SumcheckLayerProof { proof: proof_gpu_e, evals: evals_gpu_e },
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
    let num_threads = 1; // VP builder for GPU: do not use _num_threads
    let span = entered_span!("rotate_witin_selector", profiling_4 = true);
    let bh = BooleanHypercube::new(rotation_cyclic_group_log2);
    let rotation_index = bh.into_iter().take(rotation_cyclic_group_log2).collect_vec();
    println!("rotation_index: {:?}", rotation_index);
    // rotated_mles is non-deterministic input, rotated from existing witness polynomial
    // we will reduce it to zero check, and finally reduce to committed polynomial opening
    let (mut selector, mut rotated_mles) = {
        let eq = build_eq_x_r_vec(rt);
        let mut mles = raw_rotation_exprs
            .par_iter()
            .map(|rotation_expr| match rotation_expr {
                (Expression::WitIn(source_wit_id), _) => rotation_next_base_mle(
                    &bh,
                    &Arc::new(wit[*source_wit_id as usize].inner_to_mle()),
                    rotation_cyclic_group_log2,
                ),
                _ => unimplemented!("unimplemented rotation"),
            })
            .chain(rayon::iter::once(rotation_selector(
                &bh,
                &eq,
                rotation_cyclic_subgroup_size,
                rotation_cyclic_group_log2,
                wit[0].evaluations_len(), // Take first mle just to retrieve total length
            )))
            .collect::<Vec<_>>();
        let selector = mles.pop().unwrap();
        (selector, mles)
    };
    let rotation_challenges = chain!(
        global_challenges.iter().copied(),
        get_challenge_pows(raw_rotation_exprs.len(), transcript)
    )
    .collect_vec();
    exit_span!(span);
    // TODO FIXME: we pick a random point from output point, does it sound?
    let owned_mles: Vec<MultilinearExtension<E>> = rotated_mles
        .iter()
        .zip_eq(raw_rotation_exprs)
        .filter_map(|(_, (_, expr))| match expr {
            Expression::WitIn(wit_id) => Some(wit[*wit_id as usize].inner_to_mle()),
            _ => None,
        })
        .collect();

    let mut mles_cpu_ref: Vec<Either<&MultilinearExtension<'_, E>, &mut MultilinearExtension<'_, E>>> = Vec::new();

    let mut owned_idx = 0;
    for (mle, (_, expr)) in rotated_mles.iter_mut().zip_eq(raw_rotation_exprs) {
    match expr {
        Expression::WitIn(_) => {
            mles_cpu_ref.push(Either::Right(mle));
            mles_cpu_ref.push(Either::Left(&owned_mles[owned_idx]));
            owned_idx += 1;
        }
        _ => panic!(""),
    }
    }
    mles_cpu_ref.push(Either::Right(&mut selector));
    let builder = VirtualPolynomialsBuilder::new_with_mles(
        num_threads,
        max_num_variables,
        // mles format [rotation_mle1, target_mle1, rotation_mle2, target_mle2, ....., selector, eq]
        mles_cpu_ref,
    );
    let vp = builder.to_virtual_polys_with_monomial_terms(
        &rotation_sumcheck_expression,
        &[],
        &rotation_challenges,
    );

    let span = entered_span!("rotation IOPProverState::prove", profiling_4 = true);
    let (rotation_proof, prover_state) = IOPProverState::prove(vp, transcript);
    exit_span!(span);
    let mut evals = prover_state.get_mle_flatten_final_evaluations();
    let origin_point = prover_state.collect_raw_challenges();
    // skip selector/eq as verifier can derive itself
    evals.truncate(raw_rotation_exprs.len() * 2);

    let span = entered_span!("rotation derived left/right eval", profiling_4 = true);
    // post process: giving opening of rotated polys (point, evals), derive original opening before rotate
    // final format: [
    //    left_eval_0th,
    //    right_eval_0th,
    //    target_eval_0th,
    //    left_eval_1st,
    //    right_eval_1st,
    //    target_eval_1st,
    //    ...
    // ]
    let bh = BooleanHypercube::new(rotation_cyclic_group_log2);
    let (left_point, right_point) = bh.get_rotation_points(&origin_point);
    let evals = evals
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
                bh.get_rotation_right_eval_from_left(*rotated_eval, left_eval, &origin_point);
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
            proof: rotation_proof,
            evals,
        },
        RotationPoints {
            left: left_point,
            right: right_point,
            origin: origin_point,
        },
    )
}
