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
    utils::eval_by_expr_with_instance,
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
    selector::SelectorType,
};

use crate::gpu::{MultilinearExtensionGpu, gpu_prover::*};

impl<E: ExtensionField, PCS: PolynomialCommitmentScheme<E>> LinearLayerProver<GpuBackend<E, PCS>>
    for GpuProver<GpuBackend<E, PCS>>
{
    fn prove(
        layer: &Layer<E>,
        wit: LayerWitness<GpuBackend<E, PCS>>,
        out_point: &multilinear_extensions::mle::Point<E>,
        transcript: &mut impl transcript::Transcript<E>,
    ) -> crate::gkr::layer::sumcheck_layer::LayerProof<E> {
        let cpu_wits: Vec<Arc<MultilinearExtension<'_, E>>> = wit
            .0
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
        let cpu_wits: Vec<Arc<MultilinearExtension<'_, E>>> = wit
            .0
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
    all_mles: &Vec<&MultilinearExtensionGpu<'a, E>>,
    // all_mles: &[Either<&GpuPolynomial, &mut GpuPolynomial>],
    public_io_evals: &[E],
    challenges: &[E],
) -> (Vec<E>, Vec<Vec<usize>>, Vec<(usize, usize)>) {
    let mut term_coefficients = Vec::new();
    let mut mle_indices_per_term = Vec::new();
    let mut mle_size_info = Vec::new();

    for term in monomial_terms {
        // scalar - convert Either<E::BaseField, E> to E
        let scalar_either =
            eval_by_expr_with_instance(&[], &[], &[], public_io_evals, challenges, &term.scalar);
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
            let num_vars = all_mles[first_idx].mle.num_vars();
            mle_size_info.push((num_vars, num_vars));
        }
    }

    (term_coefficients, mle_indices_per_term, mle_size_info)
}

fn build_eq_x_r_with_sel_gpu<'a, E: ExtensionField>(
    hal: &'a CudaHalGL64,
    point: &Point<E>,
    num_instances: usize,
    selector: &SelectorType<E>,
) -> MultilinearExtensionGpu<'a, E> {
    if std::any::TypeId::of::<E::BaseField>()
        != std::any::TypeId::of::<p3::goldilocks::Goldilocks>()
    {
        panic!("GPU backend only supports Goldilocks base field");
    }

    let eq_len = 1 << point.len();
    let (num_instances, is_sp32, indices) = match selector {
        SelectorType::None => panic!("SelectorType::None"),
        SelectorType::Whole(_expr) => (eq_len, false, vec![]),
        SelectorType::Prefix(_, _expr) => {
            println!("eq_len = {}, num_instances = {}", eq_len, num_instances);
            (num_instances, false, vec![])
        }
        SelectorType::OrderedSparse32 { indices, .. } => (num_instances, true, indices.clone()),
    };

    // type eq
    let eq_mle = if is_sp32 {
        let eq = build_eq_x_r_gpu(hal, point);
        let mut eq_buf = match eq.mle {
            GpuFieldType::Base(_) => panic!("should be ext field"),
            GpuFieldType::Ext(mle) => mle,
            GpuFieldType::Unreachable => panic!("Unreachable GpuFieldType"),
        };
        let indices_u32 = indices.iter().map(|x| *x as u32).collect_vec();
        ordered_sparse32_selector_gpu(&hal.inner, &mut eq_buf.buf, &indices_u32, num_instances)
            .unwrap();
        eq_buf
    } else {
        let point_gl64: &Point<GL64Ext> = unsafe { std::mem::transmute(point) };
        let mut gpu_output = hal.alloc_ext_elems_on_device(eq_len).unwrap();
        let gpu_points = hal.alloc_ext_elems_from_host(&point_gl64).unwrap();
        build_mle_as_ceno(&hal.inner, &gpu_points, &mut gpu_output, num_instances).unwrap();
        GpuPolynomialExt::new(gpu_output, point.len())
    };
    let mle_gl64 = MultilinearExtensionGpu::from_ceno_gpu_ext(eq_mle);
    unsafe {
        std::mem::transmute::<MultilinearExtensionGpu<'a, GL64Ext>, MultilinearExtensionGpu<'a, E>>(
            mle_gl64,
        )
    }
}

fn build_eq_x_r_gpu<'a, E: ExtensionField>(
    hal: &'a CudaHalGL64,
    point: &Point<E>,
) -> MultilinearExtensionGpu<'a, E> {
    if std::any::TypeId::of::<E::BaseField>()
        != std::any::TypeId::of::<p3::goldilocks::Goldilocks>()
    {
        panic!("GPU backend only supports Goldilocks base field");
    }

    let eq_len = 1 << point.len();
    // type eq
    let point_gl64: &Point<GL64Ext> = unsafe { std::mem::transmute(point) };
    let eq_mle = {
        let mut gpu_output = hal.alloc_ext_elems_on_device(eq_len).unwrap();
        let gpu_points = hal.alloc_ext_elems_from_host(&point_gl64).unwrap();
        build_mle_as_ceno(&hal.inner, &gpu_points, &mut gpu_output, eq_len).unwrap();
        GpuPolynomialExt::new(gpu_output, point.len())
    };
    let mle_gl64 = MultilinearExtensionGpu::from_ceno_gpu_ext(eq_mle);
    unsafe {
        std::mem::transmute::<MultilinearExtensionGpu<'a, GL64Ext>, MultilinearExtensionGpu<'a, E>>(
            mle_gl64,
        )
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
                println!(
                    "  [GPU] call prove_rotation_gpu() with rotation_cyclic_group_log2 = {}",
                    layer.rotation_cyclic_group_log2
                );
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

        // cpu
        let span = entered_span!("IOPProverState::prove", profiling_4 = true);
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

        let eqs_gpu = layer
            .out_sel_and_eval_exprs
            .iter()
            .zip(out_points.iter())
            .filter_map(|((sel_type, _), point)| {
                Some(build_eq_x_r_with_sel_gpu(
                    &cuda_hal,
                    point,
                    num_instances,
                    sel_type,
                ))
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
        let all_witins_gpu = wit
            .iter()
            .take(layer.n_witin)
            .map(|mle| mle.as_ref())
            .chain(eqs_gpu.iter().map(|mle| mle))
            .chain(
                // fixed, start after `n_witin`
                wit.iter()
                    .skip(layer.n_witin + layer.n_structural_witin)
                    .map(|mle| mle.as_ref()),
            )
            .collect_vec();
        // Calculate max_num_var and max_degree from the extracted relationships
        let (term_coefficients, mle_indices_per_term, mle_size_info) =
            extract_mle_relationships_from_monomial_terms(
                &layer
                    .main_sumcheck_expression_monomial_terms
                    .clone()
                    .unwrap(),
                &all_witins_gpu,
                pub_io_evals,
                &main_sumcheck_challenges,
            );
        let max_num_var = max_num_variables;
        let max_degree = mle_indices_per_term
            .iter()
            .map(|indices| indices.len())
            .max()
            .unwrap_or(0);

        // transcript >>> BasicTranscript<GL64^2>
        let basic_tr: &mut BasicTranscript<EGL64> =
            unsafe { &mut *(transcript as *mut _ as *mut BasicTranscript<EGL64>) };
        // Convert types for GPU function call
        let term_coefficients_gl64: Vec<EGL64> = unsafe { std::mem::transmute(term_coefficients) };
        // let (proof_gpu, evals_gpu, challenges_gpu) = cuda_hal.sumcheck.prove_generic_sumcheck_mles(&cuda_hal, &all_witins_gpu_gl64, &mle_size_info, &term_coefficients_gl64, &mle_indices_per_term, max_num_var, max_degree, basic_tr).unwrap();
        let all_witins_gpu_gl64: Vec<&MultilinearExtensionGpu<EGL64>> =
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

        // convert to cpu type
        let proof_gpu_e = unsafe { std::mem::transmute::<IOPProof<EGL64>, IOPProof<E>>(proof_gpu) };
        let evals_gpu_e = unsafe { std::mem::transmute::<Vec<EGL64>, Vec<E>>(evals_gpu) };
        let row_challenges_e = unsafe { std::mem::transmute::<Vec<EGL64>, Vec<E>>(row_challenges) };

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
    let cuda_hal = CUDA_HAL.as_ref().unwrap().lock().unwrap();
    let span = entered_span!("rotate_witin_selector", profiling_4 = true);
    let bh = BooleanHypercube::new(rotation_cyclic_group_log2);

    // rotated_mles is non-deterministic input, rotated from existing witness polynomial
    // we will reduce it to zero check, and finally reduce to committed polynomial opening
    let rotated_mles_gpu = raw_rotation_exprs
        .iter()
        .map(|rotation_expr| match rotation_expr {
            (Expression::WitIn(source_wit_id), _) => {
                let cyclic_group_size = 1 << rotation_cyclic_group_log2;
                let rotation_index = bh
                    .into_iter()
                    .take(cyclic_group_size)
                    .map(|x| x as u32)
                    .collect_vec();
                let input_mle = wit[*source_wit_id as usize].as_ref();
                let input_buf = match &input_mle.mle {
                    GpuFieldType::Base(poly) => poly.evaluations(),
                    GpuFieldType::Ext(_) => panic!("should be base field"),
                    _ => panic!("unimplemented input mle"),
                };
                let mut output_buf = cuda_hal.alloc_elems_on_device(input_buf.len()).unwrap();
                rotation_next_base_mle_gpu(
                    &cuda_hal.inner,
                    &mut output_buf,
                    &input_buf,
                    &rotation_index,
                    cyclic_group_size,
                )
                .unwrap();
                let output_mle = MultilinearExtensionGpu::from_ceno_gpu_base(GpuPolynomial::new(
                    output_buf,
                    input_mle.mle.num_vars(),
                ));
                unsafe {
                    std::mem::transmute::<
                        MultilinearExtensionGpu<GL64Ext>,
                        MultilinearExtensionGpu<'_, E>,
                    >(output_mle)
                }
            }
            _ => unimplemented!("unimplemented rotation"),
        })
        .collect::<Vec<_>>();

    let eq = build_eq_x_r_gpu(&cuda_hal, rt);
    let eq_buf = match &eq.mle {
        GpuFieldType::Base(_) => panic!("should be ext field"),
        GpuFieldType::Ext(mle) => mle.evaluations(),
        GpuFieldType::Unreachable => panic!("Unreachable GpuFieldType"),
    };
    let selector_gpu = {
        let total_len = wit[0].evaluations_len(); // Take first mle just to retrieve total length
        assert!(total_len.is_power_of_two());
        let mut output_buf = cuda_hal.alloc_ext_elems_on_device(total_len).unwrap();
        // let eq_gl64 = unsafe { std::mem::transmute::<Vec<E>, Vec<GL64Ext>>(eq) };
        // let input_buf = cuda_hal.alloc_ext_elems_from_host(&eq_gl64).unwrap();
        let rotation_index = bh
            .into_iter()
            .take(rotation_cyclic_subgroup_size)
            .map(|x| x as u32)
            .collect_vec();
        rotation_selector_gpu(
            &cuda_hal.inner,
            &mut output_buf,
            &eq_buf,
            &rotation_index,
            1 << rotation_cyclic_group_log2,
            rotation_cyclic_subgroup_size,
        )
        .unwrap();
        let output_mle = MultilinearExtensionGpu::from_ceno_gpu_ext(GpuPolynomialExt::new(
            output_buf,
            total_len.ilog2() as usize,
        ));
        unsafe {
            std::mem::transmute::<MultilinearExtensionGpu<GL64Ext>, MultilinearExtensionGpu<'_, E>>(
                output_mle,
            )
        }
    };
    let rotation_challenges = chain!(
        global_challenges.iter().copied(),
        get_challenge_pows(raw_rotation_exprs.len(), transcript)
    )
    .collect_vec();
    exit_span!(span);

    // gpu mles
    let mut transcript_gpu = transcript.clone();
    let wit_mle_gpu: Vec<&MultilinearExtensionGpu<E>> = rotated_mles_gpu
        .iter()
        .zip_eq(raw_rotation_exprs)
        .filter_map(|(_, (_, expr))| match expr {
            Expression::WitIn(wit_id) => Some(wit[*wit_id as usize].as_ref()),
            _ => None,
        })
        .collect_vec();
    let mut gpu_owned_idx = 0;
    let mut mle_gpu_ref: Vec<&MultilinearExtensionGpu<E>> = Vec::new();
    for (mle, (_, expr)) in rotated_mles_gpu.iter().zip_eq(raw_rotation_exprs) {
        match expr {
            Expression::WitIn(_) => {
                mle_gpu_ref.push(mle);
                mle_gpu_ref.push(&wit_mle_gpu[gpu_owned_idx]);
                gpu_owned_idx += 1;
            }
            _ => panic!(""),
        }
    }
    mle_gpu_ref.push(&selector_gpu);

    let span = entered_span!("rotation IOPProverState::prove", profiling_4 = true);
    // gpu prover
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

    // transcript >>> BasicTranscript<GL64^2>
    let basic_tr: &mut BasicTranscript<GL64Ext> =
        unsafe { &mut *(&mut transcript_gpu as *mut _ as *mut BasicTranscript<GL64Ext>) };
    // Convert types for GPU function call
    let term_coefficients_gl64: Vec<GL64Ext> = unsafe { std::mem::transmute(term_coefficients) };
    // let (proof_gpu, evals_gpu, challenges_gpu) = cuda_hal.sumcheck.prove_generic_sumcheck_mles(&cuda_hal, &all_witins_gpu_gl64, &mle_size_info, &term_coefficients_gl64, &mle_indices_per_term, max_num_var, max_degree, basic_tr).unwrap();
    let all_witins_gpu_gl64: Vec<&MultilinearExtensionGpu<GL64Ext>> =
        unsafe { std::mem::transmute(mle_gpu_ref) };
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

    let proof_gpu_e = unsafe { std::mem::transmute::<IOPProof<GL64Ext>, IOPProof<E>>(proof_gpu) };
    let mut evals_gpu_e = unsafe { std::mem::transmute::<Vec<GL64Ext>, Vec<E>>(evals_gpu) };
    let row_challenges_e = unsafe { std::mem::transmute::<Vec<GL64Ext>, Vec<E>>(row_challenges) };
    // skip selector/eq as verifier can derive itself
    evals_gpu_e.truncate(raw_rotation_exprs.len() * 2);
    exit_span!(span);

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
            evals: evals,
        },
        RotationPoints {
            left: left_point,
            right: right_point,
            origin: row_challenges_e,
        },
    )
}
