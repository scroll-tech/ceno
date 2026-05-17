use super::hal::{
    BatchedMainConstraintProver, DeviceTransporter, EccQuarkProver, MainConstraintJob,
    MainConstraintResult, MainSumcheckProver, OpeningProver, ProverDevice, RotationProver,
    TowerProver, TraceCommitter,
};
use crate::{
    error::ZKVMError,
    scheme::{
        MainConstraintProof,
        constants::SEPTIC_EXTENSION_DEGREE,
        cpu::TowerRelationOutput,
        hal::{
            DeviceProvingKey, MainSumcheckEvals, ProofInput, RotationProverOutput, TowerProverSpec,
        },
        utils::{
            GkrOutputStageMask, assign_group_evals, derive_ecc_bridge_claims,
            extract_ecc_quark_witness_inputs, first_layer_output_group_stage_masks,
            split_rotation_evals,
        },
    },
    structs::{ComposedConstrainSystem, EccQuarkProof, PointAndEval, TowerProofs},
};
use ceno_gpu::{
    Buffer, CudaHal,
    bb31::{CudaHalBB31, GpuFieldType, GpuMatrix, GpuPolynomial, GpuPolynomialExt},
    common::{
        CacheLevel, get_gpu_cache_level,
        jagged::{
            JaggedSumcheckGpuCtx, batch_commit_gpu_grouped, eval_cols_at_point_gpu,
            jagged_batch_open_gpu, jagged_sumcheck_prove_gpu,
        },
        sumcheck::CommonTermPlan,
    },
    get_cuda_mem_info,
};
use either::Either;
use ff_ext::ExtensionField;
use gkr_iop::{
    error::BackendError,
    gkr::{
        self, Evaluation, GKRProof, GKRProverOutput,
        layer::{LayerWitness, gpu::utils::extract_mle_relationships_from_monomial_terms},
    },
    gpu::{
        GpuBackend, GpuBasefoldPcsData, GpuJaggedPcsData, GpuJaggedTraceLayout, GpuPcsData,
        GpuProver, gpu_prover::BB31Ext,
    },
    hal::ProverBackend,
};
use itertools::{Itertools, chain};
use mpcs::{Basefold, BasefoldRSParams, PCSFriParam, Point, PolynomialCommitmentScheme};
use multilinear_extensions::{
    Expression, ToExpr,
    mle::{FieldType, IntoMLE, MultilinearExtension},
    util::ceil_log2,
    utils::eval_by_expr_constant,
    virtual_poly::{build_eq_x_r_vec, eq_eval},
};
use p3::field::FieldAlgebra;
use rayon::{
    iter::{
        IndexedParallelIterator, IntoParallelIterator, IntoParallelRefIterator,
        IntoParallelRefMutIterator, ParallelIterator,
    },
    slice::ParallelSliceMut,
};
use std::{
    collections::BTreeMap,
    io::Write,
    iter::{once, repeat_n},
    mem::MaybeUninit,
    sync::Arc,
    time::Instant,
};
use sumcheck::{
    macros::{entered_span, exit_span},
    structs::{IOPProof, IOPProverMessage},
    util::{get_challenge_pows, optimal_sumcheck_threads},
};
use transcript::{BasicTranscript, Transcript};
use witness::{InstancePaddingStrategy, next_pow2_instance_padding};

use ceno_gpu::common::transpose::matrix_transpose;
use tracing::info_span;
use witness::DeviceMatrixLayout;

type BabyBearBasefold = Basefold<BB31Ext, BasefoldRSParams>;

struct GpuJaggedHostPreprocessed {
    q_host_evals: Vec<BB31Base>,
    q_device_evals: Option<BufferImpl<'static, BB31Base>>,
    cumulative_heights: Vec<usize>,
    poly_heights: Vec<usize>,
    total_evaluations: usize,
    reshape_log_height: usize,
}

pub(crate) fn is_babybear_jagged_pcs<E, PCS>() -> bool
where
    E: ExtensionField,
    PCS: PolynomialCommitmentScheme<E> + 'static,
{
    let field_name = std::any::type_name::<E>();
    let pcs_name = std::any::type_name::<PCS>();
    field_name.contains("BabyBear") && pcs_name.contains("Jagged")
}

fn expect_basefold_pcs_data(pcs_data: &GpuPcsData) -> &GpuBasefoldPcsData {
    match pcs_data {
        GpuPcsData::Basefold(data) => data,
        GpuPcsData::Jagged(_) => panic!("expected Basefold GPU PCS data, got Jagged"),
    }
}

fn expect_jagged_pcs_data(pcs_data: &GpuPcsData) -> &GpuJaggedPcsData {
    match pcs_data {
        GpuPcsData::Jagged(data) => data,
        GpuPcsData::Basefold(_) => panic!("expected Jagged GPU PCS data, got Basefold"),
    }
}

fn jagged_trace_layouts<T>(traces: &[witness::RowMajorMatrix<T>]) -> Vec<GpuJaggedTraceLayout>
where
    T: FieldAlgebra + Default + Sync + Clone + Send + Copy,
{
    let mut first_poly_idx = 0usize;
    traces
        .iter()
        .map(|trace| {
            let layout = GpuJaggedTraceLayout {
                first_poly_idx,
                num_polys: trace.width(),
                num_vars: trace.num_vars(),
            };
            first_poly_idx += trace.width();
            layout
        })
        .collect()
}

fn wrap_jagged_commitment_as_pcs<E, PCS>(
    inner_commit: <BabyBearBasefold as PolynomialCommitmentScheme<BB31Ext>>::Commitment,
    cumulative_heights: Vec<usize>,
    reshape_log_height: usize,
) -> PCS::Commitment
where
    E: ExtensionField,
    PCS: PolynomialCommitmentScheme<E> + 'static,
{
    assert!(
        is_babybear_jagged_pcs::<E, PCS>(),
        "Jagged GPU commitment wrapper called for non-Jagged PCS: {}",
        std::any::type_name::<PCS>(),
    );
    let jagged_commitment = mpcs::JaggedCommitment::<BB31Ext, BabyBearBasefold> {
        inner: inner_commit,
        cumulative_heights,
        reshape_log_height,
    };
    let commit: PCS::Commitment = unsafe { std::mem::transmute_copy(&jagged_commitment) };
    std::mem::forget(jagged_commitment);
    commit
}

#[cfg(feature = "gpu")]
use gkr_iop::gpu::gpu_prover::*;

mod memory;

mod util;
pub(crate) use memory::{
    check_gpu_mem_estimation, check_gpu_mem_estimation_with_context,
    check_gpu_tower_prove_mem_estimation_with_context, estimate_chip_proof_memory,
    estimate_main_witness_bytes, estimate_tower_bytes, init_gpu_mem_tracker,
};
use memory::{
    estimate_ecc_quark_bytes_from_num_vars, estimate_main_constraints_bytes,
    estimate_structural_mle_bytes, estimate_trace_extraction_bytes,
};
pub(crate) use util::expect_basic_transcript;
use util::{
    WitnessRegistry, batch_mles_take_half, hal_to_backend_error, mle_filter_even_odd_batch,
    mle_host_to_gpu, read_septic_value_from_gpu, symbolic_from_mle,
};

pub struct GpuTowerProver;

#[derive(Debug, Default, Clone, Copy)]
struct PcsResidentStats {
    digest_tree_bytes: usize,
    codeword_leaves_bytes: usize,
    trace_gpu_bytes: usize,
    rmms_device_bytes: usize,
    rmms_device_count: usize,
    total_rmms: usize,
}

fn rmm_device_backing_bytes<T>(rmm: &witness::RowMajorMatrix<T>) -> usize
where
    T: FieldAlgebra + Default + Sync + Clone + Send + Copy + 'static,
{
    rmm.device_backing_ref::<BufferImpl<'static, T>>()
        .map(|device_buffer| device_buffer.len() * std::mem::size_of::<T>())
        .unwrap_or(0)
}

fn rmm_col_major_device_rows<T>(rmm: &witness::RowMajorMatrix<T>) -> Option<usize>
where
    T: FieldAlgebra + Default + Sync + Clone + Send + Copy + 'static,
{
    if rmm.device_backing_layout() != Some(DeviceMatrixLayout::ColMajor) {
        return None;
    }
    let cols = rmm.width();
    if cols == 0 {
        return Some(0);
    }
    let device_buffer = rmm.device_backing_ref::<BufferImpl<'static, BB31Base>>()?;
    Some(device_buffer.len() / cols)
}

fn jagged_trace_physical_rows<T>(trace: &witness::RowMajorMatrix<T>) -> usize
where
    T: FieldAlgebra + Default + Sync + Clone + Send + Copy + 'static,
{
    if trace.device_backing_layout() == Some(DeviceMatrixLayout::ColMajor) {
        rmm_col_major_device_rows(trace)
            .unwrap_or_else(|| panic!("Jagged trace col-major device row count mismatch"))
    } else {
        trace.occupied_physical_rows()
    }
}

fn pcs_resident_stats(pcs_data_basefold: &GpuBasefoldPcsData) -> PcsResidentStats {
    let digest_tree_bytes =
        pcs_data_basefold.codeword.digest_buf.len() * std::mem::size_of::<BB31Base>();
    let codeword_leaves_bytes = pcs_data_basefold
        .codeword
        .leaves
        .as_ref()
        .map(|leaves| {
            leaves
                .iter()
                .map(|leaf| leaf.values().len() * std::mem::size_of::<BB31Base>())
                .sum::<usize>()
        })
        .unwrap_or(0);
    let trace_gpu_bytes = pcs_data_basefold
        .trace
        .as_ref()
        .map(|traces| {
            traces
                .iter()
                .flatten()
                .map(|poly| poly.evaluations().len() * std::mem::size_of::<BB31Base>())
                .sum::<usize>()
        })
        .unwrap_or(0);
    let (rmms_device_bytes, rmms_device_count, total_rmms) = pcs_data_basefold
        .rmms
        .as_ref()
        .map(|rmms| {
            (
                rmms.iter()
                    .filter(|rmm| rmm.has_device_backing())
                    .map(rmm_device_backing_bytes)
                    .sum::<usize>(),
                rmms.iter().filter(|rmm| rmm.has_device_backing()).count(),
                rmms.len(),
            )
        })
        .unwrap_or((0, 0, 0));
    PcsResidentStats {
        digest_tree_bytes,
        codeword_leaves_bytes,
        trace_gpu_bytes,
        rmms_device_bytes,
        rmms_device_count,
        total_rmms,
    }
}

pub fn log_gpu_pcs_baseline<E, PCS>(
    label: &str,
    pcs_data: &<GpuBackend<E, PCS> as ProverBackend>::PcsData,
) where
    E: ExtensionField,
    PCS: PolynomialCommitmentScheme<E>,
{
    assert_eq!(
        std::any::TypeId::of::<E::BaseField>(),
        std::any::TypeId::of::<BB31Base>(),
        "GPU PCS baseline logging only supports BabyBear base field",
    );
    let pcs_data_basefold = match pcs_data {
        GpuPcsData::Basefold(data) => data,
        GpuPcsData::Jagged(data) => &data.inner,
    };
    let pcs = pcs_resident_stats(pcs_data_basefold);
    let mb = |bytes: usize| bytes as f64 / (1024.0 * 1024.0);
    tracing::info!(
        "[gpu pcs baseline][{label}] digest_tree={:.2}MB leaves={:.2}MB trace_gpu={:.2}MB rmms_device={:.2}MB ({}/{})",
        mb(pcs.digest_tree_bytes),
        mb(pcs.codeword_leaves_bytes),
        mb(pcs.trace_gpu_bytes),
        mb(pcs.rmms_device_bytes),
        pcs.rmms_device_count,
        pcs.total_rmms,
    );
}

pub fn log_gpu_proof_baseline<E, PCS>(
    label: &str,
    witness_data: &<GpuBackend<E, PCS> as ProverBackend>::PcsData,
    fixed_mles: &[Arc<gkr_iop::gpu::MultilinearExtensionGpu<'static, E>>],
) where
    E: ExtensionField,
    PCS: PolynomialCommitmentScheme<E>,
{
    assert_eq!(
        std::any::TypeId::of::<E::BaseField>(),
        std::any::TypeId::of::<BB31Base>(),
        "GPU baseline logging only supports BabyBear base field",
    );
    let cuda_hal = get_cuda_hal().expect("cuda hal must exist for gpu baseline logging");
    let pool = cuda_hal.inner.mem_pool();
    let used_bytes = pool.get_used_size().unwrap_or(0);
    let reserved_bytes = pool.get_reserved_size().unwrap_or(0);
    let (cuda_free_bytes, cuda_total_bytes) = get_cuda_mem_info().unwrap_or((0usize, 0usize));
    let cuda_used_bytes = cuda_total_bytes.saturating_sub(cuda_free_bytes);

    let pcs_data_basefold = match witness_data {
        GpuPcsData::Basefold(data) => data,
        GpuPcsData::Jagged(data) => &data.inner,
    };

    let pcs = pcs_resident_stats(pcs_data_basefold);
    let fixed_mle_bytes = fixed_mles
        .iter()
        .map(|mle| match &mle.mle {
            gkr_iop::gpu::gpu_prover::GpuFieldType::Base(poly) => {
                poly.evaluations().len() * std::mem::size_of::<BB31Base>()
            }
            gkr_iop::gpu::gpu_prover::GpuFieldType::Ext(poly) => {
                poly.evaluations().len() * std::mem::size_of::<BB31Ext>()
            }
            gkr_iop::gpu::gpu_prover::GpuFieldType::Unreachable => 0,
        })
        .sum::<usize>();
    let accounted_bytes = pcs.digest_tree_bytes
        + pcs.codeword_leaves_bytes
        + pcs.trace_gpu_bytes
        + pcs.rmms_device_bytes
        + fixed_mle_bytes;
    let unaccounted_bytes = (used_bytes as usize).saturating_sub(accounted_bytes);
    let mb = |bytes: usize| bytes as f64 / (1024.0 * 1024.0);
    tracing::info!(
        "[gpu device][{label}] cuda_used={:.2}MB cuda_free={:.2}MB cuda_total={:.2}MB | pool_used={:.2}MB pool_reserved={:.2}MB pool_booked={:.2}MB pool_max={:.2}MB",
        mb(cuda_used_bytes),
        mb(cuda_free_bytes),
        mb(cuda_total_bytes),
        mb(used_bytes as usize),
        mb(reserved_bytes as usize),
        mb(pool.get_booked_total() as usize),
        mb(pool.get_max_size() as usize),
    );
    tracing::info!(
        "[gpu baseline][{label}] pool: used={:.2}MB reserved={:.2}MB | pcs: digest_tree={:.2}MB leaves={:.2}MB trace_gpu={:.2}MB rmms_device={:.2}MB ({}/{}) | fixed_mles={:.2}MB | unaccounted={:.2}MB",
        mb(used_bytes as usize),
        mb(reserved_bytes as usize),
        mb(pcs.digest_tree_bytes),
        mb(pcs.codeword_leaves_bytes),
        mb(pcs.trace_gpu_bytes),
        mb(pcs.rmms_device_bytes),
        pcs.rmms_device_count,
        pcs.total_rmms,
        mb(fixed_mle_bytes),
        mb(unaccounted_bytes),
    );
}

pub fn log_gpu_pool_usage(label: &str) {
    let cuda_hal = get_cuda_hal().expect("cuda hal must exist for gpu pool logging");
    let pool = cuda_hal.inner.mem_pool();
    let used_bytes = pool.get_used_size().unwrap_or(0);
    let reserved_bytes = pool.get_reserved_size().unwrap_or(0);
    let mb = |bytes: usize| bytes as f64 / (1024.0 * 1024.0);
    let message = format!(
        "[gpu pool][{label}] used={:.2}MB reserved={:.2}MB",
        mb(used_bytes as usize),
        mb(reserved_bytes as usize),
    );
    eprintln!("{message}");
    let _ = std::io::stderr().flush();
    tracing::info!("{}", message);
}

pub fn log_gpu_device_state(label: &str) {
    let cuda_hal = get_cuda_hal().expect("cuda hal must exist for gpu device logging");
    let pool = cuda_hal.inner.mem_pool();
    let used_bytes = pool.get_used_size().unwrap_or(0);
    let reserved_bytes = pool.get_reserved_size().unwrap_or(0);
    let booked_bytes = pool.get_booked_total();
    let max_bytes = pool.get_max_size();
    let (cuda_free_bytes, cuda_total_bytes) = get_cuda_mem_info().unwrap_or((0usize, 0usize));
    let cuda_used_bytes = cuda_total_bytes.saturating_sub(cuda_free_bytes);
    let mb = |bytes: usize| bytes as f64 / (1024.0 * 1024.0);
    let message = format!(
        "[gpu device][{label}] cuda_used={:.2}MB cuda_free={:.2}MB cuda_total={:.2}MB | pool_used={:.2}MB pool_reserved={:.2}MB pool_booked={:.2}MB pool_max={:.2}MB",
        mb(cuda_used_bytes),
        mb(cuda_free_bytes),
        mb(cuda_total_bytes),
        mb(used_bytes as usize),
        mb(reserved_bytes as usize),
        mb(booked_bytes as usize),
        mb(max_bytes as usize),
    );
    eprintln!("{message}");
    let _ = std::io::stderr().flush();
    tracing::info!("{}", message);
}
use crate::scheme::{constants::NUM_FANIN, septic_curve::SepticPoint};
use gkr_iop::{
    gpu::{ArcMultilinearExtensionGpu, BB31Base, MultilinearExtensionGpu},
    selector::{SelectorContext, SelectorType},
};

/// Standalone function for prove_tower_relation that doesn't require &self
/// This allows it to be called from parallel threads without Send/Sync bounds on GpuProver
pub fn prove_tower_relation_impl<E: ExtensionField, PCS: PolynomialCommitmentScheme<E>>(
    composed_cs: &ComposedConstrainSystem<E>,
    input: &ProofInput<'_, GpuBackend<E, PCS>>,
    records: &[ArcMultilinearExtensionGpu<'_, E>],
    challenges: &[E; 2],
    transcript: &mut impl Transcript<<GpuBackend<E, PCS> as ProverBackend>::E>,
    cuda_hal: &Arc<CudaHalBB31>,
) -> Result<TowerRelationOutput<E>, ZKVMError> {
    let stream = gkr_iop::gpu::get_thread_stream();
    if std::any::TypeId::of::<E::BaseField>() != std::any::TypeId::of::<BB31Base>() {
        panic!("GPU backend only supports Goldilocks base field");
    }

    // Calculate r_set_len directly from constraint system
    let ComposedConstrainSystem {
        zkvm_v1_css: cs, ..
    } = composed_cs;
    let r_set_len = cs.r_expressions.len() + cs.r_table_expressions.len();

    let (point, proof, lk_out_evals, w_out_evals, r_out_evals) = {
        // build_tower_witness_gpu builds compact GPU specs directly.
        let span = entered_span!("build_tower_witness", profiling_2 = true);
        let (prod_gpu, logup_gpu) =
            info_span!("[ceno] build_tower_witness_gpu").in_scope(|| {
                build_tower_witness_gpu(composed_cs, input, records, challenges, cuda_hal)
                    .map_err(|e| format!("build_tower_witness_gpu failed: {}", e))
                    .map_err(|e| ZKVMError::InvalidWitness(e.into()))
            })?;
        exit_span!(span);

        // GPU optimization: Extract out_evals from GPU-built towers before consuming them
        // This is the true optimization - using GPU tower results instead of CPU inference
        let span = entered_span!("extract_out_evals_from_gpu_towers", profiling_2 = true);
        let (r_out_evals, w_out_evals, lk_out_evals) =
            extract_out_evals_from_gpu_towers(&prod_gpu, &logup_gpu, r_set_len);
        exit_span!(span);

        // bind read/write/lookup out evals into transcript before deriving tower challenges
        for eval in r_out_evals
            .iter()
            .chain(w_out_evals.iter())
            .chain(lk_out_evals.iter())
            .flatten()
        {
            transcript.append_field_element_ext(eval);
        }

        let basic_tr = expect_basic_transcript(transcript);

        let tower_input = ceno_gpu::TowerInput {
            prod_specs: prod_gpu,
            logup_specs: logup_gpu,
        };

        let span = entered_span!("prove_tower_relation", profiling_2 = true);
        let (point_gl, proof_gpu) =
            info_span!("[ceno] prove_tower_relation_gpu").in_scope(|| {
                cuda_hal
                    .tower
                    .create_proof(cuda_hal, tower_input, NUM_FANIN, basic_tr, stream.as_ref())
                    .map_err(|e| {
                        ZKVMError::BackendError(BackendError::CircuitError(
                            format!("gpu tower create_proof failed: {e:?}").into_boxed_str(),
                        ))
                    })
            })?;
        exit_span!(span);

        // TowerProofs
        let point: Point<E> = unsafe { std::mem::transmute(point_gl) };
        let proof: TowerProofs<E> = unsafe { std::mem::transmute(proof_gpu) };
        (point, proof, lk_out_evals, w_out_evals, r_out_evals)
    };

    Ok((point, proof, lk_out_evals, w_out_evals, r_out_evals))
}

// Extract out_evals from GPU-built tower witnesses
#[allow(clippy::type_complexity)]
pub(crate) fn extract_out_evals_from_gpu_towers<E: ff_ext::ExtensionField>(
    prod_gpu: &[ceno_gpu::GpuProverSpec], // GPU-built product towers
    logup_gpu: &[ceno_gpu::GpuProverSpec], // GPU-built logup towers
    r_set_len: usize,
) -> (Vec<Vec<E>>, Vec<Vec<E>>, Vec<Vec<E>>) {
    let stream = gkr_iop::gpu::get_thread_stream();
    // Extract product out_evals from GPU towers
    let mut r_out_evals = Vec::new();
    let mut w_out_evals = Vec::new();
    for (i, gpu_spec) in prod_gpu.iter().enumerate() {
        let first_layer_evals: Vec<E> = gpu_spec
            .get_output_evals(stream.as_ref())
            .expect("Failed to extract final evals from GPU product tower");

        // Product tower first layer should have 2 MLEs
        assert_eq!(
            first_layer_evals.len(),
            2,
            "Product tower first layer should have 2 MLEs"
        );

        // Split into r_out_evals and w_out_evals based on r_set_len
        if i < r_set_len {
            r_out_evals.push(first_layer_evals);
        } else {
            w_out_evals.push(first_layer_evals);
        }
    }

    // Extract logup out_evals from GPU towers
    let mut lk_out_evals = Vec::new();
    for gpu_spec in logup_gpu.iter() {
        let first_layer_evals: Vec<E> = gpu_spec
            .get_output_evals(stream.as_ref())
            .expect("Failed to extract final evals from GPU logup tower");

        // Logup tower first layer should have 4 MLEs
        assert_eq!(
            first_layer_evals.len(),
            4,
            "Logup tower first layer should have 4 MLEs"
        );

        lk_out_evals.push(first_layer_evals);
    }

    (r_out_evals, w_out_evals, lk_out_evals)
}

/// Standalone function for prove_rotation that doesn't require &self.
/// This allows rotation proof generation from parallel task code paths.
pub fn prove_rotation_impl<E: ExtensionField, PCS: PolynomialCommitmentScheme<E> + 'static>(
    composed_cs: &ComposedConstrainSystem<E>,
    input: &ProofInput<'_, GpuBackend<E, PCS>>,
    rt_tower: &Point<E>,
    challenges: &[E; 2],
    transcript: &mut impl Transcript<E>,
) -> Result<Option<RotationProverOutput<E>>, ZKVMError> {
    let Some(gkr_circuit) = composed_cs.gkr_circuit.as_ref() else {
        return Ok(None);
    };
    let Some(layer) = gkr_circuit.layers.first() else {
        return Ok(None);
    };
    if layer.rotation_exprs.1.is_empty() {
        return Ok(None);
    }

    let Some(rotation_sumcheck_expression) =
        layer.rotation_sumcheck_expression_monomial_terms.as_ref()
    else {
        return Ok(None);
    };

    let log2_num_instances = input.log2_num_instances();
    let num_threads = optimal_sumcheck_threads(log2_num_instances);
    let num_var_with_rotation = log2_num_instances + composed_cs.rotation_vars().unwrap_or(0);

    let wit = LayerWitness(
        chain!(&input.witness, &input.fixed, &input.structural_witness)
            .cloned()
            .map(|mle| unsafe { std::mem::transmute(mle) })
            .collect(),
    );

    let (proof, points) = gkr_iop::gkr::layer::gpu::prove_rotation_gpu::<E, PCS>(
        num_threads,
        num_var_with_rotation,
        layer.rotation_cyclic_subgroup_size,
        layer.rotation_cyclic_group_log2,
        &wit,
        &layer.rotation_exprs.1,
        rotation_sumcheck_expression.clone(),
        rt_tower,
        challenges,
        transcript,
    );

    Ok(Some(RotationProverOutput {
        proof,
        left_point: points.left,
        right_point: points.right,
        point: points.origin,
    }))
}

/// Standalone function for prove_main_constraints that doesn't require &self
/// This allows it to be called from parallel threads without Send/Sync bounds on GpuProver
#[allow(clippy::type_complexity)]
#[tracing::instrument(
    skip_all,
    name = "prove_main_constraints_impl",
    fields(profiling_3),
    level = "trace"
)]
pub fn prove_main_constraints_impl<
    E: ExtensionField,
    PCS: PolynomialCommitmentScheme<E> + 'static,
>(
    rt_tower: Vec<E>,
    rotation: Option<RotationProverOutput<E>>,
    ecc_proof: Option<&EccQuarkProof<E>>,
    input: &ProofInput<'_, GpuBackend<E, PCS>>,
    composed_cs: &ComposedConstrainSystem<E>,
    challenges: &[E; 2],
    transcript: &mut impl Transcript<<GpuBackend<E, PCS> as ProverBackend>::E>,
) -> Result<
    (
        Point<E>,
        MainSumcheckEvals<E>,
        Option<Vec<IOPProverMessage<E>>>,
        Option<GKRProof<E>>,
    ),
    ZKVMError,
> {
    let ComposedConstrainSystem {
        zkvm_v1_css: cs,
        gkr_circuit,
    } = composed_cs;

    let num_instances = input.num_instances();
    let log2_num_instances = input.log2_num_instances();
    let num_threads = optimal_sumcheck_threads(log2_num_instances);
    let num_var_with_rotation = log2_num_instances + composed_cs.rotation_vars().unwrap_or(0);

    let Some(gkr_circuit) = gkr_circuit else {
        panic!("empty gkr circuit")
    };
    let estimated_main_constraints_bytes =
        estimate_main_constraints_bytes::<E, PCS>(composed_cs, input);
    if let Ok(cuda_hal) = get_cuda_hal() {
        let mem_pool = cuda_hal.inner.mem_pool();
        let used_bytes = mem_pool.get_used_size().unwrap_or(0);
        let reserved_bytes = mem_pool.get_reserved_size().unwrap_or(0);
        tracing::info!(
            "[gpu] entering prove_main_constraints: estimated={:.2}MB, used={:.2}MB, reserved={:.2}MB, witness={}, fixed={}, structural={}",
            estimated_main_constraints_bytes as f64 / (1024.0 * 1024.0),
            used_bytes as f64 / (1024.0 * 1024.0),
            reserved_bytes as f64 / (1024.0 * 1024.0),
            input.witness.len(),
            input.fixed.len(),
            input.structural_witness.len(),
        );
    }
    let first_layer = gkr_circuit.layers.first().expect("empty gkr circuit layer");
    let group_stage_masks = first_layer_output_group_stage_masks(composed_cs, gkr_circuit);
    let selector_ctxs = first_layer
        .out_sel_and_eval_exprs
        .iter()
        .zip_eq(group_stage_masks.iter())
        .map(|((selector, _), stage_mask)| {
            if !stage_mask.contains(GkrOutputStageMask::TOWER) || cs.ec_final_sum.is_empty() {
                SelectorContext {
                    offset: 0,
                    num_instances,
                    num_vars: num_var_with_rotation,
                }
            } else if cs.r_selector.as_ref() == Some(selector) {
                SelectorContext {
                    offset: 0,
                    num_instances: input.num_instances[0],
                    num_vars: num_var_with_rotation,
                }
            } else if cs.w_selector.as_ref() == Some(selector) {
                SelectorContext {
                    offset: input.num_instances[0],
                    num_instances: input.num_instances[1],
                    num_vars: num_var_with_rotation,
                }
            } else {
                SelectorContext {
                    offset: 0,
                    num_instances,
                    num_vars: num_var_with_rotation,
                }
            }
        })
        .collect_vec();

    let mut out_evals =
        vec![PointAndEval::new(rt_tower.clone(), E::ZERO); gkr_circuit.n_evaluations];

    if let Some(rotation) = rotation.as_ref() {
        let Some([left_group_idx, right_group_idx, point_group_idx]) =
            first_layer.rotation_selector_group_indices()
        else {
            panic!("rotation proof provided for non-rotation layer")
        };
        debug_assert!(group_stage_masks[left_group_idx].contains(GkrOutputStageMask::ROTATION));
        debug_assert!(group_stage_masks[right_group_idx].contains(GkrOutputStageMask::ROTATION));
        debug_assert!(group_stage_masks[point_group_idx].contains(GkrOutputStageMask::ROTATION));

        let (left_evals, right_evals, point_evals) = split_rotation_evals(&rotation.proof.evals);

        assign_group_evals(
            &mut out_evals,
            &first_layer.out_sel_and_eval_exprs[left_group_idx].1,
            &left_evals,
            &rotation.left_point,
        );
        assign_group_evals(
            &mut out_evals,
            &first_layer.out_sel_and_eval_exprs[right_group_idx].1,
            &right_evals,
            &rotation.right_point,
        );
        assign_group_evals(
            &mut out_evals,
            &first_layer.out_sel_and_eval_exprs[point_group_idx].1,
            &point_evals,
            &rotation.point,
        );
    }

    if let Some(ecc_proof) = ecc_proof {
        let Some(
            [
                x_group_idx,
                y_group_idx,
                slope_group_idx,
                x3_group_idx,
                y3_group_idx,
            ],
        ) = first_layer.ecc_bridge_group_indices()
        else {
            panic!("ecc proof provided for non-ecc layer")
        };
        debug_assert!(group_stage_masks[x_group_idx].contains(GkrOutputStageMask::ECC));
        debug_assert!(group_stage_masks[y_group_idx].contains(GkrOutputStageMask::ECC));
        debug_assert!(group_stage_masks[slope_group_idx].contains(GkrOutputStageMask::ECC));
        debug_assert!(group_stage_masks[x3_group_idx].contains(GkrOutputStageMask::ECC));
        debug_assert!(group_stage_masks[y3_group_idx].contains(GkrOutputStageMask::ECC));

        let sample_r = transcript.sample_and_append_vec(b"ecc_gkr_bridge_r", 1)[0];
        let claims = derive_ecc_bridge_claims(ecc_proof, sample_r, num_var_with_rotation)
            .expect("invalid internal ecc bridge claims");

        assign_group_evals(
            &mut out_evals,
            &first_layer.out_sel_and_eval_exprs[x_group_idx].1,
            &claims.x_evals,
            &claims.xy_point,
        );
        assign_group_evals(
            &mut out_evals,
            &first_layer.out_sel_and_eval_exprs[y_group_idx].1,
            &claims.y_evals,
            &claims.xy_point,
        );
        assign_group_evals(
            &mut out_evals,
            &first_layer.out_sel_and_eval_exprs[slope_group_idx].1,
            &claims.s_evals,
            &claims.s_point,
        );
        assign_group_evals(
            &mut out_evals,
            &first_layer.out_sel_and_eval_exprs[x3_group_idx].1,
            &claims.x3_evals,
            &claims.x3y3_point,
        );
        assign_group_evals(
            &mut out_evals,
            &first_layer.out_sel_and_eval_exprs[y3_group_idx].1,
            &claims.y3_evals,
            &claims.x3y3_point,
        );
    }

    let GKRProverOutput {
        gkr_proof,
        opening_evaluations,
        mut rt,
    } = gkr_circuit.prove::<GpuBackend<E, PCS>, GpuProver<_>>(
        num_threads,
        num_var_with_rotation,
        gkr::GKRCircuitWitness {
            layers: vec![LayerWitness(
                chain!(&input.witness, &input.fixed, &input.structural_witness,)
                    .cloned()
                    .map(|mle| unsafe { std::mem::transmute(mle) })
                    .collect(),
            )],
        },
        &out_evals,
        &input
            .pi
            .iter()
            .map(|v| v.map_either(E::from, |v| v).into_inner())
            .collect_vec(),
        challenges,
        transcript,
        &selector_ctxs,
    )?;
    assert_eq!(rt.len(), 1, "TODO support multi-layer gkr iop");
    Ok((
        rt.remove(0),
        MainSumcheckEvals {
            wits_in_evals: opening_evaluations
                .iter()
                .take(cs.num_witin as usize)
                .map(|Evaluation { value, .. }| value)
                .copied()
                .collect_vec(),
            fixed_in_evals: opening_evaluations
                .iter()
                .skip(cs.num_witin as usize)
                .take(cs.num_fixed)
                .map(|Evaluation { value, .. }| value)
                .copied()
                .collect_vec(),
        },
        None,
        Some(gkr_proof),
    ))
}

/// Standalone function for prove_ec_sum_quark that doesn't require &self
/// This allows it to be called from parallel threads without Send/Sync bounds on GpuProver
#[tracing::instrument(
    skip_all,
    name = "prove_ec_sum_quark_impl",
    fields(profiling_3),
    level = "trace"
)]
pub fn prove_ec_sum_quark_impl<'a, E: ExtensionField, PCS: PolynomialCommitmentScheme<E>>(
    composed_cs: &ComposedConstrainSystem<E>,
    input: &ProofInput<'a, GpuBackend<E, PCS>>,
    transcript: &mut impl Transcript<E>,
) -> Result<Option<EccQuarkProof<E>>, ZKVMError> {
    let Some(ecc_inputs) =
        extract_ecc_quark_witness_inputs::<GpuBackend<E, PCS>>(composed_cs, input)
    else {
        return Ok(None);
    };
    let xs = ecc_inputs.xs;
    let ys = ecc_inputs.ys;
    let invs = ecc_inputs.slopes;

    let num_instances = input.num_instances();
    let stream = gkr_iop::gpu::get_thread_stream();
    assert_eq!(xs.len(), SEPTIC_EXTENSION_DEGREE);
    assert_eq!(ys.len(), SEPTIC_EXTENSION_DEGREE);

    let n = xs[0].mle.num_vars() - 1;
    tracing::debug!(
        "Creating EC Summation Quark proof with {} points in {n} variables",
        num_instances
    );

    let out_rt = transcript.sample_and_append_vec(b"ecc", n);

    // expression with add (3 zero constraints), bypass (2 zero constraints), export (2 zero constraints)
    let alpha_pows = transcript.sample_and_append_challenge_pows(
        SEPTIC_EXTENSION_DEGREE * 3 + SEPTIC_EXTENSION_DEGREE * 2 + SEPTIC_EXTENSION_DEGREE * 2,
        b"ecc_alpha",
    );
    let mut alpha_pows_iter = alpha_pows.iter();

    let sel_add = SelectorType::QuarkBinaryTreeLessThan(0.into());
    let sel_add_ctx = SelectorContext {
        offset: 0,
        num_instances,
        num_vars: n,
    };
    let sel_add_mle: MultilinearExtension<'_, E> = sel_add.compute(&out_rt, &sel_add_ctx).unwrap();

    // the final sum is located at [1,...,1,0] (in big-endian)
    let last_evaluation_index = (1 << n) - 2;
    let lsi_on_hypercube = once(E::ZERO).chain(repeat_n(E::ONE, n - 1)).collect_vec();
    let mut sel_export = (0..(1 << n))
        .into_par_iter()
        .map(|_| E::ZERO)
        .collect::<Vec<_>>();
    sel_export[last_evaluation_index] = eq_eval(&out_rt, lsi_on_hypercube.as_slice());
    let sel_export_mle = sel_export.into_mle();

    // we construct sel_bypass witness here
    // verifier can derive it via `sel_bypass = eq - sel_add - sel_last_onehot`
    let mut sel_bypass_mle: Vec<E> = build_eq_x_r_vec(&out_rt); // CPU
    match sel_add_mle.evaluations() {
        FieldType::Ext(sel_add_mle) => sel_add_mle
            .par_iter()
            .zip(sel_bypass_mle.par_iter_mut())
            .for_each(|(sel_add, sel_bypass)| {
                if *sel_add != E::ZERO {
                    *sel_bypass = E::ZERO;
                }
            }),
        _ => unreachable!(),
    }
    *sel_bypass_mle.last_mut().unwrap() = E::ZERO;
    let sel_bypass_mle = sel_bypass_mle.into_mle();

    let cuda_hal = get_cuda_hal().map_err(hal_to_backend_error)?;
    let sel_add_gpu = mle_host_to_gpu(&cuda_hal, &sel_add_mle);
    let sel_bypass_gpu = mle_host_to_gpu(&cuda_hal, &sel_bypass_mle);
    let sel_export_gpu = mle_host_to_gpu(&cuda_hal, &sel_export_mle);
    let split_batches = mle_filter_even_odd_batch::<E>(
        &cuda_hal,
        &[(&xs, false), (&xs, true), (&ys, false), (&ys, true)],
    )?;
    let mut split_iter = split_batches.into_iter();
    let x0_gpu = split_iter.next().unwrap_or_default();
    let x1_gpu = split_iter.next().unwrap_or_default();
    let y0_gpu = split_iter.next().unwrap_or_default();
    let y1_gpu = split_iter.next().unwrap_or_default();

    // build x[1,b], y[1,b], s[1,b]
    let x3_gpu = batch_mles_take_half::<E>(&xs, 1)?;
    let y3_gpu = batch_mles_take_half::<E>(&ys, 1)?;
    let s_gpu = batch_mles_take_half::<E>(&invs, 1)?;

    let mut registry: WitnessRegistry<'a, E> = WitnessRegistry::default();
    let sel_add_expr = registry.register(sel_add_gpu);
    let sel_bypass_expr = registry.register(sel_bypass_gpu);
    let sel_export_expr = registry.register(sel_export_gpu);

    let s = symbolic_from_mle(&mut registry, &s_gpu);
    let x0 = symbolic_from_mle(&mut registry, &x0_gpu);
    let y0 = symbolic_from_mle(&mut registry, &y0_gpu);
    let x1 = symbolic_from_mle(&mut registry, &x1_gpu);
    let y1 = symbolic_from_mle(&mut registry, &y1_gpu);
    let x3 = symbolic_from_mle(&mut registry, &x3_gpu);
    let y3 = symbolic_from_mle(&mut registry, &y3_gpu);

    let mut exprs_add = vec![];
    let mut exprs_bypass = vec![];
    // affine addition
    // zerocheck: 0 = s[1,b] * (x[b,0] - x[b,1]) - (y[b,0] - y[b,1]) with b != (1,...,1)
    exprs_add.extend(
        (s.clone() * (&x0 - &x1) - (&y0 - &y1))
            .to_exprs()
            .into_iter()
            .zip_eq(alpha_pows_iter.by_ref().take(SEPTIC_EXTENSION_DEGREE))
            .map(|(e, alpha)| e * Expression::Constant(Either::Right(*alpha))),
    );

    // zerocheck: 0 = s[1,b]^2 - x[b,0] - x[b,1] - x[1,b] with b != (1,...,1)
    exprs_add.extend(
        ((&s * &s) - &x0 - &x1 - &x3)
            .to_exprs()
            .into_iter()
            .zip_eq(alpha_pows_iter.by_ref().take(SEPTIC_EXTENSION_DEGREE))
            .map(|(e, alpha)| e * Expression::Constant(Either::Right(*alpha))),
    );
    // zerocheck: 0 = s[1,b] * (x[b,0] - x[1,b]) - (y[b,0] + y[1,b]) with b != (1,...,1)
    exprs_add.extend(
        (s.clone() * (&x0 - &x3) - (&y0 + &y3))
            .to_exprs()
            .into_iter()
            .zip_eq(alpha_pows_iter.by_ref().take(SEPTIC_EXTENSION_DEGREE))
            .map(|(e, alpha)| e * Expression::Constant(Either::Right(*alpha))),
    );

    let exprs_add = exprs_add.into_iter().sum::<Expression<E>>() * sel_add_expr;

    // deal with bypass
    // 0 = (x[1,b] - x[b,0])
    exprs_bypass.extend(
        (&x3 - &x0)
            .to_exprs()
            .into_iter()
            .zip_eq(alpha_pows_iter.by_ref().take(SEPTIC_EXTENSION_DEGREE))
            .map(|(e, alpha)| e * Expression::Constant(Either::Right(*alpha))),
    );
    // 0 = (y[1,b] - y[b,0])
    exprs_bypass.extend(
        (&y3 - &y0)
            .to_exprs()
            .into_iter()
            .zip_eq(alpha_pows_iter.by_ref().take(SEPTIC_EXTENSION_DEGREE))
            .map(|(e, alpha)| e * Expression::Constant(Either::Right(*alpha))),
    );

    // export x[1,...,1,0], y[1,...,1,0] for final result (using big-endian notation)
    let xp_gpu = batch_mles_take_half::<E>(&xs, 1)?;
    let yp_gpu = batch_mles_take_half::<E>(&ys, 1)?;
    let final_sum_x = read_septic_value_from_gpu(&xp_gpu, last_evaluation_index)?;
    let final_sum_y = read_septic_value_from_gpu(&yp_gpu, last_evaluation_index)?;
    // 0 = sel_export * (x[1,b] - final_sum.x)
    // 0 = sel_export * (y[1,b] - final_sum.y)
    let export_expr =
        x3.0.iter()
            .zip_eq(final_sum_x.0.iter())
            .chain(y3.0.iter().zip_eq(final_sum_y.0.iter()))
            .map(|(x, final_x)| x - final_x.expr())
            .zip_eq(alpha_pows_iter.by_ref().take(SEPTIC_EXTENSION_DEGREE * 2))
            .map(|(e, alpha)| e * Expression::Constant(Either::Right(*alpha)))
            .sum::<Expression<E>>()
            * sel_export_expr;

    let exprs_bypass = exprs_bypass.into_iter().sum::<Expression<E>>() * sel_bypass_expr;

    let zero_expr = exprs_add + exprs_bypass + export_expr;

    let monomial_terms = zero_expr.get_monomial_terms();
    let gpu_refs = registry.gpu_refs();
    let (term_coefficients, mle_indices_per_term, mle_size_info) =
        extract_mle_relationships_from_monomial_terms(&monomial_terms, &gpu_refs, &[], &[]);
    let max_degree = mle_indices_per_term
        .iter()
        .map(|indices| indices.len())
        .max()
        .unwrap_or(0);
    let term_coefficients_gl64: Vec<BB31Ext> =
        unsafe { std::mem::transmute(term_coefficients.clone()) };
    let gpu_refs_gl64: Vec<&MultilinearExtensionGpu<BB31Ext>> =
        unsafe { std::mem::transmute(gpu_refs) };
    let gpu_field_refs = gpu_refs_gl64.iter().map(|mle| &mle.mle).collect_vec();

    let basic_transcript = expect_basic_transcript(transcript);
    let (proof_gpu, evals_gpu, challenges_gpu) = cuda_hal
        .prove_generic_sumcheck_gpu(
            gpu_field_refs,
            &mle_size_info,
            &term_coefficients_gl64,
            &mle_indices_per_term,
            n,
            max_degree,
            None,
            basic_transcript,
            stream.as_ref(),
        )
        .map_err(|e| hal_to_backend_error(format!("GPU sumcheck failed: {e:?}")))?;

    drop(cuda_hal);

    let proof_gpu_e: IOPProof<E> = unsafe { std::mem::transmute(proof_gpu) };
    let evals_gpu_e: Vec<Vec<E>> = unsafe { std::mem::transmute(evals_gpu) };
    let mut evals = Vec::new();
    for chunk in evals_gpu_e {
        evals.extend(chunk);
    }
    let rt: Point<E> = unsafe {
        std::mem::transmute::<Vec<BB31Ext>, Vec<E>>(
            challenges_gpu.iter().map(|c| c.elements).collect(),
        )
    };

    // 3 for sel_add, sel_bypass, sel_export
    // 7 for x[rt,0], x[rt,1], y[rt,0], y[rt,1], x[1,rt], y[1,rt], s[1,rt]
    assert_eq!(evals.len(), 3 + SEPTIC_EXTENSION_DEGREE * 7);
    let final_sum = SepticPoint::from_affine(final_sum_x.clone(), final_sum_y.clone());

    Ok(Some(EccQuarkProof {
        zerocheck_proof: proof_gpu_e,
        num_instances,
        evals,
        rt,
        sum: final_sum,
    }))
}

pub(crate) fn normalize_traces_to_device_col_major<E: ExtensionField>(
    cuda_hal: &Arc<CudaHalBB31>,
    vec_traces: &mut [witness::RowMajorMatrix<E::BaseField>],
    compact_prefix_rows: bool,
) {
    let mut already_col_major = 0usize;
    let mut cpu_upload_and_transpose = 0usize;
    let device_retranspose_todo = 0usize;

    for (idx, trace) in vec_traces.iter_mut().enumerate() {
        if trace.has_device_backing() {
            if trace.device_backing_layout() != Some(DeviceMatrixLayout::ColMajor) {
                panic!("TODO: GPU trace at index {idx} is device-backed but not col-major");
            }
            already_col_major += 1;
            continue;
        }

        let rows = if compact_prefix_rows {
            trace.occupied_physical_rows()
        } else {
            trace.height()
        };
        let cols = trace.width();
        if rows == 0 || cols == 0 {
            continue;
        }
        let host_vals_bb31: &[BB31Base] =
            unsafe { std::mem::transmute(&trace.values()[..rows * cols]) };

        let row_major_buf = cuda_hal
            .alloc_elems_from_host(host_vals_bb31, None)
            .unwrap_or_else(|e| panic!("failed to upload cpu trace {idx} to gpu: {e}"));
        let mut col_major_buf = cuda_hal
            .alloc_elems_on_device(rows * cols, false, None)
            .unwrap_or_else(|e| panic!("failed to alloc col-major buffer for trace {idx}: {e}"));
        matrix_transpose::<CudaHalBB31, ff_ext::BabyBearExt4, _>(
            &cuda_hal.inner,
            &mut col_major_buf,
            &row_major_buf,
            cols,
            rows,
        )
        .unwrap_or_else(|e| panic!("failed to transpose trace {idx} to col-major: {e}"));

        trace.set_device_backing(col_major_buf, DeviceMatrixLayout::ColMajor);
        cpu_upload_and_transpose += 1;
    }

    tracing::debug!(
        total_traces = vec_traces.len(),
        already_col_major,
        cpu_upload_and_transpose,
        device_retranspose_todo,
        "normalized gpu trace backing to device col-major"
    );
}

fn jagged_batch_commit_from_host(
    cuda_hal: &Arc<CudaHalBB31>,
    traces: &[witness::RowMajorMatrix<BB31Base>],
    reshape_log_height: usize,
    prefer_device_backing: bool,
) -> (GpuJaggedHostPreprocessed, GpuBasefoldPcsData) {
    let total_start = Instant::now();
    let device_ready_traces = traces
        .iter()
        .filter(|trace| trace.device_backing_layout() == Some(DeviceMatrixLayout::ColMajor))
        .count();
    let device_backed_traces = traces
        .iter()
        .filter(|trace| trace.has_device_backing())
        .count();
    tracing::info!(
        "[gpu-jagged-profile] branch_select prefer_device_backing={} cache_level={:?} device_backed_traces={}/{} col_major_device_traces={}/{}",
        prefer_device_backing,
        get_gpu_cache_level(),
        device_backed_traces,
        traces.len(),
        device_ready_traces,
        traces.len()
    );
    if device_ready_traces != 0 && device_ready_traces != traces.len() {
        let missing_device_traces = traces
            .iter()
            .enumerate()
            .filter(|(_, trace)| trace.device_backing_layout() != Some(DeviceMatrixLayout::ColMajor))
            .map(|(idx, trace)| {
                format!(
                    "#{idx}:{}x{}:phys{}:backing={}:layout={:?}",
                    trace.height(),
                    trace.width(),
                    trace.occupied_physical_rows(),
                    trace.has_device_backing(),
                    trace.device_backing_layout()
                )
            })
            .join(", ");
        tracing::info!(
            "[gpu-jagged-profile] missing_device_col_major_traces {}",
            missing_device_traces
        );
    }
    if prefer_device_backing
        && !matches!(get_gpu_cache_level(), CacheLevel::None)
        && traces
            .iter()
            .all(|trace| trace.device_backing_layout() == Some(DeviceMatrixLayout::ColMajor))
    {
        let device_branch_start = Instant::now();
        let group_width = mpcs::JAGGED_RESHAPE_GROUP_WIDTH;
        let (preprocessed, mut inner) = batch_commit_gpu_grouped(
            cuda_hal.as_ref(),
            traces,
            reshape_log_height,
            group_width,
            |reshape_rmms| {
                cuda_hal
                    .basefold
                    .batch_commit_cache_none(cuda_hal.as_ref(), reshape_rmms)
            },
        )
        .expect("failed to commit Jagged q' with GPU q' construction");
        tracing::info!(
            "[gpu-jagged-profile] device_q batch_commit_gpu_grouped_return total_evals={} elapsed_ms={:.3}",
            preprocessed.total_evaluations,
            device_branch_start.elapsed().as_secs_f64() * 1000.0
        );
        let finish_storage_start = Instant::now();
        let q_host_evals = if matches!(get_gpu_cache_level(), CacheLevel::None) {
            preprocessed
                .q_evals
                .to_vec()
                .expect("Jagged q' D2H copy failed after GPU commit")
        } else {
            Vec::new()
        };
        if matches!(get_gpu_cache_level(), CacheLevel::None) {
            if let Some(rmms) = inner.rmms.as_mut() {
                for rmm in rmms {
                    rmm.clear_device_backing();
                }
            }
        }
        tracing::info!(
            "[gpu-jagged-profile] device_q post_commit_storage elapsed_ms={:.3}",
            finish_storage_start.elapsed().as_secs_f64() * 1000.0
        );
        tracing::info!(
            "[gpu-jagged-profile] device_q jagged_batch_commit_from_host total elapsed_ms={:.3}",
            total_start.elapsed().as_secs_f64() * 1000.0
        );
        return (
            GpuJaggedHostPreprocessed {
                q_host_evals,
                q_device_evals: Some(preprocessed.q_evals),
                cumulative_heights: preprocessed.cumulative_heights,
                poly_heights: preprocessed.poly_heights,
                total_evaluations: preprocessed.total_evaluations,
                reshape_log_height: preprocessed.reshape_log_height,
            },
            inner,
        );
    }

    let metadata_start = Instant::now();
    let mut poly_heights = Vec::new();
    for trace in traces {
        let physical_rows = jagged_trace_physical_rows(trace);
        assert!(
            physical_rows <= trace.height(),
            "Jagged trace physical rows exceed logical height"
        );
        for _ in 0..trace.width() {
            poly_heights.push(physical_rows);
        }
    }
    let cumulative_heights = std::iter::once(0)
        .chain(poly_heights.iter().scan(0usize, |acc, &height| {
            *acc += height;
            Some(*acc)
        }))
        .collect_vec();
    let total_evaluations = *cumulative_heights.last().unwrap_or(&0);
    let log_h = reshape_log_height.min(ceil_log2(total_evaluations.max(1)));
    let h = 1usize << log_h;
    let w = total_evaluations.div_ceil(h);
    let padded_total = w * h;
    let q_len = padded_total.max(1);
    tracing::info!(
        "[gpu-jagged-profile] host_q metadata traces={} segments={} total_evals={} padded_evals={} h={} w={} elapsed_ms={:.3}",
        traces.len(),
        poly_heights.len(),
        total_evaluations,
        padded_total,
        h,
        w,
        metadata_start.elapsed().as_secs_f64() * 1000.0
    );

    // q' is large, and `vec![ZERO; q_len]` serializes a full-buffer zero fill
    // before the actual witness copy overwrites most entries. Allocate
    // uninitialized storage instead; the loops below initialize every real
    // q' element, and the final parallel pass initializes all padding. If a
    // panic happens mid-construction, proving aborts and the `MaybeUninit`
    // buffer will not drop uninitialized field elements.
    let mut q_host_uninit = Vec::<MaybeUninit<BB31Base>>::with_capacity(q_len);
    unsafe {
        q_host_uninit.set_len(q_len);
    }
    let host_build_start = Instant::now();
    let mut poly_idx = 0usize;
    for trace in traces {
        let physical_rows = jagged_trace_physical_rows(trace);
        let cols = trace.width();
        let start = cumulative_heights[poly_idx];
        if physical_rows == 0 {
            poly_idx += cols;
            continue;
        }
        if prefer_device_backing
            && trace.device_backing_layout() == Some(DeviceMatrixLayout::ColMajor)
        {
            let device_buffer = trace
                .device_backing_ref::<BufferImpl<'static, BB31Base>>()
                .unwrap_or_else(|| panic!("Jagged trace col-major device backing type mismatch"));
            let backing_rows = rmm_col_major_device_rows(trace)
                .unwrap_or_else(|| panic!("Jagged trace col-major device row count mismatch"));
            assert!(
                physical_rows <= trace.height(),
                "Jagged trace col-major device rows exceed logical height"
            );
            let device_values = device_buffer
                .to_vec()
                .expect("Jagged trace device backing D2H failed");
            q_host_uninit[start..start + physical_rows * cols]
                .par_chunks_mut(physical_rows)
                .enumerate()
                .for_each(|(col_idx, out)| {
                    let src_start = col_idx * backing_rows;
                    let src_end = src_start + physical_rows;
                    for (dst, src) in out[..physical_rows]
                        .iter_mut()
                        .zip(&device_values[src_start..src_end])
                    {
                        dst.write(*src);
                    }
                });
        } else {
            let values = trace.values();
            q_host_uninit[start..start + physical_rows * cols]
                .par_chunks_mut(physical_rows)
                .enumerate()
                .for_each(|(col_idx, out)| {
                    for row_idx in 0..physical_rows {
                        out[row_idx].write(values[row_idx * cols + col_idx]);
                    }
                });
        }
        poly_idx += cols;
    }
    q_host_uninit[total_evaluations..]
        .par_iter_mut()
        .for_each(|dst| {
            dst.write(BB31Base::ZERO);
        });
    let q_host = unsafe {
        let ptr = q_host_uninit.as_mut_ptr() as *mut BB31Base;
        let len = q_host_uninit.len();
        let cap = q_host_uninit.capacity();
        std::mem::forget(q_host_uninit);
        Vec::from_raw_parts(ptr, len, cap)
    };
    tracing::info!(
        "[gpu-jagged-profile] host_q build_cpu_q elapsed_ms={:.3}",
        host_build_start.elapsed().as_secs_f64() * 1000.0
    );

    let h2d_start = Instant::now();
    let q_device = if matches!(get_gpu_cache_level(), CacheLevel::None) {
        None
    } else {
        Some(
            cuda_hal
                .alloc_elems_from_host(&q_host, None)
                .expect("failed to upload Jagged q' evaluations for commit"),
        )
    };
    tracing::info!(
        "[gpu-jagged-profile] host_q upload_q h2d_bytes={} elapsed_ms={:.3}",
        q_host.len() * std::mem::size_of::<BB31Base>(),
        h2d_start.elapsed().as_secs_f64() * 1000.0
    );
    let group_width = mpcs::JAGGED_RESHAPE_GROUP_WIDTH;
    let specs_start = Instant::now();
    let specs = (0..w)
        .step_by(group_width)
        .map(|_| ceno_gpu::common::poseidon2::DeferredRmmSpec {
            height: h,
            persist_actual: false,
        })
        .collect_vec();
    tracing::info!(
        "[gpu-jagged-profile] host_q build_specs groups={} elapsed_ms={:.3}",
        specs.len(),
        specs_start.elapsed().as_secs_f64() * 1000.0
    );
    let inner_commit_start = Instant::now();
    let mut inner = cuda_hal
        .basefold
        .batch_commit_cache_none_deferred(cuda_hal.as_ref(), specs, |trace_idx| {
            let group_start_col = trace_idx * group_width;
            let group_cols = (w - group_start_col).min(group_width);
            let commit_view = if let Some(q_device) = &q_device {
                let start = group_start_col * h * std::mem::size_of::<BB31Base>();
                let end = start + group_cols * h * std::mem::size_of::<BB31Base>();
                q_device.owned_subrange(start..end)
            } else {
                let start = group_start_col * h;
                let end = start + group_cols * h;
                cuda_hal.alloc_elems_from_host(&q_host[start..end], None)?
            };
            Ok(witness::RowMajorMatrix::new_by_device_backing(
                h,
                group_cols,
                InstancePaddingStrategy::Default,
                commit_view,
                DeviceMatrixLayout::ColMajor,
            ))
        })
        .expect("failed to commit Jagged q' with deferred GPU Basefold");
    tracing::info!(
        "[gpu-jagged-profile] host_q inner_commit elapsed_ms={:.3}",
        inner_commit_start.elapsed().as_secs_f64() * 1000.0
    );
    if q_device.is_none() {
        if let Some(rmms) = inner.rmms.as_mut() {
            for rmm in rmms {
                rmm.clear_device_backing();
            }
        }
    }
    tracing::info!(
        "[gpu-jagged-profile] host_q jagged_batch_commit_from_host total elapsed_ms={:.3}",
        total_start.elapsed().as_secs_f64() * 1000.0
    );

    (
        GpuJaggedHostPreprocessed {
            q_host_evals: q_host,
            q_device_evals: q_device,
            cumulative_heights,
            poly_heights,
            total_evaluations,
            reshape_log_height: log_h,
        },
        inner,
    )
}

fn jagged_q_storage(
    cuda_hal: &Arc<CudaHalBB31>,
    q_host_evals: Vec<BB31Base>,
    q_device_evals: Option<BufferImpl<'static, BB31Base>>,
) -> (Option<BufferImpl<'static, BB31Base>>, Option<Vec<BB31Base>>) {
    match get_gpu_cache_level() {
        CacheLevel::None => (None, Some(q_host_evals)),
        CacheLevel::Trace | CacheLevel::Full => {
            let q_evals = q_device_evals.unwrap_or_else(|| {
                cuda_hal
                    .alloc_elems_from_host(&q_host_evals, None)
                    .expect("failed to upload Jagged q' evaluations")
            });
            cuda_hal
                .inner
                .synchronize()
                .expect("failed to synchronize Jagged q' upload");
            (Some(q_evals), None)
        }
    }
}

fn finish_jagged_commit<E, PCS>(
    cuda_hal: &Arc<CudaHalBB31>,
    preprocessed: GpuJaggedHostPreprocessed,
    inner: GpuBasefoldPcsData,
    trace_layouts: Vec<GpuJaggedTraceLayout>,
) -> (GpuPcsData, PCS::Commitment)
where
    E: ExtensionField,
    PCS: PolynomialCommitmentScheme<E> + 'static,
{
    let inner_commit = cuda_hal.basefold.get_pure_commitment(&inner);
    let commit = wrap_jagged_commitment_as_pcs::<E, PCS>(
        inner_commit,
        preprocessed.cumulative_heights.clone(),
        preprocessed.reshape_log_height,
    );
    let (q_evals, q_host_evals) = jagged_q_storage(
        cuda_hal,
        preprocessed.q_host_evals,
        preprocessed.q_device_evals,
    );
    (
        GpuPcsData::Jagged(GpuJaggedPcsData {
            inner,
            q_evals,
            q_host_evals,
            cumulative_heights: preprocessed.cumulative_heights,
            poly_heights: preprocessed.poly_heights,
            total_evaluations: preprocessed.total_evaluations,
            reshape_log_height: preprocessed.reshape_log_height,
            trace_layouts,
        }),
        commit,
    )
}

pub fn commit_gpu_witness_traces_cache_none<E, PCS>(
    prover: &GpuProver<GpuBackend<E, PCS>>,
    traces: BTreeMap<usize, witness::RowMajorMatrix<E::BaseField>>,
) -> (
    Vec<MultilinearExtensionGpu<'static, E>>,
    <GpuBackend<E, PCS> as ProverBackend>::PcsData,
    PCS::Commitment,
)
where
    E: ExtensionField,
    PCS: PolynomialCommitmentScheme<E> + 'static,
{
    if std::any::TypeId::of::<E::BaseField>() != std::any::TypeId::of::<BB31Base>() {
        panic!("GPU backend only supports BabyBear base field");
    }
    crate::instructions::gpu::cache::assert_caches_released_before_prove();

    let ordered_traces = traces.into_values().collect_vec();
    let max_poly_size_log2 = ordered_traces
        .iter()
        .map(|rmm| ceil_log2(rmm.height()))
        .max()
        .unwrap();
    if max_poly_size_log2 > prover.backend.max_poly_size_log2 {
        panic!(
            "max_poly_size_log2 {} > max_poly_size_log2 backend {}",
            max_poly_size_log2, prover.backend.max_poly_size_log2
        );
    }

    let is_basefold_pcs = std::mem::size_of::<mpcs::BasefoldCommitmentWithWitness<BB31Ext>>()
        == std::mem::size_of::<PCS::CommitmentWithWitness>();
    let is_jagged_pcs = is_babybear_jagged_pcs::<E, PCS>();
    if !is_basefold_pcs && !is_jagged_pcs {
        panic!("GPU commitment data is not compatible with the PCS");
    }

    let cuda_hal = get_cuda_hal().unwrap();
    cuda_hal
        .inner
        .synchronize()
        .expect("cuda synchronize before gpu batch_commit mem snapshot");
    let mem_pool = cuda_hal.inner.mem_pool();
    let used_bytes = mem_pool
        .get_used_size()
        .expect("cudaMemPoolGetAttribute UsedMemCurrent before gpu batch_commit");
    let reserved_bytes = mem_pool.get_reserved_size().unwrap_or(0);
    tracing::info!(
        "[gpu] entering gpu batch_commit: traces={}, used={:.2}MB, reserved={:.2}MB",
        ordered_traces.len(),
        used_bytes as f64 / (1024.0 * 1024.0),
        reserved_bytes as f64 / (1024.0 * 1024.0),
    );

    if is_jagged_pcs {
        let mut vec_traces = ordered_traces
            .into_iter()
            .enumerate()
            .map(|(trace_idx, witness_rmm)| {
                if witness_rmm.width() == 0 {
                    tracing::warn!(
                        "[gpu] replacing zero-width gpu witness trace at index {trace_idx} with a dummy column"
                    );
                    witness::RowMajorMatrix::<E::BaseField>::new(
                        witness_rmm.num_instances(),
                        1,
                        InstancePaddingStrategy::Default,
                    )
                } else {
                    witness_rmm
                }
            })
            .collect_vec();
        let trace_layouts = jagged_trace_layouts(&vec_traces);
        let normalize_start = Instant::now();
        normalize_traces_to_device_col_major::<E>(&cuda_hal, &mut vec_traces, true);
        tracing::info!(
            "[gpu-jagged-profile] eager_jagged_normalize_missing_traces elapsed_ms={:.3}",
            normalize_start.elapsed().as_secs_f64() * 1000.0
        );
        for (idx, trace) in vec_traces.iter().enumerate() {
            assert!(
                trace.has_device_backing(),
                "GPU jagged commit requires device-backed witness trace at index {idx}"
            );
            assert_eq!(
                trace.device_backing_layout(),
                Some(DeviceMatrixLayout::ColMajor),
                "GPU jagged commit requires col-major device-backed witness trace at index {idx}"
            );
        }
        let mut traces_bb31: Vec<witness::RowMajorMatrix<BB31Base>> =
            unsafe { std::mem::transmute(vec_traces) };
        let total_size: usize = traces_bb31
            .iter()
            .map(|trace| jagged_trace_physical_rows(trace) * trace.width())
            .sum();
        let reshape_log_height = prover
            .backend
            .pp
            .get_max_message_size_log()
            .min(crate::instructions::gpu::config::jagged_reshape_log_height_cap())
            .min(ceil_log2(total_size.max(1)));
        let (preprocessed, inner_pcs_data) =
            jagged_batch_commit_from_host(&cuda_hal, &traces_bb31, reshape_log_height, true);
        for trace in &mut traces_bb31 {
            trace.clear_device_backing();
        }
        let (pcs_data, commit) =
            finish_jagged_commit::<E, PCS>(&cuda_hal, preprocessed, inner_pcs_data, trace_layouts);
        return (vec![], pcs_data, commit);
    }

    let specs = ordered_traces
        .iter()
        .map(|rmm| ceno_gpu::common::poseidon2::DeferredRmmSpec {
            height: rmm.height(),
            persist_actual: true,
        })
        .collect_vec();
    let mut ordered_traces = ordered_traces.into_iter().map(Some).collect_vec();
    let pcs_data = cuda_hal
        .basefold
        .batch_commit_cache_none_deferred(&cuda_hal, specs, |trace_idx| {
            let witness_rmm = ordered_traces[trace_idx]
                .take()
                .expect("gpu commit source reused");
            let witness_rmm = if witness_rmm.width() == 0 {
                tracing::warn!(
                    "[gpu] replacing zero-width gpu witness trace at index {trace_idx} with a dummy column"
                );
                witness::RowMajorMatrix::<E::BaseField>::new(
                    witness_rmm.num_instances(),
                    1,
                    InstancePaddingStrategy::Default,
                )
            } else {
                witness_rmm
            };
            Ok(unsafe { std::mem::transmute(witness_rmm) })
        })
        .unwrap();

    let basefold_commit = cuda_hal.basefold.get_pure_commitment(&pcs_data);
    let commit: PCS::Commitment = unsafe { std::mem::transmute_copy(&basefold_commit) };
    let pcs_data_generic: <GpuBackend<E, PCS> as ProverBackend>::PcsData =
        GpuPcsData::Basefold(pcs_data);
    (vec![], pcs_data_generic, commit)
}

impl<E: ExtensionField, PCS: PolynomialCommitmentScheme<E> + 'static>
    TraceCommitter<GpuBackend<E, PCS>> for GpuProver<GpuBackend<E, PCS>>
{
    fn commit_traces<'a>(
        &self,
        traces: BTreeMap<usize, witness::RowMajorMatrix<E::BaseField>>,
    ) -> (
        Vec<<GpuBackend<E, PCS> as ProverBackend>::MultilinearPoly<'a>>,
        <GpuBackend<E, PCS> as ProverBackend>::PcsData,
        PCS::Commitment,
    ) {
        if std::any::TypeId::of::<E::BaseField>() != std::any::TypeId::of::<BB31Base>() {
            panic!("GPU backend only supports BabyBear base field");
        }

        let span = entered_span!("[gpu] init pp", profiling_2 = true);
        let max_poly_size_log2 = traces
            .values()
            .map(|trace| ceil_log2(next_pow2_instance_padding(trace.num_instances())))
            .max()
            .unwrap();
        if max_poly_size_log2 > self.backend.max_poly_size_log2 {
            panic!(
                "max_poly_size_log2 {} > max_poly_size_log2 backend {}",
                max_poly_size_log2, self.backend.max_poly_size_log2
            )
        }
        exit_span!(span);

        let is_pcs_match = std::mem::size_of::<mpcs::BasefoldCommitmentWithWitness<BB31Ext>>()
            == std::mem::size_of::<PCS::CommitmentWithWitness>();
        let is_jagged_pcs = is_babybear_jagged_pcs::<E, PCS>();
        let (mles, pcs_data, commit) = if is_pcs_match || is_jagged_pcs {
            let mut vec_traces: Vec<witness::RowMajorMatrix<E::BaseField>> =
                traces.into_values().collect();
            for (trace_idx, trace) in vec_traces.iter_mut().enumerate() {
                if trace.width() == 0 {
                    tracing::warn!(
                        "[gpu] replacing zero-width witness trace at index {trace_idx} with a dummy column"
                    );
                    *trace = witness::RowMajorMatrix::<E::BaseField>::new(
                        trace.num_instances(),
                        1,
                        InstancePaddingStrategy::Default,
                    );
                }
            }

            if crate::instructions::gpu::config::should_materialize_witness_on_gpu() {
                let span = entered_span!("[gpu] normalize_trace_backing", profiling_2 = true);
                let cuda_hal = get_cuda_hal().unwrap();
                normalize_traces_to_device_col_major::<E>(
                    &cuda_hal,
                    &mut vec_traces,
                    is_jagged_pcs,
                );
                drop(cuda_hal);
                for (idx, trace) in vec_traces.iter().enumerate() {
                    assert!(
                        trace.has_device_backing(),
                        "GPU mode requires device-backed witness trace at index {idx}"
                    );
                    assert_eq!(
                        trace.device_backing_layout(),
                        Some(DeviceMatrixLayout::ColMajor),
                        "GPU mode requires col-major device-backed witness trace at index {idx}"
                    );
                }
                exit_span!(span);
            }
            let span = entered_span!("[gpu] hal init", profiling_2 = true);
            let cuda_hal = get_cuda_hal().unwrap();
            exit_span!(span);

            let trace_layouts = if is_jagged_pcs {
                Some(jagged_trace_layouts(&vec_traces))
            } else {
                None
            };

            let mut traces_gl64: Vec<witness::RowMajorMatrix<BB31Base>> =
                unsafe { std::mem::transmute(vec_traces) };

            let span = entered_span!("[gpu] batch_commit", profiling_2 = true);
            cuda_hal
                .inner
                .synchronize()
                .expect("cuda synchronize before batch_commit mem snapshot");
            let mem_pool = cuda_hal.inner.mem_pool();
            let used_bytes = mem_pool
                .get_used_size()
                .expect("cudaMemPoolGetAttribute UsedMemCurrent before batch_commit");
            let reserved_bytes = mem_pool.get_reserved_size().unwrap_or(0);
            tracing::info!(
                "[gpu] entering batch_commit: traces={}, used={:.2}MB, reserved={:.2}MB",
                traces_gl64.len(),
                used_bytes as f64 / (1024.0 * 1024.0),
                reserved_bytes as f64 / (1024.0 * 1024.0),
            );
            let pcs_data = if is_jagged_pcs {
                let total_size: usize = traces_gl64
                    .iter()
                    .map(|trace| jagged_trace_physical_rows(trace) * trace.width())
                    .sum();
                let reshape_log_height = self
                    .backend
                    .pp
                    .get_max_message_size_log()
                    .min(crate::instructions::gpu::config::jagged_reshape_log_height_cap())
                    .min(ceil_log2(total_size.max(1)));
                let (preprocessed, inner_pcs_data) = jagged_batch_commit_from_host(
                    &cuda_hal,
                    &traces_gl64,
                    reshape_log_height,
                    true,
                );
                for trace in &mut traces_gl64 {
                    trace.clear_device_backing();
                }
                finish_jagged_commit::<E, PCS>(
                    &cuda_hal,
                    preprocessed,
                    inner_pcs_data,
                    trace_layouts.expect("jagged trace layouts must exist"),
                )
            } else {
                let pcs_data = cuda_hal
                    .basefold
                    .batch_commit(&cuda_hal, traces_gl64)
                    .unwrap();
                let basefold_commit = cuda_hal.basefold.get_pure_commitment(&pcs_data);
                let commit: PCS::Commitment = unsafe { std::mem::transmute_copy(&basefold_commit) };
                (GpuPcsData::Basefold(pcs_data), commit)
            };
            exit_span!(span);

            (vec![], pcs_data.0, pcs_data.1)
        } else {
            panic!("GPU commitment data is not compatible with the PCS");
        };

        // Note: mles are not used by GPU backend
        // `fn extract_witness_mles` uses `hal.basefold.get_trace` to extract mles from pcs_data
        (mles, pcs_data, commit)
    }

    fn extract_witness_mles<'a, 'b>(
        &self,
        _witness_mles: &'b mut Vec<<GpuBackend<E, PCS> as ProverBackend>::MultilinearPoly<'a>>,
        pcs_data: &'b <GpuBackend<E, PCS> as ProverBackend>::PcsData,
    ) -> Box<
        dyn Iterator<Item = Arc<<GpuBackend<E, PCS> as ProverBackend>::MultilinearPoly<'a>>> + 'b,
    > {
        if let GpuPcsData::Jagged(jagged_data) = pcs_data {
            let total_traces = jagged_data.trace_layouts.len();
            let mut trace_idx = 0usize;
            let mut current_iter: std::vec::IntoIter<
                Arc<<GpuBackend<E, PCS> as ProverBackend>::MultilinearPoly<'a>>,
            > = Vec::new().into_iter();

            let iter = std::iter::from_fn(move || {
                loop {
                    if let Some(poly) = current_iter.next() {
                        return Some(poly);
                    }
                    if trace_idx >= total_traces {
                        return None;
                    }
                    current_iter = extract_jagged_witness_mles_for_trace::<E>(
                        jagged_data,
                        trace_idx,
                        None,
                        None,
                    )
                    .into_iter();
                    trace_idx += 1;
                }
            });
            return Box::new(iter);
        }

        let pcs_data_basefold = expect_basefold_pcs_data(pcs_data);
        let total_traces = pcs_data_basefold.num_traces();
        let mut trace_idx = 0usize;
        let mut current_iter: std::vec::IntoIter<
            Arc<<GpuBackend<E, PCS> as ProverBackend>::MultilinearPoly<'a>>,
        > = Vec::new().into_iter();

        let iter = std::iter::from_fn(move || {
            loop {
                if let Some(poly) = current_iter.next() {
                    return Some(poly);
                }

                if trace_idx >= total_traces {
                    return None;
                }

                let cuda_hal = get_cuda_hal().unwrap();
                let gpu_mem_tracker = init_gpu_mem_tracker(&cuda_hal, "extract_witness_mles");

                let poly_group = cuda_hal
                    .basefold
                    .get_trace(&cuda_hal, pcs_data_basefold, trace_idx, None)
                    .unwrap_or_else(|err| panic!("Failed to extract trace {trace_idx}: {err}"));

                // Post-hoc estimation: derive num_witin and num_vars from extracted result
                let num_witin = poly_group.len();
                let num_vars = if num_witin > 0 {
                    poly_group[0].num_vars()
                } else {
                    0
                };
                let occupied_rows = poly_group
                    .first()
                    .map(|poly| poly.evaluations().len())
                    .unwrap_or(0);

                let (resident, temporary) =
                    estimate_trace_extraction_bytes(num_witin, num_vars, occupied_rows);
                check_gpu_mem_estimation(gpu_mem_tracker, resident + temporary);

                trace_idx += 1;
                drop(cuda_hal);

                current_iter = poly_group
                    .into_iter()
                    .map(|poly| Arc::new(MultilinearExtensionGpu::from_ceno_gpu(poly)))
                    .collect::<Vec<_>>()
                    .into_iter();
            }
        });

        Box::new(iter)
    }
}

/// Extract witness MLEs for a single trace from pcs_data by trace index.
/// This is the deferred-extraction counterpart of `extract_witness_mles` — it extracts
/// one circuit's witnesses just-in-time rather than all circuits eagerly.
///
/// `num_vars` is log2(num_instances) + rotation_vars, used for memory estimation validation.
pub fn extract_jagged_witness_mles_for_trace<'a, E>(
    pcs_data: &GpuJaggedPcsData,
    trace_idx: usize,
    expected_num: Option<usize>,
    num_vars: Option<usize>,
) -> Vec<Arc<MultilinearExtensionGpu<'a, E>>>
where
    E: ExtensionField,
{
    assert_eq!(
        std::any::TypeId::of::<E::BaseField>(),
        std::any::TypeId::of::<BB31Base>(),
        "GPU Jagged q' extraction only supports BabyBear base field",
    );

    let layout = pcs_data
        .trace_layouts
        .get(trace_idx)
        .unwrap_or_else(|| panic!("Jagged trace index {trace_idx} out of range"));
    if let Some(expected_num) = expected_num {
        assert_eq!(
            layout.num_polys, expected_num,
            "Jagged trace width mismatch: expected {}, got {}",
            expected_num, layout.num_polys,
        );
    }
    let num_vars = num_vars.unwrap_or(layout.num_vars);
    let elem_size = std::mem::size_of::<BB31Base>();
    let logical_len = 1usize << num_vars;

    (0..layout.num_polys)
        .map(|col_idx| {
            let poly_idx = layout.first_poly_idx + col_idx;
            let start_elem = pcs_data.cumulative_heights[poly_idx];
            let len = pcs_data.poly_heights[poly_idx];
            assert!(
                len <= logical_len,
                "Jagged q' compact MLE length exceeds logical length: trace_idx={trace_idx}, col_idx={col_idx}, len={len}, logical_len={logical_len}"
            );
            let gpu_buffer = if let Some(q_evals) = &pcs_data.q_evals {
                let start = start_elem * elem_size;
                let end = start + len * elem_size;
                q_evals.owned_subrange(start..end)
            } else if let Some(q_host) = pcs_data.q_host_evals.as_ref() {
                let cuda_hal = get_cuda_hal().unwrap();
                cuda_hal
                    .alloc_elems_from_host(&q_host[start_elem..start_elem + len], None)
                    .unwrap_or_else(|err| panic!("Jagged q' compact column H2D failed: {err:?}"))
            } else {
                panic!("Jagged q' is missing both device and host backing");
            };
            let view_poly = GpuPolynomial::new(gpu_buffer, num_vars);
            let poly_static: GpuPolynomial<'static> = unsafe { std::mem::transmute(view_poly) };
            let mle_static = MultilinearExtensionGpu::from_ceno_gpu_base(poly_static);
            Arc::new(unsafe {
                std::mem::transmute::<
                    MultilinearExtensionGpu<'static, E>,
                    MultilinearExtensionGpu<'a, E>,
                >(mle_static)
            })
        })
        .collect()
}

pub fn extract_witness_mles_for_trace<'a, E, PCS>(
    pcs_data: &<GpuBackend<E, PCS> as ProverBackend>::PcsData,
    trace_idx: usize,
    expected_num: usize,
    num_vars: usize,
) -> Vec<Arc<MultilinearExtensionGpu<'a, E>>>
where
    E: ExtensionField,
    PCS: PolynomialCommitmentScheme<E>,
{
    if let GpuPcsData::Jagged(jagged_data) = pcs_data {
        return extract_jagged_witness_mles_for_trace::<E>(
            jagged_data,
            trace_idx,
            Some(expected_num),
            Some(num_vars),
        );
    }

    let pcs_data_basefold = expect_basefold_pcs_data(pcs_data);

    let stream = gkr_iop::gpu::get_thread_stream();
    let cuda_hal = get_cuda_hal().unwrap();
    let gpu_mem_tracker = init_gpu_mem_tracker(&cuda_hal, "extract_witness_mles_for_trace");

    let poly_group = cuda_hal
        .basefold
        .get_trace(&cuda_hal, pcs_data_basefold, trace_idx, stream.as_ref())
        .unwrap_or_else(|err| panic!("Failed to extract trace {trace_idx}: {err}"));

    let occupied_rows = poly_group
        .first()
        .map(|poly| poly.evaluations().len())
        .unwrap_or(0);
    let (resident, temporary) =
        estimate_trace_extraction_bytes(expected_num, num_vars, occupied_rows);
    check_gpu_mem_estimation(gpu_mem_tracker, resident + temporary);

    let mles: Vec<Arc<MultilinearExtensionGpu<'a, E>>> = poly_group
        .into_iter()
        .map(|poly| Arc::new(MultilinearExtensionGpu::from_ceno_gpu(poly)))
        .collect();

    assert_eq!(
        mles.len(),
        expected_num,
        "expected {} witness mles from trace {}, got {}",
        expected_num,
        trace_idx,
        mles.len()
    );

    mles
}

fn shard_ram_compact_physical_rows(col_idx: usize, num_records: usize, full_rows: usize) -> usize {
    // ShardRAM witness columns are laid out as:
    //   0..7   x EC coordinates
    //   7..14  y EC coordinates
    //   14..21 EC addition slopes
    //   21..30 scalar record fields
    //   30..   Poseidon2 trace columns
    //
    // Only the scalar record fields and Poseidon2 trace are prefix-populated
    // on real record rows. EC columns also carry internal tree rows in the
    // upper half, so they must keep the full logical backing.
    if col_idx < 21 { full_rows } else { num_records }
}

pub fn extract_shard_ram_witness_mles_for_trace<'a, E, PCS>(
    pcs_data: &<GpuBackend<E, PCS> as ProverBackend>::PcsData,
    trace_idx: usize,
    expected_num: usize,
    num_vars: usize,
    num_records: usize,
) -> Vec<Arc<MultilinearExtensionGpu<'a, E>>>
where
    E: ExtensionField,
    PCS: PolynomialCommitmentScheme<E>,
{
    if let GpuPcsData::Jagged(jagged_data) = pcs_data {
        return extract_jagged_witness_mles_for_trace::<E>(
            jagged_data,
            trace_idx,
            Some(expected_num),
            Some(num_vars),
        );
    }

    assert_eq!(
        std::any::TypeId::of::<E::BaseField>(),
        std::any::TypeId::of::<BB31Base>(),
        "GPU ShardRAM compact extraction only supports BabyBear base field",
    );

    let pcs_data_basefold = expect_basefold_pcs_data(pcs_data);

    let Some(rmms) = pcs_data_basefold.rmms.as_ref() else {
        return extract_witness_mles_for_trace::<E, PCS>(
            pcs_data,
            trace_idx,
            expected_num,
            num_vars,
        );
    };
    let rmm = &rmms[trace_idx];
    assert_eq!(
        rmm.width(),
        expected_num,
        "ShardRAM trace width mismatch: expected {}, got {}",
        expected_num,
        rmm.width(),
    );

    let cuda_hal = get_cuda_hal().unwrap();
    let full_rows = rmm.height();
    assert_eq!(
        full_rows,
        1usize << num_vars,
        "ShardRAM trace height must match logical num_vars",
    );
    assert!(
        num_records <= full_rows,
        "ShardRAM compact rows exceed full rows: {} > {}",
        num_records,
        full_rows,
    );

    let mles = if rmm.device_backing_layout() == Some(DeviceMatrixLayout::ColMajor) {
        let device_buffer = rmm
            .device_backing_ref::<BufferImpl<'static, BB31Base>>()
            .unwrap_or_else(|| panic!("ShardRAM col-major device backing type mismatch"));
        let elem_size = std::mem::size_of::<BB31Base>();
        let col_stride_bytes = full_rows * elem_size;
        (0..expected_num)
            .map(|col_idx| {
                let physical_rows =
                    shard_ram_compact_physical_rows(col_idx, num_records, full_rows);
                let start = col_idx * col_stride_bytes;
                let end = start + physical_rows * elem_size;
                let view_buf = device_buffer.owned_subrange(start..end);
                let view_poly = GpuPolynomial::new(view_buf, num_vars);
                let poly_static: GpuPolynomial<'static> = unsafe { std::mem::transmute(view_poly) };
                let mle_static = MultilinearExtensionGpu::from_ceno_gpu_base(poly_static);
                Arc::new(unsafe {
                    std::mem::transmute::<
                        MultilinearExtensionGpu<'static, E>,
                        MultilinearExtensionGpu<'a, E>,
                    >(mle_static)
                })
            })
            .collect::<Vec<_>>()
    } else {
        let values = rmm.values();
        (0..expected_num)
            .map(|col_idx| {
                let physical_rows =
                    shard_ram_compact_physical_rows(col_idx, num_records, full_rows);
                let mut column = Vec::with_capacity(physical_rows);
                column.extend((0..physical_rows).map(|row| values[row * expected_num + col_idx]));
                let column_bb31: Vec<BB31Base> = unsafe {
                    let mut column = std::mem::ManuallyDrop::new(column);
                    Vec::from_raw_parts(
                        column.as_mut_ptr() as *mut BB31Base,
                        column.len(),
                        column.capacity(),
                    )
                };
                let gpu_poly = cuda_hal
                    .alloc_elems_from_host(&column_bb31, None)
                    .map(|buffer| GpuPolynomial::new(buffer, num_vars))
                    .unwrap_or_else(|err| panic!("ShardRAM compact H2D failed: {err:?}"));
                let mle_static = MultilinearExtensionGpu::from_ceno_gpu_base(gpu_poly);
                Arc::new(unsafe {
                    std::mem::transmute::<
                        MultilinearExtensionGpu<'static, E>,
                        MultilinearExtensionGpu<'a, E>,
                    >(mle_static)
                })
            })
            .collect::<Vec<_>>()
    };

    mles
}

pub fn extract_witness_mles_for_trace_rmm<'a, E>(
    witness_rmm: witness::RowMajorMatrix<<E as ExtensionField>::BaseField>,
) -> Vec<Arc<MultilinearExtensionGpu<'a, E>>>
where
    E: ExtensionField,
{
    let cuda_hal = get_cuda_hal().unwrap();
    let gpu_mem_tracker = init_gpu_mem_tracker(&cuda_hal, "extract_witness_mles_for_trace_rmm");

    assert_eq!(
        witness_rmm.device_backing_layout(),
        Some(DeviceMatrixLayout::ColMajor),
        "replayed witness RMM must keep col-major device backing",
    );
    assert_eq!(
        std::any::TypeId::of::<E::BaseField>(),
        std::any::TypeId::of::<BB31Base>(),
        "GPU replay only supports BabyBear base field",
    );

    let device_buffer = witness_rmm
        .device_backing_ref::<BufferImpl<'static, BB31Base>>()
        .unwrap_or_else(|| panic!("col-major replay witness device backing type mismatch"));
    let rows = rmm_col_major_device_rows(&witness_rmm)
        .unwrap_or_else(|| panic!("col-major replay witness device backing row count mismatch"));
    let cols = witness_rmm.width();
    let poly_len_bytes = rows * std::mem::size_of::<BB31Base>();

    // This helper only wraps already-materialized col-major device backing in
    // owned subrange handles. The preceding witness replay paid the actual
    // witness-buffer allocation cost; converting those columns into MLE
    // handles does not allocate more VRAM here.
    check_gpu_mem_estimation(gpu_mem_tracker, 0);

    (0..cols)
        .map(|col_idx| {
            let src_byte_offset = col_idx * poly_len_bytes;
            let view_buf =
                device_buffer.owned_subrange(src_byte_offset..src_byte_offset + poly_len_bytes);
            let view_poly = GpuPolynomial::new(view_buf, witness_rmm.num_vars());
            let poly_static: GpuPolynomial<'static> = unsafe { std::mem::transmute(view_poly) };
            let mle_static = MultilinearExtensionGpu::from_ceno_gpu_base(poly_static);
            Arc::new(unsafe {
                std::mem::transmute::<
                    MultilinearExtensionGpu<'static, E>,
                    MultilinearExtensionGpu<'a, E>,
                >(mle_static)
            })
        })
        .collect()
}

/// Transport a CPU-side structural witness RowMajorMatrix to GPU MLEs.
/// Standalone version that doesn't require `&self` on GpuProver, enabling
/// just-in-time GPU upload inside parallel task closures.
///
/// `num_structural_witin` and `num_vars` are used for memory estimation validation.
pub fn transport_structural_witness_to_gpu<'a, E>(
    structural_rmm: &witness::RowMajorMatrix<<E as ExtensionField>::BaseField>,
    num_structural_witin: usize,
    num_vars: usize,
) -> Vec<Arc<MultilinearExtensionGpu<'a, E>>>
where
    E: ExtensionField,
{
    let cuda_hal = get_cuda_hal().unwrap();
    let gpu_mem_tracker = init_gpu_mem_tracker(&cuda_hal, "transport_structural_witness_to_gpu");

    let result = if structural_rmm.device_backing_layout() == Some(DeviceMatrixLayout::ColMajor) {
        assert_eq!(
            std::any::TypeId::of::<E::BaseField>(),
            std::any::TypeId::of::<BB31Base>(),
            "GPU structural fast path only supports BabyBear base field"
        );
        let device_buffer = structural_rmm
            .device_backing_ref::<BufferImpl<'static, BB31Base>>()
            .unwrap_or_else(|| panic!("col-major structural device backing type mismatch"));
        let rows = rmm_col_major_device_rows(structural_rmm)
            .unwrap_or_else(|| panic!("col-major structural device backing row count mismatch"));
        let cols = structural_rmm.width();
        let poly_len_bytes = rows * std::mem::size_of::<BB31Base>();
        let total_bytes = cols * poly_len_bytes;
        assert_eq!(
            device_buffer.len() * std::mem::size_of::<BB31Base>(),
            total_bytes,
            "structural col-major buffer size mismatch"
        );
        let num_vars_in_poly = structural_rmm.num_vars();

        (0..cols)
            .map(|col_idx| {
                let src_byte_offset = col_idx * poly_len_bytes;
                // Structural MLEs also escape this helper; use an owned-range
                // buffer handle rather than a borrowed view into `structural_rmm`.
                let view_buf =
                    device_buffer.owned_subrange(src_byte_offset..src_byte_offset + poly_len_bytes);
                let view_poly = GpuPolynomial::new(view_buf, num_vars_in_poly);
                let view_poly_static: GpuPolynomial<'static> =
                    unsafe { std::mem::transmute(view_poly) };
                let mle_static = MultilinearExtensionGpu::from_ceno_gpu_base(view_poly_static);
                Arc::new(unsafe {
                    std::mem::transmute::<
                        MultilinearExtensionGpu<'static, E>,
                        MultilinearExtensionGpu<'a, E>,
                    >(mle_static)
                })
            })
            .collect()
    } else {
        let structural_mles = structural_rmm.to_mles();
        structural_mles
            .iter()
            .map(|mle| Arc::new(MultilinearExtensionGpu::from_ceno(&cuda_hal, mle)))
            .collect()
    };

    let estimated_bytes =
        if structural_rmm.device_backing_layout() == Some(DeviceMatrixLayout::ColMajor) {
            0
        } else {
            estimate_structural_mle_bytes(num_structural_witin, num_vars)
        };
    check_gpu_mem_estimation(gpu_mem_tracker, estimated_bytes);

    result
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn build_tower_witness_gpu<E: ExtensionField>(
    composed_cs: &ComposedConstrainSystem<E>,
    input: &ProofInput<'_, GpuBackend<E, impl PolynomialCommitmentScheme<E>>>,
    records: &[ArcMultilinearExtensionGpu<'_, E>],
    challenges: &[E; 2],
    cuda_hal: &CudaHalBB31,
) -> Result<
    (
        Vec<ceno_gpu::GpuProverSpec<'static>>,
        Vec<ceno_gpu::GpuProverSpec<'static>>,
    ),
    String,
> {
    let stream = gkr_iop::gpu::get_thread_stream();
    use crate::scheme::constants::{NUM_FANIN, NUM_FANIN_LOGUP};
    use ceno_gpu::bb31::GpuPolynomialExt;
    use p3::field::FieldAlgebra;

    let ComposedConstrainSystem {
        zkvm_v1_css: cs, ..
    } = composed_cs;
    let _num_instances_with_rotation =
        input.num_instances() << composed_cs.rotation_vars().unwrap_or(0);
    let chip_record_alpha: BB31Ext = unsafe { std::mem::transmute_copy(&challenges[0]) };

    // SAFETY: The `records` slice is borrowed for the duration of this function call.
    // The lifetime is erased to 'static only to satisfy GPU API signatures that require
    // 'static bounds. The actual data remains valid because:
    // 1. `records` is an immutable borrow from the caller's scope
    // 2. All derived slices (r_set_wit, w_set_wit, etc.) are consumed within this function
    // 3. No reference with the 'static lifetime escapes this function
    let records = unsafe {
        std::mem::transmute::<
            &[ArcMultilinearExtensionGpu<'_, E>],
            &[ArcMultilinearExtensionGpu<'static, E>],
        >(records)
    };

    // Parse records into different categories (same as build_tower_witness)
    let num_reads = cs.r_expressions.len() + cs.r_table_expressions.len();
    let num_writes = cs.w_expressions.len() + cs.w_table_expressions.len();
    let mut offset = 0;
    let r_set_wit = &records[offset..][..num_reads];
    offset += num_reads;
    let w_set_wit = &records[offset..][..num_writes];
    offset += num_writes;
    let lk_n_wit = &records[offset..][..cs.lk_table_expressions.len()];
    offset += cs.lk_table_expressions.len();
    let lk_d_wit = if !cs.lk_table_expressions.is_empty() {
        &records[offset..][..cs.lk_table_expressions.len()]
    } else {
        &records[offset..][..cs.lk_expressions.len()]
    };

    // prod: split last layer once, then build compact tower layers.
    let prod_last_layers = r_set_wit
        .iter()
        .chain(w_set_wit.iter())
        .map(|wit| match wit.inner() {
            gkr_iop::gpu::GpuFieldType::Ext(poly) => cuda_hal
                .tower
                .masked_mle_view_chunks(&*cuda_hal, poly, NUM_FANIN, BB31Ext::ONE, stream.as_ref())
                .map_err(|e| format!("Failed to split compact prod tower input: {e}")),
            _ => return Err("tower witness expects extension-field record MLEs".to_string()),
        })
        .collect::<Result<Vec<_>, String>>()?;
    if !prod_last_layers.is_empty() {
        let first_layer = &prod_last_layers[0];
        assert_eq!(first_layer.len(), 2, "prod last_layer must have 2 MLEs");
    }

    // logup: split last layer once, then build compact tower layers.
    let lk_numerator_last_layer = lk_n_wit
        .iter()
        .map(|wit| match wit.inner() {
            gkr_iop::gpu::GpuFieldType::Ext(poly) => cuda_hal
                .tower
                .masked_mle_view_chunks(
                    &*cuda_hal,
                    poly,
                    NUM_FANIN_LOGUP,
                    chip_record_alpha,
                    stream.as_ref(),
                )
                .map_err(|e| format!("Failed to split compact logup numerator: {e}")),
            _ => Err("tower witness expects extension-field logup numerator MLEs".to_string()),
        })
        .collect::<Result<Vec<_>, String>>()?;
    let lk_denominator_last_layer = lk_d_wit
        .iter()
        .map(|wit| match wit.inner() {
            gkr_iop::gpu::GpuFieldType::Ext(poly) => cuda_hal
                .tower
                .masked_mle_view_chunks(
                    &*cuda_hal,
                    poly,
                    NUM_FANIN_LOGUP,
                    chip_record_alpha,
                    stream.as_ref(),
                )
                .map_err(|e| format!("Failed to split compact logup denominator: {e}")),
            _ => Err("tower witness expects extension-field logup denominator MLEs".to_string()),
        })
        .collect::<Result<Vec<_>, String>>()?;
    let logup_last_layers = if !lk_numerator_last_layer.is_empty() {
        // Case when we have both numerator and denominator
        // Combine [p1, p2] from numerator and [q1, q2] from denominator
        lk_numerator_last_layer
            .into_iter()
            .zip(lk_denominator_last_layer)
            .map(|(lk_n_chunks, lk_d_chunks)| {
                let mut last_layer = lk_n_chunks;
                last_layer.extend(lk_d_chunks);
                Ok(last_layer)
            })
            .collect::<Result<Vec<_>, String>>()?
    } else if lk_denominator_last_layer.is_empty() {
        vec![]
    } else {
        // Case when numerator is empty: share one scalar compact polynomial.
        // Its tail default is also ONE, so all logical numerator entries read as ONE
        // without materializing per-chunk denominator-sized buffers.
        let nv = lk_denominator_last_layer[0][0].num_vars();
        let ones_poly = GpuPolynomialExt::new_with_scalar_len(
            &cuda_hal.inner,
            nv,
            1,
            BB31Ext::ONE,
            stream.as_ref(),
        )
        .map_err(|e| format!("Failed to create compact shared ones numerator: {e:?}"))?;
        let ones_poly: GpuPolynomialExt<'static> = unsafe { std::mem::transmute(ones_poly) };
        let one_len_bytes = ones_poly.buf.len() * std::mem::size_of::<BB31Ext>();

        lk_denominator_last_layer
            .into_iter()
            .map(|lk_d_chunks| {
                let p1_gpu = GpuPolynomialExt::new_with_tail_default(
                    ones_poly.buf.owned_subrange(0..one_len_bytes),
                    nv,
                    BB31Ext::ONE,
                );
                let p2_gpu = GpuPolynomialExt::new_with_tail_default(
                    ones_poly.buf.owned_subrange(0..one_len_bytes),
                    nv,
                    BB31Ext::ONE,
                );
                let mut last_layer = vec![p1_gpu, p2_gpu];
                last_layer.extend(lk_d_chunks);
                Ok(last_layer)
            })
            .collect::<Result<Vec<_>, String>>()?
    };
    if !logup_last_layers.is_empty() {
        let first_layer = &logup_last_layers[0];
        assert_eq!(first_layer.len(), 4, "logup last_layer must have 4 MLEs");
    }

    // Build product GpuProverSpecs
    let mut prod_gpu_specs = Vec::new();
    if !prod_last_layers.is_empty() {
        let first_layer = &prod_last_layers[0];
        assert_eq!(first_layer.len(), 2, "prod last_layer must have 2 MLEs");
        let num_vars = first_layer[0].num_vars();
        let num_towers = prod_last_layers.len();

        let span_prod = entered_span!(
            "build_prod_tower",
            prod_layers = prod_last_layers.len(),
            profiling_3 = true
        );
        let last_layers_refs: Vec<&[GpuPolynomialExt<'_>]> =
            prod_last_layers.iter().map(|v| v.as_slice()).collect();
        let gpu_specs = {
            cuda_hal.tower.build_prod_tower_from_gpu_polys_batch(
                cuda_hal,
                &last_layers_refs,
                num_vars,
                num_towers,
                stream.as_ref(),
            )
        }
        .map_err(|e| format!("build_prod_tower_from_gpu_polys_batch failed: {:?}", e))?;
        let gpu_specs = unsafe {
            std::mem::transmute::<
                Vec<ceno_gpu::GpuProverSpec<'_>>,
                Vec<ceno_gpu::GpuProverSpec<'static>>,
            >(gpu_specs)
        };
        prod_gpu_specs.extend(gpu_specs);
        exit_span!(span_prod);
    }

    // Build logup GpuProverSpecs
    let mut logup_gpu_specs = Vec::new();
    if !logup_last_layers.is_empty() {
        let first_layer = &logup_last_layers[0];
        assert_eq!(first_layer.len(), 4, "logup last_layer must have 4 MLEs");
        let num_vars = first_layer[0].num_vars();
        let num_towers = logup_last_layers.len();

        let span_logup = entered_span!(
            "build_logup_tower",
            logup_layers = logup_last_layers.len(),
            profiling_3 = true
        );
        let last_layers_refs: Vec<&[GpuPolynomialExt<'_>]> =
            logup_last_layers.iter().map(|v| v.as_slice()).collect();
        let gpu_specs = cuda_hal
            .tower
            .build_logup_tower_from_gpu_polys_batch(
                cuda_hal,
                &last_layers_refs,
                num_vars,
                num_towers,
                stream.as_ref(),
            )
            .map_err(|e| format!("build_logup_tower_from_gpu_polys_batch failed: {:?}", e))?;
        let gpu_specs = unsafe {
            std::mem::transmute::<
                Vec<ceno_gpu::GpuProverSpec<'_>>,
                Vec<ceno_gpu::GpuProverSpec<'static>>,
            >(gpu_specs)
        };
        logup_gpu_specs.extend(gpu_specs);
        exit_span!(span_logup);
    }
    Ok((prod_gpu_specs, logup_gpu_specs))
}

impl<E: ExtensionField, PCS: PolynomialCommitmentScheme<E>> TowerProver<GpuBackend<E, PCS>>
    for GpuProver<GpuBackend<E, PCS>>
{
    #[allow(clippy::type_complexity)]
    #[tracing::instrument(
        skip_all,
        name = "build_tower_witness",
        fields(profiling_3),
        level = "trace"
    )]
    fn build_tower_witness<'a, 'b, 'c>(
        &self,
        _composed_cs: &ComposedConstrainSystem<E>,
        _input: &ProofInput<'a, GpuBackend<E, PCS>>,
        _records: &'c [ArcMultilinearExtensionGpu<'b, E>],
    ) -> (
        Vec<Vec<Vec<E>>>,
        Vec<TowerProverSpec<'c, GpuBackend<E, PCS>>>,
        Vec<TowerProverSpec<'c, GpuBackend<E, PCS>>>,
    )
    where
        'a: 'b,
        'b: 'c,
    {
        panic!("use fn build_tower_witness_gpu instead");
        // (vec![], vec![], vec![])
    }

    #[tracing::instrument(
        skip_all,
        name = "prove_tower_relation",
        fields(profiling_3),
        level = "trace"
    )]
    fn prove_tower_relation<'a, 'b, 'c>(
        &self,
        composed_cs: &ComposedConstrainSystem<E>,
        input: &ProofInput<'a, GpuBackend<E, PCS>>,
        records: &'c [ArcMultilinearExtensionGpu<'b, E>],
        challenges: &[E; 2],
        transcript: &mut impl Transcript<E>,
    ) -> TowerRelationOutput<E>
    where
        'a: 'b,
        'b: 'c,
    {
        let cuda_hal = get_cuda_hal().expect("Failed to get CUDA HAL");
        let gpu_mem_tracker = init_gpu_mem_tracker(&cuda_hal, "prove_tower_relation");

        let res = prove_tower_relation_impl::<E, PCS>(
            composed_cs,
            input,
            records,
            challenges,
            transcript,
            &cuda_hal,
        )
        .expect("prove_tower_relation_impl failed");

        let estimated_bytes = estimate_tower_bytes::<E, PCS>(composed_cs, input);
        check_gpu_tower_prove_mem_estimation_with_context(
            gpu_mem_tracker,
            estimated_bytes,
            composed_cs
                .gkr_circuit
                .as_ref()
                .and_then(|circuit| circuit.layers.first())
                .map(|layer| layer.name.as_str()),
        );

        res
    }
}

impl<E: ExtensionField, PCS: PolynomialCommitmentScheme<E>> MainSumcheckProver<GpuBackend<E, PCS>>
    for GpuProver<GpuBackend<E, PCS>>
{
    #[allow(clippy::type_complexity)]
    #[tracing::instrument(
        skip_all,
        name = "prove_main_constraints",
        fields(profiling_3),
        level = "trace"
    )]
    fn prove_main_constraints<'a, 'b>(
        &self,
        rt_tower: Vec<E>,
        rotation: Option<RotationProverOutput<E>>,
        ecc_proof: Option<&EccQuarkProof<E>>,
        // _records: Vec<ArcMultilinearExtensionGpu<'b, E>>, // not used by GPU after delegation
        input: &'b ProofInput<'a, GpuBackend<E, PCS>>,
        composed_cs: &ComposedConstrainSystem<E>,
        challenges: &[E; 2],
        transcript: &mut impl Transcript<<GpuBackend<E, PCS> as ProverBackend>::E>,
    ) -> Result<
        (
            Point<E>,
            MainSumcheckEvals<E>,
            Option<Vec<IOPProverMessage<E>>>,
            Option<GKRProof<E>>,
        ),
        ZKVMError,
    > {
        let cuda_hal = get_cuda_hal().expect("Failed to get CUDA HAL");
        let gpu_mem_tracker = init_gpu_mem_tracker(&cuda_hal, "prove_main_constraints");

        let res = prove_main_constraints_impl::<E, PCS>(
            rt_tower,
            rotation,
            ecc_proof,
            input,
            composed_cs,
            challenges,
            transcript,
        );

        let estimated_bytes = estimate_main_constraints_bytes::<E, PCS>(composed_cs, input);
        check_gpu_mem_estimation_with_context(
            gpu_mem_tracker,
            estimated_bytes,
            composed_cs
                .gkr_circuit
                .as_ref()
                .and_then(|circuit| circuit.layers.first())
                .map(|layer| layer.name.as_str()),
        );

        res
    }
}

impl<E: ExtensionField, PCS: PolynomialCommitmentScheme<E>>
    BatchedMainConstraintProver<GpuBackend<E, PCS>> for GpuProver<GpuBackend<E, PCS>>
{
    fn prove_batched_main_constraints<'a>(
        &self,
        mut jobs: Vec<MainConstraintJob<'a, GpuBackend<E, PCS>>>,
        pcs_data: &<GpuBackend<E, PCS> as ProverBackend>::PcsData,
        transcript: &mut impl Transcript<E>,
    ) -> Result<(MainConstraintProof<E>, Vec<MainConstraintResult<E>>), ZKVMError> {
        struct ChipMainData<'a, E: ExtensionField> {
            circuit_idx: usize,
            layer: &'a gkr_iop::gkr::layer::Layer<E>,
            mle_start: usize,
            num_mles: usize,
            num_var_with_rotation: usize,
            pi: Vec<Either<E::BaseField, E>>,
            alpha_start: usize,
        }

        struct HostCommonGroup {
            num_vars: usize,
            term_terms: Vec<u32>,
            common_mle_indices: Vec<u32>,
        }

        if jobs.is_empty() {
            return Ok((
                MainConstraintProof {
                    proof: gkr_iop::gkr::layer::sumcheck_layer::SumcheckLayerProof {
                        proof: IOPProof { proofs: vec![] },
                        evals: vec![],
                    },
                },
                vec![],
            ));
        }

        let stream = gkr_iop::gpu::get_thread_stream();
        let cuda_hal = get_cuda_hal().map_err(hal_to_backend_error)?;
        for job in jobs.iter_mut() {
            let num_vars = job.input.log2_num_instances() + job.cs.rotation_vars().unwrap_or(0);
            if job.input.witness.is_empty() {
                if let Some(trace_idx) = job.witness_trace_idx {
                    job.input.witness =
                        info_span!("[ceno] extract_main_witness_mles").in_scope(|| {
                            if job.circuit_name == "ShardRamCircuit" {
                                extract_shard_ram_witness_mles_for_trace::<E, PCS>(
                                    pcs_data,
                                    trace_idx,
                                    job.num_witin,
                                    num_vars,
                                    job.input.num_instances(),
                                )
                            } else {
                                extract_witness_mles_for_trace::<E, PCS>(
                                    pcs_data,
                                    trace_idx,
                                    job.num_witin,
                                    num_vars,
                                )
                            }
                        });
                }
            }
            if job.input.structural_witness.is_empty() {
                if let Some(rmm) = job.structural_rmm.as_ref() {
                    let num_structural_witin = job.cs.zkvm_v1_css.num_structural_witin as usize;
                    job.input.structural_witness =
                        info_span!("[ceno] transport_main_structural_witness").in_scope(|| {
                            transport_structural_witness_to_gpu::<E>(
                                rmm,
                                num_structural_witin,
                                num_vars,
                            )
                        });
                }
            }
        }
        let mut selector_eqs_by_chip = Vec::with_capacity(jobs.len());
        let mut chip_data = Vec::with_capacity(jobs.len());
        let mut total_exprs = 0usize;
        let mut total_mles = 0usize;
        let mut max_num_variables = 0usize;

        for job in &jobs {
            let ComposedConstrainSystem {
                zkvm_v1_css: cs,
                gkr_circuit,
            } = job.cs;
            let num_instances = job.input.num_instances();
            let log2_num_instances = job.input.log2_num_instances();
            let num_var_with_rotation = log2_num_instances + job.cs.rotation_vars().unwrap_or(0);
            max_num_variables = max_num_variables.max(num_var_with_rotation);

            let Some(gkr_circuit) = gkr_circuit else {
                panic!("empty gkr circuit")
            };
            let first_layer = gkr_circuit.layers.first().expect("empty gkr circuit layer");
            let group_stage_masks = first_layer_output_group_stage_masks(job.cs, gkr_circuit);
            let selector_ctxs = first_layer
                .out_sel_and_eval_exprs
                .iter()
                .zip_eq(group_stage_masks.iter())
                .map(|((selector, _), stage_mask)| {
                    if !stage_mask.contains(GkrOutputStageMask::TOWER) || cs.ec_final_sum.is_empty()
                    {
                        SelectorContext {
                            offset: 0,
                            num_instances,
                            num_vars: num_var_with_rotation,
                        }
                    } else if cs.r_selector.as_ref() == Some(selector) {
                        SelectorContext {
                            offset: 0,
                            num_instances: job.input.num_instances[0],
                            num_vars: num_var_with_rotation,
                        }
                    } else if cs.w_selector.as_ref() == Some(selector) {
                        SelectorContext {
                            offset: job.input.num_instances[0],
                            num_instances: job.input.num_instances[1],
                            num_vars: num_var_with_rotation,
                        }
                    } else {
                        SelectorContext {
                            offset: 0,
                            num_instances,
                            num_vars: num_var_with_rotation,
                        }
                    }
                })
                .collect_vec();

            let mut out_evals =
                vec![PointAndEval::new(job.rt_tower.clone(), E::ZERO); gkr_circuit.n_evaluations];

            if let Some(rotation) = job.rotation.as_ref() {
                let Some([left_group_idx, right_group_idx, point_group_idx]) =
                    first_layer.rotation_selector_group_indices()
                else {
                    panic!("rotation proof provided for non-rotation layer")
                };
                let (left_evals, right_evals, point_evals) =
                    split_rotation_evals(&rotation.proof.evals);
                assign_group_evals(
                    &mut out_evals,
                    &first_layer.out_sel_and_eval_exprs[left_group_idx].1,
                    &left_evals,
                    &rotation.left_point,
                );
                assign_group_evals(
                    &mut out_evals,
                    &first_layer.out_sel_and_eval_exprs[right_group_idx].1,
                    &right_evals,
                    &rotation.right_point,
                );
                assign_group_evals(
                    &mut out_evals,
                    &first_layer.out_sel_and_eval_exprs[point_group_idx].1,
                    &point_evals,
                    &rotation.point,
                );
            }

            if let Some(ecc_proof) = job.ecc_proof.as_ref() {
                let Some(
                    [
                        x_group_idx,
                        y_group_idx,
                        slope_group_idx,
                        x3_group_idx,
                        y3_group_idx,
                    ],
                ) = first_layer.ecc_bridge_group_indices()
                else {
                    panic!("ecc proof provided for non-ecc layer")
                };
                let sample_r = transcript.sample_and_append_vec(b"ecc_gkr_bridge_r", 1)[0];
                let claims = derive_ecc_bridge_claims(ecc_proof, sample_r, num_var_with_rotation)
                    .expect("invalid internal ecc bridge claims");
                assign_group_evals(
                    &mut out_evals,
                    &first_layer.out_sel_and_eval_exprs[x_group_idx].1,
                    &claims.x_evals,
                    &claims.xy_point,
                );
                assign_group_evals(
                    &mut out_evals,
                    &first_layer.out_sel_and_eval_exprs[y_group_idx].1,
                    &claims.y_evals,
                    &claims.xy_point,
                );
                assign_group_evals(
                    &mut out_evals,
                    &first_layer.out_sel_and_eval_exprs[slope_group_idx].1,
                    &claims.s_evals,
                    &claims.s_point,
                );
                assign_group_evals(
                    &mut out_evals,
                    &first_layer.out_sel_and_eval_exprs[x3_group_idx].1,
                    &claims.x3_evals,
                    &claims.x3y3_point,
                );
                assign_group_evals(
                    &mut out_evals,
                    &first_layer.out_sel_and_eval_exprs[y3_group_idx].1,
                    &claims.y3_evals,
                    &claims.x3y3_point,
                );
            }

            let eval_and_dedup_points = first_layer
                .out_sel_and_eval_exprs
                .iter()
                .map(|(_, out_eval_exprs)| {
                    out_eval_exprs
                        .first()
                        .map(|out_eval| out_eval.evaluate(&out_evals, &job.challenges).point)
                })
                .collect_vec();
            let selector_eq_pairs = first_layer
                .out_sel_and_eval_exprs
                .iter()
                .zip(eval_and_dedup_points.iter())
                .zip(selector_ctxs.iter())
                .filter_map(|(((sel_type, _), point), selector_ctx)| {
                    let eq = gkr_iop::gkr::layer::gpu::utils::build_eq_x_r_with_sel_gpu(
                        &cuda_hal,
                        point.as_ref()?,
                        selector_ctx,
                        sel_type,
                    );
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
                    Some((*wit_id as usize, eq))
                })
                .collect_vec();
            let mut selector_eq_by_wit_id = vec![None; first_layer.n_structural_witin];
            for (wit_id, eq) in selector_eq_pairs {
                if selector_eq_by_wit_id[wit_id].is_none() {
                    selector_eq_by_wit_id[wit_id] = Some(eq);
                }
            }
            selector_eqs_by_chip.push(selector_eq_by_wit_id);

            let num_mles =
                first_layer.n_witin + first_layer.n_fixed + first_layer.n_structural_witin;
            chip_data.push(ChipMainData {
                circuit_idx: job.circuit_idx,
                layer: first_layer,
                mle_start: total_mles,
                num_mles,
                num_var_with_rotation,
                pi: job.input.pi.clone(),
                alpha_start: total_exprs,
            });
            total_mles += num_mles;
            total_exprs += first_layer.exprs.len();
        }
        let mut all_witins_gpu = Vec::with_capacity(total_mles);
        for ((job, chip), selector_eq_by_wit_id) in jobs
            .iter()
            .zip(chip_data.iter())
            .zip(selector_eqs_by_chip.iter())
        {
            all_witins_gpu.extend(job.input.witness.iter().map(|mle| mle.as_ref()));
            all_witins_gpu.extend(job.input.fixed.iter().map(|mle| mle.as_ref()));
            for (selector_eq, mle) in selector_eq_by_wit_id
                .iter()
                .zip(job.input.structural_witness.iter())
            {
                if let Some(eq) = selector_eq.as_ref() {
                    all_witins_gpu.push(eq);
                } else {
                    all_witins_gpu.push(mle.as_ref());
                }
            }
            assert_eq!(
                all_witins_gpu.len(),
                chip.mle_start + chip.num_mles,
                "invalid gpu main witness layout"
            );
        }
        let alpha_pows = get_challenge_pows(total_exprs, transcript);
        let mut term_coefficients = Vec::new();
        let mut mle_indices_per_term = Vec::new();
        let mut mle_size_info = Vec::new();
        let mut common_groups = Vec::new();
        for chip in &chip_data {
            let main_sumcheck_challenges = chain!(
                jobs[0].challenges.iter().copied(),
                alpha_pows[chip.alpha_start..chip.alpha_start + chip.layer.exprs.len()]
                    .iter()
                    .copied()
            )
            .collect_vec();
            let common_plan = chip.layer.main_sumcheck_expression_common_factored.as_ref();
            let monomial_terms = match (
                common_plan,
                chip.layer
                    .main_sumcheck_expression_monomial_terms_excluded_shared
                    .as_ref(),
            ) {
                (Some(_), Some(residual_terms)) => residual_terms,
                (Some(_), None) => {
                    panic!("common factoring plan present without residual monomials")
                }
                (None, Some(terms)) => terms,
                (None, None) => chip
                    .layer
                    .main_sumcheck_expression_monomial_terms
                    .as_ref()
                    .unwrap(),
            };
            let term_start = term_coefficients.len();
            for term in monomial_terms {
                let scalar =
                    eval_by_expr_constant(&chip.pi, &main_sumcheck_challenges, &term.scalar)
                        .map_either(E::from, |v| v)
                        .into_inner();
                term_coefficients.push(scalar);
                let indices = term
                    .product
                    .iter()
                    .map(|expr| {
                        let Expression::WitIn(wit_id) = expr else {
                            panic!("main monomial product must be converted to WitIn")
                        };
                        chip.mle_start + *wit_id as usize
                    })
                    .collect_vec();
                let first_idx = indices.first().copied();
                mle_indices_per_term.push(indices);
                if let Some(first_idx) = first_idx {
                    let num_vars = all_witins_gpu[first_idx].mle.num_vars();
                    mle_size_info.push((num_vars, num_vars));
                } else {
                    mle_size_info.push((0, 0));
                }
            }
            let mut covered_terms = vec![false; monomial_terms.len()];
            if let Some(common_plan) = common_plan {
                for group in &common_plan.groups {
                    assert!(
                        !group.term_indices.is_empty(),
                        "common term group must include at least one term"
                    );
                    let mut group_term_terms = Vec::with_capacity(group.term_indices.len());
                    for &term_idx in &group.term_indices {
                        assert!(
                            term_idx < monomial_terms.len(),
                            "common term index {} out of range (terms={})",
                            term_idx,
                            monomial_terms.len()
                        );
                        covered_terms[term_idx] = true;
                        group_term_terms.push(
                            u32::try_from(term_start + term_idx)
                                .expect("term index exceeds supported range for GPU plan"),
                        );
                    }

                    let mut group_mle_indices = Vec::with_capacity(group.witness_indices.len());
                    for &wit_idx in &group.witness_indices {
                        assert!(
                            wit_idx < chip.num_mles,
                            "common witness index {} out of range (mles={})",
                            wit_idx,
                            chip.num_mles
                        );
                        group_mle_indices.push(
                            u32::try_from(chip.mle_start + wit_idx)
                                .expect("witness index exceeds supported range for GPU plan"),
                        );
                    }
                    common_groups.push(HostCommonGroup {
                        num_vars: chip.num_var_with_rotation,
                        term_terms: group_term_terms,
                        common_mle_indices: group_mle_indices,
                    });
                }
            }
            let mut uncovered_terms = Vec::new();
            for (term_idx, covered) in covered_terms.iter().copied().enumerate() {
                if !covered {
                    uncovered_terms.push(
                        u32::try_from(term_start + term_idx)
                            .expect("term index exceeds supported range for GPU plan"),
                    );
                }
            }
            if !uncovered_terms.is_empty() {
                common_groups.push(HostCommonGroup {
                    num_vars: chip.num_var_with_rotation,
                    term_terms: uncovered_terms,
                    common_mle_indices: Vec::new(),
                });
            }
        }

        common_groups.sort_by(|lhs, rhs| rhs.num_vars.cmp(&lhs.num_vars));

        let mut common_term_offsets = Vec::with_capacity(common_groups.len() + 1);
        let mut common_term_terms = Vec::new();
        let mut common_mle_offsets = Vec::with_capacity(common_groups.len() + 1);
        let mut common_mle_indices = Vec::new();
        common_term_offsets.push(0);
        common_mle_offsets.push(0);
        for group in &common_groups {
            common_term_terms.extend(group.term_terms.iter().copied());
            common_term_offsets.push(common_term_terms.len() as u32);
            common_mle_indices.extend(group.common_mle_indices.iter().copied());
            common_mle_offsets.push(common_mle_indices.len() as u32);
        }

        let max_degree = common_groups
            .iter()
            .map(|group| {
                let common_len = group.common_mle_indices.len();
                let max_residual_len = group
                    .term_terms
                    .iter()
                    .map(|&term_idx| mle_indices_per_term[term_idx as usize].len())
                    .max()
                    .unwrap_or(0);
                common_len + max_residual_len
            })
            .max()
            .unwrap_or(0);
        let basic_transcript = expect_basic_transcript(transcript);
        let common_scalar_offsets = vec![0u32; common_mle_offsets.len()];
        let common_term_plan = CommonTermPlan {
            term_offsets: common_term_offsets,
            term_terms: common_term_terms,
            common_mle_offsets,
            common_mle_indices,
            common_scalar_offsets,
            common_scalar_indices: vec![],
        };
        let term_coefficients_gl64: Vec<BB31Ext> =
            unsafe { std::mem::transmute(term_coefficients) };
        let all_witins_gpu_gl64: Vec<&MultilinearExtensionGpu<BB31Ext>> =
            unsafe { std::mem::transmute(all_witins_gpu) };
        let all_witins_gpu_type_gl64 = all_witins_gpu_gl64.iter().map(|mle| &mle.mle).collect_vec();
        let (proof_gpu, evals_gpu, challenges_gpu) = cuda_hal
            .sumcheck
            .prove_generic_sumcheck_gpu_v2(
                cuda_hal.as_ref(),
                all_witins_gpu_type_gl64,
                &mle_size_info,
                &term_coefficients_gl64,
                &mle_indices_per_term,
                max_num_variables,
                max_degree,
                Some(&common_term_plan),
                basic_transcript,
                stream.as_ref(),
            )
            .map_err(|e| hal_to_backend_error(format!("GPU main sumcheck failed: {e:?}")))?;
        let proof: IOPProof<E> = unsafe { std::mem::transmute(proof_gpu) };
        let evals_gpu_e: Vec<Vec<E>> = unsafe { std::mem::transmute(evals_gpu) };
        let global_evals = evals_gpu_e.into_iter().flatten().collect_vec();
        let global_rt: Point<E> = unsafe {
            std::mem::transmute::<Vec<BB31Ext>, Vec<E>>(
                challenges_gpu.iter().map(|c| c.elements).collect(),
            )
        };

        transcript.append_field_element_exts(&global_evals);

        let mut results = Vec::with_capacity(chip_data.len());
        for chip in &chip_data {
            let input_opening_point =
                frontload_input_opening_point(&global_rt, chip.num_var_with_rotation);
            let chip_evals = &global_evals[chip.mle_start..chip.mle_start + chip.num_mles];
            results.push(MainConstraintResult {
                circuit_idx: chip.circuit_idx,
                input_opening_point,
                opening_evals: MainSumcheckEvals {
                    wits_in_evals: chip_evals[..chip.layer.n_witin].to_vec(),
                    fixed_in_evals: chip_evals
                        [chip.layer.n_witin..chip.layer.n_witin + chip.layer.n_fixed]
                        .to_vec(),
                },
            });
        }

        Ok((
            MainConstraintProof {
                proof: gkr_iop::gkr::layer::sumcheck_layer::SumcheckLayerProof {
                    proof,
                    evals: global_evals,
                },
            },
            results,
        ))
    }
}

fn frontload_input_opening_point<E: ExtensionField>(
    global_rt: &[E],
    num_var_with_rotation: usize,
) -> Point<E> {
    global_rt[..num_var_with_rotation].to_vec()
}

impl<E: ExtensionField, PCS: PolynomialCommitmentScheme<E> + 'static>
    RotationProver<GpuBackend<E, PCS>> for GpuProver<GpuBackend<E, PCS>>
{
    fn prove_rotation<'a>(
        &self,
        composed_cs: &ComposedConstrainSystem<E>,
        input: &ProofInput<'a, GpuBackend<E, PCS>>,
        rt_tower: &Point<E>,
        challenges: &[E; 2],
        transcript: &mut impl Transcript<E>,
    ) -> Result<Option<RotationProverOutput<E>>, ZKVMError> {
        prove_rotation_impl::<E, PCS>(composed_cs, input, rt_tower, challenges, transcript)
    }
}

impl<E: ExtensionField, PCS: PolynomialCommitmentScheme<E>> EccQuarkProver<GpuBackend<E, PCS>>
    for GpuProver<GpuBackend<E, PCS>>
{
    fn prove_ec_sum_quark<'a>(
        &self,
        composed_cs: &ComposedConstrainSystem<E>,
        input: &ProofInput<'a, GpuBackend<E, PCS>>,
        transcript: &mut impl Transcript<E>,
    ) -> Result<Option<EccQuarkProof<E>>, ZKVMError> {
        let cuda_hal = get_cuda_hal().expect("Failed to get CUDA HAL");
        let gpu_mem_tracker = init_gpu_mem_tracker(&cuda_hal, "prove_ec_sum_quark");

        let res = prove_ec_sum_quark_impl::<E, PCS>(composed_cs, input, transcript);

        if let Ok(Some(proof)) = &res {
            let estimated_bytes = estimate_ecc_quark_bytes_from_num_vars(proof.rt.len());
            check_gpu_mem_estimation_with_context(
                gpu_mem_tracker,
                estimated_bytes,
                composed_cs
                    .gkr_circuit
                    .as_ref()
                    .and_then(|circuit| circuit.layers.first())
                    .map(|layer| layer.name.as_str()),
            );
        }

        res
    }
}

fn open_jagged_gpu<E, PCS>(
    prover_param: &<PCS as PolynomialCommitmentScheme<E>>::ProverParam,
    rounds: Vec<(&GpuPcsData, Vec<(Point<E>, Vec<E>)>)>,
    transcript: &mut (impl Transcript<E> + 'static),
) -> PCS::Proof
where
    E: ExtensionField,
    PCS: PolynomialCommitmentScheme<E> + 'static,
{
    if std::any::TypeId::of::<E>() != std::any::TypeId::of::<BB31Ext>() {
        panic!("GPU Jagged opening only supports BabyBear field extension");
    }

    let transcript_any = transcript as &mut dyn std::any::Any;
    let basic_transcript = transcript_any
        .downcast_mut::<BasicTranscript<BB31Ext>>()
        .expect("Type should match");
    let pp_bb31: &mpcs::basefold::structure::BasefoldProverParams<BB31Ext, mpcs::BasefoldRSParams> =
        unsafe { std::mem::transmute(prover_param) };
    let cuda_hal = get_cuda_hal().unwrap();

    let mut proofs = Vec::with_capacity(rounds.len());
    for (pcs_data, openings) in rounds {
        let jagged_data = expect_jagged_pcs_data(pcs_data);
        let openings_bb31: Vec<(Point<BB31Ext>, Vec<BB31Ext>)> = openings
            .iter()
            .map(|(point, evals)| {
                let point_bb31: &Vec<BB31Ext> = unsafe { std::mem::transmute(point) };
                let evals_bb31: &Vec<BB31Ext> = unsafe { std::mem::transmute(evals) };
                (point_bb31.clone(), evals_bb31.clone())
            })
            .collect();
        let (point, evals) = mpcs::jagged::flatten_padded_openings_as_native(
            &jagged_data.poly_heights,
            openings_bb31,
        )
        .expect("invalid Jagged GPU opening shape");
        let q_evals = if let Some(q_evals) = &jagged_data.q_evals {
            let q_evals_len_bytes = q_evals.len() * std::mem::size_of::<BB31Base>();
            q_evals.owned_subrange(0..q_evals_len_bytes)
        } else {
            let q_host = jagged_data
                .q_host_evals
                .as_ref()
                .expect("Jagged q' is missing both device and host backing");
            cuda_hal
                .alloc_elems_from_host(q_host, None)
                .expect("failed to upload Jagged q' for opening")
        };
        let proof =
            jagged_batch_open_gpu::<BB31Ext, BabyBearBasefold, _>(
                &jagged_data.cumulative_heights,
                jagged_data.total_evaluations,
                jagged_data.reshape_log_height,
                &point,
                &evals,
                basic_transcript,
                |num_giga_vars, w, cumulative_heights, eq_row, eq_col, transcript| {
                    let ctx = JaggedSumcheckGpuCtx::<CudaHalBB31>::from_gpu_q_evals(
                        &cuda_hal,
                        q_evals,
                        cumulative_heights,
                        &eq_row,
                        &eq_col,
                        num_giga_vars,
                    )
                    .expect("create Jagged GPU sumcheck ctx");
                    let (proof, rho) = jagged_sumcheck_prove_gpu::<
                        CudaHalBB31,
                        BB31Ext,
                        BB31Base,
                        GpuMatrix,
                        GpuPolynomial,
                        GpuPolynomialExt,
                        GpuFieldType,
                    >(&cuda_hal, &ctx, transcript, None)
                    .expect("Jagged GPU sumcheck failed");
                    let col_evals = eval_cols_at_point_gpu::<CudaHalBB31, BB31Ext, BB31Base>(
                        &cuda_hal,
                        &ctx.q_evals,
                        &rho[..jagged_data.reshape_log_height],
                        jagged_data.reshape_log_height,
                        w,
                        jagged_data.total_evaluations,
                    )
                    .expect("Jagged GPU column eval failed");
                    (proof, rho, col_evals)
                },
                |rho_row, col_evals, transcript| {
                    let group_width = mpcs::JAGGED_RESHAPE_GROUP_WIDTH;
                    let inner_openings = col_evals
                        .chunks(group_width)
                        .map(|evals| (rho_row.clone(), evals.to_vec()))
                        .collect_vec();
                    let gpu_basefold_proof = cuda_hal.basefold.batch_open_with_trace_materializer(
                    &cuda_hal,
                    pp_bb31,
                    vec![(&jagged_data.inner, inner_openings)],
                    transcript,
                    |_round_idx, trace_idx| {
                        let h = 1usize << jagged_data.reshape_log_height;
                        let w = jagged_data.total_evaluations.div_ceil(h);
                        let group_start_col = trace_idx * group_width;
                        assert!(group_start_col < w, "Jagged inner q' trace index out of range");
                        let group_cols = (w - group_start_col).min(group_width);
                        let start = group_start_col * h;
                        let group_elems = group_cols * h;
                        let available_elems = jagged_data
                            .total_evaluations
                            .saturating_sub(start)
                            .min(group_elems);
                        let q_view = if let Some(q_evals) = jagged_data.q_evals.as_ref() {
                            if available_elems == group_elems {
                                q_evals.owned_subrange(
                                    start * std::mem::size_of::<BB31Base>()
                                        ..(start + group_elems) * std::mem::size_of::<BB31Base>(),
                                )
                            } else {
                                let mut padded = cuda_hal
                                    .alloc_elems_on_device(group_elems, true, None)
                                    .map_err(|e| {
                                        ceno_gpu::HalError::Unknown(format!(
                                            "failed to alloc padded Jagged q' opening group: {e:?}"
                                        ))
                                    })?;
                                if available_elems > 0 {
                                    let src_start = start * std::mem::size_of::<BB31Base>();
                                    let src_end = src_start
                                        + available_elems * std::mem::size_of::<BB31Base>();
                                    let src = q_evals.as_slice_range(src_start..src_end);
                                    let mut dst = padded.as_mut_slice_range(
                                        0..available_elems * std::mem::size_of::<BB31Base>(),
                                    );
                                    cuda_hal.inner.dtod_copy_sync(&src, &mut dst).map_err(|e| {
                                        ceno_gpu::HalError::Unknown(format!(
                                            "failed to pad Jagged q' opening group: {e:?}"
                                        ))
                                    })?;
                                }
                                padded
                            }
                        } else {
                            let q_host = jagged_data
                                .q_host_evals
                                .as_ref()
                                .expect("Jagged q' host backing missing for opening");
                            cuda_hal.alloc_elems_from_host(&q_host[start..start + group_elems], None).map_err(
                                |e| {
                                    ceno_gpu::HalError::Unknown(format!(
                                        "failed to upload Jagged q' group for opening: {e:?}"
                                    ))
                                },
                            )?
                        };
                        Ok(Some(witness::RowMajorMatrix::new_by_device_backing(
                            h,
                            group_cols,
                            InstancePaddingStrategy::Default,
                            q_view,
                            DeviceMatrixLayout::ColMajor,
                        )))
                    },
                )
                .map_err(|e| mpcs::Error::InvalidPcsOpen(e.to_string()))?;
                    Ok(mpcs::basefold::structure::BasefoldProof {
                        commits: gpu_basefold_proof.commits,
                        query_opening_proof: gpu_basefold_proof.query_opening_proof,
                        sumcheck_proof: gpu_basefold_proof.sumcheck_proof,
                        final_message: gpu_basefold_proof.final_message,
                        pow_witness: gpu_basefold_proof.pow_witness,
                    })
                },
            )
            .expect("Jagged GPU batch open failed");
        proofs.push(proof);
    }

    let jagged_proof = mpcs::JaggedProof::<BB31Ext, BabyBearBasefold> { rounds: proofs };
    let proof: PCS::Proof = unsafe { std::mem::transmute_copy(&jagged_proof) };
    std::mem::forget(jagged_proof);
    proof
}

impl<E: ExtensionField, PCS: PolynomialCommitmentScheme<E> + 'static>
    OpeningProver<GpuBackend<E, PCS>> for GpuProver<GpuBackend<E, PCS>>
{
    fn open(
        &self,
        witness_data: <GpuBackend<E, PCS> as ProverBackend>::PcsData,
        fixed_data: Option<Arc<<GpuBackend<E, PCS> as ProverBackend>::PcsData>>,
        points: Vec<Point<E>>,
        mut evals: Vec<Vec<Vec<E>>>, // where each inner Vec<E> = wit_evals + fixed_evals
        transcript: &mut (impl Transcript<E> + 'static),
    ) -> PCS::Proof {
        if std::any::TypeId::of::<E::BaseField>() != std::any::TypeId::of::<BB31Base>() {
            panic!("GPU backend only supports BabyBear base field");
        }

        let mut rounds = vec![];
        rounds.push((&witness_data, {
            evals
                .iter_mut()
                .zip(&points)
                .filter_map(|(evals, point)| {
                    let witin_evals = evals.remove(0);
                    if !witin_evals.is_empty() {
                        Some((point.clone(), witin_evals))
                    } else {
                        None
                    }
                })
                .collect_vec()
        }));
        if let Some(fixed_data) = fixed_data.as_ref().map(|f| f.as_ref()) {
            rounds.push((fixed_data, {
                evals
                    .iter_mut()
                    .zip(points.iter().cloned())
                    .filter_map(|(evals, point)| {
                        if !evals.is_empty() && !evals[0].is_empty() {
                            Some((point.clone(), evals.remove(0)))
                        } else {
                            None
                        }
                    })
                    .collect_vec()
            }));
        }

        if matches!(&witness_data, GpuPcsData::Jagged(_)) {
            return open_jagged_gpu::<E, PCS>(&self.backend.pp, rounds, transcript);
        }

        // Type conversions using unsafe transmute
        let prover_param = &self.backend.pp;
        let pp_gl64: &mpcs::basefold::structure::BasefoldProverParams<
            BB31Ext,
            mpcs::BasefoldRSParams,
        > = unsafe { std::mem::transmute(prover_param) };
        let rounds_gl64: Vec<_> = rounds
            .iter()
            .map(|(commitment, point_eval_pairs)| {
                let commitment_gl64 = expect_basefold_pcs_data(commitment);
                let point_eval_pairs_gl64: Vec<_> = point_eval_pairs
                    .iter()
                    .map(|(point, evals)| {
                        let point_gl64: &Vec<BB31Ext> = unsafe { std::mem::transmute(point) };
                        let evals_gl64: &Vec<BB31Ext> = unsafe { std::mem::transmute(evals) };
                        (point_gl64.clone(), evals_gl64.clone())
                    })
                    .collect();
                (commitment_gl64, point_eval_pairs_gl64)
            })
            .collect();

        if std::any::TypeId::of::<E>() == std::any::TypeId::of::<BB31Ext>() {
            let transcript_any = transcript as &mut dyn std::any::Any;
            let basic_transcript = transcript_any
                .downcast_mut::<BasicTranscript<BB31Ext>>()
                .expect("Type should match");

            let cuda_hal = get_cuda_hal().unwrap();
            let gpu_proof_basefold = cuda_hal
                .basefold
                .batch_open(&cuda_hal, pp_gl64, rounds_gl64, basic_transcript)
                .unwrap();

            let gpu_proof: PCS::Proof = unsafe { std::mem::transmute_copy(&gpu_proof_basefold) };
            std::mem::forget(gpu_proof_basefold);
            gpu_proof
        } else {
            panic!("GPU backend only supports BabyBear base field");
        }
    }
}

impl<E: ExtensionField, PCS: PolynomialCommitmentScheme<E> + 'static>
    DeviceTransporter<GpuBackend<E, PCS>> for GpuProver<GpuBackend<E, PCS>>
{
    fn transport_proving_key(
        &self,
        is_first_shard: bool,
        pk: Arc<
            crate::structs::ZKVMProvingKey<
                <GpuBackend<E, PCS> as ProverBackend>::E,
                <GpuBackend<E, PCS> as ProverBackend>::Pcs,
            >,
        >,
    ) -> DeviceProvingKey<'static, GpuBackend<E, PCS>> {
        let pcs_data_original = if is_first_shard {
            pk.fixed_commit_wd.as_ref().unwrap().clone()
        } else {
            pk.fixed_no_omc_init_commit_wd.as_ref().unwrap().clone()
        };

        let is_pcs_match = std::mem::size_of::<mpcs::BasefoldCommitmentWithWitness<BB31Ext>>()
            == std::mem::size_of::<PCS::CommitmentWithWitness>();
        let is_jagged_pcs = is_babybear_jagged_pcs::<E, PCS>();
        assert!(is_pcs_match || is_jagged_pcs, "pcs mismatch");

        let cuda_hal = get_cuda_hal().unwrap();

        if is_jagged_pcs {
            let jagged_commitment: &mpcs::JaggedCommitmentWithWitness<BB31Ext, BabyBearBasefold> =
                unsafe { std::mem::transmute_copy(&pcs_data_original.as_ref()) };
            let pcs_data_basefold = convert_ceno_to_gpu_basefold_commitment::<
                CudaHalBB31,
                BB31Ext,
                BB31Base,
                GpuDigestLayer,
                GpuMatrix,
                GpuPolynomial,
            >(&cuda_hal, &jagged_commitment.inner)
            .expect("failed to convert fixed inner basefold commitment to GPU");

            let total_evaluations = jagged_commitment.total_evaluations();
            let h = 1usize << jagged_commitment.reshape_log_height;
            let w = total_evaluations.div_ceil(h);
            let padded_total = w * h;
            let q_len = padded_total.max(1);
            let mut q_evals = vec![BB31Base::ZERO; q_len];
            for (poly_idx, poly) in jagged_commitment.polys.iter().enumerate() {
                let start = jagged_commitment.cumulative_heights[poly_idx];
                let len = jagged_commitment.poly_heights[poly_idx];
                match poly.evaluations() {
                    FieldType::Base(values) => {
                        q_evals[start..start + len].copy_from_slice(&values[..len])
                    }
                    FieldType::Ext(_) => panic!("Jagged fixed q' expects base-field polys"),
                    FieldType::Unreachable => unreachable!(),
                }
            }
            let q_evals = cuda_hal
                .alloc_elems_from_host(&q_evals, None)
                .expect("failed to upload fixed Jagged q'");
            let fixed_mles: Vec<Arc<MultilinearExtensionGpu<'static, E>>> = jagged_commitment
                .polys
                .iter()
                .map(|mle| {
                    let mle_e: &MultilinearExtension<'_, E> =
                        unsafe { std::mem::transmute(mle.as_ref()) };
                    Arc::new(MultilinearExtensionGpu::from_ceno(&cuda_hal, mle_e))
                })
                .collect_vec();
            let pcs_data = Arc::new(GpuPcsData::Jagged(GpuJaggedPcsData {
                inner: pcs_data_basefold,
                q_evals: Some(q_evals),
                q_host_evals: None,
                cumulative_heights: jagged_commitment.cumulative_heights.clone(),
                poly_heights: jagged_commitment.poly_heights.clone(),
                total_evaluations,
                reshape_log_height: jagged_commitment.reshape_log_height,
                trace_layouts: Vec::new(),
            }));

            return DeviceProvingKey {
                pcs_data,
                fixed_mles,
            };
        }

        // 1. transmute from PCS::CommitmentWithWitness to BasefoldCommitmentWithWitness<E>
        let basefold_commitment: &mpcs::BasefoldCommitmentWithWitness<BB31Ext> =
            unsafe { std::mem::transmute_copy(&pcs_data_original.as_ref()) };
        // 2. convert from BasefoldCommitmentWithWitness<E> to BasefoldCommitmentWithWitness<BB31Base>
        let pcs_data_basefold = convert_ceno_to_gpu_basefold_commitment::<
            CudaHalBB31,
            BB31Ext,
            BB31Base,
            GpuDigestLayer,
            GpuMatrix,
            GpuPolynomial,
        >(&cuda_hal, basefold_commitment)
        .expect("failed to convert fixed pcs_data to GPU basefold commitment");

        // cuda buffer as view
        let fixed_mles: Vec<Arc<MultilinearExtensionGpu<'static, E>>> = pcs_data_basefold
            .trace
            .as_ref()
            .expect("trace must be populated by convert_ceno_to_gpu_basefold_commitment")
            .iter()
            .flat_map(|poly_group| poly_group.iter())
            .map(|gpu_poly| {
                let evals = gpu_poly.evaluations();
                let byte_len = evals.len() * std::mem::size_of::<BB31Base>();
                // Fixed-trace MLEs live for the whole proving key lifetime on
                // the GPU side, so they must not borrow a temporary CudaView.
                let view_buf = evals.owned_subrange(0..byte_len);
                let view_poly = GpuPolynomial::new(view_buf, gpu_poly.num_vars());
                let view_poly_static: GpuPolynomial<'static> =
                    unsafe { std::mem::transmute(view_poly) };
                Arc::new(MultilinearExtensionGpu::from_ceno_gpu_base(
                    view_poly_static,
                ))
            })
            .collect_vec();

        let pcs_data = Arc::new(GpuPcsData::Basefold(pcs_data_basefold));

        DeviceProvingKey {
            pcs_data,
            fixed_mles,
        }
    }

    fn transport_mles<'a>(
        &self,
        mles: &[MultilinearExtension<'a, E>],
    ) -> Vec<Arc<<GpuBackend<E, PCS> as ProverBackend>::MultilinearPoly<'a>>> {
        let cuda_hal = get_cuda_hal().unwrap();
        mles.iter()
            .map(|mle| Arc::new(MultilinearExtensionGpu::from_ceno(&cuda_hal, mle)))
            .collect_vec()
    }
}

impl<E: ExtensionField, PCS: PolynomialCommitmentScheme<E>>
    super::hal::ChipInputPreparer<GpuBackend<E, PCS>> for GpuProver<GpuBackend<E, PCS>>
{
    fn prepare_chip_input(
        &self,
        task: &mut crate::scheme::scheduler::ChipTask<'_, GpuBackend<E, PCS>>,
        pcs_data: &<GpuBackend<E, PCS> as gkr_iop::hal::ProverBackend>::PcsData,
    ) {
        let num_vars =
            task.input.log2_num_instances() + task.pk.get_cs().rotation_vars().unwrap_or(0);

        // Deferred witness extraction: extract from committed pcs_data just-in-time
        if let Some(trace_idx) = task.witness_trace_idx {
            task.input.witness = info_span!("[ceno] extract_witness_mles").in_scope(|| {
                extract_witness_mles_for_trace::<E, PCS>(
                    pcs_data,
                    trace_idx,
                    task.num_witin,
                    num_vars,
                )
            });
        }

        // Deferred structural witness transport: CPU -> GPU just-in-time
        if let Some(rmm) = task.structural_rmm.as_ref() {
            let num_structural_witin = task.pk.get_cs().zkvm_v1_css.num_structural_witin as usize;
            task.input.structural_witness = info_span!("[ceno] transport_structural_witness")
                .in_scope(|| {
                    transport_structural_witness_to_gpu::<E>(rmm, num_structural_witin, num_vars)
                });
        }
    }
}

impl<E, PCS> ProverDevice<GpuBackend<E, PCS>> for GpuProver<GpuBackend<E, PCS>>
where
    E: ExtensionField,
    PCS: PolynomialCommitmentScheme<E> + 'static,
{
    fn get_pb(&self) -> &GpuBackend<E, PCS> {
        self.backend.as_ref()
    }
}
