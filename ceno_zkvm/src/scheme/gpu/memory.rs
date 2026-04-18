use crate::{
    instructions::gpu::dispatch::GpuWitgenKind,
    scheme::{
        constants::{NUM_FANIN, SEPTIC_EXTENSION_DEGREE},
        hal::ProofInput,
    },
    structs::{ComposedConstrainSystem, GpuReplayPlan},
};
use ceno_gpu::{
    estimate_build_tower_memory, estimate_prove_tower_memory, estimate_sumcheck_memory,
};
use ff_ext::ExtensionField;
use gkr_iop::gpu::{
    BB31Base, GpuBackend,
    gpu_prover::{
        BB31Ext, CacheLevel, CudaHalBB31, MemTracker, get_gpu_cache_level, get_mem_tracking_mode,
    },
};
use mpcs::PolynomialCommitmentScheme;
use std::sync::OnceLock;

#[cfg(feature = "gpu")]
use crate::instructions::gpu::config::{
    should_materialize_witness_on_gpu, should_retain_witness_device_backing_after_commit,
};
use crate::scheme::scheduler::{ChipProvingMode, get_chip_proving_mode};

pub fn init_gpu_mem_tracker<'a>(
    cuda_hal: &'a CudaHalBB31,
    label: &'static str,
) -> Option<MemTracker<'a>> {
    let is_sequential = get_chip_proving_mode() == ChipProvingMode::Sequential;
    let is_mem_tracking = get_mem_tracking_mode() == true;
    if is_sequential && is_mem_tracking {
        Some(cuda_hal.inner.mem_tracker(label))
    } else {
        None
    }
}

const ESTIMATION_TOLERANCE_BYTES: usize = 2 * 1024 * 1024; // max under-estimation error: 2 MB
const ESTIMATION_SAFETY_MARGIN_BYTES: usize = 10 * 1024 * 1024; // reserved headroom / allowed over-estimate margin: 10 MB

/// Validate that the estimated GPU memory matches actual usage within tolerance.
/// - Under-estimate (actual > estimated): diff must be <= `ESTIMATION_TOLERANCE_BYTES`
/// - Over-estimate (estimated > actual): diff must be <= `ESTIMATION_SAFETY_MARGIN_BYTES`
pub fn check_gpu_mem_estimation(mem_tracker: Option<MemTracker>, estimated_bytes: usize) {
    // `mem_tracker will` be Some only in sequential mode with mem tracking enabled, so if it's None, do nothing
    if let Some(mem_tracker) = mem_tracker {
        const ONE_MB: usize = 1024 * 1024;
        let label = mem_tracker.name();
        let mem_stats = mem_tracker.finish();
        let actual_bytes = mem_stats.mem_occupancy as usize;
        let diff = estimated_bytes as isize - actual_bytes as isize;
        let to_mb = |b: usize| b as f64 / ONE_MB as f64;
        let diff_mb = diff as f64 / ONE_MB as f64;
        tracing::info!(
            "[memcheck] {label}: estimated={:.2}MB, actual={:.2}MB, diff={:.2}MB",
            to_mb(estimated_bytes),
            to_mb(actual_bytes),
            diff_mb
        );
        if diff < 0 {
            // Under-estimate: actual exceeds estimated
            assert!(
                (-diff) as usize <= ESTIMATION_TOLERANCE_BYTES,
                "[memcheck] {label}: under-estimate! estimated={:.2}MB, actual={:.2}MB, diff={:.2}MB, tolerance={:.2}MB",
                to_mb(estimated_bytes),
                to_mb(actual_bytes),
                diff_mb,
                to_mb(ESTIMATION_TOLERANCE_BYTES),
            );
        } else {
            // Over-estimate: estimated exceeds actual
            assert!(
                diff as usize <= ESTIMATION_SAFETY_MARGIN_BYTES,
                "[memcheck] {label}: over-estimate! estimated={:.2}MB, actual={:.2}MB, diff={:.2}MB, margin={:.2}MB",
                to_mb(estimated_bytes),
                to_mb(actual_bytes),
                diff_mb,
                to_mb(ESTIMATION_SAFETY_MARGIN_BYTES),
            );
        }
    }
}

/// Pre-estimate GPU memory usage for a chip proof before actual execution.
/// Used by the concurrent proving scheduler to reserve VRAM from the GPU memory pool,
/// ensuring multiple chip proofs can run in parallel without OOM.
pub fn estimate_chip_proof_memory<E: ExtensionField, PCS: PolynomialCommitmentScheme<E>>(
    composed_cs: &ComposedConstrainSystem<E>,
    input: &ProofInput<'_, GpuBackend<E, PCS>>,
    circuit_name: &str,
    witness_replayable: bool,
) -> u64 {
    let num_var_with_rotation =
        input.log2_num_instances() + composed_cs.rotation_vars().unwrap_or(0);

    // Part 1: trace (base usage: witness & structural mles)
    let trace_est = estimate_trace_bytes(composed_cs, input, witness_replayable);

    // Part 2: main witness (base usage)
    let main_witness_bytes = estimate_main_witness_bytes(composed_cs, num_var_with_rotation);

    // Part 3: ecc quark (temporary usage)
    let n = num_var_with_rotation.saturating_sub(1);
    let ecc_quark_temporary_bytes = estimate_ecc_quark_bytes_from_num_vars(n);

    // Part 4: build/prove tower
    //
    // `tower_prove_local_bytes` is only the new allocation occupancy inside
    // `create_proof`, while `tower_input_live_bytes` tracks the already-built
    // TowerInput buffers that remain live during that stage.
    let (tower_build_bytes, tower_prove_local_bytes, tower_input_live_bytes) =
        estimate_tower_stage_components(composed_cs, input);
    let tower_prove_peak_bytes = tower_input_live_bytes + tower_prove_local_bytes;
    let tower_temporary_bytes = tower_build_bytes.max(tower_prove_peak_bytes);

    // Part 5: main constraints (temporary usage)
    let main_constraints_temporary_bytes = estimate_main_constraints_bytes(composed_cs, input);

    let replay_stage_split =
        witness_replayable && matches!(circuit_name, "Ecall_Keccak" | "ShardRamCircuit");
    let (resident_bytes, stage_peak_usage_bytes, total_usage_bytes) = if replay_stage_split {
        // Replayable large-memory chips are materialized twice:
        // - once for build_main_witness + build_tower_witness
        // - once again for main constraints
        // The replayed trace/device backing is explicitly released before the
        // standalone tower prove and again before the main-constraints stage,
        // so the peak is the max of those stage-local lifetimes.
        let tower_build_stage_bytes =
            trace_est.trace_resident_bytes + main_witness_bytes + tower_build_bytes;
        // During tower prove, the replayed witness/device backing has already
        // been cleared, but the built TowerInput buffers remain live and
        // overlap with the fresh create_proof allocations.
        let tower_prove_stage_bytes = tower_prove_peak_bytes;
        let ecc_stage_bytes = trace_est.trace_resident_bytes + ecc_quark_temporary_bytes;
        let main_stage_bytes = trace_est.trace_resident_bytes + main_constraints_temporary_bytes;
        let replay_stage_bytes = trace_est.trace_resident_bytes + trace_est.trace_temporary_bytes;
        let stage_peak = tower_build_stage_bytes
            .max(tower_prove_stage_bytes)
            .max(ecc_stage_bytes)
            .max(main_stage_bytes)
            .max(replay_stage_bytes);
        (
            0usize,
            stage_peak,
            stage_peak + ESTIMATION_SAFETY_MARGIN_BYTES,
        )
    } else {
        // Peak is max across all stages (extraction, tower, ecc, main).
        // Each stage's temporary memory is on top of the resident usage (records + deferred_resident).
        let stage_peak = trace_est
            .trace_temporary_bytes
            .max(tower_temporary_bytes)
            .max(ecc_quark_temporary_bytes)
            .max(main_constraints_temporary_bytes);
        let resident = trace_est.trace_resident_bytes + main_witness_bytes;
        (
            resident,
            stage_peak,
            resident + stage_peak + ESTIMATION_SAFETY_MARGIN_BYTES,
        )
    };

    let to_mb = |bytes: usize| bytes as f64 / (1024.0 * 1024.0);
    // Resident memory (always occupied during chip proof)
    tracing::info!(
        "[mem estimate][{}] resident: trace={:.2}MB, main_witness={:.2}MB",
        circuit_name,
        to_mb(if replay_stage_split {
            0
        } else {
            trace_est.trace_resident_bytes
        }),
        to_mb(if replay_stage_split {
            0
        } else {
            main_witness_bytes
        }),
    );
    // Temporary memory per stage (only one active at a time, peak = max)
    tracing::info!(
        "[mem estimate][{}] temporary: extract_trace={:.2}MB, ecc_quark={:.2}MB, build_tower={:.2}MB, prove_tower={:.2}MB, prove_main={:.2}MB",
        circuit_name,
        to_mb(trace_est.trace_temporary_bytes),
        to_mb(ecc_quark_temporary_bytes),
        to_mb(tower_build_bytes),
        to_mb(tower_prove_peak_bytes),
        to_mb(main_constraints_temporary_bytes),
    );
    // Total peak = resident + max(stage temporaries)
    tracing::info!(
        "[mem estimate][{}] total_usage={:.2}MB (resident={:.2}MB + temporary={:.2}MB)",
        circuit_name,
        to_mb(total_usage_bytes),
        to_mb(resident_bytes),
        to_mb(stage_peak_usage_bytes),
    );

    total_usage_bytes as u64
}

pub(crate) struct TraceEstimate {
    /// Persistent resident bytes (witness polys + structural MLEs)
    pub(crate) trace_resident_bytes: usize,
    /// Temporary peak during get_trace extraction (freed after)
    pub(crate) trace_temporary_bytes: usize,
}

/// Estimate GPU memory for structural MLEs (fixed circuit wiring polynomials).
pub(crate) fn estimate_structural_mle_bytes(num_structural_witin: usize, num_vars: usize) -> usize {
    let base_elem_size = std::mem::size_of::<BB31Base>();
    let mle_len = 1usize << num_vars;
    num_structural_witin * mle_len * base_elem_size
}

pub fn estimate_replay_materialization_bytes(
    num_witin: usize,
    num_structural_witin: usize,
    num_vars: usize,
) -> usize {
    let base_elem_size = std::mem::size_of::<BB31Base>();
    let mle_len = 1usize << num_vars;
    (num_witin + num_structural_witin) * mle_len * base_elem_size
}

pub fn estimate_replay_materialization_bytes_for_plan<E: ExtensionField>(
    replay_plan: &GpuReplayPlan<E>,
    _num_vars: usize,
) -> usize {
    let elem_size = std::mem::size_of::<BB31Base>();
    let witness_bytes = replay_plan.trace_height * replay_plan.num_witin * elem_size;
    let structural_bytes = match replay_plan.kind {
        // Standard opcode replay rebuilds structural witness on CPU and only
        // uploads it later in `transport_structural_witness_to_gpu`, so the
        // replay scope itself should not charge structural GPU bytes.
        GpuWitgenKind::Keccak | GpuWitgenKind::ShardRam => {
            replay_plan.trace_height * replay_plan.num_structural_witin * elem_size
        }
        _ => 0,
    };
    let base_bytes = witness_bytes + structural_bytes;
    let standard_indices_temp_bytes = match replay_plan.kind {
        GpuWitgenKind::Keccak | GpuWitgenKind::ShardRam => 0,
        _ => replay_plan.step_indices.len() * std::mem::size_of::<u32>(),
    };
    let keccak_instances_temp_bytes = match replay_plan.kind {
        GpuWitgenKind::Keccak => replay_plan
            .keccak_instances
            .as_ref()
            .map(|instances| {
                instances.len()
                    * std::mem::size_of::<ceno_gpu::common::witgen::types::GpuKeccakInstance>()
            })
            .unwrap_or(0),
        _ => 0,
    };

    match replay_plan.kind {
        GpuWitgenKind::ShardRam => {
            let n = replay_plan.shard_ram_num_records.next_power_of_two();
            // ShardRam replay constructs an EC tree on GPU from the device records.
            // Peak temp occurs at the first layer when cur_x/cur_y and next_x/next_y
            // coexist. Each point coordinate stores 7 BabyBear limbs.
            let ec_tree_temp_bytes = (2 * n * 7 * elem_size) + (2 * (n / 2) * 7 * elem_size);
            base_bytes + ec_tree_temp_bytes
        }
        _ => base_bytes + standard_indices_temp_bytes + keccak_instances_temp_bytes,
    }
}

pub(crate) fn estimate_trace_bytes<E: ExtensionField, PCS: PolynomialCommitmentScheme<E>>(
    composed_cs: &ComposedConstrainSystem<E>,
    input: &ProofInput<'_, GpuBackend<E, PCS>>,
    witness_replayable: bool,
) -> TraceEstimate {
    let cs = &composed_cs.zkvm_v1_css;
    let num_var_with_rotation =
        input.log2_num_instances() + composed_cs.rotation_vars().unwrap_or(0);

    let structural_mle_bytes =
        estimate_structural_mle_bytes(cs.num_structural_witin as usize, num_var_with_rotation);
    let (witness_mle_bytes, trace_temporary_bytes) = estimate_trace_extraction_bytes(
        cs.num_witin as usize,
        num_var_with_rotation,
        witness_replayable,
    );

    TraceEstimate {
        trace_resident_bytes: witness_mle_bytes + structural_mle_bytes,
        trace_temporary_bytes,
    }
}

pub fn estimate_main_witness_bytes<E: ExtensionField>(
    composed_cs: &ComposedConstrainSystem<E>,
    num_var_with_rotation: usize,
) -> usize {
    let cs = &composed_cs.zkvm_v1_css;
    let num_reads = cs.r_expressions.len() + cs.r_table_expressions.len();
    let num_writes = cs.w_expressions.len() + cs.w_table_expressions.len();
    let num_lk_num = cs.lk_table_expressions.len();
    let num_lk_den = if !cs.lk_table_expressions.is_empty() {
        cs.lk_table_expressions.len()
    } else {
        cs.lk_expressions.len()
    };
    let num_records = num_reads + num_writes + num_lk_num + num_lk_den;

    let elem_size = std::mem::size_of::<BB31Ext>();
    let record_len = 1usize << num_var_with_rotation;
    num_records * record_len * elem_size
}

pub(crate) fn estimate_main_constraints_bytes<
    E: ExtensionField,
    PCS: PolynomialCommitmentScheme<E>,
>(
    composed_cs: &ComposedConstrainSystem<E>,
    input: &ProofInput<'_, GpuBackend<E, PCS>>,
) -> usize {
    let Some(gkr_circuit) = composed_cs.gkr_circuit.as_ref() else {
        return 0;
    };
    let num_var_with_rotation =
        input.log2_num_instances() + composed_cs.rotation_vars().unwrap_or(0);
    let elem_size = std::mem::size_of::<BB31Ext>();
    let eq_len = 1usize << num_var_with_rotation;

    let max_eqs = gkr_circuit
        .layers
        .iter()
        .map(|layer| {
            let rotation_extra = if layer.rotation_sumcheck_expression_monomial_terms.is_some() {
                3
            } else {
                0
            };
            layer.out_sel_and_eval_exprs.len() + rotation_extra
        })
        .max()
        .unwrap_or(0);

    let eqs_bytes = max_eqs * eq_len * elem_size;

    let (main_sumcheck_bytes, rotation_sumcheck_bytes) = gkr_circuit
        .layers
        .iter()
        .map(|layer| {
            // +1 because the GPU sumcheck monomial terms include eq/selector multiplication,
            // which adds one degree on top of the raw constraint expressions.
            // (see ZerocheckLayer verifier: max_degree = self.max_expr_degree + 1)
            let main_sumcheck_degree = (layer.max_expr_degree + 1).max(1);

            let total_mles =
                layer.n_witin + layer.n_structural_witin + layer.n_fixed + layer.n_instance;
            let main_mle_num_vars_list = vec![num_var_with_rotation; total_mles];
            let main_est = estimate_sumcheck_memory(
                num_var_with_rotation,
                main_sumcheck_degree,
                &main_mle_num_vars_list,
                elem_size,
            );

            let rotation_exprs_len = layer.rotation_exprs.1.len();
            let rotation_est = if rotation_exprs_len > 0 {
                // Rotation sumcheck degree = 2 (raw rotation degree 1 + selector),
                // but we use main_sumcheck_degree as a safe upper bound.
                let rotation_mles = rotation_exprs_len * 2 + 1;
                let rotation_mle_num_vars_list = vec![num_var_with_rotation; rotation_mles];
                estimate_sumcheck_memory(
                    num_var_with_rotation,
                    main_sumcheck_degree,
                    &rotation_mle_num_vars_list,
                    elem_size,
                )
            } else {
                estimate_sumcheck_memory(0, 1, &[], elem_size)
            };

            (main_est.total_bytes, rotation_est.total_bytes)
        })
        .fold((0usize, 0usize), |(main_max, rot_max), (main, rot)| {
            (main_max.max(main), rot_max.max(rot))
        });

    let sumcheck_bytes = main_sumcheck_bytes.max(rotation_sumcheck_bytes);
    eqs_bytes + sumcheck_bytes
}

fn estimate_tower_stage_components<E: ExtensionField, PCS: PolynomialCommitmentScheme<E>>(
    composed_cs: &ComposedConstrainSystem<E>,
    input: &ProofInput<'_, GpuBackend<E, PCS>>,
) -> (usize, usize, usize) {
    let cs = &composed_cs.zkvm_v1_css;
    let num_prod_towers = composed_cs.num_reads() + composed_cs.num_writes();
    let num_logup_towers = if composed_cs.is_with_lk_table() {
        cs.lk_table_expressions.len()
    } else {
        cs.lk_expressions.len()
    };
    let num_vars = input
        .log2_num_instances()
        .saturating_add(composed_cs.rotation_vars().unwrap_or(0))
        .saturating_sub(1);
    let elem_size = std::mem::size_of::<BB31Ext>();
    let has_logup_numerator = composed_cs.is_with_lk_table();

    let build_est = estimate_build_tower_memory(
        num_prod_towers,
        num_logup_towers,
        num_vars,
        num_vars,
        elem_size,
        has_logup_numerator,
    );
    let prove_est = estimate_prove_tower_memory(
        num_prod_towers,
        num_logup_towers,
        num_vars,
        num_vars,
        NUM_FANIN,
        elem_size,
    );

    let tower_input_live_bytes =
        prove_est.prod_tower_buffer_bytes + prove_est.logup_tower_buffer_bytes;
    let prove_local_bytes = prove_est.total_bytes.saturating_sub(tower_input_live_bytes);

    (build_est.total_bytes, prove_local_bytes, tower_input_live_bytes)
}

/// Estimate temporary GPU memory for the tower proving stage (build + prove).
/// Used by prove_tower_relation to validate against actual mem_tracker measurements.
pub(crate) fn estimate_tower_stage_bytes<E: ExtensionField, PCS: PolynomialCommitmentScheme<E>>(
    composed_cs: &ComposedConstrainSystem<E>,
    input: &ProofInput<'_, GpuBackend<E, PCS>>,
) -> (usize, usize) {
    let (build_bytes, prove_local_bytes, _) = estimate_tower_stage_components(composed_cs, input);
    (build_bytes, prove_local_bytes)
}

pub(crate) fn estimate_tower_bytes<E: ExtensionField, PCS: PolynomialCommitmentScheme<E>>(
    composed_cs: &ComposedConstrainSystem<E>,
    input: &ProofInput<'_, GpuBackend<E, PCS>>,
) -> usize {
    let (build_bytes, prove_local_bytes, tower_input_live_bytes) =
        estimate_tower_stage_components(composed_cs, input);
    build_bytes.max(tower_input_live_bytes + prove_local_bytes)
}

/// Estimate GPU memory for trace extraction (get_trace).
/// Returns `(resident_witness_bytes, temporary_bytes)`:
/// - `resident`: poly copies that remain as witness MLEs after extraction
/// - `temporary`: temp_buffer allocation (2x), freed after extraction
///
/// Returns `(0, 0)` when trace is cached (`CacheLevel::Trace` or `CacheLevel::Full`),
/// When cache is disabled (`CacheLevel::None`, the default), estimates actual allocation costs.
pub(crate) fn estimate_trace_extraction_bytes(
    num_witin: usize,
    num_vars: usize,
    witness_replayable: bool,
) -> (usize, usize) {
    let base_elem_size = std::mem::size_of::<BB31Base>();
    let mle_len = 1usize << num_vars;
    let poly_bytes = num_witin * mle_len * base_elem_size;

    if should_materialize_witness_on_gpu() {
        if should_retain_witness_device_backing_after_commit() {
            // Eager GPU cache path: committed traces stay resident and
            // extraction builds view-based polynomials directly from the
            // already-live device buffer.
            return (0, 0);
        }

        if witness_replayable {
            // Cache-none replay path: the task regenerates one witness/device
            // backing on demand and keeps that col-major buffer resident for the
            // duration of the chip proof. There is no separate extraction temp
            // buffer, but the replayed witness itself must be accounted for as
            // resident task memory.
            return (poly_bytes, 0);
        }

        // GPU witgen alone does not imply replayability. Non-replayable traces
        // still go through basefold::get_trace in cache-none mode, which
        // allocates the extracted witness plus a temporary 2x transpose buffer.
        return (poly_bytes, 2 * poly_bytes);
    }

    if matches!(get_gpu_cache_level(), CacheLevel::None) {
        // Default cache level is None
        // get_trace allocates poly copies (resident) + temp_buffer (2x, freed after)
        (poly_bytes, 2 * poly_bytes)
    } else {
        (0, 0)
    }
}

/// Estimate GPU memory for ecc quark proving, using only the number of variables.
/// This is the variant callable from prove_ec_sum_quark where composed_cs is not available.
pub(crate) fn estimate_ecc_quark_bytes_from_num_vars(n: usize) -> usize {
    let elem_size = std::mem::size_of::<BB31Ext>();
    let base_elem_size = std::mem::size_of::<BB31Base>();
    let full_len = 1usize << n;

    // selector MLEs: sel_add, sel_bypass, sel_export (Ext field, uploaded via mle_host_to_gpu)
    let selector_bytes = 3usize * full_len * elem_size;
    // split batches via mle_filter_even_odd_batch: x0/x1/y0/y1 (Base field, new GPU allocations)
    // Input MLEs have n+1 vars, split produces MLEs with n vars (full_len elements)
    let split_bytes = 4usize * SEPTIC_EXTENSION_DEGREE * full_len * base_elem_size;
    // half batches (x3/y3/s) and final_sum (xp/yp) use batch_mles_take_half
    // which creates views via as_view_chunk — no new GPU allocation

    let base_bytes = selector_bytes + split_bytes;

    let mle_count = 3usize + SEPTIC_EXTENSION_DEGREE * 7;
    let mle_num_vars_list = vec![n; mle_count];
    let sumcheck_est = estimate_sumcheck_memory(n, 4, &mle_num_vars_list, elem_size);

    base_bytes + sumcheck_est.total_bytes
}
