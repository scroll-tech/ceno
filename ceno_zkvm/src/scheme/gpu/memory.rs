use crate::{
    scheme::{
        constants::{NUM_FANIN, SEPTIC_EXTENSION_DEGREE},
        hal::ProofInput,
    },
    structs::ComposedConstrainSystem,
};
use ceno_gpu::{
    estimate_build_tower_witness_memory, estimate_prove_tower_memory, estimate_sumcheck_memory,
};
use ff_ext::ExtensionField;
use gkr_iop::gpu::{BB31Base, GpuBackend, gpu_prover::BB31Ext};
use mpcs::PolynomialCommitmentScheme;

/// Pre-estimate GPU memory usage for a chip proof before actual execution.
/// Used by the concurrent proving scheduler to reserve VRAM from the GPU memory pool,
/// ensuring multiple chip proofs can run in parallel without OOM.
pub fn estimate_chip_proof_memory<E: ExtensionField, PCS: PolynomialCommitmentScheme<E>>(
    composed_cs: &ComposedConstrainSystem<E>,
    input: &ProofInput<'_, GpuBackend<E, PCS>>,
    circuit_name: &str,
) -> u64 {
    // chip parameters
    let cs = &composed_cs.zkvm_v1_css;
    let num_prod_towers = composed_cs.num_reads() + composed_cs.num_writes();
    let num_logup_towers = if composed_cs.is_with_lk_table() {
        cs.lk_table_expressions.len()
    } else {
        cs.lk_expressions.len()
    };
    // num_vars is log2_num_instances (+ rotation) - 1 (tower reduces by 1 layer for fanin=2)
    let num_vars = input
        .log2_num_instances()
        .saturating_add(composed_cs.rotation_vars().unwrap_or(0))
        .saturating_sub(1);
    let elem_size = std::mem::size_of::<BB31Ext>();
    let has_logup_numerator = composed_cs.is_with_lk_table();

    // Part 1: trace (base usage: witness & structural mles)
    let trace_est = estimate_trace_bytes(composed_cs, input);

    // Part 2: main witness (base usage)
    let main_witness_bytes = estimate_main_witness_bytes(composed_cs, input);

    // Part 3: ecc quark (temporary usage)
    let ecc_quark_temporary_bytes = estimate_ecc_quark_bytes(composed_cs, input);

    // Part 4: build & prove tower (temporary usage)
    let build_est = estimate_build_tower_witness_memory(
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
        true,
    );
    let tower_temporary_bytes = build_est.total_bytes + prove_est.total_bytes;

    // Part 5: main constraints (temporary usage)
    let main_constraints_temporary_bytes = estimate_main_constraints_bytes(composed_cs, input);

    // Peak is max across all stages (extraction, tower, ecc, main).
    // Each stage's temporary memory is on top of the resident usage (records + deferred_resident).
    let stage_peak_usage_bytes = trace_est
        .trace_temporary_bytes
        .max(tower_temporary_bytes)
        .max(ecc_quark_temporary_bytes)
        .max(main_constraints_temporary_bytes);
    
    let total_usage_bytes = trace_est.trace_resident_bytes + main_witness_bytes + stage_peak_usage_bytes;

    let to_mb = |bytes: usize| bytes as f64 / (1024.0 * 1024.0);
    // Resident memory (always occupied during chip proof)
    tracing::info!(
        "[mem estimate][{}] resident: trace={:.2}MB, main_witness={:.2}MB",
        circuit_name,
        to_mb(trace_est.trace_resident_bytes),
        to_mb(main_witness_bytes),
    );
    // Temporary memory per stage (only one active at a time, peak = max)
    tracing::info!(
        "[mem estimate][{}] temporary: extract_trace={:.2}MB, ecc_quark={:.2}MB, prove_tower={:.2}MB,  prove_main={:.2}MB",
        circuit_name,
        to_mb(trace_est.trace_temporary_bytes),
        to_mb(ecc_quark_temporary_bytes),
        to_mb(tower_temporary_bytes),
        to_mb(main_constraints_temporary_bytes),
    );
    // Total peak = resident + max(stage temporaries)
    tracing::info!(
        "[mem estimate][{}] total_usage={:.2}MB (resident={:.2}MB + stage_peak={:.2}MB)",
        circuit_name,
        to_mb(total_usage_bytes),
        to_mb(trace_est.trace_resident_bytes + main_witness_bytes),
        to_mb(stage_peak_usage_bytes),
    );

    total_usage_bytes as u64
}

struct TraceEstimate {
    /// Persistent resident bytes (witness polys + structural MLEs)
    trace_resident_bytes: usize,
    /// Temporary peak during get_trace extraction (freed after)
    trace_temporary_bytes: usize,
}

fn estimate_trace_bytes<E: ExtensionField, PCS: PolynomialCommitmentScheme<E>>(
    composed_cs: &ComposedConstrainSystem<E>,
    input: &ProofInput<'_, GpuBackend<E, PCS>>,
) -> TraceEstimate {
    let cs = &composed_cs.zkvm_v1_css;
    let cache_level =
        std::env::var("CENO_GPU_CACHE_LEVEL").unwrap_or_else(|_| "full".to_string());
    let has_trace_cached = matches!(cache_level.as_str(), "2" | "full" | "1" | "trace");

    let num_var_with_rotation =
        input.log2_num_instances() + composed_cs.rotation_vars().unwrap_or(0);
    let base_elem_size = std::mem::size_of::<BB31Base>();
    let mle_len = 1usize << num_var_with_rotation;
    let structural_mle_bytes = cs.num_structural_witin as usize * mle_len * base_elem_size;

    // Memory cost depends on GPU cache level set during batch_commit:
    //   "full"/"trace" (default): trace cached on GPU, get_trace creates views → no additional usage
    //   "none": trace not cached, get_trace allocates temp_buffer(2x) + poly copies
    let (witness_mle_bytes, trace_temporary_bytes) = if has_trace_cached {
        (0usize, 0usize)
    } else {
        let poly_bytes = cs.num_witin as usize * mle_len * base_elem_size;
        let temp_bytes = 2 * poly_bytes;
        (poly_bytes, temp_bytes)
    };

    let trace_resident_bytes = witness_mle_bytes + structural_mle_bytes;

    TraceEstimate {
        trace_resident_bytes,
        trace_temporary_bytes,
    }
}

fn estimate_main_witness_bytes<E: ExtensionField, PCS: PolynomialCommitmentScheme<E>>(
    composed_cs: &ComposedConstrainSystem<E>,
    input: &ProofInput<'_, GpuBackend<E, PCS>>,
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

    let num_var_with_rotation = input.log2_num_instances()
        + composed_cs.rotation_vars().unwrap_or(0);
    let elem_size = std::mem::size_of::<BB31Ext>();
    let record_len = 1usize << num_var_with_rotation;
    num_records * record_len * elem_size
}

fn estimate_ecc_quark_bytes<E: ExtensionField, PCS: PolynomialCommitmentScheme<E>>(
    composed_cs: &ComposedConstrainSystem<E>,
    input: &ProofInput<'_, GpuBackend<E, PCS>>,
) -> usize {
    let cs = &composed_cs.zkvm_v1_css;
    if cs.ec_final_sum.is_empty() {
        return 0;
    }

    let n = input.log2_num_instances().saturating_sub(1);
    let elem_size = std::mem::size_of::<BB31Ext>();
    let full_len = 1usize << n;
    let half_len = 1usize << n.saturating_sub(1);

    // selector MLEs: sel_add, sel_bypass, sel_export
    let selector_bytes = 3usize * full_len * elem_size;
    // split batches: x0/x1/y0/y1 (SEPTIC_EXTENSION_DEGREE each)
    let split_bytes = 4usize * SEPTIC_EXTENSION_DEGREE * half_len * elem_size;
    // half batches: x3/y3/s (SEPTIC_EXTENSION_DEGREE each)
    let half_bytes = 3usize * SEPTIC_EXTENSION_DEGREE * half_len * elem_size;
    // final_sum extraction uses another half-batch for xp/yp
    let final_sum_bytes = 2usize * SEPTIC_EXTENSION_DEGREE * half_len * elem_size;

    let base_bytes = selector_bytes + split_bytes + half_bytes + final_sum_bytes;

    let mle_count = 3usize + SEPTIC_EXTENSION_DEGREE * 7;
    let mle_num_vars_list = vec![n; mle_count];
    let sumcheck_est = estimate_sumcheck_memory(n, 4, &mle_num_vars_list, elem_size, true);

    base_bytes + sumcheck_est.total_bytes
}

fn estimate_main_constraints_bytes<E: ExtensionField, PCS: PolynomialCommitmentScheme<E>>(
    composed_cs: &ComposedConstrainSystem<E>,
    input: &ProofInput<'_, GpuBackend<E, PCS>>,
) -> usize {
    let Some(gkr_circuit) = composed_cs.gkr_circuit.as_ref() else {
        return 0;
    };
    let num_var_with_rotation = input.log2_num_instances()
        + composed_cs.rotation_vars().unwrap_or(0);
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
            let total_mles =
                layer.n_witin + layer.n_structural_witin + layer.n_fixed + layer.n_instance;
            let main_mle_num_vars_list = vec![num_var_with_rotation; total_mles];
            let main_est = estimate_sumcheck_memory(
                num_var_with_rotation,
                layer.max_expr_degree.max(1),
                &main_mle_num_vars_list,
                elem_size,
                true,
            );

            let rotation_exprs_len = layer.rotation_exprs.1.len();
            let rotation_est = if rotation_exprs_len > 0 {
                let rotation_mles = rotation_exprs_len * 2 + 1;
                let rotation_mle_num_vars_list = vec![num_var_with_rotation; rotation_mles];
                estimate_sumcheck_memory(
                    num_var_with_rotation,
                    layer.max_expr_degree.max(1),
                    &rotation_mle_num_vars_list,
                    elem_size,
                    true,
                )
            } else {
                estimate_sumcheck_memory(0, 1, &[], elem_size, true)
            };

            (main_est.total_bytes, rotation_est.total_bytes)
        })
        .fold((0usize, 0usize), |(main_max, rot_max), (main, rot)| {
            (main_max.max(main), rot_max.max(rot))
        });

    let sumcheck_bytes = main_sumcheck_bytes.max(rotation_sumcheck_bytes);
    eqs_bytes + sumcheck_bytes
}
