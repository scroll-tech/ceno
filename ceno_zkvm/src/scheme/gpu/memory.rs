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
use gkr_iop::gpu::{ArcMultilinearExtensionGpu, BB31Base, GpuBackend, gpu_prover::BB31Ext};
use mpcs::PolynomialCommitmentScheme;

/// Estimate GPU memory for chip proof using stage-based peak estimation.
/// Called at task creation time (doesn't need records).
pub fn estimate_chip_proof_memory<E: ExtensionField, PCS: PolynomialCommitmentScheme<E>>(
    composed_cs: &ComposedConstrainSystem<E>,
    input: &ProofInput<'_, GpuBackend<E, PCS>>,
    circuit_name: &str,
) -> u64 {
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

    let records_bytes = estimate_records_bytes(composed_cs, input);

    // Deferred witness + structural witness MLEs (base field, allocated at execution time).
    // Memory cost depends on GPU cache level set during batch_commit:
    //   "full"/"trace" (default): trace cached on GPU, get_trace creates views → zero extra
    //   "none": trace not cached, get_trace allocates temp_buffer(2x) + poly copies
    // Structural witness is always CPU→GPU transport regardless of cache level.
    let num_var_with_rotation = input.log2_num_instances()
        + composed_cs.rotation_vars().unwrap_or(0);
    let base_elem_size = std::mem::size_of::<BB31Base>();
    let mle_len = 1usize << num_var_with_rotation;

    let structural_mle_bytes =
        cs.num_structural_witin as usize * mle_len * base_elem_size;

    let cache_level =
        std::env::var("CENO_GPU_CACHE_LEVEL").unwrap_or_else(|_| "full".to_string());
    let has_trace_cached = matches!(cache_level.as_str(), "2" | "full" | "1" | "trace");

    // witness_resident: persistent poly allocations that stay for the rest of the task
    // witness_extraction_extra: temporary peak during get_trace (temp_buffer, freed after)
    let (witness_resident_bytes, witness_extraction_extra_bytes) = if has_trace_cached {
        (0usize, 0usize)
    } else {
        // cache_none: get_trace extracts from CPU RMM via extract_poly_group_from_rmm
        //   temp_buffer = 2 * mle_len * num_witin (htod copy + transpose, freed after)
        //   poly allocs = mle_len * num_witin (persistent)
        let poly_bytes = cs.num_witin as usize * mle_len * base_elem_size;
        let temp_bytes = 2 * poly_bytes;
        (poly_bytes, temp_bytes)
    };

    let deferred_resident_bytes = witness_resident_bytes + structural_mle_bytes;

    // Tower estimate here excludes records; it represents additional buffers.
    let tower_extra_bytes = build_est.total_bytes + prove_est.total_bytes;
    let ecc_quark_extra_bytes = estimate_ecc_quark_bytes(composed_cs, input);
    let main_constraints_extra_bytes = estimate_main_constraints_bytes(composed_cs, input);
    // Peak is max across all stages (extraction, tower, ecc, main).
    // Each stage's extra is on top of the resident base (records + deferred_resident).
    let stage_peak = witness_extraction_extra_bytes
        .max(tower_extra_bytes)
        .max(ecc_quark_extra_bytes)
        .max(main_constraints_extra_bytes);

    let total_peak = records_bytes + deferred_resident_bytes + stage_peak;

    tracing::debug!(
        "[estimate][{}] records={:.2}MB, deferred_resident={:.2}MB (wit={:.2}MB, struct={:.2}MB), extraction_extra={:.2}MB, tower_extra={:.2}MB (build={:.2}MB, prove={:.2}MB), ecc_quark_extra={:.2}MB, main_constraints_extra={:.2}MB, peak={:.2}MB (cache={})",
        circuit_name,
        records_bytes as f64 / (1024.0 * 1024.0),
        deferred_resident_bytes as f64 / (1024.0 * 1024.0),
        witness_resident_bytes as f64 / (1024.0 * 1024.0),
        structural_mle_bytes as f64 / (1024.0 * 1024.0),
        witness_extraction_extra_bytes as f64 / (1024.0 * 1024.0),
        tower_extra_bytes as f64 / (1024.0 * 1024.0),
        build_est.total_bytes as f64 / (1024.0 * 1024.0),
        prove_est.total_bytes as f64 / (1024.0 * 1024.0),
        ecc_quark_extra_bytes as f64 / (1024.0 * 1024.0),
        main_constraints_extra_bytes as f64 / (1024.0 * 1024.0),
        total_peak as f64 / (1024.0 * 1024.0),
        cache_level,
    );

    total_peak as u64
}

fn estimate_records_bytes<E: ExtensionField, PCS: PolynomialCommitmentScheme<E>>(
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

/// Combined memory estimate for tower operations (build + prove).
pub struct TowerMemoryEstimate {
    pub build: ceno_gpu::BuildTowerWitnessMemoryEstimate,
    pub prove: ceno_gpu::ProveTowerMemoryEstimate,
    /// Total combined bytes for both build and prove phases
    pub total_bytes: usize,
}

/// Estimate memory requirements for both build_tower_witness_gpu and prove_tower_relation.
/// Returns combined estimates that can be used to check available GPU memory before allocation.
pub(super) fn estimate_tower_memory<E: ExtensionField>(
    composed_cs: &ComposedConstrainSystem<E>,
    records: &[ArcMultilinearExtensionGpu<'_, E>],
) -> TowerMemoryEstimate {
    let ComposedConstrainSystem {
        zkvm_v1_css: cs, ..
    } = composed_cs;

    // Parse records offsets (same logic as build_tower_witness_gpu)
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

    // Calculate estimate parameters
    let num_prod_towers = num_reads + num_writes;
    let num_logup_towers = if !cs.lk_table_expressions.is_empty() {
        cs.lk_table_expressions.len()
    } else {
        cs.lk_expressions.len()
    };
    let prod_num_vars = if !r_set_wit.is_empty() {
        r_set_wit[0].mle.num_vars().saturating_sub(1)
    } else if !w_set_wit.is_empty() {
        w_set_wit[0].mle.num_vars().saturating_sub(1)
    } else {
        0
    };
    let logup_num_vars = if !lk_n_wit.is_empty() {
        lk_n_wit[0].mle.num_vars().saturating_sub(1)
    } else if !lk_d_wit.is_empty() {
        lk_d_wit[0].mle.num_vars().saturating_sub(1)
    } else {
        0
    };
    let has_logup_numerator = !lk_n_wit.is_empty();

    let elem_size = std::mem::size_of::<BB31Ext>();

    // Estimate build phase memory
    let build = estimate_build_tower_witness_memory(
        num_prod_towers,
        num_logup_towers,
        prod_num_vars,
        logup_num_vars,
        elem_size,
        has_logup_numerator,
    );

    // Estimate prove phase memory (use_v2 = true as in create_proof)
    let prove = estimate_prove_tower_memory(
        num_prod_towers,
        num_logup_towers,
        prod_num_vars,
        logup_num_vars,
        NUM_FANIN,
        elem_size,
        true, // use_v2
    );

    // Build and prove phases overlap: build allocates buffers, prove uses them + additional
    // Peak memory is max of (build alone) or (build buffers retained + prove additional)
    let total_bytes = build.total_bytes + prove.total_bytes;

    TowerMemoryEstimate {
        build,
        prove,
        total_bytes,
    }
}
