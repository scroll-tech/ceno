use openvm_stark_sdk::config::baby_bear_poseidon2::{D_EF, DIGEST_SIZE, F};

#[repr(C)]
#[derive(Debug, Default)]
pub struct TraceHeight {
    pub air_idx: usize,
    pub log_height: u8,
}

#[repr(C)]
#[derive(Debug, Default)]
pub struct TraceMetadata {
    pub cached_idx: usize,
    pub total_interactions: usize,
}

#[repr(C)]
#[derive(Debug, Default)]
pub struct PublicValueData {
    pub air_idx: usize,
    pub air_num_pvs: usize,
    pub num_airs: usize,
    pub pv_idx: usize,
    pub value: F,
}

#[repr(C)]
#[derive(Debug, Default)]
pub struct AirData {
    pub num_cached: usize,
    pub num_interactions_per_row: usize,
    pub total_width: usize,
    pub has_preprocessed: bool,
}

#[repr(C)]
#[derive(Debug, Default)]
pub struct MainEvalData {
    pub proof_idx: usize,
    pub idx: usize,
    pub eval_idx: usize,
    pub tidx: usize,
    pub value: [F; D_EF],
    pub lookup_count: usize,
}

#[repr(C)]
#[derive(Debug, Default)]
pub struct MainTowerPointEqData {
    pub proof_idx: usize,
    pub idx: usize,
    pub round_idx: usize,
    pub global_value: [F; D_EF],
    pub tower_value: [F; D_EF],
    pub eq_in: [F; D_EF],
    pub eq_out: [F; D_EF],
}

#[repr(C)]
#[derive(Debug, Default)]
pub struct MainFrontloadTermData {
    pub proof_idx: usize,
    pub idx: usize,
    pub row_idx: usize,
    pub node_idx: usize,
    pub eval_idx: usize,
    pub has_eval_factor: bool,
    pub instance_idx: usize,
    pub challenge_idx: usize,
    pub global_round_idx: usize,
    pub has_global_factor: bool,
    pub is_wit: bool,
    pub is_const: bool,
    pub is_instance: bool,
    pub is_challenge: bool,
    pub is_add: bool,
    pub is_sub: bool,
    pub is_neg: bool,
    pub is_mul: bool,
    pub is_fold: bool,
    pub is_tail: bool,
    pub constraint_idx: usize,
    pub alpha: [F; D_EF],
    pub arg0: [F; D_EF],
    pub arg1: [F; D_EF],
    pub value: [F; D_EF],
    pub chip_acc_in: [F; D_EF],
    pub chip_acc_out: [F; D_EF],
    pub is_last_chip_step: bool,
}

#[repr(C)]
#[derive(Debug, Default)]
pub struct PcsJaggedAssistQData {
    pub proof_idx: usize,
    pub round_idx: usize,
    pub sumcheck_idx: usize,
    pub commitment_kind: usize,
    pub term_idx: usize,
    pub step_idx: usize,
    pub robp_idx: usize,
    pub is_first: bool,
    pub is_last: bool,
    pub is_first_step: bool,
    pub is_last_step: bool,
    pub term_is_last: bool,
    pub eq_col: [F; D_EF],
    pub t_lo: usize,
    pub t_hi: usize,
    pub c_bit: bool,
    pub d_bit: bool,
    pub bit_pow2: usize,
    pub c_acc_in: usize,
    pub c_acc_out: usize,
    pub d_acc_in: usize,
    pub d_acc_out: usize,
    pub rho_star_c: [F; D_EF],
    pub rho_star_d: [F; D_EF],
    pub factor: [F; D_EF],
    pub term_acc_in: [F; D_EF],
    pub term_acc_out: [F; D_EF],
    pub q_acc_in: [F; D_EF],
    pub q_acc_out: [F; D_EF],
}

#[repr(C)]
#[derive(Debug, Default)]
pub struct PcsEqProductData {
    pub proof_idx: usize,
    pub kind: usize,
    pub source: usize,
    pub round_idx: usize,
    pub term_idx: usize,
    pub bit_idx: usize,
    pub is_first: bool,
    pub is_last: bool,
    pub lookup_count: usize,
    pub point_tidx: usize,
    pub sumcheck_idx: usize,
    pub point_round: usize,
    pub index_bit: bool,
    pub index_pow2: usize,
    pub index_acc_in: usize,
    pub index_acc_out: usize,
    pub point: [F; D_EF],
    pub acc_in: [F; D_EF],
    pub acc_out: [F; D_EF],
}

#[repr(C)]
#[derive(Debug, Default)]
pub struct PcsSuffixProductData {
    pub proof_idx: usize,
    pub round_idx: usize,
    pub term_idx: usize,
    pub coord_idx: usize,
    pub step_idx: usize,
    pub is_first: bool,
    pub is_last: bool,
    pub has_factor: bool,
    pub point: [F; D_EF],
    pub acc_in: [F; D_EF],
    pub acc_out: [F; D_EF],
}

#[repr(C)]
#[derive(Debug, Default)]
pub struct PcsCommitPhaseMerkleData {
    pub proof_idx: usize,
    pub query_idx: usize,
    pub round: usize,
    pub step: usize,
    pub is_first: bool,
    pub is_last: bool,
    pub idx_in: usize,
    pub idx_bit: usize,
    pub idx_out: usize,
    pub current: [F; DIGEST_SIZE],
    pub sibling: [F; DIGEST_SIZE],
    pub left: [F; DIGEST_SIZE],
    pub right: [F; DIGEST_SIZE],
    pub output: [F; DIGEST_SIZE],
}

#[repr(C)]
#[derive(Debug, Default)]
pub struct TowerSumcheckData {
    pub proof_idx: usize,
    pub idx: usize,
    pub fork_id: usize,
    pub layer_idx: usize,
    pub is_first_idx: bool,
    pub is_first_layer: bool,
    pub is_first_round: bool,
    pub is_dummy: bool,
    pub is_last_layer: bool,
    pub round: usize,
    pub tidx: usize,
    pub ev1: [F; D_EF],
    pub ev2: [F; D_EF],
    pub ev3: [F; D_EF],
    pub claim_in: [F; D_EF],
    pub claim_out: [F; D_EF],
    pub prev_challenge: [F; D_EF],
    pub challenge: [F; D_EF],
    pub eq_in: [F; D_EF],
    pub eq_out: [F; D_EF],
}

#[repr(C)]
#[derive(Debug, Default)]
pub struct MainSelectorFormulaData {
    pub proof_idx: usize,
    pub idx: usize,
    pub tower_idx: usize,
    pub air_idx: usize,
    pub selector_idx: usize,
    pub eval_idx: usize,
    pub kind: usize,
    pub source_kind: usize,
    pub is_whole: bool,
    pub is_prefix: bool,
    pub is_ordered_sparse: bool,
    pub is_quark_binary_tree_less_than: bool,
    pub ctx_offset: usize,
    pub ctx_num_instances: usize,
    pub ctx_num_vars: usize,
    pub ordered_sparse_num_vars: usize,
    pub num_sparse_indices: usize,
    pub step_kind: usize,
    pub step_idx: usize,
    pub is_shape_step: bool,
    pub is_eq_product_step: bool,
    pub is_sparse_index_step: bool,
    pub is_accumulate_step: bool,
    pub is_final_step: bool,
    pub is_multiply_step: bool,
    pub is_quark_step: bool,
    pub is_eq_lte_step: bool,
    pub is_first_eq_lte_step: bool,
    pub is_last_eq_lte_step: bool,
    pub eq_lte_output_to_value: bool,
    pub eq_lte_output_to_acc_in: bool,
    pub eq_lte_output_to_factor: bool,
    pub eq_lte_output_to_neg_factor: bool,
    pub eq_lte_value_is_zero: bool,
    pub is_first_quark_step: bool,
    pub is_last_quark_step: bool,
    pub carry_accumulator: bool,
    pub round_idx: usize,
    pub sparse_pos: usize,
    pub sparse_index: usize,
    pub sparse_index_bits_value: usize,
    pub point_active: bool,
    pub lhs_point: [F; D_EF],
    pub rhs_point: [F; D_EF],
    pub factor: [F; D_EF],
    pub acc_in: [F; D_EF],
    pub acc_out: [F; D_EF],
    pub aux: [F; D_EF],
    pub aux2: [F; D_EF],
    pub aux3: [F; D_EF],
    pub value: [F; D_EF],
}
