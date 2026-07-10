use openvm_stark_sdk::config::baby_bear_poseidon2::{D_EF, F};

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
pub struct MainFinalClaimData {
    pub proof_idx: usize,
    pub idx: usize,
    pub contribution: [F; D_EF],
    pub acc_in: [F; D_EF],
    pub acc_out: [F; D_EF],
    pub expected: [F; D_EF],
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
    pub is_next_term: bool,
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
