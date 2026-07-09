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
