use openvm_poseidon2_air::POSEIDON2_WIDTH;
use openvm_stark_backend::TranscriptLog;
use openvm_stark_sdk::config::baby_bear_poseidon2::{EF, F};

use crate::tower::TowerReplayResult;

/// Placeholder types mirroring upstream recursion preflight records.
/// These will be populated with real transcript metadata once the
/// ZKVM bridge is fully implemented.
#[derive(Clone, Debug, Default)]
pub struct Preflight {
    pub transcript: TranscriptLog<F, PoseidonWord>,
    pub proof_shape: ProofShapePreflight,
    pub main: MainPreflight,
    pub gkr: TowerPreflight,
    pub batch_constraint: BatchConstraintPreflight,
}

#[derive(Clone, Debug, Default)]
pub struct ProofShapePreflight {
    pub sorted_trace_vdata: Vec<(usize, TraceVData)>,
    pub l_skip: usize,
}

#[derive(Clone, Debug, Default)]
pub struct TraceVData {
    pub log_height: usize,
}

#[derive(Clone, Debug, Default)]
pub struct MainPreflight {
    pub chips: Vec<ChipTranscriptRange>,
}

#[derive(Clone, Debug, Default)]
pub struct TowerPreflight {
    pub chips: Vec<TowerChipTranscriptRange>,
}

#[derive(Clone, Debug, Default)]
pub struct TowerChipTranscriptRange {
    pub chip_idx: usize,
    pub tidx: usize,
    pub tower_replay: TowerReplayResult,
}

#[derive(Clone, Debug, Default)]
pub struct BatchConstraintPreflight {
    pub lambda_tidx: usize,
    pub tidx_before_univariate: usize,
    pub sumcheck_rnd: Vec<F>,
    pub eq_ns_frontloaded: Vec<EF>,
    pub eq_sharp_ns_frontloaded: Vec<EF>,
}

#[derive(Clone, Debug, Default)]
pub struct ChipTranscriptRange {
    pub chip_idx: usize,
    pub tidx: usize,
}

#[allow(dead_code)]
pub type PoseidonWord = [F; POSEIDON2_WIDTH];
