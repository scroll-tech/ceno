use openvm_poseidon2_air::POSEIDON2_WIDTH;
use openvm_stark_backend::TranscriptLog;
use openvm_stark_sdk::config::baby_bear_poseidon2::F;

/// Placeholder types mirroring upstream recursion preflight records.
/// These will be populated with real transcript metadata once the
/// ZKVM bridge is fully implemented.
#[derive(Clone, Debug, Default)]
pub struct Preflight {
    pub transcript: TranscriptLog<F, PoseidonWord>,
    pub proof_shape: ProofShapePreflight,
    pub main: MainPreflight,
    pub gkr: GkrPreflight,
    pub batch_constraint: BatchConstraintPreflight,
}

#[derive(Clone, Debug, Default)]
pub struct ProofShapePreflight;

#[derive(Clone, Debug, Default)]
pub struct MainPreflight {
    pub chips: Vec<ChipTranscriptRange>,
}

#[derive(Clone, Debug, Default)]
pub struct GkrPreflight {
    pub chips: Vec<ChipTranscriptRange>,
}

#[derive(Clone, Debug, Default)]
pub struct BatchConstraintPreflight;

#[derive(Clone, Debug, Default)]
pub struct ChipTranscriptRange {
    pub chip_idx: usize,
    pub tidx: usize,
}

#[allow(dead_code)]
pub type PoseidonWord = [F; POSEIDON2_WIDTH];
