use openvm_poseidon2_air::POSEIDON2_WIDTH;
use openvm_stark_sdk::config::baby_bear_poseidon2::F;

/// Placeholder types mirroring upstream recursion preflight records.
/// These will be populated with real transcript metadata once the
/// ZKVM bridge is fully implemented.
#[derive(Clone, Debug, Default)]
pub struct Preflight;

#[derive(Clone, Debug, Default)]
pub struct ProofShapePreflight;

#[derive(Clone, Debug, Default)]
pub struct GkrPreflight;

#[allow(dead_code)]
pub type PoseidonWord = [F; POSEIDON2_WIDTH];
