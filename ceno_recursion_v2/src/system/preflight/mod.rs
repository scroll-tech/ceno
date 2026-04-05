use openvm_poseidon2_air::POSEIDON2_WIDTH;
use openvm_stark_backend::TranscriptLog;
use openvm_stark_sdk::config::baby_bear_poseidon2::{D_EF, EF, F};

use crate::tower::TowerReplayResult;

/// Placeholder types mirroring upstream recursion preflight records.
/// These will be populated with real transcript metadata once the
/// ZKVM bridge is fully implemented.
#[derive(Clone, Debug, Default)]
pub struct Preflight {
    pub transcript: TranscriptLog<F, PoseidonWord>,
    /// Per-fork transcript logs. Each entry corresponds to one forked transcript
    /// chain (fork_id 1..N), keyed by fork index. The trunk is stored in
    /// `transcript` above.
    pub fork_transcripts: Vec<ForkTranscriptLog>,
    pub proof_shape: ProofShapePreflight,
    pub main: MainPreflight,
    pub gkr: TowerPreflight,
    pub batch_constraint: BatchConstraintPreflight,
    pub vm_pvs: VmPvsPreflight,
}

impl Preflight {
    /// Return the transcript log for a given fork index.
    pub fn fork_log(&self, fork_idx: usize) -> &TranscriptLog<F, PoseidonWord> {
        &self.fork_transcripts[fork_idx].log
    }

    /// Compute the global tidx offset for a fork, on the fly.
    ///
    /// Global layout: trunk 0..trunk_len, fork0, fork1, ...
    /// The offset for fork_idx is trunk_len + sum of preceding fork log lengths.
    pub fn fork_global_offset(&self, fork_idx: usize) -> usize {
        let trunk_len = self.transcript.len();
        let preceding: usize = self.fork_transcripts[..fork_idx]
            .iter()
            .map(|f| f.log.len())
            .sum();
        trunk_len + preceding
    }
}

/// A single forked transcript chain.
#[derive(Clone, Debug)]
pub struct ForkTranscriptLog {
    /// The log of observe/sample operations in this fork.
    pub log: TranscriptLog<F, PoseidonWord>,
    /// The fork identifier (0-based across forked chip transcripts).
    pub fork_id: usize,
}

#[derive(Clone, Debug, Default)]
pub struct ProofShapePreflight {
    pub sorted_trace_vdata: Vec<(usize, TraceVData)>,
    pub starting_tidx: Vec<usize>,
    pub post_tidx: usize,
    pub n_max: usize,
    pub n_logup: usize,
    // TODO remove l_skip
    pub l_skip: usize,
    pub fork_start_tidx: usize,
    pub lookup_challenge_alpha: [F; D_EF],
    pub lookup_challenge_beta: [F; D_EF],
    pub after_forked_challenge_1: EF,
    pub after_forked_challenge_2: EF,
}

#[derive(Clone, Debug, Default)]
pub struct VmPvsPreflight {
    pub lookup_challenge_alpha: EF,
    pub lookup_challenge_beta: EF,
    pub lookup_challenge_alpha_lookup_count: usize,
    pub lookup_challenge_beta_lookup_count: usize,
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
    pub instance_idx: usize,
    /// Fork-local tidx (position within the fork's transcript log).
    pub tidx: usize,
    /// Index into `Preflight::fork_transcripts`.
    pub fork_idx: usize,
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
    pub instance_idx: usize,
    /// Fork-local tidx (position within the fork's transcript log).
    pub tidx: usize,
    /// Index into `Preflight::fork_transcripts`.
    pub fork_idx: usize,
}

#[allow(dead_code)]
pub type PoseidonWord = [F; POSEIDON2_WIDTH];
