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
    /// Per-fork transcript logs. Each entry corresponds to one forked transcript
    /// chain (fork_id 1..N), keyed by fork index. The trunk is stored in
    /// `transcript` above.
    pub fork_transcripts: Vec<ForkTranscriptLog>,
    pub proof_shape: ProofShapePreflight,
    pub main: MainPreflight,
    pub gkr: TowerPreflight,
    pub batch_constraint: BatchConstraintPreflight,
}

impl Preflight {
    /// Given a global tidx, return the appropriate transcript log and
    /// the local position within that log.
    ///
    /// - If tidx < trunk_len, returns the trunk log with tidx unchanged.
    /// - Otherwise, finds the fork containing this tidx and returns
    ///   (fork_log, tidx - fork.global_tidx_offset).
    pub fn transcript_log_for_tidx(
        &self,
        tidx: usize,
    ) -> (&TranscriptLog<F, PoseidonWord>, usize) {
        let trunk_len = self.transcript.len();
        if tidx < trunk_len {
            return (&self.transcript, tidx);
        }
        for fork in &self.fork_transcripts {
            let fork_end = fork.global_tidx_offset + fork.log.len();
            if tidx >= fork.global_tidx_offset && tidx < fork_end {
                return (&fork.log, tidx - fork.global_tidx_offset);
            }
        }
        panic!(
            "tidx {tidx} out of range (trunk_len={trunk_len}, {} forks)",
            self.fork_transcripts.len()
        );
    }
}

/// A single forked transcript chain with its initial sponge state.
#[derive(Clone, Debug)]
pub struct ForkTranscriptLog {
    /// The log of observe/sample operations in this fork.
    pub log: TranscriptLog<F, PoseidonWord>,
    /// The sponge state this fork inherits from the trunk (after observing
    /// the fork index into it).
    pub initial_state: PoseidonWord,
    /// The fork identifier (1-based: fork 0 = trunk, 1..N = chip forks).
    pub fork_id: usize,
    /// Global tidx offset for this fork's first operation (position in the
    /// unified tidx space: trunk_len + sum of previous forks' lengths).
    pub global_tidx_offset: usize,
}

#[derive(Clone, Debug, Default)]
pub struct ProofShapePreflight {
    pub sorted_trace_vdata: Vec<(usize, TraceVData)>,
    pub starting_tidx: Vec<usize>,
    pub starting_cidx: Vec<usize>,
    pub pvs_tidx: Vec<usize>,
    pub post_tidx: usize,
    pub n_max: usize,
    pub n_logup: usize,
    pub l_skip: usize,
    pub fork_start_tidx: usize,
    pub alpha_tidx: usize,
    pub beta_tidx: usize,
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
    pub instance_idx: usize,
    pub tidx: usize,
}

#[allow(dead_code)]
pub type PoseidonWord = [F; POSEIDON2_WIDTH];
