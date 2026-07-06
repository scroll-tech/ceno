use openvm_poseidon2_air::POSEIDON2_WIDTH;
use openvm_stark_backend::TranscriptLog;
use openvm_stark_sdk::config::baby_bear_poseidon2::{D_EF, EF, F};

use crate::{system::RecursionField, tower::TowerReplayResult};

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
    pub lookup_challenge_alpha_tidx: usize,
    pub lookup_challenge_beta_tidx: usize,
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
    pub transcript_start: usize,
    pub transcript_end: usize,
    pub global_sumchecks: Vec<MainGlobalSumcheckRecord>,
    pub evals: Vec<MainEvalRecord>,
    pub selector_evals: Vec<MainSelectorEvalRecord>,
    pub selector_points: Vec<MainSelectorPointRecord>,
    pub tower_point_eqs: Vec<MainTowerPointEqRecord>,
    pub frontload_terms: Vec<MainFrontloadTermRecord>,
    pub final_claims: Vec<MainFinalClaimRecord>,
}

#[derive(Clone, Debug, Default)]
pub struct MainTranscriptRecord {
    pub proof_idx: usize,
    pub fork_id: usize,
    pub is_fork: bool,
    pub tidx: usize,
    pub value: F,
    pub is_sample: bool,
}

#[derive(Clone, Debug, Default)]
pub struct MainFinalClaimRecord {
    pub proof_idx: usize,
    pub idx: usize,
    pub contribution: EF,
    pub acc_in: EF,
    pub acc_out: EF,
    pub expected: EF,
}

#[derive(Clone, Debug, Default)]
pub struct MainEvalRecord {
    pub proof_idx: usize,
    pub idx: usize,
    pub eval_idx: usize,
    pub tidx: usize,
    pub value: EF,
    pub lookup_count: usize,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum MainSelectorKind {
    #[default]
    Whole,
    Prefix,
    OrderedSparse,
    QuarkBinaryTreeLessThan,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum MainSelectorPointSourceKind {
    #[default]
    TowerMain,
    RotationLeft,
    RotationRight,
    RotationOrigin,
    EccXY,
    EccSlope,
    EccX3Y3,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum MainSelectorPointDeriveKind {
    #[default]
    Identity,
    OneMinus,
    Zero,
    One,
}

#[derive(Clone, Debug, Default)]
pub struct MainSelectorEvalRecord {
    pub proof_idx: usize,
    pub idx: usize,
    pub tower_idx: usize,
    pub air_idx: usize,
    pub selector_idx: usize,
    pub has_eval: bool,
    pub eval_idx: usize,
    pub kind: MainSelectorKind,
    pub ctx_offset: usize,
    pub ctx_num_instances: usize,
    pub ctx_num_vars: usize,
    pub ordered_sparse_num_vars: usize,
    pub sparse_indices: Vec<usize>,
    pub in_point: Vec<RecursionField>,
    pub out_point: Vec<RecursionField>,
    pub point_source: MainSelectorPointSourceKind,
    pub fork_id: usize,
    pub rotation_cyclic_group_log2: usize,
    pub rotation_origin_selector_idx: Option<usize>,
    pub rotation_origin_tidxs: Vec<usize>,
    pub ecc_sample_tidx: Option<usize>,
    pub ecc_rt_tidxs: Vec<usize>,
    pub ecc_xy_selector_idx: Option<usize>,
    pub ecc_x3y3_selector_idx: Option<usize>,
    pub value: EF,
}

#[derive(Clone, Debug, Default)]
pub struct MainSelectorPointRecord {
    pub proof_idx: usize,
    pub idx: usize,
    pub tower_idx: usize,
    pub air_idx: usize,
    pub selector_idx: usize,
    pub round_idx: usize,
    pub value: EF,
    pub source_kind: MainSelectorPointSourceKind,
    pub lookup_count: usize,
    pub fork_id: usize,
    pub has_transcript: bool,
    pub transcript_tidx: usize,
    pub has_ecc_rt: bool,
    pub has_source: bool,
    pub source_selector_idx: usize,
    pub source_source_kind: MainSelectorPointSourceKind,
    pub source_round_idx: usize,
    pub source_value: EF,
    pub derive_kind: MainSelectorPointDeriveKind,
}

#[derive(Clone, Debug, Default)]
pub struct MainEccRtRecord {
    pub proof_idx: usize,
    pub idx: usize,
    pub fork_id: usize,
    pub round_idx: usize,
    pub tidx: usize,
    pub value: EF,
    pub lookup_count: usize,
}

#[derive(Clone, Debug, Default)]
pub struct MainTowerPointEqRecord {
    pub proof_idx: usize,
    pub idx: usize,
    pub round_idx: usize,
    pub global_value: EF,
    pub tower_value: EF,
    pub eq_in: EF,
    pub eq_out: EF,
}

#[derive(Clone, Debug, Default)]
pub struct MainFrontloadTermRecord {
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
    pub alpha: EF,
    pub arg0: EF,
    pub arg1: EF,
    pub value: EF,
    pub chip_acc_in: EF,
    pub chip_acc_out: EF,
    pub is_last_chip_step: bool,
}

#[derive(Clone, Debug, Default)]
pub struct TowerMainPointRecord {
    pub proof_idx: usize,
    pub idx: usize,
    pub round_idx: usize,
    pub value: EF,
    pub lookup_count: usize,
}

#[derive(Clone, Debug, Default)]
pub struct MainGlobalSumcheckRoundRecord {
    pub evaluations: [EF; 4],
    pub challenge: EF,
    pub challenge_tidx: usize,
    pub claim_in: EF,
    pub claim_out: EF,
    pub point_lookup_count: usize,
}

#[derive(Clone, Debug, Default)]
pub struct MainGlobalSumcheckRecord {
    pub proof_idx: usize,
    pub expected: EF,
    pub rounds: Vec<MainGlobalSumcheckRoundRecord>,
}

impl MainGlobalSumcheckRecord {
    pub fn total_rows(&self) -> usize {
        self.rounds.len().max(1)
    }
}

#[derive(Clone, Debug, Default)]
pub struct TowerPreflight {
    pub chips: Vec<TowerChipTranscriptRange>,
}

#[derive(Clone, Debug, Default)]
pub struct TowerChipTranscriptRange {
    pub chip_idx: usize,
    /// Fork-local tidx (position within the fork's transcript log).
    pub tidx: usize,
    /// Index into `Preflight::fork_transcripts`.
    pub fork_idx: usize,
    pub tower_replay: TowerReplayResult,
    pub rotation_replay: Option<RotationReplayClaims>,
    pub ecc_replay: Option<EccReplayClaims>,
}

#[derive(Clone, Debug, Default)]
pub struct EccReplayClaims {
    pub rt_tidxs: Vec<usize>,
}

#[derive(Clone, Debug, Default)]
pub struct RotationReplayClaims {
    pub left_point: Vec<RecursionField>,
    pub right_point: Vec<RecursionField>,
    pub origin_point: Vec<RecursionField>,
    pub origin_tidxs: Vec<usize>,
    pub left_evals: Vec<RecursionField>,
    pub right_evals: Vec<RecursionField>,
    pub target_evals: Vec<RecursionField>,
}

#[derive(Clone, Debug, Default)]
pub struct BatchConstraintPreflight {
    pub lambda_tidx: usize,
    pub tidx_before_univariate: usize,
    pub sumcheck_rnd: Vec<EF>,
    pub eq_ns_frontloaded: Vec<EF>,
    pub eq_sharp_ns_frontloaded: Vec<EF>,
}

#[derive(Clone, Debug, Default)]
pub struct ChipTranscriptRange {
    pub chip_idx: usize,
    /// Fork-local tidx (position within the fork's transcript log).
    pub tidx: usize,
    /// Index into `Preflight::fork_transcripts`.
    pub fork_idx: usize,
}

#[allow(dead_code)]
pub type PoseidonWord = [F; POSEIDON2_WIDTH];
