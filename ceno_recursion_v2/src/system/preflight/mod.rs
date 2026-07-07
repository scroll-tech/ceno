use openvm_poseidon2_air::POSEIDON2_WIDTH;
use openvm_stark_backend::TranscriptLog;
use openvm_stark_sdk::config::baby_bear_poseidon2::{D_EF, DIGEST_SIZE, EF, F};
use p3_field::PrimeCharacteristicRing;

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
    pub pcs: PcsPreflight,
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
pub struct PcsPreflight {
    pub opening_claims: Vec<PcsOpeningClaimRecord>,
    pub opening_points: Vec<PcsOpeningPointRecord>,
    pub opening_evals: Vec<PcsOpeningEvalRecord>,
    pub basefold_query_indices: Vec<PcsBasefoldQueryIndexRecord>,
    pub basefold_query_opens: Vec<PcsBasefoldQueryOpenRecord>,
    pub basefold_commit_phase_queries: Vec<PcsBasefoldCommitPhaseQueryRecord>,
    pub basefold_final_codeword: Vec<PcsBasefoldFinalCodewordRecord>,
    pub transcript_values: Vec<PcsTranscriptValueRecord>,
    pub sumcheck_rounds: Vec<PcsSumcheckRoundRecord>,
    pub sumcheck_inputs: Vec<PcsSumcheckInputRecord>,
    pub eq_products: Vec<PcsEqProductRecord>,
    pub suffix_products: Vec<PcsSuffixProductRecord>,
    pub jagged_assist_h: Vec<PcsJaggedAssistHRecord>,
    pub jagged_claims: Vec<PcsJaggedClaimRecord>,
    pub basefold_initial_claims: Vec<PcsBasefoldInitialClaimRecord>,
    pub jagged_assist_inputs: Vec<PcsJaggedAssistInputRecord>,
    pub batch_coeffs: Vec<PcsBatchCoeffRecord>,
    pub jagged_q_evals: Vec<PcsJaggedQEvalRecord>,
    pub jagged_assists: Vec<PcsJaggedAssistRecord>,
    pub basefold_final_claims: Vec<PcsBasefoldFinalClaimRecord>,
    pub commitment_roots: Vec<PcsCommitmentRootRecord>,
    pub base_input_leaf_hashes: Vec<PcsBaseInputLeafHashRecord>,
    pub base_input_merkle_rows: Vec<PcsBaseInputMerkleRecord>,
    pub commit_phase_leaf_hashes: Vec<PcsCommitPhaseLeafHashRecord>,
    pub commit_phase_merkle_rows: Vec<PcsCommitPhaseMerkleRecord>,
}

#[derive(Clone, Debug, Default)]
pub struct PcsOpeningClaimRecord {
    pub input_opening_point: Vec<RecursionField>,
    pub wits_in_evals: Vec<RecursionField>,
    pub fixed_in_evals: Vec<RecursionField>,
}

#[derive(Clone, Debug, Default)]
pub struct PcsOpeningPointRecord {
    pub proof_idx: usize,
    pub opening_idx: usize,
    pub coord_idx: usize,
    pub global_round_idx: usize,
    pub value: RecursionField,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PcsOpeningCommitKind {
    Witin,
    Fixed,
}

impl PcsOpeningCommitKind {
    pub const fn as_usize(self) -> usize {
        match self {
            Self::Witin => 0,
            Self::Fixed => 1,
        }
    }
}

impl Default for PcsOpeningCommitKind {
    fn default() -> Self {
        Self::Witin
    }
}

#[derive(Clone, Debug)]
pub struct PcsOpeningEvalRecord {
    pub proof_idx: usize,
    pub opening_idx: usize,
    pub commit_kind: PcsOpeningCommitKind,
    pub eval_idx: usize,
    pub main_idx: usize,
    pub main_eval_idx: usize,
    pub value: RecursionField,
    pub raw_value: RecursionField,
}

#[derive(Clone, Debug)]
pub struct PcsBasefoldQueryIndexRecord {
    pub proof_idx: usize,
    pub query_idx: usize,
    pub sample_tidx: usize,
    pub query_bits: usize,
    pub sampled_value: RecursionField,
    pub query_value: usize,
    pub high_value: usize,
    pub query_bytes: [u8; 4],
    pub high_bytes: [u8; 4],
    pub query_bit_selectors: [bool; 32],
}

#[derive(Clone, Debug)]
pub struct PcsBasefoldQueryOpenRecord {
    pub proof_idx: usize,
    pub query_idx: usize,
    pub opening_idx: usize,
    pub reduced_index: usize,
    pub global_coeff_idx: usize,
    pub value_idx: usize,
    pub elem_idx: usize,
    pub log2_height: usize,
    pub is_last_for_height: bool,
    pub coeff: RecursionField,
    pub opened_value: RecursionField,
    pub acc_in: RecursionField,
    pub acc_out: RecursionField,
}

#[derive(Clone, Debug)]
pub struct PcsBaseInputLeafHashRecord {
    pub proof_idx: usize,
    pub query_idx: usize,
    pub opening_idx: usize,
    pub block_idx: usize,
    pub log2_height: usize,
    pub reduced_index: usize,
    pub is_first: bool,
    pub is_last: bool,
    pub value_is_present: [bool; 8],
    pub value_idx: [usize; 8],
    pub elem_idx: [usize; 8],
    pub values: [RecursionField; 8],
    pub state_in: [F; POSEIDON2_WIDTH],
    pub input: [F; POSEIDON2_WIDTH],
    pub output_state: [F; POSEIDON2_WIDTH],
}

#[derive(Clone, Debug)]
pub struct PcsBaseInputMerkleRecord {
    pub proof_idx: usize,
    pub query_idx: usize,
    pub opening_idx: usize,
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

#[derive(Clone, Debug)]
pub struct PcsBasefoldCommitPhaseQueryRecord {
    pub proof_idx: usize,
    pub query_idx: usize,
    pub round: usize,
    pub query_value: usize,
    pub idx_in: usize,
    pub idx_out: usize,
    pub log2_height: usize,
    pub is_first: bool,
    pub has_reduced_opening: bool,
    pub reduced_opening: RecursionField,
    pub folded_idx: usize,
    pub folded_in: RecursionField,
    pub sibling_value: RecursionField,
    pub challenge: RecursionField,
    pub coeff: RecursionField,
    pub folded_out: RecursionField,
    pub is_last: bool,
}

#[derive(Clone, Debug)]
pub struct PcsCommitmentRootRecord {
    pub proof_idx: usize,
    pub commit_major: usize,
    pub commit_minor: usize,
    pub root: [F; DIGEST_SIZE],
    pub lookup_count: usize,
}

#[derive(Clone, Debug)]
pub struct PcsCommitPhaseLeafHashRecord {
    pub proof_idx: usize,
    pub query_idx: usize,
    pub round: usize,
    pub leaf_idx: usize,
    pub left: RecursionField,
    pub right: RecursionField,
    pub input: [F; POSEIDON2_WIDTH],
    pub output_state: [F; POSEIDON2_WIDTH],
}

#[derive(Clone, Debug)]
pub struct PcsCommitPhaseMerkleRecord {
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

#[derive(Clone, Debug)]
pub struct PcsBasefoldFinalCodewordRecord {
    pub proof_idx: usize,
    pub query_idx: usize,
    pub elem_idx: usize,
    pub final_tidx: usize,
    pub final_value: RecursionField,
    pub coeff: RecursionField,
    pub acc_in: RecursionField,
    pub acc_out: RecursionField,
    pub folded: RecursionField,
    pub is_last: bool,
}

#[derive(Clone, Debug, Default)]
pub struct PcsTranscriptValueRecord {
    pub proof_idx: usize,
    pub idx: usize,
    pub tidx: usize,
    pub value: RecursionField,
    pub is_sample: bool,
    pub is_ext: bool,
    pub is_final_message: bool,
    pub is_query_sample: bool,
    pub is_batch_alpha: bool,
    pub is_basefold_eval: bool,
    pub transcript_ext_lookup_count: usize,
    pub is_jagged_f_at_rho: bool,
}

#[derive(Clone, Debug, Default)]
pub struct PcsSumcheckRoundRecord {
    pub proof_idx: usize,
    pub idx: usize,
    pub round: usize,
    pub is_first: bool,
    pub is_last: bool,
    pub ev_tidx: usize,
    pub challenge_tidx: usize,
    pub ev1: RecursionField,
    pub ev2: RecursionField,
    pub claim_in: RecursionField,
    pub claim_out: RecursionField,
    pub challenge: RecursionField,
    pub fold_challenge_lookup_count: usize,
}

#[derive(Clone, Debug, Default)]
pub struct PcsSumcheckInputRecord {
    pub proof_idx: usize,
    pub idx: usize,
    pub claim: RecursionField,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PcsEqProductKind {
    JaggedClaim = 0,
    JaggedQEval = 1,
}

impl PcsEqProductKind {
    pub const fn as_usize(self) -> usize {
        self as usize
    }
}

impl Default for PcsEqProductKind {
    fn default() -> Self {
        Self::JaggedClaim
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PcsEqProductSource {
    Transcript = 0,
    FoldChallenge = 1,
}

impl PcsEqProductSource {
    pub const fn as_usize(self) -> usize {
        self as usize
    }
}

impl Default for PcsEqProductSource {
    fn default() -> Self {
        Self::Transcript
    }
}

#[derive(Clone, Debug, Default)]
pub struct PcsEqProductRecord {
    pub proof_idx: usize,
    pub kind: PcsEqProductKind,
    pub source: PcsEqProductSource,
    pub round_idx: usize,
    pub term_idx: usize,
    pub bit_idx: usize,
    pub is_first: bool,
    pub is_last: bool,
    pub point_tidx: usize,
    pub sumcheck_idx: usize,
    pub point_round: usize,
    pub index_bit: bool,
    pub index_pow2: usize,
    pub index_acc_in: usize,
    pub index_acc_out: usize,
    pub point: RecursionField,
    pub acc_in: RecursionField,
    pub acc_out: RecursionField,
}

#[derive(Clone, Debug, Default)]
pub struct PcsSuffixProductRecord {
    pub proof_idx: usize,
    pub round_idx: usize,
    pub term_idx: usize,
    pub coord_idx: usize,
    pub step_idx: usize,
    pub is_first: bool,
    pub is_last: bool,
    pub has_factor: bool,
    pub point: RecursionField,
    pub acc_in: RecursionField,
    pub acc_out: RecursionField,
}

#[derive(Clone, Debug, Default)]
pub struct PcsJaggedAssistHRecord {
    pub proof_idx: usize,
    pub round_idx: usize,
    pub sumcheck_idx: usize,
    pub step_idx: usize,
    pub robp_idx: usize,
    pub is_first: bool,
    pub is_last: bool,
    pub has_z_row: bool,
    pub has_rho: bool,
    pub z_row: RecursionField,
    pub rho: RecursionField,
    pub rho_star_c: RecursionField,
    pub rho_star_d: RecursionField,
    pub val_in: [RecursionField; 4],
    pub val_out: [RecursionField; 4],
}

#[derive(Clone, Debug, Default)]
pub struct PcsJaggedClaimRecord {
    pub proof_idx: usize,
    pub round_idx: usize,
    pub sumcheck_idx: usize,
    pub term_idx: usize,
    pub is_first: bool,
    pub is_last: bool,
    pub opening_idx: usize,
    pub commit_kind: PcsOpeningCommitKind,
    pub eval_idx: usize,
    pub main_idx: usize,
    pub main_eval_idx: usize,
    pub eval: RecursionField,
    pub z_col_tidx: usize,
    pub eq_col: RecursionField,
    pub tail_zero: RecursionField,
    pub acc_in: RecursionField,
    pub acc_out: RecursionField,
}

#[derive(Clone, Debug, Default)]
pub struct PcsBasefoldInitialClaimRecord {
    pub proof_idx: usize,
    pub sumcheck_idx: usize,
    pub term_idx: usize,
    pub is_first: bool,
    pub is_last: bool,
    pub global_coeff_idx: usize,
    pub eval_tidx: usize,
    pub eval: RecursionField,
    pub coeff: RecursionField,
    pub scale: RecursionField,
    pub acc_in: RecursionField,
    pub acc_out: RecursionField,
}

#[derive(Clone, Debug, Default)]
pub struct PcsJaggedAssistInputRecord {
    pub proof_idx: usize,
    pub round_idx: usize,
    pub sumcheck_idx: usize,
    pub f_tidx: usize,
    pub f_at_rho: RecursionField,
}

#[derive(Clone, Debug, Default)]
pub struct PcsBatchCoeffRecord {
    pub proof_idx: usize,
    pub global_coeff_idx: usize,
    pub alpha_tidx: usize,
    pub alpha: RecursionField,
    pub coeff: RecursionField,
    pub next_coeff: RecursionField,
    pub lookup_count: usize,
    pub is_first: bool,
    pub is_last: bool,
}

#[derive(Clone, Debug, Default)]
pub struct PcsJaggedQEvalRecord {
    pub proof_idx: usize,
    pub round_idx: usize,
    pub sumcheck_idx: usize,
    pub term_idx: usize,
    pub is_first: bool,
    pub is_last: bool,
    pub col_tidx: usize,
    pub col_eval: RecursionField,
    pub eq_rho_col: RecursionField,
    pub acc_in: RecursionField,
    pub acc_out: RecursionField,
    pub q_eval: RecursionField,
    pub f_at_rho: RecursionField,
    pub sumcheck_final: RecursionField,
}

#[derive(Clone, Debug, Default)]
pub struct PcsJaggedAssistRecord {
    pub proof_idx: usize,
    pub round_idx: usize,
    pub sumcheck_idx: usize,
    pub h_at_rho_star: RecursionField,
    pub q_at_rho_star: RecursionField,
    pub sumcheck_final: RecursionField,
}

#[derive(Clone, Debug, Default)]
pub struct PcsBasefoldFinalClaimRecord {
    pub proof_idx: usize,
    pub sumcheck_idx: usize,
    pub final_claim: RecursionField,
    pub expected: RecursionField,
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

#[derive(Clone, Debug)]
pub struct MainEccRtRecord {
    pub proof_idx: usize,
    pub idx: usize,
    pub fork_id: usize,
    pub round_idx: usize,
    pub is_first: bool,
    pub is_last: bool,
    pub tidx: usize,
    pub out_tidx: usize,
    pub alpha_tidx: usize,
    pub value: EF,
    pub out_value: EF,
    pub alpha: EF,
    pub alpha_pows: [EF; 49],
    pub ev1: EF,
    pub ev2: EF,
    pub ev3: EF,
    pub claim_in: EF,
    pub claim_out: EF,
    pub sel_add: EF,
    pub sel_bypass: EF,
    pub sel_export: EF,
    pub s0: [EF; 7],
    pub x0: [EF; 7],
    pub y0: [EF; 7],
    pub x1: [EF; 7],
    pub y1: [EF; 7],
    pub x3: [EF; 7],
    pub y3: [EF; 7],
    pub sum_x: [EF; 7],
    pub sum_y: [EF; 7],
    pub eq_in: EF,
    pub eq_out: EF,
    pub last_in: EF,
    pub last_out: EF,
    pub export_out_in: EF,
    pub export_out_out: EF,
    pub export_rt_in: EF,
    pub export_rt_out: EF,
    pub quark_in: EF,
    pub quark_factor: EF,
    pub quark_out: EF,
    pub add_eval: EF,
    pub bypass_eval: EF,
    pub export_eval: EF,
    pub lte_out_point: [EF; 32],
    pub lte_rt_point: [EF; 32],
    pub lte_prefix_acc: [EF; 33],
    pub lte_less_acc: [EF; 33],
    pub lte_bits: [bool; 32],
    pub lte_active: [bool; 32],
    pub quark_prefix_count: usize,
    pub quark_layer_n: usize,
    pub quark_parity: bool,
    pub lookup_count: usize,
}

impl Default for MainEccRtRecord {
    fn default() -> Self {
        Self {
            proof_idx: 0,
            idx: 0,
            fork_id: 0,
            round_idx: 0,
            is_first: false,
            is_last: false,
            tidx: 0,
            out_tidx: 0,
            alpha_tidx: 0,
            value: EF::ZERO,
            out_value: EF::ZERO,
            alpha: EF::ZERO,
            alpha_pows: [EF::ZERO; 49],
            ev1: EF::ZERO,
            ev2: EF::ZERO,
            ev3: EF::ZERO,
            claim_in: EF::ZERO,
            claim_out: EF::ZERO,
            sel_add: EF::ZERO,
            sel_bypass: EF::ZERO,
            sel_export: EF::ZERO,
            s0: [EF::ZERO; 7],
            x0: [EF::ZERO; 7],
            y0: [EF::ZERO; 7],
            x1: [EF::ZERO; 7],
            y1: [EF::ZERO; 7],
            x3: [EF::ZERO; 7],
            y3: [EF::ZERO; 7],
            sum_x: [EF::ZERO; 7],
            sum_y: [EF::ZERO; 7],
            eq_in: EF::ZERO,
            eq_out: EF::ZERO,
            last_in: EF::ZERO,
            last_out: EF::ZERO,
            export_out_in: EF::ZERO,
            export_out_out: EF::ZERO,
            export_rt_in: EF::ZERO,
            export_rt_out: EF::ZERO,
            quark_in: EF::ZERO,
            quark_factor: EF::ZERO,
            quark_out: EF::ZERO,
            add_eval: EF::ZERO,
            bypass_eval: EF::ZERO,
            export_eval: EF::ZERO,
            lte_out_point: [EF::ZERO; 32],
            lte_rt_point: [EF::ZERO; 32],
            lte_prefix_acc: [EF::ZERO; 33],
            lte_less_acc: [EF::ZERO; 33],
            lte_bits: [false; 32],
            lte_active: [false; 32],
            quark_prefix_count: 0,
            quark_layer_n: 0,
            quark_parity: false,
            lookup_count: 0,
        }
    }
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
    pub out_rt_tidxs: Vec<usize>,
    pub alpha_tidx: usize,
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
