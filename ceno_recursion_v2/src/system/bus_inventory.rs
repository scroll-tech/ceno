use recursion_circuit::{
    bus::{
        AirPresenceBus, AirShapeBus, FinalTranscriptStateBus, MerkleVerifyBus,
        Poseidon2CompressBus, Poseidon2PermuteBus, XiRandomnessBus,
    },
    primitives::bus::{ExpBitsLenBus, PowerCheckerBus, RangeCheckerBus, RightShiftBus},
    system::BusIndexManager,
};

use crate::bus::{
    CachedCommitBus as LocalCachedCommitBus, EccRtBus,
    ExpressionClaimNMaxBus as LocalExpressionClaimNMaxBus, ForkFinalSampleBus,
    ForkedTranscriptBus as LocalForkedTranscriptBus,
    FractionFolderInputBus as LocalFractionFolderInputBus, HyperdimBus as LocalHyperdimBus,
    LiftedHeightsBus as LocalLiftedHeightsBus, LookupChallengeBus, MainBus, MainContributionBus,
    MainEccRtChallengeBus, MainEccRtEquationTotalsBus, MainEccRtQuarkFinalBus,
    MainEccRtSumcheckFinalBus, MainEvalBus, MainExpressionClaimBus, MainGlobalClaimBus,
    MainGlobalPointBus, MainSelectorPointBus, MainSelectorResultBus, MainSelectorShapeBus,
    MainSelectorSparseIndexShapeBus, MainSumcheckInputBus, MainSumcheckOutputBus,
    NLiftBus as LocalNLiftBus, PcsBaseInputOpeningBus, PcsBasefoldEvalBus, PcsBasefoldQueryBus,
    PcsBatchAlphaBus, PcsBatchCoeffBus, PcsCommitHeightBus, PcsCommitPhaseLeafBus,
    PcsCommitmentRootBus, PcsEqProductBus, PcsFinalMessageBus, PcsFoldChallengeBus,
    PcsJaggedAssistHBus, PcsJaggedAssistQBus, PcsJaggedFEvalBus, PcsOpeningEvalBus,
    PcsQuerySampleBus, PcsSuffixProductBus, PcsSumcheckInputBus, PcsSumcheckOutputBus,
    PcsTranscriptExtBus, PublicValuesBus as LocalPublicValuesBus, TowerMainPointBus,
    TowerModuleBus, TranscriptBus as LocalTranscriptBus,
};

#[derive(Clone, Debug)]
pub struct BusInventory {
    pub transcript_bus: LocalTranscriptBus,
    pub poseidon2_permute_bus: Poseidon2PermuteBus,
    pub poseidon2_compress_bus: Poseidon2CompressBus,
    pub merkle_verify_bus: MerkleVerifyBus,
    pub tower_module_bus: TowerModuleBus,
    pub expression_claim_n_max_bus: LocalExpressionClaimNMaxBus,
    pub fraction_folder_input_bus: LocalFractionFolderInputBus,
    pub air_presence_bus: AirPresenceBus,
    pub air_shape_bus: AirShapeBus,
    pub hyperdim_bus: LocalHyperdimBus,
    pub lifted_heights_bus: LocalLiftedHeightsBus,
    pub n_lift_bus: LocalNLiftBus,
    pub cached_commit_bus: LocalCachedCommitBus,
    pub public_values_bus: LocalPublicValuesBus,
    pub range_checker_bus: RangeCheckerBus,
    pub power_checker_bus: PowerCheckerBus,
    pub exp_bits_len_bus: ExpBitsLenBus,
    pub main_bus: MainBus,
    pub main_sumcheck_input_bus: MainSumcheckInputBus,
    pub main_sumcheck_output_bus: MainSumcheckOutputBus,
    pub main_expression_claim_bus: MainExpressionClaimBus,
    pub main_global_claim_bus: MainGlobalClaimBus,
    pub main_global_point_bus: MainGlobalPointBus,
    pub main_eval_bus: MainEvalBus,
    pub main_contribution_bus: MainContributionBus,
    pub main_selector_point_bus: MainSelectorPointBus,
    pub main_selector_result_bus: MainSelectorResultBus,
    pub main_selector_shape_bus: MainSelectorShapeBus,
    pub main_selector_sparse_index_shape_bus: MainSelectorSparseIndexShapeBus,
    pub main_ecc_rt_challenge_bus: MainEccRtChallengeBus,
    pub main_ecc_rt_sumcheck_final_bus: MainEccRtSumcheckFinalBus,
    pub main_ecc_rt_equation_totals_bus: MainEccRtEquationTotalsBus,
    pub main_ecc_rt_quark_final_bus: MainEccRtQuarkFinalBus,
    pub ecc_rt_bus: EccRtBus,
    pub tower_main_point_bus: TowerMainPointBus,
    pub right_shift_bus: RightShiftBus,
    pub xi_randomness_bus: XiRandomnessBus,
    pub final_state_bus: FinalTranscriptStateBus,
    pub forked_transcript_bus: LocalForkedTranscriptBus,
    pub fork_final_sample_bus: ForkFinalSampleBus,
    pub lookup_challenge_bus: LookupChallengeBus,
    pub pcs_basefold_query_bus: PcsBasefoldQueryBus,
    pub pcs_basefold_eval_bus: PcsBasefoldEvalBus,
    pub pcs_transcript_ext_bus: PcsTranscriptExtBus,
    pub pcs_base_input_opening_bus: PcsBaseInputOpeningBus,
    pub pcs_final_message_bus: PcsFinalMessageBus,
    pub pcs_query_sample_bus: PcsQuerySampleBus,
    pub pcs_commitment_root_bus: PcsCommitmentRootBus,
    pub pcs_commit_phase_leaf_bus: PcsCommitPhaseLeafBus,
    pub pcs_sumcheck_input_bus: PcsSumcheckInputBus,
    pub pcs_sumcheck_output_bus: PcsSumcheckOutputBus,
    pub pcs_fold_challenge_bus: PcsFoldChallengeBus,
    pub pcs_batch_coeff_bus: PcsBatchCoeffBus,
    pub pcs_batch_alpha_bus: PcsBatchAlphaBus,
    pub pcs_jagged_f_eval_bus: PcsJaggedFEvalBus,
    pub pcs_opening_eval_bus: PcsOpeningEvalBus,
    pub pcs_eq_product_bus: PcsEqProductBus,
    pub pcs_suffix_product_bus: PcsSuffixProductBus,
    pub pcs_jagged_assist_h_bus: PcsJaggedAssistHBus,
    pub pcs_jagged_assist_q_bus: PcsJaggedAssistQBus,
    pub pcs_commit_height_bus: PcsCommitHeightBus,
}

impl BusInventory {
    pub fn new(b: &mut BusIndexManager) -> Self {
        let transcript_bus = LocalTranscriptBus::new(b.new_bus_idx());
        let poseidon2_permute_bus = Poseidon2PermuteBus::new(b.new_bus_idx());
        let poseidon2_compress_bus = Poseidon2CompressBus::new(b.new_bus_idx());
        let merkle_verify_bus = MerkleVerifyBus::new(b.new_bus_idx());

        let gkr_bus_idx = b.new_bus_idx();
        let tower_module_bus = TowerModuleBus::new(gkr_bus_idx);

        let air_shape_bus = AirShapeBus::new(b.new_bus_idx());
        let hyperdim_bus = LocalHyperdimBus::new(b.new_bus_idx());
        let lifted_heights_bus = LocalLiftedHeightsBus::new(b.new_bus_idx());
        let public_values_bus = LocalPublicValuesBus::new(b.new_bus_idx());
        let range_checker_bus = RangeCheckerBus::new(b.new_bus_idx());
        let power_checker_bus = PowerCheckerBus::new(b.new_bus_idx());
        let expression_claim_n_max_bus = LocalExpressionClaimNMaxBus::new(b.new_bus_idx());
        let fraction_folder_input_bus = LocalFractionFolderInputBus::new(b.new_bus_idx());
        let n_lift_bus = LocalNLiftBus::new(b.new_bus_idx());
        let air_presence_bus = AirPresenceBus::new(b.new_bus_idx());

        let xi_randomness_bus = XiRandomnessBus::new(b.new_bus_idx());

        let exp_bits_len_bus = ExpBitsLenBus::new(b.new_bus_idx());
        let right_shift_bus = RightShiftBus::new(b.new_bus_idx());
        let main_bus = MainBus::new(b.new_bus_idx());
        let main_sumcheck_input_bus = MainSumcheckInputBus::new(b.new_bus_idx());
        let main_sumcheck_output_bus = MainSumcheckOutputBus::new(b.new_bus_idx());
        let main_expression_claim_bus = MainExpressionClaimBus::new(b.new_bus_idx());
        let main_global_claim_bus = MainGlobalClaimBus::new(b.new_bus_idx());
        let main_global_point_bus = MainGlobalPointBus::new(b.new_bus_idx());
        let main_eval_bus = MainEvalBus::new(b.new_bus_idx());
        let main_contribution_bus = MainContributionBus::new(b.new_bus_idx());
        let main_selector_point_bus = MainSelectorPointBus::new(b.new_bus_idx());
        let main_selector_result_bus = MainSelectorResultBus::new(b.new_bus_idx());
        let main_selector_shape_bus = MainSelectorShapeBus::new(b.new_bus_idx());
        let main_selector_sparse_index_shape_bus =
            MainSelectorSparseIndexShapeBus::new(b.new_bus_idx());
        let main_ecc_rt_challenge_bus = MainEccRtChallengeBus::new(b.new_bus_idx());
        let main_ecc_rt_sumcheck_final_bus = MainEccRtSumcheckFinalBus::new(b.new_bus_idx());
        let main_ecc_rt_equation_totals_bus = MainEccRtEquationTotalsBus::new(b.new_bus_idx());
        let main_ecc_rt_quark_final_bus = MainEccRtQuarkFinalBus::new(b.new_bus_idx());
        let ecc_rt_bus = EccRtBus::new(b.new_bus_idx());
        let tower_main_point_bus = TowerMainPointBus::new(b.new_bus_idx());

        let cached_commit_bus = LocalCachedCommitBus::new(b.new_bus_idx());
        let final_state_bus = FinalTranscriptStateBus::new(b.new_bus_idx());
        let forked_transcript_bus = LocalForkedTranscriptBus::new(b.new_bus_idx());
        let fork_final_sample_bus = ForkFinalSampleBus::new(b.new_bus_idx());
        let lookup_challenge_bus = LookupChallengeBus::new(b.new_bus_idx());
        let pcs_basefold_query_bus = PcsBasefoldQueryBus::new(b.new_bus_idx());
        let pcs_basefold_eval_bus = PcsBasefoldEvalBus::new(b.new_bus_idx());
        let pcs_transcript_ext_bus = PcsTranscriptExtBus::new(b.new_bus_idx());
        let pcs_base_input_opening_bus = PcsBaseInputOpeningBus::new(b.new_bus_idx());
        let pcs_final_message_bus = PcsFinalMessageBus::new(b.new_bus_idx());
        let pcs_query_sample_bus = PcsQuerySampleBus::new(b.new_bus_idx());
        let pcs_commitment_root_bus = PcsCommitmentRootBus::new(b.new_bus_idx());
        let pcs_commit_phase_leaf_bus = PcsCommitPhaseLeafBus::new(b.new_bus_idx());
        let pcs_sumcheck_input_bus = PcsSumcheckInputBus::new(b.new_bus_idx());
        let pcs_sumcheck_output_bus = PcsSumcheckOutputBus::new(b.new_bus_idx());
        let pcs_fold_challenge_bus = PcsFoldChallengeBus::new(b.new_bus_idx());
        let pcs_batch_coeff_bus = PcsBatchCoeffBus::new(b.new_bus_idx());
        let pcs_batch_alpha_bus = PcsBatchAlphaBus::new(b.new_bus_idx());
        let pcs_jagged_f_eval_bus = PcsJaggedFEvalBus::new(b.new_bus_idx());
        let pcs_opening_eval_bus = PcsOpeningEvalBus::new(b.new_bus_idx());
        let pcs_eq_product_bus = PcsEqProductBus::new(b.new_bus_idx());
        let pcs_suffix_product_bus = PcsSuffixProductBus::new(b.new_bus_idx());
        let pcs_jagged_assist_h_bus = PcsJaggedAssistHBus::new(b.new_bus_idx());
        let pcs_jagged_assist_q_bus = PcsJaggedAssistQBus::new(b.new_bus_idx());
        let pcs_commit_height_bus = PcsCommitHeightBus::new(b.new_bus_idx());

        Self {
            transcript_bus,
            poseidon2_permute_bus,
            poseidon2_compress_bus,
            merkle_verify_bus,
            tower_module_bus,
            expression_claim_n_max_bus,
            fraction_folder_input_bus,
            air_presence_bus,
            air_shape_bus,
            hyperdim_bus,
            lifted_heights_bus,
            n_lift_bus,
            cached_commit_bus,
            public_values_bus,
            range_checker_bus,
            power_checker_bus,
            exp_bits_len_bus,
            main_bus,
            main_sumcheck_input_bus,
            main_sumcheck_output_bus,
            main_expression_claim_bus,
            main_global_claim_bus,
            main_global_point_bus,
            main_eval_bus,
            main_contribution_bus,
            main_selector_point_bus,
            main_selector_result_bus,
            main_selector_shape_bus,
            main_selector_sparse_index_shape_bus,
            main_ecc_rt_challenge_bus,
            main_ecc_rt_sumcheck_final_bus,
            main_ecc_rt_equation_totals_bus,
            main_ecc_rt_quark_final_bus,
            ecc_rt_bus,
            tower_main_point_bus,
            right_shift_bus,
            xi_randomness_bus,
            final_state_bus,
            forked_transcript_bus,
            fork_final_sample_bus,
            lookup_challenge_bus,
            pcs_basefold_query_bus,
            pcs_basefold_eval_bus,
            pcs_transcript_ext_bus,
            pcs_base_input_opening_bus,
            pcs_final_message_bus,
            pcs_query_sample_bus,
            pcs_commitment_root_bus,
            pcs_commit_phase_leaf_bus,
            pcs_sumcheck_input_bus,
            pcs_sumcheck_output_bus,
            pcs_fold_challenge_bus,
            pcs_batch_coeff_bus,
            pcs_batch_alpha_bus,
            pcs_jagged_f_eval_bus,
            pcs_opening_eval_bus,
            pcs_eq_product_bus,
            pcs_suffix_product_bus,
            pcs_jagged_assist_h_bus,
            pcs_jagged_assist_q_bus,
            pcs_commit_height_bus,
        }
    }
}
