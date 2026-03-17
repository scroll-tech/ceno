use recursion_circuit::{
    bus::{
        AirPresenceBus, AirPresenceBusMessage, AirShapeBus, AirShapeBusMessage,
        BatchConstraintModuleBus, CachedCommitBus, CachedCommitBusMessage, ColumnClaimsBus,
        CommitmentsBus, CommitmentsBusMessage, ConstraintSumcheckRandomnessBus,
        ConstraintsFoldingInputBus, ConstraintsFoldingInputMessage, DagCommitBus, EqNegBaseRandBus,
        EqNegResultBus, EqNsNLogupMaxBus, ExpressionClaimNMaxBus, ExpressionClaimNMaxMessage,
        FinalTranscriptStateBus, FractionFolderInputBus, FractionFolderInputMessage, HyperdimBus,
        HyperdimBusMessage, InteractionsFoldingInputBus, InteractionsFoldingInputMessage,
        LiftedHeightsBus, LiftedHeightsBusMessage, MerkleVerifyBus, NLiftBus, NLiftMessage,
        Poseidon2CompressBus, Poseidon2PermuteBus, PreHashBus, PublicValuesBus,
        PublicValuesBusMessage, SelUniBus, StackingIndicesBus, StackingModuleBus, TranscriptBus,
        TranscriptBusMessage, WhirModuleBus, WhirMuBus, WhirOpeningPointBus,
        WhirOpeningPointLookupBus, XiRandomnessBus,
    },
    primitives::bus::{ExpBitsLenBus, PowerCheckerBus, RangeCheckerBus, RightShiftBus},
    system::{BusIndexManager, BusInventory as UpstreamBusInventory},
};

use crate::bus::{
    CachedCommitBus as LocalCachedCommitBus, CommitmentsBus as LocalCommitmentsBus,
    ExpressionClaimNMaxBus as LocalExpressionClaimNMaxBus,
    FractionFolderInputBus as LocalFractionFolderInputBus, GkrModuleBus,
    HyperdimBus as LocalHyperdimBus, LiftedHeightsBus as LocalLiftedHeightsBus, MainBus,
    MainExpressionClaimBus, MainSumcheckInputBus, MainSumcheckOutputBus, NLiftBus as LocalNLiftBus,
    PublicValuesBus as LocalPublicValuesBus, TranscriptBus as LocalTranscriptBus,
};

#[derive(Clone, Debug)]
pub struct BusInventory {
    inner: UpstreamBusInventory,
    pub transcript_bus: LocalTranscriptBus,
    pub gkr_module_bus: GkrModuleBus,
    pub expression_claim_n_max_bus: LocalExpressionClaimNMaxBus,
    pub fraction_folder_input_bus: LocalFractionFolderInputBus,
    pub air_shape_bus: AirShapeBus,
    pub hyperdim_bus: LocalHyperdimBus,
    pub lifted_heights_bus: LocalLiftedHeightsBus,
    pub commitments_bus: LocalCommitmentsBus,
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
    pub right_shift_bus: RightShiftBus,
    pub xi_randomness_bus: XiRandomnessBus,
}

impl BusInventory {
    pub fn new(b: &mut BusIndexManager) -> Self {
        let transcript_bus = LocalTranscriptBus::new(b.new_bus_idx());
        let poseidon2_permute_bus = Poseidon2PermuteBus::new(b.new_bus_idx());
        let poseidon2_compress_bus = Poseidon2CompressBus::new(b.new_bus_idx());
        let merkle_verify_bus = MerkleVerifyBus::new(b.new_bus_idx());

        let gkr_bus_idx = b.new_bus_idx();
        let gkr_module_bus = GkrModuleBus::new(gkr_bus_idx);
        let upstream_gkr_module_bus = recursion_circuit::bus::GkrModuleBus::new(gkr_bus_idx);

        let bc_module_bus = BatchConstraintModuleBus::new(b.new_bus_idx());
        let stacking_module_bus = StackingModuleBus::new(b.new_bus_idx());
        let whir_module_bus = WhirModuleBus::new(b.new_bus_idx());
        let whir_mu_bus = WhirMuBus::new(b.new_bus_idx());

        let air_shape_bus = AirShapeBus::new(b.new_bus_idx());
        let air_presence_bus = AirPresenceBus::new(b.new_bus_idx());
        let hyperdim_bus = LocalHyperdimBus::new(b.new_bus_idx());
        let lifted_heights_bus = LocalLiftedHeightsBus::new(b.new_bus_idx());
        let stacking_indices_bus = StackingIndicesBus::new(b.new_bus_idx());
        let commitments_bus = LocalCommitmentsBus::new(b.new_bus_idx());
        let public_values_bus = LocalPublicValuesBus::new(b.new_bus_idx());
        let column_claims_bus = ColumnClaimsBus::new(b.new_bus_idx());
        let range_checker_bus = RangeCheckerBus::new(b.new_bus_idx());
        let power_checker_bus = PowerCheckerBus::new(b.new_bus_idx());
        let expression_claim_n_max_bus = LocalExpressionClaimNMaxBus::new(b.new_bus_idx());
        let constraints_folding_input_bus = ConstraintsFoldingInputBus::new(b.new_bus_idx());
        let interactions_folding_input_bus = InteractionsFoldingInputBus::new(b.new_bus_idx());
        let fraction_folder_input_bus = LocalFractionFolderInputBus::new(b.new_bus_idx());
        let n_lift_bus = LocalNLiftBus::new(b.new_bus_idx());
        let eq_n_logup_n_max_bus = EqNsNLogupMaxBus::new(b.new_bus_idx());

        let xi_randomness_bus = XiRandomnessBus::new(b.new_bus_idx());
        let constraint_randomness_bus = ConstraintSumcheckRandomnessBus::new(b.new_bus_idx());
        let whir_opening_point_bus = WhirOpeningPointBus::new(b.new_bus_idx());
        let whir_opening_point_lookup_bus = WhirOpeningPointLookupBus::new(b.new_bus_idx());

        let exp_bits_len_bus = ExpBitsLenBus::new(b.new_bus_idx());
        let right_shift_bus = RightShiftBus::new(b.new_bus_idx());
        let sel_uni_bus = SelUniBus::new(b.new_bus_idx());
        let eq_neg_result_bus = EqNegResultBus::new(b.new_bus_idx());
        let eq_neg_base_rand_bus = EqNegBaseRandBus::new(b.new_bus_idx());
        let main_bus = MainBus::new(b.new_bus_idx());
        let main_sumcheck_input_bus = MainSumcheckInputBus::new(b.new_bus_idx());
        let main_sumcheck_output_bus = MainSumcheckOutputBus::new(b.new_bus_idx());
        let main_expression_claim_bus = MainExpressionClaimBus::new(b.new_bus_idx());

        let cached_commit_bus = LocalCachedCommitBus::new(b.new_bus_idx());
        let pre_hash_bus = PreHashBus::new(b.new_bus_idx());
        let dag_commit_bus = DagCommitBus::new(b.new_bus_idx());
        let final_state_bus = FinalTranscriptStateBus::new(b.new_bus_idx());

        let inner = UpstreamBusInventory {
            transcript_bus,
            poseidon2_permute_bus,
            poseidon2_compress_bus,
            merkle_verify_bus,
            gkr_module_bus: upstream_gkr_module_bus,
            bc_module_bus,
            stacking_module_bus,
            whir_module_bus,
            whir_mu_bus,
            air_shape_bus,
            air_presence_bus,
            hyperdim_bus,
            lifted_heights_bus,
            stacking_indices_bus,
            commitments_bus,
            public_values_bus,
            column_claims_bus,
            range_checker_bus,
            power_checker_bus,
            expression_claim_n_max_bus,
            constraints_folding_input_bus,
            interactions_folding_input_bus,
            fraction_folder_input_bus,
            n_lift_bus,
            eq_n_logup_n_max_bus,
            xi_randomness_bus,
            constraint_randomness_bus,
            whir_opening_point_bus,
            whir_opening_point_lookup_bus,
            exp_bits_len_bus,
            right_shift_bus,
            sel_uni_bus,
            eq_neg_result_bus,
            eq_neg_base_rand_bus,
            cached_commit_bus,
            pre_hash_bus,
            dag_commit_bus,
            final_state_bus,
        };

        Self {
            inner,
            transcript_bus,
            gkr_module_bus,
            expression_claim_n_max_bus,
            fraction_folder_input_bus,
            air_shape_bus,
            hyperdim_bus,
            lifted_heights_bus,
            commitments_bus,
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
            right_shift_bus,
            xi_randomness_bus,
        }
    }

    pub fn inner(&self) -> &UpstreamBusInventory {
        &self.inner
    }

    pub fn clone_inner(&self) -> UpstreamBusInventory {
        self.inner.clone()
    }
}
