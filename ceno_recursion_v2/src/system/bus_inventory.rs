use recursion_circuit::{
    bus::{
        AirShapeBus, FinalTranscriptStateBus, MerkleVerifyBus, Poseidon2CompressBus,
        Poseidon2PermuteBus, XiRandomnessBus,
    },
    primitives::bus::{ExpBitsLenBus, PowerCheckerBus, RangeCheckerBus, RightShiftBus},
    system::BusIndexManager,
};

use crate::bus::{
    CachedCommitBus as LocalCachedCommitBus, CommitmentsBus as LocalCommitmentsBus,
    ExpressionClaimNMaxBus as LocalExpressionClaimNMaxBus,
    ForkStateBus as LocalForkStateBus,
    ForkedTranscriptBus as LocalForkedTranscriptBus,
    FractionFolderInputBus as LocalFractionFolderInputBus,
    HyperdimBus as LocalHyperdimBus, LiftedHeightsBus as LocalLiftedHeightsBus, MainBus,
    MainExpressionClaimBus, MainSumcheckInputBus, MainSumcheckOutputBus,
    NLiftBus as LocalNLiftBus, PublicValuesBus as LocalPublicValuesBus, TowerModuleBus,
    TranscriptBus as LocalTranscriptBus,
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
    pub final_state_bus: FinalTranscriptStateBus,
    pub fork_state_bus: LocalForkStateBus,
    pub forked_transcript_bus: LocalForkedTranscriptBus,
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
        let commitments_bus = LocalCommitmentsBus::new(b.new_bus_idx());
        let public_values_bus = LocalPublicValuesBus::new(b.new_bus_idx());
        let range_checker_bus = RangeCheckerBus::new(b.new_bus_idx());
        let power_checker_bus = PowerCheckerBus::new(b.new_bus_idx());
        let expression_claim_n_max_bus = LocalExpressionClaimNMaxBus::new(b.new_bus_idx());
        let fraction_folder_input_bus = LocalFractionFolderInputBus::new(b.new_bus_idx());
        let n_lift_bus = LocalNLiftBus::new(b.new_bus_idx());

        let xi_randomness_bus = XiRandomnessBus::new(b.new_bus_idx());

        let exp_bits_len_bus = ExpBitsLenBus::new(b.new_bus_idx());
        let right_shift_bus = RightShiftBus::new(b.new_bus_idx());
        let main_bus = MainBus::new(b.new_bus_idx());
        let main_sumcheck_input_bus = MainSumcheckInputBus::new(b.new_bus_idx());
        let main_sumcheck_output_bus = MainSumcheckOutputBus::new(b.new_bus_idx());
        let main_expression_claim_bus = MainExpressionClaimBus::new(b.new_bus_idx());

        let cached_commit_bus = LocalCachedCommitBus::new(b.new_bus_idx());
        let final_state_bus = FinalTranscriptStateBus::new(b.new_bus_idx());
        let fork_state_bus = LocalForkStateBus::new(b.new_bus_idx());
        let forked_transcript_bus = LocalForkedTranscriptBus::new(b.new_bus_idx());

        Self {
            transcript_bus,
            poseidon2_permute_bus,
            poseidon2_compress_bus,
            merkle_verify_bus,
            tower_module_bus,
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
            final_state_bus,
            fork_state_bus,
            forked_transcript_bus,
        }
    }
}
