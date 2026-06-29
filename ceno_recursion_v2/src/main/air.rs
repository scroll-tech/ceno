use core::borrow::Borrow;

use openvm_circuit_primitives::utils::assert_array_eq;
use openvm_stark_backend::{
    BaseAirWithPublicValues, PartitionedBaseAir, interaction::InteractionBuilder,
};
use openvm_stark_sdk::config::baby_bear_poseidon2::D_EF;
use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_matrix::Matrix;
use stark_recursion_circuit_derive::AlignedBorrow;

use crate::bus::{
    MainBus, MainExpressionClaimBus, MainExpressionClaimMessage, MainMessage, MainSumcheckInputBus,
    MainSumcheckInputMessage, MainSumcheckOutputBus, MainSumcheckOutputMessage, TranscriptBus,
};

#[repr(C)]
#[derive(AlignedBorrow, Debug)]
pub struct MainCols<T> {
    pub is_enabled: T,
    pub proof_idx: T,
    pub idx: T,
    pub chip_id: T,
    pub is_first_idx: T,
    pub is_first: T,
    pub has_tower: T,
    pub has_sumcheck: T,
    pub tidx: T,
    pub claim_in: [T; D_EF],
    pub claim_out: [T; D_EF],
}

pub struct MainAir {
    pub main_bus: MainBus,
    pub sumcheck_input_bus: MainSumcheckInputBus,
    pub sumcheck_output_bus: MainSumcheckOutputBus,
    pub expression_claim_bus: MainExpressionClaimBus,
    pub transcript_bus: TranscriptBus,
}

impl<F: Field> BaseAir<F> for MainAir {
    fn width(&self) -> usize {
        MainCols::<F>::width()
    }
}

impl<F: Field> BaseAirWithPublicValues<F> for MainAir {}
impl<F: Field> PartitionedBaseAir<F> for MainAir {}

impl<AB: AirBuilder + InteractionBuilder> Air<AB> for MainAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let (local_row, next_row) = (
            main.row_slice(0).expect("window should have two elements"),
            main.row_slice(1).expect("window should have two elements"),
        );
        let local: &MainCols<AB::Var> = (*local_row).borrow();
        let next: &MainCols<AB::Var> = (*next_row).borrow();

        builder.assert_bool(local.is_enabled);
        builder.assert_bool(local.is_first_idx);
        builder.assert_bool(local.is_first);
        builder.assert_bool(local.has_tower);
        builder.assert_bool(local.has_sumcheck);
        builder
            .when_transition()
            .when(AB::Expr::ONE - local.is_enabled)
            .assert_zero(next.is_enabled);
        builder
            .when_first_row()
            .when(local.is_enabled)
            .assert_zero(local.proof_idx);
        builder
            .when_first_row()
            .when(local.is_enabled)
            .assert_one(local.is_first_idx);

        let proof_diff = next.proof_idx - local.proof_idx;
        builder
            .when_transition()
            .when(next.is_enabled)
            .assert_bool(proof_diff.clone());
        builder
            .when_transition()
            .when(next.is_enabled * proof_diff.clone())
            .assert_one(next.is_first_idx);
        builder
            .when_transition()
            .when(next.is_enabled * (AB::Expr::ONE - proof_diff))
            .assert_zero(next.is_first_idx);

        let receive_mask = local.is_enabled * local.is_first * local.has_tower;
        self.main_bus.receive(
            builder,
            local.proof_idx,
            MainMessage {
                chip_id: local.chip_id.into(),
                tidx: local.tidx.into(),
                claim: local.claim_in.map(Into::into),
            },
            receive_mask,
        );

        let sumcheck_mask = local.is_enabled * local.has_sumcheck;
        self.sumcheck_input_bus.send(
            builder,
            local.proof_idx,
            MainSumcheckInputMessage {
                idx: local.idx.into(),
                tidx: local.tidx.into(),
                claim: local.claim_in.map(Into::into),
            },
            sumcheck_mask.clone(),
        );

        self.sumcheck_output_bus.receive(
            builder,
            local.proof_idx,
            MainSumcheckOutputMessage {
                idx: local.idx.into(),
                claim: local.claim_out.map(Into::into),
            },
            sumcheck_mask,
        );

        assert_array_eq(
            &mut builder.when(local.is_enabled),
            local.claim_in,
            local.claim_out,
        );

        let _ = (
            &self.expression_claim_bus,
            MainExpressionClaimMessage {
                idx: local.idx.into(),
                claim: local.claim_out.map(Into::into),
            },
        );

        self.transcript_bus.observe_ext(
            builder,
            local.proof_idx,
            local.tidx.into(),
            local.claim_in,
            local.is_enabled * local.has_tower,
        );
    }
}
