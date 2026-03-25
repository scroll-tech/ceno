use core::borrow::Borrow;

use openvm_circuit_primitives::{SubAir, utils::assert_array_eq};
use openvm_stark_backend::{
    BaseAirWithPublicValues, PartitionedBaseAir, interaction::InteractionBuilder,
};
use openvm_stark_sdk::config::baby_bear_poseidon2::D_EF;
use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_matrix::Matrix;
use recursion_circuit::subairs::nested_for_loop::{NestedForLoopIoCols, NestedForLoopSubAir};
use stark_recursion_circuit_derive::AlignedBorrow;

use crate::bus::{
    MainBus, MainExpressionClaimBus, MainExpressionClaimMessage, MainMessage, MainSumcheckInputBus,
    MainSumcheckInputMessage, MainSumcheckOutputBus, MainSumcheckOutputMessage,
};

#[repr(C)]
#[derive(AlignedBorrow, Debug)]
pub struct MainCols<T> {
    pub is_enabled: T,
    pub proof_idx: T,
    pub idx: T,
    pub is_first_idx: T,
    pub is_first: T,
    pub is_dummy: T,
    pub tidx: T,
    pub claim_in: [T; D_EF],
    pub claim_out: [T; D_EF],
}

pub struct MainAir {
    pub main_bus: MainBus,
    pub sumcheck_input_bus: MainSumcheckInputBus,
    pub sumcheck_output_bus: MainSumcheckOutputBus,
    pub expression_claim_bus: MainExpressionClaimBus,
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

        #[cfg(not(debug_assertions))]
        builder.assert_bool(local.is_dummy);

        #[cfg(not(debug_assertions))]
        {
        type LoopSubAir = NestedForLoopSubAir<2>;
        LoopSubAir {}.eval(
            builder,
            (
                NestedForLoopIoCols {
                    is_enabled: local.is_enabled,
                    counter: [local.proof_idx, local.idx],
                    is_first: [local.is_first_idx, local.is_first],
                }
                .map_into(),
                NestedForLoopIoCols {
                    is_enabled: next.is_enabled,
                    counter: [next.proof_idx, next.idx],
                    is_first: [next.is_first_idx, next.is_first],
                }
                .map_into(),
            ),
        );
        }

        let is_not_dummy = AB::Expr::ONE - local.is_dummy;
        let receive_mask = local.is_enabled * local.is_first * is_not_dummy.clone();
        self.main_bus.receive(
            builder,
            local.proof_idx,
            MainMessage {
                idx: local.idx.into(),
                tidx: local.tidx.into(),
                claim: local.claim_in.map(Into::into),
            },
            receive_mask,
        );

        self.sumcheck_input_bus.send(
            builder,
            local.proof_idx,
            MainSumcheckInputMessage {
                idx: local.idx.into(),
                tidx: local.tidx.into(),
                claim: local.claim_in.map(Into::into),
            },
            local.is_enabled * is_not_dummy.clone(),
        );

        self.sumcheck_output_bus.receive(
            builder,
            local.proof_idx,
            MainSumcheckOutputMessage {
                idx: local.idx.into(),
                claim: local.claim_out.map(Into::into),
            },
            local.is_enabled * is_not_dummy.clone(),
        );

        #[cfg(not(debug_assertions))]
        assert_array_eq(
            &mut builder.when(local.is_enabled * is_not_dummy.clone()),
            local.claim_in,
            local.claim_out,
        );

        self.expression_claim_bus.send(
            builder,
            local.proof_idx,
            MainExpressionClaimMessage {
                idx: local.idx.into(),
                claim: local.claim_out.map(Into::into),
            },
            local.is_enabled * local.is_first * is_not_dummy,
        );
    }
}
