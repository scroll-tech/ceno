use core::borrow::Borrow;

use openvm_circuit_primitives::{SubAir, utils::assert_array_eq};
use openvm_stark_backend::{
    BaseAirWithPublicValues, PartitionedBaseAir, interaction::InteractionBuilder,
};
use openvm_stark_sdk::config::baby_bear_poseidon2::D_EF;
use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::{Field, PrimeCharacteristicRing, extension::BinomiallyExtendable};
use p3_matrix::Matrix;
use recursion_circuit::{
    subairs::nested_for_loop::{NestedForLoopIoCols, NestedForLoopSubAir},
    utils::{
        assert_one_ext, ext_field_add, ext_field_multiply, ext_field_multiply_scalar,
        ext_field_one_minus, ext_field_subtract,
    },
};
use stark_recursion_circuit_derive::AlignedBorrow;

use crate::bus::{
    MainSumcheckInputBus, MainSumcheckInputMessage, MainSumcheckOutputBus,
    MainSumcheckOutputMessage,
};

#[repr(C)]
#[derive(AlignedBorrow, Debug)]
pub struct MainSumcheckCols<T> {
    pub is_enabled: T,
    pub proof_idx: T,
    pub idx: T,
    pub is_first_idx: T,
    pub is_first_round: T,
    pub is_last_round: T,
    pub is_dummy: T,
    pub round: T,
    pub tidx: T,
    pub ev1: [T; D_EF],
    pub ev2: [T; D_EF],
    pub ev3: [T; D_EF],
    pub claim_in: [T; D_EF],
    pub claim_out: [T; D_EF],
    pub prev_challenge: [T; D_EF],
    pub challenge: [T; D_EF],
    pub eq_in: [T; D_EF],
    pub eq_out: [T; D_EF],
}

pub struct MainSumcheckAir {
    pub sumcheck_input_bus: MainSumcheckInputBus,
    pub sumcheck_output_bus: MainSumcheckOutputBus,
}

impl<F: Field> BaseAir<F> for MainSumcheckAir {
    fn width(&self) -> usize {
        MainSumcheckCols::<F>::width()
    }
}

impl<F: Field> BaseAirWithPublicValues<F> for MainSumcheckAir {}
impl<F: Field> PartitionedBaseAir<F> for MainSumcheckAir {}

impl<AB> Air<AB> for MainSumcheckAir
where
    AB: AirBuilder + InteractionBuilder,
    <AB::Expr as PrimeCharacteristicRing>::PrimeSubfield: BinomiallyExtendable<{ D_EF }>,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let (local_row, next_row) = (
            main.row_slice(0).expect("window should have two elements"),
            main.row_slice(1).expect("window should have two elements"),
        );
        let local: &MainSumcheckCols<AB::Var> = (*local_row).borrow();
        let next: &MainSumcheckCols<AB::Var> = (*next_row).borrow();

        builder.assert_bool(local.is_dummy.clone());
        builder.assert_bool(local.is_last_round.clone());
        builder.assert_bool(local.is_first_round.clone());

        type LoopSubAir = NestedForLoopSubAir<2>;
        LoopSubAir {}.eval(
            builder,
            (
                NestedForLoopIoCols {
                    is_enabled: local.is_enabled,
                    counter: [local.proof_idx, local.idx],
                    is_first: [local.is_first_idx, local.is_first_round.clone()],
                }
                .map_into(),
                NestedForLoopIoCols {
                    is_enabled: next.is_enabled,
                    counter: [next.proof_idx, next.idx],
                    is_first: [next.is_first_idx, next.is_first_round.clone()],
                }
                .map_into(),
            ),
        );

        let is_transition_round =
            LoopSubAir::local_is_transition(next.is_enabled, next.is_first_round.clone());
        let computed_is_last = LoopSubAir::local_is_last(
            local.is_enabled,
            next.is_enabled,
            next.is_first_round.clone(),
        );

        builder
            .when(local.is_enabled.clone())
            .assert_eq(local.is_last_round.clone(), computed_is_last.clone());

        builder
            .when(local.is_first_round.clone())
            .assert_zero(local.round);
        builder
            .when(is_transition_round.clone())
            .assert_eq(next.round, local.round.clone() + AB::Expr::ONE);

        builder.when(is_transition_round.clone()).assert_eq(
            next.tidx,
            local.tidx.clone().into() + AB::Expr::from_usize(4 * D_EF),
        );

        assert_one_ext(&mut builder.when(local.is_first_round.clone()), local.eq_in);
        let eq_out = update_eq(local.eq_in, local.prev_challenge, local.challenge);
        assert_array_eq(
            &mut builder.when(local.is_enabled.clone()),
            local.eq_out,
            eq_out,
        );
        assert_array_eq(
            &mut builder.when(is_transition_round.clone()),
            local.eq_out,
            next.eq_in,
        );

        let ev0 = ext_field_subtract(local.claim_in, local.ev1);
        let claim_out =
            interpolate_cubic_at_0123(ev0, local.ev1, local.ev2, local.ev3, local.challenge);
        assert_array_eq(builder, local.claim_out, claim_out);
        assert_array_eq(
            &mut builder.when(is_transition_round.clone()),
            local.claim_out,
            next.claim_in,
        );

        let is_not_dummy = AB::Expr::ONE - local.is_dummy.clone();

        let receive_mask =
            local.is_enabled.clone() * local.is_first_round.clone() * is_not_dummy.clone();
        self.sumcheck_input_bus.receive(
            builder,
            local.proof_idx,
            MainSumcheckInputMessage {
                idx: local.idx.into(),
                tidx: local.tidx.into(),
                claim: local.claim_in.map(Into::into),
            },
            receive_mask,
        );

        let send_mask = local.is_enabled.clone() * local.is_last_round.clone() * is_not_dummy;
        self.sumcheck_output_bus.send(
            builder,
            local.proof_idx,
            MainSumcheckOutputMessage {
                idx: local.idx.into(),
                claim: local.claim_out.map(Into::into),
            },
            send_mask,
        );
    }
}

fn interpolate_cubic_at_0123<F, FA>(
    ev0: [FA; D_EF],
    ev1: [F; D_EF],
    ev2: [F; D_EF],
    ev3: [F; D_EF],
    x: [F; D_EF],
) -> [FA; D_EF]
where
    F: Into<FA> + Copy,
    FA: PrimeCharacteristicRing,
    FA::PrimeSubfield: BinomiallyExtendable<{ D_EF }>,
{
    let three: FA = FA::from_usize(3);
    let inv2: FA = FA::from_prime_subfield(FA::PrimeSubfield::from_usize(2).inverse());
    let inv6: FA = FA::from_prime_subfield(FA::PrimeSubfield::from_usize(6).inverse());

    let s1: [FA; D_EF] = ext_field_subtract(ev1, ev0.clone());
    let s2: [FA; D_EF] = ext_field_subtract(ev2, ev0.clone());
    let s3: [FA; D_EF] = ext_field_subtract(ev3, ev0.clone());

    let d3: [FA; D_EF] = ext_field_subtract::<FA>(
        s3,
        ext_field_multiply_scalar::<FA>(ext_field_subtract::<FA>(s2.clone(), s1.clone()), three),
    );

    let p: [FA; D_EF] = ext_field_multiply_scalar(d3.clone(), inv6);

    let q: [FA; D_EF] = ext_field_subtract::<FA>(
        ext_field_multiply_scalar::<FA>(ext_field_subtract::<FA>(s2, d3), inv2),
        s1.clone(),
    );

    let r: [FA; D_EF] = ext_field_subtract::<FA>(s1, ext_field_add::<FA>(p.clone(), q.clone()));

    ext_field_add::<FA>(
        ext_field_multiply::<FA>(
            ext_field_add::<FA>(
                ext_field_multiply::<FA>(ext_field_add::<FA>(ext_field_multiply::<FA>(p, x), q), x),
                r,
            ),
            x,
        ),
        ev0,
    )
}

fn update_eq<F, FA>(eq_in: [F; D_EF], prev_challenge: [F; D_EF], challenge: [F; D_EF]) -> [FA; D_EF]
where
    F: Into<FA> + Copy,
    FA: PrimeCharacteristicRing,
    FA::PrimeSubfield: BinomiallyExtendable<{ D_EF }>,
{
    ext_field_multiply::<FA>(
        eq_in,
        ext_field_add::<FA>(
            ext_field_multiply::<FA>(prev_challenge, challenge),
            ext_field_multiply::<FA>(
                ext_field_one_minus::<FA>(prev_challenge),
                ext_field_one_minus::<FA>(challenge),
            ),
        ),
    )
}
