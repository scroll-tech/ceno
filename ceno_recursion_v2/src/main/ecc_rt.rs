use core::borrow::{Borrow, BorrowMut};

use openvm_circuit_primitives::utils::assert_array_eq;
use openvm_stark_backend::{
    BaseAirWithPublicValues, PartitionedBaseAir, interaction::InteractionBuilder,
};
use openvm_stark_sdk::config::baby_bear_poseidon2::{D_EF, EF, F};
use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::{BasedVectorSpace, Field, PrimeCharacteristicRing, extension::BinomiallyExtendable};
use p3_matrix::{Matrix, dense::RowMajorMatrix};
use recursion_circuit::utils::{
    ext_field_add, ext_field_multiply, ext_field_multiply_scalar, ext_field_one_minus,
    ext_field_subtract,
};
use stark_recursion_circuit_derive::AlignedBorrow;

use crate::{
    bus::{
        EccRtBus, EccRtMessage, ForkedTranscriptBus, ForkedTranscriptBusMessage,
        MainEccRtChallengeBus, MainEccRtChallengeKind, MainEccRtChallengeMessage,
        MainEccRtEquationTotalsBus, MainEccRtEquationTotalsMessage, MainEccRtQuarkFinalBus,
        MainEccRtQuarkFinalMessage, MainEccRtSumcheckFinalBus, MainEccRtSumcheckFinalMessage,
    },
    system::MainEccRtRecord,
    tracegen::RowMajorChip,
};

const SEPTIC_DEGREE: usize = 7;
const ECC_EQUATION_FAMILIES: usize = 7;
const MAX_ECC_VARS: usize = 32;

#[repr(C)]
#[derive(AlignedBorrow, Debug)]
pub struct MainEccRtChallengeCols<T> {
    pub is_enabled: T,
    pub proof_idx: T,
    pub idx: T,
    pub fork_id: T,
    pub round_idx: T,
    pub num_rounds: T,
    pub is_first: T,
    pub tidx: T,
    pub out_tidx: T,
    pub alpha_tidx: T,
    pub lookup_count: T,
    pub rt: [T; D_EF],
    pub out_rt: [T; D_EF],
    pub alpha: [T; D_EF],
}

#[repr(C)]
#[derive(AlignedBorrow, Debug)]
pub struct MainEccRtCols<T> {
    pub is_enabled: T,
    pub proof_idx: T,
    pub idx: T,
    pub round_idx: T,
    pub is_first: T,
    pub is_last: T,
    pub rt: [T; D_EF],
    pub out_rt: [T; D_EF],
    pub sumcheck_final_claim: [T; D_EF],
    pub sel_add: [T; D_EF],
    pub sel_bypass: [T; D_EF],
    pub sel_export: [T; D_EF],
    pub eq_in: [T; D_EF],
    pub eq_out: [T; D_EF],
    pub last_in: [T; D_EF],
    pub last_out: [T; D_EF],
    pub export_out_in: [T; D_EF],
    pub export_out_out: [T; D_EF],
    pub export_rt_in: [T; D_EF],
    pub export_rt_out: [T; D_EF],
    pub quark_out: [T; D_EF],
    pub add_eval: [T; D_EF],
    pub bypass_eval: [T; D_EF],
    pub export_eval: [T; D_EF],
}

#[repr(C)]
#[derive(AlignedBorrow, Debug)]
pub struct MainEccRtEquationCols<T> {
    pub is_enabled: T,
    pub proof_idx: T,
    pub idx: T,
    pub family_idx: T,
    pub septic_idx: T,
    pub is_first: T,
    pub is_last: T,
    pub family_flags: [T; ECC_EQUATION_FAMILIES],
    pub septic_flags: [T; SEPTIC_DEGREE],
    pub alpha: [T; D_EF],
    pub alpha_pow: [T; D_EF],
    pub s0: [T; D_EF],
    pub s0_all: [[T; D_EF]; SEPTIC_DEGREE],
    pub x0: [T; D_EF],
    pub x0_all: [[T; D_EF]; SEPTIC_DEGREE],
    pub y0: [T; D_EF],
    pub x1: [T; D_EF],
    pub x1_all: [[T; D_EF]; SEPTIC_DEGREE],
    pub y1: [T; D_EF],
    pub x3: [T; D_EF],
    pub x3_all: [[T; D_EF]; SEPTIC_DEGREE],
    pub y3: [T; D_EF],
    pub sum_x: [T; D_EF],
    pub sum_y: [T; D_EF],
    pub s0_x0_x1: [T; D_EF],
    pub s0_squared: [T; D_EF],
    pub s0_x0_x3: [T; D_EF],
    pub add_in: [T; D_EF],
    pub add_out: [T; D_EF],
    pub bypass_in: [T; D_EF],
    pub bypass_out: [T; D_EF],
    pub export_in: [T; D_EF],
    pub export_out: [T; D_EF],
}

#[repr(C)]
#[derive(AlignedBorrow, Debug)]
pub struct MainEccRtSumcheckCols<T> {
    pub is_enabled: T,
    pub proof_idx: T,
    pub idx: T,
    pub round_idx: T,
    pub is_first: T,
    pub is_last: T,
    pub rt: [T; D_EF],
    pub ev1: [T; D_EF],
    pub ev2: [T; D_EF],
    pub ev3: [T; D_EF],
    pub claim_in: [T; D_EF],
    pub claim_out: [T; D_EF],
}

#[repr(C)]
#[derive(AlignedBorrow, Debug)]
pub struct MainEccRtQuarkCols<T> {
    pub is_enabled: T,
    pub proof_idx: T,
    pub idx: T,
    pub round_idx: T,
    pub bit_idx: T,
    pub bit_weight: T,
    pub is_first_round: T,
    pub is_last_round: T,
    pub is_first_bit: T,
    pub is_last_bit: T,
    pub is_active: T,
    pub bit: T,
    pub current_rt: [T; D_EF],
    pub current_out_rt: [T; D_EF],
    pub point_rt: [T; D_EF],
    pub point_out_rt: [T; D_EF],
    pub same_one: [T; D_EF],
    pub same_zero: [T; D_EF],
    pub equal_choice: [T; D_EF],
    pub active_prefix: [T; D_EF],
    pub prefix_in: [T; D_EF],
    pub prefix_out: [T; D_EF],
    pub less_in: [T; D_EF],
    pub less_from_prior: [T; D_EF],
    pub less_from_equal: [T; D_EF],
    pub active_less: [T; D_EF],
    pub less_out: [T; D_EF],
    pub active_count_in: T,
    pub active_count_out: T,
    pub bit_value_in: T,
    pub bit_value_out: T,
    pub quark_prefix_count: T,
    pub quark_prefix_is_zero: T,
    pub quark_prefix_inv: T,
    pub quark_layer_n: T,
    pub quark_parity: T,
    pub quark_in: [T; D_EF],
    pub quark_factor: [T; D_EF],
    pub quark_zero: [T; D_EF],
    pub quark_one: [T; D_EF],
    pub quark_lhs: [T; D_EF],
    pub quark_rhs: [T; D_EF],
    pub quark_out: [T; D_EF],
}

pub struct MainEccRtChallengeAir {
    pub forked_transcript_bus: ForkedTranscriptBus,
    pub ecc_rt_bus: EccRtBus,
    pub challenge_bus: MainEccRtChallengeBus,
}

impl<F: Field> BaseAir<F> for MainEccRtChallengeAir {
    fn width(&self) -> usize {
        MainEccRtChallengeCols::<F>::width()
    }
}

impl<F: Field> BaseAirWithPublicValues<F> for MainEccRtChallengeAir {}
impl<F: Field> PartitionedBaseAir<F> for MainEccRtChallengeAir {}

impl<AB> Air<AB> for MainEccRtChallengeAir
where
    AB: AirBuilder + InteractionBuilder,
    <AB::Expr as PrimeCharacteristicRing>::PrimeSubfield: BinomiallyExtendable<{ D_EF }>,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let (local_row, next_row) = (
            main.row_slice(0).expect("main row exists"),
            main.row_slice(1).expect("next row exists"),
        );
        let local: &MainEccRtChallengeCols<AB::Var> = (*local_row).borrow();
        let next: &MainEccRtChallengeCols<AB::Var> = (*next_row).borrow();

        builder.assert_bool(local.is_enabled);
        builder.assert_bool(local.is_first);

        for i in 0..D_EF {
            self.forked_transcript_bus.receive(
                builder,
                local.proof_idx,
                ForkedTranscriptBusMessage {
                    fork_id: local.fork_id.into(),
                    tidx: local.tidx + AB::Expr::from_usize(i),
                    value: local.rt[i].into(),
                    is_sample: AB::Expr::ONE,
                },
                local.is_enabled,
            );
            self.forked_transcript_bus.receive(
                builder,
                local.proof_idx,
                ForkedTranscriptBusMessage {
                    fork_id: local.fork_id.into(),
                    tidx: local.out_tidx + AB::Expr::from_usize(i),
                    value: local.out_rt[i].into(),
                    is_sample: AB::Expr::ONE,
                },
                local.is_enabled,
            );
            self.forked_transcript_bus.receive(
                builder,
                local.proof_idx,
                ForkedTranscriptBusMessage {
                    fork_id: local.fork_id.into(),
                    tidx: local.alpha_tidx + AB::Expr::from_usize(i),
                    value: local.alpha[i].into(),
                    is_sample: AB::Expr::ONE,
                },
                local.is_enabled * local.is_first,
            );
        }

        self.ecc_rt_bus.add_key_with_lookups(
            builder,
            local.proof_idx,
            EccRtMessage {
                idx: local.idx.into(),
                round_idx: local.round_idx.into(),
                value: local.rt.map(Into::into),
            },
            local.is_enabled * local.lookup_count,
        );

        self.challenge_bus.add_key_with_lookups(
            builder,
            local.proof_idx,
            MainEccRtChallengeMessage {
                idx: local.idx.into(),
                round_idx: local.round_idx.into(),
                kind: AB::Expr::from_usize(MainEccRtChallengeKind::Rt.as_usize()),
                value: local.rt.map(Into::into),
            },
            local.is_enabled * (local.num_rounds - local.round_idx + AB::Expr::from_usize(2)),
        );
        self.challenge_bus.add_key_with_lookups(
            builder,
            local.proof_idx,
            MainEccRtChallengeMessage {
                idx: local.idx.into(),
                round_idx: local.round_idx.into(),
                kind: AB::Expr::from_usize(MainEccRtChallengeKind::OutRt.as_usize()),
                value: local.out_rt.map(Into::into),
            },
            local.is_enabled * (local.num_rounds - local.round_idx + AB::Expr::ONE),
        );
        self.challenge_bus.add_key_with_lookups(
            builder,
            local.proof_idx,
            MainEccRtChallengeMessage {
                idx: local.idx.into(),
                round_idx: local.round_idx.into(),
                kind: AB::Expr::from_usize(MainEccRtChallengeKind::Alpha.as_usize()),
                value: local.alpha.map(Into::into),
            },
            local.is_enabled
                * local.is_first
                * AB::Expr::from_usize(ECC_EQUATION_FAMILIES * SEPTIC_DEGREE),
        );

        let same_ecc = local.is_enabled * next.is_enabled * (AB::Expr::ONE - next.is_first);
        builder
            .when_transition()
            .when(same_ecc.clone())
            .assert_eq(next.proof_idx, local.proof_idx);
        builder
            .when_transition()
            .when(same_ecc.clone())
            .assert_eq(next.idx, local.idx);
        builder
            .when_transition()
            .when(same_ecc.clone())
            .assert_eq(next.fork_id, local.fork_id);
        builder
            .when_transition()
            .when(same_ecc.clone())
            .assert_eq(next.round_idx, local.round_idx + AB::Expr::ONE);
        builder
            .when_transition()
            .when(same_ecc.clone())
            .assert_eq(next.num_rounds, local.num_rounds);
        assert_array_eq(
            &mut builder.when_transition().when(same_ecc),
            local.alpha,
            next.alpha,
        );
    }
}

pub struct MainEccRtAir {
    pub challenge_bus: MainEccRtChallengeBus,
    pub sumcheck_final_bus: MainEccRtSumcheckFinalBus,
    pub equation_totals_bus: MainEccRtEquationTotalsBus,
    pub quark_final_bus: MainEccRtQuarkFinalBus,
}

pub struct MainEccRtEquationAir {
    pub challenge_bus: MainEccRtChallengeBus,
    pub equation_totals_bus: MainEccRtEquationTotalsBus,
}

impl<F: Field> BaseAir<F> for MainEccRtEquationAir {
    fn width(&self) -> usize {
        MainEccRtEquationCols::<F>::width()
    }
}

impl<F: Field> BaseAirWithPublicValues<F> for MainEccRtEquationAir {}
impl<F: Field> PartitionedBaseAir<F> for MainEccRtEquationAir {}

impl<AB> Air<AB> for MainEccRtEquationAir
where
    AB: AirBuilder + InteractionBuilder,
    <AB::Expr as PrimeCharacteristicRing>::PrimeSubfield: BinomiallyExtendable<{ D_EF }>,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let (local_row, next_row) = (
            main.row_slice(0).expect("main row exists"),
            main.row_slice(1).expect("next row exists"),
        );
        let local: &MainEccRtEquationCols<AB::Var> = (*local_row).borrow();
        let next: &MainEccRtEquationCols<AB::Var> = (*next_row).borrow();

        builder.assert_bool(local.is_enabled);
        builder.assert_bool(local.is_first);
        builder.assert_bool(local.is_last);

        let mut family_sum = AB::Expr::ZERO;
        let mut family_idx = AB::Expr::ZERO;
        for (i, flag) in local.family_flags.iter().enumerate() {
            builder.assert_bool(*flag);
            family_sum += *flag;
            family_idx += *flag * AB::Expr::from_usize(i);
        }
        builder
            .when(local.is_enabled)
            .assert_eq(family_sum, AB::Expr::ONE);
        builder
            .when(local.is_enabled)
            .assert_eq(local.family_idx, family_idx);

        let mut septic_sum = AB::Expr::ZERO;
        let mut septic_idx = AB::Expr::ZERO;
        for (i, flag) in local.septic_flags.iter().enumerate() {
            builder.assert_bool(*flag);
            septic_sum += *flag;
            septic_idx += *flag * AB::Expr::from_usize(i);
        }
        builder
            .when(local.is_enabled)
            .assert_eq(septic_sum, AB::Expr::ONE);
        builder
            .when(local.is_enabled)
            .assert_eq(local.septic_idx, septic_idx);

        self.challenge_bus.lookup_key(
            builder,
            local.proof_idx,
            MainEccRtChallengeMessage {
                idx: local.idx.into(),
                round_idx: AB::Expr::ZERO,
                kind: AB::Expr::from_usize(MainEccRtChallengeKind::Alpha.as_usize()),
                value: local.alpha.map(Into::into),
            },
            local.is_enabled,
        );

        assert_array_eq(
            &mut builder.when(local.is_enabled * local.is_first),
            local.alpha_pow,
            ext_one::<AB::Expr>(),
        );
        assert_array_eq(
            &mut builder.when(local.is_enabled * local.is_first),
            local.add_in,
            ext_zero::<AB::Expr>(),
        );
        assert_array_eq(
            &mut builder.when(local.is_enabled * local.is_first),
            local.bypass_in,
            ext_zero::<AB::Expr>(),
        );
        assert_array_eq(
            &mut builder.when(local.is_enabled * local.is_first),
            local.export_in,
            ext_zero::<AB::Expr>(),
        );

        let x0_minus_x1 = core::array::from_fn(|i| {
            ext_field_subtract::<AB::Expr>(local.x0_all[i], local.x1_all[i])
        });
        let x0_minus_x3 = core::array::from_fn(|i| {
            ext_field_subtract::<AB::Expr>(local.x0_all[i], local.x3_all[i])
        });
        let s0_expr = core::array::from_fn(|i| local.s0_all[i].map(Into::into));
        assert_array_eq(
            &mut builder.when(local.is_enabled),
            local.s0_x0_x1,
            septic_mul_selected::<AB>(&local.s0_all, &x0_minus_x1, local.septic_flags),
        );
        assert_array_eq(
            &mut builder.when(local.is_enabled),
            local.s0_squared,
            septic_mul_selected::<AB>(&local.s0_all, &s0_expr, local.septic_flags),
        );
        assert_array_eq(
            &mut builder.when(local.is_enabled),
            local.s0_x0_x3,
            septic_mul_selected::<AB>(&local.s0_all, &x0_minus_x3, local.septic_flags),
        );
        let v1 = ext_field_subtract::<AB::Expr>(
            local.s0_x0_x1,
            ext_field_subtract::<AB::Expr>(local.y0, local.y1),
        );
        let v2 = ext_field_subtract::<AB::Expr>(
            ext_field_subtract::<AB::Expr>(
                ext_field_subtract::<AB::Expr>(local.s0_squared, local.x0),
                local.x1,
            ),
            local.x3,
        );
        let v3 = ext_field_subtract::<AB::Expr>(
            local.s0_x0_x3,
            ext_field_add::<AB::Expr>(local.y0, local.y3),
        );
        let v4 = ext_field_subtract::<AB::Expr>(local.x3, local.x0);
        let v5 = ext_field_subtract::<AB::Expr>(local.y3, local.y0);
        let v6 = ext_field_subtract::<AB::Expr>(local.x3, local.sum_x);
        let v7 = ext_field_subtract::<AB::Expr>(local.y3, local.sum_y);
        let add_term = [v1.clone(), v2.clone(), v3.clone()]
            .into_iter()
            .enumerate()
            .fold(ext_zero::<AB::Expr>(), |acc, (i, term)| {
                ext_field_add::<AB::Expr>(
                    acc,
                    ext_field_multiply_scalar::<AB::Expr>(term, local.family_flags[i]),
                )
            });
        let bypass_term = [v4.clone(), v5.clone()].into_iter().enumerate().fold(
            ext_zero::<AB::Expr>(),
            |acc, (i, term)| {
                ext_field_add::<AB::Expr>(
                    acc,
                    ext_field_multiply_scalar::<AB::Expr>(term, local.family_flags[3 + i]),
                )
            },
        );
        let export_term =
            [v6, v7]
                .into_iter()
                .enumerate()
                .fold(ext_zero::<AB::Expr>(), |acc, (i, term)| {
                    ext_field_add::<AB::Expr>(
                        acc,
                        ext_field_multiply_scalar::<AB::Expr>(term, local.family_flags[5 + i]),
                    )
                });
        let add_weighted = ext_field_multiply::<AB::Expr>(add_term, local.alpha_pow);
        let bypass_weighted = ext_field_multiply::<AB::Expr>(bypass_term, local.alpha_pow);
        let export_weighted = ext_field_multiply::<AB::Expr>(export_term, local.alpha_pow);
        assert_array_eq(
            &mut builder.when(local.is_enabled),
            local.add_out,
            ext_field_add::<AB::Expr>(local.add_in.map(Into::into), add_weighted),
        );
        assert_array_eq(
            &mut builder.when(local.is_enabled),
            local.bypass_out,
            ext_field_add::<AB::Expr>(local.bypass_in.map(Into::into), bypass_weighted),
        );
        assert_array_eq(
            &mut builder.when(local.is_enabled),
            local.export_out,
            ext_field_add::<AB::Expr>(local.export_in.map(Into::into), export_weighted),
        );

        let same_ecc = local.is_enabled * (AB::Expr::ONE - local.is_last);
        let is_septic_last = local.septic_flags[SEPTIC_DEGREE - 1];
        builder
            .when_transition()
            .when(same_ecc.clone())
            .assert_eq(next.proof_idx, local.proof_idx);
        builder
            .when_transition()
            .when(same_ecc.clone())
            .assert_eq(next.idx, local.idx);
        builder.when_transition().when(same_ecc.clone()).assert_eq(
            next.septic_idx,
            local.septic_idx + AB::Expr::ONE - is_septic_last * AB::Expr::from_usize(SEPTIC_DEGREE),
        );
        builder
            .when_transition()
            .when(same_ecc.clone())
            .assert_eq(next.family_idx, local.family_idx + is_septic_last);
        assert_array_eq(
            &mut builder.when_transition().when(same_ecc.clone()),
            next.alpha_pow,
            ext_field_multiply::<AB::Expr>(local.alpha_pow, local.alpha),
        );
        assert_array_eq(
            &mut builder.when_transition().when(same_ecc.clone()),
            local.add_out,
            next.add_in,
        );
        assert_array_eq(
            &mut builder.when_transition().when(same_ecc.clone()),
            local.bypass_out,
            next.bypass_in,
        );
        assert_array_eq(
            &mut builder.when_transition().when(same_ecc),
            local.export_out,
            next.export_in,
        );

        self.equation_totals_bus.send(
            builder,
            local.proof_idx,
            MainEccRtEquationTotalsMessage {
                idx: local.idx.into(),
                add_eval: local.add_out.map(Into::into),
                bypass_eval: local.bypass_out.map(Into::into),
                export_eval: local.export_out.map(Into::into),
            },
            local.is_enabled * local.is_last,
        );
    }
}

pub struct MainEccRtQuarkAir {
    pub challenge_bus: MainEccRtChallengeBus,
    pub quark_final_bus: MainEccRtQuarkFinalBus,
}

impl<F: Field> BaseAir<F> for MainEccRtQuarkAir {
    fn width(&self) -> usize {
        MainEccRtQuarkCols::<F>::width()
    }
}

impl<F: Field> BaseAirWithPublicValues<F> for MainEccRtQuarkAir {}
impl<F: Field> PartitionedBaseAir<F> for MainEccRtQuarkAir {}

impl<AB> Air<AB> for MainEccRtQuarkAir
where
    AB: AirBuilder + InteractionBuilder,
    <AB::Expr as PrimeCharacteristicRing>::PrimeSubfield: BinomiallyExtendable<{ D_EF }>,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let (local_row, next_row) = (
            main.row_slice(0).expect("main row exists"),
            main.row_slice(1).expect("next row exists"),
        );
        let local: &MainEccRtQuarkCols<AB::Var> = (*local_row).borrow();
        let next: &MainEccRtQuarkCols<AB::Var> = (*next_row).borrow();

        builder.assert_bool(local.is_enabled);
        builder.assert_bool(local.is_first_round);
        builder.assert_bool(local.is_last_round);
        builder.assert_bool(local.is_first_bit);
        builder.assert_bool(local.is_last_bit);
        builder.assert_bool(local.is_active);
        builder.assert_bool(local.bit);
        builder.assert_bool(local.quark_parity);
        builder.assert_bool(local.quark_prefix_is_zero);
        builder
            .when(local.is_enabled * local.is_first_bit)
            .assert_eq(
                local.bit_weight,
                AB::Expr::from_usize(1usize << (MAX_ECC_VARS - 1)),
            );
        builder
            .when(local.is_enabled)
            .assert_zero(local.bit * (AB::Expr::ONE - local.is_active));
        builder
            .when(local.is_enabled)
            .assert_zero(local.quark_prefix_is_zero * local.quark_prefix_count);
        builder.when(local.is_enabled).assert_eq(
            local.quark_prefix_count * local.quark_prefix_inv,
            AB::Expr::ONE - local.quark_prefix_is_zero,
        );
        builder.when(local.is_enabled).assert_eq(
            local.quark_layer_n,
            local.quark_prefix_count * AB::Expr::from_usize(2) + local.quark_parity,
        );

        self.challenge_bus.lookup_key(
            builder,
            local.proof_idx,
            MainEccRtChallengeMessage {
                idx: local.idx.into(),
                round_idx: local.round_idx.into(),
                kind: AB::Expr::from_usize(MainEccRtChallengeKind::Rt.as_usize()),
                value: local.current_rt.map(Into::into),
            },
            local.is_enabled * local.is_first_bit,
        );
        self.challenge_bus.lookup_key(
            builder,
            local.proof_idx,
            MainEccRtChallengeMessage {
                idx: local.idx.into(),
                round_idx: local.round_idx.into(),
                kind: AB::Expr::from_usize(MainEccRtChallengeKind::OutRt.as_usize()),
                value: local.current_out_rt.map(Into::into),
            },
            local.is_enabled * local.is_first_bit,
        );
        self.challenge_bus.lookup_key(
            builder,
            local.proof_idx,
            MainEccRtChallengeMessage {
                idx: local.idx.into(),
                round_idx: local.bit_idx.into(),
                kind: AB::Expr::from_usize(MainEccRtChallengeKind::Rt.as_usize()),
                value: local.point_rt.map(Into::into),
            },
            local.is_enabled * local.is_active,
        );
        self.challenge_bus.lookup_key(
            builder,
            local.proof_idx,
            MainEccRtChallengeMessage {
                idx: local.idx.into(),
                round_idx: local.bit_idx.into(),
                kind: AB::Expr::from_usize(MainEccRtChallengeKind::OutRt.as_usize()),
                value: local.point_out_rt.map(Into::into),
            },
            local.is_enabled * local.is_active,
        );

        assert_array_eq(
            &mut builder.when(local.is_enabled * local.is_first_bit),
            local.prefix_in,
            ext_one::<AB::Expr>(),
        );
        assert_array_eq(
            &mut builder.when(local.is_enabled * local.is_first_bit),
            local.less_in,
            ext_zero::<AB::Expr>(),
        );
        builder
            .when(local.is_enabled * local.is_first_bit)
            .assert_zero(local.active_count_in);
        builder
            .when(local.is_enabled * local.is_first_bit)
            .assert_zero(local.bit_value_in);
        assert_array_eq(
            &mut builder.when(local.is_enabled * local.is_first_round),
            local.quark_in,
            ext_zero::<AB::Expr>(),
        );

        assert_array_eq(
            &mut builder.when(local.is_enabled),
            local.same_one,
            ext_field_multiply::<AB::Expr>(local.point_out_rt, local.point_rt),
        );
        assert_array_eq(
            &mut builder.when(local.is_enabled),
            local.same_zero,
            ext_field_multiply::<AB::Expr>(
                one_minus_ext::<AB>(local.point_out_rt),
                one_minus_ext::<AB>(local.point_rt),
            ),
        );
        assert_array_eq(
            &mut builder.when(local.is_enabled),
            local.equal_choice,
            choose_ext::<AB>(
                local.bit,
                local.same_one.map(Into::into),
                local.same_zero.map(Into::into),
            ),
        );
        assert_array_eq(
            &mut builder.when(local.is_enabled),
            local.active_prefix,
            ext_field_multiply::<AB::Expr>(local.prefix_in, local.equal_choice),
        );
        assert_array_eq(
            &mut builder.when(local.is_enabled),
            local.prefix_out,
            choose_ext::<AB>(
                local.is_active,
                local.active_prefix.map(Into::into),
                local.prefix_in.map(Into::into),
            ),
        );
        let same_any = ext_field_add::<AB::Expr>(
            local.same_one.map(Into::into),
            local.same_zero.map(Into::into),
        );
        assert_array_eq(
            &mut builder.when(local.is_enabled),
            local.less_from_prior,
            ext_field_multiply::<AB::Expr>(local.less_in, same_any),
        );
        assert_array_eq(
            &mut builder.when(local.is_enabled),
            local.less_from_equal,
            ext_field_multiply::<AB::Expr>(local.prefix_in, local.same_zero.map(Into::into)),
        );
        assert_array_eq(
            &mut builder.when(local.is_enabled),
            local.active_less,
            ext_field_add::<AB::Expr>(
                local.less_from_prior.map(Into::into),
                ext_field_multiply_scalar::<AB::Expr>(
                    local.less_from_equal.map(Into::into),
                    local.bit,
                ),
            ),
        );
        assert_array_eq(
            &mut builder.when(local.is_enabled),
            local.less_out,
            choose_ext::<AB>(
                local.is_active,
                local.active_less.map(Into::into),
                local.less_in.map(Into::into),
            ),
        );
        builder.when(local.is_enabled).assert_eq(
            local.active_count_out,
            local.active_count_in + local.is_active,
        );
        builder.when(local.is_enabled).assert_eq(
            local.bit_value_out,
            local.bit_value_in + local.bit * local.bit_weight,
        );
        builder
            .when(local.is_enabled * local.is_last_bit)
            .assert_eq(local.active_count_out, local.round_idx);
        builder
            .when(local.is_enabled * local.is_last_bit)
            .assert_zero(
                (AB::Expr::ONE - local.quark_prefix_is_zero)
                    * (local.bit_value_out + AB::Expr::ONE - local.quark_prefix_count),
            );

        assert_array_eq(
            &mut builder.when(local.is_enabled * local.is_first_round),
            local.quark_factor,
            ext_one::<AB::Expr>(),
        );
        assert_array_eq(
            &mut builder.when(local.is_enabled * local.quark_prefix_is_zero),
            local.quark_factor,
            ext_zero::<AB::Expr>(),
        );
        let lte_value = ext_field_add::<AB::Expr>(local.prefix_out, local.less_out);
        assert_array_eq(
            &mut builder.when(
                local.is_enabled
                    * local.is_last_bit
                    * (AB::Expr::ONE - local.is_first_round)
                    * (AB::Expr::ONE - local.quark_prefix_is_zero),
            ),
            local.quark_factor,
            lte_value,
        );
        assert_array_eq(
            &mut builder.when(local.is_enabled * local.is_last_bit),
            local.quark_zero,
            ext_field_multiply::<AB::Expr>(
                one_minus_ext::<AB>(local.current_out_rt),
                one_minus_ext::<AB>(local.current_rt),
            ),
        );
        assert_array_eq(
            &mut builder.when(local.is_enabled * local.is_last_bit),
            local.quark_one,
            ext_field_multiply::<AB::Expr>(local.current_out_rt, local.current_rt),
        );
        assert_array_eq(
            &mut builder.when(local.is_enabled * local.is_last_bit),
            local.quark_lhs,
            ext_field_multiply::<AB::Expr>(local.quark_zero, local.quark_factor),
        );
        assert_array_eq(
            &mut builder.when(local.is_enabled * local.is_last_bit),
            local.quark_rhs,
            ext_field_multiply::<AB::Expr>(local.quark_one, local.quark_in),
        );
        assert_array_eq(
            &mut builder.when(local.is_enabled * local.is_last_bit),
            local.quark_out,
            ext_field_add::<AB::Expr>(
                local.quark_lhs.map(Into::into),
                local.quark_rhs.map(Into::into),
            ),
        );

        let same_round = local.is_enabled * (AB::Expr::ONE - local.is_last_bit);
        builder
            .when_transition()
            .when(same_round.clone())
            .assert_one(next.is_enabled);
        builder
            .when_transition()
            .when(same_round.clone())
            .assert_eq(next.proof_idx, local.proof_idx);
        builder
            .when_transition()
            .when(same_round.clone())
            .assert_eq(next.idx, local.idx);
        builder
            .when_transition()
            .when(same_round.clone())
            .assert_eq(next.round_idx, local.round_idx);
        builder
            .when_transition()
            .when(same_round.clone())
            .assert_eq(next.bit_idx + AB::Expr::ONE, local.bit_idx);
        builder
            .when_transition()
            .when(same_round.clone())
            .assert_eq(local.bit_weight, next.bit_weight * AB::Expr::from_usize(2));
        builder
            .when_transition()
            .when(same_round.clone())
            .assert_zero(local.is_active * (AB::Expr::ONE - next.is_active));
        assert_array_eq(
            &mut builder.when_transition().when(same_round.clone()),
            local.prefix_out,
            next.prefix_in,
        );
        assert_array_eq(
            &mut builder.when_transition().when(same_round.clone()),
            local.less_out,
            next.less_in,
        );
        builder
            .when_transition()
            .when(same_round.clone())
            .assert_eq(next.active_count_in, local.active_count_out);
        builder
            .when_transition()
            .when(same_round.clone())
            .assert_eq(next.bit_value_in, local.bit_value_out);
        assert_array_eq(
            &mut builder.when_transition().when(same_round.clone()),
            local.current_rt,
            next.current_rt,
        );
        assert_array_eq(
            &mut builder.when_transition().when(same_round.clone()),
            local.current_out_rt,
            next.current_out_rt,
        );
        assert_array_eq(
            &mut builder.when_transition().when(same_round.clone()),
            local.quark_in,
            next.quark_in,
        );
        assert_array_eq(
            &mut builder.when_transition().when(same_round.clone()),
            local.quark_factor,
            next.quark_factor,
        );
        builder
            .when_transition()
            .when(same_round.clone())
            .assert_eq(next.quark_prefix_count, local.quark_prefix_count);
        builder
            .when_transition()
            .when(same_round.clone())
            .assert_eq(next.quark_prefix_is_zero, local.quark_prefix_is_zero);
        builder
            .when_transition()
            .when(same_round.clone())
            .assert_eq(next.quark_prefix_inv, local.quark_prefix_inv);
        builder
            .when_transition()
            .when(same_round.clone())
            .assert_eq(next.quark_layer_n, local.quark_layer_n);
        builder
            .when_transition()
            .when(same_round)
            .assert_eq(next.quark_parity, local.quark_parity);

        let next_round =
            local.is_enabled * local.is_last_bit * (AB::Expr::ONE - local.is_last_round);
        builder
            .when_transition()
            .when(next_round.clone())
            .assert_one(next.is_enabled);
        builder
            .when_transition()
            .when(next_round.clone())
            .assert_eq(next.proof_idx, local.proof_idx);
        builder
            .when_transition()
            .when(next_round.clone())
            .assert_eq(next.idx, local.idx);
        builder
            .when_transition()
            .when(next_round.clone())
            .assert_eq(next.round_idx, local.round_idx + AB::Expr::ONE);
        builder
            .when_transition()
            .when(next_round.clone())
            .assert_eq(next.bit_idx, AB::Expr::from_usize(MAX_ECC_VARS - 1));
        assert_array_eq(
            &mut builder.when_transition().when(next_round.clone()),
            local.quark_out,
            next.quark_in,
        );
        builder.when_transition().when(next_round).assert_eq(
            next.quark_layer_n,
            local.quark_layer_n * AB::Expr::from_usize(2) - next.quark_parity,
        );

        self.quark_final_bus.send(
            builder,
            local.proof_idx,
            MainEccRtQuarkFinalMessage {
                idx: local.idx.into(),
                quark_out: local.quark_out.map(Into::into),
            },
            local.is_enabled * local.is_last_round * local.is_last_bit,
        );
    }
}

pub struct MainEccRtSumcheckAir {
    pub challenge_bus: MainEccRtChallengeBus,
    pub sumcheck_final_bus: MainEccRtSumcheckFinalBus,
}

impl<F: Field> BaseAir<F> for MainEccRtSumcheckAir {
    fn width(&self) -> usize {
        MainEccRtSumcheckCols::<F>::width()
    }
}

impl<F: Field> BaseAirWithPublicValues<F> for MainEccRtSumcheckAir {}
impl<F: Field> PartitionedBaseAir<F> for MainEccRtSumcheckAir {}

impl<AB> Air<AB> for MainEccRtSumcheckAir
where
    AB: AirBuilder + InteractionBuilder,
    <AB::Expr as PrimeCharacteristicRing>::PrimeSubfield: BinomiallyExtendable<{ D_EF }>,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let (local_row, next_row) = (
            main.row_slice(0).expect("main row exists"),
            main.row_slice(1).expect("next row exists"),
        );
        let local: &MainEccRtSumcheckCols<AB::Var> = (*local_row).borrow();
        let next: &MainEccRtSumcheckCols<AB::Var> = (*next_row).borrow();

        builder.assert_bool(local.is_enabled);
        builder.assert_bool(local.is_first);
        builder.assert_bool(local.is_last);

        self.challenge_bus.lookup_key(
            builder,
            local.proof_idx,
            MainEccRtChallengeMessage {
                idx: local.idx.into(),
                round_idx: local.round_idx.into(),
                kind: AB::Expr::from_usize(MainEccRtChallengeKind::Rt.as_usize()),
                value: local.rt.map(Into::into),
            },
            local.is_enabled,
        );

        assert_array_eq(
            &mut builder.when(local.is_enabled * local.is_first),
            local.claim_in,
            ext_zero::<AB::Expr>(),
        );
        let ev0 = ext_field_subtract(local.claim_in, local.ev1);
        let claim_out = interpolate_cubic_at_0123(ev0, local.ev1, local.ev2, local.ev3, local.rt);
        assert_array_eq(
            &mut builder.when(local.is_enabled),
            local.claim_out,
            claim_out,
        );

        let same_ecc = local.is_enabled * next.is_enabled * (AB::Expr::ONE - next.is_first);
        builder
            .when_transition()
            .when(same_ecc.clone())
            .assert_eq(next.proof_idx, local.proof_idx);
        builder
            .when_transition()
            .when(same_ecc.clone())
            .assert_eq(next.idx, local.idx);
        builder
            .when_transition()
            .when(same_ecc.clone())
            .assert_eq(next.round_idx, local.round_idx + AB::Expr::ONE);
        assert_array_eq(
            &mut builder.when_transition().when(same_ecc),
            local.claim_out,
            next.claim_in,
        );

        self.sumcheck_final_bus.send(
            builder,
            local.proof_idx,
            MainEccRtSumcheckFinalMessage {
                idx: local.idx.into(),
                claim: local.claim_out.map(Into::into),
            },
            local.is_enabled * local.is_last,
        );
    }
}

impl<F: Field> BaseAir<F> for MainEccRtAir {
    fn width(&self) -> usize {
        MainEccRtCols::<F>::width()
    }
}

impl<F: Field> BaseAirWithPublicValues<F> for MainEccRtAir {}
impl<F: Field> PartitionedBaseAir<F> for MainEccRtAir {}

impl<AB> Air<AB> for MainEccRtAir
where
    AB: AirBuilder + InteractionBuilder,
    <AB::Expr as PrimeCharacteristicRing>::PrimeSubfield: BinomiallyExtendable<{ D_EF }>,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let (local_row, next_row) = (
            main.row_slice(0).expect("main row exists"),
            main.row_slice(1).expect("next row exists"),
        );
        let local: &MainEccRtCols<AB::Var> = (*local_row).borrow();
        let next: &MainEccRtCols<AB::Var> = (*next_row).borrow();

        builder.assert_bool(local.is_enabled);
        builder.assert_bool(local.is_first);
        builder.assert_bool(local.is_last);

        self.challenge_bus.lookup_key(
            builder,
            local.proof_idx,
            MainEccRtChallengeMessage {
                idx: local.idx.into(),
                round_idx: local.round_idx.into(),
                kind: AB::Expr::from_usize(MainEccRtChallengeKind::Rt.as_usize()),
                value: local.rt.map(Into::into),
            },
            local.is_enabled,
        );
        self.challenge_bus.lookup_key(
            builder,
            local.proof_idx,
            MainEccRtChallengeMessage {
                idx: local.idx.into(),
                round_idx: local.round_idx.into(),
                kind: AB::Expr::from_usize(MainEccRtChallengeKind::OutRt.as_usize()),
                value: local.out_rt.map(Into::into),
            },
            local.is_enabled,
        );

        self.sumcheck_final_bus.receive(
            builder,
            local.proof_idx,
            MainEccRtSumcheckFinalMessage {
                idx: local.idx.into(),
                claim: local.sumcheck_final_claim.map(Into::into),
            },
            local.is_enabled * local.is_last,
        );
        self.equation_totals_bus.receive(
            builder,
            local.proof_idx,
            MainEccRtEquationTotalsMessage {
                idx: local.idx.into(),
                add_eval: local.add_eval.map(Into::into),
                bypass_eval: local.bypass_eval.map(Into::into),
                export_eval: local.export_eval.map(Into::into),
            },
            local.is_enabled * local.is_last,
        );
        self.quark_final_bus.receive(
            builder,
            local.proof_idx,
            MainEccRtQuarkFinalMessage {
                idx: local.idx.into(),
                quark_out: local.quark_out.map(Into::into),
            },
            local.is_enabled * local.is_last,
        );

        let eq_factor = eq_factor::<AB>(local.out_rt, local.rt);
        assert_array_eq(
            &mut builder.when(local.is_enabled),
            local.eq_out,
            ext_field_multiply::<AB::Expr>(local.eq_in, eq_factor),
        );
        assert_array_eq(
            &mut builder.when(local.is_enabled * local.is_first),
            local.eq_in,
            ext_one::<AB::Expr>(),
        );

        let last_factor = ext_field_multiply::<AB::Expr>(local.out_rt, local.rt);
        assert_array_eq(
            &mut builder.when(local.is_enabled),
            local.last_out,
            ext_field_multiply::<AB::Expr>(local.last_in, last_factor),
        );
        assert_array_eq(
            &mut builder.when(local.is_enabled * local.is_first),
            local.last_in,
            ext_one::<AB::Expr>(),
        );

        let export_out_factor = choose_ext::<AB>(
            local.is_first,
            ext_field_one_minus(local.out_rt.map(Into::into)),
            local.out_rt.map(Into::into),
        );
        assert_array_eq(
            &mut builder.when(local.is_enabled),
            local.export_out_out,
            ext_field_multiply::<AB::Expr>(local.export_out_in, export_out_factor),
        );
        let export_rt_factor = choose_ext::<AB>(
            local.is_first,
            ext_field_one_minus(local.rt.map(Into::into)),
            local.rt.map(Into::into),
        );
        assert_array_eq(
            &mut builder.when(local.is_enabled),
            local.export_rt_out,
            ext_field_multiply::<AB::Expr>(local.export_rt_in, export_rt_factor),
        );
        assert_array_eq(
            &mut builder.when(local.is_enabled * local.is_first),
            local.export_out_in,
            ext_one::<AB::Expr>(),
        );
        assert_array_eq(
            &mut builder.when(local.is_enabled * local.is_first),
            local.export_rt_in,
            ext_one::<AB::Expr>(),
        );

        let same_ecc = local.is_enabled * next.is_enabled * (AB::Expr::ONE - next.is_first);
        builder
            .when_transition()
            .when(same_ecc.clone())
            .assert_eq(next.proof_idx, local.proof_idx);
        builder
            .when_transition()
            .when(same_ecc.clone())
            .assert_eq(next.idx, local.idx);
        builder
            .when_transition()
            .when(same_ecc.clone())
            .assert_eq(next.round_idx, local.round_idx + AB::Expr::ONE);
        assert_array_eq(
            &mut builder.when_transition().when(same_ecc.clone()),
            local.eq_out,
            next.eq_in,
        );
        assert_array_eq(
            &mut builder.when_transition().when(same_ecc.clone()),
            local.last_out,
            next.last_in,
        );
        assert_array_eq(
            &mut builder.when_transition().when(same_ecc.clone()),
            local.export_out_out,
            next.export_out_in,
        );
        assert_array_eq(
            &mut builder.when_transition().when(same_ecc.clone()),
            local.export_rt_out,
            next.export_rt_in,
        );

        let sel_bypass = ext_field_subtract::<AB::Expr>(
            ext_field_subtract::<AB::Expr>(local.eq_out, local.sel_add),
            local.last_out,
        );
        let sel_export = ext_field_multiply::<AB::Expr>(local.export_out_out, local.export_rt_out);
        assert_array_eq(
            &mut builder.when(local.is_enabled * local.is_last),
            local.sel_add,
            local.quark_out,
        );
        assert_array_eq(
            &mut builder.when(local.is_enabled * local.is_last),
            local.sel_bypass,
            sel_bypass,
        );
        assert_array_eq(
            &mut builder.when(local.is_enabled * local.is_last),
            local.sel_export,
            sel_export,
        );
        let expected = ext_field_add::<AB::Expr>(
            ext_field_add::<AB::Expr>(
                ext_field_multiply::<AB::Expr>(local.add_eval, local.sel_add),
                ext_field_multiply::<AB::Expr>(local.bypass_eval, local.sel_bypass),
            ),
            ext_field_multiply::<AB::Expr>(local.export_eval, local.sel_export),
        );
        assert_array_eq(
            &mut builder.when(local.is_enabled * local.is_last),
            local.sumcheck_final_claim,
            expected,
        );
    }
}

pub struct MainEccRtChallengeTraceGenerator;

impl RowMajorChip<F> for MainEccRtChallengeTraceGenerator {
    type Ctx<'a> = &'a [MainEccRtRecord];

    fn generate_trace(
        &self,
        records: &Self::Ctx<'_>,
        required_height: Option<usize>,
    ) -> Option<RowMajorMatrix<F>> {
        let width = MainEccRtChallengeCols::<F>::width();
        let num_valid_rows = records.len().max(1);
        let height = if let Some(height) = required_height {
            if height < num_valid_rows {
                return None;
            }
            height
        } else {
            num_valid_rows.next_power_of_two()
        };

        let mut trace = vec![F::ZERO; height * width];
        if records.is_empty() {
            return Some(RowMajorMatrix::new(trace, width));
        }
        for (row_idx, record) in records.iter().enumerate() {
            let row = &mut trace[row_idx * width..(row_idx + 1) * width];
            let cols: &mut MainEccRtChallengeCols<F> = row.borrow_mut();
            fill_challenge_cols(record, cols);
        }

        Some(RowMajorMatrix::new(trace, width))
    }
}

pub struct MainEccRtTraceGenerator;

pub struct MainEccRtEquationTraceGenerator;

pub struct MainEccRtQuarkTraceGenerator;

impl RowMajorChip<F> for MainEccRtQuarkTraceGenerator {
    type Ctx<'a> = &'a [MainEccRtRecord];

    fn generate_trace(
        &self,
        records: &Self::Ctx<'_>,
        required_height: Option<usize>,
    ) -> Option<RowMajorMatrix<F>> {
        let width = MainEccRtQuarkCols::<F>::width();
        let quark_rows = build_quark_rows(records);
        let num_valid_rows = quark_rows.len().max(1);
        let height = if let Some(height) = required_height {
            if height < num_valid_rows {
                return None;
            }
            height
        } else {
            num_valid_rows.next_power_of_two()
        };

        let mut trace = vec![F::ZERO; height * width];
        if quark_rows.is_empty() {
            return Some(RowMajorMatrix::new(trace, width));
        }
        for (row_idx, row_record) in quark_rows.iter().enumerate() {
            let row = &mut trace[row_idx * width..(row_idx + 1) * width];
            let cols: &mut MainEccRtQuarkCols<F> = row.borrow_mut();
            fill_quark_cols(row_record, cols);
        }

        Some(RowMajorMatrix::new(trace, width))
    }
}

impl RowMajorChip<F> for MainEccRtEquationTraceGenerator {
    type Ctx<'a> = &'a [MainEccRtRecord];

    fn generate_trace(
        &self,
        records: &Self::Ctx<'_>,
        required_height: Option<usize>,
    ) -> Option<RowMajorMatrix<F>> {
        let width = MainEccRtEquationCols::<F>::width();
        let eq_rows = build_equation_rows(records);
        let num_valid_rows = eq_rows.len().max(1);
        let height = if let Some(height) = required_height {
            if height < num_valid_rows {
                return None;
            }
            height
        } else {
            num_valid_rows.next_power_of_two()
        };

        let mut trace = vec![F::ZERO; height * width];
        if eq_rows.is_empty() {
            return Some(RowMajorMatrix::new(trace, width));
        }
        for (row_idx, row_record) in eq_rows.iter().enumerate() {
            let row = &mut trace[row_idx * width..(row_idx + 1) * width];
            let cols: &mut MainEccRtEquationCols<F> = row.borrow_mut();
            fill_equation_cols(row_record, cols);
        }

        Some(RowMajorMatrix::new(trace, width))
    }
}

pub struct MainEccRtSumcheckTraceGenerator;

impl RowMajorChip<F> for MainEccRtSumcheckTraceGenerator {
    type Ctx<'a> = &'a [MainEccRtRecord];

    fn generate_trace(
        &self,
        records: &Self::Ctx<'_>,
        required_height: Option<usize>,
    ) -> Option<RowMajorMatrix<F>> {
        let width = MainEccRtSumcheckCols::<F>::width();
        let num_valid_rows = records.len().max(1);
        let height = if let Some(height) = required_height {
            if height < num_valid_rows {
                return None;
            }
            height
        } else {
            num_valid_rows.next_power_of_two()
        };

        let mut trace = vec![F::ZERO; height * width];
        if records.is_empty() {
            return Some(RowMajorMatrix::new(trace, width));
        }
        for (row_idx, record) in records.iter().enumerate() {
            let row = &mut trace[row_idx * width..(row_idx + 1) * width];
            let cols: &mut MainEccRtSumcheckCols<F> = row.borrow_mut();
            fill_sumcheck_cols(record, cols);
        }

        Some(RowMajorMatrix::new(trace, width))
    }
}

impl RowMajorChip<F> for MainEccRtTraceGenerator {
    type Ctx<'a> = &'a [MainEccRtRecord];

    fn generate_trace(
        &self,
        records: &Self::Ctx<'_>,
        required_height: Option<usize>,
    ) -> Option<RowMajorMatrix<F>> {
        let width = MainEccRtCols::<F>::width();
        let num_valid_rows = records.len().max(1);
        let height = if let Some(height) = required_height {
            if height < num_valid_rows {
                return None;
            }
            height
        } else {
            num_valid_rows.next_power_of_two()
        };

        let mut trace = vec![F::ZERO; height * width];
        if records.is_empty() {
            return Some(RowMajorMatrix::new(trace, width));
        }
        for (row_idx, record) in records.iter().enumerate() {
            let row = &mut trace[row_idx * width..(row_idx + 1) * width];
            let cols: &mut MainEccRtCols<F> = row.borrow_mut();
            fill_cols(record, cols);
        }

        Some(RowMajorMatrix::new(trace, width))
    }
}

fn fill_challenge_cols(record: &MainEccRtRecord, cols: &mut MainEccRtChallengeCols<F>) {
    cols.is_enabled = F::ONE;
    cols.proof_idx = F::from_usize(record.proof_idx);
    cols.idx = F::from_usize(record.idx);
    cols.fork_id = F::from_usize(record.fork_id);
    cols.round_idx = F::from_usize(record.round_idx);
    cols.num_rounds = F::from_usize(record.num_rounds);
    cols.is_first = F::from_bool(record.is_first);
    cols.tidx = F::from_usize(record.tidx);
    cols.out_tidx = F::from_usize(record.out_tidx);
    cols.alpha_tidx = F::from_usize(record.alpha_tidx);
    cols.lookup_count = F::from_usize(record.lookup_count);
    cols.rt = ext_to_basis(record.value);
    cols.out_rt = ext_to_basis(record.out_value);
    cols.alpha = ext_to_basis(record.alpha);
}

struct MainEccRtEquationRow<'a> {
    record: &'a MainEccRtRecord,
    family_idx: usize,
    septic_idx: usize,
    alpha_pow: openvm_stark_sdk::config::baby_bear_poseidon2::EF,
    add_in: openvm_stark_sdk::config::baby_bear_poseidon2::EF,
    add_out: openvm_stark_sdk::config::baby_bear_poseidon2::EF,
    bypass_in: openvm_stark_sdk::config::baby_bear_poseidon2::EF,
    bypass_out: openvm_stark_sdk::config::baby_bear_poseidon2::EF,
    export_in: openvm_stark_sdk::config::baby_bear_poseidon2::EF,
    export_out: openvm_stark_sdk::config::baby_bear_poseidon2::EF,
    is_first: bool,
    is_last: bool,
}

fn build_equation_rows(records: &[MainEccRtRecord]) -> Vec<MainEccRtEquationRow<'_>> {
    let mut rows = Vec::new();
    for record in records.iter().filter(|record| record.is_first) {
        let mut add = openvm_stark_sdk::config::baby_bear_poseidon2::EF::ZERO;
        let mut bypass = openvm_stark_sdk::config::baby_bear_poseidon2::EF::ZERO;
        let mut export = openvm_stark_sdk::config::baby_bear_poseidon2::EF::ZERO;
        for family_idx in 0..ECC_EQUATION_FAMILIES {
            for septic_idx in 0..SEPTIC_DEGREE {
                let alpha_pow = record.alpha_pows[family_idx * SEPTIC_DEGREE + septic_idx];
                let weighted = equation_term(record, family_idx, septic_idx) * alpha_pow;
                let add_in = add;
                let bypass_in = bypass;
                let export_in = export;
                match family_idx {
                    0..=2 => add += weighted,
                    3..=4 => bypass += weighted,
                    5..=6 => export += weighted,
                    _ => unreachable!("invalid ECC equation family"),
                }
                rows.push(MainEccRtEquationRow {
                    record,
                    family_idx,
                    septic_idx,
                    alpha_pow,
                    add_in,
                    add_out: add,
                    bypass_in,
                    bypass_out: bypass,
                    export_in,
                    export_out: export,
                    is_first: family_idx == 0 && septic_idx == 0,
                    is_last: family_idx + 1 == ECC_EQUATION_FAMILIES
                        && septic_idx + 1 == SEPTIC_DEGREE,
                });
            }
        }
    }
    rows
}

fn equation_term(
    record: &MainEccRtRecord,
    family_idx: usize,
    septic_idx: usize,
) -> openvm_stark_sdk::config::baby_bear_poseidon2::EF {
    match family_idx {
        0 => {
            septic_mul_coeff_native(
                &record.s0,
                &core::array::from_fn(|i| record.x0[i] - record.x1[i]),
                septic_idx,
            ) - (record.y0[septic_idx] - record.y1[septic_idx])
        }
        1 => {
            septic_mul_coeff_native(&record.s0, &record.s0, septic_idx)
                - record.x0[septic_idx]
                - record.x1[septic_idx]
                - record.x3[septic_idx]
        }
        2 => {
            septic_mul_coeff_native(
                &record.s0,
                &core::array::from_fn(|i| record.x0[i] - record.x3[i]),
                septic_idx,
            ) - (record.y0[septic_idx] + record.y3[septic_idx])
        }
        3 => record.x3[septic_idx] - record.x0[septic_idx],
        4 => record.y3[septic_idx] - record.y0[septic_idx],
        5 => record.x3[septic_idx] - record.sum_x[septic_idx],
        6 => record.y3[septic_idx] - record.sum_y[septic_idx],
        _ => unreachable!("invalid ECC equation family"),
    }
}

fn septic_mul_coeff_native(
    a: &[openvm_stark_sdk::config::baby_bear_poseidon2::EF; SEPTIC_DEGREE],
    b: &[openvm_stark_sdk::config::baby_bear_poseidon2::EF; SEPTIC_DEGREE],
    coeff_idx: usize,
) -> openvm_stark_sdk::config::baby_bear_poseidon2::EF {
    let mut out = openvm_stark_sdk::config::baby_bear_poseidon2::EF::ZERO;
    let two = openvm_stark_sdk::config::baby_bear_poseidon2::EF::from_usize(2);
    let five = openvm_stark_sdk::config::baby_bear_poseidon2::EF::from_usize(5);
    for (i, a_value) in a.iter().enumerate().take(SEPTIC_DEGREE) {
        for (j, b_value) in b.iter().enumerate().take(SEPTIC_DEGREE) {
            let term = *a_value * *b_value;
            let mut index = i + j;
            if index < SEPTIC_DEGREE {
                if index == coeff_idx {
                    out += term;
                }
            } else {
                index -= SEPTIC_DEGREE;
                if index == coeff_idx {
                    out += five * term;
                }
                if index + 1 == coeff_idx {
                    out += two * term;
                }
            }
        }
    }
    out
}

fn fill_equation_cols(row: &MainEccRtEquationRow<'_>, cols: &mut MainEccRtEquationCols<F>) {
    let record = row.record;
    cols.is_enabled = F::ONE;
    cols.proof_idx = F::from_usize(record.proof_idx);
    cols.idx = F::from_usize(record.idx);
    cols.family_idx = F::from_usize(row.family_idx);
    cols.septic_idx = F::from_usize(row.septic_idx);
    cols.is_first = F::from_bool(row.is_first);
    cols.is_last = F::from_bool(row.is_last);
    cols.family_flags = core::array::from_fn(|i| F::from_bool(i == row.family_idx));
    cols.septic_flags = core::array::from_fn(|i| F::from_bool(i == row.septic_idx));
    cols.alpha = ext_to_basis(record.alpha);
    cols.alpha_pow = ext_to_basis(row.alpha_pow);
    cols.s0 = ext_to_basis(record.s0[row.septic_idx]);
    cols.s0_all = record.s0.map(ext_to_basis);
    cols.x0 = ext_to_basis(record.x0[row.septic_idx]);
    cols.x0_all = record.x0.map(ext_to_basis);
    cols.y0 = ext_to_basis(record.y0[row.septic_idx]);
    cols.x1 = ext_to_basis(record.x1[row.septic_idx]);
    cols.x1_all = record.x1.map(ext_to_basis);
    cols.y1 = ext_to_basis(record.y1[row.septic_idx]);
    cols.x3 = ext_to_basis(record.x3[row.septic_idx]);
    cols.x3_all = record.x3.map(ext_to_basis);
    cols.y3 = ext_to_basis(record.y3[row.septic_idx]);
    cols.sum_x = ext_to_basis(record.sum_x[row.septic_idx]);
    cols.sum_y = ext_to_basis(record.sum_y[row.septic_idx]);
    cols.s0_x0_x1 = ext_to_basis(septic_mul_coeff_native(
        &record.s0,
        &core::array::from_fn(|i| record.x0[i] - record.x1[i]),
        row.septic_idx,
    ));
    cols.s0_squared = ext_to_basis(septic_mul_coeff_native(
        &record.s0,
        &record.s0,
        row.septic_idx,
    ));
    cols.s0_x0_x3 = ext_to_basis(septic_mul_coeff_native(
        &record.s0,
        &core::array::from_fn(|i| record.x0[i] - record.x3[i]),
        row.septic_idx,
    ));
    cols.add_in = ext_to_basis(row.add_in);
    cols.add_out = ext_to_basis(row.add_out);
    cols.bypass_in = ext_to_basis(row.bypass_in);
    cols.bypass_out = ext_to_basis(row.bypass_out);
    cols.export_in = ext_to_basis(row.export_in);
    cols.export_out = ext_to_basis(row.export_out);
}

struct MainEccRtQuarkRow<'a> {
    record: &'a MainEccRtRecord,
    bit_idx: usize,
    active_count_in: usize,
    active_count_out: usize,
    bit_value_in: usize,
    bit_value_out: usize,
}

fn build_quark_rows(records: &[MainEccRtRecord]) -> Vec<MainEccRtQuarkRow<'_>> {
    let mut rows = Vec::new();
    for record in records {
        let mut active_count = 0usize;
        let mut bit_value = 0usize;
        for bit_idx in (0..MAX_ECC_VARS).rev() {
            let active_count_in = active_count;
            let bit_value_in = bit_value;
            if record.lte_active[bit_idx] {
                active_count += 1;
            }
            if record.lte_bits[bit_idx] {
                bit_value += 1usize << bit_idx;
            }
            rows.push(MainEccRtQuarkRow {
                record,
                bit_idx,
                active_count_in,
                active_count_out: active_count,
                bit_value_in,
                bit_value_out: bit_value,
            });
        }
    }
    rows
}

fn fill_quark_cols(row: &MainEccRtQuarkRow<'_>, cols: &mut MainEccRtQuarkCols<F>) {
    let record = row.record;
    cols.is_enabled = F::ONE;
    cols.proof_idx = F::from_usize(record.proof_idx);
    cols.idx = F::from_usize(record.idx);
    cols.round_idx = F::from_usize(record.round_idx);
    cols.bit_idx = F::from_usize(row.bit_idx);
    cols.bit_weight = F::from_usize(1usize << row.bit_idx);
    cols.is_first_round = F::from_bool(record.is_first);
    cols.is_last_round = F::from_bool(record.is_last);
    cols.is_first_bit = F::from_bool(row.bit_idx + 1 == MAX_ECC_VARS);
    cols.is_last_bit = F::from_bool(row.bit_idx == 0);
    cols.is_active = F::from_bool(record.lte_active[row.bit_idx]);
    cols.bit = F::from_bool(record.lte_bits[row.bit_idx]);
    cols.current_rt = ext_to_basis(record.value);
    cols.current_out_rt = ext_to_basis(record.out_value);
    cols.point_rt = ext_to_basis(record.lte_rt_point[row.bit_idx]);
    cols.point_out_rt = ext_to_basis(record.lte_out_point[row.bit_idx]);
    let same_one = record.lte_out_point[row.bit_idx] * record.lte_rt_point[row.bit_idx];
    let same_zero = (EF::ONE - record.lte_out_point[row.bit_idx])
        * (EF::ONE - record.lte_rt_point[row.bit_idx]);
    let equal_choice = if record.lte_bits[row.bit_idx] {
        same_one
    } else {
        same_zero
    };
    cols.same_one = ext_to_basis(same_one);
    cols.same_zero = ext_to_basis(same_zero);
    cols.equal_choice = ext_to_basis(equal_choice);
    cols.active_prefix = ext_to_basis(record.lte_prefix_acc[row.bit_idx + 1] * equal_choice);
    cols.prefix_in = ext_to_basis(record.lte_prefix_acc[row.bit_idx + 1]);
    cols.prefix_out = ext_to_basis(record.lte_prefix_acc[row.bit_idx]);
    cols.less_in = ext_to_basis(record.lte_less_acc[row.bit_idx + 1]);
    let less_from_prior = record.lte_less_acc[row.bit_idx + 1] * (same_one + same_zero);
    let less_from_equal = record.lte_prefix_acc[row.bit_idx + 1] * same_zero;
    let active_less = less_from_prior
        + if record.lte_bits[row.bit_idx] {
            less_from_equal
        } else {
            EF::ZERO
        };
    cols.less_from_prior = ext_to_basis(less_from_prior);
    cols.less_from_equal = ext_to_basis(less_from_equal);
    cols.active_less = ext_to_basis(active_less);
    cols.less_out = ext_to_basis(record.lte_less_acc[row.bit_idx]);
    cols.active_count_in = F::from_usize(row.active_count_in);
    cols.active_count_out = F::from_usize(row.active_count_out);
    cols.bit_value_in = F::from_usize(row.bit_value_in);
    cols.bit_value_out = F::from_usize(row.bit_value_out);
    cols.quark_prefix_count = F::from_usize(record.quark_prefix_count);
    cols.quark_prefix_is_zero = F::from_bool(record.quark_prefix_count == 0);
    cols.quark_prefix_inv = if record.quark_prefix_count == 0 {
        F::ZERO
    } else {
        F::from_usize(record.quark_prefix_count).inverse()
    };
    cols.quark_layer_n = F::from_usize(record.quark_layer_n);
    cols.quark_parity = F::from_bool(record.quark_parity);
    cols.quark_in = ext_to_basis(record.quark_in);
    cols.quark_factor = ext_to_basis(record.quark_factor);
    let quark_zero = (EF::ONE - record.out_value) * (EF::ONE - record.value);
    let quark_one = record.out_value * record.value;
    cols.quark_zero = ext_to_basis(quark_zero);
    cols.quark_one = ext_to_basis(quark_one);
    cols.quark_lhs = ext_to_basis(quark_zero * record.quark_factor);
    cols.quark_rhs = ext_to_basis(quark_one * record.quark_in);
    cols.quark_out = ext_to_basis(record.quark_out);
}

fn fill_sumcheck_cols(record: &MainEccRtRecord, cols: &mut MainEccRtSumcheckCols<F>) {
    cols.is_enabled = F::ONE;
    cols.proof_idx = F::from_usize(record.proof_idx);
    cols.idx = F::from_usize(record.idx);
    cols.round_idx = F::from_usize(record.round_idx);
    cols.is_first = F::from_bool(record.is_first);
    cols.is_last = F::from_bool(record.is_last);
    cols.rt = ext_to_basis(record.value);
    cols.ev1 = ext_to_basis(record.ev1);
    cols.ev2 = ext_to_basis(record.ev2);
    cols.ev3 = ext_to_basis(record.ev3);
    cols.claim_in = ext_to_basis(record.claim_in);
    cols.claim_out = ext_to_basis(record.claim_out);
}

fn fill_cols(record: &MainEccRtRecord, cols: &mut MainEccRtCols<F>) {
    cols.is_enabled = F::ONE;
    cols.proof_idx = F::from_usize(record.proof_idx);
    cols.idx = F::from_usize(record.idx);
    cols.round_idx = F::from_usize(record.round_idx);
    cols.is_first = F::from_bool(record.is_first);
    cols.is_last = F::from_bool(record.is_last);
    cols.rt = ext_to_basis(record.value);
    cols.out_rt = ext_to_basis(record.out_value);
    cols.sumcheck_final_claim = ext_to_basis(record.claim_out);
    cols.sel_add = ext_to_basis(record.sel_add);
    cols.sel_bypass = ext_to_basis(record.sel_bypass);
    cols.sel_export = ext_to_basis(record.sel_export);
    cols.eq_in = ext_to_basis(record.eq_in);
    cols.eq_out = ext_to_basis(record.eq_out);
    cols.last_in = ext_to_basis(record.last_in);
    cols.last_out = ext_to_basis(record.last_out);
    cols.export_out_in = ext_to_basis(record.export_out_in);
    cols.export_out_out = ext_to_basis(record.export_out_out);
    cols.export_rt_in = ext_to_basis(record.export_rt_in);
    cols.export_rt_out = ext_to_basis(record.export_rt_out);
    cols.quark_out = ext_to_basis(record.quark_out);
    cols.add_eval = ext_to_basis(record.add_eval);
    cols.bypass_eval = ext_to_basis(record.bypass_eval);
    cols.export_eval = ext_to_basis(record.export_eval);
}

fn ext_to_basis(value: openvm_stark_sdk::config::baby_bear_poseidon2::EF) -> [F; D_EF] {
    value.as_basis_coefficients_slice().try_into().unwrap()
}

fn eq_factor<AB: AirBuilder>(a: [AB::Var; D_EF], b: [AB::Var; D_EF]) -> [AB::Expr; D_EF]
where
    <AB::Expr as PrimeCharacteristicRing>::PrimeSubfield: BinomiallyExtendable<{ D_EF }>,
{
    ext_field_add::<AB::Expr>(
        ext_field_multiply::<AB::Expr>(a.clone(), b.clone()),
        ext_field_multiply::<AB::Expr>(one_minus_ext::<AB>(a), one_minus_ext::<AB>(b)),
    )
}

fn one_minus_ext<AB: AirBuilder>(value: [AB::Var; D_EF]) -> [AB::Expr; D_EF] {
    ext_field_one_minus(value.map(Into::into))
}

fn choose_ext<AB: AirBuilder>(
    flag: AB::Var,
    when_one: [AB::Expr; D_EF],
    when_zero: [AB::Expr; D_EF],
) -> [AB::Expr; D_EF] {
    core::array::from_fn(|i| {
        flag.clone() * when_one[i].clone() + (AB::Expr::ONE - flag.clone()) * when_zero[i].clone()
    })
}

fn septic_mul_selected<AB: AirBuilder>(
    a: &[[AB::Var; D_EF]; SEPTIC_DEGREE],
    b: &[[AB::Expr; D_EF]; SEPTIC_DEGREE],
    septic_flags: [AB::Var; SEPTIC_DEGREE],
) -> [AB::Expr; D_EF]
where
    <AB::Expr as PrimeCharacteristicRing>::PrimeSubfield: BinomiallyExtendable<{ D_EF }>,
{
    (0..SEPTIC_DEGREE).fold(ext_zero::<AB::Expr>(), |acc, coeff_idx| {
        let coeff = septic_mul_coeff::<AB>(a, b, coeff_idx);
        ext_field_add::<AB::Expr>(
            acc,
            ext_field_multiply_scalar::<AB::Expr>(coeff, septic_flags[coeff_idx].clone()),
        )
    })
}

fn septic_mul_coeff<AB: AirBuilder>(
    a: &[[AB::Var; D_EF]; SEPTIC_DEGREE],
    b: &[[AB::Expr; D_EF]; SEPTIC_DEGREE],
    coeff_idx: usize,
) -> [AB::Expr; D_EF]
where
    <AB::Expr as PrimeCharacteristicRing>::PrimeSubfield: BinomiallyExtendable<{ D_EF }>,
{
    let mut out = ext_zero::<AB::Expr>();
    for (i, a_value) in a.iter().enumerate().take(SEPTIC_DEGREE) {
        for (j, b_value) in b.iter().enumerate().take(SEPTIC_DEGREE) {
            let term = ext_field_multiply::<AB::Expr>(
                core::array::from_fn(|idx| a_value[idx].clone().into()),
                b_value.clone(),
            );
            let mut index = i + j;
            if index < SEPTIC_DEGREE {
                if index == coeff_idx {
                    out = ext_field_add::<AB::Expr>(out, term);
                }
            } else {
                index -= SEPTIC_DEGREE;
                if index == coeff_idx {
                    out = ext_field_add::<AB::Expr>(
                        out,
                        ext_field_multiply_scalar::<AB::Expr>(
                            term.clone(),
                            AB::Expr::from_usize(5),
                        ),
                    );
                }
                if index + 1 == coeff_idx {
                    out = ext_field_add::<AB::Expr>(
                        out,
                        ext_field_multiply_scalar::<AB::Expr>(term, AB::Expr::from_usize(2)),
                    );
                }
            }
        }
    }
    out
}

fn ext_zero<FA: PrimeCharacteristicRing>() -> [FA; D_EF] {
    core::array::from_fn(|_| FA::ZERO)
}

fn ext_one<FA: PrimeCharacteristicRing>() -> [FA; D_EF] {
    let mut out = ext_zero::<FA>();
    out[0] = FA::ONE;
    out
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
