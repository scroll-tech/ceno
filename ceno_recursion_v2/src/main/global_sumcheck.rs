use core::borrow::{Borrow, BorrowMut};

use openvm_circuit_primitives::{SubAir, utils::assert_array_eq};
use openvm_stark_backend::{
    BaseAirWithPublicValues, PartitionedBaseAir, interaction::InteractionBuilder,
};
use openvm_stark_sdk::config::baby_bear_poseidon2::{D_EF, EF, F};
use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::{BasedVectorSpace, Field, PrimeCharacteristicRing, extension::BinomiallyExtendable};
use p3_matrix::{Matrix, dense::RowMajorMatrix};
use recursion_circuit::{
    subairs::nested_for_loop::{NestedForLoopIoCols, NestedForLoopSubAir},
    utils::{ext_field_add, ext_field_multiply, ext_field_multiply_scalar, ext_field_subtract},
};
use stark_recursion_circuit_derive::AlignedBorrow;

use crate::{
    bus::{MainGlobalClaimBus, MainGlobalClaimMessage},
    system::MainGlobalSumcheckRecord,
    tracegen::RowMajorChip,
};

#[repr(C)]
#[derive(AlignedBorrow, Debug)]
pub struct MainGlobalSumcheckCols<T> {
    pub is_enabled: T,
    pub proof_idx: T,
    pub is_first: T,
    pub is_last: T,
    pub is_dummy: T,
    pub round: T,
    pub ev1: [T; D_EF],
    pub ev2: [T; D_EF],
    pub ev3: [T; D_EF],
    pub ev4: [T; D_EF],
    pub claim_in: [T; D_EF],
    pub claim_out: [T; D_EF],
    pub challenge: [T; D_EF],
    pub expected: [T; D_EF],
}

pub struct MainGlobalSumcheckAir {
    pub global_claim_bus: MainGlobalClaimBus,
}

impl<F: Field> BaseAir<F> for MainGlobalSumcheckAir {
    fn width(&self) -> usize {
        MainGlobalSumcheckCols::<F>::width()
    }
}

impl<F: Field> BaseAirWithPublicValues<F> for MainGlobalSumcheckAir {}
impl<F: Field> PartitionedBaseAir<F> for MainGlobalSumcheckAir {}

impl<AB> Air<AB> for MainGlobalSumcheckAir
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
        let local: &MainGlobalSumcheckCols<AB::Var> = (*local_row).borrow();
        let next: &MainGlobalSumcheckCols<AB::Var> = (*next_row).borrow();

        builder.assert_bool(local.is_dummy);
        builder.assert_bool(local.is_last);

        type LoopSubAir = NestedForLoopSubAir<1>;
        LoopSubAir {}.eval(
            builder,
            (
                NestedForLoopIoCols {
                    is_enabled: local.is_enabled,
                    counter: [local.proof_idx],
                    is_first: [local.is_first],
                }
                .map_into(),
                NestedForLoopIoCols {
                    is_enabled: next.is_enabled,
                    counter: [next.proof_idx],
                    is_first: [next.is_first],
                }
                .map_into(),
            ),
        );

        let is_transition = LoopSubAir::local_is_transition(next.is_enabled, next.is_first);
        builder.when(local.is_first).assert_zero(local.round);
        builder
            .when(is_transition.clone())
            .assert_eq(next.round, local.round + AB::Expr::ONE);
        builder
            .when(is_transition.clone())
            .assert_zero(local.is_last);

        let ev0 = ext_field_subtract(local.claim_in, local.ev1);
        let claim_out = interpolate_quartic_at_01234(
            ev0,
            local.ev1,
            local.ev2,
            local.ev3,
            local.ev4,
            local.challenge,
        );
        assert_array_eq(builder, local.claim_out, claim_out);
        assert_array_eq(
            &mut builder.when(is_transition.clone()),
            local.claim_out,
            next.claim_in,
        );
        assert_array_eq(
            &mut builder.when(is_transition),
            local.expected,
            next.expected,
        );
        assert_array_eq(
            &mut builder.when(local.is_enabled * local.is_last),
            local.claim_out,
            local.expected,
        );

        self.global_claim_bus.send(
            builder,
            local.proof_idx,
            MainGlobalClaimMessage {
                expected: local.expected.map(Into::into),
            },
            local.is_enabled * local.is_last,
        );
    }
}

fn interpolate_quartic_at_01234<F, FA>(
    ev0: [FA; D_EF],
    ev1: [F; D_EF],
    ev2: [F; D_EF],
    ev3: [F; D_EF],
    ev4: [F; D_EF],
    x: [F; D_EF],
) -> [FA; D_EF]
where
    F: Into<FA> + Copy,
    FA: PrimeCharacteristicRing,
    FA::PrimeSubfield: BinomiallyExtendable<{ D_EF }>,
{
    let x: [FA; D_EF] = x.map(Into::into);
    let scalar_ext = |value: usize| {
        let mut scalar = core::array::from_fn(|_| FA::ZERO);
        scalar[0] = FA::from_usize(value);
        scalar
    };
    let xm0 = x.clone();
    let xm1 = ext_field_subtract::<FA>(x.clone(), scalar_ext(1));
    let xm2 = ext_field_subtract::<FA>(x.clone(), scalar_ext(2));
    let xm3 = ext_field_subtract::<FA>(x.clone(), scalar_ext(3));
    let xm4 = ext_field_subtract::<FA>(x, scalar_ext(4));

    let inv4: FA = FA::from_prime_subfield(FA::PrimeSubfield::from_usize(4).inverse());
    let inv6: FA = FA::from_prime_subfield(FA::PrimeSubfield::from_usize(6).inverse());
    let inv24: FA = FA::from_prime_subfield(FA::PrimeSubfield::from_usize(24).inverse());

    let prod4 = |a: &[FA; D_EF], b: &[FA; D_EF], c: &[FA; D_EF], d: &[FA; D_EF]| {
        ext_field_multiply::<FA>(
            ext_field_multiply::<FA>(ext_field_multiply::<FA>(a.clone(), b.clone()), c.clone()),
            d.clone(),
        )
    };

    let basis0 = ext_field_multiply_scalar::<FA>(prod4(&xm1, &xm2, &xm3, &xm4), inv24.clone());
    let basis1 = ext_field_multiply_scalar::<FA>(prod4(&xm0, &xm2, &xm3, &xm4), -inv6.clone());
    let basis2 = ext_field_multiply_scalar::<FA>(prod4(&xm0, &xm1, &xm3, &xm4), inv4);
    let basis3 = ext_field_multiply_scalar::<FA>(prod4(&xm0, &xm1, &xm2, &xm4), -inv6);
    let basis4 = ext_field_multiply_scalar::<FA>(prod4(&xm0, &xm1, &xm2, &xm3), inv24);

    ext_field_add::<FA>(
        ext_field_add::<FA>(
            ext_field_add::<FA>(
                ext_field_multiply::<FA>(ev0, basis0),
                ext_field_multiply::<FA>(ev1, basis1),
            ),
            ext_field_add::<FA>(
                ext_field_multiply::<FA>(ev2, basis2),
                ext_field_multiply::<FA>(ev3, basis3),
            ),
        ),
        ext_field_multiply::<FA>(ev4, basis4),
    )
}

pub struct MainGlobalSumcheckTraceGenerator;

impl RowMajorChip<F> for MainGlobalSumcheckTraceGenerator {
    type Ctx<'a> = &'a [MainGlobalSumcheckRecord];

    fn generate_trace(
        &self,
        records: &Self::Ctx<'_>,
        required_height: Option<usize>,
    ) -> Option<RowMajorMatrix<F>> {
        let width = MainGlobalSumcheckCols::<F>::width();
        let num_valid_rows: usize = records
            .iter()
            .map(MainGlobalSumcheckRecord::total_rows)
            .sum();
        let num_valid_rows = num_valid_rows.max(1);
        let height = if let Some(height) = required_height {
            if height < num_valid_rows {
                return None;
            }
            height
        } else {
            num_valid_rows.next_power_of_two()
        };

        let mut trace = vec![F::ZERO; height * width];
        let mut row_offset = 0;
        for record in records.iter() {
            let rows = record.total_rows();
            let is_dummy = record.rounds.is_empty();
            for round_idx in 0..rows {
                let row = &mut trace[row_offset * width..(row_offset + 1) * width];
                let cols: &mut MainGlobalSumcheckCols<F> = row.borrow_mut();
                let round = record.rounds.get(round_idx);

                cols.is_enabled = F::ONE;
                cols.proof_idx = F::from_usize(record.proof_idx);
                cols.is_first = F::from_bool(round_idx == 0);
                cols.is_last = F::from_bool(round_idx + 1 == rows);
                cols.is_dummy = F::from_bool(is_dummy);
                cols.round = F::from_usize(round_idx);

                let evs = round
                    .map(|round| round.evaluations)
                    .unwrap_or([EF::ZERO; 4]);
                cols.ev1 = evs[0].as_basis_coefficients_slice().try_into().unwrap();
                cols.ev2 = evs[1].as_basis_coefficients_slice().try_into().unwrap();
                cols.ev3 = evs[2].as_basis_coefficients_slice().try_into().unwrap();
                cols.ev4 = evs[3].as_basis_coefficients_slice().try_into().unwrap();

                let claim_in = round.map(|round| round.claim_in).unwrap_or(record.expected);
                let claim_out = round
                    .map(|round| round.claim_out)
                    .unwrap_or(record.expected);
                let challenge = round.map(|round| round.challenge).unwrap_or(EF::ZERO);
                cols.claim_in = claim_in.as_basis_coefficients_slice().try_into().unwrap();
                cols.claim_out = claim_out.as_basis_coefficients_slice().try_into().unwrap();
                cols.challenge = challenge.as_basis_coefficients_slice().try_into().unwrap();
                cols.expected = record
                    .expected
                    .as_basis_coefficients_slice()
                    .try_into()
                    .unwrap();

                row_offset += 1;
            }
        }

        Some(RowMajorMatrix::new(trace, width))
    }
}
