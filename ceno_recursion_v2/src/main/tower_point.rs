use core::borrow::{Borrow, BorrowMut};

use openvm_circuit_primitives::utils::assert_array_eq;
use openvm_stark_backend::{
    BaseAirWithPublicValues, PartitionedBaseAir, interaction::InteractionBuilder,
};
use openvm_stark_sdk::config::baby_bear_poseidon2::{D_EF, F};
use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::{BasedVectorSpace, Field, PrimeCharacteristicRing, extension::BinomiallyExtendable};
use p3_matrix::{Matrix, dense::RowMajorMatrix};
use stark_recursion_circuit_derive::AlignedBorrow;

use crate::{
    bus::{MainGlobalPointBus, MainGlobalPointMessage, TowerMainPointBus, TowerMainPointMessage},
    system::MainTowerPointEqRecord,
    tracegen::RowMajorChip,
};

#[repr(C)]
#[derive(AlignedBorrow, Debug)]
pub struct MainTowerPointEqCols<T> {
    pub is_enabled: T,
    pub proof_idx: T,
    pub idx: T,
    pub round_idx: T,
    pub global_value: [T; D_EF],
    pub tower_value: [T; D_EF],
    pub eq_in: [T; D_EF],
    pub eq_out: [T; D_EF],
}

pub struct MainTowerPointEqAir {
    pub global_point_bus: MainGlobalPointBus,
    pub tower_point_bus: TowerMainPointBus,
}

impl<F: Field> BaseAir<F> for MainTowerPointEqAir {
    fn width(&self) -> usize {
        MainTowerPointEqCols::<F>::width()
    }
}

impl<F: Field> BaseAirWithPublicValues<F> for MainTowerPointEqAir {}
impl<F: Field> PartitionedBaseAir<F> for MainTowerPointEqAir {}

impl<AB> Air<AB> for MainTowerPointEqAir
where
    AB: AirBuilder + InteractionBuilder,
    <AB::Expr as PrimeCharacteristicRing>::PrimeSubfield: BinomiallyExtendable<{ D_EF }>,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local_row = main.row_slice(0).expect("main row exists");
        let local: &MainTowerPointEqCols<AB::Var> = (*local_row).borrow();

        builder.assert_bool(local.is_enabled);
        self.global_point_bus.lookup_key(
            builder,
            local.proof_idx,
            MainGlobalPointMessage {
                round_idx: local.round_idx.into(),
                value: local.global_value.map(Into::into),
            },
            local.is_enabled,
        );
        self.tower_point_bus.lookup_key(
            builder,
            local.proof_idx,
            TowerMainPointMessage {
                idx: local.idx.into(),
                round_idx: local.round_idx.into(),
                value: local.tower_value.map(Into::into),
            },
            local.is_enabled,
        );
        let same_bit: [AB::Expr; D_EF] =
            recursion_circuit::utils::ext_field_multiply(local.global_value, local.tower_value);
        let opposite_zero: [AB::Expr; D_EF] = recursion_circuit::utils::ext_field_multiply(
            recursion_circuit::utils::ext_field_one_minus(local.global_value),
            recursion_circuit::utils::ext_field_one_minus(local.tower_value),
        );
        let eq_factor: [AB::Expr; D_EF] =
            recursion_circuit::utils::ext_field_add(same_bit, opposite_zero);
        let eq_out = recursion_circuit::utils::ext_field_multiply(local.eq_in, eq_factor);
        assert_array_eq(&mut builder.when(local.is_enabled), local.eq_out, eq_out);
    }
}

pub struct MainTowerPointEqTraceGenerator;

impl RowMajorChip<F> for MainTowerPointEqTraceGenerator {
    type Ctx<'a> = &'a [MainTowerPointEqRecord];

    fn generate_trace(
        &self,
        records: &Self::Ctx<'_>,
        required_height: Option<usize>,
    ) -> Option<RowMajorMatrix<F>> {
        let width = MainTowerPointEqCols::<F>::width();
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
        for (row_idx, record) in records.iter().enumerate() {
            let row = &mut trace[row_idx * width..(row_idx + 1) * width];
            let cols: &mut MainTowerPointEqCols<F> = row.borrow_mut();
            cols.is_enabled = F::ONE;
            cols.proof_idx = F::from_usize(record.proof_idx);
            cols.idx = F::from_usize(record.idx);
            cols.round_idx = F::from_usize(record.round_idx);
            cols.global_value = record
                .global_value
                .as_basis_coefficients_slice()
                .try_into()
                .unwrap();
            cols.tower_value = record
                .tower_value
                .as_basis_coefficients_slice()
                .try_into()
                .unwrap();
            cols.eq_in = record
                .eq_in
                .as_basis_coefficients_slice()
                .try_into()
                .unwrap();
            cols.eq_out = record
                .eq_out
                .as_basis_coefficients_slice()
                .try_into()
                .unwrap();
        }
        Some(RowMajorMatrix::new(trace, width))
    }
}
