use core::borrow::{Borrow, BorrowMut};

use openvm_stark_backend::{
    BaseAirWithPublicValues, PartitionedBaseAir, interaction::InteractionBuilder,
};
use openvm_stark_sdk::config::baby_bear_poseidon2::{D_EF, F};
use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::{BasedVectorSpace, Field, PrimeCharacteristicRing};
use p3_matrix::{Matrix, dense::RowMajorMatrix};
use stark_recursion_circuit_derive::AlignedBorrow;

use crate::{
    bus::{TowerMainPointBus, TowerMainPointMessage},
    system::TowerMainPointRecord,
    tracegen::RowMajorChip,
};

#[repr(C)]
#[derive(AlignedBorrow, Debug)]
pub struct TowerMainPointCols<T> {
    pub is_enabled: T,
    pub proof_idx: T,
    pub idx: T,
    pub round_idx: T,
    pub value: [T; D_EF],
}

pub struct TowerMainPointAir {
    pub tower_point_bus: TowerMainPointBus,
}

impl<F: Field> BaseAir<F> for TowerMainPointAir {
    fn width(&self) -> usize {
        TowerMainPointCols::<F>::width()
    }
}

impl<F: Field> BaseAirWithPublicValues<F> for TowerMainPointAir {}
impl<F: Field> PartitionedBaseAir<F> for TowerMainPointAir {}

impl<AB: AirBuilder + InteractionBuilder> Air<AB> for TowerMainPointAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local_row = main.row_slice(0).expect("main row exists");
        let local: &TowerMainPointCols<AB::Var> = (*local_row).borrow();

        builder.assert_bool(local.is_enabled);
        self.tower_point_bus.send(
            builder,
            local.proof_idx,
            TowerMainPointMessage {
                idx: local.idx.into(),
                round_idx: local.round_idx.into(),
                value: local.value.map(Into::into),
            },
            local.is_enabled,
        );
    }
}

pub struct TowerMainPointTraceGenerator;

impl RowMajorChip<F> for TowerMainPointTraceGenerator {
    type Ctx<'a> = &'a [TowerMainPointRecord];

    fn generate_trace(
        &self,
        records: &Self::Ctx<'_>,
        required_height: Option<usize>,
    ) -> Option<RowMajorMatrix<F>> {
        let width = TowerMainPointCols::<F>::width();
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
            let cols: &mut TowerMainPointCols<F> = row.borrow_mut();
            cols.is_enabled = F::ONE;
            cols.proof_idx = F::from_usize(record.proof_idx);
            cols.idx = F::from_usize(record.idx);
            cols.round_idx = F::from_usize(record.round_idx);
            cols.value = record
                .value
                .as_basis_coefficients_slice()
                .try_into()
                .unwrap();
        }
        Some(RowMajorMatrix::new(trace, width))
    }
}
