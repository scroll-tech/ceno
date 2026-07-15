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
    bus::{MainEvalBus, MainEvalMessage, TranscriptBus, TranscriptBusMessage},
    system::MainEvalRecord,
    tracegen::RowMajorChip,
};

#[repr(C)]
#[derive(AlignedBorrow, Debug)]
pub struct MainEvalAbsorbCols<T> {
    pub is_enabled: T,
    pub proof_idx: T,
    pub idx: T,
    pub eval_idx: T,
    pub tidx: T,
    pub lookup_count: T,
    pub value: [T; D_EF],
}

pub struct MainEvalAbsorbAir {
    pub transcript_bus: TranscriptBus,
    pub eval_bus: MainEvalBus,
}

impl<F: Field> BaseAir<F> for MainEvalAbsorbAir {
    fn width(&self) -> usize {
        MainEvalAbsorbCols::<F>::width()
    }
}

impl<F: Field> BaseAirWithPublicValues<F> for MainEvalAbsorbAir {}
impl<F: Field> PartitionedBaseAir<F> for MainEvalAbsorbAir {}

impl<AB: AirBuilder + InteractionBuilder> Air<AB> for MainEvalAbsorbAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local_row = main.row_slice(0).expect("main row exists");
        let local: &MainEvalAbsorbCols<AB::Var> = (*local_row).borrow();

        builder.assert_bool(local.is_enabled);
        self.eval_bus.add_key_with_lookups(
            builder,
            local.proof_idx,
            MainEvalMessage {
                idx: local.idx.into(),
                eval_idx: local.eval_idx.into(),
                value: local.value.map(Into::into),
            },
            local.is_enabled * local.lookup_count,
        );
        for i in 0..D_EF {
            self.transcript_bus.receive(
                builder,
                local.proof_idx,
                TranscriptBusMessage {
                    tidx: local.tidx + AB::Expr::from_usize(i),
                    value: local.value[i].into(),
                    is_sample: AB::Expr::ZERO,
                },
                local.is_enabled,
            );
        }
    }
}

pub struct MainEvalAbsorbTraceGenerator;

impl RowMajorChip<F> for MainEvalAbsorbTraceGenerator {
    type Ctx<'a> = &'a [MainEvalRecord];

    fn generate_trace(
        &self,
        records: &Self::Ctx<'_>,
        required_height: Option<usize>,
    ) -> Option<RowMajorMatrix<F>> {
        let width = MainEvalAbsorbCols::<F>::width();
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
            let cols: &mut MainEvalAbsorbCols<F> = row.borrow_mut();
            cols.is_enabled = F::ONE;
            cols.proof_idx = F::from_usize(record.proof_idx);
            cols.idx = F::from_usize(record.idx);
            cols.eval_idx = F::from_usize(record.eval_idx);
            cols.tidx = F::from_usize(record.tidx);
            cols.lookup_count = F::from_usize(record.lookup_count);
            cols.value = record
                .value
                .as_basis_coefficients_slice()
                .try_into()
                .unwrap();
        }
        Some(RowMajorMatrix::new(trace, width))
    }
}
