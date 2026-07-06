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
    bus::{EccRtBus, EccRtMessage, ForkedTranscriptBus, ForkedTranscriptBusMessage},
    system::MainEccRtRecord,
    tracegen::RowMajorChip,
};

#[repr(C)]
#[derive(AlignedBorrow, Debug)]
pub struct MainEccRtCols<T> {
    pub is_enabled: T,
    pub proof_idx: T,
    pub idx: T,
    pub fork_id: T,
    pub round_idx: T,
    pub tidx: T,
    pub lookup_count: T,
    pub value: [T; D_EF],
}

pub struct MainEccRtAir {
    pub forked_transcript_bus: ForkedTranscriptBus,
    pub ecc_rt_bus: EccRtBus,
}

impl<F: Field> BaseAir<F> for MainEccRtAir {
    fn width(&self) -> usize {
        MainEccRtCols::<F>::width()
    }
}

impl<F: Field> BaseAirWithPublicValues<F> for MainEccRtAir {}
impl<F: Field> PartitionedBaseAir<F> for MainEccRtAir {}

impl<AB: AirBuilder + InteractionBuilder> Air<AB> for MainEccRtAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local_row = main.row_slice(0).expect("main row exists");
        let local: &MainEccRtCols<AB::Var> = (*local_row).borrow();

        builder.assert_bool(local.is_enabled);

        for i in 0..D_EF {
            self.forked_transcript_bus.receive(
                builder,
                local.proof_idx,
                ForkedTranscriptBusMessage {
                    fork_id: local.fork_id.into(),
                    tidx: local.tidx + AB::Expr::from_usize(i),
                    value: local.value[i].into(),
                    is_sample: AB::Expr::ONE,
                },
                local.is_enabled,
            );
        }

        self.ecc_rt_bus.add_key_with_lookups(
            builder,
            local.proof_idx,
            EccRtMessage {
                idx: local.idx.into(),
                round_idx: local.round_idx.into(),
                value: local.value.map(Into::into),
            },
            local.is_enabled * local.lookup_count,
        );
    }
}

pub struct MainEccRtTraceGenerator;

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
            cols.is_enabled = F::ONE;
            cols.proof_idx = F::from_usize(record.proof_idx);
            cols.idx = F::from_usize(record.idx);
            cols.fork_id = F::from_usize(record.fork_id);
            cols.round_idx = F::from_usize(record.round_idx);
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
