use core::borrow::{Borrow, BorrowMut};

use openvm_stark_backend::{
    BaseAirWithPublicValues, PartitionedBaseAir, interaction::InteractionBuilder,
};
use openvm_stark_sdk::config::baby_bear_poseidon2::F;
use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_matrix::{Matrix, dense::RowMajorMatrix};
use stark_recursion_circuit_derive::AlignedBorrow;

use crate::{
    bus::{ForkedTranscriptBus, ForkedTranscriptBusMessage, TranscriptBus, TranscriptBusMessage},
    system::MainTranscriptRecord,
    tracegen::RowMajorChip,
};

#[repr(C)]
#[derive(AlignedBorrow, Debug)]
pub struct MainTranscriptBindCols<T> {
    pub is_enabled: T,
    pub proof_idx: T,
    pub fork_id: T,
    pub is_fork: T,
    pub tidx: T,
    pub value: T,
    pub is_sample: T,
}

pub struct MainTranscriptBindAir {
    pub transcript_bus: TranscriptBus,
    pub forked_transcript_bus: ForkedTranscriptBus,
}

impl<F: Field> BaseAir<F> for MainTranscriptBindAir {
    fn width(&self) -> usize {
        MainTranscriptBindCols::<F>::width()
    }
}

impl<F: Field> BaseAirWithPublicValues<F> for MainTranscriptBindAir {}
impl<F: Field> PartitionedBaseAir<F> for MainTranscriptBindAir {}

impl<AB: AirBuilder + InteractionBuilder> Air<AB> for MainTranscriptBindAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local_row = main.row_slice(0).expect("main row exists");
        let local: &MainTranscriptBindCols<AB::Var> = (*local_row).borrow();

        builder.assert_bool(local.is_enabled);
        builder.assert_bool(local.is_sample);
        builder.assert_bool(local.is_fork);

        self.transcript_bus.receive(
            builder,
            local.proof_idx,
            TranscriptBusMessage {
                tidx: local.tidx.into(),
                value: local.value.into(),
                is_sample: local.is_sample.into(),
            },
            local.is_enabled * (AB::Expr::ONE - local.is_fork),
        );
        self.forked_transcript_bus.receive(
            builder,
            local.proof_idx,
            ForkedTranscriptBusMessage {
                fork_id: local.fork_id.into(),
                tidx: local.tidx.into(),
                value: local.value.into(),
                is_sample: local.is_sample.into(),
            },
            local.is_enabled * local.is_fork,
        );
    }
}

pub struct MainTranscriptBindTraceGenerator;

impl RowMajorChip<F> for MainTranscriptBindTraceGenerator {
    type Ctx<'a> = &'a [MainTranscriptRecord];

    fn generate_trace(
        &self,
        records: &Self::Ctx<'_>,
        required_height: Option<usize>,
    ) -> Option<RowMajorMatrix<F>> {
        let width = MainTranscriptBindCols::<F>::width();
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
            let cols: &mut MainTranscriptBindCols<F> = row.borrow_mut();
            cols.is_enabled = F::ONE;
            cols.proof_idx = F::from_usize(record.proof_idx);
            cols.fork_id = F::from_usize(record.fork_id);
            cols.is_fork = F::from_bool(record.is_fork);
            cols.tidx = F::from_usize(record.tidx);
            cols.value = record.value;
            cols.is_sample = F::from_bool(record.is_sample);
        }

        Some(RowMajorMatrix::new(trace, width))
    }
}
