use openvm_stark_sdk::config::baby_bear_poseidon2::F;
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;

use crate::{
    proof_shape::commit::CommitAirCols,
    system::{Preflight, RecursionProof},
    tracegen::RowMajorChip,
};

pub struct CommitTraceGenerator;

impl RowMajorChip<F> for CommitTraceGenerator {
    type Ctx<'a> = (&'a [RecursionProof], &'a [Preflight]);

    #[tracing::instrument(level = "trace", skip_all)]
    fn generate_trace(
        &self,
        _ctx: &Self::Ctx<'_>,
        required_height: Option<usize>,
    ) -> Option<RowMajorMatrix<F>> {
        let rows = required_height.unwrap_or(1).max(1);
        let width = CommitAirCols::<u8>::width();
        Some(RowMajorMatrix::new(vec![F::ZERO; rows * width], width))
    }
}
