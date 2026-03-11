use openvm_stark_sdk::config::baby_bear_poseidon2::{EF, F};
use p3_matrix::dense::RowMajorMatrix;

use super::{GkrLogupInitSumCheckClaimCols, GkrLogupSumCheckClaimCols};
use crate::{gkr::layer::trace::GkrLayerRecord, tracegen::RowMajorChip};

fn zero_trace(width: usize, required_height: Option<usize>) -> Option<RowMajorMatrix<F>> {
    let height = required_height.unwrap_or(1).max(1);
    Some(RowMajorMatrix::new(vec![F::ZERO; height * width], width))
}

pub struct GkrLogupSumCheckClaimTraceGenerator;
pub struct GkrLogupInitSumCheckClaimTraceGenerator;

impl RowMajorChip<F> for GkrLogupSumCheckClaimTraceGenerator {
    type Ctx<'a> = (&'a [GkrLayerRecord], &'a [Vec<EF>]);

    #[tracing::instrument(level = "trace", skip_all)]
    fn generate_trace(
        &self,
        _ctx: &Self::Ctx<'_>,
        required_height: Option<usize>,
    ) -> Option<RowMajorMatrix<F>> {
        zero_trace(GkrLogupSumCheckClaimCols::<F>::width(), required_height)
    }
}

impl RowMajorChip<F> for GkrLogupInitSumCheckClaimTraceGenerator {
    type Ctx<'a> = (&'a [GkrLayerRecord], &'a [Vec<EF>]);

    #[tracing::instrument(level = "trace", skip_all)]
    fn generate_trace(
        &self,
        _ctx: &Self::Ctx<'_>,
        required_height: Option<usize>,
    ) -> Option<RowMajorMatrix<F>> {
        zero_trace(GkrLogupInitSumCheckClaimCols::<F>::width(), required_height)
    }
}
