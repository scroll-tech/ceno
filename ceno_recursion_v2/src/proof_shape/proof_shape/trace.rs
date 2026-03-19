use std::sync::Arc;

use openvm_circuit_primitives::encoder::Encoder;
use openvm_stark_backend::keygen::types::MultiStarkVerifyingKey;
use openvm_stark_sdk::config::baby_bear_poseidon2::{BabyBearPoseidon2Config, DIGEST_SIZE, F};
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;

use super::air::ProofShapeCols;
use crate::{
    primitives::{pow::PowerCheckerCpuTraceGenerator, range::RangeCheckerCpuTraceGenerator},
    system::{POW_CHECKER_HEIGHT, Preflight, RecursionProof},
    tracegen::RowMajorChip,
};

#[derive(derive_new::new)]
#[allow(dead_code)]
pub(in crate::proof_shape) struct ProofShapeChip<const NUM_LIMBS: usize, const LIMB_BITS: usize> {
    idx_encoder: Arc<Encoder>,
    min_cached_idx: usize,
    max_cached: usize,
    range_checker: Arc<RangeCheckerCpuTraceGenerator<LIMB_BITS>>,
    pow_checker: Arc<PowerCheckerCpuTraceGenerator<2, POW_CHECKER_HEIGHT>>,
}

impl<const NUM_LIMBS: usize, const LIMB_BITS: usize> ProofShapeChip<NUM_LIMBS, LIMB_BITS> {
    pub(in crate::proof_shape) fn placeholder_width(&self) -> usize {
        ProofShapeCols::<u8, NUM_LIMBS>::width()
            + self.idx_encoder.width()
            + self.max_cached * DIGEST_SIZE
    }
}

impl<const NUM_LIMBS: usize, const LIMB_BITS: usize> RowMajorChip<F>
    for ProofShapeChip<NUM_LIMBS, LIMB_BITS>
{
    type Ctx<'a> = (
        &'a MultiStarkVerifyingKey<BabyBearPoseidon2Config>,
        &'a [RecursionProof],
        &'a [Preflight],
    );

    #[tracing::instrument(level = "trace", skip_all)]
    fn generate_trace(
        &self,
        _ctx: &Self::Ctx<'_>,
        required_height: Option<usize>,
    ) -> Option<RowMajorMatrix<F>> {
        let rows = required_height.unwrap_or(1).max(1);
        let width = self.placeholder_width();
        Some(RowMajorMatrix::new(vec![F::ZERO; rows * width], width))
    }
}
