use std::sync::Arc;

use openvm_cuda_backend::GpuBackend;
use openvm_stark_backend::prover::AirProvingContext;

use crate::{
    cuda::{preflight::PreflightGpu, vk::VerifyingKeyGpu},
    system::POW_CHECKER_HEIGHT,
    tracegen::ModuleChip,
};
use recursion_circuit::primitives::{
    pow::cuda::PowerCheckerGpuTraceGenerator, range::cuda::RangeCheckerGpuTraceGenerator,
};

#[derive(derive_new::new)]
#[allow(dead_code)]
pub(in crate::proof_shape) struct ProofShapeChipGpu<const NUM_LIMBS: usize, const LIMB_BITS: usize>
{
    encoder_width: usize,
    min_cached_idx: usize,
    max_cached: usize,
    range_checker: Arc<RangeCheckerGpuTraceGenerator<LIMB_BITS>>,
    pow_checker: Arc<PowerCheckerGpuTraceGenerator<2, POW_CHECKER_HEIGHT>>,
}

const NUM_LIMBS: usize = 4;
const LIMB_BITS: usize = 8;
impl ModuleChip<GpuBackend> for ProofShapeChipGpu<NUM_LIMBS, LIMB_BITS> {
    type Ctx<'a> = (&'a VerifyingKeyGpu, &'a [PreflightGpu]);

    #[tracing::instrument(level = "trace", skip_all)]
    fn generate_proving_ctx(
        &self,
        ctx: &Self::Ctx<'_>,
        height: Option<usize>,
    ) -> Option<AirProvingContext<GpuBackend>> {
        let _ = (self, ctx, height);
        None
    }
}
