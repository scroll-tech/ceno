use std::sync::Arc;

use openvm_circuit_primitives::encoder::Encoder;
use openvm_stark_backend::{interaction::Interaction, keygen::types::MultiStarkVerifyingKey};
use openvm_stark_sdk::config::baby_bear_poseidon2::{BabyBearPoseidon2Config, F};
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;

use crate::{
    primitives::{pow::PowerCheckerCpuTraceGenerator, range::RangeCheckerCpuTraceGenerator},
    system::{POW_CHECKER_HEIGHT, Preflight, RecursionProof},
    tracegen::RowMajorChip,
};

pub(crate) fn compute_air_shape_lookup_counts(
    child_vk: &MultiStarkVerifyingKey<BabyBearPoseidon2Config>,
) -> Vec<usize> {
    child_vk
        .inner
        .per_air
        .iter()
        .map(|avk| {
            let dag = &avk.symbolic_constraints;
            dag.constraints.nodes.len()
                + avk.unused_variables.len()
                + dag
                    .interactions
                    .iter()
                    .map(interaction_length)
                    .sum::<usize>()
        })
        .collect::<Vec<_>>()
}

fn interaction_length<T>(interaction: &Interaction<T>) -> usize {
    interaction.message.len() + 2
}

#[derive(derive_new::new)]
pub(in crate::proof_shape) struct ProofShapeChip<const NUM_LIMBS: usize, const LIMB_BITS: usize> {
    idx_encoder: Arc<Encoder>,
    min_cached_idx: usize,
    max_cached: usize,
    range_checker: Arc<RangeCheckerCpuTraceGenerator<LIMB_BITS>>,
    pow_checker: Arc<PowerCheckerCpuTraceGenerator<2, POW_CHECKER_HEIGHT>>,
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
        Some(RowMajorMatrix::new(vec![F::ZERO; rows], 1))
    }
}
