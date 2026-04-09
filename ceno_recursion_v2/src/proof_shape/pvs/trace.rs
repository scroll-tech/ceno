use core::borrow::BorrowMut;

use openvm_stark_sdk::config::baby_bear_poseidon2::F;
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;

use crate::{
    proof_shape::pvs::PublicValuesCols,
    system::{Preflight, RecursionField, RecursionProof, RecursionVk},
    tracegen::RowMajorChip,
};

pub struct PublicValuesTraceGenerator;

impl RowMajorChip<F> for PublicValuesTraceGenerator {
    type Ctx<'a> = (&'a RecursionVk, &'a [RecursionProof], &'a [Preflight]);

    #[tracing::instrument(level = "trace", skip_all)]
    fn generate_trace(
        &self,
        ctx: &Self::Ctx<'_>,
        required_height: Option<usize>,
    ) -> Option<RowMajorMatrix<F>> {
        let (child_vk, proofs, _preflights) = ctx;
        let width = PublicValuesCols::<F>::width();
        let num_rows_per_proof = child_vk
            .circuit_vks
            .values()
            .map(|circuit_vk| circuit_vk.get_cs().zkvm_v1_css.instance.len())
            .sum::<usize>();
        let num_valid_rows = proofs.len() * num_rows_per_proof;
        let height = if let Some(height) = required_height {
            if height < num_valid_rows {
                return None;
            }
            height
        } else {
            num_valid_rows.next_power_of_two().max(1)
        };

        let mut trace = vec![F::ZERO; height * width];
        let mut rows = trace.chunks_exact_mut(width);

        for (proof_idx, proof) in proofs.iter().enumerate() {
            let mut is_first_in_proof = true;
            // TODO first tidx start from TranscriptLabel::Riscv.field_len()
            let mut tidx = 0usize;

            for (air_idx, (_, circuit_vk)) in child_vk.circuit_vks.iter().enumerate() {
                let instance_openings = &circuit_vk.get_cs().zkvm_v1_css.instance;
                if instance_openings.is_empty() {
                    continue;
                }

                for (pv_idx, instance) in instance_openings.iter().enumerate() {
                    let row = rows.next().unwrap();
                    let cols: &mut PublicValuesCols<F> = row.borrow_mut();
                    let value = proof
                        .public_values
                        .query_by_index::<RecursionField>(instance.0);

                    cols.is_valid = F::ONE;
                    cols.proof_idx = F::from_usize(proof_idx);
                    cols.air_idx = F::from_usize(air_idx);
                    cols.pv_idx = F::from_usize(pv_idx);
                    cols.is_first_in_proof = F::from_bool(is_first_in_proof);
                    cols.is_first_in_air = F::from_bool(pv_idx == 0);
                    cols.tidx = F::from_usize(tidx);
                    cols.value = value;

                    is_first_in_proof = false;
                    tidx += 1;
                }
            }
        }

        Some(RowMajorMatrix::new(trace, width))
    }
}
