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
        let (child_vk, proofs, preflights) = ctx;
        let width = PublicValuesCols::<F>::width();
        let num_valid_rows = proofs
            .iter()
            .map(|proof| {
                (0..child_vk.circuit_vks.len())
                    .filter(|&air_idx| proof.chip_proofs.contains_key(&air_idx))
                    .filter_map(|air_idx| {
                        child_vk
                            .circuit_index_to_name
                            .get(&air_idx)
                            .and_then(|name| child_vk.circuit_vks.get(name))
                            .map(|vk| vk.get_cs().zkvm_v1_css.instance.len())
                    })
                    .sum::<usize>()
            })
            .sum::<usize>();
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

        for (proof_idx, (proof, preflight)) in proofs.iter().zip(preflights.iter()).enumerate() {
            let mut is_first_in_proof = true;
            let mut pvs_tidx_idx = 0usize;

            for air_idx in 0..child_vk.circuit_vks.len() {
                if !proof.chip_proofs.contains_key(&air_idx) {
                    continue;
                }
                let Some(circuit_name) = child_vk.circuit_index_to_name.get(&air_idx) else {
                    continue;
                };
                let Some(circuit_vk) = child_vk.circuit_vks.get(circuit_name) else {
                    continue;
                };
                let instance_openings = &circuit_vk.get_cs().zkvm_v1_css.instance;
                if instance_openings.is_empty() {
                    continue;
                }

                let tidx_base = preflight.proof_shape.pvs_tidx[pvs_tidx_idx];
                pvs_tidx_idx += 1;

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
                    cols.tidx = F::from_usize(tidx_base + pv_idx);
                    cols.value = value;

                    is_first_in_proof = false;
                }
            }
        }

        Some(RowMajorMatrix::new(trace, width))
    }
}
