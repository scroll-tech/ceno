use std::{borrow::BorrowMut, sync::Arc};

use openvm_circuit_primitives::encoder::Encoder;
use openvm_stark_sdk::config::baby_bear_poseidon2::{D_EF, EF, F};
use p3_field::{BasedVectorSpace, PrimeCharacteristicRing};
use p3_matrix::dense::RowMajorMatrix;

use super::air::ProofShapeCols;
use crate::{
    primitives::{pow::PowerCheckerCpuTraceGenerator, range::RangeCheckerCpuTraceGenerator},
    system::{POW_CHECKER_HEIGHT, Preflight, RecursionField, RecursionProof, RecursionVk},
    tracegen::RowMajorChip,
};

pub(in crate::proof_shape) struct ProofShapeVarColsMut<'a, F> {
    pub idx_flags: &'a mut [F],
}

fn borrow_var_cols_mut<F>(slice: &mut [F], idx_flags: usize) -> ProofShapeVarColsMut<'_, F> {
    ProofShapeVarColsMut {
        idx_flags: &mut slice[..idx_flags],
    }
}

fn root_claims_for_chip(proof: &RecursionProof, air_idx: usize) -> (EF, EF, EF, EF) {
    let Some(chip_proof) = proof
        .chip_proofs
        .get(&air_idx)
        .and_then(|instances| instances.first())
    else {
        return (EF::ZERO, EF::ZERO, EF::ZERO, EF::ZERO);
    };

    let r0 = chip_proof
        .r_out_evals
        .iter()
        .map(|evals| evals[0] * evals[1])
        .product::<EF>();
    let w0 = chip_proof
        .w_out_evals
        .iter()
        .map(|evals| evals[0] * evals[1])
        .product::<EF>();
    let mut p0 = EF::ZERO;
    let mut q0 = EF::ONE;
    for evals in &chip_proof.lk_out_evals {
        let p_cross = evals[0] * evals[3] + evals[1] * evals[2];
        let q_cross = evals[2] * evals[3];
        p0 = p0 * q_cross + p_cross * q0;
        q0 *= q_cross;
    }
    (r0, w0, p0, q0)
}

fn assign_ext(dst: &mut [F; D_EF], value: EF) {
    dst.copy_from_slice(value.as_basis_coefficients_slice());
}

fn tower_layer_count(chip_proof: &ceno_zkvm::scheme::ZKVMChipProof<RecursionField>) -> usize {
    let proof_layers = chip_proof.tower_proof.proofs.len();
    let has_root_specs = !chip_proof.r_out_evals.is_empty()
        || !chip_proof.w_out_evals.is_empty()
        || !chip_proof.lk_out_evals.is_empty();
    if proof_layers == 0 && !has_root_specs {
        0
    } else {
        proof_layers + 1
    }
}

fn decompose_usize<const NUM_LIMBS: usize, const LIMB_BITS: usize>(
    mut value: usize,
) -> [usize; NUM_LIMBS] {
    let mask = (1usize << LIMB_BITS) - 1;
    core::array::from_fn(|_| {
        let limb = value & mask;
        value >>= LIMB_BITS;
        limb
    })
}

fn two_instance_heights_from_chip_instances(
    chip_instances: &[impl BorrowNumInstances],
) -> (usize, usize) {
    chip_instances
        .iter()
        .fold((0usize, 0usize), |(h1, h2), instance| {
            let num_instances = instance.borrow_num_instances();
            (
                h1 + num_instances.first().copied().unwrap_or(0),
                h2 + num_instances.get(1).copied().unwrap_or(0),
            )
        })
}

fn fork_merge_sample(preflight: &Preflight, fork_id: usize) -> Option<(usize, [F; D_EF])> {
    let fork_log = preflight
        .fork_transcripts
        .iter()
        .find(|fork| fork.fork_id == fork_id)?;
    let sample_tidx = fork_log.log.len().checked_sub(D_EF)?;
    let mut sample = [F::ZERO; D_EF];
    sample.copy_from_slice(&fork_log.log.values()[sample_tidx..sample_tidx + D_EF]);
    Some((sample_tidx, sample))
}

trait BorrowNumInstances {
    fn borrow_num_instances(&self) -> &[usize];
}

impl BorrowNumInstances for ceno_zkvm::scheme::ZKVMChipProof<crate::system::RecursionField> {
    fn borrow_num_instances(&self) -> &[usize] {
        &self.num_instances
    }
}

#[derive(derive_new::new)]
#[allow(dead_code)]
pub(in crate::proof_shape) struct ProofShapeChip<const NUM_LIMBS: usize, const LIMB_BITS: usize> {
    idx_encoder: Arc<Encoder>,
    range_checker: Arc<RangeCheckerCpuTraceGenerator<LIMB_BITS>>,
    pow_checker: Arc<PowerCheckerCpuTraceGenerator<2, POW_CHECKER_HEIGHT>>,
}

impl<const NUM_LIMBS: usize, const LIMB_BITS: usize> ProofShapeChip<NUM_LIMBS, LIMB_BITS> {
    pub(in crate::proof_shape) fn placeholder_width(&self) -> usize {
        ProofShapeCols::<u8, NUM_LIMBS>::width() + self.idx_encoder.width()
    }
}

impl<const NUM_LIMBS: usize, const LIMB_BITS: usize> RowMajorChip<F>
    for ProofShapeChip<NUM_LIMBS, LIMB_BITS>
{
    type Ctx<'a> = (&'a RecursionVk, &'a [RecursionProof], &'a [Preflight]);

    #[tracing::instrument(level = "trace", skip_all)]
    fn generate_trace(
        &self,
        ctx: &Self::Ctx<'_>,
        required_height: Option<usize>,
    ) -> Option<RowMajorMatrix<F>> {
        let (child_vk, proofs, preflights) = ctx;
        let num_airs = child_vk.circuit_vks.len();
        let num_valid_rows = proofs.len() * (num_airs + 1);
        let height = if let Some(height) = required_height {
            if height < num_valid_rows {
                return None;
            }
            height
        } else {
            num_valid_rows.next_power_of_two().max(1)
        };

        let cols_width = ProofShapeCols::<F, NUM_LIMBS>::width();
        let width = self.placeholder_width();
        let mut trace = vec![F::ZERO; height * width];
        let mut chunks = trace.chunks_exact_mut(width);

        for (proof_idx, (proof, preflight)) in proofs.iter().zip(preflights.iter()).enumerate() {
            let fork_id_by_chip: std::collections::BTreeMap<usize, usize> = proof
                .chip_proofs
                .iter()
                .flat_map(|(chip_idx, instances)| {
                    instances
                        .iter()
                        .enumerate()
                        .map(move |(instance_idx, _)| (*chip_idx, instance_idx))
                })
                .enumerate()
                .map(|(fork_id, (chip_idx, _instance_idx))| (chip_idx, fork_id))
                .collect();
            let mut sorted_idx = 0usize;
            let mut num_present = 0usize;

            for (air_idx, vdata) in &preflight.proof_shape.sorted_trace_vdata {
                let chunk = chunks.next().unwrap();
                let (fixed_cols, variable_cols) = chunk.split_at_mut(cols_width);
                let cols: &mut ProofShapeCols<F, NUM_LIMBS> = fixed_cols.borrow_mut();
                let var_cols = &mut borrow_var_cols_mut(variable_cols, self.idx_encoder.width());

                let log_height = vdata.log_height;
                let (height_1, height_2) = proof
                    .chip_proofs
                    .get(air_idx)
                    .map(|instances| two_instance_heights_from_chip_instances(instances))
                    .unwrap_or((0, 0));
                num_present += 1;

                cols.proof_idx = F::from_usize(proof_idx);
                cols.is_valid = F::ONE;
                cols.is_first = F::from_bool(sorted_idx == 0);
                cols.is_last = F::ZERO;
                cols.sorted_idx = F::from_usize(sorted_idx);
                cols.log_height = F::from_usize(log_height);
                cols.need_rot = F::ZERO;
                cols.num_tower_layers = F::from_usize(
                    proof
                        .chip_proofs
                        .get(air_idx)
                        .and_then(|instances| instances.iter().map(tower_layer_count).max())
                        .unwrap_or(0),
                );
                cols.starting_tidx = F::from_usize(preflight.proof_shape.starting_tidx[*air_idx]);
                cols.is_present = F::ONE;
                cols.height_1 = F::from_usize(height_1);
                cols.height_2 = F::from_usize(height_2);
                cols.num_present = F::from_usize(num_present);
                let fork_id = fork_id_by_chip
                    .get(air_idx)
                    .copied()
                    .unwrap_or(num_present.saturating_sub(1));
                cols.fork_id = F::from_usize(fork_id);
                cols.height_1_limbs =
                    decompose_usize::<NUM_LIMBS, LIMB_BITS>(height_1).map(F::from_usize);
                cols.height_2_limbs =
                    decompose_usize::<NUM_LIMBS, LIMB_BITS>(height_2).map(F::from_usize);
                cols.n_max = F::from_usize(preflight.proof_shape.n_max);
                cols.is_n_max_greater = F::ZERO;
                cols.num_air_id_lookups = F::ZERO;
                cols.num_columns = F::ZERO;
                cols.lookup_challenge_alpha = preflight.proof_shape.lookup_challenge_alpha;
                cols.lookup_challenge_beta = preflight.proof_shape.lookup_challenge_beta;
                if let Some((sample_tidx, sample)) = fork_merge_sample(preflight, fork_id) {
                    cols.fork_sample_tidx = F::from_usize(sample_tidx);
                    cols.merge_tidx =
                        F::from_usize(preflight.proof_shape.fork_start_tidx + fork_id * D_EF);
                    cols.fork_merge_sample = sample;
                }
                let (r0, w0, p0, q0) = root_claims_for_chip(proof, *air_idx);
                assign_ext(&mut cols.r0_claim, r0);
                assign_ext(&mut cols.w0_claim, w0);
                assign_ext(&mut cols.p0_claim, p0);
                assign_ext(&mut cols.q0_claim, q0);

                for (dst, src) in var_cols
                    .idx_flags
                    .iter_mut()
                    .zip(self.idx_encoder.get_flag_pt(*air_idx).iter())
                {
                    *dst = F::from_u32(*src);
                }

                sorted_idx += 1;
            }

            for air_idx in 0..num_airs {
                if proof.chip_proofs.contains_key(&air_idx) {
                    continue;
                }
                let chunk = chunks.next().unwrap();
                let (fixed_cols, variable_cols) = chunk.split_at_mut(cols_width);
                let cols: &mut ProofShapeCols<F, NUM_LIMBS> = fixed_cols.borrow_mut();
                let var_cols = &mut borrow_var_cols_mut(variable_cols, self.idx_encoder.width());

                cols.proof_idx = F::from_usize(proof_idx);
                cols.is_valid = F::ONE;
                cols.is_first = F::from_bool(sorted_idx == 0);
                cols.is_last = F::ZERO;
                cols.sorted_idx = F::from_usize(sorted_idx);
                cols.log_height = F::ZERO;
                cols.need_rot = F::ZERO;
                cols.num_tower_layers = F::ZERO;
                cols.starting_tidx = F::from_usize(preflight.proof_shape.starting_tidx[air_idx]);
                cols.is_present = F::ZERO;
                cols.height_1 = F::ZERO;
                cols.height_2 = F::ZERO;
                cols.num_present = F::from_usize(num_present);
                cols.fork_id = F::ZERO;
                cols.height_1_limbs = [F::ZERO; NUM_LIMBS];
                cols.height_2_limbs = [F::ZERO; NUM_LIMBS];
                cols.n_max = F::from_usize(preflight.proof_shape.n_max);
                cols.is_n_max_greater = F::ZERO;
                cols.num_air_id_lookups = F::ZERO;
                cols.num_columns = F::ZERO;
                cols.lookup_challenge_alpha = preflight.proof_shape.lookup_challenge_alpha;
                cols.lookup_challenge_beta = preflight.proof_shape.lookup_challenge_beta;
                cols.fork_sample_tidx = F::ZERO;
                cols.merge_tidx = F::ZERO;
                cols.fork_merge_sample = [F::ZERO; D_EF];

                for (dst, src) in var_cols
                    .idx_flags
                    .iter_mut()
                    .zip(self.idx_encoder.get_flag_pt(air_idx).iter())
                {
                    *dst = F::from_u32(*src);
                }

                sorted_idx += 1;
            }

            let chunk = chunks.next().unwrap();
            let (fixed_cols, variable_cols) = chunk.split_at_mut(cols_width);
            let cols: &mut ProofShapeCols<F, NUM_LIMBS> = fixed_cols.borrow_mut();
            let _var_cols = &mut borrow_var_cols_mut(variable_cols, self.idx_encoder.width());
            cols.proof_idx = F::from_usize(proof_idx);
            cols.is_valid = F::ZERO;
            cols.is_first = F::ZERO;
            cols.is_last = F::ONE;
            cols.sorted_idx = F::ZERO;
            cols.log_height = F::from_usize(preflight.proof_shape.n_logup);
            cols.need_rot = F::ZERO;
            cols.num_tower_layers = F::from_usize(preflight.proof_shape.n_logup);
            cols.starting_tidx = F::from_usize(preflight.proof_shape.post_tidx);
            cols.is_present = F::ZERO;
            cols.height_1 = F::ZERO;
            cols.height_2 = F::ZERO;
            cols.num_present = F::from_usize(num_present);
            cols.fork_id = F::ZERO;
            cols.height_1_limbs = [F::ZERO; NUM_LIMBS];
            cols.height_2_limbs = [F::ZERO; NUM_LIMBS];
            cols.n_max = F::from_usize(preflight.proof_shape.n_max);
            cols.is_n_max_greater =
                F::from_bool(preflight.proof_shape.n_max > preflight.proof_shape.n_logup);
            cols.num_air_id_lookups = F::ZERO;
            cols.num_columns = F::ZERO;
            cols.lookup_challenge_alpha = preflight.proof_shape.lookup_challenge_alpha;
            cols.lookup_challenge_beta = preflight.proof_shape.lookup_challenge_beta;
            cols.fork_sample_tidx = F::ZERO;
            cols.merge_tidx = F::ZERO;
            cols.fork_merge_sample = [F::ZERO; D_EF];
        }

        for chunk in chunks {
            let cols: &mut ProofShapeCols<F, NUM_LIMBS> = chunk[..cols_width].borrow_mut();
            cols.proof_idx = F::from_usize(proofs.len());
        }

        Some(RowMajorMatrix::new(trace, width))
    }
}
