use std::{borrow::BorrowMut, sync::Arc};

use ceno_zkvm::scheme::constants::{MAX_NUM_INSTANCE_BITS, MAX_NUM_INSTANCES};
use openvm_circuit_primitives::encoder::Encoder;
use openvm_stark_sdk::config::baby_bear_poseidon2::{D_EF, EF, F};
use p3_field::{BasedVectorSpace, PrimeCharacteristicRing};
use p3_matrix::dense::RowMajorMatrix;

use super::air::ProofShapeCols;
use crate::{
    primitives::{pow::PowerCheckerCpuTraceGenerator, range::RangeCheckerCpuTraceGenerator},
    proof_shape::AirMetadata,
    system::{POW_CHECKER_HEIGHT, Preflight, RecursionProof, RecursionVk},
    tower::tower_pre_alpha_tidx,
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

fn bounded_height_witness<const NUM_LIMBS: usize, const LIMB_BITS: usize>(
    height: usize,
) -> ([usize; NUM_LIMBS], usize) {
    // This is the tracegen mirror of the ProofShapeAir constraint below:
    // height < 2^MAX_NUM_INSTANCE_BITS is encoded with four u8 limbs by checking the
    // high limb against the exclusive raw per-entry bound.
    assert!(
        height < MAX_NUM_INSTANCES,
        "recursion proof-shape num_instances value {height} exceeds exclusive max {MAX_NUM_INSTANCES} (2^{MAX_NUM_INSTANCE_BITS})"
    );

    let limbs = decompose_usize::<NUM_LIMBS, LIMB_BITS>(height);
    let high_limb_idx = MAX_NUM_INSTANCE_BITS / LIMB_BITS;
    let high_limb_exclusive_max = 1usize << (MAX_NUM_INSTANCE_BITS % LIMB_BITS);
    assert!(
        high_limb_idx < NUM_LIMBS,
        "proof-shape height bound needs enough limbs to represent 2^{MAX_NUM_INSTANCE_BITS}"
    );

    (limbs, high_limb_exclusive_max - 1 - limbs[high_limb_idx])
}

fn two_instance_heights_from_chip_proof(instance: &impl BorrowNumInstances) -> (usize, usize) {
    let num_instances = instance.borrow_num_instances();
    assert_eq!(
        num_instances.len(),
        2,
        "recursion-v2 currently supports exactly two num_instances entries per chip"
    );
    (num_instances[0], num_instances[1])
}

fn tower_shape_max(metadata: &AirMetadata, log_height: usize) -> (usize, bool, bool, bool) {
    let num_vars = log_height + metadata.rotation_vars + metadata.ecc_extra_vars;
    let read_tower_vars = if metadata.num_read_count > 0 {
        num_vars + metadata.read_op_vars
    } else {
        0
    };
    let write_tower_vars = if metadata.num_write_count > 0 {
        num_vars + metadata.write_op_vars
    } else {
        0
    };
    let logup_tower_vars = if metadata.num_logup_count > 0 {
        num_vars + metadata.logup_op_vars
    } else {
        0
    };
    let max_tower_vars = read_tower_vars.max(write_tower_vars).max(logup_tower_vars);
    (
        max_tower_vars.saturating_sub(1),
        max_tower_vars != 0 && read_tower_vars == max_tower_vars,
        max_tower_vars != 0
            && read_tower_vars != max_tower_vars
            && write_tower_vars == max_tower_vars,
        max_tower_vars != 0
            && read_tower_vars != max_tower_vars
            && write_tower_vars != max_tower_vars
            && logup_tower_vars == max_tower_vars,
    )
}

fn fork_sample(preflight: &Preflight, fork_id: usize) -> EF {
    preflight
        .fork_transcripts
        .iter()
        .find(|fork| fork.fork_id == fork_id)
        .and_then(|fork| {
            fork.log
                .values()
                .get(fork.log.len().saturating_sub(D_EF)..)
                .and_then(EF::from_basis_coefficients_slice)
        })
        .unwrap_or(EF::ZERO)
}

fn fork_sample_tidx(preflight: &Preflight, fork_id: usize) -> usize {
    preflight
        .fork_transcripts
        .iter()
        .find(|fork| fork.fork_id == fork_id)
        .map(|fork| fork.log.len().saturating_sub(D_EF))
        .unwrap_or(0)
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
    per_air: Arc<Vec<AirMetadata>>,
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
            let mut sorted_idx = 0usize;
            let mut num_present = 0usize;
            let mut row_log_heights = Vec::with_capacity(num_airs);
            let fork_id_by_chip = proof
                .chip_proofs
                .keys()
                .enumerate()
                .map(|(fork_id, chip_idx)| (*chip_idx, fork_id))
                .collect::<std::collections::BTreeMap<_, _>>();
            let tower_tidx_by_chip = preflight
                .gkr
                .chips
                .iter()
                .filter_map(|chip| {
                    proof.chip_proofs.get(&chip.chip_idx).map(|chip_proof| {
                        (chip.chip_idx, tower_pre_alpha_tidx(chip_proof, chip.tidx))
                    })
                })
                .collect::<std::collections::BTreeMap<_, _>>();
            for (air_idx, vdata) in &preflight.proof_shape.sorted_trace_vdata {
                let chunk = chunks.next().unwrap();
                let (fixed_cols, variable_cols) = chunk.split_at_mut(cols_width);
                let cols: &mut ProofShapeCols<F, NUM_LIMBS> = fixed_cols.borrow_mut();
                let var_cols = &mut borrow_var_cols_mut(variable_cols, self.idx_encoder.width());

                let log_height = vdata.log_height;
                let (height_1, height_2) = proof
                    .chip_proofs
                    .get(air_idx)
                    .map(two_instance_heights_from_chip_proof)
                    .unwrap_or((0, 0));
                num_present += 1;

                cols.proof_idx = F::from_usize(proof_idx);
                cols.is_valid = F::ONE;
                cols.is_first = F::from_bool(sorted_idx == 0);
                cols.is_last = F::ZERO;
                cols.sorted_idx = F::from_usize(sorted_idx);
                cols.log_height = F::from_usize(log_height);
                let starting_tidx = preflight.proof_shape.starting_tidx[*air_idx];
                cols.starting_tidx = F::from_usize(starting_tidx);
                cols.tower_tidx =
                    F::from_usize(tower_tidx_by_chip.get(air_idx).copied().unwrap_or(0));
                cols.fork_start_tidx = F::from_usize(preflight.proof_shape.fork_start_tidx);
                let fork_id = fork_id_by_chip.get(air_idx).copied().unwrap_or(0);
                cols.fork_id = F::from_usize(fork_id);
                cols.is_present = F::ONE;
                cols.height_1 = F::from_usize(height_1);
                cols.height_2 = F::from_usize(height_2);
                cols.num_present = F::from_usize(num_present);
                let (height_1_limbs, height_1_high_limb_range_value) =
                    bounded_height_witness::<NUM_LIMBS, LIMB_BITS>(height_1);
                let (height_2_limbs, height_2_high_limb_range_value) =
                    bounded_height_witness::<NUM_LIMBS, LIMB_BITS>(height_2);
                cols.height_1_limbs = height_1_limbs.map(F::from_usize);
                cols.height_2_limbs = height_2_limbs.map(F::from_usize);
                for limb in height_1_limbs {
                    self.range_checker.add_count(limb);
                }
                for limb in height_2_limbs {
                    self.range_checker.add_count(limb);
                }
                self.range_checker.add_count(height_1_high_limb_range_value);
                self.range_checker.add_count(height_2_high_limb_range_value);
                cols.n_max = F::from_usize(preflight.proof_shape.n_max);
                cols.is_n_max_greater = F::ZERO;
                cols.lookup_challenge_alpha = preflight.proof_shape.lookup_challenge_alpha;
                cols.lookup_challenge_beta = preflight.proof_shape.lookup_challenge_beta;
                cols.after_forked_challenge_1 = ef_to_limbs(fork_sample(preflight, fork_id));
                cols.after_forked_challenge_1_tidx =
                    F::from_usize(fork_sample_tidx(preflight, fork_id));
                cols.after_forked_challenge_2 = [F::ZERO; D_EF];
                let (tower_n_logup, is_read_max, is_write_max, is_logup_max) =
                    tower_shape_max(&self.per_air[*air_idx], log_height);
                cols.tower_n_logup = F::from_usize(tower_n_logup);
                cols.tower_is_read_max = F::from_bool(is_read_max);
                cols.tower_is_write_max = F::from_bool(is_write_max);
                cols.tower_is_logup_max = F::from_bool(is_logup_max);

                for (dst, src) in var_cols
                    .idx_flags
                    .iter_mut()
                    .zip(self.idx_encoder.get_flag_pt(*air_idx).iter())
                {
                    *dst = F::from_u32(*src);
                }

                self.pow_checker.add_pow(log_height);
                self.range_checker.add_count(log_height);
                row_log_heights.push(log_height);
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
                cols.starting_tidx = F::from_usize(preflight.proof_shape.starting_tidx[air_idx]);
                cols.tower_tidx = F::ZERO;
                cols.fork_start_tidx = F::from_usize(preflight.proof_shape.fork_start_tidx);
                cols.fork_id = F::ZERO;
                cols.is_present = F::ZERO;
                cols.height_1 = F::ZERO;
                cols.height_2 = F::ZERO;
                cols.num_present = F::from_usize(num_present);
                cols.height_1_limbs = [F::ZERO; NUM_LIMBS];
                cols.height_2_limbs = [F::ZERO; NUM_LIMBS];
                for _ in 0..(2 * NUM_LIMBS) {
                    self.range_checker.add_count(0);
                }
                let high_limb_exclusive_max = 1usize << (MAX_NUM_INSTANCE_BITS % LIMB_BITS);
                for _ in 0..2 {
                    self.range_checker.add_count(high_limb_exclusive_max - 1);
                }
                cols.n_max = F::from_usize(preflight.proof_shape.n_max);
                cols.is_n_max_greater = F::ZERO;
                cols.lookup_challenge_alpha = preflight.proof_shape.lookup_challenge_alpha;
                cols.lookup_challenge_beta = preflight.proof_shape.lookup_challenge_beta;
                cols.after_forked_challenge_1 = [F::ZERO; D_EF];
                cols.after_forked_challenge_1_tidx = F::ZERO;
                cols.after_forked_challenge_2 = [F::ZERO; D_EF];
                cols.tower_n_logup = F::ZERO;
                cols.tower_is_read_max = F::ZERO;
                cols.tower_is_write_max = F::ZERO;
                cols.tower_is_logup_max = F::ZERO;

                for (dst, src) in var_cols
                    .idx_flags
                    .iter_mut()
                    .zip(self.idx_encoder.get_flag_pt(air_idx).iter())
                {
                    *dst = F::from_u32(*src);
                }

                row_log_heights.push(0);
                sorted_idx += 1;
            }

            for pair in row_log_heights.windows(2) {
                self.range_checker.add_count(pair[0] - pair[1]);
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
            cols.starting_tidx = F::from_usize(preflight.proof_shape.post_tidx);
            cols.tower_tidx = F::ZERO;
            cols.fork_start_tidx = F::from_usize(preflight.proof_shape.fork_start_tidx);
            cols.fork_id = F::ZERO;
            cols.is_present = F::ZERO;
            cols.height_1 = F::ZERO;
            cols.height_2 = F::ZERO;
            cols.num_present = F::from_usize(num_present);
            cols.height_1_limbs = [F::ZERO; NUM_LIMBS];
            cols.height_2_limbs = [F::ZERO; NUM_LIMBS];
            cols.n_max = F::from_usize(preflight.proof_shape.n_max);
            cols.is_n_max_greater =
                F::from_bool(preflight.proof_shape.n_max > preflight.proof_shape.n_logup);
            self.range_checker.add_count(
                preflight
                    .proof_shape
                    .n_max
                    .abs_diff(preflight.proof_shape.n_logup),
            );
            cols.lookup_challenge_alpha = preflight.proof_shape.lookup_challenge_alpha;
            cols.lookup_challenge_beta = preflight.proof_shape.lookup_challenge_beta;
            cols.after_forked_challenge_1 = [F::ZERO; D_EF];
            cols.after_forked_challenge_1_tidx = F::ZERO;
            cols.after_forked_challenge_2 = [F::ZERO; D_EF];
            cols.tower_n_logup = F::ZERO;
            cols.tower_is_read_max = F::ZERO;
            cols.tower_is_write_max = F::ZERO;
            cols.tower_is_logup_max = F::ZERO;
        }

        for chunk in chunks {
            let cols: &mut ProofShapeCols<F, NUM_LIMBS> = chunk[..cols_width].borrow_mut();
            cols.proof_idx = F::from_usize(proofs.len());
        }

        Some(RowMajorMatrix::new(trace, width))
    }
}

fn ef_to_limbs(value: EF) -> [F; D_EF] {
    let mut out = [F::ZERO; D_EF];
    out.copy_from_slice(value.as_basis_coefficients_slice());
    out
}
