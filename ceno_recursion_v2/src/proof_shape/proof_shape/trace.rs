use std::{borrow::BorrowMut, sync::Arc};

use openvm_circuit_primitives::encoder::Encoder;
use openvm_stark_sdk::config::baby_bear_poseidon2::{DIGEST_SIZE, F};
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;

use super::air::ProofShapeCols;
use crate::{
    primitives::{pow::PowerCheckerCpuTraceGenerator, range::RangeCheckerCpuTraceGenerator},
    system::{POW_CHECKER_HEIGHT, Preflight, RecursionProof, RecursionVk},
    tracegen::RowMajorChip,
};

pub(in crate::proof_shape) struct ProofShapeVarColsMut<'a, F> {
    pub idx_flags: &'a mut [F],
    pub cached_commits: &'a mut [[F; DIGEST_SIZE]],
}

fn borrow_var_cols_mut<F>(
    slice: &mut [F],
    idx_flags: usize,
    max_cached: usize,
) -> ProofShapeVarColsMut<'_, F> {
    let (idx_flags_slice, cached_flat) = slice.split_at_mut(idx_flags);
    let cached_commits: &mut [[F; DIGEST_SIZE]] = unsafe {
        std::slice::from_raw_parts_mut(
            cached_flat.as_mut_ptr() as *mut [F; DIGEST_SIZE],
            max_cached,
        )
    };
    ProofShapeVarColsMut {
        idx_flags: idx_flags_slice,
        cached_commits,
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

#[derive(derive_new::new)]
#[allow(dead_code)]
pub(in crate::proof_shape) struct ProofShapeChip<const NUM_LIMBS: usize, const LIMB_BITS: usize> {
    idx_encoder: Arc<Encoder>,
    min_cached_idx: usize,
    max_cached: usize,
    cidx_deltas: Vec<usize>,
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
            let mut _current_cidx = 1usize;

            for (air_idx, vdata) in &preflight.proof_shape.sorted_trace_vdata {
                let chunk = chunks.next().unwrap();
                let (fixed_cols, variable_cols) = chunk.split_at_mut(cols_width);
                let cols: &mut ProofShapeCols<F, NUM_LIMBS> = fixed_cols.borrow_mut();
                let var_cols = &mut borrow_var_cols_mut(
                    variable_cols,
                    self.idx_encoder.width(),
                    self.max_cached,
                );

                let log_height = vdata.log_height;
                let trace_height = 1usize << log_height;
                num_present += 1;

                cols.proof_idx = F::from_usize(proof_idx);
                cols.is_valid = F::ONE;
                cols.is_first = F::from_bool(sorted_idx == 0);
                cols.is_last = F::ZERO;
                cols.idx = F::from_usize(*air_idx);
                cols.sorted_idx = F::from_usize(sorted_idx);
                cols.log_height = F::from_usize(log_height);
                cols.need_rot = F::ZERO;
                cols.starting_tidx = F::from_usize(preflight.proof_shape.starting_tidx[*air_idx]);
                cols.is_present = F::ONE;
                cols.height = F::from_usize(trace_height);
                cols.num_present = F::from_usize(num_present);
                cols.height_limbs =
                    decompose_usize::<NUM_LIMBS, LIMB_BITS>(trace_height).map(F::from_usize);
                cols.n_max = F::from_usize(preflight.proof_shape.n_max);
                cols.is_n_max_greater = F::ZERO;
                cols.num_air_id_lookups = F::ZERO;
                cols.num_columns = F::ZERO;
                cols.current_snapshot_state = preflight.proof_shape.fork_start_state;

                for (dst, src) in var_cols
                    .idx_flags
                    .iter_mut()
                    .zip(self.idx_encoder.get_flag_pt(*air_idx).iter())
                {
                    *dst = F::from_u32(*src);
                }

                if *air_idx == self.min_cached_idx {
                    var_cols.cached_commits[self.max_cached - 1] = [F::ZERO; DIGEST_SIZE];
                }

                _current_cidx += self.cidx_deltas.get(*air_idx).copied().unwrap_or(0);
                self.pow_checker.add_pow(log_height);
                sorted_idx += 1;
            }

            for air_idx in 0..num_airs {
                if proof.chip_proofs.contains_key(&air_idx) {
                    continue;
                }
                let chunk = chunks.next().unwrap();
                let (fixed_cols, variable_cols) = chunk.split_at_mut(cols_width);
                let cols: &mut ProofShapeCols<F, NUM_LIMBS> = fixed_cols.borrow_mut();
                let var_cols = &mut borrow_var_cols_mut(
                    variable_cols,
                    self.idx_encoder.width(),
                    self.max_cached,
                );

                cols.proof_idx = F::from_usize(proof_idx);
                cols.is_valid = F::ONE;
                cols.is_first = F::from_bool(sorted_idx == 0);
                cols.is_last = F::ZERO;
                cols.idx = F::from_usize(air_idx);
                cols.sorted_idx = F::from_usize(sorted_idx);
                cols.log_height = F::ZERO;
                cols.need_rot = F::ZERO;
                cols.starting_tidx = F::from_usize(preflight.proof_shape.starting_tidx[air_idx]);
                cols.is_present = F::ZERO;
                cols.height = F::ZERO;
                cols.num_present = F::from_usize(num_present);
                cols.height_limbs = [F::ZERO; NUM_LIMBS];
                cols.n_max = F::from_usize(preflight.proof_shape.n_max);
                cols.is_n_max_greater = F::ZERO;
                cols.num_air_id_lookups = F::ZERO;
                cols.num_columns = F::ZERO;
                cols.current_snapshot_state = preflight.proof_shape.fork_start_state;

                for (dst, src) in var_cols
                    .idx_flags
                    .iter_mut()
                    .zip(self.idx_encoder.get_flag_pt(air_idx).iter())
                {
                    *dst = F::from_u32(*src);
                }

                if air_idx == self.min_cached_idx {
                    var_cols.cached_commits[self.max_cached - 1] = [F::ZERO; DIGEST_SIZE];
                }

                _current_cidx += self.cidx_deltas.get(air_idx).copied().unwrap_or(0);
                sorted_idx += 1;
            }

            let chunk = chunks.next().unwrap();
            let (fixed_cols, variable_cols) = chunk.split_at_mut(cols_width);
            let cols: &mut ProofShapeCols<F, NUM_LIMBS> = fixed_cols.borrow_mut();
            let var_cols =
                &mut borrow_var_cols_mut(variable_cols, self.idx_encoder.width(), self.max_cached);
            cols.proof_idx = F::from_usize(proof_idx);
            cols.is_valid = F::ZERO;
            cols.is_first = F::ZERO;
            cols.is_last = F::ONE;
            cols.idx = F::ZERO;
            cols.sorted_idx = F::ZERO;
            cols.log_height = F::from_usize(preflight.proof_shape.n_logup);
            cols.need_rot = F::ZERO;
            cols.starting_tidx = F::from_usize(preflight.proof_shape.post_tidx);
            cols.is_present = F::ZERO;
            cols.height = F::ZERO;
            cols.num_present = F::from_usize(num_present);
            cols.height_limbs = [F::ZERO; NUM_LIMBS];
            cols.n_max = F::from_usize(preflight.proof_shape.n_max);
            cols.is_n_max_greater =
                F::from_bool(preflight.proof_shape.n_max > preflight.proof_shape.n_logup);
            cols.num_air_id_lookups = F::ZERO;
            cols.num_columns = F::ZERO;
            cols.current_snapshot_state = preflight.proof_shape.fork_start_state;
            if self.max_cached != 0 {
                var_cols.cached_commits[self.max_cached - 1] = [F::ZERO; DIGEST_SIZE];
            }
        }

        for chunk in chunks {
            let cols: &mut ProofShapeCols<F, NUM_LIMBS> = chunk[..cols_width].borrow_mut();
            cols.proof_idx = F::from_usize(proofs.len());
        }

        Some(RowMajorMatrix::new(trace, width))
    }
}
