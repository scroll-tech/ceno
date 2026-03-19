use core::borrow::BorrowMut;
use std::sync::Arc;

use openvm_cpu_backend::CpuBackend;
use openvm_poseidon2_air::{POSEIDON2_WIDTH, Poseidon2Config, Poseidon2SubChip};
use openvm_stark_backend::{AirRef, StarkProtocolConfig, SystemParams, prover::AirProvingContext};
use openvm_stark_sdk::{
    config::baby_bear_poseidon2::{F, poseidon2_perm},
    p3_baby_bear::Poseidon2BabyBear,
};
use p3_air::BaseAir;
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_matrix::dense::RowMajorMatrix;
use p3_symmetric::Permutation;

use crate::system::{
    AirModule, GlobalCtxCpu, Preflight, RecursionProof, RecursionVk, TraceGenModule,
};
use recursion_circuit::{
    system::BusInventory,
    transcript::{
        merkle_verify::{MerkleVerifyAir, MerkleVerifyCols},
        poseidon2::{CHUNK, Poseidon2Air, Poseidon2Cols},
        transcript::{TranscriptAir, TranscriptCols},
    },
};

// Should be 1 when 3 <= max_constraint_degree < 7.
const SBOX_REGISTERS: usize = 1;

pub struct TranscriptModule {
    pub bus_inventory: BusInventory,
    params: SystemParams,
    final_state_bus_enabled: bool,

    sub_chip: Poseidon2SubChip<F, SBOX_REGISTERS>,
    perm: Poseidon2BabyBear<POSEIDON2_WIDTH>,
}

impl TranscriptModule {
    pub fn new(
        bus_inventory: BusInventory,
        params: SystemParams,
        final_state_bus_enabled: bool,
    ) -> Self {
        let sub_chip = Poseidon2SubChip::<F, 1>::new(Poseidon2Config::default().constants);
        Self {
            bus_inventory,
            params,
            final_state_bus_enabled,
            sub_chip,
            perm: poseidon2_perm().clone(),
        }
    }

    #[tracing::instrument(name = "generate_trace.transcript", level = "trace", skip_all)]
    fn build_transcript_trace(
        &self,
        preflights: &[Preflight],
        required_height: Option<usize>,
    ) -> Option<(RowMajorMatrix<F>, Vec<[F; POSEIDON2_WIDTH]>)> {
        let transcript_width = TranscriptCols::<F>::width();
        let mut valid_rows = Vec::with_capacity(preflights.len());

        let mut transcript_valid_rows = 0usize;
        for preflight in preflights {
            let mut cur_is_sample = false;
            let mut count = 0usize;
            let mut num_valid_rows = 0usize;

            for op_is_sample in preflight.transcript.samples() {
                if *op_is_sample {
                    if !cur_is_sample {
                        num_valid_rows += 1;
                        cur_is_sample = true;
                        count = 1;
                    } else {
                        if count == CHUNK {
                            num_valid_rows += 1;
                            count = 0;
                        }
                        count += 1;
                    }
                } else if cur_is_sample {
                    num_valid_rows += 1;
                    cur_is_sample = false;
                    count = 1;
                } else {
                    if count == CHUNK {
                        num_valid_rows += 1;
                        count = 0;
                    }
                    count += 1;
                }
            }

            if count > 0 {
                num_valid_rows += 1;
            }
            valid_rows.push(num_valid_rows);
            transcript_valid_rows += num_valid_rows;
        }

        let transcript_num_rows = if let Some(height) = required_height {
            if height == 0 || height < transcript_valid_rows {
                return None;
            }
            height
        } else if transcript_valid_rows == 0 {
            1
        } else {
            transcript_valid_rows.next_power_of_two()
        };

        let mut transcript_trace = vec![F::ZERO; transcript_num_rows * transcript_width];
        let mut poseidon2_perm_inputs = vec![];

        let mut skip = 0usize;
        for (pidx, preflight) in preflights.iter().enumerate() {
            let mut tidx = 0usize;
            let mut prev_poseidon_state = [F::ZERO; POSEIDON2_WIDTH];
            let off = skip * transcript_width;
            let end = off + valid_rows[pidx] * transcript_width;

            for (i, row) in transcript_trace[off..end]
                .chunks_exact_mut(transcript_width)
                .enumerate()
            {
                let cols: &mut TranscriptCols<F> = row.borrow_mut();
                cols.proof_idx = F::from_usize(pidx);
                if i == 0 {
                    cols.is_proof_start = F::ONE;
                }
                let is_sample = preflight.transcript.samples()[tidx];
                cols.is_sample = F::from_bool(is_sample);
                cols.tidx = F::from_usize(tidx);
                cols.mask[0] = F::ONE;
                cols.prev_state = prev_poseidon_state;

                if is_sample {
                    debug_assert_eq!(
                        cols.prev_state[CHUNK - 1],
                        preflight.transcript.values()[tidx]
                    );
                } else {
                    cols.prev_state[0] = preflight.transcript.values()[tidx];
                }

                tidx += 1;
                let mut idx = 1usize;
                let mut permuted = false;
                loop {
                    if tidx >= preflight.transcript.len() {
                        break;
                    }

                    if preflight.transcript.samples()[tidx] != is_sample {
                        permuted = preflight.transcript.samples()[tidx];
                        break;
                    }

                    cols.mask[idx] = F::ONE;
                    if is_sample {
                        debug_assert_eq!(
                            cols.prev_state[CHUNK - 1 - idx],
                            preflight.transcript.values()[tidx]
                        );
                    } else {
                        cols.prev_state[idx] = preflight.transcript.values()[tidx];
                    }

                    tidx += 1;
                    idx += 1;
                    if idx == CHUNK {
                        permuted = tidx < preflight.transcript.len()
                            && (!is_sample || preflight.transcript.samples()[tidx]);
                        break;
                    }
                }

                prev_poseidon_state = cols.prev_state;
                if permuted {
                    self.perm.permute_mut(&mut prev_poseidon_state);
                    poseidon2_perm_inputs.push(cols.prev_state);
                }
                cols.post_state = prev_poseidon_state;
            }

            skip += valid_rows[pidx];
            debug_assert_eq!(tidx, preflight.transcript.len());
        }

        Some((
            RowMajorMatrix::new(transcript_trace, transcript_width),
            poseidon2_perm_inputs,
        ))
    }

    fn dedup_poseidon_inputs(
        poseidon2_perm_inputs: Vec<[F; POSEIDON2_WIDTH]>,
        poseidon2_compress_inputs: Vec<[F; POSEIDON2_WIDTH]>,
    ) -> (Vec<[F; POSEIDON2_WIDTH]>, Vec<Poseidon2Count>) {
        let mut keyed_states: Vec<([u32; POSEIDON2_WIDTH], [F; POSEIDON2_WIDTH], bool)> =
            Vec::with_capacity(poseidon2_perm_inputs.len() + poseidon2_compress_inputs.len());

        for state in poseidon2_perm_inputs {
            keyed_states.push((state.map(|x| x.as_canonical_u32()), state, true));
        }
        for state in poseidon2_compress_inputs {
            keyed_states.push((state.map(|x| x.as_canonical_u32()), state, false));
        }

        keyed_states.sort_unstable_by(|a, b| a.0.cmp(&b.0));

        let mut deduped = Vec::new();
        let mut counts: Vec<Poseidon2Count> = Vec::new();
        let mut last_key: Option<[u32; POSEIDON2_WIDTH]> = None;

        for (key, state, is_perm) in keyed_states {
            if last_key == Some(key) {
                let last = counts.last_mut().expect("counts not empty");
                if is_perm {
                    last.perm += 1;
                } else {
                    last.compress += 1;
                }
            } else {
                deduped.push(state);
                counts.push(if is_perm {
                    Poseidon2Count {
                        perm: 1,
                        compress: 0,
                    }
                } else {
                    Poseidon2Count {
                        perm: 0,
                        compress: 1,
                    }
                });
                last_key = Some(key);
            }
        }

        (deduped, counts)
    }
}

impl AirModule for TranscriptModule {
    fn num_airs(&self) -> usize {
        3
    }

    fn airs<SC: StarkProtocolConfig<F = F>>(&self) -> Vec<AirRef<SC>> {
        let transcript_air = TranscriptAir {
            transcript_bus: self.bus_inventory.transcript_bus,
            poseidon2_permute_bus: self.bus_inventory.poseidon2_permute_bus,
            final_state_bus: self
                .final_state_bus_enabled
                .then_some(self.bus_inventory.final_state_bus),
        };
        let poseidon2_air = Poseidon2Air::<F, SBOX_REGISTERS> {
            subair: self.sub_chip.air.clone(),
            poseidon2_permute_bus: self.bus_inventory.poseidon2_permute_bus,
            poseidon2_compress_bus: self.bus_inventory.poseidon2_compress_bus,
        };
        let merkle_verify_air = MerkleVerifyAir {
            poseidon2_compress_bus: self.bus_inventory.poseidon2_compress_bus,
            merkle_verify_bus: self.bus_inventory.merkle_verify_bus,
            commitments_bus: self.bus_inventory.commitments_bus,
            right_shift_bus: self.bus_inventory.right_shift_bus,
            k: self.params.k_whir(),
        };
        vec![
            Arc::new(transcript_air),
            Arc::new(poseidon2_air),
            Arc::new(merkle_verify_air),
        ]
    }
}

#[repr(C)]
#[derive(Copy, Clone, Default)]
struct Poseidon2Count {
    perm: u32,
    compress: u32,
}

impl<SC: StarkProtocolConfig<F = F>> TraceGenModule<GlobalCtxCpu, CpuBackend<SC>>
    for TranscriptModule
{
    // (external poseidon2 permute, external poseidon2 compress)
    type ModuleSpecificCtx<'a> = (&'a [[F; POSEIDON2_WIDTH]], &'a [[F; POSEIDON2_WIDTH]]);

    #[tracing::instrument(skip_all)]
    fn generate_proving_ctxs(
        &self,
        child_vk: &RecursionVk,
        proofs: &[RecursionProof],
        preflights: &[Preflight],
        ctx: &Self::ModuleSpecificCtx<'_>,
        required_heights: Option<&[usize]>,
    ) -> Option<Vec<AirProvingContext<CpuBackend<SC>>>> {
        let _ = (child_vk, proofs);

        let (required_transcript, required_poseidon2, required_merkle_verify) =
            if let Some(heights) = required_heights {
                if heights.len() != 3 {
                    return None;
                }
                (Some(heights[0]), Some(heights[1]), Some(heights[2]))
            } else {
                (None, None, None)
            };

        // TODO(recursion-proof-bridge): Implement MerkleVerify trace generation using
        // RecursionProof/RecursionVk once those fields are available in local bridge APIs.
        let merkle_rows = required_merkle_verify.unwrap_or(1);
        if merkle_rows == 0 {
            return None;
        }
        let merkle_verify_trace = RowMajorMatrix::new(
            vec![F::ZERO; merkle_rows * MerkleVerifyCols::<F>::width()],
            MerkleVerifyCols::<F>::width(),
        );

        let (transcript_trace, mut poseidon2_perm_inputs) =
            self.build_transcript_trace(preflights, required_transcript)?;
        let mut poseidon2_compress_inputs = Vec::new();

        poseidon2_perm_inputs.extend_from_slice(ctx.0);
        poseidon2_compress_inputs.extend_from_slice(ctx.1);

        let poseidon2_trace = {
            let (mut poseidon_states, poseidon_counts) =
                Self::dedup_poseidon_inputs(poseidon2_perm_inputs, poseidon2_compress_inputs);
            let poseidon2_valid_rows = poseidon_states.len();
            let poseidon2_num_rows = if let Some(height) = required_poseidon2 {
                if height == 0 || poseidon2_valid_rows > height {
                    return None;
                }
                height
            } else if poseidon2_valid_rows == 0 {
                1
            } else {
                poseidon2_valid_rows.next_power_of_two()
            };

            poseidon_states.resize(poseidon2_num_rows, [F::ZERO; POSEIDON2_WIDTH]);

            let inner_width = self.sub_chip.air.width();
            let poseidon2_width = Poseidon2Cols::<F, SBOX_REGISTERS>::width();
            let inner_trace = self.sub_chip.generate_trace(poseidon_states);
            let mut poseidon_trace = vec![F::ZERO; poseidon2_num_rows * poseidon2_width];

            for (i, row) in poseidon_trace.chunks_exact_mut(poseidon2_width).enumerate() {
                let inner_off = i * inner_width;
                row[..inner_width]
                    .copy_from_slice(&inner_trace.values[inner_off..inner_off + inner_width]);
                let cols: &mut Poseidon2Cols<F, SBOX_REGISTERS> = row.borrow_mut();
                let count = poseidon_counts.get(i).copied().unwrap_or_default();
                cols.permute_mult = F::from_u32(count.perm);
                cols.compress_mult = F::from_u32(count.compress);
            }
            RowMajorMatrix::new(poseidon_trace, poseidon2_width)
        };

        Some(vec![
            AirProvingContext::simple_no_pis(transcript_trace),
            AirProvingContext::simple_no_pis(poseidon2_trace),
            AirProvingContext::simple_no_pis(merkle_verify_trace),
        ])
    }
}
