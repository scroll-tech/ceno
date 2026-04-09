use core::borrow::BorrowMut;
use std::sync::Arc;

use openvm_cpu_backend::CpuBackend;
use openvm_poseidon2_air::{POSEIDON2_WIDTH, Poseidon2Config, Poseidon2SubChip};
use openvm_stark_backend::{AirRef, StarkProtocolConfig, prover::AirProvingContext};
use openvm_stark_sdk::{
    config::baby_bear_poseidon2::{F, poseidon2_perm},
    p3_baby_bear::Poseidon2BabyBear,
};
use p3_air::BaseAir;
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_matrix::dense::RowMajorMatrix;
use p3_symmetric::Permutation;

use crate::system::{
    AirModule, BusInventory, GlobalCtxCpu, Preflight, RecursionProof, RecursionVk, TraceGenModule,
};
use recursion_circuit::transcript::poseidon2::{CHUNK, Poseidon2Air, Poseidon2Cols};

mod transcript_air;
pub use transcript_air::{ForkedTranscriptAir, ForkedTranscriptCols};

// Should be 1 when 3 <= max_constraint_degree < 7.
const SBOX_REGISTERS: usize = 1;

pub struct TranscriptModule {
    pub bus_inventory: BusInventory,
    final_state_bus_enabled: bool,

    sub_chip: Poseidon2SubChip<F, SBOX_REGISTERS>,
    perm: Poseidon2BabyBear<POSEIDON2_WIDTH>,
}

impl TranscriptModule {
    pub fn new(bus_inventory: BusInventory, final_state_bus_enabled: bool) -> Self {
        let sub_chip = Poseidon2SubChip::<F, 1>::new(Poseidon2Config::default().constants);
        Self {
            bus_inventory,
            final_state_bus_enabled,
            sub_chip,
            perm: poseidon2_perm().clone(),
        }
    }

    /// Count the number of valid trace rows needed for a single transcript log.
    fn count_log_rows(log: &openvm_stark_backend::TranscriptLog<F, [F; POSEIDON2_WIDTH]>) -> usize {
        let mut cur_is_sample = false;
        let mut count = 0usize;
        let mut num_valid_rows = 0usize;

        for op_is_sample in log.samples() {
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
        num_valid_rows
    }

    /// Fill transcript trace rows from a single transcript log.
    ///
    /// `tidx_offset` is added to the local tidx.
    ///
    /// Returns the final sponge state after processing the log.
    #[allow(clippy::too_many_arguments)]
    fn fill_log_rows(
        &self,
        trace: &mut [F],
        transcript_width: usize,
        log: &openvm_stark_backend::TranscriptLog<F, [F; POSEIDON2_WIDTH]>,
        proof_idx: usize,
        fork_id: usize,
        is_proof_start: bool,
        is_fork_start: bool,
        initial_state: [F; POSEIDON2_WIDTH],
        tidx_offset: usize,
        poseidon2_perm_inputs: &mut Vec<[F; POSEIDON2_WIDTH]>,
    ) -> [F; POSEIDON2_WIDTH] {
        let mut tidx = 0usize;
        let mut prev_poseidon_state = initial_state;

        for (i, row) in trace.chunks_exact_mut(transcript_width).enumerate() {
            let cols: &mut ForkedTranscriptCols<F> = row.borrow_mut();
            cols.proof_idx = F::from_usize(proof_idx);
            cols.fork_id = F::from_usize(fork_id);

            if i == 0 && is_proof_start {
                cols.is_proof_start = F::ONE;
            }
            if i == 0 && is_fork_start {
                cols.is_fork_start = F::ONE;
            }

            let is_sample = log.samples()[tidx];
            cols.is_sample = F::from_bool(is_sample);
            cols.tidx = F::from_usize(tidx + tidx_offset);
            cols.mask[0] = F::ONE;
            cols.prev_state = prev_poseidon_state;

            if is_sample {
                debug_assert_eq!(cols.prev_state[CHUNK - 1], log.values()[tidx]);
            } else {
                cols.prev_state[0] = log.values()[tidx];
            }

            tidx += 1;
            let mut idx = 1usize;
            let mut permuted = false;
            loop {
                if tidx >= log.len() {
                    break;
                }

                if log.samples()[tidx] != is_sample {
                    permuted = log.samples()[tidx];
                    break;
                }

                cols.mask[idx] = F::ONE;
                if is_sample {
                    debug_assert_eq!(cols.prev_state[CHUNK - 1 - idx], log.values()[tidx]);
                } else {
                    cols.prev_state[idx] = log.values()[tidx];
                }

                tidx += 1;
                idx += 1;
                if idx == CHUNK {
                    permuted = tidx < log.len() && (!is_sample || log.samples()[tidx]);
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

        debug_assert_eq!(tidx, log.len());
        prev_poseidon_state
    }

    #[tracing::instrument(name = "generate_trace.transcript", level = "trace", skip_all)]
    fn build_transcript_trace(
        &self,
        preflights: &[Preflight],
        required_height: Option<usize>,
    ) -> Option<(RowMajorMatrix<F>, Vec<[F; POSEIDON2_WIDTH]>)> {
        let transcript_width = ForkedTranscriptCols::<F>::width();

        // Count valid rows for each proof (trunk + all forks).
        struct ProofRowInfo {
            trunk_rows: usize,
            fork_rows: Vec<usize>,
        }
        let mut proof_infos: Vec<ProofRowInfo> = Vec::with_capacity(preflights.len());
        let mut total_valid_rows = 0usize;

        for preflight in preflights {
            let trunk_rows = Self::count_log_rows(&preflight.transcript);
            let fork_rows: Vec<usize> = preflight
                .fork_transcripts
                .iter()
                .map(|ft| Self::count_log_rows(&ft.log))
                .collect();
            let proof_total = trunk_rows + fork_rows.iter().sum::<usize>();
            total_valid_rows += proof_total;
            proof_infos.push(ProofRowInfo {
                trunk_rows,
                fork_rows,
            });
        }

        let transcript_num_rows = if let Some(height) = required_height {
            if height == 0 || height < total_valid_rows {
                return None;
            }
            height
        } else if total_valid_rows == 0 {
            1
        } else {
            total_valid_rows.next_power_of_two()
        };

        let mut transcript_trace = vec![F::ZERO; transcript_num_rows * transcript_width];
        let mut poseidon2_perm_inputs = vec![];

        let mut offset = 0usize;
        for (pidx, preflight) in preflights.iter().enumerate() {
            let info = &proof_infos[pidx];

            // Fill trunk rows (fork_id = 0, tidx_offset = 0).
            let trunk_end = offset + info.trunk_rows;
            let trunk_slice =
                &mut transcript_trace[offset * transcript_width..trunk_end * transcript_width];
            let _trunk_final_state = self.fill_log_rows(
                trunk_slice,
                transcript_width,
                &preflight.transcript,
                pidx,
                0,                          // fork_id
                true,                       // is_proof_start
                false,                      // is_fork_start
                [F::ZERO; POSEIDON2_WIDTH], // trunk starts with zero state
                0,                          // tidx_offset: trunk starts at global tidx 0
                &mut poseidon2_perm_inputs,
            );
            offset = trunk_end;

            // Fill fork rows with fork-local tidx offsets.
            for (fi, fork_log) in preflight.fork_transcripts.iter().enumerate() {
                let fork_rows = info.fork_rows[fi];
                let fork_end = offset + fork_rows;
                let fork_slice =
                    &mut transcript_trace[offset * transcript_width..fork_end * transcript_width];
                // Fresh fork semantics: every fork transcript starts from a
                // clean sponge state and is domain-separated by "fork".
                let _ = self.fill_log_rows(
                    fork_slice,
                    transcript_width,
                    &fork_log.log,
                    pidx,
                    fork_log.fork_id,
                    false, // is_proof_start
                    true,  // is_fork_start
                    [F::ZERO; POSEIDON2_WIDTH],
                    0,
                    &mut poseidon2_perm_inputs,
                );
                offset = fork_end;
            }
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
        2
    }

    fn airs<SC: StarkProtocolConfig<F = F>>(&self) -> Vec<AirRef<SC>> {
        let transcript_air = ForkedTranscriptAir {
            transcript_bus: self.bus_inventory.transcript_bus,
            forked_transcript_bus: self.bus_inventory.forked_transcript_bus,
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
        vec![Arc::new(transcript_air), Arc::new(poseidon2_air)]
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

        let (required_transcript, required_poseidon2) = if let Some(heights) = required_heights {
            if heights.len() != 2 {
                return None;
            }
            (Some(heights[0]), Some(heights[1]))
        } else {
            (None, None)
        };

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
        ])
    }
}
