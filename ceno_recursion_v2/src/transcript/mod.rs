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

use crate::{
    system::{
        AirModule, BusInventory, GlobalCtxCpu, Preflight, RecursionProof, RecursionVk,
        TraceGenModule,
    },
    utils::digests_to_poseidon2_input,
};
use recursion_circuit::transcript::poseidon2::{CHUNK, Poseidon2Air, Poseidon2Cols};

mod transcript_air;
pub use transcript_air::{ForkedTranscriptAir, ForkedTranscriptCols};

// Should be 1 when 3 <= max_constraint_degree < 7.
const SBOX_REGISTERS: usize = 1;

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
struct TranscriptRowData {
    proof_idx: usize,
    is_proof_start: bool,
    tidx: usize,
    is_sample: bool,
    mask: [F; CHUNK],
    prev_state: [F; POSEIDON2_WIDTH],
    post_state: [F; POSEIDON2_WIDTH],
    is_fork_start: bool,
    is_fork: bool,
    fork_id: usize,
}

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

    /// Build transcript row records from a single transcript log.
    ///
    /// `tidx_offset` is added to the local tidx. Returns the final sponge state after processing
    /// the log.
    #[allow(clippy::too_many_arguments)]
    fn collect_log_row_records(
        &self,
        log: &openvm_stark_backend::TranscriptLog<F, [F; POSEIDON2_WIDTH]>,
        proof_idx: usize,
        fork_id: usize,
        is_proof_start: bool,
        is_fork_start: bool,
        initial_state: [F; POSEIDON2_WIDTH],
        tidx_offset: usize,
        out: &mut Vec<TranscriptRowData>,
        poseidon2_perm_inputs: &mut Vec<[F; POSEIDON2_WIDTH]>,
    ) -> [F; POSEIDON2_WIDTH] {
        let mut tidx = 0usize;
        let mut prev_poseidon_state = initial_state;
        let start_row = out.len();

        while tidx < log.len() {
            let local_row = out.len() - start_row;
            let mut record = TranscriptRowData {
                proof_idx,
                is_proof_start: local_row == 0 && is_proof_start,
                fork_id,
                is_fork_start: local_row == 0 && is_fork_start,
                is_fork: is_fork_start,
                prev_state: prev_poseidon_state,
                ..Default::default()
            };

            let is_sample = log.samples()[tidx];
            record.is_sample = is_sample;
            record.tidx = tidx + tidx_offset;
            record.mask[0] = F::ONE;

            if is_sample {
                debug_assert_eq!(record.prev_state[CHUNK - 1], log.values()[tidx]);
            } else {
                record.prev_state[0] = log.values()[tidx];
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

                record.mask[idx] = F::ONE;
                if is_sample {
                    debug_assert_eq!(record.prev_state[CHUNK - 1 - idx], log.values()[tidx]);
                } else {
                    record.prev_state[idx] = log.values()[tidx];
                }

                tidx += 1;
                idx += 1;
                if idx == CHUNK {
                    permuted = tidx < log.len() && (!is_sample || log.samples()[tidx]);
                    break;
                }
            }

            prev_poseidon_state = record.prev_state;
            if permuted {
                self.perm.permute_mut(&mut prev_poseidon_state);
                poseidon2_perm_inputs.push(record.prev_state);
            }
            record.post_state = prev_poseidon_state;
            out.push(record);
        }

        debug_assert_eq!(tidx, log.len());
        prev_poseidon_state
    }

    #[tracing::instrument(name = "generate_trace.transcript", level = "trace", skip_all)]
    fn collect_transcript_row_records(
        &self,
        preflights: &[&Preflight],
        required_height: Option<usize>,
    ) -> Option<(Vec<TranscriptRowData>, usize, Vec<[F; POSEIDON2_WIDTH]>)> {
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

        let mut records = Vec::with_capacity(total_valid_rows);
        let mut poseidon2_perm_inputs = vec![];

        for (pidx, preflight) in preflights.iter().enumerate() {
            let info = &proof_infos[pidx];

            // Fill trunk rows (fork_id = 0, tidx_offset = 0).
            let before_trunk = records.len();
            let _trunk_final_state = self.collect_log_row_records(
                &preflight.transcript,
                pidx,
                0,                          // fork_id
                true,                       // is_proof_start
                false,                      // is_fork_start
                [F::ZERO; POSEIDON2_WIDTH], // trunk starts with zero state
                0,                          // tidx_offset: trunk starts at global tidx 0
                &mut records,
                &mut poseidon2_perm_inputs,
            );
            debug_assert_eq!(records.len() - before_trunk, info.trunk_rows);

            // Fill fork rows with fork-local tidx offsets.
            for (fi, fork_log) in preflight.fork_transcripts.iter().enumerate() {
                let before_fork = records.len();
                // Fresh fork semantics: every fork transcript starts from a
                // clean sponge state and is domain-separated by "fork".
                let _ = self.collect_log_row_records(
                    &fork_log.log,
                    pidx,
                    fork_log.fork_id,
                    false, // is_proof_start
                    true,  // is_fork_start
                    [F::ZERO; POSEIDON2_WIDTH],
                    0,
                    &mut records,
                    &mut poseidon2_perm_inputs,
                );
                debug_assert_eq!(records.len() - before_fork, info.fork_rows[fi]);
            }
        }
        debug_assert_eq!(records.len(), total_valid_rows);

        Some((records, transcript_num_rows, poseidon2_perm_inputs))
    }

    fn transcript_trace_from_records(
        records: &[TranscriptRowData],
        height: usize,
    ) -> RowMajorMatrix<F> {
        let transcript_width = ForkedTranscriptCols::<F>::width();
        let mut transcript_trace = vec![F::ZERO; height * transcript_width];
        for (record, row) in records
            .iter()
            .zip(transcript_trace.chunks_exact_mut(transcript_width))
        {
            let cols: &mut ForkedTranscriptCols<F> = row.borrow_mut();
            cols.proof_idx = F::from_usize(record.proof_idx);
            cols.is_proof_start = F::from_bool(record.is_proof_start);
            cols.tidx = F::from_usize(record.tidx);
            cols.is_sample = F::from_bool(record.is_sample);
            cols.mask = record.mask;
            cols.prev_state = record.prev_state;
            cols.post_state = record.post_state;
            cols.is_fork_start = F::from_bool(record.is_fork_start);
            cols.is_fork = F::from_bool(record.is_fork);
            cols.fork_id = F::from_usize(record.fork_id);
        }
        RowMajorMatrix::new(transcript_trace, transcript_width)
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

        let preflight_refs = preflights.iter().collect::<Vec<_>>();
        let (transcript_records, transcript_height, mut poseidon2_perm_inputs) =
            self.collect_transcript_row_records(&preflight_refs, required_transcript)?;
        let transcript_trace =
            Self::transcript_trace_from_records(&transcript_records, transcript_height);
        let mut poseidon2_compress_inputs = Vec::new();

        poseidon2_perm_inputs.extend_from_slice(ctx.0);
        poseidon2_compress_inputs.extend_from_slice(ctx.1);
        for preflight in preflights {
            poseidon2_perm_inputs.extend(
                preflight
                    .pcs
                    .base_input_leaf_hashes
                    .iter()
                    .map(|record| record.input),
            );
            poseidon2_perm_inputs.extend(
                preflight
                    .pcs
                    .commit_phase_leaf_hashes
                    .iter()
                    .map(|record| record.input),
            );
            poseidon2_compress_inputs.extend(
                preflight
                    .pcs
                    .base_input_merkle_rows
                    .iter()
                    .map(|record| digests_to_poseidon2_input(record.left, record.right)),
            );
            poseidon2_compress_inputs.extend(
                preflight
                    .pcs
                    .commit_phase_merkle_rows
                    .iter()
                    .map(|record| digests_to_poseidon2_input(record.left, record.right)),
            );
        }

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

#[cfg(feature = "cuda")]
mod cuda_tracegen {
    use openvm_cuda_backend::{
        GpuBackend, base::DeviceMatrix, data_transporter::transport_matrix_h2d_row,
    };
    use openvm_cuda_common::{
        d_buffer::DeviceBuffer,
        error::CudaError,
        memory_manager::MemTracker,
        stream::{GpuDeviceCtx, cudaStream_t},
    };
    use p3_matrix::Matrix;

    use super::*;
    use crate::cuda::{
        GlobalCtxGpu, preflight::PreflightGpu, proof::ProofGpu, to_device_or_nullptr,
        vk::VerifyingKeyGpu,
    };

    unsafe extern "C" {
        fn _transcript_tracegen(
            d_trace: *mut F,
            height: usize,
            d_records: *const TranscriptRowData,
            num_records: usize,
            stream: cudaStream_t,
        ) -> i32;
    }

    unsafe fn transcript_tracegen(
        d_trace: &DeviceBuffer<F>,
        height: usize,
        d_records: &DeviceBuffer<TranscriptRowData>,
        num_records: usize,
        stream: cudaStream_t,
    ) -> Result<(), CudaError> {
        unsafe {
            CudaError::from_result(_transcript_tracegen(
                d_trace.as_mut_ptr(),
                height,
                d_records.as_ptr(),
                num_records,
                stream,
            ))
        }
    }

    fn generate_transcript_gpu_ctx(
        records: &[TranscriptRowData],
        height: usize,
    ) -> Option<AirProvingContext<GpuBackend>> {
        let mem = MemTracker::start("tracegen.transcript");
        let width = ForkedTranscriptCols::<F>::width();
        let device_ctx = GpuDeviceCtx::for_current_device().ok()?;
        let trace = DeviceMatrix::with_capacity_on(height, width, &device_ctx);

        let h2d_start = std::time::Instant::now();
        let d_records = to_device_or_nullptr(records).ok()?;
        tracing::info!(
            elapsed_ms = h2d_start.elapsed().as_secs_f64() * 1000.0,
            record_count = records.len(),
            height,
            width,
            cells = height * width,
            "transcript.h2d_row_records"
        );

        let kernel_start = std::time::Instant::now();
        unsafe {
            if let Err(err) = transcript_tracegen(
                trace.buffer(),
                height,
                &d_records,
                records.len(),
                device_ctx.stream.as_raw(),
            ) {
                tracing::warn!(?err, "transcript_tracegen failed");
                return None;
            }
        }
        device_ctx.stream.synchronize().ok()?;
        tracing::info!(
            elapsed_ms = kernel_start.elapsed().as_secs_f64() * 1000.0,
            record_count = records.len(),
            height,
            width,
            cells = height * width,
            "transcript.kernel_launch_sync"
        );
        mem.emit_metrics();

        Some(AirProvingContext::simple_no_pis(trace))
    }

    impl TraceGenModule<GlobalCtxGpu, GpuBackend> for TranscriptModule {
        type ModuleSpecificCtx<'a> = (
            &'a [Preflight],
            &'a [[F; POSEIDON2_WIDTH]],
            &'a [[F; POSEIDON2_WIDTH]],
        );

        #[tracing::instrument(skip_all)]
        fn generate_proving_ctxs(
            &self,
            child_vk: &VerifyingKeyGpu,
            proofs: &[ProofGpu],
            preflights: &[PreflightGpu],
            ctx: &Self::ModuleSpecificCtx<'_>,
            required_heights: Option<&[usize]>,
        ) -> Option<Vec<AirProvingContext<GpuBackend>>> {
            let device_ctx = GpuDeviceCtx::for_current_device().ok()?;
            let _ = (child_vk, proofs);
            let _ = preflights;
            let preflight_refs = ctx.0.iter().collect::<Vec<_>>();

            let (required_transcript, required_poseidon2) = if let Some(heights) = required_heights
            {
                if heights.len() != 2 {
                    return None;
                }
                (Some(heights[0]), Some(heights[1]))
            } else {
                (None, None)
            };

            let transcript_start = std::time::Instant::now();
            let (transcript_records, transcript_height, mut poseidon2_perm_inputs) =
                self.collect_transcript_row_records(&preflight_refs, required_transcript)?;
            tracing::info!(
                elapsed_ms = transcript_start.elapsed().as_secs_f64() * 1000.0,
                record_count = transcript_records.len(),
                height = transcript_height,
                width = ForkedTranscriptCols::<F>::width(),
                cells = transcript_height * ForkedTranscriptCols::<F>::width(),
                "transcript.collect_row_records"
            );
            let mut poseidon2_compress_inputs = Vec::new();

            let collect_poseidon_start = std::time::Instant::now();
            poseidon2_perm_inputs.extend_from_slice(ctx.1);
            poseidon2_compress_inputs.extend_from_slice(ctx.2);
            for preflight in &preflight_refs {
                poseidon2_perm_inputs.extend(
                    preflight
                        .pcs
                        .base_input_leaf_hashes
                        .iter()
                        .map(|record| record.input),
                );
                poseidon2_perm_inputs.extend(
                    preflight
                        .pcs
                        .commit_phase_leaf_hashes
                        .iter()
                        .map(|record| record.input),
                );
                poseidon2_compress_inputs.extend(
                    preflight
                        .pcs
                        .base_input_merkle_rows
                        .iter()
                        .map(|record| digests_to_poseidon2_input(record.left, record.right)),
                );
                poseidon2_compress_inputs.extend(
                    preflight
                        .pcs
                        .commit_phase_merkle_rows
                        .iter()
                        .map(|record| digests_to_poseidon2_input(record.left, record.right)),
                );
            }
            let perm_input_count = poseidon2_perm_inputs.len();
            let compress_input_count = poseidon2_compress_inputs.len();
            tracing::info!(
                elapsed_ms = collect_poseidon_start.elapsed().as_secs_f64() * 1000.0,
                perm_input_count,
                compress_input_count,
                total_input_count = perm_input_count + compress_input_count,
                "transcript.collect_poseidon_inputs"
            );

            let poseidon2_trace = {
                let dedup_start = std::time::Instant::now();
                let (mut poseidon_states, poseidon_counts) =
                    Self::dedup_poseidon_inputs(poseidon2_perm_inputs, poseidon2_compress_inputs);
                let unique_state_count = poseidon_states.len();
                tracing::info!(
                    elapsed_ms = dedup_start.elapsed().as_secs_f64() * 1000.0,
                    unique_state_count,
                    duplicate_count = (perm_input_count + compress_input_count)
                        .saturating_sub(unique_state_count),
                    "transcript.dedup_poseidon_inputs"
                );
                let build_poseidon_start = std::time::Instant::now();
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
                let trace = RowMajorMatrix::new(poseidon_trace, poseidon2_width);
                tracing::info!(
                    elapsed_ms = build_poseidon_start.elapsed().as_secs_f64() * 1000.0,
                    height = trace.height(),
                    width = trace.width(),
                    cells = trace.height() * trace.width(),
                    valid_rows = poseidon2_valid_rows,
                    "transcript.build_poseidon2_trace"
                );
                trace
            };

            let transcript_trace =
                generate_transcript_gpu_ctx(&transcript_records, transcript_height)?;
            let poseidon2_height = poseidon2_trace.height();
            let poseidon2_width = poseidon2_trace.width();
            let h2d_poseidon_start = std::time::Instant::now();
            let poseidon2_trace = transport_matrix_h2d_row(&poseidon2_trace, &device_ctx).ok()?;
            tracing::info!(
                elapsed_ms = h2d_poseidon_start.elapsed().as_secs_f64() * 1000.0,
                height = poseidon2_height,
                width = poseidon2_width,
                cells = poseidon2_height * poseidon2_width,
                "transcript.h2d_poseidon2_trace"
            );

            Some(vec![
                transcript_trace,
                AirProvingContext::simple_no_pis(poseidon2_trace),
            ])
        }
    }
}
