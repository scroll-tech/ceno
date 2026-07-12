use openvm_cuda_backend::{GpuBackend, base::DeviceMatrix};
use openvm_cuda_common::{
    d_buffer::DeviceBuffer,
    error::CudaError,
    memory_manager::MemTracker,
    stream::{GpuDeviceCtx, cudaStream_t},
};
use openvm_stark_backend::{poly_common::interpolate_cubic_at_0123, prover::AirProvingContext};
use openvm_stark_sdk::config::baby_bear_poseidon2::{D_EF, EF, F};
use p3_field::{BasedVectorSpace, PrimeCharacteristicRing};

use crate::{
    cuda::{to_device_or_nullptr, types::TowerSumcheckData},
    tower::sumcheck::{TowerLayerSumcheckCols, TowerSumcheckRecord},
    tracegen::ModuleChip,
};

unsafe extern "C" {
    fn _tower_sumcheck_tracegen(
        d_trace: *mut F,
        height: usize,
        d_records: *const TowerSumcheckData,
        num_records: usize,
        stream: cudaStream_t,
    ) -> i32;
}

unsafe fn tower_sumcheck_tracegen(
    d_trace: &DeviceBuffer<F>,
    height: usize,
    d_records: &DeviceBuffer<TowerSumcheckData>,
    num_records: usize,
    stream: cudaStream_t,
) -> Result<(), CudaError> {
    unsafe {
        CudaError::from_result(_tower_sumcheck_tracegen(
            d_trace.as_mut_ptr(),
            height,
            d_records.as_ptr(),
            num_records,
            stream,
        ))
    }
}

pub struct TowerSumcheckGpuTraceGenerator;

impl ModuleChip<GpuBackend> for TowerSumcheckGpuTraceGenerator {
    type Ctx<'a> = (&'a [TowerSumcheckRecord], &'a [Vec<EF>]);

    #[tracing::instrument(level = "trace", skip_all)]
    fn generate_proving_ctx(
        &self,
        ctx: &Self::Ctx<'_>,
        required_height: Option<usize>,
    ) -> Option<AirProvingContext<GpuBackend>> {
        let mem = MemTracker::start("tracegen.tower_sumcheck");
        let (sumcheck_records, mus) = ctx;
        debug_assert_eq!(sumcheck_records.len(), mus.len());

        let rows_per_proof = sumcheck_records
            .iter()
            .map(|record| record.total_rounds().max(1))
            .collect::<Vec<_>>();
        let num_valid_rows = rows_per_proof.iter().sum::<usize>();
        let height = if let Some(height) = required_height {
            if height < num_valid_rows {
                return None;
            }
            height
        } else {
            num_valid_rows.next_power_of_two()
        };
        let width = TowerLayerSumcheckCols::<F>::width();
        let device_ctx = GpuDeviceCtx::for_current_device().ok()?;
        let trace = DeviceMatrix::with_capacity_on(height, width, &device_ctx);

        let records = build_tower_sumcheck_rows(sumcheck_records, mus);
        debug_assert_eq!(records.len(), num_valid_rows);
        let d_records = to_device_or_nullptr(&records).ok()?;
        unsafe {
            if let Err(err) = tower_sumcheck_tracegen(
                trace.buffer(),
                height,
                &d_records,
                records.len(),
                device_ctx.stream.as_raw(),
            ) {
                tracing::warn!(?err, "tower_sumcheck_tracegen failed");
                return None;
            }
        }
        if let Err(err) = device_ctx.stream.synchronize() {
            tracing::warn!(?err, "tower_sumcheck_tracegen synchronize failed");
            return None;
        }
        mem.emit_metrics();
        Some(AirProvingContext::simple_no_pis(trace))
    }
}

fn build_tower_sumcheck_rows(
    sumcheck_records: &[TowerSumcheckRecord],
    mus: &[Vec<EF>],
) -> Vec<TowerSumcheckData> {
    let mut rows = Vec::with_capacity(
        sumcheck_records
            .iter()
            .map(|record| record.total_rounds().max(1))
            .sum(),
    );

    for (record, mus_for_proof) in sumcheck_records.iter().zip(mus.iter()) {
        let total_rounds = record.total_rounds();
        let num_layers = record.num_layers();
        debug_assert_eq!(record.ris.len(), total_rounds);
        debug_assert_eq!(record.evals.len(), total_rounds);
        debug_assert!(mus_for_proof.len() >= num_layers);

        if total_rounds == 0 {
            rows.push(TowerSumcheckData {
                proof_idx: record.proof_idx,
                idx: record.idx,
                fork_id: record.fork_id,
                layer_idx: 1,
                is_first_idx: record.is_first_air_idx,
                is_first_layer: true,
                is_first_round: true,
                is_dummy: true,
                is_last_layer: true,
                tidx: D_EF,
                eq_in: ef_to_base(EF::ONE),
                eq_out: ef_to_base(EF::ONE),
                claim_in: ef_to_base(EF::ONE),
                claim_out: ef_to_base(EF::ONE),
                ..Default::default()
            });
            continue;
        }

        let mut global_round_idx = 0usize;
        for layer_idx in 0..num_layers {
            let layer_rounds = TowerSumcheckRecord::layer_rounds(layer_idx);
            let layer_idx_value = layer_idx + 1;
            let is_last_layer = layer_idx == num_layers.saturating_sub(1);
            let mut claim = record.claims[layer_idx];
            let mut eq = EF::ONE;

            for round_in_layer in 0..layer_rounds {
                let challenge = record.ris[global_round_idx];
                let evals = record.evals[global_round_idx];
                let prev_challenge = TowerSumcheckRecord::prev_challenge(
                    layer_idx,
                    round_in_layer,
                    record.beta,
                    mus_for_proof,
                    &record.ris,
                );
                let ev0 = claim - evals[0];
                let evals_full = [ev0, evals[0], evals[1], evals[2]];
                let claim_out = interpolate_cubic_at_0123(&evals_full, challenge);
                let eq_factor =
                    prev_challenge * challenge + (EF::ONE - prev_challenge) * (EF::ONE - challenge);
                let eq_out = eq * eq_factor;

                rows.push(TowerSumcheckData {
                    proof_idx: record.proof_idx,
                    idx: record.idx,
                    fork_id: record.fork_id,
                    layer_idx: layer_idx_value,
                    is_first_idx: layer_idx == 0 && round_in_layer == 0 && record.is_first_air_idx,
                    is_first_layer: layer_idx == 0 && round_in_layer == 0,
                    is_first_round: round_in_layer == 0,
                    is_last_layer,
                    round: round_in_layer,
                    tidx: record.derive_tidx(layer_idx, round_in_layer),
                    ev1: ef_to_base(evals[0]),
                    ev2: ef_to_base(evals[1]),
                    ev3: ef_to_base(evals[2]),
                    claim_in: ef_to_base(claim),
                    claim_out: ef_to_base(claim_out),
                    prev_challenge: ef_to_base(prev_challenge),
                    challenge: ef_to_base(challenge),
                    eq_in: ef_to_base(eq),
                    eq_out: ef_to_base(eq_out),
                    ..Default::default()
                });

                claim = claim_out;
                eq = eq_out;
                global_round_idx += 1;
            }
        }

        debug_assert_eq!(global_round_idx, total_rounds);
    }

    rows
}

fn ef_to_base(value: EF) -> [F; D_EF] {
    value.as_basis_coefficients_slice().try_into().unwrap()
}
