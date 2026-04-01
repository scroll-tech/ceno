use std::sync::Arc;

use openvm_cpu_backend::CpuBackend;
use openvm_stark_backend::{
    AirRef, FiatShamirTranscript, StarkProtocolConfig, TranscriptHistory,
    prover::AirProvingContext,
};
use openvm_stark_sdk::config::baby_bear_poseidon2::{BabyBearPoseidon2Config, F};
use p3_field::PrimeCharacteristicRing;

use crate::{
    proof_shape::bus::CommitmentsBus,
    system::{
        AirModule, BusIndexManager, BusInventory, GlobalCtxCpu, Preflight, RecursionProof,
        RecursionVk, TraceGenModule,
    },
    tracegen::RowMajorChip,
};

mod air;
mod trace;

pub use air::*;
pub use trace::*;

/// Circuit-level module for commitment observations.
///
/// Fixed commitments (`fixed_commit`, `fixed_no_omc_init_commit`) and the witness
/// commitment (`witin_commit`) should each be observed exactly once per proof.
/// This module owns that logic, keeping it separate from the per-AIR proof-shape
/// metadata handled by [`ProofShapeModule`].
pub struct VerifierModule {
    bus_inventory: BusInventory,
    commitments_tidx_bus: CommitmentsBus,
}

impl VerifierModule {
    pub fn new(b: &mut BusIndexManager, bus_inventory: BusInventory) -> Self {
        Self {
            bus_inventory,
            commitments_tidx_bus: CommitmentsBus::new(b.new_bus_idx()),
        }
    }

    /// Observe fixed commitments (`fixed_commit`, `fixed_no_omc_init_commit`) into the
    /// Fiat-Shamir transcript. Called during the trunk phase, before per-AIR shape
    /// observations.
    pub fn observe_fixed_commits<TS>(&self, child_vk: &RecursionVk, ts: &mut TS)
    where
        TS: FiatShamirTranscript<BabyBearPoseidon2Config> + TranscriptHistory,
    {
        if let Some(fixed_commit) = child_vk.fixed_commit.as_ref() {
            for elem in fixed_commit.commit.clone().into_iter() {
                ts.observe(elem);
            }
            ts.observe(F::from_u64(fixed_commit.log2_max_codeword_size as u64));
        }
        if let Some(fixed_no_omc) = child_vk.fixed_no_omc_init_commit.as_ref() {
            for elem in fixed_no_omc.commit.clone().into_iter() {
                ts.observe(elem);
            }
            ts.observe(F::from_u64(
                fixed_no_omc.log2_max_codeword_size as u64,
            ));
        }
    }

    /// Observe the witness commitment (`witin_commit`) into the Fiat-Shamir transcript.
    /// Called during the trunk phase, after per-AIR shape and chip-index observations,
    /// before alpha/beta sampling.
    pub fn observe_witness_commit<TS>(&self, proof: &RecursionProof, ts: &mut TS)
    where
        TS: FiatShamirTranscript<BabyBearPoseidon2Config> + TranscriptHistory,
    {
        let witin = &proof.witin_commit;
        for elem in witin.commit.clone().into_iter() {
            ts.observe(elem);
        }
        ts.observe(F::from_u64(witin.log2_max_codeword_size as u64));
    }
}

impl AirModule for VerifierModule {
    fn num_airs(&self) -> usize {
        1
    }

    fn airs<SC: StarkProtocolConfig<F = F>>(&self) -> Vec<AirRef<SC>> {
        let commit_air = CommitAir {
            commitments_bus: self.commitments_tidx_bus,
            transcript_bus: self.bus_inventory.transcript_bus,
        };
        vec![Arc::new(commit_air) as AirRef<_>]
    }
}

impl<SC: StarkProtocolConfig<F = F>> TraceGenModule<GlobalCtxCpu, CpuBackend<SC>>
    for VerifierModule
{
    type ModuleSpecificCtx<'a> = ();

    #[tracing::instrument(skip_all)]
    fn generate_proving_ctxs(
        &self,
        _child_vk: &RecursionVk,
        proofs: &[RecursionProof],
        preflights: &[Preflight],
        _ctx: &(),
        required_heights: Option<&[usize]>,
    ) -> Option<Vec<AirProvingContext<CpuBackend<SC>>>> {
        let commit_ctx: (&[RecursionProof], &[Preflight]) = (proofs, preflights);
        let height = required_heights.and_then(|h| h.first().copied());
        let trace = CommitTraceGenerator.generate_trace(&commit_ctx, height)?;
        Some(vec![AirProvingContext::simple_no_pis(trace)])
    }
}

#[cfg(feature = "cuda")]
mod cuda_tracegen {
    use openvm_cuda_backend::{GpuBackend, base::DeviceMatrix};

    use super::*;
    use crate::cuda::{
        GlobalCtxGpu, preflight::PreflightGpu, proof::ProofGpu, vk::VerifyingKeyGpu,
    };

    impl TraceGenModule<GlobalCtxGpu, GpuBackend> for VerifierModule {
        type ModuleSpecificCtx<'a> = ();

        #[tracing::instrument(skip_all)]
        fn generate_proving_ctxs(
            &self,
            _child_vk: &VerifyingKeyGpu,
            _proofs: &[ProofGpu],
            _preflights: &[PreflightGpu],
            _ctx: &(),
            required_heights: Option<&[usize]>,
        ) -> Option<Vec<AirProvingContext<GpuBackend>>> {
            let width = CommitAirCols::<u8>::width();
            let height = required_heights
                .and_then(|h| h.first().copied())
                .unwrap_or(1)
                .max(1);
            let trace = DeviceMatrix::with_capacity(height, width);
            Some(vec![AirProvingContext::simple_no_pis(trace)])
        }
    }
}
