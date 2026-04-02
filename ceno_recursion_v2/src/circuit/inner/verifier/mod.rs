use std::sync::Arc;

use openvm_stark_backend::{
    AirRef, FiatShamirTranscript, StarkProtocolConfig, TranscriptHistory,
};
use openvm_stark_sdk::config::baby_bear_poseidon2::{BabyBearPoseidon2Config, F};

use crate::{
    proof_shape::bus::CommitmentsBus,
    system::{
        AirModule, BusIndexManager, BusInventory, Preflight, RecursionProof,
        RecursionVk,
    },
};

mod air;
mod trace;

pub use air::*;
pub use trace::*;

/// Circuit-level module for commitment-trace constraints.
///
/// Preflight transcript commitment observations are now emitted by vm_pvs so the
/// system can keep explicit module ordering.
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

    #[tracing::instrument(level = "trace", skip_all)]
    pub fn run_preflight<TS>(
        &self,
        _child_vk: &RecursionVk,
        _proof: &RecursionProof,
        _preflight: &mut Preflight,
        _ts: &mut TS,
    ) where
        TS: FiatShamirTranscript<BabyBearPoseidon2Config> + TranscriptHistory,
    {
        // Intentionally a no-op: vm_pvs now owns transcript commitment observations.
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
