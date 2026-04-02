use std::sync::Arc;

use openvm_stark_backend::{
    AirRef, FiatShamirTranscript, StarkProtocolConfig, TranscriptHistory,
};
use openvm_stark_sdk::config::baby_bear_poseidon2::{BabyBearPoseidon2Config, F};
use p3_field::PrimeCharacteristicRing;

use crate::{
    proof_shape::bus::CommitmentsBus,
    system::{
        AirModule, BusIndexManager, BusInventory, RecursionProof,
        RecursionVk,
    },
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
            ts.observe(F::from_u64(fixed_no_omc.log2_max_codeword_size as u64));
        }
    }

    /// Observe the witness commitment (`witin_commit`) into the Fiat-Shamir transcript.
    /// Called during the verifier-owned trunk preflight.
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

    #[tracing::instrument(level = "trace", skip_all)]
    pub fn run_preflight<TS>(
        &self,
        child_vk: &RecursionVk,
        proof: &RecursionProof,
        _preflight: &mut Preflight,
        ts: &mut TS,
    ) where
        TS: FiatShamirTranscript<BabyBearPoseidon2Config> + TranscriptHistory,
    {
        // Verifier-only trunk phase observations.
        self.observe_fixed_commits(child_vk, ts);
        self.observe_witness_commit(proof, ts);
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
