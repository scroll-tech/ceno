use openvm_stark_backend::{FiatShamirTranscript, TranscriptHistory};
use openvm_stark_sdk::config::baby_bear_poseidon2::{BabyBearPoseidon2Config, DIGEST_SIZE, F};
use p3_field::PrimeCharacteristicRing;
use stark_recursion_circuit_derive::AlignedBorrow;

use crate::system::{Preflight, RecursionField, RecursionProof, RecursionVk};

mod air;
mod trace;

pub const SEPTIC_EXTENSION_DEGREE: usize = 7;

#[repr(C)]
#[derive(AlignedBorrow, Clone, Copy, Debug)]
pub struct VmPvs<F> {
    pub fixed_commit: [F; DIGEST_SIZE],
    pub fixed_no_omc_init_commit: [F; DIGEST_SIZE],
    pub witness_commit: [F; DIGEST_SIZE],

    // Ordered to match ceno_zkvm::scheme::PublicValues.
    pub exit_code: [F; 2],
    pub init_pc: F,
    pub init_cycle: F,
    pub end_pc: F,
    pub end_cycle: F,
    pub shard_id: F,
    pub heap_start_addr: F,
    pub heap_shard_len: F,
    pub hint_start_addr: F,
    pub hint_shard_len: F,
    pub public_io: [F; 2],
    pub shard_rw_sum: [F; 2 * SEPTIC_EXTENSION_DEGREE],
}

pub use air::*;
pub use trace::*;

#[tracing::instrument(level = "trace", skip_all)]
pub fn run_preflight<TS>(
    child_vk: &RecursionVk,
    proof: &RecursionProof,
    _preflight: &mut Preflight,
    ts: &mut TS,
) where
    TS: FiatShamirTranscript<BabyBearPoseidon2Config> + TranscriptHistory,
{
    // Observe public values in canonical circuit-instance order first.
    for (_, circuit_vk) in child_vk.circuit_vks.iter() {
        for instance_value in circuit_vk.get_cs().zkvm_v1_css.instance.iter() {
            ts.observe(
                proof
                    .public_values
                    .query_by_index::<RecursionField>(instance_value.0),
            );
        }
    }

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

    let witin = &proof.witin_commit;
    for elem in witin.commit.clone().into_iter() {
        ts.observe(elem);
    }
    ts.observe(F::from_u64(witin.log2_max_codeword_size as u64));
}
