use openvm_stark_sdk::config::baby_bear_poseidon2::DIGEST_SIZE;
use stark_recursion_circuit_derive::AlignedBorrow;

mod air;
mod trace;

pub const SEPTIC_EXTENSION_DEGREE: usize = 7;

#[repr(C)]
#[derive(AlignedBorrow, Clone, Copy, Debug)]
pub struct VmPvs<F> {
    pub fixed_commit: [F; DIGEST_SIZE],
    pub fixed_no_omc_init_commit: [F; DIGEST_SIZE],

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
