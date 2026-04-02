use openvm_stark_backend::{FiatShamirTranscript, TranscriptHistory};
use openvm_stark_sdk::config::baby_bear_poseidon2::BabyBearPoseidon2Config;

use crate::system::{Preflight, RecursionProof, RecursionVk};

mod air;
mod trace;

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
    // Reserved verifier-owned preflight step. VmPvs currently owns transcript observations.
    let _ = (child_vk, proof, ts);
}
