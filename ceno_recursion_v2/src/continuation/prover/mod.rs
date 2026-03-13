use continuations_v2::{SC, circuit::inner::InnerTraceGenImpl};
use openvm_stark_backend::prover::CpuBackend;

use crate::system::VerifierSubCircuit;

mod inner;
pub use inner::*;

pub type InnerCpuProver<const MAX_NUM_PROOFS: usize> =
    InnerAggregationProver<CpuBackend<SC>, VerifierSubCircuit<MAX_NUM_PROOFS>, InnerTraceGenImpl>;
