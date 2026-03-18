use continuations_v2::SC;
use openvm_cpu_backend::CpuBackend;

use crate::{circuit::inner::InnerTraceGenImpl, system::VerifierSubCircuit};

mod inner;

pub use inner::*;

pub type InnerCpuProver<const MAX_NUM_PROOFS: usize> =
    InnerAggregationProver<CpuBackend<SC>, VerifierSubCircuit<MAX_NUM_PROOFS>, InnerTraceGenImpl>;
