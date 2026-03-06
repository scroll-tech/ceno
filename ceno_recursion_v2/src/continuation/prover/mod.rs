use continuations_v2::{
    RootSC, SC,
    circuit::{inner::InnerTraceGenImpl, root::RootTraceGenImpl},
    prover::{CompressionProver, InnerAggregationProver, RootProver},
};
use openvm_stark_backend::prover::CpuBackend;

use crate::system::VerifierSubCircuit;

pub type InnerCpuProver<const MAX_NUM_PROOFS: usize> =
    InnerAggregationProver<CpuBackend<SC>, VerifierSubCircuit<MAX_NUM_PROOFS>, InnerTraceGenImpl>;
pub type CompressionCpuProver =
    CompressionProver<CpuBackend<SC>, VerifierSubCircuit<1>, InnerTraceGenImpl>;
pub type RootCpuProver = RootProver<CpuBackend<RootSC>, VerifierSubCircuit<1>, RootTraceGenImpl>;
