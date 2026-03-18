use std::sync::Arc;

use openvm_stark_backend::{AirRef, StarkProtocolConfig};
use recursion_circuit::{prelude::F, system::AggregationSubCircuit};

use crate::{bn254::CommitBytes, circuit::Circuit};

pub mod app {
    pub use openvm_circuit::arch::{
        CONNECTOR_AIR_ID, MERKLE_AIR_ID, PROGRAM_AIR_ID, PROGRAM_CACHED_TRACE_INDEX,
    };
}

mod trace;
pub use trace::*;

#[derive(derive_new::new, Clone)]
pub struct InnerCircuit<S: AggregationSubCircuit> {
    pub verifier_circuit: Arc<S>,
    pub def_hook_commit: Option<CommitBytes>,
}

impl<SC: StarkProtocolConfig<F = F>, S: AggregationSubCircuit> Circuit<SC> for InnerCircuit<S> {
    fn airs(&self) -> Vec<AirRef<SC>> {
        // Local fork scaffold: keep verifier AIRs active while inner-specific AIRs are
        // progressively adapted to RecursionProof inputs.
        self.verifier_circuit.airs()
    }
}

impl<SC: StarkProtocolConfig<F = F>, S: AggregationSubCircuit> continuations_v2::circuit::Circuit<SC>
    for InnerCircuit<S>
{
    fn airs(&self) -> Vec<AirRef<SC>> {
        <Self as Circuit<SC>>::airs(self)
    }
}
