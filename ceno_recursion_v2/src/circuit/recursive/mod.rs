use std::sync::Arc;

use openvm_stark_backend::{AirRef, StarkProtocolConfig};
use openvm_stark_sdk::config::baby_bear_poseidon2::F;
use recursion_circuit::system::AggregationSubCircuit;
use verify_stark::pvs::VkCommit;

use crate::circuit::Circuit;

pub mod prover;
pub mod trace;
pub mod verifier;
pub mod vm_pvs;

#[derive(derive_new::new, Clone)]
pub struct CenoRecursiveCircuit<S: AggregationSubCircuit> {
    pub verifier_circuit: Arc<S>,
    pub child_vk_commit: VkCommit<F>,
    pub child_constraint_eval_air_id: usize,
    pub bridge_child_cached_commit: bool,
}

impl<SC: StarkProtocolConfig<F = F>, S: AggregationSubCircuit> Circuit<SC>
    for CenoRecursiveCircuit<S>
{
    fn airs(&self) -> Vec<AirRef<SC>> {
        let bus_inventory = self.verifier_circuit.bus_inventory();
        let verifier_pvs_air = Arc::new(verifier::CenoRecursiveVerifierPvsAir {
            public_values_bus: bus_inventory.public_values_bus,
            cached_commit_bus: bus_inventory.cached_commit_bus,
            pre_hash_bus: bus_inventory.pre_hash_bus,
            child_vk_commit: self.child_vk_commit,
            child_constraint_eval_air_id: self.child_constraint_eval_air_id,
            bridge_child_cached_commit: self.bridge_child_cached_commit,
        }) as AirRef<SC>;
        let vm_pvs_air = Arc::new(vm_pvs::CenoRecursiveVmPvsAir {
            public_values_bus: bus_inventory.public_values_bus,
        }) as AirRef<SC>;

        [verifier_pvs_air, vm_pvs_air]
            .into_iter()
            .chain(self.verifier_circuit.airs())
            .collect()
    }
}

impl<SC: StarkProtocolConfig<F = F>, S: AggregationSubCircuit>
    continuations_v2::circuit::Circuit<SC> for CenoRecursiveCircuit<S>
{
    fn airs(&self) -> Vec<AirRef<SC>> {
        <Self as Circuit<SC>>::airs(self)
    }
}
