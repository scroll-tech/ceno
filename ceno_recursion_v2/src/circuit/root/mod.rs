use std::sync::Arc;

use openvm_stark_backend::{AirRef, StarkProtocolConfig};
use openvm_stark_sdk::config::{
    baby_bear_bn254_poseidon2::BabyBearBn254Poseidon2Config,
    baby_bear_poseidon2::{DIGEST_SIZE, F},
};

use crate::circuit::Circuit;

pub mod prover;
pub mod trace;
pub mod verifier;

pub type RootSC = BabyBearBn254Poseidon2Config;

#[derive(derive_new::new, Clone)]
pub struct CenoRootCircuit<S: recursion_circuit::system::AggregationSubCircuit> {
    pub verifier_circuit: Arc<S>,
    pub child_vk_pre_hash: [F; DIGEST_SIZE],
}

impl<SC: StarkProtocolConfig<F = F>, S: recursion_circuit::system::AggregationSubCircuit>
    Circuit<SC> for CenoRootCircuit<S>
{
    fn airs(&self) -> Vec<AirRef<SC>> {
        let bus_inventory = self.verifier_circuit.bus_inventory();
        let ceno_pvs_air = Arc::new(verifier::CenoRootVerifierPvsAir {
            public_values_bus: bus_inventory.public_values_bus,
            cached_commit_bus: bus_inventory.cached_commit_bus,
            pre_hash_bus: bus_inventory.pre_hash_bus,
            child_vk_pre_hash: self.child_vk_pre_hash,
        }) as AirRef<SC>;

        [ceno_pvs_air]
            .into_iter()
            .chain(self.verifier_circuit.airs())
            .collect()
    }
}

impl<SC: StarkProtocolConfig<F = F>, S: recursion_circuit::system::AggregationSubCircuit>
    continuations_v2::circuit::Circuit<SC> for CenoRootCircuit<S>
{
    fn airs(&self) -> Vec<AirRef<SC>> {
        <Self as Circuit<SC>>::airs(self)
    }
}
