use std::sync::Arc;

use openvm_stark_backend::{AirRef, StarkProtocolConfig};
use recursion_circuit::prelude::F;
use verify_stark::pvs::{DEF_PVS_AIR_ID, DeferralPvs, VM_PVS_AIR_ID, VmPvs};

use crate::{
    bn254::CommitBytes,
    circuit::{Circuit, inner::bus::PvsAirConsistencyBus},
    system::AggregationSubCircuit,
};

pub mod app {
    pub use openvm_circuit::arch::{
        CONNECTOR_AIR_ID, MERKLE_AIR_ID, PROGRAM_AIR_ID, PROGRAM_CACHED_TRACE_INDEX,
    };
}

pub mod bus;
pub mod def_pvs;
pub mod unset;
pub mod verifier;
pub mod vm_pvs;

mod trace;
pub use trace::*;

#[derive(derive_new::new, Clone)]
pub struct InnerCircuit<S: AggregationSubCircuit> {
    pub verifier_circuit: Arc<S>,
    pub def_hook_commit: Option<CommitBytes>,
}

impl<SC: StarkProtocolConfig<F = F>, S: AggregationSubCircuit> Circuit<SC> for InnerCircuit<S> {
    fn airs(&self) -> Vec<AirRef<SC>> {
        let bus_inventory = self.verifier_circuit.bus_inventory();
        let public_values_bus = bus_inventory.public_values_bus;
        let cached_commit_bus = bus_inventory.cached_commit_bus;
        let poseidon2_compress_bus = bus_inventory.poseidon2_compress_bus;
        let pvs_air_consistency_bus =
            PvsAirConsistencyBus::new(self.verifier_circuit.next_bus_idx());

        let deferral_enabled = self.def_hook_commit.is_some();

        let deferral_config = if deferral_enabled {
            verifier::VerifierDeferralConfig::Enabled {
                poseidon2_bus: poseidon2_compress_bus,
            }
        } else {
            verifier::VerifierDeferralConfig::Disabled
        };

        let verifier_pvs_air = Arc::new(verifier::VerifierPvsAir {
            public_values_bus,
            // cached_commit_bus,
            pvs_air_consistency_bus,
            deferral_config,
        }) as AirRef<SC>;

        let vm_pvs_air = Arc::new(vm_pvs::VmPvsAir {
            public_values_bus,
            cached_commit_bus,
            pvs_air_consistency_bus,
            deferral_enabled,
        }) as AirRef<SC>;

        let (idx2_air, post_airs): (AirRef<SC>, Vec<AirRef<SC>>) = if deferral_enabled {
            let def_pvs_air = Arc::new(def_pvs::DeferralPvsAir {
                public_values_bus,
                cached_commit_bus,
                poseidon2_bus: poseidon2_compress_bus,
                pvs_air_consistency_bus,
                expected_def_hook_commit: self
                    .def_hook_commit
                    .expect("def_hook_commit must be set when deferral is enabled"),
            }) as AirRef<SC>;
            let unset_vm_pvs_air = Arc::new(unset::UnsetPvsAir {
                public_values_bus,
                pvs_air_consistency_bus,
                air_idx: VM_PVS_AIR_ID,
                num_pvs: VmPvs::<u8>::width(),
                def_flag: 1,
            }) as AirRef<SC>;
            let unset_def_pvs_air = Arc::new(unset::UnsetPvsAir {
                public_values_bus,
                pvs_air_consistency_bus,
                air_idx: DEF_PVS_AIR_ID,
                num_pvs: DeferralPvs::<u8>::width(),
                def_flag: 0,
            }) as AirRef<SC>;
            (def_pvs_air, vec![unset_vm_pvs_air, unset_def_pvs_air])
        } else {
            let unset_dummy_air = Arc::new(unset::UnsetPvsAir {
                public_values_bus,
                pvs_air_consistency_bus,
                air_idx: 0,
                num_pvs: 0,
                def_flag: 0,
            }) as AirRef<SC>;
            (unset_dummy_air, vec![])
        };

        [verifier_pvs_air, vm_pvs_air, idx2_air]
            .into_iter()
            .chain(self.verifier_circuit.airs())
            .chain(post_airs)
            .collect()
    }
}

impl<SC: StarkProtocolConfig<F = F>, S: AggregationSubCircuit>
    continuations_v2::circuit::Circuit<SC> for InnerCircuit<S>
{
    fn airs(&self) -> Vec<AirRef<SC>> {
        <Self as Circuit<SC>>::airs(self)
    }
}
