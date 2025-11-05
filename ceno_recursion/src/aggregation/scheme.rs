use std::sync::Arc;

use crate::zkvm_verifier::binding::{ZKVMProofInput, E, F};
use crate::zkvm_verifier::verifier::verify_zkvm_proof;
use ceno_zkvm::structs::ZKVMVerifyingKey;
use mpcs::{Basefold, BasefoldRSParams};
use openvm_circuit::arch::VirtualMachine;
use openvm_circuit::arch::VmConfig;
use openvm_circuit::{
    arch::{instructions::program::Program, SystemConfig},
    system::memory::tree::public_values::PUBLIC_VALUES_ADDRESS_SPACE_OFFSET,
};
use openvm_continuations::verifier::{
    internal::types::VmStarkProof, root::types::RootVmVerifierInput,
};
use openvm_continuations::C;
use openvm_native_circuit::NativeConfig;
use openvm_native_compiler::{conversion::CompilerOptions, prelude::*};
use openvm_native_recursion::hints::Hintable;
use openvm_sdk::prover::vm::types::VmProvingKey;
use openvm_sdk::{
    config::AggregationTreeConfig,
    keygen::AggStarkProvingKey,
    prover::{
        vm::{local::VmLocalProver, SingleSegmentVmProver},
        RootVerifierLocalProver,
    },
    NonRootCommittedExe, RootSC, SC,
};
use openvm_stark_backend::{proof::Proof, Chip};
use openvm_stark_sdk::config::baby_bear_poseidon2::BabyBearPoseidon2Engine;
use openvm_stark_sdk::{config::FriParameters, engine::StarkFriEngine};
use serde::{Deserialize, Serialize};

/// Config to generate leaf VM verifier program.
pub struct CenoLeafVmVerifierConfig {
    pub vk: ZKVMVerifyingKey<E, Basefold<E, BasefoldRSParams>>,
    pub compiler_options: CompilerOptions,
}

impl CenoLeafVmVerifierConfig {
    pub fn build_program(&self) -> Program<F> {
        let mut builder = Builder::<C>::default();

        {
            builder.cycle_tracker_start("VerifyCenoProof");

            let zkvm_proof_input_variables = ZKVMProofInput::read(&mut builder);
            verify_zkvm_proof(&mut builder, zkvm_proof_input_variables, &self.vk);

            builder.cycle_tracker_end("VerifyCenoProof");
            builder.halt();
        }

        builder.compile_isa_with_options(self.compiler_options)
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct RecursionProvingKeys {
    pub ceno_leaf_vm_pk: Arc<VmProvingKey<SC, NativeConfig>>,
    // pub internal_vm_pk: Arc<VmProvingKey<SC, NativeConfig>>,
    // pub internal_committed_exe: Arc<NonRootCommittedExe>,
    // pub root_verifier_pk: RootVerifierProvingKey,
}

impl RecursionProvingKeys {
    pub fn keygen(leaf_fri_params: FriParameters, leaf_vm_config: NativeConfig) -> Self {
        // let internal_vm_config = config.internal_vm_config();
        // let root_vm_config = config.root_verifier_vm_config();

        let ceno_leaf_engine = BabyBearPoseidon2Engine::new(leaf_fri_params);
        let ceno_leaf_vm_pk = Arc::new({
            let vm = VirtualMachine::new(ceno_leaf_engine, leaf_vm_config.clone());
            let vm_pk = vm.keygen();
            assert!(vm_pk.max_constraint_degree <= leaf_fri_params.max_constraint_degree());
            VmProvingKey {
                fri_params: leaf_fri_params,
                vm_config: leaf_vm_config,
                vm_pk,
            }
        });

        Self { ceno_leaf_vm_pk }
    }
}
