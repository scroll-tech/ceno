use std::sync::Arc;
use crate::zkvm_verifier::binding::{ZKVMProofInput, E, F};
use crate::zkvm_verifier::verifier::verify_zkvm_proof;
use ceno_zkvm::scheme::ZKVMProof;
use ceno_zkvm::structs::ZKVMVerifyingKey;
use mpcs::{Basefold, BasefoldRSParams};
use openvm_circuit::arch::VirtualMachine;
use openvm_circuit::arch::VmConfig;
use openvm_circuit::{
    arch::{instructions::program::Program, SystemConfig, instructions::exe::VmExe},
    system::memory::tree::public_values::PUBLIC_VALUES_ADDRESS_SPACE_OFFSET,
};
use openvm_continuations::verifier::{
    internal::types::VmStarkProof, root::types::RootVmVerifierInput,
};
use openvm_continuations::C;
use openvm_native_circuit::NativeConfig;
use openvm_native_compiler::{asm::AsmBuilder, conversion::{convert_program, CompilerOptions}, prelude::*};
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
use serde::{Deserialize, Serialize};
use openvm_stark_sdk::{
    config::FriParameters, engine::StarkFriEngine,
    config::baby_bear_poseidon2::BabyBearPoseidon2Engine,
    config::baby_bear_poseidon2_root::BabyBearPoseidon2RootEngine,
    openvm_stark_backend::{
        config::{Com, StarkGenericConfig},
        keygen::types::MultiStarkVerifyingKey,
    },
    p3_bn254_fr::Bn254Fr,
};
use openvm_sdk::Sdk;
use std::io::Write;
use std::time::Instant;
use std::fs::File;
use openvm_circuit::system::program::trace::VmCommittedExe;
use openvm_circuit::{
    arch::{
        ExecutionBridge, InitFileGenerator, MemoryConfig, SystemPort, VmExtension, VmInventory,
        VmInventoryBuilder, VmInventoryError,
    },
    system::phantom::PhantomChip,
};
use openvm_circuit::arch::verify_single;
use openvm_continuations::verifier::common::types::VmVerifierPvs;
use openvm_continuations::verifier::internal::types::InternalVmVerifierInput;
use openvm_continuations::verifier::internal::types::InternalVmVerifierPvs;
use openvm_continuations::verifier::internal::InternalVmVerifierConfig;
pub type RecPcs = Basefold<E, BasefoldRSParams>;

const LEAF_LOG_BLOWUP: usize = 1;
const INTERNAL_LOG_BLOWUP: usize = 2;
const ROOT_LOG_BLOWUP: usize = 3;
const SBOX_SIZE: usize = 7;

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

pub fn compress_to_root_proof(
    zkvm_proofs: Vec<ZKVMProof<E, RecPcs>>,
    vk: ZKVMVerifyingKey<E, Basefold<E, BasefoldRSParams>>,
) {
    // Construct zkvm proof input
    let zkvm_proof_inputs: Vec<ZKVMProofInput> = zkvm_proofs.into_iter().map(|p| ZKVMProofInput::from(p)).collect();

    let aggregation_start_timestamp = Instant::now();
    let sdk = Sdk::new();

    let [leaf_fri_params, internal_fri_params, root_fri_params] =
        [LEAF_LOG_BLOWUP, INTERNAL_LOG_BLOWUP, ROOT_LOG_BLOWUP]
            .map(FriParameters::standard_with_100_bits_conjectured_security);

    let leaf_vm_config = NativeConfig {
        system: SystemConfig::new(
            SBOX_SIZE.min(leaf_fri_params.max_constraint_degree()),
            MemoryConfig {
                max_access_adapter_n: 16,
                ..Default::default()
            },
            VmVerifierPvs::<u8>::width(),
        )
        .with_max_segment_len((1 << 24) - 100),
        native: Default::default(),
    };

    let leaf_committed_exe = {
        let leaf_engine = BabyBearPoseidon2Engine::new(leaf_fri_params);
        let leaf_program = CenoLeafVmVerifierConfig {
            vk,
            compiler_options: CompilerOptions::default(),
        }
        .build_program();

        Arc::new(VmCommittedExe::commit(
            leaf_program.into(),
            leaf_engine.config.pcs(),
        ))
    };

    let recursion_proving_keys = RecursionProvingKeys::keygen(leaf_fri_params, leaf_vm_config);
    let leaf_prover = VmLocalProver::<SC, NativeConfig, BabyBearPoseidon2Engine>::new(
        recursion_proving_keys.ceno_leaf_vm_pk.clone(),
        leaf_committed_exe,
    );

    let leaf_proofs = zkvm_proof_inputs.into_iter().enumerate().map(|(proof_idx, p)| {
        println!(
            "Aggregation - Start leaf proof (idx: {:?}) at: {:?}",
            proof_idx,
            aggregation_start_timestamp.elapsed()
        );
        let mut witness_stream: Vec<Vec<F>> = Vec::new();
        witness_stream.extend(p.write());
        let leaf_proof = SingleSegmentVmProver::prove(&leaf_prover, witness_stream);

        // _debug: export leaf proof
        let mut file =
            File::create(format!("leaf_proof_{:?}.bin", proof_idx)).expect("Create export proof file");
        bincode::serialize_into(file, &leaf_proof).expect("failed to serialize leaf proof");

        println!(
            "Aggregation - Completed leaf proof (idx: {:?}) at: {:?}",
            proof_idx,
            aggregation_start_timestamp.elapsed()
        );

        leaf_proof
    }).collect::<Vec<_>>();

    // Internal engine and config
    let internal_engine = BabyBearPoseidon2Engine::new(internal_fri_params);
    let internal_vm_config = NativeConfig {
        system: SystemConfig::new(
            SBOX_SIZE.min(internal_fri_params.max_constraint_degree()),
            MemoryConfig {
                max_access_adapter_n: 8,
                ..Default::default()
            },
            InternalVmVerifierPvs::<u8>::width(),
        )
        .with_max_segment_len((1 << 24) - 100),
        native: Default::default(),
    };

    // Construct internal vm, pk and vk
    let internal_vm = VirtualMachine::new(internal_engine, internal_vm_config.clone());
    let internal_vm_pk = Arc::new({
        let vm_pk = internal_vm.keygen();
        assert!(vm_pk.max_constraint_degree <= internal_fri_params.max_constraint_degree());
        VmProvingKey {
            fri_params: internal_fri_params,
            vm_config: internal_vm_config,
            vm_pk,
        }
    });
    let internal_vm_vk = internal_vm_pk.vm_pk.get_vk();

    // Commit internal program
    let internal_program = InternalVmVerifierConfig {
        leaf_fri_params: leaf_fri_params,
        internal_fri_params: internal_fri_params,
        compiler_options: CompilerOptions::default(),
    }
    .build_program(
        &recursion_proving_keys.ceno_leaf_vm_pk.vm_pk.get_vk(),
        &internal_vm_vk,
    );
    let internal_committed_exe = Arc::new(VmCommittedExe::<SC>::commit(
        internal_program.into(),
        internal_vm.engine.config.pcs(),
    ));
    let internal_prover = VmLocalProver::<SC, NativeConfig, BabyBearPoseidon2Engine>::new(
        internal_vm_pk,
        internal_committed_exe,
    );

    // Aggregate tree to root proof
    let mut internal_node_idx = -1;
    let mut internal_node_height = 0;
    let mut proofs = leaf_proofs;

    println!(
        "Aggregation - Start internal aggregation at: {:?}",
        aggregation_start_timestamp.elapsed()
    );
    // We will always generate at least one internal proof, even if there is only one leaf
    // proof, in order to shrink the proof size
    while proofs.len() > 1 || internal_node_height == 0 {
        let internal_inputs = InternalVmVerifierInput::chunk_leaf_or_internal_proofs(
            internal_prover.committed_exe.get_program_commit().into(),
            &proofs,
            3, // _debug
        );
        proofs = internal_inputs
            .into_iter()
            .map(|input| {
                internal_node_idx += 1;
                let internal_proof =
                    SingleSegmentVmProver::prove(&internal_prover, input.write());
                println!("Aggregation - Completed internal node (idx: {:?}) at height {:?}: {:?}", internal_node_idx, internal_node_height, aggregation_start_timestamp.elapsed());

                // _debug: export
                let mut file = File::create(format!(
                    "internal_proof_{:?}_height_{:?}.bin",
                    internal_node_idx, internal_node_height
                ))
                .expect("Create export proof file");
                bincode::serialize_into(file, &internal_proof).expect("failed to serialize internal proof");

                internal_proof
            })
            .collect();
        internal_node_height += 1;
    }
    println!(
        "Aggregation - Completed internal aggregation at: {:?}",
        aggregation_start_timestamp.elapsed()
    );
    println!("Aggregation - Final height: {:?}", internal_node_height);
    
    /* _debug: aggregation
    let root_stark_proof = VmStarkProof {
        proof: proofs.pop().unwrap(),
        user_public_values: public_values,
    };
    */
}

/// Build Ceno's zkVM verifier program from vk in OpenVM's eDSL
pub fn build_zkvm_verifier_program(
    vk: &ZKVMVerifyingKey<E, Basefold<E, BasefoldRSParams>>,
) -> Program<F> {
    let mut builder = AsmBuilder::<F, E>::default();

    let zkvm_proof_input_variables = ZKVMProofInput::read(&mut builder);
    verify_zkvm_proof(&mut builder, zkvm_proof_input_variables, vk);
    builder.halt();

    // Compile program
    #[cfg(feature = "bench-metrics")]
    let options = CompilerOptions::default().with_cycle_tracker();
    #[cfg(not(feature = "bench-metrics"))]
    let options = CompilerOptions::default();
    let mut compiler = AsmCompiler::new(options.word_size);
    compiler.build(builder.operations);
    let asm_code = compiler.code();

    let program: Program<F> = convert_program(asm_code, options);
    program
}

pub fn verify_proofs(
    zkvm_proofs: Vec<ZKVMProof<E, RecPcs>>,
    vk: ZKVMVerifyingKey<E, Basefold<E, BasefoldRSParams>>,
) {
    let program = build_zkvm_verifier_program(&vk);
    if zkvm_proofs.len() > 0 {
        let zkvm_proof_input = ZKVMProofInput::from(zkvm_proofs[0].clone());

        // Pass in witness stream
        let mut witness_stream: Vec<Vec<F>> = Vec::new();
        witness_stream.extend(zkvm_proof_input.write());

        let log_blowup = 1;
        let poseidon2_max_constraint_degree: usize = 3;
        let fri_params = FriParameters::standard_with_100_bits_conjectured_security(log_blowup);

        let engine = BabyBearPoseidon2Engine::new(fri_params);
        let mut config = NativeConfig::aggregation(0, poseidon2_max_constraint_degree);
        config.system.memory_config.max_access_adapter_n = 16;

        let vm = VirtualMachine::new(engine, config);

        let pk = vm.keygen();
        let result = vm.execute_and_generate(program, witness_stream).unwrap();
        let proofs = vm.prove(&pk, result);
        for proof in proofs {
            verify_single(&vm.engine, &pk.get_vk(), &proof).expect("Verification failed");
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::aggregation::{compress_to_root_proof, verify_proofs};
    use crate::{
        aggregation::{CenoLeafVmVerifierConfig, RecursionProvingKeys},
        zkvm_verifier::binding::{E, F},
    };
    use ceno_zkvm::scheme::ZKVMProof;
    use ceno_zkvm::structs::ZKVMVerifyingKey;
    use mpcs::{Basefold, BasefoldRSParams};
    use std::fs::File;
    use openvm_stark_sdk::config::setup_tracing_with_log_level;

    pub fn aggregation_inner_thread() {
        setup_tracing_with_log_level(tracing::Level::WARN);

        let proof_path = "./src/imported/proof.bin";
        let vk_path = "./src/imported/vk.bin";

        let zkvm_proofs: Vec<ZKVMProof<E, Basefold<E, BasefoldRSParams>>> =
            bincode::deserialize_from(File::open(proof_path).expect("Failed to open proof file"))
                .expect("Failed to deserialize proof file");

        let vk: ZKVMVerifyingKey<E, Basefold<E, BasefoldRSParams>> =
            bincode::deserialize_from(File::open(vk_path).expect("Failed to open vk file"))
                .expect("Failed to deserialize vk file");

        compress_to_root_proof(zkvm_proofs, vk);
    }

    pub fn verify_single_inner_thread() {
        setup_tracing_with_log_level(tracing::Level::WARN);

        let proof_path = "./src/imported/proof.bin";
        let vk_path = "./src/imported/vk.bin";

        let zkvm_proofs: Vec<ZKVMProof<E, Basefold<E, BasefoldRSParams>>> =
            bincode::deserialize_from(File::open(proof_path).expect("Failed to open proof file"))
                .expect("Failed to deserialize proof file");

        let vk: ZKVMVerifyingKey<E, Basefold<E, BasefoldRSParams>> =
            bincode::deserialize_from(File::open(vk_path).expect("Failed to open vk file"))
                .expect("Failed to deserialize vk file");

        verify_proofs(zkvm_proofs, vk);
    }

    #[test]
    pub fn test_aggregation() {
        let stack_size = 256 * 1024 * 1024; // 64 MB

        let handler = std::thread::Builder::new()
            .stack_size(stack_size)
            .spawn(aggregation_inner_thread)
            .expect("Failed to spawn thread");

        handler.join().expect("Thread panicked");
    }

    #[test]
    pub fn test_single() {
        let stack_size = 256 * 1024 * 1024; // 64 MB

        let handler = std::thread::Builder::new()
            .stack_size(stack_size)
            .spawn(verify_single_inner_thread)
            .expect("Failed to spawn thread");

        handler.join().expect("Thread panicked");
    }
}
