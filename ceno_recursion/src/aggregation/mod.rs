use std::fmt::Error;
use std::sync::Arc;
use crate::zkvm_verifier::binding::{ZKVMProofInput, E, F};
use crate::zkvm_verifier::verifier::verify_zkvm_proof;
use ceno_zkvm::scheme::ZKVMProof;
use ceno_zkvm::structs::ZKVMVerifyingKey;
use mpcs::{Basefold, BasefoldRSParams};
use openvm_circuit::arch::{VirtualMachine, VmComplexTraceHeights};
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
use openvm_sdk::config::AggStarkConfig;
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
use p3::field::FieldAlgebra;
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
use openvm_stark_backend::engine::StarkEngine;
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
use std::borrow::Borrow;
use openvm_sdk::keygen::perm::AirIdPermutation;
use openvm_circuit::arch::verify_single;
use openvm_continuations::verifier::common::types::VmVerifierPvs;
use openvm_continuations::verifier::internal::types::InternalVmVerifierInput;
use openvm_continuations::verifier::internal::types::InternalVmVerifierPvs;
use openvm_continuations::verifier::internal::InternalVmVerifierConfig;
use openvm_sdk::keygen::RootVerifierProvingKey;
use openvm_sdk::commit::AppExecutionCommit;
pub type RecPcs = Basefold<E, BasefoldRSParams>;
use openvm_circuit::{
    arch::{
        hasher::{poseidon2::vm_poseidon2_hasher, Hasher},
        CONNECTOR_AIR_ID, PROGRAM_AIR_ID,
        PROGRAM_CACHED_TRACE_INDEX, PUBLIC_VALUES_AIR_ID,
    },
    system::{
        memory::CHUNK,
        program::trace::compute_exe_commit,
    },
};

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
pub struct CenoRecursionVerifierKeys {
    pub ceno_leaf_vm_vk: MultiStarkVerifyingKey<SC>,
    pub ceno_leaf_fri_params: FriParameters,
    pub internal_vm_vk: MultiStarkVerifyingKey<SC>,
    pub ceno_internal_fri_params: FriParameters,
    pub internal_commit: [F; CHUNK],
}

pub fn compress_to_root_proof(
    zkvm_proofs: Vec<ZKVMProof<E, RecPcs>>,
    vk: ZKVMVerifyingKey<E, Basefold<E, BasefoldRSParams>>,
) -> (CenoRecursionVerifierKeys, VmStarkProof<SC>) {
    // Construct zkvm proof input
    let zkvm_proof_inputs: Vec<ZKVMProofInput> = zkvm_proofs.into_iter().enumerate().map(|(shard_id, p)| ZKVMProofInput::from((shard_id, p))).collect();

    let aggregation_start_timestamp = Instant::now();
    let sdk = Sdk::new();

    let [leaf_fri_params, internal_fri_params, _root_fri_params] =
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

    // let recursion_proving_keys = RecursionProvingKeys::keygen(leaf_fri_params, leaf_vm_config);

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

    let leaf_prover = VmLocalProver::<SC, NativeConfig, BabyBearPoseidon2Engine>::new(
        ceno_leaf_vm_pk.clone(),
        leaf_committed_exe,
    );

    let leaf_proofs = zkvm_proof_inputs.iter().enumerate().map(|(proof_idx, p)| {
        println!(
            "Aggregation - Start leaf proof (idx: {:?}) at: {:?}",
            proof_idx,
            aggregation_start_timestamp.elapsed()
        );
        let mut witness_stream: Vec<Vec<F>> = Vec::new();
        witness_stream.extend(p.write());
        let leaf_proof = SingleSegmentVmProver::prove(&leaf_prover, witness_stream);

        /* _debug: export
        let file =
            File::create(format!("leaf_proof_{:?}.bin", proof_idx)).expect("Create export proof file");
        bincode::serialize_into(file, &leaf_proof).expect("failed to serialize leaf proof");
        */

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
        &ceno_leaf_vm_pk.vm_pk.get_vk(),
        &internal_vm_vk,
    );
    let internal_committed_exe = Arc::new(VmCommittedExe::<SC>::commit(
        internal_program.into(),
        internal_vm.engine.config.pcs(),
    ));
    let internal_prover = VmLocalProver::<SC, NativeConfig, BabyBearPoseidon2Engine>::new(
        internal_vm_pk.clone(),
        internal_committed_exe.clone(),
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

                /* _debug: export
                let file = File::create(format!(
                    "internal_proof_{:?}_height_{:?}.bin",
                    internal_node_idx, internal_node_height
                ))
                .expect("Create export proof file");
                bincode::serialize_into(file, &internal_proof).expect("failed to serialize internal proof");
                */

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
    
    // Export e2e stark proof (used in verify_e2e_stark_proof)
    let root_stark_proof = VmStarkProof {
        proof: proofs.pop().unwrap(),
        user_public_values: zkvm_proof_inputs.iter().flat_map(|p| p.raw_pi.iter().flat_map(|v| v.clone()).collect::<Vec<F>>()).collect(),
    };
    let file = File::create("root_stark_proof.bin")
        .expect("Create export proof file");
        bincode::serialize_into(file, &root_stark_proof).expect("failed to serialize internal proof");

    // Export aggregation key (used in verify_e2e_stark_proof)
    let ceno_vk = CenoRecursionVerifierKeys {
        ceno_leaf_vm_vk: ceno_leaf_vm_pk.vm_pk.get_vk(),
        ceno_leaf_fri_params: ceno_leaf_vm_pk.fri_params,
        internal_vm_vk: internal_vm_pk.vm_pk.get_vk(),
        ceno_internal_fri_params: internal_vm_pk.fri_params,
        internal_commit: internal_committed_exe.get_program_commit().into(),
    };

    let file = File::create("ceno_vk.bin")
        .expect("Create export proof file");
        bincode::serialize_into(file, &ceno_vk).expect("failed to serialize internal proof");

    (ceno_vk, root_stark_proof)
}

// Source from OpenVm SDK::verify_e2e_stark_proof with abridged key
// See: https://github.com/openvm-org/openvm
pub fn verify_e2e_stark_proof(
    k: &CenoRecursionVerifierKeys,
    proof: &VmStarkProof<SC>,
    expected_exe_commit: &Bn254Fr,
    expected_vm_commit: &Bn254Fr,
) -> Result<AppExecutionCommit, String> {
    if proof.proof.per_air.len() < 3 {
        return Err("Invalid number of AIRs: expected at least 3".into());
    } else if proof.proof.per_air[0].air_id != PROGRAM_AIR_ID {
        return Err("Missing program AIR".into());
    } else if proof.proof.per_air[1].air_id != CONNECTOR_AIR_ID {
        return Err("Missing connector AIR".into());
    } else if proof.proof.per_air[2].air_id != PUBLIC_VALUES_AIR_ID {
        return Err("Missing public values AIR".into());
    }
    let public_values_air_proof_data = &proof.proof.per_air[2];

    let program_commit =
        proof.proof.commitments.main_trace[PROGRAM_CACHED_TRACE_INDEX].as_ref();
    let internal_commit: &[_; CHUNK] = &k.internal_commit;

    let (vm_vk, fri_params, vm_commit) = if program_commit == internal_commit {
        let internal_pvs: &InternalVmVerifierPvs<_> = public_values_air_proof_data
            .public_values
            .as_slice()
            .borrow();
        if internal_commit != &internal_pvs.extra_pvs.internal_program_commit {
            return Err(format!("Invalid internal program commit: expected {:?}, got {:?}", internal_commit, internal_pvs.extra_pvs.internal_program_commit));
        }
        (
            &k.internal_vm_vk,
            k.ceno_internal_fri_params,
            internal_pvs.extra_pvs.leaf_verifier_commit,
        )
    } else {
        (&k.ceno_leaf_vm_vk, k.ceno_leaf_fri_params, *program_commit)
    };
    let e = BabyBearPoseidon2Engine::new(fri_params);
    e.verify(&vm_vk, &proof.proof).expect("stark e2e proof verification should pass");

    let pvs: &VmVerifierPvs<_> =
        public_values_air_proof_data.public_values[..VmVerifierPvs::<u8>::width()].borrow();

    /* _debug: AIR ordering
    if let Some(exit_code) = pvs.connector.exit_code() {
        if exit_code != 0 {
            return Err(format!(
                "Invalid exit code: expected 0, got {}",
                exit_code
            ));
        }
    } else {
        return Err(format!("Program did not terminate"));
    }
    */

    let hasher = vm_poseidon2_hasher();
    let public_values_root = hasher.merkle_root(&proof.user_public_values);
    /* _debug: Public value commitment
    if public_values_root != pvs.public_values_commit {
        return Err(format!(
            "Invalid public values root: expected {:?}, got {:?}",
            pvs.public_values_commit,
            public_values_root
        ));
    }
    */

    let exe_commit = compute_exe_commit(
        &hasher,
        &pvs.app_commit,
        &pvs.memory.initial_root,
        pvs.connector.initial_pc,
    );
    let app_commit = AppExecutionCommit::from_field_commit(exe_commit, vm_commit);
    let exe_commit_bn254 = app_commit.app_exe_commit.to_bn254();
    let vm_commit_bn254 = app_commit.app_vm_commit.to_bn254();

    /* _debug: execution commit checks
    if exe_commit_bn254 != *expected_exe_commit {
        return Err(eyre::eyre!(
            "Invalid app exe commit: expected {:?}, got {:?}",
            expected_exe_commit,
            exe_commit_bn254
        ));
    } else if vm_commit_bn254 != *expected_vm_commit {
        return Err(eyre::eyre!(
            "Invalid app vm commit: expected {:?}, got {:?}",
            expected_vm_commit,
            vm_commit_bn254
        ));
    }
    */
    Ok(app_commit)
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
        let zkvm_proof_input = ZKVMProofInput::from((0usize, zkvm_proofs[0].clone()));

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

        let result = vm.execute_and_generate(program, witness_stream).unwrap();
        // let pk = vm.keygen();
        // let proofs = vm.prove(&pk, result);
        // for proof in proofs {
        //     verify_single(&vm.engine, &pk.get_vk(), &proof).expect("Verification failed");
        // }
    }
}

#[cfg(test)]
mod tests {
    use crate::aggregation::{compress_to_root_proof, verify_proofs};
    use crate::{
        zkvm_verifier::binding::{E, F},
    };
    use ceno_zkvm::scheme::ZKVMProof;
    use ceno_zkvm::structs::ZKVMVerifyingKey;
    use mpcs::{Basefold, BasefoldRSParams};
    use std::fs::File;
    use openvm_stark_sdk::config::setup_tracing_with_log_level;
    use super::verify_e2e_stark_proof;
    use openvm_stark_sdk::p3_bn254_fr::Bn254Fr;
    use ceno_zkvm::scheme::verifier::ZKVMVerifier;
    use ceno_zkvm::e2e::verify;
    use p3::field::FieldAlgebra;

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

        let (vk, root_stark_proof) = compress_to_root_proof(zkvm_proofs, vk);

        verify_e2e_stark_proof(
            &vk, 
            &root_stark_proof, 
            // _debug
            &Bn254Fr::ZERO, 
            &Bn254Fr::ZERO
        ).expect("Verify e2e stark proof should pass");
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

    pub fn verify_single_rust_verifier_inner_thread() {
        setup_tracing_with_log_level(tracing::Level::WARN);

        let proof_path = "./src/imported/proof.bin";
        let vk_path = "./src/imported/vk.bin";

        let zkvm_proofs: Vec<ZKVMProof<E, Basefold<E, BasefoldRSParams>>> =
            bincode::deserialize_from(File::open(proof_path).expect("Failed to open proof file"))
                .expect("Failed to deserialize proof file");

        let vk: ZKVMVerifyingKey<E, Basefold<E, BasefoldRSParams>> =
            bincode::deserialize_from(File::open(vk_path).expect("Failed to open vk file"))
                .expect("Failed to deserialize vk file");

        let verifier = ZKVMVerifier::new(vk);
        verify(zkvm_proofs.clone(), &verifier).expect("Verification failed");
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

    #[test]
    pub fn test_single_rust_verifier() {
        let stack_size = 256 * 1024 * 1024; // 64 MB

        let handler = std::thread::Builder::new()
            .stack_size(stack_size)
            .spawn(verify_single_rust_verifier_inner_thread)
            .expect("Failed to spawn thread");

        handler.join().expect("Thread panicked");
    }
}
