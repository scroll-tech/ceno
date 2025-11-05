pub mod scheme;

#[cfg(test)]
mod tests {
    use crate::e2e::build_zkvm_verifier_program;
    use crate::{
        aggregation::scheme::{CenoLeafVmVerifierConfig, RecursionProvingKeys},
        zkvm_verifier::binding::{E, F},
    };
    use ceno_zkvm::scheme::ZKVMProof;
    use ceno_zkvm::structs::ZKVMVerifyingKey;
    use mpcs::{Basefold, BasefoldRSParams};
    use openvm_circuit::arch::{instructions::exe::VmExe, SystemConfig};
    use openvm_native_circuit::NativeConfig;
    use openvm_native_compiler::conversion::CompilerOptions;
    use openvm_native_recursion::hints::Hintable;
    use openvm_sdk::Sdk;
    use openvm_stark_sdk::config::{baby_bear_poseidon2::BabyBearPoseidon2Engine, FriParameters};
    use std::fs::File;
    use std::sync::Arc;
    /* _debug: single proof verification
    use openvm_stark_sdk::engine::StarkFriEngine;
    use openvm_circuit::arch::verify_single;
    use openvm_circuit::arch::VirtualMachine;
    use openvm_native_circuit::{Native, NativeConfig};
    */
    use openvm_circuit::arch::VirtualMachine;
    use openvm_circuit::system::program::trace::VmCommittedExe;
    use openvm_circuit::{
        arch::{
            ExecutionBridge, InitFileGenerator, MemoryConfig, SystemPort, VmExtension, VmInventory,
            VmInventoryBuilder, VmInventoryError,
        },
        system::phantom::PhantomChip,
    };
    use openvm_continuations::verifier::common::types::VmVerifierPvs;
    use openvm_continuations::verifier::internal::types::InternalVmVerifierInput;
    use openvm_continuations::verifier::internal::types::InternalVmVerifierPvs;
    use openvm_continuations::verifier::internal::InternalVmVerifierConfig;
    use openvm_sdk::prover::vm::types::VmProvingKey;
    use openvm_sdk::{
        config::AggregationTreeConfig,
        prover::{
            vm::{local::VmLocalProver, SingleSegmentVmProver},
            RootVerifierLocalProver,
        },
        NonRootCommittedExe, RootSC, SC,
    };
    use openvm_stark_sdk::config::setup_tracing_with_log_level;
    use openvm_stark_sdk::{
        config::baby_bear_poseidon2_root::BabyBearPoseidon2RootEngine,
        engine::StarkFriEngine,
        openvm_stark_backend::{
            config::{Com, StarkGenericConfig},
            keygen::types::MultiStarkVerifyingKey,
            proof::Proof,
            Chip,
        },
        p3_bn254_fr::Bn254Fr,
    };
    use std::io::Write;
    use std::time::Instant;

    const LEAF_LOG_BLOWUP: usize = 1;
    const INTERNAL_LOG_BLOWUP: usize = 2;
    const ROOT_LOG_BLOWUP: usize = 3;
    const SBOX_SIZE: usize = 7;

    pub fn aggregation_inner_thread() {
        setup_tracing_with_log_level(tracing::Level::WARN);

        let proof_path = "./src/e2e/encoded/proof.bin";
        let vk_path = "./src/e2e/encoded/vk.bin";

        let zkvm_proof: ZKVMProof<E, Basefold<E, BasefoldRSParams>> =
            bincode::deserialize_from(File::open(proof_path).expect("Failed to open proof file"))
                .expect("Failed to deserialize proof file");

        let vk: ZKVMVerifyingKey<E, Basefold<E, BasefoldRSParams>> =
            bincode::deserialize_from(File::open(vk_path).expect("Failed to open vk file"))
                .expect("Failed to deserialize vk file");

        // Construct zkvm proof input
        let mut witness_stream: Vec<Vec<F>> = Vec::new();
        witness_stream.extend(zkvm_proof.write());

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

        println!(
            "Aggregation - Start leaf proof at: {:?}",
            aggregation_start_timestamp.elapsed()
        );
        let leaf_proof = SingleSegmentVmProver::prove(&leaf_prover, witness_stream);
        println!(
            "Aggregation - Completed leaf proof at: {:?}",
            aggregation_start_timestamp.elapsed()
        );

        // _debug: export leaf proof
        let json = serde_json::to_string(&leaf_proof).unwrap();
        let mut file =
            File::create(format!("leaf_proof_{:?}.json", 0)).expect("Create export proof file");
        file.write_all(json.as_bytes()).expect("Export proof");

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
        let mut proofs = vec![leaf_proof];

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
                1, // _debug
            );
            proofs = internal_inputs
                .into_iter()
                .map(|input| {
                    internal_node_idx += 1;
                    let internal_proof =
                        SingleSegmentVmProver::prove(&internal_prover, input.write());
                    // println!("Aggregation - Completed internal node (idx: {:?}) at height {:?}: {:?}", internal_node_idx, internal_node_height, aggregation_start_timestamp.elapsed());

                    // _debug: export
                    let json = serde_json::to_string(&internal_proof).unwrap();
                    let mut file = File::create(format!(
                        "internal_proof_{:?}_height_{:?}.json",
                        internal_node_idx, internal_node_height
                    ))
                    .expect("Create export proof file");
                    file.write_all(json.as_bytes()).expect("Export proof");

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

        // let root_stark_proof = VmStarkProof {
        //     proof: proofs.pop().unwrap(),
        //     user_public_values: public_values,
        // };

        /* _debug: verify single passes
        let log_blowup = 1;
        let poseidon2_max_constraint_degree: usize = 3;
        let fri_params = if matches!(std::env::var("OPENVM_FAST_TEST"), Ok(x) if &x == "1") {
            FriParameters {
                log_blowup,
                log_final_poly_len: 0,
                num_queries: 10,
                proof_of_work_bits: 0,
            }
        } else {
            standard_fri_params_with_100_bits_conjectured_security(log_blowup)
        };

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
        */
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
}
