use crate::zkvm_verifier::{
    binding::{E, F, ZKVMProofInput, ZKVMProofInputVariable},
    verifier::verify_zkvm_proof,
};
use ceno_zkvm::{
    instructions::riscv::constants::{END_PC_IDX, EXIT_CODE_IDX, INIT_PC_IDX},
    scheme::ZKVMProof,
    structs::ZKVMVerifyingKey,
};
use ff_ext::BabyBearExt4;
use mpcs::{Basefold, BasefoldRSParams};
use openvm_circuit::{
    arch::{
        MemoryConfig, SystemConfig, VirtualMachine, VmInstance, instructions::program::Program,
    },
    system::program::trace::VmCommittedExe,
    utils::air_test_impl,
};
use openvm_stark_backend::config::{PcsProverData, Val};

use internal::InternalVmVerifierConfig;
use openvm_continuations::{
    C,
    verifier::{
        common::types::VmVerifierPvs,
        internal::types::{InternalVmVerifierInput, InternalVmVerifierPvs, VmStarkProof},
    },
};
#[cfg(feature = "gpu")]
use openvm_cuda_backend::engine::GpuBabyBearPoseidon2Engine as BabyBearPoseidon2Engine;
#[cfg(feature = "gpu")]
use openvm_stark_sdk::config::baby_bear_poseidon2::BabyBearPoseidon2Engine as CpuBabyBearPoseidon2Engine;
use openvm_native_circuit::{NativeBuilder, NativeConfig};
use openvm_native_compiler::{
    asm::AsmBuilder,
    conversion::{CompilerOptions, convert_program},
    prelude::*,
};
use openvm_native_recursion::hints::Hintable;
use openvm_sdk::{
    SC,
    commit::AppExecutionCommit,
    config::DEFAULT_NUM_CHILDREN_INTERNAL,
    prover::vm::{new_local_prover, types::VmProvingKey},
};
use openvm_stark_backend::{
    config::{Com, StarkGenericConfig},
    engine::StarkEngine,
};
#[cfg(not(feature = "gpu"))]
use openvm_stark_sdk::config::baby_bear_poseidon2::BabyBearPoseidon2Engine;
use openvm_stark_sdk::{
    config::{
        FriParameters, baby_bear_poseidon2::BabyBearPoseidon2Config,
        fri_params::standard_fri_params_with_100_bits_conjectured_security,
    },
    engine::StarkFriEngine,
    openvm_stark_backend::keygen::types::MultiStarkVerifyingKey,
    p3_bn254_fr::Bn254Fr,
};
use p3::field::FieldAlgebra;
use serde::{Deserialize, Serialize};
use std::{borrow::Borrow, io::Write, sync::Arc, time::Instant};
pub type RecPcs = Basefold<E, BasefoldRSParams>;
use openvm_circuit::{
    arch::{
        CONNECTOR_AIR_ID, PROGRAM_AIR_ID, PROGRAM_CACHED_TRACE_INDEX, PUBLIC_VALUES_AIR_ID,
        SingleSegmentVmProver,
        hasher::{Hasher, poseidon2::vm_poseidon2_hasher},
        instructions::exe::VmExe,
    },
    system::{memory::CHUNK, program::trace::compute_exe_commit},
};
use openvm_native_compiler::{
    asm::AsmConfig,
    ir::{Builder, Config, Felt},
};
use openvm_sdk::util::check_max_constraint_degrees;
use openvm_stark_backend::proof::Proof;

mod internal;
mod root;
mod types;

pub type InnerConfig = AsmConfig<F, E>;
pub const LEAF_LOG_BLOWUP: usize = 1;
pub const INTERNAL_LOG_BLOWUP: usize = 2;
pub const ROOT_LOG_BLOWUP: usize = 3;
pub const SBOX_SIZE: usize = 7;
const VM_MAX_TRACE_HEIGHTS: &[u32] = &[
    4194304, 4, 128, 2097152, 8388608, 4194304, 262144, 8388608, 16777216, 16777216, 2097152,
    16777216, 2097152, 8388608, 262144, 2097152, 1048576, 4194304, 1048576, 262144,
];

use std::fs::File;

pub struct CenoAggregationProver {
    pub base_vk: ZKVMVerifyingKey<E, Basefold<E, BasefoldRSParams>>,
    pub leaf_prover: VmInstance<BabyBearPoseidon2Engine, NativeBuilder>,
    pub internal_prover: VmInstance<BabyBearPoseidon2Engine, NativeBuilder>,
    pub vk: CenoRecursionVerifierKeys<BabyBearPoseidon2Config>,
    pub pk: CenoRecursionProvingKeys<BabyBearPoseidon2Config, NativeConfig>,
}

impl CenoAggregationProver {
    pub fn new(
        base_vk: ZKVMVerifyingKey<E, Basefold<E, BasefoldRSParams>>,
        leaf_prover: VmInstance<BabyBearPoseidon2Engine, NativeBuilder>,
        internal_prover: VmInstance<BabyBearPoseidon2Engine, NativeBuilder>,
        pk: CenoRecursionProvingKeys<BabyBearPoseidon2Config, NativeConfig>,
    ) -> Self {
        Self {
            base_vk,
            leaf_prover,
            internal_prover,
            vk: pk.get_vk(),
            pk,
        }
    }

    pub fn from_base_vk(vk: ZKVMVerifyingKey<E, Basefold<E, BasefoldRSParams>>) -> Self {
        let vb = NativeBuilder::default();
        let [leaf_fri_params, internal_fri_params, _root_fri_params] =
            [LEAF_LOG_BLOWUP, INTERNAL_LOG_BLOWUP, ROOT_LOG_BLOWUP]
                .map(FriParameters::standard_with_100_bits_conjectured_security);

        // Configure vm for the leaf layer
        let leaf_vm_config = NativeConfig {
            system: SystemConfig::new(
                SBOX_SIZE.min(leaf_fri_params.max_constraint_degree()),
                MemoryConfig {
                    max_access_adapter_n: 16,
                    ..Default::default()
                },
                VmVerifierPvs::<u8>::width(),
            )
            .with_max_segment_len((1 << 24) - 100)
            .with_profiling()
            .without_continuations(),
            native: Default::default(),
        };

        // Leaf layer keygen
        let leaf_vm_pk = {
            let leaf_engine = BabyBearPoseidon2Engine::new(leaf_fri_params);
            let (_, vm_pk) =
                VirtualMachine::new_with_keygen(leaf_engine, vb.clone(), leaf_vm_config.clone())
                    .expect("leaf keygen");
            assert!(vm_pk.max_constraint_degree <= leaf_fri_params.max_constraint_degree());
            check_max_constraint_degrees(&leaf_vm_config.system, &leaf_fri_params);
            Arc::new(VmProvingKey {
                fri_params: leaf_fri_params,
                vm_config: leaf_vm_config,
                vm_pk,
            })
        };
        let leaf_vm_vk = leaf_vm_pk.vm_pk.get_vk();

        // Leaf layer program
        let leaf_engine = BabyBearPoseidon2Engine::new(leaf_fri_params);
        let leaf_vm_verifier_config = CenoLeafVmVerifierConfig {
            vk,
            compiler_options: CompilerOptions::default().with_cycle_tracker(),
        };
        let leaf_program = leaf_vm_verifier_config.build_program();
        let leaf_committed_exe = Arc::new(VmCommittedExe::<SC>::commit(
            leaf_program.into(),
            leaf_engine.config().pcs(),
        ));
        let leaf_prover = new_local_prover::<BabyBearPoseidon2Engine, NativeBuilder>(
            vb.clone(),
            &leaf_vm_pk,
            leaf_committed_exe.exe.clone(),
        )
        .expect("leaf prover");

        // Configure vm for internal layers
        // needs to be a multiple of DIGEST_SIZE
        let num_public_values =
            InternalVmVerifierPvs::<u8>::width().div_ceil(DIGEST_SIZE) * DIGEST_SIZE;
        let internal_vm_config = NativeConfig {
            system: SystemConfig::new(
                SBOX_SIZE.min(internal_fri_params.max_constraint_degree()),
                MemoryConfig {
                    max_access_adapter_n: 16,
                    ..Default::default()
                },
                num_public_values,
            )
            .with_max_segment_len((1 << 24) - 100)
            .with_profiling()
            .without_continuations(),
            native: Default::default(),
        };

        // Internal keygen
        let internal_engine = BabyBearPoseidon2Engine::new(internal_fri_params);
        let (internal_vm, vm_pk) = VirtualMachine::new_with_keygen(
            internal_engine,
            vb.clone(),
            internal_vm_config.clone(),
        )
        .expect("internal keygen");
        check_max_constraint_degrees(&internal_vm_config.system, &internal_fri_params);
        assert!(vm_pk.max_constraint_degree <= internal_fri_params.max_constraint_degree());
        let internal_vm_pk = Arc::new(VmProvingKey {
            fri_params: internal_fri_params,
            vm_config: internal_vm_config,
            vm_pk,
        });
        let internal_vm_vk = internal_vm_pk.vm_pk.get_vk();

        // Internal program
        let internal_program = InternalVmVerifierConfig {
            leaf_fri_params,
            internal_fri_params,
            compiler_options: CompilerOptions::default().with_cycle_tracker(),
        }
        .build_program(&leaf_vm_vk, &internal_vm_vk);
        let internal_committed_exe = Arc::new(VmCommittedExe::<SC>::commit(
            internal_program.into(),
            internal_vm.engine.config().pcs(),
        ));
        let internal_prover = new_local_prover::<BabyBearPoseidon2Engine, NativeBuilder>(
            vb.clone(),
            &internal_vm_pk,
            internal_committed_exe.exe.clone(),
        )
        .expect("internal prover");

        // TODO: build root program (requires shard ram ec point is zero)
        // TODO: add root prover

        let vk = CenoRecursionVerifierKeys {
            leaf_vm_vk,
            leaf_fri_params: leaf_vm_pk.fri_params,
            internal_vm_vk,
            internal_fri_params: internal_vm_pk.fri_params,
            internal_commit: internal_committed_exe.get_program_commit(),
        };

        let pk = CenoRecursionProvingKeys {
            leaf_vm_pk,
            leaf_committed_exe,
            internal_vm_pk,
            internal_committed_exe,
        };

        Self {
            base_vk: leaf_vm_verifier_config.vk,
            leaf_prover,
            internal_prover,
            vk,
            pk,
        }
    }

    pub fn generate_root_proof(
        &mut self,
        base_proofs: Vec<ZKVMProof<BabyBearExt4, Basefold<E, BasefoldRSParams>>>,
    ) -> VmStarkProof<SC> {
        let aggregation_start_timestamp = Instant::now();
        let expected_leaf_program_commit = self.pk.leaf_committed_exe.get_program_commit();

        println!(
            "Aggregation - Config fingerprint: gpu_feature={}, num_children_internal={}",
            cfg!(feature = "gpu"),
            DEFAULT_NUM_CHILDREN_INTERNAL
        );
        println!(
            "Aggregation - Program commits: leaf={:?}, internal={:?}",
            expected_leaf_program_commit,
            self.pk.internal_committed_exe.get_program_commit()
        );
        println!(
            "Aggregation - FRI params: leaf={:?}, internal={:?}",
            self.vk.leaf_fri_params,
            self.vk.internal_fri_params
        );

        // Construct zkvm proof input
        let zkvm_proof_inputs: Vec<ZKVMProofInput> = base_proofs
            .into_iter()
            .enumerate()
            .map(|(shard_id, p)| ZKVMProofInput::from_proof(shard_id, p, &self.base_vk))
            .collect();
        let user_public_values: Vec<F> = zkvm_proof_inputs
            .iter()
            .flat_map(|p| p.raw_pi.iter().flat_map(|v| v.clone()).collect::<Vec<F>>())
            .collect();
        let leaf_inputs = chunk_ceno_leaf_proof_inputs(zkvm_proof_inputs);

        let leaf_proofs = leaf_inputs
            .iter()
            .enumerate()
            .map(|(proof_idx, p)| {
                println!(
                    "Aggregation - Start leaf proof (idx: {:?}) at: {:?}",
                    proof_idx,
                    aggregation_start_timestamp.elapsed()
                );

                let mut witness_stream: Vec<Vec<F>> = Vec::new();
                witness_stream.extend(p.write());

                let leaf_proof = SingleSegmentVmProver::prove(
                    &mut self.leaf_prover,
                    witness_stream,
                    VM_MAX_TRACE_HEIGHTS,
                )
                .expect("leaf proof generation failed");

                println!(
                    "Aggregation - Leaf proof program commit (idx: {:?}): {:?}",
                    proof_idx,
                    leaf_proof.commitments.main_trace[PROGRAM_CACHED_TRACE_INDEX].as_ref()
                );

                maybe_log_leaf_air_summary(proof_idx, &leaf_proof);
                maybe_export_leaf_air_debug_snapshot(
                    proof_idx,
                    &leaf_proof,
                    &expected_leaf_program_commit,
                    &self.vk.leaf_fri_params,
                );

                // Debug safety net: catch invalid leaf proofs at generation time.
                // If this fails, the issue is in proving (or backend), not in
                // internal-input chunking/serialization.
                let leaf_engine = BabyBearPoseidon2Engine::new(self.vk.leaf_fri_params);
                if let Err(gpu_verify_err) = leaf_engine.verify(&self.vk.leaf_vm_vk, &leaf_proof) {
                    #[cfg(feature = "gpu")]
                    {
                        // Cross-check with CPU verifier to isolate GPU prover vs GPU verifier issues.
                        let cpu_engine = CpuBabyBearPoseidon2Engine::new(self.vk.leaf_fri_params);
                        let cpu_verify_res = cpu_engine.verify(&self.vk.leaf_vm_vk, &leaf_proof);
                        maybe_export_leaf_air_debug_snapshot(
                            proof_idx,
                            &leaf_proof,
                            &expected_leaf_program_commit,
                            &self.vk.leaf_fri_params,
                        );
                        panic!(
                            "leaf proof generation produced invalid proof at idx {}: gpu_verify={:?}, cpu_verify={:?}",
                            proof_idx, gpu_verify_err, cpu_verify_res
                        );
                    }
                    #[cfg(not(feature = "gpu"))]
                    {
                        panic!(
                            "leaf proof generation produced invalid proof at idx {}: {:?}",
                            proof_idx, gpu_verify_err
                        );
                    }
                }

                // _debug: export
                let file =
                    File::create(format!("leaf_proof_{:?}.bin", proof_idx)).expect("Create export proof file");
                bincode::serialize_into(file, &leaf_proof).expect("failed to serialize leaf proof");

                println!(
                    "Aggregation - Completed leaf proof (idx: {:?}) at: {:?}, public values: {:?}",
                    proof_idx,
                    aggregation_start_timestamp.elapsed(),
                    leaf_proof.per_air[PUBLIC_VALUES_AIR_ID].public_values,
                );

                leaf_proof
            })
            .collect::<Vec<_>>();

        // Aggregate leaf proofs into a single internal proof via binary tree
        let root_inner = self.aggregate_internal_proofs(leaf_proofs);

        // Export e2e stark proof (used in verify_e2e_stark_proof)
        VmStarkProof {
            inner: root_inner,
            user_public_values,
        }
    }

    /// Aggregate leaf (or internal) proofs into a single root internal proof
    /// via a binary tree of internal proving rounds.
    pub fn aggregate_internal_proofs(&mut self, leaf_proofs: Vec<Proof<SC>>) -> Proof<SC> {
        let start = Instant::now();

        let mut internal_node_idx = -1;
        let mut internal_node_height = 0;
        let mut proofs = leaf_proofs;

        println!(
            "Aggregation - Start internal aggregation at: {:?}",
            start.elapsed()
        );
        // We will always generate at least one internal proof, even if there is only one leaf
        // proof, in order to shrink the proof size
        while proofs.len() > 1 || internal_node_height == 0 {
            let internal_inputs = InternalVmVerifierInput::chunk_leaf_or_internal_proofs(
                (*self.internal_prover.program_commitment()).into(),
                &proofs,
                DEFAULT_NUM_CHILDREN_INTERNAL,
            );
            let layer_proofs: Vec<Proof<_>> = internal_inputs
                .into_iter()
                .map(|input| {
                    internal_node_idx += 1;
                    self.precheck_internal_input(&input, internal_node_idx, internal_node_height);

                    let internal_proof = SingleSegmentVmProver::prove(
                        &mut self.internal_prover,
                        input.write(),
                        VM_MAX_TRACE_HEIGHTS,
                    )
                    .expect("internal proof generation failed");

                    println!(
                        "Aggregation - Completed internal node (idx: {:?}) at height {:?}: {:?}",
                        internal_node_idx,
                        internal_node_height,
                        start.elapsed()
                    );

                    // _debug: export
                    // let file = File::create(format!(
                    // "internal_proof_{:?}_height_{:?}.bin",
                    // internal_node_idx, internal_node_height
                    // ))
                    // .expect("Create export proof file");
                    // bincode::serialize_into(file, &internal_proof).expect("failed to serialize internal proof");
                    internal_proof
                })
                .collect();

            proofs = layer_proofs;
            internal_node_height += 1;
        }
        println!(
            "Aggregation - Completed internal aggregation at: {:?}",
            start.elapsed()
        );
        println!("Aggregation - Final height: {:?}", internal_node_height);

        // TODO: generate root proof from last internal proof

        proofs.pop().unwrap()
    }

    fn precheck_internal_input(
        &self,
        input: &InternalVmVerifierInput<SC>,
        internal_node_idx: i32,
        internal_node_height: i32,
    ) {
        let do_child_verify = std::env::var("CENO_DEBUG_VERIFY_CHILD_STARK")
            .ok()
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            // Default to verifying child proofs on the first internal layer only.
            .unwrap_or(internal_node_height == 0);

        println!(
            "Aggregation - Precheck internal node (idx: {:?}) at height {:?}: {} child proofs",
            internal_node_idx,
            internal_node_height,
            input.proofs.len()
        );

        let mut prev_final_pc = None;
        let mut first_app_commit = None;

        for (proof_idx, proof) in input.proofs.iter().enumerate() {
            assert!(
                proof.per_air.len() > PUBLIC_VALUES_AIR_ID,
                "internal precheck: proof {} missing PUBLIC_VALUES AIR",
                proof_idx
            );
            assert!(
                proof.per_air.len() > CONNECTOR_AIR_ID,
                "internal precheck: proof {} missing CONNECTOR AIR",
                proof_idx
            );

            let connector_air = &proof.per_air[CONNECTOR_AIR_ID];
            let vm_connector = &connector_air.public_values;
            assert!(
                vm_connector.len() >= 4,
                "internal precheck: proof {} has malformed vm connector pv len {}",
                proof_idx,
                vm_connector.len()
            );

            let pvs: &VmVerifierPvs<_> =
                proof.per_air[PUBLIC_VALUES_AIR_ID].public_values[..VmVerifierPvs::<u8>::width()]
                    .borrow();

            if let Some(prev) = prev_final_pc {
                assert_eq!(
                    prev, pvs.connector.initial_pc,
                    "internal precheck: connector chain break at child {}",
                    proof_idx
                );
            }
            prev_final_pc = Some(pvs.connector.final_pc);

            if let Some(app_commit) = first_app_commit {
                assert_eq!(
                    app_commit, pvs.app_commit,
                    "internal precheck: app_commit mismatch at child {}",
                    proof_idx
                );
            } else {
                first_app_commit = Some(pvs.app_commit);
            }

            println!(
                "Aggregation -   child {} vm_connector=[init:{:?}, final:{:?}, exit:{:?}, term:{:?}] agg_connector=[init:{:?}, final:{:?}, exit:{:?}, term:{:?}]",
                proof_idx,
                vm_connector[0],
                vm_connector[1],
                vm_connector[2],
                vm_connector[3],
                pvs.connector.initial_pc,
                pvs.connector.final_pc,
                pvs.connector.exit_code,
                pvs.connector.is_terminate
            );

            if do_child_verify {
                let program_commit = proof.commitments.main_trace[PROGRAM_CACHED_TRACE_INDEX].as_ref();
                let internal_commit: &[_; CHUNK] = &self.vk.internal_commit.into();

                if program_commit == internal_commit {
                    let e = BabyBearPoseidon2Engine::new(self.vk.internal_fri_params);
                    e.verify(&self.vk.internal_vm_vk, proof)
                        .unwrap_or_else(|err| {
                            panic!(
                                "internal precheck: child {} failed internal-vk verify: {:?}",
                                proof_idx, err
                            )
                        });
                } else {
                    let e = BabyBearPoseidon2Engine::new(self.vk.leaf_fri_params);
                    e.verify(&self.vk.leaf_vm_vk, proof)
                        .unwrap_or_else(|err| {
                            panic!(
                                "internal precheck: child {} failed leaf-vk verify: {:?}",
                                proof_idx, err
                            )
                        });
                }
            }
        }
    }
}

fn env_flag_default_off(name: &str) -> bool {
    std::env::var(name)
        .ok()
        .is_some_and(|v| v == "1" || v.eq_ignore_ascii_case("true"))
}

fn maybe_log_leaf_air_summary(proof_idx: usize, proof: &Proof<SC>) {
    println!(
        "Aggregation - Leaf AIR summary (idx: {}): num_airs={}",
        proof_idx,
        proof.per_air.len()
    );
    for (slot, air) in proof.per_air.iter().enumerate() {
        println!(
            "Aggregation -   air slot {} -> air_id={}, pv_len={}",
            slot,
            air.air_id,
            air.public_values.len()
        );
    }
}

fn maybe_export_leaf_air_debug_snapshot(
    proof_idx: usize,
    proof: &Proof<SC>,
    expected_leaf_program_commit: &Com<SC>,
    leaf_fri_params: &FriParameters,
) {
    let export_dir = std::env::var("CENO_LEAF_AIR_DEBUG_DIR")
        .unwrap_or_else(|_| "leaf_air_debug".to_string());
    if let Err(err) = std::fs::create_dir_all(&export_dir) {
        eprintln!(
            "Aggregation - failed to create leaf AIR debug dir '{}': {:?}",
            export_dir, err
        );
        return;
    }

    let path = format!("{}/leaf_air_debug_{:03}.txt", export_dir, proof_idx);
    let mut file = match std::fs::File::create(&path) {
        Ok(f) => f,
        Err(err) => {
            eprintln!(
                "Aggregation - failed to create leaf AIR debug file '{}': {:?}",
                path, err
            );
            return;
        }
    };

    let _ = writeln!(file, "gpu_feature={}", cfg!(feature = "gpu"));
    let _ = writeln!(file, "proof_idx={}", proof_idx);
    let _ = writeln!(file, "leaf_fri_params={:?}", leaf_fri_params);
    let _ = writeln!(
        file,
        "expected_leaf_program_commit={:?}",
        expected_leaf_program_commit
    );
    let _ = writeln!(
        file,
        "proof_program_commit={:?}",
        proof.commitments.main_trace[PROGRAM_CACHED_TRACE_INDEX].as_ref()
    );
    let _ = writeln!(file, "num_airs={}", proof.per_air.len());

    let full_pv = env_flag_default_off("CENO_LEAF_AIR_DEBUG_FULL_PV");
    let sample = 16usize;
    for (slot, air) in proof.per_air.iter().enumerate() {
        let _ = writeln!(
            file,
            "air[{}]: air_id={}, pv_len={}",
            slot,
            air.air_id,
            air.public_values.len()
        );
        if full_pv {
            let _ = writeln!(file, "air[{}].pv={:?}", slot, air.public_values);
        } else {
            let head_len = air.public_values.len().min(sample);
            let _ = writeln!(
                file,
                "air[{}].pv_head({})={:?}",
                slot,
                head_len,
                &air.public_values[..head_len]
            );
        }
    }

    if proof.per_air.len() > CONNECTOR_AIR_ID {
        let connector_air = &proof.per_air[CONNECTOR_AIR_ID];
        let _ = writeln!(
            file,
            "connector_air(air_id={})_pv={:?}",
            connector_air.air_id,
            connector_air.public_values
        );
    }
    if proof.per_air.len() > PUBLIC_VALUES_AIR_ID {
        let pv_air = &proof.per_air[PUBLIC_VALUES_AIR_ID];
        let _ = writeln!(
            file,
            "public_values_air(air_id={})_pv={:?}",
            pv_air.air_id,
            pv_air.public_values
        );
    }

    println!("Aggregation - exported leaf AIR debug snapshot: {}", path);
}

/// Config to generate leaf VM verifier program.
pub struct CenoLeafVmVerifierConfig {
    pub vk: ZKVMVerifyingKey<E, Basefold<E, BasefoldRSParams>>,
    pub compiler_options: CompilerOptions,
}

impl CenoLeafVmVerifierConfig {
    pub fn build_program(&self) -> Program<F> {
        let mut builder = Builder::<C>::default();

        {
            builder.cycle_tracker_start("Read Ceno ZKVM Proof");
            let ceno_leaf_input = CenoLeafVmVerifierInput::read(&mut builder);
            builder.cycle_tracker_end("Read Ceno ZKVM Proof");
            let stark_pvs = VmVerifierPvs::<Felt<F>>::uninit(&mut builder);

            builder.cycle_tracker_start("Verify Ceno ZKVM Proof");
            let zkvm_proof = ceno_leaf_input.proof;
            let raw_pi = zkvm_proof.raw_pi.clone();
            let _calculated_shard_ec_sum = verify_zkvm_proof(&mut builder, zkvm_proof, &self.vk);
            builder.cycle_tracker_end("Verify Ceno ZKVM Proof");

            builder.cycle_tracker_start("PV Operations");

            // TODO: define our own VmVerifierPvs
            for i in 0..DIGEST_SIZE {
                builder.assign(&stark_pvs.app_commit[i], F::ZERO);
            }

            let pv = &raw_pi;
            let init_pc = {
                let arr = builder.get(pv, INIT_PC_IDX);
                builder.get(&arr, 0)
            };
            let end_pc = {
                let arr = builder.get(pv, END_PC_IDX);
                builder.get(&arr, 0)
            };
            let exit_code = {
                let arr = builder.get(pv, EXIT_CODE_IDX);
                builder.get(&arr, 0)
            };
            builder.assign(&stark_pvs.connector.initial_pc, init_pc);
            builder.assign(&stark_pvs.connector.final_pc, end_pc);
            builder.assign(&stark_pvs.connector.exit_code, exit_code);
            // Internal aggregation asserts connector chaining on this field.
            builder
                .if_eq(ceno_leaf_input.is_last, Usize::from(1))
                .then_or_else(
                    |builder| {
                        builder.assign(&stark_pvs.connector.is_terminate, F::ONE);
                    },
                    |builder| {
                        builder.assign(&stark_pvs.connector.is_terminate, F::ZERO);
                    },
                );

            // Keep remaining committed PVs deterministic until real memory/public-values
            // commitments are wired through this custom leaf program.
            for i in 0..DIGEST_SIZE {
                builder.assign(&stark_pvs.memory.initial_root[i], F::ZERO);
                builder.assign(&stark_pvs.memory.final_root[i], F::ZERO);
                builder.assign(&stark_pvs.public_values_commit[i], F::ZERO);
            }

            // TODO: assign shard_ec_sum to stark_pvs.shard_ec_sum

            // builder
            //     .if_eq(ceno_leaf_input.is_last, Usize::from(1))
            //     .then(|builder| {
            //         builder.assert_nonzero(&pv.len());

            //         // PC and cycle checks
            //         let prev_pc: Ext<_, _> = builder.uninit();
            //         builder.range(0, pv.len()).for_each(|idx_vec, builder| {
            //             let shard_pi = builder.get(&pv, idx_vec[0]);
            //             let init_cycle = builder.get(&shard_pi, INIT_CYCLE_IDX);
            //             let tracer_default: Ext<_, _> =
            //                 builder.constant(E::from_canonical_u64(Tracer::SUBCYCLES_PER_INSN));
            //             builder.assert_ext_eq(init_cycle, tracer_default);
            //             let end_pc = builder.get(&shard_pi, END_PC_IDX);
            //             let init_pc = builder.get(&shard_pi, INIT_PC_IDX);
            //             builder.if_eq(idx_vec[0], Usize::from(0)).then_or_else(
            //                 |builder| {
            //                     let entry_point: Ext<_, _> =
            //                         builder.constant(E::from_canonical_u32(self.vk.entry_pc));
            //                     builder.assert_ext_eq(init_pc, entry_point);
            //                 },
            //                 |builder| {
            //                     builder.assert_ext_eq(init_pc, prev_pc);
            //                 },
            //             );
            //             builder.assign(&prev_pc, end_pc);
            //         });

            //     });

            for pv in stark_pvs.flatten() {
                builder.commit_public_value(pv);
            }
            builder.cycle_tracker_end("PV Operations");
            builder.halt();
        }

        builder.compile_isa_with_options(self.compiler_options)
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(
    serialize = "Com<SC>: Serialize",
    deserialize = "Com<SC>: Deserialize<'de>"
))]
pub struct CenoRecursionVerifierKeys<SC: StarkGenericConfig> {
    pub leaf_vm_vk: MultiStarkVerifyingKey<SC>,
    pub leaf_fri_params: FriParameters,
    pub internal_vm_vk: MultiStarkVerifyingKey<SC>,
    pub internal_fri_params: FriParameters,
    pub internal_commit: Com<SC>,
}

#[derive(Serialize, Deserialize)]
#[serde(bound(
    serialize = "VmExe<Val<SC>>: Serialize, PcsProverData<SC>: Serialize, VC: Serialize",
    deserialize = "VmExe<Val<SC>>: Deserialize<'de>, PcsProverData<SC>: Deserialize<'de>, VC: Deserialize<'de>"
))]
pub struct CenoRecursionProvingKeys<SC: StarkGenericConfig, VC> {
    pub leaf_vm_pk: Arc<VmProvingKey<SC, VC>>,
    pub leaf_committed_exe: Arc<VmCommittedExe<SC>>,
    pub internal_vm_pk: Arc<VmProvingKey<SC, VC>>,
    pub internal_committed_exe: Arc<VmCommittedExe<SC>>,
}

impl<SC: StarkGenericConfig, VC> Clone for CenoRecursionProvingKeys<SC, VC> {
    fn clone(&self) -> Self {
        Self {
            leaf_vm_pk: self.leaf_vm_pk.clone(),
            leaf_committed_exe: self.leaf_committed_exe.clone(),
            internal_vm_pk: self.internal_vm_pk.clone(),
            internal_committed_exe: self.internal_committed_exe.clone(),
        }
    }
}

impl<SC: StarkGenericConfig, VC> CenoRecursionProvingKeys<SC, VC> {
    pub fn get_vk(&self) -> CenoRecursionVerifierKeys<SC> {
        CenoRecursionVerifierKeys {
            leaf_vm_vk: self.leaf_vm_pk.vm_pk.get_vk(),
            leaf_fri_params: self.leaf_vm_pk.fri_params,
            internal_vm_vk: self.internal_vm_pk.vm_pk.get_vk(),
            internal_fri_params: self.internal_vm_pk.fri_params,
            internal_commit: self.internal_committed_exe.get_program_commit(),
        }
    }
}
pub(crate) struct CenoLeafVmVerifierInput {
    pub proof: ZKVMProofInput,
    pub is_last: usize,
}

#[derive(DslVariable, Clone)]
pub(crate) struct CenoLeafVmVerifierInputVariable<C: Config> {
    pub proof: ZKVMProofInputVariable<C>,
    pub is_last: Usize<C::N>,
}

impl Hintable<InnerConfig> for CenoLeafVmVerifierInput {
    type HintVariable = CenoLeafVmVerifierInputVariable<InnerConfig>;

    fn read(builder: &mut Builder<InnerConfig>) -> Self::HintVariable {
        let proof = ZKVMProofInput::read(builder);
        let is_last = Usize::Var(usize::read(builder));

        Self::HintVariable { proof, is_last }
    }

    fn write(&self) -> Vec<Vec<<InnerConfig as Config>::N>> {
        let mut stream = Vec::new();
        stream.extend(self.proof.write());
        stream.extend(<usize as Hintable<InnerConfig>>::write(&self.is_last));
        stream
    }
}

pub(crate) fn chunk_ceno_leaf_proof_inputs(
    zkvm_proofs: Vec<ZKVMProofInput>,
) -> Vec<CenoLeafVmVerifierInput> {
    let mut ret: Vec<CenoLeafVmVerifierInput> = zkvm_proofs
        .into_iter()
        .map(|p| CenoLeafVmVerifierInput {
            proof: p,
            is_last: 0,
        })
        .collect();

    let last = ret.last_mut().unwrap();
    last.is_last = 1;

    ret
}

// Source from OpenVm SDK::verify_e2e_stark_proof with abridged key
// See: https://github.com/openvm-org/openvm
pub fn verify_e2e_stark_proof(
    k: &CenoRecursionVerifierKeys<SC>,
    proof: &VmStarkProof<SC>,
    _expected_exe_commit: &Bn254Fr,
    _expected_vm_commit: &Bn254Fr,
) -> Result<AppExecutionCommit, String> {
    if proof.inner.per_air.len() < 3 {
        return Err("Invalid number of AIRs: expected at least 3".into());
    } else if proof.inner.per_air[0].air_id != PROGRAM_AIR_ID {
        return Err("Missing program AIR".into());
    } else if proof.inner.per_air[1].air_id != CONNECTOR_AIR_ID {
        return Err("Missing connector AIR".into());
    } else if proof.inner.per_air[2].air_id != PUBLIC_VALUES_AIR_ID {
        return Err("Missing public values AIR".into());
    }
    let public_values_air_proof_data = &proof.inner.per_air[2];

    let program_commit = proof.inner.commitments.main_trace[PROGRAM_CACHED_TRACE_INDEX].as_ref();
    let internal_commit: &[_; CHUNK] = &k.internal_commit.into();

    let (vm_vk, fri_params, vm_commit) = if program_commit == internal_commit {
        let internal_pvs: &InternalVmVerifierPvs<_> = public_values_air_proof_data
            .public_values
            .as_slice()
            .borrow();
        if internal_commit != &internal_pvs.extra_pvs.internal_program_commit {
            return Err(format!(
                "Invalid internal program commit: expected {:?}, got {:?}",
                internal_commit, internal_pvs.extra_pvs.internal_program_commit
            ));
        }
        (
            &k.internal_vm_vk,
            k.internal_fri_params,
            internal_pvs.extra_pvs.leaf_verifier_commit,
        )
    } else {
        (&k.leaf_vm_vk, k.leaf_fri_params, *program_commit)
    };
    let e = BabyBearPoseidon2Engine::new(fri_params);
    e.verify(vm_vk, &proof.inner)
        .expect("stark e2e proof verification should pass");

    let pvs: &VmVerifierPvs<_> =
        public_values_air_proof_data.public_values[..VmVerifierPvs::<u8>::width()].borrow();

    // _debug: AIR ordering
    // if let Some(exit_code) = pvs.connector.exit_code() {
    // if exit_code != 0 {
    // return Err(format!(
    // "Invalid exit code: expected 0, got {}",
    // exit_code
    // ));
    // }
    // } else {
    // return Err(format!("Program did not terminate"));
    // }

    let hasher = vm_poseidon2_hasher();
    let _public_values_root = hasher.merkle_root(&proof.user_public_values);
    // _debug: Public value commitment
    // if public_values_root != pvs.public_values_commit {
    // return Err(format!(
    // "Invalid public values root: expected {:?}, got {:?}",
    // pvs.public_values_commit,
    // public_values_root
    // ));
    // }

    let exe_commit = compute_exe_commit(
        &hasher,
        &pvs.app_commit,
        &pvs.memory.initial_root,
        pvs.connector.initial_pc,
    );
    let app_commit = AppExecutionCommit::from_field_commit(exe_commit, vm_commit);
    let _exe_commit_bn254 = app_commit.app_exe_commit.to_bn254();
    let _vm_commit_bn254 = app_commit.app_vm_commit.to_bn254();

    // _debug: execution commit checks
    // if exe_commit_bn254 != *expected_exe_commit {
    // return Err(eyre::eyre!(
    // "Invalid app exe commit: expected {:?}, got {:?}",
    // expected_exe_commit,
    // exe_commit_bn254
    // ));
    // } else if vm_commit_bn254 != *expected_vm_commit {
    // return Err(eyre::eyre!(
    // "Invalid app vm commit: expected {:?}, got {:?}",
    // expected_vm_commit,
    // vm_commit_bn254
    // ));
    // }
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
    if !zkvm_proofs.is_empty() {
        let zkvm_proof_input = ZKVMProofInput::from_proof(0usize, zkvm_proofs[0].clone(), &vk);

        // Pass in witness stream
        let mut witness_stream: Vec<Vec<F>> = Vec::new();
        witness_stream.extend(zkvm_proof_input.write());

        let poseidon2_max_constraint_degree: usize = 3;
        let mut config = NativeConfig::aggregation(0, poseidon2_max_constraint_degree);
        config.system.memory_config.max_access_adapter_n = 16;

        let exe = VmExe::new(program);

        let fri_params = standard_fri_params_with_100_bits_conjectured_security(1);
        let vb = NativeBuilder::default();

        air_test_impl::<BabyBearPoseidon2Engine, _>(
            fri_params,
            vb,
            config,
            exe,
            witness_stream,
            1,
            true,
        )
        .unwrap();

        // _debug
        // let engine = BabyBearPoseidon2Engine::new(fri_params);
        // let (mut vm, pk) = VirtualMachine::new_with_keygen(engine, vb, config).expect("create vm");
        // let vk = pk.get_vk();
        // vm.verify(&vk, &proofs)
        //     .expect("segment proofs should verify");
    }
}

#[cfg(test)]
mod tests {
    use super::verify_e2e_stark_proof;
    use crate::{
        aggregation::{CenoAggregationProver, SC, verify_proofs},
        zkvm_verifier::binding::E,
    };
    use ceno_zkvm::{
        e2e::verify,
        scheme::{ZKVMProof, verifier::ZKVMVerifier},
        structs::ZKVMVerifyingKey,
    };
    use mpcs::{Basefold, BasefoldRSParams};
    use openvm_stark_backend::proof::Proof;
    use openvm_stark_sdk::{config::setup_tracing_with_log_level, p3_bn254_fr::Bn254Fr};
    use p3::field::FieldAlgebra;
    use std::fs::File;

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

        let mut agg_prover = CenoAggregationProver::from_base_vk(vk);
        let root_stark_proof = agg_prover.generate_root_proof(zkvm_proofs);

        // _debug
        verify_e2e_stark_proof(
            &agg_prover.vk,
            &root_stark_proof,
            &Bn254Fr::ZERO,
            &Bn254Fr::ZERO,
        )
        .expect("Verify e2e stark proof should pass");
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

    pub fn internal_aggregation_inner_thread() {
        setup_tracing_with_log_level(tracing::Level::WARN);

        let vk_path = "./src/imported/vk.bin";
        let vk: ZKVMVerifyingKey<E, Basefold<E, BasefoldRSParams>> =
            bincode::deserialize_from(File::open(vk_path).expect("Failed to open vk file"))
                .expect("Failed to deserialize vk file");

        let mut agg_prover = CenoAggregationProver::from_base_vk(vk);

        // Load exported leaf proofs
        let leaf_proof_0: Proof<SC> = bincode::deserialize_from(
            File::open("./leaf_proof_0.bin").expect("Failed to open leaf_proof_0.bin"),
        )
        .expect("Failed to deserialize leaf_proof_0");
        let leaf_proof_1: Proof<SC> = bincode::deserialize_from(
            File::open("./leaf_proof_1.bin").expect("Failed to open leaf_proof_1.bin"),
        )
        .expect("Failed to deserialize leaf_proof_1");

        let leaf_proofs = vec![leaf_proof_0, leaf_proof_1];
        let _root_proof = agg_prover.aggregate_internal_proofs(leaf_proofs);
        println!("Internal aggregation completed successfully");
    }

    #[test]
    #[ignore = "need to generate proof first"]
    pub fn test_aggregation() {
        let stack_size = 256 * 1024 * 1024; // 64 MB

        let handler = std::thread::Builder::new()
            .stack_size(stack_size)
            .spawn(aggregation_inner_thread)
            .expect("Failed to spawn thread");

        handler.join().expect("Thread panicked");
    }

    #[test]
    #[ignore = "need to generate proof first"]
    pub fn test_internal_aggregation() {
        let stack_size = 256 * 1024 * 1024;

        let handler = std::thread::Builder::new()
            .stack_size(stack_size)
            .spawn(internal_aggregation_inner_thread)
            .expect("Failed to spawn thread");

        handler.join().expect("Thread panicked");
    }

    #[test]
    #[ignore = "need to generate proof first"]
    pub fn test_single() {
        let stack_size = 256 * 1024 * 1024; // 64 MB

        let handler = std::thread::Builder::new()
            .stack_size(stack_size)
            .spawn(verify_single_inner_thread)
            .expect("Failed to spawn thread");

        handler.join().expect("Thread panicked");
    }

    #[test]
    #[ignore = "need to generate proof first"]
    pub fn test_single_rust_verifier() {
        let stack_size = 256 * 1024 * 1024; // 64 MB

        let handler = std::thread::Builder::new()
            .stack_size(stack_size)
            .spawn(verify_single_rust_verifier_inner_thread)
            .expect("Failed to spawn thread");

        handler.join().expect("Thread panicked");
    }
}
