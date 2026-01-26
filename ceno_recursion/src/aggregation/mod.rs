use crate::{
    aggregation::{root::CenoRootVmVerifierConfig, statics::StaticProverVerifier},
    zkvm_verifier::{
        binding::{E, F, ZKVMProofInput, ZKVMProofInputVariable},
        verifier::verify_zkvm_proof,
    },
};
use ceno_zkvm::{
    instructions::riscv::constants::{END_PC_IDX, EXIT_CODE_IDX, INIT_PC_IDX},
    scheme::{ZKVMProof, constants::SEPTIC_EXTENSION_DEGREE},
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
use openvm_stark_backend::{
    config::{PcsProverData, Val},
    verifier::VerificationError,
};

use internal::InternalVmVerifierConfig;
use openvm_continuations::{
    C,
    verifier::{internal::types::InternalVmVerifierInput, root::types::RootVmVerifierInput},
};
#[cfg(feature = "gpu")]
use openvm_cuda_backend::engine::GpuBabyBearPoseidon2Engine as BabyBearPoseidon2Engine;
use openvm_native_circuit::{NativeBuilder, NativeConfig, NativeCpuBuilder};
use openvm_native_compiler::{
    asm::AsmBuilder,
    conversion::{CompilerOptions, convert_program},
    prelude::*,
};
use openvm_native_recursion::{halo2::RawEvmProof, hints::Hintable};
use openvm_sdk::{
    SC,
    config::DEFAULT_NUM_CHILDREN_INTERNAL,
    keygen::{RootVerifierProvingKey, perm::AirIdPermutation},
    prover::{
        RootVerifierLocalProver,
        vm::{new_local_prover, types::VmProvingKey},
    },
    util::check_max_constraint_degrees,
};
use openvm_stark_backend::{
    config::{Com, StarkGenericConfig},
    engine::StarkEngine,
    proof::Proof,
};
#[cfg(not(feature = "gpu"))]
use openvm_stark_sdk::config::baby_bear_poseidon2::BabyBearPoseidon2Engine;
use openvm_stark_sdk::{
    config::{
        FriParameters, baby_bear_poseidon2::BabyBearPoseidon2Config,
        baby_bear_poseidon2_root::BabyBearPoseidon2RootEngine,
        fri_params::standard_fri_params_with_100_bits_conjectured_security,
    },
    engine::StarkFriEngine,
    openvm_stark_backend::keygen::types::MultiStarkVerifyingKey,
};
use p3::field::FieldAlgebra;
use serde::{Deserialize, Serialize};
use std::{fs::File, path::Path, sync::Arc, time::Instant};
pub type RecPcs = Basefold<E, BasefoldRSParams>;
use crate::aggregation::types::{InternalVmVerifierPvs, VmVerifierPvs};
use anyhow::Result;
use openvm_circuit::arch::{
    PUBLIC_VALUES_AIR_ID, PreflightExecutionOutput, SingleSegmentVmProver, instructions::exe::VmExe,
};
use openvm_continuations::RootSC;
use openvm_native_circuit::extension::Native;
use openvm_native_compiler::{
    asm::AsmConfig,
    ir::{Builder, Config, Felt},
};

mod internal;
mod root;
mod statics;
mod types;

pub type InnerConfig = AsmConfig<F, E>;
pub const LEAF_LOG_BLOWUP: usize = 1;
pub const INTERNAL_LOG_BLOWUP: usize = 2;
pub const ROOT_LOG_BLOWUP: usize = 3;
pub const ROOT_MAX_CONSTRAINT_DEG: usize = (1 << ROOT_LOG_BLOWUP) + 1;
pub const ROOT_NUM_PUBLIC_VALUES: usize = 15;
pub const SBOX_SIZE: usize = 7;
const VM_MAX_TRACE_HEIGHTS: &[u32] = &[
    4194304, 4, 128, 2097152, 8388608, 4194304, 262144, 8388608, 16777216, 2097152, 16777216,
    2097152, 8388608, 262144, 2097152, 1048576, 4194304, 1048576, 262144,
];
const ROOT_VM_MAX_TRACE_HEIGHTS: &[u32] = &[
    4194304, 4, 128, 2097152, 8388608, 4194304, 262144, 2097152, 16777216, 2097152, 8388608,
    262144, 2097152, 1048576, 4194304, 1048576, 262144,
];
pub struct CenoAggregationProver {
    pub base_vk: ZKVMVerifyingKey<E, Basefold<E, BasefoldRSParams>>,
    pub leaf_prover: VmInstance<BabyBearPoseidon2Engine, NativeBuilder>,
    pub internal_prover: VmInstance<BabyBearPoseidon2Engine, NativeBuilder>,
    pub root_prover: VmInstance<BabyBearPoseidon2RootEngine, NativeCpuBuilder>,
    pub permuted_root_prover: Option<RootVerifierLocalProver>,
    pub static_prover_verifier: StaticProverVerifier,
    pub vk: CenoRecursionVerifierKeys<BabyBearPoseidon2Config>,
    pub pk: CenoRecursionProvingKeys<BabyBearPoseidon2Config, NativeConfig>,
}

impl CenoAggregationProver {
    pub fn new(
        base_vk: ZKVMVerifyingKey<E, Basefold<E, BasefoldRSParams>>,
        leaf_prover: VmInstance<BabyBearPoseidon2Engine, NativeBuilder>,
        internal_prover: VmInstance<BabyBearPoseidon2Engine, NativeBuilder>,
        root_prover: VmInstance<BabyBearPoseidon2RootEngine, NativeCpuBuilder>,
        pk: CenoRecursionProvingKeys<BabyBearPoseidon2Config, NativeConfig>,
    ) -> Self {
        Self {
            base_vk,
            leaf_prover,
            internal_prover,
            root_prover,
            permuted_root_prover: None,
            static_prover_verifier: StaticProverVerifier::new(),
            vk: pk.get_vk(),
            pk,
        }
    }

    pub fn from_base_vk(vk: ZKVMVerifyingKey<E, Basefold<E, BasefoldRSParams>>) -> Self {
        let vb = NativeBuilder::default();
        let [leaf_fri_params, internal_fri_params, root_fri_params] =
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
            native: Native(true),
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
            native: Native(true),
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
        let internal_vm_verifier_commit: [F; DIGEST_SIZE] =
            internal_committed_exe.get_program_commit().into();
        let internal_prover = new_local_prover::<BabyBearPoseidon2Engine, NativeBuilder>(
            vb.clone(),
            &internal_vm_pk,
            internal_committed_exe.exe.clone(),
        )
        .expect("internal prover");

        // Root prover
        let root_vm_config = NativeConfig {
            system: SystemConfig::new(
                SBOX_SIZE.min(ROOT_MAX_CONSTRAINT_DEG),
                MemoryConfig {
                    max_access_adapter_n: 8,
                    ..Default::default()
                },
                ROOT_NUM_PUBLIC_VALUES,
            )
            .without_continuations()
            .with_max_segment_len((1 << 24) - 100)
            .with_profiling(),
            native: Native(false),
        };

        let mut root_engine = BabyBearPoseidon2RootEngine::new(root_fri_params);
        root_engine.max_constraint_degree = ROOT_MAX_CONSTRAINT_DEG;

        let (root_vm, root_vm_pk) = VirtualMachine::<_, NativeCpuBuilder>::new_with_keygen(
            root_engine,
            Default::default(),
            root_vm_config.clone(),
        )
        .expect("root keygen");
        let root_program = CenoRootVmVerifierConfig {
            leaf_fri_params,
            internal_fri_params,
            num_user_public_values: ROOT_NUM_PUBLIC_VALUES,
            internal_vm_verifier_commit,
            compiler_options: CompilerOptions::default().with_cycle_tracker(),
        }
        .build_program(&leaf_vm_vk, &internal_vm_vk);
        let root_committed_exe = Arc::new(VmCommittedExe::<RootSC>::commit(
            root_program.into(),
            root_vm.engine.config().pcs(),
        ));
        let root_vm_pk = Arc::new(VmProvingKey {
            fri_params: root_fri_params,
            vm_config: root_vm_config,
            vm_pk: root_vm_pk,
        });
        let root_prover = new_local_prover::<BabyBearPoseidon2RootEngine, NativeCpuBuilder>(
            Default::default(),
            &root_vm_pk,
            root_committed_exe.exe.clone(),
        )
        .expect("root prover");

        // Recursion keys
        let vk = CenoRecursionVerifierKeys {
            leaf_vm_vk,
            leaf_fri_params: leaf_vm_pk.fri_params,
            internal_vm_vk,
            internal_fri_params: internal_vm_pk.fri_params,
            internal_commit: internal_committed_exe.get_program_commit(),
            root_vm_vk: root_vm_pk.vm_pk.get_vk(),
        };
        let pk = CenoRecursionProvingKeys {
            leaf_vm_pk,
            leaf_committed_exe,
            internal_vm_pk,
            internal_committed_exe,
            root_vm_pk,
            root_committed_exe,
            permuted_root_pk: None,
        };

        Self {
            base_vk: leaf_vm_verifier_config.vk,
            leaf_prover,
            internal_prover,
            root_prover,
            permuted_root_prover: None,
            static_prover_verifier: StaticProverVerifier::new(),
            vk,
            pk,
        }
    }

    pub fn generate_root_proof(
        &mut self,
        base_proofs: Vec<ZKVMProof<BabyBearExt4, Basefold<E, BasefoldRSParams>>>,
    ) -> Proof<RootSC> {
        let aggregation_start_timestamp = Instant::now();

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

                // _debug: export
                // let file =
                // File::create(format!("leaf_proof_{:?}.bin", proof_idx)).expect("Create export proof file");
                // bincode::serialize_into(file, &leaf_proof).expect("failed to serialize leaf proof");

                println!(
                    "Aggregation - Completed leaf proof (idx: {:?}) at: {:?}, public values: {:?}",
                    proof_idx,
                    aggregation_start_timestamp.elapsed(),
                    leaf_proof.per_air[PUBLIC_VALUES_AIR_ID].public_values,
                );

                leaf_proof
            })
            .collect::<Vec<_>>();

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
                (*self.internal_prover.program_commitment()).into(),
                &proofs,
                DEFAULT_NUM_CHILDREN_INTERNAL,
            );

            let layer_proofs: Vec<Proof<_>> = internal_inputs
                .into_iter()
                .map(|input| {
                    internal_node_idx += 1;
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
                        aggregation_start_timestamp.elapsed()
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
            aggregation_start_timestamp.elapsed()
        );
        println!("Aggregation - Final height: {:?}", internal_node_height);

        let last_internal = proofs.pop().unwrap();

        // Export last internal proof
        let file = File::create(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("src/exports/internal_proof.bin"),
        )
        .expect("Create export proof file");
        bincode::serialize_into(file, &last_internal).expect("failed to serialize internal proof");

        // _todo: possible multi-layer wrapping for reducing AIR heights

        let root_input = RootVmVerifierInput {
            proofs: vec![last_internal],
            public_values: user_public_values,
        };

        // Initiate the root prover with AIR height permutation
        // This step is skipped if the permuted root prover is already initiated
        // (either from a run of `generate_root_proof`` or with a dummy)
        let root_permutation_start_timestamp = Instant::now();
        if self.permuted_root_prover.is_none() {
            self.init_root_prover_with_permutation(&root_input);
        }
        println!(
            "Root - AIR-permuted root prover is not initiated. Completed initiation at: {:?}",
            root_permutation_start_timestamp.elapsed()
        );

        // Generate root proof (AIR-permuted)
        let root_start_timestamp = Instant::now();
        let air_permuted_root_proof = SingleSegmentVmProver::prove(
            self.permuted_root_prover.as_mut().unwrap(),
            root_input.write(),
            ROOT_VM_MAX_TRACE_HEIGHTS,
        )
        .expect("root proof");

        // Export root proof
        let file =
            File::create(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/exports/root_proof.bin"))
                .expect("Create export proof file");
        bincode::serialize_into(file, &air_permuted_root_proof)
            .expect("failed to serialize root proof");

        println!(
            "Root - Completed root proof at: {:?}",
            root_start_timestamp.elapsed()
        );

        air_permuted_root_proof
    }

    pub fn prove_static(&mut self, root_proof: &Proof<RootSC>) -> RawEvmProof {
        let halo2_proof = self
            .static_prover_verifier
            .prove_static(root_proof, &self.pk);

        // Export halo2 proof
        let file =
            File::create(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/exports/halo2_proof.bin"))
                .expect("Create export proof file");
        bincode::serialize_into(file, &halo2_proof).expect("failed to serialize halo2 proof");

        halo2_proof
    }

    pub fn verify_static(&mut self, halo2_proof: RawEvmProof) -> Result<()> {
        let _ = self.static_prover_verifier.verify_static(halo2_proof);
        Ok(())
    }

    pub fn init_root_prover_with_permutation(&mut self, root_input: &RootVmVerifierInput<SC>) {
        self.root_prover.reset_state(root_input.write());
        let mut trace_heights = ROOT_VM_MAX_TRACE_HEIGHTS.to_vec();

        let num_public_values = self.root_prover.vm.config().as_ref().num_public_values as u32;
        trace_heights[PUBLIC_VALUES_AIR_ID] = num_public_values;

        let state = self
            .root_prover
            .state
            .take()
            .expect("vm state should exist");
        let vm = &mut self.root_prover.vm;
        vm.transport_init_memory_to_device(&state.memory);

        let PreflightExecutionOutput {
            system_records,
            record_arenas,
            to_state: _,
        } = vm
            .execute_preflight(
                &mut self.root_prover.interpreter,
                state,
                None,
                &trace_heights,
            )
            .expect("execute preflight");

        let ctx = vm
            .generate_proving_ctx(system_records, record_arenas)
            .expect("proving context");
        let air_heights: Vec<u32> = ctx
            .into_iter()
            .map(|(_, air_ctx)| air_ctx.main_trace_height().next_power_of_two() as u32)
            .collect();
        let root_air_perm = AirIdPermutation::compute(&air_heights);
        let mut root_vm_pk = self.pk.root_vm_pk.vm_pk.clone();
        root_air_perm.permute(&mut root_vm_pk.per_air);

        let root_permuted_pk = RootVerifierProvingKey {
            vm_pk: Arc::new(VmProvingKey {
                fri_params: self.pk.root_vm_pk.fri_params,
                vm_config: self.pk.root_vm_pk.vm_config.clone(),
                vm_pk: root_vm_pk,
            }),
            root_committed_exe: self.pk.root_committed_exe.clone(),
            air_heights,
        };
        self.permuted_root_prover =
            Some(RootVerifierLocalProver::new(&root_permuted_pk).expect("create a root prover"));
        self.pk.permuted_root_pk = Some(Arc::new(root_permuted_pk));
    }
}

pub fn verify_root_proof(
    vk: &CenoRecursionVerifierKeys<SC>,
    root_proof: &Proof<RootSC>,
) -> Result<(), VerificationError> {
    let root_fri_params =
        FriParameters::standard_with_100_bits_conjectured_security(ROOT_LOG_BLOWUP);
    let root_engine = BabyBearPoseidon2RootEngine::new(root_fri_params);
    root_engine.verify(&vk.root_vm_vk, root_proof)?;
    Ok(())
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
            let ceno_leaf_input = CenoLeafVmVerifierInput::read(&mut builder);
            let stark_pvs = VmVerifierPvs::<Felt<F>>::uninit(&mut builder);

            builder.cycle_tracker_start("Verify Ceno ZKVM Proof");
            let zkvm_proof = ceno_leaf_input.proof;
            let raw_pi = zkvm_proof.raw_pi.clone();
            let shard_ec_sum = verify_zkvm_proof(&mut builder, zkvm_proof, &self.vk);
            builder.cycle_tracker_end("Verify Ceno ZKVM Proof");

            builder.cycle_tracker_start("PV Operations");
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

            for i in 0..SEPTIC_EXTENSION_DEGREE {
                let x_ext = builder.get(&shard_ec_sum.x.vs, i);
                let y_ext = builder.get(&shard_ec_sum.y.vs, i);
                let x_fs = builder.ext2felt(x_ext);
                let y_fs = builder.ext2felt(y_ext);
                let x = builder.get(&x_fs, 0);
                let y = builder.get(&y_fs, 0);

                builder.assign(&stark_pvs.shard_ram_connector.x[i], x);
                builder.assign(&stark_pvs.shard_ram_connector.y[i], y);
            }
            builder
                .if_eq(shard_ec_sum.is_infinity, Usize::from(1))
                .then_or_else(
                    |builder| {
                        builder.assign(&stark_pvs.shard_ram_connector.is_infinity, F::ONE);
                    },
                    |builder| {
                        builder.assign(&stark_pvs.shard_ram_connector.is_infinity, F::ZERO);
                    },
                );

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
    pub root_vm_vk: MultiStarkVerifyingKey<RootSC>,
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
    pub root_vm_pk: Arc<VmProvingKey<RootSC, VC>>,
    pub root_committed_exe: Arc<VmCommittedExe<RootSC>>,
    pub permuted_root_pk: Option<Arc<RootVerifierProvingKey>>,
}

impl<SC: StarkGenericConfig, VC> Clone for CenoRecursionProvingKeys<SC, VC> {
    fn clone(&self) -> Self {
        Self {
            leaf_vm_pk: self.leaf_vm_pk.clone(),
            leaf_committed_exe: self.leaf_committed_exe.clone(),
            internal_vm_pk: self.internal_vm_pk.clone(),
            internal_committed_exe: self.internal_committed_exe.clone(),
            root_vm_pk: self.root_vm_pk.clone(),
            root_committed_exe: self.root_committed_exe.clone(),
            permuted_root_pk: self.permuted_root_pk.clone(),
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
            root_vm_vk: self.root_vm_pk.vm_pk.get_vk(),
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
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        aggregation::{
            CenoAggregationProver, F, RootVmVerifierInput, ZKVMProofInput, verify_proofs,
        },
        zkvm_verifier::binding::E,
    };
    use ceno_zkvm::{
        e2e::verify,
        scheme::{ZKVMProof, verifier::ZKVMVerifier},
        structs::ZKVMVerifyingKey,
    };
    use mpcs::{Basefold, BasefoldRSParams};
    use openvm_sdk::SC;
    use openvm_stark_backend::proof::Proof;
    use openvm_stark_sdk::config::setup_tracing_with_log_level;
    use std::fs::File;

    pub fn root_proof_permutation_inner_thread() {
        setup_tracing_with_log_level(tracing::Level::WARN);

        let proof_path = "./src/imported/proof.bin";
        let vk_path = "./src/imported/vk.bin";
        let internal_proof_path = "./src/exports/internal_proof.bin";

        let zkvm_proofs: Vec<ZKVMProof<E, Basefold<E, BasefoldRSParams>>> =
            bincode::deserialize_from(File::open(proof_path).expect("Failed to open proof file"))
                .expect("Failed to deserialize proof file");

        let vk: ZKVMVerifyingKey<E, Basefold<E, BasefoldRSParams>> =
            bincode::deserialize_from(File::open(vk_path).expect("Failed to open vk file"))
                .expect("Failed to deserialize vk file");
        let mut agg_prover = CenoAggregationProver::from_base_vk(vk);

        // _debug
        let internal_proof: Proof<SC> = bincode::deserialize_from(
            File::open(internal_proof_path).expect("Failed to open proof file"),
        )
        .expect("Failed to deserialize proof file");

        let zkvm_proof_inputs: Vec<ZKVMProofInput> = zkvm_proofs
            .into_iter()
            .enumerate()
            .map(|(shard_id, p)| ZKVMProofInput::from_proof(shard_id, p, &agg_prover.base_vk))
            .collect();
        let user_public_values: Vec<F> = zkvm_proof_inputs
            .iter()
            .flat_map(|p| p.raw_pi.iter().flat_map(|v| v.clone()).collect::<Vec<F>>())
            .collect();
        let root_input = RootVmVerifierInput {
            proofs: vec![internal_proof],
            public_values: user_public_values,
        };

        agg_prover.init_root_prover_with_permutation(&root_input);
    }

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
        let root_proof = agg_prover.generate_root_proof(zkvm_proofs);
        let halo2_proof = agg_prover.prove_static(&root_proof);
        agg_prover
            .verify_static(halo2_proof)
            .expect("halo2 proof is ok");
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
    #[ignore = "need to generate proof first"]
    pub fn test_root_proof_permutation() {
        let stack_size = 256 * 1024 * 1024; // 64 MB

        let handler = std::thread::Builder::new()
            .stack_size(stack_size)
            .spawn(root_proof_permutation_inner_thread)
            .expect("Failed to spawn thread");

        handler.join().expect("Thread panicked");
    }

    #[test]
    #[ignore = "need to generate proof first"]
    pub fn test_aggregation() {
        let stack_size = 1024 * 1024 * 1024; // 512 MB

        let handler = std::thread::Builder::new()
            .stack_size(stack_size)
            .spawn(aggregation_inner_thread)
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
