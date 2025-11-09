use crate::basefold_verifier::basefold::BasefoldCommitment;
use crate::tower_verifier::binding::{IOPProverMessage, IOPProverMessageVec};
use crate::zkvm_verifier::binding::{
    GKRProofInput, LayerProofInput, SumcheckLayerProofInput, TowerProofInput, ZKVMChipProofInput,
    ZKVMProofInput, E, F,
};

use crate::zkvm_verifier::verifier::verify_zkvm_proof;
use multilinear_extensions::util::ceil_log2;
use ceno_zkvm::scheme::ZKVMProof;
use ceno_zkvm::structs::ZKVMVerifyingKey;
use ff_ext::BabyBearExt4;
use mpcs::{Basefold, BasefoldRSParams};
use openvm_circuit::arch::instructions::program::Program;
use openvm_native_compiler::{
    asm::AsmBuilder,
    conversion::{convert_program, CompilerOptions},
    prelude::AsmCompiler,
};
use openvm_native_recursion::hints::Hintable;
use openvm_stark_backend::config::StarkGenericConfig;
use openvm_stark_sdk::config::baby_bear_poseidon2::BabyBearPoseidon2Config;

type SC = BabyBearPoseidon2Config;
type EF = <SC as StarkGenericConfig>::Challenge;

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

#[cfg(test)]
mod tests {
    use crate::e2e::build_zkvm_verifier_program;
    use crate::zkvm_verifier::binding::{E, F};
    use ceno_zkvm::scheme::ZKVMProof;
    use ceno_zkvm::structs::ZKVMVerifyingKey;
    use mpcs::{Basefold, BasefoldRSParams};
    use openvm_circuit::arch::verify_single;
    use openvm_circuit::arch::VirtualMachine;
    use openvm_circuit::arch::{SystemConfig, VmExecutor};
    use openvm_native_circuit::{Native, NativeConfig};
    use openvm_native_recursion::hints::Hintable;
    use openvm_stark_sdk::config::{
        baby_bear_poseidon2::BabyBearPoseidon2Engine,
        fri_params::standard_fri_params_with_100_bits_conjectured_security,
        setup_tracing_with_log_level, FriParameters,
    };
    use openvm_stark_sdk::engine::StarkFriEngine;
    use std::fs::File;

    pub fn inner_test_thread() {
        setup_tracing_with_log_level(tracing::Level::WARN);

        let proof_path = "./src/imported/proof.bin";
        let vk_path = "./src/imported/vk.bin";

        let zkvm_proofs: Vec<ZKVMProof<E, Basefold<E, BasefoldRSParams>>> =
            bincode::deserialize_from(File::open(proof_path).expect("Failed to open proof file"))
                .expect("Failed to deserialize proof file");

        let vk: ZKVMVerifyingKey<E, Basefold<E, BasefoldRSParams>> =
            bincode::deserialize_from(File::open(vk_path).expect("Failed to open vk file"))
                .expect("Failed to deserialize vk file");

        let program = build_zkvm_verifier_program(&vk);

        /* _debug: 
        // Construct zkvm proof input
        let zkvm_proof_input = parse_zkvm_proof_import(zkvm_proof, &vk);

        // Pass in witness stream
        let mut witness_stream: Vec<Vec<F>> = Vec::new();
        witness_stream.extend(zkvm_proof_input.write());

        let mut system_config = SystemConfig::default()
            .with_public_values(4)
            .with_max_segment_len((1 << 25) - 100);
        system_config.profiling = true;
        let config = NativeConfig::new(system_config, Native);

        let executor = VmExecutor::<F, NativeConfig>::new(config);

        let res = executor
            .execute_and_then(
                program.clone(),
                witness_stream.clone(),
                |_, seg| Ok(seg),
                |err| err,
            )
            .unwrap();

        for (i, seg) in res.iter().enumerate() {
            println!("=> segment {:?} metrics: {:?}", i, seg.metrics);
        }

        let poseidon2_max_constraint_degree = 3;
        let log_blowup = 1;

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
    pub fn test_zkvm_verifier() {
        let stack_size = 64 * 1024 * 1024; // 64 MB

        let handler = std::thread::Builder::new()
            .stack_size(stack_size)
            .spawn(inner_test_thread)
            .expect("Failed to spawn thread");

        handler.join().expect("Thread panicked");
    }
}
