use std::time::Instant;

use ark_std::test_rng;
use ceno_zkvm::{
    instructions::riscv::arith::AddInstruction, scheme::prover::ZKVMProver,
    tables::ProgramTableCircuit,
};
use clap::Parser;
use const_env::from_env;

use ceno_emul::{ByteAddr, InsnKind::ADD, StepRecord, VMState, CENO_PLATFORM};
use ceno_zkvm::{
    scheme::verifier::ZKVMVerifier,
    structs::{ZKVMConstraintSystem, ZKVMFixedTraces, ZKVMWitnesses},
    tables::U16TableCircuit,
};
use ff_ext::ff::Field;
use goldilocks::GoldilocksExt2;
use sumcheck::util::is_power_of_2;
use tracing_flame::FlameLayer;
use tracing_subscriber::{fmt, layer::SubscriberExt, EnvFilter, Registry};
use transcript::Transcript;

#[from_env]
const RAYON_NUM_THREADS: usize = 8;

// For now, we assume registers
//  - x0 is not touched,
//  - x1 is initialized to 1,
//  - x2 is initialized to -1,
//  - x3 is initialized to loop bound.
// we use x4 to hold the acc_sum.
#[allow(clippy::unusual_byte_groupings)]
const PROGRAM_ADD_LOOP: [u32; 4] = [
    // func7   rs2   rs1   f3  rd    opcode
    0b_0000000_00100_00001_000_00100_0110011, // add x4, x4, x1 <=> addi x4, x4, 1
    0b_0000000_00011_00010_000_00011_0110011, // add x3, x3, x2 <=> addi x3, x3, -1
    0b_1_111111_00000_00011_001_1100_1_1100011, // bne x3, x0, -8
    0b_000000000000_00000_000_00000_1110011,  // ecall halt
];

/// Simple program to greet a person
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// start round
    #[arg(short, long, default_value_t = 8)]
    start: u8,

    /// end round
    #[arg(short, long, default_value_t = 22)]
    end: u8,
}

fn main() {
    let args = Args::parse();
    type E = GoldilocksExt2;

    let max_threads = {
        if !is_power_of_2(RAYON_NUM_THREADS) {
            #[cfg(not(feature = "non_pow2_rayon_thread"))]
            {
                panic!(
                    "add --features non_pow2_rayon_thread to enable unsafe feature which support non pow of 2 rayon thread pool"
                );
            }

            #[cfg(feature = "non_pow2_rayon_thread")]
            {
                use sumcheck::{local_thread_pool::create_local_pool_once, util::ceil_log2};
                let max_thread_id = 1 << ceil_log2(RAYON_NUM_THREADS);
                create_local_pool_once(1 << ceil_log2(RAYON_NUM_THREADS), true);
                max_thread_id
            }
        } else {
            RAYON_NUM_THREADS
        }
    };

    let (flame_layer, _guard) = FlameLayer::with_file("./tracing.folded").unwrap();
    let subscriber = Registry::default()
        .with(
            fmt::layer()
                .compact()
                .with_thread_ids(false)
                .with_thread_names(false),
        )
        .with(EnvFilter::from_default_env())
        .with(flame_layer.with_threads_collapsed(true));
    tracing::subscriber::set_global_default(subscriber).unwrap();

    // keygen
    let mut zkvm_cs = ZKVMConstraintSystem::default();
    let add_config = zkvm_cs.register_opcode_circuit::<AddInstruction<E>>();
    let range_config = zkvm_cs.register_table_circuit::<U16TableCircuit<E>>();
    let prog_config = zkvm_cs.register_table_circuit::<ProgramTableCircuit<E>>();

    let mut zkvm_fixed_traces = ZKVMFixedTraces::default();
    zkvm_fixed_traces.register_opcode_circuit::<AddInstruction<E>>(&zkvm_cs);
    zkvm_fixed_traces.register_table_circuit::<U16TableCircuit<E>>(
        &zkvm_cs,
        range_config.clone(),
        &(),
    );
    zkvm_fixed_traces.register_table_circuit::<ProgramTableCircuit<E>>(
        &zkvm_cs,
        prog_config.clone(),
        &PROGRAM_ADD_LOOP,
    );

    let pk = zkvm_cs
        .clone()
        .key_gen(zkvm_fixed_traces)
        .expect("keygen failed");
    let vk = pk.get_vk();

    // proving
    let prover = ZKVMProver::new(pk);
    let verifier = ZKVMVerifier::new(vk);

    for instance_num_vars in args.start..args.end {
        let step_loop = 1 << (instance_num_vars - 1); // 1 step in loop contribute to 2 add instance
        let mut vm = VMState::new(CENO_PLATFORM);
        let pc_start = ByteAddr(CENO_PLATFORM.pc_start()).waddr();

        // init vm.x1 = 1, vm.x2 = -1, vm.x3 = num_instances
        // vm.x4 += vm.x1
        vm.init_register_unsafe(1usize, 1);
        vm.init_register_unsafe(2usize, u32::MAX); // -1 in two's complement
        vm.init_register_unsafe(3usize, step_loop as u32);
        for (i, inst) in PROGRAM_ADD_LOOP.iter().enumerate() {
            vm.init_memory(pc_start + i, *inst);
        }
        let records = vm
            .iter_until_success()
            .collect::<Result<Vec<StepRecord>, _>>()
            .expect("vm exec failed")
            .into_iter()
            .filter(|record| record.insn().kind().1 == ADD)
            .collect::<Vec<_>>();
        tracing::info!("tracer generated {} ADD records", records.len());

        let mut zkvm_witness = ZKVMWitnesses::default();
        // assign opcode circuits
        zkvm_witness
            .assign_opcode_circuit::<AddInstruction<E>>(&zkvm_cs, &add_config, records)
            .unwrap();
        zkvm_witness.finalize_lk_multiplicities();
        // assign table circuits
        zkvm_witness
            .assign_table_circuit::<U16TableCircuit<E>>(&zkvm_cs, &range_config, &())
            .unwrap();
        zkvm_witness
            .assign_table_circuit::<ProgramTableCircuit<E>>(
                &zkvm_cs,
                &prog_config,
                &PROGRAM_ADD_LOOP.len(),
            )
            .unwrap();

        let timer = Instant::now();

        let transcript = Transcript::new(b"riscv");
        let mut rng = test_rng();
        let real_challenges = [E::random(&mut rng), E::random(&mut rng)];

        let zkvm_proof = prover
            .create_proof(zkvm_witness, max_threads, transcript, &real_challenges)
            .expect("create_proof failed");

        println!(
            "AddInstruction::create_proof, instance_num_vars = {}, time = {}",
            instance_num_vars,
            timer.elapsed().as_secs_f64()
        );

        let transcript = Transcript::new(b"riscv");
        assert!(
            verifier
                .verify_proof(zkvm_proof, transcript, &real_challenges)
                .expect("verify proof return with error"),
        );
    }
}
