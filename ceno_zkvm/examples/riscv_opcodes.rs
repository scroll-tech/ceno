use std::{iter, panic, time::Instant};

use ceno_zkvm::{
    instructions::riscv::{arith::AddInstruction, branch::BltuInstruction, jump::JalInstruction},
    scheme::prover::ZKVMProver,
    tables::ProgramTableCircuit,
};
use clap::Parser;
use const_env::from_env;

use ceno_emul::{
    ByteAddr,
    InsnKind::{ADD, BLTU, EANY, JAL},
    StepRecord, VMState, CENO_PLATFORM,
};
use ceno_zkvm::{
    instructions::riscv::ecall::HaltInstruction,
    scheme::{constants::MAX_NUM_VARIABLES, verifier::ZKVMVerifier, PublicValues},
    structs::{ZKVMConstraintSystem, ZKVMFixedTraces, ZKVMWitnesses},
    tables::{AndTableCircuit, LtuTableCircuit, U16TableCircuit},
};
use ff_ext::ff::Field;
use goldilocks::GoldilocksExt2;
use mpcs::{Basefold, BasefoldRSParams, PolynomialCommitmentScheme};
use rand_chacha::ChaCha8Rng;
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
const ECALL_HALT: u32 = 0b_000000000000_00000_000_00000_1110011;
#[allow(clippy::unusual_byte_groupings)]
const PROGRAM_CODE: [u32; 5] = [
    // func7   rs2   rs1   f3  rd    opcode
    0b_0000000_00100_00001_000_00100_0110011, // add x4, x4, x1 <=> addi x4, x4, 1
    0b_0000000_00011_00010_000_00011_0110011, // add x3, x3, x2 <=> addi x3, x3, -1
    0b_1_111111_00011_00000_110_1100_1_1100011, // bltu x0, x3, -8
    0b_0_0000000010_0_00000000_00001_1101111, // jal x1, 4
    ECALL_HALT,                               // ecall halt
];

/// Simple program to greet a person
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// start round
    #[arg(short, long, default_value_t = 8)]
    start: u8,

    /// end round
    #[arg(short, long, default_value_t = 9)]
    end: u8,
}

fn main() {
    let args = Args::parse();
    type E = GoldilocksExt2;
    type Pcs = Basefold<GoldilocksExt2, BasefoldRSParams, ChaCha8Rng>;

    let max_threads = {
        if !RAYON_NUM_THREADS.is_power_of_two() {
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
    let pcs_param = Pcs::setup(1 << MAX_NUM_VARIABLES).expect("Basefold PCS setup");
    let (pp, vp) = Pcs::trim(&pcs_param, 1 << MAX_NUM_VARIABLES).expect("Basefold trim");
    let mut zkvm_cs = ZKVMConstraintSystem::default();
    // opcode circuits
    let add_config = zkvm_cs.register_opcode_circuit::<AddInstruction<E>>();
    let bltu_config = zkvm_cs.register_opcode_circuit::<BltuInstruction>();
    let jal_config = zkvm_cs.register_opcode_circuit::<JalInstruction<E>>();
    let halt_config = zkvm_cs.register_opcode_circuit::<HaltInstruction<E>>();
    // tables
    let u16_range_config = zkvm_cs.register_table_circuit::<U16TableCircuit<E>>();
    let and_config = zkvm_cs.register_table_circuit::<AndTableCircuit<E>>();
    let ltu_config = zkvm_cs.register_table_circuit::<LtuTableCircuit<E>>();
    let prog_config = zkvm_cs.register_table_circuit::<ProgramTableCircuit<E>>();

    let program_code: Vec<u32> = PROGRAM_CODE
        .iter()
        .cloned()
        .chain(iter::repeat(ECALL_HALT))
        .take(512)
        .collect();
    let mut zkvm_fixed_traces = ZKVMFixedTraces::default();
    zkvm_fixed_traces.register_opcode_circuit::<AddInstruction<E>>(&zkvm_cs);
    zkvm_fixed_traces.register_opcode_circuit::<BltuInstruction>(&zkvm_cs);
    zkvm_fixed_traces.register_opcode_circuit::<JalInstruction<E>>(&zkvm_cs);
    zkvm_fixed_traces.register_opcode_circuit::<HaltInstruction<E>>(&zkvm_cs);

    zkvm_fixed_traces.register_table_circuit::<U16TableCircuit<E>>(
        &zkvm_cs,
        u16_range_config.clone(),
        &(),
    );
    zkvm_fixed_traces.register_table_circuit::<AndTableCircuit<E>>(
        &zkvm_cs,
        and_config.clone(),
        &(),
    );
    zkvm_fixed_traces.register_table_circuit::<LtuTableCircuit<E>>(
        &zkvm_cs,
        ltu_config.clone(),
        &(),
    );
    zkvm_fixed_traces.register_table_circuit::<ProgramTableCircuit<E>>(
        &zkvm_cs,
        prog_config.clone(),
        &program_code,
    );

    let pk = zkvm_cs
        .clone()
        .key_gen::<Pcs>(pp, vp, zkvm_fixed_traces)
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
        for (i, inst) in program_code.iter().enumerate() {
            vm.init_memory(pc_start + i, *inst);
        }

        let all_records = vm
            .iter_until_halt()
            .collect::<Result<Vec<StepRecord>, _>>()
            .expect("vm exec failed")
            .into_iter()
            .collect::<Vec<_>>();
        let mut add_records = Vec::new();
        let mut bltu_records = Vec::new();
        let mut jal_records = Vec::new();
        let mut halt_records = Vec::new();
        all_records.into_iter().for_each(|record| {
            let kind = record.insn().kind().1;
            match kind {
                ADD => add_records.push(record),
                BLTU => bltu_records.push(record),
                JAL => jal_records.push(record),
                EANY => {
                    if record.rs1().unwrap().value == CENO_PLATFORM.ecall_halt() {
                        halt_records.push(record);
                    }
                }
                _ => {}
            }
        });

        assert_eq!(halt_records.len(), 1);
        let exit_code = halt_records[0].rs2().unwrap().value;
        let pi = PublicValues::new(exit_code, 0);

        tracing::info!(
            "tracer generated {} ADD records, {} BLTU records, {} JAL records",
            add_records.len(),
            bltu_records.len(),
            jal_records.len(),
        );

        let mut zkvm_witness = ZKVMWitnesses::default();
        // assign opcode circuits
        zkvm_witness
            .assign_opcode_circuit::<AddInstruction<E>>(&zkvm_cs, &add_config, add_records)
            .unwrap();
        zkvm_witness
            .assign_opcode_circuit::<BltuInstruction>(&zkvm_cs, &bltu_config, bltu_records)
            .unwrap();
        zkvm_witness
            .assign_opcode_circuit::<JalInstruction<E>>(&zkvm_cs, &jal_config, jal_records)
            .unwrap();
        zkvm_witness
            .assign_opcode_circuit::<HaltInstruction<E>>(&zkvm_cs, &halt_config, halt_records)
            .unwrap();

        zkvm_witness.finalize_lk_multiplicities();
        // assign table circuits
        zkvm_witness
            .assign_table_circuit::<U16TableCircuit<E>>(&zkvm_cs, &u16_range_config, &())
            .unwrap();
        zkvm_witness
            .assign_table_circuit::<AndTableCircuit<E>>(&zkvm_cs, &and_config, &())
            .unwrap();
        zkvm_witness
            .assign_table_circuit::<LtuTableCircuit<E>>(&zkvm_cs, &ltu_config, &())
            .unwrap();
        zkvm_witness
            .assign_table_circuit::<ProgramTableCircuit<E>>(
                &zkvm_cs,
                &prog_config,
                &program_code.len(),
            )
            .unwrap();

        let timer = Instant::now();

        let transcript = Transcript::new(b"riscv");
        let mut zkvm_proof = prover
            .create_proof(zkvm_witness, pi, max_threads, transcript)
            .expect("create_proof failed");

        println!(
            "riscv_opcodes::create_proof, instance_num_vars = {}, time = {}",
            instance_num_vars,
            timer.elapsed().as_secs_f64()
        );

        let transcript = Transcript::new(b"riscv");
        assert!(
            verifier
                .verify_proof(zkvm_proof.clone(), transcript)
                .expect("verify proof return with error"),
        );

        let transcript = Transcript::new(b"riscv");
        // change public input maliciously should cause verifier to reject proof
        zkvm_proof.pv[0] = <GoldilocksExt2 as ff_ext::ExtensionField>::BaseField::ONE;
        zkvm_proof.pv[1] = <GoldilocksExt2 as ff_ext::ExtensionField>::BaseField::ONE;

        // capture panic message, if have
        let default_hook = panic::take_hook();
        panic::set_hook(Box::new(|_info| {
            // by default it will print msg to stdout/stderr
            // we override it to avoid print msg since we will capture the msg by our own
        }));
        let result = panic::catch_unwind(|| verifier.verify_proof(zkvm_proof, transcript));
        panic::set_hook(default_hook);
        match result {
            Ok(res) => {
                res.expect_err("verify proof should return with error");
            }
            Err(err) => {
                let msg: String = if let Some(message) = err.downcast_ref::<&str>() {
                    message.to_string()
                } else if let Some(message) = err.downcast_ref::<String>() {
                    message.to_string()
                } else if let Some(message) = err.downcast_ref::<&String>() {
                    message.to_string()
                } else {
                    unreachable!()
                };

                if !msg.starts_with("0th round's prover message is not consistent with the claim") {
                    println!("unknown panic {msg:?}");
                    panic::resume_unwind(err);
                };
            }
        };
    }
}
