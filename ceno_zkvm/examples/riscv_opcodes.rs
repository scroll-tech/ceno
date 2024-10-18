use std::{panic, time::Instant};

use ceno_zkvm::{
    Value, declare_program,
    instructions::riscv::{Rv32imConfig, constants::EXIT_PC},
    scheme::prover::ZKVMProver,
    state::GlobalState,
    tables::{ProgramTableCircuit, RegTableCircuit},
};
use clap::Parser;
use const_env::from_env;

use ceno_emul::{
    ByteAddr, CENO_PLATFORM, EmuContext, InsnKind::EANY, StepRecord, Tracer, VMState, WordAddr,
};
use ceno_zkvm::{
    scheme::{PublicValues, constants::MAX_NUM_VARIABLES, verifier::ZKVMVerifier},
    structs::{ZKVMConstraintSystem, ZKVMFixedTraces, ZKVMWitnesses},
};
use ff_ext::ff::Field;
use goldilocks::GoldilocksExt2;
use itertools::Itertools;
use mpcs::{Basefold, BasefoldRSParams, PolynomialCommitmentScheme};
use rand_chacha::ChaCha8Rng;
use tracing_flame::FlameLayer;
use tracing_subscriber::{EnvFilter, Registry, fmt, layer::SubscriberExt};
use transcript::Transcript;

#[from_env]
const RAYON_NUM_THREADS: usize = 8;

const PROGRAM_SIZE: usize = 512;
// For now, we assume registers
//  - x0 is not touched,
//  - x1 is initialized to 1,
//  - x2 is initialized to -1,
//  - x3 is initialized to loop bound.
// we use x4 to hold the acc_sum.
#[allow(clippy::unusual_byte_groupings)]
const ECALL_HALT: u32 = 0b_000000000000_00000_000_00000_1110011;
#[allow(clippy::unusual_byte_groupings)]
const PROGRAM_CODE: [u32; PROGRAM_SIZE] = {
    let mut program: [u32; PROGRAM_SIZE] = [ECALL_HALT; PROGRAM_SIZE];
    declare_program!(
        program,
        // func7   rs2   rs1   f3  rd    opcode
        0b_0000000_00100_00001_000_00100_0110011, // add x4, x4, x1 <=> addi x4, x4, 1
        0b_0000000_00011_00010_000_00011_0110011, // add x3, x3, x2 <=> addi x3, x3, -1
        0b_1_111111_00011_00000_110_1100_1_1100011, // bltu x0, x3, -8
        0b_0_0000000010_0_00000000_00001_1101111, // jal x1, 4
        ECALL_HALT,                               // ecall halt
    );
    program
};
type ExampleProgramTableCircuit<E> = ProgramTableCircuit<E, PROGRAM_SIZE>;

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

    let config = Rv32imConfig::<E>::construct_circuits(&mut zkvm_cs);
    let reg_config = zkvm_cs.register_table_circuit::<RegTableCircuit<E>>();
    let prog_config = zkvm_cs.register_table_circuit::<ExampleProgramTableCircuit<E>>();
    zkvm_cs.register_global_state::<GlobalState>();

    for instance_num_vars in args.start..args.end {
        let step_loop = 1 << (instance_num_vars - 1); // 1 step in loop contribute to 2 add instance

        let mut zkvm_fixed_traces = ZKVMFixedTraces::default();
        config.generate_fixed_traces(&zkvm_cs, &mut zkvm_fixed_traces);

        zkvm_fixed_traces.register_table_circuit::<ExampleProgramTableCircuit<E>>(
            &zkvm_cs,
            prog_config.clone(),
            &PROGRAM_CODE,
        );

        // init vm.x1 = 1, vm.x2 = -1, vm.x3 = step_loop
        // vm.x4 += vm.x1
        zkvm_fixed_traces.register_table_circuit::<RegTableCircuit<E>>(
            &zkvm_cs,
            reg_config.clone(),
            &Some(
                vec![
                    0,         // x0
                    1,         // x1
                    u32::MAX,  // x2
                    step_loop, // x3
                ]
                .into_iter()
                .chain(std::iter::repeat(0u32))
                .take(32)
                .flat_map(|v| {
                    Value::<u32>::new_unchecked(v)
                        .as_u16_limbs()
                        .iter()
                        .map(|v| *v as u32)
                        .chain(std::iter::once(0))
                        .collect_vec()
                })
                .collect_vec(),
            ),
        );

        let pk = zkvm_cs
            .clone()
            .key_gen::<Pcs>(pp.clone(), vp.clone(), zkvm_fixed_traces)
            .expect("keygen failed");
        let vk = pk.get_vk();

        // proving
        let prover = ZKVMProver::new(pk);
        let verifier = ZKVMVerifier::new(vk);

        let mut vm = VMState::new(CENO_PLATFORM);
        let pc_start = ByteAddr(CENO_PLATFORM.pc_start()).waddr();

        vm.init_register_unsafe(1usize, 1);
        vm.init_register_unsafe(2usize, u32::MAX); // -1 in two's complement
        vm.init_register_unsafe(3usize, step_loop);
        for (i, inst) in PROGRAM_CODE.iter().enumerate() {
            vm.init_memory(pc_start + i, *inst);
        }

        let all_records = vm
            .iter_until_halt()
            .collect::<Result<Vec<StepRecord>, _>>()
            .expect("vm exec failed")
            .into_iter()
            .collect::<Vec<_>>();

        let halt_record = all_records
            .iter()
            .rev()
            .find(|record| {
                record.insn().codes().kind == EANY
                    && record.rs1().unwrap().value == CENO_PLATFORM.ecall_halt()
            })
            .expect("halt record not found");

        let final_access = vm.tracer().final_accesses();
        let end_cycle = final_access.get(&CENO_PLATFORM.pc_vma().into()).unwrap();
        let exit_code = halt_record.rs2().unwrap().value;
        let pi = PublicValues::new(
            exit_code,
            CENO_PLATFORM.rom_start(),
            Tracer::SUBCYCLES_PER_INSN as u32,
            EXIT_PC as u32,
            *end_cycle as u32,
        );

        let mut zkvm_witness = ZKVMWitnesses::default();
        // assign opcode circuits
        config
            .assign_opcode_circuit(&zkvm_cs, &mut zkvm_witness, all_records)
            .unwrap();
        zkvm_witness.finalize_lk_multiplicities();
        // assign table circuits
        config
            .assign_table_circuit(&zkvm_cs, &mut zkvm_witness)
            .unwrap();
        // assign cpu register circuit
        zkvm_witness
            .assign_table_circuit::<RegTableCircuit<E>>(
                &zkvm_cs,
                &reg_config,
                &(0..32)
                    .flat_map(|reg_id| {
                        let vma: WordAddr = CENO_PLATFORM.register_vma(reg_id).into();
                        let reg_value = Value::<u32>::new_unchecked(vm.peek_register(reg_id));
                        reg_value
                            .as_u16_limbs()
                            .iter()
                            .cloned()
                            .map(|limb| limb as u32)
                            .chain(std::iter::once(*final_access.get(&vma).unwrap_or(&0) as u32))
                            .collect_vec()
                    })
                    .collect_vec(),
            )
            .unwrap();
        // assign program circuit
        zkvm_witness
            .assign_table_circuit::<ExampleProgramTableCircuit<E>>(
                &zkvm_cs,
                &prog_config,
                &PROGRAM_CODE.len(),
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
