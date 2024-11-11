use std::{panic, time::Instant};

use ceno_zkvm::{
    declare_program,
    instructions::riscv::{Rv32imConfig, constants::EXIT_PC},
    scheme::{mock_prover::MockProver, prover::ZKVMProver},
    state::GlobalState,
    tables::{
        DynVolatileRamTable, MemFinalRecord, MemTable, ProgramTableCircuit, init_program_data,
        init_public_io, initial_registers,
    },
};
use clap::Parser;

use ceno_emul::{
    ByteAddr, CENO_PLATFORM, EmuContext,
    InsnKind::{ADD, BLTU, EANY, LUI, LW},
    PC_WORD_SIZE, Program, StepRecord, Tracer, VMState, WordAddr, encode_rv32,
};
use ceno_zkvm::{
    scheme::{PublicValues, constants::MAX_NUM_VARIABLES, verifier::ZKVMVerifier},
    structs::{ZKVMConstraintSystem, ZKVMFixedTraces, ZKVMWitnesses},
};
use ff_ext::ff::Field;
use goldilocks::GoldilocksExt2;
use itertools::Itertools;
use mpcs::{Basefold, BasefoldRSParams, PolynomialCommitmentScheme};
use tracing_flame::FlameLayer;
use tracing_subscriber::{EnvFilter, Registry, fmt, layer::SubscriberExt};
use transcript::Transcript;

const PROGRAM_SIZE: usize = 16;
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
        encode_rv32(LUI, 0, 0, 10, CENO_PLATFORM.public_io_start()), // lui x10, public_io
        encode_rv32(LW, 10, 0, 1, 0),                                // lw x1, 0(x10)
        encode_rv32(LW, 10, 0, 2, 4),                                // lw x2, 4(x10)
        encode_rv32(LW, 10, 0, 3, 8),                                // lw x3, 8(x10)
        // Main loop.
        encode_rv32(ADD, 1, 4, 4, 0),              // add x4, x1, x4
        encode_rv32(ADD, 2, 3, 3, 0),              // add x3, x2, x3
        encode_rv32(BLTU, 0, 3, 0, -8_i32 as u32), // bltu x0, x3, -8
        // End.
        ECALL_HALT, // ecall halt
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
    type Pcs = Basefold<GoldilocksExt2, BasefoldRSParams>;

    let program = Program::new(
        CENO_PLATFORM.pc_base(),
        CENO_PLATFORM.pc_base(),
        PROGRAM_CODE.to_vec(),
        PROGRAM_CODE
            .iter()
            .enumerate()
            .map(|(insn_idx, &insn)| {
                (
                    (insn_idx * PC_WORD_SIZE) as u32 + CENO_PLATFORM.pc_base(),
                    insn,
                )
            })
            .collect(),
    );
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
    let (pp, vp) = Pcs::trim(pcs_param, 1 << MAX_NUM_VARIABLES).expect("Basefold trim");
    let mut zkvm_cs = ZKVMConstraintSystem::default();

    let config = Rv32imConfig::<E>::construct_circuits(&mut zkvm_cs);
    let prog_config = zkvm_cs.register_table_circuit::<ExampleProgramTableCircuit<E>>();
    zkvm_cs.register_global_state::<GlobalState>();

    let mut zkvm_fixed_traces = ZKVMFixedTraces::default();

    zkvm_fixed_traces.register_table_circuit::<ExampleProgramTableCircuit<E>>(
        &zkvm_cs,
        &prog_config,
        &program,
    );

    let reg_init = initial_registers();
    // Define program constant here
    let program_data: &[u32] = &[];
    let program_data_init = init_program_data(program_data);

    config.generate_fixed_traces(
        &zkvm_cs,
        &mut zkvm_fixed_traces,
        &reg_init,
        &program_data_init,
    );

    let pk = zkvm_cs
        .clone()
        .key_gen::<Pcs>(pp.clone(), vp.clone(), zkvm_fixed_traces.clone())
        .expect("keygen failed");
    let vk = pk.get_vk();

    // proving
    let prover = ZKVMProver::new(pk);
    let verifier = ZKVMVerifier::new(vk);

    for instance_num_vars in args.start..args.end {
        // The performance benchmark is hook on number of "add" opcode instances.
        // Each iteration in the loop contributes 2 add instances,
        // so we divide by 2 here to ensure "instance_num_vars" aligns with the actual number of add instances.
        let step_loop = 1 << (instance_num_vars - 1);

        // init vm.x1 = 1, vm.x2 = -1, vm.x3 = step_loop
        let public_io_init = init_public_io(&[1, u32::MAX, step_loop]);

        let mut vm = VMState::new(CENO_PLATFORM, program.clone());

        // init mmio
        for record in program_data_init.iter().chain(public_io_init.iter()) {
            vm.init_memory(record.addr.into(), record.value);
        }

        let all_records = vm
            .iter_until_halt()
            .collect::<Result<Vec<StepRecord>, _>>()
            .expect("vm exec failed");

        let halt_record = all_records
            .iter()
            .rev()
            .find(|record| {
                record.insn().codes().kind == EANY
                    && record.rs1().unwrap().value == CENO_PLATFORM.ecall_halt()
            })
            .expect("halt record not found");

        let final_access = vm.tracer().final_accesses();

        let end_cycle: u32 = vm.tracer().cycle().try_into().unwrap();
        let exit_code = halt_record.rs2().unwrap().value;
        let pi = PublicValues::new(
            exit_code,
            CENO_PLATFORM.rom_start(),
            Tracer::SUBCYCLES_PER_INSN as u32,
            EXIT_PC as u32,
            end_cycle,
            public_io_init.iter().map(|v| v.value).collect(),
        );

        let mut zkvm_witness = ZKVMWitnesses::default();
        // assign opcode circuits
        config
            .assign_opcode_circuit(&zkvm_cs, &mut zkvm_witness, all_records)
            .unwrap();
        zkvm_witness.finalize_lk_multiplicities();

        // Find the final register values and cycles.
        let reg_final = reg_init
            .iter()
            .map(|rec| {
                let index = rec.addr as usize;
                if index < VMState::REG_COUNT {
                    let vma: WordAddr = CENO_PLATFORM.register_vma(index).into();
                    MemFinalRecord {
                        addr: rec.addr,
                        value: vm.peek_register(index),
                        cycle: *final_access.get(&vma).unwrap_or(&0),
                    }
                } else {
                    // The table is padded beyond the number of registers.
                    MemFinalRecord {
                        addr: rec.addr,
                        value: 0,
                        cycle: 0,
                    }
                }
            })
            .collect_vec();

        // Find the final program_data cycles.
        let program_data_final = program_data_init
            .iter()
            .map(|rec| {
                let vma: WordAddr = rec.addr.into();
                MemFinalRecord {
                    addr: rec.addr,
                    value: rec.value,
                    cycle: *final_access.get(&vma).unwrap_or(&0),
                }
            })
            .collect_vec();

        // Find the final public io cycles.
        let public_io_final = public_io_init
            .iter()
            .map(|rec| {
                let vma: WordAddr = rec.addr.into();
                MemFinalRecord {
                    addr: rec.addr,
                    value: rec.value,
                    cycle: *final_access.get(&vma).unwrap_or(&0),
                }
            })
            .collect_vec();

        // Find the final mem data and cycles.
        // TODO retrieve max address access
        // as we already support non-uniform proving of memory
        let num_entry = 1 << 12;
        let mem_final = (0..num_entry)
            .map(|entry_index| {
                let byte_addr = ByteAddr::from(MemTable::addr(entry_index));
                let vma = byte_addr.waddr();
                MemFinalRecord {
                    addr: byte_addr.0,
                    value: vm.peek_memory(vma),
                    cycle: *final_access.get(&vma).unwrap_or(&0),
                }
            })
            .collect_vec();

        // assign table circuits
        config
            .assign_table_circuit(
                &zkvm_cs,
                &mut zkvm_witness,
                &reg_final,
                &mem_final,
                &program_data_final,
                &public_io_final,
            )
            .unwrap();

        // assign program circuit
        zkvm_witness
            .assign_table_circuit::<ExampleProgramTableCircuit<E>>(&zkvm_cs, &prog_config, &program)
            .unwrap();

        MockProver::assert_satisfied_full(
            zkvm_cs.clone(),
            zkvm_fixed_traces.clone(),
            &zkvm_witness,
            &pi,
        );

        let timer = Instant::now();

        let transcript = Transcript::new(b"riscv");
        let mut zkvm_proof = prover
            .create_proof(zkvm_witness, pi, transcript)
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
        zkvm_proof.raw_pi[0] = vec![<GoldilocksExt2 as ff_ext::ExtensionField>::BaseField::ONE];
        zkvm_proof.raw_pi[1] = vec![<GoldilocksExt2 as ff_ext::ExtensionField>::BaseField::ONE];

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
