use std::{panic, time::Instant};

use ceno_zkvm::{
    declare_program,
    instructions::riscv::{MemPadder, MmuConfig, Rv32imConfig, constants::EXIT_PC},
    scheme::{mock_prover::MockProver, prover::ZKVMProver},
    state::GlobalState,
    structs::ProgramParams,
    tables::{MemFinalRecord, ProgramTableCircuit},
    with_panic_hook,
};
use clap::Parser;

use ceno_emul::{
    CENO_PLATFORM, EmuContext,
    InsnKind::{ADD, BLTU, EANY, LUI, LW},
    PC_WORD_SIZE, Platform, Program, StepRecord, Tracer, VMState, Word, WordAddr, encode_rv32,
};
use ceno_zkvm::{
    scheme::{PublicValues, constants::MAX_NUM_VARIABLES, verifier::ZKVMVerifier},
    stats::{StaticReport, TraceReport},
    structs::{ZKVMConstraintSystem, ZKVMFixedTraces, ZKVMWitnesses},
};
use ff_ext::ff::Field;
use goldilocks::{Goldilocks, GoldilocksExt2};
use itertools::Itertools;
use mpcs::{Basefold, BasefoldRSParams, PolynomialCommitmentScheme};
use sumcheck::macros::{entered_span, exit_span};
use tracing_subscriber::{EnvFilter, Registry, fmt, fmt::format::FmtSpan, layer::SubscriberExt};
use transcript::BasicTranscript as Transcript;
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
        encode_rv32(LUI, 0, 0, 10, CENO_PLATFORM.public_io.start), // lui x10, public_io
        encode_rv32(LW, 10, 0, 1, 0),                              // lw x1, 0(x10)
        encode_rv32(LW, 10, 0, 2, 4),                              // lw x2, 4(x10)
        encode_rv32(LW, 10, 0, 3, 8),                              // lw x3, 8(x10)
        // Main loop.
        encode_rv32(ADD, 1, 4, 4, 0),              // add x4, x1, x4
        encode_rv32(ADD, 2, 3, 3, 0),              // add x3, x2, x3
        encode_rv32(BLTU, 0, 3, 0, -8_i32 as u32), // bltu x0, x3, -8
        // End.
        ECALL_HALT, // ecall halt
    );
    program
};
type ExampleProgramTableCircuit<E> = ProgramTableCircuit<E>;

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
    let mem_addresses = CENO_PLATFORM.ram.clone();
    let io_addresses = CENO_PLATFORM.public_io.clone();

    let mut fmt_layer = fmt::layer()
        .compact()
        .with_span_events(FmtSpan::CLOSE)
        .with_thread_ids(false)
        .with_thread_names(false);
    fmt_layer.set_ansi(false);

    // Take filtering directives from RUST_LOG env_var
    // Directive syntax: https://docs.rs/tracing-subscriber/latest/tracing_subscriber/filter/struct.EnvFilter.html#directives
    // Example: RUST_LOG="info" cargo run.. to get spans/events at info level; profiling spans are info
    // Example: RUST_LOG="[sumcheck]" cargo run.. to get only events under the "sumcheck" span
    let filter = EnvFilter::from_default_env();

    let subscriber = Registry::default().with(fmt_layer).with(filter);
    tracing::subscriber::set_global_default(subscriber).unwrap();

    let top_level = entered_span!("TOPLEVEL");

    let keygen = entered_span!("KEYGEN");

    // keygen
    let pcs_param = Pcs::setup(1 << MAX_NUM_VARIABLES).expect("Basefold PCS setup");
    let (pp, vp) = Pcs::trim(pcs_param, 1 << MAX_NUM_VARIABLES).expect("Basefold trim");
    let program_params = ProgramParams {
        program_size: PROGRAM_SIZE,
        ..Default::default()
    };
    let mut zkvm_cs = ZKVMConstraintSystem::new_with_platform(program_params);

    let config = Rv32imConfig::<E>::construct_circuits(&mut zkvm_cs);
    let mmu_config = MmuConfig::<E>::construct_circuits(&mut zkvm_cs);
    let prog_config = zkvm_cs.register_table_circuit::<ExampleProgramTableCircuit<E>>();
    zkvm_cs.register_global_state::<GlobalState>();

    let mut zkvm_fixed_traces = ZKVMFixedTraces::default();

    zkvm_fixed_traces.register_table_circuit::<ExampleProgramTableCircuit<E>>(
        &zkvm_cs,
        &prog_config,
        &program,
    );

    let static_report = StaticReport::new(&zkvm_cs);

    let reg_init = mmu_config.initial_registers();

    // RAM is not used in this program, but it must have a particular size at the moment.
    let mem_init = MemPadder::init_mem(mem_addresses, mmu_config.static_mem_len(), &[]);

    let init_public_io = |values: &[Word]| {
        MemPadder::init_mem(io_addresses.clone(), mmu_config.public_io_len(), values)
    };

    let io_addrs = init_public_io(&[]).iter().map(|v| v.addr).collect_vec();

    config.generate_fixed_traces(&zkvm_cs, &mut zkvm_fixed_traces);
    mmu_config.generate_fixed_traces(
        &zkvm_cs,
        &mut zkvm_fixed_traces,
        &reg_init,
        &mem_init,
        &io_addrs,
    );

    let pk = zkvm_cs
        .clone()
        .key_gen::<Pcs>(pp.clone(), vp.clone(), zkvm_fixed_traces.clone())
        .expect("keygen failed");
    let vk = pk.get_vk();

    exit_span!(keygen);
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

        // init memory mapped IO
        for record in &public_io_init {
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
                    && record.rs1().unwrap().value == Platform::ecall_halt()
            })
            .expect("halt record not found");

        let final_access = vm.tracer().final_accesses();

        let end_cycle: u32 = vm.tracer().cycle().try_into().unwrap();
        let exit_code = halt_record.rs2().unwrap().value;
        let pi = PublicValues::new(
            exit_code,
            vm.program().entry,
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
                    let vma: WordAddr = Platform::register_vma(index).into();
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

        // Find the final memory values and cycles.
        let mem_final = mem_init
            .iter()
            .map(|rec| {
                let vma: WordAddr = rec.addr.into();
                MemFinalRecord {
                    addr: rec.addr,
                    value: vm.peek_memory(vma),
                    cycle: *final_access.get(&vma).unwrap_or(&0),
                }
            })
            .collect_vec();

        // Find the final public io cycles.
        let public_io_final = public_io_init
            .iter()
            .map(|rec| *final_access.get(&rec.addr.into()).unwrap_or(&0))
            .collect_vec();

        // assign table circuits
        config
            .assign_table_circuit(&zkvm_cs, &mut zkvm_witness)
            .unwrap();
        mmu_config
            .assign_table_circuit(
                &zkvm_cs,
                &mut zkvm_witness,
                &reg_final,
                &mem_final,
                &public_io_final,
                &[],
            )
            .unwrap();

        // assign program circuit
        zkvm_witness
            .assign_table_circuit::<ExampleProgramTableCircuit<E>>(&zkvm_cs, &prog_config, &program)
            .unwrap();

        // get instance counts from witness matrices
        let trace_report = TraceReport::new_via_witnesses(
            &static_report,
            &zkvm_witness,
            "EXAMPLE_PROGRAM in riscv_opcodes.rs",
        );

        trace_report.save_json("report.json");
        trace_report.save_table("report.txt");

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
            timer.elapsed().as_secs()
        );

        let transcript = Transcript::new(b"riscv");
        assert!(
            verifier
                .verify_proof(zkvm_proof.clone(), transcript)
                .expect("verify proof return with error"),
        );

        let transcript = Transcript::new(b"riscv");
        // change public input maliciously should cause verifier to reject proof
        zkvm_proof.raw_pi[0] = vec![Goldilocks::ONE];
        zkvm_proof.raw_pi[1] = vec![Goldilocks::ONE];

        // capture panic message, if have
        let result = with_panic_hook(Box::new(|_info| ()), || {
            panic::catch_unwind(|| verifier.verify_proof(zkvm_proof, transcript))
        });
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
    exit_span!(top_level);
}
