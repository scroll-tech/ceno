use std::{panic, time::Instant};

use ceno_zkvm::{
    declare_program,
    instructions::riscv::{Rv32imConfig, constants::EXIT_PC},
    scheme::prover::ZKVMProver,
    state::GlobalState,
    tables::{
        DynVolatileRamTable, MemFinalRecord, MemTable, ProgramTableCircuit, 
        init_program_data, init_public_io, initial_registers,
    },
};

use ceno_emul::{
    ByteAddr, CENO_PLATFORM, EmuContext,
    InsnKind::{ADD, ADDI, BNE, JAL},
    PC_WORD_SIZE, Program, StepRecord, Tracer, VMState, WordAddr,
};
use goldilocks::GoldilocksExt2;
use mpcs::{Basefold, BasefoldRSParams, PolynomialCommitmentScheme};
use rand_chacha::ChaCha8Rng;
use transcript::Transcript;

const PROGRAM_SIZE: usize = 16;
const ECALL_HALT: u32 = 0b_000000000000_00000_000_00000_1110011;

// Program to calculate nth Fibonacci number
// Registers:
// x1: n (input)
// x2: current number (initialized to 0)
// x3: next number (initialized to 1)
// x4: temp register
const PROGRAM_CODE: [u32; PROGRAM_SIZE] = {
    let mut program: [u32; PROGRAM_SIZE] = [ECALL_HALT; PROGRAM_SIZE];
    declare_program!(
        program,
        // Initialize registers
        encode_rv32(ADDI, 0, 0, 2, 0),     // x2 = 0 (first number)
        encode_rv32(ADDI, 0, 0, 3, 1),     // x3 = 1 (second number)
        // Main loop
        encode_rv32(BNE, 1, 0, 0, 28),     // if x1 != 0 goto loop
        encode_rv32(ADD, 2, 3, 4, 0),      // x4 = x2 + x3 
        encode_rv32(ADD, 0, 3, 2, 0),      // x2 = x3
        encode_rv32(ADD, 0, 4, 3, 0),      // x3 = x4
        encode_rv32(ADDI, 1, 1, 1, -1),    // x1 = x1 - 1
        encode_rv32(JAL, 0, 0, 0, -16),    // jump back to loop
        ECALL_HALT,                        // halt
    );
    program
};

fn main() {
    type E = GoldilocksExt2;
    type Pcs = Basefold<E, BasefoldRSParams, ChaCha8Rng>;

    // Initialize program
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

    // Setup zkVM circuits
    let mut zkvm_cs = ZKVMConstraintSystem::default();
    let config = Rv32imConfig::<E>::construct_circuits(&mut zkvm_cs);
    let prog_config = zkvm_cs.register_table_circuit::<ProgramTableCircuit<E, PROGRAM_SIZE>>();
    zkvm_cs.register_global_state::<GlobalState>();

    // Initialize traces
    let mut zkvm_fixed_traces = ZKVMFixedTraces::default();
    zkvm_fixed_traces.register_table_circuit::<ProgramTableCircuit<E, PROGRAM_SIZE>>(
        &zkvm_cs,
        &prog_config,
        &program,
    );

    // Setup initial state
    let reg_init = initial_registers();
    let program_data = &[];
    let program_data_init = init_program_data(program_data);
    
    config.generate_fixed_traces(
        &zkvm_cs,
        &mut zkvm_fixed_traces,
        &reg_init,
        &program_data_init,
    );

    // Generate proving/verifying keys
    let pcs_param = Pcs::setup(1 << 10).expect("PCS setup failed");
    let (pp, vp) = Pcs::trim(&pcs_param, 1 << 10).expect("PCS trim failed");
    let pk = zkvm_cs
        .clone()
        .key_gen::<Pcs>(pp.clone(), vp.clone(), zkvm_fixed_traces)
        .expect("keygen failed");
    let vk = pk.get_vk();

    // Calculate 10th Fibonacci number
    let n = 10;
    let public_io_init = init_public_io(&[n]);
    let mut vm = VMState::new(CENO_PLATFORM, program.clone());

    // Initialize memory
    for record in program_data_init.iter().chain(public_io_init.iter()) {
        vm.init_memory(record.addr.into(), record.value);
    }

    // Execute program
    let all_records = vm
        .iter_until_halt()
        .collect::<Result<Vec<StepRecord>, _>>()
        .expect("VM execution failed");

    // Generate and verify proof
    let prover = ZKVMProver::new(pk);
    let mut zkvm_witness = ZKVMWitnesses::default();
    config
        .assign_opcode_circuit(&zkvm_cs, &mut zkvm_witness, all_records)
        .unwrap();
    
    let transcript = Transcript::new(b"fibonacci");
    let proof = prover
        .create_proof(zkvm_witness, pi, transcript)
        .expect("Proof generation failed");

    // Verify the result matches expected Fibonacci number
    assert_eq!(vm.peek_register(2), 55); // 10th Fibonacci number
    println!("Successfully calculated and verified {}th Fibonacci number: {}", n, vm.peek_register(2));
}