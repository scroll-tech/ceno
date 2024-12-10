use crate::{
    instructions::riscv::{DummyExtraConfig, MemPadder, MmuConfig, Rv32imConfig},
    scheme::{
        PublicValues, ZKVMProof, constants::MAX_NUM_VARIABLES, mock_prover::MockProver,
        prover::ZKVMProver, verifier::ZKVMVerifier,
    },
    state::GlobalState,
    structs::{
        ProgramParams, ZKVMConstraintSystem, ZKVMFixedTraces, ZKVMProvingKey, ZKVMWitnesses,
    },
    tables::{MemFinalRecord, MemInitRecord, ProgramTableCircuit, ProgramTableConfig},
};
use ceno_emul::{
    ByteAddr, EmuContext, InsnKind::EANY, IterAddresses, Platform, Program, StepRecord, Tracer,
    VMState, WORD_SIZE, WordAddr,
};
use ff_ext::ExtensionField;
use itertools::{Itertools, MinMaxResult, chain};
use mpcs::PolynomialCommitmentScheme;
use std::{
    collections::{HashMap, HashSet},
    iter::zip,
    ops::Deref,
    sync::Arc,
};
use transcript::BasicTranscript as Transcript;

pub struct FullMemState<Record> {
    mem: Vec<Record>,
    io: Vec<Record>,
    reg: Vec<Record>,
    priv_io: Vec<Record>,
}

type InitMemState = FullMemState<MemInitRecord>;
type FinalMemState = FullMemState<MemFinalRecord>;

pub struct EmulationResult {
    exit_code: Option<u32>,
    all_records: Vec<StepRecord>,
    final_mem_state: FinalMemState,
    pi: PublicValues<u32>,
}

fn emulate_program(
    program: Arc<Program>,
    max_steps: usize,
    init_mem_state: InitMemState,
    platform: &Platform,
    hints: Vec<u32>,
) -> EmulationResult {
    let InitMemState {
        mem: mem_init,
        io: io_init,
        reg: reg_init,
        priv_io: _,
    } = init_mem_state;

    let mut vm: VMState = VMState::new(platform.clone(), program);

    for (addr, value) in zip(platform.hints.iter_addresses(), &hints) {
        vm.init_memory(addr.into(), *value);
    }

    let all_records = vm
        .iter_until_halt()
        .take(max_steps)
        .collect::<Result<Vec<StepRecord>, _>>()
        .expect("vm exec failed");

    // Find the exit code from the HALT step, if halting at all.
    let exit_code = all_records
        .iter()
        .rev()
        .find(|record| {
            record.insn().codes().kind == EANY
                && record.rs1().unwrap().value == Platform::ecall_halt()
        })
        .and_then(|halt_record| halt_record.rs2())
        .map(|rs2| rs2.value);

    let final_access = vm.tracer().final_accesses();
    let end_cycle: u32 = vm.tracer().cycle().try_into().unwrap();

    let pi = PublicValues::new(
        exit_code.unwrap_or(0),
        vm.program().entry,
        Tracer::SUBCYCLES_PER_INSN as u32,
        vm.get_pc().into(),
        end_cycle,
        io_init.iter().map(|rec| rec.value).collect_vec(),
    );

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
    debug_memory_ranges(&vm, &mem_final);

    // Find the final public IO cycles.
    let io_final = io_init
        .iter()
        .map(|rec| MemFinalRecord {
            addr: rec.addr,
            value: rec.value,
            cycle: *final_access.get(&rec.addr.into()).unwrap_or(&0),
        })
        .collect_vec();

    let priv_io_final = zip(platform.hints.iter_addresses(), &hints)
        .map(|(addr, &value)| MemFinalRecord {
            addr,
            value,
            cycle: *final_access.get(&addr.into()).unwrap_or(&0),
        })
        .collect_vec();

    EmulationResult {
        pi,
        exit_code,
        all_records,
        final_mem_state: FinalMemState {
            reg: reg_final,
            io: io_final,
            mem: mem_final,
            priv_io: priv_io_final,
        },
    }
}

fn init_mem(
    program: &Program,
    platform: &Platform,
    mem_padder: &mut MemPadder,
    stack_size: u32,
    heap_size: u32,
) -> Vec<MemInitRecord> {
    let stack_addrs = platform.stack_top - stack_size..platform.stack_top;
    // Detect heap as starting after program data.
    let heap_start = program.image.keys().max().unwrap() + WORD_SIZE as u32;
    let heap_addrs = heap_start..heap_start + heap_size;
    let program_addrs = program.image.iter().map(|(addr, value)| MemInitRecord {
        addr: *addr,
        value: *value,
    });

    let stack = stack_addrs
        .iter_addresses()
        .map(|addr| MemInitRecord { addr, value: 0 });

    let heap = heap_addrs
        .iter_addresses()
        .map(|addr| MemInitRecord { addr, value: 0 });

    let mem_init = chain!(program_addrs, stack, heap).collect_vec();

    mem_padder.padded_sorted(mem_init.len().next_power_of_two(), mem_init)
}

pub struct ConstraintSystemConfig<E: ExtensionField> {
    zkvm_cs: ZKVMConstraintSystem<E>,
    config: Rv32imConfig<E>,
    mmu_config: MmuConfig<E>,
    dummy_config: DummyExtraConfig<E>,
    prog_config: ProgramTableConfig,
}

fn construct_configs<E: ExtensionField>(
    program_params: ProgramParams,
) -> ConstraintSystemConfig<E> {
    let mut zkvm_cs = ZKVMConstraintSystem::new_with_platform(program_params);

    let config = Rv32imConfig::<E>::construct_circuits(&mut zkvm_cs);
    let mmu_config = MmuConfig::<E>::construct_circuits(&mut zkvm_cs);
    let dummy_config = DummyExtraConfig::<E>::construct_circuits(&mut zkvm_cs);
    let prog_config = zkvm_cs.register_table_circuit::<ProgramTableCircuit<E>>();
    zkvm_cs.register_global_state::<GlobalState>();
    ConstraintSystemConfig {
        zkvm_cs,
        config,
        mmu_config,
        dummy_config,
        prog_config,
    }
}

fn generate_fixed_traces<E: ExtensionField>(
    system_config: &ConstraintSystemConfig<E>,
    init_mem_state: &InitMemState,
    program: &Program,
) -> ZKVMFixedTraces<E> {
    let mut zkvm_fixed_traces = ZKVMFixedTraces::default();

    zkvm_fixed_traces.register_table_circuit::<ProgramTableCircuit<E>>(
        &system_config.zkvm_cs,
        &system_config.prog_config,
        program,
    );

    system_config
        .config
        .generate_fixed_traces(&system_config.zkvm_cs, &mut zkvm_fixed_traces);
    system_config.mmu_config.generate_fixed_traces(
        &system_config.zkvm_cs,
        &mut zkvm_fixed_traces,
        &init_mem_state.reg,
        &init_mem_state.mem,
        &init_mem_state.io.iter().map(|rec| rec.addr).collect_vec(),
    );
    system_config
        .dummy_config
        .generate_fixed_traces(&system_config.zkvm_cs, &mut zkvm_fixed_traces);

    zkvm_fixed_traces
}

pub fn generate_witness<E: ExtensionField>(
    system_config: &ConstraintSystemConfig<E>,
    emul_result: EmulationResult,
    program: &Program,
) -> ZKVMWitnesses<E> {
    let mut zkvm_witness = ZKVMWitnesses::default();
    // assign opcode circuits
    let dummy_records = system_config
        .config
        .assign_opcode_circuit(
            &system_config.zkvm_cs,
            &mut zkvm_witness,
            emul_result.all_records,
        )
        .unwrap();
    system_config
        .dummy_config
        .assign_opcode_circuit(&system_config.zkvm_cs, &mut zkvm_witness, dummy_records)
        .unwrap();
    zkvm_witness.finalize_lk_multiplicities();

    // assign table circuits
    system_config
        .config
        .assign_table_circuit(&system_config.zkvm_cs, &mut zkvm_witness)
        .unwrap();
    system_config
        .mmu_config
        .assign_table_circuit(
            &system_config.zkvm_cs,
            &mut zkvm_witness,
            &emul_result.final_mem_state.reg,
            &emul_result.final_mem_state.mem,
            &emul_result
                .final_mem_state
                .io
                .iter()
                .map(|rec| rec.cycle)
                .collect_vec(),
            &emul_result.final_mem_state.priv_io,
        )
        .unwrap();
    // assign program circuit
    zkvm_witness
        .assign_table_circuit::<ProgramTableCircuit<E>>(
            &system_config.zkvm_cs,
            &system_config.prog_config,
            program,
        )
        .unwrap();

    zkvm_witness
}

// Encodes useful early return points of the e2e pipeline
pub enum Checkpoint {
    PrepE2EProving,
    PrepWitnessGen,
    PrepSanityCheck,
    Complete,
}

// Currently handles state required by the sanity check in `bin/e2e.rs`
// Future cases would require this to be an enum
pub type IntermediateState<E, PCS> = (ZKVMProof<E, PCS>, ZKVMVerifier<E, PCS>);

// Runs end-to-end pipeline, stopping at a certain checkpoint and yielding useful state.
//
// The return type is a pair of:
// 1. Explicit state
// 2. A no-input-no-ouptut closure
//
// (2.) is useful when you want to setup a certain action and run it
// elsewhere (i.e, in a benchmark)
// (1.) is useful for exposing state which must be further combined with
// state external to this pipeline (e.g, sanity check in bin/e2e.rs)

#[allow(clippy::type_complexity)]
pub fn run_e2e_with_checkpoint<E: ExtensionField, PCS: PolynomialCommitmentScheme<E> + 'static>(
    program: Program,
    platform: Platform,
    stack_size: u32,
    heap_size: u32,
    hints: Vec<u32>,
    max_steps: usize,
    checkpoint: Checkpoint,
) -> (Option<IntermediateState<E, PCS>>, Box<dyn FnOnce()>) {
    // Detect heap as starting after program data.
    let heap_start = program.image.keys().max().unwrap() + WORD_SIZE as u32;
    let heap_addrs = heap_start..heap_start + heap_size;
    let mut mem_padder = MemPadder::new(heap_addrs.end..platform.ram.end);
    let mem_init = init_mem(&program, &platform, &mut mem_padder, stack_size, heap_size);

    let program_params = ProgramParams {
        platform: platform.clone(),
        program_size: program.instructions.len(),
        static_memory_len: mem_init.len(),
        ..ProgramParams::default()
    };

    let program = Arc::new(program);
    let system_config = construct_configs::<E>(program_params);

    // IO is not used in this program, but it must have a particular size at the moment.
    let io_init = mem_padder.padded_sorted(system_config.mmu_config.public_io_len(), vec![]);
    let reg_init = system_config.mmu_config.initial_registers();

    let init_full_mem = InitMemState {
        mem: mem_init,
        reg: reg_init,
        io: io_init,
        priv_io: vec![],
    };

    // Generate fixed traces
    let zkvm_fixed_traces = generate_fixed_traces(&system_config, &init_full_mem, &program);

    // Keygen
    let pcs_param = PCS::setup(1 << MAX_NUM_VARIABLES).expect("Basefold PCS setup");
    let (pp, vp) = PCS::trim(pcs_param, 1 << MAX_NUM_VARIABLES).expect("Basefold trim");
    let pk = system_config
        .zkvm_cs
        .clone()
        .key_gen::<PCS>(pp.clone(), vp.clone(), zkvm_fixed_traces.clone())
        .expect("keygen failed");
    let vk = pk.get_vk();

    if let Checkpoint::PrepE2EProving = checkpoint {
        return (
            None,
            Box::new(move || {
                _ = run_e2e_proof(
                    program,
                    max_steps,
                    init_full_mem,
                    platform,
                    hints,
                    &system_config,
                    pk,
                    zkvm_fixed_traces,
                )
            }),
        );
    }

    // Emulate program
    let emul_result = emulate_program(program.clone(), max_steps, init_full_mem, &platform, hints);

    // Clone some emul_result fields before consuming
    let pi = emul_result.pi.clone();
    let exit_code = emul_result.exit_code;

    if let Checkpoint::PrepWitnessGen = checkpoint {
        return (
            None,
            Box::new(move || _ = generate_witness(&system_config, emul_result, program.deref())),
        );
    }

    // Generate witness
    let zkvm_witness = generate_witness(&system_config, emul_result, &program);

    // proving
    let prover = ZKVMProver::new(pk);

    if std::env::var("MOCK_PROVING").is_ok() {
        MockProver::assert_satisfied_full(
            &system_config.zkvm_cs,
            zkvm_fixed_traces.clone(),
            &zkvm_witness,
            &pi,
        );
        tracing::info!("Mock proving passed");
    }

    // Run proof phase
    let transcript = Transcript::new(b"riscv");
    let zkvm_proof = prover
        .create_proof(zkvm_witness, pi, transcript)
        .expect("create_proof failed");

    let verifier = ZKVMVerifier::new(vk);

    run_e2e_verify(&verifier, zkvm_proof.clone(), exit_code, max_steps);

    if let Checkpoint::PrepSanityCheck = checkpoint {
        return (Some((zkvm_proof, verifier)), Box::new(|| ()));
    }

    (None, Box::new(|| ()))
}

// Runs program emulation + witness generation + proving
#[allow(clippy::too_many_arguments)]
pub fn run_e2e_proof<E: ExtensionField, PCS: PolynomialCommitmentScheme<E>>(
    program: Arc<Program>,
    max_steps: usize,
    init_full_mem: InitMemState,
    platform: Platform,
    hints: Vec<u32>,
    system_config: &ConstraintSystemConfig<E>,
    pk: ZKVMProvingKey<E, PCS>,
    zkvm_fixed_traces: ZKVMFixedTraces<E>,
) -> ZKVMProof<E, PCS> {
    // Emulate program
    let emul_result = emulate_program(program.clone(), max_steps, init_full_mem, &platform, hints);

    // clone pi before consuming
    let pi = emul_result.pi.clone();

    // Generate witness
    let zkvm_witness = generate_witness(system_config, emul_result, program.deref());

    // proving
    let prover = ZKVMProver::new(pk);

    if std::env::var("MOCK_PROVING").is_ok() {
        MockProver::assert_satisfied_full(
            &system_config.zkvm_cs,
            zkvm_fixed_traces.clone(),
            &zkvm_witness,
            &pi,
        );
        tracing::info!("Mock proving passed");
    }

    let transcript = Transcript::new(b"riscv");
    prover
        .create_proof(zkvm_witness, pi, transcript)
        .expect("create_proof failed")
}

pub fn run_e2e_verify<E: ExtensionField, PCS: PolynomialCommitmentScheme<E>>(
    verifier: &ZKVMVerifier<E, PCS>,
    zkvm_proof: ZKVMProof<E, PCS>,
    exit_code: Option<u32>,
    max_steps: usize,
) {
    let transcript = Transcript::new(b"riscv");
    assert!(
        verifier
            .verify_proof_halt(zkvm_proof, transcript, exit_code.is_some())
            .expect("verify proof return with error"),
    );
    match exit_code {
        Some(0) => tracing::info!("exit code 0. Success."),
        Some(code) => tracing::error!("exit code {}. Failure.", code),
        None => tracing::error!("Unfinished execution. max_steps={:?}.", max_steps),
    }
}

fn debug_memory_ranges(vm: &VMState, mem_final: &[MemFinalRecord]) {
    let accessed_addrs = vm
        .tracer()
        .final_accesses()
        .iter()
        .filter(|(_, &cycle)| (cycle != 0))
        .map(|(&addr, _)| addr.baddr())
        .filter(|addr| vm.platform().can_read(addr.0))
        .collect_vec();

    let handled_addrs = mem_final
        .iter()
        .filter(|rec| rec.cycle != 0)
        .map(|rec| ByteAddr(rec.addr))
        .collect::<HashSet<_>>();

    tracing::debug!(
        "Memory range (accessed): {:?}",
        format_segments(vm.platform(), accessed_addrs.iter().copied())
    );
    tracing::debug!(
        "Memory range (handled):  {:?}",
        format_segments(vm.platform(), handled_addrs.iter().copied())
    );

    for addr in &accessed_addrs {
        assert!(handled_addrs.contains(addr), "unhandled addr: {:?}", addr);
    }
}

fn format_segments(
    platform: &Platform,
    addrs: impl Iterator<Item = ByteAddr>,
) -> HashMap<String, MinMaxResult<ByteAddr>> {
    addrs
        .into_grouping_map_by(|addr| format_segment(platform, addr.0))
        .minmax()
}

fn format_segment(platform: &Platform, addr: u32) -> String {
    format!(
        "{}{}{}",
        if platform.can_read(addr) { "R" } else { "-" },
        if platform.can_write(addr) { "W" } else { "-" },
        if platform.can_execute(addr) { "X" } else { "-" },
    )
}
