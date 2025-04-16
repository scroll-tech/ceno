use crate::{
    error::ZKVMError,
    instructions::riscv::{DummyExtraConfig, MemPadder, MmuConfig, Rv32imConfig},
    scheme::{
        PublicValues, ZKVMProof,
        constants::MAX_NUM_VARIABLES,
        mock_prover::{LkMultiplicityKey, MockProver},
        prover::ZKVMProver,
        verifier::ZKVMVerifier,
    },
    state::GlobalState,
    structs::{
        ProgramParams, ZKVMConstraintSystem, ZKVMFixedTraces, ZKVMProvingKey, ZKVMVerifyingKey,
        ZKVMWitnesses,
    },
    tables::{MemFinalRecord, MemInitRecord, ProgramTableCircuit, ProgramTableConfig},
};
use ceno_emul::{
    ByteAddr, CENO_PLATFORM, EmuContext, InsnKind, IterAddresses, Platform, Program, StepRecord,
    Tracer, VMState, WORD_SIZE, WordAddr,
};
use clap::ValueEnum;
use ff_ext::{ExtensionField, GoldilocksExt2};
use itertools::{Itertools, MinMaxResult, chain};
use mpcs::{Basefold, BasefoldRSParams, PolynomialCommitmentScheme};
use p3::goldilocks::Goldilocks;
use std::{
    collections::{BTreeSet, HashMap, HashSet},
    sync::Arc,
};
use tracing::info;
use transcript::{BasicTranscript as Transcript, BasicTranscriptWithStat, StatisticRecorder};

pub type E = GoldilocksExt2;
pub type B = Goldilocks;
pub type Pcs = Basefold<GoldilocksExt2, BasefoldRSParams>;

pub struct FullMemState<Record> {
    mem: Vec<Record>,
    io: Vec<Record>,
    reg: Vec<Record>,
    hints: Vec<Record>,
    stack: Vec<Record>,
    heap: Vec<Record>,
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
) -> EmulationResult {
    let InitMemState {
        mem: mem_init,
        io: io_init,
        reg: reg_init,
        hints: hints_init,
        stack: _,
        heap: _,
    } = init_mem_state;

    let mut vm: VMState = VMState::new(platform.clone(), program);

    for record in chain!(&hints_init, &io_init) {
        vm.init_memory(record.addr.into(), record.value);
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
            record.insn().kind == InsnKind::ECALL
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

    // Find the final public IO cycles.
    let io_final = io_init
        .iter()
        .map(|rec| MemFinalRecord {
            addr: rec.addr,
            value: rec.value,
            cycle: *final_access.get(&rec.addr.into()).unwrap_or(&0),
        })
        .collect_vec();

    let hints_final = hints_init
        .iter()
        .map(|rec| MemFinalRecord {
            addr: rec.addr,
            value: rec.value,
            cycle: *final_access.get(&rec.addr.into()).unwrap_or(&0),
        })
        .collect_vec();

    // get stack access by min/max range
    let stack_final = if let Some((start, end)) = vm
        .tracer()
        .probe_min_max_address_by_start_addr(ByteAddr::from(platform.stack.start).waddr())
    {
        (start..end)
            // stack record collect in reverse order
            .rev()
            .map(|vma| {
                let byte_addr = vma.baddr();
                MemFinalRecord {
                    addr: byte_addr.0,
                    value: vm.peek_memory(vma),
                    cycle: *final_access.get(&vma).unwrap_or(&0),
                }
            })
            .collect_vec()
    } else {
        vec![]
    };

    // get heap access by min/max range
    let heap_final = if let Some((start, end)) = vm
        .tracer()
        .probe_min_max_address_by_start_addr(ByteAddr::from(platform.heap.start).waddr())
    {
        (start..end)
            .map(|vma| {
                let byte_addr = vma.baddr();
                MemFinalRecord {
                    addr: byte_addr.0,
                    value: vm.peek_memory(vma),
                    cycle: *final_access.get(&vma).unwrap_or(&0),
                }
            })
            .collect_vec()
    } else {
        vec![]
    };

    debug_memory_ranges(
        &vm,
        chain!(
            &mem_final,
            &io_final,
            &hints_final,
            &stack_final,
            &heap_final
        ),
    );

    EmulationResult {
        pi,
        exit_code,
        all_records,
        final_mem_state: FinalMemState {
            reg: reg_final,
            io: io_final,
            mem: mem_final,
            hints: hints_final,
            stack: stack_final,
            heap: heap_final,
        },
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
pub enum Preset {
    Ceno,
    Sp1,
}

pub fn setup_platform(
    preset: Preset,
    program: &Program,
    stack_size: u32,
    heap_size: u32,
    pub_io_size: u32,
) -> Platform {
    let preset = match preset {
        Preset::Ceno => CENO_PLATFORM,
        Preset::Sp1 => Platform {
            // The stack section is not mentioned in ELF headers, so we repeat the constant STACK_TOP here.
            stack: 0x0020_0400..0x0020_0400,
            unsafe_ecall_nop: true,
            ..CENO_PLATFORM
        },
    };

    let prog_data = program.image.keys().copied().collect::<BTreeSet<_>>();
    let stack = preset.stack.end - stack_size..preset.stack.end;

    let heap = {
        // Detect heap as starting after program data.
        let heap_start = program.sheap;
        let heap = heap_start..heap_start + heap_size;
        // pad the total size to the next power of two.
        let mem_size = heap.iter_addresses().len();
        let pad_size = mem_size.next_power_of_two() - mem_size;
        let heap_end = heap.end as usize + pad_size * WORD_SIZE;
        assert!(
            heap_end <= u32::MAX as usize,
            "not enough space for padding; reduce heap size"
        );
        heap.start..heap_end as u32
    };

    // TODO check AFTER padding, all addresses no overlapping

    Platform {
        rom: program.base_address
            ..program.base_address + (program.instructions.len() * WORD_SIZE) as u32,
        prog_data,
        stack,
        heap,
        public_io: preset.public_io.start..preset.public_io.start + pub_io_size.next_power_of_two(),
        ..preset
    }
}

fn init_static_addrs(program: &Program) -> Vec<MemInitRecord> {
    let program_addrs = program
        .image
        .iter()
        .map(|(addr, value)| MemInitRecord {
            addr: *addr,
            value: *value,
        })
        .sorted_by_key(|record| record.addr)
        .collect_vec();

    assert!(
        program_addrs.len().is_power_of_two(),
        "program_addrs.len {} is not pow2",
        program_addrs.len(),
    );
    program_addrs
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
    is_mock_proving: bool,
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
    zkvm_witness.finalize_lk_multiplicities(is_mock_proving);

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
            &emul_result.final_mem_state.hints,
            &emul_result.final_mem_state.stack,
            &emul_result.final_mem_state.heap,
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
    Keygen,
    PrepE2EProving,
    PrepWitnessGen,
    PrepSanityCheck,
    Complete,
}

// Currently handles state required by the sanity check in `bin/e2e.rs`
// Future cases would require this to be an enum
pub type IntermediateState<E, PCS> = (Option<ZKVMProof<E, PCS>>, Option<ZKVMVerifyingKey<E, PCS>>);

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
pub fn run_e2e_with_checkpoint<
    E: ExtensionField + LkMultiplicityKey + serde::de::DeserializeOwned,
    PCS: PolynomialCommitmentScheme<E> + 'static,
>(
    program: Program,
    platform: Platform,
    hints: Vec<u32>,
    public_io: Vec<u32>,
    max_steps: usize,
    checkpoint: Checkpoint,
) -> (IntermediateState<E, PCS>, Box<dyn FnOnce()>) {
    let static_addrs = init_static_addrs(&program);

    let pubio_len = platform.public_io.iter_addresses().len();
    let program_params = ProgramParams {
        platform: platform.clone(),
        program_size: program.instructions.len(),
        static_memory_len: static_addrs.len(),
        pubio_len,
    };

    let program = Arc::new(program);
    let system_config = construct_configs::<E>(program_params);
    let reg_init = system_config.mmu_config.initial_registers();

    let io_init = MemPadder::init_mem(platform.public_io.clone(), pubio_len, &public_io);
    let hint_init = MemPadder::init_mem(
        platform.hints.clone(),
        hints.len().next_power_of_two(),
        &hints,
    );

    let init_full_mem = InitMemState {
        mem: static_addrs,
        reg: reg_init,
        io: io_init,
        hints: hint_init,
        // stack/heap both init value 0 and range is dynamic
        stack: vec![],
        heap: vec![],
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
    if let Checkpoint::Keygen = checkpoint {
        return ((None, Some(vk)), Box::new(|| ()));
    }

    // Generate witness
    let is_mock_proving = std::env::var("MOCK_PROVING").is_ok();
    if let Checkpoint::PrepE2EProving = checkpoint {
        return (
            (None, None),
            Box::new(move || {
                _ = run_e2e_proof::<E, _>(
                    program,
                    max_steps,
                    init_full_mem,
                    platform,
                    &system_config,
                    pk,
                    zkvm_fixed_traces,
                    is_mock_proving,
                )
            }),
        );
    }

    // Emulate program
    let emul_result = emulate_program(program.clone(), max_steps, init_full_mem, &platform);

    // Clone some emul_result fields before consuming
    let pi = emul_result.pi.clone();
    let exit_code = emul_result.exit_code;

    if let Checkpoint::PrepWitnessGen = checkpoint {
        return (
            (None, None),
            Box::new(move || _ = generate_witness(&system_config, emul_result, &program, false)),
        );
    }

    let zkvm_witness = generate_witness(&system_config, emul_result, &program, is_mock_proving);

    // proving
    let prover = ZKVMProver::new(pk);

    if is_mock_proving {
        MockProver::assert_satisfied_full(
            &system_config.zkvm_cs,
            zkvm_fixed_traces.clone(),
            &zkvm_witness,
            &pi,
            &program,
        );
        tracing::info!("Mock proving passed");
    }

    // Run proof phase
    let transcript = Transcript::new(b"riscv");
    let zkvm_proof = prover
        .create_proof(zkvm_witness, pi, transcript)
        .expect("create_proof failed");

    let verifier = ZKVMVerifier::new(vk.clone());

    run_e2e_verify::<E, _>(&verifier, zkvm_proof.clone(), exit_code, max_steps);

    if let Checkpoint::PrepSanityCheck = checkpoint {
        return ((Some(zkvm_proof), Some(vk)), Box::new(|| ()));
    }

    ((None, None), Box::new(|| ()))
}

// Runs program emulation + witness generation + proving
#[allow(clippy::too_many_arguments)]
pub fn run_e2e_proof<E: ExtensionField + LkMultiplicityKey, PCS: PolynomialCommitmentScheme<E>>(
    program: Arc<Program>,
    max_steps: usize,
    init_full_mem: InitMemState,
    platform: Platform,
    system_config: &ConstraintSystemConfig<E>,
    pk: ZKVMProvingKey<E, PCS>,
    zkvm_fixed_traces: ZKVMFixedTraces<E>,
    is_mock_proving: bool,
) -> ZKVMProof<E, PCS> {
    // Emulate program
    let emul_result = emulate_program(program.clone(), max_steps, init_full_mem, &platform);

    // clone pi before consuming
    let pi = emul_result.pi.clone();

    // Generate witness
    let zkvm_witness = generate_witness(system_config, emul_result, &program, is_mock_proving);

    // proving
    let prover = ZKVMProver::new(pk);

    if is_mock_proving {
        MockProver::assert_satisfied_full(
            &system_config.zkvm_cs,
            zkvm_fixed_traces.clone(),
            &zkvm_witness,
            &pi,
            &program,
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

fn debug_memory_ranges<'a, I: Iterator<Item = &'a MemFinalRecord>>(vm: &VMState, mem_final: I) {
    let accessed_addrs = vm
        .tracer()
        .final_accesses()
        .iter()
        .filter(|(_, &cycle)| (cycle != 0))
        .map(|(&addr, _)| addr.baddr())
        .filter(|addr| vm.platform().can_read(addr.0))
        .collect_vec();

    let handled_addrs = mem_final
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
        "{}{}",
        if platform.can_read(addr) { "R" } else { "-" },
        if platform.can_write(addr) { "W" } else { "-" },
    )
}

pub fn verify(
    zkvm_proof: &ZKVMProof<E, Pcs>,
    verifier: &ZKVMVerifier<E, Pcs>,
) -> Result<(), ZKVMError> {
    // print verification statistics like proof size and hash count
    let stat_recorder = StatisticRecorder::default();
    let transcript = BasicTranscriptWithStat::new(&stat_recorder, b"riscv");
    verifier.verify_proof_halt(
        zkvm_proof.clone(),
        transcript,
        zkvm_proof.has_halt(&verifier.vk),
    )?;
    info!("e2e proof stat: {}", zkvm_proof);
    info!(
        "hashes count = {}",
        stat_recorder.into_inner().field_appended_num
    );
    Ok(())
}
