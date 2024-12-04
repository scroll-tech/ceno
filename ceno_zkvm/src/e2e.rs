use crate::{
    instructions::riscv::{DummyExtraConfig, MemPadder, MmuConfig, Rv32imConfig},
    scheme::{
        PublicValues, constants::MAX_NUM_VARIABLES, mock_prover::MockProver, prover::ZKVMProver,
        verifier::ZKVMVerifier,
    },
    state::GlobalState,
    structs::{ProgramParams, ZKVMConstraintSystem, ZKVMFixedTraces, ZKVMWitnesses},
    tables::{MemFinalRecord, MemInitRecord, ProgramTableCircuit, ProgramTableConfig},
};
use ceno_emul::{
    ByteAddr, EmuContext, InsnKind::EANY, IterAddresses, Platform, Program, StepRecord, Tracer,
    VMState, WORD_SIZE, WordAddr,
};
use ff_ext::ff::Field;
use goldilocks::GoldilocksExt2;
use itertools::{Itertools, MinMaxResult, chain};
use mpcs::{Basefold, BasefoldRSParams, PolynomialCommitmentScheme};
use std::{
    collections::{HashMap, HashSet},
    iter::zip,
    panic,
    time::Instant,
};
use transcript::Transcript;

type E = GoldilocksExt2;
type Pcs = Basefold<GoldilocksExt2, BasefoldRSParams>;
type ExampleProgramTableCircuit<E> = ProgramTableCircuit<E>;

struct FullMemState<Record> {
    mem: Vec<Record>,
    io: Vec<Record>,
    reg: Vec<Record>,
    priv_io: Vec<Record>,
}

type InitMemState = FullMemState<MemInitRecord>;
type FinalMemState = FullMemState<MemFinalRecord>;

struct SimulationResult {
    exit_code: Option<u32>,
    all_records: Vec<StepRecord>,
    final_mem_state: FinalMemState,
    pi: PublicValues<u32>,
}

fn simulate_program(
    program: &Program,
    max_steps: usize,
    init_mem_state: InitMemState,
    platform: &Platform,
    hints: Vec<u32>,
) -> SimulationResult {
    let InitMemState {
        mem: mem_init,
        io: io_init,
        reg: reg_init,
        priv_io: _,
    } = init_mem_state;

    let mut vm: VMState = VMState::new(platform.clone(), program.clone());

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

    return SimulationResult {
        pi,
        exit_code,
        all_records,
        final_mem_state: FinalMemState {
            reg: reg_final,
            io: io_final,
            mem: mem_final,
            priv_io: priv_io_final,
        },
    };
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

struct LargeConfig {
    zkvm_cs: ZKVMConstraintSystem<E>,
    config: Rv32imConfig<E>,
    mmu_config: MmuConfig<E>,
    dummy_config: DummyExtraConfig<E>,
    prog_config: ProgramTableConfig,
}
fn construct_configs(program_params: ProgramParams) -> LargeConfig {
    let mut zkvm_cs = ZKVMConstraintSystem::new_with_platform(program_params);

    let config = Rv32imConfig::<E>::construct_circuits(&mut zkvm_cs);
    let mmu_config = MmuConfig::<E>::construct_circuits(&mut zkvm_cs);
    let dummy_config = DummyExtraConfig::<E>::construct_circuits(&mut zkvm_cs);
    let prog_config = zkvm_cs.register_table_circuit::<ExampleProgramTableCircuit<E>>();
    zkvm_cs.register_global_state::<GlobalState>();
    LargeConfig {
        zkvm_cs,
        config,
        mmu_config,
        dummy_config,
        prog_config,
    }
}

struct WithFixedTraces {
    large_config: LargeConfig,
    zkvm_fixed_traces: ZKVMFixedTraces<E>,
}

fn construct_with_fixed_traces(
    large_config: LargeConfig,
    init_mem_state: &InitMemState,
    program: &Program,
) -> WithFixedTraces {
    let mut zkvm_fixed_traces = ZKVMFixedTraces::default();

    zkvm_fixed_traces.register_table_circuit::<ExampleProgramTableCircuit<E>>(
        &large_config.zkvm_cs,
        &large_config.prog_config,
        program,
    );

    large_config
        .config
        .generate_fixed_traces(&large_config.zkvm_cs, &mut zkvm_fixed_traces);
    large_config.mmu_config.generate_fixed_traces(
        &large_config.zkvm_cs,
        &mut zkvm_fixed_traces,
        &init_mem_state.reg,
        &init_mem_state.mem,
        &init_mem_state.io.iter().map(|rec| rec.addr).collect_vec(),
    );
    large_config
        .dummy_config
        .generate_fixed_traces(&large_config.zkvm_cs, &mut zkvm_fixed_traces);

    WithFixedTraces {
        large_config,
        zkvm_fixed_traces,
    }
}

struct WithWitness {
    with_fixed_traces: WithFixedTraces,
    zkvm_witnesses: ZKVMWitnesses<E>,
}

fn construct_with_witness(
    with_fixed_traces: WithFixedTraces,
    sim_result: SimulationResult,
    program: &Program,
) -> WithWitness {
    let mut zkvm_witness = ZKVMWitnesses::default();
    // assign opcode circuits
    let dummy_records = with_fixed_traces
        .large_config
        .config
        .assign_opcode_circuit(
            &with_fixed_traces.large_config.zkvm_cs,
            &mut zkvm_witness,
            sim_result.all_records,
        )
        .unwrap();
    with_fixed_traces
        .large_config
        .dummy_config
        .assign_opcode_circuit(
            &with_fixed_traces.large_config.zkvm_cs,
            &mut zkvm_witness,
            dummy_records,
        )
        .unwrap();
    zkvm_witness.finalize_lk_multiplicities();

    // assign table circuits
    with_fixed_traces
        .large_config
        .config
        .assign_table_circuit(&with_fixed_traces.large_config.zkvm_cs, &mut zkvm_witness)
        .unwrap();
    with_fixed_traces
        .large_config
        .mmu_config
        .assign_table_circuit(
            &with_fixed_traces.large_config.zkvm_cs,
            &mut zkvm_witness,
            &sim_result.final_mem_state.reg,
            &sim_result.final_mem_state.mem,
            &sim_result
                .final_mem_state
                .io
                .iter()
                .map(|rec| rec.cycle)
                .collect_vec(),
            &sim_result.final_mem_state.priv_io,
        )
        .unwrap();
    // assign program circuit
    zkvm_witness
        .assign_table_circuit::<ExampleProgramTableCircuit<E>>(
            &with_fixed_traces.large_config.zkvm_cs,
            &with_fixed_traces.large_config.prog_config,
            &program,
        )
        .unwrap();

    WithWitness {
        with_fixed_traces,
        zkvm_witnesses: zkvm_witness,
    }
}

pub fn run_e2e(
    program: Program,
    platform: Platform,
    stack_size: u32,
    heap_size: u32,
    hints: Vec<u32>,
    max_steps: usize,
) {
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
    // let mut zkvm_cs = ZKVMConstraintSystem::new_with_platform(program_params);

    // let config = Rv32imConfig::<E>::construct_circuits(&mut zkvm_cs);
    // let mmu_config = MmuConfig::<E>::construct_circuits(&mut zkvm_cs);
    // let dummy_config = DummyExtraConfig::<E>::construct_circuits(&mut zkvm_cs);
    // let prog_config = zkvm_cs.register_table_circuit::<ExampleProgramTableCircuit<E>>();
    // zkvm_cs.register_global_state::<GlobalState>();

    let large_config = construct_configs(program_params);
    // IO is not used in this program, but it must have a particular size at the moment.
    let io_init = mem_padder.padded_sorted(large_config.mmu_config.public_io_len(), vec![]);
    let reg_init = large_config.mmu_config.initial_registers();

    let init_full_mem = InitMemState {
        mem: mem_init,
        reg: reg_init,
        io: io_init,
        priv_io: vec![],
    };

    let with_fixed_traces = construct_with_fixed_traces(large_config, &init_full_mem, &program);

    let sim_result = simulate_program(&program, max_steps, init_full_mem, &platform, hints.clone());

    // Clone some sim_result fields before consuming
    let pi = sim_result.pi.clone();
    let exit_code = sim_result.exit_code;
    let cycle_num = sim_result.all_records.len();

    let with_witness = construct_with_witness(with_fixed_traces, sim_result, &program);

    // keygen
    let pcs_param = Pcs::setup(1 << MAX_NUM_VARIABLES).expect("Basefold PCS setup");
    let (pp, vp) = Pcs::trim(pcs_param, 1 << MAX_NUM_VARIABLES).expect("Basefold trim");
    let pk = with_witness
        .with_fixed_traces
        .large_config
        .zkvm_cs
        .clone()
        .key_gen::<Pcs>(
            pp.clone(),
            vp.clone(),
            with_witness.with_fixed_traces.zkvm_fixed_traces.clone(),
        )
        .expect("keygen failed");
    let vk = pk.get_vk();

    // proving
    let e2e_start = Instant::now();
    let prover = ZKVMProver::new(pk);
    let verifier = ZKVMVerifier::new(vk);

    if std::env::var("MOCK_PROVING").is_ok() {
        MockProver::assert_satisfied_full(
            &with_witness.with_fixed_traces.large_config.zkvm_cs,
            with_witness.with_fixed_traces.zkvm_fixed_traces,
            &with_witness.zkvm_witnesses,
            &pi,
        );
        tracing::info!("Mock proving passed");
    }
    let timer = Instant::now();

    let transcript = Transcript::new(b"riscv");
    let mut zkvm_proof = prover
        .create_proof(with_witness.zkvm_witnesses, pi, transcript)
        .expect("create_proof failed");

    let proving_time = timer.elapsed().as_secs_f64();
    let e2e_time = e2e_start.elapsed().as_secs_f64();
    let witgen_time = e2e_time - proving_time;

    println!(
        "Proving finished.\n\
\tProving time = {:.3}s, freq = {:.3}khz\n\
\tWitgen  time = {:.3}s, freq = {:.3}khz\n\
\tTotal   time = {:.3}s, freq = {:.3}khz\n\
\tthread num: {}",
        proving_time,
        cycle_num as f64 / proving_time / 1000.0,
        witgen_time,
        cycle_num as f64 / witgen_time / 1000.0,
        e2e_time,
        cycle_num as f64 / e2e_time / 1000.0,
        rayon::current_num_threads()
    );

    let transcript = Transcript::new(b"riscv");
    assert!(
        verifier
            .verify_proof_halt(zkvm_proof.clone(), transcript, exit_code.is_some())
            .expect("verify proof return with error"),
    );
    match exit_code {
        Some(0) => tracing::info!("exit code 0. Success."),
        Some(code) => tracing::error!("exit code {}. Failure.", code),
        None => tracing::error!("Unfinished execution. max_steps={:?}.", max_steps),
    }

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
