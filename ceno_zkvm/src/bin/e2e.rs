use ceno_emul::{
    ByteAddr, CENO_PLATFORM, EmuContext, InsnKind::EANY, IterAddresses, Platform, Program,
    StepRecord, Tracer, VMState, WORD_SIZE, Word, WordAddr,
};
use ceno_zkvm::{
    instructions::riscv::{DummyExtraConfig, MemPadder, MmuConfig, Rv32imConfig},
    scheme::{
        PublicValues, constants::MAX_NUM_VARIABLES, mock_prover::MockProver, prover::ZKVMProver,
        verifier::ZKVMVerifier,
    },
    state::GlobalState,
    structs::{ProgramParams, ZKVMConstraintSystem, ZKVMFixedTraces, ZKVMWitnesses},
    tables::{MemFinalRecord, MemInitRecord, ProgramTableCircuit},
};
use clap::{Parser, ValueEnum};
use ff_ext::ff::Field;
use goldilocks::GoldilocksExt2;
use itertools::{Itertools, MinMaxResult, chain, enumerate};
use mpcs::{Basefold, BasefoldRSParams, PolynomialCommitmentScheme};
use std::{
    collections::{HashMap, HashSet},
    fs,
    iter::zip,
    panic,
    time::Instant,
};
use tracing::level_filters::LevelFilter;
use tracing_flame::FlameLayer;
use tracing_subscriber::{EnvFilter, Registry, fmt, layer::SubscriberExt};
use transcript::Transcript;

/// Prove the execution of a fixed RISC-V program.
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// The path to the ELF file to execute.
    elf: String,

    /// The maximum number of steps to execute the program.
    #[arg(short, long)]
    max_steps: Option<usize>,

    /// The preset configuration to use.
    #[arg(short, long, value_enum, default_value_t = Preset::Ceno)]
    platform: Preset,

    /// Hints: prover-private unconstrained input.
    /// This is a raw file mapped as a memory segment.
    /// Zero-padded to the right to the next power-of-two size.
    #[arg(long)]
    hints: Option<String>,

    /// Stack size in bytes.
    #[arg(long, default_value = "32768")]
    stack_size: u32,

    /// Heap size in bytes.
    #[arg(long, default_value = "2097152")]
    heap_size: u32,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum Preset {
    Ceno,
    Sp1,
}

fn main() {
    let args = {
        let mut args = Args::parse();
        args.stack_size = args.stack_size.next_multiple_of(WORD_SIZE as u32);
        args.heap_size = args.heap_size.next_multiple_of(WORD_SIZE as u32);
        args
    };

    type E = GoldilocksExt2;
    type Pcs = Basefold<GoldilocksExt2, BasefoldRSParams>;
    type ExampleProgramTableCircuit<E> = ProgramTableCircuit<E>;

    // set up logger
    let (flame_layer, _guard) = FlameLayer::with_file("./tracing.folded").unwrap();
    let subscriber = Registry::default()
        .with(
            fmt::layer()
                .compact()
                .with_thread_ids(false)
                .with_thread_names(false),
        )
        .with(
            EnvFilter::builder()
                .with_default_directive(LevelFilter::DEBUG.into())
                .from_env_lossy(),
        )
        .with(flame_layer.with_threads_collapsed(true));
    tracing::subscriber::set_global_default(subscriber).unwrap();

    let elf_bytes = fs::read(&args.elf).expect("read elf file");
    let program = Program::load_elf(&elf_bytes, u32::MAX).unwrap();

    let platform = match args.platform {
        Preset::Ceno => CENO_PLATFORM,
        Preset::Sp1 => Platform {
            // The stack section is not mentioned in ELF headers, so we repeat the constant STACK_TOP here.
            stack_top: 0x0020_0400,
            rom: program.base_address
                ..program.base_address + (program.instructions.len() * WORD_SIZE) as u32,
            ram: 0x0010_0000..0xFFFF_0000,
            unsafe_ecall_nop: true,
            ..CENO_PLATFORM
        },
    };
    tracing::info!("Running on platform {:?} {:?}", args.platform, platform);
    tracing::info!(
        "Stack: {} bytes. Heap: {} bytes.",
        args.stack_size,
        args.heap_size
    );

    let stack_addrs = platform.stack_top - args.stack_size..platform.stack_top;

    // Detect heap as starting after program data.
    let heap_start = program.image.keys().max().unwrap() + WORD_SIZE as u32;
    let heap_addrs = heap_start..heap_start + args.heap_size;

    let mut mem_padder = MemPadder::new(heap_addrs.end..platform.ram.end);

    let mem_init = {
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
    };

    tracing::info!("Loading ELF file: {}", args.elf);
    let mut vm = VMState::new(platform.clone(), program);

    tracing::info!("Loading hints file: {:?}", args.hints);
    let hints = memory_from_file(&args.hints);
    assert!(
        hints.len() <= platform.hints.iter_addresses().len(),
        "hints must fit in {} bytes",
        platform.hints.len()
    );
    for (addr, value) in zip(platform.hints.iter_addresses(), &hints) {
        vm.init_memory(addr.into(), *value);
    }

    // keygen
    let pcs_param = Pcs::setup(1 << MAX_NUM_VARIABLES).expect("Basefold PCS setup");
    let (pp, vp) = Pcs::trim(pcs_param, 1 << MAX_NUM_VARIABLES).expect("Basefold trim");
    let program_params = ProgramParams {
        platform: platform.clone(),
        program_size: vm.program().instructions.len(),
        static_memory_len: mem_init.len(),
        ..ProgramParams::default()
    };
    let mut zkvm_cs = ZKVMConstraintSystem::new_with_platform(program_params);

    let config = Rv32imConfig::<E>::construct_circuits(&mut zkvm_cs);
    let mmu_config = MmuConfig::<E>::construct_circuits(&mut zkvm_cs);
    let dummy_config = DummyExtraConfig::<E>::construct_circuits(&mut zkvm_cs);
    let prog_config = zkvm_cs.register_table_circuit::<ExampleProgramTableCircuit<E>>();
    zkvm_cs.register_global_state::<GlobalState>();

    let mut zkvm_fixed_traces = ZKVMFixedTraces::default();

    zkvm_fixed_traces.register_table_circuit::<ExampleProgramTableCircuit<E>>(
        &zkvm_cs,
        &prog_config,
        vm.program(),
    );

    // IO is not used in this program, but it must have a particular size at the moment.
    let io_init = mem_padder.padded_sorted(mmu_config.public_io_len(), vec![]);

    let reg_init = mmu_config.initial_registers();
    config.generate_fixed_traces(&zkvm_cs, &mut zkvm_fixed_traces);
    mmu_config.generate_fixed_traces(
        &zkvm_cs,
        &mut zkvm_fixed_traces,
        &reg_init,
        &mem_init,
        &io_init.iter().map(|rec| rec.addr).collect_vec(),
    );
    dummy_config.generate_fixed_traces(&zkvm_cs, &mut zkvm_fixed_traces);

    let pk = zkvm_cs
        .clone()
        .key_gen::<Pcs>(pp.clone(), vp.clone(), zkvm_fixed_traces.clone())
        .expect("keygen failed");
    let vk = pk.get_vk();

    // proving
    let e2e_start = Instant::now();
    let prover = ZKVMProver::new(pk);
    let verifier = ZKVMVerifier::new(vk);

    let all_records = vm
        .iter_until_halt()
        .take(args.max_steps.unwrap_or(usize::MAX))
        .collect::<Result<Vec<StepRecord>, _>>()
        .expect("vm exec failed");

    let cycle_num = all_records.len();
    tracing::info!("Proving {} execution steps", cycle_num);
    for (i, step) in enumerate(&all_records).rev().take(5).rev() {
        tracing::trace!("Step {i}: {:?} - {:?}\n", step.insn().codes().kind, step);
    }

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

    let mut zkvm_witness = ZKVMWitnesses::default();
    // assign opcode circuits
    let dummy_records = config
        .assign_opcode_circuit(&zkvm_cs, &mut zkvm_witness, all_records)
        .unwrap();
    dummy_config
        .assign_opcode_circuit(&zkvm_cs, &mut zkvm_witness, dummy_records)
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
    debug_memory_ranges(&vm, &mem_final);

    // Find the final public IO cycles.
    let io_final = io_init
        .iter()
        .map(|rec| *final_access.get(&rec.addr.into()).unwrap_or(&0))
        .collect_vec();

    let priv_io_final = zip(platform.hints.iter_addresses(), &hints)
        .map(|(addr, &value)| MemFinalRecord {
            addr,
            value,
            cycle: *final_access.get(&addr.into()).unwrap_or(&0),
        })
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
            &io_final,
            &priv_io_final,
        )
        .unwrap();
    // assign program circuit
    zkvm_witness
        .assign_table_circuit::<ExampleProgramTableCircuit<E>>(&zkvm_cs, &prog_config, vm.program())
        .unwrap();

    if std::env::var("MOCK_PROVING").is_ok() {
        MockProver::assert_satisfied_full(zkvm_cs, zkvm_fixed_traces, &zkvm_witness, &pi);
        tracing::info!("Mock proving passed");
    }
    let timer = Instant::now();

    let transcript = Transcript::new(b"riscv");
    let mut zkvm_proof = prover
        .create_proof(zkvm_witness, pi, transcript)
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
        None => tracing::error!("Unfinished execution. max_steps={:?}.", args.max_steps),
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

fn memory_from_file(path: &Option<String>) -> Vec<u32> {
    path.as_ref()
        .map(|path| {
            let mut buf = fs::read(path).expect("could not read file");
            buf.resize(buf.len().next_multiple_of(WORD_SIZE), 0);
            buf.chunks_exact(WORD_SIZE)
                .map(|word| Word::from_le_bytes(word.try_into().unwrap()))
                .collect_vec()
        })
        .unwrap_or_default()
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
