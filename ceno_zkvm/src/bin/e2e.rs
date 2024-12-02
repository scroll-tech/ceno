use ceno_emul::{
    ByteAddr, CENO_PLATFORM, EmuContext, InsnKind::EANY, IterAddresses, Platform, Program,
    StepRecord, Tracer, VMState, WORD_SIZE, Word, WordAddr,
};
use ceno_zkvm::{
    e2e::run_e2e,
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
    usize,
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

    let args = {
        let mut args = Args::parse();
        args.stack_size = args.stack_size.next_multiple_of(WORD_SIZE as u32);
        args.heap_size = args.heap_size.next_multiple_of(WORD_SIZE as u32);
        args
    };

    type E = GoldilocksExt2;
    type Pcs = Basefold<GoldilocksExt2, BasefoldRSParams>;
    type ExampleProgramTableCircuit<E> = ProgramTableCircuit<E>;

    tracing::info!("Loading ELF file: {}", &args.elf);
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

    tracing::info!("Loading hints file: {:?}", args.hints);
    let hints = memory_from_file(&args.hints);
    assert!(
        hints.len() <= platform.hints.iter_addresses().len(),
        "hints must fit in {} bytes",
        platform.hints.len()
    );

    let max_steps = args.max_steps.unwrap_or(usize::MAX);
    run_e2e(
        program,
        platform,
        args.stack_size,
        args.heap_size,
        hints,
        max_steps,
    );
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
