use ceno_emul::{CENO_PLATFORM, IterAddresses, Platform, Program, WORD_SIZE, Word};
use ceno_zkvm::{
    e2e::{run_e2e_gen_witness, run_e2e_proof, run_e2e_verify},
    with_panic_hook,
};
use clap::{Parser, ValueEnum};
use ff_ext::ff::Field;
use goldilocks::{Goldilocks, GoldilocksExt2};
use itertools::Itertools;
use mpcs::{Basefold, BasefoldRSParams};
use std::{fs, panic, time::Instant};
use tracing::level_filters::LevelFilter;
use tracing_forest::ForestLayer;
use tracing_subscriber::{
    EnvFilter, Registry, filter::filter_fn, fmt, layer::SubscriberExt, util::SubscriberInitExt,
};
use transcript::BasicTranscript as Transcript;

/// Prove the execution of a fixed RISC-V program.
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// The path to the ELF file to execute.
    elf: String,

    /// The maximum number of steps to execute the program.
    #[arg(short, long)]
    max_steps: Option<usize>,

    // Profiling granularity.
    // Setting any value restricts logs to profiling information
    #[arg(long)]
    profiling: Option<usize>,

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

    // default filter
    let default_filter = EnvFilter::builder()
        .with_default_directive(LevelFilter::DEBUG.into())
        .from_env_lossy();

    // filter by profiling level;
    // spans with level i contain the field "profiling_{i}"
    // this restricts statistics to first (args.profiling) levels
    let profiling_level = args.profiling.unwrap_or(1);
    let filter_by_profiling_level = filter_fn(move |metadata| {
        (1..=profiling_level)
            .map(|i| format!("profiling_{i}"))
            .any(|field| metadata.fields().field(&field).is_some())
    });

    let fmt_layer = fmt::layer()
        .compact()
        .with_thread_ids(false)
        .with_thread_names(false)
        .without_time();

    Registry::default()
        .with(args.profiling.is_some().then_some(ForestLayer::default()))
        .with(fmt_layer)
        // if some profiling granularity is specified, use the profiling filter,
        // otherwise use the default
        .with(
            args.profiling
                .is_some()
                .then_some(filter_by_profiling_level),
        )
        .with(args.profiling.is_none().then_some(default_filter))
        .init();

    let args = {
        let mut args = Args::parse();
        args.stack_size = args.stack_size.next_multiple_of(WORD_SIZE as u32);
        args.heap_size = args.heap_size.next_multiple_of(WORD_SIZE as u32);
        args
    };

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

    type E = GoldilocksExt2;
    type B = Goldilocks;
    type Pcs = Basefold<GoldilocksExt2, BasefoldRSParams>;

    let (prover, verifier, zkvm_witness, pi, cycle_num, e2e_start, exit_code) =
        run_e2e_gen_witness::<E, Pcs>(
            program,
            platform,
            args.stack_size,
            args.heap_size,
            hints,
            max_steps,
        );

    let timer = Instant::now();
    let mut zkvm_proof = run_e2e_proof(prover, zkvm_witness, pi);
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

    run_e2e_verify(&verifier, zkvm_proof.clone(), exit_code, max_steps);

    // do sanity check
    let transcript = Transcript::new(b"riscv");
    // change public input maliciously should cause verifier to reject proof
    zkvm_proof.raw_pi[0] = vec![B::ONE];
    zkvm_proof.raw_pi[1] = vec![B::ONE];

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
