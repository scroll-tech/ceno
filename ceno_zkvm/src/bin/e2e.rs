use ceno_emul::{IterAddresses, Program, WORD_SIZE, Word};
use ceno_host::CenoStdin;
use ceno_zkvm::{
    e2e::{Checkpoint, Preset, run_e2e_with_checkpoint, setup_platform},
    with_panic_hook,
};
use clap::Parser;
use ff_ext::ff::Field;
use goldilocks::{Goldilocks, GoldilocksExt2};
use itertools::Itertools;
use mpcs::{Basefold, BasefoldRSParams};
use std::{fs, panic};
use tracing::level_filters::LevelFilter;
use tracing_forest::ForestLayer;
use tracing_subscriber::{
    EnvFilter, Registry, filter::filter_fn, fmt, layer::SubscriberExt, util::SubscriberInitExt,
};
use transcript::{
    BasicTranscript as Transcript, BasicTranscriptWithStat as TranscriptWithStat, StatisticRecorder,
};

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

    #[arg(long, default_value = "100")]
    n: u32,

    /// Stack size in bytes.
    #[arg(long, default_value = "32768")]
    stack_size: u32,

    /// Heap size in bytes.
    #[arg(long, default_value = "2097152")]
    heap_size: u32,
}

fn main() {
    let args = {
        let mut args = Args::parse();
        args.stack_size = args.stack_size.next_multiple_of(WORD_SIZE as u32);
        args.heap_size = args.heap_size.next_multiple_of(WORD_SIZE as u32);
        args
    };
    let pub_io_size = 16; // TODO: configure.

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

    tracing::info!("Loading ELF file: {}", &args.elf);
    // let elf_bytes = fs::read(&args.elf).expect("read elf file");
    let elf_bytes = ceno_examples::sorting;
    let program = Program::load_elf(&elf_bytes, u32::MAX).unwrap();
    let platform = setup_platform(
        args.platform,
        &program,
        args.stack_size,
        args.heap_size,
        pub_io_size,
    );
    tracing::info!("Running on platform {:?} {:?}", args.platform, platform);
    tracing::info!(
        "Stack: {} bytes. Heap: {} bytes.",
        args.stack_size,
        args.heap_size
    );

    tracing::info!("Loading hints file: {:?}", args.hints);
    // let hints = memory_from_file(&args.hints);
    let mut hints = CenoStdin::default();
    _ = hints.write(&args.n);
    let hints: Vec<u32> = (&hints).into();
    assert!(
        hints.len() <= platform.hints.iter_addresses().len(),
        "hints must fit in {} bytes",
        platform.hints.len()
    );

    let max_steps = args.max_steps.unwrap_or(usize::MAX);

    type E = GoldilocksExt2;
    type B = Goldilocks;
    type Pcs = Basefold<GoldilocksExt2, BasefoldRSParams>;

    let (state, _) = run_e2e_with_checkpoint::<E, Pcs>(
        program,
        platform,
        hints,
        max_steps,
        Checkpoint::PrepSanityCheck,
    );

    let (mut zkvm_proof, verifier) = state.expect("PrepSanityCheck should yield state.");

    // do statistics
    let serialize_size = bincode::serialize(&zkvm_proof).unwrap().len();
    let stat_recorder = StatisticRecorder::default();
    let transcript = TranscriptWithStat::new(&stat_recorder, b"riscv");
    verifier.verify_proof(zkvm_proof.clone(), transcript).ok();
    println!(
        "e2e proof stat: proof size = {}, hashes count = {}",
        serialize_size,
        stat_recorder.into_inner().field_appended_num
    );

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
