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

fn parse_size(s: &str) -> Result<u32, parse_size::Error> {
    parse_size::Config::new()
        .with_binary()
        .parse_size(s)
        .map(|size| size as u32)
}

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
    #[arg(long, conflicts_with = "structured_hints")]
    raw_hints: Option<String>,

    /// Hints: prover-private unconstrained input.
    /// This is a file containing decimal representations of
    /// a value N, followed by N u32 integers.
    /// The N integers are processed so they can be read
    /// directly by guest programs.
    #[arg(long, conflicts_with = "raw_hints")]
    structured_hints: Option<String>,

    /// Stack size in bytes.
    #[arg(long, default_value = "32k", value_parser = parse_size)]
    stack_size: u32,

    /// Heap size in bytes.
    #[arg(long, default_value = "2M", value_parser = parse_size)]
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
    let elf_bytes = fs::read(&args.elf).expect("read elf file");
    let program = Program::load_elf(&elf_bytes, u32::MAX).unwrap();
    let platform = setup_platform(
        args.platform,
        &program,
        args.stack_size,
        args.heap_size,
        pub_io_size,
    );
    tracing::info!("Running on platform {:?} {}", args.platform, platform);
    tracing::info!(
        "Stack: {} bytes. Heap: {} bytes.",
        args.stack_size,
        args.heap_size
    );

    let (hints, filename) = if args.raw_hints.is_some() {
        (read_raw_hints(&args.raw_hints), args.raw_hints)
    } else if args.structured_hints.is_some() {
        (
            read_structured_hints(&args.structured_hints),
            args.structured_hints,
        )
    } else {
        (vec![], None)
    };

    tracing::info!("Loading hints file: {:?}", filename);

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
fn read_raw_hints(path: &Option<String>) -> Vec<u32> {
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

/// Reads a sequence of u32s and formats it as guest input
fn read_structured_hints(path: &Option<String>) -> Vec<u32> {
    let structured_hints =
        fs::read_to_string(path.as_ref().unwrap()).expect("could not read structured hints file");

    let mut parts = structured_hints.split_whitespace();
    let n: usize = parts.next().unwrap().parse().expect("could not parse N");
    let values: Vec<u32> = parts
        .take(n)
        .map(|part| part.parse().expect("could not parse hint"))
        .collect();

    // Serialize the read values into the suitable format
    let mut input = CenoStdin::default();
    input.write(&values).unwrap();
    (&input).into()
}
