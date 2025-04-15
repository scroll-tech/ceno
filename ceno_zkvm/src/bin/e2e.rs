use ceno_emul::{IterAddresses, Program, WORD_SIZE, Word};
use ceno_host::{CenoStdin, memory_from_file};
use ceno_zkvm::e2e::{Checkpoint, E, Pcs, Preset, run_e2e_with_checkpoint, setup_platform, verify};
use clap::Parser;
use tracing::level_filters::LevelFilter;
use tracing_forest::ForestLayer;
use tracing_subscriber::{
    EnvFilter, Registry, filter::filter_fn, fmt, layer::SubscriberExt, util::SubscriberInitExt,
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
    // /// The path to the ELF file to execute.
    // elf: String,
    /// The path to the proof file to write.
    #[arg(default_value = "proof.bin")]
    proof_file: String,

    /// The path to the verification key file to write.
    #[arg(default_value = "vk.bin")]
    vk_file: String,

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
    #[arg(long, conflicts_with = "hints")]
    hints_file: Option<String>,

    #[arg(long, conflicts_with = "hints_file", value_parser, num_args = 1.., value_delimiter = ',')]
    hints: Option<Vec<Word>>,

    #[arg(long, default_value = "100")]
    n: u32,

    /// Stack size in bytes.
    #[arg(long, default_value = "2M", value_parser = parse_size)]
    stack_size: u32,

    /// Heap size in bytes.
    #[arg(long, default_value = "2M", value_parser = parse_size)]
    heap_size: u32,

    #[arg(long, value_parser, num_args = 1.., value_delimiter = ',')]
    public_io: Option<Vec<Word>>,
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

    // process public input first
    let public_io = args
        .public_io
        .and_then(|public_io| {
            public_io
                .iter()
                .try_fold(CenoStdin::default(), |mut std_in, public_io| {
                    std_in.write(public_io)?;
                    Ok::<CenoStdin, rkyv::rancor::Error>(std_in)
                })
                .ok()
                .map(|std_in| Into::<Vec<u32>>::into(&std_in))
        })
        .unwrap_or_default();

    // estimate required pub io size, which is required in platform/key setup phase
    let pub_io_size: u32 = ((public_io.len() * WORD_SIZE) as u32)
        .next_power_of_two()
        .max(16);

    // tracing::info!("Loading ELF file: {}", &args.elf);
    // let elf_bytes = fs::read(&args.elf).expect("read elf file");
    let elf_bytes = ceno_examples::ceno_rt_mini;
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

    let hints = args
        .hints_file
        .as_ref()
        .map(|file_path| {
            tracing::info!("Loading hints file: {:?}", file_path);
            let hints = memory_from_file(file_path).expect("failed to read hints file");
            assert!(
                hints.len() <= platform.hints.iter_addresses().len(),
                "hints must fit in {} bytes",
                platform.hints.len()
            );
            hints
        })
        .or_else(|| {
            args.hints.and_then(|hint| {
                hint.iter()
                    .try_fold(CenoStdin::default(), |mut std_in, hint| {
                        std_in.write(hint)?;
                        Ok::<CenoStdin, rkyv::rancor::Error>(std_in)
                    })
                    .ok()
                    .map(|std_in| Into::<Vec<u32>>::into(&std_in))
            })
        })
        .unwrap_or_default();

    let max_steps = args.max_steps.unwrap_or(usize::MAX);

    let ((zkvm_proof, vk), _) = run_e2e_with_checkpoint::<E, Pcs>(
        program,
        platform,
        hints,
        public_io,
        max_steps,
        Checkpoint::PrepSanityCheck,
    );

    let zkvm_proof = zkvm_proof.expect("PrepSanityCheck should yield zkvm_proof.");
    let vk = vk.expect("PrepSanityCheck should yield vk.");

    let proof_bytes = bincode::serialize(&zkvm_proof).unwrap();
    std::fs::write(&args.proof_file, proof_bytes).unwrap();
    let vk_bytes = bincode::serialize(&vk).unwrap();
    std::fs::write(&args.vk_file, vk_bytes).unwrap();

    verify(zkvm_proof, vk).expect("Verification failed");
}
