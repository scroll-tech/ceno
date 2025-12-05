use ceno_emul::{IterAddresses, Program, WORD_SIZE, Word};
use ceno_host::{CenoStdin, memory_from_file};
use ceno_recursion::aggregation::CenoAggregationProver;
use ceno_zkvm::{
    e2e::{
        Checkpoint, FieldType, MultiProver, PcsKind, Preset, run_e2e_with_checkpoint,
        setup_platform, setup_platform_debug,
    },
    scheme::{constants::MAX_NUM_VARIABLES, create_backend, create_prover},
};
use clap::Parser;
use ff_ext::BabyBearExt4;
use mpcs::{Basefold, BasefoldRSParams, SecurityLevel};
use std::{fs, path::PathBuf};
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
    /// The path to the ELF file to execute.
    elf: PathBuf,
    /// The path to the proof file to write.
    #[arg(default_value = "proof.bin")]
    proof_file: PathBuf,

    /// The path to the verification key file to write.
    #[arg(default_value = "vk.bin")]
    vk_file: PathBuf,

    /// The maximum number of steps to execute the program.
    #[arg(short, long)]
    max_steps: Option<usize>,

    // Profiling granularity.
    // Setting any value restricts logs to profiling information
    #[arg(long)]
    profiling: Option<usize>,

    /// The preset configuration to use.
    #[arg(long, value_enum, default_value_t = Preset::Ceno)]
    platform: Preset,

    /// The polynomial commitment scheme to use.
    #[arg(long, value_enum, default_value_t = PcsKind::default())]
    pcs: PcsKind,
    /// The field to use, eg. goldilocks
    #[arg(long, value_enum, default_value_t = FieldType::default())]
    field: FieldType,

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

    /// Max number of variables
    #[clap(long, default_value_t = MAX_NUM_VARIABLES)]
    max_num_variables: usize,

    #[arg(long, value_parser, num_args = 1.., value_delimiter = ',')]
    public_io: Option<Vec<Word>>,

    /// pub io size in byte
    #[arg(long, default_value = "1k", value_parser = parse_size)]
    public_io_size: u32,

    /// The security level to use.
    #[arg(short, long, value_enum, default_value_t = SecurityLevel::default())]
    security_level: SecurityLevel,

    // prover id
    #[arg(long, default_value = "0")]
    prover_id: u32,

    // number of available prover.
    #[arg(long, default_value = "1")]
    num_provers: u32,

    // max cycle per shard
    // default value: 16GB VRAM, each cell 4 byte, log explosion 2
    // => 2^30 * 16 / 4 / 2
    #[arg(long, default_value = "2147483648")]
    max_cell_per_shard: u64,

    // max cycle per shard
    #[arg(long, default_value = "536870912")] // 536870912 = 2^29
    max_cycle_per_shard: u64,
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
            // if the vector contains only one element, write it as a raw `u32`
            // otherwise, write the entire vector
            // in both cases, convert the resulting `CenoStdin` into a `Vec<u32>`
            if public_io.len() == 1 {
                CenoStdin::default()
                    .write(&public_io[0])
                    .ok()
                    .map(|stdin| Into::<Vec<u32>>::into(&*stdin))
            } else {
                CenoStdin::default()
                    .write(&public_io)
                    .ok()
                    .map(|stdin| Into::<Vec<u32>>::into(&*stdin))
            }
        })
        .unwrap_or_default();
    assert!(
        public_io.len() <= args.public_io_size as usize / WORD_SIZE,
        "require pub io length {} < max public_io_size {}",
        public_io.len(),
        args.public_io_size as usize / WORD_SIZE
    );

    tracing::info!("Loading ELF file: {}", args.elf.display());
    let elf_bytes = fs::read(&args.elf).expect("read elf file");
    let program = Program::load_elf(&elf_bytes, u32::MAX).unwrap();
    let platform = if cfg!(debug_assertions) {
        setup_platform_debug(
            args.platform,
            &program,
            args.stack_size,
            args.heap_size,
            args.public_io_size,
        )
    } else {
        setup_platform(
            args.platform,
            &program,
            args.stack_size,
            args.heap_size,
            args.public_io_size,
        )
    };
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
                // if the vector contains only one element, write it as a raw `u32`
                // otherwise, write the entire vector
                // in both cases, convert the resulting `CenoStdin` into a `Vec<u32>`
                if hint.len() == 1 {
                    CenoStdin::default()
                        .write(&hint[0])
                        .ok()
                        .map(|stdin| Into::<Vec<u32>>::into(&*stdin))
                } else {
                    CenoStdin::default()
                        .write(&hint)
                        .ok()
                        .map(|stdin| Into::<Vec<u32>>::into(&*stdin))
                }
            })
        })
        .unwrap_or_default();

    let max_steps = args.max_steps.unwrap_or(usize::MAX);
    let multi_prover = MultiProver::new(
        args.prover_id as usize,
        args.num_provers as usize,
        args.max_cell_per_shard,
        args.max_cycle_per_shard,
    );

    let backend = create_backend(args.max_num_variables, args.security_level);
    let prover = create_prover(backend);
    let result =
        run_e2e_with_checkpoint::<BabyBearExt4, Basefold<BabyBearExt4, BasefoldRSParams>, _, _>(
            prover,
            program,
            platform,
            multi_prover,
            &hints,
            &public_io,
            max_steps,
            Checkpoint::Complete,
            None,
        );

    let zkvm_proofs = result
        .proofs
        .expect("PrepSanityCheck should yield zkvm_proof.");
    let vk = result.vk.expect("PrepSanityCheck should yield vk.");

    let mut agg_prover = CenoAggregationProver::from_base_vk(vk);
    let _ = agg_prover.generate_root_proof(zkvm_proofs);
}
