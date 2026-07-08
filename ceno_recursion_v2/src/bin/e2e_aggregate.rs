use std::{fs, path::PathBuf, sync::Arc};

use ceno_emul::{IterAddresses, Program, WORD_SIZE, Word};
use ceno_host::{CenoStdin, memory_from_file};
use ceno_recursion_v2::{
    continuation::prover::{AggProver, AggregationOptions},
    system::{RecursionField, RecursionPcs, utils::test_system_params_zero_pow},
};
use ceno_zkvm::{
    e2e::{
        Checkpoint, MultiProver, Preset, public_io_words_to_digest_words, run_e2e_with_checkpoint,
        setup_platform, setup_platform_debug,
    },
    scheme::{constants::MAX_NUM_VARIABLES, create_backend, create_prover, hal::ProverDevice},
};
use clap::Parser;
use eyre::{Context, ContextCompat, Result, eyre};
use gkr_iop::hal::ProverBackend;
use mpcs::SecurityLevel;

fn parse_size(s: &str) -> Result<u32, parse_size::Error> {
    parse_size::Config::new()
        .with_binary()
        .parse_size(s)
        .map(|size| size as u32)
}

/// Generate Ceno base proofs for an ELF and aggregate them with recursion v2.
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// The path to the ELF file to execute.
    elf: PathBuf,

    /// The preset configuration to use.
    #[arg(long, value_enum, default_value_t = Preset::Ceno)]
    platform: Preset,

    /// The maximum number of steps to execute the program.
    #[arg(short, long)]
    max_steps: Option<usize>,

    /// Prover-private unconstrained input from a raw memory file.
    #[arg(long, conflicts_with = "hints")]
    hints_file: Option<PathBuf>,

    /// Prover-private unconstrained input as u32 words.
    #[arg(long, conflicts_with = "hints_file", value_parser, num_args = 1.., value_delimiter = ',')]
    hints: Option<Vec<Word>>,

    /// Public constrained input as u32 words.
    #[arg(long, value_parser, num_args = 1.., value_delimiter = ',')]
    public_io: Option<Vec<Word>>,

    /// Stack size in bytes.
    #[arg(long, default_value = "2M", value_parser = parse_size)]
    stack_size: u32,

    /// Heap size in bytes.
    #[arg(long, default_value = "2M", value_parser = parse_size)]
    heap_size: u32,

    /// Max number of PCS variables.
    #[arg(long, default_value_t = MAX_NUM_VARIABLES)]
    max_num_variables: usize,

    /// The security level to use.
    #[arg(short, long, value_enum, default_value_t = SecurityLevel::default())]
    security_level: SecurityLevel,

    /// Prover id.
    #[arg(long, default_value_t = 0)]
    prover_id: u32,

    /// Number of available provers.
    #[arg(long, default_value_t = 1)]
    num_provers: u32,

    /// Max cycles per shard.
    #[arg(long, default_value_t = 536_870_912)]
    max_cycle_per_shard: u64,

    /// Max cells per shard.
    #[arg(long, default_value_t = 2_147_483_648)]
    max_cell_per_shard: u64,

    /// Only generate and aggregate a specific shard.
    #[arg(long)]
    shard_id: Option<u64>,
}

fn main() -> Result<()> {
    tracing_subscriber::fmt::try_init().ok();

    let mut args = Args::parse();
    args.stack_size = args.stack_size.next_multiple_of(WORD_SIZE as u32);
    args.heap_size = args.heap_size.next_multiple_of(WORD_SIZE as u32);

    let elf_bytes = fs::read(&args.elf).wrap_err_with(|| {
        format!(
            "failed to read ELF for recursion-v2 aggregation: {}",
            args.elf.display()
        )
    })?;
    let program = Program::load_elf(&elf_bytes, u32::MAX)
        .map_err(|err| eyre!("failed to load ELF: {err:#}"))?;
    let platform = if cfg!(debug_assertions) {
        setup_platform_debug(args.platform, &program, args.stack_size, args.heap_size)
    } else {
        setup_platform(args.platform, &program, args.stack_size, args.heap_size)
    };

    let hints = read_hints(&args, &platform)?;
    let public_io = args.public_io.as_deref().unwrap_or_default();
    let public_io_digest = public_io_words_to_digest_words(public_io);
    let multi_prover = MultiProver::new(
        args.prover_id as usize,
        args.num_provers as usize,
        args.max_cell_per_shard,
        args.max_cycle_per_shard,
    );
    let backend = create_backend(args.max_num_variables, args.security_level);
    let prover = create_prover(backend);

    run_aggregate(
        prover,
        program,
        platform,
        multi_prover,
        &hints,
        public_io_digest,
        args.max_steps.unwrap_or(usize::MAX),
        args.shard_id.map(|v| v as usize),
    )
}

fn read_hints(args: &Args, platform: &ceno_emul::Platform) -> Result<Vec<u32>> {
    if let Some(file_path) = args.hints_file.as_ref() {
        let hints = memory_from_file(file_path)
            .wrap_err_with(|| format!("failed to read hints file {}", file_path.display()))?;
        ensure_hints_fit(&hints, platform);
        return Ok(hints);
    }

    let Some(hints) = args.hints.as_ref() else {
        return Ok(Vec::new());
    };

    let mut stdin = CenoStdin::default();
    if hints.len() == 1 {
        stdin.write(&hints[0])
    } else {
        stdin.write(hints)
    }
    .map_err(|err| eyre!("failed to encode hints: {err:#}"))?;
    let encoded = Vec::<u32>::from(&stdin);

    ensure_hints_fit(&encoded, platform);
    Ok(encoded)
}

fn ensure_hints_fit(hints: &[u32], platform: &ceno_emul::Platform) {
    assert!(
        hints.len() <= platform.hints.iter_addresses().len(),
        "hints must fit in {} bytes",
        platform.hints.len()
    );
}

#[allow(clippy::too_many_arguments)]
fn run_aggregate<PB, PD>(
    pd: PD,
    program: Program,
    platform: ceno_emul::Platform,
    multi_prover: MultiProver,
    hints: &[u32],
    public_io_digest: [u32; 8],
    max_steps: usize,
    target_shard_id: Option<usize>,
) -> Result<()>
where
    PB: ProverBackend<E = RecursionField, Pcs = RecursionPcs> + 'static,
    PD: ProverDevice<PB> + 'static,
{
    let result = run_e2e_with_checkpoint::<RecursionField, RecursionPcs, _, _>(
        pd,
        program,
        platform,
        multi_prover,
        hints,
        public_io_digest,
        max_steps,
        Checkpoint::Complete,
        target_shard_id,
    );

    let shard_proofs = result
        .proofs
        .wrap_err("base proving did not return proofs")?;
    let child_vk = result.vk.wrap_err("base proving did not return a vk")?;
    let options = AggregationOptions::new(test_system_params_zero_pow(5, 16, 3));
    let prover = AggProver::<2, 2>::new(Arc::new(child_vk), options);
    let root_output = prover.prove_with_root_vk(&shard_proofs)?;
    prover.verify_root_proof(&root_output.root_vk, &root_output.root_proof)?;
    let proof_size = bincode::serialized_size(&root_output.root_proof)?;
    println!(
        "recursion-v2 root proof size: {proof_size} bytes ({:.2} MiB)",
        proof_size as f64 / (1024.0 * 1024.0)
    );

    tracing::info!(
        shard_count = shard_proofs.len(),
        proof_size_bytes = proof_size,
        "recursion-v2 aggregation produced a root proof"
    );
    Ok(())
}
