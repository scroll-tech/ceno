use std::{path::PathBuf, sync::Arc, thread};

use ceno_recursion_v2::{continuation::prover::InnerCpuProver, system::RecursionVk};
use clap::{Parser, ValueEnum};
use eyre::{Result, bail};
use openvm_stark_backend::{
    SystemParams, WhirConfig, WhirParams, WhirProximityStrategy,
    interaction::LogUpSecurityParameters,
};
use openvm_stark_sdk::config::baby_bear_poseidon2::{BabyBearPoseidon2CpuEngine, DuplexSponge};
use serde::Serialize;

type Engine = BabyBearPoseidon2CpuEngine<DuplexSponge>;

#[derive(Clone, Copy, Debug, ValueEnum)]
enum OutputFormat {
    Table,
    Json,
}

#[derive(Parser, Debug)]
#[command(about = "Run recursion-v2 keygen and print per-AIR metadata")]
struct Args {
    /// Path to a bincode-serialized Ceno ZKVM verifying key.
    #[arg(long)]
    vk: Option<PathBuf>,

    /// Directory used to find vk.bin when --vk is omitted.
    #[arg(long)]
    fixture_dir: Option<PathBuf>,

    /// Maximum number of child proofs verified by the recursion circuit.
    #[arg(long, default_value_t = 2)]
    max_num_proofs: usize,

    /// l_skip used for the small local SystemParams profile.
    #[arg(long, default_value_t = 5)]
    l_skip: usize,

    /// n_stack used for the small local SystemParams profile.
    #[arg(long, default_value_t = 16)]
    n_stack: usize,

    /// k_whir used for the small local SystemParams profile.
    #[arg(long, default_value_t = 3)]
    k_whir: usize,

    /// Configured global SystemParams.max_constraint_degree for keygen.
    #[arg(long, default_value_t = 5)]
    max_constraint_degree: usize,

    /// Output format.
    #[arg(long, value_enum, default_value_t = OutputFormat::Table)]
    format: OutputFormat,
}

#[derive(Serialize)]
struct KeygenMeta {
    vk_path: PathBuf,
    max_num_proofs: usize,
    configured_max_constraint_degree: usize,
    keygen_max_constraint_degree: usize,
    air_count: usize,
    total_trace_width: usize,
    max_air_constraint_degree: u8,
    airs: Vec<AirMeta>,
}

#[derive(Serialize)]
struct AirMeta {
    air_idx: usize,
    air_name: String,
    trace_width: TraceWidthMeta,
    max_constraint_degree: u8,
    num_constraints: usize,
    num_interactions: usize,
    need_rot: bool,
    is_required: bool,
}

#[derive(Serialize)]
struct TraceWidthMeta {
    preprocessed: Option<usize>,
    cached_mains: Vec<usize>,
    common_main: usize,
    main: usize,
    total: usize,
}

fn main() -> Result<()> {
    thread::Builder::new()
        .name("air-keygen-meta".to_string())
        .stack_size(64 * 1024 * 1024)
        .spawn(run)?
        .join()
        .map_err(|err| eyre::eyre!("air-keygen-meta thread panicked: {err:?}"))?
}

fn run() -> Result<()> {
    let args = Args::parse();
    let vk_path = vk_path(&args)?;
    let child_vk = load_vk(&vk_path)?;
    let params = system_params_zero_pow(
        args.l_skip,
        args.n_stack,
        args.k_whir,
        args.max_constraint_degree,
    );

    let meta = match args.max_num_proofs {
        1 => extract_keygen_meta::<1>(vk_path, child_vk, params),
        2 => extract_keygen_meta::<2>(vk_path, child_vk, params),
        4 => extract_keygen_meta::<4>(vk_path, child_vk, params),
        8 => extract_keygen_meta::<8>(vk_path, child_vk, params),
        16 => extract_keygen_meta::<16>(vk_path, child_vk, params),
        max_num_proofs => bail!(
            "unsupported --max-num-proofs={max_num_proofs}; supported values are 1, 2, 4, 8, 16"
        ),
    }?;

    match args.format {
        OutputFormat::Table => print_table(&meta),
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&meta)?),
    }

    Ok(())
}

fn vk_path(args: &Args) -> Result<PathBuf> {
    if let Some(path) = args.vk.clone() {
        return Ok(path);
    }

    let dirs = args
        .fixture_dir
        .clone()
        .into_iter()
        .chain(std::env::var_os("CENO_RECURSION_V2_FIXTURE_DIR").map(PathBuf::from))
        .chain([PathBuf::from("./src/imported")]);

    for dir in dirs {
        let path = dir.join("vk.bin");
        if path.exists() {
            return Ok(path);
        }
    }

    bail!("could not find vk.bin; pass --vk or --fixture-dir")
}

fn load_vk(path: &PathBuf) -> Result<RecursionVk> {
    let bytes = std::fs::read(path)?;
    let mut vk: RecursionVk = bincode::deserialize(&bytes)?;
    vk.rebuild_circuit_index();
    Ok(vk)
}

fn system_params_zero_pow(
    l_skip: usize,
    n_stack: usize,
    k_whir: usize,
    max_constraint_degree: usize,
) -> SystemParams {
    let log_final_poly_len = (n_stack + l_skip) % k_whir;
    let log_blowup = 1;
    let mut params = SystemParams {
        l_skip,
        n_stack,
        w_stack: 1 << 12,
        log_blowup,
        whir: whir_config_small(log_blowup, l_skip + n_stack, k_whir, log_final_poly_len),
        logup: LogUpSecurityParameters {
            max_interaction_count: 1 << 30,
            log_max_message_length: 7,
            pow_bits: 2,
        },
        max_constraint_degree,
    };
    params.whir.mu_pow_bits = 0;
    params.whir.folding_pow_bits = 0;
    params.whir.query_phase_pow_bits = 0;
    params
}

fn whir_config_small(
    log_blowup: usize,
    log_stacked_height: usize,
    k_whir: usize,
    log_final_poly_len: usize,
) -> WhirConfig {
    let params = WhirParams {
        k: k_whir,
        log_final_poly_len,
        query_phase_pow_bits: 1,
        folding_pow_bits: 2,
        mu_pow_bits: 3,
        proximity: WhirProximityStrategy::SplitUniqueList {
            m: 3,
            list_start_round: 1,
        },
    };
    WhirConfig::new(log_blowup, log_stacked_height, params, 5)
}

fn extract_keygen_meta<const MAX_NUM_PROOFS: usize>(
    vk_path: PathBuf,
    child_vk: RecursionVk,
    params: SystemParams,
) -> Result<KeygenMeta> {
    let configured_max_constraint_degree = params.max_constraint_degree;
    let prover =
        InnerCpuProver::<MAX_NUM_PROOFS>::new::<Engine>(Arc::new(child_vk), params, false, None);
    let air_names = prover.air_names();
    let vk = prover.get_vk();

    if air_names.len() != vk.inner.per_air.len() {
        bail!(
            "AIR name count ({}) did not match keygen VK AIR count ({})",
            air_names.len(),
            vk.inner.per_air.len()
        );
    }

    let mut total_trace_width = 0usize;
    let mut max_air_constraint_degree = 0u8;
    let airs = air_names
        .into_iter()
        .zip(vk.inner.per_air.iter())
        .enumerate()
        .map(|(air_idx, (air_name, air_vk))| {
            let width = &air_vk.params.width;
            let main_width = width.main_width();
            let total_width = width.total_width();
            total_trace_width += total_width;
            max_air_constraint_degree = max_air_constraint_degree.max(air_vk.max_constraint_degree);
            AirMeta {
                air_idx,
                air_name,
                trace_width: TraceWidthMeta {
                    preprocessed: width.preprocessed,
                    cached_mains: width.cached_mains.clone(),
                    common_main: width.common_main,
                    main: main_width,
                    total: total_width,
                },
                max_constraint_degree: air_vk.max_constraint_degree,
                num_constraints: air_vk.symbolic_constraints.constraints.num_constraints(),
                num_interactions: air_vk.num_interactions(),
                need_rot: air_vk.params.need_rot,
                is_required: air_vk.is_required,
            }
        })
        .collect::<Vec<_>>();

    Ok(KeygenMeta {
        vk_path,
        max_num_proofs: MAX_NUM_PROOFS,
        configured_max_constraint_degree,
        keygen_max_constraint_degree: vk.max_constraint_degree(),
        air_count: airs.len(),
        total_trace_width,
        max_air_constraint_degree,
        airs,
    })
}

fn print_table(meta: &KeygenMeta) {
    println!("vk_path: {}", meta.vk_path.display());
    println!(
        "max_num_proofs={} configured_max_constraint_degree={} keygen_max_constraint_degree={} air_count={} total_trace_width={}",
        meta.max_num_proofs,
        meta.configured_max_constraint_degree,
        meta.keygen_max_constraint_degree,
        meta.air_count,
        meta.total_trace_width
    );
    println!(
        "{:>3}  {:<44}  {:>5}  {:>5}  {:>5}  {:>7}  {:>7}  {:>7}  {:>5}  {:>5}  {:>8}",
        "idx",
        "air",
        "prep",
        "cache",
        "main",
        "total",
        "degree",
        "constr",
        "ints",
        "rot",
        "required"
    );
    for air in &meta.airs {
        let cached_width: usize = air.trace_width.cached_mains.iter().sum();
        let preprocessed = air
            .trace_width
            .preprocessed
            .map(|width| width.to_string())
            .unwrap_or_else(|| "-".to_string());
        println!(
            "{:>3}  {:<44}  {:>5}  {:>5}  {:>5}  {:>7}  {:>7}  {:>7}  {:>5}  {:>5}  {:>8}",
            air.air_idx,
            truncate(&air.air_name, 44),
            preprocessed,
            cached_width,
            air.trace_width.common_main,
            air.trace_width.total,
            air.max_constraint_degree,
            air.num_constraints,
            air.num_interactions,
            air.need_rot,
            air.is_required
        );
    }
}

fn truncate(value: &str, max_len: usize) -> String {
    if value.len() <= max_len {
        return value.to_string();
    }
    format!("{}...", &value[..max_len.saturating_sub(3)])
}
