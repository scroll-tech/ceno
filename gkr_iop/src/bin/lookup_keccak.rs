use clap::{Parser, command};
use ff_ext::GoldilocksExt2;
use gkr_iop::precompiles::{run_faster_keccakf, setup_lookup_keccak_gkr_circuit};
use itertools::Itertools;
use mpcs::BasefoldDefault;
use rand::{RngCore, SeedableRng};
use tracing::level_filters::LevelFilter;
use tracing_forest::ForestLayer;
use tracing_subscriber::{
    EnvFilter, Registry, filter::filter_fn, fmt, layer::SubscriberExt, util::SubscriberInitExt,
};

// Use jemalloc as global allocator for performance
#[cfg(all(feature = "jemalloc", unix, not(test)))]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    // Profiling granularity.
    // Setting any value restricts logs to profiling information
    #[arg(long)]
    profiling: Option<usize>,
}

fn main() {
    let args = Args::parse();
    type E = GoldilocksExt2;
    type Pcs = BasefoldDefault<E>;

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

    let random_u64: u64 = rand::random();
    // Use seeded rng for debugging convenience
    let mut rng = rand::rngs::StdRng::seed_from_u64(random_u64);
    let num_instance = 8192;
    let states: Vec<[u64; 25]> = (0..num_instance)
        .map(|_| std::array::from_fn(|_| rng.next_u64()))
        .collect_vec();
    let circuit_setup = setup_lookup_keccak_gkr_circuit();
    let proof =
        run_faster_keccakf::<E, Pcs>(circuit_setup, states, true, true).expect("generate proof");
    tracing::info!("lookup keccak proof stat: {}", proof);
}
