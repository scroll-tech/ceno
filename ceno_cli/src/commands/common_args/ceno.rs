use crate::utils::*;
use ceno_emul::{Word, WORD_SIZE};
use ceno_host::{memory_from_file, CenoStdin};
use ceno_zkvm::e2e::*;
use clap::Args;
use std::path::PathBuf;
use anyhow::Context;

/// Ceno options
#[derive(Clone, Args)]
pub struct CenoOptions {
    /// The preset configuration to use.
    #[arg(short, long, value_enum, default_value_t = Preset::Ceno)]
    pub platform: Preset,

    /// The maximum number of steps to execute the program.
    #[arg(short, long, default_value_t = usize::MAX)]
    pub max_steps: usize,

    /// Prover-private unconstrained input.
    /// This is a raw file mapped as a memory segment. Zero-padded to the right to the next power-of-two size.
    #[arg(long, conflicts_with = "hints")]
    hints_file: Option<PathBuf>,
    /// Prover-private unconstrained input as a list of words separated by commas or spaces.
    #[arg(long, conflicts_with = "hints_file", value_parser, num_args = 1..)]
    hints: Option<Vec<Word>>,

    #[arg(long, value_parser, num_args = 1.., value_delimiter = ',')]
    public_io: Option<Vec<Word>>,

    /// Stack size in bytes.
    #[arg(long, default_value = "2M", value_parser = parse_size)]
    stack_size: u32,
    /// Heap size in bytes.
    #[arg(long, default_value = "2M", value_parser = parse_size)]
    heap_size: u32,

    /// The path to the proof file to write.
    #[arg(long)]
    pub out_proof: Option<PathBuf>,
    /// The path to the verification key file to write.
    #[arg(long)]
    pub out_vk: Option<PathBuf>,

    /// Profiling granularity.
    /// Setting any value restricts logs to profiling information
    #[arg(long)]
    profiling: Option<usize>,
}

impl CenoOptions {
    /// Try set up the logger based on the verbosity level
    pub fn try_setup_logger(&self) {
        use tracing_forest::ForestLayer;
        use tracing_subscriber::{
            fmt, Registry,
            EnvFilter,
            filter::{LevelFilter, filter_fn},
            layer::SubscriberExt,
            util::SubscriberInitExt,
        };

        if *QUITE.get_or_init(|| false) {
            return;
        }

        // default filter
        let default_filter = EnvFilter::builder()
            .with_default_directive(LevelFilter::DEBUG.into())
            .from_env_lossy();

        // filter by profiling level;
        // spans with level i contain the field "profiling_{i}"
        // this restricts statistics to first (args.profiling) levels
        let profiling_level = self.profiling.unwrap_or(1);
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
            .with(self.profiling.is_some().then_some(ForestLayer::default()))
            .with(fmt_layer)
            // if some profiling granularity is specified, use the profiling filter,
            // otherwise use the default
            .with(
                self.profiling
                    .is_some()
                    .then_some(filter_by_profiling_level),
            )
            .with(self.profiling.is_none().then_some(default_filter))
            .try_init()
            .ok();
    }

    /// Get stack size
    pub fn stack_size(&self) -> u32 {
        self.stack_size.next_multiple_of(WORD_SIZE as u32)
    }

    /// Get heap size
    pub fn heap_size(&self) -> u32 {
        self.heap_size.next_multiple_of(WORD_SIZE as u32)
    }

    /// Read the public io into ceno stdin
    pub fn read_public_io(&self) -> anyhow::Result<Vec<u32>> {
        let mut stdin = CenoStdin::default();
        if let Some(public_io) = &self.public_io {
            for word in public_io.iter() {
                stdin.write(word)?;
            }
        }
        Ok((&stdin).into())
    }

    /// Read the hints
    pub fn read_hints(&self) -> anyhow::Result<Vec<u32>> {
        if self.hints_file.is_some() {
            let file_path = self.hints_file.as_deref().unwrap();
            tracing::info!("Loading hints file: {:?}", file_path);
            memory_from_file(file_path).context(
                format!("failed to read {}", file_path.display())
            )
        } else if self.hints.is_some() {
            let hints = self.hints.as_ref().unwrap();
            let mut stdin = CenoStdin::default();
            for hint in hints.iter() {
                stdin.write(hint)?;
            }
            Ok((&stdin).into())
        } else {
            Ok(vec![])
        }
    }
}
