use crate::utils::*;
use anyhow::{Context, bail};
use ceno_emul::{IterAddresses, Program, WORD_SIZE, Word};
use ceno_host::{CenoStdin, memory_from_file};
use ceno_zkvm::{
    e2e::*,
    scheme::{
        constants::MAX_NUM_VARIABLES, mock_prover::LkMultiplicityKey, verifier::ZKVMVerifier,
    },
};
use clap::Args;
use ff_ext::{BabyBearExt4, ExtensionField, GoldilocksExt2};
use mpcs::{Basefold, BasefoldRSParams, PolynomialCommitmentScheme};
use serde::Serialize;
use std::{
    fs::File,
    path::{Path, PathBuf},
};

/// Ceno options
#[derive(Clone, Args)]
pub struct CenoOptions {
    /// The preset configuration to use.
    #[arg(short, long, value_enum, default_value_t = Preset::Ceno)]
    pub platform: Preset,

    /// The polynomial commitment scheme to use.
    #[arg(long, value_enum, default_value_t = PcsKind::default())]
    pcs: PcsKind,
    /// The field to use, eg. goldilocks
    #[arg(long, value_enum, default_value_t = FieldType::default())]
    field: FieldType,

    /// The maximum number of steps to execute the program.
    #[arg(long, default_value_t = usize::MAX)]
    pub max_steps: usize,

    /// The maximum number of variables the polynomial commitment scheme
    #[arg(long, default_value_t = MAX_NUM_VARIABLES)]
    pub max_num_variables: usize,

    /// Prover-private unconstrained input.
    /// This is a raw file mapped as a memory segment. Zero-padded to the right to the next power-of-two size.
    #[arg(long, conflicts_with = "hints")]
    hints_file: Option<PathBuf>,
    /// Prover-private unconstrained input as a list of words separated by commas or spaces.
    #[arg(long, conflicts_with = "hints_file", value_parser, num_args = 1..)]
    hints: Option<Vec<Word>>,

    /// Public constrained input.
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
            EnvFilter, Registry,
            filter::{LevelFilter, filter_fn},
            fmt,
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
            memory_from_file(file_path).context(format!("failed to read {}", file_path.display()))
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

    /// Run keygen the ceno elf file with given options
    pub fn keygen<P: AsRef<Path>>(&self, elf_path: P) -> anyhow::Result<()> {
        self.try_setup_logger();
        match (self.pcs, self.field) {
            (PcsKind::Basefold, FieldType::Goldilocks) => {
                keygen_inner::<GoldilocksExt2, Basefold<GoldilocksExt2, BasefoldRSParams>, P>(
                    self, elf_path,
                )
            }
            (PcsKind::Basefold, FieldType::BabyBear) => {
                keygen_inner::<BabyBearExt4, Basefold<BabyBearExt4, BasefoldRSParams>, P>(
                    self, elf_path,
                )
            }
            (PcsKind::Whir, FieldType::Goldilocks) => todo!(),
            (PcsKind::Whir, FieldType::BabyBear) => todo!(),
        }
    }

    /// Run the ceno elf file with given options
    pub fn run<P: AsRef<Path>>(&self, elf_path: P) -> anyhow::Result<()> {
        self.try_setup_logger();
        let runner = match (self.pcs, self.field) {
            (PcsKind::Basefold, FieldType::Goldilocks) => {
                run_elf_inner::<GoldilocksExt2, Basefold<GoldilocksExt2, BasefoldRSParams>, P>(
                    self,
                    elf_path,
                    Checkpoint::PrepWitnessGen,
                )?
                .1
            }
            (PcsKind::Basefold, FieldType::BabyBear) => {
                run_elf_inner::<BabyBearExt4, Basefold<BabyBearExt4, BasefoldRSParams>, P>(
                    self,
                    elf_path,
                    Checkpoint::PrepWitnessGen,
                )?
                .1
            }
            (PcsKind::Whir, FieldType::Goldilocks) => todo!(),
            (PcsKind::Whir, FieldType::BabyBear) => todo!(),
        };
        runner();
        Ok(())
    }

    /// Run and prove the ceno elf file with given options
    pub fn prove<P: AsRef<Path>>(&self, elf_path: P) -> anyhow::Result<()> {
        self.try_setup_logger();
        match (self.pcs, self.field) {
            (PcsKind::Basefold, FieldType::Goldilocks) => {
                prove_inner::<GoldilocksExt2, Basefold<GoldilocksExt2, BasefoldRSParams>, P>(
                    self, elf_path,
                )
            }
            (PcsKind::Basefold, FieldType::BabyBear) => {
                prove_inner::<BabyBearExt4, Basefold<BabyBearExt4, BasefoldRSParams>, P>(
                    self, elf_path,
                )
            }
            (PcsKind::Whir, FieldType::Goldilocks) => todo!(),
            (PcsKind::Whir, FieldType::BabyBear) => todo!(),
        }
    }
}

type E2EResult<E, PCS> = (IntermediateState<E, PCS>, Box<dyn FnOnce()>);

fn run_elf_inner<
    E: ExtensionField + LkMultiplicityKey,
    PCS: PolynomialCommitmentScheme<E> + 'static,
    P: AsRef<Path>,
>(
    options: &CenoOptions,
    elf_path: P,
    checkpoint: Checkpoint,
) -> anyhow::Result<E2EResult<E, PCS>> {
    let elf_path = elf_path.as_ref();
    let elf_bytes =
        std::fs::read(elf_path).context(format!("failed to read {}", elf_path.display()))?;
    let program = Program::load_elf(&elf_bytes, u32::MAX).context("failed to load elf")?;
    print_cargo_message("Loaded", format_args!("{}", elf_path.display()));

    let public_io = options
        .read_public_io()
        .context("failed to read public io")?;
    // estimate required pub io size, which is required in platform/key setup phase
    let pub_io_size: u32 = ((public_io.len() * WORD_SIZE) as u32)
        .next_power_of_two()
        .max(16);

    let platform = setup_platform(
        options.platform,
        &program,
        options.stack_size(),
        options.heap_size(),
        pub_io_size,
    );
    tracing::info!("Running on platform {:?} {}", options.platform, platform);
    tracing::info!(
        "Stack: {} bytes. Heap: {} bytes.",
        options.stack_size(),
        options.heap_size()
    );

    let hints = options.read_hints().context("failed to read hints")?;
    assert!(
        hints.len() <= platform.hints.iter_addresses().len(),
        "hints must fit in {} bytes",
        platform.hints.len()
    );

    Ok(run_e2e_with_checkpoint::<E, PCS>(
        program,
        platform,
        hints,
        public_io,
        options.max_steps,
        options.max_num_variables,
        checkpoint,
    ))
}

fn keygen_inner<
    E: ExtensionField + LkMultiplicityKey,
    PCS: PolynomialCommitmentScheme<E> + Serialize + 'static,
    P: AsRef<Path>,
>(
    args: &CenoOptions,
    elf_path: P,
) -> anyhow::Result<()> {
    let ((_, vk), _) = run_elf_inner::<E, PCS, P>(args, elf_path, Checkpoint::Keygen)?;
    let vk = vk.expect("Keygen should yield vk.");
    if let Some(out_vk) = args.out_vk.as_ref() {
        let path = out_vk.canonicalize()?;
        print_cargo_message("Writing", format_args!("vk to {}", path.display()));
        let vk_file =
            File::create(&path).context(format!("failed to create {}", path.display()))?;
        bincode::serialize_into(vk_file, &vk).context("failed to serialize vk")?;
    }
    Ok(())
}

fn prove_inner<
    E: ExtensionField + LkMultiplicityKey,
    PCS: PolynomialCommitmentScheme<E> + Serialize + 'static,
    P: AsRef<Path>,
>(
    args: &CenoOptions,
    elf_path: P,
) -> anyhow::Result<()> {
    let ((zkvm_proof, vk), _) =
        run_elf_inner::<E, PCS, P>(args, elf_path, Checkpoint::PrepSanityCheck)?;
    let zkvm_proof = zkvm_proof.expect("PrepSanityCheck should yield proof.");
    let vk = vk.expect("PrepSanityCheck should yield vk.");

    let start = std::time::Instant::now();
    let verifier = ZKVMVerifier::new(vk);
    if let Err(e) = verify(&zkvm_proof, &verifier) {
        bail!("Verification failed: {e:?}");
    }
    print_cargo_message(
        "Verified",
        format_args!("proof in {:.2}s", start.elapsed().as_secs_f32()),
    );

    if let Some(out_proof) = args.out_proof.as_ref() {
        let path = out_proof.canonicalize()?;
        print_cargo_message("Writing", format_args!("proof to {}", path.display()));
        let proof_file =
            File::create(&path).context(format!("failed to create {}", path.display()))?;
        bincode::serialize_into(proof_file, &zkvm_proof)
            .context("failed to serialize zkvm proof")?;
    }
    if let Some(out_vk) = args.out_vk.as_ref() {
        let path = out_vk.canonicalize()?;
        print_cargo_message("Writing", format_args!("vk to {}", path.display()));
        let vk_file =
            File::create(&path).context(format!("failed to create {}", path.display()))?;
        bincode::serialize_into(vk_file, &verifier.into_inner())
            .context("failed to serialize vk")?;
    }
    Ok(())
}
