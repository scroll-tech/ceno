use super::CompilationOptions;
use crate::utils::*;
use anyhow::{Context, bail};
use ceno_emul::{IterAddresses, Program, WORD_SIZE, Word};
use ceno_host::{CenoStdin, memory_from_file};
use ceno_zkvm::{
    e2e::*,
    scheme::{
        constants::MAX_NUM_VARIABLES, create_backend, create_prover,
        mock_prover::LkMultiplicityKey, verifier::ZKVMVerifier,
    },
};
use clap::Args;
use ff_ext::{BabyBearExt4, ExtensionField, GoldilocksExt2};

use mpcs::{
    Basefold, BasefoldRSParams, PolynomialCommitmentScheme, SecurityLevel, Whir, WhirDefaultSpec,
};
use serde::Serialize;
use std::{
    fs::File,
    path::{Path, PathBuf},
};

/// Ceno options
#[derive(Clone, Args)]
pub struct CenoOptions {
    /// The preset configuration to use.
    #[arg(long, value_enum, default_value_t = Preset::Ceno)]
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

    /// pub io size in byte
    #[arg(long, default_value = "1k", value_parser = parse_size)]
    public_io_size: u32,

    /// The preset configuration to use.
    #[arg(short, long, value_enum, default_value_t = SecurityLevel::default())]
    security_level: SecurityLevel,

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

        if *QUIET.get_or_init(|| false) {
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
        if let Some(public_io) = &self.public_io {
            // if vector contains only one element, write it as a raw `u32`
            // otherwise, write the entire vector
            // in both cases, convert the resulting `CenoStdin` into a `Vec<u32>`
            if public_io.len() == 1 {
                CenoStdin::default()
                    .write(&public_io[0])
                    .map(|stdin| Into::<Vec<u32>>::into(&*stdin))
            } else {
                CenoStdin::default()
                    .write(public_io)
                    .map(|stdin| Into::<Vec<u32>>::into(&*stdin))
            }
            .context("failed to get public_io".to_string())
        } else {
            Ok(vec![])
        }
    }

    /// Read the hints
    pub fn read_hints(&self) -> anyhow::Result<Vec<u32>> {
        if self.hints_file.is_some() {
            let file_path = self.hints_file.as_deref().unwrap();
            tracing::info!("Loading hints file: {:?}", file_path);
            memory_from_file(file_path).context(format!("failed to read {}", file_path.display()))
        } else if self.hints.is_some() {
            let hints = self.hints.as_ref().unwrap();
            // if the vector contains only one element, write it as a raw `u32`
            // otherwise, write the entire vector
            // in both cases, convert the resulting `CenoStdin` into a `Vec<u32>`
            if hints.len() == 1 {
                CenoStdin::default()
                    .write(&hints[0])
                    .ok()
                    .map(|stdin| Into::<Vec<u32>>::into(&*stdin))
            } else {
                CenoStdin::default()
                    .write(hints)
                    .ok()
                    .map(|stdin| Into::<Vec<u32>>::into(&*stdin))
            }
            .context("failed to get hints".to_string())
        } else {
            Ok(vec![])
        }
    }

    /// Run keygen the ceno elf file with given options
    pub fn keygen<P: AsRef<Path>>(
        &self,
        compilation_options: &CompilationOptions,
        elf_path: P,
    ) -> anyhow::Result<()> {
        self.try_setup_logger();
        match (self.pcs, self.field) {
            (PcsKind::Basefold, FieldType::Goldilocks) => {
                keygen_inner::<GoldilocksExt2, Basefold<GoldilocksExt2, BasefoldRSParams>, P>(
                    self,
                    compilation_options,
                    elf_path,
                )
            }
            (PcsKind::Basefold, FieldType::BabyBear) => {
                keygen_inner::<BabyBearExt4, Basefold<BabyBearExt4, BasefoldRSParams>, P>(
                    self,
                    compilation_options,
                    elf_path,
                )
            }
            (PcsKind::Whir, FieldType::Goldilocks) => {
                keygen_inner::<GoldilocksExt2, Whir<GoldilocksExt2, WhirDefaultSpec>, P>(
                    self,
                    compilation_options,
                    elf_path,
                )
            }
            (PcsKind::Whir, FieldType::BabyBear) => {
                keygen_inner::<BabyBearExt4, Whir<BabyBearExt4, WhirDefaultSpec>, P>(
                    self,
                    compilation_options,
                    elf_path,
                )
            }
        }
    }

    /// Run the ceno elf file with given options
    pub fn run<P: AsRef<Path>>(
        &self,
        compilation_options: &CompilationOptions,
        elf_path: P,
    ) -> anyhow::Result<()> {
        self.try_setup_logger();
        match (self.pcs, self.field) {
            (PcsKind::Basefold, FieldType::Goldilocks) => {
                run_elf_inner::<GoldilocksExt2, Basefold<GoldilocksExt2, BasefoldRSParams>, P>(
                    self,
                    compilation_options,
                    elf_path,
                    Checkpoint::PrepWitnessGen,
                )?;
            }
            (PcsKind::Basefold, FieldType::BabyBear) => {
                run_elf_inner::<BabyBearExt4, Basefold<BabyBearExt4, BasefoldRSParams>, P>(
                    self,
                    compilation_options,
                    elf_path,
                    Checkpoint::PrepWitnessGen,
                )?;
            }
            (PcsKind::Whir, FieldType::Goldilocks) => {
                run_elf_inner::<GoldilocksExt2, Whir<GoldilocksExt2, WhirDefaultSpec>, P>(
                    self,
                    compilation_options,
                    elf_path,
                    Checkpoint::PrepWitnessGen,
                )?;
            }
            (PcsKind::Whir, FieldType::BabyBear) => {
                run_elf_inner::<BabyBearExt4, Whir<BabyBearExt4, WhirDefaultSpec>, P>(
                    self,
                    compilation_options,
                    elf_path,
                    Checkpoint::PrepWitnessGen,
                )?;
            }
        };
        Ok(())
    }

    /// Run and prove the ceno elf file with given options
    pub fn prove<P: AsRef<Path>>(
        &self,
        compilation_options: &CompilationOptions,
        elf_path: P,
    ) -> anyhow::Result<()> {
        self.try_setup_logger();
        match (self.pcs, self.field) {
            (PcsKind::Basefold, FieldType::Goldilocks) => {
                prove_inner::<GoldilocksExt2, Basefold<GoldilocksExt2, BasefoldRSParams>, P>(
                    self,
                    compilation_options,
                    elf_path,
                    Checkpoint::Complete,
                )
            }
            (PcsKind::Basefold, FieldType::BabyBear) => {
                prove_inner::<BabyBearExt4, Basefold<BabyBearExt4, BasefoldRSParams>, P>(
                    self,
                    compilation_options,
                    elf_path,
                    Checkpoint::Complete,
                )
            }
            (PcsKind::Whir, FieldType::Goldilocks) => {
                prove_inner::<GoldilocksExt2, Whir<GoldilocksExt2, WhirDefaultSpec>, P>(
                    self,
                    compilation_options,
                    elf_path,
                    Checkpoint::PrepVerify, // FIXME: when whir and babybear is ready
                )
            }
            (PcsKind::Whir, FieldType::BabyBear) => {
                prove_inner::<BabyBearExt4, Whir<BabyBearExt4, WhirDefaultSpec>, P>(
                    self,
                    compilation_options,
                    elf_path,
                    Checkpoint::PrepVerify, // FIXME: when whir and babybear is ready
                )
            }
        }
    }
}

fn run_elf_inner<
    E: ExtensionField + LkMultiplicityKey,
    PCS: PolynomialCommitmentScheme<E> + Serialize + 'static,
    P: AsRef<Path>,
>(
    options: &CenoOptions,
    compilation_options: &CompilationOptions,
    elf_path: P,
    checkpoint: Checkpoint,
) -> anyhow::Result<E2ECheckpointResult<E, PCS>> {
    let elf_path = elf_path.as_ref();
    let elf_bytes =
        std::fs::read(elf_path).context(format!("failed to read {}", elf_path.display()))?;
    let program = Program::load_elf(&elf_bytes, u32::MAX).context("failed to load elf")?;
    print_cargo_message("Loaded", format_args!("{}", elf_path.display()));

    let public_io = options
        .read_public_io()
        .context("failed to read public io")?;
    let public_io_size = options.public_io_size;
    assert!(
        public_io.len() <= public_io_size as usize / WORD_SIZE,
        "require pub io length {} < max public_io_size {}",
        public_io.len(),
        public_io_size as usize / WORD_SIZE
    );

    let platform = if compilation_options.release {
        setup_platform(
            options.platform,
            &program,
            options.stack_size(),
            options.heap_size(),
            public_io_size,
        )
    } else {
        setup_platform_debug(
            options.platform,
            &program,
            options.stack_size(),
            options.heap_size(),
            public_io_size,
        )
    };
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

    let backend = create_backend(options.max_num_variables, options.security_level);
    Ok(run_e2e_with_checkpoint::<E, PCS, _, _>(
        create_prover(backend.clone()),
        program,
        platform,
        &hints,
        &public_io,
        options.max_steps,
        checkpoint,
    ))
}

fn keygen_inner<
    E: ExtensionField + LkMultiplicityKey,
    PCS: PolynomialCommitmentScheme<E> + Serialize + 'static,
    P: AsRef<Path>,
>(
    args: &CenoOptions,
    compilation_options: &CompilationOptions,
    elf_path: P,
) -> anyhow::Result<()> {
    let result = run_elf_inner::<E, PCS, P>(
        args,
        compilation_options,
        elf_path,
        Checkpoint::PrepE2EProving,
    )?;
    let vk = result.vk.expect("Keygen should yield vk.");
    if let Some(out_vk) = args.out_vk.as_ref() {
        let path = canonicalize_allow_nx(out_vk)?;
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
    compilation_options: &CompilationOptions,
    elf_path: P,
    checkpoint: Checkpoint,
) -> anyhow::Result<()> {
    let result = run_elf_inner::<E, PCS, P>(args, compilation_options, elf_path, checkpoint)?;
    let zkvm_proof = result.proof.expect("PrepSanityCheck should yield proof.");
    let vk = result.vk.expect("PrepSanityCheck should yield vk.");

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
        let path = canonicalize_allow_nx(out_proof)?;
        print_cargo_message("Writing", format_args!("proof to {}", path.display()));
        let proof_file =
            File::create(&path).context(format!("failed to create {}", path.display()))?;
        bincode::serialize_into(proof_file, &zkvm_proof)
            .context("failed to serialize zkvm proof")?;
    }
    if let Some(out_vk) = args.out_vk.as_ref() {
        let path = canonicalize_allow_nx(out_vk)?;
        print_cargo_message("Writing", format_args!("vk to {}", path.display()));
        let vk_file =
            File::create(&path).context(format!("failed to create {}", path.display()))?;
        bincode::serialize_into(vk_file, &verifier.into_inner())
            .context("failed to serialize vk")?;
    }
    Ok(())
}
