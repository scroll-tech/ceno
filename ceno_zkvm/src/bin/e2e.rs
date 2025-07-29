use ceno_emul::{IterAddresses, Platform, Program, WORD_SIZE, Word};
use ceno_host::{CenoStdin, memory_from_file};
#[cfg(all(feature = "jemalloc", unix, not(test)))]
use ceno_zkvm::print_allocated_bytes;
use ceno_zkvm::{
    e2e::{
        Checkpoint, FieldType, PcsKind, Preset, run_e2e_with_checkpoint, setup_platform,
        setup_platform_debug, verify,
    },
    scheme::{
        ZKVMProof, constants::MAX_NUM_VARIABLES, hal::ProverDevice, mock_prover::LkMultiplicityKey,
        verifier::ZKVMVerifier,
    },
    with_panic_hook,
};
use clap::Parser;
use ff_ext::{BabyBearExt4, ExtensionField, GoldilocksExt2};
use gkr_iop::{
    cpu::{CpuBackend, CpuProver},
    hal::ProverBackend,
};
use mpcs::{
    Basefold, BasefoldRSParams, PolynomialCommitmentScheme, SecurityLevel, Whir, WhirDefaultSpec,
};
use p3::field::FieldAlgebra;
use serde::{Serialize, de::DeserializeOwned};
use std::{fs, panic, panic::AssertUnwindSafe, path::PathBuf};
use tracing::{error, level_filters::LevelFilter};
use tracing_forest::ForestLayer;
use tracing_subscriber::{
    EnvFilter, Registry, filter::filter_fn, fmt, layer::SubscriberExt, util::SubscriberInitExt,
};
use transcript::BasicTranscript as Transcript;

// Use jemalloc as global allocator for performance
#[cfg(all(feature = "jemalloc", unix, not(test)))]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

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

    /// The security level to use.
    #[arg(short, long, value_enum, default_value_t = SecurityLevel::default())]
    security_level: SecurityLevel,
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

    // estimate required pub io size, which is required in platform/key setup phase
    let pub_io_size: u32 = ((public_io.len() * WORD_SIZE) as u32)
        .next_power_of_two()
        .max(16);

    tracing::info!("Loading ELF file: {}", args.elf.display());
    let elf_bytes = fs::read(&args.elf).expect("read elf file");
    let program = Program::load_elf(&elf_bytes, u32::MAX).unwrap();
    let platform = if cfg!(debug_assertions) {
        setup_platform_debug(
            args.platform,
            &program,
            args.stack_size,
            args.heap_size,
            pub_io_size,
        )
    } else {
        setup_platform(
            args.platform,
            &program,
            args.stack_size,
            args.heap_size,
            pub_io_size,
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

    // TODO support GPU backend

    match (args.pcs, args.field) {
        (PcsKind::Basefold, FieldType::Goldilocks) => {
            let backend =
                CpuBackend::<_, _>::new(args.max_num_variables, args.security_level).into();
            let prover = CpuProver::new(backend);
            run_inner::<GoldilocksExt2, Basefold<GoldilocksExt2, BasefoldRSParams>, _, _>(
                prover,
                program,
                platform,
                &hints,
                &public_io,
                max_steps,
                args.proof_file,
                args.vk_file,
                Checkpoint::Complete,
            )
        }
        (PcsKind::Basefold, FieldType::BabyBear) => {
            let backend =
                CpuBackend::<_, _>::new(args.max_num_variables, args.security_level).into();
            let prover = CpuProver::new(backend);
            run_inner::<BabyBearExt4, Basefold<BabyBearExt4, BasefoldRSParams>, _, _>(
                prover,
                program,
                platform,
                &hints,
                &public_io,
                max_steps,
                args.proof_file,
                args.vk_file,
                Checkpoint::PrepVerify, // FIXME: when whir and babybear is ready
            )
        }
        (PcsKind::Whir, FieldType::Goldilocks) => {
            let backend =
                CpuBackend::<_, _>::new(args.max_num_variables, args.security_level).into();
            let prover = CpuProver::new(backend);
            run_inner::<GoldilocksExt2, Whir<GoldilocksExt2, WhirDefaultSpec>, _, _>(
                prover,
                program,
                platform,
                &hints,
                &public_io,
                max_steps,
                args.proof_file,
                args.vk_file,
                Checkpoint::PrepVerify, // FIXME: when whir and babybear is ready
            )
        }
        (PcsKind::Whir, FieldType::BabyBear) => {
            let backend =
                CpuBackend::<_, _>::new(args.max_num_variables, args.security_level).into();
            let prover = CpuProver::new(backend);
            run_inner::<BabyBearExt4, Whir<BabyBearExt4, WhirDefaultSpec>, _, _>(
                prover,
                program,
                platform,
                &hints,
                &public_io,
                max_steps,
                args.proof_file,
                args.vk_file,
                Checkpoint::PrepVerify, // FIXME: when whir and babybear is ready
            )
        }
    };

    #[cfg(all(feature = "jemalloc", unix, not(test)))]
    {
        print_allocated_bytes();
    }
}

#[allow(clippy::too_many_arguments)]
fn run_inner<
    E: ExtensionField + LkMultiplicityKey + DeserializeOwned,
    PCS: PolynomialCommitmentScheme<E> + Serialize + 'static,
    PB: ProverBackend<E = E, Pcs = PCS> + 'static,
    PD: ProverDevice<PB> + 'static,
>(
    pd: PD,
    program: Program,
    platform: Platform,
    hints: &[u32],
    public_io: &[u32],
    max_steps: usize,
    proof_file: PathBuf,
    vk_file: PathBuf,
    checkpoint: Checkpoint,
) {
    let result = run_e2e_with_checkpoint::<E, PCS, _, _>(
        pd, program, platform, hints, public_io, max_steps, checkpoint,
    );

    let zkvm_proof = result
        .proof
        .expect("PrepSanityCheck should yield zkvm_proof.");
    let vk = result.vk.expect("PrepSanityCheck should yield vk.");

    let proof_bytes = bincode::serialize(&zkvm_proof).unwrap();
    fs::write(&proof_file, proof_bytes).unwrap();
    let vk_bytes = bincode::serialize(&vk).unwrap();
    fs::write(&vk_file, vk_bytes).unwrap();

    if checkpoint > Checkpoint::PrepVerify {
        let verifier = ZKVMVerifier::new(vk);
        verify(&zkvm_proof, &verifier).expect("Verification failed");
        soundness_test(zkvm_proof, &verifier);
    }
}

fn soundness_test<E: ExtensionField, Pcs: PolynomialCommitmentScheme<E>>(
    mut zkvm_proof: ZKVMProof<E, Pcs>,
    verifier: &ZKVMVerifier<E, Pcs>,
) {
    // do sanity check
    let transcript = Transcript::new(b"riscv");
    // change public input maliciously should cause verifier to reject proof
    zkvm_proof.raw_pi[0] = vec![E::BaseField::ONE];
    zkvm_proof.raw_pi[1] = vec![E::BaseField::ONE];

    // capture panic message, if have
    let result = with_panic_hook(Box::new(|_info| ()), || {
        panic::catch_unwind(AssertUnwindSafe(|| {
            verifier.verify_proof(zkvm_proof, transcript)
        }))
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
                error!("unknown panic {msg:?}");
                panic::resume_unwind(err);
            };
        }
    };
}
