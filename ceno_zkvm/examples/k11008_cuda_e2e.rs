//! Direct, one-cell K11008 CUDA syscall/provider proof E2E.
//!
//! This executable intentionally stops at one production intermediate MatMul;
//! it is not a Llama layer or full-width model run.

use std::sync::Arc;

use ceno_emul::tensor::{
    TensorWitnessProvider,
    production::{ProductionMatMulSignature, sparse_production_dot_fixture},
};
use ceno_zkvm::{
    e2e::{
        KECCAK_EMPTY_WORDS, MultiProver, Preset, TensorProofContext,
        prepare_fulltracer_aot_program, prepare_preflight_aot_program, run_e2e_full_trace_verify,
        run_e2e_proof, setup_platform, setup_program,
    },
    scheme::{
        create_backend, create_prover, hal::ProverDevice, prover::ZKVMProver,
        verifier::ZKVMVerifier,
    },
};
use ff_ext::BabyBearExt4;
use gkr_iop::cpu::default_backend_config;
use mpcs::BasefoldDefault;

type E = BabyBearExt4;
type Pcs = BasefoldDefault<E>;

fn main() {
    rayon::ThreadPoolBuilder::new()
        // Production symbolic expression trees exceed Rayon’s default worker
        // stack. Keep setup, proof, and teardown on this dedicated stack.
        .stack_size(256 * 1024 * 1024)
        .build()
        .expect("construct K11008 E2E Rayon pool")
        .install(run);
}

fn run() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init();

    let program =
        ceno_emul::Program::load_elf(ceno_examples::tensor_matmul_intermediate_v1, u32::MAX)
            .expect("load K11008 guest");
    // The single K11008 input is 44 KiB.  This is still one syscall, but it
    // cannot fit in the generic small-guest stack used by TensorBus examples.
    let platform = setup_platform(Preset::Ceno, &program, 128 * 1024, 2 * 1024 * 1024);
    let mut ctx = setup_program::<E>(program, platform, MultiProver::default());
    let (_desc, _entry, provider) = sparse_production_dot_fixture(
        ProductionMatMulSignature::IntermediateK11008,
        83,
        0x4b31_3130,
    )
    .expect("construct deterministic K11008 raw-hint fixture");
    let provider: Arc<dyn TensorWitnessProvider> = Arc::new(provider);
    ctx.set_tensor_proof_context(Arc::new(TensorProofContext::new(Arc::clone(&provider))));

    // The proof path replays the guest with FullTracer.  Prepare both AOT
    // artifacts before key generation so the replay is identical to the
    // preflight used to derive shard layout and syscall witnesses.
    let init_mem = ctx.setup_init_mem(&[]);
    let raw_step_cell_extractor = Arc::clone(&ctx.system_config.config);
    let step_cell_extractor: Arc<dyn ceno_emul::StepCellExtractor> = raw_step_cell_extractor;
    let preflight_aot = prepare_preflight_aot_program(
        Arc::clone(&ctx.program),
        &ctx.platform,
        &ctx.multi_prover,
        step_cell_extractor,
        &init_mem,
    );
    ctx.fulltracer_aot_program = Some(prepare_fulltracer_aot_program(preflight_aot.as_ref()));
    ctx.preflight_aot_program = Some(preflight_aot);

    let (max_num_variables, security_level) = default_backend_config();
    let backend = create_backend::<E, Pcs>(max_num_variables, security_level);
    let device = create_prover(backend);
    let (pk, vk) = ctx.keygen_with_pb(device.get_pb());
    let prover = ZKVMProver::new(pk.into(), device);
    let init_mem = prover.setup_init_mem(&[]);
    let proofs = run_e2e_proof(&prover, &init_mem, KECCAK_EMPTY_WORDS, 1 << 20, false, None);
    assert!(!proofs.is_empty(), "K11008 E2E produced no shard proofs");
    run_e2e_full_trace_verify(&ZKVMVerifier::new(vk), proofs, Some(0), 1 << 20);

    let metrics = provider.metrics();
    assert!(
        metrics.read_calls >= 33,
        "K11008 provider was not replayed across proof stages"
    );
    println!(
        "K11008 CUDA syscall/provider E2E verified: provider_reads={} bytes_read={}",
        metrics.read_calls, metrics.bytes_read,
    );
}
