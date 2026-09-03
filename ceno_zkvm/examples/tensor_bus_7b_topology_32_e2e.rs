//! Direct default-width, tied-weight 32-layer topology E2E.
//!
//! This benchmark proves eight atomic 4-layer resident blocks.  The selected
//! shard budget intentionally cuts only between complete import/export
//! boundaries; the final ordinary guest operation is admitted separately.

use std::{
    panic::{AssertUnwindSafe, catch_unwind, resume_unwind},
    sync::Arc,
    time::Instant,
};

use ceno_zkvm::{
    e2e::{
        KECCAK_EMPTY_WORDS, MultiProver, Preset, emulate_program, prepare_fulltracer_aot_program,
        prepare_preflight_aot_program, run_e2e_full_trace_verify, run_e2e_proof, setup_platform,
        setup_program,
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

const RESIDENT_BLOCKS: usize = 8;
const LAYERS_PER_BLOCK: usize = 4;
const WORDS: u64 = 4096;
// This admits the initial (larger) resident segment, but not two steady
// resident segments.  Shard boundaries are therefore planner capacity cuts,
// never an explicit TensorBus policy.
// Four attention→FFN pairs is the demonstrated resident-memory envelope.
// This is deliberately below the next TensorBus-region admission threshold;
// preflight verifies that no shard receives a second resident block.
const MAX_CELLS_PER_SHARD: u64 = 4_379_000;

fn main() {
    rayon::ThreadPoolBuilder::new()
        .stack_size(256 * 1024 * 1024)
        .build()
        .expect("construct topology E2E Rayon pool")
        .install(run);
}

fn run() {
    let started = Instant::now();
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init();
    let program =
        ceno_emul::Program::load_elf(ceno_examples::tensor_bus_handle_7b_topology_32_v1, u32::MAX)
            .expect("load tied-weight 32-layer topology guest");
    let platform = setup_platform(Preset::Ceno, &program, 512 * 1024, 2 * 1024 * 1024);
    // Direct AOT stays enabled.  Its generated block entry guard switches to
    // exact preflight fallback only while a matched TensorBus region is
    // pending, then resumes native planning after EXPORT_END.
    let multi_prover = MultiProver::new(0, 1, MAX_CELLS_PER_SHARD, u64::MAX)
        .with_tensor_segment_inner_repetitions(LAYERS_PER_BLOCK);
    let mut ctx = setup_program::<E>(program, platform, multi_prover);
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
    // Calibration is a runner-only escape hatch.  It neither changes the
    // registry nor proof semantics and lets us select an atomic shard budget
    // before the single expensive proof run.
    if std::env::var_os("CENO_TOPOLOGY_PREFLIGHT_ONLY").is_some() {
        let raw_step_cell_extractor = Arc::clone(&ctx.system_config.config);
        let step_cell_extractor: Arc<dyn ceno_emul::StepCellExtractor> = raw_step_cell_extractor;
        let emulation = emulate_program(
            ctx.program.clone(),
            1 << 20,
            &init_mem,
            KECCAK_EMPTY_WORDS,
            &ctx.platform,
            &ctx.multi_prover,
            step_cell_extractor,
            ctx.tensor_proof_context.clone(),
            ctx.preflight_aot_program.clone(),
            ctx.fulltracer_aot_program.clone(),
        );
        let boundaries = emulation.shard_cycle_boundaries;
        let predicted_shard_costs = emulation.predicted_shard_costs;
        let admitted_tensor_segments = emulation.admitted_tensor_segments;
        println!(
            "topology preflight: resident_blocks={RESIDENT_BLOCKS} layers_per_block={LAYERS_PER_BLOCK} planned_shards={} shard_cycle_boundaries={:?} predicted_shard_cells={:?} tensor_regions={:?} max_cells_per_shard={MAX_CELLS_PER_SHARD}",
            boundaries.len().saturating_sub(1),
            boundaries,
            predicted_shard_costs,
            admitted_tensor_segments
        );
        return;
    }
    let prepared = Instant::now();

    let (max_num_variables, security_level) = default_backend_config();
    let backend = create_backend::<E, Pcs>(max_num_variables, security_level);
    let device = create_prover(backend);
    let (pk, vk) = ctx.keygen_with_pb(device.get_pb());
    let keyed = Instant::now();
    let prover = ZKVMProver::new(pk.into(), device);
    let init_mem = prover.setup_init_mem(&[]);
    let is_mock_proving = std::env::var_os("MOCK_PROVING").is_some();
    let proofs = run_e2e_proof(
        &prover,
        &init_mem,
        KECCAK_EMPTY_WORDS,
        1 << 20,
        is_mock_proving,
        None,
    );
    let proved = Instant::now();
    assert_eq!(
        proofs.len(),
        9,
        "eight resident blocks plus trailing operation need nine shards"
    );
    let proof_bytes: Vec<u64> = proofs
        .iter()
        .map(|proof| bincode::serialized_size(proof).expect("serialize topology proof"))
        .collect();
    let total_proof_bytes = proof_bytes.iter().sum::<u64>();
    let timing_trace = std::env::var_os("CENO_TOPOLOGY_TIMING_TRACE").is_some();
    let verifier = ZKVMVerifier::new(vk);
    if timing_trace {
        // Print the base-path boundary before verification.  If verification
        // panics, the catch below prints its own elapsed time before resuming
        // the original failure, keeping diagnostic timing failure-safe.
        eprintln!(
            "topology timing before_verify: prepare_ms={} keygen_ms={} witness_base_prove_ms={}",
            prepared.duration_since(started).as_millis(),
            keyed.duration_since(prepared).as_millis(),
            proved.duration_since(keyed).as_millis(),
        );
        let verify_result = catch_unwind(AssertUnwindSafe(|| {
            run_e2e_full_trace_verify(&verifier, proofs, Some(0), 1 << 20)
        }));
        let verified = Instant::now();
        eprintln!(
            "topology timing verification_finished: verify_ms={} total_ms={} status={}",
            verified.duration_since(proved).as_millis(),
            verified.duration_since(started).as_millis(),
            if verify_result.is_ok() { "ok" } else { "error" },
        );
        if let Err(payload) = verify_result {
            resume_unwind(payload);
        }
    } else {
        run_e2e_full_trace_verify(&verifier, proofs, Some(0), 1 << 20);
    }
    let verified = Instant::now();
    let transfer_bytes = RESIDENT_BLOCKS as u64 * WORDS * 4;
    println!(
        "tied-weight 7B topology E2E verified: resident_blocks={RESIDENT_BLOCKS} layers={} shards=9 proof_bytes_total={total_proof_bytes} proof_bytes_per_shard={proof_bytes:?} h2d_bytes={transfer_bytes} d2h_bytes={transfer_bytes} intermediate_h2d_bytes=0 intermediate_d2h_bytes=0 peak_device_bytes_per_block={} prepare_ms={} keygen_ms={} witness_base_prove_ms={} verify_ms={} total_ms={}",
        RESIDENT_BLOCKS * LAYERS_PER_BLOCK,
        WORDS * 12,
        prepared.duration_since(started).as_millis(),
        keyed.duration_since(prepared).as_millis(),
        proved.duration_since(keyed).as_millis(),
        verified.duration_since(proved).as_millis(),
        verified.duration_since(started).as_millis(),
    );
}
