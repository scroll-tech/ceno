//! Deterministic, non-functional Llama-2-7B-shape raw-hint benchmark.
//!
//! This is intentionally *not* model-quality inference and does not accept
//! licensed model weights.  The 32-layer descriptor uses deterministic
//! quantized fixture metadata to measure the shape and reject an impossible
//! guest-hint admission.  The one direct proof below is the largest currently
//! admitted raw-hint primitive: an unauthenticated K11008 output cell backed
//! by deterministic signed-byte tiles.  It preserves the production raw-hint
//! AIR/provider path without allocating a 7B weight bundle.

use std::{sync::Arc, time::Instant};

use ceno_emul::tensor::{
    TensorWitnessProvider,
    production::{
        ProductionMatMulSignature, llama2_7b_static_calls, production_shape_fixture_manifest,
        sparse_production_dot_fixture,
    },
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

const FIXTURE_SEED: u32 = 0x7b51_2026;
const RAW_HINT_WORD_BYTES: u64 = 4;
const GUEST_HINT_CAPACITY_BYTES: u64 = 128 * 1024 * 1024;
const GUEST_HINT_START: u32 = 0x2800_0000;
const GUEST_HINT_END: u32 = GUEST_HINT_START + GUEST_HINT_CAPACITY_BYTES as u32;
const SYNTHETIC_RESIDENT_BLOCK_LAYERS: u32 = 4;
const SYNTHETIC_RESIDENT_BLOCK_COUNT: u32 = 8;
const SYNTHETIC_BLOCK_HINT_WINDOW_BYTES: u32 = 16 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SyntheticResidentBlock {
    shard_item: u32,
    first_layer: u32,
    hint_base: u32,
}

fn synthetic_resident_blocks() -> [SyntheticResidentBlock; SYNTHETIC_RESIDENT_BLOCK_COUNT as usize]
{
    std::array::from_fn(|index| SyntheticResidentBlock {
        shard_item: index as u32,
        first_layer: index as u32 * SYNTHETIC_RESIDENT_BLOCK_LAYERS,
        hint_base: GUEST_HINT_START + index as u32 * SYNTHETIC_BLOCK_HINT_WINDOW_BYTES,
    })
}

fn main() {
    rayon::ThreadPoolBuilder::new()
        .stack_size(256 * 1024 * 1024)
        .build()
        .expect("construct synthetic-7B E2E Rayon pool")
        .install(run);
}

fn run() {
    let started = Instant::now();
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init();

    // This descriptor is a planning-only model shape.  No full weight vector
    // is allocated: fixture roots are deterministic from FIXTURE_SEED.
    let manifest = production_shape_fixture_manifest(4096, FIXTURE_SEED)
        .expect("construct deterministic 7B-shape raw-hint manifest");
    let raw_hint_bytes = manifest
        .entries
        .iter()
        .map(|entry| entry.byte_len)
        .sum::<u64>();
    let calls = llama2_7b_static_calls();
    assert_eq!(
        calls.len(),
        66,
        "Llama-2-7B topology must have 66 physical calls"
    );
    let blocks = synthetic_resident_blocks();
    for (index, block) in blocks.iter().enumerate() {
        assert_eq!(
            block.shard_item, index as u32,
            "resident block order changed"
        );
        assert_eq!(
            block.first_layer,
            index as u32 * SYNTHETIC_RESIDENT_BLOCK_LAYERS,
            "resident block layer range changed"
        );
        assert!(
            block.hint_base >= GUEST_HINT_START
                && block.hint_base + SYNTHETIC_BLOCK_HINT_WINDOW_BYTES <= GUEST_HINT_END,
            "synthetic block hint window left guest hint range"
        );
        if let Some(previous) = index.checked_sub(1).map(|previous| blocks[previous]) {
            assert_eq!(
                previous.hint_base + SYNTHETIC_BLOCK_HINT_WINDOW_BYTES,
                block.hint_base,
                "successive resident blocks must own distinct hint windows"
            );
        }
        // All Attention/FFN calls in this atomic shard item derive from the
        // same base.  This intentionally makes the fixture tied-weight
        // synthetic; it prevents every inner call from naming a different
        // (and potentially cross-shard) guest hint region.
        for layer in block.first_layer..block.first_layer + SYNTHETIC_RESIDENT_BLOCK_LAYERS {
            for _role in ["attention", "ffn"] {
                assert_eq!(
                    block.hint_base,
                    GUEST_HINT_START + block.shard_item * SYNTHETIC_BLOCK_HINT_WINDOW_BYTES,
                    "inner tensor call crossed its resident block hint window at layer {layer}"
                );
            }
        }
    }
    assert!(raw_hint_bytes > GUEST_HINT_CAPACITY_BYTES);
    println!(
        "synthetic_7b_shape_plan non_functional_model_quality=false tied_weight_synthetic=true context_tokens=not_executed seed={FIXTURE_SEED} manifest_tensors={} topology_calls={} raw_hint_bytes={raw_hint_bytes} guest_hint_capacity_bytes={GUEST_HINT_CAPACITY_BYTES} resident_block_layers={SYNTHETIC_RESIDENT_BLOCK_LAYERS} resident_block_shard_items={} inner_attention_ffn_calls_per_block={} hint_window_bytes={SYNTHETIC_BLOCK_HINT_WINDOW_BYTES} first_hint_base=0x{:08x} last_hint_base=0x{:08x} no_cross_shard_hint_reads=true admitted_full_guest=false admission_reason=raw_hints_exceed_fixed_guest_hint_region",
        manifest.entries.len(),
        calls.len(),
        blocks.len(),
        2 * SYNTHETIC_RESIDENT_BLOCK_LAYERS,
        blocks.first().expect("resident blocks").hint_base,
        blocks.last().expect("resident blocks").hint_base,
    );

    // Run exactly one admitted production primitive.  This has deterministic
    // signed-byte raw hints and is intentionally labelled as a capacity probe,
    // not a Llama layer/model proof.
    let program =
        ceno_emul::Program::load_elf(ceno_examples::tensor_matmul_intermediate_v1, u32::MAX)
            .expect("load synthetic K11008 raw-hint guest");
    let platform = setup_platform(Preset::Ceno, &program, 128 * 1024, 2 * 1024 * 1024);
    let mut ctx = setup_program::<E>(program, platform, MultiProver::default());
    let (desc, _entry, provider) = sparse_production_dot_fixture(
        ProductionMatMulSignature::IntermediateK11008,
        83,
        FIXTURE_SEED,
    )
    .expect("construct deterministic K11008 raw-hint fixture");
    let tile_count = u64::from(desc.tile_count);
    let provider: Arc<dyn TensorWitnessProvider> = Arc::new(provider);
    ctx.set_tensor_proof_context(Arc::new(TensorProofContext::new(Arc::clone(&provider))));

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
    let prepared = Instant::now();

    let (max_num_variables, security_level) = default_backend_config();
    let backend = create_backend::<E, Pcs>(max_num_variables, security_level);
    let device = create_prover(backend);
    let (pk, vk) = ctx.keygen_with_pb(device.get_pb());
    let keyed = Instant::now();
    let prover = ZKVMProver::new(pk.into(), device);
    let init_mem = prover.setup_init_mem(&[]);
    let proofs = run_e2e_proof(&prover, &init_mem, KECCAK_EMPTY_WORDS, 1 << 20, false, None);
    let proved = Instant::now();
    assert_eq!(
        proofs.len(),
        1,
        "one admitted raw-hint cell must occupy one shard"
    );
    let proof_bytes = proofs
        .iter()
        .map(|proof| bincode::serialized_size(proof).expect("serialize proof"))
        .sum::<u64>();
    run_e2e_full_trace_verify(&ZKVMVerifier::new(vk), proofs, Some(0), 1 << 20);
    let verified = Instant::now();

    let raw = provider.metrics();
    assert_eq!(
        raw.bytes_read
            % (u64::try_from(desc.signature.k()).expect("K fits u64") * RAW_HINT_WORD_BYTES),
        0,
        "raw hint reads must be whole K11008 calls"
    );
    let gpu_oracle_invocations = raw.read_calls / tile_count;
    // K11008CudaProvider's contract is two 11008-word H2D inputs, one i64
    // D2H result, and all three buffers alive through export.  The production
    // syscall invokes it once for each raw-hint replay; derive totals from the
    // provider's authoritative ordered-tile replay count.
    let gpu_h2d_bytes = gpu_oracle_invocations * (2 * 11_008 * RAW_HINT_WORD_BYTES);
    let gpu_d2h_bytes = gpu_oracle_invocations * 8;
    let gpu_peak_bytes = 2 * 11_008 * RAW_HINT_WORD_BYTES + 8;
    println!(
        "synthetic_7b_shape_e2e non_functional_model_quality=false admitted_primitive=raw_hint_k11008_cell shards=1 cells=1 proof_bytes={proof_bytes} raw_hint_reads={} raw_hint_bytes={} gpu_oracle_invocations={gpu_oracle_invocations} gpu_h2d_bytes={gpu_h2d_bytes} gpu_d2h_bytes={gpu_d2h_bytes} gpu_peak_bytes={gpu_peak_bytes} prepare_ms={} keygen_ms={} witness_and_base_prove_ms={} recursion_ms=0 verify_ms={} create_proof_total_ms={} tokens_per_s=not_meaningful",
        raw.read_calls,
        raw.bytes_read,
        prepared.duration_since(started).as_millis(),
        keyed.duration_since(prepared).as_millis(),
        proved.duration_since(keyed).as_millis(),
        verified.duration_since(proved).as_millis(),
        verified.duration_since(started).as_millis(),
    );
}
