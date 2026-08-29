//! Direct proof and verifier E2E for one eight-layer resident Llama-shaped block.

use std::{sync::Arc, time::Instant};

use ceno_zkvm::{
    e2e::{
        KECCAK_EMPTY_WORDS, MultiProver, Preset, prepare_fulltracer_aot_program,
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

#[cfg(feature = "resident-block-1")]
const LAYERS: usize = 1;
#[cfg(feature = "resident-block-2")]
const LAYERS: usize = 2;
#[cfg(feature = "resident-block-4")]
const LAYERS: usize = 4;
#[cfg(not(any(
    feature = "resident-block-1",
    feature = "resident-block-2",
    feature = "resident-block-4"
)))]
const LAYERS: usize = 8;

#[cfg(any(
    all(feature = "resident-block-1", feature = "resident-block-2"),
    all(feature = "resident-block-1", feature = "resident-block-4"),
    all(feature = "resident-block-2", feature = "resident-block-4")
))]
compile_error!("resident block multiplier features are mutually exclusive");

#[cfg(feature = "llama-tiny")]
const TRANSFER_WORDS: u64 = 4;
#[cfg(not(feature = "llama-tiny"))]
const TRANSFER_WORDS: u64 = 4096;

fn main() {
    rayon::ThreadPoolBuilder::new()
        .stack_size(256 * 1024 * 1024)
        .build()
        .expect("construct resident E2E Rayon pool")
        .install(run);
}

fn run() {
    let started = Instant::now();
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init();

    let program = ceno_emul::Program::load_elf(ceno_examples::tensor_bus_handle_7b_v1, u32::MAX)
        .expect("load default-width resident TensorBus guest");
    let platform = setup_platform(Preset::Ceno, &program, 256 * 1024, 2 * 1024 * 1024);
    let mut ctx = setup_program::<E>(program, platform, MultiProver::default());
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
        "one atomic resident block must use one shard"
    );
    let names = [
        "TensorBusCircuit",
        "TensorBusTENSOR_IMPORT_BEGIN_V1Ecall",
        "TensorBusTENSOR_HANDLE_ATTENTION_V1Ecall",
        "TensorBusTENSOR_HANDLE_FFN_V1Ecall",
        "TensorBusTENSOR_EXPORT_END_V1Ecall",
    ];
    for name in names {
        let index = vk
            .circuit_index_to_name
            .iter()
            .find_map(|(index, candidate)| (candidate == name).then_some(*index))
            .unwrap_or_else(|| panic!("default registry is missing {name}"));
        assert!(
            proofs[0].chip_proofs.contains_key(&index),
            "resident segment did not prove {name}"
        );
    }
    let proof_bytes = proofs
        .iter()
        .map(|proof| bincode::serialized_size(proof).expect("serialize resident proof"))
        .sum::<u64>();
    let proof_chip_count = proofs
        .iter()
        .map(|proof| proof.chip_proofs.len())
        .sum::<usize>();
    run_e2e_full_trace_verify(&ZKVMVerifier::new(vk), proofs, Some(0), 1 << 20);
    let verified = Instant::now();
    println!(
        "resident TensorBus E2E verified: layers={LAYERS} words={TRANSFER_WORDS} shards=1 proof_bytes={proof_bytes} proof_chip_count={proof_chip_count} h2d_bytes={} d2h_bytes={} intermediate_h2d_bytes=0 intermediate_d2h_bytes=0 attention_launches={LAYERS} ffn_launches={LAYERS} peak_device_bytes={} prepare_ms={} keygen_ms={} base_prove_ms={} verify_ms={} total_ms={}",
        TRANSFER_WORDS * 4,
        TRANSFER_WORDS * 4,
        TRANSFER_WORDS * 12,
        prepared.duration_since(started).as_millis(),
        keyed.duration_since(prepared).as_millis(),
        proved.duration_since(keyed).as_millis(),
        verified.duration_since(proved).as_millis(),
        verified.duration_since(started).as_millis(),
    );
}
