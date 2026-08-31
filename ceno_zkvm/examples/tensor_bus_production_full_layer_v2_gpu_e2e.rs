//! Production GPU proof gate for one exact batch-one Llama-2-7B S2048 layer.

use std::{sync::Arc, time::Instant};

use ceno_zkvm::{
    e2e::{
        KECCAK_EMPTY_WORDS, MultiProver, Preset, prepare_fulltracer_aot_program,
        prepare_preflight_aot_program, run_e2e_proof, setup_platform, setup_program,
    },
    scheme::{
        ZKVMProof, create_backend, create_prover, hal::ProverDevice, prover::ZKVMProver,
        verifier::ZKVMVerifier,
    },
};
use ff_ext::BabyBearExt4;
use gkr_iop::cpu::default_backend_config;
use mpcs::{Basefold, BasefoldRSParams, Jagged};
use p3::field::PrimeCharacteristicRing;
use transcript::BasicTranscript;

type E = BabyBearExt4;
type Pcs = Jagged<Basefold<E, BasefoldRSParams>>;

const MAX_STEPS: usize = 1 << 28;
const MAX_CELLS_PER_SHARD: u64 = u64::MAX;
const HIDDEN_BYTES: u64 = 32 * 1024 * 1024;
const TOTAL_MULTIPLICATIONS: u64 = 34_359_738_368;

fn circuit_index(vk: &ceno_zkvm::structs::ZKVMVerifyingKey<E, Pcs>, name: &str) -> usize {
    vk.circuit_index_to_name
        .iter()
        .find_map(|(index, candidate)| (candidate == name).then_some(*index))
        .unwrap_or_else(|| panic!("production verifying key is missing {name}"))
}

fn rejects(verifier: &ZKVMVerifier<E, Pcs>, proofs: Vec<ZKVMProof<E, Pcs>>) -> bool {
    let transcripts = (0..proofs.len())
        .map(|_| BasicTranscript::new(b"riscv"))
        .collect();
    verifier
        .verify_full_trace_proofs_halt(proofs, transcripts, true)
        .is_err()
}

fn main() {
    rayon::ThreadPoolBuilder::new()
        .stack_size(256 * 1024 * 1024)
        .build()
        .expect("construct production-attention E2E Rayon pool")
        .install(run);
}

fn run() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init();
    let started = Instant::now();
    let program =
        ceno_emul::Program::load_elf(ceno_examples::tensor_bus_production_full_layer_v2, u32::MAX)
            .expect("load exact production-attention guest");
    let platform = setup_platform(Preset::Ceno, &program, 1024 * 1024, 160 * 1024 * 1024);
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
    let mock_proving = std::env::var_os("MOCK_PROVING").is_some_and(|value| value == "1");
    let target_shard_id = std::env::var("CENO_TARGET_SHARD_ID").ok().map(|value| {
        value
            .parse::<usize>()
            .expect("CENO_TARGET_SHARD_ID must be a non-negative integer")
    });
    assert!(
        target_shard_id.is_none() || mock_proving,
        "CENO_TARGET_SHARD_ID is diagnostic-only and requires MOCK_PROVING=1"
    );
    let proofs = run_e2e_proof(
        &prover,
        &init_mem,
        KECCAK_EMPTY_WORDS,
        MAX_STEPS,
        mock_proving,
        target_shard_id,
    );
    let proved = Instant::now();
    let mut names = vec![
        "TensorProductionImportBeginAnchor".to_string(),
        "TensorProductionFullLayerAnchor".to_string(),
        "TensorProductionExportEndAnchor".to_string(),
        "TensorProductionBoundaryHiddenInput".to_string(),
        "TensorProductionBoundaryHiddenOutput".to_string(),
    ];
    for prefix in [
        "TensorAttentionQKHeads",
        "TensorAttentionSoftmaxHeads",
        "TensorAttentionPVHeads",
    ] {
        for group in 0..8 {
            names.push(format!("{prefix}{:02}_{:02}", group * 4, group * 4 + 3));
        }
    }
    assert_eq!(names.len(), 29, "production circuit inventory changed");
    let indices = names
        .iter()
        .map(|name| circuit_index(&vk, name))
        .collect::<Vec<_>>();
    assert!(
        indices.windows(2).all(|pair| pair[0] < pair[1]),
        "production circuits are not in canonical registration order"
    );
    let production_shards = proofs
        .iter()
        .enumerate()
        .filter_map(|(shard, proof)| {
            indices
                .iter()
                .any(|index| proof.chip_proofs.contains_key(index))
                .then_some(shard)
        })
        .collect::<Vec<_>>();
    assert_eq!(
        production_shards.len(),
        1,
        "exactly one shard must contain production circuits"
    );
    let production_shard = production_shards[0];
    assert!(
        indices
            .iter()
            .all(|index| proofs[production_shard].chip_proofs.contains_key(index)),
        "the unique production shard must contain all 29 production circuits"
    );

    let verifier = ZKVMVerifier::new(vk);
    let transcripts = (0..proofs.len())
        .map(|_| BasicTranscript::new(b"riscv"))
        .collect();
    assert!(
        verifier
            .verify_full_trace_proofs_halt(proofs.clone(), transcripts, true)
            .expect("independent production verification returned an error"),
        "independent production verification rejected an honest GPU shard"
    );
    let verified = Instant::now();

    for (label, index) in [
        ("boundary", indices[3]),
        ("qk", indices[5]),
        ("softmax_limb0", indices[13]),
        ("softmax_limb1", indices[13]),
        ("softmax_limb2", indices[13]),
        ("softmax_exp3", indices[13]),
        ("softmax_exp4", indices[13]),
        ("causal", indices[13]),
        ("pv_k128", indices[21]),
    ] {
        let mut tampered = proofs.clone();
        tampered[production_shard]
            .chip_proofs
            .get_mut(&index)
            .unwrap_or_else(|| panic!("{label} proof missing"))
            .w_out_evals[0][0] += E::ONE;
        assert!(rejects(&verifier, tampered), "{label} tamper verified");
    }

    let proof_bytes = proofs
        .iter()
        .map(|proof| bincode::serialized_size(proof).expect("serialize production proof"))
        .sum::<u64>();
    let shards = proofs.len();
    println!(
        "production full-layer GPU E2E verified: batch=1 sequence=2048 hidden=4096 heads=32 head_dim=128 profile=2 layer=0 shards={shards} production_shard={production_shard} max_cells_per_shard={MAX_CELLS_PER_SHARD} circuits=29 hidden_input_bytes={HIDDEN_BYTES} hidden_output_bytes={HIDDEN_BYTES} logical_h2d_bytes={HIDDEN_BYTES} logical_d2h_bytes={HIDDEN_BYTES} intermediate_h2d_bytes=0 intermediate_d2h_bytes=0 qk_multiplications={} pv_multiplications={} total_multiplications={TOTAL_MULTIPLICATIONS} pv_k_tile=128 pv_k_tiles=16 proof_bytes={proof_bytes} prepare_ms={} keygen_ms={} witness_and_base_prove_ms={} verify_ms={} total_ms={} boundary_tamper=reject qk_tamper=reject five_softmax_lookups_tamper=reject causal_tamper=reject pv_k128_tamper=reject",
        TOTAL_MULTIPLICATIONS / 2,
        TOTAL_MULTIPLICATIONS / 2,
        prepared.duration_since(started).as_millis(),
        keyed.duration_since(prepared).as_millis(),
        proved.duration_since(keyed).as_millis(),
        verified.duration_since(proved).as_millis(),
        verified.duration_since(started).as_millis(),
    );
}
