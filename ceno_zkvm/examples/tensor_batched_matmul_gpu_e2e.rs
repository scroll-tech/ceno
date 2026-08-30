//! Focused real-guest GPU proof for two complete tiny 2x2 MatMul sections.

use std::sync::Arc;

use ceno_zkvm::{
    e2e::{
        KECCAK_EMPTY_WORDS, MultiProver, Preset, prepare_fulltracer_aot_program,
        prepare_preflight_aot_program, run_e2e_proof, setup_platform, setup_program,
    },
    scheme::{
        create_backend, create_prover, hal::ProverDevice, prover::ZKVMProver,
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

fn rejects(verifier: &ZKVMVerifier<E, Pcs>, proof: ceno_zkvm::scheme::ZKVMProof<E, Pcs>) -> bool {
    verifier
        .verify_full_trace_proofs_halt(vec![proof], vec![BasicTranscript::new(b"riscv")], true)
        .is_err()
}

fn main() {
    rayon::ThreadPoolBuilder::new()
        .stack_size(256 * 1024 * 1024)
        .build()
        .expect("construct tiny batched MatMul E2E Rayon pool")
        .install(run);
}

fn run() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init();
    let program =
        ceno_emul::Program::load_elf(ceno_examples::tensor_batched_matmul_2x2_v1, u32::MAX)
            .expect("load tiny batched MatMul guest");
    let platform = setup_platform(Preset::Ceno, &program, 128 * 1024, 2 * 1024 * 1024);
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

    let (max_num_variables, security_level) = default_backend_config();
    let backend = create_backend::<E, Pcs>(max_num_variables, security_level);
    let device = create_prover(backend);
    let (pk, vk) = ctx.keygen_with_pb(device.get_pb());
    let prover = ZKVMProver::new(pk.into(), device);
    let init_mem = prover.setup_init_mem(&[]);
    let proofs = run_e2e_proof(&prover, &init_mem, KECCAK_EMPTY_WORDS, 1 << 20, false, None);
    assert_eq!(proofs.len(), 1, "tiny complete calls must share one shard");

    let core_index = vk
        .circuit_index_to_name
        .iter()
        .find_map(|(index, name)| (name == "TensorBatchedMatMulCore").then_some(*index))
        .expect("tiny batched MatMul Core missing from verifying key");
    let matrix = proofs[0]
        .chip_proofs
        .get(&core_index)
        .expect("tiny batched MatMul Core proof missing");
    assert_eq!(matrix.num_instances[0], 8, "expected two complete sections");
    assert!(
        matrix.matrix_reduction.is_some(),
        "matrix reduction missing"
    );
    assert_eq!(proofs[0].additional_witness_openings.len(), 3);

    if let Some(dir) = std::env::var_os("CENO_TENSOR_MATMUL_RECURSION_FIXTURE_DIR") {
        let dir = std::path::PathBuf::from(dir);
        std::fs::create_dir_all(&dir).expect("create recursion fixture directory");
        std::fs::write(
            dir.join("proof.bin"),
            bincode::serialize(&proofs).expect("serialize GPU proof fixture"),
        )
        .expect("write GPU proof fixture");
        std::fs::write(
            dir.join("vk.bin"),
            bincode::serialize(&vk).expect("serialize GPU vk fixture"),
        )
        .expect("write GPU vk fixture");
    }

    let verifier = ZKVMVerifier::new(vk);
    assert!(
        verifier
            .verify_full_trace_proofs_halt(
                proofs.clone(),
                vec![BasicTranscript::new(b"riscv")],
                true,
            )
            .expect("native verification returned an error"),
        "native verification rejected the honest GPU proof"
    );

    let mut product_tamper = proofs[0].clone();
    product_tamper
        .chip_proofs
        .get_mut(&core_index)
        .unwrap()
        .matrix_reduction
        .as_mut()
        .unwrap()
        .sumcheck_proof[0]
        .evaluations[0] += E::ONE;
    assert!(
        rejects(&verifier, product_tamper),
        "product tamper verified"
    );

    let mut quotient_tamper = proofs[0].clone();
    quotient_tamper
        .chip_proofs
        .get_mut(&core_index)
        .unwrap()
        .matrix_reduction
        .as_mut()
        .unwrap()
        .output_evals[0] += E::ONE;
    assert!(
        rejects(&verifier, quotient_tamper),
        "quotient tamper verified"
    );

    let mut remainder_tamper = proofs[0].clone();
    remainder_tamper
        .chip_proofs
        .get_mut(&core_index)
        .unwrap()
        .matrix_reduction
        .as_mut()
        .unwrap()
        .output_evals[1] += E::ONE;
    assert!(
        rejects(&verifier, remainder_tamper),
        "remainder tamper verified"
    );

    println!(
        "tiny batched MatMul GPU E2E verified: sections=2 same_commitment_rounds=3 product_tamper=reject quotient_tamper=reject remainder_tamper=reject"
    );
}
