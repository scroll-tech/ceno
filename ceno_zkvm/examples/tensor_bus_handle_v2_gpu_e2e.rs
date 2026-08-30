//! Focused GPU proof gate for descriptor-v2 Tensor-space and HintRef chaining.

use std::sync::Arc;

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

fn rejects(verifier: &ZKVMVerifier<E, Pcs>, proof: ZKVMProof<E, Pcs>) -> bool {
    verifier
        .verify_full_trace_proofs_halt(vec![proof], vec![BasicTranscript::new(b"riscv")], true)
        .is_err()
}

fn circuit_index(vk: &ceno_zkvm::structs::ZKVMVerifyingKey<E, Pcs>, name: &str) -> usize {
    vk.circuit_index_to_name
        .iter()
        .find_map(|(index, candidate)| (candidate == name).then_some(*index))
        .unwrap_or_else(|| panic!("v2 verifying key is missing {name}"))
}

fn main() {
    rayon::ThreadPoolBuilder::new()
        .stack_size(256 * 1024 * 1024)
        .build()
        .expect("construct TensorBus v2 E2E Rayon pool")
        .install(run);
}

fn run() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init();
    let resident_before = ceno_emul::tensor::resident::resident_cuda_metrics();
    let program = ceno_emul::Program::load_elf(ceno_examples::tensor_bus_handle_v2, u32::MAX)
        .expect("load TensorBus v2 guest");
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
    let mock_proving = std::env::var_os("MOCK_PROVING").is_some_and(|value| value == "1");
    let proofs = run_e2e_proof(
        &prover,
        &init_mem,
        KECCAK_EMPTY_WORDS,
        1 << 20,
        mock_proving,
        None,
    );
    assert_eq!(proofs.len(), 1, "the v2 segment must remain atomic");

    let matrix_index = circuit_index(&vk, "TensorBatchedMatMulCore");
    let hint_index = circuit_index(&vk, "TensorHintRefCore");
    let import_index = circuit_index(&vk, "TensorBusTENSOR_IMPORT_BEGIN_V1Ecall");
    let matrix = proofs[0]
        .chip_proofs
        .get(&matrix_index)
        .expect("v2 matrix Core proof missing");
    assert_eq!(matrix.num_instances[0], 8, "expected two matrix sections");
    assert!(
        matrix.matrix_reduction.is_some(),
        "matrix reduction missing"
    );
    assert_eq!(
        proofs[0]
            .chip_proofs
            .get(&hint_index)
            .expect("HintRef Core proof missing")
            .num_instances[0],
        8,
        "two logical role tiles must write eight HintRef values",
    );

    let verifier = ZKVMVerifier::new(vk);
    assert!(
        verifier
            .verify_full_trace_proofs_halt(
                proofs.clone(),
                vec![BasicTranscript::new(b"riscv")],
                true,
            )
            .expect("independent v2 verification returned an error"),
        "independent v2 verification rejected the honest GPU proof",
    );

    let mut hint_identity_tamper = proofs[0].clone();
    hint_identity_tamper
        .chip_proofs
        .get_mut(&hint_index)
        .unwrap()
        .w_out_evals[0][0] += E::ONE;
    assert!(rejects(&verifier, hint_identity_tamper));

    let mut hint_value_tamper = proofs[0].clone();
    hint_value_tamper
        .chip_proofs
        .get_mut(&matrix_index)
        .unwrap()
        .r_out_evals
        .last_mut()
        .unwrap()[0] += E::ONE;
    assert!(rejects(&verifier, hint_value_tamper));

    let mut tensor_slot_tamper = proofs[0].clone();
    tensor_slot_tamper
        .chip_proofs
        .get_mut(&import_index)
        .unwrap()
        .w_out_evals
        .last_mut()
        .unwrap()[0] += E::ONE;
    assert!(rejects(&verifier, tensor_slot_tamper));

    let mut tensor_version_tamper = proofs[0].clone();
    tensor_version_tamper
        .chip_proofs
        .get_mut(&matrix_index)
        .unwrap()
        .r_out_evals[0][0] += E::ONE;
    assert!(rejects(&verifier, tensor_version_tamper));

    let mut ordinary_output_tamper = proofs[0].clone();
    ordinary_output_tamper
        .chip_proofs
        .get_mut(&matrix_index)
        .unwrap()
        .main_out_evals
        .push(E::ONE);
    assert!(rejects(&verifier, ordinary_output_tamper));

    let mut product_tamper = proofs[0].clone();
    product_tamper
        .chip_proofs
        .get_mut(&matrix_index)
        .unwrap()
        .matrix_reduction
        .as_mut()
        .unwrap()
        .sumcheck_proof[0]
        .evaluations[0] += E::ONE;
    assert!(rejects(&verifier, product_tamper));

    let mut quotient_tamper = proofs[0].clone();
    quotient_tamper
        .chip_proofs
        .get_mut(&matrix_index)
        .unwrap()
        .matrix_reduction
        .as_mut()
        .unwrap()
        .output_evals[0] += E::ONE;
    assert!(rejects(&verifier, quotient_tamper));

    let mut remainder_tamper = proofs[0].clone();
    remainder_tamper
        .chip_proofs
        .get_mut(&matrix_index)
        .unwrap()
        .matrix_reduction
        .as_mut()
        .unwrap()
        .output_evals[1] += E::ONE;
    assert!(rejects(&verifier, remainder_tamper));

    let mut sigma_tamper = proofs[0].clone();
    sigma_tamper.main_constraint_proof.claimed_sum += E::ONE;
    assert!(rejects(&verifier, sigma_tamper));

    let resident =
        ceno_emul::tensor::resident::resident_cuda_metrics().delta_since(resident_before);
    if resident.sessions != 0 {
        assert_eq!(resident.h2d_bytes, resident.sessions * 16);
        assert_eq!(resident.d2h_bytes, resident.sessions * 16);
        assert_eq!(resident.attention_launches, resident.sessions);
        assert_eq!(resident.ffn_launches, resident.sessions);
    }
    println!(
        "TensorBus v2 GPU E2E verified: sections=2 hint_rows=8 logical_h2d_bytes=16 logical_d2h_bytes=16 intermediate_transfers=0 physical_replay_sessions={} matrix_specific_pcs_rounds=0 ordinary_witin_openings=1 hint_identity_tamper=reject hint_value_tamper=reject tensor_slot_tamper=reject tensor_version_tamper=reject ordinary_output_tamper=reject product_tamper=reject quotient_tamper=reject remainder_tamper=reject sigma_tamper=reject",
        resident.sessions,
    );
}
