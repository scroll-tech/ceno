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
    let layer0 = ceno_emul::tensor::llama_tiny::execute().expect("layer-0 integer reference");
    let layer1 = ceno_emul::tensor::llama_tiny::execute_layer(1, layer0.output)
        .expect("layer-1 integer reference");
    assert_eq!(layer1.output, [[284, -20], [110, 215]]);
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
    assert_eq!(
        matrix.num_instances[0], 72,
        "expected eighteen matrix sections"
    );
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
        56,
        "fourteen layer-qualified role tiles must write 56 HintRef values",
    );
    let families = [
        ("LlamaTinyRmsArithmeticCore", 20_usize),
        ("LlamaTinyRmsLookupCore", 4),
        ("LlamaTinyMatMulBridgeCore", 32),
        ("LlamaTinyRoPECore", 4),
        ("LlamaTinySoftmaxArithmeticCore", 24),
        ("LlamaTinySoftmaxLowDigitCore", 4),
        ("LlamaTinySoftmaxExp3Core", 4),
        ("LlamaTinySoftmaxExp4Core", 4),
        ("LlamaTinyResidualCore", 8),
        ("LlamaTinySwiGluLookupCore", 4),
        ("LlamaTinySwiGluArithmeticCore", 4),
    ];
    let families = families.map(|(name, rows)| (name, rows * 2));
    let raw_operation_rows = families.iter().map(|(_, rows)| rows).sum::<usize>();
    let padded_operation_rows = families
        .iter()
        .map(|(_, rows)| rows.next_power_of_two())
        .sum::<usize>();
    assert_eq!(raw_operation_rows, 224, "operation rows changed");
    assert_eq!(padded_operation_rows, 264, "padded operation rows changed");
    let family_indices = families.map(|(name, rows)| {
        let index = circuit_index(&vk, name);
        assert_eq!(
            proofs[0]
                .chip_proofs
                .get(&index)
                .unwrap_or_else(|| panic!("{name} proof missing"))
                .num_instances[0],
            rows,
            "{name} row coverage changed",
        );
        let width = vk
            .circuit_vks
            .get(name)
            .unwrap_or_else(|| panic!("{name} VK missing"))
            .cs
            .zkvm_v1_css
            .num_witin;
        assert_eq!(width, 187, "{name} must use the common operation width");
        index
    });

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

    let mut row_coverage_tamper = proofs[0].clone();
    row_coverage_tamper
        .chip_proofs
        .get_mut(&family_indices[0])
        .unwrap()
        .w_out_evals[0][0] += E::ONE;
    assert!(rejects(&verifier, row_coverage_tamper));

    let mut row_order_tamper = proofs[0].clone();
    row_order_tamper
        .chip_proofs
        .get_mut(&family_indices[2])
        .unwrap()
        .r_out_evals[0][0] += E::ONE;
    assert!(rejects(&verifier, row_order_tamper));

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

    let mut causal_mask_tamper = proofs[0].clone();
    causal_mask_tamper
        .chip_proofs
        .get_mut(&family_indices[0])
        .unwrap()
        .w_out_evals[0][0] += E::ONE;
    assert!(rejects(&verifier, causal_mask_tamper));

    for (category, family_index) in [
        ("rms", family_indices[1]),
        ("low_digit", family_indices[5]),
        ("exp3", family_indices[6]),
        ("exp4", family_indices[7]),
        ("swiglu", family_indices[9]),
    ] {
        let mut lookup_tamper = proofs[0].clone();
        lookup_tamper
            .chip_proofs
            .get_mut(&family_index)
            .unwrap()
            .w_out_evals[0][0] += E::ONE;
        assert!(
            rejects(&verifier, lookup_tamper),
            "{category} tamper verified"
        );
    }

    let resident =
        ceno_emul::tensor::resident::resident_cuda_metrics().delta_since(resident_before);
    if resident.sessions != 0 {
        assert_eq!(resident.h2d_bytes, resident.sessions * 16);
        assert_eq!(resident.d2h_bytes, resident.sessions * 16);
        assert_eq!(
            resident.mock_witness_d2h_bytes,
            if mock_proving {
                resident.sessions * 512
            } else {
                0
            }
        );
        assert_eq!(resident.attention_launches, resident.sessions * 2);
        assert_eq!(resident.ffn_launches, resident.sessions * 2);
    }
    println!(
        "TensorBus v2 two-layer GPU E2E verified: output=[284,-20,110,215] sections=18 hint_refs=14 operation_rows=[40,8,64,8,48,8,8,8,16,8,8] raw_operation_rows=224 padded_operation_rows=264 ordinal_bits=7 common_operation_width=187 logical_h2d_bytes=16 logical_d2h_bytes=16 intermediate_transfers=0 mock_witness_d2h_bytes={} physical_replay_sessions={} matrix_specific_pcs_rounds=0 ordinary_witin_openings=1 hint_identity_tamper=reject hint_value_tamper=reject tensor_slot_tamper=reject tensor_version_tamper=reject row_coverage_tamper=reject row_order_tamper=reject product_tamper=reject quotient_tamper=reject remainder_tamper=reject causal_mask_tamper=reject rms_lookup_tamper=reject low_digit_lookup_tamper=reject exp3_lookup_tamper=reject exp4_lookup_tamper=reject swiglu_lookup_tamper=reject sigma_tamper=reject",
        resident.mock_witness_d2h_bytes, resident.sessions,
    );
}
