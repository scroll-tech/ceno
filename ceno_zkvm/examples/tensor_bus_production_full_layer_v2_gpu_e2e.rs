//! Production GPU proof gate for one exact batch-one Llama-2-7B S2048 layer.

use std::{sync::Arc, time::Instant};

use ceno_zkvm::{
    e2e::{
        KECCAK_EMPTY_WORDS, MultiProver, Preset, emulate_program, prepare_fulltracer_aot_program,
        prepare_preflight_aot_program, run_e2e_proof, run_e2e_single_shard_debug_verify,
        setup_platform, setup_program,
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
const DEFAULT_MAX_CELLS_PER_SHARD: u64 = u64::MAX;
const HIDDEN_BYTES: u64 = 32 * 1024 * 1024;
const TOTAL_MULTIPLICATIONS: u64 = 34_359_738_368;
const HEADS_PER_CIRCUIT: usize = ceno_emul::tensor::production_attention::HEADS_PER_CIRCUIT;
const ATTENTION_GROUPS: usize = ceno_emul::tensor::production_attention::CIRCUITS;

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

fn rejects_single_shard(verifier: &ZKVMVerifier<E, Pcs>, proof: ZKVMProof<E, Pcs>) -> bool {
    let expect_halt = proof.has_halt(&verifier.vk);
    verifier
        .verify_single_shard_segment_halt(proof, BasicTranscript::new(b"riscv"), expect_halt)
        .is_err()
}

fn validate_tensor_bus_event_indices() {
    use ceno_emul::{
        SyscallSpec, TensorExportEndV1Spec, TensorImportBeginV1Spec,
        TensorProductionExportEndV2Spec, TensorProductionImportBeginV2Spec,
        tensor::production_attention::{CONTEXT_WORDS, HIDDEN_WORDS, ProductionStage, SEQUENCE},
    };
    use ceno_zkvm::{structs::CustomRWTag, tables::verify_tensor_bus_events};

    let event = |code| {
        let mut event = [0; 25];
        event[0] = CustomRWTag::TensorBusEvent as u32;
        event[1] = code;
        event
    };
    let finish_pair = |mut import: [u32; 25], mut export: [u32; 25]| {
        import[2] = ceno_emul::tensor::TENSOR_ABI_V2;
        export[2] = ceno_emul::tensor::TENSOR_ABI_V2;
        import[12] = 1;
        export[12] = 1;
        import[14] = 1;
        export[14] = 2;
        export[23] = 4;
        vec![import, export]
    };

    let mut legacy_import = event(TensorImportBeginV1Spec::CODE);
    legacy_import[2] = ceno_emul::tensor::TENSOR_ABI_V1;
    legacy_import[5] = ceno_emul::TENSOR_BUS_FIXED_TRANSFER_WORDS;
    legacy_import[10] = legacy_import[5] * 4;
    legacy_import[11] = legacy_import[5];
    legacy_import[12] = 1;
    legacy_import[14] = 1;
    let mut legacy_export = event(TensorExportEndV1Spec::CODE);
    legacy_export[2] = ceno_emul::tensor::TENSOR_ABI_V1;
    legacy_export[6] = ceno_emul::TENSOR_BUS_FIXED_TRANSFER_WORDS;
    legacy_export[10..14].copy_from_slice(&legacy_import[10..14]);
    legacy_export[14] = 2;
    legacy_export[23] = 4;
    let legacy = vec![legacy_import, legacy_export];
    verify_tensor_bus_events(&legacy).expect("V1 TensorBus event indices changed");
    let mut bad_legacy = legacy.clone();
    bad_legacy[0][5] += 1;
    assert!(verify_tensor_bus_events(&bad_legacy).is_err());

    for (import_stage, export_stage, head_start, head_count, import_words, export_words) in [
        (
            ProductionStage::Projection.as_raw(),
            ProductionStage::Attention.as_raw(),
            0,
            HEADS_PER_CIRCUIT as u32,
            HIDDEN_WORDS as u32,
            HEADS_PER_CIRCUIT as u32 * (SEQUENCE * 128) as u32,
        ),
        (
            ProductionStage::PostFfn.as_raw(),
            ProductionStage::PostFfn.as_raw(),
            0,
            32,
            2 * HIDDEN_WORDS as u32,
            CONTEXT_WORDS as u32,
        ),
    ] {
        let packed = head_start | (head_count << 16);
        let mut import = event(TensorProductionImportBeginV2Spec::CODE);
        import[3] = 7;
        import[8] = import_stage;
        import[9] = packed;
        import[10] = import_words * 4;
        import[11] = import_words;
        let mut export = event(TensorProductionExportEndV2Spec::CODE);
        export[3] = 7;
        export[6] = export_words;
        export[7] = export_stage;
        export[8] = packed;
        export[10] = export_words * 4;
        export[11] = export_words;
        let honest = finish_pair(import, export);
        verify_tensor_bus_events(&honest).expect("production TensorBus event indices changed");
        for (endpoint, word) in [(1, 3), (1, 7), (1, 8), (0, 10), (0, 11), (1, 6)] {
            let mut tampered = honest.clone();
            tampered[endpoint][word] ^= 1;
            assert!(
                verify_tensor_bus_events(&tampered).is_err(),
                "production TensorBus mutation endpoint={endpoint} word={word} was accepted"
            );
        }
    }
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
    validate_tensor_bus_event_indices();
    let program =
        ceno_emul::Program::load_elf(ceno_examples::tensor_bus_production_full_layer_v2, u32::MAX)
            .expect("load exact production-attention guest");
    // Hidden and Context are provider witnesses, so the guest has no activation heap.
    let platform = setup_platform(Preset::Ceno, &program, 1024 * 1024, 96 * 1024 * 1024);
    let max_cells_per_shard = std::env::var("CENO_MAX_CELLS_PER_SHARD")
        .map(|value| {
            value
                .parse::<u64>()
                .expect("CENO_MAX_CELLS_PER_SHARD must be a non-negative integer")
        })
        .unwrap_or(DEFAULT_MAX_CELLS_PER_SHARD);
    let shard_ram_device_budget_bytes = std::env::var("CENO_SHARD_RAM_DEVICE_BUDGET_BYTES")
        .ok()
        .map(|value| {
            value
                .parse::<u64>()
                .expect("CENO_SHARD_RAM_DEVICE_BUDGET_BYTES must be a positive integer")
        });
    let multi_prover = shard_ram_device_budget_bytes.map_or_else(
        || MultiProver::new(0, 1, max_cells_per_shard, u64::MAX),
        |bytes| {
            MultiProver::new(0, 1, max_cells_per_shard, u64::MAX)
                .with_shard_ram_device_budget_bytes(bytes)
        },
    );
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
    let prepared = Instant::now();

    if std::env::var_os("CENO_PREFLIGHT_ONLY").is_some_and(|value| value == "1") {
        assert!(
            max_cells_per_shard != u64::MAX,
            "planner gate requires an explicit CENO_MAX_CELLS_PER_SHARD"
        );
        let device_budget_bytes = shard_ram_device_budget_bytes
            .expect("planner gate requires CENO_SHARD_RAM_DEVICE_BUDGET_BYTES");
        let raw_step_cell_extractor = Arc::clone(&ctx.system_config.config);
        let step_cell_extractor: Arc<dyn ceno_emul::StepCellExtractor> = raw_step_cell_extractor;
        let emulation = emulate_program(
            Arc::clone(&ctx.program),
            MAX_STEPS,
            &init_mem,
            KECCAK_EMPTY_WORDS,
            &ctx.platform,
            &ctx.multi_prover,
            step_cell_extractor,
            ctx.tensor_proof_context.clone(),
            #[cfg(all(feature = "aot-x86_64", target_arch = "x86_64", target_os = "linux"))]
            ctx.preflight_aot_program.clone(),
            #[cfg(all(feature = "aot-x86_64", target_arch = "x86_64", target_os = "linux"))]
            ctx.fulltracer_aot_program.clone(),
        );
        assert!(
            emulation
                .predicted_shard_costs
                .iter()
                .all(|&cells| cells <= max_cells_per_shard),
            "planner emitted a shard above the explicit Core budget"
        );
        let segment_shards = emulation
            .admitted_tensor_segments
            .iter()
            .map(|segment| segment.shard_id)
            .collect::<Vec<_>>();
        assert_eq!(segment_shards.len(), ATTENTION_GROUPS + 1);
        assert!(
            segment_shards.windows(2).all(|pair| pair[0] <= pair[1]),
            "production segments are not packed in order"
        );
        assert_eq!(
            segment_shards
                .iter()
                .copied()
                .collect::<std::collections::BTreeSet<_>>(),
            (0..=segment_shards.last().copied().unwrap()).collect(),
            "planner emitted an empty production shard"
        );
        let predicted_shard_costs = emulation.predicted_shard_costs.clone();
        let replayed_shards = emulation.shard_cycle_boundaries.len() - 1;
        println!(
            "production PureAotPrepass passed: heads_per_circuit={HEADS_PER_CIRCUIT} groups={ATTENTION_GROUPS} planned_shards={replayed_shards} segment_shards={segment_shards:?} shard_cells={predicted_shard_costs:?} max_cells_per_shard={max_cells_per_shard} shard_ram_device_budget_bytes={device_budget_bytes}",
        );
        return;
    }

    let (max_num_variables, security_level) = default_backend_config();
    let backend = create_backend::<E, Pcs>(max_num_variables, security_level);
    let device = create_prover(backend);
    let (pk, vk) = ctx.keygen_with_pb(device.get_pb());
    let keyed = Instant::now();
    if let Some(path) = std::env::var_os("CENO_VERIFY_TARGET_PROOF_PATH") {
        let encoded = std::fs::read(&path)
            .expect("read persisted shard-0 production proof for diagnostic verification");
        let proof: ZKVMProof<E, Pcs> = bincode::deserialize(&encoded)
            .expect("deserialize persisted shard-0 production proof for diagnostic verification");
        let verifier = ZKVMVerifier::new(vk);
        run_e2e_single_shard_debug_verify(&verifier, proof, None, MAX_STEPS);
        println!(
            "production persisted shard-0 independent segment verification: path={} bytes={} result=Ok(true)",
            path.to_string_lossy(),
            encoded.len(),
        );
        return;
    }
    let prover = ZKVMProver::new(pk.into(), device);
    let init_mem = prover.setup_init_mem(&[]);
    let mock_proving = std::env::var_os("MOCK_PROVING").is_some_and(|value| value == "1");
    let target_shard_id = std::env::var("CENO_TARGET_SHARD_ID").ok().map(|value| {
        value
            .parse::<usize>()
            .expect("CENO_TARGET_SHARD_ID must be a non-negative integer")
    });
    assert!(
        target_shard_id.is_none_or(|shard_id| shard_id < ATTENTION_GROUPS + 1),
        "production target shard is outside the exact layer"
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
    if mock_proving {
        assert!(
            proofs.is_empty(),
            "mock-only diagnostic constructed a proof"
        );
        println!("production shard-0 exact GPU MLE MockProver diagnostic completed");
        return;
    }
    if let Some(target_shard_id) = target_shard_id {
        assert_eq!(
            proofs.len(),
            1,
            "target-shard selector produced multiple proofs"
        );
        assert_eq!(
            proofs[0].public_values.shard_id as usize, target_shard_id,
            "target-shard selector returned another shard"
        );
        let proof_bytes =
            bincode::serialized_size(&proofs[0]).expect("serialize target-shard production proof");
        let opening_bytes = bincode::serialized_size(&proofs[0].opening_proof)
            .expect("serialize target-shard production opening");
        let commitment_bytes = bincode::serialized_size(&proofs[0].witin_commit)
            .expect("serialize target-shard production commitment");
        if let Some(path) = std::env::var_os("CENO_TARGET_PROOF_PATH") {
            let encoded = bincode::serialize(&proofs[0])
                .expect("serialize target-shard production proof for diagnostic persistence");
            std::fs::write(&path, &encoded)
                .expect("persist target-shard production proof before verification");
            println!(
                "production target-shard proof persisted: shard={target_shard_id} path={} bytes={}",
                path.to_string_lossy(),
                encoded.len()
            );
        }
        println!(
            "production target-shard proof inventory: shard={target_shard_id}\n{}",
            proofs[0]
        );
        for (index, proof) in &proofs[0].chip_proofs {
            let name = vk
                .circuit_index_to_name
                .get(index)
                .unwrap_or_else(|| panic!("target-shard circuit index {index} missing from VK"));
            println!(
                "production target-shard chip metadata: shard={target_shard_id} index={index} name={name} instances={:?} main_out={} read_groups={} write_groups={} lookup_groups={} proof_bytes={}",
                proof.num_instances,
                proof.main_out_evals.len(),
                proof.r_out_evals.len(),
                proof.w_out_evals.len(),
                proof.lk_out_evals.len(),
                bincode::serialized_size(proof).expect("serialize shard-0 chip proof"),
            );
        }
        let fused_index = circuit_index(&vk, "TensorAttentionQkShiftSoftmax");
        let verifier = ZKVMVerifier::new(vk);
        run_e2e_single_shard_debug_verify(&verifier, proofs[0].clone(), None, MAX_STEPS);

        let mut product_tamper = proofs[0].clone();
        product_tamper
            .chip_proofs
            .get_mut(&fused_index)
            .expect("fused chip proof missing")
            .matrix_reduction
            .as_mut()
            .expect("fused matrix reduction missing")
            .sumcheck_proof[0]
            .evaluations[0] += E::ONE;
        assert!(
            rejects_single_shard(&verifier, product_tamper),
            "fused matrix-product tamper verified"
        );

        for (label, output_index) in [("quotient", 0), ("remainder", 1)] {
            let mut tampered = proofs[0].clone();
            tampered
                .chip_proofs
                .get_mut(&fused_index)
                .expect("fused chip proof missing")
                .matrix_reduction
                .as_mut()
                .expect("fused matrix reduction missing")
                .output_evals[output_index] += E::ONE;
            assert!(
                rejects_single_shard(&verifier, tampered),
                "fused {label} tamper verified"
            );
        }

        for (label, tamper_read) in [("read", true), ("write", false)] {
            let mut omitted = proofs[0].clone();
            let omitted_groups = if tamper_read {
                &mut omitted
                    .chip_proofs
                    .get_mut(&fused_index)
                    .expect("fused chip proof missing")
                    .r_out_evals
            } else {
                &mut omitted
                    .chip_proofs
                    .get_mut(&fused_index)
                    .expect("fused chip proof missing")
                    .w_out_evals
            };
            assert!(
                omitted_groups.pop().is_some(),
                "fused {label} group missing"
            );
            assert!(
                rejects_single_shard(&verifier, omitted),
                "fused {label}-record omission verified"
            );

            let mut tampered = proofs[0].clone();
            let output_groups = if tamper_read {
                &mut tampered
                    .chip_proofs
                    .get_mut(&fused_index)
                    .expect("fused chip proof missing")
                    .r_out_evals
            } else {
                &mut tampered
                    .chip_proofs
                    .get_mut(&fused_index)
                    .expect("fused chip proof missing")
                    .w_out_evals
            };
            *output_groups
                .first_mut()
                .expect("fused record output group missing")
                .first_mut()
                .expect("fused record output evaluation missing") += E::ONE;
            assert!(
                rejects_single_shard(&verifier, tampered),
                "fused {label}-record tamper verified"
            );
        }
        println!(
            "production target-shard independent segment verification: shard={target_shard_id} proof_bytes={proof_bytes} commitment_bytes={commitment_bytes} opening_bytes={opening_bytes} result=Ok(true) fused_product_tamper=reject fused_quotient_tamper=reject fused_remainder_tamper=reject fused_read_record_omission=reject fused_write_record_omission=reject fused_read_record_tamper=reject fused_write_record_tamper=reject"
        );
        return;
    }
    assert_eq!(
        proofs.len(),
        ATTENTION_GROUPS + 1,
        "production full layer did not produce exact shard count"
    );
    let mut names = vec![
        "TensorProductionImportBeginAnchor".to_string(),
        "TensorProductionStageAnchor".to_string(),
        "TensorProductionExportEndAnchor".to_string(),
        "TensorProductionBoundaryProjectionInputPart0".to_string(),
        "TensorProductionBoundaryPostFfnOutputPart0".to_string(),
    ];
    names.extend([
        "TensorAttentionQkShiftSoftmax".to_string(),
        "TensorAttentionPv".to_string(),
    ]);
    let expected_circuits = 7;
    assert_eq!(
        names.len(),
        expected_circuits,
        "production circuit inventory changed"
    );
    let boundary_index = circuit_index(&vk, "TensorProductionBoundaryProjectionInputPart0");
    let tensor_bus_index = circuit_index(&vk, "TensorBusCircuit");
    let import_anchor_index = circuit_index(&vk, "TensorProductionImportBeginAnchor");
    let export_anchor_index = circuit_index(&vk, "TensorProductionExportEndAnchor");
    let qk_index = circuit_index(&vk, "TensorAttentionQkShiftSoftmax");
    let softmax_index = qk_index;
    let pv_index = circuit_index(&vk, "TensorAttentionPv");
    names.sort_by_key(|name| circuit_index(&vk, name));
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
    assert!(
        indices.iter().all(|index| proofs
            .iter()
            .any(|proof| proof.chip_proofs.contains_key(index))),
        "production shards do not cover the complete compile-selected circuit inventory"
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
        ("tensor_bus_core_omission", tensor_bus_index),
        ("import_anchor_omission", import_anchor_index),
        ("export_anchor_omission", export_anchor_index),
        ("boundary_omission", boundary_index),
        ("qk_omission", qk_index),
        ("softmax_omission", softmax_index),
        ("pv_omission", pv_index),
    ] {
        let mut omitted = proofs.clone();
        let production_shard = omitted
            .iter()
            .position(|proof| proof.chip_proofs.contains_key(&index))
            .unwrap_or_else(|| panic!("{label} proof shard missing"));
        assert!(
            omitted[production_shard]
                .chip_proofs
                .remove(&index)
                .is_some(),
            "{label} proof missing"
        );
        assert!(rejects(&verifier, omitted), "{label} verified");
    }

    for (label, index, tamper_read) in [
        ("tensor_bus_core", tensor_bus_index, true),
        ("import_anchor", import_anchor_index, false),
        ("export_anchor", export_anchor_index, false),
        ("boundary", boundary_index, false),
        ("qk", qk_index, false),
        ("softmax_limb0", softmax_index, false),
        ("softmax_limb1", softmax_index, false),
        ("softmax_limb2", softmax_index, false),
        ("softmax_exp3", softmax_index, false),
        ("softmax_exp4", softmax_index, false),
        ("causal", softmax_index, false),
        ("pv_k128", pv_index, false),
    ] {
        let mut tampered = proofs.clone();
        let production_shard = tampered
            .iter()
            .position(|proof| proof.chip_proofs.contains_key(&index))
            .unwrap_or_else(|| panic!("{label} proof shard missing"));
        let proof = tampered[production_shard]
            .chip_proofs
            .get_mut(&index)
            .unwrap_or_else(|| panic!("{label} proof missing"));
        let output_evals = if tamper_read {
            &mut proof.r_out_evals
        } else {
            &mut proof.w_out_evals
        };
        let output_group = output_evals
            .first_mut()
            .unwrap_or_else(|| panic!("{label} tamper output group missing"));
        *output_group
            .first_mut()
            .unwrap_or_else(|| panic!("{label} tamper output evaluation missing")) += E::ONE;
        assert!(rejects(&verifier, tampered), "{label} tamper verified");
    }

    let proof_bytes = proofs
        .iter()
        .map(|proof| bincode::serialized_size(proof).expect("serialize production proof"))
        .sum::<u64>();
    let shards = proofs.len();
    println!(
        "production full-layer GPU E2E verified: batch=1 sequence=2048 hidden=4096 heads=32 heads_per_circuit={HEADS_PER_CIRCUIT} head_dim=128 profile=2 layer=0 shards={shards} production_shards={production_shards:?} max_cells_per_shard={max_cells_per_shard} circuits={expected_circuits} hidden_input_bytes={HIDDEN_BYTES} hidden_output_bytes={HIDDEN_BYTES} hidden_boundary_memory_rows=0 context_boundary_memory_rows=0 logical_h2d_bytes={HIDDEN_BYTES} logical_d2h_bytes={HIDDEN_BYTES} intermediate_h2d_bytes=0 intermediate_d2h_bytes=0 qk_multiplications={} pv_multiplications={} total_multiplications={TOTAL_MULTIPLICATIONS} pv_k_tile=128 pv_k_tiles=16 proof_bytes={proof_bytes} prepare_ms={} keygen_ms={} witness_and_base_prove_ms={} verify_ms={} total_ms={} tensor_bus_core_omission=reject import_anchor_omission=reject export_anchor_omission=reject boundary_omission=reject qk_omission=reject softmax_omission=reject pv_omission=reject tensor_bus_core_tamper=reject import_anchor_tamper=reject export_anchor_tamper=reject boundary_tamper=reject qk_tamper=reject five_softmax_lookups_tamper=reject causal_tamper=reject pv_k128_tamper=reject",
        TOTAL_MULTIPLICATIONS / 2,
        TOTAL_MULTIPLICATIONS / 2,
        prepared.duration_since(started).as_millis(),
        keyed.duration_since(prepared).as_millis(),
        proved.duration_since(keyed).as_millis(),
        verified.duration_since(proved).as_millis(),
        verified.duration_since(started).as_millis(),
    );
}
