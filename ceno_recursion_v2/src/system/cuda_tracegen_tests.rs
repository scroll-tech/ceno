use std::{
    path::{Path, PathBuf},
    sync::{Arc, Once},
};

use eyre::{Result, eyre};
use openvm_cuda_backend::{GpuBackend, data_transporter::transport_matrix_d2h_row_major};
use openvm_cuda_common::stream::GpuDeviceCtx;
use openvm_poseidon2_air::POSEIDON2_WIDTH;
use openvm_stark_backend::prover::{AirProvingContext, MatrixDimensions};
use openvm_stark_sdk::config::baby_bear_poseidon2::{
    BabyBearPoseidon2Config, DuplexSpongeRecorder, F, default_duplex_sponge_recorder,
};
use p3_matrix::Matrix;
use tracing_subscriber::EnvFilter;

use super::{AggregationSubCircuit, RecursionProof, RecursionVk, VerifierSubCircuit};
use crate::{
    circuit::inner::{InnerTraceGen, InnerTraceGenImpl, PreVerifierSubCircuitInput, ProofsType},
    system::{VerifierExternalData, VerifierTraceGen},
    utils::{TranscriptLabel, transcript_observe_label},
};

const MAX_NUM_PROOFS: usize = 2;

fn init_test_tracing() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
        let _ = tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_test_writer()
            .try_init();
    });
}

fn fixture_path(file_name: &str) -> Option<PathBuf> {
    std::env::var_os("CENO_RECURSION_V2_FIXTURE_DIR")
        .map(PathBuf::from)
        .into_iter()
        .chain([
            PathBuf::from("./src/imported"),
            PathBuf::from("./ceno_recursion_v2/src/imported"),
            PathBuf::from("."),
        ])
        .map(|dir| dir.join(file_name))
        .find(|path| path.exists())
}

fn load_proofs(path: &Path) -> Result<Option<Vec<RecursionProof>>> {
    let bytes = std::fs::read(path)?;
    if let Ok(proofs) = bincode::deserialize::<Vec<RecursionProof>>(&bytes) {
        return Ok(Some(proofs));
    }
    if let Ok(single) = bincode::deserialize::<RecursionProof>(&bytes) {
        return Ok(Some(vec![single]));
    }
    println!(
        "skipping CUDA tracegen comparison: incompatible proof fixture at {}",
        path.display()
    );
    Ok(None)
}

fn load_vk(path: &Path) -> Result<Option<RecursionVk>> {
    match bincode::deserialize::<RecursionVk>(&std::fs::read(path)?) {
        Ok(mut vk) => {
            vk.rebuild_circuit_index();
            Ok(Some(vk))
        }
        Err(err) => {
            println!(
                "skipping CUDA tracegen comparison: incompatible vk fixture at {}: {err}",
                path.display()
            );
            Ok(None)
        }
    }
}

fn load_fixtures() -> Result<Option<(Vec<RecursionProof>, RecursionVk)>> {
    let Some(proof_path) = fixture_path("proof.bin") else {
        println!("skipping CUDA tracegen comparison: missing proof.bin fixture");
        return Ok(None);
    };
    let Some(vk_path) = fixture_path("vk.bin") else {
        println!("skipping CUDA tracegen comparison: missing vk.bin fixture");
        return Ok(None);
    };
    let Some(proofs) = load_proofs(&proof_path)? else {
        return Ok(None);
    };
    let Some(vk) = load_vk(&vk_path)? else {
        return Ok(None);
    };
    Ok(Some((proofs, vk)))
}

fn select_proofs(proofs: &[RecursionProof], count: usize) -> Result<Vec<RecursionProof>> {
    if proofs.is_empty() {
        return Err(eyre!("proof fixture did not contain any proofs"));
    }
    Ok(proofs.iter().cycle().take(count).cloned().collect())
}

fn prepare_verifier_inputs(
    child_vk: &RecursionVk,
    proofs: &[RecursionProof],
) -> (Vec<[F; POSEIDON2_WIDTH]>, Vec<DuplexSpongeRecorder>) {
    let mut initial_transcript = default_duplex_sponge_recorder();
    transcript_observe_label(&mut initial_transcript, TranscriptLabel::Riscv.as_bytes());

    let tracegen = <InnerTraceGenImpl as InnerTraceGen<
        openvm_cpu_backend::CpuBackend<BabyBearPoseidon2Config>,
    >>::new(false);
    let (_, poseidon2_compress_inputs, initial_transcripts) =
        <InnerTraceGenImpl as InnerTraceGen<
            openvm_cpu_backend::CpuBackend<BabyBearPoseidon2Config>,
        >>::generate_pre_verifier_subcircuit_ctxs(&tracegen, PreVerifierSubCircuitInput {
            proofs,
            proofs_type: ProofsType::Vm,
            absent_trace_pvs: None,
            child_is_app: true,
            child_vk,
            child_dag_commit: Default::default(),
            initial_transcript,
        });
    (poseidon2_compress_inputs, initial_transcripts)
}

fn generate_cpu_ctxs(
    circuit: &VerifierSubCircuit<MAX_NUM_PROOFS>,
    child_vk: &RecursionVk,
    proofs: &[RecursionProof],
    required_heights: Option<&[usize]>,
) -> Vec<AirProvingContext<openvm_cpu_backend::CpuBackend<BabyBearPoseidon2Config>>> {
    let (poseidon2_compress_inputs, initial_transcripts) =
        prepare_verifier_inputs(child_vk, proofs);
    let poseidon2_permute_inputs: Vec<[F; POSEIDON2_WIDTH]> = vec![];
    let range_check_inputs = vec![];
    let power_check_inputs = vec![];
    let mut external_data = VerifierExternalData {
        poseidon2_compress_inputs: &poseidon2_compress_inputs,
        poseidon2_permute_inputs: &poseidon2_permute_inputs,
        range_check_inputs: &range_check_inputs,
        power_check_inputs: &power_check_inputs,
        required_heights,
        final_transcript_state: None,
    };
    <VerifierSubCircuit<MAX_NUM_PROOFS> as VerifierTraceGen<
        openvm_cpu_backend::CpuBackend<BabyBearPoseidon2Config>,
        BabyBearPoseidon2Config,
    >>::generate_proving_ctxs(
        circuit,
        child_vk,
        None,
        proofs,
        &mut external_data,
        initial_transcripts,
    )
    .expect("CPU tracegen should succeed")
}

fn generate_gpu_ctxs(
    circuit: &VerifierSubCircuit<MAX_NUM_PROOFS>,
    child_vk: &RecursionVk,
    proofs: &[RecursionProof],
    required_heights: Option<&[usize]>,
) -> Vec<AirProvingContext<GpuBackend>> {
    let (poseidon2_compress_inputs, initial_transcripts) =
        prepare_verifier_inputs(child_vk, proofs);
    let poseidon2_permute_inputs: Vec<[F; POSEIDON2_WIDTH]> = vec![];
    let range_check_inputs = vec![];
    let power_check_inputs = vec![];
    let mut external_data = VerifierExternalData {
        poseidon2_compress_inputs: &poseidon2_compress_inputs,
        poseidon2_permute_inputs: &poseidon2_permute_inputs,
        range_check_inputs: &range_check_inputs,
        power_check_inputs: &power_check_inputs,
        required_heights,
        final_transcript_state: None,
    };
    <VerifierSubCircuit<MAX_NUM_PROOFS> as VerifierTraceGen<
        GpuBackend,
        BabyBearPoseidon2Config,
    >>::generate_proving_ctxs(
        circuit,
        child_vk,
        None,
        proofs,
        &mut external_data,
        initial_transcripts,
    )
    .expect("GPU tracegen should succeed")
}

fn assert_ctxs_match(
    circuit: &VerifierSubCircuit<MAX_NUM_PROOFS>,
    cpu_ctxs: Vec<AirProvingContext<openvm_cpu_backend::CpuBackend<BabyBearPoseidon2Config>>>,
    gpu_ctxs: Vec<AirProvingContext<GpuBackend>>,
) {
    let device_ctx = GpuDeviceCtx::for_current_device().expect("failed to get CUDA device");
    let airs = circuit.airs::<BabyBearPoseidon2Config>();
    assert_eq!(cpu_ctxs.len(), airs.len(), "CPU ctx count must match AIRs");
    assert_eq!(gpu_ctxs.len(), airs.len(), "GPU ctx count must match AIRs");
    assert_eq!(cpu_ctxs.len(), gpu_ctxs.len(), "ctx count mismatch");

    for (air_idx, ((cpu, gpu), air)) in cpu_ctxs.into_iter().zip(gpu_ctxs).zip(airs).enumerate() {
        assert_eq!(
            cpu.cached_mains.len(),
            gpu.cached_mains.len(),
            "cached main count mismatch for AIR {air_idx} ({})",
            air.name()
        );
        assert_eq!(
            cpu.public_values,
            gpu.public_values,
            "public values mismatch for AIR {air_idx} ({})",
            air.name()
        );

        let cpu_trace = cpu.common_main;
        let gpu_trace = gpu.common_main;
        let cpu_height = Matrix::height(&cpu_trace);
        let cpu_width = Matrix::width(&cpu_trace);
        let gpu_height = MatrixDimensions::height(&gpu_trace);
        let gpu_width = MatrixDimensions::width(&gpu_trace);
        assert_eq!(
            cpu_width,
            gpu_width,
            "width mismatch for AIR {air_idx} ({})",
            air.name()
        );
        assert_eq!(
            cpu_height,
            gpu_height,
            "height mismatch for AIR {air_idx} ({})",
            air.name()
        );
        let gpu_trace = transport_matrix_d2h_row_major(&gpu_trace, &device_ctx)
            .expect("failed to copy GPU trace to host");
        for r in 0..cpu_height {
            for c in 0..cpu_width {
                assert_eq!(
                    cpu_trace.get(r, c),
                    gpu_trace.get(r, c),
                    "trace mismatch for AIR {air_idx} ({}) at row {r} column {c}",
                    air.name()
                );
            }
        }
    }
}

fn compare_tracegen(shard_count: usize, replay_required_heights: bool) -> Result<()> {
    init_test_tracing();
    let Some((loaded_proofs, child_vk)) = load_fixtures()? else {
        return Ok(());
    };
    let proofs = select_proofs(&loaded_proofs, shard_count)?;
    let circuit = VerifierSubCircuit::<MAX_NUM_PROOFS>::new(Arc::new(child_vk.clone()));

    let required_heights = if replay_required_heights {
        Some(
            generate_cpu_ctxs(&circuit, &child_vk, &proofs, None)
                .iter()
                .map(|ctx| Matrix::height(&ctx.common_main))
                .collect::<Vec<_>>(),
        )
    } else {
        None
    };
    let required_heights_ref = required_heights.as_deref();

    let cpu_ctxs = generate_cpu_ctxs(&circuit, &child_vk, &proofs, required_heights_ref);
    let gpu_ctxs = generate_gpu_ctxs(&circuit, &child_vk, &proofs, required_heights_ref);
    assert_ctxs_match(&circuit, cpu_ctxs, gpu_ctxs);
    Ok(())
}

#[test]
fn test_cuda_tracegen_compare_single_fixture_proof() -> Result<()> {
    compare_tracegen(1, false)
}

#[test]
fn test_cuda_tracegen_compare_multi_fixture_proofs() -> Result<()> {
    compare_tracegen(MAX_NUM_PROOFS, false)
}

#[test]
fn test_cuda_tracegen_required_heights_match_cpu() -> Result<()> {
    compare_tracegen(MAX_NUM_PROOFS, true)
}
