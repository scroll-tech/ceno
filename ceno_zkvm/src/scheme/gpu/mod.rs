use super::hal::{
    DeviceTransporter, MainSumcheckProver, OpeningProver, ProverDevice, TowerProver, TraceCommitter,
};
use crate::{
    error::ZKVMError,
    scheme::hal::{DeviceProvingKey, MainSumcheckEvals, ProofInput, TowerProverSpec},
    structs::{ComposedConstrainSystem, TowerProofs},
};
use ff_ext::{ExtensionField, GoldilocksExt2};
use gkr_iop::{
    gkr::GKRProof,
    gpu::{GpuBackend, GpuProver},
    hal::ProverBackend,
};
use itertools::Itertools;
use mpcs::{Point, PolynomialCommitmentScheme};
use multilinear_extensions::{
    mle::{ArcMultilinearExtension, MultilinearExtension},
    util::ceil_log2,
};
use std::{collections::BTreeMap, rc::Rc, sync::Arc};
use sumcheck::{
    macros::{entered_span, exit_span},
    structs::IOPProverMessage,
};
use transcript::{BasicTranscript, Transcript};
use witness::next_pow2_instance_padding;

use gkr_iop::cpu::{CpuBackend, CpuProver};

#[cfg(feature = "gpu")]
mod gpu_prover {
    use once_cell::sync::Lazy;
    use std::sync::{Arc, Mutex};

    use ceno_gpu::gl64::CudaHalGL64;
    pub use ceno_gpu::gl64::convert_ceno_to_gpu_basefold_commitment;
    use cudarc::driver::{CudaDevice, DriverError};

    pub static CUDA_DEVICE: Lazy<Result<Arc<CudaDevice>, DriverError>> =
        Lazy::new(|| CudaDevice::new(0));

    pub static CUDA_HAL: Lazy<
        Result<Arc<Mutex<CudaHalGL64>>, Box<dyn std::error::Error + Send + Sync>>,
    > = Lazy::new(|| {
        let device = CUDA_DEVICE
            .as_ref()
            .map_err(|e| format!("Device init failed: {:?}", e))?;
        device.bind_to_thread()?;

        CudaHalGL64::new()
            .map(|hal| Arc::new(Mutex::new(hal)))
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)
    });
}

#[cfg(feature = "gpu")]
pub use gpu_prover::*;

pub struct GpuTowerProver;

/// Temporary wrapper for GPU prover that reuses CPU prover functionality
/// during development phase. This struct will be refactored once GPU
/// implementation is complete and CPU dependencies are removed.
///
/// TODO: Remove this wrapper and consolidate into a single GPU prover
/// once all modules are fully migrated to GPU implementation.
pub struct TemporaryGpuProver<E: ExtensionField, PCS: PolynomialCommitmentScheme<E> + 'static> {
    pub gpu: GpuProver<GpuBackend<E, PCS>>,
    /// CPU prover used temporarily for modules not yet fully ported to GPU
    pub inner_cpu: CpuProver<CpuBackend<E, PCS>>,
}

impl<E: ExtensionField, PCS: PolynomialCommitmentScheme<E> + 'static> TemporaryGpuProver<E, PCS> {
    pub fn new(backend: Rc<GpuBackend<E, PCS>>) -> Self {
        let gpu = GpuProver::new(backend.clone());
        let cpu_backend = Rc::new(CpuBackend::<E, PCS>::new(
            backend.max_poly_size_log2,
            backend.security_level,
        ));
        let inner_cpu = CpuProver::new(cpu_backend);
        Self { gpu, inner_cpu }
    }

    // Extract out_evals from GPU-built tower witnesses
    // This is the true GPU optimization - directly using GPU tower results
    fn extract_out_evals_from_gpu_towers(
        &self,
        prod_gpu: &[ceno_gpu::GpuProverSpec], // GPU-built product towers
        logup_gpu: &[ceno_gpu::GpuProverSpec], // GPU-built logup towers
        r_set_len: usize,
    ) -> (Vec<Vec<E>>, Vec<Vec<E>>, Vec<Vec<E>>) {
        // Extract product out_evals from GPU towers
        let mut r_out_evals = Vec::new();
        let mut w_out_evals = Vec::new();
        for (i, gpu_spec) in prod_gpu.iter().enumerate() {
            let first_layer_evals: Vec<E> = gpu_spec
                .get_final_evals(0)
                .expect("Failed to extract final evals from GPU product tower");

            // Product tower first layer should have 2 MLEs
            assert_eq!(
                first_layer_evals.len(),
                2,
                "Product tower first layer should have 2 MLEs"
            );

            // Split into r_out_evals and w_out_evals based on r_set_len
            if i < r_set_len {
                r_out_evals.push(first_layer_evals);
            } else {
                w_out_evals.push(first_layer_evals);
            }
        }

        // Extract logup out_evals from GPU towers
        let mut lk_out_evals = Vec::new();
        for (_i, gpu_spec) in logup_gpu.iter().enumerate() {
            let first_layer_evals: Vec<E> = gpu_spec
                .get_final_evals(0)
                .expect("Failed to extract final evals from GPU logup tower");

            // Logup tower first layer should have 4 MLEs
            assert_eq!(
                first_layer_evals.len(),
                4,
                "Logup tower first layer should have 4 MLEs"
            );

            lk_out_evals.push(first_layer_evals);
        }

        (r_out_evals, w_out_evals, lk_out_evals)
    }
}

impl<E: ExtensionField, PCS: PolynomialCommitmentScheme<E>> TraceCommitter<GpuBackend<E, PCS>>
    for TemporaryGpuProver<E, PCS>
{
    fn commit_traces<'a>(
        &mut self,
        traces: BTreeMap<usize, witness::RowMajorMatrix<E::BaseField>>,
    ) -> (
        Vec<MultilinearExtension<'a, E>>,
        <GpuBackend<E, PCS> as ProverBackend>::PcsData, /* PCS::CommitmentWithWitness = BasefoldCommitmentWithWitnessGpu */
        PCS::Commitment,
    ) {
        if std::any::TypeId::of::<E::BaseField>()
            != std::any::TypeId::of::<p3::goldilocks::Goldilocks>()
        {
            panic!("GPU backend only supports Goldilocks base field");
        }

        let span = entered_span!("[gpu] init pp", profiling_2 = true);
        let max_poly_size_log2 = traces
            .values()
            .map(|trace| ceil_log2(next_pow2_instance_padding(trace.num_instances())))
            .max()
            .unwrap();
        if max_poly_size_log2 > self.gpu.backend.max_poly_size_log2 {
            panic!(
                "max_poly_size_log2 {} > max_poly_size_log2 backend {}",
                max_poly_size_log2, self.gpu.backend.max_poly_size_log2
            )
        }
        exit_span!(span);

        let is_pcs_match =
            std::mem::size_of::<mpcs::BasefoldCommitmentWithWitness<GoldilocksExt2>>()
                == std::mem::size_of::<PCS::CommitmentWithWitness>();
        let (mles, pcs_data, commit) = if is_pcs_match {
            let vec_traces: Vec<witness::RowMajorMatrix<E::BaseField>> =
                traces.into_values().collect();

            let span = entered_span!("[gpu] hal init", profiling_2 = true);
            // let cuda_hal = CUDA_HAL.lock().unwrap(); // CudaHalGL64::new().unwrap();
            let device = CUDA_DEVICE
                .as_ref()
                .map_err(|e| format!("Device not available: {:?}", e))
                .unwrap();
            device.bind_to_thread().unwrap();
            let hal_arc = CUDA_HAL
                .as_ref()
                .map_err(|e| format!("HAL not available: {:?}", e))
                .unwrap();
            let cuda_hal = hal_arc.lock().unwrap();
            exit_span!(span);

            let traces_gl64: Vec<witness::RowMajorMatrix<p3::goldilocks::Goldilocks>> =
                unsafe { std::mem::transmute(vec_traces) };

            let span = entered_span!("[gpu] batch_commit", profiling_2 = true);
            let pcs_data = cuda_hal.basefold.batch_commit(traces_gl64).unwrap();
            exit_span!(span);

            let span = entered_span!("[gpu] get_pure_commitment", profiling_2 = true);
            let basefold_commit = cuda_hal.basefold.get_pure_commitment(&pcs_data);
            exit_span!(span);

            let span = entered_span!("[gpu] get_mle_witness_from_commitment", profiling_2 = true);
            let basefold_mles = cuda_hal.basefold.get_mle_witness_from_commitment(&pcs_data);
            exit_span!(span);

            let span = entered_span!("[gpu] transmute back", profiling_2 = true);
            let commit: PCS::Commitment = unsafe { std::mem::transmute_copy(&basefold_commit) };
            std::mem::forget(basefold_commit);
            let mles: Vec<MultilinearExtension<'a, E>> =
                unsafe { std::mem::transmute_copy(&basefold_mles) };
            std::mem::forget(basefold_mles);
            // transmute pcs_data from GPU specific type to generic PcsData type
            let pcs_data_generic: <GpuBackend<E, PCS> as ProverBackend>::PcsData =
                unsafe { std::mem::transmute_copy(&pcs_data) };
            std::mem::forget(pcs_data);
            exit_span!(span);

            (mles, pcs_data_generic, commit)
        } else {
            panic!("GPU commitment data is not compatible with the PCS");
        };

        (mles, pcs_data, commit)
    }
}

fn build_tower_witness_gpu<'hal, 'buf, E: ExtensionField>(
    composed_cs: &ComposedConstrainSystem<E>,
    input: &ProofInput<'_, GpuBackend<E, impl PolynomialCommitmentScheme<E>>>,
    records: &[Arc<MultilinearExtension<'_, E>>],
    challenges: &[E; 2],
    cuda_hal: &'hal ceno_gpu::gl64::CudaHalGL64,
    prod_buffers: &'buf mut Vec<ceno_gpu::gl64::buffer::BufferImpl<ff_ext::GoldilocksExt2>>,
    logup_buffers: &'buf mut Vec<ceno_gpu::gl64::buffer::BufferImpl<ff_ext::GoldilocksExt2>>,
) -> Result<
    (
        Vec<ceno_gpu::GpuProverSpec<'buf>>,
        Vec<ceno_gpu::GpuProverSpec<'buf>>,
    ),
    String,
> {
    use ceno_gpu::gl64::GpuPolynomialExt;
    use crate::scheme::constants::{NUM_FANIN, NUM_FANIN_LOGUP};
    use ceno_gpu::CudaHal as _;
    use p3::field::FieldAlgebra;
    type EGL64 = ff_ext::GoldilocksExt2;

    let ComposedConstrainSystem {
        zkvm_v1_css: cs, ..
    } = composed_cs;
    let num_instances_with_rotation =
        input.num_instances << composed_cs.rotation_vars().unwrap_or(0);
    let chip_record_alpha = challenges[0];

    // Parse records into different categories (same as build_tower_witness)
    let num_reads = cs.r_expressions.len() + cs.r_table_expressions.len();
    let num_writes = cs.w_expressions.len() + cs.w_table_expressions.len();
    let mut offset = 0;
    let r_set_wit = &records[offset..][..num_reads];
    offset += num_reads;
    let w_set_wit = &records[offset..][..num_writes];
    offset += num_writes;
    let lk_n_wit = &records[offset..][..cs.lk_table_expressions.len()];
    offset += cs.lk_table_expressions.len();
    let lk_d_wit = if !cs.lk_table_expressions.is_empty() {
        &records[offset..][..cs.lk_table_expressions.len()]
    } else {
        &records[offset..][..cs.lk_expressions.len()]
    };

    // Use GPU version of masked_mle_split_to_chunks to avoid CPU-GPU data transfers
    let mut r_set_gpu_chunks = Vec::new();
    let mut w_set_gpu_chunks = Vec::new();

    // Process read set witnesses using GPU
    for wit in r_set_wit.iter() {
        let data = wit.get_ext_field_vec();
        let data_gl: &[EGL64] = unsafe { std::mem::transmute(data) };
        let gpu_chunks = cuda_hal
            .tower
            .masked_mle_split_to_chunks(data_gl, num_instances_with_rotation, NUM_FANIN, EGL64::ONE)
            .map_err(|e| format!("GPU masked_mle_split_to_chunks failed for r_set: {:?}", e))?;
        r_set_gpu_chunks.push(gpu_chunks);
    }

    // Process write set witnesses using GPU
    for wit in w_set_wit.iter() {
        let data = wit.get_ext_field_vec();
        let data_gl: &[EGL64] = unsafe { std::mem::transmute(data) };
        let gpu_chunks = cuda_hal
            .tower
            .masked_mle_split_to_chunks(data_gl, num_instances_with_rotation, NUM_FANIN, EGL64::ONE)
            .map_err(|e| format!("GPU masked_mle_split_to_chunks failed for w_set: {:?}", e))?;
        w_set_gpu_chunks.push(gpu_chunks);
    }

    // Process logup witnesses using GPU
    let mut lk_numerator_gpu_chunks = Vec::new();
    let mut lk_denominator_gpu_chunks = Vec::new();

    for wit in lk_n_wit.iter() {
        let data = wit.get_ext_field_vec();
        let data_gl: &[EGL64] = unsafe { std::mem::transmute(data) };
        let gpu_chunks = cuda_hal
            .tower
            .masked_mle_split_to_chunks(
                data_gl,
                num_instances_with_rotation,
                NUM_FANIN_LOGUP,
                EGL64::ONE,
            )
            .map_err(|e| format!("GPU masked_mle_split_to_chunks failed for lk_n: {:?}", e))?;
        lk_numerator_gpu_chunks.push(gpu_chunks);
    }

    for wit in lk_d_wit.iter() {
        let data = wit.get_ext_field_vec();
        let data_gl: &[EGL64] = unsafe { std::mem::transmute(data) };
        // For GPU backend, E must be GoldilocksExt2. This is ensured by the caller.
        let chip_record_alpha_gl: EGL64 = unsafe {
            assert_eq!(std::mem::size_of::<E>(), std::mem::size_of::<EGL64>());
            std::mem::transmute_copy(&chip_record_alpha)
        };
        let gpu_chunks = cuda_hal
            .tower
            .masked_mle_split_to_chunks(
                data_gl,
                num_instances_with_rotation,
                NUM_FANIN_LOGUP,
                chip_record_alpha_gl,
            )
            .map_err(|e| format!("GPU masked_mle_split_to_chunks failed for lk_d: {:?}", e))?;
        lk_denominator_gpu_chunks.push(gpu_chunks);
    }

    // First, allocate buffers based on original witness num_vars
    // This avoids the need to call build_tower_witness just to get buffer sizes
    for wit in r_set_wit.iter().chain(w_set_wit.iter()) {
        let nv = wit.num_vars();
        let buf = cuda_hal
            .alloc_ext_elems_on_device(1 << (nv + 2))
            .map_err(|e| format!("Failed to allocate prod GPU buffer: {:?}", e))?;
        prod_buffers.push(buf);
    }
    // Allocate logup buffers based on original witness num_vars
    for wit in lk_n_wit.iter().chain(lk_d_wit.iter()) {
        let nv = wit.num_vars();
        let buf = cuda_hal
            .alloc_ext_elems_on_device(1 << (nv + 3))
            .map_err(|e| format!("Failed to allocate logup GPU buffer: {:?}", e))?;
        logup_buffers.push(buf);
    }

    // Build product GpuProverSpecs using GPU polynomials directly
    let mut prod_gpu_specs = Vec::new();
    let mut remaining_prod_buffers = &mut prod_buffers[..];

    // Process all product chunks (r_set and w_set) uniformly
    for gpu_chunks in r_set_gpu_chunks.into_iter().chain(w_set_gpu_chunks) {
        assert_eq!(gpu_chunks.len(), 2, "prod_spec must have 2 MLEs");
        let nv = gpu_chunks[0].num_vars();

        let (current_buffer_slice, rest) = remaining_prod_buffers.split_at_mut(1);
        remaining_prod_buffers = rest;

        let gpu_spec = cuda_hal
            .tower
            .build_prod_tower_from_gpu_polys(nv, &gpu_chunks, &mut current_buffer_slice[0])
            .map_err(|e| format!("build_prod_tower_from_gpu_polys failed: {:?}", e))?;

        prod_gpu_specs.push(gpu_spec);
    }

    // Build logup GpuProverSpecs using GPU polynomials directly
    let mut logup_gpu_specs = Vec::new();
    let mut remaining_logup_buffers = &mut logup_buffers[..];

    // Prepare last_layer for all logup cases
    let logup_last_layers = if !lk_numerator_gpu_chunks.is_empty() {
        // Case when we have both numerator and denominator
        // Combine [p1, p2] from numerator and [q1, q2] from denominator
        lk_numerator_gpu_chunks
            .into_iter()
            .zip(lk_denominator_gpu_chunks)
            .map(|(lk_n_chunks, lk_d_chunks)| {
                let mut last_layer = lk_n_chunks;
                last_layer.extend(lk_d_chunks);
                last_layer
            })
            .collect::<Vec<_>>()
    } else {
        // Case when numerator is empty - create GPU polynomials with scalar E::ONE
        lk_denominator_gpu_chunks
            .into_iter()
            .map(|lk_d_chunks| {
                let nv = lk_d_chunks[0].num_vars();
                let p1_gpu = GpuPolynomialExt::new_with_scalar(&cuda_hal.inner, nv, EGL64::ONE)
                    .map_err(|e| format!("Failed to create p1 GPU polynomial with scalar: {:?}", e))
                    .unwrap();
                let p2_gpu = GpuPolynomialExt::new_with_scalar(&cuda_hal.inner, nv, EGL64::ONE)
                    .map_err(|e| format!("Failed to create p2 GPU polynomial with scalar: {:?}", e))
                    .unwrap();
                // Use [1, 1, q1, q2] format for the last layer
                let mut last_layer = vec![p1_gpu, p2_gpu];
                last_layer.extend(lk_d_chunks);
                last_layer
            })
            .collect::<Vec<_>>()
    };

    // Process all logup last_layers uniformly
    for last_layer in logup_last_layers {
        assert_eq!(last_layer.len(), 4, "logup last_layer must have 4 MLEs");
        let nv = last_layer[0].num_vars();

        let (current_buffer_slice, rest) = remaining_logup_buffers.split_at_mut(1);
        remaining_logup_buffers = rest;

        let gpu_spec = cuda_hal
            .tower
            .build_logup_tower_from_gpu_polys(nv, &last_layer, &mut current_buffer_slice[0])
            .map_err(|e| format!("build_logup_tower_from_gpu_polys failed: {:?}", e))?;

        logup_gpu_specs.push(gpu_spec);
    }

    Ok((prod_gpu_specs, logup_gpu_specs))
}

impl<E: ExtensionField, PCS: PolynomialCommitmentScheme<E>> TowerProver<GpuBackend<E, PCS>>
    for TemporaryGpuProver<E, PCS>
{
    #[allow(clippy::type_complexity)]
    #[tracing::instrument(
        skip_all,
        name = "build_tower_witness",
        fields(profiling_3),
        level = "trace"
    )]
    fn build_tower_witness<'a, 'b, 'c>(
        &self,
        _composed_cs: &ComposedConstrainSystem<E>,
        _input: &ProofInput<'a, GpuBackend<E, PCS>>,
        _records: &'c [ArcMultilinearExtension<'b, E>],
        _is_padded: bool,
        _challenges: &[E; 2],
    ) -> (
        Vec<Vec<Vec<E>>>,
        Vec<TowerProverSpec<'c, GpuBackend<E, PCS>>>,
        Vec<TowerProverSpec<'c, GpuBackend<E, PCS>>>,
    )
    where
        'a: 'b,
        'b: 'c,
    {
        panic!("use fn build_tower_witness_gpu instead");
        // (vec![], vec![], vec![])
    }

    #[tracing::instrument(
        skip_all,
        name = "prove_tower_relation",
        fields(profiling_3),
        level = "trace"
    )]
    fn prove_tower_relation<'a, 'b, 'c>(
        &self,
        composed_cs: &ComposedConstrainSystem<E>,
        input: &ProofInput<'a, GpuBackend<E, PCS>>,
        records: &'c [Arc<MultilinearExtension<'b, E>>],
        _is_padded: bool,
        challenges: &[E; 2],
        transcript: &mut impl Transcript<E>,
    ) -> (
        Point<E>,
        TowerProofs<E>,
        Vec<Vec<E>>,
        Vec<Vec<E>>,
        Vec<Vec<E>>,
    )
    where
        'a: 'b,
        'b: 'c,
    {
        if std::any::TypeId::of::<E::BaseField>()
            != std::any::TypeId::of::<p3::goldilocks::Goldilocks>()
        {
            panic!("GPU backend only supports Goldilocks base field");
        }

        // Calculate r_set_len directly from constraint system
        let ComposedConstrainSystem {
            zkvm_v1_css: cs, ..
        } = composed_cs;
        let r_set_len = cs.r_expressions.len() + cs.r_table_expressions.len();

        // cuda hal for transcript conversion
        let device = CUDA_DEVICE
            .as_ref()
            .map_err(|e| format!("Device not available: {:?}", e))
            .unwrap();
        device.bind_to_thread().unwrap();
        let hal_arc = CUDA_HAL
            .as_ref()
            .map_err(|e| format!("HAL not available: {:?}", e))
            .unwrap();
        let cuda_hal = hal_arc.lock().unwrap();

        // GPU optimization: Use build_tower_witness_gpu which handles buffer allocation internally
        type EGL64 = ff_ext::GoldilocksExt2;
        let mut _prod_buffers: Vec<ceno_gpu::gl64::buffer::BufferImpl<EGL64>> = Vec::new();
        let mut _logup_buffers: Vec<ceno_gpu::gl64::buffer::BufferImpl<EGL64>> = Vec::new();

        // Call build_tower_witness_gpu which will allocate buffers and build GPU specs
        let (prod_gpu, logup_gpu) = build_tower_witness_gpu(
            composed_cs,
            input,
            records,
            challenges,
            &*cuda_hal,
            &mut _prod_buffers,
            &mut _logup_buffers,
        )
        .map_err(|e| format!("build_tower_witness_gpu failed: {}", e))
        .unwrap();

        // GPU optimization: Extract out_evals from GPU-built towers before consuming them
        // This is the true optimization - using GPU tower results instead of CPU inference
        let (r_out_evals, w_out_evals, lk_out_evals) =
            self.extract_out_evals_from_gpu_towers(&prod_gpu, &logup_gpu, r_set_len);

        // transcript >>> BasicTranscript<GL64^2>
        let basic_tr: &mut BasicTranscript<GoldilocksExt2> =
            unsafe { &mut *(transcript as *mut _ as *mut BasicTranscript<GoldilocksExt2>) };

        let input = ceno_gpu::TowerInput {
            prod_specs: prod_gpu,
            logup_specs: logup_gpu,
        };

        let (point_gl, proof_gpu) = cuda_hal
            .tower
            .create_proof(&input, basic_tr)
            .expect("gpu tower create_proof failed");

        // TowerProofs
        let point: Point<E> = unsafe { std::mem::transmute(point_gl) };
        let proof: TowerProofs<E> = unsafe { std::mem::transmute(proof_gpu) };

        (point, proof, lk_out_evals, w_out_evals, r_out_evals)
    }
}

impl<E: ExtensionField, PCS: PolynomialCommitmentScheme<E>> MainSumcheckProver<GpuBackend<E, PCS>>
    for TemporaryGpuProver<E, PCS>
{
    #[allow(clippy::type_complexity)]
    #[tracing::instrument(
        skip_all,
        name = "build_main_witness",
        fields(profiling_3),
        level = "trace"
    )]
    fn build_main_witness<'a, 'b>(
        &self,
        composed_cs: &ComposedConstrainSystem<E>,
        input: &ProofInput<'a, GpuBackend<E, PCS>>,
        challenges: &[E; 2],
    ) -> (Vec<ArcMultilinearExtension<'b, E>>, bool)
    where
        'a: 'b,
    {
        let cpu_input: &ProofInput<'a, CpuBackend<E, PCS>> = unsafe {
            &*(input as *const ProofInput<'a, GpuBackend<E, PCS>>
                as *const ProofInput<'a, CpuBackend<E, PCS>>)
        };
        self.inner_cpu
            .build_main_witness(composed_cs, cpu_input, challenges)
    }

    #[allow(clippy::type_complexity)]
    #[tracing::instrument(
        skip_all,
        name = "prove_main_constraints",
        fields(profiling_3),
        level = "trace"
    )]
    fn prove_main_constraints<'a, 'b>(
        &self,
        rt_tower: Vec<E>,
        _records: Vec<ArcMultilinearExtension<'b, E>>, // not used by GPU after delegation
        input: &'b ProofInput<'a, GpuBackend<E, PCS>>,
        composed_cs: &ComposedConstrainSystem<E>,
        challenges: &[E; 2],
        transcript: &mut impl Transcript<<GpuBackend<E, PCS> as ProverBackend>::E>,
    ) -> Result<
        (
            Point<E>,
            MainSumcheckEvals<E>,
            Option<Vec<IOPProverMessage<E>>>,
            Option<GKRProof<E>>,
        ),
        ZKVMError,
    > {
        let cpu_input: &ProofInput<'a, CpuBackend<E, PCS>> = unsafe {
            &*(input as *const ProofInput<'a, GpuBackend<E, PCS>>
                as *const ProofInput<'a, CpuBackend<E, PCS>>)
        };
        self.inner_cpu.prove_main_constraints(
            rt_tower,
            vec![],
            cpu_input,
            composed_cs,
            challenges,
            transcript,
        )
    }
}

use p3::field::extension::BinomialExtensionField;
type GL64 = p3::goldilocks::Goldilocks;
type EGL64 = BinomialExtensionField<GL64, 2>;

impl<E: ExtensionField, PCS: PolynomialCommitmentScheme<E>> OpeningProver<GpuBackend<E, PCS>>
    for TemporaryGpuProver<E, PCS>
{
    fn open(
        &self,
        witness_data: <GpuBackend<E, PCS> as ProverBackend>::PcsData,
        fixed_data: Option<Arc<<GpuBackend<E, PCS> as ProverBackend>::PcsData>>,
        points: Vec<Point<E>>,
        mut evals: Vec<Vec<E>>, // where each inner Vec<E> = wit_evals + fixed_evals
        circuit_num_polys: &[(usize, usize)],
        num_instances: &[(usize, usize)],
        transcript: &mut (impl Transcript<E> + 'static),
    ) -> PCS::Proof {
        if std::any::TypeId::of::<E::BaseField>()
            != std::any::TypeId::of::<p3::goldilocks::Goldilocks>()
        {
            panic!("GPU backend only supports Goldilocks base field");
        }

        // use p3::field::extension::BinomialExtensionField;
        // type GL64 = p3::goldilocks::Goldilocks;
        // type EGL64 = BinomialExtensionField<GL64, 2>;
        // let cuda_hal = CUDA_HAL.lock().unwrap(); //CudaHalGL64::new().unwrap();
        let device = CUDA_DEVICE
            .as_ref()
            .map_err(|e| format!("Device not available: {:?}", e))
            .unwrap();
        device.bind_to_thread().unwrap();
        let hal_arc = CUDA_HAL
            .as_ref()
            .map_err(|e| format!("HAL not available: {:?}", e))
            .unwrap();
        let cuda_hal = hal_arc.lock().unwrap();

        let mut rounds = vec![];
        rounds.push((
            &witness_data,
            points
                .iter()
                .zip_eq(evals.iter_mut())
                .zip_eq(num_instances.iter())
                .map(|((point, evals), (chip_idx, _))| {
                    let (num_witin, _) = circuit_num_polys[*chip_idx];
                    (point.clone(), evals.drain(..num_witin).collect_vec())
                })
                .collect_vec(),
        ));
        if let Some(fixed_data) = fixed_data.as_ref().map(|f| f.as_ref()) {
            rounds.push((
                fixed_data,
                points
                    .iter()
                    .zip_eq(evals.iter_mut())
                    .zip_eq(num_instances.iter())
                    .filter(|(_, (chip_idx, _))| {
                        let (_, num_fixed) = circuit_num_polys[*chip_idx];
                        num_fixed > 0
                    })
                    .map(|((point, evals), _)| (point.clone(), evals.to_vec()))
                    .collect_vec(),
            ));
        }

        use ceno_gpu::{
            BasefoldCommitmentWithWitness as BasefoldCommitmentWithWitnessGpu,
            gl64::buffer::BufferImpl,
        };

        // Type conversions using unsafe transmute
        let prover_param = &self.gpu.backend.pp;
        let pp_gl64: &mpcs::basefold::structure::BasefoldProverParams<
            EGL64,
            mpcs::BasefoldRSParams,
        > = unsafe { std::mem::transmute(prover_param) };
        let rounds_gl64: Vec<_> = rounds
            .iter()
            .map(|(commitment, point_eval_pairs)| {
                let commitment_gl64: &BasefoldCommitmentWithWitnessGpu<GL64, BufferImpl<GL64>> =
                    unsafe { std::mem::transmute(*commitment) };
                let point_eval_pairs_gl64: Vec<_> = point_eval_pairs
                    .iter()
                    .map(|(point, evals)| {
                        let point_gl64: &Vec<EGL64> = unsafe { std::mem::transmute(point) };
                        let evals_gl64: &Vec<EGL64> = unsafe { std::mem::transmute(evals) };
                        (point_gl64.clone(), evals_gl64.clone())
                    })
                    .collect();
                (commitment_gl64, point_eval_pairs_gl64)
            })
            .collect();

        let gpu_proof = if std::any::TypeId::of::<E>() == std::any::TypeId::of::<GoldilocksExt2>() {
            let transcript_any = transcript as &mut dyn std::any::Any;
            let basic_transcript = transcript_any
                .downcast_mut::<BasicTranscript<GoldilocksExt2>>()
                .expect("Type should match");

            let gpu_proof_basefold = cuda_hal
                .basefold
                .batch_open(&cuda_hal, pp_gl64, rounds_gl64, basic_transcript)
                .unwrap();

            let gpu_proof: PCS::Proof = unsafe { std::mem::transmute_copy(&gpu_proof_basefold) };
            std::mem::forget(gpu_proof_basefold);
            println!("construct cpu commitment from gpu data");
            gpu_proof
        } else {
            panic!("GPU backend only supports Goldilocks base field");
        };
        gpu_proof

        // PCS::batch_open(
        //     self.pp.as_ref().unwrap(),
        //     rounds,
        //     transcript
        // )
        // .unwrap()
    }
}

impl<E: ExtensionField, PCS: PolynomialCommitmentScheme<E>> DeviceTransporter<GpuBackend<E, PCS>>
    for TemporaryGpuProver<E, PCS>
{
    fn transport_proving_key(
        &self,
        pk: Arc<
            crate::structs::ZKVMProvingKey<
                <GpuBackend<E, PCS> as ProverBackend>::E,
                <GpuBackend<E, PCS> as ProverBackend>::Pcs,
            >,
        >,
    ) -> DeviceProvingKey<GpuBackend<E, PCS>> {
        let pcs_data_original = pk.fixed_commit_wd.clone().unwrap();

        // assert pcs match
        let is_pcs_match =
            std::mem::size_of::<mpcs::BasefoldCommitmentWithWitness<GoldilocksExt2>>()
                == std::mem::size_of::<PCS::CommitmentWithWitness>();
        assert!(is_pcs_match, "pcs mismatch");

        // 1. transmute from PCS::CommitmentWithWitness to BasefoldCommitmentWithWitness<E>
        let basefold_commitment: &mpcs::BasefoldCommitmentWithWitness<GoldilocksExt2> =
            unsafe { std::mem::transmute_copy(&pcs_data_original.as_ref()) };
        // 2. convert from BasefoldCommitmentWithWitness<E> to BasefoldCommitmentWithWitness<GL64>
        let hal_arc = CUDA_HAL
            .as_ref()
            .map_err(|e| format!("HAL not available: {:?}", e))
            .unwrap();
        let cuda_hal = hal_arc.lock().unwrap();
        let pcs_data_basefold =
            convert_ceno_to_gpu_basefold_commitment(&cuda_hal, basefold_commitment);
        let pcs_data: <GpuBackend<E, PCS> as ProverBackend>::PcsData =
            unsafe { std::mem::transmute_copy(&pcs_data_basefold) };
        std::mem::forget(pcs_data_basefold);
        let pcs_data = Arc::new(pcs_data);

        let fixed_mles =
            PCS::get_arc_mle_witness_from_commitment(pk.fixed_commit_wd.as_ref().unwrap());

        DeviceProvingKey {
            pcs_data,
            fixed_mles,
        }
    }

    fn transport_mles<'a>(
        &self,
        mles: Vec<MultilinearExtension<'a, E>>,
    ) -> Vec<ArcMultilinearExtension<'a, E>> {
        mles.into_iter().map(|mle| mle.into()).collect_vec()
    }
}

impl<E, PCS> ProverDevice<GpuBackend<E, PCS>> for TemporaryGpuProver<E, PCS>
where
    E: ExtensionField,
    PCS: PolynomialCommitmentScheme<E> + 'static,
{
    fn get_pb(&self) -> &GpuBackend<E, PCS> {
        self.gpu.backend.as_ref()
    }
}
