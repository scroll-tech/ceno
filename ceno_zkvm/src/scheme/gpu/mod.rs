use super::hal::{
    DeviceTransporter, EccQuarkProver, MainSumcheckProver, OpeningProver, ProverDevice,
    TowerProver, TraceCommitter,
};
use crate::{
    error::ZKVMError,
    scheme::{
        cpu::TowerRelationOutput,
        hal::{DeviceProvingKey, MainSumcheckEvals, ProofInput, TowerProverSpec},
    },
    structs::{ComposedConstrainSystem, PointAndEval, TowerProofs},
};
use ceno_gpu::bb31::{CudaHalBB31, GpuPolynomial};
use either::Either;
use ff_ext::ExtensionField;
use gkr_iop::{
    gkr::{
        self, Evaluation, GKRProof, GKRProverOutput,
        layer::{LayerWitness, gpu::utils::extract_mle_relationships_from_monomial_terms},
    },
    gpu::{GpuBackend, GpuProver, gpu_prover::BB31Ext},
    hal::ProverBackend,
};
use itertools::{Itertools, chain};
use mpcs::{Point, PolynomialCommitmentScheme};
use multilinear_extensions::{
    Expression, ToExpr,
    mle::{FieldType, IntoMLE, MultilinearExtension},
    util::ceil_log2,
    virtual_poly::{build_eq_x_r_vec, eq_eval},
};
use rayon::iter::{
    IndexedParallelIterator, IntoParallelIterator, IntoParallelRefIterator,
    IntoParallelRefMutIterator, ParallelIterator,
};
use std::{
    collections::BTreeMap,
    iter::{once, repeat_n},
    sync::Arc,
};
use sumcheck::{
    macros::{entered_span, exit_span},
    structs::{IOPProof, IOPProverMessage},
    util::optimal_sumcheck_threads,
};
use transcript::{BasicTranscript, Transcript};
use witness::next_pow2_instance_padding;

use tracing::info_span;

#[cfg(feature = "gpu")]
use gkr_iop::gpu::gpu_prover::*;

mod util;
use util::{
    WitnessRegistry, batch_mles_take_half, expect_basic_transcript, hal_to_backend_error,
    mle_filter_even_odd_batch, mle_host_to_gpu, read_septic_value_from_gpu, symbolic_from_mle,
};
pub struct GpuTowerProver;

use crate::{
    scheme::{
        constants::{NUM_FANIN, SEPTIC_EXTENSION_DEGREE},
        septic_curve::SepticPoint,
    },
    structs::EccQuarkProof,
};
use gkr_iop::{
    gpu::{ArcMultilinearExtensionGpu, BB31Base, MultilinearExtensionGpu},
    selector::{SelectorContext, SelectorType},
};

// Extract out_evals from GPU-built tower witnesses
#[allow(clippy::type_complexity)]
fn extract_out_evals_from_gpu_towers<E: ff_ext::ExtensionField>(
    prod_gpu: &[ceno_gpu::GpuProverSpec], // GPU-built product towers
    logup_gpu: &[ceno_gpu::GpuProverSpec], // GPU-built logup towers
    r_set_len: usize,
) -> (Vec<Vec<E>>, Vec<Vec<E>>, Vec<Vec<E>>) {
    // Extract product out_evals from GPU towers
    let mut r_out_evals = Vec::new();
    let mut w_out_evals = Vec::new();
    for (i, gpu_spec) in prod_gpu.iter().enumerate() {
        let first_layer_evals: Vec<E> = gpu_spec
            .get_output_evals()
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
    for gpu_spec in logup_gpu.iter() {
        let first_layer_evals: Vec<E> = gpu_spec
            .get_output_evals()
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

impl<E: ExtensionField, PCS: PolynomialCommitmentScheme<E>> TraceCommitter<GpuBackend<E, PCS>>
    for GpuProver<GpuBackend<E, PCS>>
{
    fn commit_traces<'a>(
        &self,
        traces: BTreeMap<usize, witness::RowMajorMatrix<E::BaseField>>,
    ) -> (
        Vec<MultilinearExtensionGpu<'a, E>>,
        <GpuBackend<E, PCS> as ProverBackend>::PcsData,
        PCS::Commitment,
    ) {
        if std::any::TypeId::of::<E::BaseField>() != std::any::TypeId::of::<BB31Base>() {
            panic!("GPU backend only supports BabyBear base field");
        }

        let span = entered_span!("[gpu] init pp", profiling_2 = true);
        let max_poly_size_log2 = traces
            .values()
            .map(|trace| ceil_log2(next_pow2_instance_padding(trace.num_instances())))
            .max()
            .unwrap();
        if max_poly_size_log2 > self.backend.max_poly_size_log2 {
            panic!(
                "max_poly_size_log2 {} > max_poly_size_log2 backend {}",
                max_poly_size_log2, self.backend.max_poly_size_log2
            )
        }
        exit_span!(span);

        let is_pcs_match = std::mem::size_of::<mpcs::BasefoldCommitmentWithWitness<BB31Ext>>()
            == std::mem::size_of::<PCS::CommitmentWithWitness>();
        let (mles, pcs_data, commit) = if is_pcs_match {
            let vec_traces: Vec<witness::RowMajorMatrix<E::BaseField>> =
                traces.into_values().collect();

            let span = entered_span!("[gpu] hal init", profiling_2 = true);
            let cuda_hal = get_cuda_hal().unwrap();
            exit_span!(span);

            let traces_gl64: Vec<witness::RowMajorMatrix<BB31Base>> =
                unsafe { std::mem::transmute(vec_traces) };

            let span = entered_span!("[gpu] batch_commit", profiling_2 = true);
            let pcs_data = cuda_hal
                .basefold
                .batch_commit(&cuda_hal, traces_gl64)
                .unwrap();
            exit_span!(span);

            let span = entered_span!("[gpu] get_pure_commitment", profiling_2 = true);
            let basefold_commit = cuda_hal.basefold.get_pure_commitment(&pcs_data);
            exit_span!(span);

            let span = entered_span!("[gpu] transmute back", profiling_2 = true);
            let commit: PCS::Commitment = unsafe { std::mem::transmute_copy(&basefold_commit) };
            // transmute pcs_data from GPU specific type to generic PcsData type
            let pcs_data_generic: <GpuBackend<E, PCS> as ProverBackend>::PcsData =
                unsafe { std::mem::transmute_copy(&pcs_data) };
            std::mem::forget(pcs_data);
            exit_span!(span);

            (vec![], pcs_data_generic, commit)
        } else {
            panic!("GPU commitment data is not compatible with the PCS");
        };

        // Note: mles are not used by GPU backend
        // `fn extract_witness_mles` uses `hal.basefold.get_trace` to extract mles from pcs_data
        (mles, pcs_data, commit)
    }

    fn extract_witness_mles<'a, 'b>(
        &self,
        _witness_mles: &'b mut Vec<<GpuBackend<E, PCS> as ProverBackend>::MultilinearPoly<'a>>,
        pcs_data: &'b <GpuBackend<E, PCS> as ProverBackend>::PcsData,
    ) -> Box<
        dyn Iterator<Item = Arc<<GpuBackend<E, PCS> as ProverBackend>::MultilinearPoly<'a>>> + 'b,
    > {
        // transmute pcs_data from generic PcsData type to GPU-specific type
        let pcs_data_basefold: &BasefoldCommitmentWithWitnessGpu<
            BB31Base,
            BufferImpl<BB31Base>,
            GpuDigestLayer,
            GpuMatrix<'static>,
            GpuPolynomial<'static>,
        > = unsafe { std::mem::transmute(pcs_data) };

        let total_traces = pcs_data_basefold.num_traces();
        let mut trace_idx = 0usize;
        let mut current_iter: std::vec::IntoIter<
            Arc<<GpuBackend<E, PCS> as ProverBackend>::MultilinearPoly<'a>>,
        > = Vec::new().into_iter();

        let iter = std::iter::from_fn(move || {
            loop {
                if let Some(poly) = current_iter.next() {
                    return Some(poly);
                }

                if trace_idx >= total_traces {
                    return None;
                }

                let cuda_hal = get_cuda_hal().unwrap();
                let poly_group = cuda_hal
                    .basefold
                    .get_trace(&cuda_hal, pcs_data_basefold, trace_idx)
                    .unwrap_or_else(|err| panic!("Failed to extract trace {trace_idx}: {err}"));
                trace_idx += 1;
                drop(cuda_hal);

                current_iter = poly_group
                    .into_iter()
                    .map(|poly| Arc::new(MultilinearExtensionGpu::from_ceno_gpu(poly)))
                    .collect::<Vec<_>>()
                    .into_iter();
            }
        });

        Box::new(iter)
    }
}

#[allow(clippy::too_many_arguments)]
fn build_tower_witness_gpu<'buf, E: ExtensionField>(
    composed_cs: &ComposedConstrainSystem<E>,
    input: &ProofInput<'_, GpuBackend<E, impl PolynomialCommitmentScheme<E>>>,
    records: &[ArcMultilinearExtensionGpu<'_, E>],
    challenges: &[E; 2],
    cuda_hal: &CudaHalBB31,
    big_buffers: &'buf mut Vec<BufferImpl<BB31Ext>>,
    ones_buffer: &mut Vec<GpuPolynomialExt<'static>>,
    view_last_layers: &mut Vec<Vec<Vec<GpuPolynomialExt<'static>>>>,
) -> Result<
    (
        Vec<ceno_gpu::GpuProverSpec<'buf>>,
        Vec<ceno_gpu::GpuProverSpec<'buf>>,
    ),
    String,
> {
    use crate::scheme::constants::{NUM_FANIN, NUM_FANIN_LOGUP};
    use ceno_gpu::{CudaHal as _, bb31::GpuPolynomialExt};
    use p3::field::FieldAlgebra;

    let ComposedConstrainSystem {
        zkvm_v1_css: cs, ..
    } = composed_cs;
    let _num_instances_with_rotation =
        input.num_instances() << composed_cs.rotation_vars().unwrap_or(0);
    let _chip_record_alpha = challenges[0];

    // TODO: safety ?
    let records = unsafe {
        std::mem::transmute::<
            &[ArcMultilinearExtensionGpu<'_, E>],
            &[ArcMultilinearExtensionGpu<'static, E>],
        >(records)
    };

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

    assert_eq!(big_buffers.len(), 0, "expect no big buffers");

    // prod: last layes & buffer
    let mut is_prod_buffer_exists = false;
    let prod_last_layers = r_set_wit
        .iter()
        .chain(w_set_wit.iter())
        .map(|wit| wit.as_view_chunks(NUM_FANIN))
        .collect::<Vec<_>>();
    if !prod_last_layers.is_empty() {
        let first_layer = &prod_last_layers[0];
        assert_eq!(first_layer.len(), 2, "prod last_layer must have 2 MLEs");
        let num_vars = first_layer[0].num_vars();
        let num_towers = prod_last_layers.len();
        view_last_layers.push(prod_last_layers);

        // Allocate one big buffer for all product towers and add it to big_buffers
        let tower_size = 1 << (num_vars + 1); // 2 * mle_len elements per tower
        let total_buffer_size = num_towers * tower_size;
        tracing::debug!(
            "prod tower request buffer size: {:.2} MB",
            (total_buffer_size * std::mem::size_of::<BB31Ext>()) as f64 / (1024.0 * 1024.0)
        );
        let big_buffer = cuda_hal
            .alloc_ext_elems_on_device(total_buffer_size, false)
            .map_err(|e| format!("Failed to allocate prod GPU buffer: {:?}", e))?;
        big_buffers.push(big_buffer);
        is_prod_buffer_exists = true;
    }

    // logup: last layes
    let mut is_logup_buffer_exists = false;
    let lk_numerator_last_layer = lk_n_wit
        .iter()
        .map(|wit| wit.as_view_chunks(NUM_FANIN_LOGUP))
        .collect::<Vec<_>>();
    let lk_denominator_last_layer = lk_d_wit
        .iter()
        .map(|wit| wit.as_view_chunks(NUM_FANIN_LOGUP))
        .collect::<Vec<_>>();
    let logup_last_layers = if !lk_numerator_last_layer.is_empty() {
        // Case when we have both numerator and denominator
        // Combine [p1, p2] from numerator and [q1, q2] from denominator
        lk_numerator_last_layer
            .into_iter()
            .zip(lk_denominator_last_layer)
            .map(|(lk_n_chunks, lk_d_chunks)| {
                let mut last_layer = lk_n_chunks;
                last_layer.extend(lk_d_chunks);
                last_layer
            })
            .collect::<Vec<_>>()
    } else if lk_denominator_last_layer.is_empty() {
        vec![]
    } else {
        // Case when numerator is empty - create shared ones_buffer and use views
        // This saves memory by having all p1, p2 polynomials reference the same buffer
        let nv = lk_denominator_last_layer[0][0].num_vars();

        // Create one shared ones_buffer as Owned (can be 'static)
        let ones_poly = GpuPolynomialExt::new_with_scalar(&cuda_hal.inner, nv, BB31Ext::ONE)
            .map_err(|e| format!("Failed to create shared ones_buffer: {:?}", e))
            .unwrap();
        // SAFETY: Owned buffer can be safely treated as 'static
        let ones_poly_static: GpuPolynomialExt<'static> = unsafe { std::mem::transmute(ones_poly) };
        ones_buffer.push(ones_poly_static);

        // Get reference from storage to ensure proper lifetime
        let ones_poly_ref = ones_buffer.last().unwrap();
        let mle_len_bytes = ones_poly_ref.evaluations().len() * std::mem::size_of::<BB31Ext>();

        // Create views referencing the shared ones_buffer for each tower's p1, p2
        lk_denominator_last_layer
            .into_iter()
            .map(|lk_d_chunks| {
                // Create views of ones_buffer for p1 and p2
                let p1_view = ones_poly_ref.evaluations().as_slice_range(0..mle_len_bytes);
                let p2_view = ones_poly_ref.evaluations().as_slice_range(0..mle_len_bytes);
                let p1_gpu = GpuPolynomialExt::new(BufferImpl::new_from_view(p1_view), nv);
                let p2_gpu = GpuPolynomialExt::new(BufferImpl::new_from_view(p2_view), nv);
                // SAFETY: views from 'static buffer can be 'static
                let p1_gpu: GpuPolynomialExt<'static> = unsafe { std::mem::transmute(p1_gpu) };
                let p2_gpu: GpuPolynomialExt<'static> = unsafe { std::mem::transmute(p2_gpu) };
                // Use [p1, p2, q1, q2] format for the last layer
                let mut last_layer = vec![p1_gpu, p2_gpu];
                last_layer.extend(lk_d_chunks);
                last_layer
            })
            .collect::<Vec<_>>()
    };
    if !logup_last_layers.is_empty() {
        let first_layer = &logup_last_layers[0];
        assert_eq!(first_layer.len(), 4, "logup last_layer must have 4 MLEs");
        let num_vars = first_layer[0].num_vars();
        let num_towers = logup_last_layers.len();
        view_last_layers.push(logup_last_layers);

        // Allocate one big buffer for all towers and add it to big_buffers
        let tower_size = 1 << (num_vars + 2); // 4 * mle_len elements per tower
        let total_buffer_size = num_towers * tower_size;
        tracing::debug!(
            "logup tower request buffer size: {:.2} MB",
            (total_buffer_size * std::mem::size_of::<BB31Ext>()) as f64 / (1024.0 * 1024.0)
        );
        let big_buffer = cuda_hal
            .alloc_ext_elems_on_device(total_buffer_size, false)
            .unwrap();
        big_buffers.push(big_buffer);
        is_logup_buffer_exists = true;
    }

    let (_, pushed_big_buffers) = big_buffers.split_at_mut(0);
    let (prod_big_buffer, logup_big_buffer) = match (
        is_prod_buffer_exists,
        is_logup_buffer_exists,
        pushed_big_buffers,
    ) {
        (false, false, []) => (None, None),
        (true, false, [prod]) => (Some(prod), None),
        (false, true, [logup]) => (None, Some(logup)),
        (true, true, [prod, logup]) => (Some(prod), Some(logup)),
        (prod_flag, logup_flag, slice) => {
            panic!(
                "unexpected state: prod={}, logup={}, newly_pushed_len={}",
                prod_flag,
                logup_flag,
                slice.len()
            );
        }
    };

    // Build product GpuProverSpecs
    let mut prod_gpu_specs = Vec::new();
    if is_prod_buffer_exists {
        let prod_last_layers = &view_last_layers[0];
        let first_layer = &prod_last_layers[0];
        assert_eq!(first_layer.len(), 2, "prod last_layer must have 2 MLEs");
        let num_vars = first_layer[0].num_vars();
        let num_towers = prod_last_layers.len();
        let Some(prod_big_buffer) = prod_big_buffer else {
            panic!("prod big buffer not found");
        };

        let span_prod = entered_span!(
            "build_prod_tower",
            prod_layers = prod_last_layers.len(),
            profiling_3 = true
        );
        let last_layers_refs: Vec<&[GpuPolynomialExt<'_>]> =
            prod_last_layers.iter().map(|v| v.as_slice()).collect();
        let gpu_specs = {
            cuda_hal.tower.build_prod_tower_from_gpu_polys_batch(
                cuda_hal,
                prod_big_buffer,
                &last_layers_refs,
                num_vars,
                num_towers,
            )
        }
        .map_err(|e| format!("build_prod_tower_from_gpu_polys_batch failed: {:?}", e))?;
        prod_gpu_specs.extend(gpu_specs);
        exit_span!(span_prod);
    }

    // Build logup GpuProverSpecs
    let mut logup_gpu_specs = Vec::new();
    if is_logup_buffer_exists {
        let logup_last_layers = view_last_layers.last().unwrap();
        let first_layer = &logup_last_layers[0];
        assert_eq!(first_layer.len(), 4, "logup last_layer must have 4 MLEs");
        let num_vars = first_layer[0].num_vars();
        let num_towers = logup_last_layers.len();
        let Some(logup_big_buffer) = logup_big_buffer else {
            panic!("logup big buffer not found");
        };

        let span_logup = entered_span!(
            "build_logup_tower",
            logup_layers = logup_last_layers.len(),
            profiling_3 = true
        );
        let last_layers_refs: Vec<&[GpuPolynomialExt<'_>]> =
            logup_last_layers.iter().map(|v| v.as_slice()).collect();
        let gpu_specs = cuda_hal
            .tower
            .build_logup_tower_from_gpu_polys_batch(
                cuda_hal,
                logup_big_buffer,
                &last_layers_refs,
                num_vars,
                num_towers,
            )
            .map_err(|e| format!("build_logup_tower_from_gpu_polys_batch failed: {:?}", e))?;

        logup_gpu_specs.extend(gpu_specs);
        exit_span!(span_logup);
    }
    Ok((prod_gpu_specs, logup_gpu_specs))
}

impl<E: ExtensionField, PCS: PolynomialCommitmentScheme<E>> TowerProver<GpuBackend<E, PCS>>
    for GpuProver<GpuBackend<E, PCS>>
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
        _records: &'c [ArcMultilinearExtensionGpu<'b, E>],
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
        records: &'c [ArcMultilinearExtensionGpu<'b, E>],
        challenges: &[E; 2],
        transcript: &mut impl Transcript<E>,
    ) -> TowerRelationOutput<E>
    where
        'a: 'b,
        'b: 'c,
    {
        if std::any::TypeId::of::<E::BaseField>() != std::any::TypeId::of::<BB31Base>() {
            panic!("GPU backend only supports BabyBear base field");
        }

        // Calculate r_set_len directly from constraint system
        let ComposedConstrainSystem {
            zkvm_v1_css: cs, ..
        } = composed_cs;
        let r_set_len = cs.r_expressions.len() + cs.r_table_expressions.len();

        let cuda_hal = get_cuda_hal().unwrap();
        let (point, proof, lk_out_evals, w_out_evals, r_out_evals) = {
            // build_tower_witness_gpu will allocate buffers and build GPU specs
            let span = entered_span!("build_tower_witness", profiling_2 = true);
            let mut _big_buffers: Vec<BufferImpl<BB31Ext>> = Vec::new();
            let mut _ones_buffer: Vec<GpuPolynomialExt<'static>> = Vec::new();
            let mut _view_last_layers: Vec<Vec<Vec<GpuPolynomialExt<'static>>>> = Vec::new();
            let (prod_gpu, logup_gpu) =
                info_span!("[ceno] build_tower_witness_gpu").in_scope(|| {
                    build_tower_witness_gpu(
                        composed_cs,
                        input,
                        records,
                        challenges,
                        &cuda_hal,
                        &mut _big_buffers,
                        &mut _ones_buffer,
                        &mut _view_last_layers,
                    )
                    .map_err(|e| format!("build_tower_witness_gpu failed: {}", e))
                    .unwrap()
                });
            exit_span!(span);

            // GPU optimization: Extract out_evals from GPU-built towers before consuming them
            // This is the true optimization - using GPU tower results instead of CPU inference
            let span = entered_span!("extract_out_evals_from_gpu_towers", profiling_2 = true);
            let (r_out_evals, w_out_evals, lk_out_evals) =
                extract_out_evals_from_gpu_towers(&prod_gpu, &logup_gpu, r_set_len);
            exit_span!(span);

            // transcript >>> BasicTranscript<E>
            let basic_tr: &mut BasicTranscript<BB31Ext> =
                unsafe { &mut *(transcript as *mut _ as *mut BasicTranscript<BB31Ext>) };

            let input = ceno_gpu::TowerInput {
                prod_specs: prod_gpu,
                logup_specs: logup_gpu,
            };

            let span = entered_span!("prove_tower_relation", profiling_2 = true);
            let (point_gl, proof_gpu) =
                info_span!("[ceno] prove_tower_relation_gpu").in_scope(|| {
                    cuda_hal
                        .tower
                        .create_proof(&cuda_hal, &input, NUM_FANIN, basic_tr)
                        .expect("gpu tower create_proof failed")
                });
            exit_span!(span);

            // TowerProofs
            let point: Point<E> = unsafe { std::mem::transmute(point_gl) };
            let proof: TowerProofs<E> = unsafe { std::mem::transmute(proof_gpu) };
            (point, proof, lk_out_evals, w_out_evals, r_out_evals)
        };

        (point, proof, lk_out_evals, w_out_evals, r_out_evals)
    }
}

impl<E: ExtensionField, PCS: PolynomialCommitmentScheme<E>> MainSumcheckProver<GpuBackend<E, PCS>>
    for GpuProver<GpuBackend<E, PCS>>
{
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
        // _records: Vec<ArcMultilinearExtensionGpu<'b, E>>, // not used by GPU after delegation
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
        let ComposedConstrainSystem {
            zkvm_v1_css: cs,
            gkr_circuit,
        } = composed_cs;

        let num_instances = input.num_instances();
        let log2_num_instances = input.log2_num_instances();
        let num_threads = optimal_sumcheck_threads(log2_num_instances);
        let num_var_with_rotation = log2_num_instances + composed_cs.rotation_vars().unwrap_or(0);

        let Some(gkr_circuit) = gkr_circuit else {
            panic!("empty gkr circuit")
        };
        let selector_ctxs = if cs.ec_final_sum.is_empty() {
            // it's not global chip
            vec![
                SelectorContext {
                    offset: 0,
                    num_instances,
                    num_vars: num_var_with_rotation,
                };
                gkr_circuit
                    .layers
                    .first()
                    .map(|layer| layer.out_sel_and_eval_exprs.len())
                    .unwrap_or(0)
            ]
        } else {
            // it's global chip
            vec![
                SelectorContext {
                    offset: 0,
                    num_instances: input.num_instances[0],
                    num_vars: num_var_with_rotation,
                },
                SelectorContext {
                    offset: input.num_instances[0],
                    num_instances: input.num_instances[1],
                    num_vars: num_var_with_rotation,
                },
                SelectorContext {
                    offset: 0,
                    num_instances,
                    num_vars: num_var_with_rotation,
                },
            ]
        };
        let pub_io_mles = cs
            .instance_openings
            .iter()
            .map(|instance| input.public_input[instance.0].clone())
            .collect_vec();
        let GKRProverOutput {
            gkr_proof,
            opening_evaluations,
            mut rt,
        } = gkr_circuit.prove::<GpuBackend<E, PCS>, GpuProver<_>>(
            num_threads,
            num_var_with_rotation,
            gkr::GKRCircuitWitness {
                layers: vec![LayerWitness(
                    chain!(
                        &input.witness,
                        &input.fixed,
                        &pub_io_mles,
                        &input.structural_witness,
                    )
                    .cloned()
                    .collect_vec(),
                )],
            },
            // eval value doesnt matter as it wont be used by prover
            &vec![PointAndEval::new(rt_tower, E::ZERO); gkr_circuit.final_out_evals.len()],
            &input
                .pub_io_evals
                .iter()
                .map(|v| v.map_either(E::from, |v| v).into_inner())
                .collect_vec(),
            challenges,
            transcript,
            &selector_ctxs,
        )?;
        assert_eq!(rt.len(), 1, "TODO support multi-layer gkr iop");
        Ok((
            rt.remove(0),
            MainSumcheckEvals {
                wits_in_evals: opening_evaluations
                    .iter()
                    .take(cs.num_witin as usize)
                    .map(|Evaluation { value, .. }| value)
                    .copied()
                    .collect_vec(),
                fixed_in_evals: opening_evaluations
                    .iter()
                    .skip(cs.num_witin as usize)
                    .take(cs.num_fixed)
                    .map(|Evaluation { value, .. }| value)
                    .copied()
                    .collect_vec(),
            },
            None,
            Some(gkr_proof),
        ))
    }
}

impl<E: ExtensionField, PCS: PolynomialCommitmentScheme<E>> EccQuarkProver<GpuBackend<E, PCS>>
    for GpuProver<GpuBackend<E, PCS>>
{
    fn prove_ec_sum_quark<'a>(
        &self,
        num_instances: usize,
        xs: Vec<Arc<MultilinearExtensionGpu<'a, E>>>,
        ys: Vec<Arc<MultilinearExtensionGpu<'a, E>>>,
        invs: Vec<Arc<MultilinearExtensionGpu<'a, E>>>,
        transcript: &mut impl Transcript<E>,
    ) -> Result<EccQuarkProof<E>, ZKVMError> {
        assert_eq!(xs.len(), SEPTIC_EXTENSION_DEGREE);
        assert_eq!(ys.len(), SEPTIC_EXTENSION_DEGREE);

        let n = xs[0].mle.num_vars() - 1;
        tracing::debug!(
            "Creating EC Summation Quark proof with {} points in {n} variables",
            num_instances
        );

        let out_rt = transcript.sample_and_append_vec(b"ecc", n);

        // expression with add (3 zero constraints), bypass (2 zero constraints), export (2 zero constraints)
        let alpha_pows = transcript.sample_and_append_challenge_pows(
            SEPTIC_EXTENSION_DEGREE * 3 + SEPTIC_EXTENSION_DEGREE * 2 + SEPTIC_EXTENSION_DEGREE * 2,
            b"ecc_alpha",
        );
        let mut alpha_pows_iter = alpha_pows.iter();

        let sel_add = SelectorType::QuarkBinaryTreeLessThan(0.into());
        let sel_add_ctx = SelectorContext {
            offset: 0,
            num_instances,
            num_vars: n,
        };
        let sel_add_mle: MultilinearExtension<'_, E> =
            sel_add.compute(&out_rt, &sel_add_ctx).unwrap();

        // the final sum is located at [1,...,1,0] (in big-endian)
        let last_evaluation_index = (1 << n) - 2;
        let lsi_on_hypercube = once(E::ZERO).chain(repeat_n(E::ONE, n - 1)).collect_vec();
        let mut sel_export = (0..(1 << n))
            .into_par_iter()
            .map(|_| E::ZERO)
            .collect::<Vec<_>>();
        sel_export[last_evaluation_index] = eq_eval(&out_rt, lsi_on_hypercube.as_slice());
        let sel_export_mle = sel_export.into_mle();

        // we construct sel_bypass witness here
        // verifier can derive it via `sel_bypass = eq - sel_add - sel_last_onehot`
        let mut sel_bypass_mle: Vec<E> = build_eq_x_r_vec(&out_rt);
        match sel_add_mle.evaluations() {
            FieldType::Ext(sel_add_mle) => sel_add_mle
                .par_iter()
                .zip(sel_bypass_mle.par_iter_mut())
                .for_each(|(sel_add, sel_bypass)| {
                    if *sel_add != E::ZERO {
                        *sel_bypass = E::ZERO;
                    }
                }),
            _ => unreachable!(),
        }
        *sel_bypass_mle.last_mut().unwrap() = E::ZERO;
        let sel_bypass_mle = sel_bypass_mle.into_mle();

        let cuda_hal = get_cuda_hal().map_err(hal_to_backend_error)?;
        let sel_add_gpu = mle_host_to_gpu(&cuda_hal, &sel_add_mle);
        let sel_bypass_gpu = mle_host_to_gpu(&cuda_hal, &sel_bypass_mle);
        let sel_export_gpu = mle_host_to_gpu(&cuda_hal, &sel_export_mle);
        let split_batches = mle_filter_even_odd_batch::<E>(
            &cuda_hal,
            &[(&xs, false), (&xs, true), (&ys, false), (&ys, true)],
        )?;
        let mut split_iter = split_batches.into_iter();
        let x0_gpu = split_iter.next().unwrap_or_default();
        let x1_gpu = split_iter.next().unwrap_or_default();
        let y0_gpu = split_iter.next().unwrap_or_default();
        let y1_gpu = split_iter.next().unwrap_or_default();

        // build x[1,b], y[1,b], s[1,b]
        let x3_gpu = batch_mles_take_half::<E>(&xs, 1)?;
        let y3_gpu = batch_mles_take_half::<E>(&ys, 1)?;
        let s_gpu = batch_mles_take_half::<E>(&invs, 1)?;

        let mut registry: WitnessRegistry<'a, E> = WitnessRegistry::default();
        let sel_add_expr = registry.register(sel_add_gpu);
        let sel_bypass_expr = registry.register(sel_bypass_gpu);
        let sel_export_expr = registry.register(sel_export_gpu);

        let s = symbolic_from_mle(&mut registry, &s_gpu);
        let x0 = symbolic_from_mle(&mut registry, &x0_gpu);
        let y0 = symbolic_from_mle(&mut registry, &y0_gpu);
        let x1 = symbolic_from_mle(&mut registry, &x1_gpu);
        let y1 = symbolic_from_mle(&mut registry, &y1_gpu);
        let x3 = symbolic_from_mle(&mut registry, &x3_gpu);
        let y3 = symbolic_from_mle(&mut registry, &y3_gpu);

        let mut exprs_add = vec![];
        let mut exprs_bypass = vec![];
        // affine addition
        // zerocheck: 0 = s[1,b] * (x[b,0] - x[b,1]) - (y[b,0] - y[b,1]) with b != (1,...,1)
        exprs_add.extend(
            (s.clone() * (&x0 - &x1) - (&y0 - &y1))
                .to_exprs()
                .into_iter()
                .zip_eq(alpha_pows_iter.by_ref().take(SEPTIC_EXTENSION_DEGREE))
                .map(|(e, alpha)| e * Expression::Constant(Either::Right(*alpha))),
        );

        // zerocheck: 0 = s[1,b]^2 - x[b,0] - x[b,1] - x[1,b] with b != (1,...,1)
        exprs_add.extend(
            ((&s * &s) - &x0 - &x1 - &x3)
                .to_exprs()
                .into_iter()
                .zip_eq(alpha_pows_iter.by_ref().take(SEPTIC_EXTENSION_DEGREE))
                .map(|(e, alpha)| e * Expression::Constant(Either::Right(*alpha))),
        );
        // zerocheck: 0 = s[1,b] * (x[b,0] - x[1,b]) - (y[b,0] + y[1,b]) with b != (1,...,1)
        exprs_add.extend(
            (s.clone() * (&x0 - &x3) - (&y0 + &y3))
                .to_exprs()
                .into_iter()
                .zip_eq(alpha_pows_iter.by_ref().take(SEPTIC_EXTENSION_DEGREE))
                .map(|(e, alpha)| e * Expression::Constant(Either::Right(*alpha))),
        );

        let exprs_add = exprs_add.into_iter().sum::<Expression<E>>() * sel_add_expr;

        // deal with bypass
        // 0 = (x[1,b] - x[b,0])
        exprs_bypass.extend(
            (&x3 - &x0)
                .to_exprs()
                .into_iter()
                .zip_eq(alpha_pows_iter.by_ref().take(SEPTIC_EXTENSION_DEGREE))
                .map(|(e, alpha)| e * Expression::Constant(Either::Right(*alpha))),
        );
        // 0 = (y[1,b] - y[b,0])
        exprs_bypass.extend(
            (&y3 - &y0)
                .to_exprs()
                .into_iter()
                .zip_eq(alpha_pows_iter.by_ref().take(SEPTIC_EXTENSION_DEGREE))
                .map(|(e, alpha)| e * Expression::Constant(Either::Right(*alpha))),
        );

        // export x[1,...,1,0], y[1,...,1,0] for final result (using big-endian notation)
        let xp_gpu = batch_mles_take_half::<E>(&xs, 1)?;
        let yp_gpu = batch_mles_take_half::<E>(&ys, 1)?;
        let final_sum_x = read_septic_value_from_gpu(&xp_gpu, last_evaluation_index)?;
        let final_sum_y = read_septic_value_from_gpu(&yp_gpu, last_evaluation_index)?;
        // 0 = sel_export * (x[1,b] - final_sum.x)
        // 0 = sel_export * (y[1,b] - final_sum.y)
        let export_expr =
            x3.0.iter()
                .zip_eq(final_sum_x.0.iter())
                .chain(y3.0.iter().zip_eq(final_sum_y.0.iter()))
                .map(|(x, final_x)| x - final_x.expr())
                .zip_eq(alpha_pows_iter.by_ref().take(SEPTIC_EXTENSION_DEGREE * 2))
                .map(|(e, alpha)| e * Expression::Constant(Either::Right(*alpha)))
                .sum::<Expression<E>>()
                * sel_export_expr;

        let exprs_bypass = exprs_bypass.into_iter().sum::<Expression<E>>() * sel_bypass_expr;

        let zero_expr = exprs_add + exprs_bypass + export_expr;

        let monomial_terms = zero_expr.get_monomial_terms();
        let gpu_refs = registry.gpu_refs();
        let (term_coefficients, mle_indices_per_term, mle_size_info) =
            extract_mle_relationships_from_monomial_terms(&monomial_terms, &gpu_refs, &[], &[]);
        let max_degree = mle_indices_per_term
            .iter()
            .map(|indices| indices.len())
            .max()
            .unwrap_or(0);
        let term_coefficients_gl64: Vec<BB31Ext> =
            unsafe { std::mem::transmute(term_coefficients.clone()) };
        let gpu_refs_gl64: Vec<&MultilinearExtensionGpu<BB31Ext>> =
            unsafe { std::mem::transmute(gpu_refs) };
        let gpu_field_refs = gpu_refs_gl64.iter().map(|mle| &mle.mle).collect_vec();

        let basic_transcript = expect_basic_transcript(transcript);
        let (proof_gpu, evals_gpu, challenges_gpu) = cuda_hal
            .prove_generic_sumcheck_gpu(
                gpu_field_refs,
                &mle_size_info,
                &term_coefficients_gl64,
                &mle_indices_per_term,
                n,
                max_degree,
                None,
                basic_transcript,
            )
            .map_err(|e| hal_to_backend_error(format!("GPU sumcheck failed: {e:?}")))?;

        drop(cuda_hal);

        let proof_gpu_e: IOPProof<E> = unsafe { std::mem::transmute(proof_gpu) };
        let evals_gpu_e: Vec<Vec<E>> = unsafe { std::mem::transmute(evals_gpu) };
        let mut evals = Vec::new();
        for chunk in evals_gpu_e {
            evals.extend(chunk);
        }
        let rt: Point<E> = unsafe {
            std::mem::transmute::<Vec<BB31Ext>, Vec<E>>(
                challenges_gpu.iter().map(|c| c.elements).collect(),
            )
        };

        // 3 for sel_add, sel_bypass, sel_export
        // 7 for x[rt,0], x[rt,1], y[rt,0], y[rt,1], x[1,rt], y[1,rt], s[1,rt]
        assert_eq!(evals.len(), 3 + SEPTIC_EXTENSION_DEGREE * 7);
        let final_sum = SepticPoint::from_affine(final_sum_x.clone(), final_sum_y.clone());
        assert_eq!(proof_gpu_e.extract_sum(), E::ZERO);

        Ok(EccQuarkProof {
            zerocheck_proof: proof_gpu_e,
            num_instances,
            evals,
            rt,
            sum: final_sum,
        })
    }
}

impl<E: ExtensionField, PCS: PolynomialCommitmentScheme<E>> OpeningProver<GpuBackend<E, PCS>>
    for GpuProver<GpuBackend<E, PCS>>
{
    fn open(
        &self,
        witness_data: <GpuBackend<E, PCS> as ProverBackend>::PcsData,
        fixed_data: Option<Arc<<GpuBackend<E, PCS> as ProverBackend>::PcsData>>,
        points: Vec<Point<E>>,
        mut evals: Vec<Vec<Vec<E>>>, // where each inner Vec<E> = wit_evals + fixed_evals
        transcript: &mut (impl Transcript<E> + 'static),
    ) -> PCS::Proof {
        if std::any::TypeId::of::<E::BaseField>() != std::any::TypeId::of::<BB31Base>() {
            panic!("GPU backend only supports BabyBear base field");
        }

        let mut rounds = vec![];
        rounds.push((&witness_data, {
            evals
                .iter_mut()
                .zip(&points)
                .filter_map(|(evals, point)| {
                    let witin_evals = evals.remove(0);
                    if !witin_evals.is_empty() {
                        Some((point.clone(), witin_evals))
                    } else {
                        None
                    }
                })
                .collect_vec()
        }));
        if let Some(fixed_data) = fixed_data.as_ref().map(|f| f.as_ref()) {
            rounds.push((fixed_data, {
                evals
                    .iter_mut()
                    .zip(points)
                    .filter_map(|(evals, point)| {
                        if !evals.is_empty() && !evals[0].is_empty() {
                            Some((point.clone(), evals.remove(0)))
                        } else {
                            None
                        }
                    })
                    .collect_vec()
            }));
        }

        // Type conversions using unsafe transmute
        let prover_param = &self.backend.pp;
        let pp_gl64: &mpcs::basefold::structure::BasefoldProverParams<
            BB31Ext,
            mpcs::BasefoldRSParams,
        > = unsafe { std::mem::transmute(prover_param) };
        let rounds_gl64: Vec<_> = rounds
            .iter()
            .map(|(commitment, point_eval_pairs)| {
                let commitment_gl64: &BasefoldCommitmentWithWitnessGpu<
                    BB31Base,
                    BufferImpl<BB31Base>,
                    GpuDigestLayer,
                    GpuMatrix<'static>,
                    GpuPolynomial<'static>,
                > = unsafe { std::mem::transmute(*commitment) };
                let point_eval_pairs_gl64: Vec<_> = point_eval_pairs
                    .iter()
                    .map(|(point, evals)| {
                        let point_gl64: &Vec<BB31Ext> = unsafe { std::mem::transmute(point) };
                        let evals_gl64: &Vec<BB31Ext> = unsafe { std::mem::transmute(evals) };
                        (point_gl64.clone(), evals_gl64.clone())
                    })
                    .collect();
                (commitment_gl64, point_eval_pairs_gl64)
            })
            .collect();

        if std::any::TypeId::of::<E>() == std::any::TypeId::of::<BB31Ext>() {
            let transcript_any = transcript as &mut dyn std::any::Any;
            let basic_transcript = transcript_any
                .downcast_mut::<BasicTranscript<BB31Ext>>()
                .expect("Type should match");

            let cuda_hal = get_cuda_hal().unwrap();
            let gpu_proof_basefold = cuda_hal
                .basefold
                .batch_open(&cuda_hal, pp_gl64, rounds_gl64, basic_transcript)
                .unwrap();

            let gpu_proof: PCS::Proof = unsafe { std::mem::transmute_copy(&gpu_proof_basefold) };
            std::mem::forget(gpu_proof_basefold);
            gpu_proof
        } else {
            panic!("GPU backend only supports BabyBear base field");
        }
    }
}

impl<E: ExtensionField, PCS: PolynomialCommitmentScheme<E>> DeviceTransporter<GpuBackend<E, PCS>>
    for GpuProver<GpuBackend<E, PCS>>
{
    fn transport_proving_key(
        &self,
        is_first_shard: bool,
        pk: Arc<
            crate::structs::ZKVMProvingKey<
                <GpuBackend<E, PCS> as ProverBackend>::E,
                <GpuBackend<E, PCS> as ProverBackend>::Pcs,
            >,
        >,
    ) -> DeviceProvingKey<'static, GpuBackend<E, PCS>> {
        let pcs_data_original = if is_first_shard {
            pk.fixed_commit_wd.clone().unwrap()
        } else {
            pk.fixed_no_omc_init_commit_wd.clone().unwrap()
        };

        // assert pcs match
        let is_pcs_match = std::mem::size_of::<mpcs::BasefoldCommitmentWithWitness<BB31Ext>>()
            == std::mem::size_of::<PCS::CommitmentWithWitness>();
        assert!(is_pcs_match, "pcs mismatch");

        // 1. transmute from PCS::CommitmentWithWitness to BasefoldCommitmentWithWitness<E>
        let basefold_commitment: &mpcs::BasefoldCommitmentWithWitness<BB31Ext> =
            unsafe { std::mem::transmute_copy(&pcs_data_original.as_ref()) };
        // 2. convert from BasefoldCommitmentWithWitness<E> to BasefoldCommitmentWithWitness<BB31Base>
        let cuda_hal = get_cuda_hal().unwrap();
        let pcs_data_basefold = convert_ceno_to_gpu_basefold_commitment::<
            CudaHalBB31,
            BB31Ext,
            BB31Base,
            GpuDigestLayer,
            GpuMatrix,
            GpuPolynomial,
        >(&cuda_hal, basefold_commitment);
        let pcs_data: <GpuBackend<E, PCS> as ProverBackend>::PcsData =
            unsafe { std::mem::transmute_copy(&pcs_data_basefold) };
        std::mem::forget(pcs_data_basefold);
        let pcs_data = Arc::new(pcs_data);

        let fixed_mles = PCS::get_arc_mle_witness_from_commitment(pcs_data_original.as_ref());
        let fixed_mles = fixed_mles
            .iter()
            .map(|mle| Arc::new(MultilinearExtensionGpu::from_ceno(&cuda_hal, mle)))
            .collect_vec();

        DeviceProvingKey {
            pcs_data,
            fixed_mles,
        }
    }

    fn transport_mles<'a>(
        &self,
        mles: &[MultilinearExtension<'a, E>],
    ) -> Vec<ArcMultilinearExtensionGpu<'a, E>> {
        let cuda_hal = get_cuda_hal().unwrap();
        mles.iter()
            .map(|mle| Arc::new(MultilinearExtensionGpu::from_ceno(&cuda_hal, mle)))
            .collect_vec()
    }
}

impl<E, PCS> ProverDevice<GpuBackend<E, PCS>> for GpuProver<GpuBackend<E, PCS>>
where
    E: ExtensionField,
    PCS: PolynomialCommitmentScheme<E> + 'static,
{
    fn get_pb(&self) -> &GpuBackend<E, PCS> {
        self.backend.as_ref()
    }
}
