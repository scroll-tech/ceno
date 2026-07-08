use std::sync::Arc;

use ceno_zkvm::structs::VK_DIGEST_LEN;
use eyre::{Result, bail, eyre};
use itertools::Itertools;
use multilinear_extensions::Expression;
use openvm_circuit_primitives::encoder::Encoder;
use openvm_cpu_backend::CpuBackend;
use openvm_stark_backend::{
    AirRef, FiatShamirTranscript, StarkProtocolConfig, TranscriptHistory,
    p3_maybe_rayon::prelude::*, prover::AirProvingContext,
};
use openvm_stark_sdk::config::baby_bear_poseidon2::{BabyBearPoseidon2Config, D_EF, F};
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;
use witness::next_pow2_instance_padding;

use crate::{
    proof_shape::{
        bus::{NumPublicValuesBus, ProofShapePermutationBus, StartingTidxBus},
        proof_shape::ProofShapeAir,
        pvs::PublicValuesAir,
    },
    system::{
        AirModule, BusIndexManager, BusInventory, GlobalCtxCpu, POW_CHECKER_HEIGHT, Preflight,
        RecursionField, RecursionProof, RecursionVk, TraceGenModule, TraceVData,
    },
    tracegen::{ModuleChip, RowMajorChip},
    utils::TranscriptLabel,
};
use recursion_circuit::primitives::{
    bus::RangeCheckerBus,
    pow::PowerCheckerCpuTraceGenerator,
    range::{RangeCheckerAir, RangeCheckerCols, RangeCheckerCpuTraceGenerator},
};

pub mod bus;
#[allow(clippy::module_inception)]
pub mod proof_shape;
pub mod pvs;

#[cfg(feature = "cuda")]
mod cuda_abi;

#[derive(Clone)]
pub struct AirMetadata {
    is_required: bool,
    num_public_values: usize,
    num_witin: usize,
    num_structural_witin: usize,
    num_fixed: usize,
    num_read_count: usize,
    num_write_count: usize,
    num_logup_count: usize,
    rotation_vars: usize,
    ecc_extra_vars: usize,
    read_op_vars: usize,
    write_op_vars: usize,
    logup_op_vars: usize,
    selectors: Vec<SelectorMetadata>,
}

#[derive(Clone)]
pub struct SelectorMetadata {
    selector_idx: usize,
    kind: usize,
    point_source: usize,
    eval_idx: usize,
    context_mode: SelectorContextMode,
    ordered_sparse_num_vars: usize,
    sparse_indices: Vec<usize>,
}

#[derive(Clone, Copy)]
enum SelectorContextMode {
    Total,
    Read,
    Write,
}

pub struct ProofShapeModule {
    // Verifying key fields
    per_air: Vec<AirMetadata>,

    // Buses (inventory for external, others are internal)
    bus_inventory: BusInventory,
    range_bus: RangeCheckerBus,
    permutation_bus: ProofShapePermutationBus,
    starting_tidx_bus: StartingTidxBus,
    num_pvs_bus: NumPublicValuesBus,

    // Required for ProofShapeAir tracegen + constraints
    idx_encoder: Arc<Encoder>,

    // Module sends extra public values message for use outside of verifier
    // sub-circuit if true
    continuations_enabled: bool,
    public_values_start_tidx: usize,
}

impl ProofShapeModule {
    pub fn new(
        child_vk: &RecursionVk,
        b: &mut BusIndexManager,
        bus_inventory: BusInventory,
        continuations_enabled: bool,
    ) -> Self {
        let num_airs = child_vk.circuit_vks.len();
        let idx_encoder = Arc::new(Encoder::new(num_airs, 2, true));
        let per_air = extract_air_metadata_from_vk(child_vk);
        let public_values_start_tidx = TranscriptLabel::Riscv.field_len() + VK_DIGEST_LEN * D_EF;

        let range_bus = bus_inventory.range_checker_bus;
        Self {
            per_air,
            bus_inventory,
            range_bus,
            permutation_bus: ProofShapePermutationBus::new(b.new_bus_idx()),
            starting_tidx_bus: StartingTidxBus::new(b.new_bus_idx()),
            num_pvs_bus: NumPublicValuesBus::new(b.new_bus_idx()),
            idx_encoder,
            continuations_enabled,
            public_values_start_tidx,
        }
    }

    #[tracing::instrument(level = "trace", skip_all)]
    pub fn run_preflight<TS>(
        &self,
        child_vk: &RecursionVk,
        proof: &RecursionProof,
        preflight: &mut Preflight,
        ts: &mut TS,
    ) where
        TS: FiatShamirTranscript<BabyBearPoseidon2Config> + TranscriptHistory,
    {
        let _ = self;

        let transcript_start_tidx = ts.len();
        preflight.proof_shape.fork_start_tidx = ts.len();

        // Build per-air shape metadata from present chip proofs.
        let mut sorted_trace_vdata = proof
            .chip_proofs
            .iter()
            .map(|(&chip_idx, chip_proof)| {
                let num_instances: usize = chip_proof.num_instances.iter().copied().sum();
                let padded = next_pow2_instance_padding(num_instances);
                let log_height = padded.ilog2() as usize;
                (chip_idx, TraceVData { log_height })
            })
            .collect_vec();
        sorted_trace_vdata.sort_by_key(|(air_idx, v)| (usize::MAX - v.log_height, *air_idx));
        preflight.proof_shape.sorted_trace_vdata = sorted_trace_vdata;
        // TODO remove l_skip
        preflight.proof_shape.l_skip = 0;

        let mut current_tidx = transcript_start_tidx;
        let mut starting_tidx = vec![0usize; child_vk.circuit_vks.len()];
        let n_max = preflight
            .proof_shape
            .sorted_trace_vdata
            .iter()
            .map(|(_, vdata)| vdata.log_height)
            .max()
            .unwrap_or(0);

        for air_idx in 0..child_vk.circuit_vks.len() {
            let metadata = &self.per_air[air_idx];
            let is_present = proof.chip_proofs.contains_key(&air_idx);
            starting_tidx[air_idx] = current_tidx;

            if !metadata.is_required {
                current_tidx += 1;
            }

            if is_present {
                current_tidx += 1;

                if metadata.num_public_values != 0 {
                    current_tidx += metadata.num_public_values;
                }
            }
        }

        preflight.proof_shape.starting_tidx = starting_tidx;
        preflight.proof_shape.post_tidx = current_tidx;
        preflight.proof_shape.n_max = n_max;
        // n_logup is the per-proof max number of tower layers (num_layers).
        // Keep this independent from tower replay side effects.
        preflight.proof_shape.n_logup = proof
            .chip_proofs
            .values()
            .map(|chip_proof| chip_proof.tower_proof.proofs.len())
            .max()
            .unwrap_or(0);

        let _ = child_vk;
    }

    #[allow(dead_code)]
    fn placeholder_air_widths(&self) -> Vec<usize> {
        let proof_shape_width =
            proof_shape::ProofShapeCols::<u8, 4>::width() + self.idx_encoder.width();
        let pvs_width = pvs::PublicValuesCols::<u8>::width();
        let range_width = RangeCheckerCols::<u8>::width();
        // TODO(recursion-proof-bridge): replace proof-shape module placeholder contexts with
        // real tracegen so RangeCheckerAir rows are semantically valid, not only width-correct.
        vec![proof_shape_width, pvs_width, range_width]
    }
}

fn grouped_op_vars(raw_count: usize) -> usize {
    if raw_count == 0 {
        0
    } else {
        raw_count.next_power_of_two().ilog2() as usize
    }
}

fn extract_air_metadata_from_vk(child_vk: &RecursionVk) -> Vec<AirMetadata> {
    (0..child_vk.circuit_vks.len())
        .map(|idx| {
            let (
                num_public_values,
                num_witin,
                num_structural_witin,
                num_fixed,
                raw_read_count,
                raw_write_count,
                raw_logup_count,
                rotation_vars,
                ecc_extra_vars,
            ) = child_vk
                .circuit_index_to_name
                .get(&idx)
                .and_then(|name| child_vk.circuit_vks.get(name))
                .map(|circuit_vk| {
                    let cs = circuit_vk.get_cs();
                    let css = &cs.zkvm_v1_css;
                    (
                        css.instance.len(),
                        css.num_witin as usize,
                        css.num_structural_witin as usize,
                        css.num_fixed,
                        cs.num_reads(),
                        cs.num_writes(),
                        cs.num_lks(),
                        cs.rotation_vars().unwrap_or(0),
                        usize::from(cs.has_ecc_ops()),
                    )
                })
                .unwrap_or((0, 0, 0, 0, 0, 0, 0, 0, 0));
            let selectors = child_vk
                .circuit_index_to_name
                .get(&idx)
                .and_then(|name| child_vk.circuit_vks.get(name))
                .map(|circuit_vk| selector_metadata_from_circuit(circuit_vk.get_cs()))
                .transpose()
                .unwrap_or_else(|err| {
                    panic!("failed to extract selector metadata for air {idx}: {err}")
                })
                .unwrap_or_default();
            let num_read_count = usize::from(raw_read_count > 0);
            let num_write_count = usize::from(raw_write_count > 0);
            let num_logup_count = usize::from(raw_logup_count > 0);

            AirMetadata {
                is_required: false,
                num_public_values,
                num_witin,
                num_structural_witin,
                num_fixed,
                num_read_count,
                num_write_count,
                num_logup_count,
                rotation_vars,
                ecc_extra_vars,
                read_op_vars: grouped_op_vars(raw_read_count),
                write_op_vars: grouped_op_vars(raw_write_count),
                logup_op_vars: grouped_op_vars(raw_logup_count),
                selectors,
            }
        })
        .collect_vec()
}

fn selector_metadata_from_circuit(
    composed_cs: &ceno_zkvm::structs::ComposedConstrainSystem<RecursionField>,
) -> Result<Vec<SelectorMetadata>> {
    let Some(circuit) = composed_cs.gkr_circuit.as_ref() else {
        return Ok(Vec::new());
    };
    let first_layer = circuit
        .layers
        .first()
        .ok_or_else(|| eyre!("empty gkr circuit layer"))?;
    let group_stage_masks = first_layer_output_group_stage_masks(composed_cs, circuit)?;
    let mut point_sources = vec![0usize; first_layer.out_sel_and_eval_exprs.len()];
    if let Some([left, right, origin]) = first_layer.rotation_selector_group_indices() {
        point_sources[left] = 1;
        point_sources[right] = 2;
        point_sources[origin] = 3;
    }
    if let Some([x, y, slope, x3, y3]) = first_layer.ecc_bridge_group_indices() {
        point_sources[x] = 4;
        point_sources[y] = 4;
        point_sources[slope] = 5;
        point_sources[x3] = 6;
        point_sources[y3] = 6;
    }
    let cs = &composed_cs.zkvm_v1_css;
    let distinct_rw_selectors =
        cs.r_selector.is_some() && cs.w_selector.is_some() && cs.r_selector != cs.w_selector;

    first_layer
        .out_sel_and_eval_exprs
        .iter()
        .zip_eq(group_stage_masks.iter())
        .enumerate()
        .map(|(selector_idx, ((selector, _), stage_mask))| {
            let (kind, ordered_sparse_num_vars, sparse_indices, wit_id) =
                selector_shape_metadata(selector)?;
            let context_mode = if stage_mask.contains(GkrOutputStageMask::TOWER)
                && distinct_rw_selectors
                && matches!(selector, gkr_iop::selector::SelectorType::Prefix(_))
            {
                if cs.r_selector.as_ref() == Some(selector) {
                    SelectorContextMode::Read
                } else if cs.w_selector.as_ref() == Some(selector) {
                    SelectorContextMode::Write
                } else {
                    SelectorContextMode::Total
                }
            } else {
                SelectorContextMode::Total
            };

            Ok(SelectorMetadata {
                selector_idx,
                kind,
                point_source: point_sources[selector_idx],
                eval_idx: first_layer.n_witin + first_layer.n_fixed + wit_id as usize,
                context_mode,
                ordered_sparse_num_vars,
                sparse_indices,
            })
        })
        .collect()
}

fn selector_shape_metadata(
    selector: &gkr_iop::selector::SelectorType<RecursionField>,
) -> Result<(usize, usize, Vec<usize>, multilinear_extensions::WitnessId)> {
    use gkr_iop::selector::SelectorType;
    let (kind, ordered_sparse_num_vars, sparse_indices, expr) = match selector {
        SelectorType::None => bail!("SelectorType::None is not supported in recursion-v2 main"),
        SelectorType::Whole(expr) => (0, 0, Vec::new(), expr),
        SelectorType::Prefix(expr) => (1, 0, Vec::new(), expr),
        SelectorType::OrderedSparse {
            num_vars,
            indices,
            expression,
        } => (2, *num_vars, indices.clone(), expression),
        SelectorType::QuarkBinaryTreeLessThan(expr) => (3, 0, Vec::new(), expr),
    };
    let Expression::StructuralWitIn(wit_id, _) = expr else {
        bail!("selector expression must be StructuralWitIn");
    };
    Ok((kind, ordered_sparse_num_vars, sparse_indices, *wit_id))
}

#[derive(Clone, Copy, Default)]
struct GkrOutputStageMask(u8);

impl GkrOutputStageMask {
    const TOWER: Self = Self(1 << 0);
    const ECC: Self = Self(1 << 1);
    const ROTATION: Self = Self(1 << 2);
    const ZERO: Self = Self(1 << 3);

    const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }
}

fn first_layer_output_group_stage_masks(
    composed_cs: &ceno_zkvm::structs::ComposedConstrainSystem<RecursionField>,
    circuit: &gkr_iop::gkr::GKRCircuit<RecursionField>,
) -> Result<Vec<GkrOutputStageMask>> {
    let first_layer = circuit
        .layers
        .first()
        .ok_or_else(|| eyre!("empty gkr circuit layer"))?;
    let mut group_masks = vec![GkrOutputStageMask::ZERO; first_layer.out_sel_and_eval_exprs.len()];

    if let Some(rotation_groups) = first_layer.rotation_selector_group_indices() {
        for group_idx in rotation_groups {
            let Some(mask) = group_masks.get_mut(group_idx) else {
                bail!("rotation selector group index {group_idx} out of range");
            };
            *mask = GkrOutputStageMask::ROTATION;
        }
    }
    if let Some(ecc_groups) = first_layer.ecc_bridge_group_indices() {
        for group_idx in ecc_groups {
            let Some(mask) = group_masks.get_mut(group_idx) else {
                bail!("ecc selector group index {group_idx} out of range");
            };
            *mask = GkrOutputStageMask::ECC;
        }
    }

    let tower_outputs = tower_output_count(composed_cs);
    let mut seen_tower_outputs = 0usize;
    for (group_mask, (_, outputs)) in group_masks
        .iter_mut()
        .zip(first_layer.out_sel_and_eval_exprs.iter())
    {
        if seen_tower_outputs >= tower_outputs {
            break;
        }
        *group_mask = group_mask.union(GkrOutputStageMask::TOWER);
        seen_tower_outputs += outputs.len();
    }
    if seen_tower_outputs < tower_outputs {
        bail!(
            "failed to cover all tower outputs: layer={}, seen_tower_outputs={}, tower_outputs={}",
            first_layer.name,
            seen_tower_outputs,
            tower_outputs
        );
    }

    Ok(group_masks)
}

fn tower_output_count(
    composed_cs: &ceno_zkvm::structs::ComposedConstrainSystem<RecursionField>,
) -> usize {
    let cs = &composed_cs.zkvm_v1_css;
    let num_reads = cs.r_expressions.len() + cs.r_table_expressions.len();
    let num_writes = cs.w_expressions.len() + cs.w_table_expressions.len();
    let num_lk_num = cs.lk_table_expressions.len();
    let num_lk_den = if !cs.lk_table_expressions.is_empty() {
        cs.lk_table_expressions.len()
    } else {
        cs.lk_expressions.len()
    };
    num_reads + num_writes + num_lk_num + num_lk_den
}

impl AirModule for ProofShapeModule {
    fn num_airs(&self) -> usize {
        3
    }

    fn airs<SC: StarkProtocolConfig<F = F>>(&self) -> Vec<AirRef<SC>> {
        let proof_shape_air = ProofShapeAir::<4, 8> {
            per_air: self.per_air.clone(),
            idx_encoder: self.idx_encoder.clone(),
            range_bus: self.range_bus,
            permutation_bus: self.permutation_bus,
            starting_tidx_bus: self.starting_tidx_bus,
            lookup_challenge_bus: self.bus_inventory.lookup_challenge_bus,
            fraction_folder_input_bus: self.bus_inventory.fraction_folder_input_bus,
            expression_claim_n_max_bus: self.bus_inventory.expression_claim_n_max_bus,
            tower_module_bus: self.bus_inventory.tower_module_bus,
            air_presence_bus: self.bus_inventory.air_presence_bus,
            air_shape_bus: self.bus_inventory.air_shape_bus,
            hyperdim_bus: self.bus_inventory.hyperdim_bus,
            lifted_heights_bus: self.bus_inventory.lifted_heights_bus,
            transcript_bus: self.bus_inventory.transcript_bus,
            forked_transcript_bus: self.bus_inventory.forked_transcript_bus,
            fork_final_sample_bus: self.bus_inventory.fork_final_sample_bus,
            n_lift_bus: self.bus_inventory.n_lift_bus,
            main_selector_shape_bus: self.bus_inventory.main_selector_shape_bus,
            main_selector_sparse_index_shape_bus: self
                .bus_inventory
                .main_selector_sparse_index_shape_bus,
        };
        let pvs_air = PublicValuesAir {
            public_values_bus: self.bus_inventory.public_values_bus,
            num_pvs_bus: self.num_pvs_bus,
            transcript_bus: self.bus_inventory.transcript_bus,
            continuations_enabled: self.continuations_enabled,
            public_values_start_tidx: self.public_values_start_tidx,
        };
        let range_checker = RangeCheckerAir::<8> {
            bus: self.range_bus,
        };
        vec![
            Arc::new(proof_shape_air) as AirRef<_>,
            Arc::new(pvs_air) as AirRef<_>,
            Arc::new(range_checker) as AirRef<_>,
        ]
    }
}

impl<SC: StarkProtocolConfig<F = F>> TraceGenModule<GlobalCtxCpu, CpuBackend<SC>>
    for ProofShapeModule
{
    // (pow_checker, external_range_checks)
    type ModuleSpecificCtx<'a> = (
        Arc<PowerCheckerCpuTraceGenerator<2, POW_CHECKER_HEIGHT>>,
        &'a [usize],
    );

    #[tracing::instrument(skip_all)]
    fn generate_proving_ctxs(
        &self,
        child_vk: &RecursionVk,
        proofs: &[RecursionProof],
        preflights: &[Preflight],
        ctx: &<Self as TraceGenModule<GlobalCtxCpu, CpuBackend<SC>>>::ModuleSpecificCtx<'_>,
        required_heights: Option<&[usize]>,
    ) -> Option<Vec<AirProvingContext<CpuBackend<SC>>>> {
        let pow_checker = &ctx.0;
        let external_range_checks = ctx.1;

        let range_checker = Arc::new(RangeCheckerCpuTraceGenerator::<8>::default());
        let proof_shape = proof_shape::ProofShapeChip::<4, 8>::new(
            self.idx_encoder.clone(),
            Arc::new(self.per_air.clone()),
            range_checker.clone(),
            pow_checker.clone(),
        );
        let chips = [
            ProofShapeModuleChip::ProofShape(proof_shape),
            ProofShapeModuleChip::PublicValues,
        ];
        let ctx = (child_vk, proofs, preflights);
        let mut ctxs: Vec<_> = chips
            .par_iter()
            .map(|chip| {
                chip.generate_proving_ctx(
                    &ctx,
                    required_heights.and_then(|heights| heights.get(chip.index()).copied()),
                )
            })
            .collect::<Vec<_>>()
            .into_iter()
            .collect::<Option<Vec<_>>>()?;

        for &value in external_range_checks {
            range_checker.add_count(value);
        }
        ctxs.push(AirProvingContext::simple_no_pis(
            range_checker.generate_trace_row_major(),
        ));
        Some(ctxs)
    }
}

#[allow(dead_code)]
fn zero_air_ctx<SC: StarkProtocolConfig<F = F>>(
    height: usize,
    width: usize,
) -> AirProvingContext<CpuBackend<SC>> {
    let rows = height.max(1);
    let cols = width.max(1);
    let matrix = RowMajorMatrix::new(vec![F::ZERO; rows * cols], cols);
    AirProvingContext::simple_no_pis(matrix)
}

#[allow(dead_code)]
#[derive(strum_macros::Display, strum::EnumDiscriminants)]
#[strum_discriminants(repr(usize))]
enum ProofShapeModuleChip {
    ProofShape(proof_shape::ProofShapeChip<4, 8>),
    PublicValues,
}

impl ProofShapeModuleChip {
    fn index(&self) -> usize {
        ProofShapeModuleChipDiscriminants::from(self) as usize
    }
}

impl RowMajorChip<F> for ProofShapeModuleChip {
    type Ctx<'a> = (&'a RecursionVk, &'a [RecursionProof], &'a [Preflight]);

    #[tracing::instrument(
        name = "wrapper.generate_trace",
        level = "trace",
        skip_all,
        fields(air = %self)
    )]
    fn generate_trace(
        &self,
        ctx: &Self::Ctx<'_>,
        required_height: Option<usize>,
    ) -> Option<RowMajorMatrix<F>> {
        match self {
            ProofShapeModuleChip::ProofShape(chip) => chip.generate_trace(ctx, required_height),
            ProofShapeModuleChip::PublicValues => {
                pvs::PublicValuesTraceGenerator.generate_trace(ctx, required_height)
            }
        }
    }
}

#[cfg(feature = "cuda")]
mod cuda_tracegen {
    use openvm_cuda_backend::{GpuBackend, data_transporter::transport_matrix_h2d_row};
    use openvm_cuda_common::stream::GpuDeviceCtx;

    use super::*;
    use crate::cuda::{
        GlobalCtxGpu, preflight::PreflightGpu, proof::ProofGpu, vk::VerifyingKeyGpu,
    };
    use recursion_circuit::primitives::range::RangeCheckerCpuTraceGenerator;

    impl TraceGenModule<GlobalCtxGpu, GpuBackend> for ProofShapeModule {
        type ModuleSpecificCtx<'a> = (
            Arc<PowerCheckerCpuTraceGenerator<2, POW_CHECKER_HEIGHT>>,
            &'a [usize],
        );

        #[tracing::instrument(skip_all)]
        fn generate_proving_ctxs(
            &self,
            child_vk: &VerifyingKeyGpu,
            proofs: &[ProofGpu],
            preflights: &[PreflightGpu],
            ctx: &<Self as TraceGenModule<GlobalCtxGpu, GpuBackend>>::ModuleSpecificCtx<'_>,
            required_heights: Option<&[usize]>,
        ) -> Option<Vec<AirProvingContext<GpuBackend>>> {
            let device_ctx = GpuDeviceCtx::for_current_device().ok()?;
            let pow_checker = &ctx.0;
            let external_range_checks = ctx.1;
            let proofs_cpu = proofs
                .iter()
                .map(|proof| proof.cpu.clone())
                .collect::<Vec<_>>();
            let preflights_cpu = preflights
                .iter()
                .map(|preflight| preflight.cpu.clone())
                .collect::<Vec<_>>();

            let range_checker = Arc::new(RangeCheckerCpuTraceGenerator::<8>::default());
            let proof_shape = proof_shape::ProofShapeChip::<4, 8>::new(
                self.idx_encoder.clone(),
                Arc::new(self.per_air.clone()),
                range_checker.clone(),
                pow_checker.clone(),
            );
            let cpu_ctx = (
                &child_vk.cpu,
                proofs_cpu.as_slice(),
                preflights_cpu.as_slice(),
            );
            let proof_shape_chip = ProofShapeModuleChip::ProofShape(proof_shape);
            // TODO(cuda-tracegen): replace this CPU fallback with a Ceno-specific
            // proof-shape kernel. The OpenVM proof-shape kernel has incompatible columns.
            let proof_shape_trace = proof_shape_chip.generate_trace(
                &cpu_ctx,
                required_heights.and_then(|heights| heights.get(proof_shape_chip.index()).copied()),
            )?;
            let mut ctxs = vec![AirProvingContext::simple_no_pis(
                transport_matrix_h2d_row(&proof_shape_trace, &device_ctx).ok()?,
            )];

            ctxs.push(
                pvs::cuda::PublicValuesGpuTraceGenerator.generate_proving_ctx(
                    &(proofs, preflights),
                    required_heights.and_then(|heights| heights.get(1).copied()),
                )?,
            );

            for &value in external_range_checks {
                range_checker.add_count(value);
            }
            let range_trace = range_checker.generate_trace_row_major();
            ctxs.push(AirProvingContext::simple_no_pis(
                transport_matrix_h2d_row(&range_trace, &device_ctx).ok()?,
            ));
            Some(ctxs)
        }
    }
}
