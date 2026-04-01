use std::sync::Arc;

use itertools::Itertools;
use openvm_circuit_primitives::encoder::Encoder;
use openvm_cpu_backend::CpuBackend;
use openvm_stark_backend::{
    AirRef, FiatShamirTranscript, StarkProtocolConfig, TranscriptHistory,
    keygen::types::VerifierSinglePreprocessedData, p3_maybe_rayon::prelude::*,
    prover::AirProvingContext,
};
use openvm_stark_sdk::config::baby_bear_poseidon2::{
    BabyBearPoseidon2Config, DIGEST_SIZE, Digest, F,
};
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;

use crate::{
    proof_shape::{
        bus::{NumPublicValuesBus, ProofShapePermutationBus, StartingTidxBus},
        proof_shape::ProofShapeAir,
        pvs::PublicValuesAir,
    },
    system::{
        AirModule, BusIndexManager, BusInventory, GlobalCtxCpu, POW_CHECKER_HEIGHT, Preflight,
        RecursionProof, RecursionVk, TraceGenModule, TraceVData,
    },
    tracegen::{ModuleChip, RowMajorChip},
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
    main_width: usize,
    cached_widths: Vec<usize>,
    num_read_count: usize,
    num_write_count: usize,
    num_logup_count: usize,
    preprocessed_width: Option<usize>,
    preprocessed_data: Option<VerifierSinglePreprocessedData<Digest>>,
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
    min_cached_idx: usize,
    max_cached: usize,
    commit_mult: usize,

    // Module sends extra public values message for use outside of verifier
    // sub-circuit if true
    continuations_enabled: bool,
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

        let min_cached_idx = 0;
        let _min_cached = 1;
        let max_cached = 2;

        let per_air = extract_air_metadata_from_vk(child_vk, max_cached);

        let range_bus = bus_inventory.range_checker_bus;
        Self {
            per_air,
            bus_inventory,
            range_bus,
            permutation_bus: ProofShapePermutationBus::new(b.new_bus_idx()),
            starting_tidx_bus: StartingTidxBus::new(b.new_bus_idx()),
            num_pvs_bus: NumPublicValuesBus::new(b.new_bus_idx()),
            idx_encoder,
            min_cached_idx,
            max_cached,
            commit_mult: 100,
            continuations_enabled,
        }
    }

    #[tracing::instrument(level = "trace", skip_all)]
    pub fn run_preflight_with_verifier<TS>(
        &self,
        child_vk: &RecursionVk,
        proof: &RecursionProof,
        preflight: &mut Preflight,
        ts: &mut TS,
        verifier: &crate::circuit::inner::verifier::VerifierModule,
    ) where
        TS: FiatShamirTranscript<BabyBearPoseidon2Config> + TranscriptHistory,
    {
        let _ = self;

        // Verifier preprocess: absorb raw public input polynomials.
        for raw_pi in &proof.raw_pi {
            for &value in raw_pi {
                ts.observe(value);
            }
        }

        // Fixed commitment observations (fixed_commit, fixed_no_omc_init_commit)
        // are handled by VerifierModule, which owns the CommitAir constraints.
        verifier.observe_fixed_commits(child_vk, ts);

        // Build per-air shape metadata from present chip proofs.
        let mut sorted_trace_vdata = proof
            .chip_proofs
            .iter()
            .map(|(&chip_idx, chip_instances)| {
                let num_instances: usize = chip_instances
                    .iter()
                    .flat_map(|instance| instance.num_instances.iter())
                    .copied()
                    .sum();
                let padded = num_instances.max(1).next_power_of_two();
                let log_height = padded.ilog2() as usize;
                (chip_idx, TraceVData { log_height })
            })
            .collect_vec();
        sorted_trace_vdata.sort_by_key(|(air_idx, v)| (usize::MAX - v.log_height, *air_idx));
        preflight.proof_shape.sorted_trace_vdata = sorted_trace_vdata;
        preflight.proof_shape.l_skip = 0;

        let mut current_tidx = crate::utils::TranscriptLabel::Riscv.field_len();
        let mut current_cidx = 1usize;
        let mut starting_tidx = vec![0usize; child_vk.circuit_vks.len()];
        let mut starting_cidx = vec![0usize; child_vk.circuit_vks.len()];
        let mut pvs_tidx = Vec::new();
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
            starting_cidx[air_idx] = current_cidx;

            current_cidx += usize::from(metadata.preprocessed_data.is_some());
            current_cidx += metadata.cached_widths.len();

            if !metadata.is_required {
                current_tidx += 1;
            }

            if is_present {
                if metadata.preprocessed_data.is_some() {
                    current_tidx += DIGEST_SIZE;
                } else {
                    current_tidx += 1;
                }

                for cached_width in &metadata.cached_widths {
                    if *cached_width != 0 {
                        current_tidx += DIGEST_SIZE;
                    }
                }

                if metadata.num_public_values != 0 {
                    pvs_tidx.push(current_tidx);
                    current_tidx += metadata.num_public_values;
                }
            }
        }

        preflight.proof_shape.starting_tidx = starting_tidx;
        preflight.proof_shape.starting_cidx = starting_cidx;
        preflight.proof_shape.pvs_tidx = pvs_tidx;
        preflight.proof_shape.post_tidx = current_tidx;
        preflight.proof_shape.n_max = n_max;
        preflight.proof_shape.n_logup = preflight
            .gkr
            .chips
            .iter()
            .filter(|entry| proof.chip_proofs.contains_key(&entry.chip_idx))
            .map(|entry| entry.tower_replay.layers.len())
            .max()
            .unwrap_or(0);

        // Verifier preprocess: absorb fixed commitment.
        // Mirrors v1 verifier order: fixed_commit → (chip_idx, num_instance) → witin_commit → α, β
        // TODO(recursion-proof-bridge): absorb fixed commitment digest + log2_max_codeword_size
        // once basefold module is integrated. See v1: PCS::write_commitment(fixed_commit, transcript)

        // Verifier preprocess: absorb (circuit_idx, num_instance...) for all chip proofs.
        for (&chip_idx, chip_instances) in &proof.chip_proofs {
            ts.observe(F::from_usize(chip_idx));
            for num_instance in chip_instances
                .iter()
                .flat_map(|instance| &instance.num_instances)
            {
                ts.observe(F::from_usize(*num_instance));
            }
        }

        // TODO(recursion-proof-bridge): absorb witness commitment digest + log2_max_codeword_size
        // once basefold module is integrated. See v1: PCS::write_commitment(&witin_commit, transcript)
        // Witness commitment observation is handled by VerifierModule.
        verifier.observe_witness_commit(proof, ts);

        preflight.proof_shape.alpha_tidx = ts.len();
        let _alpha = FiatShamirTranscript::<BabyBearPoseidon2Config>::sample_ext(ts);
        preflight.proof_shape.beta_tidx = ts.len();
        let _beta = FiatShamirTranscript::<BabyBearPoseidon2Config>::sample_ext(ts);
        preflight.proof_shape.fork_start_tidx = ts.len();

        let _ = child_vk;
    }

    #[allow(dead_code)]
    fn placeholder_air_widths(&self) -> Vec<usize> {
        let proof_shape_width = proof_shape::ProofShapeCols::<u8, 4>::width()
            + self.idx_encoder.width()
            + self.max_cached * DIGEST_SIZE;
        let pvs_width = pvs::PublicValuesCols::<u8>::width();
        let range_width = RangeCheckerCols::<u8>::width();
        // TODO(recursion-proof-bridge): replace proof-shape module placeholder contexts with
        // real tracegen so RangeCheckerAir rows are semantically valid, not only width-correct.
        vec![proof_shape_width, pvs_width, range_width]
    }
}

fn extract_rwlk_counts(child_vk: &RecursionVk, expected_len: usize) -> Vec<(usize, usize, usize)> {
    (0..expected_len)
        .map(|idx| {
            child_vk
                .circuit_index_to_name
                .get(&idx)
                .and_then(|name| child_vk.circuit_vks.get(name))
                .map(|circuit_vk| {
                    let cs = circuit_vk.get_cs();
                    (cs.num_reads(), cs.num_writes(), cs.num_lks())
                })
                .unwrap_or_else(|| {
                    (0, 0, 0)
                })
        })
        .collect()
}

fn extract_air_metadata_from_vk(child_vk: &RecursionVk, max_cached: usize) -> Vec<AirMetadata> {
    let rwlk_counts = extract_rwlk_counts(child_vk, child_vk.circuit_vks.len());
    (0..child_vk.circuit_vks.len())
        .map(|idx| {
            let (num_read_count, num_write_count, num_logup_count) =
                rwlk_counts.get(idx).copied().unwrap_or((0, 0, 0));

            let num_public_values = child_vk
                .circuit_index_to_name
                .get(&idx)
                .and_then(|name| child_vk.circuit_vks.get(name))
                .map(|circuit_vk| circuit_vk.get_cs().instance_openings().len())
                .unwrap_or(0);

            AirMetadata {
                is_required: false,
                num_public_values,
                main_width: 0,
                cached_widths: vec![0; max_cached],
                num_read_count,
                num_write_count,
                num_logup_count,
                preprocessed_width: None,
                preprocessed_data: None,
            }
        })
        .collect_vec()
}

impl AirModule for ProofShapeModule {
    fn num_airs(&self) -> usize {
        3
    }

    fn airs<SC: StarkProtocolConfig<F = F>>(&self) -> Vec<AirRef<SC>> {
        let proof_shape_air = ProofShapeAir::<4, 8> {
            per_air: self.per_air.clone(),
            min_cached_idx: self.min_cached_idx,
            max_cached: self.max_cached,
            commit_mult: self.commit_mult,
            idx_encoder: self.idx_encoder.clone(),
            range_bus: self.range_bus,
            permutation_bus: self.permutation_bus,
            starting_tidx_bus: self.starting_tidx_bus,
            num_pvs_bus: self.num_pvs_bus,
            fraction_folder_input_bus: self.bus_inventory.fraction_folder_input_bus,
            expression_claim_n_max_bus: self.bus_inventory.expression_claim_n_max_bus,
            tower_module_bus: self.bus_inventory.tower_module_bus,
            air_shape_bus: self.bus_inventory.air_shape_bus,
            hyperdim_bus: self.bus_inventory.hyperdim_bus,
            lifted_heights_bus: self.bus_inventory.lifted_heights_bus,
            // commitments_bus: self.bus_inventory.commitments_bus,
            transcript_bus: self.bus_inventory.transcript_bus,
            forked_transcript_bus: self.bus_inventory.forked_transcript_bus,
            n_lift_bus: self.bus_inventory.n_lift_bus,
            cached_commit_bus: self.bus_inventory.cached_commit_bus,
            continuations_enabled: self.continuations_enabled,
        };
        let pvs_air = PublicValuesAir {
            public_values_bus: self.bus_inventory.public_values_bus,
            num_pvs_bus: self.num_pvs_bus,
            transcript_bus: self.bus_inventory.transcript_bus,
            continuations_enabled: self.continuations_enabled,
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
        let cidx_deltas = self
            .per_air
            .iter()
            .map(|metadata| {
                usize::from(metadata.preprocessed_data.is_some()) + metadata.cached_widths.len()
            })
            .collect();

        let range_checker = Arc::new(RangeCheckerCpuTraceGenerator::<8>::default());
        let proof_shape = proof_shape::ProofShapeChip::<4, 8>::new(
            self.idx_encoder.clone(),
            self.min_cached_idx,
            self.max_cached,
            cidx_deltas,
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
    use openvm_cuda_backend::{GpuBackend, base::DeviceMatrix};

    use super::*;
    use crate::cuda::{
        GlobalCtxGpu, preflight::PreflightGpu, proof::ProofGpu, vk::VerifyingKeyGpu,
    };

    impl TraceGenModule<GlobalCtxGpu, GpuBackend> for ProofShapeModule {
        type ModuleSpecificCtx<'a> = ();

        #[tracing::instrument(skip_all)]
        fn generate_proving_ctxs(
            &self,
            child_vk: &VerifyingKeyGpu,
            proofs: &[ProofGpu],
            preflights: &[PreflightGpu],
            _ctx: &<Self as TraceGenModule<GlobalCtxGpu, GpuBackend>>::ModuleSpecificCtx<'_>,
            required_heights: Option<&[usize]>,
        ) -> Option<Vec<AirProvingContext<GpuBackend>>> {
            let _ = (child_vk, proofs, preflights);
            let widths = self.placeholder_air_widths();
            let air_count = required_heights
                .map(|heights| heights.len())
                .unwrap_or_else(|| self.num_airs());
            Some(
                (0..air_count)
                    .map(|idx| {
                        let height = required_heights
                            .and_then(|heights| heights.get(idx).copied())
                            .unwrap_or(1);
                        let width = widths.get(idx).copied().unwrap_or(1);
                        zero_gpu_ctx(height, width)
                    })
                    .collect(),
            )
        }
    }

    fn zero_gpu_ctx(height: usize, width: usize) -> AirProvingContext<GpuBackend> {
        let rows = height.max(1);
        let cols = width.max(1);
        let trace = DeviceMatrix::with_capacity(rows, cols);
        AirProvingContext::simple_no_pis(trace)
    }
}
