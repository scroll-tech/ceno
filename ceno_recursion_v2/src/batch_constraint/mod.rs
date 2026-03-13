use std::sync::Arc;

use openvm_poseidon2_air::POSEIDON2_WIDTH;
use openvm_stark_backend::{
    AirRef, FiatShamirTranscript, StarkEngine, StarkProtocolConfig, TranscriptHistory,
    keygen::types::MultiStarkVerifyingKey,
    prover::{AirProvingContext, ColMajorMatrix, CommittedTraceData, CpuBackend},
};
use openvm_stark_sdk::config::baby_bear_poseidon2::{BabyBearPoseidon2Config, F};
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;
use recursion_circuit::{
    bus::{BatchConstraintModuleBus, TranscriptBus},
    primitives::pow::PowerCheckerCpuTraceGenerator,
    system::{AirModule, BusIndexManager, BusInventory},
};

pub use recursion_circuit::batch_constraint::expr_eval::CachedTraceRecord;

use crate::system::{
    GlobalCtxCpu, POW_CHECKER_HEIGHT, Preflight, RecursionProof, RecursionVk, TraceGenModule,
    convert_vk_from_zkvm,
};

pub(crate) const LOCAL_SYMBOLIC_EXPRESSION_AIR_IDX: usize = 0;

/// Thin wrapper around the upstream BatchConstraintModule so we can reference
/// transcript and bc-module buses locally without copying the entire module.
pub struct BatchConstraintModule {
    pub transcript_bus: TranscriptBus,
    pub gkr_claim_bus: BatchConstraintModuleBus,
    inner: Arc<recursion_circuit::batch_constraint::BatchConstraintModule>,
    has_cached: bool,
}

impl BatchConstraintModule {
    pub fn new(
        child_vk: &MultiStarkVerifyingKey<BabyBearPoseidon2Config>,
        b: &mut BusIndexManager,
        bus_inventory: BusInventory,
        max_num_proofs: usize,
        has_cached: bool,
    ) -> Self {
        let inner = recursion_circuit::batch_constraint::BatchConstraintModule::new(
            child_vk,
            b,
            bus_inventory.clone(),
            max_num_proofs,
            has_cached,
        );
        Self {
            transcript_bus: bus_inventory.transcript_bus,
            gkr_claim_bus: bus_inventory.bc_module_bus,
            inner: Arc::new(inner),
            has_cached,
        }
    }

    pub fn has_cached(&self) -> bool {
        self.has_cached
    }

    pub fn run_preflight<TS>(
        &self,
        child_vk: &RecursionVk,
        proof: &RecursionProof,
        preflight: &mut Preflight,
        ts: &mut TS,
    ) where
        TS: FiatShamirTranscript<BabyBearPoseidon2Config>
            + TranscriptHistory<F = F, State = [F; POSEIDON2_WIDTH]>,
    {
        let _ = (self, child_vk, proof, preflight);
        ts.observe(F::ZERO);
    }

    pub fn cached_trace_record(&self, child_vk: &RecursionVk) -> CachedTraceRecord {
        let child_vk = convert_vk_from_zkvm(child_vk);
        self.inner.cached_trace_record(child_vk.as_ref())
    }

    pub fn commit_child_vk<E, SC>(
        &self,
        engine: &E,
        child_vk: &RecursionVk,
    ) -> CommittedTraceData<CpuBackend<SC>>
    where
        E: StarkEngine<SC = SC, PB = CpuBackend<SC>>,
        SC: StarkProtocolConfig<F = F>,
    {
        let child_vk = convert_vk_from_zkvm(child_vk);
        self.inner.commit_child_vk(engine, child_vk.as_ref())
    }
}

impl AirModule for BatchConstraintModule {
    fn num_airs(&self) -> usize {
        self.inner.num_airs()
    }

    fn airs<SC: StarkProtocolConfig<F = F>>(&self) -> Vec<AirRef<SC>> {
        self.inner.airs()
    }
}

impl<SC: StarkProtocolConfig<F = F>> TraceGenModule<GlobalCtxCpu, CpuBackend<SC>>
    for BatchConstraintModule
{
    type ModuleSpecificCtx<'a> = (
        &'a Option<&'a CachedTraceRecord>,
        &'a Arc<PowerCheckerCpuTraceGenerator<2, POW_CHECKER_HEIGHT>>,
    );

    fn generate_proving_ctxs(
        &self,
        child_vk: &RecursionVk,
        proofs: &[RecursionProof],
        preflights: &[Preflight],
        ctx: &<Self as TraceGenModule<GlobalCtxCpu, CpuBackend<SC>>>::ModuleSpecificCtx<'_>,
        required_heights: Option<&[usize]>,
    ) -> Option<Vec<AirProvingContext<CpuBackend<SC>>>> {
        let _ = (self, child_vk, proofs, preflights, ctx);
        let num_airs = required_heights
            .map(|heights| heights.len())
            .unwrap_or_else(|| self.num_airs());
        Some(
            (0..num_airs)
                .map(|idx| {
                    let height = required_heights
                        .and_then(|heights| heights.get(idx).copied())
                        .unwrap_or(1);
                    zero_air_ctx(height)
                })
                .collect(),
        )
    }
}

fn zero_air_ctx<SC: StarkProtocolConfig<F = F>>(
    height: usize,
) -> AirProvingContext<CpuBackend<SC>> {
    let rows = height.max(1);
    let matrix = RowMajorMatrix::new(vec![F::ZERO; rows], 1);
    AirProvingContext::simple_no_pis(ColMajorMatrix::from_row_major(&matrix))
}
