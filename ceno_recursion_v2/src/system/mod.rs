mod types;
pub mod frame;

pub use crate::proof_shape::ProofShapeModule;
pub use types::{RecursionField, RecursionPcs, RecursionVk};

use std::sync::Arc;

use openvm_poseidon2_air::POSEIDON2_WIDTH;
use openvm_stark_backend::{
    interaction::BusIndex,
    proof::Proof,
    prover::{AirProvingContext, CommittedTraceData, ProverBackend},
    AirRef, FiatShamirTranscript, StarkEngine, StarkProtocolConfig, TranscriptHistory,
};
use openvm_stark_sdk::config::baby_bear_poseidon2::{BabyBearPoseidon2Config, F};
use recursion_circuit::batch_constraint::expr_eval::CachedTraceRecord;

use crate::gkr::GkrModule;
pub use recursion_circuit::{
    batch_constraint::BatchConstraintModule,
    system::{
        AirModule, AggregationSubCircuit, BusIndexManager, BusInventory, CachedTraceCtx,
        GkrPreflight, GlobalCtxCpu, Preflight, ProofShapePreflight, TraceGenModule, VerifierConfig,
        VerifierExternalData,
    },
    transcript::TranscriptModule,
};

pub const POW_CHECKER_HEIGHT: usize = 32;

pub trait VerifierTraceGen<PB: ProverBackend, SC: StarkProtocolConfig<F = F>> {
    fn new(child_vk: Arc<RecursionVk>, config: VerifierConfig) -> Self;

    fn commit_child_vk<E: StarkEngine<SC = SC, PB = PB>>(
        &self,
        engine: &E,
        child_vk: &RecursionVk,
    ) -> CommittedTraceData<PB>;

    fn cached_trace_record(&self, child_vk: &RecursionVk) -> CachedTraceRecord;

    #[allow(clippy::ptr_arg)]
    fn generate_proving_ctxs<
        TS: FiatShamirTranscript<BabyBearPoseidon2Config>
            + TranscriptHistory<F = F, State = [F; POSEIDON2_WIDTH]>,
    >(
        &self,
        child_vk: &RecursionVk,
        cached_trace_ctx: CachedTraceCtx<PB>,
        proofs: &[Proof<BabyBearPoseidon2Config>],
        external_data: &mut VerifierExternalData<PB>,
        initial_transcript: TS,
    ) -> Option<Vec<AirProvingContext<PB>>>;

    fn generate_proving_ctxs_base<
        TS: FiatShamirTranscript<BabyBearPoseidon2Config>
            + TranscriptHistory<F = F, State = [F; POSEIDON2_WIDTH]>,
    >(
        &self,
        child_vk: &RecursionVk,
        cached_trace_ctx: CachedTraceCtx<PB>,
        proofs: &[Proof<BabyBearPoseidon2Config>],
        initial_transcript: TS,
    ) -> Vec<AirProvingContext<PB>> {
        let poseidon2_compress_inputs = vec![];
        let range_check_inputs = vec![];

        let mut external_data = VerifierExternalData {
            poseidon2_compress_inputs: &poseidon2_compress_inputs,
            range_check_inputs: &range_check_inputs,
            required_heights: None,
            final_transcript_state: None,
        };

        self.generate_proving_ctxs::<TS>(
            child_vk,
            cached_trace_ctx,
            proofs,
            &mut external_data,
            initial_transcript,
        )
        .unwrap()
    }
}

/// The recursive verifier sub-circuit consists of multiple chips, grouped into **modules**.
///
/// This struct is stateful.
pub struct VerifierSubCircuit<const MAX_NUM_PROOFS: usize> {
    pub(crate) bus_inventory: BusInventory,
    pub(crate) bus_idx_manager: BusIndexManager,
    pub(crate) transcript: TranscriptModule,
    pub(crate) proof_shape: ProofShapeModule,
    pub(crate) gkr: GkrModule,
    pub(crate) batch_constraint: BatchConstraintModule,
}

impl<
        PB: ProverBackend,
        SC: StarkProtocolConfig<F = F>,
        const MAX_NUM_PROOFS: usize,
    > VerifierTraceGen<PB, SC> for VerifierSubCircuit<MAX_NUM_PROOFS>
{
    fn new(_child_vk: Arc<RecursionVk>, _config: VerifierConfig) -> Self {
        unimplemented!("VerifierSubCircuit::new placeholder")
    }

    fn commit_child_vk<E: StarkEngine<SC = SC, PB = PB>>(
        &self,
        _engine: &E,
        _child_vk: &RecursionVk,
    ) -> CommittedTraceData<PB> {
        unimplemented!("VerifierSubCircuit::commit_child_vk placeholder")
    }

    fn cached_trace_record(&self, _child_vk: &RecursionVk) -> CachedTraceRecord {
        unimplemented!("VerifierSubCircuit::cached_trace_record placeholder")
    }

    fn generate_proving_ctxs<
        TS: FiatShamirTranscript<BabyBearPoseidon2Config>
            + TranscriptHistory<F = F, State = [F; POSEIDON2_WIDTH]>,
    >(
        &self,
        _child_vk: &RecursionVk,
        _cached_trace_ctx: CachedTraceCtx<PB>,
        _proofs: &[Proof<BabyBearPoseidon2Config>],
        _external_data: &mut VerifierExternalData<PB>,
        _initial_transcript: TS,
    ) -> Option<Vec<AirProvingContext<PB>>> {
        unimplemented!("VerifierSubCircuit::generate_proving_ctxs placeholder")
    }
}
impl<const MAX_NUM_PROOFS: usize> AggregationSubCircuit for VerifierSubCircuit<MAX_NUM_PROOFS> {
    fn airs<SC: StarkProtocolConfig<F = F>>(&self) -> Vec<AirRef<SC>> {
        unimplemented!("VerifierSubCircuit::airs placeholder")
    }

    fn bus_inventory(&self) -> &BusInventory {
        &self.bus_inventory
    }

    fn next_bus_idx(&self) -> BusIndex {
        unimplemented!("VerifierSubCircuit::next_bus_idx placeholder")
    }

    fn max_num_proofs(&self) -> usize {
        MAX_NUM_PROOFS
    }
}
