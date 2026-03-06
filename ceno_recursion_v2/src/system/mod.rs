use crate::gkr::GkrModule;
pub use recursion_circuit::{
    batch_constraint::BatchConstraintModule,
    proof_shape::ProofShapeModule,
    system::{
        AirModule, BusIndexManager, BusInventory, GkrPreflight, GlobalCtxCpu, Preflight,
        TraceGenModule,
    },
    transcript::TranscriptModule,
};

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
