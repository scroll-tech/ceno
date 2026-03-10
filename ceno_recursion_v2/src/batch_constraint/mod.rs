use std::sync::Arc;

use openvm_stark_backend::keygen::types::MultiStarkVerifyingKey;
use openvm_stark_sdk::config::baby_bear_poseidon2::BabyBearPoseidon2Config;
use recursion_circuit::{
    bus::{BatchConstraintModuleBus, TranscriptBus},
    system::{BusIndexManager, BusInventory},
};

pub use recursion_circuit::batch_constraint::expr_eval::CachedTraceRecord;

/// Thin wrapper around the upstream BatchConstraintModule so we can reference
/// transcript and bc-module buses locally without copying the entire module.
pub struct BatchConstraintModule {
    pub transcript_bus: TranscriptBus,
    pub gkr_claim_bus: BatchConstraintModuleBus,
    inner: Arc<recursion_circuit::batch_constraint::BatchConstraintModule>,
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
        }
    }
}
