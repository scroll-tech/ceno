use std::sync::Arc;

use openvm_cpu_backend::CpuBackend;
use openvm_stark_backend::{
    StarkEngine, StarkProtocolConfig,
    prover::{CommittedTraceData, TraceCommitter},
};
use openvm_stark_sdk::config::baby_bear_poseidon2::F;

use crate::system::RecursionVk;

pub mod expr_eval;
pub mod expression_claim;
pub mod bus {
    use p3_field::PrimeCharacteristicRing;
    pub use recursion_circuit::batch_constraint::bus::*;

    #[repr(u8)]
    #[derive(Debug, Copy, Clone)]
    pub enum BatchConstraintInnerMessageType {
        R,
        Xi,
        Mu,
    }

    impl BatchConstraintInnerMessageType {
        pub fn to_field<T: PrimeCharacteristicRing>(self) -> T {
            T::from_u8(self as u8)
        }
    }
}

pub use expr_eval::CachedTraceRecord;

pub fn cached_trace_record(child_vk: &RecursionVk) -> CachedTraceRecord {
    expr_eval::symbolic_expression::build_cached_trace_record(child_vk)
}

pub fn commit_child_vk<E, SC>(
    engine: &E,
    child_vk: &RecursionVk,
) -> CommittedTraceData<CpuBackend<SC>>
where
    E: StarkEngine<SC = SC, PB = CpuBackend<SC>>,
    SC: StarkProtocolConfig<F = F>,
{
    let cached_trace = expr_eval::symbolic_expression::generate_symbolic_expr_cached_trace(
        &cached_trace_record(child_vk),
    );
    let (commitment, data) = engine.device().commit(&[&cached_trace]).unwrap();
    CommittedTraceData {
        commitment,
        data: Arc::new(data),
        trace: cached_trace,
    }
}
