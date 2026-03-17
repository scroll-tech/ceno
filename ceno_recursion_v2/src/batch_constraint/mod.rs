use std::sync::Arc;

use openvm_cpu_backend::CpuBackend;
use openvm_stark_backend::{
    StarkEngine, StarkProtocolConfig,
    prover::{CommittedTraceData, TraceCommitter},
};
use openvm_stark_sdk::config::baby_bear_poseidon2::F;

use crate::system::{RecursionVk, convert_vk_from_zkvm};

pub mod expression_claim;
pub mod expr_eval;
pub mod bus {
    pub use recursion_circuit::batch_constraint::bus::*;
    use p3_field::PrimeCharacteristicRing;

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
    let child_vk = convert_vk_from_zkvm(child_vk);
    expr_eval::symbolic_expression::build_cached_trace_record(child_vk.as_ref())
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
