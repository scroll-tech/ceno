use openvm_cuda_backend::prelude::EF;
use openvm_cuda_common::d_buffer::DeviceBuffer;
use openvm_stark_sdk::config::baby_bear_poseidon2::Digest;

use crate::system::{Preflight, RecursionProof, RecursionVk};

use super::{
    to_device_or_nullptr,
    types::{TraceHeight, TraceMetadata},
};

#[derive(Debug)]
pub struct PreflightGpu {
    pub cpu: Preflight,
    pub transcript: TranscriptLog,
    pub proof_shape: ProofShapePreflightGpu,
    pub gkr: TowerPreflightGpu,
    pub batch_constraint: BatchConstraintPreflightGpu,
    pub stacking: StackingPreflightGpu,
    pub whir: WhirPreflightGpu,
}

#[derive(Debug, Clone, Default)]
pub struct TranscriptLog {
    _dummy: usize,
}

#[derive(Debug)]
pub struct ProofShapePreflightGpu {
    pub sorted_trace_heights: DeviceBuffer<TraceHeight>,
    pub sorted_trace_metadata: DeviceBuffer<TraceMetadata>,
    pub sorted_cached_commits: DeviceBuffer<Digest>,
    pub per_row_tidx: DeviceBuffer<usize>,
    pub pvs_tidx: DeviceBuffer<usize>,
    pub post_tidx: usize,
    pub num_present: usize,
    pub n_max: usize,
    pub n_logup: usize,
    pub final_cidx: usize,
    pub final_total_interactions: usize,
    pub main_commit: Digest,
}

#[derive(Debug, Clone, Default)]
pub struct TowerPreflightGpu {
    _dummy: usize,
}

#[derive(Debug)]
pub struct BatchConstraintPreflightGpu {
    pub sumcheck_rnd: DeviceBuffer<EF>,
}

#[derive(Debug)]
pub struct StackingPreflightGpu {
    pub sumcheck_rnd: DeviceBuffer<EF>,
}

#[derive(Debug, Clone, Default)]
pub struct WhirPreflightGpu {
    _dummy: usize,
}

impl PreflightGpu {
    pub fn new(vk: &RecursionVk, proof: &RecursionProof, preflight: &Preflight) -> Self {
        PreflightGpu {
            cpu: preflight.clone(),
            transcript: Self::transcript(preflight),
            proof_shape: Self::proof_shape(vk, proof, preflight),
            gkr: Self::gkr(preflight),
            batch_constraint: Self::batch_constraint(preflight),
            stacking: Self::stacking(preflight),
            whir: Self::whir(preflight),
        }
    }

    fn transcript(_preflight: &Preflight) -> TranscriptLog {
        TranscriptLog { _dummy: 0 }
    }

    fn proof_shape(
        _vk: &RecursionVk,
        _proof: &RecursionProof,
        _preflight: &Preflight,
    ) -> ProofShapePreflightGpu {
        let empty_heights: [TraceHeight; 0] = [];
        let empty_metadata: [TraceMetadata; 0] = [];
        let empty_commits: [Digest; 0] = [];
        let empty_indices: [usize; 0] = [];
        ProofShapePreflightGpu {
            sorted_trace_heights: to_device_or_nullptr(&empty_heights).unwrap(),
            sorted_trace_metadata: to_device_or_nullptr(&empty_metadata).unwrap(),
            sorted_cached_commits: to_device_or_nullptr(&empty_commits).unwrap(),
            per_row_tidx: to_device_or_nullptr(&empty_indices).unwrap(),
            pvs_tidx: to_device_or_nullptr(&empty_indices).unwrap(),
            post_tidx: 0,
            num_present: 0,
            n_max: 0,
            n_logup: 0,
            final_cidx: 0,
            final_total_interactions: 0,
            main_commit: Digest::default(),
        }
    }

    fn gkr(_preflight: &Preflight) -> TowerPreflightGpu {
        TowerPreflightGpu { _dummy: 0 }
    }

    fn batch_constraint(_preflight: &Preflight) -> BatchConstraintPreflightGpu {
        let empty: [EF; 0] = [];
        BatchConstraintPreflightGpu {
            sumcheck_rnd: to_device_or_nullptr(&empty).unwrap(),
        }
    }

    fn stacking(_preflight: &Preflight) -> StackingPreflightGpu {
        let empty: [EF; 0] = [];
        StackingPreflightGpu {
            sumcheck_rnd: to_device_or_nullptr(&empty).unwrap(),
        }
    }

    fn whir(_preflight: &Preflight) -> WhirPreflightGpu {
        WhirPreflightGpu { _dummy: 0 }
    }
}
