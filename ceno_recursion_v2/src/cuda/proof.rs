use openvm_cuda_common::d_buffer::DeviceBuffer;

use crate::system::{RecursionProof, RecursionVk};

use super::{to_device_or_nullptr, types::PublicValueData};

#[derive(Debug)]
pub struct ProofGpu {
    pub cpu: RecursionProof,
    pub proof_shape: ProofShapeProofGpu,
    pub gkr: GkrProofGpu,
    pub batch_constraint: BatchConstraintProofGpu,
    pub stacking: StackingProofGpu,
    pub whir: WhirProofGpu,
}

#[derive(Debug)]
pub struct ProofShapeProofGpu {
    pub public_values: DeviceBuffer<PublicValueData>,
}

#[derive(Debug)]
pub struct GkrProofGpu {
    _dummy: usize,
}

#[derive(Debug)]
pub struct BatchConstraintProofGpu {
    _dummy: usize,
}

#[derive(Debug)]
pub struct StackingProofGpu {
    _dummy: usize,
}

#[derive(Debug)]
pub struct WhirProofGpu {
    _dummy: usize,
}

impl ProofGpu {
    pub fn new(_vk: &RecursionVk, proof: &RecursionProof) -> Self {
        ProofGpu {
            cpu: proof.clone(),
            proof_shape: Self::proof_shape(),
            gkr: Self::gkr(proof),
            batch_constraint: Self::batch_constraint(proof),
            stacking: Self::stacking(proof),
            whir: Self::whir(proof),
        }
    }

    fn proof_shape() -> ProofShapeProofGpu {
        let empty: [PublicValueData; 0] = [];
        ProofShapeProofGpu {
            public_values: to_device_or_nullptr(&empty).unwrap(),
        }
    }

    fn gkr(_proof: &RecursionProof) -> GkrProofGpu {
        GkrProofGpu { _dummy: 0 }
    }

    fn batch_constraint(_proof: &RecursionProof) -> BatchConstraintProofGpu {
        BatchConstraintProofGpu { _dummy: 0 }
    }

    fn stacking(_proof: &RecursionProof) -> StackingProofGpu {
        StackingProofGpu { _dummy: 0 }
    }

    fn whir(_proof: &RecursionProof) -> WhirProofGpu {
        WhirProofGpu { _dummy: 0 }
    }
}
