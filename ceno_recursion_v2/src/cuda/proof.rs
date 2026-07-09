use openvm_cuda_common::d_buffer::DeviceBuffer;

use crate::system::{RecursionField, RecursionProof, RecursionVk};

use super::{to_device_or_nullptr, types::PublicValueData};

pub struct ProofGpu {
    pub cpu: RecursionProof,
    pub proof_shape: ProofShapeProofGpu,
    pub gkr: TowerProofGpu,
    pub batch_constraint: BatchConstraintProofGpu,
    pub stacking: StackingProofGpu,
    pub whir: WhirProofGpu,
}

pub struct ProofShapeProofGpu {
    pub public_values: DeviceBuffer<PublicValueData>,
}

pub struct TowerProofGpu {
    _dummy: usize,
}

pub struct BatchConstraintProofGpu {
    _dummy: usize,
}

pub struct StackingProofGpu {
    _dummy: usize,
}

pub struct WhirProofGpu {
    _dummy: usize,
}

impl ProofGpu {
    pub fn new(vk: &RecursionVk, proof: &RecursionProof) -> Self {
        ProofGpu {
            cpu: proof.clone(),
            proof_shape: Self::proof_shape(vk, proof),
            gkr: Self::gkr(proof),
            batch_constraint: Self::batch_constraint(proof),
            stacking: Self::stacking(proof),
            whir: Self::whir(proof),
        }
    }

    fn proof_shape(vk: &RecursionVk, proof: &RecursionProof) -> ProofShapeProofGpu {
        let num_airs = vk.circuit_vks.len();
        let mut public_values = Vec::new();
        for (air_idx, circuit_vk) in vk.circuit_vks.values().enumerate() {
            let instance_openings = &circuit_vk.get_cs().zkvm_v1_css.instance;
            let air_num_pvs = instance_openings.len();
            public_values.extend(
                instance_openings
                    .iter()
                    .enumerate()
                    .map(|(pv_idx, instance)| PublicValueData {
                        air_idx,
                        air_num_pvs,
                        num_airs,
                        pv_idx,
                        value: proof
                            .public_values
                            .query_by_index::<RecursionField>(instance.0),
                    }),
            );
        }
        ProofShapeProofGpu {
            public_values: to_device_or_nullptr(&public_values).unwrap(),
        }
    }

    fn gkr(_proof: &RecursionProof) -> TowerProofGpu {
        TowerProofGpu { _dummy: 0 }
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
