#[cfg(test)]
mod prover_integration {
    use crate::{
        continuation::prover::{ChildVkKind, InnerCpuProver},
        system::utils::test_system_params_zero_pow,
    };
    use bincode;
    use ceno_zkvm::{scheme::ZKVMProof, structs::ZKVMVerifyingKey};
    use eyre::{Result, eyre};
    use mpcs::{Basefold, BasefoldRSParams};
    use openvm_stark_sdk::{
        config::baby_bear_poseidon2::{BabyBearPoseidon2CpuEngine, DuplexSponge},
        p3_baby_bear::BabyBear,
    };
    use p3::field::extension::BinomialExtensionField;
    use std::sync::Arc;

    type Engine = BabyBearPoseidon2CpuEngine<DuplexSponge>;
    type E = BinomialExtensionField<BabyBear, 4>;
    type ZkvmProof = ZKVMProof<E, Basefold<E, BasefoldRSParams>>;
    type ZkvmVk = ZKVMVerifyingKey<E, Basefold<E, BasefoldRSParams>>;

    fn load_proofs(path: &str) -> Result<Vec<ZkvmProof>> {
        let bytes = std::fs::read(path)?;
        if let Ok(proofs) = bincode::deserialize::<Vec<ZkvmProof>>(&bytes) {
            return Ok(proofs);
        }
        if let Ok(single) = bincode::deserialize::<ZkvmProof>(&bytes) {
            return Ok(vec![single]);
        }
        Err(eyre!(
            "failed to deserialize proof fixture as Vec<ZKVMProof> or ZKVMProof"
        ))
    }

    #[test]
    fn leaf_app_proof_round_trip_placeholder() -> Result<()> {
        let proof_path = "./src/imported/proof.bin";
        let vk_path = "./src/imported/vk.bin";

        let zkvm_proofs = load_proofs(proof_path)?;

        let child_vk: ZkvmVk = bincode::deserialize(&std::fs::read(vk_path)?)?;

        const MAX_NUM_PROOFS: usize = 2;
        let system_params = test_system_params_zero_pow(5, 16, 3);
        let leaf_prover = InnerCpuProver::<MAX_NUM_PROOFS>::new::<Engine>(
            Arc::new(child_vk),
            system_params,
            false,
            None,
        );

        let _leaf_proof = leaf_prover.agg_prove_no_def::<Engine>(&zkvm_proofs, ChildVkKind::App)?;
        let overall_size = bincode::serialized_size(&_leaf_proof).expect("serialization error");
        println!("proof size {:.2}mb.", byte_to_mb(overall_size));
        Ok(())
    }

    fn byte_to_mb(byte_size: u64) -> f64 {
        byte_size as f64 / (1024.0 * 1024.0)
    }
}
