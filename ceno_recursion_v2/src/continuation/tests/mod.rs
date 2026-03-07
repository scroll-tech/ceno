#[cfg(test)]
mod prover_integration {
    use crate::continuation::prover::{InnerCpuProver, ChildVkKind};
    use bincode;
    use ceno_zkvm::{scheme::ZKVMProof, structs::ZKVMVerifyingKey};
    use eyre::Result;
    use mpcs::{Basefold, BasefoldRSParams};
    use openvm_stark_backend::SystemParams;
    use openvm_stark_sdk::{
        config::baby_bear_poseidon2::{BabyBearPoseidon2CpuEngine, DuplexSponge},
        p3_baby_bear::BabyBear,
    };
    use p3::field::extension::BinomialExtensionField;
    use std::{fs::File, sync::Arc};

    type Engine = BabyBearPoseidon2CpuEngine<DuplexSponge>;
    type E = BinomialExtensionField<BabyBear, 4>;

    #[test]
    fn leaf_app_proof_round_trip_placeholder() -> Result<()> {
        let proof_path = "./src/imported/proof.bin";
        let vk_path = "./src/imported/vk.bin";

        let zkvm_proofs: Vec<ZKVMProof<E, Basefold<E, BasefoldRSParams>>> =
            bincode::deserialize_from(File::open(proof_path).expect("open proof file"))
                .expect("deserialize zkvm proofs");

        let child_vk: ZKVMVerifyingKey<E, Basefold<E, BasefoldRSParams>> =
            bincode::deserialize_from(File::open(vk_path).expect("open vk file"))
                .expect("deserialize vk file");

        const MAX_NUM_PROOFS: usize = 4;
        let system_params = placeholder_system_params();
        let leaf_prover = InnerCpuProver::<MAX_NUM_PROOFS>::new::<Engine>(
            Arc::new(child_vk),
            system_params,
            false,
            None,
        );

        let _leaf_proof = leaf_prover.agg_prove_no_def::<Engine>(&zkvm_proofs, ChildVkKind::App)?;
        Ok(())
    }

    fn placeholder_system_params() -> SystemParams {
        unimplemented!("derive actual SystemParams for the inner prover")
    }
}
