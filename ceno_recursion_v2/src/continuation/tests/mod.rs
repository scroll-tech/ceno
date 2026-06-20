#[cfg(test)]
mod prover_integration {
    use crate::{
        continuation::prover::{ChildVkKind, InnerCpuProver},
        system::{AggregationSubCircuit, VerifierSubCircuit, utils::test_system_params_zero_pow},
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
    use std::{
        path::{Path, PathBuf},
        sync::{Arc, Once},
        time::Instant,
    };
    use tracing_subscriber::EnvFilter;

    type Engine = BabyBearPoseidon2CpuEngine<DuplexSponge>;
    type E = BinomialExtensionField<BabyBear, 4>;
    type ZkvmProof = ZKVMProof<E, Basefold<E, BasefoldRSParams>>;
    type ZkvmVk = ZKVMVerifyingKey<E, Basefold<E, BasefoldRSParams>>;

    fn init_test_tracing() {
        static INIT: Once = Once::new();
        INIT.call_once(|| {
            let filter =
                EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
            let _ = tracing_subscriber::fmt()
                .with_env_filter(filter)
                .with_test_writer()
                .try_init();
        });
    }

    fn load_proofs(path: &Path) -> Result<Option<Vec<ZkvmProof>>> {
        let bytes = std::fs::read(path)?;
        if let Ok(proofs) = bincode::deserialize::<Vec<ZkvmProof>>(&bytes) {
            return Ok(Some(proofs));
        }
        if let Ok(single) = bincode::deserialize::<ZkvmProof>(&bytes) {
            return Ok(Some(vec![single]));
        }
        println!("skipping recursion v2 test: incompatible proof.bin fixture");
        Ok(None)
    }

    fn fixture_path(file_name: &str) -> Option<PathBuf> {
        std::env::var_os("CENO_RECURSION_V2_FIXTURE_DIR")
            .map(PathBuf::from)
            .into_iter()
            .chain([PathBuf::from("./src/imported")])
            .map(|dir| dir.join(file_name))
            .find(|path| path.exists())
    }

    fn select_proofs(proofs: &[ZkvmProof], count: usize) -> Result<Vec<ZkvmProof>> {
        if proofs.is_empty() {
            return Err(eyre!("proof fixture did not contain any proofs"));
        }
        Ok(proofs.iter().cycle().take(count).cloned().collect())
    }

    fn load_vk(path: &Path) -> Result<Option<ZkvmVk>> {
        match bincode::deserialize(&std::fs::read(path)?) {
            Ok(vk) => Ok(Some(vk)),
            Err(err) => {
                println!("skipping recursion v2 test: incompatible vk.bin fixture: {err}");
                Ok(None)
            }
        }
    }

    fn leaf_app_proof_round_trip_placeholder_with_count(proof_count: usize) -> Result<()> {
        init_test_tracing();

        let Some(proof_path) = fixture_path("proof.bin") else {
            println!("skipping recursion v2 round trip: missing src/imported/proof.bin");
            return Ok(());
        };
        let Some(vk_path) = fixture_path("vk.bin") else {
            println!("skipping recursion v2 round trip: missing src/imported/vk.bin");
            return Ok(());
        };

        let Some(loaded_proofs) = load_proofs(&proof_path)? else {
            return Ok(());
        };
        let zkvm_proofs = select_proofs(&loaded_proofs, proof_count)?;

        let Some(child_vk) = load_vk(&vk_path)? else {
            return Ok(());
        };

        const MAX_NUM_PROOFS: usize = 2;
        let system_params = test_system_params_zero_pow(5, 16, 3);
        let leaf_prover = InnerCpuProver::<MAX_NUM_PROOFS>::new::<Engine>(
            Arc::new(child_vk),
            system_params,
            false,
            None,
        );

        let start = Instant::now();
        let leaf_proof = leaf_prover.agg_prove_no_def::<Engine>(&zkvm_proofs, ChildVkKind::App)?;
        let elapsed = start.elapsed();
        let overall_size = bincode::serialized_size(&leaf_proof).expect("serialization error");
        println!(
            "recursion v2 placeholder round trip: proofs={proof_count}, prove+verify={elapsed:?}, proof_size={:.2}mb",
            byte_to_mb(overall_size)
        );
        Ok(())
    }

    #[test]
    fn leaf_app_proof_round_trip_placeholder() -> Result<()> {
        leaf_app_proof_round_trip_placeholder_with_count(1)
    }

    #[test]
    fn leaf_app_proof_round_trip_placeholder_two_proofs() -> Result<()> {
        leaf_app_proof_round_trip_placeholder_with_count(2)
    }

    #[test]
    fn leaf_app_batch_air_registration_placeholder() -> Result<()> {
        let Some(vk_path) = fixture_path("vk.bin") else {
            println!("skipping recursion v2 AIR registration: missing src/imported/vk.bin");
            return Ok(());
        };
        let Some(child_vk) = load_vk(&vk_path)? else {
            return Ok(());
        };
        const MAX_NUM_PROOFS: usize = 2;
        let subcircuit = VerifierSubCircuit::<MAX_NUM_PROOFS>::new(Arc::new(child_vk));
        let mut air_names = <VerifierSubCircuit<MAX_NUM_PROOFS> as AggregationSubCircuit>::airs::<
            continuations_v2::SC,
        >(&subcircuit)
        .iter()
        .map(|air| air.name().to_string())
        .collect::<Vec<_>>();
        air_names.sort_unstable();
        assert!(
            air_names
                .iter()
                .any(|name| name.contains("SymbolicExpressionAir")),
            "SymbolicExpressionAir missing from recursion v2 verifier"
        );
        assert!(
            air_names
                .iter()
                .any(|name| name.contains("ConstraintsFoldingAir")),
            "ConstraintsFoldingAir missing from recursion v2 verifier"
        );
        assert!(
            air_names
                .iter()
                .any(|name| name.contains("ExpressionClaimAir")),
            "ExpressionClaimAir missing from recursion v2 verifier"
        );

        println!("registered recursion v2 airs={}", air_names.len());
        Ok(())
    }

    fn byte_to_mb(byte_size: u64) -> f64 {
        byte_size as f64 / (1024.0 * 1024.0)
    }
}
