#[cfg(test)]
mod prover_integration {
    use crate::{
        continuation::prover::{AggProver, AggregationOptions},
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
        match bincode::deserialize::<ZkvmVk>(&std::fs::read(path)?) {
            Ok(mut vk) => {
                vk.rebuild_circuit_index();
                Ok(Some(vk))
            }
            Err(err) => {
                println!("skipping recursion v2 test: incompatible vk.bin fixture: {err}");
                Ok(None)
            }
        }
    }

    fn load_fixtures() -> Result<Option<(Vec<ZkvmProof>, ZkvmVk)>> {
        let Some(proof_path) = fixture_path("proof.bin") else {
            println!("skipping recursion v2 test: missing proof.bin fixture");
            return Ok(None);
        };
        let Some(vk_path) = fixture_path("vk.bin") else {
            println!("skipping recursion v2 test: missing vk.bin fixture");
            return Ok(None);
        };
        let Some(proofs) = load_proofs(&proof_path)? else {
            return Ok(None);
        };
        let Some(vk) = load_vk(&vk_path)? else {
            return Ok(None);
        };
        Ok(Some((proofs, vk)))
    }

    fn agg_prove_with_count(shard_count: usize) -> Result<()> {
        init_test_tracing();

        let Some((loaded_proofs, child_vk)) = load_fixtures()? else {
            return Ok(());
        };
        let shard_proofs = select_proofs(&loaded_proofs, shard_count)?;

        let options = AggregationOptions::new(test_system_params_zero_pow(5, 16, 3));
        let prover = AggProver::<2, 2>::new(Arc::new(child_vk), options);

        let start = Instant::now();
        let root_proof = prover.prove(&shard_proofs)?;
        let elapsed = start.elapsed();
        let proof_size =
            bincode::serialized_size(&root_proof.inner_proof).expect("serialization error");
        println!(
            "agg prover ({shard_count} shards): elapsed={elapsed:?}, proof_size={:.2}mb",
            byte_to_mb(proof_size)
        );
        Ok(())
    }

    #[test]
    fn agg_prover_single_shard() -> Result<()> {
        agg_prove_with_count(1)
    }

    #[test]
    fn agg_prover_two_shards() -> Result<()> {
        agg_prove_with_count(2)
    }

    // ---- AIR registration test ----

    #[test]
    fn leaf_app_batch_air_registration_placeholder() -> Result<()> {
        let Some((_, child_vk)) = load_fixtures()? else {
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

    // ---- Diagnostic test ----

    #[test]
    fn dump_fixture_public_values() -> Result<()> {
        let Some((proofs, vk)) = load_fixtures()? else {
            return Ok(());
        };
        for (i, proof) in proofs.iter().enumerate() {
            let pv = &proof.public_values;
            println!("proof[{i}] public_values:");
            println!("  exit_code={}", pv.exit_code);
            println!("  init_pc={:#x}", pv.init_pc);
            println!("  init_cycle={}", pv.init_cycle);
            println!("  end_pc={:#x}", pv.end_pc);
            println!("  end_cycle={}", pv.end_cycle);
            println!("  shard_id={}", pv.shard_id);
            println!("  heap_start_addr={:#x}", pv.heap_start_addr);
            println!("  heap_shard_len={}", pv.heap_shard_len);
            println!("  hint_start_addr={:#x}", pv.hint_start_addr);
            println!("  hint_shard_len={}", pv.hint_shard_len);
            println!("  public_io_digest={:?}", pv.public_io_digest);
            println!("  shard_rw_sum={:?}", pv.shard_rw_sum);
            println!(
                "  chip_proofs keys={:?}",
                proof.chip_proofs.keys().collect::<Vec<_>>()
            );
        }
        println!("vk entry_pc={:#x}", vk.entry_pc);
        println!("vk circuit_vks count={}", vk.circuit_vks.len());
        println!(
            "vk circuit_index_to_name count={}",
            vk.circuit_index_to_name.len()
        );
        for (name, _cvk) in &vk.circuit_vks {
            println!("  circuit_vk: {name}");
        }
        Ok(())
    }

    fn byte_to_mb(byte_size: u64) -> f64 {
        byte_size as f64 / (1024.0 * 1024.0)
    }
}
