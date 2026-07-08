#[cfg(test)]
mod prover_integration {
    use crate::{
        continuation::prover::{AggProver, AggregationOptions, ChildVkKind, InnerCpuProver},
        system::{
            AggregationSubCircuit, RecursionField, RecursionProof, RecursionVk, VerifierSubCircuit,
            VerifierTraceGen, utils::test_system_params_zero_pow,
        },
    };
    use bincode;
    use ceno_zkvm::scheme::{MainConstraintProof, PublicValues, ZKVMChipProof, ZKVMProof};
    use eyre::{Result, eyre};
    use ff_ext::GoldilocksExt2;
    use mpcs::{Basefold, BasefoldRSParams, Jagged, Whir, WhirDefaultSpec};
    use openvm_stark_sdk::config::baby_bear_poseidon2::{
        BabyBearPoseidon2CpuEngine, DuplexSponge, DuplexSpongeRecorder, F,
        default_duplex_sponge_recorder,
    };
    use p3_field::PrimeCharacteristicRing;
    use std::{
        collections::BTreeMap,
        io::Cursor,
        path::{Path, PathBuf},
        sync::{Arc, Once},
        time::Instant,
    };
    use tracing_subscriber::EnvFilter;

    type Engine = BabyBearPoseidon2CpuEngine<DuplexSponge>;
    type E = RecursionField;
    type ZkvmProof = RecursionProof;
    type ZkvmVk = RecursionVk;
    type BabyBearJaggedProof = ZKVMProof<E, Jagged<Basefold<E, BasefoldRSParams>>>;
    type BabyBearWhirProof = ZKVMProof<E, Whir<E, WhirDefaultSpec>>;
    type GoldilocksBasefoldProof =
        ZKVMProof<GoldilocksExt2, Basefold<GoldilocksExt2, BasefoldRSParams>>;
    type GoldilocksJaggedProof =
        ZKVMProof<GoldilocksExt2, Jagged<Basefold<GoldilocksExt2, BasefoldRSParams>>>;
    type GoldilocksWhirProof = ZKVMProof<GoldilocksExt2, Whir<GoldilocksExt2, WhirDefaultSpec>>;

    fn probe_proof_fixture_type(bytes: &[u8]) -> &'static str {
        if bincode::deserialize::<Vec<BabyBearJaggedProof>>(bytes).is_ok() {
            return "babybear+jagged-basefold";
        }
        if bincode::deserialize::<Vec<BabyBearWhirProof>>(bytes).is_ok() {
            return "babybear+whir";
        }
        if bincode::deserialize::<Vec<GoldilocksBasefoldProof>>(bytes).is_ok() {
            return "goldilocks+basefold";
        }
        if bincode::deserialize::<Vec<GoldilocksJaggedProof>>(bytes).is_ok() {
            return "goldilocks+jagged-basefold";
        }
        if bincode::deserialize::<Vec<GoldilocksWhirProof>>(bytes).is_ok() {
            return "goldilocks+whir";
        }
        "unknown"
    }

    fn diagnose_current_proof_layout(bytes: &[u8]) {
        let mut cursor = Cursor::new(bytes);
        let len = bincode::deserialize_from::<_, u64>(&mut cursor);
        println!(
            "proof decode probe: vec_len={len:?}, offset={}",
            cursor.position()
        );
        let public_values = bincode::deserialize_from::<_, PublicValues>(&mut cursor);
        println!(
            "proof decode probe: public_values={} offset={}",
            public_values
                .as_ref()
                .map(|pv| format!(
                    "ok(exit_code={}, shard_id={}, end_cycle={})",
                    pv.exit_code, pv.shard_id, pv.end_cycle
                ))
                .unwrap_or_else(|err| format!("err({err})")),
            cursor.position()
        );
        let chip_proofs =
            bincode::deserialize_from::<_, BTreeMap<usize, ZKVMChipProof<E>>>(&mut cursor);
        println!(
            "proof decode probe: chip_proofs={} offset={}",
            chip_proofs
                .as_ref()
                .map(|chips| format!("ok(len={})", chips.len()))
                .unwrap_or_else(|err| format!("err({err})")),
            cursor.position()
        );
        if chip_proofs.is_err() {
            let mut gl_cursor = Cursor::new(bytes);
            let _: Result<u64, _> = bincode::deserialize_from(&mut gl_cursor);
            let _: Result<PublicValues, _> = bincode::deserialize_from(&mut gl_cursor);
            let gl_chip_proofs = bincode::deserialize_from::<
                _,
                BTreeMap<usize, ZKVMChipProof<GoldilocksExt2>>,
            >(&mut gl_cursor);
            println!(
                "proof decode probe: goldilocks chip_proofs={} offset={}",
                gl_chip_proofs
                    .as_ref()
                    .map(|chips| format!("ok(len={})", chips.len()))
                    .unwrap_or_else(|err| format!("err({err})")),
                gl_cursor.position()
            );
        }
        if chip_proofs.is_err() {
            return;
        }
        let main_constraint = bincode::deserialize_from::<_, MainConstraintProof<E>>(&mut cursor);
        println!(
            "proof decode probe: main_constraint={} offset={}",
            main_constraint
                .as_ref()
                .map(|_| "ok".to_string())
                .unwrap_or_else(|err| format!("err({err})")),
            cursor.position()
        );
    }

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
        let vec_err = match bincode::deserialize::<Vec<ZkvmProof>>(&bytes) {
            Ok(_) => unreachable!("proof vec deserialize should have returned above"),
            Err(err) => err,
        };
        if let Ok(single) = bincode::deserialize::<ZkvmProof>(&bytes) {
            return Ok(Some(vec![single]));
        }
        let single_err = match bincode::deserialize::<ZkvmProof>(&bytes) {
            Ok(_) => unreachable!("proof deserialize should have returned above"),
            Err(err) => err,
        };
        println!(
            "skipping recursion v2 test: incompatible proof.bin fixture: detected_type={}; vec_err={vec_err}; single_err={single_err}",
            probe_proof_fixture_type(&bytes),
        );
        diagnose_current_proof_layout(&bytes);
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

    fn first_fixture_proof_and_vk() -> Result<Option<(ZkvmProof, ZkvmVk)>> {
        let Some((proofs, child_vk)) = load_fixtures()? else {
            return Ok(None);
        };
        Ok(Some((select_proofs(&proofs, 1)?.remove(0), child_vk)))
    }

    fn assert_recursion_pcs_rejects(child_vk: &ZkvmVk, proof: ZkvmProof) {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            const MAX_NUM_PROOFS: usize = 2;
            let subcircuit = VerifierSubCircuit::<MAX_NUM_PROOFS>::new(Arc::new(child_vk.clone()));
            let mut transcript = default_duplex_sponge_recorder();
            crate::utils::transcript_observe_label(
                &mut transcript,
                crate::utils::TranscriptLabel::Riscv.as_bytes(),
            );
            <VerifierSubCircuit<MAX_NUM_PROOFS> as VerifierTraceGen<
                openvm_cpu_backend::CpuBackend<continuations_v2::SC>,
                continuations_v2::SC,
            >>::generate_proving_ctxs_base::<DuplexSpongeRecorder>(
                &subcircuit,
                child_vk,
                None,
                &[proof],
                transcript,
            )
        }));
        assert!(
            result.is_err(),
            "mutated PCS proof unexpectedly generated recursion-v2 traces"
        );
    }

    fn assert_recursion_pcs_air_rejects(
        child_vk: &ZkvmVk,
        proof: ZkvmProof,
        case_name: &str,
        mutate: impl FnOnce(&mut crate::system::Preflight),
    ) -> bool {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let prover = InnerCpuProver::<2>::new::<Engine>(
                Arc::new(child_vk.clone()),
                test_system_params_zero_pow(5, 16, 3),
                false,
                None,
            );
            prover.debug_with_preflight_mutation::<Engine, _>(
                &[proof],
                ChildVkKind::App,
                |preflights| {
                    mutate(&mut preflights[0]);
                    true
                },
            )
        }));
        match result {
            Ok(false) => false,
            Ok(true) => {
                panic!("{case_name}: mutated PCS preflight unexpectedly satisfied AIR/LogUp")
            }
            Err(_) => true,
        }
    }

    fn mutate_first_jagged_col_eval(proof: &mut ZkvmProof) {
        proof.opening_proof.rounds[0].col_evals[0] += E::ONE;
    }

    fn mutate_first_jagged_assist_round_eval(proof: &mut ZkvmProof) {
        proof.opening_proof.rounds[0].assist_proof.proofs[0].evaluations[0] += E::ONE;
    }

    fn mutate_last_jagged_assist_round_eval(proof: &mut ZkvmProof) {
        let round = proof.opening_proof.rounds[0]
            .assist_proof
            .proofs
            .last_mut()
            .expect("fixture has assist sumcheck rounds");
        round.evaluations[0] += E::ONE;
    }

    fn mutate_second_final_message_value(proof: &mut ZkvmProof) {
        let row = proof
            .opening_proof
            .inner_proof
            .final_message
            .first_mut()
            .expect("fixture has basefold final message rows");
        let idx = usize::from(row.len() > 1);
        row[idx] += E::ONE;
    }

    fn mutate_first_final_expected(
        preflight: &mut crate::system::Preflight,
        mutate: impl FnOnce(&mut crate::system::PcsBasefoldFinalExpectedRecord),
    ) {
        let record = preflight
            .pcs
            .basefold_final_expected
            .first_mut()
            .expect("fixture has basefold final expected rows");
        mutate(record);
    }

    fn mutate_first_final_codeword(
        preflight: &mut crate::system::Preflight,
        mutate: impl FnOnce(&mut crate::system::PcsBasefoldFinalCodewordRecord),
    ) {
        let record = preflight
            .pcs
            .basefold_final_codeword
            .first_mut()
            .expect("fixture has basefold final codeword rows");
        mutate(record);
    }

    fn mutate_first_final_message_transcript(
        preflight: &mut crate::system::Preflight,
        mutate: impl FnOnce(&mut crate::system::PcsTranscriptValueRecord),
    ) {
        let record = preflight
            .pcs
            .transcript_values
            .iter_mut()
            .find(|record| record.is_final_message)
            .expect("fixture has PCS final-message transcript rows");
        mutate(record);
    }

    fn mutate_first_basefold_sumcheck_round(
        preflight: &mut crate::system::Preflight,
        mutate: impl FnOnce(&mut crate::system::PcsSumcheckRoundRecord),
    ) {
        let record = preflight
            .pcs
            .sumcheck_rounds
            .iter_mut()
            .find(|record| record.idx == 8_000_000)
            .expect("fixture has basefold sumcheck rows");
        mutate(record);
    }

    #[test]
    fn agg_prover_single_shard() -> Result<()> {
        agg_prove_with_count(1)
    }

    #[test]
    fn agg_prover_two_shards() -> Result<()> {
        agg_prove_with_count(2)
    }

    #[test]
    fn pcs_rejects_jagged_round_count_mismatch() -> Result<()> {
        let Some((mut proof, child_vk)) = first_fixture_proof_and_vk()? else {
            return Ok(());
        };
        proof.opening_proof.rounds.clear();
        assert_recursion_pcs_rejects(&child_vk, proof);
        Ok(())
    }

    #[test]
    fn pcs_rejects_jagged_claimed_sum_mismatch() -> Result<()> {
        let Some((mut proof, child_vk)) = first_fixture_proof_and_vk()? else {
            return Ok(());
        };
        proof.opening_proof.rounds[0].sumcheck_proof.proofs[0].evaluations[0] += E::ONE;
        assert_recursion_pcs_rejects(&child_vk, proof);
        Ok(())
    }

    #[test]
    fn pcs_rejects_jagged_subclaim_multiplication_mismatch() -> Result<()> {
        let Some((mut proof, child_vk)) = first_fixture_proof_and_vk()? else {
            return Ok(());
        };
        proof.opening_proof.rounds[0].f_at_rho += E::ONE;
        assert_recursion_pcs_rejects(&child_vk, proof);
        Ok(())
    }

    #[test]
    fn pcs_rejects_jagged_q_eval_col_eval_mismatch() -> Result<()> {
        let Some((mut proof, child_vk)) = first_fixture_proof_and_vk()? else {
            return Ok(());
        };
        mutate_first_jagged_col_eval(&mut proof);
        assert_recursion_pcs_rejects(&child_vk, proof);
        Ok(())
    }

    #[test]
    fn pcs_rejects_jagged_assist_final_check_mismatch() -> Result<()> {
        let Some((mut proof, child_vk)) = first_fixture_proof_and_vk()? else {
            return Ok(());
        };
        mutate_first_jagged_assist_round_eval(&mut proof);
        assert_recursion_pcs_rejects(&child_vk, proof);
        Ok(())
    }

    #[test]
    fn pcs_rejects_jagged_assist_operand_mismatch() -> Result<()> {
        let Some((mut proof, child_vk)) = first_fixture_proof_and_vk()? else {
            return Ok(());
        };
        mutate_last_jagged_assist_round_eval(&mut proof);
        assert_recursion_pcs_rejects(&child_vk, proof);
        Ok(())
    }

    #[test]
    fn pcs_rejects_basefold_final_claim_mismatch() -> Result<()> {
        let Some((mut proof, child_vk)) = first_fixture_proof_and_vk()? else {
            return Ok(());
        };
        proof.opening_proof.inner_proof.final_message[0][0] += E::ONE;
        assert_recursion_pcs_rejects(&child_vk, proof);
        Ok(())
    }

    #[test]
    fn pcs_rejects_basefold_final_codeword_folding_mismatch() -> Result<()> {
        let Some((mut proof, child_vk)) = first_fixture_proof_and_vk()? else {
            return Ok(());
        };
        mutate_second_final_message_value(&mut proof);
        assert_recursion_pcs_rejects(&child_vk, proof);
        Ok(())
    }

    #[test]
    fn pcs_rejects_basefold_merkle_query_mismatch() -> Result<()> {
        let Some((mut proof, child_vk)) = first_fixture_proof_and_vk()? else {
            return Ok(());
        };
        proof.opening_proof.inner_proof.query_opening_proof[0].input_proofs[0].opened_values[0]
            [0] += F::ONE;
        assert_recursion_pcs_rejects(&child_vk, proof);
        Ok(())
    }

    #[test]
    fn pcs_rejects_basefold_base_sibling_mismatch() -> Result<()> {
        let Some((mut proof, child_vk)) = first_fixture_proof_and_vk()? else {
            return Ok(());
        };
        proof.opening_proof.inner_proof.query_opening_proof[0].input_proofs[0].opening_proof[0]
            [0] += F::ONE;
        assert_recursion_pcs_rejects(&child_vk, proof);
        Ok(())
    }

    #[test]
    fn pcs_rejects_basefold_base_root_mismatch() -> Result<()> {
        let Some((mut proof, child_vk)) = first_fixture_proof_and_vk()? else {
            return Ok(());
        };
        let mut root: [F; 8] = proof.witin_commit.inner.commit.into();
        root[0] += F::ONE;
        proof.witin_commit.inner.commit = root.into();
        assert_recursion_pcs_rejects(&child_vk, proof);
        Ok(())
    }

    #[test]
    fn pcs_rejects_basefold_commit_phase_sibling_mismatch() -> Result<()> {
        let Some((mut proof, child_vk)) = first_fixture_proof_and_vk()? else {
            return Ok(());
        };
        proof.opening_proof.inner_proof.query_opening_proof[0].commit_phase_openings[0]
            .opening_proof[0][0] += F::ONE;
        assert_recursion_pcs_rejects(&child_vk, proof);
        Ok(())
    }

    #[test]
    fn pcs_rejects_basefold_commit_phase_root_mismatch() -> Result<()> {
        let Some((mut proof, child_vk)) = first_fixture_proof_and_vk()? else {
            return Ok(());
        };
        let mut root: [F; 8] = proof.opening_proof.inner_proof.commits[0].into();
        root[0] += F::ONE;
        proof.opening_proof.inner_proof.commits[0] = root.into();
        assert_recursion_pcs_rejects(&child_vk, proof);
        Ok(())
    }

    #[test]
    fn pcs_air_rejects_mutated_final_expected_values() -> Result<()> {
        let Some((proof, child_vk)) = first_fixture_proof_and_vk()? else {
            return Ok(());
        };
        assert_recursion_pcs_air_rejects(
            &child_vk,
            proof.clone(),
            "final_expected.point_value",
            |p| {
                mutate_first_final_expected(p, |record| record.point_value += E::ONE);
            },
        );
        assert_recursion_pcs_air_rejects(&child_vk, proof.clone(), "final_expected.acc_in", |p| {
            mutate_first_final_expected(p, |record| record.acc_in += E::ONE);
        });
        assert_recursion_pcs_air_rejects(&child_vk, proof.clone(), "final_expected.acc_out", |p| {
            mutate_first_final_expected(p, |record| record.acc_out += E::ONE);
        });
        assert_recursion_pcs_air_rejects(
            &child_vk,
            proof.clone(),
            "final_expected.coeff_in",
            |p| {
                mutate_first_final_expected(p, |record| record.coeff_in += E::ONE);
            },
        );
        assert_recursion_pcs_air_rejects(&child_vk, proof, "final_expected.coeff_out", |p| {
            mutate_first_final_expected(p, |record| record.coeff_out += E::ONE);
        });
        Ok(())
    }

    #[test]
    fn pcs_air_rejects_mutated_final_codeword_shape_values() -> Result<()> {
        let Some((proof, child_vk)) = first_fixture_proof_and_vk()? else {
            return Ok(());
        };
        assert_recursion_pcs_air_rejects(&child_vk, proof.clone(), "final_codeword.coeff", |p| {
            mutate_first_final_codeword(p, |record| record.coeff += E::ONE);
        });
        assert_recursion_pcs_air_rejects(&child_vk, proof, "final_codeword.elem_idx", |p| {
            mutate_first_final_codeword(p, |record| record.elem_idx += 1);
        });
        Ok(())
    }

    #[test]
    fn pcs_air_rejects_mutated_final_point_multiplicity_and_keys() -> Result<()> {
        let Some((proof, child_vk)) = first_fixture_proof_and_vk()? else {
            return Ok(());
        };
        assert_recursion_pcs_air_rejects(&child_vk, proof.clone(), "drop final point row", |p| {
            p.pcs.basefold_final_points.remove(0);
        });
        assert_recursion_pcs_air_rejects(
            &child_vk,
            proof.clone(),
            "duplicate final point row",
            |p| {
                let row = p.pcs.basefold_final_points[0].clone();
                p.pcs.basefold_final_points.push(row);
            },
        );
        assert_recursion_pcs_air_rejects(
            &child_vk,
            proof.clone(),
            "final point sumcheck_idx",
            |p| {
                p.pcs.basefold_final_points[0].sumcheck_idx += 1;
            },
        );
        assert_recursion_pcs_air_rejects(&child_vk, proof.clone(), "final point point_idx", |p| {
            p.pcs.basefold_final_points[0].point_idx += 1;
        });
        assert_recursion_pcs_air_rejects(&child_vk, proof, "final point coord_idx", |p| {
            p.pcs.basefold_final_points[0].coord_idx += 1;
        });
        Ok(())
    }

    #[test]
    fn pcs_air_rejects_mutated_final_expected_multiplicity() -> Result<()> {
        let Some((proof, child_vk)) = first_fixture_proof_and_vk()? else {
            return Ok(());
        };
        assert_recursion_pcs_air_rejects(
            &child_vk,
            proof.clone(),
            "drop final expected row",
            |p| {
                p.pcs.basefold_final_expected.remove(0);
            },
        );
        assert_recursion_pcs_air_rejects(&child_vk, proof, "duplicate final expected row", |p| {
            let row = p.pcs.basefold_final_expected[0].clone();
            p.pcs.basefold_final_expected.push(row);
        });
        Ok(())
    }

    #[test]
    fn pcs_air_rejects_mutated_final_message_transcript_binding() -> Result<()> {
        let Some((proof, child_vk)) = first_fixture_proof_and_vk()? else {
            return Ok(());
        };
        assert_recursion_pcs_air_rejects(&child_vk, proof.clone(), "final message tidx", |p| {
            mutate_first_final_message_transcript(p, |record| record.tidx += 1);
        });
        assert_recursion_pcs_air_rejects(&child_vk, proof.clone(), "final message value", |p| {
            mutate_first_final_message_transcript(p, |record| record.value += E::ONE);
        });
        assert_recursion_pcs_air_rejects(&child_vk, proof, "drop final message row", |p| {
            let idx = p
                .pcs
                .transcript_values
                .iter()
                .position(|record| record.is_final_message)
                .expect("fixture has PCS final-message transcript rows");
            p.pcs.transcript_values.remove(idx);
        });
        Ok(())
    }

    #[test]
    fn pcs_air_rejects_mutated_basefold_sumcheck_count_and_keys() -> Result<()> {
        let Some((proof, child_vk)) = first_fixture_proof_and_vk()? else {
            return Ok(());
        };
        assert_recursion_pcs_air_rejects(
            &child_vk,
            proof.clone(),
            "basefold fold challenge multiplicity",
            |p| {
                mutate_first_basefold_sumcheck_round(p, |record| {
                    record.fold_challenge_lookup_count += 1;
                });
            },
        );
        assert_recursion_pcs_air_rejects(
            &child_vk,
            proof.clone(),
            "basefold sumcheck round",
            |p| {
                mutate_first_basefold_sumcheck_round(p, |record| record.round += 1);
            },
        );
        assert_recursion_pcs_air_rejects(&child_vk, proof, "drop basefold sumcheck round", |p| {
            let idx = p
                .pcs
                .sumcheck_rounds
                .iter()
                .position(|record| record.idx == 8_000_000)
                .expect("fixture has basefold sumcheck rows");
            p.pcs.sumcheck_rounds.remove(idx);
        });
        Ok(())
    }

    #[test]
    fn pcs_air_rejects_mutated_basefold_query_and_opening_counts() -> Result<()> {
        let Some((proof, child_vk)) = first_fixture_proof_and_vk()? else {
            return Ok(());
        };
        assert_recursion_pcs_air_rejects(&child_vk, proof.clone(), "drop query index row", |p| {
            p.pcs.basefold_query_indices.remove(0);
        });
        assert_recursion_pcs_air_rejects(
            &child_vk,
            proof.clone(),
            "duplicate query index row",
            |p| {
                let row = p.pcs.basefold_query_indices[0].clone();
                p.pcs.basefold_query_indices.push(row);
            },
        );
        assert_recursion_pcs_air_rejects(
            &child_vk,
            proof.clone(),
            "drop base input leaf row",
            |p| {
                p.pcs.base_input_leaf_hashes.remove(0);
            },
        );
        assert_recursion_pcs_air_rejects(
            &child_vk,
            proof,
            "drop basefold query opening row",
            |p| {
                p.pcs.basefold_query_opens.remove(0);
            },
        );
        Ok(())
    }

    #[test]
    fn pcs_air_rejects_mutated_commit_phase_counts() -> Result<()> {
        let Some((proof, child_vk)) = first_fixture_proof_and_vk()? else {
            return Ok(());
        };
        assert_recursion_pcs_air_rejects(
            &child_vk,
            proof.clone(),
            "drop commit phase leaf row",
            |p| {
                p.pcs.commit_phase_leaf_hashes.remove(0);
            },
        );
        assert_recursion_pcs_air_rejects(
            &child_vk,
            proof.clone(),
            "duplicate commit phase leaf row",
            |p| {
                let row = p.pcs.commit_phase_leaf_hashes[0].clone();
                p.pcs.commit_phase_leaf_hashes.push(row);
            },
        );
        assert_recursion_pcs_air_rejects(&child_vk, proof, "drop commit phase merkle row", |p| {
            p.pcs.commit_phase_merkle_rows.remove(0);
        });
        Ok(())
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
        let batch_main_airs = [
            "MainGlobalSumcheckAir",
            "MainEvalAbsorbAir",
            "MainTowerPointEqAir",
            "MainFrontloadTermAir",
            "MainFinalClaimAir",
        ];
        for air in batch_main_airs {
            assert!(
                air_names.iter().any(|name| name.contains(air)),
                "{air} missing from recursion v2 verifier"
            );
        }
        for air in [
            "PcsEqProductAir",
            "PcsSuffixProductAir",
            "PcsJaggedAssistHAir",
            "PcsJaggedAssistQAir",
        ] {
            assert!(
                air_names.iter().any(|name| name.contains(air)),
                "{air} missing from recursion v2 verifier"
            );
        }
        for removed_air in [
            "SymbolicExpressionAir",
            "ConstraintsFoldingAir",
            "ExpressionClaimAir",
        ] {
            assert!(
                !air_names.iter().any(|name| name.contains(removed_air)),
                "{removed_air} should not be registered in recursion v2 verifier"
            );
        }

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
        for name in vk.circuit_vks.keys() {
            println!("  circuit_vk: {name}");
        }
        Ok(())
    }

    fn byte_to_mb(byte_size: u64) -> f64 {
        byte_size as f64 / (1024.0 * 1024.0)
    }
}
