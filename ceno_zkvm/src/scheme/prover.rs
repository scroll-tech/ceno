use ff_ext::ExtensionField;
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    sync::Arc,
};

use ff::Field;
use itertools::{Itertools, enumerate, izip};
use mpcs::PolynomialCommitmentScheme;
use multilinear_extensions::{
    mle::{IntoMLE, MultilinearExtension},
    util::ceil_log2,
    virtual_poly::{ArcMultilinearExtension, build_eq_x_r_vec},
};
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use sumcheck::{
    macros::{entered_span, exit_span},
    structs::{IOPProverMessage, IOPProverState},
};
use transcript::{ForkableTranscript, Transcript};

use crate::{
    error::ZKVMError,
    expression::Instance,
    scheme::{
        constants::{MAINCONSTRAIN_SUMCHECK_BATCH_SIZE, NUM_FANIN, NUM_FANIN_LOGUP},
        utils::{
            infer_tower_logup_witness, infer_tower_product_witness, interleaving_mles_to_mles,
            wit_infer_by_expr,
        },
    },
    structs::{
        Point, ProvingKey, TowerProofs, TowerProver, TowerProverSpec, ZKVMProvingKey, ZKVMWitnesses,
    },
    utils::{get_challenge_pows, next_pow2_instance_padding, optimal_sumcheck_threads},
    virtual_polys::VirtualPolynomials,
};

use super::{PublicValues, ZKVMOpcodeProof, ZKVMProof, ZKVMTableProof};

type ResultCreateTableProof<E, PCS> = (ZKVMTableProof<E, PCS>, HashMap<usize, E>);

pub struct ZKVMProver<E: ExtensionField, PCS: PolynomialCommitmentScheme<E>> {
    pub pk: ZKVMProvingKey<E, PCS>,
}

impl<E: ExtensionField, PCS: PolynomialCommitmentScheme<E>> ZKVMProver<E, PCS> {
    pub fn new(pk: ZKVMProvingKey<E, PCS>) -> Self {
        ZKVMProver { pk }
    }

    /// create proof for zkvm execution
    #[tracing::instrument(
        skip_all,
        name = "ZKVM_create_proof",
        fields(profiling_1),
        level = "trace"
    )]
    pub fn create_proof(
        &self,
        witnesses: ZKVMWitnesses<E>,
        pi: PublicValues<u32>,
        mut transcript: impl ForkableTranscript<E>,
    ) -> Result<ZKVMProof<E, PCS>, ZKVMError> {
        let span = entered_span!("commit_to_fixed_commit", profiling_1 = true);
        let mut vm_proof = ZKVMProof::empty(pi);

        // including raw public input to transcript
        for v in vm_proof.raw_pi.iter().flatten() {
            transcript.append_field_element(v);
        }

        let pi: Vec<ArcMultilinearExtension<E>> = vm_proof
            .raw_pi
            .iter()
            .map(|p| {
                let pi_mle: ArcMultilinearExtension<E> = p.to_vec().into_mle().into();
                pi_mle
            })
            .collect();

        // commit to fixed commitment
        for pk in self.pk.circuit_pks.values() {
            if let Some(fixed_commit) = &pk.vk.fixed_commit {
                PCS::write_commitment(fixed_commit, &mut transcript)
                    .map_err(ZKVMError::PCSError)?;
            }
        }
        exit_span!(span);

        // commit to main traces
        let mut commitments = BTreeMap::new();
        let mut wits = BTreeMap::new();
        let mut structural_wits = BTreeMap::new();

        let commit_to_traces_span = entered_span!("commit_to_traces", profiling_1 = true);
        // commit to opcode circuits first and then commit to table circuits, sorted by name
        for (circuit_name, witness) in witnesses.into_iter_sorted() {
            let num_instances = witness.num_instances();
            let span = entered_span!(
                "commit to iteration",
                circuit_name = circuit_name,
                profiling_2 = true
            );
            let num_witin = self
                .pk
                .circuit_pks
                .get(&circuit_name)
                .unwrap()
                .get_cs()
                .num_witin;

            let (witness, structural_witness) = match num_instances {
                0 => (vec![], vec![]),
                _ => {
                    let mut witness = witness.into_mles();
                    let structural_witness = witness.split_off(num_witin as usize);
                    commitments.insert(
                        circuit_name.clone(),
                        PCS::batch_commit_and_write(&self.pk.pp, &witness, &mut transcript)
                            .map_err(ZKVMError::PCSError)?,
                    );

                    (witness, structural_witness)
                }
            };
            exit_span!(span);
            wits.insert(
                circuit_name.clone(),
                (
                    witness.into_iter().map(|w| w.into()).collect_vec(),
                    num_instances,
                ),
            );
            structural_wits.insert(
                circuit_name,
                (
                    structural_witness
                        .into_iter()
                        .map(|v| v.into())
                        .collect_vec(),
                    num_instances,
                ),
            );
        }
        exit_span!(commit_to_traces_span);

        // squeeze two challenges from transcript
        let challenges = [
            transcript.read_challenge().elements,
            transcript.read_challenge().elements,
        ];
        tracing::debug!("challenges in prover: {:?}", challenges);

        let main_proofs_span = entered_span!("main_proofs", profiling_1 = true);
        let mut transcripts = transcript.fork(self.pk.circuit_pks.len());
        for ((circuit_name, pk), (i, transcript)) in self
            .pk
            .circuit_pks
            .iter() // Sorted by key.
            .zip_eq(transcripts.iter_mut().enumerate())
        {
            let (witness, num_instances) = wits
                .remove(circuit_name)
                .ok_or(ZKVMError::WitnessNotFound(circuit_name.clone()))?;
            if witness.is_empty() {
                continue;
            }
            let wits_commit = commitments.remove(circuit_name).unwrap();
            // TODO: add an enum for circuit type either in constraint_system or vk
            let cs = pk.get_cs();
            let is_opcode_circuit = cs.lk_table_expressions.is_empty()
                && cs.r_table_expressions.is_empty()
                && cs.w_table_expressions.is_empty();

            if is_opcode_circuit {
                tracing::debug!(
                    "opcode circuit {} has {} witnesses, {} reads, {} writes, {} lookups",
                    circuit_name,
                    cs.num_witin,
                    cs.r_expressions.len(),
                    cs.w_expressions.len(),
                    cs.lk_expressions.len(),
                );
                let opcode_proof = self.create_opcode_proof(
                    circuit_name,
                    &self.pk.pp,
                    pk,
                    witness,
                    wits_commit,
                    &pi,
                    num_instances,
                    transcript,
                    &challenges,
                )?;
                tracing::info!(
                    "generated proof for opcode {} with num_instances={}",
                    circuit_name,
                    num_instances
                );
                vm_proof
                    .opcode_proofs
                    .insert(circuit_name.clone(), (i, opcode_proof));
            } else {
                let (structural_witness, structural_num_instances) = structural_wits
                    .remove(circuit_name)
                    .ok_or(ZKVMError::WitnessNotFound(circuit_name.clone()))?;
                let (table_proof, pi_in_evals) = self.create_table_proof(
                    circuit_name,
                    &self.pk.pp,
                    pk,
                    witness,
                    wits_commit,
                    structural_witness,
                    &pi,
                    transcript,
                    &challenges,
                )?;
                tracing::info!(
                    "generated proof for table {} with num_instances={}, structural_num_instances={}",
                    circuit_name,
                    num_instances,
                    structural_num_instances
                );
                vm_proof
                    .table_proofs
                    .insert(circuit_name.clone(), (i, table_proof));
                for (idx, eval) in pi_in_evals {
                    vm_proof.update_pi_eval(idx, eval);
                }
            }
        }
        exit_span!(main_proofs_span);

        Ok(vm_proof)
    }
    /// create proof giving witness and num_instances
    /// major flow break down into
    /// 1: witness layer inferring from input -> output
    /// 2: proof (sumcheck reduce) from output to input
    #[allow(clippy::too_many_arguments)]
    #[tracing::instrument(skip_all, name = "create_opcode_proof", fields(circuit_name=name,profiling_2), level="trace")]
    pub fn create_opcode_proof(
        &self,
        name: &str,
        pp: &PCS::ProverParam,
        circuit_pk: &ProvingKey<E, PCS>,
        witnesses: Vec<ArcMultilinearExtension<'_, E>>,
        wits_commit: PCS::CommitmentWithWitness,
        pi: &[ArcMultilinearExtension<'_, E>],
        num_instances: usize,
        transcript: &mut impl Transcript<E>,
        challenges: &[E; 2],
    ) -> Result<ZKVMOpcodeProof<E, PCS>, ZKVMError> {
        let cs = circuit_pk.get_cs();
        let next_pow2_instances = next_pow2_instance_padding(num_instances);
        let log2_num_instances = ceil_log2(next_pow2_instances);
        let (chip_record_alpha, _) = (challenges[0], challenges[1]);

        // sanity check
        assert_eq!(witnesses.len(), cs.num_witin as usize);
        assert!(
            witnesses
                .iter()
                .all(|v| { v.evaluations().len() == next_pow2_instances })
        );

        let wit_inference_span = entered_span!("wit_inference", profiling_3 = true);
        // main constraint: read/write record witness inference
        let record_span = entered_span!("record");
        let records_wit: Vec<ArcMultilinearExtension<'_, E>> = cs
            .r_expressions
            .par_iter()
            .chain(cs.w_expressions.par_iter())
            .chain(cs.lk_expressions.par_iter())
            .map(|expr| {
                assert_eq!(expr.degree(), 1);
                wit_infer_by_expr(&[], &witnesses, &[], pi, challenges, expr)
            })
            .collect();
        let (r_records_wit, w_lk_records_wit) = records_wit.split_at(cs.r_expressions.len());
        let (w_records_wit, lk_records_wit) = w_lk_records_wit.split_at(cs.w_expressions.len());
        exit_span!(record_span);

        // product constraint: tower witness inference
        let (r_counts_per_instance, w_counts_per_instance, lk_counts_per_instance) = (
            cs.r_expressions.len(),
            cs.w_expressions.len(),
            cs.lk_expressions.len(),
        );
        let (log2_r_count, log2_w_count, log2_lk_count) = (
            ceil_log2(r_counts_per_instance),
            ceil_log2(w_counts_per_instance),
            ceil_log2(lk_counts_per_instance),
        );
        // process last layer by interleaving all the read/write record respectively
        // as last layer is the output of sel stage
        let span = entered_span!("tower_witness_r_last_layer");
        // TODO optimize last layer to avoid alloc new vector to save memory
        let r_records_last_layer =
            interleaving_mles_to_mles(r_records_wit, num_instances, NUM_FANIN, E::ONE);
        assert_eq!(r_records_last_layer.len(), NUM_FANIN);
        exit_span!(span);

        // infer all tower witness after last layer
        let span = entered_span!("tower_witness_r_layers");
        let r_wit_layers = infer_tower_product_witness(
            log2_num_instances + log2_r_count,
            r_records_last_layer,
            NUM_FANIN,
        );
        exit_span!(span);

        let span = entered_span!("tower_witness_w_last_layer");
        // TODO optimize last layer to avoid alloc new vector to save memory
        let w_records_last_layer =
            interleaving_mles_to_mles(w_records_wit, num_instances, NUM_FANIN, E::ONE);
        assert_eq!(w_records_last_layer.len(), NUM_FANIN);
        exit_span!(span);

        let span = entered_span!("tower_witness_w_layers");
        let w_wit_layers = infer_tower_product_witness(
            log2_num_instances + log2_w_count,
            w_records_last_layer,
            NUM_FANIN,
        );
        exit_span!(span);

        let span = entered_span!("tower_witness_lk_last_layer");
        // TODO optimize last layer to avoid alloc new vector to save memory
        let lk_records_last_layer =
            interleaving_mles_to_mles(lk_records_wit, num_instances, NUM_FANIN, chip_record_alpha);
        assert_eq!(lk_records_last_layer.len(), 2);
        exit_span!(span);

        let span = entered_span!("tower_witness_lk_layers");
        let lk_wit_layers = infer_tower_logup_witness(None, lk_records_last_layer);
        exit_span!(span);
        exit_span!(wit_inference_span);

        if cfg!(test) {
            // sanity check
            assert_eq!(lk_wit_layers.len(), log2_num_instances + log2_lk_count);
            assert_eq!(r_wit_layers.len(), log2_num_instances + log2_r_count);
            assert_eq!(w_wit_layers.len(), log2_num_instances + log2_w_count);
            assert!(lk_wit_layers.iter().enumerate().all(|(i, w)| {
                let expected_size = 1 << i;
                let (p1, p2, q1, q2) = (&w[0], &w[1], &w[2], &w[3]);
                p1.evaluations().len() == expected_size
                    && p2.evaluations().len() == expected_size
                    && q1.evaluations().len() == expected_size
                    && q2.evaluations().len() == expected_size
            }));
            assert!(r_wit_layers.iter().enumerate().all(|(i, r_wit_layer)| {
                let expected_size = 1 << (ceil_log2(NUM_FANIN) * i);
                r_wit_layer.len() == NUM_FANIN
                    && r_wit_layer
                        .iter()
                        .all(|f| f.evaluations().len() == expected_size)
            }));
            assert!(w_wit_layers.iter().enumerate().all(|(i, w_wit_layer)| {
                let expected_size = 1 << (ceil_log2(NUM_FANIN) * i);
                w_wit_layer.len() == NUM_FANIN
                    && w_wit_layer
                        .iter()
                        .all(|f| f.evaluations().len() == expected_size)
            }));
        }

        let sumcheck_span = entered_span!("SUMCHECK", profiling_3 = true);
        // product constraint tower sumcheck
        let tower_span = entered_span!("tower");
        // final evals for verifier
        let record_r_out_evals: Vec<E> = r_wit_layers[0]
            .iter()
            .map(|w| w.get_ext_field_vec()[0])
            .collect();
        let record_w_out_evals: Vec<E> = w_wit_layers[0]
            .iter()
            .map(|w| w.get_ext_field_vec()[0])
            .collect();
        let lk_p1_out_eval = lk_wit_layers[0][0].get_ext_field_vec()[0];
        let lk_p2_out_eval = lk_wit_layers[0][1].get_ext_field_vec()[0];
        let lk_q1_out_eval = lk_wit_layers[0][2].get_ext_field_vec()[0];
        let lk_q2_out_eval = lk_wit_layers[0][3].get_ext_field_vec()[0];
        assert!(record_r_out_evals.len() == NUM_FANIN && record_w_out_evals.len() == NUM_FANIN);
        let (rt_tower, tower_proof) = TowerProver::create_proof(
            vec![
                TowerProverSpec {
                    witness: r_wit_layers,
                },
                TowerProverSpec {
                    witness: w_wit_layers,
                },
            ],
            vec![TowerProverSpec {
                witness: lk_wit_layers,
            }],
            NUM_FANIN,
            transcript,
        );
        assert_eq!(
            rt_tower.len(),
            log2_num_instances
                + [log2_r_count, log2_w_count, log2_lk_count]
                    .iter()
                    .max()
                    .unwrap()
        );
        exit_span!(tower_span);

        tracing::debug!("tower sumcheck finished");
        // batch sumcheck: selector + main degree > 1 constraints
        let main_sel_span = entered_span!("main_sel");
        let (rt_r, rt_w, rt_lk, rt_non_lc_sumcheck): (Vec<E>, Vec<E>, Vec<E>, Vec<E>) = (
            tower_proof.prod_specs_points[0]
                .last()
                .expect("error getting rt_r")
                .to_vec(),
            tower_proof.prod_specs_points[1]
                .last()
                .expect("error getting rt_w")
                .to_vec(),
            tower_proof.logup_specs_points[0]
                .last()
                .expect("error getting rt_lk")
                .to_vec(),
            rt_tower[..log2_num_instances].to_vec(),
        );

        let num_threads = optimal_sumcheck_threads(log2_num_instances);
        let alpha_pow = get_challenge_pows(
            MAINCONSTRAIN_SUMCHECK_BATCH_SIZE + cs.assert_zero_sumcheck_expressions.len(),
            transcript,
        );
        let mut alpha_pow_iter = alpha_pow.iter();
        let (alpha_read, alpha_write, alpha_lk) = (
            alpha_pow_iter.next().unwrap(),
            alpha_pow_iter.next().unwrap(),
            alpha_pow_iter.next().unwrap(),
        );
        // create selector: all ONE, but padding ZERO to ceil_log2
        let (sel_r, sel_w, sel_lk): (
            ArcMultilinearExtension<E>,
            ArcMultilinearExtension<E>,
            ArcMultilinearExtension<E>,
        ) = {
            // TODO sel can be shared if expression count match
            let mut sel_r = build_eq_x_r_vec(&rt_r[log2_r_count..]);
            if num_instances < sel_r.len() {
                sel_r.splice(
                    num_instances..sel_r.len(),
                    std::iter::repeat(E::ZERO).take(sel_r.len() - num_instances),
                );
            }

            let mut sel_w = build_eq_x_r_vec(&rt_w[log2_w_count..]);
            if num_instances < sel_w.len() {
                sel_w.splice(
                    num_instances..sel_w.len(),
                    std::iter::repeat(E::ZERO).take(sel_w.len() - num_instances),
                );
            }

            let mut sel_lk = build_eq_x_r_vec(&rt_lk[log2_lk_count..]);
            if num_instances < sel_lk.len() {
                sel_lk.splice(
                    num_instances..sel_lk.len(),
                    std::iter::repeat(E::ZERO).take(sel_lk.len() - num_instances),
                );
            }

            (
                sel_r.into_mle().into(),
                sel_w.into_mle().into(),
                sel_lk.into_mle().into(),
            )
        };

        // only initialize when circuit got assert_zero_sumcheck_expressions
        let sel_non_lc_zero_sumcheck = {
            if !cs.assert_zero_sumcheck_expressions.is_empty() {
                let mut sel_non_lc_zero_sumcheck = build_eq_x_r_vec(&rt_non_lc_sumcheck);
                if num_instances < sel_non_lc_zero_sumcheck.len() {
                    sel_non_lc_zero_sumcheck.splice(
                        num_instances..sel_non_lc_zero_sumcheck.len(),
                        std::iter::repeat(E::ZERO)
                            .take(sel_non_lc_zero_sumcheck.len() - num_instances),
                    );
                }
                let sel_non_lc_zero_sumcheck: ArcMultilinearExtension<E> =
                    sel_non_lc_zero_sumcheck.into_mle().into();
                Some(sel_non_lc_zero_sumcheck)
            } else {
                None
            }
        };

        let mut virtual_polys = VirtualPolynomials::<E>::new(num_threads, log2_num_instances);

        let eq_r = build_eq_x_r_vec(&rt_r[..log2_r_count]);
        let eq_w = build_eq_x_r_vec(&rt_w[..log2_w_count]);
        let eq_lk = build_eq_x_r_vec(&rt_lk[..log2_lk_count]);

        // read
        // rt_r := rt || rs
        for i in 0..r_counts_per_instance {
            // \sum_t (sel(rt, t) * (\sum_i alpha_read * eq(rs, i) * record_r[t] ))
            virtual_polys.add_mle_list(vec![&sel_r, &r_records_wit[i]], eq_r[i] * alpha_read);
        }
        // \sum_t alpha_read * sel(rt, t) * (\sum_i (eq(rs, i)) - 1)
        virtual_polys.add_mle_list(
            vec![&sel_r],
            *alpha_read * eq_r[r_counts_per_instance..].iter().sum::<E>() - *alpha_read,
        );

        // write
        // rt := rt || rs
        for i in 0..w_counts_per_instance {
            // \sum_t (sel(rt, t) * (\sum_i alpha_write * eq(rs, i) * record_w[i] ))
            virtual_polys.add_mle_list(vec![&sel_w, &w_records_wit[i]], eq_w[i] * alpha_write);
        }
        // \sum_t alpha_write * sel(rt, t) * (\sum_i (eq(rs, i)) - 1)
        virtual_polys.add_mle_list(
            vec![&sel_w],
            *alpha_write * eq_w[w_counts_per_instance..].iter().sum::<E>() - *alpha_write,
        );

        // lk denominator
        // rt := rt || rs
        for i in 0..lk_counts_per_instance {
            // \sum_t (sel(rt, t) * (\sum_i alpha_lk* eq(rs, i) * record_w[i]))
            virtual_polys.add_mle_list(vec![&sel_lk, &lk_records_wit[i]], eq_lk[i] * alpha_lk);
        }
        // \sum_t alpha_lk * sel(rt, t) * chip_record_alpha * (\sum_i (eq(rs, i)) - 1)
        virtual_polys.add_mle_list(
            vec![&sel_lk],
            *alpha_lk
                * chip_record_alpha
                * (eq_lk[lk_counts_per_instance..].iter().sum::<E>() - E::ONE),
        );

        let mut distrinct_zerocheck_terms_set = BTreeSet::new();
        // degree > 1 zero expression sumcheck
        if !cs.assert_zero_sumcheck_expressions.is_empty() {
            assert!(sel_non_lc_zero_sumcheck.is_some());

            // \sum_t (sel(rt, t) * (\sum_j alpha_{j} * all_monomial_terms(t) ))
            for ((expr, name), alpha) in cs
                .assert_zero_sumcheck_expressions
                .iter()
                .zip_eq(cs.assert_zero_sumcheck_expressions_namespace_map.iter())
                .zip_eq(alpha_pow_iter)
            {
                // sanity check in debug build and output != instance index for zero check sumcheck poly
                if cfg!(debug_assertions) {
                    let expected_zero_poly =
                        wit_infer_by_expr(&[], &witnesses, &[], pi, challenges, expr);
                    let top_100_errors = expected_zero_poly
                        .get_base_field_vec()
                        .iter()
                        .enumerate()
                        .filter(|(_, v)| **v != E::BaseField::ZERO)
                        .take(100)
                        .collect_vec();
                    if !top_100_errors.is_empty() {
                        return Err(ZKVMError::InvalidWitness(format!(
                            "degree > 1 zero check virtual poly: expr {name} != 0 on instance indexes: {}...",
                            top_100_errors.into_iter().map(|(i, _)| i).join(",")
                        )));
                    }
                }

                distrinct_zerocheck_terms_set.extend(virtual_polys.add_mle_list_by_expr(
                    sel_non_lc_zero_sumcheck.as_ref(),
                    witnesses.iter().collect_vec(),
                    expr,
                    challenges,
                    *alpha,
                ));
            }
        }

        tracing::debug!("main sel sumcheck start");
        let (main_sel_sumcheck_proofs, state) = IOPProverState::prove_batch_polys(
            num_threads,
            virtual_polys.get_batched_polys(),
            transcript,
        );
        tracing::debug!("main sel sumcheck end");

        let main_sel_evals = state.get_mle_final_evaluations();
        assert_eq!(
            main_sel_evals.len(),
            r_counts_per_instance
                + w_counts_per_instance
                + lk_counts_per_instance
                + 3 // 3 from [sel_r, sel_w, sel_lk]
                + if cs.assert_zero_sumcheck_expressions.is_empty() {
                    0
                } else {
                    distrinct_zerocheck_terms_set.len() + 1 // +1 from sel_non_lc_zero_sumcheck
                }
        );
        let mut main_sel_evals_iter = main_sel_evals.into_iter();
        main_sel_evals_iter.next(); // skip sel_r
        let r_records_in_evals = (0..r_counts_per_instance)
            .map(|_| main_sel_evals_iter.next().unwrap())
            .collect_vec();
        main_sel_evals_iter.next(); // skip sel_w
        let w_records_in_evals = (0..w_counts_per_instance)
            .map(|_| main_sel_evals_iter.next().unwrap())
            .collect_vec();
        main_sel_evals_iter.next(); // skip sel_lk
        let lk_records_in_evals = (0..lk_counts_per_instance)
            .map(|_| main_sel_evals_iter.next().unwrap())
            .collect_vec();
        assert!(
            // we can skip all the rest of degree > 1 monomial terms because all the witness evaluation will be evaluated at last step
            // and pass to verifier
            main_sel_evals_iter.count()
                == if cs.assert_zero_sumcheck_expressions.is_empty() {
                    0
                } else {
                    distrinct_zerocheck_terms_set.len() + 1
                }
        );
        let input_open_point = main_sel_sumcheck_proofs.point.clone();
        assert!(input_open_point.len() == log2_num_instances);
        exit_span!(main_sel_span);
        exit_span!(sumcheck_span);

        let span = entered_span!("witin::evals", profiling_3 = true);
        let wits_in_evals: Vec<E> = witnesses
            .par_iter()
            .map(|poly| poly.evaluate(&input_open_point))
            .collect();
        exit_span!(span);

        let pcs_open_span = entered_span!("pcs_open", profiling_3 = true);
        let opening_dur = std::time::Instant::now();
        tracing::debug!(
            "[opcode {}]: build opening proof for {} polys",
            name,
            witnesses.len()
        );
        let wits_opening_proof = PCS::simple_batch_open(
            pp,
            &witnesses,
            &wits_commit,
            &input_open_point,
            wits_in_evals.as_slice(),
            transcript,
        )
        .map_err(ZKVMError::PCSError)?;
        tracing::info!(
            "[opcode {}] build opening proof took {:?}",
            name,
            opening_dur.elapsed(),
        );
        exit_span!(pcs_open_span);
        let wits_commit = PCS::get_pure_commitment(&wits_commit);

        Ok(ZKVMOpcodeProof {
            num_instances,
            record_r_out_evals,
            record_w_out_evals,
            lk_p1_out_eval,
            lk_p2_out_eval,
            lk_q1_out_eval,
            lk_q2_out_eval,
            tower_proof,
            main_sel_sumcheck_proofs: main_sel_sumcheck_proofs.proofs,
            r_records_in_evals,
            w_records_in_evals,
            lk_records_in_evals,
            wits_commit,
            wits_opening_proof,
            wits_in_evals,
        })
    }

    #[allow(clippy::too_many_arguments)]
    /// support batch prove for logup + product arguments each with different num_vars()
    /// side effect: concurrency will be determine based on min(thread, num_vars()),
    /// so suggest dont batch too small table (size < threads) with large table together
    #[tracing::instrument(skip_all, name = "create_table_proof", fields(table_name=name, profiling_2), level="trace")]
    pub fn create_table_proof(
        &self,
        name: &str,
        pp: &PCS::ProverParam,
        circuit_pk: &ProvingKey<E, PCS>,
        witnesses: Vec<ArcMultilinearExtension<'_, E>>,
        wits_commit: PCS::CommitmentWithWitness,
        structural_witnesses: Vec<ArcMultilinearExtension<'_, E>>,
        pi: &[ArcMultilinearExtension<'_, E>],
        transcript: &mut impl Transcript<E>,
        challenges: &[E; 2],
    ) -> Result<ResultCreateTableProof<E, PCS>, ZKVMError> {
        let cs = circuit_pk.get_cs();
        let fixed = circuit_pk
            .fixed_traces
            .as_ref()
            .map(|fixed_traces| {
                fixed_traces
                    .iter()
                    .map(|f| -> ArcMultilinearExtension<E> { Arc::new(f.get_ranged_mle(1, 0)) })
                    .collect::<Vec<ArcMultilinearExtension<E>>>()
            })
            .unwrap_or_default();
        // sanity check
        assert_eq!(witnesses.len(), cs.num_witin as usize);
        assert_eq!(structural_witnesses.len(), cs.num_structural_witin as usize);
        assert_eq!(fixed.len(), cs.num_fixed);
        // check all witness size are power of 2
        assert!(
            witnesses
                .iter()
                .all(|v| { v.evaluations().len().is_power_of_two() })
        );
        assert!(
            structural_witnesses
                .iter()
                .all(|v| { v.evaluations().len().is_power_of_two() })
        );
        assert!(
            !cs.r_table_expressions.is_empty()
                || !cs.w_table_expressions.is_empty()
                || !cs.lk_table_expressions.is_empty()
        );
        assert!(
            cs.r_table_expressions
                .iter()
                .zip_eq(cs.w_table_expressions.iter())
                .all(|(r, w)| r.table_spec.len == w.table_spec.len)
        );

        let wit_inference_span = entered_span!("wit_inference");
        // main constraint: lookup denominator and numerator record witness inference
        let record_span = entered_span!("record");
        let mut records_wit: Vec<ArcMultilinearExtension<'_, E>> = cs
            .r_table_expressions
            .par_iter()
            .map(|r| &r.expr)
            .chain(cs.w_table_expressions.par_iter().map(|w| &w.expr))
            .chain(
                cs.lk_table_expressions
                    .par_iter()
                    .map(|lk| &lk.multiplicity),
            )
            .chain(cs.lk_table_expressions.par_iter().map(|lk| &lk.values))
            .map(|expr| {
                assert_eq!(expr.degree(), 1);
                wit_infer_by_expr(
                    &fixed,
                    &witnesses,
                    &structural_witnesses,
                    pi,
                    challenges,
                    expr,
                )
            })
            .collect();
        let max_log2_num_instance = records_wit.iter().map(|mle| mle.num_vars()).max().unwrap();
        let min_log2_num_instance = records_wit.iter().map(|mle| mle.num_vars()).min().unwrap();
        let (r_set_wit, remains) = records_wit.split_at_mut(cs.r_table_expressions.len());
        let (w_set_wit, remains) = remains.split_at_mut(cs.w_table_expressions.len());
        let (lk_n_wit, remains) = remains.split_at_mut(cs.lk_table_expressions.len());
        let (lk_d_wit, _empty) = remains.split_at_mut(cs.lk_table_expressions.len());
        assert!(_empty.is_empty());

        exit_span!(record_span);

        // infer all tower witness after last layer
        let span = entered_span!("tower_witness_lk_last_layer");
        let mut r_set_last_layer = r_set_wit
            .iter()
            .chain(w_set_wit.iter())
            .map(|wit| {
                let (first, second) = wit
                    .get_ext_field_vec()
                    .split_at(wit.evaluations().len() / 2);
                let res = vec![
                    first.to_vec().into_mle().into(),
                    second.to_vec().into_mle().into(),
                ];
                assert_eq!(res.len(), NUM_FANIN_LOGUP);
                res
            })
            .collect::<Vec<_>>();
        let w_set_last_layer = r_set_last_layer.split_off(r_set_wit.len());

        let lk_numerator_last_layer = lk_n_wit
            .iter()
            .map(|wit| {
                let (first, second) = wit
                    .get_base_field_vec()
                    .split_at(wit.evaluations().len() / 2);
                let res = vec![
                    first.to_vec().into_mle().into(),
                    second.to_vec().into_mle().into(),
                ];
                assert_eq!(res.len(), NUM_FANIN_LOGUP);
                res
            })
            .collect::<Vec<_>>();
        let lk_denominator_last_layer = lk_d_wit
            .iter_mut()
            .map(|wit| {
                let (first, second) = wit
                    .get_ext_field_vec()
                    .split_at(wit.evaluations().len() / 2);
                let res = vec![
                    first.to_vec().into_mle().into(),
                    second.to_vec().into_mle().into(),
                ];
                assert_eq!(res.len(), NUM_FANIN_LOGUP);
                res
            })
            .collect::<Vec<_>>();
        exit_span!(span);

        let span = entered_span!("tower_witness_lk_layers");
        let r_wit_layers = r_set_last_layer
            .into_iter()
            .zip(r_set_wit.iter())
            .map(|(last_layer, origin_mle)| {
                infer_tower_product_witness(origin_mle.num_vars(), last_layer, NUM_FANIN)
            })
            .collect_vec();
        let w_wit_layers = w_set_last_layer
            .into_iter()
            .zip(w_set_wit.iter())
            .map(|(last_layer, origin_mle)| {
                infer_tower_product_witness(origin_mle.num_vars(), last_layer, NUM_FANIN)
            })
            .collect_vec();
        let lk_wit_layers = lk_numerator_last_layer
            .into_iter()
            .zip(lk_denominator_last_layer)
            .map(|(lk_n, lk_d)| infer_tower_logup_witness(Some(lk_n), lk_d))
            .collect_vec();
        exit_span!(span);
        exit_span!(wit_inference_span);

        if cfg!(test) {
            // sanity check
            assert_eq!(r_wit_layers.len(), cs.r_table_expressions.len());
            assert!(
                r_wit_layers
                    .iter()
                    .zip(r_set_wit.iter()) // depth equals to num_vars
                    .all(|(layers, origin_mle)| layers.len() == origin_mle.num_vars())
            );
            assert!(r_wit_layers.iter().all(|layers| {
                layers.iter().enumerate().all(|(i, w)| {
                    let expected_size = 1 << i;
                    w[0].evaluations().len() == expected_size
                        && w[1].evaluations().len() == expected_size
                })
            }));

            assert_eq!(w_wit_layers.len(), cs.w_table_expressions.len());
            assert!(
                w_wit_layers
                    .iter()
                    .zip(w_set_wit.iter()) // depth equals to num_vars
                    .all(|(layers, origin_mle)| layers.len() == origin_mle.num_vars())
            );
            assert!(w_wit_layers.iter().all(|layers| {
                layers.iter().enumerate().all(|(i, w)| {
                    let expected_size = 1 << i;
                    w[0].evaluations().len() == expected_size
                        && w[1].evaluations().len() == expected_size
                })
            }));

            assert_eq!(lk_wit_layers.len(), cs.lk_table_expressions.len());
            assert!(
                lk_wit_layers
                    .iter()
                    .zip(lk_n_wit.iter()) // depth equals to num_vars
                    .all(|(layers, origin_mle)| layers.len() == origin_mle.num_vars())
            );
            assert!(lk_wit_layers.iter().all(|layers| {
                layers.iter().enumerate().all(|(i, w)| {
                    let expected_size = 1 << i;
                    let (p1, p2, q1, q2) = (&w[0], &w[1], &w[2], &w[3]);
                    p1.evaluations().len() == expected_size
                        && p2.evaluations().len() == expected_size
                        && q1.evaluations().len() == expected_size
                        && q2.evaluations().len() == expected_size
                })
            }));
        }

        let sumcheck_span = entered_span!("sumcheck");
        // product constraint tower sumcheck
        let tower_span = entered_span!("tower");
        // final evals for verifier
        let r_out_evals = r_wit_layers
            .iter()
            .map(|r_wit_layers| {
                [
                    r_wit_layers[0][0].get_ext_field_vec()[0],
                    r_wit_layers[0][1].get_ext_field_vec()[0],
                ]
            })
            .collect_vec();
        let w_out_evals = w_wit_layers
            .iter()
            .map(|w_wit_layers| {
                [
                    w_wit_layers[0][0].get_ext_field_vec()[0],
                    w_wit_layers[0][1].get_ext_field_vec()[0],
                ]
            })
            .collect_vec();
        let lk_out_evals = lk_wit_layers
            .iter()
            .map(|lk_wit_layers| {
                [
                    // p1, p2, q1, q2
                    lk_wit_layers[0][0].get_ext_field_vec()[0],
                    lk_wit_layers[0][1].get_ext_field_vec()[0],
                    lk_wit_layers[0][2].get_ext_field_vec()[0],
                    lk_wit_layers[0][3].get_ext_field_vec()[0],
                ]
            })
            .collect_vec();

        // (non uniform) collect dynamic address hints as witness for verifier
        let rw_hints_num_vars = structural_witnesses
            .iter()
            .map(|mle| mle.num_vars())
            .collect_vec();
        for var in rw_hints_num_vars.iter() {
            transcript.append_message(&var.to_le_bytes());
        }

        let (rt_tower, tower_proof) = TowerProver::create_proof(
            // pattern [r1, w1, r2, w2, ...] same pair are chain together
            r_wit_layers
                .into_iter()
                .zip(w_wit_layers)
                .flat_map(|(r, w)| {
                    vec![TowerProverSpec { witness: r }, TowerProverSpec {
                        witness: w,
                    }]
                })
                .collect_vec(),
            lk_wit_layers
                .into_iter()
                .map(|lk_wit_layers| TowerProverSpec {
                    witness: lk_wit_layers,
                })
                .collect_vec(),
            NUM_FANIN_LOGUP,
            transcript,
        );
        assert_eq!(
            rt_tower.len(), // num var length should equal to max_num_instance
            max_log2_num_instance
        );
        exit_span!(tower_span);

        // In table proof, we always skip same point sumcheck for now
        // as tower sumcheck batch product argument/logup in same length
        let is_skip_same_point_sumcheck = true;

        let (input_open_point, same_r_sumcheck_proofs, rw_in_evals, lk_in_evals) =
            if is_skip_same_point_sumcheck {
                (rt_tower, None, vec![], vec![])
            } else {
                // one sumcheck to make them opening on same point r (with different prefix)
                // If all table length are the same, we can skip this sumcheck
                let span = entered_span!("opening_same_point");
                // NOTE: max concurrency will be dominated by smallest table since it will blo
                let num_threads = optimal_sumcheck_threads(min_log2_num_instance);
                let alpha_pow = get_challenge_pows(
                    cs.r_table_expressions.len()
                        + cs.w_table_expressions.len()
                        + cs.lk_table_expressions.len() * 2,
                    transcript,
                );
                let mut alpha_pow_iter = alpha_pow.iter();

                // create eq
                // TODO same size rt lead to same identical poly eq which can be merged together
                let eq = tower_proof
                    .prod_specs_points
                    .iter()
                    .step_by(2) // r,w are in same length therefore share same point
                    .chain(tower_proof.logup_specs_points.iter())
                    .map(|layer_points| {
                        let rt = layer_points.last().unwrap();
                        build_eq_x_r_vec(rt).into_mle().into()
                    })
                    .collect::<Vec<ArcMultilinearExtension<E>>>();

                let (eq_rw, eq_lk) = eq.split_at(cs.r_table_expressions.len());

                let mut virtual_polys =
                    VirtualPolynomials::<E>::new(num_threads, max_log2_num_instance);

                // alpha_r{i} * eq(rt_{i}, s) * r(s) + alpha_w{i} * eq(rt_{i}, s) * w(s)
                for ((r_set_wit, w_set_wit), eq) in r_set_wit
                    .iter()
                    .zip_eq(w_set_wit.iter())
                    .zip_eq(eq_rw.iter())
                {
                    let alpha = alpha_pow_iter.next().unwrap();
                    virtual_polys.add_mle_list(vec![eq, r_set_wit], *alpha);
                    let alpha = alpha_pow_iter.next().unwrap();
                    virtual_polys.add_mle_list(vec![eq, w_set_wit], *alpha);
                }

                // alpha_lkn{i} * eq(rt_{i}, s) * lk_n(s) + alpha_lkd{i} * eq(rt_{i}, s) * lk_d(s)
                for ((lk_n_wit, lk_d_wit), eq) in
                    lk_n_wit.iter().zip_eq(lk_d_wit.iter()).zip_eq(eq_lk.iter())
                {
                    let alpha = alpha_pow_iter.next().unwrap();
                    virtual_polys.add_mle_list(vec![eq, lk_n_wit], *alpha);
                    let alpha = alpha_pow_iter.next().unwrap();
                    virtual_polys.add_mle_list(vec![eq, lk_d_wit], *alpha);
                }

                let (same_r_sumcheck_proofs, state) = IOPProverState::prove_batch_polys(
                    num_threads,
                    virtual_polys.get_batched_polys(),
                    transcript,
                );
                let evals = state.get_mle_final_evaluations();
                let mut evals_iter = evals.into_iter();
                let rw_in_evals = cs
                    // r, w table len are identical
                    .r_table_expressions
                    .iter()
                    .flat_map(|_table| {
                        let _eq = evals_iter.next().unwrap(); // skip eq
                        [evals_iter.next().unwrap(), evals_iter.next().unwrap()] // r, w
                    })
                    .collect_vec();
                let lk_in_evals = cs
                    .lk_table_expressions
                    .iter()
                    .flat_map(|_table| {
                        let _eq = evals_iter.next().unwrap(); // skip eq
                        [evals_iter.next().unwrap(), evals_iter.next().unwrap()] // n, d
                    })
                    .collect_vec();
                assert_eq!(evals_iter.count(), 0);

                let input_open_point = same_r_sumcheck_proofs.point.clone();
                assert_eq!(input_open_point.len(), max_log2_num_instance);
                exit_span!(span);

                (
                    input_open_point,
                    Some(same_r_sumcheck_proofs.proofs),
                    rw_in_evals,
                    lk_in_evals,
                )
            };

        exit_span!(sumcheck_span);
        let span = entered_span!("fixed::evals + witin::evals");
        let mut evals = witnesses
            .par_iter()
            .chain(fixed.par_iter())
            .map(|poly| poly.evaluate(&input_open_point[..poly.num_vars()]))
            .collect::<Vec<_>>();
        let fixed_in_evals = evals.split_off(witnesses.len());
        let wits_in_evals = evals;

        // evaluate pi if there is instance query
        let mut pi_in_evals: HashMap<usize, E> = HashMap::new();
        if !cs.instance_name_map.is_empty() {
            let span = entered_span!("pi::evals");
            for &Instance(idx) in cs.instance_name_map.keys() {
                let poly = &pi[idx];
                pi_in_evals.insert(idx, poly.evaluate(&input_open_point[..poly.num_vars()]));
            }
            exit_span!(span);
        }
        exit_span!(span);

        let pcs_opening = entered_span!("pcs_opening");
        let (fixed_opening_proof, _fixed_commit) = if !fixed.is_empty() {
            (
                Some(
                    PCS::simple_batch_open(
                        pp,
                        &fixed,
                        circuit_pk.fixed_commit_wd.as_ref().unwrap(),
                        &input_open_point,
                        fixed_in_evals.as_slice(),
                        transcript,
                    )
                    .map_err(ZKVMError::PCSError)?,
                ),
                Some(PCS::get_pure_commitment(
                    circuit_pk.fixed_commit_wd.as_ref().unwrap(),
                )),
            )
        } else {
            (None, None)
        };

        tracing::debug!(
            "[table {}] build opening proof for {} fixed polys",
            name,
            fixed.len()
        );
        let wits_opening_proof = PCS::simple_batch_open(
            pp,
            &witnesses,
            &wits_commit,
            &input_open_point,
            wits_in_evals.as_slice(),
            transcript,
        )
        .map_err(ZKVMError::PCSError)?;
        exit_span!(pcs_opening);
        let wits_commit = PCS::get_pure_commitment(&wits_commit);
        tracing::debug!(
            "[table {}] build opening proof for {} polys",
            name,
            witnesses.len(),
        );

        Ok((
            ZKVMTableProof {
                r_out_evals,
                w_out_evals,
                lk_out_evals,
                same_r_sumcheck_proofs,
                rw_in_evals,
                lk_in_evals,
                tower_proof,
                fixed_in_evals,
                fixed_opening_proof,
                rw_hints_num_vars,
                wits_in_evals,
                wits_commit,
                wits_opening_proof,
            },
            pi_in_evals,
        ))
    }
}

/// TowerProofs
impl<E: ExtensionField> TowerProofs<E> {
    pub fn new(prod_spec_size: usize, logup_spec_size: usize) -> Self {
        TowerProofs {
            proofs: vec![],
            prod_specs_eval: vec![vec![]; prod_spec_size],
            logup_specs_eval: vec![vec![]; logup_spec_size],
            prod_specs_points: vec![vec![]; prod_spec_size],
            logup_specs_points: vec![vec![]; logup_spec_size],
        }
    }
    pub fn push_sumcheck_proofs(&mut self, proofs: Vec<IOPProverMessage<E>>) {
        self.proofs.push(proofs);
    }

    pub fn push_prod_evals_and_point(&mut self, spec_index: usize, evals: Vec<E>, point: Vec<E>) {
        self.prod_specs_eval[spec_index].push(evals);
        self.prod_specs_points[spec_index].push(point);
    }

    pub fn push_logup_evals_and_point(&mut self, spec_index: usize, evals: Vec<E>, point: Vec<E>) {
        self.logup_specs_eval[spec_index].push(evals);
        self.logup_specs_points[spec_index].push(point);
    }

    pub fn prod_spec_size(&self) -> usize {
        self.prod_specs_eval.len()
    }

    pub fn logup_spec_size(&self) -> usize {
        self.logup_specs_eval.len()
    }
}

/// Tower Prover
impl TowerProver {
    #[tracing::instrument(skip_all, name = "tower_prover_create_proof", level = "trace")]
    pub fn create_proof<'a, E: ExtensionField>(
        prod_specs: Vec<TowerProverSpec<'a, E>>,
        logup_specs: Vec<TowerProverSpec<'a, E>>,
        num_fanin: usize,
        transcript: &mut impl Transcript<E>,
    ) -> (Point<E>, TowerProofs<E>) {
        // XXX to sumcheck batched product argument with logup, we limit num_product_fanin to 2
        // TODO mayber give a better naming?
        assert_eq!(num_fanin, 2);

        let mut proofs = TowerProofs::new(prod_specs.len(), logup_specs.len());
        let log_num_fanin = ceil_log2(num_fanin);
        // -1 for sliding windows size 2: (cur_layer, next_layer) w.r.t total size
        let max_round_index = prod_specs
            .iter()
            .chain(logup_specs.iter())
            .map(|m| m.witness.len())
            .max()
            .unwrap()
            - 1; // index start from 0

        // generate alpha challenge
        let alpha_pows = get_challenge_pows(
            prod_specs.len() +
            // logup occupy 2 sumcheck: numerator and denominator
            logup_specs.len() * 2,
            transcript,
        );
        let initial_rt: Point<E> = (0..log_num_fanin)
            .map(|_| transcript.get_and_append_challenge(b"product_sum").elements)
            .collect_vec();

        let (next_rt, _) =
            (1..=max_round_index).fold((initial_rt, alpha_pows), |(out_rt, alpha_pows), round| {
                // in first few round we just run on single thread
                let num_threads = optimal_sumcheck_threads(out_rt.len());

                let eq: ArcMultilinearExtension<E> = build_eq_x_r_vec(&out_rt).into_mle().into();
                let mut virtual_polys = VirtualPolynomials::<E>::new(num_threads, out_rt.len());

                for (s, alpha) in izip!(&prod_specs, &alpha_pows) {
                    if round < s.witness.len() {
                        let layer_polys = &s.witness[round];

                        // sanity check
                        assert_eq!(layer_polys.len(), num_fanin);
                        assert!(
                            layer_polys
                                .iter()
                                .all(|f| {
                                    f.evaluations().len() == 1 << (log_num_fanin * round)
                                })
                        );

                        // \sum_s eq(rt, s) * alpha^{i} * ([in_i0[s] * in_i1[s] * .... in_i{num_product_fanin}[s]])
                        virtual_polys.add_mle_list(
                            [vec![&eq], layer_polys.iter().collect()].concat(),
                            *alpha,
                        )
                    }
                }

                for (s, alpha) in izip!(&logup_specs, alpha_pows[prod_specs.len()..].chunks(2))
                {
                    if round < s.witness.len() {
                        let layer_polys = &s.witness[round];
                        // sanity check
                        assert_eq!(layer_polys.len(), 4); // p1, q1, p2, q2
                        assert!(
                            layer_polys
                                .iter()
                                .all(|f| f.evaluations().len() == 1 << (log_num_fanin * round)),
                        );

                        let (alpha_numerator, alpha_denominator) = (&alpha[0], &alpha[1]);

                        let (q2, q1, p2, p1) = (
                            &layer_polys[3],
                            &layer_polys[2],
                            &layer_polys[1],
                            &layer_polys[0],
                        );

                        // \sum_s eq(rt, s) * alpha_numerator^{i} * (p1 * q2 + p2 * q1)
                        virtual_polys.add_mle_list(vec![&eq, &p1, &q2], *alpha_numerator);
                        virtual_polys.add_mle_list(vec![&eq, &p2, &q1], *alpha_numerator);

                        // \sum_s eq(rt, s) * alpha_denominator^{i} * (q1 * q2)
                        virtual_polys.add_mle_list(vec![&eq, &q1, &q2], *alpha_denominator);
                    }
                }

                let wrap_batch_span = entered_span!("wrap_batch");
                // NOTE: at the time of adding this span, visualizing it with the flamegraph layer
                // shows it to be (inexplicably) much more time-consuming than the call to `prove_batch_polys`
                // This is likely a bug in the tracing-flame crate.
                let (sumcheck_proofs, state) = IOPProverState::prove_batch_polys(
                    num_threads,
                    virtual_polys.get_batched_polys(),
                    transcript,
                );
                exit_span!(wrap_batch_span);

                proofs.push_sumcheck_proofs(sumcheck_proofs.proofs);

                // rt' = r_merge || rt
                let r_merge = (0..log_num_fanin)
                    .map(|_| transcript.get_and_append_challenge(b"merge").elements)
                    .collect_vec();
                let rt_prime = [sumcheck_proofs.point, r_merge].concat();

                // generate next round challenge
                let next_alpha_pows = get_challenge_pows(
                    prod_specs.len() +logup_specs.len() * 2, // logup occupy 2 sumcheck: numerator and denominator
                    transcript,
                );
                let evals = state.get_mle_final_evaluations();
                let mut evals_iter = evals.iter();
                evals_iter.next(); // skip first eq
                for (i, s) in enumerate(&prod_specs) {
                    if round < s.witness.len() {
                        // collect evals belong to current spec
                        proofs.push_prod_evals_and_point(
                            i,
                            (0..num_fanin)
                                .map(|_| *evals_iter.next().expect("insufficient evals length"))
                                .collect::<Vec<E>>(),
                                rt_prime.clone(),
                        );
                    }
                }
                for (i, s) in enumerate(&logup_specs) {
                    if round < s.witness.len() {
                        // collect evals belong to current spec
                        // p1, q2, p2, q1
                        let p1 = *evals_iter.next().expect("insufficient evals length");
                        let q2 = *evals_iter.next().expect("insufficient evals length");
                        let p2 = *evals_iter.next().expect("insufficient evals length");
                        let q1 = *evals_iter.next().expect("insufficient evals length");
                        proofs.push_logup_evals_and_point(i, vec![p1, p2, q1, q2], rt_prime.clone());
                    }
                }
                assert_eq!(evals_iter.next(), None);
                (rt_prime, next_alpha_pows)
            });

        (next_rt, proofs)
    }
}
