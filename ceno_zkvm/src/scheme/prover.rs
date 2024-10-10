use ff_ext::ExtensionField;
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

use itertools::Itertools;
use mpcs::PolynomialCommitmentScheme;
use multilinear_extensions::{
    mle::{IntoMLE, MultilinearExtension},
    util::ceil_log2,
    virtual_poly::build_eq_x_r_vec,
    virtual_poly_v2::ArcMultilinearExtension,
};
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use sumcheck::{
    entered_span, exit_span,
    structs::{IOPProverMessage, IOPProverStateV2},
};
use transcript::Transcript;

use crate::{
    error::ZKVMError,
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
    utils::{get_challenge_pows, next_pow2_instance_padding, proper_num_threads},
    virtual_polys::VirtualPolynomials,
};

use super::{PublicValues, ZKVMOpcodeProof, ZKVMProof, ZKVMTableProof};

pub struct ZKVMProver<E: ExtensionField, PCS: PolynomialCommitmentScheme<E>> {
    pub pk: ZKVMProvingKey<E, PCS>,
}

impl<E: ExtensionField, PCS: PolynomialCommitmentScheme<E>> ZKVMProver<E, PCS> {
    pub fn new(pk: ZKVMProvingKey<E, PCS>) -> Self {
        ZKVMProver { pk }
    }

    /// create proof for zkvm execution
    pub fn create_proof(
        &self,
        witnesses: ZKVMWitnesses<E>,
        pi: PublicValues<u32>,
        max_threads: usize,
        mut transcript: Transcript<E>,
    ) -> Result<ZKVMProof<E, PCS>, ZKVMError> {
        let mut vm_proof = ZKVMProof::empty(pi);
        let pi = &vm_proof.pv;

        // commit to fixed commitment
        for (_, pk) in self.pk.circuit_pks.iter() {
            if let Some(fixed_commit) = &pk.vk.fixed_commit {
                PCS::write_commitment(fixed_commit, &mut transcript)
                    .map_err(ZKVMError::PCSError)?;
            }
        }

        // commit to main traces
        let mut commitments = BTreeMap::new();
        let mut wits = BTreeMap::new();
        // sort by circuit name, and we rely on an assumption that
        // table circuit witnesses come after opcode circuit witnesses
        for (circuit_name, witness) in witnesses.witnesses {
            let commit_dur = std::time::Instant::now();
            let num_instances = witness.num_instances();
            let witness = witness.into_mles();
            commitments.insert(
                circuit_name.clone(),
                PCS::batch_commit_and_write(&self.pk.pp, &witness, &mut transcript)
                    .map_err(ZKVMError::PCSError)?,
            );
            tracing::info!(
                "commit to {} traces took {:?}",
                circuit_name,
                commit_dur.elapsed()
            );
            wits.insert(circuit_name, (witness, num_instances));
        }

        // squeeze two challenges from transcript
        let challenges = [
            transcript.read_challenge().elements,
            transcript.read_challenge().elements,
        ];
        tracing::debug!("challenges in prover: {:?}", challenges);

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
            let wits_commit = commitments.remove(circuit_name).unwrap();
            // TODO: add an enum for circuit type either in constraint_system or vk
            let cs = pk.get_cs();
            let is_opcode_circuit = cs.lk_table_expressions.is_empty();

            if is_opcode_circuit {
                tracing::debug!(
                    "opcode circuit {} has {} witnesses, {} reads, {} writes, {} lookups",
                    circuit_name,
                    cs.num_witin,
                    cs.r_expressions.len(),
                    cs.w_expressions.len(),
                    cs.lk_expressions.len(),
                );
                for lk_s in cs.lk_expressions_namespace_map.iter() {
                    tracing::debug!("opcode circuit {}: {}", circuit_name, lk_s);
                }
                let opcode_proof = self.create_opcode_proof(
                    circuit_name,
                    &self.pk.pp,
                    pk,
                    witness.into_iter().map(|w| w.into()).collect_vec(),
                    wits_commit,
                    pi,
                    num_instances,
                    max_threads,
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
                let table_proof = self.create_table_proof(
                    circuit_name,
                    &self.pk.pp,
                    pk,
                    witness.into_iter().map(|v| v.into()).collect_vec(),
                    wits_commit,
                    pi,
                    num_instances,
                    max_threads,
                    transcript,
                    &challenges,
                )?;
                tracing::info!(
                    "generated proof for table {} with num_instances={}",
                    circuit_name,
                    num_instances
                );
                vm_proof
                    .table_proofs
                    .insert(circuit_name.clone(), (i, table_proof));
            }
        }

        Ok(vm_proof)
    }
    /// create proof giving witness and num_instances
    /// major flow break down into
    /// 1: witness layer inferring from input -> output
    /// 2: proof (sumcheck reduce) from output to input
    #[allow(clippy::too_many_arguments)]
    pub fn create_opcode_proof(
        &self,
        name: &str,
        pp: &PCS::ProverParam,
        circuit_pk: &ProvingKey<E, PCS>,
        witnesses: Vec<ArcMultilinearExtension<'_, E>>,
        wits_commit: PCS::CommitmentWithData,
        pi: &[E::BaseField],
        num_instances: usize,
        max_threads: usize,
        transcript: &mut Transcript<E>,
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

        // main constraint: read/write record witness inference
        let span = entered_span!("wit_inference::record");
        let records_wit: Vec<ArcMultilinearExtension<'_, E>> = cs
            .r_expressions
            .par_iter()
            .chain(cs.w_expressions.par_iter())
            .chain(cs.lk_expressions.par_iter())
            .map(|expr| {
                assert_eq!(expr.degree(), 1);
                wit_infer_by_expr(&[], &witnesses, pi, challenges, expr)
            })
            .collect();
        let (r_records_wit, w_lk_records_wit) = records_wit.split_at(cs.r_expressions.len());
        let (w_records_wit, lk_records_wit) = w_lk_records_wit.split_at(cs.w_expressions.len());
        exit_span!(span);

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
        let span = entered_span!("wit_inference::tower_witness_r_last_layer");
        // TODO optimize last layer to avoid alloc new vector to save memory
        let r_records_last_layer =
            interleaving_mles_to_mles(r_records_wit, num_instances, NUM_FANIN, E::ONE);
        assert_eq!(r_records_last_layer.len(), NUM_FANIN);
        exit_span!(span);

        // infer all tower witness after last layer
        let span = entered_span!("wit_inference::tower_witness_r_layers");
        let r_wit_layers = infer_tower_product_witness(
            log2_num_instances + log2_r_count,
            r_records_last_layer,
            NUM_FANIN,
        );
        exit_span!(span);

        let span = entered_span!("wit_inference::tower_witness_w_last_layer");
        // TODO optimize last layer to avoid alloc new vector to save memory
        let w_records_last_layer =
            interleaving_mles_to_mles(w_records_wit, num_instances, NUM_FANIN, E::ONE);
        assert_eq!(w_records_last_layer.len(), NUM_FANIN);
        exit_span!(span);

        let span = entered_span!("wit_inference::tower_witness_w_layers");
        let w_wit_layers = infer_tower_product_witness(
            log2_num_instances + log2_w_count,
            w_records_last_layer,
            NUM_FANIN,
        );
        exit_span!(span);

        let span = entered_span!("wit_inference::tower_witness_lk_last_layer");
        // TODO optimize last layer to avoid alloc new vector to save memory
        let lk_records_last_layer =
            interleaving_mles_to_mles(lk_records_wit, num_instances, NUM_FANIN, chip_record_alpha);
        assert_eq!(lk_records_last_layer.len(), 2);
        exit_span!(span);

        let span = entered_span!("wit_inference::tower_witness_lk_layers");
        let lk_wit_layers = infer_tower_logup_witness(None, lk_records_last_layer);
        exit_span!(span);

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

        // product constraint tower sumcheck
        let span = entered_span!("sumcheck::tower");
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
            max_threads,
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
        exit_span!(span);

        // batch sumcheck: selector + main degree > 1 constraints
        let span = entered_span!("sumcheck::main_sel");
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

        let num_threads = proper_num_threads(log2_num_instances, max_threads);
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
                        wit_infer_by_expr(&[], &witnesses, pi, challenges, expr);
                    let top_100_errors = expected_zero_poly
                        .get_ext_field_vec()
                        .iter()
                        .enumerate()
                        .filter(|(_, v)| **v != E::ZERO)
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

        let (main_sel_sumcheck_proofs, state) = IOPProverStateV2::prove_batch_polys(
            num_threads,
            virtual_polys.get_batched_polys(),
            transcript,
        );
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
        exit_span!(span);

        let span = entered_span!("witin::evals");
        let wits_in_evals: Vec<E> = witnesses
            .par_iter()
            .map(|poly| poly.evaluate(&input_open_point))
            .collect();
        exit_span!(span);

        let span = entered_span!("pcs_open");
        let opening_dur = std::time::Instant::now();
        tracing::debug!(
            "[opcode {}]: build opening proof for {} polys at {:?}",
            name,
            witnesses.len(),
            input_open_point
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
        exit_span!(span);
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
    pub fn create_table_proof(
        &self,
        name: &str,
        pp: &PCS::ProverParam,
        circuit_pk: &ProvingKey<E, PCS>,
        witnesses: Vec<ArcMultilinearExtension<'_, E>>,
        wits_commit: PCS::CommitmentWithData,
        pi: &[E::BaseField],
        num_instances: usize,
        max_threads: usize,
        transcript: &mut Transcript<E>,
        challenges: &[E; 2],
    ) -> Result<ZKVMTableProof<E, PCS>, ZKVMError> {
        let cs = circuit_pk.get_cs();
        let fixed = circuit_pk
            .fixed_traces
            .as_ref()
            .expect("pk.fixed_traces must not be none for table circuit")
            .iter()
            .map(|f| -> ArcMultilinearExtension<E> { Arc::new(f.get_ranged_mle(1, 0)) })
            .collect::<Vec<ArcMultilinearExtension<E>>>();
        let log2_num_instances = ceil_log2(num_instances);
        let next_pow2_instances = 1 << log2_num_instances;

        // sanity check
        assert_eq!(witnesses.len(), cs.num_witin as usize);
        assert_eq!(fixed.len(), cs.num_fixed);
        assert!(witnesses.iter().all(|v| {
            v.num_vars() == log2_num_instances && v.evaluations().len() == next_pow2_instances
        }));
        assert!(!cs.lk_table_expressions.is_empty());

        // main constraint: lookup denominator and numerator record witness inference
        let span = entered_span!("wit_inference::record");
        let records_wit: Vec<ArcMultilinearExtension<'_, E>> = cs
            .lk_table_expressions
            .par_iter()
            .map(|lk| &lk.values)
            .chain(
                cs.lk_table_expressions
                    .par_iter()
                    .map(|lk| &lk.multiplicity),
            )
            .map(|expr| {
                assert_eq!(expr.degree(), 1);
                wit_infer_by_expr(&fixed, &witnesses, pi, challenges, expr)
            })
            .collect();
        let (lk_d_wit, lk_n_wit) = records_wit.split_at(cs.lk_table_expressions.len());
        exit_span!(span);

        let lk_counts_per_instance = cs.lk_table_expressions.len();
        let log2_lk_count = ceil_log2(lk_counts_per_instance);

        // infer all tower witness after last layer
        let span = entered_span!("wit_inference::tower_witness_lk_last_layer");
        // TODO optimize last layer to avoid alloc new vector to save memory
        let lk_denominator_last_layer =
            interleaving_mles_to_mles(lk_d_wit, num_instances, NUM_FANIN_LOGUP, E::ONE);
        let lk_numerator_last_layer =
            interleaving_mles_to_mles(lk_n_wit, num_instances, NUM_FANIN_LOGUP, E::ZERO);
        assert_eq!(lk_denominator_last_layer.len(), NUM_FANIN_LOGUP);
        assert_eq!(lk_numerator_last_layer.len(), NUM_FANIN_LOGUP);
        exit_span!(span);

        let span = entered_span!("wit_inference::tower_witness_lk_layers");
        let lk_wit_layers =
            infer_tower_logup_witness(Some(lk_numerator_last_layer), lk_denominator_last_layer);
        exit_span!(span);

        if cfg!(test) {
            // sanity check
            assert_eq!(lk_wit_layers.len(), log2_num_instances + log2_lk_count);
            assert!(lk_wit_layers.iter().enumerate().all(|(i, w)| {
                let expected_size = 1 << i;
                let (p1, p2, q1, q2) = (&w[0], &w[1], &w[2], &w[3]);
                p1.evaluations().len() == expected_size
                    && p2.evaluations().len() == expected_size
                    && q1.evaluations().len() == expected_size
                    && q2.evaluations().len() == expected_size
            }));
        }

        // product constraint tower sumcheck
        let span = entered_span!("sumcheck::tower");
        // final evals for verifier
        let lk_p1_out_eval = lk_wit_layers[0][0].get_ext_field_vec()[0];
        let lk_p2_out_eval = lk_wit_layers[0][1].get_ext_field_vec()[0];
        let lk_q1_out_eval = lk_wit_layers[0][2].get_ext_field_vec()[0];
        let lk_q2_out_eval = lk_wit_layers[0][3].get_ext_field_vec()[0];
        let (rt_tower, tower_proof) = TowerProver::create_proof(
            max_threads,
            vec![],
            vec![TowerProverSpec {
                witness: lk_wit_layers,
            }],
            NUM_FANIN_LOGUP,
            transcript,
        );
        assert_eq!(rt_tower.len(), log2_num_instances + log2_lk_count);
        exit_span!(span);

        // selector layer sumcheck
        let span = entered_span!("sumcheck::main_sel");
        let rt_lk: Vec<E> = tower_proof.logup_specs_points[0]
            .last()
            .expect("error getting rt_lk")
            .to_vec();

        let num_threads = proper_num_threads(log2_num_instances, max_threads);
        // 2 for denominator and numerator
        let alpha_pow = get_challenge_pows(2, transcript);
        let mut alpha_pow_iter = alpha_pow.iter();
        let (alpha_lk_d, alpha_lk_n) = (
            alpha_pow_iter.next().unwrap(),
            alpha_pow_iter.next().unwrap(),
        );
        // create selector: all ONE, but padding ZERO to ceil_log2
        let sel_lk: ArcMultilinearExtension<E> = {
            let mut sel_lk = build_eq_x_r_vec(&rt_lk[log2_lk_count..]);
            if num_instances < sel_lk.len() {
                sel_lk.splice(
                    num_instances..sel_lk.len(),
                    std::iter::repeat(E::ZERO).take(sel_lk.len() - num_instances),
                );
            }
            sel_lk.into_mle().into()
        };

        let mut virtual_polys = VirtualPolynomials::<E>::new(num_threads, log2_num_instances);

        let eq_lk = build_eq_x_r_vec(&rt_lk[..log2_lk_count]);
        // lk denominator
        // rt := rt || rs
        for i in 0..lk_counts_per_instance {
            // \sum_t (sel(rt, t) * (\sum_i alpha_lk_d * eq(rs, i) * lk_d_record[i]))
            virtual_polys.add_mle_list(vec![&sel_lk, &lk_d_wit[i]], eq_lk[i] * alpha_lk_d);
        }
        // \sum_t alpha_lk_d * sel(rt, t) * (\sum_i (eq(rs, i)) - 1)
        virtual_polys.add_mle_list(
            vec![&sel_lk],
            *alpha_lk_d * (eq_lk[lk_counts_per_instance..].iter().sum::<E>() - E::ONE),
        );

        // lk numerator
        for i in 0..lk_counts_per_instance {
            // \sum_t (sel(rt, t) * (\sum_i alpha_lk_n * eq(rs, i) * lk_n_record[i]))
            virtual_polys.add_mle_list(vec![&sel_lk, &lk_n_wit[i]], eq_lk[i] * alpha_lk_n);
        }

        let (sel_sumcheck_proofs, state) = IOPProverStateV2::prove_batch_polys(
            num_threads,
            virtual_polys.get_batched_polys(),
            transcript,
        );
        let sel_evals = state.get_mle_final_evaluations();
        assert_eq!(
            sel_evals.len(),
            lk_counts_per_instance * 2 + 1 // 1 for sel_lk
        );
        let mut sel_evals_iter = sel_evals.into_iter();
        sel_evals_iter.next(); // skip sel_lk
        let lk_d_in_evals = (0..lk_counts_per_instance)
            .map(|_| sel_evals_iter.next().unwrap())
            .collect_vec();
        let lk_n_in_evals = (0..lk_counts_per_instance)
            .map(|_| sel_evals_iter.next().unwrap())
            .collect_vec();
        assert!(sel_evals_iter.count() == 0);
        let input_open_point = sel_sumcheck_proofs.point.clone();
        assert!(input_open_point.len() == log2_num_instances);
        exit_span!(span);

        let span = entered_span!("fixed::evals + witin::evals");
        let mut evals = witnesses
            .par_iter()
            .chain(fixed.par_iter())
            .map(|poly| poly.evaluate(&input_open_point))
            .collect::<Vec<_>>();
        let fixed_in_evals = evals.split_off(witnesses.len());
        let wits_in_evals = evals;
        exit_span!(span);

        let span = entered_span!("pcs_opening");
        let fixed_opening_proof = PCS::simple_batch_open(
            pp,
            &fixed,
            circuit_pk.fixed_commit_wd.as_ref().unwrap(),
            &input_open_point,
            fixed_in_evals.as_slice(),
            transcript,
        )
        .map_err(ZKVMError::PCSError)?;
        let fixed_commit = PCS::get_pure_commitment(circuit_pk.fixed_commit_wd.as_ref().unwrap());
        tracing::debug!(
            "[table {}] build opening proof for {} fixed polys at {:?}: values = {:?}, commit = {:?}",
            name,
            fixed.len(),
            input_open_point,
            fixed_in_evals,
            fixed_commit,
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
        exit_span!(span);
        let wits_commit = PCS::get_pure_commitment(&wits_commit);
        tracing::debug!(
            "[table {}] build opening proof for {} polys at {:?}: values = {:?}, commit = {:?}",
            name,
            witnesses.len(),
            input_open_point,
            wits_in_evals,
            wits_commit,
        );

        Ok(ZKVMTableProof {
            num_instances,
            lk_p1_out_eval,
            lk_p2_out_eval,
            lk_q1_out_eval,
            lk_q2_out_eval,
            tower_proof,
            sel_sumcheck_proofs: sel_sumcheck_proofs.proofs,
            lk_d_in_evals,
            lk_n_in_evals,
            fixed_in_evals,
            fixed_opening_proof,
            wits_in_evals,
            wits_commit,
            wits_opening_proof,
        })
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
    pub fn create_proof<'a, E: ExtensionField>(
        max_threads: usize,
        prod_specs: Vec<TowerProverSpec<'a, E>>,
        logup_specs: Vec<TowerProverSpec<'a, E>>,
        num_fanin: usize,
        transcript: &mut Transcript<E>,
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
                let num_threads = proper_num_threads(out_rt.len(), max_threads);

                let eq: ArcMultilinearExtension<E> = build_eq_x_r_vec(&out_rt).into_mle().into();
                let mut virtual_polys = VirtualPolynomials::<E>::new(num_threads, out_rt.len());

                for (s, alpha) in prod_specs.iter().zip(alpha_pows.iter()) {
                    if round < s.witness.len() {
                        let layer_polys = &s.witness[round];

                        // sanity check
                        assert_eq!(layer_polys.len(), num_fanin);
                        assert!(
                            layer_polys
                                .iter()
                                .all(|f| {
                                    f.evaluations().len() == (1 << (log_num_fanin * round))
                                })
                        );

                        // \sum_s eq(rt, s) * alpha^{i} * ([in_i0[s] * in_i1[s] * .... in_i{num_product_fanin}[s]])
                        virtual_polys.add_mle_list(
                            [vec![&eq], layer_polys.iter().collect()].concat(),
                            *alpha,
                        )
                    }
                }

                for (s, alpha) in logup_specs
                    .iter()
                    .zip(alpha_pows[prod_specs.len()..].chunks(2))
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

                let (sumcheck_proofs, state) = IOPProverStateV2::prove_batch_polys(
                    num_threads,
                    virtual_polys.get_batched_polys(),
                    transcript,
                );
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
                for (i, s) in prod_specs.iter().enumerate() {
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
                for (i, s) in logup_specs.iter().enumerate() {
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
