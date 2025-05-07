use super::hal::{MainSumcheckProver, ProverBackend, TraceCommitter};
use crate::{
    circuit_builder::ConstraintSystem,
    expression::Expression,
    scheme::{
        constants::{MAINCONSTRAIN_SUMCHECK_BATCH_SIZE, NUM_FANIN},
        hal::{TowerProver, TowerProverSpec},
        utils::{
            infer_tower_logup_witness, infer_tower_product_witness, interleaving_mles_to_mles,
            wit_infer_by_expr,
        },
    },
    structs::{ProofInput, TowerProofs},
    utils::{add_mle_list_by_expr, get_challenge_pows},
};
use ff_ext::{ExtensionField, PoseidonField};
use itertools::{Itertools, enumerate, izip};
use mpcs::{Point, PolynomialCommitmentScheme};
use multilinear_extensions::{
    mle::{DenseMultilinearExtension, IntoMLE, MultilinearExtension},
    virtual_poly::{ArcMultilinearExtension, build_eq_x_r_vec},
    virtual_polys::VirtualPolynomials,
};
use p3::{commit::Mmcs, field::PrimeCharacteristicRing};
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use std::{collections::BTreeSet, sync::Arc};
use sumcheck::{
    macros::{entered_span, exit_span},
    structs::IOPProverState,
    util::{ceil_log2, optimal_sumcheck_threads},
};
use transcript::Transcript;
use witness::next_pow2_instance_padding;
struct CpuBackend<E, PCS> {
    _marker: std::marker::PhantomData<(E, PCS)>,
}

impl<E: ExtensionField, PCS: PolynomialCommitmentScheme<E>> ProverBackend for CpuBackend<E, PCS> {
    type E = E;
    type PcsOpeningProof = PCS::Proof;
    type MultilinearPoly = ArcMultilinearExtension<E>;
    type Matrix = p3::matrix::dense::RowMajorMatrix<E::BaseField>;
    type PcsData = PCS::CommitmentWithWitness;
}

/// CPU prover for CPU backend
struct CpuProver {}

impl<E: ExtensionField, PCS: PolynomialCommitmentScheme<E>> TraceCommitter<CpuBackend<E, PCS>>
    for CpuProver
{
    fn commit_trace(
        &self,
        _traces: Vec<witness::RowMajorMatrix<E>>,
    ) -> (
        Vec<Vec<ArcMultilinearExtension<E>>>,
        PCS::CommitmentWithWitness,
    ) {
        todo!()
    }
}

impl<E: ExtensionField, PCS: PolynomialCommitmentScheme<E>> TowerProver<CpuBackend<E, PCS>>
    for CpuProver
{
    fn build_tower_witness(
        &self,
        input: ProofInput<CpuBackend<E, PCS>>,
        read_exprs: &[Expression<E>],
        write_exprs: &[Expression<E>],
        lookup_exprs: &[Expression<E>],
        challenges: &[E; 2],
    ) -> (
        Vec<TowerProverSpec<CpuBackend<E, PCS>>>,
        Vec<TowerProverSpec<CpuBackend<E, PCS>>>,
    ) {
        let polys = &input.witness;
        let pi = &input.public_input;
        let num_instances = input.num_instances;

        let next_pow2_instances = next_pow2_instance_padding(num_instances);
        let log2_num_instances = ceil_log2(next_pow2_instances);
        let (chip_record_alpha, _) = (challenges[0], challenges[1]);

        // main constraint: read/write record witness inference
        let record_span = entered_span!("infer record");
        let records_wit: Vec<ArcMultilinearExtension<'_, E>> = read_exprs
            .par_iter()
            .chain(write_exprs.par_iter())
            .chain(lookup_exprs.par_iter())
            .map(|expr| {
                assert_eq!(expr.degree(), 1);
                let polys: &[ArcMultilinearExtension<'_, E>] = polys.as_slice();
                wit_infer_by_expr(&[], polys, &[], pi, challenges, expr)
            })
            .collect();

        let (r_records_wit, w_lk_records_wit) = records_wit.split_at(read_exprs.len());
        let (w_records_wit, lk_records_wit) = w_lk_records_wit.split_at(write_exprs.len());
        exit_span!(record_span);

        let wit_inference_span = entered_span!("infer tower witness", profiling_3 = true);

        // product constraint: tower witness inference
        let (r_counts_per_instance, w_counts_per_instance, lk_counts_per_instance) =
            (read_exprs.len(), write_exprs.len(), lookup_exprs.len());
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

        let prod_specs = vec![
            TowerProverSpec {
                witness: r_wit_layers,
            },
            TowerProverSpec {
                witness: w_wit_layers,
            },
        ];
        let lookup_specs = vec![TowerProverSpec {
            witness: lk_wit_layers,
        }];

        (prod_specs, lookup_specs)
    }

    fn prove_tower_relation(
        &self,
        prod_specs: Vec<TowerProverSpec<CpuBackend<E, PCS>>>,
        logup_specs: Vec<TowerProverSpec<CpuBackend<E, PCS>>>,
        num_fanin: usize,
        transcript: &mut impl Transcript<E>,
    ) -> (Point<E>, TowerProofs<E>) {
        // product constraint tower sumcheck
        let tower_span = entered_span!("tower");
        // final evals for verifier
        let record_r_out_evals: Vec<E> = prod_specs[0].witness[0]
            .iter()
            .map(|w: &ArcMultilinearExtension<E>| w.get_ext_field_vec()[0])
            .collect();
        let record_w_out_evals: Vec<E> = prod_specs[1].witness[0]
            .iter()
            .map(|w: &ArcMultilinearExtension<E>| w.get_ext_field_vec()[0])
            .collect();
        let lk_wit_layers = &logup_specs[0].witness;
        let lk_p1_out_eval = lk_wit_layers[0][0].get_ext_field_vec()[0];
        let lk_p2_out_eval = lk_wit_layers[0][1].get_ext_field_vec()[0];
        let lk_q1_out_eval = lk_wit_layers[0][2].get_ext_field_vec()[0];
        let lk_q2_out_eval = lk_wit_layers[0][3].get_ext_field_vec()[0];
        assert!(record_r_out_evals.len() == NUM_FANIN && record_w_out_evals.len() == NUM_FANIN);

        // in order to batch product argument with logup in one sumcheck, we limit num_product_fanin to 2
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
        let initial_rt: Point<E> = transcript.sample_and_append_vec(b"product_sum", log_num_fanin);

        let (next_rt, _) =
            (1..=max_round_index).fold((initial_rt, alpha_pows), |(out_rt, alpha_pows), round| {
                // in first few rounds we just run on single thread
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
                                .all(|f: &ArcMultilinearExtension<E>| {
                                    f.evaluations().len() == 1 << (log_num_fanin * round)
                                })
                        );

                        // \sum_s eq(rt, s) * alpha^{i} * ([in_i0[s] * in_i1[s] * .... in_i{num_product_fanin-1}[s]])
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
                                .all(|f: &ArcMultilinearExtension<E>| f.evaluations().len() == 1 << (log_num_fanin * round)),
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
                let (sumcheck_proofs, state) = IOPProverState::prove(
                    virtual_polys,
                    transcript,
                );
                exit_span!(wrap_batch_span);

                proofs.push_sumcheck_proofs(sumcheck_proofs.proofs);

                // rt' = r_merge || rt
                let r_merge =  transcript.sample_and_append_vec(b"merge", log_num_fanin);
                let rt_prime = [sumcheck_proofs.point, r_merge].concat();

                // generate next round challenge
                let next_alpha_pows = get_challenge_pows(
                    prod_specs.len() +logup_specs.len() * 2, // logup occupy 2 sumcheck: numerator and denominator
                    transcript,
                );
                let evals = state.get_mle_flatten_final_evaluations();
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

        exit_span!(tower_span);

        tracing::debug!("tower sumcheck finished");

        (next_rt, proofs)
    }
}

impl<E: ExtensionField, PCS: PolynomialCommitmentScheme<E>> MainSumcheckProver<CpuBackend<E, PCS>>
    for CpuProver
{
    fn prove_main_constraints(
        &self,
        rt_tower: Vec<E>,
        tower_proof: &TowerProofs<E>,
        r_records: Vec<ArcMultilinearExtension<E>>,
        w_records: Vec<ArcMultilinearExtension<E>>,
        lk_records: Vec<ArcMultilinearExtension<E>>,
        input: ProofInput<CpuBackend<E, PCS>>,
        cs: ConstraintSystem<E>,
        transcript: &mut impl Transcript<<CpuBackend<E, PCS> as ProverBackend>::E>,
    ) -> Point<E> {
        let num_instances = input.num_instances;
        let log2_num_instances = input.log2_num_instances();
        let log2_r_count = ceil_log2(cs.r_expressions.len());
        let log2_w_count = ceil_log2(cs.w_expressions.len());
        let log2_lk_count = ceil_log2(cs.lk_expressions.len());

        assert_eq!(
            rt_tower.len(),
            log2_num_instances
                + [log2_r_count, log2_w_count, log2_lk_count]
                    .iter()
                    .max()
                    .unwrap()
        );
        assert_eq!(tower_proof.prod_specs_points.len(), 2); // read/write

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

        assert_eq!(rt_r.len(), log2_num_instances + log2_r_count);
        assert_eq!(rt_w.len(), log2_num_instances + log2_w_count);
        assert_eq!(rt_lk.len(), log2_num_instances + log2_lk_count);

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
                    std::iter::repeat_n(E::ZERO, sel_r.len() - num_instances),
                );
            }

            let mut sel_w = build_eq_x_r_vec(&rt_w[log2_w_count..]);
            if num_instances < sel_w.len() {
                sel_w.splice(
                    num_instances..sel_w.len(),
                    std::iter::repeat_n(E::ZERO, sel_w.len() - num_instances),
                );
            }

            let mut sel_lk = build_eq_x_r_vec(&rt_lk[log2_lk_count..]);
            if num_instances < sel_lk.len() {
                sel_lk.splice(
                    num_instances..sel_lk.len(),
                    std::iter::repeat_n(E::ZERO, sel_lk.len() - num_instances),
                );
            }

            (
                sel_r.into_mle().into(),
                sel_w.into_mle().into(),
                sel_lk.into_mle().into(),
            )
        };

        let mut virtual_polys = VirtualPolynomials::<E>::new(num_threads, log2_num_instances);

        let eq_r = build_eq_x_r_vec(&rt_r[..log2_r_count]);
        let eq_w = build_eq_x_r_vec(&rt_w[..log2_w_count]);
        let eq_lk = build_eq_x_r_vec(&rt_lk[..log2_lk_count]);

        let r_counts = cs.r_expressions.len();
        let w_counts = cs.w_expressions.len();
        let lk_counts = cs.lk_expressions.len();

        // read
        // rt_r := rs || rt
        for i in 0..r_counts {
            // \sum_t sel(rt, t) * (\sum_i alpha_read * eq(rs, i) * record_r[t])
            virtual_polys.add_mle_list(vec![&sel_r, &r_records[i]], eq_r[i] * *alpha_read);
        }
        // \sum_t alpha_read * sel(rt, t) * (\sum_i (eq(rs, i)) - 1)
        virtual_polys.add_mle_list(
            vec![&sel_r],
            *alpha_read * eq_r[r_counts..].iter().copied().sum::<E>() - *alpha_read,
        );

        // write
        // rt_w := rs || rt
        for i in 0..cs.w_expressions.len() {
            // \sum_t (sel(rt, t) * (\sum_i alpha_write * eq(rs, i) * record_w[i] ))
            virtual_polys.add_mle_list(vec![&sel_w, &w_records[i]], eq_w[i] * *alpha_write);
        }
        // \sum_t alpha_write * sel(rt, t) * (\sum_i (eq(rs, i)) - 1)
        virtual_polys.add_mle_list(
            vec![&sel_w],
            *alpha_write * eq_w[w_counts..].iter().copied().sum::<E>() - *alpha_write,
        );

        // lk denominator
        // rt := rt || rs
        for i in 0..lk_counts {
            // \sum_t (sel(rt, t) * (\sum_i alpha_lk* eq(rs, i) * record_w[i]))
            virtual_polys.add_mle_list(vec![&sel_lk, &lk_records[i]], eq_lk[i] * *alpha_lk);
        }
        // \sum_t alpha_lk * sel(rt, t) * chip_record_alpha * (\sum_i (eq(rs, i)) - 1)
        virtual_polys.add_mle_list(
            vec![&sel_lk],
            *alpha_lk
                * chip_record_alpha
                * (eq_lk[lk_counts..].iter().copied().sum::<E>() - E::ONE),
        );

        // only initialize when circuit got assert_zero_sumcheck_expressions
        let sel_non_lc_zero_sumcheck = {
            if !cs.assert_zero_sumcheck_expressions.is_empty() {
                let mut sel_non_lc_zero_sumcheck = build_eq_x_r_vec(&rt_non_lc_sumcheck);
                if num_instances < sel_non_lc_zero_sumcheck.len() {
                    sel_non_lc_zero_sumcheck.splice(
                        num_instances..sel_non_lc_zero_sumcheck.len(),
                        std::iter::repeat_n(
                            E::ZERO,
                            sel_non_lc_zero_sumcheck.len() - num_instances,
                        ),
                    );
                }
                let sel_non_lc_zero_sumcheck: ArcMultilinearExtension<E> =
                    sel_non_lc_zero_sumcheck.into_mle().into();
                Some(sel_non_lc_zero_sumcheck)
            } else {
                None
            }
        };

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
                        wit_infer_by_expr(&[], input.witness.as_slice(), &[], pi, challenges, expr);
                    let top_100_errors = expected_zero_poly
                        .get_base_field_vec()
                        .iter()
                        .enumerate()
                        .filter(|(_, v)| **v != E::BaseField::ZERO)
                        .take(100)
                        .collect_vec();
                    if !top_100_errors.is_empty() {
                        // return Err(ZKVMError::InvalidWitness(format!(
                        //     "degree > 1 zero check virtual poly: expr {name} != 0 on instance indexes: {}...",
                        //     top_100_errors.into_iter().map(|(i, _)| i).join(",")
                        // )));
                    }
                }

                distrinct_zerocheck_terms_set.extend(add_mle_list_by_expr(
                    &mut virtual_polys,
                    sel_non_lc_zero_sumcheck.as_ref(),
                    input.witness.iter().collect_vec(),
                    expr,
                    challenges,
                    *alpha,
                ));
            }
        }

        tracing::debug!("main sel sumcheck start");
        let (main_sel_sumcheck_proofs, state) = IOPProverState::prove(virtual_polys, transcript);
        tracing::debug!("main sel sumcheck end");

        let main_sel_evals = state.get_mle_flatten_final_evaluations();
        assert_eq!(
            main_sel_evals.len(),
            r_counts
                + w_counts
                + lk_counts
                + 3 // 3 from [sel_r, sel_w, sel_lk]
                + if cs.assert_zero_sumcheck_expressions.is_empty() {
                    0
                } else {
                    distrinct_zerocheck_terms_set.len() + 1 // +1 from sel_non_lc_zero_sumcheck
                }
        );
        let mut main_sel_evals_iter = main_sel_evals.into_iter();
        main_sel_evals_iter.next(); // skip sel_r
        let r_records_in_evals = (0..r_counts)
            .map(|_| main_sel_evals_iter.next().unwrap())
            .collect_vec();
        main_sel_evals_iter.next(); // skip sel_w
        let w_records_in_evals = (0..w_counts)
            .map(|_| main_sel_evals_iter.next().unwrap())
            .collect_vec();
        main_sel_evals_iter.next(); // skip sel_lk
        let lk_records_in_evals = (0..lk_counts)
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

        input_open_point
    }
}
