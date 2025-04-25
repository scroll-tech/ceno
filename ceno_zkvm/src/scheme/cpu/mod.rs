use super::hal::ProverBackend;
use crate::{
    expression::Expression,
    scheme::hal::{TowerProver, TowerProverSpec},
    structs::TowerProofs,
    utils::get_challenge_pows,
};
use ff_ext::{ExtensionField, PoseidonField};
use itertools::{enumerate, izip};
use mpcs::Point;
use multilinear_extensions::{
    mle::IntoMLE,
    virtual_poly::{ArcMultilinearExtension, build_eq_x_r_vec},
    virtual_polys::VirtualPolynomials,
};
use p3::{commit::Mmcs, matrix::dense::RowMajorMatrix};
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use sumcheck::{
    macros::{entered_span, exit_span},
    structs::IOPProverState,
    util::{ceil_log2, optimal_sumcheck_threads},
};
use transcript::Transcript;

struct CpuBackend<E> {
    _marker: std::marker::PhantomData<E>,
}

impl<E: ExtensionField> ProverBackend for CpuBackend<E> {
    type E = E;
    type Matrix = RowMajorMatrix<E::BaseField>;
    type MultilinearPoly = ArcMultilinearExtension<E>;
    type MmcsProverData = <<<E as ExtensionField>::BaseField as PoseidonField>::MMCS as Mmcs<
        E::BaseField,
    >>::ProverData<Self::Matrix>;
}

/// tower prover for CPU backend
struct CpuTowerProver {}

impl<E: ExtensionField> TowerProver<CpuBackend<E>> for CpuTowerProver {
    fn build_witness(
        &self,
        polys: &[<CpuBackend<E> as ProverBackend>::MultilinearPoly],
        read_exprs: &[Expression<E>],
        write_exprs: &[Expression<E>],
        lookup_exprs: &[Expression<E>],
    ) -> (
        Vec<TowerProverSpec<CpuBackend<E>>>,
        TowerProverSpec<CpuBackend<E>>,
    ) {
        // main constraint: read/write record witness inference
        let record_span = entered_span!("record");
        let records_wit: Vec<ArcMultilinearExtension<'_, E>> = read_exprs
            .par_iter()
            .chain(write_exprs.par_iter())
            .chain(lookup_exprs.par_iter())
            .map(|expr| {
                assert_eq!(expr.degree(), 1);
                wit_infer_by_expr(&[], &polys, &[], pi, challenges, expr)
            })
            .collect();

        let (r_records_wit, w_lk_records_wit) = records_wit.split_at(cs.r_expressions.len());
        let (w_records_wit, lk_records_wit) = w_lk_records_wit.split_at(cs.w_expressions.len());
        exit_span!(record_span);

        let wit_inference_span = entered_span!("wit_inference", profiling_3 = true);

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
    }

    fn prove(
        &self,
        prod_specs: Vec<TowerProverSpec<CpuBackend<E>>>,
        logup_specs: Vec<TowerProverSpec<CpuBackend<E>>>,
        num_fanin: usize,
        transcript: &mut impl Transcript<E>,
    ) -> (Point<E>, TowerProofs<E>) {
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

        (next_rt, proofs)
    }
}
