use super::hal::{DeviceProvingKey, MainSumcheckProver, OpeningProver, ProverBackend, TraceCommitter};
use crate::{
    circuit_builder::ConstraintSystem,
    scheme::{
        constants::{NUM_FANIN, NUM_FANIN_LOGUP},
        hal::{TowerProver, TowerProverSpec},
        utils::{
            infer_tower_logup_witness, infer_tower_product_witness, masked_mle_split_to_chunks,
            wit_infer_by_expr,
        },
    },
    structs::{ProofInput, TowerProofs},
    utils::{add_mle_list_by_expr, get_challenge_pows},
};
use either::Either;
use ff_ext::ExtensionField;
use itertools::Itertools;
use mpcs::{Point, PolynomialCommitmentScheme};
use multilinear_extensions::{
    Expression,
    mle::{ArcMultilinearExtension, FieldType, IntoMLE, MultilinearExtension},
    virtual_poly::build_eq_x_r_vec,
    virtual_polys::VirtualPolynomialsBuilder,
};
use p3::field::{PrimeCharacteristicRing, dot_product};
use rayon::iter::{IntoParallelIterator, IntoParallelRefIterator, ParallelIterator};
use std::collections::BTreeSet;
use sumcheck::{
    macros::{entered_span, exit_span},
    structs::{IOPProverMessage, IOPProverState},
    util::{ceil_log2, optimal_sumcheck_threads},
};
use transcript::Transcript;
use witness::next_pow2_instance_padding;
struct CpuBackend<E, PCS> {
    _marker: std::marker::PhantomData<(E, PCS)>,
}

impl<'a, E: ExtensionField, PCS: PolynomialCommitmentScheme<E>> ProverBackend for CpuBackend<E, PCS> {
    type E = E;
    type Pcs = PCS;
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
        pk: &DeviceProvingKey<CpuBackend<E, PCS>>,
        cs: &ConstraintSystem<E>,
        input: &ProofInput<CpuBackend<E, PCS>>,
        challenges: &[E; 2],
    ) -> (
        Vec<Vec<Vec<E>>>,
        Vec<Vec<ArcMultilinearExtension<E>>>,
        Vec<TowerProverSpec<CpuBackend<E, PCS>>>,
        Vec<TowerProverSpec<CpuBackend<E, PCS>>>,
    ) {
        let num_instances = input.num_instances;
        let next_pow2_instances = next_pow2_instance_padding(input.num_instances);
        let log2_num_instances = ceil_log2(next_pow2_instances);
        let chip_record_alpha = challenges[0];

        // opcode must have at least one read/write/lookup
        let is_opcode_circuit = !cs.lk_expressions.is_empty()
            || !cs.r_expressions.is_empty()
            || !cs.w_expressions.is_empty();
        // table must have at least one read/write/lookup
        let is_table_circuit = !cs.lk_table_expressions.is_empty()
            || !cs.r_table_expressions.is_empty()
            || !cs.w_table_expressions.is_empty();

        // sanity check
        assert_eq!(input.witness.len(), cs.num_witin as usize);
        assert_eq!(input.structural_witness.len(), cs.num_structural_witin as usize);
        assert_eq!(pk.fixed_polys.len(), cs.num_fixed);
        // check all witness size are power of 2
        assert!(
            input
                .witness
                .iter()
                .all(|v| { v.evaluations().len().is_power_of_two() })
        );
        assert!(
            input.structural_witness
                .iter()
                .all(|v| { v.evaluations().len().is_power_of_two() })
        );
        assert!(is_table_circuit || is_opcode_circuit);
        assert!(
            cs.r_table_expressions
                .iter()
                .zip_eq(cs.w_table_expressions.iter())
                .all(|(r, w)| r.table_spec.len == w.table_spec.len)
        );

        let wit_inference_span = entered_span!("wit_inference");
        // main constraint: lookup denominator and numerator record witness inference
        let record_span = entered_span!("record");
        let records_wit: Vec<ArcMultilinearExtension<'_, E>> = cs
            .r_table_expressions
            .par_iter()
            .map(|r| &r.expr)
            .chain(cs.r_expressions.par_iter())
            .chain(cs.w_table_expressions.par_iter().map(|w| &w.expr))
            .chain(cs.w_expressions.par_iter())
            .chain(
                cs.lk_table_expressions
                    .par_iter()
                    .map(|lk| &lk.multiplicity),
            )
            .chain(cs.lk_table_expressions.par_iter().map(|lk| &lk.values))
            .chain(cs.lk_expressions.par_iter())
            .map(|expr| {
                assert_eq!(expr.degree(), 1);
                wit_infer_by_expr(
                    &pk.fixed_polys,
                    &input.witness,
                    &input.structural_witness,
                    &input.public_input,
                    challenges,
                    expr,
                )
            })
            .collect();

        let num_reads = cs.r_expressions.len() + cs.r_table_expressions.len();
        let num_writes = cs.w_expressions.len() + cs.w_table_expressions.len();
        let mut remains = records_wit;
        let r_set_wit: Vec<_> = remains.drain(..num_reads).collect();
        let w_set_wit: Vec<_> = remains.drain(..num_writes).collect();
        let lk_n_wit: Vec<_> = remains.drain(..cs.lk_table_expressions.len()).collect();
        let lk_d_wit: Vec<_> = if !cs.lk_table_expressions.is_empty() {
            remains.drain(..cs.lk_table_expressions.len()).collect()
        } else {
            remains.drain(..cs.lk_expressions.len()).collect()
        };

        assert!(remains.is_empty());

        exit_span!(record_span);

        // infer all tower witness after last layer
        let span = entered_span!("tower_witness_last_layer");
        let mut r_set_last_layer = r_set_wit
            .iter()
            .chain(w_set_wit.iter())
            .map(|wit| masked_mle_split_to_chunks(wit, num_instances, NUM_FANIN, E::ONE))
            .collect::<Vec<_>>();
        let w_set_last_layer = r_set_last_layer.split_off(r_set_wit.len());

        let mut lk_numerator_last_layer = lk_n_wit
            .iter()
            .chain(lk_d_wit.iter())
            .enumerate()
            .map(|(i, wit)| {
                let default = if i < lk_n_wit.len() {
                    // For table circuit, the last layer's length is always two's power
                    // so the padding will not happen, therefore we can use any value here.
                    E::ONE
                } else {
                    chip_record_alpha
                };
                masked_mle_split_to_chunks(wit, num_instances, NUM_FANIN_LOGUP, default)
            })
            .collect::<Vec<_>>();
        let lk_denominator_last_layer = lk_numerator_last_layer.split_off(lk_n_wit.len());
        exit_span!(span);

        let span = entered_span!("tower_tower_witness");
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
        let lk_wit_layers = if !lk_numerator_last_layer.is_empty() {
            lk_numerator_last_layer
                .into_iter()
                .zip(lk_denominator_last_layer)
                .map(|(lk_n, lk_d)| infer_tower_logup_witness(Some(lk_n), lk_d))
                .collect_vec()
        } else {
            lk_denominator_last_layer
                .into_iter()
                .map(|lk_d| infer_tower_logup_witness(None, lk_d))
                .collect_vec()
        };
        exit_span!(span);
        exit_span!(wit_inference_span);

        if cfg!(test) {
            // sanity check
            assert_eq!(r_wit_layers.len(), num_reads);
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

            assert_eq!(w_wit_layers.len(), num_writes);
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

            assert_eq!(
                lk_wit_layers.len(),
                cs.lk_table_expressions.len() + cs.lk_expressions.len()
            );
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

        // final evals for verifier
        let r_out_evals = r_wit_layers
            .iter()
            .map(|r_wit_layers| {
                r_wit_layers[0]
                    .iter()
                    .map(|mle| mle.get_ext_field_vec()[0])
                    .collect_vec()
            })
            .collect_vec();
        let w_out_evals = w_wit_layers
            .iter()
            .map(|w_wit_layers| {
                w_wit_layers[0]
                    .iter()
                    .map(|mle| mle.get_ext_field_vec()[0])
                    .collect_vec()
            })
            .collect_vec();
        let lk_out_evals = lk_wit_layers
            .iter()
            .map(|lk_wit_layers| {
                lk_wit_layers[0]
                    .iter()
                    .map(|mle| mle.get_ext_field_vec()[0])
                    .collect_vec()
            })
            .collect_vec();

        let records = vec![r_set_wit, w_set_wit, lk_n_wit, lk_d_wit];
        let prod_specs = r_wit_layers
            .into_iter()
            .chain(w_wit_layers.into_iter())
            .map(|witness| TowerProverSpec { witness })
            .collect_vec();
        let lookup_specs = lk_wit_layers
            .into_iter()
            .map(|witness| TowerProverSpec { witness })
            .collect_vec();

        let out_evals = vec![r_out_evals, w_out_evals, lk_out_evals];

        (out_evals, records, prod_specs, lookup_specs)
    }

    fn prove_tower_relation(
        &self,
        prod_specs: Vec<TowerProverSpec<CpuBackend<E, PCS>>>,
        logup_specs: Vec<TowerProverSpec<CpuBackend<E, PCS>>>,
        num_fanin: usize,
        transcript: &mut impl Transcript<E>,
    ) -> (Point<E>, TowerProofs<E>) {
        #[derive(Debug, Clone)]
        enum GroupedMLE<'a, E: ExtensionField> {
            Prod((usize, Vec<MultilinearExtension<'a, E>>)), // usize is the index in prod_specs
            Logup((usize, Vec<MultilinearExtension<'a, E>>)), // usize is the index in logup_specs
        }

        // XXX to sumcheck batched product argument with logup, we limit num_product_fanin to 2
        // TODO mayber give a better naming?
        assert_eq!(num_fanin, 2);

        let (prod_specs_len, logup_specs_len) = (prod_specs.len(), logup_specs.len());
        let mut proofs = TowerProofs::new(prod_specs_len, logup_specs_len);
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
            prod_specs_len +
            // logup occupy 2 sumcheck: numerator and denominator
            logup_specs_len * 2,
            transcript,
        );
        let initial_rt: Point<E> = transcript.sample_and_append_vec(b"product_sum", log_num_fanin);
        let (mut out_rt, mut alpha_pows) = (initial_rt, alpha_pows);

        let mut layer_witness: Vec<Vec<GroupedMLE<'a, E>>> = vec![Vec::new(); max_round_index + 1];

        #[allow(clippy::type_complexity)]
        fn merge_spec_witness<'a, E: ExtensionField>(
            merged: &mut [Vec<GroupedMLE<'a, E>>],
            spec: TowerProverSpec<E>,
            index: usize,
            group_ctor: fn((usize, Vec<MultilinearExtension<'a, E>>)) -> GroupedMLE<'a, E>,
        ) {
            for (round_idx, round_vec) in spec.witness.into_iter().enumerate() {
                merged[round_idx].push(group_ctor((index, round_vec)));
            }
        }

        // merge prod_specs
        for (i, spec) in prod_specs.into_iter().enumerate() {
            merge_spec_witness(&mut layer_witness, spec, i, GroupedMLE::Prod);
        }

        // merge logup_specs
        for (i, spec) in logup_specs.into_iter().enumerate() {
            merge_spec_witness(&mut layer_witness, spec, i, GroupedMLE::Logup);
        }

        // skip(1) for output layer
        for (round, mut layer_witness) in layer_witness.into_iter().enumerate().skip(1) {
            // in first few round we just run on single thread
            let num_threads = optimal_sumcheck_threads(out_rt.len());
            let mut exprs = Vec::<Expression<E>>::with_capacity(prod_specs_len + logup_specs_len);
            let mut expr_builder = VirtualPolynomialsBuilder::new(num_threads, out_rt.len());
            let mut witness_prod_expr = vec![vec![]; prod_specs_len];
            let mut witness_lk_expr = vec![vec![]; logup_specs_len];

            let mut eq: MultilinearExtension<E> = build_eq_x_r_vec(&out_rt).into_mle();
            let eq_expr = expr_builder.lift(Either::Right(&mut eq));

            // processing exprs
            for group_witness in layer_witness.iter_mut() {
                match group_witness {
                    GroupedMLE::Prod((i, layer_polys)) => {
                        let alpha_expr = Expression::Constant(Either::Right(alpha_pows[*i]));
                        // sanity check
                        assert_eq!(layer_polys.len(), num_fanin);
                        assert!(
                            layer_polys
                                .iter()
                                .all(|f| { f.evaluations().len() == 1 << (log_num_fanin * round) })
                        );

                        let layer_polys = layer_polys
                            .iter_mut()
                            .map(|layer_poly| expr_builder.lift(layer_poly.to_either()))
                            .collect_vec();

                        witness_prod_expr[*i].extend(layer_polys.clone());
                        let layer_polys_product =
                            layer_polys.into_iter().product::<Expression<E>>();
                        // \sum_s eq(rt, s) * alpha^{i} * ([in_i0[s] * in_i1[s] * .... in_i{num_product_fanin}[s]])
                        exprs.push(eq_expr.clone() * alpha_expr * layer_polys_product);
                    }
                    GroupedMLE::Logup((i, layer_polys)) => {
                        // sanity check
                        assert_eq!(layer_polys.len(), 2 * num_fanin); // p1, p2, q1, q2
                        assert!(
                            layer_polys
                                .iter()
                                .all(|f| f.evaluations().len() == 1 << (log_num_fanin * round)),
                        );

                        let (alpha_numerator, alpha_denominator) = (
                            Expression::Constant(Either::Right(
                                alpha_pows[prod_specs_len + *i * 2], // numerator and denominator
                            )),
                            Expression::Constant(Either::Right(
                                alpha_pows[prod_specs_len + *i * 2 + 1],
                            )),
                        );

                        let (p1, rest) = layer_polys.split_at_mut(1);
                        let (p2, rest) = rest.split_at_mut(1);
                        let (q1, q2) = rest.split_at_mut(1);

                        let (p1, p2, q1, q2) = (
                            expr_builder.lift(p1[0].to_either()),
                            expr_builder.lift(p2[0].to_either()),
                            expr_builder.lift(q1[0].to_either()),
                            expr_builder.lift(q2[0].to_either()),
                        );
                        witness_lk_expr[*i].extend(vec![
                            p1.clone(),
                            p2.clone(),
                            q1.clone(),
                            q2.clone(),
                        ]);

                        // \sum_s eq(rt, s) * (alpha_numerator^{i} * (p1 * q2 + p2 * q1) + alpha_denominator^{i} * q1 * q2)
                        exprs.push(
                            eq_expr.clone()
                                * (alpha_numerator * (p1 * q2.clone() + p2 * q1.clone())
                                    + alpha_denominator * q1 * q2),
                        );
                    }
                }
            }

            let wrap_batch_span = entered_span!("wrap_batch");
            let (sumcheck_proofs, state) = IOPProverState::prove(
                expr_builder.to_virtual_polys(&[exprs.into_iter().sum()], &[]),
                transcript,
            );
            exit_span!(wrap_batch_span);

            proofs.push_sumcheck_proofs(sumcheck_proofs.proofs);

            // rt' = r_merge || rt
            let r_merge = transcript.sample_and_append_vec(b"merge", log_num_fanin);
            let rt_prime = [sumcheck_proofs.point, r_merge].concat();

            // generate next round challenge
            let next_alpha_pows = get_challenge_pows(
                prod_specs_len + logup_specs_len * 2, /* logup occupy 2 sumcheck: numerator and denominator */
                transcript,
            );
            let evals = state.get_mle_flatten_final_evaluations();
            // retrieve final evaluation to proof
            for (i, witness_prod_expr) in witness_prod_expr.iter().enumerate().take(prod_specs_len)
            {
                let evals = witness_prod_expr
                    .iter()
                    .map(|expr| match expr {
                        Expression::WitIn(wit_id) => evals[*wit_id as usize],
                        _ => unreachable!(),
                    })
                    .collect_vec();
                if !evals.is_empty() {
                    assert_eq!(evals.len(), num_fanin);
                    proofs.push_prod_evals_and_point(i, evals, rt_prime.clone());
                }
            }
            for (i, witness_lk_expr) in witness_lk_expr.iter().enumerate().take(logup_specs_len) {
                let evals = witness_lk_expr
                    .iter()
                    .map(|expr| match expr {
                        Expression::WitIn(wit_id) => evals[*wit_id as usize],
                        _ => unreachable!(),
                    })
                    .collect_vec();
                if !evals.is_empty() {
                    assert_eq!(evals.len(), 4); // p1, p2, q1, q2
                    proofs.push_logup_evals_and_point(i, evals, rt_prime.clone());
                }
            }
            out_rt = rt_prime;
            alpha_pows = next_alpha_pows;
        }
        let next_rt = out_rt;

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
        challenges: &[E; 2],
        transcript: &mut impl Transcript<<CpuBackend<E, PCS> as ProverBackend>::E>,
    ) -> (Point<E>, Option<Vec<IOPProverMessage<E>>>) {
        let num_instances = input.num_instances;
        let log2_num_instances = ceil_log2(input.num_instances);
        let num_reads = cs.r_expressions.len() + cs.r_table_expressions.len();
        let num_writes = cs.w_expressions.len() + cs.w_table_expressions.len();
        let (chip_record_alpha, _) = (challenges[0], challenges[1]);
        let is_opcode_circuit = !cs.lk_expressions.is_empty()
            || !cs.r_expressions.is_empty()
            || !cs.w_expressions.is_empty();

        // main selector sumcheck / same point sumcheck
        let sumcheck_span = entered_span!("main sumcheck");
        let (input_opening_point, main_sumcheck_proofs) = if is_opcode_circuit {
            let main_sel_span = entered_span!("main_sel");
            let num_threads = optimal_sumcheck_threads(log2_num_instances);
            let alpha_pow = get_challenge_pows(
                num_reads
                    + num_writes
                    + cs.lk_expressions.len()
                    + cs.lk_table_expressions.len()
                    + cs.assert_zero_sumcheck_expressions.len(),
                transcript,
            );
            // create selector: all ONE, but padding ZERO to ceil_log2
            let sel: MultilinearExtension<E> = {
                // TODO sel can be shared if expression count match
                let mut sel = build_eq_x_r_vec(&rt_tower);
                if num_instances < sel.len() {
                    sel.splice(
                        num_instances..sel.len(),
                        std::iter::repeat_n(E::ZERO, sel.len() - num_instances),
                    );
                }
                sel.into_mle()
            };

            // for each j, computes \sum_i coeffs[i] * (mles[i][j] + shifting)
            let linear_combine_mles =
                |coeffs: &[E], mles: &[ArcMultilinearExtension<E>], shifting: E| {
                    assert!(!mles.is_empty());
                    assert_eq!(coeffs.len(), mles.len());

                    let n = mles[0].evaluations().len();

                    // combine into single mle by dot product with coeff
                    (0..n)
                        .into_par_iter()
                        .map(|j| {
                            dot_product::<E, _, _>(
                                mles.iter().map(|mle| match mle.evaluations() {
                                    FieldType::Ext(evals) => evals[j] + shifting,
                                    FieldType::Base(evals) => E::from(evals[j]) + shifting,
                                    _ => unreachable!(),
                                }),
                                // mle_evals.iter().map(|mle_eval| mle_eval[j] + shifting),
                                coeffs.iter().copied(),
                            )
                        })
                        .collect::<Vec<_>>()
                        .into_mle()
                };

            // The relation between the last layer of tower binary tree and read/write/logup records is
            //
            // outs[i][j] = padding + sel[j] * (records[i][j] - padding)
            //
            // it's easy to see the above formula is right because
            //   1. outs[i][j] = padding, if j > num_instances
            //   2. outs[i][j] = records[i][j], otherwise
            //
            // Then we have
            // outs[i](rt) - padding = \sum_j sel[j] * (records[i][j] - padding)

            let mut alpha_offset = 0;
            // r_records_combined is \sum_i alpha^i * (r_records[i][j]-padding) where padding = 1
            let mut r_records_combined: MultilinearExtension<E> = linear_combine_mles(
                &alpha_pow[alpha_offset..alpha_offset + num_reads],
                &r_records,
                E::ONE.neg(),
            );
            alpha_offset += num_reads;

            // w_records_combined is \sum_i alpha^i * (w_records[i][j]-padding) where padding = 1
            let mut w_records_combined: MultilinearExtension<E> = linear_combine_mles(
                &alpha_pow[alpha_offset..(alpha_offset + num_writes)],
                &w_records,
                E::ONE.neg(),
            );
            alpha_offset += num_writes;

            // lk_records_combined is \sum_i alpha^i * (lk_records[i][j]-padding)
            //  where padding = chip_record_alpha
            let mut lk_records_combined: MultilinearExtension<E> = linear_combine_mles(
                &alpha_pow[alpha_offset..(alpha_offset + cs.lk_expressions.len())],
                &lk_records,
                chip_record_alpha.neg(),
            );
            alpha_offset += cs.lk_expressions.len();

            let mut exprs = vec![];
            let mut expr_builder = VirtualPolynomialsBuilder::new(num_threads, log2_num_instances);
            let (sel_expr, r_records_combined, w_records_combined, lk_records_combined) = (
                expr_builder.lift(Either::Left(&sel)),
                expr_builder.lift(Either::Right(&mut r_records_combined)),
                expr_builder.lift(Either::Right(&mut w_records_combined)),
                expr_builder.lift(Either::Right(&mut lk_records_combined)),
            );

            exprs.push(sel_expr * (r_records_combined + w_records_combined + lk_records_combined));

            let mut distrinct_zerocheck_terms_set = BTreeSet::new();
            // degree > 1 zero expression sumcheck
            if !cs.assert_zero_sumcheck_expressions.is_empty() {
                // \sum_t sel(rt, t) * \sum_j alpha_{j} * all_monomial_terms(t)
                for ((expr, name), alpha) in cs
                    .assert_zero_sumcheck_expressions
                    .iter()
                    .zip_eq(cs.assert_zero_sumcheck_expressions_namespace_map.iter())
                    .zip_eq(&alpha_pow[alpha_offset..])
                {
                    // sanity check in debug build and output != instance index for zero check sumcheck poly
                    if cfg!(debug_assertions) {
                        let expected_zero_poly = wit_infer_by_expr(
                            &[],
                            &input.witness,
                            &[],
                            &input.public_input,
                            challenges,
                            expr,
                        );
                        let top_100_errors = expected_zero_poly
                            .get_base_field_vec()
                            .iter()
                            .enumerate()
                            .filter(|(_, v)| **v != E::BaseField::ZERO)
                            .take(100)
                            .collect_vec();
                        // if !top_100_errors.is_empty() {
                        //     return Err(ZKVMError::InvalidWitness(format!(
                        //         "degree > 1 zero check virtual poly: expr {name} != 0 on instance indexes: {}...",
                        //         top_100_errors.into_iter().map(|(i, _)| i).join(",")
                        //     )));
                        // }
                    }

                    distrinct_zerocheck_terms_set.extend(add_mle_list_by_expr(
                        &mut expr_builder,
                        &mut exprs,
                        Some(&sel),
                        input.witness.iter().collect_vec(),
                        expr,
                        challenges,
                        *alpha,
                    ));
                }
            }
            tracing::trace!("main sel sumcheck start");
            let (main_sel_sumcheck_proofs, _) = IOPProverState::prove(
                expr_builder.to_virtual_polys(&[exprs.into_iter().sum()], &[]),
                transcript,
            );
            tracing::trace!("main sel sumcheck end");
            exit_span!(main_sel_span);

            (
                main_sel_sumcheck_proofs.point,
                Some(main_sel_sumcheck_proofs.proofs),
            )
        } else {
            // In table proof, we always skip same point sumcheck for now
            // as tower sumcheck batch product argument/logup in same length

            (rt_tower, None)
        };

        exit_span!(sumcheck_span);

        (input_opening_point, main_sumcheck_proofs)
    }
}

impl<E: ExtensionField, PCS: PolynomialCommitmentScheme<E>> OpeningProver<CpuBackend<E, PCS>>
    for CpuProver
{
    fn open(
        &self,
        _witness_data: PCS::CommitmentWithWitness,
        _fixed_data: Option<PCS::CommitmentWithWitness>,
        _points: Vec<Point<E>>,
        _evals: Vec<E>,
        _transcript: &mut impl Transcript<E>,
    ) -> PCS::Proof {
        todo!()
    }
}
