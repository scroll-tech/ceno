use super::hal::{
    DeviceTransporter, MainSumcheckEvals, MainSumcheckProver, OpeningProver, ProverDevice,
    TowerProver, TraceCommitter,
};
use crate::{
    error::ZKVMError,
    scheme::{
        constants::{NUM_FANIN, SEPTIC_EXTENSION_DEGREE},
        hal::{DeviceProvingKey, EccQuarkProver, ProofInput, TowerProverSpec},
        septic_curve::{SepticExtension, SepticPoint, SymbolicSepticExtension},
        utils::{infer_tower_logup_witness, infer_tower_product_witness},
    },
    structs::{ComposedConstrainSystem, EccQuarkProof, PointAndEval, TowerProofs},
};
use either::Either;
use ff_ext::ExtensionField;
use gkr_iop::{
    cpu::{CpuBackend, CpuProver},
    gkr::{self, Evaluation, GKRProof, GKRProverOutput, layer::LayerWitness},
    hal::ProverBackend,
    selector::{SelectorContext, SelectorType},
};
use itertools::{Itertools, chain};
use mpcs::{Point, PolynomialCommitmentScheme};
use multilinear_extensions::{
    Expression, ToExpr,
    mle::{ArcMultilinearExtension, FieldType, IntoMLE, MultilinearExtension},
    util::ceil_log2,
    virtual_poly::{build_eq_x_r_vec, eq_eval},
    virtual_polys::VirtualPolynomialsBuilder,
};
use rayon::iter::{
    IndexedParallelIterator, IntoParallelIterator, IntoParallelRefIterator,
    IntoParallelRefMutIterator, ParallelIterator,
};
use std::{
    collections::BTreeMap,
    iter::{once, repeat_n},
    sync::Arc,
};
use sumcheck::{
    macros::{entered_span, exit_span},
    structs::{IOPProverMessage, IOPProverState},
    util::{get_challenge_pows, optimal_sumcheck_threads},
};
use p3::field::FieldAlgebra;
use transcript::{BasicTranscript, Transcript};
use witness::next_pow2_instance_padding;

pub type TowerRelationOutput<E> = (
    Point<E>,
    TowerProofs<E>,
    Vec<Vec<E>>,
    Vec<Vec<E>>,
    Vec<Vec<E>>,
);

// accumulate N=2^n EC points into one EC point using affine coordinates
// in one layer which borrows ideas from the [Quark paper](https://eprint.iacr.org/2020/1275.pdf)
pub struct CpuEccProver;

impl CpuEccProver {
    pub fn create_ecc_proof<'a, E: ExtensionField>(
        num_instances: usize,
        xs: Vec<Arc<MultilinearExtension<'a, E>>>,
        ys: Vec<Arc<MultilinearExtension<'a, E>>>,
        invs: Vec<Arc<MultilinearExtension<'a, E>>>,
        transcript: &mut impl Transcript<E>,
    ) -> EccQuarkProof<E> {
        assert_eq!(xs.len(), SEPTIC_EXTENSION_DEGREE);
        assert_eq!(ys.len(), SEPTIC_EXTENSION_DEGREE);

        let n = xs[0].num_vars() - 1;
        tracing::debug!(
            "Creating EC Summation Quark proof with {} points in {n} variables",
            num_instances
        );

        let out_rt = transcript.sample_and_append_vec(b"ecc", n);
        let num_threads = optimal_sumcheck_threads(out_rt.len());

        // expression with add (3 zero constraints), bypass (2 zero constraints), export (2 zero constraints)
        let alpha_pows = transcript.sample_and_append_challenge_pows(
            SEPTIC_EXTENSION_DEGREE * 3 + SEPTIC_EXTENSION_DEGREE * 2 + SEPTIC_EXTENSION_DEGREE * 2,
            b"ecc_alpha",
        );
        let mut alpha_pows_iter = alpha_pows.iter();

        let mut expr_builder = VirtualPolynomialsBuilder::new(num_threads, out_rt.len());

        let sel_add = SelectorType::QuarkBinaryTreeLessThan(0.into());
        let sel_add_ctx = SelectorContext {
            offset: 0,
            num_instances,
            num_vars: n,
        };
        let mut sel_add_mle: MultilinearExtension<'_, E> =
            sel_add.compute(&out_rt, &sel_add_ctx).unwrap();

        // the final sum is located at [1,...,1,0] (in big-endian)
        let last_evaluation_index = (1 << n) - 2;
        let lsi_on_hypercube = once(E::ZERO).chain(repeat_n(E::ONE, n - 1)).collect_vec();
        let mut sel_export = (0..(1 << n))
            .into_par_iter()
            .map(|_| E::ZERO)
            .collect::<Vec<_>>();
        sel_export[last_evaluation_index] = eq_eval(&out_rt, lsi_on_hypercube.as_slice());
        let mut sel_export_mle = sel_export.into_mle();

        // we construct sel_bypass witness here
        // verifier can derive it via `sel_bypass = eq - sel_add - sel_last_onehot`
        let mut sel_bypass_mle: Vec<E> = build_eq_x_r_vec(&out_rt);
        match sel_add_mle.evaluations() {
            FieldType::Ext(sel_add_mle) => sel_add_mle
                .par_iter()
                .zip_eq(sel_bypass_mle.par_iter_mut())
                .for_each(|(sel_add, sel_bypass)| {
                    if *sel_add != E::ZERO {
                        *sel_bypass = E::ZERO;
                    }
                }),
            _ => unreachable!(),
        }
        *sel_bypass_mle.last_mut().unwrap() = E::ZERO;
        let mut sel_bypass_mle = sel_bypass_mle.into_mle();
        let sel_add_expr = expr_builder.lift(sel_add_mle.to_either());
        let sel_bypass_expr = expr_builder.lift(sel_bypass_mle.to_either());
        let sel_export_expr = expr_builder.lift(sel_export_mle.to_either());

        let mut exprs_add = vec![];
        let mut exprs_bypass = vec![];

        let filter_bj = |v: &[Arc<MultilinearExtension<'_, E>>], j: usize| {
            v.iter()
                .map(|v| {
                    v.get_base_field_vec()
                        .iter()
                        .enumerate()
                        .filter(|(i, _)| *i % 2 == j)
                        .map(|(_, v)| v)
                        .cloned()
                        .collect_vec()
                        .into_mle()
                })
                .collect_vec()
        };
        // build x[b,0], x[b,1], y[b,0], y[b,1]
        let mut x0 = filter_bj(&xs, 0);
        let mut y0 = filter_bj(&ys, 0);
        let mut x1 = filter_bj(&xs, 1);
        let mut y1 = filter_bj(&ys, 1);
        // build x[1,b], y[1,b], s[1,b]
        let mut x3 = xs.iter().map(|x| x.as_view_slice(2, 1)).collect_vec();
        let mut y3 = ys.iter().map(|x| x.as_view_slice(2, 1)).collect_vec();
        let mut s = invs.iter().map(|x| x.as_view_slice(2, 1)).collect_vec();

        let s = SymbolicSepticExtension::new(
            s.iter_mut()
                .map(|s| expr_builder.lift(s.to_either()))
                .collect(),
        );
        let x0 = SymbolicSepticExtension::new(
            x0.iter_mut()
                .map(|x| expr_builder.lift(x.to_either()))
                .collect(),
        );
        let y0 = SymbolicSepticExtension::new(
            y0.iter_mut()
                .map(|y| expr_builder.lift(y.to_either()))
                .collect(),
        );
        let x1 = SymbolicSepticExtension::new(
            x1.iter_mut()
                .map(|x| expr_builder.lift(x.to_either()))
                .collect(),
        );
        let y1 = SymbolicSepticExtension::new(
            y1.iter_mut()
                .map(|y| expr_builder.lift(y.to_either()))
                .collect(),
        );
        let x3 = SymbolicSepticExtension::new(
            x3.iter_mut()
                .map(|x| expr_builder.lift(x.to_either()))
                .collect(),
        );
        let y3 = SymbolicSepticExtension::new(
            y3.iter_mut()
                .map(|y| expr_builder.lift(y.to_either()))
                .collect(),
        );
        // affine addition
        // zerocheck: 0 = s[1,b] * (x[b,0] - x[b,1]) - (y[b,0] - y[b,1]) with b != (1,...,1)
        exprs_add.extend(
            (s.clone() * (&x0 - &x1) - (&y0 - &y1))
                .to_exprs()
                .into_iter()
                .zip_eq(alpha_pows_iter.by_ref().take(SEPTIC_EXTENSION_DEGREE))
                .map(|(e, alpha)| e * Expression::Constant(Either::Right(*alpha))),
        );

        // zerocheck: 0 = s[1,b]^2 - x[b,0] - x[b,1] - x[1,b] with b != (1,...,1)
        exprs_add.extend(
            ((&s * &s) - &x0 - &x1 - &x3)
                .to_exprs()
                .into_iter()
                .zip_eq(alpha_pows_iter.by_ref().take(SEPTIC_EXTENSION_DEGREE))
                .map(|(e, alpha)| e * Expression::Constant(Either::Right(*alpha))),
        );
        // zerocheck: 0 = s[1,b] * (x[b,0] - x[1,b]) - (y[b,0] + y[1,b]) with b != (1,...,1)
        exprs_add.extend(
            (s.clone() * (&x0 - &x3) - (&y0 + &y3))
                .to_exprs()
                .into_iter()
                .zip_eq(alpha_pows_iter.by_ref().take(SEPTIC_EXTENSION_DEGREE))
                .map(|(e, alpha)| e * Expression::Constant(Either::Right(*alpha))),
        );

        let exprs_add = exprs_add.into_iter().sum::<Expression<E>>() * sel_add_expr;

        // deal with bypass
        // 0 = (x[1,b] - x[b,0])
        exprs_bypass.extend(
            (&x3 - &x0)
                .to_exprs()
                .into_iter()
                .zip_eq(alpha_pows_iter.by_ref().take(SEPTIC_EXTENSION_DEGREE))
                .map(|(e, alpha)| e * Expression::Constant(Either::Right(*alpha))),
        );
        // 0 = (y[1,b] - y[b,0])
        exprs_bypass.extend(
            (&y3 - &y0)
                .to_exprs()
                .into_iter()
                .zip_eq(alpha_pows_iter.by_ref().take(SEPTIC_EXTENSION_DEGREE))
                .map(|(e, alpha)| e * Expression::Constant(Either::Right(*alpha))),
        );

        // export x[1,...,1,0], y[1,...,1,0] for final result (using big-endian notation)
        let xp = xs.iter().map(|x| x.as_view_slice(2, 1)).collect_vec();
        let yp = ys.iter().map(|y| y.as_view_slice(2, 1)).collect_vec();
        let final_sum_x: SepticExtension<E::BaseField> = (xp.iter())
            .map(|x| x.get_base_field_vec()[last_evaluation_index]) // x[1,...,1,0]
            .collect_vec()
            .into();
        let final_sum_y: SepticExtension<E::BaseField> = (yp.iter())
            .map(|y| y.get_base_field_vec()[last_evaluation_index]) // x[1,...,1,0]
            .collect_vec()
            .into();
        // 0 = sel_export * (x[1,b] - final_sum.x)
        // 0 = sel_export * (y[1,b] - final_sum.y)
        let export_expr =
            x3.0.iter()
                .zip_eq(final_sum_x.0.iter())
                .chain(y3.0.iter().zip_eq(final_sum_y.0.iter()))
                .map(|(x, final_x)| x - final_x.expr())
                .zip_eq(alpha_pows_iter.by_ref().take(SEPTIC_EXTENSION_DEGREE * 2))
                .map(|(e, alpha)| e * Expression::Constant(Either::Right(*alpha)))
                .sum::<Expression<E>>()
                * sel_export_expr;

        let exprs_bypass = exprs_bypass.into_iter().sum::<Expression<E>>() * sel_bypass_expr;

        let (zerocheck_proof, state) = IOPProverState::prove(
            expr_builder.to_virtual_polys(&[exprs_add + exprs_bypass + export_expr], &[]),
            transcript,
        );

        let rt = state.collect_raw_challenges();
        let evals = state.get_mle_flatten_final_evaluations();

        // 3 for sel_add, sel_bypass, sel_export
        // 7 for x[rt,0], x[rt,1], y[rt,0], y[rt,1], x[1,rt], y[1,rt], s[1,rt]
        assert_eq!(evals.len(), 3 + SEPTIC_EXTENSION_DEGREE * 7);

        #[cfg(feature = "sanity-check")]
        {
            let s = invs.iter().map(|x| x.as_view_slice(2, 1)).collect_vec();
            let x0 = filter_bj(&xs, 0);
            let y0 = filter_bj(&ys, 0);
            let x1 = filter_bj(&xs, 1);
            let y1 = filter_bj(&ys, 1);
            let sel_export = eq_eval(&out_rt, &lsi_on_hypercube) * eq_eval(&rt, &lsi_on_hypercube);
            assert_eq!(sel_export, evals[2]);

            let evals = &evals[3..];
            // check evaluations
            for i in 0..SEPTIC_EXTENSION_DEGREE {
                assert_eq!(s[i].evaluate(&rt), evals[i]);
                assert_eq!(x0[i].evaluate(&rt), evals[SEPTIC_EXTENSION_DEGREE + i]);
                assert_eq!(y0[i].evaluate(&rt), evals[SEPTIC_EXTENSION_DEGREE * 2 + i]);
                assert_eq!(x1[i].evaluate(&rt), evals[SEPTIC_EXTENSION_DEGREE * 3 + i]);
                assert_eq!(y1[i].evaluate(&rt), evals[SEPTIC_EXTENSION_DEGREE * 4 + i]);
                assert_eq!(xp[i].evaluate(&rt), evals[SEPTIC_EXTENSION_DEGREE * 5 + i]);
                assert_eq!(yp[i].evaluate(&rt), evals[SEPTIC_EXTENSION_DEGREE * 6 + i]);
            }
        }
        let final_sum = SepticPoint::from_affine(final_sum_x, final_sum_y);

        EccQuarkProof {
            zerocheck_proof,
            num_instances,
            evals,
            rt,
            sum: final_sum,
        }
    }
}

impl<E: ExtensionField, PCS: PolynomialCommitmentScheme<E>> EccQuarkProver<CpuBackend<E, PCS>>
    for CpuProver<CpuBackend<E, PCS>>
{
    fn prove_ec_sum_quark<'a>(
        &self,
        num_instances: usize,
        xs: Vec<Arc<MultilinearExtension<'a, E>>>,
        ys: Vec<Arc<MultilinearExtension<'a, E>>>,
        invs: Vec<Arc<MultilinearExtension<'a, E>>>,
        transcript: &mut impl Transcript<E>,
    ) -> Result<EccQuarkProof<E>, ZKVMError> {
        Ok(CpuEccProver::create_ecc_proof(
            num_instances,
            xs,
            ys,
            invs,
            transcript,
        ))
    }
}

pub struct CpuTowerProver;

impl CpuTowerProver {
    pub fn create_proof<'a, E: ExtensionField, PCS: PolynomialCommitmentScheme<E>>(
        prod_specs: Vec<TowerProverSpec<'a, CpuBackend<E, PCS>>>,
        logup_specs: Vec<TowerProverSpec<'a, CpuBackend<E, PCS>>>,
        num_fanin: usize,
        transcript: &mut impl Transcript<E>,
    ) -> (Point<E>, TowerProofs<E>) {
        #[derive(Debug, Clone)]
        enum GroupedMLE<'a, E: ExtensionField> {
            Prod((usize, Vec<MultilinearExtension<'a, E>>)), // usize is the index in prod_specs
            Logup((usize, Vec<MultilinearExtension<'a, E>>)), // usize is the index in logup_specs
        }

        // XXX to sumcheck batched product argument with logup, we limit num_product_fanin to 2
        // TODO maybe give a better naming?
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
        fn merge_spec_witness<'b, E: ExtensionField, PCS: PolynomialCommitmentScheme<E>>(
            merged: &mut [Vec<GroupedMLE<'b, E>>],
            spec: TowerProverSpec<'b, CpuBackend<E, PCS>>,
            index: usize,
            group_ctor: fn((usize, Vec<MultilinearExtension<'b, E>>)) -> GroupedMLE<'b, E>,
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
            let rt_prime = [state.collect_raw_challenges(), r_merge].concat();

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
impl<E: ExtensionField, PCS: PolynomialCommitmentScheme<E>> TraceCommitter<CpuBackend<E, PCS>>
    for CpuProver<CpuBackend<E, PCS>>
{
    fn commit_traces<'a>(
        &self,
        traces: BTreeMap<usize, witness::RowMajorMatrix<E::BaseField>>,
    ) -> (
        Vec<MultilinearExtension<'a, E>>,
        PCS::CommitmentWithWitness,
        PCS::Commitment,
    ) {
        let max_poly_size_log2 = traces
            .values()
            .map(|trace| ceil_log2(next_pow2_instance_padding(trace.num_instances())))
            .max()
            .unwrap();
        if max_poly_size_log2 > self.backend.max_poly_size_log2 {
            panic!(
                "max_poly_size_log2 {max_poly_size_log2} > max_poly_size_log2 backend {}",
                self.backend.max_poly_size_log2
            )
        }
        let prover_param = &self.backend.pp;
        let pcs_data = PCS::batch_commit(prover_param, traces.into_values().collect_vec()).unwrap();
        let commit = PCS::get_pure_commitment(&pcs_data);
        let mles = PCS::get_arc_mle_witness_from_commitment(&pcs_data)
            .into_par_iter()
            .map(|mle| mle.as_ref().clone())
            .collect::<Vec<_>>();

        (mles, pcs_data, commit)
    }

    fn extract_witness_mles<'a, 'b>(
        &self,
        witness_mles: &'b mut Vec<<CpuBackend<E, PCS> as ProverBackend>::MultilinearPoly<'a>>,
        _pcs_data: &'b <CpuBackend<E, PCS> as ProverBackend>::PcsData,
    ) -> Box<
        dyn Iterator<Item = Arc<<CpuBackend<E, PCS> as ProverBackend>::MultilinearPoly<'a>>> + 'b,
    > {
        let iter = witness_mles.drain(..).map(Arc::new);
        Box::new(iter)
    }
}

impl<E: ExtensionField, PCS: PolynomialCommitmentScheme<E>> TowerProver<CpuBackend<E, PCS>>
    for CpuProver<CpuBackend<E, PCS>>
{
    #[allow(clippy::type_complexity)]
    #[tracing::instrument(
        skip_all,
        name = "build_tower_witness",
        fields(profiling_3),
        level = "trace"
    )]
    fn build_tower_witness<'a, 'b, 'c>(
        &self,
        composed_cs: &ComposedConstrainSystem<E>,
        input: &ProofInput<'a, CpuBackend<E, PCS>>,
        records: &'c [ArcMultilinearExtension<'b, E>],
    ) -> (
        Vec<Vec<Vec<E>>>,
        Vec<TowerProverSpec<'c, CpuBackend<E, PCS>>>,
        Vec<TowerProverSpec<'c, CpuBackend<E, PCS>>>,
    )
    where
        'a: 'b,
        'b: 'c,
    {
        let ComposedConstrainSystem {
            zkvm_v1_css: cs, ..
        } = composed_cs;
        let num_var_with_rotation =
            input.log2_num_instances() + composed_cs.rotation_vars().unwrap_or(0);

        let num_reads = cs.r_expressions.len() + cs.r_table_expressions.len();
        let num_writes = cs.w_expressions.len() + cs.w_table_expressions.len();
        let mut offset = 0;
        let r_set_wit = &records[offset..][..num_reads];
        assert_eq!(r_set_wit.len(), num_reads);
        offset += num_reads;
        let w_set_wit = &records[offset..][..num_writes];
        assert_eq!(w_set_wit.len(), num_writes);
        offset += num_writes;
        let lk_n_wit = &records[offset..][..cs.lk_table_expressions.len()];
        offset += cs.lk_table_expressions.len();
        let lk_d_wit = if !cs.lk_table_expressions.is_empty() {
            &records[offset..][..cs.lk_table_expressions.len()]
        } else {
            &records[offset..][..cs.lk_expressions.len()]
        };

        // infer all tower witness after last layer
        let span = entered_span!("tower_witness_last_layer");
        let mut r_set_last_layer = r_set_wit
            .iter()
            .chain(w_set_wit.iter())
            .map(|wit| wit.as_view_chunks(NUM_FANIN))
            .collect::<Vec<_>>();
        let w_set_last_layer = r_set_last_layer.split_off(r_set_wit.len());

        let mut lk_numerator_last_layer = lk_n_wit
            .iter()
            .chain(lk_d_wit.iter())
            .map(|wit| wit.as_view_chunks(NUM_FANIN))
            .collect::<Vec<_>>();
        let lk_denominator_last_layer = lk_numerator_last_layer.split_off(lk_n_wit.len());
        exit_span!(span);

        let span = entered_span!("tower_tower_witness");
        let r_wit_layers = r_set_last_layer
            .into_iter()
            .map(|last_layer| {
                infer_tower_product_witness(num_var_with_rotation, last_layer, NUM_FANIN)
            })
            .collect_vec();
        let w_wit_layers = w_set_last_layer
            .into_iter()
            .map(|last_layer| {
                infer_tower_product_witness(num_var_with_rotation, last_layer, NUM_FANIN)
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

        let prod_specs = r_wit_layers
            .into_iter()
            .chain(w_wit_layers)
            .map(|witness| TowerProverSpec { witness })
            .collect_vec();
        let lookup_specs = lk_wit_layers
            .into_iter()
            .map(|witness| TowerProverSpec { witness })
            .collect_vec();

        let out_evals = vec![r_out_evals, w_out_evals, lk_out_evals];

        (out_evals, prod_specs, lookup_specs)
    }

    #[tracing::instrument(
        skip_all,
        name = "prove_tower_relation",
        fields(profiling_3),
        level = "trace"
    )]
    fn prove_tower_relation<'a, 'b, 'c>(
        &self,
        composed_cs: &ComposedConstrainSystem<E>,
        input: &ProofInput<'a, CpuBackend<E, PCS>>,
        records: &'c [Arc<MultilinearExtension<'b, E>>],
        _challenges: &[E; 2],
        transcript: &mut impl Transcript<E>,
    ) -> TowerRelationOutput<E>
    where
        'a: 'b,
        'b: 'c,
    {
        // First build tower witness
        let span = entered_span!("build_tower_witness", profiling_2 = true);
        let (mut out_evals, prod_specs, logup_specs) =
            self.build_tower_witness(composed_cs, input, records);
        exit_span!(span);

        // Then prove the tower relation
        let span = entered_span!("prove_tower_relation", profiling_2 = true);
        let (rt, proofs) = CpuTowerProver::create_proof(prod_specs, logup_specs, 2, transcript);

        let lk_out_evals = out_evals.pop().unwrap();
        let w_out_evals = out_evals.pop().unwrap();
        let r_out_evals = out_evals.pop().unwrap();
        exit_span!(span);
        (rt, proofs, lk_out_evals, w_out_evals, r_out_evals)
    }
}

impl<E: ExtensionField, PCS: PolynomialCommitmentScheme<E>> MainSumcheckProver<CpuBackend<E, PCS>>
    for CpuProver<CpuBackend<E, PCS>>
{
    #[allow(clippy::type_complexity)]
    #[tracing::instrument(
        skip_all,
        name = "prove_main_constraints",
        fields(profiling_3),
        level = "trace"
    )]
    fn prove_main_constraints<'a, 'b>(
        &self,
        rt_tower: Vec<E>,
        input: &'b ProofInput<'a, CpuBackend<E, PCS>>,
        composed_cs: &ComposedConstrainSystem<E>,
        challenges: &[E; 2],
        transcript: &mut impl Transcript<<CpuBackend<E, PCS> as ProverBackend>::E>,
    ) -> Result<
        (
            Point<E>,
            MainSumcheckEvals<E>,
            Option<Vec<IOPProverMessage<E>>>,
            Option<GKRProof<E>>,
        ),
        ZKVMError,
    > {
        let ComposedConstrainSystem {
            zkvm_v1_css: cs,
            gkr_circuit,
        } = composed_cs;

        let num_instances = input.num_instances();
        let log2_num_instances = input.log2_num_instances();
        let num_threads = optimal_sumcheck_threads(log2_num_instances);
        let num_var_with_rotation = log2_num_instances + composed_cs.rotation_vars().unwrap_or(0);

        let Some(gkr_circuit) = gkr_circuit else {
            panic!("empty gkr circuit")
        };
        let pub_io_mles = cs
            .instance_openings
            .iter()
            .map(|instance| input.public_input[instance.0].clone())
            .collect_vec();
        let selector_ctxs = if cs.ec_final_sum.is_empty() {
            // it's not global chip
            vec![
                SelectorContext {
                    offset: 0,
                    num_instances,
                    num_vars: num_var_with_rotation,
                };
                gkr_circuit
                    .layers
                    .first()
                    .map(|layer| layer.out_sel_and_eval_exprs.len())
                    .unwrap_or(0)
            ]
        } else {
            // it's global chip
            vec![
                SelectorContext {
                    offset: 0,
                    num_instances: input.num_instances[0],
                    num_vars: num_var_with_rotation,
                },
                SelectorContext {
                    offset: input.num_instances[0],
                    num_instances: input.num_instances[1],
                    num_vars: num_var_with_rotation,
                },
                SelectorContext {
                    offset: 0,
                    num_instances,
                    num_vars: num_var_with_rotation,
                },
            ]
        };
        let GKRProverOutput {
            gkr_proof,
            opening_evaluations,
            mut rt,
        } = gkr_circuit.prove::<CpuBackend<E, PCS>, CpuProver<_>>(
            num_threads,
            num_var_with_rotation,
            gkr::GKRCircuitWitness {
                layers: vec![LayerWitness(
                    chain!(
                        &input.witness,
                        &input.fixed,
                        &pub_io_mles,
                        &input.structural_witness,
                    )
                    .cloned()
                    .collect_vec(),
                )],
            },
            // eval value doesnt matter as it wont be used by prover
            &vec![PointAndEval::new(rt_tower, E::ZERO); gkr_circuit.final_out_evals.len()],
            &input
                .pub_io_evals
                .iter()
                .map(|v| v.map_either(E::from, |v| v).into_inner())
                .collect_vec(),
            challenges,
            transcript,
            &selector_ctxs,
        )?;
        assert_eq!(rt.len(), 1, "TODO support multi-layer gkr iop");
        Ok((
            rt.remove(0),
            MainSumcheckEvals {
                wits_in_evals: opening_evaluations
                    .iter()
                    .take(cs.num_witin as usize)
                    .map(|Evaluation { value, .. }| value)
                    .copied()
                    .collect_vec(),
                fixed_in_evals: opening_evaluations
                    .iter()
                    .skip(cs.num_witin as usize)
                    .take(cs.num_fixed)
                    .map(|Evaluation { value, .. }| value)
                    .copied()
                    .collect_vec(),
            },
            None,
            Some(gkr_proof),
        ))
    }
}

impl<E: ExtensionField, PCS: PolynomialCommitmentScheme<E>> OpeningProver<CpuBackend<E, PCS>>
    for CpuProver<CpuBackend<E, PCS>>
{
    fn open(
        &self,
        witness_data: PCS::CommitmentWithWitness,
        fixed_data: Option<Arc<PCS::CommitmentWithWitness>>,
        points: Vec<Point<E>>,
        mut evals: Vec<Vec<Vec<E>>>, // where each inner vec![wit_evals, fixed_evals]
        transcript: &mut impl Transcript<E>,
    ) -> PCS::Proof {
        let mut rounds = vec![];
        rounds.push((&witness_data, {
            evals
                .iter_mut()
                .zip(&points)
                .filter_map(|(evals, point)| {
                    let witin_evals = evals.remove(0);
                    if !witin_evals.is_empty() {
                        Some((point.clone(), witin_evals))
                    } else {
                        None
                    }
                })
                .collect_vec()
        }));
        if let Some(fixed_data) = fixed_data.as_ref().map(|f| f.as_ref()) {
            rounds.push((fixed_data, {
                evals
                    .iter_mut()
                    .zip(points)
                    .filter_map(|(evals, point)| {
                        if !evals.is_empty() && !evals[0].is_empty() {
                            Some((point.clone(), evals.remove(0)))
                        } else {
                            None
                        }
                    })
                    .collect_vec()
            }));
        }
        PCS::batch_open(&self.backend.pp, rounds, transcript).unwrap()
    }
}

impl<E: ExtensionField, PCS: PolynomialCommitmentScheme<E>> DeviceTransporter<CpuBackend<E, PCS>>
    for CpuProver<CpuBackend<E, PCS>>
{
    fn transport_proving_key(
        &self,
        is_first_shard: bool,
        pk: Arc<
            crate::structs::ZKVMProvingKey<
                <CpuBackend<E, PCS> as ProverBackend>::E,
                <CpuBackend<E, PCS> as ProverBackend>::Pcs,
            >,
        >,
    ) -> DeviceProvingKey<'static, CpuBackend<E, PCS>> {
        let pcs_data = if is_first_shard {
            pk.fixed_commit_wd.clone().unwrap()
        } else {
            pk.fixed_no_omc_init_commit_wd.clone().unwrap()
        };

        let fixed_mles = PCS::get_arc_mle_witness_from_commitment(pcs_data.as_ref());

        DeviceProvingKey {
            pcs_data,
            fixed_mles,
        }
    }

    fn transport_mles<'a>(
        &self,
        mles: &[MultilinearExtension<'a, E>],
    ) -> Vec<ArcMultilinearExtension<'a, E>> {
        mles.iter().map(|mle| mle.clone().into()).collect_vec()
    }
}

// impl<E: ExtensionField, PCS: PolynomialCommitmentScheme<E>> FixedMLEPadder<CpuBackend<E, PCS>>
//     for CpuProver<CpuBackend<E, PCS>>
// {
//     fn padding_fixed_mle<'a, 'b>(
//         &self,
//         composed_cs: &ComposedConstrainSystem<<CpuBackend<E, PCS> as ProverBackend>::E>,
//         fixed_mles: Vec<ArcMultilinearExtension<'b, E>>,
//         num_instances: usize,
//     ) -> Vec<ArcMultilinearExtension<'a, E>>
//     where
//         'b: 'a,
//     {
//         let num_vars = ceil_log2(next_pow2_instance_padding(num_instances));
//         let num_var_with_rotation = num_vars + composed_cs.rotation_vars().unwrap_or(0);
//         // fix polynomial might be short length
//         let fixed_poly_expand_span = entered_span!("fixed_poly_expand");
//         let fixed_mles = if fixed_mles
//             .iter()
//             .all(|v| v.evaluations().len() == 1 << num_var_with_rotation)
//         {
//             fixed_mles.clone()
//         } else {
//             fixed_mles
//                 .par_iter()
//                 .map(|v| {
//                     v.get_base_field_vec()
//                         .iter()
//                         .copied()
//                         .cycle()
//                         .take(1 << num_var_with_rotation)
//                         .collect_vec()
//                         .into_mle()
//                         .into()
//                 })
//                 .collect::<Vec<ArcMultilinearExtension<E>>>()
//         };
//         exit_span!(fixed_poly_expand_span);
//         fixed_mles
//     }
// }

impl<E: ExtensionField, PCS: PolynomialCommitmentScheme<E>>
    super::hal::ChipInputPreparer<CpuBackend<E, PCS>> for CpuProver<CpuBackend<E, PCS>>
{
    fn prepare_chip_input(
        &self,
        _task: &mut crate::scheme::scheduler::ChipTask<'_, CpuBackend<E, PCS>>,
        _pcs_data: &<CpuBackend<E, PCS> as ProverBackend>::PcsData,
    ) {
        // No-op: CPU tasks are eagerly populated during build_chip_tasks
    }
}

impl<E, PCS> ProverDevice<CpuBackend<E, PCS>> for CpuProver<CpuBackend<E, PCS>>
where
    E: ExtensionField,
    PCS: PolynomialCommitmentScheme<E>,
{
    fn get_pb(&self) -> &CpuBackend<E, PCS> {
        self.backend.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use crate::scheme::{
        constants::SEPTIC_EXTENSION_DEGREE,
        cpu::CpuEccProver,
        septic_curve::{SepticExtension, SepticPoint},
        verifier::EccVerifier,
    };
    use ff_ext::BabyBearExt4;
    use itertools::Itertools;
    use multilinear_extensions::{
        mle::{IntoMLE, MultilinearExtension},
        util::transpose,
    };
    use p3::babybear::BabyBear;
    use std::{iter::repeat_n, sync::Arc};
    use transcript::BasicTranscript;
    use witness::next_pow2_instance_padding;

    #[test]
    fn test_ecc_quark_prover() {
        for n_points in 1..2 ^ 10 {
            test_ecc_quark_prover_inner(n_points)
        }
    }

    fn test_ecc_quark_prover_inner(n_points: usize) {
        type E = BabyBearExt4;
        type F = BabyBear;

        let log2_n = next_pow2_instance_padding(n_points).ilog2();
        let mut rng = rand::thread_rng();

        let final_sum;
        // generate 1 ecc add witness
        let ecc_spec: Vec<MultilinearExtension<'_, E>> = {
            // sample N = 2^n points
            let mut points = (0..n_points)
                .map(|_| SepticPoint::<F>::random(&mut rng))
                .collect_vec();
            points.extend(repeat_n(
                SepticPoint::point_at_infinity(),
                (1 << log2_n) - points.len(),
            ));
            let mut s = Vec::with_capacity(1 << (log2_n + 1));
            s.extend(repeat_n(SepticExtension::zero(), 1 << log2_n));

            for layer in (1..=log2_n).rev() {
                let num_inputs = 1 << layer;
                let inputs = &points[points.len() - num_inputs..];

                s.extend(inputs.chunks_exact(2).map(|chunk| {
                    let p = &chunk[0];
                    let q = &chunk[1];
                    if q.is_infinity {
                        SepticExtension::zero()
                    } else {
                        (&p.y - &q.y) * (&p.x - &q.x).inverse().unwrap()
                    }
                }));

                points.extend(
                    inputs
                        .chunks_exact(2)
                        .map(|chunk| {
                            let p = chunk[0].clone();
                            let q = chunk[1].clone();
                            p + q
                        })
                        .collect_vec(),
                );
            }
            final_sum = points.last().cloned().unwrap();

            // padding to 2*N
            s.push(SepticExtension::zero());
            points.push(SepticPoint::point_at_infinity());

            assert_eq!(s.len(), 1 << (log2_n + 1));
            assert_eq!(points.len(), 1 << (log2_n + 1));

            // transform points to row major matrix
            let trace = points
                .iter()
                .zip_eq(s.iter())
                .map(|(p, s)| {
                    p.x.iter()
                        .chain(p.y.iter())
                        .chain(s.iter())
                        .copied()
                        .collect_vec()
                })
                .collect_vec();

            // transpose row major matrix to column major matrix
            transpose(trace)
                .into_iter()
                .map(|v| v.into_mle())
                .collect_vec()
        };
        let (xs, rest) = ecc_spec.split_at(SEPTIC_EXTENSION_DEGREE);
        let (ys, s) = rest.split_at(SEPTIC_EXTENSION_DEGREE);

        let mut transcript = BasicTranscript::new(b"test");
        let quark_proof = CpuEccProver::create_ecc_proof(
            n_points,
            xs.iter().cloned().map(Arc::new).collect_vec(),
            ys.iter().cloned().map(Arc::new).collect_vec(),
            s.iter().cloned().map(Arc::new).collect_vec(),
            &mut transcript,
        );

        assert_eq!(quark_proof.sum, final_sum);
        let mut transcript = BasicTranscript::new(b"test");
        assert!(
            EccVerifier::verify_ecc_proof(&quark_proof, &mut transcript)
                .inspect_err(|err| println!("err {:?}", err))
                .is_ok()
        );
    }
}
