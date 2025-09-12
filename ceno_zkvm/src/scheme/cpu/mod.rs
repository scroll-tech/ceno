use super::hal::{
    DeviceTransporter, MainSumcheckProver, OpeningProver, ProverDevice, TowerProver, TraceCommitter,
};
use crate::{
    circuit_builder::ConstraintSystem,
    error::ZKVMError,
    scheme::{
        constants::{NUM_FANIN, NUM_FANIN_LOGUP},
        hal::{DeviceProvingKey, MainSumcheckEvals, ProofInput, TowerProverSpec},
        septic_curve::{SepticExtension, SymbolicSepticExtension},
        utils::{
            infer_tower_logup_witness, infer_tower_product_witness, masked_mle_split_to_chunks,
            wit_infer_by_expr,
        },
    },
    structs::{ComposedConstrainSystem, PointAndEval, TowerProofs},
};
use either::Either;
use ff_ext::ExtensionField;
use gkr_iop::{
    cpu::{CpuBackend, CpuProver},
    gkr::{self, Evaluation, GKRProof, GKRProverOutput, layer::LayerWitness},
    hal::ProverBackend,
};
use itertools::{Itertools, chain};
use mpcs::{Point, PolynomialCommitmentScheme};
use multilinear_extensions::{
    Expression, Instance, WitnessId,
    mle::{ArcMultilinearExtension, FieldType, IntoMLE, MultilinearExtension},
    util::ceil_log2,
    virtual_poly::build_eq_x_r_vec,
    virtual_polys::VirtualPolynomialsBuilder,
};
use rayon::iter::{IntoParallelIterator, IntoParallelRefIterator, ParallelIterator};
use std::{collections::BTreeMap, sync::Arc};
use sumcheck::{
    macros::{entered_span, exit_span},
    structs::{IOPProverMessage, IOPProverState},
    util::{get_challenge_pows, optimal_sumcheck_threads},
};
use transcript::Transcript;
use witness::next_pow2_instance_padding;

pub type TowerRelationOutput<E> = (
    Point<E>,
    TowerProofs<E>,
    Vec<Vec<E>>,
    Vec<Vec<E>>,
    Vec<Vec<E>>,
);
pub struct CpuTowerProver;

impl CpuTowerProver {
    pub fn create_proof<'a, E: ExtensionField, PCS: PolynomialCommitmentScheme<E>>(
        prod_specs: Vec<TowerProverSpec<'a, CpuBackend<E, PCS>>>,
        logup_specs: Vec<TowerProverSpec<'a, CpuBackend<E, PCS>>>,
        ecc_spec: Option<TowerProverSpec<'a, CpuBackend<E, PCS>>>,
        num_fanin: usize,
        transcript: &mut impl Transcript<E>,
    ) -> (Point<E>, TowerProofs<E>) {
        #[derive(Debug, Clone)]
        enum GroupedMLE<'a, E: ExtensionField> {
            Prod((usize, Vec<MultilinearExtension<'a, E>>)), // usize is the index in prod_specs
            Logup((usize, Vec<MultilinearExtension<'a, E>>)), // usize is the index in logup_specs
            EcAdd(
                (
                    Vec<MultilinearExtension<'a, E>>,
                    Vec<MultilinearExtension<'a, E>>,
                ),
            ),
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
                logup_specs_len * 2
                + ecc_spec.as_ref().map_or(0, |_| 14),
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

        if let Some(ecc_spec) = ecc_spec {
            for i in 0..max_round_index {
                layer_witness[i + 1].push(GroupedMLE::EcAdd((
                    // TODO: avoid clone
                    ecc_spec.witness[i].clone(),
                    ecc_spec.witness[i + 1].clone(),
                )));
            }
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
                    GroupedMLE::EcAdd((prev_layer, curr_layer)) => {
                        assert_eq!(curr_layer.len(), 2 * 14); // 3 points, each point has 14 polys
                        assert_eq!(prev_layer.len(), 2 * 14);
                        let (x1, rest) = curr_layer.split_at(7);
                        let (y1, rest) = rest.split_at(7);
                        let (x2, rest) = rest.split_at(7);
                        let (y2, _) = rest.split_at(7);
                        let (x3, y3) = prev_layer.split_at(7);

                        let x1 = &SymbolicSepticExtension::new(
                            x1.into_iter()
                                .map(|x| expr_builder.lift(Either::Left(x)))
                                .collect(),
                        );
                        let y1 = &SymbolicSepticExtension::new(
                            y1.into_iter()
                                .map(|y| expr_builder.lift(Either::Left(y)))
                                .collect(),
                        );
                        let x2 = &SymbolicSepticExtension::new(
                            x2.into_iter()
                                .map(|x| expr_builder.lift(Either::Left(x)))
                                .collect(),
                        );
                        let y2 = &SymbolicSepticExtension::new(
                            y2.into_iter()
                                .map(|y| expr_builder.lift(Either::Left(y)))
                                .collect(),
                        );
                        let x3 = &SymbolicSepticExtension::new(
                            x3.into_iter()
                                .map(|x| expr_builder.lift(Either::Left(x)))
                                .collect(),
                        );
                        let y3 = &SymbolicSepticExtension::new(
                            y3.into_iter()
                                .map(|y| expr_builder.lift(Either::Left(y)))
                                .collect(),
                        );

                        // 0 = eq * ((x3 + x1 + x2) * (x2 - x1)^2 - (y2 - y1)^2)
                        exprs.extend(
                            (((x3 + x1 + x2) * (x2 - x1) * (x2 - x1) - (y2 - y1) * (y2 - y1))
                                * &eq_expr)
                                .to_exprs(),
                        );
                        // 0 = eq * ((y3 + y1) * (x2 - x1) - (y2 - y1) * (x1 - x3))
                        exprs.extend(
                            (((y3 + y1) * (x2 - x1) - (y2 - y1) * (x1 - x3))
                                * &eq_expr)
                                .to_exprs(),
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
        &mut self,
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
        is_padded: bool,
        challenges: &[E; 2],
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
        let num_instances_with_rotation =
            input.num_instances << composed_cs.rotation_vars().unwrap_or(0);
        let num_var_with_rotation =
            input.log2_num_instances() + composed_cs.rotation_vars().unwrap_or(0);

        let chip_record_alpha = challenges[0];

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

        // infer last layer witness for septic points' accumulation

        // infer all tower witness after last layer
        let span = entered_span!("tower_witness_last_layer");
        let mut r_set_last_layer = r_set_wit
            .iter()
            .chain(w_set_wit.iter())
            .map(|wit| {
                if is_padded {
                    wit.as_view_chunks(NUM_FANIN)
                } else {
                    masked_mle_split_to_chunks(wit, num_instances_with_rotation, NUM_FANIN, E::ONE)
                }
            })
            .collect::<Vec<_>>();
        let w_set_last_layer = r_set_last_layer.split_off(r_set_wit.len());

        let mut lk_numerator_last_layer = lk_n_wit
            .iter()
            .chain(lk_d_wit.iter())
            .enumerate()
            .map(|(i, wit)| {
                if is_padded {
                    wit.as_view_chunks(NUM_FANIN)
                } else {
                    let default = if i < lk_n_wit.len() {
                        // For table circuit, the last layer's length is always two's power
                        // so the padding will not happen, therefore we can use any value here.
                        E::ONE
                    } else {
                        chip_record_alpha
                    };
                    masked_mle_split_to_chunks(
                        wit,
                        num_instances_with_rotation,
                        NUM_FANIN_LOGUP,
                        default,
                    )
                }
            })
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
        is_padded: bool,
        challenges: &[E; 2],
        transcript: &mut impl Transcript<E>,
    ) -> TowerRelationOutput<E>
    where
        'a: 'b,
        'b: 'c,
    {
        // First build tower witness
        let span = entered_span!("build_tower_witness", profiling_2 = true);
        let (mut out_evals, prod_specs, logup_specs) =
            self.build_tower_witness(composed_cs, input, records, is_padded, challenges);
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
    #[tracing::instrument(skip_all, name = "table_witness", fields(profiling_3), level = "trace")]
    fn table_witness<'a>(
        &self,
        input: &ProofInput<'a, CpuBackend<<CpuBackend<E, PCS> as ProverBackend>::E, PCS>>,
        cs: &ConstraintSystem<<CpuBackend<E, PCS> as ProverBackend>::E>,
        challenges: &[<CpuBackend<E, PCS> as ProverBackend>::E],
    ) -> Vec<Arc<<CpuBackend<E, PCS> as ProverBackend>::MultilinearPoly<'a>>> {
        // main constraint: lookup denominator and numerator record witness inference
        let record_span = entered_span!("record");
        let records: Vec<ArcMultilinearExtension<'_, E>> = cs
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
                    expr,
                    cs.num_witin,
                    cs.num_structural_witin,
                    cs.num_fixed as WitnessId,
                    &input.fixed,
                    &input.witness,
                    &input.structural_witness,
                    &input.public_input,
                    challenges,
                )
            })
            .collect();
        exit_span!(record_span);
        records
    }

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

        let num_instances = input.num_instances;
        let next_pow2_instances = next_pow2_instance_padding(num_instances);
        let log2_num_instances = ceil_log2(next_pow2_instances);
        let num_threads = optimal_sumcheck_threads(log2_num_instances);
        let num_var_with_rotation = log2_num_instances + composed_cs.rotation_vars().unwrap_or(0);

        if let Some(gkr_circuit) = gkr_circuit {
            let pub_io_evals = // get public io evaluations
                cs.instance_name_map
                    .keys()
                    .sorted()
                    .map(|Instance(inst_id)| {
                        let mle = &input.public_input[*inst_id];
                        assert_eq!(
                            mle.evaluations.len(),
                            1,
                            "doesnt support instance with evaluation length > 1"
                        );
                        match mle.evaluations() {
                            FieldType::Base(smart_slice) => E::from(smart_slice[0]),
                            FieldType::Ext(smart_slice) => smart_slice[0],
                            _ => unreachable!(),
                        }
                    })
                    .collect_vec();
            let GKRProverOutput {
                gkr_proof,
                opening_evaluations,
            } = gkr_circuit.prove::<CpuBackend<E, PCS>, CpuProver<_>>(
                num_threads,
                num_var_with_rotation,
                gkr::GKRCircuitWitness {
                    layers: vec![LayerWitness(
                        chain!(&input.witness, &input.structural_witness, &input.fixed)
                            .cloned()
                            .collect_vec(),
                    )],
                },
                // eval value doesnt matter as it wont be used by prover
                &vec![PointAndEval::new(rt_tower, E::ZERO); gkr_circuit.final_out_evals.len()],
                &pub_io_evals,
                challenges,
                transcript,
                num_instances,
            )?;
            Ok((
                opening_evaluations[0].point.clone(),
                MainSumcheckEvals {
                    wits_in_evals: opening_evaluations
                        .iter()
                        .take(cs.num_witin as usize)
                        .map(|Evaluation { value, .. }| value)
                        .copied()
                        .collect_vec(),
                    fixed_in_evals: opening_evaluations
                        .iter()
                        .skip((cs.num_witin + cs.num_structural_witin) as usize)
                        .take(cs.num_fixed)
                        .map(|Evaluation { value, .. }| value)
                        .copied()
                        .collect_vec(),
                },
                None,
                Some(gkr_proof),
            ))
        } else {
            let span = entered_span!("fixed::evals + witin::evals");
            // In table proof, we always skip same point sumcheck for now
            // as tower sumcheck batch product argument/logup in same length
            let mut evals = input
                .witness
                .par_iter()
                .chain(input.fixed.par_iter())
                .map(|poly| poly.evaluate(&rt_tower[..poly.num_vars()]))
                .collect::<Vec<_>>();
            let fixed_in_evals = evals.split_off(input.witness.len());
            let wits_in_evals = evals;
            exit_span!(span);

            Ok((
                rt_tower,
                MainSumcheckEvals {
                    wits_in_evals,
                    fixed_in_evals,
                },
                None,
                None,
            ))
        }
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
        mut evals: Vec<Vec<E>>, // where each inner Vec<E> = wit_evals + fixed_evals
        circuit_num_polys: &[(usize, usize)],
        num_instances: &[(usize, usize)],
        transcript: &mut impl Transcript<E>,
    ) -> PCS::Proof {
        let mut rounds = vec![];
        rounds.push((
            &witness_data,
            points
                .iter()
                .zip_eq(evals.iter_mut())
                .zip_eq(num_instances.iter())
                .map(|((point, evals), (chip_idx, _))| {
                    let (num_witin, _) = circuit_num_polys[*chip_idx];
                    (point.clone(), evals.drain(..num_witin).collect_vec())
                })
                .collect_vec(),
        ));
        if let Some(fixed_data) = fixed_data.as_ref().map(|f| f.as_ref()) {
            rounds.push((
                fixed_data,
                points
                    .iter()
                    .zip_eq(evals.iter_mut())
                    .zip_eq(num_instances.iter())
                    .filter(|(_, (chip_idx, _))| {
                        let (_, num_fixed) = circuit_num_polys[*chip_idx];
                        num_fixed > 0
                    })
                    .map(|((point, evals), _)| (point.clone(), evals.to_vec()))
                    .collect_vec(),
            ));
        }
        PCS::batch_open(&self.backend.pp, rounds, transcript).unwrap()
    }
}

impl<E: ExtensionField, PCS: PolynomialCommitmentScheme<E>> DeviceTransporter<CpuBackend<E, PCS>>
    for CpuProver<CpuBackend<E, PCS>>
{
    fn transport_proving_key(
        &self,
        pk: Arc<
            crate::structs::ZKVMProvingKey<
                <CpuBackend<E, PCS> as ProverBackend>::E,
                <CpuBackend<E, PCS> as ProverBackend>::Pcs,
            >,
        >,
    ) -> DeviceProvingKey<CpuBackend<E, PCS>> {
        let pcs_data = pk.fixed_commit_wd.clone().unwrap();
        let fixed_mles =
            PCS::get_arc_mle_witness_from_commitment(pk.fixed_commit_wd.as_ref().unwrap());

        DeviceProvingKey {
            pcs_data,
            fixed_mles,
        }
    }

    fn transport_mles<'a>(
        &self,
        mles: Vec<MultilinearExtension<'a, E>>,
    ) -> Vec<ArcMultilinearExtension<'a, E>> {
        mles.into_iter().map(|mle| mle.into()).collect_vec()
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

    #[test]
    fn test_ecc_tower_prover() {

    }
}
