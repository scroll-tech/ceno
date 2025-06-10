use super::hal::{
    DeviceTransporter, MainSumcheckProver, MultilinearPolynomial, OpeningProver, ProverBackend,
    ProverDevice, TowerProver, TraceCommitter,
};
use crate::{
    circuit_builder::ConstraintSystem,
    error::ZKVMError,
    scheme::{
        constants::{NUM_FANIN, NUM_FANIN_LOGUP},
        hal::{DeviceProvingKey, ProofInput, TowerProverSpec},
        utils::{
            infer_tower_logup_witness, infer_tower_product_witness, masked_mle_split_to_chunks,
            wit_infer_by_expr,
        },
    },
    structs::TowerProofs,
    utils::add_mle_list_by_expr,
};
use either::Either;
use ff_ext::ExtensionField;
use itertools::Itertools;
use mpcs::{Point, PolynomialCommitmentScheme, SecurityLevel};
use multilinear_extensions::{
    Expression,
    mle::{ArcMultilinearExtension, FieldType, IntoMLE, MultilinearExtension},
    virtual_poly::build_eq_x_r_vec,
    virtual_polys::VirtualPolynomialsBuilder,
};
use p3::{
    field::{PrimeCharacteristicRing, TwoAdicField, dot_product},
    matrix::dense::RowMajorMatrix,
};
use rayon::iter::{IntoParallelIterator, IntoParallelRefIterator, ParallelIterator};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};
use sumcheck::{
    macros::{entered_span, exit_span},
    structs::{IOPProverMessage, IOPProverState},
    util::{ceil_log2, get_challenge_pows, optimal_sumcheck_threads},
};
use transcript::Transcript;
use witness::next_pow2_instance_padding;

pub struct CpuBackend<E: ExtensionField, PCS: PolynomialCommitmentScheme<E>> {
    pub param: PCS::Param,
    _marker: std::marker::PhantomData<E>,
}

impl<E: ExtensionField, PCS: PolynomialCommitmentScheme<E>> Default for CpuBackend<E, PCS> {
    fn default() -> Self {
        Self::new()
    }
}

impl<E: ExtensionField, PCS: PolynomialCommitmentScheme<E>> CpuBackend<E, PCS> {
    pub fn new() -> Self {
        let param =
            PCS::setup(E::BaseField::TWO_ADICITY, SecurityLevel::Conjecture100bits).unwrap();
        Self {
            param,
            _marker: std::marker::PhantomData,
        }
    }
}

impl<'a, E: ExtensionField> MultilinearPolynomial<E> for MultilinearExtension<'a, E> {
    fn num_vars(&self) -> usize {
        self.num_vars()
    }

    fn eval(&self, point: Point<E>) -> E {
        self.evaluate(&point)
    }
}

impl<E: ExtensionField, PCS: PolynomialCommitmentScheme<E>> ProverBackend for CpuBackend<E, PCS> {
    type E = E;
    type Pcs = PCS;
    type MultilinearPoly<'a> = MultilinearExtension<'a, E>;
    type Matrix = RowMajorMatrix<E::BaseField>;
    type PcsData = PCS::CommitmentWithWitness;
}

/// CPU prover for CPU backend
pub struct CpuProver<PB: ProverBackend> {
    backend: PB,
    pp: Option<<<PB as ProverBackend>::Pcs as PolynomialCommitmentScheme<PB::E>>::ProverParam>,
    largest_poly_size: Option<usize>,
}

impl<PB: ProverBackend> CpuProver<PB> {
    pub fn new(backend: PB) -> Self {
        Self {
            backend,
            pp: None,
            largest_poly_size: None,
        }
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
            Logup((usize, Vec<MultilinearExtension<'a, E>>)), /* usize is the index in logup_specs */
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
        &mut self,
        traces: BTreeMap<usize, witness::RowMajorMatrix<E::BaseField>>,
    ) -> (
        Vec<MultilinearExtension<'a, E>>,
        PCS::CommitmentWithWitness,
        PCS::Commitment,
    ) {
        let largest_poly_size = traces
            .values()
            .map(|trace| next_pow2_instance_padding(trace.num_instances()) << 1)
            .max()
            .unwrap();
        let prover_param = if let Some(s) = self.largest_poly_size
            && s >= largest_poly_size
        {
            self.pp.as_ref().unwrap()
        } else {
            let (prover_param, _) =
                PCS::trim(self.backend.param.clone(), largest_poly_size).unwrap();
            self.largest_poly_size = Some(largest_poly_size);
            self.pp = Some(prover_param);
            self.pp.as_ref().unwrap()
        };
        let pcs_data = PCS::batch_commit(prover_param, traces).unwrap();
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
    fn build_tower_witness<'a, 'b>(
        &self,
        cs: &ConstraintSystem<E>,
        input: &'b ProofInput<'a, CpuBackend<E, PCS>>,
        challenges: &[E; 2],
    ) -> (
        Vec<Vec<Vec<E>>>,
        Vec<ArcMultilinearExtension<'b, E>>,
        Vec<TowerProverSpec<'b, CpuBackend<E, PCS>>>,
        Vec<TowerProverSpec<'b, CpuBackend<E, PCS>>>,
    ) {
        let num_instances = input.num_instances;
        let log2_num_instances = input.log2_num_instances();
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
        assert_eq!(
            input.structural_witness.len(),
            cs.num_structural_witin as usize
        );
        assert_eq!(input.fixed.len(), cs.num_fixed);
        // check all witness size are power of 2
        assert!(
            input
                .witness
                .iter()
                .all(|v| { v.evaluations().len() == 1 << log2_num_instances })
        );
        assert!(
            input
                .structural_witness
                .iter()
                .all(|v| { v.evaluations().len() == 1 << log2_num_instances })
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
                    &input.fixed,
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
            .map(|last_layer| {
                infer_tower_product_witness(log2_num_instances, last_layer, NUM_FANIN)
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

        (out_evals, records, prod_specs, lookup_specs)
    }

    fn prove_tower_relation<'a>(
        &self,
        prod_specs: Vec<TowerProverSpec<'a, CpuBackend<E, PCS>>>,
        logup_specs: Vec<TowerProverSpec<'a, CpuBackend<E, PCS>>>,
        num_fanin: usize,
        transcript: &mut impl Transcript<E>,
    ) -> (Point<E>, TowerProofs<E>) {
        CpuTowerProver::create_proof(prod_specs, logup_specs, num_fanin, transcript)
    }
}

impl<E: ExtensionField, PCS: PolynomialCommitmentScheme<E>> MainSumcheckProver<CpuBackend<E, PCS>>
    for CpuProver<CpuBackend<E, PCS>>
{
    fn prove_main_constraints<'a, 'b>(
        &self,
        rt_tower: Vec<E>,
        records: Vec<ArcMultilinearExtension<'b, E>>,
        input: &'b ProofInput<'a, CpuBackend<E, PCS>>,
        cs: &ConstraintSystem<E>,
        challenges: &[E; 2],
        transcript: &mut impl Transcript<<CpuBackend<E, PCS> as ProverBackend>::E>,
    ) -> Result<(Point<E>, Option<Vec<IOPProverMessage<E>>>), ZKVMError> {
        let num_instances = input.num_instances;
        let next_pow2_instances = next_pow2_instance_padding(num_instances);
        let log2_num_instances = ceil_log2(next_pow2_instances);
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
                &records[..num_reads],
                E::ONE.neg(),
            );
            alpha_offset += num_reads;

            // w_records_combined is \sum_i alpha^i * (w_records[i][j]-padding) where padding = 1
            let mut w_records_combined: MultilinearExtension<E> = linear_combine_mles(
                &alpha_pow[alpha_offset..(alpha_offset + num_writes)],
                &records[num_reads..(num_reads + num_writes)],
                E::ONE.neg(),
            );
            alpha_offset += num_writes;

            // lk_records_combined is \sum_i alpha^i * (lk_records[i][j]-padding)
            //  where padding = chip_record_alpha
            let mut lk_records_combined: MultilinearExtension<E> = linear_combine_mles(
                &alpha_pow[alpha_offset..(alpha_offset + cs.lk_expressions.len())],
                &records[(num_reads + num_writes)..],
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

            let mut distinct_zerocheck_terms_set = BTreeSet::new();
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
                        if !top_100_errors.is_empty() {
                            return Err(ZKVMError::InvalidWitness(format!(
                                "degree > 1 zero check virtual poly: expr {name} != 0 on instance indexes: {}...",
                                top_100_errors.into_iter().map(|(i, _)| i).join(",")
                            )));
                        }
                    }

                    distinct_zerocheck_terms_set.extend(add_mle_list_by_expr(
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
            let (main_sel_sumcheck_proofs, state) = IOPProverState::prove(
                expr_builder.to_virtual_polys(&[exprs.into_iter().sum()], &[]),
                transcript,
            );
            tracing::trace!("main sel sumcheck end");
            exit_span!(main_sel_span);

            (
                state.collect_raw_challenges(),
                Some(main_sel_sumcheck_proofs.proofs),
            )
        } else {
            // In table proof, we always skip same point sumcheck for now
            // as tower sumcheck batch product argument/logup in same length

            (rt_tower, None)
        };

        exit_span!(sumcheck_span);

        Ok((input_opening_point, main_sumcheck_proofs))
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
        evals: Vec<Vec<E>>,
        circuit_num_polys: &[(usize, usize)],
        num_instances: &[(usize, usize)],
        transcript: &mut impl Transcript<E>,
    ) -> PCS::Proof {
        PCS::batch_open(
            self.pp.as_ref().unwrap(),
            num_instances,
            fixed_data.as_ref().map(|f| f.as_ref()),
            &witness_data,
            &points,
            &evals,
            circuit_num_polys,
            transcript,
        )
        .unwrap()
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

impl<E, PCS> ProverDevice<CpuBackend<E, PCS>> for CpuProver<CpuBackend<E, PCS>>
where
    E: ExtensionField,
    PCS: PolynomialCommitmentScheme<E>,
{
}
