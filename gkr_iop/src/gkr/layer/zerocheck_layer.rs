use ff_ext::ExtensionField;
use itertools::{Itertools, chain, izip};
use multilinear_extensions::{
    ChallengeId, Expression, StructuralWitIn, StructuralWitInType, ToExpr, WitnessId,
    macros::{entered_span, exit_span},
    mle::Point,
    monomial::Term,
    monomialize_expr_to_wit_terms,
    utils::{eval_by_expr, eval_by_expr_with_instance, expr_convert_to_witins},
    virtual_poly::VPAuxInfo,
};
use p3::field::{FieldAlgebra, dot_product};
use smallvec::SmallVec;
use std::{cmp::Ordering, collections::BTreeMap, marker::PhantomData, ops::Neg};
use sumcheck::{
    structs::{IOPProof, IOPVerifierState, SumCheckSubClaim, VerifierError},
    util::get_challenge_pows,
};
use transcript::Transcript;

use super::{
    CommonFactoredTermPlan, CommonTermGroup, Layer, LayerWitness,
    linear_layer::LayerClaims,
    sumcheck_layer::{LayerProof, bind_prover_evals},
};
use crate::{
    error::BackendError,
    evaluation::EvalExpression,
    gkr::{
        booleanhypercube::BooleanHypercube,
        layer::{hal::ZerocheckLayerProver, sumcheck_layer::SumcheckLayerProof},
    },
    hal::{ProverBackend, ProverDevice},
    selector::{SelectorContext, SelectorType},
    utils::{
        eval_inner_repeated_incremental_vec, eval_outer_repeated_incremental_vec,
        eval_stacked_constant_vec, eval_stacked_wellform_address_vec, eval_wellform_address_vec,
        rotation_selector_eval,
    },
};

pub struct RotationPoints<E: ExtensionField> {
    pub left: Point<E>,
    pub right: Point<E>,
    pub origin: Point<E>,
}

pub struct RotationClaims<E: ExtensionField> {
    pub left_evals: Vec<E>,
    pub right_evals: Vec<E>,
    pub target_evals: Vec<E>,
    pub rotation_points: RotationPoints<E>,
}

pub trait ZerocheckLayer<E: ExtensionField> {
    // static expression on circuit setup
    fn build_static_expression(&mut self);

    #[allow(clippy::too_many_arguments)]
    fn prove<PB: ProverBackend<E = E>, PD: ProverDevice<PB>>(
        &self,
        num_threads: usize,
        max_num_variables: usize,
        wit: LayerWitness<PB>,
        out_points: &[Point<PB::E>],
        pub_io_evals: &[PB::E],
        challenges: &[PB::E],
        transcript: &mut impl Transcript<PB::E>,
        selector_ctxs: &[SelectorContext],
    ) -> (LayerProof<PB::E>, Point<PB::E>);

    #[allow(clippy::too_many_arguments)]
    fn verify(
        &self,
        max_num_variables: usize,
        proof: LayerProof<E>,
        eval_and_dedup_points: Vec<(Vec<E>, Option<Point<E>>)>,
        pub_io_evals: &[E],
        challenges: &[E],
        transcript: &mut impl Transcript<E>,
        selector_ctxs: &[SelectorContext],
    ) -> Result<LayerClaims<E>, BackendError>;
}

impl<E: ExtensionField> ZerocheckLayer<E> for Layer<E> {
    fn build_static_expression(&mut self) {
        let span = entered_span!("gen_expr", profiling_4 = true);
        // build rotation expression
        let num_rotations = self.rotation_exprs.1.len();
        let rotation_expr = if num_rotations > 0 {
            let alpha_pows_expr = (2..)
                .take(num_rotations)
                .map(|id| Expression::Challenge(id as ChallengeId, 1, E::ONE, E::ZERO))
                .collect_vec();
            let rotation_expr = (0..)
                .tuples()
                .take(num_rotations)
                .zip_eq(&alpha_pows_expr)
                .map(|((rotate_wit_id, target_wit_id), alpha)| {
                    alpha * (Expression::WitIn(rotate_wit_id) - Expression::WitIn(target_wit_id))
                })
                .sum::<Expression<E>>();
            let rotation_selector_expr = Expression::<E>::WitIn((num_rotations * 2) as WitnessId);
            Some(rotation_selector_expr * rotation_expr)
        } else {
            None
        };

        // generate static expression
        let out_evals: Vec<_> = self
            .out_sel_and_eval_exprs
            .iter()
            .flat_map(|(sel_type, out_eval)| izip!(std::iter::repeat(sel_type), out_eval.iter()))
            .collect();
        self.exprs_with_selector_out_eval_monomial_form = self
            .exprs
            .iter()
            .zip_eq(out_evals.iter())
            .map(|(expr, (sel_type, out_eval))| {
                let sel_expr = sel_type.selector_expr();
                let expr = match out_eval {
                    EvalExpression::Linear(_, a, b) => {
                        // See `gkr_iop/src/gkr/layer.rs` for the +/-1 linear-coefficient derivation.
                        let coeff = a.as_ref();
                        if *coeff == E::BaseField::ONE.expr() {
                            sel_expr.clone() * expr + b.as_ref().neg().clone()
                        } else if *coeff == E::BaseField::ONE.neg().expr() {
                            b.as_ref().clone() - sel_expr.clone() * expr
                        } else {
                            panic!("unsupported linear eval coefficient: expected +/-1")
                        }
                    }
                    EvalExpression::Single(_) => sel_expr.clone() * expr,
                    EvalExpression::Zero => Expression::ZERO,
                    EvalExpression::Partition(_, _) => unimplemented!(),
                };

                monomialize_expr_to_wit_terms(
                    &expr,
                    self.n_witin as WitnessId,
                    self.n_fixed as WitnessId,
                    0,
                )
            })
            .collect::<Vec<_>>();

        // Build the concrete main-sumcheck polynomial by batching smaller sumchecks.
        // For each selector group g with expressions expr_{g,0..k-1}, define:
        //   p_g(x) = sel_g(x) * Σ_j (α_{2+offset(g,j)} * expr_{g,j}(x)).
        // The corresponding smaller sumcheck target is:
        //   S_g = Σ_{x in {0,1}^n} p_g(x).
        // For zerocheck constraints contributed by each chip, the expected target is S_g = 0.
        // Main sumcheck batches them into:
        //   p(x) = Σ_g p_g(x), so Σ_{x in {0,1}^n} p(x) = Σ_g S_g = 0.
        // `rlc_zero_expr` returns the per-group p_g terms, then we sum them into p.
        let alpha_pows_expr = (2..)
            .take(self.exprs.len())
            .map(|id| Expression::Challenge(id as ChallengeId, 1, E::ONE, E::ZERO))
            .collect_vec();
        let mut zero_expr = rlc_zero_expr(self, &alpha_pows_expr)
            .into_iter()
            .sum::<Expression<E>>();

        self.rotation_sumcheck_expression = rotation_expr.clone();
        self.rotation_sumcheck_expression_monomial_terms =
            self.rotation_sumcheck_expression.as_ref().map(|expr| {
                monomialize_expr_to_wit_terms(
                    expr,
                    self.n_witin as WitnessId,
                    self.n_fixed as WitnessId,
                    0,
                )
            });

        expr_convert_to_witins(
            &mut zero_expr,
            self.n_witin as WitnessId,
            self.n_fixed as WitnessId,
            0,
        );
        tracing::trace!("{} main sumcheck degree: {}", self.name, zero_expr.degree());
        self.main_sumcheck_expression = Some(zero_expr);
        if let Some(expr) = self.main_sumcheck_expression.as_ref() {
            let mut monomial_terms = expr.get_monomial_terms();
            normalize_monomial_term_products(&mut monomial_terms);
            monomial_terms.sort_by(|a, b| compare_monomials(a, b));
            log_monomial_term_stats(&self.name, &monomial_terms);
            self.main_sumcheck_expression_monomial_terms = Some(monomial_terms.clone());
            let (common_plan, residual_terms) =
                build_common_factored_plan_and_residual_terms(&monomial_terms);
            debug_assert!(
                common_plan.is_none() || !residual_terms.is_empty(),
                "residual monomials must exist when common plan is present"
            );
            log_common_term_plan_stats(&self.name, common_plan.as_ref(), &monomial_terms);
            self.main_sumcheck_expression_common_factored = common_plan;
            self.main_sumcheck_expression_monomial_terms_excluded_shared = Some(residual_terms);
        }
        tracing::trace!(
            "{} main sumcheck monomial terms count: {}",
            self.name,
            self.main_sumcheck_expression_monomial_terms
                .as_ref()
                .map_or(0, |terms| terms.len()),
        );
        exit_span!(span);
    }

    fn prove<PB: ProverBackend<E = E>, PD: ProverDevice<PB>>(
        &self,
        num_threads: usize,
        max_num_variables: usize,
        wit: LayerWitness<PB>,
        out_points: &[Point<PB::E>],
        pub_io_evals: &[PB::E],
        challenges: &[PB::E],
        transcript: &mut impl Transcript<PB::E>,
        selector_ctxs: &[SelectorContext],
    ) -> (LayerProof<PB::E>, Point<PB::E>) {
        <PD as ZerocheckLayerProver<PB>>::prove(
            self,
            num_threads,
            max_num_variables,
            wit,
            out_points,
            pub_io_evals,
            challenges,
            transcript,
            selector_ctxs,
        )
    }

    fn verify(
        &self,
        max_num_variables: usize,
        proof: LayerProof<E>,
        eval_and_dedup_points: Vec<(Vec<E>, Option<Point<E>>)>,
        pub_io_evals: &[E],
        challenges: &[E],
        transcript: &mut impl Transcript<E>,
        selector_ctxs: &[SelectorContext],
    ) -> Result<LayerClaims<E>, BackendError> {
        assert_eq!(
            self.out_sel_and_eval_exprs.len(),
            eval_and_dedup_points.len(),
            "out eval length {} != with eval_and_dedup_points {}",
            self.out_sel_and_eval_exprs.len(),
            eval_and_dedup_points.len(),
        );
        let LayerProof {
            main:
                SumcheckLayerProof {
                    proof: IOPProof { proofs },
                    evals: main_evals,
                },
        } = proof;

        assert_eq!(
            main_evals.len(),
            self.n_witin + self.n_fixed + self.n_structural_witin,
            "invalid main_evals length",
        );

        let main_sumcheck_challenges = chain!(
            challenges.iter().copied(),
            get_challenge_pows(self.exprs.len(), transcript)
        )
        .collect_vec();

        let sigma = dot_product(
            main_sumcheck_challenges.iter().skip(2).copied(), // skip first 2 global challenges
            eval_and_dedup_points
                .iter()
                .flat_map(|(sigmas, _)| sigmas)
                .copied(),
        );

        let SumCheckSubClaim {
            point: in_point,
            expected_evaluation,
        } = IOPVerifierState::verify(
            sigma,
            &IOPProof { proofs },
            &VPAuxInfo {
                max_degree: self.max_expr_degree + 1, // +1 due to eq
                max_num_variables,
                phantom: PhantomData,
            },
            transcript,
        );
        let in_point = in_point.into_iter().map(|c| c.elements).collect_vec();

        bind_prover_evals(transcript, &main_evals);
        let structural_witin_offset = self.n_witin + self.n_fixed;
        // eval selector and set to respective witin
        izip!(
            &self.out_sel_and_eval_exprs,
            &eval_and_dedup_points,
            selector_ctxs.iter()
        )
        .for_each(|((sel_type, _), (_, out_point), selector_ctx)| {
            if let Some((expected_eval, wit_id)) =
                sel_type.evaluate(out_point.as_ref().unwrap(), &in_point, selector_ctx)
            {
                let wit_id = wit_id as usize + structural_witin_offset;
                assert_eq!(main_evals[wit_id], expected_eval);
            }
        });

        // check structural witin
        for StructuralWitIn { id, witin_type } in &self.structural_witins {
            let wit_id = *id as usize + structural_witin_offset;
            let expected_eval = match witin_type {
                StructuralWitInType::EqualDistanceSequence {
                    offset,
                    multi_factor,
                    descending,
                    ..
                } => eval_wellform_address_vec(
                    *offset as u64,
                    *multi_factor as u64,
                    &in_point,
                    *descending,
                ),
                StructuralWitInType::EqualDistanceDynamicSequence {
                    offset_instance_id,
                    multi_factor,
                    descending,
                    ..
                } => {
                    let offset = pub_io_evals[*offset_instance_id as usize].to_canonical_u64();
                    eval_wellform_address_vec(offset, *multi_factor as u64, &in_point, *descending)
                }
                StructuralWitInType::StackedIncrementalSequence { .. } => {
                    eval_stacked_wellform_address_vec(&in_point)
                }

                StructuralWitInType::StackedConstantSequence { .. } => {
                    eval_stacked_constant_vec(&in_point)
                }
                StructuralWitInType::InnerRepeatingIncrementalSequence { k, .. } => {
                    eval_inner_repeated_incremental_vec(*k as u64, &in_point)
                }
                StructuralWitInType::OuterRepeatingIncrementalSequence { k, .. } => {
                    eval_outer_repeated_incremental_vec(*k as u64, &in_point)
                }
                StructuralWitInType::Empty => continue,
            };
            if expected_eval != main_evals[wit_id] {
                return Err(BackendError::LayerVerificationFailed(
                    format!("layer {} structural witin mismatch", self.name.clone()).into(),
                    VerifierError::ClaimNotMatch(
                        format!("{}", expected_eval).into(),
                        format!("{}", main_evals[wit_id]).into(),
                    ),
                ));
            }
        }

        let got_claim = eval_by_expr_with_instance(
            &[],
            &main_evals,
            &[],
            pub_io_evals,
            &main_sumcheck_challenges,
            self.main_sumcheck_expression.as_ref().unwrap(),
        )
        .map_either(E::from, |v| v)
        .into_inner();

        if got_claim != expected_evaluation {
            return Err(BackendError::LayerVerificationFailed(
                self.name.clone().into(),
                VerifierError::ClaimNotMatch(
                    format!("{}", expected_evaluation).into(),
                    format!("{}", got_claim).into(),
                ),
            ));
        }

        Ok(LayerClaims {
            in_point,
            evals: main_evals,
        })
    }
}

#[allow(clippy::type_complexity)]
fn build_common_factored_plan_and_residual_terms<E: ExtensionField>(
    monomial_terms: &[Term<Expression<E>, Expression<E>>],
) -> (
    Option<CommonFactoredTermPlan>,
    Vec<Term<Expression<E>, Expression<E>>>,
) {
    if monomial_terms.is_empty() {
        return (None, Vec::new());
    }

    let mut sorted_witnesses = Vec::with_capacity(monomial_terms.len());
    for term in monomial_terms {
        let witnesses = term
            .product
            .iter()
            .map(witness_index_from_expr)
            .collect_vec();
        sorted_witnesses.push(witnesses);
    }

    let mut prefix_counts: BTreeMap<Vec<usize>, usize> = BTreeMap::new();
    for witnesses in &sorted_witnesses {
        let mut prefix = Vec::new();
        for &wit in witnesses {
            prefix.push(wit);
            *prefix_counts.entry(prefix.clone()).or_default() += 1;
        }
    }

    let mut grouped: BTreeMap<Vec<usize>, Vec<usize>> = BTreeMap::new();
    for (term_idx, witnesses) in sorted_witnesses.iter().enumerate() {
        let mut prefix = Vec::new();
        let mut best_prefix = None;
        for &wit in witnesses {
            prefix.push(wit);
            if prefix_counts.get(&prefix).copied().unwrap_or(0) >= 2 {
                best_prefix = Some(prefix.clone());
            }
        }
        if let Some(best_prefix) = best_prefix {
            grouped.entry(best_prefix).or_default().push(term_idx);
        }
    }

    let mut term_common_lengths = vec![0usize; monomial_terms.len()];
    let mut groups = Vec::with_capacity(grouped.len());
    let mut has_shared_prefix = false;
    for (mut witness_indices, term_indices) in grouped {
        let min_term_len = term_indices
            .iter()
            .map(|&term_idx| sorted_witnesses[term_idx].len())
            .min()
            .unwrap_or(0);
        if min_term_len == 0 {
            continue;
        }
        if witness_indices.len() > min_term_len {
            witness_indices.truncate(min_term_len);
        }
        let effective_len = witness_indices.len();
        if effective_len == 0 {
            continue;
        }
        has_shared_prefix = true;
        for &term_idx in &term_indices {
            term_common_lengths[term_idx] = effective_len;
        }
        groups.push(CommonTermGroup {
            shared_len: effective_len,
            witness_indices,
            term_indices,
        });
    }
    {
        let mut coverage = vec![0usize; monomial_terms.len()];
        for group in &groups {
            for &term_idx in &group.term_indices {
                coverage[term_idx] += 1;
            }
        }
        debug_assert!(
            coverage
                .iter()
                .zip(term_common_lengths.iter())
                .all(|(&count, &len)| { (len == 0 && count == 0) || (len > 0 && count == 1) }),
            "factored monomials must appear exactly once in common term plan"
        );
    }

    let mut residual_terms = monomial_terms.to_vec();
    for (term_idx, remove_len) in term_common_lengths.iter().enumerate() {
        if *remove_len == 0 {
            continue;
        }
        {
            let original = &monomial_terms[term_idx].product;
            debug_assert!(
                original.len() >= *remove_len,
                "term {} shorter than common prefix",
                term_idx
            );
            for (expr, expected) in original
                .iter()
                .take(*remove_len)
                .zip(sorted_witnesses[term_idx].iter().take(*remove_len))
            {
                let witness_id = witness_index_from_expr(expr);
                debug_assert_eq!(
                    witness_id, *expected,
                    "term {} common prefix mismatch: expected {} got {}",
                    term_idx, expected, witness_id
                );
            }
        }
        residual_terms[term_idx].product.drain(..*remove_len);
    }

    let plan = if !has_shared_prefix {
        None
    } else {
        Some(CommonFactoredTermPlan { groups })
    };

    (plan, residual_terms)
}

fn compare_monomials<E: ExtensionField>(
    lhs: &Term<Expression<E>, Expression<E>>,
    rhs: &Term<Expression<E>, Expression<E>>,
) -> Ordering {
    let lhs_indices = sorted_witness_indices(lhs);
    let rhs_indices = sorted_witness_indices(rhs);

    match rhs_indices.len().cmp(&lhs_indices.len()) {
        Ordering::Equal => {
            for (&lhs_idx, &rhs_idx) in lhs_indices.iter().zip(rhs_indices.iter()) {
                match rhs_idx.cmp(&lhs_idx) {
                    Ordering::Equal => continue,
                    ord => return ord,
                }
            }
            Ordering::Equal
        }
        ord => ord,
    }
}

fn sorted_witness_indices<E: ExtensionField>(
    term: &Term<Expression<E>, Expression<E>>,
) -> SmallVec<[usize; 8]> {
    let mut indices = term
        .product
        .iter()
        .map(witness_index_from_expr)
        .collect::<SmallVec<[usize; 8]>>();
    indices.sort_unstable_by(|a: &usize, b: &usize| b.cmp(a));
    indices
}

fn normalize_monomial_term_products<E: ExtensionField>(
    terms: &mut [Term<Expression<E>, Expression<E>>],
) {
    for term in terms {
        term.product.sort_unstable_by(|lhs, rhs| {
            witness_index_from_expr(rhs).cmp(&witness_index_from_expr(lhs))
        });
    }
}

fn witness_index_from_expr<E: ExtensionField>(expr: &Expression<E>) -> usize {
    match expr {
        Expression::WitIn(witness_id) => *witness_id as usize,
        _ => panic!("expected witness expression in monomial term"),
    }
}

fn log_monomial_term_stats<E: ExtensionField>(
    layer_name: &str,
    terms: &[Term<Expression<E>, Expression<E>>],
) {
    let total_terms = terms.len();
    let mut total_factors = 0usize;
    let mut min_factors = usize::MAX;
    let mut max_factors = 0usize;

    for term in terms {
        let factors = term.product.len();
        total_factors += factors;
        min_factors = min_factors.min(factors);
        max_factors = max_factors.max(factors);
    }

    let avg_factors = if total_terms > 0 {
        total_factors as f64 / total_terms as f64
    } else {
        0.0
    };

    tracing::info!(
        target: "gkr::layer",
        layer = layer_name,
        total_terms,
        total_factors,
        min_factors = if min_factors == usize::MAX { 0 } else { min_factors },
        max_factors,
        avg_factors,
        "main sumcheck monomial terms stats"
    );
}

fn log_common_term_plan_stats<E: ExtensionField>(
    layer_name: &str,
    plan: Option<&CommonFactoredTermPlan>,
    terms: &[Term<Expression<E>, Expression<E>>],
) {
    let total_terms = terms.len();
    let term_factor_counts: Vec<usize> = terms.iter().map(|term| term.product.len()).collect();
    let Some(plan) = plan else {
        tracing::info!(
            target: "gkr::layer",
            layer = layer_name,
            total_terms,
            "main sumcheck common-term stats unavailable (no shared plan)"
        );
        return;
    };
    if total_terms == 0 {
        tracing::info!(
            target: "gkr::layer",
            layer = layer_name,
            total_groups = plan.groups.len(),
            "main sumcheck common-term stats unavailable (no terms)"
        );
        return;
    }

    let mut coverage = vec![0usize; total_terms];
    let mut factored_terms = 0usize;
    let mut shared_terms = 0usize;
    let mut min_common = usize::MAX;
    let mut max_common = 0usize;
    let mut factored_mul_count = 0usize;

    for group in &plan.groups {
        let common_len = group.witness_indices.len();
        for &term_idx in &group.term_indices {
            coverage[term_idx] += 1;
            let term_len = *term_factor_counts
                .get(term_idx)
                .expect("term index should exist in factor counts");
            let effective_common = common_len.min(term_len);
            factored_mul_count += term_len - effective_common;
            if common_len > 0 {
                shared_terms += 1;
                if common_len < term_len {
                    factored_terms += 1;
                }
            }
        }
        if common_len > 0 {
            min_common = min_common.min(common_len);
            max_common = max_common.max(common_len);
            factored_mul_count += common_len;
        }
    }

    debug_assert!(
        coverage.iter().all(|&count| count == 1),
        "common term plan must cover every monomial exactly once"
    );

    let naive_mul_count: usize = term_factor_counts.iter().sum();
    let coverage_percentage = (shared_terms as f64 / total_terms.max(1) as f64) * 100.0;
    let factored_percentage = (factored_terms as f64 / total_terms.max(1) as f64) * 100.0;
    tracing::info!(
        target: "gkr::layer",
        "[CommonFactoredTermPlan] gkr::layer {} groups={} shared_terms={}/{} ({coverage_percentage:.2}%) factored_terms={}/{} ({factored_percentage:.2}%) common_wit_range=[{}, {}] naive_mul={} factored_mul={}",
        layer_name,
        plan.groups.len(),
        shared_terms,
        total_terms,
        shared_terms,
        total_terms,
        if min_common == usize::MAX { 0 } else { min_common },
        max_common,
        naive_mul_count,
        factored_mul_count,
    );
}

#[allow(clippy::too_many_arguments)]
pub fn verify_rotation<E: ExtensionField>(
    max_num_variables: usize,
    num_rotations: usize,
    rotation_sumcheck_expression: &Expression<E>,
    rotation_proof: SumcheckLayerProof<E>,
    rotation_cyclic_subgroup_size: usize,
    rotation_cyclic_group_log2: usize,
    rt: &Point<E>,
    challenges: &[E],
    transcript: &mut impl Transcript<E>,
) -> Result<RotationClaims<E>, BackendError> {
    let SumcheckLayerProof { proof, evals } = rotation_proof;
    assert_eq!(num_rotations * 3, evals.len());
    let rotation_challenges = chain!(
        challenges.iter().copied(),
        get_challenge_pows(num_rotations, transcript)
    )
    .collect_vec();

    let sigma = E::ZERO;

    let SumCheckSubClaim {
        point: in_point,
        expected_evaluation,
    } = IOPVerifierState::verify(
        sigma,
        &proof,
        &VPAuxInfo {
            max_degree: 2, // selector * (rotated - target)
            max_num_variables,
            phantom: PhantomData,
        },
        transcript,
    );
    let origin_point = in_point.into_iter().map(|c| c.elements).collect_vec();

    bind_prover_evals(transcript, &evals);

    // compute the selector evaluation
    let bh = BooleanHypercube::new(rotation_cyclic_group_log2);
    let selector_eval = rotation_selector_eval(
        &bh,
        rt,
        &origin_point,
        rotation_cyclic_subgroup_size,
        rotation_cyclic_group_log2,
    );

    // check the final evaluations.
    let mut left_evals = Vec::with_capacity(evals.len() / 3);
    let mut right_evals = Vec::with_capacity(evals.len() / 3);
    let mut target_evals = Vec::with_capacity(evals.len() / 3);

    let got_claim = eval_by_expr(
        &evals
            .chunks_exact(3)
            .flat_map(|evals| {
                let [left_eval, right_eval, target_eval] = evals else {
                    unreachable!()
                };
                left_evals.push(*left_eval);
                right_evals.push(*right_eval);
                target_evals.push(*target_eval);
                [
                    (E::ONE - origin_point[rotation_cyclic_group_log2 - 1]) * *left_eval
                        + origin_point[rotation_cyclic_group_log2 - 1] * *right_eval,
                    *target_eval,
                ]
            })
            .chain(std::iter::once(selector_eval))
            .collect_vec(),
        &[],
        &rotation_challenges,
        rotation_sumcheck_expression,
    );

    if got_claim != expected_evaluation {
        return Err(BackendError::LayerVerificationFailed(
            "rotation verify failed".to_string().into(),
            VerifierError::ClaimNotMatch(
                format!("{}", expected_evaluation).into(),
                format!("{}", got_claim).into(),
            ),
        ));
    }

    let (left_point, right_point) =
        BooleanHypercube::new(rotation_cyclic_group_log2).get_rotation_points(&origin_point);

    Ok(RotationClaims {
        left_evals,
        right_evals,
        target_evals,
        rotation_points: RotationPoints {
            left: left_point,
            right: right_point,
            origin: origin_point,
        },
    })
}

pub fn rlc_zero_expr<E: ExtensionField>(
    layer: &Layer<E>,
    alpha_pows: &[Expression<E>],
) -> Vec<Expression<E>> {
    let offset_structural_witid = (layer.n_witin + layer.n_fixed) as WitnessId;
    let mut alpha_pows_iter = alpha_pows.iter();
    let mut expr_iter = layer.exprs.iter();
    let mut zero_check_exprs = Vec::with_capacity(layer.out_sel_and_eval_exprs.len());

    let match_expr = |sel_expr: &Expression<E>| match sel_expr {
        Expression::StructuralWitIn(id, ..) => Expression::WitIn(offset_structural_witid + *id),
        invalid => panic!("invalid eq format {:?}", invalid),
    };

    for (sel_type, out_evals) in layer.out_sel_and_eval_exprs.iter() {
        let group_length = out_evals.len();
        let zero_check_expr = expr_iter
            .by_ref()
            .take(group_length)
            .cloned()
            .zip_eq(alpha_pows_iter.by_ref().take(group_length))
            .map(|(expr, alpha)| alpha * expr)
            .sum::<Expression<E>>();
        let expr = match sel_type {
            SelectorType::None => zero_check_expr,
            SelectorType::Whole(sel)
            | SelectorType::Prefix(sel)
            | SelectorType::OrderedSparse {
                expression: sel, ..
            }
            | SelectorType::QuarkBinaryTreeLessThan(sel) => match_expr(sel) * zero_check_expr,
        };
        zero_check_exprs.push(expr);
    }

    assert!(expr_iter.next().is_none() && alpha_pows_iter.next().is_none());

    zero_check_exprs
}
