use ff_ext::ExtensionField;
use itertools::{Itertools, chain, izip};
use linear_layer::{LayerClaims, LinearLayer};
use multilinear_extensions::{
    Expression, Instance, StructuralWitIn, ToExpr,
    mle::{Point, PointAndEval},
    monomial::Term,
};
use p3::field::FieldAlgebra;
use rayon::iter::{IntoParallelIterator, IntoParallelRefIterator};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::{fmt::Debug, ops::Neg, sync::Arc, vec::IntoIter};
use sumcheck_layer::LayerProof;
use transcript::Transcript;
use zerocheck_layer::ZerocheckLayer;

use crate::{
    OutEvalGroups,
    circuit_builder::{CircuitBuilder, ConstraintSystem, RotationParams},
    error::BackendError,
    evaluation::EvalExpression,
    hal::{MultilinearPolynomial, ProverBackend, ProverDevice},
    selector::{SelectorContext, SelectorType},
};

pub mod cpu;
#[cfg(feature = "gpu")]
pub mod gpu;
pub mod hal;
pub mod linear_layer;
pub mod sumcheck_layer;
pub mod zerocheck_layer;

pub type ExprEvalType<E> = (SelectorType<E>, Vec<EvalExpression<E>>);
pub type RotateExprs<E> = (
    Option<[Expression<E>; ROTATION_OPENING_COUNT]>,
    Vec<(Expression<E>, Expression<E>)>,
);

// rotation contribute
// left + right + target, overall 3
pub const ROTATION_OPENING_COUNT: usize = 3;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum LayerType {
    Zerocheck,
    Linear,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct CommonFactoredTermPlan {
    pub groups: Vec<CommonTermGroup>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct CommonTermGroup {
    pub witness_indices: Vec<usize>,
    pub term_indices: Vec<usize>,
    pub shared_len: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound(
    serialize = "E::BaseField: Serialize",
    deserialize = "E::BaseField: DeserializeOwned"
))]
pub struct Layer<E: ExtensionField> {
    pub name: String,
    pub ty: LayerType,
    pub n_witin: usize,
    pub n_structural_witin: usize,
    pub n_fixed: usize,
    pub n_instance: usize,
    pub max_expr_degree: usize,
    /// keep all structural witin which could be evaluated succinctly without PCS
    pub structural_witins: Vec<StructuralWitIn>,
    /// instance openings
    pub instance_openings: Vec<Instance>,
    /// num challenges dedicated to this layer.
    pub n_challenges: usize,
    /// Expressions to prove in this layer. For zerocheck and linear layers,
    /// each expression corresponds to an output. While in sumcheck, there
    /// is only 1 expression, which corresponds to the sum of all outputs.
    /// This design is for the convenience when building the following
    /// expression: `r^0 e_0 + r^1 * e_1 + ...
    ///    = \sum_x (r^0 eq_0(X) \cdot expr_0(x) + r^1 eq_1(X) \cdot expr_1(x) + ...)`.
    /// where `vec![e_0, e_1, ...]` will be the output evaluation expressions.
    /// TODO we should convert into monimial format Vec<Vec<Term<Expression<E>, Expression<E>>>
    /// TODO once we make eq, zero_check rlc challenge alpha all encoded into static expression
    pub exprs: Vec<Expression<E>>,
    /// `exprs` in monomial form
    pub exprs_with_selector_out_eval_monomial_form: Vec<Vec<Term<Expression<E>, Expression<E>>>>,

    /// Positions to place the evaluations of the base inputs of this layer.
    pub in_eval_expr: Vec<usize>,
    /// The expressions of the evaluations from the succeeding layers, which are
    /// connected to the outputs of this layer.
    /// It formats indicated as different output group
    /// first tuple value is optional eq
    pub out_sel_and_eval_exprs: Vec<ExprEvalType<E>>,

    // format: ([eq0, eq1, eq2], Vec<(rotatition_expr, expr)>) such that rotation_expr - expr == 0
    // there got 3 different eq for (left, right, target) during rotation argument
    // refer https://hackmd.io/HAAj1JTQQiKfu0SIwOJDRw?view#Rotation
    pub rotation_exprs: RotateExprs<E>,
    pub rotation_cyclic_group_log2: usize,
    pub rotation_cyclic_subgroup_size: usize,

    // For debugging purposes
    pub expr_names: Vec<String>,

    // static expression, only valid for zerocheck & sumcheck layer
    // store in 2 forms: expression & monomial
    pub main_sumcheck_expression_monomial_terms: Option<Vec<Term<Expression<E>, Expression<E>>>>,
    pub main_sumcheck_expression_monomial_terms_excluded_shared:
        Option<Vec<Term<Expression<E>, Expression<E>>>>,
    pub main_sumcheck_expression: Option<Expression<E>>,
    pub main_sumcheck_expression_common_factored: Option<CommonFactoredTermPlan>,

    // rotation sumcheck expression, only optionally valid for zerocheck
    // store in 2 forms: expression & monomial
    pub rotation_sumcheck_expression_monomial_terms:
        Option<Vec<Term<Expression<E>, Expression<E>>>>,
    pub rotation_sumcheck_expression: Option<Expression<E>>,
}

#[derive(Clone)]
pub struct LayerWitness<'a, PB: ProverBackend>(pub Vec<Arc<PB::MultilinearPoly<'a>>>);

impl<PB: ProverBackend> Debug for LayerWitness<'_, PB> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list().entries(self.0.iter()).finish()
    }
}

impl<'a, PB: ProverBackend> std::ops::Index<usize> for LayerWitness<'a, PB> {
    type Output = Arc<PB::MultilinearPoly<'a>>;

    fn index(&self, index: usize) -> &Self::Output {
        &self.0[index]
    }
}

impl<E: ExtensionField> Layer<E> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        name: String,
        ty: LayerType,
        n_witin: usize,
        n_structural_witin: usize,
        n_fixed: usize,
        n_instance: usize,
        // exprs concat zero/non-zero expression.
        exprs: Vec<Expression<E>>,
        n_challenges: usize,
        in_eval_expr: Vec<usize>,
        // first tuple value is eq
        out_sel_and_eval_exprs: Vec<ExprEvalType<E>>,
        ((rotation_eq, rotation_exprs), rotation_cyclic_group_log2, rotation_cyclic_subgroup_size): (
            RotateExprs<E>,
            usize,
            usize,
        ),
        expr_names: Vec<String>,
        structural_witins: Vec<StructuralWitIn>,
        instance_openings: Vec<Instance>,
    ) -> Self {
        assert_eq!(expr_names.len(), exprs.len(), "there are expr without name");
        let max_expr_degree = exprs
            .iter()
            .map(|expr| expr.degree())
            .max()
            .expect("empty exprs");

        match ty {
            LayerType::Zerocheck => {
                let mut layer = Self {
                    name,
                    ty,
                    n_witin,
                    n_structural_witin,
                    n_fixed,
                    n_instance,
                    max_expr_degree,
                    structural_witins,
                    instance_openings,
                    n_challenges,
                    exprs,
                    exprs_with_selector_out_eval_monomial_form: vec![],
                    in_eval_expr,
                    out_sel_and_eval_exprs,
                    rotation_exprs: (rotation_eq, rotation_exprs),
                    rotation_cyclic_group_log2,
                    rotation_cyclic_subgroup_size,
                    expr_names,
                    main_sumcheck_expression_monomial_terms: None,
                    main_sumcheck_expression_monomial_terms_excluded_shared: None,
                    main_sumcheck_expression: None,
                    main_sumcheck_expression_common_factored: None,
                    rotation_sumcheck_expression_monomial_terms: None,
                    rotation_sumcheck_expression: None,
                };
                <Self as ZerocheckLayer<E>>::build_static_expression(&mut layer);
                layer
            }
            LayerType::Linear => unimplemented!(""),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn prove<T: Transcript<E>, PB: ProverBackend<E = E>, PD: ProverDevice<PB>>(
        &self,
        num_threads: usize,
        max_num_variables: usize,
        wit: LayerWitness<PB>,
        claims: &mut [PointAndEval<E>],
        pub_io_evals: &[E],
        challenges: &mut Vec<E>,
        transcript: &mut T,
        selector_ctxs: &[SelectorContext],
    ) -> (LayerProof<E>, Point<E>) {
        self.update_challenges(challenges, transcript);
        let mut eval_and_dedup_points = self.extract_claim_and_point(claims, challenges);

        let (sumcheck_layer_proof, point) = match self.ty {
            LayerType::Zerocheck => {
                let out_points = eval_and_dedup_points
                    .into_iter()
                    .map(|(_, point)| point.expect("point must exist"))
                    .collect_vec();
                <Layer<PB::E> as ZerocheckLayer<E>>::prove::<PB, PD>(
                    self,
                    num_threads,
                    max_num_variables,
                    wit,
                    &out_points,
                    pub_io_evals,
                    challenges,
                    transcript,
                    selector_ctxs,
                )
            }
            LayerType::Linear => {
                assert_eq!(eval_and_dedup_points.len(), 1);
                let (_, point) = eval_and_dedup_points.remove(0);
                let point = point.clone().unwrap();
                (
                    <Layer<E> as LinearLayer<E>>::prove::<PB, PD>(self, wit, &point, transcript),
                    point,
                )
            }
        };

        self.update_claims(claims, &sumcheck_layer_proof.main.evals, &point);

        (sumcheck_layer_proof, point)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn verify<Trans: Transcript<E>>(
        &self,
        max_num_variables: usize,
        proof: LayerProof<E>,
        claims: &mut [PointAndEval<E>],
        pub_io_evals: &[E],
        raw_pi: &[Vec<E::BaseField>],
        challenges: &mut Vec<E>,
        transcript: &mut Trans,
        selector_ctxs: &[SelectorContext],
    ) -> Result<Point<E>, BackendError> {
        self.update_challenges(challenges, transcript);
        let mut eval_and_dedup_points = self.extract_claim_and_point(claims, challenges);

        let LayerClaims { in_point, evals } = match self.ty {
            LayerType::Zerocheck => <Layer<_> as ZerocheckLayer<E>>::verify(
                self,
                max_num_variables,
                proof,
                eval_and_dedup_points,
                pub_io_evals,
                raw_pi,
                challenges,
                transcript,
                selector_ctxs,
            )?,
            LayerType::Linear => {
                assert_eq!(eval_and_dedup_points.len(), 1);
                let (sigmas, point) = eval_and_dedup_points.remove(0);
                <Layer<_> as LinearLayer<E>>::verify(
                    self,
                    proof,
                    &sigmas,
                    point.as_ref().unwrap(),
                    challenges,
                    transcript,
                )?
            }
        };

        self.update_claims(claims, &evals, &in_point);

        Ok(in_point)
    }

    pub fn selector_ctxs_len(&self) -> usize {
        self.out_sel_and_eval_exprs.len()
    }

    // extract claim and dudup point
    fn extract_claim_and_point(
        &self,
        claims: &[PointAndEval<E>],
        challenges: &[E],
    ) -> Vec<(Vec<E>, Option<Point<E>>)> {
        self.out_sel_and_eval_exprs
            .iter()
            .map(|(_, out_evals)| {
                let evals = out_evals
                    .iter()
                    .map(|out_eval| {
                        let PointAndEval { eval, .. } = out_eval.evaluate(claims, challenges);
                        eval
                    })
                    .collect_vec();
                // within same group, all the point should be the same
                // so we assume only take first point as representative
                let point = out_evals.first().map(|out_eval| {
                    let PointAndEval { point, .. } = out_eval.evaluate(claims, challenges);
                    point
                });
                (evals, point)
            })
            .collect_vec()
    }

    // generate layer challenge by order, starting from index 2
    // as challenge id 0, 1 are occupied
    fn update_challenges(&self, challenges: &mut Vec<E>, transcript: &mut impl Transcript<E>) {
        if challenges.len() <= self.n_challenges + 2 {
            challenges.resize(self.n_challenges + 2, E::default());
        };
        challenges[2..].copy_from_slice(
            &transcript.sample_and_append_challenge_pows(self.n_challenges, b"layer challenge"),
        );
    }

    fn update_claims(&self, claims: &mut [PointAndEval<E>], evals: &[E], point: &Point<E>) {
        for (value, pos) in izip!(chain![evals], chain![&self.in_eval_expr]) {
            claims[*pos] = PointAndEval {
                point: point.clone(),
                eval: *value,
            };
        }
    }

    pub fn from_circuit_builder(
        cb: &CircuitBuilder<E>,
        layer_name: String,
        n_challenges: usize,
        out_evals: OutEvalGroups<E>,
    ) -> Layer<E> {
        let mut expr_evals = vec![];
        let mut expr_names = Vec::with_capacity(cb.cs.expressions_len());
        let mut expressions = Vec::with_capacity(cb.cs.expressions_len());

        for (selector, group) in cb.cs.expression_groups.iter() {
            let Some(selector) = selector else {
                assert!(group.is_empty(), "all expressions must have a selector");
                continue;
            };
            let [r_record_evals, w_record_evals, lookup_evals] = out_evals.get(selector).unwrap();
            let (r_expr_evals, r_table_evals) = r_record_evals.split_at(group.r_expressions.len());
            let (w_expr_evals, w_table_evals) = w_record_evals.split_at(group.w_expressions.len());
            let (lk_expr_evals, lk_table_evals) = lookup_evals.split_at(group.lk_expressions.len());
            let (lk_table_mult_evals, lk_table_val_evals) =
                lk_table_evals.split_at(group.lk_table_expressions.len());

            extend_evals_and_exprs(
                selector,
                group
                    .r_expressions
                    .iter()
                    .map(|re| (&re.expression, &re.expression_namespace_map)),
                r_expr_evals,
                &mut expr_evals,
                &mut expressions,
                &mut expr_names,
                |ram_expr| ram_expr - E::BaseField::ONE.expr(),
                |ram_eval| {
                    EvalExpression::Linear(
                        // evaluation = claim * one - one (padding)
                        ram_eval,
                        E::BaseField::ONE.expr().into(),
                        E::BaseField::ONE.neg().expr().into(),
                    )
                },
            );
            if !group.r_table_expressions.is_empty() {
                extend_evals_and_exprs(
                    selector,
                    group
                        .r_table_expressions
                        .iter()
                        .map(|re| (&re.expr, &re.expression_namespace_map)),
                    r_table_evals,
                    &mut expr_evals,
                    &mut expressions,
                    &mut expr_names,
                    |ram_expr| ram_expr - E::BaseField::ONE.expr(),
                    |ram_eval| {
                        EvalExpression::Linear(
                            // evaluation = claim * one - one (padding)
                            ram_eval,
                            E::BaseField::ONE.expr().into(),
                            E::BaseField::ONE.neg().expr().into(),
                        )
                    },
                );
            }

            extend_evals_and_exprs(
                selector,
                group
                    .w_expressions
                    .iter()
                    .map(|re| (&re.expression, &re.expression_namespace_map)),
                w_expr_evals,
                &mut expr_evals,
                &mut expressions,
                &mut expr_names,
                |ram_expr| ram_expr - E::BaseField::ONE.expr(),
                |ram_eval| {
                    EvalExpression::Linear(
                        // evaluation = claim * one - one (padding)
                        ram_eval,
                        E::BaseField::ONE.expr().into(),
                        E::BaseField::ONE.neg().expr().into(),
                    )
                },
            );
            if !group.w_table_expressions.is_empty() {
                extend_evals_and_exprs(
                    selector,
                    group
                        .w_table_expressions
                        .iter()
                        .map(|re| (&re.expr, &re.expression_namespace_map)),
                    w_table_evals,
                    &mut expr_evals,
                    &mut expressions,
                    &mut expr_names,
                    |ram_expr| ram_expr - E::BaseField::ONE.expr(),
                    |ram_eval| {
                        EvalExpression::Linear(
                            // evaluation = claim * one - one (padding)
                            ram_eval,
                            E::BaseField::ONE.expr().into(),
                            E::BaseField::ONE.neg().expr().into(),
                        )
                    },
                );
            }

            extend_evals_and_exprs(
                selector,
                group
                    .lk_expressions
                    .iter()
                    .map(|re| (&re.expression, &re.expression_namespace_map)),
                lk_expr_evals,
                &mut expr_evals,
                &mut expressions,
                &mut expr_names,
                |lookup| lookup - cb.cs.chip_record_alpha.clone(),
                |lookup_eval| {
                    EvalExpression::<E>::Linear(
                        // evaluation = claim * one - alpha (padding)
                        lookup_eval,
                        E::BaseField::ONE.expr().into(),
                        cb.cs.chip_record_alpha.clone().neg().into(),
                    )
                },
            );
            if !group.lk_table_expressions.is_empty() {
                extend_evals_and_exprs(
                    selector,
                    group
                        .lk_table_expressions
                        .iter()
                        .map(|re| (&re.multiplicity, &re.expression_namespace_map)),
                    lk_table_mult_evals,
                    &mut expr_evals,
                    &mut expressions,
                    &mut expr_names,
                    |lookup| lookup - cb.cs.chip_record_alpha.clone(),
                    |lookup_eval| {
                        EvalExpression::<E>::Linear(
                            // evaluation = claim * one - alpha (padding)
                            lookup_eval,
                            E::BaseField::ONE.expr().into(),
                            cb.cs.chip_record_alpha.clone().neg().into(),
                        )
                    },
                );
                extend_evals_and_exprs(
                    selector,
                    group
                        .lk_table_expressions
                        .iter()
                        .map(|re| (&re.values, &re.expression_namespace_map)),
                    lk_table_val_evals,
                    &mut expr_evals,
                    &mut expressions,
                    &mut expr_names,
                    |lookup| lookup - cb.cs.chip_record_alpha.clone(),
                    |lookup_eval| {
                        EvalExpression::<E>::Linear(
                            // evaluation = claim * one - alpha (padding)
                            lookup_eval,
                            E::BaseField::ONE.expr().into(),
                            cb.cs.chip_record_alpha.clone().neg().into(),
                        )
                    },
                );
            }

            extend_evals_and_exprs(
                selector,
                group
                    .assert_zero_expressions
                    .iter()
                    .map(|re| (&re.expression, &re.expression_namespace_map)),
                &vec![0; group.assert_zero_expressions.len()],
                &mut expr_evals,
                &mut expressions,
                &mut expr_names,
                |zero_expr| zero_expr.clone(),
                |_| EvalExpression::Zero,
            );

            extend_evals_and_exprs(
                selector,
                group
                    .assert_zero_sumcheck_expressions
                    .iter()
                    .map(|re| (&re.expression, &re.expression_namespace_map)),
                &vec![0; group.assert_zero_sumcheck_expressions.len()],
                &mut expr_evals,
                &mut expressions,
                &mut expr_names,
                |zero_expr| zero_expr.clone(),
                |_| EvalExpression::Zero,
            );
        }

        // Sort expressions, expr_names, and evals according to eval.0 and classify evals.
        let ConstraintSystem {
            rotation_params,
            rotations,
            ..
        } = &cb.cs;

        let in_eval_expr = (cb.cs.non_zero_expressions_len()..)
            .take(cb.cs.num_witin as usize + cb.cs.num_fixed + cb.cs.instance_openings.len())
            .collect_vec();
        if rotations.is_empty() {
            Layer::new(
                layer_name,
                LayerType::Zerocheck,
                cb.cs.num_witin as usize,
                cb.cs.num_structural_witin as usize,
                cb.cs.num_fixed,
                cb.cs.instance_openings.len(),
                expressions,
                n_challenges,
                in_eval_expr,
                expr_evals,
                ((None, vec![]), 0, 0),
                expr_names,
                cb.cs.structural_witins.clone(),
                cb.cs.instance_openings.clone(),
            )
        } else {
            let Some(RotationParams {
                rotation_eqs,
                rotation_cyclic_group_log2,
                rotation_cyclic_subgroup_size,
            }) = rotation_params
            else {
                panic!("rotation params not set");
            };
            Layer::new(
                layer_name,
                LayerType::Zerocheck,
                cb.cs.num_witin as usize,
                cb.cs.num_structural_witin as usize,
                cb.cs.num_fixed,
                cb.cs.instance_openings.len(),
                expressions,
                n_challenges,
                in_eval_expr,
                expr_evals,
                (
                    (rotation_eqs.clone(), rotations.clone()),
                    *rotation_cyclic_group_log2,
                    *rotation_cyclic_subgroup_size,
                ),
                expr_names,
                cb.cs.structural_witins.clone(),
                cb.cs.instance_openings.clone(),
            )
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn extend_evals_and_exprs<'a, E: ExtensionField>(
    selector: &SelectorType<E>,
    record_exprs: impl Iterator<Item = (&'a Expression<E>, &'a String)>,
    record_evals: &[usize],
    expr_evals: &mut Vec<ExprEvalType<E>>,
    expressions: &mut Vec<Expression<E>>,
    expr_names: &mut Vec<String>,
    compute_expr: impl Fn(&Expression<E>) -> Expression<E>,
    compute_eval: impl Fn(usize) -> EvalExpression<E>,
) {
    if expr_evals.is_empty() || expr_evals.last().unwrap().0 != *selector {
        expr_evals.push((selector.clone(), vec![]));
    }

    let evals: &mut Vec<EvalExpression<E>> = expr_evals.last_mut().unwrap().1.as_mut();
    for (idx, ((expr, name), eval)) in record_exprs.zip_eq(record_evals).enumerate() {
        expressions.push(compute_expr(expr));
        evals.push(compute_eval(*eval));
        expr_names.push(format!("{}/{idx}", name));
    }
}

impl<'a, PB: ProverBackend> LayerWitness<'a, PB> {
    pub fn new(
        wits: Vec<Arc<PB::MultilinearPoly<'a>>>,
        fixed: Vec<Arc<PB::MultilinearPoly<'a>>>,
    ) -> Self {
        let mut wits_and_fixed = wits;
        wits_and_fixed.extend(fixed);
        assert!(!wits_and_fixed.is_empty());
        assert!(wits_and_fixed.iter().map(|b| b.num_vars()).all_equal());
        Self(wits_and_fixed)
    }

    pub fn num_vars(&self) -> usize {
        if self.0.is_empty() {
            0
        } else {
            self[0].num_vars()
        }
    }
}

impl<'a, PB: ProverBackend> IntoIterator for LayerWitness<'a, PB> {
    type Item = Arc<PB::MultilinearPoly<'a>>;
    type IntoIter = IntoIter<Arc<PB::MultilinearPoly<'a>>>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<'a, PB: ProverBackend> LayerWitness<'a, PB> {
    pub fn iter(&self) -> impl Iterator<Item = &Arc<PB::MultilinearPoly<'a>>> {
        self.0.iter()
    }
}

impl<'a, PB: ProverBackend> IntoParallelIterator for LayerWitness<'a, PB> {
    type Iter = rayon::vec::IntoIter<Arc<PB::MultilinearPoly<'a>>>;
    type Item = Arc<PB::MultilinearPoly<'a>>;

    fn into_par_iter(self) -> Self::Iter {
        self.0.into_par_iter()
    }
}

impl<'a, PB: ProverBackend> IntoParallelIterator for &'a LayerWitness<'a, PB> {
    type Iter = rayon::slice::Iter<'a, Arc<PB::MultilinearPoly<'a>>>;
    type Item = &'a Arc<PB::MultilinearPoly<'a>>;

    fn into_par_iter(self) -> Self::Iter {
        self.0.par_iter()
    }
}
