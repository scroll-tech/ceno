use either::Either;
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
use std::{ops::Neg, sync::Arc, vec::IntoIter};
use sumcheck_layer::LayerProof;
use transcript::Transcript;
use zerocheck_layer::ZerocheckLayer;

use crate::{
    OutEvalGroups,
    circuit_builder::{CircuitBuilder, ConstraintSystem, RotationParams},
    error::BackendError,
    evaluation::EvalExpression,
    hal::{MultilinearPolynomial, ProverBackend, ProverDevice},
    selector::SelectorType,
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
    pub main_sumcheck_expression: Option<Expression<E>>,

    // rotation sumcheck expression, only optionally valid for zerocheck
    // store in 2 forms: expression & monomial
    pub rotation_sumcheck_expression_monomial_terms:
        Option<Vec<Term<Expression<E>, Expression<E>>>>,
    pub rotation_sumcheck_expression: Option<Expression<E>>,
}

#[derive(Clone, Debug)]
pub struct LayerWitness<'a, PB: ProverBackend>(pub Vec<Arc<PB::MultilinearPoly<'a>>>);

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
                    main_sumcheck_expression: None,
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
        num_instances: usize,
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
                    num_instances,
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
        num_instances: usize,
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
                num_instances,
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
        out_evals: OutEvalGroups,
    ) -> Layer<E> {
        let w_len = cb.cs.w_expressions.len() + cb.cs.w_table_expressions.len();
        let r_len = cb.cs.r_expressions.len() + cb.cs.r_table_expressions.len();
        let lk_len = cb.cs.lk_expressions.len() + cb.cs.lk_table_expressions.len() * 2; // logup lk table include p, q
        let zero_len =
            cb.cs.assert_zero_expressions.len() + cb.cs.assert_zero_sumcheck_expressions.len();

        let [r_record_evals, w_record_evals, lookup_evals, zero_evals] = out_evals;
        assert_eq!(r_record_evals.len(), r_len);
        assert_eq!(w_record_evals.len(), w_len);
        assert_eq!(lookup_evals.len(), lk_len);
        assert_eq!(zero_evals.len(), zero_len);

        let non_zero_expr_len = cb.cs.w_expressions.len()
            + cb.cs.w_table_expressions.len()
            + cb.cs.r_expressions.len()
            + cb.cs.r_table_expressions.len()
            + cb.cs.lk_expressions.len()
            + cb.cs.lk_table_expressions.len() * 2;
        let zero_expr_len =
            cb.cs.assert_zero_expressions.len() + cb.cs.assert_zero_sumcheck_expressions.len();

        let mut expr_evals = Vec::with_capacity(4);
        let mut expr_names = Vec::with_capacity(non_zero_expr_len + zero_expr_len);
        let mut expressions = Vec::with_capacity(non_zero_expr_len + zero_expr_len);

        if let Some(r_selector) = cb.cs.r_selector.as_ref() {
            // process r_record
            let evals = Self::dedup_last_selector_evals(r_selector, &mut expr_evals);
            for (idx, ((ram_expr, name), ram_eval)) in (cb
                .cs
                .r_expressions
                .iter()
                .chain(cb.cs.r_table_expressions.iter().map(|t| &t.expr)))
            .zip_eq(
                cb.cs
                    .r_expressions_namespace_map
                    .iter()
                    .chain(&cb.cs.r_table_expressions_namespace_map),
            )
            .zip_eq(&r_record_evals)
            .enumerate()
            {
                expressions.push(ram_expr - E::BaseField::ONE.expr());
                evals.push(EvalExpression::<E>::Linear(
                    // evaluation = claim * one - one (padding)
                    *ram_eval,
                    E::BaseField::ONE.expr().into(),
                    E::BaseField::ONE.neg().expr().into(),
                ));
                expr_names.push(format!("{}/{idx}", name));
            }
        }

        if let Some(w_selector) = cb.cs.w_selector.as_ref() {
            // process w_record
            let evals = Self::dedup_last_selector_evals(w_selector, &mut expr_evals);
            for (idx, ((ram_expr, name), ram_eval)) in (cb
                .cs
                .w_expressions
                .iter()
                .chain(cb.cs.w_table_expressions.iter().map(|t| &t.expr)))
            .zip_eq(
                cb.cs
                    .w_expressions_namespace_map
                    .iter()
                    .chain(&cb.cs.w_table_expressions_namespace_map),
            )
            .zip_eq(&w_record_evals)
            .enumerate()
            {
                expressions.push(ram_expr - E::BaseField::ONE.expr());
                evals.push(EvalExpression::<E>::Linear(
                    // evaluation = claim * one - one (padding)
                    *ram_eval,
                    E::BaseField::ONE.expr().into(),
                    E::BaseField::ONE.neg().expr().into(),
                ));
                expr_names.push(format!("{}/{idx}", name));
            }
        }

        if let Some(lk_selector) = cb.cs.lk_selector.as_ref() {
            // process lookup records
            let evals = Self::dedup_last_selector_evals(lk_selector, &mut expr_evals);
            for (idx, ((lookup, name), lookup_eval)) in (cb
                .cs
                .lk_expressions
                .iter()
                .chain(cb.cs.lk_table_expressions.iter().map(|t| &t.multiplicity))
                .chain(cb.cs.lk_table_expressions.iter().map(|t| &t.values)))
            .zip_eq(if cb.cs.lk_table_expressions.is_empty() {
                Either::Left(cb.cs.lk_expressions_namespace_map.iter())
            } else {
                // repeat expressions_namespace_map twice to deal with lk p, q
                Either::Right(
                    cb.cs
                        .lk_expressions_namespace_map
                        .iter()
                        .chain(&cb.cs.lk_expressions_namespace_map),
                )
            })
            .zip_eq(&lookup_evals)
            .enumerate()
            {
                expressions.push(lookup - cb.cs.chip_record_alpha.clone());
                evals.push(EvalExpression::<E>::Linear(
                    // evaluation = claim * one - alpha (padding)
                    *lookup_eval,
                    E::BaseField::ONE.expr().into(),
                    cb.cs.chip_record_alpha.clone().neg().into(),
                ));
                expr_names.push(format!("{}/{idx}", name));
            }
        }

        if let Some(zero_selector) = cb.cs.zero_selector.as_ref() {
            // process zero_record
            let evals = Self::dedup_last_selector_evals(zero_selector, &mut expr_evals);
            for (idx, (zero_expr, name)) in izip!(
                0..,
                chain!(
                    cb.cs
                        .assert_zero_expressions
                        .iter()
                        .zip_eq(&cb.cs.assert_zero_expressions_namespace_map),
                    cb.cs
                        .assert_zero_sumcheck_expressions
                        .iter()
                        .zip_eq(&cb.cs.assert_zero_sumcheck_expressions_namespace_map)
                )
            ) {
                expressions.push(zero_expr.clone());
                evals.push(EvalExpression::Zero);
                expr_names.push(format!("{}/{idx}", name));
            }
        }

        // Sort expressions, expr_names, and evals according to eval.0 and classify evals.
        let ConstraintSystem {
            rotation_params,
            rotations,
            ..
        } = &cb.cs;

        let in_eval_expr = (non_zero_expr_len..)
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

    // return previous evals for extend, if new selector match with last selector
    // otherwise push new evals and return it for mutability
    fn dedup_last_selector_evals<'a>(
        new_selector: &SelectorType<E>,
        expr_evals: &'a mut Vec<(SelectorType<E>, Vec<EvalExpression<E>>)>,
    ) -> &'a mut Vec<EvalExpression<E>>
    where
        SelectorType<E>: Clone + PartialEq,
    {
        let need_push = match expr_evals.last() {
            Some((last_sel, _)) => last_sel != new_selector,
            None => true,
        };

        if need_push {
            expr_evals.push((new_selector.clone(), vec![]));
        }

        &mut expr_evals.last_mut().unwrap().1
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
