use std::{marker::PhantomData, sync::Arc};

use ff_ext::ExtensionField;
use itertools::{Itertools, izip};
use multilinear_extensions::{
    WitnessId,
    mle::{MultilinearExtension, Point},
    util::ceil_log2,
    virtual_poly::build_eq_x_r_vec_with_scalar,
};
use rand::{rngs::OsRng, thread_rng};
use thiserror::Error;

use crate::evaluation::EvalExpression;
use multilinear_extensions::{
    Expression, mle::FieldType, smart_slice::SmartSlice, wit_infer_by_expr,
};
use rand::Rng;

use super::{GKRCircuit, GKRCircuitWitness, layer::LayerType};

pub struct MockProver<E: ExtensionField>(PhantomData<E>);

#[derive(Clone, Debug, Error)]
pub enum MockProverError<'a, E: ExtensionField> {
    #[error("sumcheck layer should have only one expression, got {0}")]
    SumcheckExprLenError(usize),
    #[error("sumcheck expression not match, out: {0:?}, expr: {1:?}, expect: {2:?}. got: {3:?}")]
    SumcheckExpressionNotMatch(
        Box<Vec<EvalExpression<E>>>,
        Box<Expression<E>>,
        Box<FieldType<'a, E>>,
        Box<FieldType<'a, E>>,
    ),
    #[error(
        "zerocheck expression not match, out: {0:?}, expr: {1:?}, expect: {2:?}. got: {3:?}, expr_name: {4:?}"
    )]
    ZerocheckExpressionNotMatch(
        Box<EvalExpression<E>>,
        Box<Expression<E>>,
        Box<FieldType<'a, E>>,
        Box<FieldType<'a, E>>,
        String,
    ),
    #[error("linear expression not match, out: {0:?}, expr: {1:?}, expect: {2:?}. got: {3:?}")]
    LinearExpressionNotMatch(
        Box<EvalExpression<E>>,
        Box<Expression<E>>,
        Box<FieldType<'a, E>>,
        Box<FieldType<'a, E>>,
    ),
}

impl<E: ExtensionField> MockProver<E> {
    pub fn check<'a>(
        circuit: GKRCircuit<E>,
        circuit_wit: &'a GKRCircuitWitness<'a, E>,
        evaluations: Vec<&FieldType<'a, E>>,
        mut challenges: Vec<E>,
    ) -> Result<(), MockProverError<'a, E>> {
        // TODO: check the rotation argument.
        let mut rng = thread_rng();
        let field_type_default = FieldType::default();
        let mut evaluations = evaluations; // Change evaluations' lifetime.
        evaluations.resize_with(circuit.n_evaluations, || &field_type_default);
        challenges.resize_with(circuit.n_challenges, || E::random(&mut rng));
        // check the input layer
        for (layer, layer_wit) in izip!(circuit.layers, &circuit_wit.layers) {
            let num_vars = layer_wit.num_vars();
            let points = (0..layer.out_eq_and_eval_exprs.len())
                .map(|_| random_point::<E>(OsRng, num_vars))
                .collect_vec();
            let eqs = eq_mles(points.clone(), &vec![E::ONE; points.len()])
                .into_iter()
                .map(Arc::new)
                .collect_vec();
            let gots = layer
                .exprs
                .iter()
                .map(|expr| {
                    wit_infer_by_expr(
                        &[],
                        &layer_wit
                            .iter()
                            .map(|mle| mle.as_view().into())
                            .chain(eqs.clone())
                            .collect_vec(),
                        &[],
                        &[],
                        &challenges,
                        expr,
                    )
                    .as_ref()
                    .clone()
                    .evaluations_to_owned()
                })
                .collect_vec();
            let expects = layer
                .out_eq_and_eval_exprs
                .iter()
                .flat_map(|(_, out)| out)
                .map(|out| out.mock_evaluate(&evaluations, &challenges, num_vars))
                .collect_vec();
            match layer.ty {
                LayerType::Zerocheck => {
                    for (got, expect, expr, expr_name, out) in izip!(
                        gots,
                        expects,
                        &layer.exprs,
                        &layer.expr_names,
                        &layer.out_eq_and_eval_exprs
                    ) {
                        if !expect.is_equal(&got) {
                            return Err(MockProverError::ZerocheckExpressionNotMatch(
                                Box::new(out.1[0].clone()),
                                Box::new(expr.clone()),
                                Box::new(expect),
                                Box::new(got),
                                expr_name.to_string(),
                            ));
                        }
                    }
                }
                LayerType::Linear => {
                    for (got, expect, expr, out) in
                        izip!(gots, expects, &layer.exprs, &layer.out_eq_and_eval_exprs)
                    {
                        if !expect.is_equal(&got) {
                            return Err(MockProverError::LinearExpressionNotMatch(
                                Box::new(out.1[0].clone()),
                                Box::new(expr.clone()),
                                Box::new(expect),
                                Box::new(got),
                            ));
                        }
                    }
                }
            }
            for (in_pos, wit) in izip!(layer.in_eval_expr.iter(), layer_wit.iter()) {
                evaluations[*in_pos] = wit.evaluations();
            }
        }
        Ok(())
    }
}

impl<E: ExtensionField> EvalExpression<E> {
    pub fn mock_evaluate<'a>(
        &self,
        evals: &[&FieldType<'a, E>],
        challenges: &[E],
        num_vars: usize,
    ) -> FieldType<'a, E> {
        match self {
            EvalExpression::Zero => FieldType::zero(num_vars),
            EvalExpression::Single(i) => evals[*i].clone(),
            EvalExpression::Linear(i, c0, c1) => wit_infer_by_expr(
                &[],
                &evals
                    .iter()
                    .map(|field_type| {
                        MultilinearExtension::from_field_type_borrowed(
                            ceil_log2(field_type.len()),
                            field_type,
                        )
                        .into()
                    })
                    .collect_vec(),
                &[],
                &[],
                challenges,
                &(Expression::WitIn(*i as WitnessId) * *c0.clone() + *c1.clone()),
            )
            .as_ref()
            .clone()
            .evaluations_to_owned(),
            EvalExpression::Partition(parts, indices) => {
                assert_eq!(parts.len(), 1 << indices.len());
                let parts = parts
                    .iter()
                    .map(|part| part.mock_evaluate(evals, challenges, num_vars))
                    .collect_vec();
                indices
                    .iter()
                    .fold(parts, |acc, (i, _c)| {
                        let step_size = 1 << i;
                        acc.chunks_exact(2)
                            .map(|chunk| match (&chunk[0], &chunk[1]) {
                                (FieldType::Base(v0), FieldType::Base(v1)) => {
                                    let res = (0..v0.len())
                                        .step_by(step_size)
                                        .flat_map(|j| {
                                            v0[j..j + step_size]
                                                .iter()
                                                .chain(v1[j..j + step_size].iter())
                                                .cloned()
                                        })
                                        .collect_vec();
                                    FieldType::Base(SmartSlice::Owned(res))
                                }
                                (FieldType::Ext(v0), FieldType::Ext(v1)) => {
                                    let res = (0..v0.len())
                                        .step_by(step_size)
                                        .flat_map(|j| {
                                            v0[j..j + step_size]
                                                .iter()
                                                .chain(v1[j..j + step_size].iter())
                                                .cloned()
                                        })
                                        .collect_vec();
                                    FieldType::Ext(SmartSlice::Owned(res))
                                }
                                _ => unreachable!(),
                            })
                            .collect_vec()
                    })
                    .pop()
                    .unwrap()
            }
        }
    }
}

fn eq_mles<'a, E: ExtensionField>(
    points: Vec<Point<E>>,
    scalars: &[E],
) -> Vec<MultilinearExtension<'a, E>> {
    izip!(points, scalars)
        .map(|(point, scalar)| {
            MultilinearExtension::from_evaluations_ext_vec(
                point.len(),
                build_eq_x_r_vec_with_scalar(&point, *scalar),
            )
        })
        .collect_vec()
}

fn random_point<E: ExtensionField>(mut rng: impl Rng, num_vars: usize) -> Vec<E> {
    (0..num_vars).map(|_| E::random(&mut rng)).collect_vec()
}
