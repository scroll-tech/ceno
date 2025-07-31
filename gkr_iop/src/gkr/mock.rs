use std::{iter, marker::PhantomData};

use ff_ext::ExtensionField;
use itertools::{Itertools, izip};
use mpcs::PolynomialCommitmentScheme;
use multilinear_extensions::{
    Expression, WitnessId,
    mle::{ArcMultilinearExtension, FieldType, MultilinearExtension},
    smart_slice::SmartSlice,
    util::ceil_log2,
    wit_infer_by_expr,
};
use rand::thread_rng;
use thiserror::Error;

use crate::{cpu::CpuBackend, evaluation::EvalExpression, selector::SelectorType};

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
    #[error("zerocheck expression not match, out: {0:?}, expr: {1:?}, expr_name: {2:?}")]
    ZerocheckExpressionNotMatch(Box<EvalExpression<E>>, Box<Expression<E>>, String),
    #[error("zerocheck expression not match, type: {0:?}, expect: {1:?}. got: {2:?}")]
    ZerocheckSelectorError(SelectorType<E>, E, E),
    #[error("linear expression not match, out: {0:?}, expr: {1:?}")]
    LinearExpressionNotMatch(Box<EvalExpression<E>>, Box<Expression<E>>),
}

impl<E: ExtensionField> MockProver<E> {
    pub fn check<'a, 'b, PCS: PolynomialCommitmentScheme<E>>(
        circuit: &'a GKRCircuit<E>,
        circuit_wit: &'a GKRCircuitWitness<'b, CpuBackend<E, PCS>>,
        mut evaluations: Vec<ArcMultilinearExtension<'b, E>>,
        mut challenges: Vec<E>,
    ) -> Result<(), MockProverError<'a, E>>
    where
        'b: 'a,
    {
        // TODO: check the rotation argument.
        let mut rng = thread_rng();
        evaluations.resize_with(circuit.n_evaluations, Default::default);
        challenges.resize_with(2 + circuit.n_challenges, || E::random(&mut rng));
        // check the input layer
        for (layer, layer_wit) in izip!(&circuit.layers, &circuit_wit.layers) {
            let num_vars = layer_wit.num_vars();
            let mut wits = layer_wit
                .iter()
                .map(|mle| mle.as_view().into())
                .collect::<Vec<_>>();
            let structural_wits = wits.split_off(layer.n_witin);
            let gots = layer
                .exprs
                .iter()
                .zip_eq(
                    layer
                        .out_sel_and_eval_exprs
                        .iter()
                        .flat_map(|(sel_type, out)| izip!(iter::repeat(sel_type), out)),
                )
                .map(|(expr, (sel, _))| {
                    wit_infer_by_expr(
                        &[],
                        &wits,
                        &structural_wits,
                        &[],
                        &challenges,
                        &(sel.selector_expr() * expr),
                    )
                })
                .collect_vec();

            let expects = layer
                .out_sel_and_eval_exprs
                .iter()
                .flat_map(|(_, out)| {
                    out.iter()
                        .map(|out| out.mock_evaluate(&evaluations, &challenges, num_vars))
                })
                .collect::<Result<Vec<_>, _>>()?;
            match layer.ty {
                LayerType::Zerocheck => {
                    for (got, expect, expr, expr_name, (_, out_eval)) in izip!(
                        gots,
                        expects,
                        &layer.exprs,
                        &layer.expr_names,
                        layer
                            .out_sel_and_eval_exprs
                            .iter()
                            .flat_map(|(sel_type, out)| izip!(iter::repeat(sel_type), out))
                    ) {
                        // let got = select_from_expression_result(sel_type, got, num_instances);
                        if expect != got {
                            return Err(MockProverError::ZerocheckExpressionNotMatch(
                                Box::new(out_eval.clone()),
                                Box::new(expr.clone()),
                                expr_name.to_string(),
                            ));
                        }
                    }
                }
                LayerType::Linear => {
                    for (got, expect, expr, out) in
                        izip!(gots, expects, &layer.exprs, &layer.out_sel_and_eval_exprs)
                    {
                        if expect != got {
                            return Err(MockProverError::LinearExpressionNotMatch(
                                Box::new(out.1[0].clone()),
                                Box::new(expr.clone()),
                            ));
                        }
                    }
                }
            }
            for (in_pos, wit) in izip!(layer.in_eval_expr.iter(), layer_wit.iter()) {
                evaluations[*in_pos] = wit.clone();
            }
        }
        Ok(())
    }
}

impl<E: ExtensionField> EvalExpression<E> {
    pub fn mock_evaluate<'a>(
        &self,
        evals: &[ArcMultilinearExtension<'a, E>],
        challenges: &[E],
        num_vars: usize,
    ) -> Result<ArcMultilinearExtension<'a, E>, MockProverError<'a, E>> {
        let output = match self {
            EvalExpression::Zero => {
                MultilinearExtension::from_field_type(num_vars, FieldType::zero(num_vars)).into()
            }
            EvalExpression::Single(i) => evals[*i].clone(),
            EvalExpression::Linear(i, c0, c1) => wit_infer_by_expr(
                &[],
                evals,
                &[],
                &[],
                challenges,
                &(Expression::WitIn(*i as WitnessId) * *c0.clone() + *c1.clone()),
            ),
            EvalExpression::Partition(parts, indices) => {
                assert_eq!(parts.len(), 1 << indices.len());
                let parts = parts
                    .iter()
                    .map(|part| part.mock_evaluate(evals, challenges, num_vars))
                    .collect::<Result<Vec<_>, _>>()?;
                indices
                    .iter()
                    .fold(parts, |acc, (i, _c)| {
                        let step_size = 1 << i;
                        acc.chunks_exact(2)
                            .map(|chunk| {
                                MultilinearExtension::from_field_type(
                                    ceil_log2(chunk[0].evaluations().len()),
                                    match (&chunk[0].evaluations(), &chunk[1].evaluations()) {
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
                                    },
                                )
                                .into()
                            })
                            .collect_vec()
                    })
                    .pop()
                    .unwrap()
            }
        };
        Ok(output)
    }
}
