use std::marker::PhantomData;

use ff_ext::ExtensionField;
use itertools::{Itertools, izip};
use rand::rngs::OsRng;
use subprotocols::{
    expression::{Expression, VectorType},
    test_utils::random_point,
    utils::eq_vecs,
};
use thiserror::Error;

use crate::{evaluation::EvalExpression, utils::SliceIterator};

use super::{GKRCircuit, GKRCircuitWitness, layer::LayerType};

pub struct MockProver<E: ExtensionField>(PhantomData<E>);

#[derive(Clone, Debug, Error)]
pub enum MockProverError<F: ExtensionField> {
    #[error("sumcheck layer should have only one expression, got {0}")]
    SumcheckExprLenError(usize),
    #[error("sumcheck expression not match, out: {0:?}, expr: {1:?}, expect: {2:?}. got: {3:?}")]
    SumcheckExpressionNotMatch(
        Vec<EvalExpression>,
        Expression,
        VectorType<F>,
        VectorType<F>,
    ),
    #[error("zerocheck expression not match, out: {0:?}, expr: {1:?}, expect: {2:?}. got: {3:?}")]
    ZerocheckExpressionNotMatch(EvalExpression, Expression, VectorType<F>, VectorType<F>),
    #[error("linear expression not match, out: {0:?}, expr: {1:?}, expect: {2:?}. got: {3:?}")]
    LinearExpressionNotMatch(EvalExpression, Expression, VectorType<F>, VectorType<F>),
}

impl<E: ExtensionField> MockProver<E> {
    pub fn check(
        circuit: GKRCircuit<'_>,
        circuit_wit: &GKRCircuitWitness<E>,
        mut evaluations: Vec<VectorType<E>>,
        mut challenges: Vec<E>,
    ) -> Result<(), MockProverError<E>> {
        evaluations.resize(circuit.n_evaluations, VectorType::Base(vec![]));
        challenges.resize_with(circuit.n_challenges, || E::random(OsRng));
        for (layer, layer_wit) in izip!(circuit.layers, &circuit_wit.layers) {
            let num_vars = layer_wit.num_vars;
            let points = (0..layer.outs.len())
                .map(|_| random_point::<E>(OsRng, num_vars))
                .collect_vec();
            let eqs = eq_vecs(points.slice_iter(), &vec![E::ONE; points.len()]);
            let gots = layer
                .exprs
                .iter()
                .map(|expr| expr.calc(&layer_wit.exts, &layer_wit.bases, &eqs, &challenges))
                .collect_vec();
            let expects = layer
                .outs
                .iter()
                .map(|out| out.mock_evaluate(&evaluations, &challenges, 1 << num_vars))
                .collect_vec();
            match layer.ty {
                LayerType::Sumcheck => {
                    if gots.len() != 1 {
                        return Err(MockProverError::SumcheckExprLenError(gots.len()));
                    }
                    let got = gots.into_iter().next().unwrap();
                    let expect = expects.into_iter().reduce(|a, b| a + b).unwrap();
                    if expect != got {
                        return Err(MockProverError::SumcheckExpressionNotMatch(
                            layer.outs.clone(),
                            layer.exprs[0].clone(),
                            expect,
                            got,
                        ));
                    }
                }
                LayerType::Zerocheck => {
                    for (got, expect, expr, out) in izip!(gots, expects, &layer.exprs, &layer.outs)
                    {
                        if expect != got {
                            return Err(MockProverError::ZerocheckExpressionNotMatch(
                                out.clone(),
                                expr.clone(),
                                expect,
                                got,
                            ));
                        }
                    }
                }
                LayerType::Linear => {
                    for (got, expect, expr, out) in izip!(gots, expects, &layer.exprs, &layer.outs)
                    {
                        if expect != got {
                            return Err(MockProverError::LinearExpressionNotMatch(
                                out.clone(),
                                expr.clone(),
                                expect,
                                got,
                            ));
                        }
                    }
                }
            }
            for (in_pos, base) in izip!(&layer.in_bases, &layer_wit.bases) {
                *(in_pos.entry_mut(&mut evaluations)) = VectorType::Base(base.clone());
            }
            for (in_pos, ext) in izip!(&layer.in_exts, &layer_wit.exts) {
                *(in_pos.entry_mut(&mut evaluations)) = VectorType::Ext(ext.clone());
            }
        }
        Ok(())
    }
}

impl EvalExpression {
    pub fn mock_evaluate<E: ExtensionField>(
        &self,
        evals: &[VectorType<E>],
        challenges: &[E],
        len: usize,
    ) -> VectorType<E> {
        match self {
            EvalExpression::Single(i) => evals[*i].clone(),
            EvalExpression::Linear(i, c0, c1) => {
                evals[*i].clone() * VectorType::Ext(vec![c0.evaluate(challenges); len])
                    + VectorType::Ext(vec![c1.evaluate(challenges); len])
            }
            EvalExpression::Partition(parts, indices) => {
                assert_eq!(parts.len(), 1 << indices.len());
                let parts = parts
                    .iter()
                    .map(|part| part.mock_evaluate(evals, challenges, len))
                    .collect_vec();
                indices
                    .iter()
                    .fold(parts, |acc, (i, _c)| {
                        let step_size = 1 << i;
                        acc.chunks_exact(2)
                            .map(|chunk| match (&chunk[0], &chunk[1]) {
                                (VectorType::Base(v0), VectorType::Base(v1)) => {
                                    let res = (0..v0.len())
                                        .step_by(step_size)
                                        .flat_map(|j| {
                                            v0[j..j + step_size]
                                                .iter()
                                                .chain(v1[j..j + step_size].iter())
                                                .cloned()
                                        })
                                        .collect_vec();
                                    VectorType::Base(res)
                                }
                                (VectorType::Ext(v0), VectorType::Ext(v1)) => {
                                    let res = (0..v0.len())
                                        .step_by(step_size)
                                        .flat_map(|j| {
                                            v0[j..j + step_size]
                                                .iter()
                                                .chain(v1[j..j + step_size].iter())
                                                .cloned()
                                        })
                                        .collect_vec();
                                    VectorType::Ext(res)
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
