use ff_ext::ExtensionField;
use itertools::{Itertools, izip};
use multilinear_extensions::{
    Expression, mle::PointAndEval, utils::eval_by_expr_with_fixed,
    virtual_poly::build_eq_x_r_vec_sequential,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};

/// Evaluation expression for the gkr layer reduction and PCS opening
/// preparation.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound = "E: ExtensionField + DeserializeOwned")]
pub enum EvalExpression<E: ExtensionField> {
    Zero,
    /// Single entry in the evaluation vector.
    Single(usize),
    /// Linear expression of an entry with the scalar and offset.
    Linear(usize, Box<Expression<E>>, Box<Expression<E>>),
    /// Merging multiple evaluations which denotes a partition of the original
    /// polynomial. `(usize, Constant)` denote the modification of the point.
    /// For example, when it receive a point `(p0, p1, p2, p3)` from a
    /// succeeding layer, `vec![(2, c0), (4, c1)]` will modify the point to
    /// `(p0, p1, c0, p2, c1, p3)`. where the indices specify how the
    /// partition applied to the original polynomial.
    Partition(
        Vec<Box<EvalExpression<E>>>,
        Vec<(usize, Box<Expression<E>>)>,
    ),
}

impl<E: ExtensionField> Default for EvalExpression<E> {
    fn default() -> Self {
        EvalExpression::Single(0)
    }
}

fn evaluate<E: ExtensionField>(expr: &Expression<E>, challenges: &[E]) -> E {
    eval_by_expr_with_fixed(&[], &[], &[], challenges, expr)
}

use std::sync::Arc;
use crate::gpu::CudaStream;

impl<E: ExtensionField> EvalExpression<E> {
    pub fn evaluate(&self, evals: &[PointAndEval<E>], challenges: &[E], option_stream: Option<&Arc<CudaStream>>) -> PointAndEval<E> {
        match self {
            // assume all point in evals are derived in random, thus pick arbirary one is ok
            // here we pick first point as representative.
            // for zero eval, eval is always zero
            EvalExpression::Zero => PointAndEval {
                point: evals[0].point.clone(),
                eval: E::ZERO,
            },
            EvalExpression::Single(i) => evals[*i].clone(),
            EvalExpression::Linear(i, c0, c1) => PointAndEval {
                point: evals[*i].point.clone(),
                eval: evals[*i].eval * evaluate(c0, challenges) + evaluate(c1, challenges),
            },
            EvalExpression::Partition(parts, indices) => {
                assert!(izip!(indices.iter(), indices.iter().skip(1)).all(|(a, b)| a.0 < b.0));
                let vars = indices
                    .iter()
                    .map(|(_, c)| evaluate(c, challenges))
                    .collect_vec();

                let parts = parts
                    .iter()
                    .map(|part| part.evaluate(evals, &vars, option_stream))
                    .collect_vec();
                assert_eq!(parts.len(), 1 << indices.len());
                assert!(parts.iter().all(|part| part.point == parts[0].point));

                let mut new_point = parts[0].point.to_vec();
                for (index_in_point, c) in indices {
                    new_point.insert(*index_in_point, evaluate(c, challenges));
                }

                let eq = build_eq_x_r_vec_sequential(&vars);
                let eval = izip!(parts, &eq).fold(E::ZERO, |acc, (part, eq)| acc + part.eval * *eq);

                PointAndEval {
                    point: new_point,
                    eval,
                }
            }
        }
    }

    pub fn entry<'a, T>(&self, evals: &'a [T]) -> &'a T {
        match self {
            EvalExpression::Single(i) => &evals[*i],
            _ => panic!("invalid operation"),
        }
    }

    pub fn entry_mut<'a, T>(&self, evals: &'a mut [T]) -> &'a mut T {
        match self {
            EvalExpression::Single(i) => &mut evals[*i],
            _ => panic!("invalid operation"),
        }
    }
}
