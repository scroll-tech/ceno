use std::sync::Arc;

use ff_ext::ExtensionField;
use itertools::{Itertools, izip};
use multilinear_extensions::virtual_poly::build_eq_x_r_vec_sequential;
use subprotocols::expression::{Constant, Point};

/// Evaluation expression for the gkr layer reduction and PCS opening preparation.
#[derive(Clone, Debug)]
pub enum EvalExpression {
    /// Single entry in the evaluation vector.
    Single(usize),
    /// Linear expression of an entry with the scalar and offset.
    Linear(usize, Constant, Constant),
    /// Merging multiple evaluations which denotes a partition of the original
    /// polynomial. `(usize, Constant)` denote the modification of the point.
    /// For example, when it receive a point `(p0, p1, p2, p3)` from a succeeding
    /// layer, `vec![(2, c0), (4, c1)]` will modify the point to `(p0, p1, c0, p2, c1, p3)`.
    /// where the indices specify how the partition applied to the original polynomial.
    Partition(Vec<Box<EvalExpression>>, Vec<(usize, Constant)>),
}

#[derive(Clone, Debug, Default)]
pub struct PointAndEval<E: ExtensionField> {
    pub point: Point<E>,
    pub eval: E,
}

impl Default for EvalExpression {
    fn default() -> Self {
        EvalExpression::Single(0)
    }
}

impl EvalExpression {
    pub fn evaluate<E: ExtensionField>(
        &self,
        evals: &[PointAndEval<E>],
        challenges: &[E],
    ) -> PointAndEval<E> {
        match self {
            EvalExpression::Single(i) => evals[*i].clone(),
            EvalExpression::Linear(i, c0, c1) => PointAndEval {
                point: evals[*i].point.clone(),
                eval: evals[*i].eval * c0.evaluate(challenges) + c1.evaluate(challenges),
            },
            EvalExpression::Partition(parts, indices) => {
                assert!(izip!(indices.iter(), indices.iter().skip(1)).all(|(a, b)| a.0 < b.0));
                let vars = indices
                    .iter()
                    .map(|(_, c)| c.evaluate(challenges))
                    .collect_vec();

                let parts = parts
                    .iter()
                    .map(|part| part.evaluate(evals, &vars))
                    .collect_vec();
                assert_eq!(parts.len(), 1 << indices.len());
                assert!(parts.iter().all(|part| part.point == parts[0].point));

                let mut new_point = parts[0].point.to_vec();
                for (index_in_point, c) in indices {
                    new_point.insert(*index_in_point, c.evaluate(challenges));
                }

                let eq = build_eq_x_r_vec_sequential(&vars);
                let eval = izip!(parts, &eq).fold(E::ZERO, |acc, (part, eq)| acc + part.eval * eq);

                PointAndEval {
                    point: Arc::new(new_point),
                    eval,
                }
            }
        }
    }

    pub fn entry<'a, T>(&self, evals: &'a [T]) -> &'a T {
        match self {
            EvalExpression::Single(i) => &evals[*i],
            _ => unreachable!(),
        }
    }

    pub fn entry_mut<'a, T>(&self, evals: &'a mut [T]) -> &'a mut T {
        match self {
            EvalExpression::Single(i) => &mut evals[*i],
            _ => unreachable!(),
        }
    }
}
