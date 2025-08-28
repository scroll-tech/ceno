use rayon::iter::IndexedParallelIterator;

use ff_ext::ExtensionField;
use multilinear_extensions::{
    Expression,
    mle::{IntoMLE, MultilinearExtension, Point},
    virtual_poly::{build_eq_x_r_vec, eq_eval},
};
use rayon::{iter::ParallelIterator, slice::ParallelSliceMut};
use serde::{Deserialize, Serialize, de::DeserializeOwned};

use crate::{gkr::booleanhypercube::CYCLIC_POW2_5, utils::eq_eval_less_or_equal_than};

/// Selector selects part of the witnesses in the sumcheck protocol.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(bound(
    serialize = "E::BaseField: Serialize",
    deserialize = "E::BaseField: DeserializeOwned"
))]
pub enum SelectorType<E: ExtensionField> {
    None,
    Whole(Expression<E>),
    /// Select a prefix as the instances, padded with a field element.
    Prefix(E::BaseField, Expression<E>),
    /// selector activates on the specified `indices`, which are assumed to be in ascending order.
    /// each index corresponds to a position within a fixed-size chunk (e.g., size 32),
    OrderedSparse32 {
        indices: Vec<usize>,
        expression: Expression<E>,
    },
}

impl<E: ExtensionField> SelectorType<E> {
    /// Compute true and false mle eq(1; b[..5]) * sel(y; b[5..]), and eq(1; b[..5]) * (eq() - sel(y; b[5..]))
    pub fn compute(
        &self,
        out_point: &Point<E>,
        num_instances: usize,
    ) -> Option<MultilinearExtension<'_, E>> {
        match self {
            SelectorType::None => None,
            SelectorType::Whole(_expr) => Some(build_eq_x_r_vec(out_point).into_mle()),
            SelectorType::Prefix(_, _expr) => {
                let mut sel = build_eq_x_r_vec(out_point);
                if num_instances < sel.len() {
                    sel.splice(
                        num_instances..sel.len(),
                        std::iter::repeat_n(E::ZERO, sel.len() - num_instances),
                    );
                }
                Some(sel.into_mle())
            }
            SelectorType::OrderedSparse32 { indices, .. } => {
                let mut sel = build_eq_x_r_vec(out_point);
                sel.par_chunks_exact_mut(CYCLIC_POW2_5.len())
                    .enumerate()
                    .for_each(|(chunk_index, chunk)| {
                        if chunk_index >= num_instances {
                            // Zero out the entire chunk if out of instance range
                            chunk.iter_mut().for_each(|e| *e = E::ZERO);
                            return;
                        }

                        let mut indices_iter = indices.iter().copied();
                        let mut next_keep = indices_iter.next();

                        for (i, e) in chunk.iter_mut().enumerate() {
                            match next_keep {
                                Some(idx) if i == idx => {
                                    next_keep = indices_iter.next(); // Keep this one
                                }
                                _ => *e = E::ZERO, // Not in indices
                            }
                        }
                    });
                Some(sel.into_mle())
            }
        }
    }

    /// Evaluate true and false mle eq(CYCLIC_POW2_5[round]; b[..5]) * sel(y; b[5..]), and eq(1; b[..5]) * (1 - sel(y; b[5..]))
    pub fn evaluate(
        &self,
        evals: &mut Vec<E>,
        out_point: &Point<E>,
        in_point: &Point<E>,
        num_instances: usize,
        offset_eq_id: usize,
    ) {
        let (expr, eval) = match self {
            SelectorType::None => return,
            SelectorType::Whole(expr) => {
                debug_assert_eq!(out_point.len(), in_point.len());
                (expr, eq_eval(out_point, in_point))
            }
            SelectorType::Prefix(_, expr) => {
                debug_assert!(num_instances <= (1 << out_point.len()));
                (
                    expr,
                    eq_eval_less_or_equal_than(num_instances - 1, out_point, in_point),
                )
            }
            SelectorType::OrderedSparse32 {
                indices,
                expression,
            } => {
                let out_subgroup_eq = build_eq_x_r_vec(&out_point[..5]);
                let in_subgroup_eq = build_eq_x_r_vec(&in_point[..5]);
                let mut eval = E::ZERO;
                for index in indices {
                    eval += out_subgroup_eq[*index] * in_subgroup_eq[*index];
                }
                let sel =
                    eq_eval_less_or_equal_than(num_instances - 1, &out_point[5..], &in_point[5..]);
                (expression, eval * sel)
            }
        };
        let Expression::StructuralWitIn(wit_id, _) = expr else {
            panic!("Wrong selector expression format");
        };
        let wit_id = *wit_id as usize + offset_eq_id;
        if wit_id >= evals.len() {
            evals.resize(wit_id + 1, E::ZERO);
        }
        evals[wit_id] = eval;
    }

    /// return ordered indices of OrderedSparse32
    pub fn sparse32_indices(&self) -> &[usize] {
        match self {
            Self::OrderedSparse32 { indices, .. } => indices,
            _ => panic!("invalid calling on non sparse type"),
        }
    }

    pub fn selector_expr(&self) -> &Expression<E> {
        match self {
            Self::OrderedSparse32 { expression, .. }
            | Self::Whole(expression)
            | Self::Prefix(_, expression) => expression,
            e => unimplemented!("no selector expression in {:?}", e),
        }
    }
}
