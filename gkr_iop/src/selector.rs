use rayon::iter::{IndexedParallelIterator, IntoParallelIterator};

use ff_ext::ExtensionField;
use itertools::{Itertools, assert_equal};
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
    /// binary tree [`quark`] from paper
    QuarkBinaryTreeLessThan(Expression<E>),
}

impl<E: ExtensionField> SelectorType<E> {
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
            /// Compute true and false mle eq(1; b[..5]) * sel(y; b[5..]), and eq(1; b[..5]) * (eq() - sel(y; b[5..]))
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
            SelectorType::QuarkBinaryTreeLessThan(_) => {
                let mut sel: Vec<E> = build_eq_x_r_vec(out_point);
                let n = sel.len();

                let num_instances_sequence = (0..out_point.len())
                    // clean up sig bits
                    .scan(num_instances & !1, |acc, _| {
                        if *acc > 0 {
                            let cur = *acc;
                            *acc /= 2;
                            Some(cur)
                        } else {
                            Some(0)
                        }
                    })
                    .collect::<Vec<_>>();

                (0..out_point.len())
                    .into_par_iter()
                    .zip_eq(num_instances_sequence)
                    .for_each(|(level, num_instance_in_level)| {
                        let chunk_size = n / (1 << (level + 1)); // divide by 2^level

                        // Compute sub-slice
                        let start = chunk_size / 2; // Example offset logic
                        let end = start + chunk_size.min(n - start);

                        if start < n {
                            let slice = &mut sel[start..end];
                            // SAFETY: Each `level` writes to disjoint regions
                            for x in slice
                                .iter_mut()
                                .take(num_instance_in_level.min(slice.len()))
                            {
                                *x = E::ZERO;
                            }
                        }
                    });
                Some(sel.into_mle())
            }
        }
    }

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
            /// Evaluate true and false mle eq(CYCLIC_POW2_5[round]; b[..5]) * sel(y; b[5..]), and eq(1; b[..5]) * (1 - sel(y; b[5..]))
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
            SelectorType::QuarkBinaryTreeLessThan(expr) => {
                // num_instances count on leaf layer
                // where nodes size is 2^(N) / 2
                debug_assert!(num_instances <= (1 << (out_point.len() - 1)));
                if out_point.is_empty() {
                    panic!("empty out_point size")
                }
                assert_eq!(out_point.len(), in_point.len());
                if out_point.len() == 1 {
                    (
                        expr,
                        eq_eval_less_or_equal_than(num_instances - 1, &out_point, &in_point),
                    )
                } else {
                    let mut num_instances_sequence = (0..out_point.len())
                        // clean up sig bits
                        .scan(num_instances & !1, |acc, _| {
                            if *acc > 0 {
                                let cur = *acc;
                                *acc /= 2;
                                Some(cur)
                            } else {
                                Some(0)
                            }
                        })
                        .collect::<Vec<_>>();
                    num_instances_sequence.reverse();
                    // traverse tuple 2 per iteration
                    let mut num_instances_sequence_iter =
                        num_instances_sequence.iter().tuple_windows();

                    let mut res = E::ZERO;
                    for i in 1..out_point.len() {
                        let (num_instances_rhs_half, num_instances_lhs) =
                            num_instances_sequence_iter.by_ref().next().unwrap();
                        let lhs_res = if *num_instances_lhs > 0 {
                            (E::ONE - out_point[i])
                                * (E::ONE - in_point[i])
                                * eq_eval_less_or_equal_than(
                                    *num_instances_lhs - 1,
                                    &out_point[..i],
                                    &in_point[..i],
                                )
                        } else {
                            E::ZERO
                        };
                        let rhs_res = if *num_instances_rhs_half > 0 {
                            (out_point[i] * in_point[i]) * res
                        } else {
                            E::ZERO
                        };
                        res = lhs_res + rhs_res;
                    }
                    (expr, res)
                }
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
