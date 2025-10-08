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
            // compute true and false mle eq(1; b[..5]) * sel(y; b[5..]), and eq(1; b[..5]) * (eq() - sel(y; b[5..]))
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
            // also see evaluate() function for more explanation
            SelectorType::QuarkBinaryTreeLessThan(_) => {
                // num_instances: number of prefix one in leaf layer
                let mut sel: Vec<E> = build_eq_x_r_vec(out_point);
                let n = sel.len();

                let num_instances_sequence = (0..out_point.len())
                    // clean up sig bits
                    .scan(
                        (num_instances / 2, num_instances.div_ceil(2)),
                        |(n_instance, raw_instance_ceiling), _| {
                            if *n_instance > 0 {
                                let cur = *n_instance;
                                *n_instance = *raw_instance_ceiling / 2;
                                *raw_instance_ceiling = raw_instance_ceiling.div_ceil(2);
                                Some(cur)
                            } else {
                                Some(0)
                            }
                        },
                    )
                    .collect::<Vec<_>>();

                // split sel into different size of region, set tailing 0 of respective chunk size
                // 1st round: take v = sel[0..sel.len()/2], zero out v[num_instances_sequence[0]..]
                // 2nd round: take v = sel[sel.len()/2 .. sel.len()/4], zero out v[num_instances_sequence[1]..]
                // ...
                // each round: progressively smaller chunk
                // example: round 0 uses first half, round 1 uses next quarter, etc.
                // compute cumulative start indices:
                // e.g. chunk = n/2, then start = 0, chunk, chunk + chunk/2, chunk + chunk/2 + chunk/4, ...
                // compute disjoint start indices and lengths
                let chunks: Vec<(usize, usize)> = {
                    let mut result = Vec::new();
                    let mut start = 0;
                    let mut chunk_len = n / 2;
                    while chunk_len > 0 {
                        result.push((start, chunk_len));
                        start += chunk_len;
                        chunk_len /= 2;
                    }
                    result
                };

                for (i, (start, len)) in chunks.into_iter().enumerate() {
                    let slice = &mut sel[start..start + len];

                    // determine from which index to zero
                    let zero_start = num_instances_sequence.get(i).copied().unwrap_or(0).min(len);

                    for x in &mut slice[zero_start..] {
                        *x = E::ZERO;
                    }
                }

                // zero out last bh evaluations
                *sel.last_mut().unwrap() = E::ZERO;
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
            // evaluate true and false mle eq(CYCLIC_POW2_5[round]; b[..5]) * sel(y; b[5..]), and eq(1; b[..5]) * (1 - sel(y; b[5..]))
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
                // out_point.len() is also log(2^(N)) - 1
                // so num_instances and 1 << out_point.len() are on same scaling
                assert!(num_instances > 0);
                assert!(num_instances <= (1 << out_point.len()));
                if out_point.is_empty() {
                    panic!("empty out_point size")
                }
                assert_eq!(out_point.len(), in_point.len());

                // we break down this special selector evaluation into recursive structure
                // iterating through out_point and in_point, for each i
                // next_eval = lhs * (1-out_point[i]) * (1 - in_point[i]) + prev_eval * out_point[i] * in_point[i]
                // where the lhs is in consecutive prefix 1 follow by 0

                // calculate prefix 1 length of each layer
                let mut prefix_one_seq = (0..out_point.len())
                    .scan(
                        (num_instances / 2, num_instances.div_ceil(2)),
                        |(n_instance, raw_instance_ceiling), _| {
                            if *n_instance > 0 {
                                let cur = *n_instance;
                                *n_instance = *raw_instance_ceiling / 2;
                                *raw_instance_ceiling = raw_instance_ceiling.div_ceil(2);
                                Some(cur)
                            } else {
                                Some(0)
                            }
                        },
                    )
                    .collect::<Vec<_>>();
                prefix_one_seq.reverse();
                let mut prefix_one_seq_iter = prefix_one_seq.iter();

                let mut res = if let Some(first) = prefix_one_seq_iter.by_ref().next() {
                    if *first > 0 {
                        assert_eq!(*first, 1);
                        (E::ONE - out_point[0]) * (E::ONE - in_point[0])
                    } else {
                        E::ZERO
                    }
                } else {
                    unreachable!()
                };
                for i in 1..out_point.len() {
                    let num_prefix_one_lhs = prefix_one_seq_iter.by_ref().next().unwrap();
                    let lhs_res = if *num_prefix_one_lhs > 0 {
                        (E::ONE - out_point[i])
                            * (E::ONE - in_point[i])
                            * eq_eval_less_or_equal_than(
                                *num_prefix_one_lhs - 1,
                                &out_point[..i],
                                &in_point[..i],
                            )
                    } else {
                        E::ZERO
                    };
                    let rhs_res = (out_point[i] * in_point[i]) * res;
                    res = lhs_res + rhs_res;
                }
                (expr, res)
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
