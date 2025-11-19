use std::iter::repeat_n;

use rayon::iter::IndexedParallelIterator;

use ff_ext::ExtensionField;
use multilinear_extensions::{
    Expression, WitnessId,
    mle::{IntoMLE, MultilinearExtension, Point},
    util::ceil_log2,
    virtual_poly::{build_eq_x_r_vec, eq_eval},
};
use p3::field::FieldAlgebra;
use rayon::{
    iter::{IntoParallelIterator, ParallelIterator},
    slice::ParallelSliceMut,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};

use crate::{gkr::booleanhypercube::CYCLIC_POW2_5, utils::eq_eval_less_or_equal_than};

/// Provide context for selector's instantiation at runtime
#[derive(Clone, Debug)]
pub struct SelectorContext {
    pub offset: usize,
    pub num_instances: usize,
    pub num_vars: usize,
}

impl SelectorContext {
    pub fn new(offset: usize, num_instances: usize, num_vars: usize) -> Self {
        Self {
            offset,
            num_instances,
            num_vars,
        }
    }
}

/// Selector selects part of the witnesses in the sumcheck protocol.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(bound(
    serialize = "E::BaseField: Serialize",
    deserialize = "E::BaseField: DeserializeOwned"
))]
pub enum SelectorType<E: ExtensionField> {
    None,
    Whole(Expression<E>),
    /// Select part of the instances, other parts padded with a field element.
    Prefix(Expression<E>),
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
    /// Returns an MultilinearExtension with `ctx.num_vars` variables whenever applicable
    pub fn to_mle(&self, ctx: &SelectorContext) -> Option<MultilinearExtension<'_, E>> {
        match self {
            SelectorType::None => None,
            SelectorType::Whole(_) => {
                assert_eq!(ceil_log2(ctx.num_instances), ctx.num_vars);
                Some(
                    (0..(1 << ctx.num_vars))
                        .into_par_iter()
                        .map(|_| E::BaseField::ONE)
                        .collect::<Vec<_>>()
                        .into_mle(),
                )
            }
            SelectorType::Prefix(_) => {
                assert!(ctx.offset + ctx.num_instances <= (1 << ctx.num_vars));
                let start = ctx.offset;
                let end = start + ctx.num_instances;
                Some(
                    (0..start)
                        .into_par_iter()
                        .map(|_| E::BaseField::ZERO)
                        .chain((start..end).into_par_iter().map(|_| E::BaseField::ONE))
                        .chain(
                            (end..(1 << ctx.num_vars))
                                .into_par_iter()
                                .map(|_| E::BaseField::ZERO),
                        )
                        .collect::<Vec<_>>()
                        .into_mle(),
                )
            }
            SelectorType::OrderedSparse32 {
                indices,
                expression: _,
            } => {
                assert_eq!(ceil_log2(ctx.num_instances) + 5, ctx.num_vars);
                Some(
                    (0..(1 << (ctx.num_vars - 5)))
                        .into_par_iter()
                        .flat_map(|chunk_index| {
                            if chunk_index >= ctx.num_instances {
                                vec![E::ZERO; 32]
                            } else {
                                let mut chunk = vec![E::ZERO; 32];
                                let mut indices_iter = indices.iter().copied();
                                let mut next_keep = indices_iter.next();

                                for (i, e) in chunk.iter_mut().enumerate() {
                                    if let Some(idx) = next_keep
                                        && i == idx
                                    {
                                        *e = E::ONE;
                                        next_keep = indices_iter.next(); // Keep this one
                                    }
                                }
                                chunk
                            }
                        })
                        .collect::<Vec<E>>()
                        .into_mle(),
                )
            }
            SelectorType::QuarkBinaryTreeLessThan(..) => unimplemented!(),
        }
    }

    /// Compute true and false mle eq(1; b[..5]) * sel(y; b[5..]), and eq(1; b[..5]) * (eq() - sel(y; b[5..]))
    pub fn compute(
        &self,
        out_point: &Point<E>,
        ctx: &SelectorContext,
    ) -> Option<MultilinearExtension<'_, E>> {
        assert_eq!(out_point.len(), ctx.num_vars);

        match self {
            SelectorType::None => None,
            SelectorType::Whole(_) => Some(build_eq_x_r_vec(out_point).into_mle()),
            SelectorType::Prefix(_) => {
                let start = ctx.offset;
                let end = start + ctx.num_instances;
                assert!(
                    end <= (1 << ctx.num_vars),
                    "start: {}, num_instances: {}, num_vars: {}",
                    start,
                    ctx.num_instances,
                    ctx.num_vars
                );

                let mut sel = build_eq_x_r_vec(out_point);
                sel.splice(0..start, repeat_n(E::ZERO, start));
                sel.splice(end..sel.len(), repeat_n(E::ZERO, sel.len() - end));
                Some(sel.into_mle())
            }
            // compute true and false mle eq(1; b[..5]) * sel(y; b[5..]), and eq(1; b[..5]) * (eq() - sel(y; b[5..]))
            SelectorType::OrderedSparse32 { indices, .. } => {
                assert_eq!(out_point.len(), ceil_log2(ctx.num_instances) + 5);

                let mut sel = build_eq_x_r_vec(out_point);
                sel.par_chunks_exact_mut(CYCLIC_POW2_5.len())
                    .enumerate()
                    .for_each(|(chunk_index, chunk)| {
                        if chunk_index >= ctx.num_instances {
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
                assert_eq!(ctx.offset, 0);
                // num_instances: number of prefix one in leaf layer
                let mut sel: Vec<E> = build_eq_x_r_vec(out_point);
                let n = sel.len();

                let num_instances_sequence = (0..out_point.len())
                    // clean up sig bits
                    .scan(ctx.num_instances, |n_instance, _| {
                        // n points to sum means we have n/2 addition pairs
                        let cur = *n_instance / 2;
                        // the next layer has ceil(n/2) points to sum
                        *n_instance = (*n_instance).div_ceil(2);
                        Some(cur)
                    })
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
        out_point: &Point<E>,
        in_point: &Point<E>,
        ctx: &SelectorContext,
    ) -> Option<(E, WitnessId)> {
        assert_eq!(in_point.len(), ctx.num_vars);
        assert_eq!(out_point.len(), ctx.num_vars);

        let (expr, eval) = match self {
            SelectorType::None => return None,
            SelectorType::Whole(expr) => {
                debug_assert_eq!(out_point.len(), in_point.len());
                (expr, eq_eval(out_point, in_point))
            }
            SelectorType::Prefix(expression) => {
                let start = ctx.offset;
                let end = start + ctx.num_instances;

                assert_eq!(in_point.len(), out_point.len());
                assert!(
                    end <= (1 << out_point.len()),
                    "start: {}, num_instances: {}, num_vars: {}",
                    start,
                    ctx.num_instances,
                    ctx.num_vars
                );

                if end == 0 {
                    (expression, E::ZERO)
                } else {
                    let eq_end = eq_eval_less_or_equal_than(end - 1, out_point, in_point);
                    let sel = if start > 0 {
                        let eq_start = eq_eval_less_or_equal_than(start - 1, out_point, in_point);
                        eq_end - eq_start
                    } else {
                        eq_end
                    };
                    (expression, sel)
                }
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
                let sel = eq_eval_less_or_equal_than(
                    ctx.num_instances - 1,
                    &out_point[5..],
                    &in_point[5..],
                );
                (expression, eval * sel)
            }
            SelectorType::QuarkBinaryTreeLessThan(expr) => {
                // num_instances count on leaf layer
                // where nodes size is 2^(N) / 2
                // out_point.len() is also log(2^(N)) - 1
                // so num_instances and 1 << out_point.len() are on same scaling
                assert!(ctx.num_instances > 0);
                assert!(ctx.num_instances <= (1 << out_point.len()));
                assert!(!out_point.is_empty());
                assert_eq!(out_point.len(), in_point.len());

                // we break down this special selector evaluation into recursive structure
                // iterating through out_point and in_point, for each i
                // next_eval = lhs * (1-out_point[i]) * (1 - in_point[i]) + prev_eval * out_point[i] * in_point[i]
                // where the lhs is in consecutive prefix 1 follow by 0

                // calculate prefix 1 length of each layer
                let mut prefix_one_seq = (0..out_point.len())
                    .scan(ctx.num_instances, |n_instance, _| {
                        // n points to sum means we have n/2 addition pairs
                        let cur = *n_instance / 2;
                        // next layer has ceil(n/2) points to sum
                        *n_instance = (*n_instance).div_ceil(2);
                        Some(cur)
                    })
                    .collect::<Vec<_>>();
                prefix_one_seq.reverse();

                // _debug
                println!("=> ctx.num_instances: {:?}", ctx.num_instances);
                println!("=> prefix_one_seq: {:?}", prefix_one_seq);

                let mut res = if prefix_one_seq[0] == 0 {
                    E::ZERO
                } else {
                    assert_eq!(prefix_one_seq[0], 1);
                    (E::ONE - out_point[0]) * (E::ONE - in_point[0])
                };
                for i in 1..out_point.len() {
                    let num_prefix_one_lhs = prefix_one_seq[i];
                    let lhs_res = if num_prefix_one_lhs == 0 {
                        E::ZERO
                    } else {
                        (E::ONE - out_point[i])
                            * (E::ONE - in_point[i])
                            * eq_eval_less_or_equal_than(
                                num_prefix_one_lhs - 1,
                                &out_point[..i],
                                &in_point[..i],
                            )
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
        Some((eval, *wit_id))
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
            | Self::Prefix(expression) => expression,
            e => unimplemented!("no selector expression in {:?}", e),
        }
    }
}

#[cfg(test)]
mod tests {
    use ff_ext::{BabyBearExt4, FromUniformBytes};
    use multilinear_extensions::{
        StructuralWitIn, ToExpr, util::ceil_log2, virtual_poly::build_eq_x_r_vec,
    };
    use p3::field::FieldAlgebra;
    use rand::thread_rng;

    use crate::selector::{SelectorContext, SelectorType};

    type E = BabyBearExt4;

    #[test]
    fn test_quark_lt_selector() {
        let mut rng = thread_rng();
        let n_points = 5;
        let n_vars = ceil_log2(n_points);
        let witin = StructuralWitIn {
            id: 0,
            witin_type: multilinear_extensions::StructuralWitInType::EqualDistanceSequence {
                max_len: 0,
                offset: 0,
                multi_factor: 0,
                descending: false,
            },
        };
        let selector = SelectorType::QuarkBinaryTreeLessThan(witin.expr());
        let ctx = SelectorContext::new(0, n_points, n_vars);
        let out_rt = E::random_vec(n_vars, &mut rng);
        let sel_mle = selector.compute(&out_rt, &ctx).unwrap();

        // if we have 5 points to sum, then
        // in 1st layer: two additions p12 = p1 + p2, p34 = p3 + p4, p5 kept
        // in 2nd layer: one addition p14 = p12 + p34, p5 kept
        // in 3rd layer: one addition p15 = p14 + p5
        let eq = build_eq_x_r_vec(&out_rt);
        let vec = sel_mle.get_ext_field_vec();
        assert_eq!(vec[0], eq[0]); // p1+p2
        assert_eq!(vec[1], eq[1]); // p3+p4
        assert_eq!(vec[2], E::ZERO); // p5
        assert_eq!(vec[3], E::ZERO);
        assert_eq!(vec[4], eq[4]); // p1+p2+p3+p4
        assert_eq!(vec[5], E::ZERO); // p5
        assert_eq!(vec[6], eq[6]); // p1+p2+p3+p4+p5
        assert_eq!(vec[7], E::ZERO);

        let in_rt = E::random_vec(n_vars, &mut rng);
        let Some((eval, _)) = selector.evaluate(&out_rt, &in_rt, &ctx) else {
            unreachable!()
        };
        assert_eq!(sel_mle.evaluate(&in_rt), eval);
    }
}
