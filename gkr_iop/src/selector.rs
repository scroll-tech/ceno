use std::iter::repeat_n;

use rayon::iter::IndexedParallelIterator;

use ff_ext::ExtensionField;
use multilinear_extensions::{
    Expression,
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
                assert!(end <= (1 << ctx.num_vars), "start: {}, num_instances: {}, num_vars: {}", start, ctx.num_instances, ctx.num_vars);

                let mut sel = build_eq_x_r_vec(out_point);
                sel.splice(0..start, repeat_n(E::ZERO, start));
                sel.splice(end..sel.len(), repeat_n(E::ZERO, sel.len() - end));
                Some(sel.into_mle())
            }
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
        }
    }

    /// Evaluate true and false mle eq(CYCLIC_POW2_5[round]; b[..5]) * sel(y; b[5..]), and eq(1; b[..5]) * (1 - sel(y; b[5..]))
    pub fn evaluate(
        &self,
        evals: &mut Vec<E>,
        out_point: &Point<E>,
        in_point: &Point<E>,
        ctx: &SelectorContext,
        offset_eq_id: usize,
    ) {
        assert_eq!(in_point.len(), ctx.num_vars);
        assert_eq!(out_point.len(), ctx.num_vars);

        let (expr, eval) = match self {
            SelectorType::None => return,
            SelectorType::Whole(expr) => {
                debug_assert_eq!(out_point.len(), in_point.len());
                (expr, eq_eval(out_point, in_point))
            }
            SelectorType::Prefix(expression) => {
                let start = ctx.offset;
                let end = start + ctx.num_instances;

                assert_eq!(in_point.len(), out_point.len());
                assert!(end <= (1 << out_point.len()));

                let eq_end = eq_eval_less_or_equal_than(end - 1, out_point, in_point);
                let sel = if start > 0 {
                    let eq_start = eq_eval_less_or_equal_than(start - 1, out_point, in_point);
                    eq_end - eq_start
                } else {
                    eq_end
                };
                (expression, sel)
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
                let sel = eq_eval_less_or_equal_than(
                    ctx.num_instances - 1,
                    &out_point[5..],
                    &in_point[5..],
                );
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
            | Self::Prefix(expression) => expression,
            e => unimplemented!("no selector expression in {:?}", e),
        }
    }
}
