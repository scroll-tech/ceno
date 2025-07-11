pub mod lk_multiplicity;

use ff_ext::{ExtensionField, SmallField};
use itertools::{Itertools, izip};
use multilinear_extensions::{
    Expression, Fixed, WitIn, WitnessId,
    mle::{ArcMultilinearExtension, MultilinearExtension},
    util::ceil_log2,
    virtual_poly::{build_eq_x_r_vec, eq_eval},
    wit_infer_by_expr,
};
use p3_field::FieldAlgebra;
use rayon::{
    iter::{
        IndexedParallelIterator, IntoParallelIterator, IntoParallelRefIterator, ParallelExtend,
        ParallelIterator,
    },
    slice::{ParallelSlice, ParallelSliceMut},
};

use crate::{
    evaluation::EvalExpression,
    gkr::{booleanhypercube::BooleanHypercube, layer::Layer},
};

pub fn infer_layer_witness<'a, E>(
    layer: &Layer<E>,
    layer_wits: &[ArcMultilinearExtension<'a, E>],
    challenges: &[E],
) -> Vec<ArcMultilinearExtension<'a, E>>
where
    E: ExtensionField,
{
    let out_evals: Vec<_> = layer
        .out_eq_and_eval_exprs
        .iter()
        .flat_map(|(_, out_eval)| out_eval.iter())
        .collect();
    layer
        .exprs
        .par_iter()
        .zip_eq(layer.expr_names.par_iter())
        .zip_eq(out_evals.par_iter())
        .map(|((expr, expr_name), out_eval)| {
            let out_mle = wit_infer_by_expr(&[], layer_wits, &[], &[], challenges, expr);
            if let EvalExpression::Zero = out_eval {
                // sanity check: zero mle
                if cfg!(debug_assertions) {
                    let all_zero = match out_mle.evaluations() {
                        multilinear_extensions::mle::FieldType::Base(smart_slice) => {
                            smart_slice.iter().copied().all(|v| v == E::BaseField::ZERO)
                        }
                        multilinear_extensions::mle::FieldType::Ext(smart_slice) => {
                            smart_slice.iter().copied().all(|v| v == E::ZERO)
                        }
                        multilinear_extensions::mle::FieldType::Unreachable => unreachable!(),
                    };
                    if !all_zero {
                        panic!(
                            "layer name: {}, expr name: \"{expr_name}\" got non_zero mle",
                            layer.name
                        );
                    }
                }
            };
            out_mle
        })
        .collect::<Vec<_>>()
}

pub fn extend_exprs_with_rotation<E: ExtensionField>(
    layer: &Layer<E>,
    alpha_pows: &[Expression<E>],
) -> Vec<Expression<E>> {
    let mut alpha_pows_iter = alpha_pows.iter();
    let mut expr_iter = layer.exprs.iter();
    let mut zero_check_exprs = Vec::with_capacity(layer.out_eq_and_eval_exprs.len());
    for (eq_expr, out_evals) in layer.out_eq_and_eval_exprs.iter() {
        let group_length = out_evals.len();
        let zero_check_expr = expr_iter
            .by_ref()
            .take(group_length)
            .cloned()
            .zip_eq(alpha_pows_iter.by_ref().take(group_length))
            .map(|(expr, alpha)| alpha * expr)
            .sum::<Expression<E>>();
        zero_check_exprs.push(eq_expr.clone().unwrap() * zero_check_expr);
    }

    // prepare rotation expr
    let (rotation_eq, rotation_exprs) = &layer.rotation_exprs;
    if rotation_eq.is_none() {
        return zero_check_exprs;
    }

    let left_rotation_expr: Expression<E> = izip!(
        rotation_exprs.iter(),
        alpha_pows_iter.by_ref().take(rotation_exprs.len())
    )
    .map(|((rotate_expr, _), alpha)| {
        assert!(matches!(rotate_expr, Expression::WitIn(_)));
        alpha * rotate_expr
    })
    .sum();
    let right_rotation_expr: Expression<E> = izip!(
        rotation_exprs.iter(),
        alpha_pows_iter.by_ref().take(rotation_exprs.len())
    )
    .map(|((rotate_expr, _), alpha)| {
        assert!(matches!(rotate_expr, Expression::WitIn(_)));
        alpha * rotate_expr
    })
    .sum();
    let rotation_expr: Expression<E> = izip!(
        rotation_exprs.iter(),
        alpha_pows_iter.by_ref().take(rotation_exprs.len())
    )
    .map(|((_, expr), alpha)| {
        assert!(matches!(expr, Expression::WitIn(_)));
        alpha * expr
    })
    .sum();

    // push rotation expr to zerocheck expr
    if let Some(
        [
            rotation_left_eq_expr,
            rotation_right_eq_expr,
            rotation_eq_expr,
        ],
    ) = rotation_eq.as_ref()
    {
        // add rotation left expr
        zero_check_exprs.push(rotation_left_eq_expr * left_rotation_expr);
        // add rotation right expr
        zero_check_exprs.push(rotation_right_eq_expr * right_rotation_expr);
        // add target expr
        zero_check_exprs.push(rotation_eq_expr * rotation_expr);
    }
    assert!(expr_iter.next().is_none() && alpha_pows_iter.next().is_none());

    zero_check_exprs
}

pub fn rotation_next_base_mle<'a, E: ExtensionField>(
    bh: &BooleanHypercube,
    mle: &ArcMultilinearExtension<'a, E>,
    cyclic_group_log2_size: usize,
) -> MultilinearExtension<'a, E> {
    let cyclic_group_size = 1 << cyclic_group_log2_size;
    let rotation_index = bh.into_iter().take(cyclic_group_size + 1).collect_vec();
    let mut rotated_mle_evals = Vec::with_capacity(mle.evaluations().len());
    rotated_mle_evals.par_extend(
        (0..mle.evaluations().len())
            .into_par_iter()
            .map(|_| E::BaseField::ZERO),
    );
    rotated_mle_evals
        .par_chunks_mut(cyclic_group_size)
        .zip(mle.get_base_field_vec().par_chunks(cyclic_group_size))
        .for_each(|(rotate_chunk, original_chunk)| {
            let first = rotation_index[0] as usize;
            let last = rotation_index[rotation_index.len() - 1] as usize;

            if first == last {
                rotate_chunk[last] = original_chunk[first]
            }

            rotate_chunk[0] = original_chunk[0];

            for i in (0..rotation_index.len() - 1).rev() {
                let to = rotation_index[i] as usize;
                let from = rotation_index[i + 1] as usize;
                rotate_chunk[to] = original_chunk[from];
            }
        });
    MultilinearExtension::from_evaluation_vec_smart(mle.num_vars(), rotated_mle_evals)
}

pub fn rotation_selector<'a, E: ExtensionField>(
    bh: &BooleanHypercube,
    eq: &[E],
    cyclic_subgroup_size: usize,
    cyclic_group_log2_size: usize,
    total_len: usize,
) -> MultilinearExtension<'a, E> {
    assert!(total_len.is_power_of_two());
    let cyclic_group_size = 1 << cyclic_group_log2_size;
    assert!(cyclic_subgroup_size <= cyclic_group_size);
    let rotation_index = bh.into_iter().take(cyclic_subgroup_size).collect_vec();
    let mut rotated_mle_evals = Vec::with_capacity(total_len);
    rotated_mle_evals.par_extend((0..total_len).into_par_iter().map(|_| E::ZERO));
    rotated_mle_evals
        .par_chunks_mut(cyclic_group_size)
        .zip_eq(eq.par_chunks(cyclic_group_size))
        .for_each(|(rotate_chunk, eq_chunk)| {
            for i in (0..rotation_index.len()).rev() {
                let to = rotation_index[i] as usize;
                rotate_chunk[to] = eq_chunk[to];
            }
        });
    MultilinearExtension::from_evaluation_vec_smart(ceil_log2(total_len), rotated_mle_evals)
}

/// sel(rx)
/// = (\sum_{b = 0}^{cyclic_subgroup_size - 1} eq(out_point[..cyclic_group_log2_size], b) * eq(in_point[..cyclic_group_log2_size], b))
///     * \prod_{k = cyclic_group_log2_size}^{n - 1} eq(out_point[k], in_point[k])
pub fn rotation_selector_eval<E: ExtensionField>(
    bh: &BooleanHypercube,
    out_point: &[E],
    in_point: &[E],
    cyclic_subgroup_size: usize,
    cyclic_group_log2_size: usize,
) -> E {
    let cyclic_group_size = 1 << cyclic_group_log2_size;
    assert!(cyclic_subgroup_size <= cyclic_group_size);
    let rotation_index = bh.into_iter().take(cyclic_subgroup_size).collect_vec();
    let out_subgroup_eq = build_eq_x_r_vec(&out_point[..cyclic_group_log2_size]);
    let in_subgroup_eq = build_eq_x_r_vec(&in_point[..cyclic_group_log2_size]);
    let mut eval = E::ZERO;
    for b in rotation_index {
        let b = b as usize;
        eval += out_subgroup_eq[b] * in_subgroup_eq[b];
    }
    eval * eq_eval(
        &out_point[cyclic_group_log2_size..],
        &in_point[cyclic_group_log2_size..],
    )
}

pub fn i64_to_base<F: SmallField>(x: i64) -> F {
    if x >= 0 {
        F::from_canonical_u64(x as u64)
    } else {
        -F::from_canonical_u64((-x) as u64)
    }
}

/// Returns `[0 + offset, ..., N - 1 + offset]`.
#[must_use]
pub const fn indices_arr_with_offset<const N: usize, const OFFSET: usize>() -> [usize; N] {
    let mut indices_arr = [0; N];
    let mut i = 0;
    while i < N {
        indices_arr[i] = i + OFFSET;
        i += 1;
    }
    indices_arr
}

pub fn indices_arr_with_offset_non_const<const N: usize>(offset: usize) -> [usize; N] {
    let mut indices_arr = [0; N];
    let mut i = 0;
    while i < N {
        indices_arr[i] = i + offset;
        i += 1;
    }
    indices_arr
}

/// Returns `[WitIn(0), ..., WitIn(N - 1)], [Fixed(N), Fixed(N + 1), ..., Fixed(N + M)], [WitIn(N + M + 1), ...]`.
#[must_use]
pub const fn wits_fixed_and_eqs<const N: usize, const M: usize, const Q: usize>()
-> ([WitIn; N], [Fixed; M], [WitIn; Q]) {
    let mut wits = [WitIn { id: 0 }; N];
    let mut i = 0;
    while i < N {
        wits[i] = WitIn { id: i as WitnessId };
        i += 1;
    }
    let mut i = 0;
    let mut fixed = [Fixed(0); M];
    while i < M {
        fixed[i] = Fixed(i);
        i += 1;
    }
    let mut i = 0;
    let mut eqs = [WitIn { id: 0 }; Q];
    while i < Q {
        eqs[i] = WitIn {
            id: (i + N + M) as WitnessId,
        };
        i += 1;
    }
    (wits, fixed, eqs)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use ff_ext::{FromUniformBytes, GoldilocksExt2};
    use p3_goldilocks::Goldilocks;

    use super::*;

    fn make_mle<'a, E: ExtensionField>(
        values: Vec<E::BaseField>,
    ) -> ArcMultilinearExtension<'a, E> {
        Arc::new(MultilinearExtension::from_evaluation_vec_smart(
            values.len().ilog2() as usize,
            values,
        ))
    }

    #[test]
    fn test_rotation_next_base_mle_eval() {
        type E = GoldilocksExt2;
        let bh = BooleanHypercube::new(5);
        let poly = make_mle::<E>(
            (0..128u64)
                .map(Goldilocks::from_canonical_u64)
                .collect_vec(),
        );
        let rotated = rotation_next_base_mle(&bh, &poly, 5);

        let mut rng = rand::thread_rng();
        let point: Vec<_> = (0..7).map(|_| E::random(&mut rng)).collect();
        let (left_point, right_point) = bh.get_rotation_points(&point);
        let rotated_eval = rotated.evaluate(&point);
        let left_eval = poly.evaluate(&left_point);
        let right_eval = poly.evaluate(&right_point);
        assert_eq!(
            rotated_eval,
            (E::ONE - point[4]) * left_eval + point[4] * right_eval
        );
        assert_eq!(
            right_eval,
            bh.get_rotation_right_eval_from_left(rotated_eval, left_eval, &point)
        );
    }
}
