pub mod lk_multiplicity;

use ff_ext::{ExtensionField, SmallField};
use itertools::Itertools;
use multilinear_extensions::{
    Fixed, WitIn, WitnessId,
    mle::{ArcMultilinearExtension, MultilinearExtension},
    util::ceil_log2,
    virtual_poly::{build_eq_x_r_vec, eq_eval},
};
use p3::field::FieldAlgebra;
use rayon::{
    iter::{IndexedParallelIterator, IntoParallelIterator, ParallelExtend, ParallelIterator},
    slice::{ParallelSlice, ParallelSliceMut},
};

use crate::gkr::booleanhypercube::BooleanHypercube;

pub fn rotation_next_base_mle<'a, E: ExtensionField>(
    bh: &BooleanHypercube,
    mle: &ArcMultilinearExtension<'a, E>,
    cyclic_group_log2_size: usize,
) -> MultilinearExtension<'a, E> {
    let cyclic_group_size = 1 << cyclic_group_log2_size;
    let rotation_index = bh.into_iter().take(cyclic_group_size).collect_vec();
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
/// TODO remove me
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

/// This is to compute a variant of eq(\mathbf{x}, \mathbf{y}) for indices in
/// [0..=max_idx]. Specifically, it is an MLE of the following vector:
///     partial_eq_{\mathbf{x}}(\mathbf{y})
///         = \sum_{\mathbf{b}=0}^{max_idx} \prod_{i=0}^{n-1} (x_i y_i b_i + (1 - x_i)(1 - y_i)(1 - b_i))
pub fn eq_eval_less_or_equal_than<E: ExtensionField>(max_idx: usize, a: &[E], b: &[E]) -> E {
    assert!(a.len() >= b.len());
    // Compute running product of ( x_i y_i + (1 - x_i)(1 - y_i) )_{0 <= i <= n}
    let running_product = {
        let mut running_product = Vec::with_capacity(b.len() + 1);
        running_product.push(E::ONE);
        for i in 0..b.len() {
            let x = running_product[i] * (a[i] * b[i] + (E::ONE - a[i]) * (E::ONE - b[i]));
            running_product.push(x);
        }
        running_product
    };

    let running_product2 = {
        let mut running_product = vec![E::ZERO; b.len() + 1];
        running_product[b.len()] = E::ONE;
        for i in (0..b.len()).rev() {
            let bit = E::from_canonical_u64(((max_idx >> i) & 1) as u64);
            running_product[i] = running_product[i + 1]
                * (a[i] * b[i] * bit + (E::ONE - a[i]) * (E::ONE - b[i]) * (E::ONE - bit));
        }
        running_product
    };

    // Here is an example of how this works:
    // Suppose max_idx = (110101)_2
    // Then ans = eq(a, b)
    //          - eq(11011, a[1..6], b[1..6])eq(a[0..1], b[0..1])
    //          - eq(111, a[3..6], b[3..6])eq(a[0..3], b[0..3])
    let mut ans = running_product[b.len()];
    for i in 0..b.len() {
        let bit = (max_idx >> i) & 1;
        if bit == 1 {
            continue;
        }
        ans -= running_product[i] * running_product2[i + 1] * a[i] * b[i];
    }
    for v in a.iter().skip(b.len()) {
        ans *= E::ONE - *v;
    }
    ans
}

/// evaluate MLE M(x0, x1, x2, ..., xn) address vector with it evaluation format
/// on r = [r0, r1, r2, ...rn] succinctly
/// where `M = descending * scaled * M' + offset`
/// offset, scaled, is constant, descending = +1/-1
/// and M' := [0, 1, 2, 3, ....2^n-1]
/// succinctly format of M'(r) = r0 + r1 * 2 + r2 * 2^2 + .... rn * 2^n
pub fn eval_wellform_address_vec<E: ExtensionField>(
    offset: u64,
    scaled: u64,
    r: &[E],
    descending: bool,
) -> E {
    let (offset, scaled) = (E::from_canonical_u64(offset), E::from_canonical_u64(scaled));
    let tmp = scaled
        * r.iter()
            .scan(E::ONE, |state, x| {
                let result = *x * *state;
                *state *= E::from_canonical_u64(2); // Update the state for the next power of 2
                Some(result)
            })
            .sum::<E>();
    let tmp = if descending { tmp.neg() } else { tmp };
    offset + tmp
}

/// Evaluate MLE with the following evaluation over the hypercube:
/// [0, 0, 0, 1, 0, 1, 2, 3, 0, 1, 2, 3, 4, 5, 6, 7, ..., 0, 1, 2, ..., 2^n-1]
/// which is the concatenation of
/// [0]
/// [0, 1]
/// [0, 1, 2, 3]
/// ...
/// [0, 1, 2, ..., 2^n-1]
/// which is then prefixed by a single zero to make all the subvectors aligned to powers of two.
/// This function is used to support dynamic range check.
/// Note that this MLE has n+1 variables, so r should have length n+1.
///
/// conceptually, we traverse evaluations in the sequence:
///   [0, 0], [0, 1], [0, 1, 2, 3], ...
/// for every `next` element is already in a well-formed incremental structure,
/// so we can reuse `eval_wellform_address_vec` to obtain its value.
///
/// at each step `i`, we combine:
///   - the accumulated result so far, weighted by `(1 - r[i])`
///   - the evaluation of the current prefix `r[..i]`, weighted by `r[i]`.
///
/// this iterative version avoids recursion for efficiency and clarity.
pub fn eval_stacked_wellform_address_vec<E: ExtensionField>(r: &[E]) -> E {
    if r.len() < 2 {
        return E::ZERO;
    }

    let mut res = E::ZERO;
    for i in 1..r.len() {
        res = res * (E::ONE - r[i]) + eval_wellform_address_vec(0, 1, &r[..i], false) * r[i];
    }
    res
}

/// Evaluate MLE with the following evaluation over the hypercube:
/// [0, 0, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 3, 3, 3, 3, ..., n, n, n, ..., n]
/// which is the concatenation of
/// [0]
/// [1, 1]
/// [2, 2, 2, 2]
/// ...
/// [n, n, n, ..., n]
/// which is then prefixed by a single zero to make all the subvectors aligned to powers of two.
/// This function is used to support dynamic range check.
/// Note that this MLE has n+1 variables, so r should have length n+1.
pub fn eval_stacked_constant_vec<E: ExtensionField>(r: &[E]) -> E {
    if r.len() < 2 {
        return E::ZERO;
    }

    let mut res = E::ZERO;
    for (i, r) in r.iter().enumerate().skip(1) {
        res = res * (E::ONE - *r) + E::from_canonical_usize(i) * *r;
    }
    res
}

/// evaluate MLE M(x0, x1, x2, ..., xn) address vector with it evaluation format
/// on r = [r0, r1, r2, ...rn] succinctly
/// where `M = [0 ... 0 1 ... 1 ... 2^(n-k)-1 ... 2^(n-k)-1]`
/// where each element is repeated 2^k times
/// The value is the same as M(xk, xk+1, ..., xn), i.e., just abandoning
/// the first k elements from r
pub fn eval_inner_repeated_incremental_vec<E: ExtensionField>(k: u64, r: &[E]) -> E {
    eval_wellform_address_vec(0, 1, &r[k as usize..], false)
}

/// evaluate MLE M(x0, x1, x2, ..., xn) address vector with it evaluation format
/// on r = [r0, r1, r2, ...rn] succinctly
/// where `M = [0 1 ... 2^k-1] * 2^(n-k)`
/// The value is the same as M(x0, ..., xk), i.e., just taking
/// the first k elements from r
pub fn eval_outer_repeated_incremental_vec<E: ExtensionField>(k: u64, r: &[E]) -> E {
    eval_wellform_address_vec(0, 1, &r[..k as usize], false)
}

#[cfg(test)]
mod tests {
    use ff_ext::{FromUniformBytes, GoldilocksExt2};
    use p3::{field::FieldAlgebra, goldilocks::Goldilocks};
    use std::{iter, sync::Arc};

    type E = GoldilocksExt2;

    use multilinear_extensions::mle::MultilinearExtension;

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

    #[test]
    fn test_eval_stacked_wellform_address_vec() {
        let r = [
            E::from_canonical_usize(123),
            E::from_canonical_usize(456),
            E::from_canonical_usize(789),
            E::from_canonical_usize(3210),
            E::from_canonical_usize(9876),
        ];
        for n in 0..r.len() {
            let v = iter::once(E::ZERO)
                .chain((0..=n).flat_map(|i| (0..(1 << i)).map(E::from_canonical_usize)))
                .collect::<Vec<E>>();
            let poly = MultilinearExtension::from_evaluations_ext_vec(n + 1, v);
            assert_eq!(
                eval_stacked_wellform_address_vec(&r[0..=n]),
                poly.evaluate(&r[0..=n])
            )
        }
    }

    #[test]
    fn test_eval_stacked_constant_vec() {
        let r = [
            E::from_canonical_usize(123),
            E::from_canonical_usize(456),
            E::from_canonical_usize(789),
            E::from_canonical_usize(3210),
            E::from_canonical_usize(9876),
        ];
        for n in 0..r.len() {
            let v = iter::once(E::ZERO)
                .chain((0..=n).flat_map(|i| iter::repeat_n(i, 1 << i).map(E::from_canonical_usize)))
                .collect::<Vec<E>>();
            let poly = MultilinearExtension::from_evaluations_ext_vec(n + 1, v);
            assert_eq!(
                eval_stacked_constant_vec(&r[0..=n]),
                poly.evaluate(&r[0..=n])
            )
        }
    }

    #[test]
    fn test_eval_inner_repeating_incremental_vec() {
        let r = [
            E::from_canonical_usize(123),
            E::from_canonical_usize(456),
            E::from_canonical_usize(789),
            E::from_canonical_usize(3210),
            E::from_canonical_usize(9876),
        ];
        for n in 1..=r.len() {
            for k in 0..=n {
                let v = (0..(1 << (n - k)))
                    .flat_map(|i| iter::repeat_n(E::from_canonical_usize(i), 1 << k))
                    .collect::<Vec<E>>();
                let poly = MultilinearExtension::from_evaluations_ext_vec(n, v);
                assert_eq!(
                    eval_inner_repeated_incremental_vec(k as u64, &r[0..n]),
                    poly.evaluate(&r[0..n])
                )
            }
        }
    }

    #[test]
    fn test_eval_outer_repeating_incremental_vec() {
        let r = [
            E::from_canonical_usize(123),
            E::from_canonical_usize(456),
            E::from_canonical_usize(789),
            E::from_canonical_usize(3210),
            E::from_canonical_usize(9876),
        ];
        for n in 1..=r.len() {
            for k in 0..=n {
                let v = iter::repeat_n(0, 1 << (n - k))
                    .flat_map(|_| (0..(1 << k)).map(E::from_canonical_usize))
                    .collect::<Vec<E>>();
                let poly = MultilinearExtension::from_evaluations_ext_vec(n, v);
                assert_eq!(
                    eval_outer_repeated_incremental_vec(k as u64, &r[0..n]),
                    poly.evaluate(&r[0..n])
                )
            }
        }
    }
}
