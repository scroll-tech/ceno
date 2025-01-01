use std::{iter, ops::Mul};

use ff::{Field, PrimeField};
use ff_ext::ExtensionField;
use itertools::{Itertools, chain, izip};
use multilinear_extensions::virtual_poly::build_eq_x_r_vec_with_scalar;
use rayon::iter::{
    IndexedParallelIterator, IntoParallelRefIterator, IntoParallelRefMutIterator, ParallelIterator,
};

pub fn i64_to_field<F: PrimeField>(i: i64) -> F {
    if i < 0 {
        -F::from(i.unsigned_abs())
    } else {
        F::from(i as u64)
    }
}

pub fn power_list<F: Field>(ele: &F, size: usize) -> Vec<F> {
    (0..size)
        .scan(F::ONE, |state, _| {
            let last = *state;
            *state *= *ele;
            Some(last)
        })
        .collect()
}

/// Grand product of ele, start from 1, with length ele.len() + 1.
pub fn grand_product<F: Field>(ele: &[F]) -> Vec<F> {
    let one = F::ONE;
    chain![iter::once(&one), ele.iter()]
        .scan(F::ONE, |state, e| {
            *state *= *e;
            Some(*state)
        })
        .collect()
}

pub fn eq_vecs<'a, E: ExtensionField>(
    points: impl Iterator<Item = &'a [E]>,
    scalars: &[E],
) -> Vec<Vec<E>> {
    izip!(points, scalars)
        .map(|(point, scalar)| build_eq_x_r_vec_with_scalar(point, *scalar))
        .collect_vec()
}

#[inline(always)]
pub fn eq<F: PrimeField>(x: &F, y: &F) -> F {
    // x * y + (1 - x) * (1 - y)
    let xy = *x * y;
    xy + xy - x - y + F::ONE
}

pub fn fix_variables_ext<E: ExtensionField>(base_mle: &[E::BaseField], r: &E) -> Vec<E> {
    base_mle
        .par_iter()
        .chunks(2)
        .with_min_len(64)
        .map(|buf| *r * (*buf[1] - *buf[0]) + *buf[0])
        .collect()
}

pub fn fix_variables_inplace<E: ExtensionField>(ext_mle: &mut [E], r: &E) {
    ext_mle
        .par_iter_mut()
        .chunks(2)
        .with_min_len(64)
        .for_each(|mut buf| *buf[0] = *buf[0] + (*buf[1] - *buf[0]) * r);
    // sequentially update buf[b1, b2,..bt] = buf[b1, b2,..bt, 0]
    let half_len = ext_mle.len() >> 1;
    for index in 0..half_len {
        ext_mle[index] = ext_mle[index << 1];
    }
}

pub fn evaluate_mle_inplace<E: ExtensionField>(mle: &mut [E], point: &[E]) -> E {
    for r in point {
        fix_variables_inplace(mle, r);
    }
    mle[0]
}

pub fn evaluate_mle_ext<E: ExtensionField>(mle: &[E::BaseField], point: &[E]) -> E {
    let mut ext_mle = fix_variables_ext(mle, &point[0]);
    evaluate_mle_inplace(&mut ext_mle, &point[1..])
}

/// Interpolate a uni-variate degree-`p_i.len()-1` polynomial and evaluate this
/// polynomial at `eval_at`:
///
///   \sum_{i=0}^len p_i * (\prod_{j!=i} (eval_at - j)/(i-j) )
///
/// This implementation is linear in number of inputs in terms of field
/// operations. It also has a quadratic term in primitive operations which is
/// negligible compared to field operations.
/// TODO: The quadratic term can be removed by precomputing the lagrange
/// coefficients.
pub(crate) fn interpolate_uni_poly<F: PrimeField, E: PrimeField + Mul<F, Output = E>>(
    p_iter_rev: impl Iterator<Item = F>,
    len: usize,
    eval_at: E,
) -> E {
    let mut evals = vec![eval_at];
    let mut prod = eval_at;

    // `prod = \prod_{j} (eval_at - j)`
    for j in 1..len {
        let tmp = eval_at - E::from(j as u64);
        evals.push(tmp);
        prod *= tmp;
    }
    let mut res = E::ZERO;
    // we want to compute \prod (j!=i) (i-j) for a given i
    //
    // we start from the last step, which is
    //  denom[len-1] = (len-1) * (len-2) *... * 2 * 1
    // the step before that is
    //  denom[len-2] = (len-2) * (len-3) * ... * 2 * 1 * -1
    // and the step before that is
    //  denom[len-3] = (len-3) * (len-4) * ... * 2 * 1 * -1 * -2
    //
    // i.e., for any i, the one before this will be derived from
    //  denom[i-1] = denom[i] * (len-i) / i
    //
    // that is, we only need to store
    // - the last denom for i = len-1, and
    // - the ratio between current step and fhe last step, which is the product of (len-i) / i from
    //   all previous steps and we store this product as a fraction number to reduce field
    //   divisions.

    let mut denom_up = field_factorial::<F>(len - 1);
    let mut denom_down = F::ONE;

    for (j, p_i) in p_iter_rev.enumerate() {
        let i = len - j - 1;
        res += prod * p_i * denom_down * (evals[i] * denom_up).invert().unwrap();

        // compute denom for the next step is current_denom * (len-i)/i
        if i != 0 {
            denom_up *= -F::from((j + 1) as u64);
            denom_down *= F::from(i as u64);
        }
    }
    res
}

/// compute the factorial(a) = 1 * 2 * ... * a
#[inline]
fn field_factorial<F: PrimeField>(a: usize) -> F {
    let mut res = F::ONE;
    for i in 2..=a {
        res *= F::from(i as u64);
    }
    res
}

#[cfg(test)]
mod test {
    use goldilocks::{Goldilocks as F, GoldilocksExt2 as E};
    use itertools::Itertools;
    use multilinear_extensions::virtual_poly::eq_eval;

    use crate::field_vec;

    use super::*;

    #[test]
    fn test_power_list() {
        let ele = F::from(3u64);
        let list = power_list(&ele, 4);
        assert_eq!(list, field_vec![F, 1, 3, 9, 27]);
    }

    #[test]
    fn test_grand_product() {
        let ele = field_vec![F, 2, 3, 4, 5];
        let expected = field_vec![F, 1, 2, 6, 24, 120];
        assert_eq!(grand_product(&ele), expected);
    }

    #[test]
    fn test_eq_vecs() {
        let points = [field_vec![E, 2, 3, 5], field_vec![E, 7, 11, 13]];
        let point_refs = points.iter().map(|p| p.as_slice()).collect_vec();

        let scalars = field_vec![E, 3, 5];

        let eq_evals = eq_vecs(point_refs.into_iter(), &scalars);

        let expected = vec![
            field_vec![E, -24, 48, 36, -72, 30, -60, -45, 90],
            field_vec![E, -3600, 4200, 3960, -4620, 3900, -4550, -4290, 5005],
        ];
        assert_eq!(eq_evals, expected);
    }

    #[test]
    fn test_eq_eval() {
        let xs = field_vec![E, 2, 3, 5];
        let ys = field_vec![E, 7, 11, 13];
        let expected = E::from(119780);
        assert_eq!(eq_eval(&xs, &ys), expected);
    }

    #[test]
    fn test_fix_variables_ext() {
        let base_mle = field_vec![F, 1, 2, 3, 4, 5, 6];
        let r = E::from(3u64);
        let expected = field_vec![E, 4, 6, 8];
        assert_eq!(fix_variables_ext(&base_mle, &r), expected);
    }

    #[test]
    fn test_fix_variables_inplace() {
        let mut ext_mle = field_vec![E, 1, 2, 3, 4, 5, 6];
        let r = E::from(3u64);
        fix_variables_inplace(&mut ext_mle, &r);
        let expected = field_vec![E, 4, 6, 8];
        assert_eq!(ext_mle[..3], expected);
    }

    #[test]
    fn test_interpolate_uni_poly() {
        // p(x) = x^3 + 2x^2 + 3x + 4
        let p_iter = field_vec![F, 4, 10, 26, 58].into_iter().rev();
        let eval_at = E::from(11);
        let expected = E::from(1610);
        assert_eq!(interpolate_uni_poly(p_iter, 4, eval_at), expected);
    }
}
