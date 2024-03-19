use ff::Field;
use std::{iter, sync::Arc};

use ark_std::{end_timer, start_timer};
use goldilocks::SmallField;
use itertools::Itertools;
use multilinear_extensions::mle::DenseMultilinearExtension;
use rayon::prelude::*;

pub fn i64_to_field<F: SmallField>(x: i64) -> F {
    if x >= 0 {
        F::from(x as u64)
    } else {
        -F::from((-x) as u64)
    }
}

pub fn ceil_log2(x: usize) -> usize {
    assert!(x > 0, "ceil_log2: x must be positive");
    // Calculate the number of bits in usize
    let usize_bits = std::mem::size_of::<usize>() * 8;
    usize_bits - (x - 1).leading_zeros() as usize
}

/// This is to compute a segment indicator. Specifically, it is an MLE of the
/// following vector:
///     segment_{\mathbf{x}}
///         = \sum_{\mathbf{b}=min_idx + 1}^{2^n - 1} \prod_{i=0}^{n-1} (x_i b_i + (1 - x_i)(1 - b_i))
pub(crate) fn segment_eval_greater_than<F: SmallField>(min_idx: usize, a: &[F]) -> F {
    let running_product2 = {
        let mut running_product = vec![F::ZERO; a.len() + 1];
        running_product[a.len()] = F::ONE;
        for i in (0..a.len()).rev() {
            let bit = F::from(((min_idx >> i) & 1) as u64);
            running_product[i] =
                running_product[i + 1] * (a[i] * bit + (F::ONE - a[i]) * (F::ONE - bit));
        }
        running_product
    };
    // Here is an example of how this works:
    // Suppose min_idx = (110101)_2
    // Then ans = eq(11011, a[1..6])
    //          + eq(111, a[3..6], b[3..6])
    let mut ans = F::ZERO;
    for i in 0..a.len() {
        let bit = (min_idx >> i) & 1;
        if bit == 1 {
            continue;
        }
        ans += running_product2[i + 1] * a[i];
    }
    ans
}

/// This is to compute a variant of eq(\mathbf{x}, \mathbf{y}) for indices in
/// (min_idx, 2^n]. Specifically, it is an MLE of the following vector:
///     partial_eq_{\mathbf{x}}(\mathbf{y})
///         = \sum_{\mathbf{b}=min_idx + 1}^{2^n - 1} \prod_{i=0}^{n-1} (x_i y_i b_i + (1 - x_i)(1 - y_i)(1 - b_i))
#[allow(dead_code)]
pub(crate) fn eq_eval_greater_than<F: SmallField>(min_idx: usize, a: &[F], b: &[F]) -> F {
    assert!(a.len() >= b.len());
    // Compute running product of ( x_i y_i + (1 - x_i)(1 - y_i) )_{0 <= i <= n}
    let running_product = {
        let mut running_product = Vec::with_capacity(a.len() + 1);
        running_product.push(F::ONE);
        for i in 0..b.len() {
            let x = running_product[i] * (a[i] * b[i] + (F::ONE - a[i]) * (F::ONE - b[i]));
            running_product.push(x);
        }
        running_product
    };

    let running_product2 = {
        let mut running_product = vec![F::ZERO; b.len() + 1];
        running_product[b.len()] = F::ONE;
        for i in (0..b.len()).rev() {
            let bit = F::from(((min_idx >> i) & 1) as u64);
            running_product[i] = running_product[i + 1]
                * (a[i] * b[i] * bit + (F::ONE - a[i]) * (F::ONE - b[i]) * (F::ONE - bit));
        }
        running_product
    };

    // Here is an example of how this works:
    // Suppose min_idx = (110101)_2
    // Then ans = eq(11011, a[1..6], b[1..6])eq(a[0..1], b[0..1])
    //          + eq(111, a[3..6], b[3..6])eq(a[0..3], b[0..3])
    let mut ans = F::ZERO;
    for i in 0..b.len() {
        let bit = (min_idx >> i) & 1;
        if bit == 1 {
            continue;
        }
        ans += running_product[i] * running_product2[i + 1] * a[i] * b[i];
    }
    for i in b.len()..a.len() {
        ans *= F::ONE - a[i];
    }
    ans
}

/// This is to compute a variant of eq(\mathbf{x}, \mathbf{y}) for indices in
/// [0, max_idx]. Specifically, it is an MLE of the following vector:
///     partial_eq_{\mathbf{x}}(\mathbf{y})
///         = \sum_{\mathbf{b}=0}^{max_idx} \prod_{i=0}^{n-1} (x_i y_i b_i + (1 - x_i)(1 - y_i)(1 - b_i))
pub(crate) fn eq_eval_less_or_equal_than<F: SmallField>(max_idx: usize, a: &[F], b: &[F]) -> F {
    assert!(a.len() >= b.len());
    // Compute running product of ( x_i y_i + (1 - x_i)(1 - y_i) )_{0 <= i <= n}
    let running_product = {
        let mut running_product = Vec::with_capacity(b.len() + 1);
        running_product.push(F::ONE);
        for i in 0..b.len() {
            let x = running_product[i] * (a[i] * b[i] + (F::ONE - a[i]) * (F::ONE - b[i]));
            running_product.push(x);
        }
        running_product
    };

    let running_product2 = {
        let mut running_product = vec![F::ZERO; b.len() + 1];
        running_product[b.len()] = F::ONE;
        for i in (0..b.len()).rev() {
            let bit = F::from(((max_idx >> i) & 1) as u64);
            running_product[i] = running_product[i + 1]
                * (a[i] * b[i] * bit + (F::ONE - a[i]) * (F::ONE - b[i]) * (F::ONE - bit));
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
    for i in b.len()..a.len() {
        ans *= F::ONE - a[i];
    }
    ans
}

pub fn counter_eval<F: SmallField>(num_vars: usize, x: &[F]) -> F {
    assert_eq!(x.len(), num_vars, "invalid size of x");
    let mut ans = F::ZERO;
    for (i, &xi) in x.iter().enumerate() {
        ans += xi * F::from(1 << i)
    }
    ans
}

/// Reduce the number of variables of `self` by fixing the
/// `partial_point.len()` variables at `partial_point`.
pub fn fix_high_variables<F: SmallField>(
    poly: &Arc<DenseMultilinearExtension<F>>,
    partial_point: &[F],
) -> DenseMultilinearExtension<F> {
    // TODO: return error.
    assert!(
        partial_point.len() <= poly.num_vars,
        "invalid size of partial point"
    );
    let nv = poly.num_vars;
    let new_len = 1 << (nv - partial_point.len());
    let mut poly = poly.evaluations.to_vec();

    for i in 0..new_len {
        let partial_poly = DenseMultilinearExtension::from_evaluations_vec(
            partial_point.len(),
            poly[i..].iter().step_by(new_len).map(|x| *x).collect_vec(),
        );
        poly[i] = partial_poly.evaluate(&partial_point);
    }

    poly.resize(new_len, F::ZERO);
    DenseMultilinearExtension::from_evaluations_vec(nv - partial_point.len(), poly)
}

/// Evaluate eq polynomial for 3 random points.
pub fn eq3_eval<F: SmallField>(x: &[F], y: &[F], z: &[F]) -> F {
    assert_eq!(x.len(), y.len(), "x and y have different length");

    let start = start_timer!(|| "eq3_eval");
    let mut res = F::ONE;
    for ((&xi, &yi), &zi) in x.iter().zip(y.iter()).zip(z.iter()) {
        res *= xi * yi * zi + (F::ONE - xi) * (F::ONE - yi) * (F::ONE - zi);
    }
    end_timer!(start);
    res
}

/// Evaluate eq polynomial for 4 random points
pub fn eq4_eval<F: SmallField>(x: &[F], y: &[F], z: &[F], w: &[F]) -> F {
    assert_eq!(x.len(), y.len(), "x and y have different length");

    let start = start_timer!(|| "eq3_eval");
    let mut res = F::ONE;
    for (((&xi, &yi), &zi), &wi) in x.iter().zip(y.iter()).zip(z.iter()).zip(w.iter()) {
        res *= xi * yi * zi * wi + (F::ONE - xi) * (F::ONE - yi) * (F::ONE - zi) * (F::ONE - wi);
    }
    end_timer!(start);
    res
}

pub fn tensor_product<F: SmallField>(a: &[F], b: &[F]) -> Vec<F> {
    let mut res = vec![F::ZERO; a.len() * b.len()];
    for i in 0..a.len() {
        for j in 0..b.len() {
            res[i * b.len() + j] = a[i] * b[j];
        }
    }
    res
}

pub trait MultilinearExtensionFromVectors<F: SmallField> {
    fn mle(&self, lo_num_vars: usize, hi_num_vars: usize) -> Arc<DenseMultilinearExtension<F>>;
    fn original_mle(&self) -> Arc<DenseMultilinearExtension<F>>;
}

impl<F: SmallField> MultilinearExtensionFromVectors<F> for &[Vec<F::BaseField>] {
    fn mle(&self, lo_num_vars: usize, hi_num_vars: usize) -> Arc<DenseMultilinearExtension<F>> {
        let n_zeros = (1 << lo_num_vars) - self[0].len();
        let n_zero_vecs = (1 << hi_num_vars) - self.len();
        let vecs = self.to_vec();

        Arc::new(DenseMultilinearExtension::from_evaluations_vec(
            lo_num_vars + hi_num_vars,
            vecs.into_iter()
                .flat_map(|instance| {
                    instance
                        .into_iter()
                        .chain(iter::repeat(F::BaseField::ZERO).take(n_zeros))
                })
                .chain(vec![F::BaseField::ZERO; n_zero_vecs])
                .map(|x| F::from_base(&x))
                .collect_vec(),
        ))
    }
    fn original_mle(&self) -> Arc<DenseMultilinearExtension<F>> {
        let lo_num_vars = ceil_log2(self[0].len());
        let hi_num_vars = ceil_log2(self.len());
        let n_zeros = (1 << lo_num_vars) - self[0].len();
        let n_zero_vecs = (1 << hi_num_vars) - self.len();
        let vecs = self.to_vec();

        Arc::new(DenseMultilinearExtension::from_evaluations_vec(
            lo_num_vars + hi_num_vars,
            vecs.into_iter()
                .flat_map(|instance| {
                    instance
                        .into_iter()
                        .chain(iter::repeat(F::BaseField::ZERO).take(n_zeros))
                })
                .chain(vec![F::BaseField::ZERO; n_zero_vecs])
                .map(|x| F::from_base(&x))
                .collect_vec(),
        ))
    }
}

pub(crate) trait MatrixMLEColumnFirst<F: SmallField> {
    fn fix_row_col_first(&self, row_point_eq: &[F], col_num_vars: usize) -> Vec<F>;
    fn fix_row_col_first_with_scalar(
        &self,
        row_point_eq: &[F],
        col_num_vars: usize,
        scalar: &F,
    ) -> Vec<F>;
    fn eval_col_first(&self, row_point_eq: &[F], col_point_eq: &[F]) -> F;
}

impl<F: SmallField> MatrixMLEColumnFirst<F> for &[usize] {
    fn fix_row_col_first(&self, row_point_eq: &[F], col_num_vars: usize) -> Vec<F> {
        let mut ans = vec![F::ZERO; 1 << col_num_vars];
        for (col, &non_zero_row) in self.iter().enumerate() {
            ans[col] = row_point_eq[non_zero_row];
        }
        ans
    }

    fn fix_row_col_first_with_scalar(
        &self,
        row_point_eq: &[F],
        col_num_vars: usize,
        scalar: &F,
    ) -> Vec<F> {
        let mut ans = vec![F::ZERO; 1 << col_num_vars];
        for (col, &non_zero_row) in self.iter().enumerate() {
            ans[col] = row_point_eq[non_zero_row] * scalar;
        }
        ans
    }

    fn eval_col_first(&self, row_point_eq: &[F], col_point_eq: &[F]) -> F {
        self.iter()
            .enumerate()
            .fold(F::ZERO, |acc, (col, &non_zero_row)| {
                acc + row_point_eq[non_zero_row] * col_point_eq[col]
            })
    }
}

pub(crate) trait MatrixMLERowFirst<F: SmallField> {
    fn fix_row_row_first(&self, row_point_eq: &[F], col_num_vars: usize) -> Vec<F>;
    fn fix_row_row_first_with_scalar(
        &self,
        row_point_eq: &[F],
        col_num_vars: usize,
        scalar: &F,
    ) -> Vec<F>;
    fn eval_row_first(&self, row_point_eq: &[F], col_point_eq: &[F]) -> F;
}

impl<F: SmallField> MatrixMLERowFirst<F> for &[usize] {
    fn fix_row_row_first(&self, row_point_eq: &[F], col_num_vars: usize) -> Vec<F> {
        let mut ans = vec![F::ZERO; 1 << col_num_vars];
        for (row, &non_zero_col) in self.iter().enumerate() {
            ans[non_zero_col] = row_point_eq[row];
        }
        ans
    }

    fn fix_row_row_first_with_scalar(
        &self,
        row_point_eq: &[F],
        col_num_vars: usize,
        scalar: &F,
    ) -> Vec<F> {
        let mut ans = vec![F::ZERO; 1 << col_num_vars];
        for (row, &non_zero_col) in self.iter().enumerate() {
            ans[non_zero_col] = row_point_eq[row] * scalar;
        }
        ans
    }

    fn eval_row_first(&self, row_point_eq: &[F], col_point_eq: &[F]) -> F {
        self.iter()
            .enumerate()
            .fold(F::ZERO, |acc, (row, &non_zero_col)| {
                acc + row_point_eq[row] * col_point_eq[non_zero_col]
            })
    }
}

pub(crate) trait SubsetIndices<F: SmallField> {
    fn subset_eq_with_scalar(&self, eq: &[F], scalar: &F) -> Vec<F>;
    fn subset_eq_eval(&self, eq_1: &[F]) -> F;
    fn subset_eq2_eval(&self, eq_1: &[F], eq_2: &[F]) -> F;
}

impl<F: SmallField> SubsetIndices<F> for &[usize] {
    fn subset_eq_with_scalar(&self, eq: &[F], scalar: &F) -> Vec<F> {
        let mut ans = vec![F::ZERO; eq.len()];
        for &non_zero_i in self.iter() {
            ans[non_zero_i] = eq[non_zero_i] * scalar;
        }
        ans
    }
    fn subset_eq_eval(&self, eq_1: &[F]) -> F {
        self.iter()
            .fold(F::ZERO, |acc, &non_zero_i| acc + eq_1[non_zero_i])
    }
    fn subset_eq2_eval(&self, eq_1: &[F], eq_2: &[F]) -> F {
        self.iter().fold(F::ZERO, |acc, &non_zero_i| {
            acc + eq_1[non_zero_i] * eq_2[non_zero_i]
        })
    }
}

// test
#[cfg(test)]
mod test {
    use super::*;
    use ark_std::test_rng;
    use ff::Field;
    use goldilocks::Goldilocks;
    use itertools::Itertools;
    use multilinear_extensions::{mle::DenseMultilinearExtension, virtual_poly::build_eq_x_r_vec};

    #[test]
    fn test_ceil_log2() {
        assert_eq!(ceil_log2(1), 0);
        assert_eq!(ceil_log2(2), 1);
        assert_eq!(ceil_log2(3), 2);
        assert_eq!(ceil_log2(4), 2);
        assert_eq!(ceil_log2(5), 3);
        assert_eq!(ceil_log2(8), 3);
        assert_eq!(ceil_log2(9), 4);
        assert_eq!(ceil_log2(16), 4);
    }

    #[test]
    fn test_eq_eval_less_or_equal_than() {
        let mut rng = test_rng();
        let n = 5;
        let pow_n = 1 << n;
        let a = (0..n).map(|_| Goldilocks::random(&mut rng)).collect_vec();
        let b = (0..n).map(|_| Goldilocks::random(&mut rng)).collect_vec();

        let eq_vec = build_eq_x_r_vec(&a);

        {
            let max_idx = 0;
            let mut partial_eq_vec: Vec<_> = eq_vec[0..=max_idx].to_vec();
            partial_eq_vec.extend(vec![Goldilocks::ZERO; pow_n - max_idx - 1]);
            let expected_ans =
                DenseMultilinearExtension::from_evaluations_vec(n, partial_eq_vec).evaluate(&b);
            assert_eq!(expected_ans, eq_eval_less_or_equal_than(max_idx, &a, &b));
        }

        {
            let max_idx = 1;
            let mut partial_eq_vec: Vec<_> = eq_vec[0..=max_idx].to_vec();
            partial_eq_vec.extend(vec![Goldilocks::ZERO; pow_n - max_idx - 1]);
            let expected_ans =
                DenseMultilinearExtension::from_evaluations_vec(n, partial_eq_vec).evaluate(&b);
            assert_eq!(expected_ans, eq_eval_less_or_equal_than(max_idx, &a, &b));
        }

        {
            let max_idx = 12;
            let mut partial_eq_vec: Vec<_> = eq_vec[0..=max_idx].to_vec();
            partial_eq_vec.extend(vec![Goldilocks::ZERO; pow_n - max_idx - 1]);
            let expected_ans =
                DenseMultilinearExtension::from_evaluations_vec(n, partial_eq_vec).evaluate(&b);
            assert_eq!(expected_ans, eq_eval_less_or_equal_than(max_idx, &a, &b));
        }

        {
            let max_idx = 1 << (n - 1) - 1;
            let mut partial_eq_vec: Vec<_> = eq_vec[0..=max_idx].to_vec();
            partial_eq_vec.extend(vec![Goldilocks::ZERO; pow_n - max_idx - 1]);
            let expected_ans =
                DenseMultilinearExtension::from_evaluations_vec(n, partial_eq_vec).evaluate(&b);
            assert_eq!(expected_ans, eq_eval_less_or_equal_than(max_idx, &a, &b));
        }

        {
            let max_idx = 1 << (n - 1);
            let mut partial_eq_vec: Vec<_> = eq_vec[0..=max_idx].to_vec();
            partial_eq_vec.extend(vec![Goldilocks::ZERO; pow_n - max_idx - 1]);
            let expected_ans =
                DenseMultilinearExtension::from_evaluations_vec(n, partial_eq_vec).evaluate(&b);
            assert_eq!(expected_ans, eq_eval_less_or_equal_than(max_idx, &a, &b));
        }
    }

    #[test]
    fn test_fix_high_variables() {
        let poly = DenseMultilinearExtension::from_evaluations_vec(
            3,
            vec![
                Goldilocks::from(13),
                Goldilocks::from(97),
                Goldilocks::from(11),
                Goldilocks::from(101),
                Goldilocks::from(7),
                Goldilocks::from(103),
                Goldilocks::from(5),
                Goldilocks::from(107),
            ],
        );
        let poly = Arc::new(poly);

        let partial_point = vec![Goldilocks::from(3), Goldilocks::from(5)];

        let expected1 = DenseMultilinearExtension::from_evaluations_vec(
            2,
            vec![
                -Goldilocks::from(17),
                Goldilocks::from(127),
                -Goldilocks::from(19),
                Goldilocks::from(131),
            ],
        );
        let got1 = fix_high_variables(&poly, &partial_point[1..]);
        assert_eq!(got1, expected1);

        let expected2 = DenseMultilinearExtension::from_evaluations_vec(
            1,
            vec![-Goldilocks::from(23), Goldilocks::from(139)],
        );
        let got2: DenseMultilinearExtension<Goldilocks> = fix_high_variables(&poly, &partial_point);
        assert_eq!(got2, expected2);
    }

    #[test]
    fn test_counter_eval() {
        let vec = (0..(1 << 4)).map(|x| Goldilocks::from(x)).collect_vec();
        let point = vec![
            Goldilocks::from(97),
            Goldilocks::from(101),
            Goldilocks::from(23),
            Goldilocks::from(29),
        ];
        let got_value = counter_eval(4, &point);
        let poly = DenseMultilinearExtension::from_evaluations_vec(4, vec);
        let expected_value = poly.evaluate(&point);
        assert_eq!(got_value, expected_value);
    }
}
