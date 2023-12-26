use goldilocks::SmallField;

pub(crate) fn ceil_log2(x: usize) -> usize {
    assert!(x > 0, "ceil_log2: x must be positive");
    // Calculate the number of bits in usize
    let usize_bits = std::mem::size_of::<usize>() * 8;
    usize_bits - (x - 1).leading_zeros() as usize
}

/// This is to compute a variant of eq(\mathbf{x}, \mathbf{y}) for indices in
/// [0, max_idx]. Specifically, it is an MLE of the following vector:
///     partial_eq_{\mathbf{x}}(\mathbf{y})
///         = \sum_{\mathbf{b}=0}^{max_idx} \prod_{i=0}^{n-1} (x_i y_i + (1 - x_i)(1 - y_i))
pub(crate) fn evaluate_partial_eq<F: SmallField>(max_idx: usize, a: &[F], b: &[F]) -> F {
    assert!(a.len() == b.len());

    // Compute running product of ( x_i y_i + (1 - x_i)(1 - y_i) )_{0 <= i <= n}
    let running_product = {
        let mut running_product = Vec::with_capacity(a.len() + 1);
        running_product.push(F::ONE);
        for i in 0..a.len() {
            let x = running_product[i] * (a[i] * b[i] + (F::ONE - a[i]) * (F::ONE - b[i]));
            running_product.push(x);
        }
        running_product
    };

    // Compute eq(a, b, num) = \prod_{ i = 0 }^{ m - 1 } ( a_i b_i num_i + (1 - a_i)(1 - b_i)(1 - num_i) )
    let compute_eq_ab_num = |a: &[F], b: &[F], num: usize, m: usize| -> F {
        let mut ans = F::ONE;
        for i in 0..m {
            let bit = F::from(((num >> i) & 1) as u64);
            ans = ans * (a[i] * b[i] * bit + (F::ONE - a[i]) * (F::ONE - b[i]) * (F::ONE - bit));
        }
        ans
    };

    // Here is an example of how this works:
    // Suppose max_idx = (110101)_2
    // Then ans = eq(a, b)
    //          - eq(11011, a[1..6], b[1..6])eq(a[0..1], b[0..1])
    //          - eq(111, a[3..6], b[3..6])eq(a[0..3], b[0..3])
    let mut ans = running_product[a.len()];
    for i in 0..a.len() {
        let bit = (max_idx >> i) & 1;
        if bit == 1 {
            continue;
        }
        ans -= running_product[i]
            * compute_eq_ab_num(
                &a[i..a.len()],
                &b[i..b.len()],
                (max_idx >> i) ^ 1,
                a.len() - i,
            );
    }
    ans
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
    fn test_evaluate_partial_eq() {
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
            assert_eq!(expected_ans, evaluate_partial_eq(max_idx, &a, &b));
        }

        {
            let max_idx = 1;
            let mut partial_eq_vec: Vec<_> = eq_vec[0..=max_idx].to_vec();
            partial_eq_vec.extend(vec![Goldilocks::ZERO; pow_n - max_idx - 1]);
            let expected_ans =
                DenseMultilinearExtension::from_evaluations_vec(n, partial_eq_vec).evaluate(&b);
            assert_eq!(expected_ans, evaluate_partial_eq(max_idx, &a, &b));
        }

        {
            let max_idx = 12;
            let mut partial_eq_vec: Vec<_> = eq_vec[0..=max_idx].to_vec();
            partial_eq_vec.extend(vec![Goldilocks::ZERO; pow_n - max_idx - 1]);
            let expected_ans =
                DenseMultilinearExtension::from_evaluations_vec(n, partial_eq_vec).evaluate(&b);
            assert_eq!(expected_ans, evaluate_partial_eq(max_idx, &a, &b));
        }

        {
            let max_idx = 1 << (n - 1) - 1;
            let mut partial_eq_vec: Vec<_> = eq_vec[0..=max_idx].to_vec();
            partial_eq_vec.extend(vec![Goldilocks::ZERO; pow_n - max_idx - 1]);
            let expected_ans =
                DenseMultilinearExtension::from_evaluations_vec(n, partial_eq_vec).evaluate(&b);
            assert_eq!(expected_ans, evaluate_partial_eq(max_idx, &a, &b));
        }

        {
            let max_idx = 1 << (n - 1);
            let mut partial_eq_vec: Vec<_> = eq_vec[0..=max_idx].to_vec();
            partial_eq_vec.extend(vec![Goldilocks::ZERO; pow_n - max_idx - 1]);
            let expected_ans =
                DenseMultilinearExtension::from_evaluations_vec(n, partial_eq_vec).evaluate(&b);
            assert_eq!(expected_ans, evaluate_partial_eq(max_idx, &a, &b));
        }
    }
}
