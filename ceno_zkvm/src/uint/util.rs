// calculate the maximum number of combinations for stars and bars formula
const fn max_combinations(degree: usize, num_cells: usize) -> usize {
    // compute factorial of n using usize
    const fn factorial(n: usize) -> usize {
        let mut result = 1;
        let mut i = 1;
        while i <= n {
            result *= i;
            i += 1;
        }
        result
    }
    // compute binomial coefficient "n choose k" using usize
    const fn binomial(n: usize, k: usize) -> usize {
        if k > n {
            return 0;
        }
        factorial(n) / (factorial(k) * factorial(n - k))
    }

    // Here we consider the sum as num_cells - 1 (max value each degree can take)
    let n = num_cells - 1;
    binomial(n + degree - 1, degree - 1)
}

// compute the max_word (max value of carry) for n limbs with each m overall bit, c limb bit multiplication
// for example, n = 2 means u1*u2, while n = 3 means u1*u2*u3
pub(crate) const fn max_carry_word_for_multiplication(n: usize, m: usize, c: usize) -> u64 {
    assert!(n > 1);
    assert!(m <= u64::BITS as usize);
    let num_cells = m.div_ceil(c);

    // calculate maximum multiplication value max_limb^(n)
    let mut max_mul_value = 1u128;
    let max_val = (1 << c) - 1;
    let mut i = 0;
    while i < n {
        max_mul_value *= max_val as u128;
        i += 1;
    }

    let max_mul_sum_value: u128 = max_mul_value * (max_combinations(n, num_cells)) as u128;
    let estimated_max_prev_carry_bound = max_mul_sum_value >> c;
    let max_carry_value = (max_mul_sum_value + estimated_max_prev_carry_bound) >> c;
    let max_carry_value_gt = max_carry_value + 1; // + 1 for less than comparison

    assert!(max_carry_value_gt <= u64::MAX as u128);
    max_carry_value_gt as u64
}

#[cfg(test)]
mod tests {
    use crate::uint::util::{max_carry_word_for_multiplication, max_combinations};

    #[test]
    fn test_max_combinations_degree() {
        // degree=1 is pure add, therefore only one term
        assert_eq!(1, max_combinations(1, 4));
        // for degree=2 mul, we have u[0]*v[3], u[1]*v[2], u[2]*v[1], u[3]*v[0]
        // thus 4 terms
        assert_eq!(4, max_combinations(2, 4));
    }

    #[test]
    fn test_max_word_of_limb_degree() {
        assert_eq!(131070, max_carry_word_for_multiplication(2, 32, 16));
    }
}
