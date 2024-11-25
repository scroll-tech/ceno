use std::{collections::HashMap, fmt::Display, hash::Hash};

use ff::Field;
use ff_ext::ExtensionField;
use goldilocks::SmallField;
use itertools::Itertools;
use multilinear_extensions::util::max_usable_threads;
use transcript::Transcript;

pub fn i64_to_base<F: SmallField>(x: i64) -> F {
    if x >= 0 {
        F::from(x as u64)
    } else {
        -F::from((-x) as u64)
    }
}

pub fn split_to_u8<T: From<u8>>(value: u32) -> Vec<T> {
    (0..(u32::BITS / 8))
        .scan(value, |acc, _| {
            let limb = ((*acc & 0xFF) as u8).into();
            *acc >>= 8;
            Some(limb)
        })
        .collect_vec()
}

/// Compile time evaluated minimum function
/// returns min(a, b)
pub(crate) const fn const_min(a: usize, b: usize) -> usize {
    if a <= b { a } else { b }
}

/// Assumes each limb < max_value
/// adds 1 to the big value, while preserving the above constraint
pub(crate) fn add_one_to_big_num<F: Field>(limb_modulo: F, limbs: &[F]) -> Vec<F> {
    let mut should_add_one = true;
    let mut result = vec![];

    for limb in limbs {
        let mut new_limb_value = *limb;
        if should_add_one {
            new_limb_value += F::ONE;
            if new_limb_value == limb_modulo {
                new_limb_value = F::ZERO;
            } else {
                should_add_one = false;
            }
        }
        result.push(new_limb_value);
    }

    result
}

/// derive challenge from transcript and return all pows result
pub fn get_challenge_pows<E: ExtensionField>(
    size: usize,
    transcript: &mut Transcript<E>,
) -> Vec<E> {
    // println!("alpha_pow");
    let alpha = transcript
        .get_and_append_challenge(b"combine subset evals")
        .elements;
    (0..size)
        .scan(E::ONE, |state, _| {
            let res = *state;
            *state *= alpha;
            Some(res)
        })
        .collect_vec()
}

// split single u64 value into W slices, each slice got C bits.
// all the rest slices will be filled with 0 if W x C > 64
pub fn u64vec<const W: usize, const C: usize>(x: u64) -> [u64; W] {
    assert!(C <= 64);
    let mut x = x;
    let mut ret = [0; W];
    for ret in ret.iter_mut() {
        *ret = x & ((1 << C) - 1);
        x >>= C;
    }
    ret
}

/// we expect each thread at least take 4 num of sumcheck variables
/// return optimal num threads to run sumcheck
pub fn optimal_sumcheck_threads(num_vars: usize) -> usize {
    let expected_max_threads = max_usable_threads();
    let min_numvar_per_thread = 4;
    if num_vars <= min_numvar_per_thread {
        1
    } else {
        (1 << (num_vars - min_numvar_per_thread)).min(expected_max_threads)
    }
}

/// TODO this is copy from gkr crate
/// including gkr crate after gkr clippy fix
///
/// This is to compute a variant of eq(\mathbf{x}, \mathbf{y}) for indices in
/// [0..=max_idx]. Specifically, it is an MLE of the following vector:
///     partial_eq_{\mathbf{x}}(\mathbf{y})
///         = \sum_{\mathbf{b}=0}^{max_idx} \prod_{i=0}^{n-1} (x_i y_i b_i + (1 - x_i)(1 - y_i)(1 - b_i))
pub(crate) fn eq_eval_less_or_equal_than<E: ExtensionField>(max_idx: usize, a: &[E], b: &[E]) -> E {
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
            let bit = E::from(((max_idx >> i) & 1) as u64);
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
        ans *= E::ONE - v;
    }
    ans
}

/// evaluate MLE M(x0, x1, x2, ..., xn) address vector with it evaluation format a*[0, 1, 2, 3, ....2^n-1] + b
/// on r = [r0, r1, r2, ...rn] succintly
/// a, b, is constant
/// the result M(r0, r1,... rn) = r0 + r1 * 2 + r2 * 2^2 + .... rn * 2^n
pub fn eval_wellform_address_vec<E: ExtensionField>(offset: u64, scaled: u64, r: &[E]) -> E {
    let (offset, scaled) = (E::from(offset), E::from(scaled));
    offset
        + scaled
            * r.iter()
                .scan(E::ONE, |state, x| {
                    let result = *x * *state;
                    *state *= E::from(2); // Update the state for the next power of 2
                    Some(result)
                })
                .sum::<E>()
}

/// transpose 2d vector without clone
pub fn transpose<T>(v: Vec<Vec<T>>) -> Vec<Vec<T>> {
    assert!(!v.is_empty());
    let len = v[0].len();
    let mut iters: Vec<_> = v.into_iter().map(|n| n.into_iter()).collect();
    (0..len)
        .map(|_| {
            iters
                .iter_mut()
                .map(|n| n.next().unwrap())
                .collect::<Vec<T>>()
        })
        .collect()
}

/// get next power of 2 instance with minimal size 2
pub fn next_pow2_instance_padding(num_instance: usize) -> usize {
    num_instance.next_power_of_two().max(2)
}

pub fn display_hashmap<K: Display, V: Display>(map: &HashMap<K, V>) -> String {
    format!(
        "[{}]",
        map.iter().map(|(k, v)| format!("{k}: {v}")).join(",")
    )
}

pub fn merge_frequency_tables<K: Hash + std::cmp::Eq>(
    lhs: HashMap<K, usize>,
    rhs: HashMap<K, usize>,
) -> HashMap<K, usize> {
    let mut ret = lhs;
    rhs.into_iter().for_each(|(key, value)| {
        *ret.entry(key).or_insert(0) += value;
    });
    ret
}
