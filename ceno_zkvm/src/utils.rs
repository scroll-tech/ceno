use ff_ext::ExtensionField;
use itertools::Itertools;
use transcript::Transcript;

pub(crate) fn i64_to_base_field<E: ExtensionField>(x: i64) -> E::BaseField {
    if x >= 0 {
        E::BaseField::from(x as u64)
    } else {
        -E::BaseField::from((-x) as u64)
    }
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
    for i in 0..ret.len() {
        ret[i] = x & ((1 << C) - 1);
        x >>= C;
    }
    ret
}

/// we expect each thread at least take 4 num of sumcheck variables
/// return optimal num threads to run sumcheck
pub fn proper_num_threads(num_vars: usize, expected_max_threads: usize) -> usize {
    let min_numvar_per_thread = 4;
    if num_vars <= min_numvar_per_thread {
        return 1;
    } else {
        (1 << (num_vars - min_numvar_per_thread)).min(expected_max_threads)
    }
}

// evaluate sel(r) for raw MLE [1, 1,...1, 0, 0, 0] where the length of [1] equal to #num_instance
pub fn sel_eval<E: ExtensionField>(num_instances: usize, r: &[E]) -> E {
    assert!(num_instances > 0);
    E::ONE - segment_eval_greater_than(num_instances - 1, &r)
}

/// This is to compute a segment indicator. Specifically, it is an MLE of the
/// following vector:
///     segment_{\mathbf{x}}
///         = \sum_{\mathbf{b}=min_idx + 1}^{2^n - 1} \prod_{i=0}^{n-1} (x_i b_i + (1 - x_i)(1 - b_i))
pub(crate) fn segment_eval_greater_than<E: ExtensionField>(min_idx: usize, a: &[E]) -> E {
    let running_product2 = {
        let mut running_product = vec![E::ZERO; a.len() + 1];
        running_product[a.len()] = E::ONE;
        for i in (0..a.len()).rev() {
            let bit = E::from(((min_idx >> i) & 1) as u64);
            running_product[i] =
                running_product[i + 1] * (a[i] * bit + (E::ONE - a[i]) * (E::ONE - bit));
        }
        running_product
    };
    // Here is an example of how this works:
    // Suppose min_idx = (110101)_2
    // Then ans = eq(11011, a[1..6])
    //          + eq(111, a[3..6], b[3..6])
    let mut ans = E::ZERO;
    for i in 0..a.len() {
        let bit = (min_idx >> i) & 1;
        if bit == 1 {
            continue;
        }
        ans += running_product2[i + 1] * a[i];
    }
    ans
}
