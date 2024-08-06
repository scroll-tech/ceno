use ff_ext::ExtensionField;
use itertools::Itertools;
use multilinear_extensions::util::ceil_log2;
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
