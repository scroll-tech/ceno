use ff::Field;
use ff_ext::ExtensionField;
use goldilocks::SmallField;
use itertools::Itertools;
use std::mem;
use transcript::Transcript;

/// convert ext field element to u64, assume it is inside the range
#[allow(dead_code)]
pub fn ext_to_u64<E: ExtensionField>(x: &E) -> u64 {
    let bases = x.as_bases();
    bases[0].to_canonical_u64()
}

pub fn i64_to_base<F: SmallField>(x: i64) -> F {
    if x >= 0 {
        F::from(x as u64)
    } else {
        -F::from((-x) as u64)
    }
}

/// This is helper function to convert witness of u8 limb into u16 limb
/// TODO: need a better way to keep consistency of VALUE_BIT_WIDTH
#[allow(dead_code)]
pub fn limb_u8_to_u16(input: &[u8]) -> Vec<u16> {
    input
        .chunks(2)
        .map(|chunk| {
            let low = chunk[0] as u16;
            let high = if chunk.len() > 1 { chunk[1] as u16 } else { 0 };
            high * 256 + low
        })
        .collect()
}

pub fn split_to_u8<T: Into<u64>>(value: T) -> Vec<u8> {
    let value: u64 = value.into(); // Convert to u64 for generality
    let limbs: usize = {
        let u8_bytes = (u16::BITS / 8) as usize;
        mem::size_of::<T>() / u8_bytes
    };
    (0..limbs)
        .scan(value, |acc, _| {
            let limb = (*acc & 0xFF) as u8;
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

#[allow(dead_code)]
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
    for ret in ret.iter_mut() {
        *ret = x & ((1 << C) - 1);
        x >>= C;
    }
    ret
}

/// we expect each thread at least take 4 num of sumcheck variables
/// return optimal num threads to run sumcheck
pub fn proper_num_threads(num_vars: usize, expected_max_threads: usize) -> usize {
    let min_numvar_per_thread = 4;
    if num_vars <= min_numvar_per_thread {
        1
    } else {
        (1 << (num_vars - min_numvar_per_thread)).min(expected_max_threads)
    }
}

// evaluate sel(r) for raw MLE where the length of [1] equal to #num_instance
pub fn sel_eval<E: ExtensionField>(num_instances: usize, r: &[E]) -> E {
    assert!(num_instances > 0 && !r.is_empty());
    // e.g. lagrange basis with boolean hypercube n=3 can be viewed as binary tree
    //         root
    //       /     \
    //      / \   / \
    //     /\ /\ /\ /\
    // with 2^n leafs as [eq(r, 000), eq(r, 001), eq(r, 010), eq(r, 011), eq(r, 100), eq(r, 101), eq(r, 110), eq(r, 111)]

    // giving a selector for evaluations e.g. [1, 1, 1, 1, 1, 1, 0, 0]
    // it's equivalent that we only wanna sum up to 6th terms, in index position should be 6-1 = 5 = (101)_2
    //       /     \
    //      / \   / \
    //     /\ /\ /\ /\
    //     11 11 11 00

    // which algorithms can be view as traversing (101)_2 from msb to lsb order and check bit ?= 1
    // if bit = 1 we need to sum all the left sub-tree, otherwise we do nothing
    // and finally, add the leaf term to final sum

    // sum for all lagrange terms = 1 = (1-r2 + r2) x (1-r1 + r1) x (1-r0 + r0)...
    // for left sub-tree terms of root, it's equivalent to (1-r2) x (1-r1 + r1) x (1-r0 + r0) = (1-r2)
    // observe from the rule, the left sub-tree of any intermediate node is eq(r.rev()[..depth], bit_patterns) x (1-r[depth]) x 1
    // bit_patterns := bit traverse from root to this node

    // so for the above case
    // sum
    // = (1-r2) -> left sub-tree from root
    // + 0 -> goes to left, therefore do nothing
    // + (r2) x (1-r1) x (1-r0) -> goes to right, therefore add left sub-tree
    // + (r2) x (1-r1) x (r0) -> final term

    let mut acc = E::ONE;
    let mut sum = E::ZERO;

    let (bits, _) = (0..r.len()).fold((vec![], num_instances - 1), |(mut bits, mut cur_num), _| {
        let bit = cur_num & 1;
        bits.push(bit);
        cur_num >>= 1;

        (bits, cur_num)
    });

    for (r, bit) in r.iter().rev().zip(bits.iter().rev()) {
        if *bit == 1 {
            // push left sub tree
            sum += acc * (E::ONE - r);
            // acc
            acc *= r
        } else {
            acc *= E::ONE - r;
        }
    }
    sum += acc; // final term
    sum
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

#[cfg(test)]
mod tests {
    use goldilocks::GoldilocksExt2;

    use crate::utils::sel_eval;
    use ff::Field;

    #[test]
    fn test_sel_eval() {
        type E = GoldilocksExt2;
        let ra = [E::from(2), E::from(3), E::from(4)]; // r2, r1, r0

        assert_eq!(
            sel_eval(6, &ra),
            (E::from(1) - E::from(4)) // 1-r0
                + (E::from(4)) * (E::ONE - E::from(3)) * (E::ONE - E::from(2)) // (r0) * (1-r1) * (1-r2)
                + (E::from(4)) * (E::ONE - E::from(3)) * (E::from(2)) // (r0) * (1-r1) * (r2)
        );

        assert_eq!(
            sel_eval(5, &ra),
            (E::from(1) - E::from(4)) // 1-r0
                + (E::from(4)) * (E::ONE - E::from(3)) * (E::ONE - E::from(2)) /* (r0) * (1-r1) * (1-r2) */
        );

        // assert_eq!(sel_eval(7, &ra), sel_eval_ori(7, &ra));
    }
}
