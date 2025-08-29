use std::{
    collections::HashMap,
    fmt::Display,
    hash::Hash,
    panic::{self, PanicHookInfo},
};

use ff_ext::ExtensionField;
pub use gkr_iop::utils::i64_to_base;
use itertools::Itertools;
use p3::field::Field;

#[cfg(feature = "u16limb_circuit")]
use crate::instructions::riscv::constants::UINT_LIMBS;
#[cfg(feature = "u16limb_circuit")]
use multilinear_extensions::Expression;
#[cfg(feature = "u16limb_circuit")]
use multilinear_extensions::ToExpr;
#[cfg(feature = "u16limb_circuit")]
use p3::field::FieldAlgebra;

pub fn split_to_u8<T: From<u8>>(value: u32) -> Vec<T> {
    (0..(u32::BITS / 8))
        .scan(value, |acc, _| {
            let limb = ((*acc & 0xFF) as u8).into();
            *acc >>= 8;
            Some(limb)
        })
        .collect_vec()
}

#[allow(dead_code)]
pub fn split_to_limb<T: From<u8>, const LIMB_BITS: usize>(value: u32) -> Vec<T> {
    (0..(u32::BITS as usize / LIMB_BITS))
        .scan(value, |acc, _| {
            let limb = ((*acc & ((1 << LIMB_BITS) - 1)) as u8).into();
            *acc >>= LIMB_BITS;
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

/// Temporarily override the panic hook
///
/// We restore the original hook after we are done.
pub fn with_panic_hook<F, R>(
    hook: Box<dyn Fn(&PanicHookInfo<'_>) + Sync + Send + 'static>,
    f: F,
) -> R
where
    F: FnOnce() -> R,
{
    // Save the current panic hook
    let original_hook = panic::take_hook();

    // Set the new panic hook
    panic::set_hook(hook);

    let result = f();

    // Restore the original panic hook
    panic::set_hook(original_hook);

    result
}

#[cfg(feature = "u16limb_circuit")]
pub fn imm_sign_extend_circuit<E: ExtensionField>(
    require_signed: bool,
    is_signed: Expression<E>,
    imm: Expression<E>,
) -> [Expression<E>; UINT_LIMBS] {
    if !require_signed {
        [imm, E::BaseField::ZERO.expr()]
    } else {
        [
            imm,
            is_signed * E::BaseField::from_canonical_u16(0xffff).expr(),
        ]
    }
}

#[cfg(feature = "u16limb_circuit")]
#[inline(always)]
pub fn imm_sign_extend(is_signed_extension: bool, imm: i16) -> [u16; UINT_LIMBS] {
    #[allow(clippy::if_same_then_else)]
    if !is_signed_extension {
        [imm as u16, 0]
    } else if imm >= 0 {
        [imm as u16, 0u16]
    } else {
        [imm as u16, 0xffff]
    }
}

#[cfg(all(feature = "jemalloc", unix, not(test)))]
pub fn print_allocated_bytes() {
    use tikv_jemalloc_ctl::{epoch, stats};

    // Advance the epoch to refresh the stats
    let e = epoch::mib().unwrap();
    e.advance().unwrap();

    // Read allocated bytes
    let allocated = stats::allocated::read().unwrap();
    tracing::info!("jemalloc total allocated bytes: {}", allocated);
}

#[cfg(test)]
mod tests {
    use std::iter;

    use ff_ext::GoldilocksExt2;
    use p3::field::FieldAlgebra;

    use super::*;

    type E = GoldilocksExt2;
    use multilinear_extensions::mle::MultilinearExtension;

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
