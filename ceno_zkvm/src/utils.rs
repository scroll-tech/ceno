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
pub fn eval_stacked_wellform_address_vec<E: ExtensionField>(r: &[E]) -> E {
    if r.len() < 2 {
        return E::ZERO;
    }
    eval_stacked_wellform_address_vec(&r[..r.len() - 1])
        + eval_wellform_address_vec(0, 1, &r[..r.len() - 1], false) * (E::ONE - r[r.len() - 1])
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
