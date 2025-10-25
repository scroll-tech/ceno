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
