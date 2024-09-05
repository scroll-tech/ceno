extern crate core;

pub(crate) mod constants;
pub(crate) mod digest;
pub(crate) mod poseidon;
mod poseidon_goldilocks;
pub(crate) mod poseidon_hash;
pub(crate) mod poseidon_permutation;

use crate::poseidon::Poseidon;
use goldilocks::{ExtensionField, SmallField};
use serde::Serialize;

// helpers
#[inline(always)]
const fn add_u160_u128((x_lo, x_hi): (u128, u32), y: u128) -> (u128, u32) {
    let (res_lo, over) = x_lo.overflowing_add(y);
    let res_hi = x_hi + (over as u32);
    (res_lo, res_hi)
}

#[inline(always)]
fn reduce_u160<F: Poseidon>((n_lo, n_hi): (u128, u32)) -> F {
    let n_lo_hi = (n_lo >> 64) as u64;
    let n_lo_lo = n_lo as u64;
    let reduced_hi: u64 = F::from_noncanonical_u96(n_lo_hi, n_hi).to_noncanonical_u64();
    let reduced128: u128 = ((reduced_hi as u128) << 64) + (n_lo_lo as u128);
    F::from_noncanonical_u128(reduced128)
}
