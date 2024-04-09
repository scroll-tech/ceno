pub mod arithmetic;
pub mod expression;
pub mod hash;
pub mod parallel;
pub mod plonky2_util;
mod timer;
pub mod transcript;
use ff::PrimeField;
use goldilocks::SmallField;
use itertools::{izip, Itertools};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
pub use timer::start_unit_timer;
pub mod merkle_tree;

#[cfg(feature = "print-trace")]
use ark_std::{end_timer as ark_end_timer, start_timer as ark_start_timer};
#[cfg(feature = "print-trace")]
#[macro_export]
macro_rules! start_timer {
    ($msg: expr) => {
        ark_start_timer!($msg)
    };
}

#[cfg(not(feature = "print-trace"))]
#[macro_export]
macro_rules! start_timer {
    ($msg: expr) => {{
        $msg
    }};
}

#[cfg(feature = "print-trace")]
#[macro_export]
macro_rules! end_timer {
    ($time: expr) => {
        #![feature(print-trace)]
        ark_end_timer!($time);
    };

    ($time:expr, $msg:expr) => {
        #![feature(print-trace)]
        ark_end_timer!($time, $msg);
    };
}

#[cfg(not(feature = "print-trace"))]
#[macro_export]
macro_rules! end_timer {
    ($time: expr) => {
        let _ = $time;
    };
}

pub fn log2_strict(n: usize) -> usize {
    let res = n.trailing_zeros();
    assert!(n.wrapping_shr(res) == 1, "Not a power of two: {n}");
    // Tell the optimizer about the semantics of `log2_strict`. i.e. it can replace `n` with
    // `1 << res` and vice versa.

    res as usize
}

pub fn field_to_usize<F: SmallField>(x: &F) -> usize {
    x.to_canonical_u64_vec()[0] as usize
}

pub fn u32_to_field<F: SmallField>(x: u32) -> F {
    F::from(x as u64)
}

pub trait BitIndex {
    fn nth_bit(&self, nth: usize) -> bool;
}

impl BitIndex for usize {
    fn nth_bit(&self, nth: usize) -> bool {
        (self >> nth) & 1 == 1
    }
}

/// How many bytes are required to store n field elements?
pub fn num_of_bytes<F: PrimeField>(n: usize) -> usize {
    (F::NUM_BITS as usize).next_power_of_two() * n / 8
}

macro_rules! impl_index {
    (@ $name:ty, $field:tt, [$($range:ty => $output:ty),*$(,)?]) => {
        $(
            impl<F> std::ops::Index<$range> for $name {
                type Output = $output;

                fn index(&self, index: $range) -> &$output {
                    self.$field.index(index)
                }
            }

            impl<F> std::ops::IndexMut<$range> for $name {
                fn index_mut(&mut self, index: $range) -> &mut $output {
                    self.$field.index_mut(index)
                }
            }
        )*
    };
    (@ $name:ty, $field:tt) => {
        impl_index!(
            @ $name, $field,
            [
                usize => F,
                std::ops::Range<usize> => [F],
                std::ops::RangeFrom<usize> => [F],
                std::ops::RangeFull => [F],
                std::ops::RangeInclusive<usize> => [F],
                std::ops::RangeTo<usize> => [F],
                std::ops::RangeToInclusive<usize> => [F],
            ]
        );
    };
    ($name:ident, $field:tt) => {
        impl_index!(@ $name<F>, $field);
    };
}

pub(crate) use impl_index;

#[cfg(any(test, feature = "benchmark"))]
pub mod test {
    use crate::util::{field_to_usize, u32_to_field};
    use ff::Field;
    type F = goldilocks::Goldilocks;
    use rand::{
        rngs::{OsRng, StdRng},
        CryptoRng, RngCore, SeedableRng,
    };
    use std::{array, iter, ops::Range};

    pub fn std_rng() -> impl RngCore + CryptoRng {
        StdRng::from_seed(Default::default())
    }

    pub fn seeded_std_rng() -> impl RngCore + CryptoRng {
        StdRng::seed_from_u64(OsRng.next_u64())
    }

    pub fn rand_idx(range: Range<usize>, mut rng: impl RngCore) -> usize {
        range.start + (rng.next_u64() as usize % (range.end - range.start))
    }

    pub fn rand_array<F: Field, const N: usize>(mut rng: impl RngCore) -> [F; N] {
        array::from_fn(|_| F::random(&mut rng))
    }

    pub fn rand_vec<F: Field>(n: usize, mut rng: impl RngCore) -> Vec<F> {
        iter::repeat_with(|| F::random(&mut rng)).take(n).collect()
    }

    #[test]
    pub fn test_field_transform() {
        assert_eq!(F::from(2) * F::from(3), F::from(6));
        assert_eq!(field_to_usize(&u32_to_field::<F>(1u32)), 1);
        assert_eq!(field_to_usize(&u32_to_field::<F>(10u32)), 10);
    }
}
