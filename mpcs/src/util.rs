pub mod arithmetic;
pub mod code;
pub mod expression;
pub mod ff_255;
pub mod goldilocks_mont;
pub mod hash;
pub mod mersenne_61_mont;
pub mod new_fields;
pub mod parallel;
pub mod plonky2_util;
mod timer;
pub mod transcript;
use ff::PrimeField;
pub use itertools::{chain, izip, Itertools};
pub use num_bigint::BigUint;
pub use serde::{de::DeserializeOwned, Deserialize, Deserializer, Serialize, Serializer};
pub use timer::{end_timer, start_timer, start_unit_timer};
pub mod merkle_tree;

pub fn log2_strict(n: usize) -> usize {
    let res = n.trailing_zeros();
    assert!(n.wrapping_shr(res) == 1, "Not a power of two: {n}");
    // Tell the optimizer about the semantics of `log2_strict`. i.e. it can replace `n` with
    // `1 << res` and vice versa.

    res as usize
}

pub fn field_to_usize<F: PrimeField>(x: &F, n: usize) -> usize {
    let x_rep = (*x).to_repr();
    let mut x: &[u8] = x_rep.as_ref();
    let (int_bytes, _) = x.split_at(std::mem::size_of::<u32>());
    let x_int: u32 = u32::from_be_bytes(int_bytes.try_into().unwrap());
    ((x_int as usize) % n).into()
}

macro_rules! izip_eq {
    (@closure $p:pat => $tup:expr) => {
        |$p| $tup
    };
    (@closure $p:pat => ($($tup:tt)*) , $_iter:expr $(, $tail:expr)*) => {
        $crate::util::izip_eq!(@closure ($p, b) => ($($tup)*, b) $(, $tail)*)
    };
    ($first:expr $(,)*) => {
        itertools::__std_iter::IntoIterator::into_iter($first)
    };
    ($first:expr, $second:expr $(,)*) => {
        $crate::util::izip_eq!($first).zip_eq($second)
    };
    ($first:expr $(, $rest:expr)* $(,)*) => {
        $crate::util::izip_eq!($first)
            $(.zip_eq($rest))*
            .map($crate::util::izip_eq!(@closure a => (a) $(, $rest)*))
    };
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

pub(crate) use {impl_index, izip_eq};

#[cfg(any(test, feature = "benchmark"))]
pub mod test {
    use crate::util::arithmetic::Field;
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
}
