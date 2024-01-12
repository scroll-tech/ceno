pub mod arithmetic;
pub mod expression;
pub mod hash;
pub mod parallel;
pub mod plonky2_util;
mod timer;
pub mod transcript;
use ff::PrimeField;
use itertools::{izip, Itertools};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
pub use timer::{end_timer, start_timer, start_unit_timer};
pub mod merkle_tree;

pub fn log2_strict(n: usize) -> usize {
    let res = n.trailing_zeros();
    assert!(n.wrapping_shr(res) == 1, "Not a power of two: {n}");
    // Tell the optimizer about the semantics of `log2_strict`. i.e. it can replace `n` with
    // `1 << res` and vice versa.

    res as usize
}

pub fn field_to_usize<F: PrimeField>(x: &F, n: Option<usize>) -> usize {
    let x_rep = (*x).to_repr();
    let x: &[u8] = x_rep.as_ref();
    let (int_bytes, _) = x.split_at(std::mem::size_of::<u32>());
    let x_int: u32 = u32::from_be_bytes(int_bytes.try_into().unwrap());
    if let Some(n) = n {
        ((x_int as usize) % n).into()
    } else {
        x_int as usize
    }
}

/// PrimeField does not have a to_u32 method, so field_to_usize(F::from(k))
/// does not necessarily return k. So let u32_to_field be the reverse of
/// field_to_usize.
pub fn u32_to_field<F: PrimeField>(x: u32) -> F {
    let mut repr = F::Repr::default();
    let bytes = x.to_be_bytes();
    let desired_length = repr.as_mut().len();
    if desired_length > bytes.len() {
        repr.as_mut()[..bytes.len()].copy_from_slice(&bytes);
    } else {
        repr.as_mut().copy_from_slice(&bytes[..desired_length]);
    }
    F::from_repr(repr).unwrap()
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
    type F = halo2_curves::bn256::Fr;
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
        assert_eq!(field_to_usize(&u32_to_field::<F>(1u32), None), 1);
        assert_eq!(field_to_usize(&u32_to_field::<F>(10u32), None), 10);
    }
}
