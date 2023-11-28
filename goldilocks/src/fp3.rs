//! This module implements degree 3 Goldilocks extension field mod x^3-x-1

use crate::Goldilocks;
use core::iter::{Product, Sum};
use core::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};
use ff::{Field, PrimeField};
use rand_core::RngCore;
use serde::{Deserialize, Serialize};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption};

/// Degree 3 Goldilocks extension field mod x^3-x-1
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GoldilocksExt3(pub [Goldilocks; 3]);

/// For a = (a1, a2, a3) and b = (b1, b2, b3)
/// The multiplication is define as
/// c := a * b = a(x) * b(x) % (x^3-x-1)
///    = x^2*a3*b1 + x^2*a2*b2 + x^2*a1*b3 + x^2*a3*b3
///    + x*a2*b1 + x*a1*b2 + x*a3*b2 + x*a2*b3 + x*a3*b3
///    + a1*b1 + a3*b2 + a2*b3
/// This requires 9 multiplications and 6 1 additions
fn mul_internal(a: &GoldilocksExt3, b: &GoldilocksExt3) -> GoldilocksExt3 {
    // todo: optimizations?
    let a1b1 = a.0[0] * b.0[0];
    let a1b2 = a.0[0] * b.0[1];
    let a1b3 = a.0[0] * b.0[2];
    let a2b1 = a.0[1] * b.0[0];
    let a2b2 = a.0[1] * b.0[1];
    let a2b3 = a.0[1] * b.0[2];
    let a3b1 = a.0[2] * b.0[0];
    let a3b2 = a.0[2] * b.0[1];
    let a3b3 = a.0[2] * b.0[2];

    let c1 = a1b1 + a3b2 + a2b3;
    let c2 = a2b1 + a1b2 + a2b3 + a3b2 + a3b3;
    let c3 = a3b1 + a2b2 + a1b3 + a3b3;
    GoldilocksExt3([c1, c2, c3])
}

impl GoldilocksExt3 {
    fn to_canonical_u64_array(&self) -> [u64; 3] {
        [
            self.0[0].to_canonical_u64(),
            self.0[1].to_canonical_u64(),
            self.0[2].to_canonical_u64(),
        ]
    }
}

impl Field for GoldilocksExt3 {
    /// The zero element of the field, the additive identity.
    const ZERO: Self = Self([Goldilocks::ZERO; 3]);

    /// The one element of the field, the multiplicative identity.
    const ONE: Self = Self([Goldilocks::ONE, Goldilocks::ZERO, Goldilocks::ZERO]);

    /// Returns an element chosen uniformly at random using a user-provided RNG.
    /// Note: this sampler is not constant time!
    fn random(mut rng: impl RngCore) -> Self {
        let a1 = Goldilocks::random(&mut rng);
        let a2 = Goldilocks::random(&mut rng);
        let a3 = Goldilocks::random(&mut rng);

        Self([a1, a2, a3])
    }

    /// Squares this element.
    #[must_use]
    fn square(&self) -> Self {
        *self * *self
    }

    /// Cubes this element.
    #[must_use]
    fn cube(&self) -> Self {
        self.square() * self
    }

    /// Doubles this element.
    #[must_use]
    fn double(&self) -> Self {
        *self + *self
    }

    /// Computes the multiplicative inverse of this element,
    /// failing if the element is zero.
    fn invert(&self) -> CtOption<Self> {
        unimplemented!()
    }

    /// Returns the square root of the field element, if it is
    /// quadratic residue.
    fn sqrt(&self) -> CtOption<Self> {
        unimplemented!()
    }

    /// Computes:
    ///
    /// - $(\textsf{true}, \sqrt{\textsf{num}/\textsf{div}})$, if $\textsf{num}$ and
    ///   $\textsf{div}$ are nonzero and $\textsf{num}/\textsf{div}$ is a square in the
    ///   field;
    /// - $(\textsf{true}, 0)$, if $\textsf{num}$ is zero;
    /// - $(\textsf{false}, 0)$, if $\textsf{num}$ is nonzero and $\textsf{div}$ is zero;
    /// - $(\textsf{false}, \sqrt{G_S \cdot \textsf{num}/\textsf{div}})$, if
    ///   $\textsf{num}$ and $\textsf{div}$ are nonzero and $\textsf{num}/\textsf{div}$ is
    ///   a nonsquare in the field;
    ///
    /// where $G_S$ is a non-square.
    ///
    /// # Warnings
    ///
    /// - The choice of root from `sqrt` is unspecified.
    /// - The value of $G_S$ is unspecified, and cannot be assumed to have any specific
    ///   value in a generic context.
    fn sqrt_ratio(_: &Self, _: &Self) -> (Choice, Self) {
        unimplemented!()
    }
}

impl ConditionallySelectable for GoldilocksExt3 {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self([
            Goldilocks::conditional_select(&a.0[0], &b.0[0], choice),
            Goldilocks::conditional_select(&a.0[1], &b.0[1], choice),
            Goldilocks::conditional_select(&a.0[2], &b.0[2], choice),
        ])
    }
}

impl ConstantTimeEq for GoldilocksExt3 {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.to_canonical_u64_array()
            .ct_eq(&other.to_canonical_u64_array())
    }
}
impl Neg for GoldilocksExt3 {
    type Output = Self;

    #[inline]
    fn neg(self) -> Self {
        Self([-self.0[0], -self.0[1], -self.0[2]])
    }
}

impl Add for GoldilocksExt3 {
    type Output = Self;

    #[inline]
    fn add(self, rhs: Self) -> Self::Output {
        Self([
            self.0[0] + rhs.0[0],
            self.0[1] + rhs.0[1],
            self.0[2] + rhs.0[2],
        ])
    }
}

impl<'a> Add<&'a GoldilocksExt3> for GoldilocksExt3 {
    type Output = Self;

    #[inline]
    fn add(self, rhs: &'a GoldilocksExt3) -> Self::Output {
        self + *rhs
    }
}

impl AddAssign for GoldilocksExt3 {
    #[inline]
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}

impl<'a> AddAssign<&'a GoldilocksExt3> for GoldilocksExt3 {
    #[inline]
    fn add_assign(&mut self, rhs: &'a GoldilocksExt3) {
        *self = *self + *rhs;
    }
}

impl Sub for GoldilocksExt3 {
    type Output = Self;

    #[inline]
    fn sub(self, rhs: Self) -> Self {
        Self([
            self.0[0] - rhs.0[0],
            self.0[1] - rhs.0[1],
            self.0[2] - rhs.0[2],
        ])
    }
}

impl<'a> Sub<&'a GoldilocksExt3> for GoldilocksExt3 {
    type Output = Self;

    #[inline]
    fn sub(self, rhs: &'a GoldilocksExt3) -> Self::Output {
        self - *rhs
    }
}

impl SubAssign for GoldilocksExt3 {
    #[inline]
    fn sub_assign(&mut self, rhs: Self) {
        *self = *self - rhs;
    }
}

impl<'a> SubAssign<&'a GoldilocksExt3> for GoldilocksExt3 {
    #[inline]
    fn sub_assign(&mut self, rhs: &'a GoldilocksExt3) {
        *self = *self - *rhs;
    }
}

impl<T: ::core::borrow::Borrow<GoldilocksExt3>> Sum<T> for GoldilocksExt3 {
    fn sum<I: Iterator<Item = T>>(iter: I) -> Self {
        iter.fold(Self::ZERO, |acc, item| acc + item.borrow())
    }
}

impl Mul for GoldilocksExt3 {
    type Output = Self;

    #[inline]
    fn mul(self, rhs: Self) -> Self {
        mul_internal(&self, &rhs)
    }
}

impl<'a> Mul<&'a GoldilocksExt3> for GoldilocksExt3 {
    type Output = Self;

    #[inline]
    fn mul(self, rhs: &'a GoldilocksExt3) -> Self::Output {
        self * *rhs
    }
}

impl MulAssign for GoldilocksExt3 {
    #[inline]
    fn mul_assign(&mut self, rhs: Self) {
        *self = *self * rhs;
    }
}

impl<'a> MulAssign<&'a GoldilocksExt3> for GoldilocksExt3 {
    #[inline]
    fn mul_assign(&mut self, rhs: &'a GoldilocksExt3) {
        *self = *self * *rhs;
    }
}

impl<T: ::core::borrow::Borrow<GoldilocksExt3>> Product<T> for GoldilocksExt3 {
    fn product<I: Iterator<Item = T>>(iter: I) -> Self {
        iter.fold(Self::ONE, |acc, item| acc * item.borrow())
    }
}

impl AsMut<[u8]> for GoldilocksExt3 {
    fn as_mut(&mut self) -> &mut [u8] {
        let ptr = self as *mut Self as *mut u8;
        // SAFETY Self is repr(transparent) and u64 is 8 bytes wide,
        // with alignment greater than that of u8
        unsafe { std::slice::from_raw_parts_mut(ptr, 24) }
    }
}

impl AsRef<[u8]> for GoldilocksExt3 {
    fn as_ref(&self) -> &[u8] {
        let ptr = self as *const Self as *const u8;
        // SAFETY Self is repr(transparent) and u64 is 8 bytes wide,
        // with alignment greater than that of u8
        unsafe { std::slice::from_raw_parts(ptr, 24) }
    }
}

impl From<Goldilocks> for GoldilocksExt3 {
    fn from(a: Goldilocks) -> Self {
        Self([a, Goldilocks::ZERO, Goldilocks::ZERO])
    }
}

impl From<u64> for GoldilocksExt3 {
    fn from(a: u64) -> Self {
        Goldilocks::from(a).into()
    }
}

/// This represents an element of a prime field.
impl PrimeField for GoldilocksExt3 {
    /// The prime field can be converted back and forth into this binary
    /// representation.
    type Repr = Self;

    /// Modulus of the field written as a string for debugging purposes.
    ///
    /// The encoding of the modulus is implementation-specific. Generic users of the
    /// `PrimeField` trait should treat this string as opaque.
    const MODULUS: &'static str = "0xffffffff00000001";

    /// How many bits are needed to represent an element of this field.
    const NUM_BITS: u32 = 64;

    /// How many bits of information can be reliably stored in the field element.
    ///
    /// This is usually `Self::NUM_BITS - 1`.
    const CAPACITY: u32 = 63;

    /// An integer `s` satisfying the equation `2^s * t = modulus - 1` with `t` odd.
    ///
    /// This is the number of leading zero bits in the little-endian bit representation of
    /// `modulus - 1`.
    const S: u32 = 32;

    /// Inverse of $2$ in the field.
    const TWO_INV: Self = GoldilocksExt3([Goldilocks::TWO_INV, Goldilocks::ZERO, Goldilocks::ZERO]);

    /// A fixed multiplicative generator of `modulus - 1` order. This element must also be
    /// a quadratic nonresidue.
    ///
    /// It can be calculated using [SageMath] as `GF(modulus).primitive_element()`.
    ///
    /// Implementations of this trait MUST ensure that this is the generator used to
    /// derive `Self::ROOT_OF_UNITY`.
    ///
    /// [SageMath]: https://www.sagemath.org/
    const MULTIPLICATIVE_GENERATOR: Self = GoldilocksExt3([
        Goldilocks::MULTIPLICATIVE_GENERATOR,
        Goldilocks::ZERO,
        Goldilocks::ZERO,
    ]);

    /// The `2^s` root of unity.
    ///
    /// It can be calculated by exponentiating `Self::MULTIPLICATIVE_GENERATOR` by `t`,
    /// where `t = (modulus - 1) >> Self::S`.
    const ROOT_OF_UNITY: Self = GoldilocksExt3([
        Goldilocks::ROOT_OF_UNITY,
        Goldilocks::ZERO,
        Goldilocks::ZERO,
    ]);

    /// Inverse of [`Self::ROOT_OF_UNITY`].
    const ROOT_OF_UNITY_INV: Self = GoldilocksExt3([
        Goldilocks::ROOT_OF_UNITY_INV,
        Goldilocks::ZERO,
        Goldilocks::ZERO,
    ]);

    /// Generator of the `t-order` multiplicative subgroup.
    ///
    /// It can be calculated by exponentiating [`Self::MULTIPLICATIVE_GENERATOR`] by `2^s`,
    /// where `s` is [`Self::S`].
    const DELTA: Self = GoldilocksExt3([Goldilocks::DELTA, Goldilocks::ZERO, Goldilocks::ZERO]);

    /// Attempts to convert a byte representation of a field element into an element of
    /// this prime field, failing if the input is not canonical (is not smaller than the
    /// field's modulus).
    ///
    /// The byte representation is interpreted with the same endianness as elements
    /// returned by [`PrimeField::to_repr`].
    fn from_repr(repr: Self::Repr) -> CtOption<Self> {
        CtOption::new(repr, Choice::from(1))
    }

    /// Attempts to convert a byte representation of a field element into an element of
    /// this prime field, failing if the input is not canonical (is not smaller than the
    /// field's modulus).
    ///
    /// The byte representation is interpreted with the same endianness as elements
    /// returned by [`PrimeField::to_repr`].
    ///
    /// # Security
    ///
    /// This method provides **no** constant-time guarantees. Implementors of the
    /// `PrimeField` trait **may** optimise this method using non-constant-time logic.
    fn from_repr_vartime(repr: Self::Repr) -> Option<Self> {
        Self::from_repr(repr).into()
    }

    /// Converts an element of the prime field into the standard byte representation for
    /// this field.
    ///
    /// The endianness of the byte representation is implementation-specific. Generic
    /// encodings of field elements should be treated as opaque.
    fn to_repr(&self) -> Self::Repr {
        *self
    }

    /// Returns true iff this element is odd.
    fn is_odd(&self) -> Choice {
        unimplemented!()
    }
}
