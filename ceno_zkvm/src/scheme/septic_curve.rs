// The extension field and curve definition are adapted from
// https://github.com/succinctlabs/sp1/blob/v5.2.1/crates/stark/src/septic_curve.rs
use p3::field::{Field, FieldAlgebra};
use serde::{Deserialize, Serialize};
use std::ops::{Add, Deref, Mul, Sub};

/// F[z] / (z^6 - z - 4)
///
/// ```sage
/// # finite field F = GF(2^31 - 2^27 + 1)
/// p = 2^31 - 2^27 + 1
/// F = GF(p)
///
/// # polynomial ring over F
/// R.<x> = PolynomialRing(F)
/// f = x^6 - x - 4
///
/// # check if f(x) is irreducible
/// print(f.is_irreducible())
/// ```
pub struct SexticExtension<F>([F; 6]);

/// F[z] / (z^7 - 2z - 5)
///
/// ```sage
/// # finite field F = GF(2^31 - 2^27 + 1)
/// p = 2^31 - 2^27 + 1
/// F = GF(p)
///
/// # polynomial ring over F
/// R.<x> = PolynomialRing(F)
/// f = x^7 - 2x - 5
///
/// # check if f(x) is irreducible
/// print(f.is_irreducible())
/// ```
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct SepticExtension<F>(pub [F; 7]);

impl<F: Copy + Clone + Default> From<&[F]> for SepticExtension<F> {
    fn from(slice: &[F]) -> Self {
        assert!(slice.len() == 7);
        let mut arr = [F::default(); 7];
        arr.copy_from_slice(&slice[0..7]);
        Self(arr)
    }
}

impl<F> Deref for SepticExtension<F> {
    type Target = [F];

    fn deref(&self) -> &[F] {
        &self.0
    }
}

impl<F: Field> SepticExtension<F> {
    pub fn is_zero(&self) -> bool {
        self.0.iter().all(|c| *c == F::ZERO)
    }

    pub fn inverse(&self) -> Option<Self> {
        match self.is_zero() {
            true => None,
            false => {
                todo!()
            }
        }
    }

    pub fn square(&self) -> Self {
        let mut result = [F::ZERO; 7];
        let two = F::from_canonical_u32(2);
        let five = F::from_canonical_u32(5);

        // i < j
        for i in 0..7 {
            for j in (i + 1)..7 {
                let term = two * self.0[i] * self.0[j];
                let mut index = i + j;
                if index < 7 {
                    result[index] += term;
                } else {
                    index -= 7;
                    // x^7 = 2x + 5
                    result[index] += five * term;
                    result[index + 1] += two * term;
                }
            }
        }
        // i == j
        result[0] += self.0[0] * self.0[0];
        result[2] += self.0[1] * self.0[1];
        result[4] += self.0[2] * self.0[2];
        result[6] += self.0[3] * self.0[3];
        // a4^2 * x^8 = a4^2 * (2x + 5)x = 5a4^2 * x + 2a4^2 * x^2
        let term = self.0[4] * self.0[4];
        result[1] += five * term;
        result[2] += two * term;
        // a5^2 * x^10 = a5^2 * (2x + 5)x^3 = 5a5^2 * x^3 + 2a5^2 * x^4
        let term = self.0[5] * self.0[5];
        result[3] += five * term;
        result[4] += two * term;
        // a6^2 * x^12 = a6^2 * (2x + 5)x^5 = 5a6^2 * x^5 + 2a6^2 * x^6
        let term = self.0[6] * self.0[6];
        result[5] += five * term;
        result[6] += two * term;

        Self(result)
    }
}

impl<F: Field> From<[u32; 7]> for SepticExtension<F> {
    fn from(arr: [u32; 7]) -> Self {
        let mut result = [F::ZERO; 7];
        for i in 0..7 {
            result[i] = F::from_canonical_u32(arr[i]);
        }
        Self(result)
    }
}

impl<F: FieldAlgebra + Copy> Add<&Self> for SepticExtension<F> {
    type Output = SepticExtension<F>;

    fn add(self, other: &Self) -> Self {
        let mut result = [F::ZERO; 7];
        for i in 0..7 {
            result[i] = self.0[i] + other.0[i];
        }
        Self(result)
    }
}

impl<F: FieldAlgebra + Copy> Add<Self> for &SepticExtension<F> {
    type Output = SepticExtension<F>;

    fn add(self, other: Self) -> SepticExtension<F> {
        let mut result = [F::ZERO; 7];
        for i in 0..7 {
            result[i] = self.0[i] + other.0[i];
        }
        SepticExtension(result)
    }
}

impl<F: FieldAlgebra + Copy> Add for SepticExtension<F> {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        self.add(&other)
    }
}

impl<F: FieldAlgebra + Copy> Sub<&Self> for SepticExtension<F> {
    type Output = SepticExtension<F>;

    fn sub(self, other: &Self) -> Self {
        let mut result = [F::ZERO; 7];
        for i in 0..7 {
            result[i] = self.0[i] - other.0[i];
        }
        Self(result)
    }
}

impl<F: FieldAlgebra + Copy> Sub<Self> for &SepticExtension<F> {
    type Output = SepticExtension<F>;

    fn sub(self, other: Self) -> SepticExtension<F> {
        let mut result = [F::ZERO; 7];
        for i in 0..7 {
            result[i] = self.0[i] - other.0[i];
        }
        SepticExtension(result)
    }
}

impl<F: FieldAlgebra + Copy> Sub for SepticExtension<F> {
    type Output = Self;

    fn sub(self, other: Self) -> Self {
        self.sub(&other)
    }
}

impl<F: Field> Mul<&Self> for SepticExtension<F> {
    type Output = Self;

    fn mul(self, other: &Self) -> Self {
        let mut result = [F::ZERO; 7];
        let five = F::from_canonical_u32(5);
        let two = F::from_canonical_u32(2);
        for i in 0..7 {
            for j in 0..7 {
                let term = self.0[i] * other.0[j];
                let mut index = i + j;
                if index < 7 {
                    result[index] += term;
                } else {
                    index -= 7;
                    // x^7 = 2x + 5
                    result[index] += five * term;
                    result[index + 1] += two * term;
                }
            }
        }
        Self(result)
    }
}

impl<F: Field> Mul for SepticExtension<F> {
    type Output = Self;

    fn mul(self, other: Self) -> Self {
        self.mul(&other)
    }
}

/// A point on the short Weierstrass curve defined by
///       y^2 = x^3 + 2x + 26z^5
/// over the extension field F[z] / (z^7 - 2z - 5).
///
/// Note that
/// 1. The curve's cofactor is 1
/// 2. The curve's order is a large prime number of 31x7 bits
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct SepticPoint<F> {
    pub x: SepticExtension<F>,
    pub y: SepticExtension<F>,
}

impl<F: Field> Add<Self> for SepticPoint<F> {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        assert!(other.x != self.x, "other = self or other = -self");
        let slope = (other.y - &self.y) * (other.x.clone() - &self.x).inverse().unwrap();
        let x = slope.square() - (self.x.clone() + other.x);
        let y = slope * (x.clone() - self.x) - self.y;

        Self { x, y }
    }
}

#[cfg(test)]
mod tests {
    use super::SepticExtension;
    use p3::babybear::BabyBear;

    type F = BabyBear;
    #[test]
    fn test_septic_extension_arithmetic() {
        // a = z, b = z^6 + z^5 + z^4
        let a: SepticExtension<F> = SepticExtension::from([0, 1, 0, 0, 0, 0, 0]);
        let b: SepticExtension<F> = SepticExtension::from([0, 0, 0, 0, 1, 1, 1]);

        assert_eq!(
            a * b,
            // z^5 + z^6 + 2*z + 5
            SepticExtension::from([5, 2, 0, 0, 0, 1, 1])
        )
    }
}
