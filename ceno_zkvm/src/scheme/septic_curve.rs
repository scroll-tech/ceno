use either::Either;
use ff_ext::{ExtensionField, FromUniformBytes};
use multilinear_extensions::Expression;
// The extension field and curve definition are adapted from
// https://github.com/succinctlabs/sp1/blob/v5.2.1/crates/stark/src/septic_curve.rs
use p3::field::{Field, FieldAlgebra};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::{
    iter::Sum,
    ops::{Add, Deref, Mul, MulAssign, Sub},
};

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

    pub fn zero() -> Self {
        Self([F::ZERO; 7])
    }

    pub fn one() -> Self {
        let mut arr = [F::ZERO; 7];
        arr[0] = F::ONE;
        Self(arr)
    }

    // returns z^{i*p} for i = 0..6
    //
    // The sage script to compute z^{i*p} is as follows:
    // ```sage
    // p = 2^31 - 2^27 + 1
    // Fp = GF(p)
    // R.<z> = PolynomialRing(Fp)
    // mod_poly = z^7 - 2*z - 5
    // Q = R.quotient(mod_poly)
    //
    // # compute z^(i*p) for i = 1..6
    // for k in range(1, 7):
    //     power = k * p
    //     z_power = Q(z)^power
    //     print(f"z^({k}*p) = {z_power}")
    // ```
    fn z_pow_p(i: usize) -> Self {
        match i {
            0 => [1, 0, 0, 0, 0, 0, 0].into(),
            1 => [
                954599710, 1359279693, 566669999, 1982781815, 1735718361, 1174868538, 1120871770,
            ]
            .into(),
            2 => [
                862825265, 597046311, 978840770, 1790138282, 1044777201, 835869808, 1342179023,
            ]
            .into(),
            3 => [
                596273169, 658837454, 1515468261, 367059247, 781278880, 1544222616, 155490465,
            ]
            .into(),
            4 => [
                557608863, 1173670028, 1749546888, 1086464137, 803900099, 1288818584, 1184677604,
            ]
            .into(),
            5 => [
                763416381, 1252567168, 628856225, 1771903394, 650712211, 19417363, 57990258,
            ]
            .into(),
            6 => [
                1734711039, 1749813853, 1227235221, 1707730636, 424560395, 1007029514, 498034669,
            ]
            .into(),
            _ => unimplemented!("i should be in [0, 7]"),
        }
    }

    // returns z^{i*p^2} for i = 0..6
    // we can change the above sage script to compute z^{i*p^2} by replacing
    // `power = k * p` with `power = k * p * p`
    fn z_pow_p_square(i: usize) -> Self {
        match i {
            0 => [1, 0, 0, 0, 0, 0, 0].into(),
            1 => [
                1013489358, 1619071628, 304593143, 1949397349, 1564307636, 327761151, 415430835,
            ]
            .into(),
            2 => [
                209824426, 1313900768, 38410482, 256593180, 1708830551, 1244995038, 1555324019,
            ]
            .into(),
            3 => [
                1475628651, 777565847, 704492386, 1218528120, 1245363405, 475884575, 649166061,
            ]
            .into(),
            4 => [
                550038364, 948935655, 68722023, 1251345762, 1692456177, 1177958698, 350232928,
            ]
            .into(),
            5 => [
                882720258, 821925756, 199955840, 812002876, 1484951277, 1063138035, 491712810,
            ]
            .into(),
            6 => [
                738287111, 1955364991, 552724293, 1175775744, 341623997, 1454022463, 408193320,
            ]
            .into(),
            _ => unimplemented!("i should be in [0, 7]"),
        }
    }

    // returns self^p = (a0 + a1*z^p + ... + a6*z^(6p))
    pub fn frobenius(&self) -> Self {
        Self::z_pow_p(0) * self.0[0]
            + Self::z_pow_p(1) * self.0[1]
            + Self::z_pow_p(2) * self.0[2]
            + Self::z_pow_p(3) * self.0[3]
            + Self::z_pow_p(4) * self.0[4]
            + Self::z_pow_p(5) * self.0[5]
            + Self::z_pow_p(6) * self.0[6]
    }

    // returns self^(p^2) = (a0 + a1*z^(p^2) + ... + a6*z^(6*p^2))
    pub fn double_frobenius(&self) -> Self {
        Self::z_pow_p_square(0) * self.0[0]
            + Self::z_pow_p_square(1) * self.0[1]
            + Self::z_pow_p_square(2) * self.0[2]
            + Self::z_pow_p_square(3) * self.0[3]
            + Self::z_pow_p_square(4) * self.0[4]
            + Self::z_pow_p_square(5) * self.0[5]
            + Self::z_pow_p_square(6) * self.0[6]
    }

    // returns self^(p + p^2 + ... + p^6)
    fn norm_sub(&self) -> Self {
        let a = self.frobenius() * self.double_frobenius();
        let b = a.double_frobenius();
        let c = b.double_frobenius();

        a * b * c
    }

    // norm = self^(1 + p + ... + p^6)
    //      = self^((p^7-1)/(p-1))
    // it's a field element in F since norm^p = norm
    fn norm(&self) -> F {
        (self.norm_sub() * self).0[0]
    }

    pub fn is_square(&self) -> bool {
        // since a^((p^7 - 1)/2) = norm(a)^((p-1)/2)
        // to test if self^((p^7 - 1) / 2) == 1?
        // we can just test if norm(a)^((p-1)/2) == 1?
        let exp_digits = ((F::order() - 1u32) / 2u32).to_u64_digits();
        debug_assert!(exp_digits.len() == 1);
        let exp = exp_digits[0];

        self.norm().exp_u64(exp) == F::ONE
    }

    pub fn inverse(&self) -> Option<Self> {
        match self.is_zero() {
            true => None,
            false => {
                // since norm(a)^(-1) * a^(p + p^2 + ... + p^6) * a = 1
                // it's easy to see a^(-1) = norm(a)^(-1) * a^(p + p^2 + ... + p^6)
                let x = self.norm_sub();
                let norm = (self * &x).0[0];
                // since self is not zero, norm is not zero
                let norm_inv = norm.try_inverse().unwrap();

                Some(x * norm_inv)
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
        // i == j: i \in [0, 3]
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

    pub fn pow(&self, exp: u64) -> Self {
        let mut result = Self::one();
        let num_bits = 64 - exp.leading_zeros();
        for j in (0..num_bits).rev() {
            result = result.square();
            if (exp >> j) & 1u64 == 1u64 {
                result = result * self;
            }
        }
        result
    }

    pub fn sqrt(&self) -> Option<Self> {
        // the algorithm is adapted from [Cipolla's algorithm](https://en.wikipedia.org/wiki/Cipolla%27s_algorithm
        // the code is taken from https://github.com/succinctlabs/sp1/blob/dev/crates/stark/src/septic_extension.rs#L623
        let n = self.clone();

        if n == Self::zero() || n == Self::one() {
            return Some(n);
        }

        // norm = n^(1 + p + ... + p^6) = n^(p^7-1)/(p-1)
        let norm = n.norm();
        let exp = ((F::order() - 1u32) / 2u32).to_u64_digits()[0];
        // euler's criterion n^((p^7-1)/2) == 1 iff n is quadratic residue
        if norm.exp_u64(exp) != F::ONE {
            // it's not a square
            return None;
        };

        // n_power = n^((p+1)/2)
        let exp = ((F::order() + 1u32) / 2u32).to_u64_digits()[0];
        let n_power = self.pow(exp);

        // n^((p^2 + p)/2)
        let mut n_frobenius = n_power.frobenius();
        let mut denominator = n_frobenius.clone();

        // n^((p^4 + p^3)/2)
        n_frobenius = n_frobenius.double_frobenius();
        denominator *= n_frobenius.clone();
        // n^((p^6 + p^5)/2)
        n_frobenius = n_frobenius.double_frobenius();
        // d = n^((p^6 + p^5 + p^4 + p^3 + p^2 + p) / 2)
        // d^2 * n = norm
        denominator *= n_frobenius;
        // d' = d*n
        denominator *= n;

        let base = norm.inverse(); // norm^(-1)
        let g = F::GENERATOR;
        let mut a = F::ONE;
        let mut non_residue = F::ONE - base;
        let legendre_exp = (F::order() - 1u32) / 2u32; // (p-1)/2

        // non_residue = a^2 - 1/norm
        // find `a` such that non_residue is not a square in F
        while non_residue.exp_u64(legendre_exp.to_u64_digits()[0]) == F::ONE {
            a *= g;
            non_residue = a.square() - base;
        }

        // (p+1)/2
        let cipolla_exp = ((F::order() + 1u32) / 2u32).to_u64_digits()[0];
        // x = (a+i)^((p+1)/2) where a in Fp
        // x^2 = (a+i) * (a+i)^p = (a+i)*(a-i) = a^2 - i^2
        //     = a^2 - non_residue = 1/norm
        // therefore, x is the square root of 1/norm
        let mut x = QuadraticExtension::new(a, F::ONE, non_residue);
        x = x.pow(cipolla_exp);

        // (x*d')^2 = x^2 * d^2 * n^2 = 1/norm * norm * n
        Some(denominator * x.real)
    }
}

// a + bi where i^2 = non_residue
#[derive(Clone, Debug)]
pub struct QuadraticExtension<F> {
    pub real: F,
    pub imag: F,
    pub non_residue: F,
}

impl<F: Field> QuadraticExtension<F> {
    pub fn new(real: F, imag: F, non_residue: F) -> Self {
        Self {
            real,
            imag,
            non_residue,
        }
    }

    pub fn square(&self) -> Self {
        // (a + bi)^2 = (a^2 + b^2*i^2) + 2ab*i
        let real = self.real * self.real + self.non_residue * self.imag * self.imag;
        let mut imag = self.real * self.imag;
        imag += imag;

        Self {
            real,
            imag,
            non_residue: self.non_residue,
        }
    }

    pub fn mul(&self, other: &Self) -> Self {
        // (a + bi)(c + di) = (ac + bd*i^2) + (ad + bc)i
        let real = self.real * other.real + self.non_residue * self.imag * other.imag;
        let imag = self.real * other.imag + self.imag * other.real;

        Self {
            real,
            imag,
            non_residue: self.non_residue,
        }
    }

    pub fn pow(&self, exp: u64) -> Self {
        let mut result = Self {
            real: F::ONE,
            imag: F::ZERO,
            non_residue: self.non_residue,
        };

        let num_bits = 64 - exp.leading_zeros();
        for j in (0..num_bits).rev() {
            result = result.square();
            if (exp >> j) & 1u64 == 1u64 {
                result = result.mul(self);
            }
        }

        result
    }
}

impl<F: Field + FromUniformBytes> SepticExtension<F> {
    pub fn random(mut rng: impl RngCore) -> Self {
        let mut arr = [F::ZERO; 7];
        for i in 0..7 {
            arr[i] = F::random(&mut rng);
        }
        Self(arr)
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

impl<F: Field> Mul<F> for &SepticExtension<F> {
    type Output = SepticExtension<F>;

    fn mul(self, other: F) -> Self::Output {
        let mut result = [F::ZERO; 7];
        for i in 0..7 {
            result[i] = self.0[i] * other;
        }
        SepticExtension(result)
    }
}

impl<F: Field> Mul<F> for SepticExtension<F> {
    type Output = SepticExtension<F>;

    fn mul(self, other: F) -> Self::Output {
        (&self).mul(other)
    }
}

impl<F: Field> Mul<Self> for &SepticExtension<F> {
    type Output = SepticExtension<F>;

    fn mul(self, other: Self) -> Self::Output {
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
        SepticExtension(result)
    }
}

impl<F: Field> Mul for SepticExtension<F> {
    type Output = Self;

    fn mul(self, other: Self) -> Self {
        (&self).mul(&other)
    }
}

impl<F: Field> Mul<&Self> for SepticExtension<F> {
    type Output = Self;

    fn mul(self, other: &Self) -> Self {
        (&self).mul(other)
    }
}

impl<F: Field> MulAssign<Self> for SepticExtension<F> {
    fn mul_assign(&mut self, other: Self) {
        *self = (&*self).mul(&other);
    }
}

pub struct SymbolicSepticExtension<E: ExtensionField>(pub Vec<Expression<E>>);

impl<E: ExtensionField> Add<Self> for &SymbolicSepticExtension<E> {
    type Output = SymbolicSepticExtension<E>;

    fn add(self, other: Self) -> Self::Output {
        let res = self
            .0
            .iter()
            .zip(other.0.iter())
            .map(|(a, b)| a.clone() + b.clone())
            .collect();

        SymbolicSepticExtension(res)
    }
}

impl<E: ExtensionField> Add<&Self> for SymbolicSepticExtension<E> {
    type Output = Self;

    fn add(self, other: &Self) -> Self {
        (&self).add(other)
    }
}

impl<E: ExtensionField> Add for SymbolicSepticExtension<E> {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        (&self).add(&other)
    }
}

impl<E: ExtensionField> Sub<Self> for &SymbolicSepticExtension<E> {
    type Output = SymbolicSepticExtension<E>;

    fn sub(self, other: Self) -> Self::Output {
        let res = self
            .0
            .iter()
            .zip(other.0.iter())
            .map(|(a, b)| a.clone() - b.clone())
            .collect();

        SymbolicSepticExtension(res)
    }
}

impl<E: ExtensionField> Sub<&Self> for SymbolicSepticExtension<E> {
    type Output = Self;

    fn sub(self, other: &Self) -> Self {
        (&self).sub(other)
    }
}

impl<E: ExtensionField> Sub for SymbolicSepticExtension<E> {
    type Output = Self;

    fn sub(self, other: Self) -> Self {
        (&self).sub(&other)
    }
}

impl<E: ExtensionField> Mul<Self> for &SymbolicSepticExtension<E> {
    type Output = SymbolicSepticExtension<E>;

    fn mul(self, other: Self) -> Self::Output {
        let mut result = vec![Expression::Constant(Either::Left(E::BaseField::ZERO)); 7];
        let five = Expression::Constant(Either::Left(E::BaseField::from_canonical_u32(5)));
        let two = Expression::Constant(Either::Left(E::BaseField::from_canonical_u32(2)));

        for i in 0..7 {
            for j in 0..7 {
                let term = self.0[i].clone() * other.0[j].clone();
                let mut index = i + j;
                if index < 7 {
                    result[index] += term;
                } else {
                    index -= 7;
                    // x^7 = 2x + 5
                    result[index] += five.clone() * term.clone();
                    result[index + 1] += two.clone() * term.clone();
                }
            }
        }
        SymbolicSepticExtension(result)
    }
}

impl<E: ExtensionField> Mul<&Self> for SymbolicSepticExtension<E> {
    type Output = Self;

    fn mul(self, other: &Self) -> Self {
        (&self).mul(other)
    }
}

impl<E: ExtensionField> Mul for SymbolicSepticExtension<E> {
    type Output = Self;

    fn mul(self, other: Self) -> Self {
        (&self).mul(&other)
    }
}

impl<E: ExtensionField> Mul<&Expression<E>> for SymbolicSepticExtension<E> {
    type Output = SymbolicSepticExtension<E>;

    fn mul(self, other: &Expression<E>) -> Self::Output {
        let res = self.0.iter().map(|a| a.clone() * other.clone()).collect();
        SymbolicSepticExtension(res)
    }
}

impl<E: ExtensionField> Mul<Expression<E>> for SymbolicSepticExtension<E> {
    type Output = SymbolicSepticExtension<E>;

    fn mul(self, other: Expression<E>) -> Self::Output {
        self.mul(&other)
    }
}

impl<E: ExtensionField> SymbolicSepticExtension<E> {
    pub fn new(exprs: Vec<Expression<E>>) -> Self {
        assert!(exprs.len() == 7);
        Self(exprs)
    }

    pub fn to_exprs(&self) -> Vec<Expression<E>> {
        self.0.clone()
    }
}

/// A point on the short Weierstrass curve defined by
///       y^2 = x^3 + 2x + 26z^5
/// over the extension field F[z] / (z^7 - 2z - 5).
///
/// Note that
/// 1. The curve's cofactor is 1
/// 2. The curve's order is a large prime number of 31x7 bits
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SepticPoint<F> {
    pub x: SepticExtension<F>,
    pub y: SepticExtension<F>,
    pub is_infinity: bool,
}

impl<F: Field> SepticPoint<F> {
    pub fn double(&self) -> Self {
        todo!()
    }
}

impl<F: Field> Default for SepticPoint<F> {
    fn default() -> Self {
        Self {
            x: SepticExtension::zero(),
            y: SepticExtension::zero(),
            is_infinity: true,
        }
    }
}

impl<F: Field> Add<Self> for SepticPoint<F> {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        if self.is_infinity {
            return other;
        }

        if other.is_infinity {
            return self;
        }

        if self.x == other.x {
            if self.y == other.y {
                return self.double();
            } else {
                assert!((self.y + other.y).is_zero());

                return Self {
                    x: SepticExtension::zero(),
                    y: SepticExtension::zero(),
                    is_infinity: true,
                };
            }
        }

        let slope = (other.y - &self.y) * (other.x.clone() - &self.x).inverse().unwrap();
        let x = slope.square() - (&self.x + &other.x);
        let y = slope * (self.x - &x) - self.y;

        Self {
            x,
            y,
            is_infinity: false,
        }
    }
}

impl<F: Field> Sum<Self> for SepticPoint<F> {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Self::default(), |acc, p| acc + p)
    }
}

impl<F: Field> SepticPoint<F> {
    pub fn is_on_curve(&self) -> bool {
        if self.is_infinity && self.x.is_zero() && self.y.is_zero() {
            return true;
        }

        let b: SepticExtension<F> = [0, 0, 0, 0, 0, 26, 0].into();
        let a: F = F::from_canonical_u32(2);

        self.y.square() == self.x.square() * &self.x + (&self.x * a) + b
    }
}

impl<F: Field + FromUniformBytes> SepticPoint<F> {
    pub fn random(mut rng: impl RngCore) -> Self {
        let b: SepticExtension<F> = [0, 0, 0, 0, 0, 26, 0].into();
        let a: F = F::from_canonical_u32(2);

        loop {
            let x = SepticExtension::random(&mut rng);
            let y2 = x.square() * &x + (&x * a) + &b;
            if y2.is_square() {
                let y = y2.sqrt().unwrap();

                return Self {
                    x,
                    y,
                    is_infinity: false,
                };
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::SepticExtension;
    use crate::scheme::septic_curve::SepticPoint;
    use p3::{babybear::BabyBear, field::Field};
    use rand::thread_rng;

    type F = BabyBear;
    #[test]
    fn test_septic_extension_arithmetic() {
        let mut rng = thread_rng();
        // a = z, b = z^6 + z^5 + z^4
        let a: SepticExtension<F> = SepticExtension::from([0, 1, 0, 0, 0, 0, 0]);
        let b: SepticExtension<F> = SepticExtension::from([0, 0, 0, 0, 1, 1, 1]);

        let c = SepticExtension::from([5, 2, 0, 0, 0, 1, 1]);
        assert_eq!(a * b, c);

        // a^(p^2) = (a^p)^p
        assert_eq!(c.double_frobenius(), c.frobenius().frobenius());

        // norm_sub(a) * a must be in F
        let norm = c.norm_sub() * &c;
        assert!(norm.0[1..7].iter().all(|x| x.is_zero()));

        let d: SepticExtension<F> = SepticExtension::random(&mut rng);
        let e = d.square();
        assert!(e.is_square());

        let f = e.sqrt().unwrap();
        let zero = SepticExtension::zero();
        assert!(f == d || f == zero - d);
    }

    #[test]
    fn test_septic_curve_arithmetic() {
        let mut rng = thread_rng();
        let p1 = SepticPoint::<F>::random(&mut rng);
        let p2 = SepticPoint::<F>::random(&mut rng);

        let p3 = p1 + p2;
        assert!(p3.is_on_curve());
    }
}
