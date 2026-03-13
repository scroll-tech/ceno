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
    ops::{Add, Deref, Mul, MulAssign, Neg, Sub},
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
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub struct SepticExtension<F>(pub [F; 7]);

impl<F: Copy + Clone + Default> From<&[F]> for SepticExtension<F> {
    fn from(slice: &[F]) -> Self {
        assert!(slice.len() == 7);
        let mut arr = [F::default(); 7];
        arr.copy_from_slice(&slice[0..7]);
        Self(arr)
    }
}

impl<F: Copy + Clone + Default> From<Vec<F>> for SepticExtension<F> {
    fn from(v: Vec<F>) -> Self {
        assert!(v.len() == 7);
        let mut arr = [F::default(); 7];
        arr.copy_from_slice(&v[0..7]);
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
        for item in arr.iter_mut() {
            *item = F::random(&mut rng);
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
        for (i, res) in result.iter_mut().enumerate() {
            *res = self.0[i] + other.0[i];
        }
        Self(result)
    }
}

impl<F: FieldAlgebra + Copy> Add<Self> for &SepticExtension<F> {
    type Output = SepticExtension<F>;

    fn add(self, other: Self) -> SepticExtension<F> {
        let mut result = [F::ZERO; 7];
        for (i, res) in result.iter_mut().enumerate() {
            *res = self.0[i] + other.0[i];
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

impl<F: FieldAlgebra + Copy> Neg for SepticExtension<F> {
    type Output = Self;

    fn neg(self) -> Self {
        let mut result = [F::ZERO; 7];
        for (res, src) in result.iter_mut().zip(self.0.iter()) {
            *res = -(*src);
        }
        Self(result)
    }
}

impl<F: FieldAlgebra + Copy> Sub<&Self> for SepticExtension<F> {
    type Output = SepticExtension<F>;

    fn sub(self, other: &Self) -> Self {
        let mut result = [F::ZERO; 7];
        for (i, res) in result.iter_mut().enumerate() {
            *res = self.0[i] - other.0[i];
        }
        Self(result)
    }
}

impl<F: FieldAlgebra + Copy> Sub<Self> for &SepticExtension<F> {
    type Output = SepticExtension<F>;

    fn sub(self, other: Self) -> SepticExtension<F> {
        let mut result = [F::ZERO; 7];
        for (i, res) in result.iter_mut().enumerate() {
            *res = self.0[i] - other.0[i];
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

impl<F: Field> Add<F> for &SepticExtension<F> {
    type Output = SepticExtension<F>;

    fn add(self, other: F) -> Self::Output {
        let mut result = self.clone();
        result.0[0] += other;

        result
    }
}

impl<F: Field> Add<F> for SepticExtension<F> {
    type Output = SepticExtension<F>;

    fn add(self, other: F) -> Self::Output {
        (&self).add(other)
    }
}

impl<F: Field> Mul<F> for &SepticExtension<F> {
    type Output = SepticExtension<F>;

    fn mul(self, other: F) -> Self::Output {
        let mut result = [F::ZERO; 7];
        for (i, res) in result.iter_mut().enumerate() {
            *res = self.0[i] * other;
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

#[derive(Clone, Debug)]
pub struct SymbolicSepticExtension<E: ExtensionField>(pub Vec<Expression<E>>);

impl<E: ExtensionField> SymbolicSepticExtension<E> {
    pub fn mul_scalar(&self, scalar: Either<E::BaseField, E>) -> Self {
        let res = self
            .0
            .iter()
            .map(|a| a.clone() * Expression::Constant(scalar))
            .collect();

        SymbolicSepticExtension(res)
    }

    pub fn add_scalar(&self, scalar: Either<E::BaseField, E>) -> Self {
        let res = self
            .0
            .iter()
            .map(|a| a.clone() + Expression::Constant(scalar))
            .collect();

        SymbolicSepticExtension(res)
    }
}

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
        assert!(
            exprs.len() == 7,
            "exprs length must be 7, but got {}",
            exprs.len()
        );
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
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub struct SepticPoint<F> {
    pub x: SepticExtension<F>,
    pub y: SepticExtension<F>,
    pub is_infinity: bool,
}

impl<F: Field> SepticPoint<F> {
    // if there exists y such that (x, y) is on the curve, return one of them
    pub fn from_x(x: SepticExtension<F>) -> Option<Self> {
        let b: SepticExtension<F> = [0, 0, 0, 0, 0, 26, 0].into();
        let a: F = F::from_canonical_u32(2);

        let y2 = x.square() * &x + (&x * a) + &b;
        if y2.is_square() {
            let y = y2.sqrt().unwrap();

            Some(Self {
                x,
                y,
                is_infinity: false,
            })
        } else {
            None
        }
    }

    pub fn from_affine(x: SepticExtension<F>, y: SepticExtension<F>) -> Self {
        let is_infinity = x.is_zero() && y.is_zero();

        Self { x, y, is_infinity }
    }
    pub fn double(&self) -> Self {
        let a = F::from_canonical_u32(2);
        let three = F::from_canonical_u32(3);
        let two = F::from_canonical_u32(2);

        let x1 = &self.x;
        let y1 = &self.y;
        let x1_sqr = x1.square();

        // x3 = (3*x1^2 + a)^2 / (2*y1)^2 - x1 - x1
        let slope = (x1_sqr * three + a) * (y1 * two).inverse().unwrap();
        let x3 = slope.square() - x1 - x1;
        // y3 = slope * (x1 - x3) - y1
        let y3 = slope * (x1 - &x3) - y1;

        Self {
            x: x3,
            y: y3,
            is_infinity: false,
        }
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

impl<F: Field> Neg for SepticPoint<F> {
    type Output = SepticPoint<F>;

    fn neg(self) -> Self::Output {
        if self.is_infinity {
            return self;
        }

        Self {
            x: self.x,
            y: -self.y,
            is_infinity: false,
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

    pub fn point_at_infinity() -> Self {
        Self::default()
    }
}

impl<F: Field + FromUniformBytes> SepticPoint<F> {
    pub fn random(mut rng: impl RngCore) -> Self {
        loop {
            let x = SepticExtension::random(&mut rng);
            if let Some(point) = Self::from_x(x) {
                return point;
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SepticJacobianPoint<F> {
    pub x: SepticExtension<F>,
    pub y: SepticExtension<F>,
    pub z: SepticExtension<F>,
}

impl<F: Field> From<SepticPoint<F>> for SepticJacobianPoint<F> {
    fn from(p: SepticPoint<F>) -> Self {
        if p.is_infinity {
            Self::default()
        } else {
            Self {
                x: p.x,
                y: p.y,
                z: SepticExtension::one(),
            }
        }
    }
}

impl<F: Field> Default for SepticJacobianPoint<F> {
    fn default() -> Self {
        // return the point at infinity
        Self {
            x: SepticExtension::zero(),
            y: SepticExtension::one(),
            z: SepticExtension::zero(),
        }
    }
}

impl<F: Field> SepticJacobianPoint<F> {
    pub fn point_at_infinity() -> Self {
        Self::default()
    }

    pub fn is_on_curve(&self) -> bool {
        if self.z.is_zero() {
            return self.x.is_zero() && !self.y.is_zero();
        }

        let b: SepticExtension<F> = [0, 0, 0, 0, 0, 26, 0].into();
        let a: F = F::from_canonical_u32(2);

        let z2 = self.z.square();
        let z4 = z2.square();
        let z6 = &z4 * &z2;

        // y^2 = x^3 + 2x*z^4 + b*z^6
        self.y.square() == self.x.square() * &self.x + (&self.x * a * z4) + (b * &z6)
    }

    pub fn into_affine(self) -> SepticPoint<F> {
        if self.z.is_zero() {
            return SepticPoint::point_at_infinity();
        }

        let z_inv = self.z.inverse().unwrap();
        let z_inv2 = z_inv.square();
        let z_inv3 = &z_inv2 * &z_inv;

        let x = &self.x * &z_inv2;
        let y = &self.y * &z_inv3;

        SepticPoint {
            x,
            y,
            is_infinity: false,
        }
    }
}

impl<F: Field> Add<Self> for &SepticJacobianPoint<F> {
    type Output = SepticJacobianPoint<F>;

    fn add(self, rhs: Self) -> Self::Output {
        // https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html#addition-add-2007-bl
        if self.z.is_zero() {
            return rhs.clone();
        }

        if rhs.z.is_zero() {
            return self.clone();
        }

        let z1z1 = self.z.square();
        let z2z2 = rhs.z.square();

        let u1 = &self.x * &z2z2;
        let u2 = &rhs.x * &z1z1;

        let s1 = &self.y * &z2z2 * &rhs.z;
        let s2 = &rhs.y * &z1z1 * &self.z;

        if u1 == u2 {
            if s1 == s2 {
                return self.double();
            } else {
                return SepticJacobianPoint::point_at_infinity();
            }
        }

        let two = F::from_canonical_u32(2);
        let h = u2 - &u1;
        let i = (&h * two).square();
        let j = &h * &i;
        let r = (s2 - &s1) * two;
        let v = u1 * &i;

        let x3 = r.square() - &j - &v * two;
        let y3 = r * (v - &x3) - s1 * &j * two;
        let z3 = (&self.z + &rhs.z).square() - &z1z1 - &z2z2;
        let z3 = z3 * h;

        Self::Output {
            x: x3,
            y: y3,
            z: z3,
        }
    }
}

impl<F: Field> Add<Self> for SepticJacobianPoint<F> {
    type Output = SepticJacobianPoint<F>;

    fn add(self, rhs: Self) -> Self::Output {
        (&self).add(&rhs)
    }
}

impl<F: Field> SepticJacobianPoint<F> {
    pub fn double(&self) -> Self {
        // https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian.html#doubling-dbl-2007-bl

        // y = 0 means self.order = 2
        if self.y.is_zero() {
            return SepticJacobianPoint::point_at_infinity();
        }

        let two = F::from_canonical_u32(2);
        let three = F::from_canonical_u32(3);
        let eight = F::from_canonical_u32(8);
        let a = F::from_canonical_u32(2); // The curve coefficient a

        // xx = x1^2
        let xx = self.x.square();

        // yy = y1^2
        let yy = self.y.square();

        // yyyy = yy^2
        let yyyy = yy.square();

        // zz = z1^2
        let zz = self.z.square();

        // S = 2*((x1 + y1^2)^2 - x1^2 - y1^4)
        let s = (&self.x + &yy).square() - &xx - &yyyy;
        let s = s * two;

        // M = 3*x1^2 + a*z1^4
        let m = &xx * three + zz.square() * a;

        // T = M^2 - 2*S
        let t = m.square() - &s * two;

        // Y3 = M*(S-T)-8*y^4
        let y3 = m * (&s - &t) - &yyyy * eight;

        // X3 = T
        let x3 = t;

        // Z3 = (y1+z1)^2 - y1^2 - z1^2
        let z3 = (&self.y + &self.z).square() - &yy - &zz;

        Self {
            x: x3,
            y: y3,
            z: z3,
        }
    }
}

impl<F: Field> Sum<Self> for SepticJacobianPoint<F> {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Self::default(), |acc, p| acc + p)
    }
}

impl<F: Field + FromUniformBytes> SepticJacobianPoint<F> {
    pub fn random(rng: impl RngCore) -> Self {
        SepticPoint::random(rng).into()
    }
}

#[cfg(test)]
mod tests {
    use super::SepticExtension;
    use crate::scheme::septic_curve::{SepticJacobianPoint, SepticPoint};
    use p3::{babybear::BabyBear, field::{Field, FieldAlgebra}};
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

        let j1 = SepticJacobianPoint::from(p1.clone());
        let j2 = SepticJacobianPoint::from(p2.clone());

        let p3 = p1 + p2;
        let j3 = &j1 + &j2;

        assert!(j1.is_on_curve());
        assert!(j2.is_on_curve());

        assert!(j3.is_on_curve());
        assert!(p3.is_on_curve());

        assert_eq!(p3, j3.clone().into_affine());

        // 2*p3 - p3 = p3
        let p4 = p3.double();
        assert_eq!((-p3.clone() + p4.clone()), p3);

        // 2*j3 = 2*p3
        let j4 = j3.double();
        assert!(j4.is_on_curve());
        assert_eq!(j4.into_affine(), p4);
    }

    /// GPU vs CPU EC point computation test.
    /// Launches the `test_septic_ec_point` CUDA kernel with known inputs,
    /// then compares GPU outputs against CPU `ShardRamRecord::to_ec_point()`.
    #[test]
    #[cfg(feature = "gpu")]
    fn test_gpu_ec_point_matches_cpu() {
        use crate::tables::{ECPoint, ShardRamRecord};
        use ceno_gpu::bb31::test_impl::{TestEcInput, run_gpu_ec_test};
        use ceno_gpu::bb31::CudaHalBB31;
        use ff_ext::{PoseidonField, SmallField};
        use gkr_iop::RAMType;

        let hal = CudaHalBB31::new(0).unwrap();
        let perm = F::get_default_perm();

        // Test cases: various write/read, register/memory, edge cases
        let test_inputs = vec![
            TestEcInput { addr: 5, ram_type: 1, value: 0x12345678, is_write: 1, shard: 1, global_clk: 100 },
            TestEcInput { addr: 5, ram_type: 1, value: 0x12345678, is_write: 0, shard: 0, global_clk: 50 },
            TestEcInput { addr: 0x80000, ram_type: 2, value: 0xDEADBEEF, is_write: 1, shard: 2, global_clk: 200 },
            TestEcInput { addr: 0x80000, ram_type: 2, value: 0xDEADBEEF, is_write: 0, shard: 1, global_clk: 150 },
            TestEcInput { addr: 0, ram_type: 1, value: 0, is_write: 1, shard: 0, global_clk: 1 },
            TestEcInput { addr: 31, ram_type: 1, value: 0xFFFFFFFF, is_write: 0, shard: 3, global_clk: 999 },
            TestEcInput { addr: 0x40000000, ram_type: 2, value: 42, is_write: 1, shard: 5, global_clk: 500000 },
            TestEcInput { addr: 10, ram_type: 1, value: 1, is_write: 0, shard: 100, global_clk: 1000000 },
        ];

        let gpu_results = run_gpu_ec_test(&hal, &test_inputs);

        let mut mismatches = 0;
        for (i, (input, gpu_rec)) in test_inputs.iter().zip(gpu_results.iter()).enumerate() {
            // Build CPU ShardRamRecord and compute EC point
            let cpu_record = ShardRamRecord {
                addr: input.addr,
                ram_type: if input.ram_type == 1 { RAMType::Register } else { RAMType::Memory },
                value: input.value,
                shard: input.shard,
                local_clk: if input.is_write != 0 { input.global_clk } else { 0 },
                global_clk: input.global_clk,
                is_to_write_set: input.is_write != 0,
            };
            let cpu_ec: ECPoint<ff_ext::BabyBearExt4> = cpu_record.to_ec_point(&perm);

            let mut has_diff = false;

            if gpu_rec.nonce != cpu_ec.nonce {
                eprintln!("[{i}] nonce: gpu={} cpu={}", gpu_rec.nonce, cpu_ec.nonce);
                has_diff = true;
            }

            for j in 0..7 {
                let gpu_x = gpu_rec.point_x[j];
                let cpu_x = cpu_ec.point.x.0[j].to_canonical_u64() as u32;
                if gpu_x != cpu_x {
                    eprintln!("[{i}] x[{j}]: gpu={gpu_x} cpu={cpu_x}");
                    has_diff = true;
                }
                let gpu_y = gpu_rec.point_y[j];
                let cpu_y = cpu_ec.point.y.0[j].to_canonical_u64() as u32;
                if gpu_y != cpu_y {
                    eprintln!("[{i}] y[{j}]: gpu={gpu_y} cpu={cpu_y}");
                    has_diff = true;
                }
            }

            if has_diff {
                eprintln!("MISMATCH [{i}]: addr={} ram_type={} value={:#x} is_write={} shard={} clk={}",
                    input.addr, input.ram_type, input.value, input.is_write, input.shard, input.global_clk);
                mismatches += 1;
            }
        }

        assert_eq!(mismatches, 0,
            "{mismatches}/{} test cases had GPU/CPU EC point mismatches",
            test_inputs.len());
        eprintln!("All {} GPU EC point test cases match CPU!", test_inputs.len());
    }

    /// Verify GPU Poseidon2 permutation matches CPU on the exact sponge packing
    /// used by to_ec_point(). This isolates Montgomery encoding correctness.
    #[test]
    #[cfg(feature = "gpu")]
    fn test_gpu_poseidon2_sponge_matches_cpu() {
        use ceno_gpu::bb31::test_impl::{run_gpu_poseidon2_sponge, SPONGE_WIDTH};
        use ceno_gpu::bb31::CudaHalBB31;
        use ff_ext::{PoseidonField, SmallField};
        use p3::symmetric::Permutation;

        let hal = CudaHalBB31::new(0).unwrap();
        let perm = F::get_default_perm();

        // Build sponge inputs matching to_ec_point packing:
        // [addr, ram_type, value_lo16, value_hi16, shard, global_clk, nonce, 0..0]
        let test_cases: Vec<[u32; SPONGE_WIDTH]> = vec![
            // Case 1: typical write record
            {
                let mut s = [0u32; SPONGE_WIDTH];
                s[0] = 5;               // addr
                s[1] = 1;               // ram_type (Register)
                s[2] = 0x5678;          // value lo16
                s[3] = 0x1234;          // value hi16
                s[4] = 1;               // shard
                s[5] = 100;             // global_clk
                s[6] = 0;               // nonce
                s
            },
            // Case 2: memory read, different values
            {
                let mut s = [0u32; SPONGE_WIDTH];
                s[0] = 0x80000;
                s[1] = 2;               // Memory
                s[2] = 0xBEEF;
                s[3] = 0xDEAD;
                s[4] = 2;
                s[5] = 200;
                s[6] = 3;               // nonce=3
                s
            },
            // Case 3: all zeros (edge case)
            [0u32; SPONGE_WIDTH],
        ];

        let count = test_cases.len();
        let flat_input: Vec<u32> = test_cases.iter().flat_map(|s| s.iter().copied()).collect();
        let gpu_output = run_gpu_poseidon2_sponge(&hal, &flat_input, count);

        let mut mismatches = 0;
        for (i, input) in test_cases.iter().enumerate() {
            // CPU Poseidon2
            let cpu_input: Vec<F> = input.iter().map(|&v| F::from_canonical_u32(v)).collect();
            let cpu_output = perm.permute(cpu_input);

            for j in 0..SPONGE_WIDTH {
                let gpu_v = gpu_output[i * SPONGE_WIDTH + j];
                let cpu_v = cpu_output[j].to_canonical_u64() as u32;
                if gpu_v != cpu_v {
                    eprintln!("[case {i}] sponge[{j}]: gpu={gpu_v} cpu={cpu_v}");
                    mismatches += 1;
                }
            }
        }

        assert_eq!(mismatches, 0, "{mismatches} Poseidon2 output elements differ between GPU and CPU");
        eprintln!("All {} Poseidon2 sponge test cases match!", count);
    }

    /// Verify GPU septic_point_from_x matches CPU SepticPoint::from_x.
    /// Tests the full GF(p^7) sqrt (Cipolla) + curve equation.
    #[test]
    #[cfg(feature = "gpu")]
    fn test_gpu_septic_from_x_matches_cpu() {
        use ceno_gpu::bb31::test_impl::run_gpu_septic_from_x;
        use ceno_gpu::bb31::CudaHalBB31;
        use ff_ext::SmallField;

        let hal = CudaHalBB31::new(0).unwrap();

        // Generate test x-coordinates by hashing known inputs
        // (ensures we get a mix of points-exist and points-don't-exist cases)
        let test_xs: Vec<[u32; 7]> = vec![
            // x from Poseidon2([5,1,0x5678,0x1234,1,100,0, 0..]) — known to have a point
            [1594766074, 868528894, 1733778006, 1242721508, 1690833816, 1437202757, 1753525271],
            // Simple: x = [1,0,0,0,0,0,0]
            [1, 0, 0, 0, 0, 0, 0],
            // x = [0,0,0,0,0,0,0] (zero)
            [0, 0, 0, 0, 0, 0, 0],
            // x = [42, 17, 999, 0, 0, 0, 0]
            [42, 17, 999, 0, 0, 0, 0],
            // Random-ish values
            [1000000007, 123456789, 987654321, 111111111, 222222222, 333333333, 444444444],
        ];

        let count = test_xs.len();
        let flat_x: Vec<u32> = test_xs.iter().flat_map(|x| x.iter().copied()).collect();
        let (gpu_y, gpu_flags) = run_gpu_septic_from_x(&hal, &flat_x, count);

        let mut mismatches = 0;
        for (i, x_arr) in test_xs.iter().enumerate() {
            // CPU: SepticPoint::from_x
            let x = SepticExtension(x_arr.map(|v| F::from_canonical_u32(v)));
            let cpu_result = SepticPoint::<F>::from_x(x);

            let gpu_found = gpu_flags[i] != 0;
            let cpu_found = cpu_result.is_some();

            if gpu_found != cpu_found {
                eprintln!("[{i}] from_x existence: gpu={gpu_found} cpu={cpu_found}");
                mismatches += 1;
                continue;
            }

            if let Some(cpu_pt) = cpu_result {
                // Compare y coordinates (GPU returns canonical, before any negation)
                for j in 0..7 {
                    let gpu_v = gpu_y[i * 7 + j];
                    let cpu_v = cpu_pt.y.0[j].to_canonical_u64() as u32;
                    // from_x returns the "natural" sqrt; they should match exactly
                    if gpu_v != cpu_v {
                        eprintln!("[{i}] y[{j}]: gpu={gpu_v} cpu={cpu_v}");
                        mismatches += 1;
                    }
                }
            }
        }

        assert_eq!(mismatches, 0,
            "{mismatches} septic_from_x results differ between GPU and CPU");
        eprintln!("All {} septic_from_x test cases match!", count);
    }
}
