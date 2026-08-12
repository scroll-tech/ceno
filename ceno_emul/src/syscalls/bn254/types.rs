use substrate_bn::{AffineG1, Fq, Fq2, Fr, G1};

use crate::Word;

pub const BN254_FP_WORDS: usize = 8;
pub const BN254_FP2_WORDS: usize = 2 * BN254_FP_WORDS;
pub const BN254_POINT_WORDS: usize = 2 * BN254_FP_WORDS;

pub struct Bn254Fp(substrate_bn::Fq);

impl From<[Word; BN254_FP_WORDS]> for Bn254Fp {
    fn from(value: [Word; BN254_FP_WORDS]) -> Self {
        let mut bytes_be: [u8; 32] = unsafe { std::mem::transmute(value) };
        bytes_be.reverse();
        Bn254Fp(Fq::from_slice(&bytes_be).expect("cannot parse Fq"))
    }
}

impl From<Bn254Fp> for [Word; BN254_FP_WORDS] {
    fn from(value: Bn254Fp) -> Self {
        let mut bytes_be = [0u8; 32];
        value
            .0
            .to_big_endian(&mut bytes_be)
            .expect("cannot serialize Fq");
        bytes_be.reverse();

        unsafe { std::mem::transmute(bytes_be) }
    }
}

impl std::ops::Add for Bn254Fp {
    type Output = Bn254Fp;
    fn add(self, rhs: Self) -> Self::Output {
        Bn254Fp(self.0 + rhs.0)
    }
}

impl std::ops::Mul for Bn254Fp {
    type Output = Bn254Fp;
    fn mul(self, rhs: Self) -> Self::Output {
        Bn254Fp(self.0 * rhs.0)
    }
}

pub struct Bn254Fp2(substrate_bn::Fq2);

impl From<[Word; BN254_FP2_WORDS]> for Bn254Fp2 {
    fn from(value: [Word; BN254_FP2_WORDS]) -> Self {
        let first_half: [Word; BN254_FP_WORDS] = value[..BN254_FP_WORDS].try_into().unwrap();
        let second_half: [Word; BN254_FP_WORDS] = value[BN254_FP_WORDS..].try_into().unwrap();
        // notation: Fq2 is a + bi (a real and b imaginary)
        let a = Bn254Fp::from(first_half).0;
        let b = Bn254Fp::from(second_half).0;
        Bn254Fp2(Fq2::new(a, b))
    }
}

impl From<Bn254Fp2> for [Word; BN254_FP2_WORDS] {
    fn from(value: Bn254Fp2) -> Self {
        // notation: Fq2 is a + bi (a real and b imaginary)
        let first_half: [Word; BN254_FP_WORDS] = Bn254Fp(value.0.real()).into();
        let second_half: [Word; BN254_FP_WORDS] = Bn254Fp(value.0.imaginary()).into();

        let mut words = [0; BN254_FP2_WORDS];
        words[..BN254_FP_WORDS].copy_from_slice(&first_half);
        words[BN254_FP_WORDS..].copy_from_slice(&second_half);
        words
    }
}

impl std::ops::Add for Bn254Fp2 {
    type Output = Bn254Fp2;
    fn add(self, rhs: Self) -> Self::Output {
        Bn254Fp2(self.0 + rhs.0)
    }
}

impl std::ops::Mul for Bn254Fp2 {
    type Output = Bn254Fp2;
    fn mul(self, rhs: Self) -> Self::Output {
        Bn254Fp2(self.0 * rhs.0)
    }
}

#[derive(Debug)]
pub struct Bn254Point(substrate_bn::G1);

impl From<[Word; BN254_POINT_WORDS]> for Bn254Point {
    fn from(value: [Word; BN254_POINT_WORDS]) -> Self {
        let first_half: [Word; BN254_FP_WORDS] = value[..BN254_FP_WORDS].try_into().unwrap();
        let second_half: [Word; BN254_FP_WORDS] = value[BN254_FP_WORDS..].try_into().unwrap();
        let a = Bn254Fp::from(first_half).0;
        let b = Bn254Fp::from(second_half).0;
        Bn254Point(G1::new(a, b, Fq::one()))
    }
}

impl From<Bn254Point> for [Word; BN254_POINT_WORDS] {
    fn from(value: Bn254Point) -> Self {
        let affine = AffineG1::from_jacobian(value.0).expect("cannot unpack affine");
        let first_half: [Word; BN254_FP_WORDS] = Bn254Fp(affine.x()).into();
        let second_half: [Word; BN254_FP_WORDS] = Bn254Fp(affine.y()).into();

        let mut words = [0; BN254_POINT_WORDS];
        words[..BN254_FP_WORDS].copy_from_slice(&first_half);
        words[BN254_FP_WORDS..].copy_from_slice(&second_half);
        words
    }
}

impl std::ops::Add for Bn254Point {
    type Output = Bn254Point;
    fn add(self, rhs: Self) -> Self::Output {
        Bn254Point(self.0 + rhs.0)
    }
}

impl Bn254Point {
    pub fn double(&self) -> Self {
        let two = Fr::from_str("2").unwrap();
        Bn254Point(self.0 * two)
    }
}
