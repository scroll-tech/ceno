use std::ops::Neg;

use crate::fp::Goldilocks;
use crate::fp::LegendreSymbol;

use ark_std::{end_timer, start_timer};
use ff::Field;
use ff::PrimeField;
use rand_core::RngCore;
use rand_core::SeedableRng;
use rand_xorshift::XorShiftRng;

use super::random_field_tests;
use super::random_prime_field_tests;
#[test]
fn test_sqrt_fq() {
    let mut rng = XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);

    let two_inv = Goldilocks(0x7fffffff80000001);
    let v = two_inv.square().sqrt().unwrap();
    assert!(v == two_inv || (-v) == two_inv);

    for _ in 0..10000 {
        let a = Goldilocks::random(&mut rng);
        let mut b = a;
        b = b.square();
        assert_eq!(b.legendre(), LegendreSymbol::QuadraticResidue);

        let b = b.sqrt().unwrap();
        let mut negb = b;
        negb = negb.neg();
        assert!(a == b || a == negb);
    }

    let mut c = Goldilocks::ONE;
    for _ in 0..10000 {
        let mut b = c;
        b = b.square();
        assert_eq!(b.legendre(), LegendreSymbol::QuadraticResidue);

        b = b.sqrt().unwrap();

        if b != c {
            b = b.neg();
        }

        assert_eq!(b, c);

        c += &Goldilocks::ONE;
    }
}

#[test]
fn test_field() {
    random_field_tests::<Goldilocks>("Goldilocks".to_string());
    random_prime_field_tests::<Goldilocks>("Goldilocks".to_string());
}
