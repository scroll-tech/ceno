use std::ops::Neg;

use crate::fp::Goldilocks;
use crate::fp::LegendreSymbol;
use crate::fp3::GoldilocksExt3;

use ark_std::{end_timer, start_timer};
use ff::Field;
use ff::PrimeField;
use rand_core::RngCore;
use rand_core::SeedableRng;
use rand_xorshift::XorShiftRng;

use super::random_field_tests;
use super::random_prime_field_tests;

#[test]
fn test_field() {
    random_field_tests::<GoldilocksExt3>("GoldilocksExt3".to_string());
    random_prime_field_tests::<Goldilocks>("Goldilocks".to_string());
}

#[test]
fn known_answer_tests() {
    let a = GoldilocksExt3([
        Goldilocks::from(1),
        Goldilocks::from(2),
        Goldilocks::from(3),
    ]);
    let b = GoldilocksExt3([
        Goldilocks::from(4),
        Goldilocks::from(5),
        Goldilocks::from(6),
    ]);
    let c = GoldilocksExt3([
        Goldilocks::from(31),
        Goldilocks::from(31),
        Goldilocks::from(28),
    ]);
    assert_eq!(a * b, c)
}
