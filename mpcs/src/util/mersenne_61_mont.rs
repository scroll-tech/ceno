use crate::util::{
    arithmetic::{modulus, Field},
    BigUint,
};
use core::{
    iter::{Product, Sum},
    ops::{Add, AddAssign, Div, DivAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};
use ff::{BatchInvert, PrimeFieldBits};
use halo2_curves::ff::PrimeField;
use rand::RngCore;
use rand::SeedableRng;
use serde::{Deserialize, Serialize};
use std::fmt::{Debug, Display, Formatter};
use std::ops::{BitAnd, Shr};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption};

#[derive(PrimeField, Serialize, Deserialize, Hash)]
#[PrimeFieldModulus = "2305843009213693951"]
#[PrimeFieldGenerator = "7"]
#[PrimeFieldReprEndianness = "little"]
pub struct Mersenne61Mont([u64; 1]);
