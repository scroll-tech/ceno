use crate::util::{
    arithmetic::{Field},
};
use core::{
    ops::{AddAssign, MulAssign, SubAssign},
};

use halo2_curves::ff::PrimeField;
use rand::RngCore;

use serde::{Deserialize, Serialize};


use subtle::{ConditionallySelectable, ConstantTimeEq};

#[derive(PrimeField, Serialize, Deserialize, Hash)]
#[PrimeFieldModulus = "2305843009213693951"]
#[PrimeFieldGenerator = "7"]
#[PrimeFieldReprEndianness = "little"]
pub struct Mersenne61Mont([u64; 1]);
