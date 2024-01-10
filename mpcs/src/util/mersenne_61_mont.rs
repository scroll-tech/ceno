use halo2_curves::ff::PrimeField;
use serde::{Deserialize, Serialize};

#[derive(PrimeField, Serialize, Deserialize, Hash)]
#[PrimeFieldModulus = "2305843009213693951"]
#[PrimeFieldGenerator = "7"]
#[PrimeFieldReprEndianness = "little"]
pub struct Mersenne61Mont([u64; 1]);
