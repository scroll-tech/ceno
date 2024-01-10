use halo2_curves::ff::PrimeField;
use serde::{Deserialize, Serialize};

#[derive(PrimeField, Serialize, Deserialize, Hash)]
#[PrimeFieldModulus = "18446744069414584321"]
#[PrimeFieldGenerator = "7"]
#[PrimeFieldReprEndianness = "little"]
pub struct GoldilocksMont([u64; 2]);
