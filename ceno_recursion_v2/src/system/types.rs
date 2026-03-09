use ceno_zkvm::structs::ZKVMVerifyingKey;
use ff_ext::BabyBearExt4;
use mpcs::{Basefold, BasefoldRSParams};

pub type RecursionField = BabyBearExt4;
pub type RecursionPcs = Basefold<RecursionField, BasefoldRSParams>;
pub type RecursionVk = ZKVMVerifyingKey<RecursionField, RecursionPcs>;
