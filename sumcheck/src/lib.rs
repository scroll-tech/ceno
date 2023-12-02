mod prover;
pub mod structs;
mod util;
mod verifier;
use std::{fmt::Debug, sync::Arc};

use ff::FromUniformBytes;
use goldilocks::SmallField;
use multilinear_extensions::{
    mle::DenseMultilinearExtension,
    virtual_poly::{VPAuxInfo, VirtualPolynomial},
};
use structs::{IOPProof, SumCheckSubClaim};
use transcript::Transcript;

use crate::structs::IOPProverState;

#[cfg(test)]
mod test;
