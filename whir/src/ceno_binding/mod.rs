mod merkle_config;
mod pcs;
pub use ark_crypto_primitives::merkle_tree::Config;
pub use pcs::{DefaultHash, InnerDigestOf, Whir, WhirDefaultSpec, WhirSpec};

use ark_ff::FftField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use serde::{Serialize, de::DeserializeOwned};
use std::fmt::Debug;

pub use nimue::{
    ProofResult,
    plugins::ark::{FieldChallenges, FieldWriter},
};

#[derive(Debug, Clone, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    ProofError(#[from] nimue::ProofError),
    #[error("CommitmentMismatchFromDigest")]
    CommitmentMismatchFromDigest,
    #[error("InvalidPcsParams")]
    InvalidPcsParam,
}

/// The trait for a non-interactive polynomial commitment scheme.
/// This trait serves as the intermediate step between WHIR and the
/// trait required in Ceno mpcs. Because Ceno and the WHIR implementation
/// in this crate assume different types of transcripts, to connect
/// them we can provide a non-interactive interface from WHIR.
pub trait PolynomialCommitmentScheme<E: FftField>: Clone {
    type Param: Clone + Debug + Serialize + DeserializeOwned;
    type Commitment: Clone + Debug;
    type CommitmentWithWitness: Clone + Debug;
    type Proof: Clone + CanonicalSerialize + CanonicalDeserialize + Serialize + DeserializeOwned;
    type Poly: Clone + Debug + Serialize + DeserializeOwned;

    fn setup(poly_size: usize) -> Self::Param;

    fn commit(pp: &Self::Param, poly: &Self::Poly) -> Result<Self::CommitmentWithWitness, Error>;

    fn batch_commit(
        pp: &Self::Param,
        polys: &[Self::Poly],
    ) -> Result<Self::CommitmentWithWitness, Error>;

    fn open(
        pp: &Self::Param,
        comm: &Self::CommitmentWithWitness,
        point: &[E],
        eval: &E,
    ) -> Result<Self::Proof, Error>;

    /// This is a simple version of batch open:
    /// 1. Open at one point
    /// 2. All the polynomials share the same commitment.
    /// 3. The point is already a random point generated by a sum-check.
    fn simple_batch_open(
        pp: &Self::Param,
        comm: &Self::CommitmentWithWitness,
        point: &[E],
        evals: &[E],
    ) -> Result<Self::Proof, Error>;

    fn verify(
        vp: &Self::Param,
        comm: &Self::Commitment,
        point: &[E],
        eval: &E,
        proof: &Self::Proof,
    ) -> Result<(), Error>;

    fn simple_batch_verify(
        vp: &Self::Param,
        comm: &Self::Commitment,
        point: &[E],
        evals: &[E],
        proof: &Self::Proof,
    ) -> Result<(), Error>;
}
