use super::PolynomialCommitmentScheme;
use ark_ff::{FftField, Field, PrimeField};
use ff_ext::ExtensionField;
use std::marker::PhantomData;
use whir::whir::pcs::Whir as WhirInner;

mod ff;
mod fp;

#[derive(Default, Clone, Debug)]
pub struct Whir<E: ExtensionField>(PhantomData<E>);

impl<E: ExtensionField> PolynomialCommitmentScheme<E> for Whir<E> {
    type Param;
    type ProverParam;
    type VerifierParam;
    type CommitmentWithData;
    type Commitment;
    type CommitmentChunk;
    type Proof;

    fn setup(poly_size: usize) -> Result<Self::Param, crate::Error> {
        todo!()
    }

    fn trim(
        param: Self::Param,
        poly_size: usize,
    ) -> Result<(Self::ProverParam, Self::VerifierParam), crate::Error> {
        todo!()
    }

    fn commit(
        pp: &Self::ProverParam,
        poly: &multilinear_extensions::mle::DenseMultilinearExtension<E>,
    ) -> Result<Self::CommitmentWithData, crate::Error> {
        todo!()
    }

    fn write_commitment(
        comm: &Self::Commitment,
        transcript: &mut transcript::Transcript<E>,
    ) -> Result<(), crate::Error> {
        todo!()
    }

    fn get_pure_commitment(comm: &Self::CommitmentWithData) -> Self::Commitment {
        todo!()
    }

    fn batch_commit(
        pp: &Self::ProverParam,
        polys: &[multilinear_extensions::mle::DenseMultilinearExtension<E>],
    ) -> Result<Self::CommitmentWithData, crate::Error> {
        todo!()
    }

    fn open(
        pp: &Self::ProverParam,
        poly: &multilinear_extensions::mle::DenseMultilinearExtension<E>,
        comm: &Self::CommitmentWithData,
        point: &[E],
        eval: &E,
        transcript: &mut transcript::Transcript<E>,
    ) -> Result<Self::Proof, crate::Error> {
        todo!()
    }

    fn batch_open(
        pp: &Self::ProverParam,
        polys: &[multilinear_extensions::mle::DenseMultilinearExtension<E>],
        comms: &[Self::CommitmentWithData],
        points: &[Vec<E>],
        evals: &[crate::Evaluation<E>],
        transcript: &mut transcript::Transcript<E>,
    ) -> Result<Self::Proof, crate::Error> {
        todo!()
    }

    fn simple_batch_open(
        pp: &Self::ProverParam,
        polys: &[multilinear_extensions::virtual_poly_v2::ArcMultilinearExtension<E>],
        comm: &Self::CommitmentWithData,
        point: &[E],
        evals: &[E],
        transcript: &mut transcript::Transcript<E>,
    ) -> Result<Self::Proof, crate::Error> {
        todo!()
    }

    fn verify(
        vp: &Self::VerifierParam,
        comm: &Self::Commitment,
        point: &[E],
        eval: &E,
        proof: &Self::Proof,
        transcript: &mut transcript::Transcript<E>,
    ) -> Result<(), crate::Error> {
        todo!()
    }

    fn batch_verify(
        vp: &Self::VerifierParam,
        comms: &[Self::Commitment],
        points: &[Vec<E>],
        evals: &[crate::Evaluation<E>],
        proof: &Self::Proof,
        transcript: &mut transcript::Transcript<E>,
    ) -> Result<(), crate::Error> {
        todo!()
    }

    fn simple_batch_verify(
        vp: &Self::VerifierParam,
        comm: &Self::Commitment,
        point: &[E],
        evals: &[E],
        proof: &Self::Proof,
        transcript: &mut transcript::Transcript<E>,
    ) -> Result<(), crate::Error> {
        todo!()
    }
}
