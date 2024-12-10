use super::PolynomialCommitmentScheme;
use ark_ff::{FftField, Field, PrimeField};
use ff_ext::ExtensionField;
use serde::{Deserialize, Serialize};
use std::marker::PhantomData;
use whir::whir::{PolynomialCommitmentScheme as WhirPCS, pcs::Whir as WhirInner};

mod ff;
use ff::ExtensionFieldWrapper as FieldWrapper;
// mod fp;

#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct Whir<E: ExtensionField> {
    _marker: PhantomData<E>,
    inner: WhirInner<E>,
}

impl<E: ExtensionField> PolynomialCommitmentScheme<E> for Whir<E> {
    type Param = <WhirInner<FieldWrapper<E>> as WhirPCS<FieldWrapper<E>>>::Param;
    type ProverParam = <WhirInner<FieldWrapper<E>> as WhirPCS<FieldWrapper<E>>>::Param;
    type VerifierParam = <WhirInner<FieldWrapper<E>> as WhirPCS<FieldWrapper<E>>>::Param;
    type Commitment = <WhirInner<FieldWrapper<E>> as WhirPCS<FieldWrapper<E>>>::Commitment;
    type Proof = <WhirInner<FieldWrapper<E>> as WhirPCS<FieldWrapper<E>>>::Proof;
    type CommitmentWithData =
        <WhirInner<FieldWrapper<E>> as WhirPCS<FieldWrapper<E>>>::CommitmentWithData;
    type CommitmentChunk =
        <WhirInner<FieldWrapper<E>> as WhirPCS<FieldWrapper<E>>>::CommitmentChunk;

    fn setup(poly_size: usize) -> Result<Self::Param, crate::Error> {
        Ok(WhirInner::default())
    }

    fn trim(
        param: Self::Param,
        poly_size: usize,
    ) -> Result<(Self::ProverParam, Self::VerifierParam), crate::Error> {
        Ok((param.clone(), param))
    }

    fn commit(
        pp: &Self::ProverParam,
        poly: &multilinear_extensions::mle::DenseMultilinearExtension<E>,
    ) -> Result<Self::Commitment, crate::Error> {
        Ok(pp.clone())
    }

    fn write_commitment(
        comm: &Self::Commitment,
        transcript: &mut transcript::Transcript<E>,
    ) -> Result<(), crate::Error> {
        Ok(())
    }

    fn open(
        pp: &Self::ProverParam,
        poly: &multilinear_extensions::mle::DenseMultilinearExtension<E>,
        comm: &Self::Commitment,
        point: &[E],
        eval: &E,
        transcript: &mut transcript::Transcript<E>,
    ) -> Result<Self::Proof, crate::Error> {
        Ok(pp.clone())
    }

    fn verify(
        vp: &Self::VerifierParam,
        comm: &Self::Commitment,
        point: &[E],
        eval: &E,
        proof: &Self::Proof,
        transcript: &mut transcript::Transcript<E>,
    ) -> Result<(), crate::Error> {
        Ok(())
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
