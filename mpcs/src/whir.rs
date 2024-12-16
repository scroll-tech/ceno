use super::PolynomialCommitmentScheme;
use ark_ff::{FftField, Field, PrimeField};
use ff_ext::ExtensionField;
use rand::{distributions::Standard, prelude::Distribution};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::marker::PhantomData;
use whir::{
    ceno_binding::{
        DigestIO, PolynomialCommitmentScheme as WhirPCS, Whir as WhirInner,
        WhirSpec as WhirSpecInner,
    },
    whir::iopattern::WhirIOPattern,
};

mod ff;
mod ff_base;
use ff::ExtensionFieldWrapper as FieldWrapper;

trait WhirSpec<E: ExtensionField>: std::fmt::Debug + Clone {
    type Spec: WhirSpecInner<FieldWrapper<E>> + std::fmt::Debug
    where
        <Self::Spec as WhirSpecInner<FieldWrapper<E>>>::MerkleConfig: DigestIO<FieldWrapper<E>>;
}

#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct Whir<E: ExtensionField, Spec: WhirSpec<E>>
where
    <Spec::Spec as WhirSpecInner<FieldWrapper<E>>>::MerkleConfig: DigestIO<FieldWrapper<E>>,
{
    inner: WhirInner<FieldWrapper<E>, Spec::Spec>,
}

type WhirInnerT<E, Spec> = WhirInner<FieldWrapper<E>, <Spec as WhirSpec<E>>::Spec>;

impl<E: ExtensionField, Spec: WhirSpec<E>> PolynomialCommitmentScheme<E> for Whir<E, Spec>
where
    E: Serialize + DeserializeOwned,
    E::BaseField: Serialize + DeserializeOwned,
    <Spec::Spec as WhirSpecInner<FieldWrapper<E>>>::MerkleConfig: DigestIO<FieldWrapper<E>>,
{
    type Param = <WhirInnerT<E, Spec> as WhirPCS<FieldWrapper<E>>>::Param;
    type ProverParam = <WhirInnerT<E, Spec> as WhirPCS<FieldWrapper<E>>>::Param;
    type VerifierParam = <WhirInnerT<E, Spec> as WhirPCS<FieldWrapper<E>>>::Param;
    type Commitment = <WhirInnerT<E, Spec> as WhirPCS<FieldWrapper<E>>>::Commitment;
    type Proof = <WhirInnerT<E, Spec> as WhirPCS<FieldWrapper<E>>>::Proof;
    type CommitmentWithWitness =
        <WhirInnerT<E, Spec> as WhirPCS<FieldWrapper<E>>>::CommitmentWithWitness;
    type CommitmentChunk = <WhirInnerT<E, Spec> as WhirPCS<FieldWrapper<E>>>::CommitmentChunk;

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

#[cfg(test)]
mod tests {
    use ark_ff::{Field, Fp2, MontBackend, MontConfig};
    use goldilocks::GoldilocksExt2;
    use rand::Rng;

    use super::*;

    type F = ff::ExtensionFieldWrapper<GoldilocksExt2>;

    use whir::ceno_binding::{PolynomialCommitmentScheme, WhirDefaultSpec};

    #[test]
    fn single_point_verify() {
        let poly_size = 10;
        let num_coeffs = 1 << poly_size;
        let pp = WhirInner::<F, WhirDefaultSpec>::setup(poly_size);

        let poly = CoefficientList::new(
            (0..num_coeffs)
                .map(<F as Field>::BasePrimeField::from)
                .collect(),
        );

        let io = IOPattern::<DefaultHash>::new("🌪️")
            .commit_statement(&pp)
            .add_whir_proof(&pp);
        let mut merlin = io.to_merlin();

        let witness = Whir::<F, Spec>::commit_and_write(&pp, &poly, &mut merlin).unwrap();

        let mut rng = rand::thread_rng();
        let point: Vec<F> = (0..poly_size).map(|_| F::from(rng.gen::<u64>())).collect();
        let eval = poly.evaluate_at_extension(&MultilinearPoint(point.clone()));

        let proof = Whir::<F, Spec>::open(&pp, witness, &point, &eval, &mut merlin).unwrap();
        Whir::<F, Spec>::verify(&pp, &point, &eval, &proof, &merlin).unwrap();
    }
}
