use core::todo;

use super::PolynomialCommitmentScheme;
use utils::poly2whir;
pub use whir::ceno_binding::Error;

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ff_ext::ExtensionField;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use whir::ceno_binding::{
    InnerDigestOf as InnerDigestOfInner, PolynomialCommitmentScheme as WhirPCS, Whir as WhirInner,
    WhirDefaultSpec as WhirDefaultSpecInner, WhirSpec as WhirSpecInner,
};

mod field_wrapper;
mod utils;
use field_wrapper::ExtensionFieldWrapper as FieldWrapper;

pub trait WhirSpec<E: ExtensionField>: Default + std::fmt::Debug + Clone {
    type Spec: WhirSpecInner<FieldWrapper<E>> + std::fmt::Debug + Default;
}

type InnerDigestOf<Spec, E> = InnerDigestOfInner<<Spec as WhirSpec<E>>::Spec, FieldWrapper<E>>;

#[derive(Debug, Clone, Default)]
pub struct WhirDefaultSpec;

impl<E: ExtensionField> WhirSpec<E> for WhirDefaultSpec {
    type Spec = WhirDefaultSpecInner;
}

#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct Whir<E: ExtensionField, Spec: WhirSpec<E>> {
    inner: WhirInner<FieldWrapper<E>, Spec::Spec>,
}

type WhirInnerT<E, Spec> = WhirInner<FieldWrapper<E>, <Spec as WhirSpec<E>>::Spec>;

#[derive(Default, Clone, Debug)]
pub struct WhirDigest<E: ExtensionField, Spec: WhirSpec<E>> {
    inner: InnerDigestOf<Spec, E>,
}

impl<E: ExtensionField, Spec: WhirSpec<E>> Serialize for WhirDigest<E, Spec> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let digest = &self.inner;
        // Create a buffer that implements the `Write` trait
        let mut buffer = Vec::new();
        digest.serialize_compressed(&mut buffer).unwrap();
        serializer.serialize_bytes(&buffer)
    }
}

impl<'de, E: ExtensionField, Spec: WhirSpec<E>> Deserialize<'de> for WhirDigest<E, Spec> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // Deserialize the bytes into a buffer
        let buffer: Vec<u8> = Deserialize::deserialize(deserializer)?;
        // Deserialize the buffer into a proof
        let inner = InnerDigestOf::<Spec, E>::deserialize_compressed(&buffer[..])
            .map_err(serde::de::Error::custom)?;
        Ok(WhirDigest { inner })
    }
}

impl<E: ExtensionField, Spec: WhirSpec<E>> PolynomialCommitmentScheme<E> for Whir<E, Spec>
where
    E: Serialize + DeserializeOwned,
    E::BaseField: Serialize + DeserializeOwned,
{
    type Param = <WhirInnerT<E, Spec> as WhirPCS<FieldWrapper<E>>>::Param;
    type ProverParam = <WhirInnerT<E, Spec> as WhirPCS<FieldWrapper<E>>>::Param;
    type VerifierParam = <WhirInnerT<E, Spec> as WhirPCS<FieldWrapper<E>>>::Param;
    type Commitment = WhirDigest<E, Spec>;
    type Proof = <WhirInnerT<E, Spec> as WhirPCS<FieldWrapper<E>>>::Proof;
    type CommitmentWithWitness =
        <WhirInnerT<E, Spec> as WhirPCS<FieldWrapper<E>>>::CommitmentWithWitness;
    type CommitmentChunk = WhirDigest<E, Spec>;

    fn setup(poly_size: usize) -> Result<Self::Param, crate::Error> {
        Ok(WhirInnerT::<E, Spec>::setup(poly_size))
    }

    fn trim(
        param: Self::Param,
        poly_size: usize,
    ) -> Result<(Self::ProverParam, Self::VerifierParam), crate::Error> {
        if poly_size > (1 << param.num_variables) {
            return Err(crate::Error::InvalidPcsParam(
                "Poly size is greater than param poly size".to_string(),
            ));
        }
        // TODO: Do the real trim instead of regenerating.
        let param = WhirInnerT::<E, Spec>::setup(poly_size);
        Ok((param.clone(), param.clone()))
    }

    fn commit(
        pp: &Self::ProverParam,
        poly: &multilinear_extensions::mle::DenseMultilinearExtension<E>,
    ) -> Result<Self::CommitmentWithWitness, crate::Error> {
        let witness = WhirInnerT::<E, Spec>::commit(&pp, &poly2whir(&poly))
            .map_err(crate::Error::WhirError)?;

        Ok(witness)
    }

    fn write_commitment(
        comm: &Self::Commitment,
        transcript: &mut impl transcript::Transcript<E>,
    ) -> Result<(), crate::Error> {
        let mut buffer = Vec::new();
        comm.inner
            .serialize_compressed(&mut buffer)
            .map_err(|err| crate::Error::Serialization(err.to_string()))?;
        transcript.append_message(&buffer);
        Ok(())
    }

    fn open(
        pp: &Self::ProverParam,
        _poly: &multilinear_extensions::mle::DenseMultilinearExtension<E>,
        comm: &Self::CommitmentWithWitness,
        point: &[E],
        eval: &E,
        _transcript: &mut impl transcript::Transcript<E>,
    ) -> Result<Self::Proof, crate::Error> {
        WhirInnerT::<E, Spec>::open(
            &pp,
            comm.clone(), // TODO: Remove clone
            point
                .iter()
                .map(|x| FieldWrapper(*x))
                .collect::<Vec<_>>()
                .as_slice(),
            &FieldWrapper(*eval),
        )
        .map_err(crate::Error::WhirError)
    }

    fn verify(
        vp: &Self::VerifierParam,
        comm: &Self::Commitment,
        point: &[E],
        eval: &E,
        proof: &Self::Proof,
        _transcript: &mut impl transcript::Transcript<E>,
    ) -> Result<(), crate::Error> {
        WhirInnerT::<E, Spec>::verify(
            vp,
            &comm.inner,
            &point.iter().map(|x| FieldWrapper(*x)).collect::<Vec<_>>(),
            &FieldWrapper(*eval),
            proof,
        )
        .map_err(crate::Error::WhirError)
    }

    fn get_pure_commitment(comm: &Self::CommitmentWithWitness) -> Self::Commitment {
        Self::Commitment {
            inner: comm.commitment.clone(),
        }
    }

    fn batch_commit(
        pp: &Self::ProverParam,
        polys: &[multilinear_extensions::mle::DenseMultilinearExtension<E>],
    ) -> Result<Self::CommitmentWithWitness, crate::Error> {
        todo!()
    }

    fn batch_open(
        pp: &Self::ProverParam,
        polys: &[multilinear_extensions::mle::DenseMultilinearExtension<E>],
        comms: &[Self::CommitmentWithWitness],
        points: &[Vec<E>],
        evals: &[crate::Evaluation<E>],
        transcript: &mut impl transcript::Transcript<E>,
    ) -> Result<Self::Proof, crate::Error> {
        todo!()
    }

    fn simple_batch_open(
        pp: &Self::ProverParam,
        polys: &[multilinear_extensions::virtual_poly_v2::ArcMultilinearExtension<E>],
        comm: &Self::CommitmentWithWitness,
        point: &[E],
        evals: &[E],
        transcript: &mut impl transcript::Transcript<E>,
    ) -> Result<Self::Proof, crate::Error> {
        todo!()
    }

    fn batch_verify(
        vp: &Self::VerifierParam,
        comms: &[Self::Commitment],
        points: &[Vec<E>],
        evals: &[crate::Evaluation<E>],
        proof: &Self::Proof,
        transcript: &mut impl transcript::Transcript<E>,
    ) -> Result<(), crate::Error> {
        todo!()
    }

    fn simple_batch_verify(
        vp: &Self::VerifierParam,
        comm: &Self::Commitment,
        point: &[E],
        evals: &[E],
        proof: &Self::Proof,
        transcript: &mut impl transcript::Transcript<E>,
    ) -> Result<(), crate::Error> {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use ark_ff::Field;
    use goldilocks::GoldilocksExt2;
    use rand::Rng;

    use crate::test_util::{gen_rand_poly_base, run_commit_open_verify};

    use super::*;

    type F = field_wrapper::ExtensionFieldWrapper<GoldilocksExt2>;

    use whir::{
        ceno_binding::{PolynomialCommitmentScheme, WhirDefaultSpec as WhirDefaultSpecInner},
        poly_utils::{MultilinearPoint, coeffs::CoefficientList},
    };

    #[test]
    fn whir_inner_commit_prove_verify() {
        let poly_size = 10;
        let num_coeffs = 1 << poly_size;
        let pp = WhirInner::<F, WhirDefaultSpecInner>::setup(num_coeffs as usize);

        let poly = CoefficientList::new(
            (0..num_coeffs)
                .map(<F as Field>::BasePrimeField::from)
                .collect(),
        );

        let witness = WhirInner::<F, WhirDefaultSpecInner>::commit(&pp, &poly).unwrap();
        let comm = witness.commitment;

        let mut rng = rand::thread_rng();
        let point: Vec<F> = (0..poly_size).map(|_| F::from(rng.gen::<u64>())).collect();
        let eval = poly.evaluate_at_extension(&MultilinearPoint(point.clone()));

        let proof =
            WhirInner::<F, WhirDefaultSpecInner>::open(&pp, witness, &point, &eval).unwrap();
        WhirInner::<F, WhirDefaultSpecInner>::verify(&pp, &comm, &point, &eval, &proof).unwrap();
    }

    type PcsGoldilocks = Whir<GoldilocksExt2, WhirDefaultSpec>;

    #[test]
    fn commit_open_verify_goldilocks() {
        // TODO: Only support committing to base field polynomial now
        for gen_rand_poly in [gen_rand_poly_base] {
            // Challenge is over extension field, poly over the base field
            run_commit_open_verify::<GoldilocksExt2, PcsGoldilocks>(gen_rand_poly, 10, 11);
            // Test trivial proof with small num vars
            run_commit_open_verify::<GoldilocksExt2, PcsGoldilocks>(gen_rand_poly, 4, 6);
        }
    }
}
