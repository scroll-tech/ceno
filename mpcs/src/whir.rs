use core::todo;

use super::PolynomialCommitmentScheme;
use utils::poly2whir;
pub use whir::ceno_binding::Error;

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ff_ext::ExtensionField;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use whir::{
    ceno_binding::{
        Config, DefaultHash, FieldChallenges, FieldWriter, PolynomialCommitmentScheme as WhirPCS,
        Whir as WhirInner, WhirSpec as WhirSpecInner,
    },
    whir::{
        fs_utils::{DigestReader, DigestWriter},
        iopattern::{Arthur, IOPattern, Merlin, WhirIOPattern},
    },
};

mod ff;
mod ff_base;
mod utils;
use ff::ExtensionFieldWrapper as FieldWrapper;

pub trait WhirSpec<E: ExtensionField>: Default + std::fmt::Debug + Clone {
    // TODO: Remove these horrifying where clauses
    type Spec: WhirSpecInner<FieldWrapper<E>> + std::fmt::Debug + Default;
}

#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct Whir<E: ExtensionField, Spec: WhirSpec<E>>
// TODO: Remove these horrifying where clauses
where
    Merlin: DigestWriter<<Spec::Spec as WhirSpecInner<FieldWrapper<E>>>::MerkleConfig>,
    for<'a> Arthur<'a>: DigestReader<<Spec::Spec as WhirSpecInner<FieldWrapper<E>>>::MerkleConfig>,
    IOPattern: WhirIOPattern<FieldWrapper<E>, <Spec::Spec as WhirSpecInner<FieldWrapper<E>>>::MerkleConfig>,
{
    inner: WhirInner<FieldWrapper<E>, Spec::Spec>,
}

type WhirInnerT<E, Spec> = WhirInner<FieldWrapper<E>, <Spec as WhirSpec<E>>::Spec>;

#[derive(Default, Clone, Debug)]
pub struct WhirDigest<E: ExtensionField, Spec: WhirSpec<E>> {
    inner: <<Spec::Spec as WhirSpecInner<FieldWrapper<E>>>::MerkleConfig as Config>::InnerDigest,
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
        let inner = <<Spec::Spec as WhirSpecInner<FieldWrapper<E>>>::MerkleConfig as Config>::InnerDigest::deserialize_compressed(&buffer[..]).map_err(serde::de::Error::custom)?;
        Ok(WhirDigest { inner })
    }
}

impl<E: ExtensionField, Spec: WhirSpec<E>> PolynomialCommitmentScheme<E> for Whir<E, Spec>
where
    E: Serialize + DeserializeOwned,
    E::BaseField: Serialize + DeserializeOwned,
    // TODO: Remove these horrifying stuffs
    Merlin: DigestWriter<<Spec::Spec as WhirSpecInner<FieldWrapper<E>>>::MerkleConfig>,
    for<'a> Arthur<'a>: DigestReader<<Spec::Spec as WhirSpecInner<FieldWrapper<E>>>::MerkleConfig>,
    IOPattern: WhirIOPattern<FieldWrapper<E>, <Spec::Spec as WhirSpecInner<FieldWrapper<E>>>::MerkleConfig>,
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
        // WhirInner only provides commit_and_write, which directly writes the
        // commitment to the transcript. We provide it with a temporary merlin
        // transcript.

        let io = IOPattern::<DefaultHash>::new("🌪️");
        let mut merlin = io.to_merlin();

        let witness = WhirInnerT::<E, Spec>::commit_and_write(&pp, &poly2whir(&poly), &mut merlin)
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
        transcript: &mut impl transcript::Transcript<E>,
    ) -> Result<Self::Proof, crate::Error> {
        let io = IOPattern::<DefaultHash>::new("🌪️");
        let mut merlin = io.to_merlin();
        // In WHIR, the prover writes the commitment to the transcript, then
        // the commitment is read from the transcript by the verifier, after
        // the transcript is transformed into a arthur transcript.
        // Here we repeat whatever the prover does.
        // TODO: This is a hack. There should be a better design that does not
        // require non-black-box knowledge of the inner working of WHIR.
        merlin
            .add_digest(comm.commitment.clone())
            .map_err(|err| crate::Error::WhirError(whir::ceno_binding::Error::ProofError(err)))?;
        let ood_answers = comm.ood_answers();
        if ood_answers.len() > 0 {
            let mut ood_points =
                vec![<FieldWrapper::<E> as ark_ff::AdditiveGroup>::ZERO; ood_answers.len()];
            merlin
                .fill_challenge_scalars(&mut ood_points)
                .map_err(|err| {
                    crate::Error::WhirError(whir::ceno_binding::Error::ProofError(err))
                })?;
            merlin.add_scalars(&ood_answers).map_err(|err| {
                crate::Error::WhirError(whir::ceno_binding::Error::ProofError(err))
            })?;
        }
        // Now the Merlin transcript is ready to pass to the verifier.

        WhirInnerT::<E, Spec>::open(
            &pp,
            comm.clone(), // TODO: Remove clone
            point
                .iter()
                .map(|x| FieldWrapper(*x))
                .collect::<Vec<_>>()
                .as_slice(),
            &FieldWrapper(*eval),
            &mut merlin,
        )
        .map_err(crate::Error::WhirError)
    }

    fn verify(
        vp: &Self::VerifierParam,
        comm: &Self::Commitment,
        point: &[E],
        eval: &E,
        proof: &Self::Proof,
        transcript: &mut impl transcript::Transcript<E>,
    ) -> Result<(), crate::Error> {
        Ok(())
    }
    fn get_pure_commitment(comm: &Self::CommitmentWithWitness) -> Self::Commitment {
        todo!()
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
    use ark_ff::{Field, Fp2, MontBackend, MontConfig};
    use goldilocks::GoldilocksExt2;
    use rand::Rng;

    use super::*;

    type F = ff::ExtensionFieldWrapper<GoldilocksExt2>;

    use whir::{
        ceno_binding::{DefaultHash, PolynomialCommitmentScheme, WhirDefaultSpec},
        poly_utils::{MultilinearPoint, coeffs::CoefficientList},
        whir::iopattern::IOPattern,
    };

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

        let io = IOPattern::<DefaultHash>::new("🌪️");
        let mut merlin = io.to_merlin();

        let witness =
            WhirInner::<F, WhirDefaultSpec>::commit_and_write(&pp, &poly, &mut merlin).unwrap();

        let mut rng = rand::thread_rng();
        let point: Vec<F> = (0..poly_size).map(|_| F::from(rng.gen::<u64>())).collect();
        let eval = poly.evaluate_at_extension(&MultilinearPoint(point.clone()));

        let proof = WhirInner::<F, WhirDefaultSpec>::open(&pp, witness, &point, &eval, &mut merlin)
            .unwrap();
        WhirInner::<F, WhirDefaultSpec>::verify(&pp, &point, &eval, &proof, &merlin).unwrap();
    }
}
