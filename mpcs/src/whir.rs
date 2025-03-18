mod field_wrapper;
mod spec;
mod structure;
mod utils;

use super::PolynomialCommitmentScheme;
use ff_ext::ExtensionField;
use field_wrapper::ExtensionFieldWrapper as FieldWrapper;
use serde::{Serialize, de::DeserializeOwned};
pub use spec::WhirDefaultSpec;
use spec::WhirSpec;
pub use structure::{Whir, WhirDefault};
use structure::{WhirDigest, WhirInnerT, digest_to_bytes};
use utils::{poly2whir, polys2whir};
pub use whir::ceno_binding::Error;
use whir::ceno_binding::PolynomialCommitmentScheme as WhirPCS;
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
        WhirInnerT::<E, Spec>::setup(poly_size);
        Ok(())
    }

    fn trim(
        param: Self::Param,
        _poly_size: usize,
    ) -> Result<(Self::ProverParam, Self::VerifierParam), crate::Error> {
        Ok((param, param))
    }

    fn commit(
        pp: &Self::ProverParam,
        poly: &multilinear_extensions::mle::DenseMultilinearExtension<E>,
    ) -> Result<Self::CommitmentWithWitness, crate::Error> {
        let witness =
            WhirInnerT::<E, Spec>::commit(pp, &poly2whir(poly)).map_err(crate::Error::WhirError)?;

        Ok(witness)
    }

    fn write_commitment(
        comm: &Self::Commitment,
        transcript: &mut impl transcript::Transcript<E>,
    ) -> Result<(), crate::Error> {
        transcript.append_message(&digest_to_bytes::<Spec, E>(&comm.inner)?);
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
            pp,
            comm,
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
        let witness = WhirInnerT::<E, Spec>::batch_commit(pp, &polys2whir(polys))
            .map_err(crate::Error::WhirError)?;

        Ok(witness)
    }

    fn batch_open(
        _pp: &Self::ProverParam,
        _polys: &[multilinear_extensions::mle::DenseMultilinearExtension<E>],
        _comms: &[Self::CommitmentWithWitness],
        _points: &[Vec<E>],
        _evals: &[crate::Evaluation<E>],
        _transcript: &mut impl transcript::Transcript<E>,
    ) -> Result<Self::Proof, crate::Error> {
        todo!()
    }

    fn simple_batch_open(
        pp: &Self::ProverParam,
        _polys: &[multilinear_extensions::virtual_poly::ArcMultilinearExtension<E>],
        comm: &Self::CommitmentWithWitness,
        point: &[E],
        evals: &[E],
        _transcript: &mut impl transcript::Transcript<E>,
    ) -> Result<Self::Proof, crate::Error> {
        WhirInnerT::<E, Spec>::simple_batch_open(
            pp,
            comm,
            point
                .iter()
                .map(|x| FieldWrapper(*x))
                .collect::<Vec<_>>()
                .as_slice(),
            &evals.iter().map(|x| FieldWrapper(*x)).collect::<Vec<_>>(),
        )
        .map_err(crate::Error::WhirError)
    }

    fn batch_verify(
        _vp: &Self::VerifierParam,
        _comms: &[Self::Commitment],
        _points: &[Vec<E>],
        _evals: &[crate::Evaluation<E>],
        _proof: &Self::Proof,
        _transcript: &mut impl transcript::Transcript<E>,
    ) -> Result<(), crate::Error> {
        todo!()
    }

    fn simple_batch_verify(
        vp: &Self::VerifierParam,
        comm: &Self::Commitment,
        point: &[E],
        evals: &[E],
        proof: &Self::Proof,
        _transcript: &mut impl transcript::Transcript<E>,
    ) -> Result<(), crate::Error> {
        WhirInnerT::<E, Spec>::simple_batch_verify(
            vp,
            &comm.inner,
            &point.iter().map(|x| FieldWrapper(*x)).collect::<Vec<_>>(),
            &evals.iter().map(|x| FieldWrapper(*x)).collect::<Vec<_>>(),
            proof,
        )
        .map_err(crate::Error::WhirError)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::{
        gen_rand_poly_base, run_commit_open_verify, run_diff_size_batch_commit_open_verify, run_simple_batch_commit_open_verify
    };
    use ff_ext::GoldilocksExt2;
    use spec::WhirDefaultSpec;

    type PcsGoldilocks = Whir<GoldilocksExt2, WhirDefaultSpec>;

    #[test]
    fn whir_commit_open_verify_goldilocks() {
        // TODO: Only support committing to base field polynomial now
        {
            let gen_rand_poly = gen_rand_poly_base;
            // Challenge is over extension field, poly over the base field
            run_commit_open_verify::<GoldilocksExt2, PcsGoldilocks>(gen_rand_poly, 10, 11);
            // Test trivial proof with small num vars
            run_commit_open_verify::<GoldilocksExt2, PcsGoldilocks>(gen_rand_poly, 4, 6);
        }
    }

    #[test]
    #[ignore = "For benchmarking and profiling only"]
    fn bench_whir_simple_batch_commit_open_verify_goldilocks() {
        {
            let gen_rand_poly = gen_rand_poly_base;
            run_commit_open_verify::<GoldilocksExt2, PcsGoldilocks>(gen_rand_poly, 20, 21);
            run_simple_batch_commit_open_verify::<GoldilocksExt2, PcsGoldilocks>(
                gen_rand_poly,
                20,
                21,
                64,
            );
        }
    }

    #[test]
    fn whir_simple_batch_commit_open_verify_goldilocks() {
        {
            let gen_rand_poly = gen_rand_poly_base;
            // Both challenge and poly are over base field
            run_simple_batch_commit_open_verify::<GoldilocksExt2, PcsGoldilocks>(
                gen_rand_poly,
                10,
                16,
                1,
            );
            run_simple_batch_commit_open_verify::<GoldilocksExt2, PcsGoldilocks>(
                gen_rand_poly,
                10,
                11,
                4,
            );
            run_simple_batch_commit_open_verify::<GoldilocksExt2, PcsGoldilocks>(
                gen_rand_poly,
                7,
                8,
                3,
            );
            run_simple_batch_commit_open_verify::<GoldilocksExt2, PcsGoldilocks>(
                gen_rand_poly,
                7,
                8,
                2,
            );
            // Test trivial proof with small num vars
            run_simple_batch_commit_open_verify::<GoldilocksExt2, PcsGoldilocks>(
                gen_rand_poly,
                4,
                6,
                4,
            );
            // Both challenge and poly are over base field
            run_simple_batch_commit_open_verify::<GoldilocksExt2, PcsGoldilocks>(
                gen_rand_poly,
                4,
                6,
                1,
            );
        }
    }

    #[test]
    fn batch_commit_diff_size_open_verify() {
        let gen_rand_poly = gen_rand_poly_base;
        run_diff_size_batch_commit_open_verify::<GoldilocksExt2, PcsGoldilocks>(
            gen_rand_poly,
            20,
            3,
            3,
        );
    }
}
