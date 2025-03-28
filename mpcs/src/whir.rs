mod spec;
mod structure;

use crate::util::log2_strict;

use super::PolynomialCommitmentScheme;
use ff_ext::ExtensionField;
use multilinear_extensions::mle::MultilinearExtension;
use serde::{Serialize, de::DeserializeOwned};
pub use spec::WhirDefaultSpec;
use spec::WhirSpec;
use structure::WhirCommitment;
pub use structure::{Whir, WhirDefault};
use whir_external::{
    crypto::{Digest, MerklePathExt, MerkleTreeExt},
    parameters::MultivariateParameters,
    whir::{
        Statement, WhirProof, batch::Witnesses, committer::Committer, parameters::WhirConfig,
        prover::Prover, verifier::Verifier,
    },
};

impl<E: ExtensionField, Spec: WhirSpec<E>> PolynomialCommitmentScheme<E> for Whir<E, Spec>
where
    E: Serialize + DeserializeOwned,
    E::BaseField: Serialize + DeserializeOwned,
    Digest<E>: IntoIterator<Item = E::BaseField> + PartialEq,
    MerklePathExt<E>: Send + Sync,
    MerkleTreeExt<E>: Send + Sync,
{
    type Param = ();
    type ProverParam = ();
    type VerifierParam = ();
    type Commitment = WhirCommitment<E>;
    type Proof = WhirProof<E>;
    type CommitmentWithWitness = Witnesses<E>;
    type CommitmentChunk = WhirCommitment<E>;

    fn setup(_poly_size: usize) -> Result<Self::Param, crate::Error> {
        Ok(())
    }

    fn trim(
        param: Self::Param,
        _poly_size: usize,
    ) -> Result<(Self::ProverParam, Self::VerifierParam), crate::Error> {
        Ok((param, param))
    }

    fn commit(
        _pp: &Self::ProverParam,
        poly: &multilinear_extensions::mle::DenseMultilinearExtension<E>,
    ) -> Result<Self::CommitmentWithWitness, crate::Error> {
        let parameters = Spec::get_whir_parameters(false);
        let whir_config = WhirConfig::new(MultivariateParameters::new(poly.num_vars()), parameters);
        let (witness, _commitment) = Committer::new(whir_config)
            .commit(poly.clone())
            .map_err(crate::Error::WhirError)?;

        Ok(witness.into())
    }

    fn write_commitment(
        comm: &Self::Commitment,
        transcript: &mut impl transcript::Transcript<E>,
    ) -> Result<(), crate::Error> {
        let parameters = Spec::get_whir_parameters(false);
        let whir_config = WhirConfig::new(MultivariateParameters::new(comm.num_vars), parameters);
        Verifier::new(whir_config)
            .write_commitment_to_transcript(comm.inner.as_ref().unwrap(), transcript);
        Ok(())
    }

    fn open(
        _pp: &Self::ProverParam,
        poly: &multilinear_extensions::mle::DenseMultilinearExtension<E>,
        comm: &Self::CommitmentWithWitness,
        point: &[E],
        eval: &E,
        transcript: &mut impl transcript::Transcript<E>,
    ) -> Result<Self::Proof, crate::Error> {
        let parameters = Spec::get_whir_parameters(false);
        let whir_config = WhirConfig::new(MultivariateParameters::new(poly.num_vars()), parameters);
        Prover(whir_config)
            .prove(
                transcript,
                Statement {
                    points: vec![point.to_vec()],
                    evaluations: vec![*eval],
                },
                comm,
            )
            .map_err(crate::Error::WhirError)
    }

    fn verify(
        _vp: &Self::VerifierParam,
        comm: &Self::Commitment,
        point: &[E],
        eval: &E,
        proof: &Self::Proof,
        transcript: &mut impl transcript::Transcript<E>,
    ) -> Result<(), crate::Error> {
        let parameters = Spec::get_whir_parameters(false);
        let whir_config = WhirConfig::new(MultivariateParameters::new(comm.num_vars), parameters);
        assert_eq!(comm.num_vars, point.len());
        Verifier::new(whir_config)
            .verify(
                comm.inner.as_ref().unwrap(),
                transcript,
                &Statement {
                    points: vec![point.to_vec()],
                    evaluations: vec![*eval],
                },
                proof,
            )
            .map_err(crate::Error::WhirError)
    }

    fn get_pure_commitment(comm: &Self::CommitmentWithWitness) -> Self::Commitment {
        Self::Commitment {
            inner: Some(comm.to_commitment_in_transcript()),
            num_vars: comm.num_vars(),
        }
    }

    fn batch_commit(
        _pp: &Self::ProverParam,
        rmm: witness::RowMajorMatrix<E::BaseField>,
    ) -> Result<Self::CommitmentWithWitness, crate::Error> {
        let parameters = Spec::get_whir_parameters(true);
        let whir_config = WhirConfig::new(
            MultivariateParameters::new(log2_strict(rmm.num_instances())),
            parameters,
        );
        let (witness, _commitment) = Committer::new(whir_config)
            .batch_commit(rmm)
            .map_err(crate::Error::WhirError)?;

        Ok(witness.into())
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
        _pp: &Self::ProverParam,
        polys: &[multilinear_extensions::virtual_poly::ArcMultilinearExtension<E>],
        comm: &Self::CommitmentWithWitness,
        point: &[E],
        evals: &[E],
        transcript: &mut impl transcript::Transcript<E>,
    ) -> Result<Self::Proof, crate::Error> {
        let parameters = Spec::get_whir_parameters(true);
        let whir_config =
            WhirConfig::new(MultivariateParameters::new(polys[0].num_vars()), parameters);
        let proof = Prover(whir_config)
            .simple_batch_prove(transcript, &[point.to_vec()], &[evals.to_vec()], comm)
            .map_err(crate::Error::WhirError)?;
        Ok(proof)
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
        _vp: &Self::VerifierParam,
        comm: &Self::Commitment,
        point: &[E],
        evals: &[E],
        proof: &Self::Proof,
        transcript: &mut impl transcript::Transcript<E>,
    ) -> Result<(), crate::Error> {
        let parameters = Spec::get_whir_parameters(true);
        let whir_config = WhirConfig::new(MultivariateParameters::new(comm.num_vars), parameters);
        assert_eq!(comm.num_vars, point.len());
        Verifier::new(whir_config)
            .simple_batch_verify(
                comm.inner.as_ref().unwrap(),
                transcript,
                evals.len(),
                &[point.to_vec()],
                &[evals.to_vec()],
                proof,
            )
            .map_err(crate::Error::WhirError)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::{
        gen_rand_poly_base, run_commit_open_verify, run_simple_batch_commit_open_verify,
    };
    use ff_ext::GoldilocksExt2;
    use spec::WhirDefaultSpec;
    use tracing_subscriber::{EnvFilter, Registry, layer::SubscriberExt};

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
        let filter = EnvFilter::from_default_env();
        let mut fmt_layer = tracing_subscriber::fmt::layer()
            .compact()
            .with_span_events(tracing_subscriber::fmt::format::FmtSpan::ENTER)
            .with_span_events(tracing_subscriber::fmt::format::FmtSpan::EXIT)
            .with_span_events(tracing_subscriber::fmt::format::FmtSpan::CLOSE)
            .with_thread_ids(false)
            .with_thread_names(false);
        fmt_layer.set_ansi(false);
        let subscriber = Registry::default().with(fmt_layer).with(filter);
        tracing::subscriber::set_global_default(subscriber).unwrap();
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
}
