use super::merkle_config::{Blake3ConfigWrapper, WhirMerkleConfigWrapper};
use super::{Error, PolynomialCommitmentScheme};
use crate::crypto::merkle_tree::blake3::{self as mt};
use crate::parameters::{
    default_max_pow, FoldType, FoldingFactor, MultivariateParameters, SoundnessType, WhirParameters,
};
use crate::poly_utils::{coeffs::CoefficientList, MultilinearPoint};
use crate::whir::{
    batch::Witnesses, committer::Committer, parameters::WhirConfig, prover::Prover,
    verifier::Verifier, Statement, WhirProof,
};

use ark_crypto_primitives::merkle_tree::Config;
use ark_ff::FftField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use nimue::plugins::ark::{FieldChallenges, FieldWriter};
pub use nimue::DefaultHash;
use nimue::IOPattern;
use nimue_pow::blake3::Blake3PoW;
use rand::prelude::*;
use rand_chacha::ChaCha8Rng;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::fmt::{self, Debug, Formatter};
use std::marker::PhantomData;

pub trait WhirSpec<E: FftField>: Default + std::fmt::Debug + Clone {
    type MerkleConfigWrapper: WhirMerkleConfigWrapper<E>;
    fn get_parameters(
        num_variables: usize,
        for_batch: bool,
    ) -> WhirParameters<MerkleConfigOf<Self, E>, PowOf<Self, E>>;

    fn prepare_whir_config(
        num_variables: usize,
        for_batch: bool,
    ) -> WhirConfig<E, MerkleConfigOf<Self, E>, PowOf<Self, E>> {
        let whir_params = Self::get_parameters(num_variables, for_batch);
        let mv_params = MultivariateParameters::new(num_variables);
        ConfigOf::<Self, E>::new(mv_params, whir_params)
    }

    fn prepare_io_pattern(num_variables: usize) -> IOPattern {
        let params = Self::prepare_whir_config(num_variables, false);

        let io = IOPattern::<DefaultHash>::new("🌪️");
        let io = <Self::MerkleConfigWrapper as WhirMerkleConfigWrapper<E>>::commit_statement_to_io_pattern(
            io, &params,
        );
        let io =
            <Self::MerkleConfigWrapper as WhirMerkleConfigWrapper<E>>::add_whir_proof_to_io_pattern(
                io, &params,
            );

        io
    }

    fn prepare_batch_io_pattern(num_variables: usize, batch_size: usize) -> IOPattern {
        let params = Self::prepare_whir_config(num_variables, true);

        let io = IOPattern::<DefaultHash>::new("🌪️");
        let io = <Self::MerkleConfigWrapper as WhirMerkleConfigWrapper<E>>::commit_batch_statement_to_io_pattern(
            io, &params, batch_size
        );
        let io =
            <Self::MerkleConfigWrapper as WhirMerkleConfigWrapper<E>>::add_whir_batch_proof_to_io_pattern(
                io, &params, batch_size
            );

        io
    }
}

type MerkleConfigOf<Spec, E> =
    <<Spec as WhirSpec<E>>::MerkleConfigWrapper as WhirMerkleConfigWrapper<E>>::MerkleConfig;
type ConfigOf<Spec, E> = WhirConfig<E, MerkleConfigOf<Spec, E>, PowOf<Spec, E>>;

pub type InnerDigestOf<Spec, E> = <MerkleConfigOf<Spec, E> as Config>::InnerDigest;

type PowOf<Spec, E> =
    <<Spec as WhirSpec<E>>::MerkleConfigWrapper as WhirMerkleConfigWrapper<E>>::PowStrategy;

#[derive(Debug, Clone, Default)]
pub struct WhirDefaultSpec;

impl<E: FftField> WhirSpec<E> for WhirDefaultSpec {
    type MerkleConfigWrapper = Blake3ConfigWrapper<E>;
    fn get_parameters(
        num_variables: usize,
        for_batch: bool,
    ) -> WhirParameters<MerkleConfigOf<Self, E>, Blake3PoW> {
        let mut rng = ChaCha8Rng::from_seed([0u8; 32]);
        let (leaf_hash_params, two_to_one_params) = mt::default_config::<E>(&mut rng);
        WhirParameters::<MerkleConfigOf<Self, E>, Blake3PoW> {
            initial_statement: true,
            security_level: 100,
            pow_bits: default_max_pow(num_variables, 1),
            // For batching, the first round folding factor should be set small
            // to avoid large leaf nodes in proof
            folding_factor: if for_batch {
                FoldingFactor::ConstantFromSecondRound(1, 4)
            } else {
                FoldingFactor::Constant(4)
            },
            leaf_hash_params,
            two_to_one_params,
            soundness_type: SoundnessType::ConjectureList,
            fold_optimisation: FoldType::ProverHelps,
            _pow_parameters: Default::default(),
            starting_log_inv_rate: 1,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct WhirSetupParams<E: FftField> {
    pub num_variables: usize,
    _phantom: PhantomData<E>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Whir<E: FftField, Spec: WhirSpec<E>>(PhantomData<(E, Spec)>);

// Wrapper for WhirProof
#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct WhirProofWrapper<MerkleConfig, F>
where
    MerkleConfig: Config<Leaf = [F]>,
    F: Sized + Clone + CanonicalSerialize + CanonicalDeserialize,
{
    pub proof: WhirProof<MerkleConfig, F>,
    pub transcript: Vec<u8>,
}

impl<MerkleConfig, F> Serialize for WhirProofWrapper<MerkleConfig, F>
where
    MerkleConfig: Config<Leaf = [F]>,
    F: Sized + Clone + CanonicalSerialize + CanonicalDeserialize,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let proof = &self.proof.0;
        // Create a buffer that implements the `Write` trait
        let mut buffer = Vec::new();
        proof.serialize_compressed(&mut buffer).unwrap();
        let proof_size = buffer.len();
        let proof_size_bytes = proof_size.to_le_bytes();
        let mut data = proof_size_bytes.to_vec();
        data.extend_from_slice(&buffer);
        data.extend_from_slice(&self.transcript);
        serializer.serialize_bytes(&data)
    }
}

impl<'de, MerkleConfig, F> Deserialize<'de> for WhirProofWrapper<MerkleConfig, F>
where
    MerkleConfig: Config<Leaf = [F]>,
    F: Sized + Clone + CanonicalSerialize + CanonicalDeserialize,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let data: Vec<u8> = Deserialize::deserialize(deserializer)?;
        let proof_size_bytes = &data[0..8];
        let proof_size = u64::from_le_bytes(proof_size_bytes.try_into().unwrap());
        let proof_bytes = &data[8..8 + proof_size as usize];
        let proof = WhirProof::deserialize_compressed(&proof_bytes[..]).unwrap();
        let transcript = data[8 + proof_size as usize..].to_vec();
        Ok(WhirProofWrapper { proof, transcript })
    }
}

impl<MerkleConfig, F> Debug for WhirProofWrapper<MerkleConfig, F>
where
    MerkleConfig: Config<Leaf = [F]>,
    F: Sized + Clone + CanonicalSerialize + CanonicalDeserialize,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str("WhirProofWrapper")
    }
}

#[derive(Clone)]
pub struct CommitmentWithWitness<F, MerkleConfig>
where
    MerkleConfig: Config,
{
    pub commitment: MerkleConfig::InnerDigest,
    pub witness: Witnesses<F, MerkleConfig>,
}

impl<F: FftField, MerkleConfig> CommitmentWithWitness<F, MerkleConfig>
where
    MerkleConfig: Config,
{
    pub fn ood_answers(&self) -> Vec<F> {
        self.witness.ood_answers.clone()
    }
}

impl<F, MerkleConfig> Debug for CommitmentWithWitness<F, MerkleConfig>
where
    MerkleConfig: Config,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str("CommitmentWithWitness")
    }
}

impl<E, Spec: WhirSpec<E>> PolynomialCommitmentScheme<E> for Whir<E, Spec>
where
    E: FftField + Serialize + DeserializeOwned + Debug,
    E::BasePrimeField: Serialize + DeserializeOwned + Debug,
{
    type Param = ();
    type Commitment = <MerkleConfigOf<Spec, E> as Config>::InnerDigest;
    type CommitmentWithWitness = CommitmentWithWitness<E, MerkleConfigOf<Spec, E>>;
    type Proof = WhirProofWrapper<MerkleConfigOf<Spec, E>, E>;
    type Poly = CoefficientList<E::BasePrimeField>;

    fn setup(_poly_size: usize) -> Self::Param {
        ()
    }

    fn commit(_pp: &Self::Param, poly: &Self::Poly) -> Result<Self::CommitmentWithWitness, Error> {
        let params = Spec::prepare_whir_config(poly.num_variables(), false);

        // The merlin here is just for satisfying the interface of
        // WHIR, which only provides a commit_and_write function.
        // It will be abandoned once this function finishes.
        let io = Spec::prepare_io_pattern(poly.num_variables());
        let mut merlin = io.to_merlin();

        let committer = Committer::new(params);
        let witness = Witnesses::from(Spec::MerkleConfigWrapper::commit_to_merlin(
            &committer,
            &mut merlin,
            poly.clone(),
        )?);

        Ok(CommitmentWithWitness {
            commitment: witness.merkle_tree.root(),
            witness,
        })
    }

    fn batch_commit(
        _pp: &Self::Param,
        polys: &[Self::Poly],
    ) -> Result<Self::CommitmentWithWitness, Error> {
        if polys.is_empty() {
            return Err(Error::InvalidPcsParam);
        }

        for i in 1..polys.len() {
            if polys[i].num_variables() != polys[0].num_variables() {
                return Err(Error::InvalidPcsParam);
            }
        }

        let params = Spec::prepare_whir_config(polys[0].num_variables(), true);

        // The merlin here is just for satisfying the interface of
        // WHIR, which only provides a commit_and_write function.
        // It will be abandoned once this function finishes.
        let io = Spec::prepare_batch_io_pattern(polys[0].num_variables(), polys.len());
        let mut merlin = io.to_merlin();

        let committer = Committer::new(params);
        let witness =
            Spec::MerkleConfigWrapper::commit_to_merlin_batch(&committer, &mut merlin, polys)?;
        Ok(CommitmentWithWitness {
            commitment: witness.merkle_tree.root(),
            witness,
        })
    }

    fn open(
        _pp: &Self::Param,
        witness: &Self::CommitmentWithWitness,
        point: &[E],
        eval: &E,
    ) -> Result<Self::Proof, Error> {
        let params = Spec::prepare_whir_config(witness.witness.polys[0].num_variables(), false);
        let io = Spec::prepare_io_pattern(witness.witness.polys[0].num_variables());
        let mut merlin = io.to_merlin();
        // In WHIR, the prover writes the commitment to the transcript, then
        // the commitment is read from the transcript by the verifier, after
        // the transcript is transformed into a arthur transcript.
        // Here we repeat whatever the prover does.
        // TODO: This is a hack. There should be a better design that does not
        // require non-black-box knowledge of the inner working of WHIR.

        <Spec::MerkleConfigWrapper as WhirMerkleConfigWrapper<E>>::add_digest_to_merlin(
            &mut merlin,
            witness.commitment.clone(),
        )
        .map_err(Error::ProofError)?;
        let ood_answers = witness.ood_answers();
        if ood_answers.len() > 0 {
            let mut ood_points = vec![<E as ark_ff::AdditiveGroup>::ZERO; ood_answers.len()];
            merlin
                .fill_challenge_scalars(&mut ood_points)
                .map_err(Error::ProofError)?;
            merlin
                .add_scalars(&ood_answers)
                .map_err(Error::ProofError)?;
        }
        // Now the Merlin transcript is ready to pass to the verifier.

        let prover = Prover(params);
        let statement = Statement {
            points: vec![MultilinearPoint(point.to_vec())],
            evaluations: vec![eval.clone()],
        };

        let proof = Spec::MerkleConfigWrapper::prove_with_merlin(
            &prover,
            &mut merlin,
            statement,
            witness.witness.clone().into(),
        )?;

        Ok(WhirProofWrapper {
            proof,
            transcript: merlin.transcript().to_vec(),
        })
    }

    fn simple_batch_open(
        _pp: &Self::Param,
        witness: &Self::CommitmentWithWitness,
        point: &[E],
        evals: &[E],
    ) -> Result<Self::Proof, Error> {
        let params = Spec::prepare_whir_config(witness.witness.polys[0].num_variables(), true);
        let io =
            Spec::prepare_batch_io_pattern(witness.witness.polys[0].num_variables(), evals.len());
        let mut merlin = io.to_merlin();
        // In WHIR, the prover writes the commitment to the transcript, then
        // the commitment is read from the transcript by the verifier, after
        // the transcript is transformed into a arthur transcript.
        // Here we repeat whatever the prover does.
        // TODO: This is a hack. There should be a better design that does not
        // require non-black-box knowledge of the inner working of WHIR.

        <Spec::MerkleConfigWrapper as WhirMerkleConfigWrapper<E>>::add_digest_to_merlin(
            &mut merlin,
            witness.commitment.clone(),
        )
        .map_err(Error::ProofError)?;
        let ood_answers = witness.ood_answers();
        if ood_answers.len() > 0 {
            let mut ood_points =
                vec![<E as ark_ff::AdditiveGroup>::ZERO; ood_answers.len() / evals.len()];
            merlin
                .fill_challenge_scalars(&mut ood_points)
                .map_err(Error::ProofError)?;
            merlin
                .add_scalars(&ood_answers)
                .map_err(Error::ProofError)?;
        }
        // Now the Merlin transcript is ready to pass to the verifier.

        let prover = Prover(params);

        let proof = Spec::MerkleConfigWrapper::prove_with_merlin_simple_batch(
            &prover,
            &mut merlin,
            point,
            evals,
            &witness.witness,
        )?;

        Ok(WhirProofWrapper {
            proof,
            transcript: merlin.transcript().to_vec(),
        })
    }

    fn verify(
        _vp: &Self::Param,
        comm: &Self::Commitment,
        point: &[E],
        eval: &E,
        proof: &Self::Proof,
    ) -> Result<(), Error> {
        let params = Spec::prepare_whir_config(point.len(), false);
        let verifier = Verifier::new(params);
        let io = Spec::prepare_io_pattern(point.len());
        let mut arthur = io.to_arthur(&proof.transcript);

        let statement = Statement {
            points: vec![MultilinearPoint(point.to_vec())],
            evaluations: vec![eval.clone()],
        };

        let digest = Spec::MerkleConfigWrapper::verify_with_arthur(
            &verifier,
            &mut arthur,
            &statement,
            &proof.proof,
        )?;

        if &digest != comm {
            return Err(Error::CommitmentMismatchFromDigest);
        }

        Ok(())
    }

    fn simple_batch_verify(
        _vp: &Self::Param,
        comm: &Self::Commitment,
        point: &[E],
        evals: &[E],
        proof: &Self::Proof,
    ) -> Result<(), Error> {
        let params = Spec::prepare_whir_config(point.len(), true);
        let verifier = Verifier::new(params);
        let io = Spec::prepare_batch_io_pattern(point.len(), evals.len());
        let mut arthur = io.to_arthur(&proof.transcript);

        let digest = Spec::MerkleConfigWrapper::verify_with_arthur_simple_batch(
            &verifier,
            &mut arthur,
            point,
            evals,
            &proof.proof,
        )?;

        if &digest != comm {
            return Err(Error::CommitmentMismatchFromDigest);
        }

        Ok(())
    }
}
