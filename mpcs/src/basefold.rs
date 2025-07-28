use crate::{
    Error, PCSFriParam, Point, PolynomialCommitmentScheme, SecurityLevel,
    util::{
        hash::write_digest_to_transcript,
        merkle_tree::{Poseidon2ExtMerkleMmcs, poseidon2_merkle_tree},
    },
};
pub use encoding::{EncodingScheme, RSCode, RSCodeDefaultSpec};
use ff_ext::ExtensionField;
use p3::{commit::Mmcs, field::FieldAlgebra, matrix::dense::DenseMatrix, util::log2_strict_usize};
use query_phase::{batch_query_phase, batch_verifier_query_phase};
use structure::BasefoldProof;
pub use structure::{BasefoldSpec, Digest};
use sumcheck::macros::{entered_span, exit_span};
use transcript::Transcript;
use witness::RowMajorMatrix;

use itertools::Itertools;
use serde::{Serialize, de::DeserializeOwned};

pub mod structure;
pub use structure::{
    Basefold, BasefoldCommitment, BasefoldCommitmentWithWitness, BasefoldDefault, BasefoldParams,
    BasefoldProverParams, BasefoldRSParams, BasefoldVerifierParams,
};
pub mod commit_phase;
use commit_phase::batch_commit_phase;
pub mod encoding;
use multilinear_extensions::mle::ArcMultilinearExtension;

#[cfg(debug_assertions)]
use ff_ext::{Instrumented, PoseidonField};

pub mod query_phase;

/// Implement the Polynomial Commitment Scheme present in the BaseFold paper
/// https://eprint.iacr.org/2023/1705
///
/// Here is a high-level explanation of the BaseFold PCS.
///
/// BaseFold is the mixture of FRI and Sum-Check for proving the sum-check
/// statement
/// y = \sum_{b\in H} f(b) eq(b, r)
/// where
/// (1) f is the committed multilinear polynomial with n variables
/// (2) H is the n-dimensional hypercube
/// (3) r is the evaluation point (where the polynomial commitment is opened)
/// (4) y is the evaluation result (the opening result)
///
/// To prove this statement, the parties execute the normal sum-check,
/// which reduces the sum-check statement to a evaluation statement of f
/// at random point \alpha sampled during sum-check. Unlike normal sum-check,
/// where this final evaluation statement is delegated to a PCS, in BaseFold
/// this evaluation result is provided by FRI. This is possible because in
/// FRI, the repeated folding of the originally committed codeword is
/// effectively applying the even-odd folding to the message, which is
/// equivalent to applying the evaluating algorithm of multilinear polynomials.
///
/// The commit algorithm is the same as FRI, i.e., encode the polynomial
/// with RS code (or more generally, with a _foldable code_), and commit
/// to the codeword with Merkle tree. The key point is that the encoded
/// message is the coefficient vector (instead of the evaluations over the
/// hypercube), because the FRI folding is working on the coefficients.
///
/// The opening and verification protocol is, similar to FRI, divided into
/// two parts:
/// (1) the committing phase (not to confused with commit algorithm of PCS)
/// (2) the query phase
///
/// The committing phase proceed by interleavingly execute FRI committing phase
/// and the sum-check protocol. More precisely, in each round, the parties
/// execute:
/// (a) The prover sends the partially summed polynomial (sum-check).
/// (b) The verifier samples a challenge (sum-check and FRI).
/// (c) The prover substitutes one variable of the current polynomial
///     at the challenge (sum-check).
/// (d) The prover folds the codeword by the challenge and sends the
///     Merkle root of the folded codeword (FRI).
///
/// At the end of the committing phase:
/// (a) The prover sends the final codeword in the clear (in practice, it
///     suffices to send the message and let the verifier encode it locally
///     to save the proof size).
/// (b) The verifier interprets this last FRI message as a multilinear
///     polynomial, sums it over the hypercube, and compares the sum with
///     the current claimed sum of the sum-check protocol.
///
/// Now the sum-check part of the protocol is finished. The query phase
/// proceed exactly the same as FRI: for each query
/// (a) The verifier samples an index i in the codeword.
/// (b) The prover opens the codeword at i and i XOR 1, and the sequence of
///     folded codewords at the folded positions, i.e., for round k, the
///     positions are (i >> k) and (i >> k) XOR 1.
/// (c) The verifier checks that the folding has been correctly computed
///     at these positions.
impl<E: ExtensionField, Spec: BasefoldSpec<E>> PolynomialCommitmentScheme<E> for Basefold<E, Spec>
where
    E: Serialize + DeserializeOwned,
    E::BaseField: Serialize + DeserializeOwned,
    Spec: BasefoldSpec<E, EncodingScheme = RSCode<RSCodeDefaultSpec>>,
    <Poseidon2ExtMerkleMmcs<E> as Mmcs<E>>::Commitment:
        IntoIterator<Item = E::BaseField> + PartialEq,
{
    type Param = BasefoldParams<E, Spec>;
    type ProverParam = BasefoldProverParams<E, Spec>;
    type VerifierParam = BasefoldVerifierParams<E, Spec>;
    type CommitmentWithWitness = BasefoldCommitmentWithWitness<E>;
    type Commitment = BasefoldCommitment<E>;
    type CommitmentChunk = Digest<E>;
    type Proof = BasefoldProof<E>;

    fn setup(poly_size: usize, security_level: SecurityLevel) -> Result<Self::Param, Error> {
        let pp = <Spec::EncodingScheme as EncodingScheme<E>>::setup(log2_strict_usize(poly_size));

        Ok(BasefoldParams {
            params: pp,
            security_level,
        })
    }

    /// Derive the proving key and verification key from the public parameter.
    /// This step simultaneously trims the parameter for the particular size.
    fn trim(
        pp: Self::Param,
        poly_size: usize,
    ) -> Result<(Self::ProverParam, Self::VerifierParam), Error> {
        let security_level = pp.security_level;
        <Spec::EncodingScheme as EncodingScheme<E>>::trim(pp.params, log2_strict_usize(poly_size))
            .map(|(pp, vp)| {
                (
                    BasefoldProverParams {
                        encoding_params: pp,
                        security_level,
                    },
                    BasefoldVerifierParams {
                        encoding_params: vp,
                        security_level,
                    },
                )
            })
    }

    fn commit(
        _pp: &Self::ProverParam,
        _rmm: RowMajorMatrix<E::BaseField>,
    ) -> Result<Self::CommitmentWithWitness, Error> {
        unimplemented!()
    }

    fn batch_commit(
        pp: &Self::ProverParam,
        rmms: Vec<RowMajorMatrix<E::BaseField>>,
    ) -> Result<Self::CommitmentWithWitness, Error> {
        if rmms.is_empty() {
            return Err(Error::InvalidPcsParam(
                "cannot batch commit to zero polynomials".to_string(),
            ));
        }

        let mmcs = poseidon2_merkle_tree::<E>();

        let span = entered_span!("to_mles", profiling_3 = true);
        let polys: Vec<Vec<ArcMultilinearExtension<E>>> = rmms
            .iter()
            .map(|rmm| rmm.to_mles().into_iter().map(|p| p.into()).collect_vec())
            .collect_vec();
        exit_span!(span);

        let span = entered_span!("encode_codeword_and_mle", profiling_3 = true);
        let evals_codewords = rmms
            .into_iter()
            .map(|rmm| Spec::EncodingScheme::encode(&pp.encoding_params, rmm))
            .collect::<Result<Vec<DenseMatrix<E::BaseField>>, _>>()?;
        exit_span!(span);

        let span = entered_span!("build mt", profiling_3 = true);
        let (comm, codeword) = mmcs.commit(evals_codewords);
        exit_span!(span);
        Ok(BasefoldCommitmentWithWitness::new(comm, codeword, polys))
    }

    fn write_commitment(
        comm: &Self::Commitment,
        transcript: &mut impl Transcript<E>,
    ) -> Result<(), Error> {
        write_digest_to_transcript(&comm.commit(), transcript);
        transcript.append_field_element(&E::BaseField::from_canonical_u64(
            comm.log2_max_codeword_size as u64,
        ));
        Ok(())
    }

    fn get_pure_commitment(comm: &Self::CommitmentWithWitness) -> Self::Commitment {
        comm.to_commitment()
    }

    /// Open a single polynomial commitment at one point. If the given
    /// commitment with data contains more than one polynomial, this function
    /// will panic.
    fn open(
        _pp: &Self::ProverParam,
        _poly: &ArcMultilinearExtension<E>,
        _comm: &Self::CommitmentWithWitness,
        _point: &[E],
        _eval: &E, // Opening does not need eval, except for sanity check
        _transcript: &mut impl Transcript<E>,
    ) -> Result<Self::Proof, Error> {
        unimplemented!()
    }

    /// Open a batch of polynomial commitments at several points.
    fn batch_open(
        pp: &Self::ProverParam,
        rounds: Vec<(
            &Self::CommitmentWithWitness,
            // for each matrix open at one point
            Vec<(Point<E>, Vec<E>)>,
        )>,
        transcript: &mut impl Transcript<E>,
    ) -> Result<Self::Proof, Error> {
        let span = entered_span!("Basefold::batch_open");

        let base_mmcs = poseidon2_merkle_tree::<E>();

        // sanity check
        for (pcs_data, point_and_evals) in rounds.iter() {
            let matrices = base_mmcs.get_matrices(&pcs_data.codeword);
            // number of point match with number of matrices committed
            assert_eq!(matrices.len(), point_and_evals.len());
        }

        if cfg!(feature = "sanity-check") {
            // check poly evaluated on point equals to the expected value
            for (pcs_data, point_and_evals) in rounds.iter() {
                for (polys, (point, evals)) in pcs_data.polys.iter().zip_eq(point_and_evals.iter())
                {
                    assert_eq!(polys.len(), evals.len());
                    assert!(
                        polys.iter().all(|poly| poly.num_vars() == point.len()),
                        "all polys must have the same number of variables as the point"
                    );
                    assert!(
                        polys
                            .iter()
                            .zip_eq(evals.iter())
                            .all(|(poly, eval)| poly.evaluate(point) == *eval),
                        "all polys must evaluate to the same value at the point"
                    )
                }
            }
        }

        let max_num_var = rounds
            .iter()
            .map(|(pcs_data, _)| pcs_data.log2_max_codeword_size - Spec::get_rate_log())
            .max()
            .unwrap();

        // Basefold IOP commit phase
        let commit_phase_span = entered_span!("Basefold::open::commit_phase");
        let (trees, commit_phase_proof) = batch_commit_phase::<E, Spec>(
            &pp.encoding_params,
            &rounds,
            max_num_var,
            max_num_var - Spec::get_basecode_msg_size_log(),
            transcript,
        );
        exit_span!(commit_phase_span);

        let pow_bits = pp.get_pow_bits_by_level(crate::PowStrategy::FriPow);
        let pow_witness = if pow_bits > 0 {
            let grind_span = entered_span!("Basefold::open::grind");
            let pow_witness = transcript.grind(pow_bits);
            exit_span!(grind_span);
            pow_witness
        } else {
            E::BaseField::ZERO
        };

        let query_span = entered_span!("Basefold::open::query_phase");
        // Each entry in queried_els stores a list of triples (F, F, i) indicating the
        // position opened at each round and the two values at that round
        let query_opening_proof = batch_query_phase(
            rounds.iter().map(|(pcs_data, _)| *pcs_data).collect_vec(),
            &trees,
            Spec::get_number_queries(),
            max_num_var + Spec::get_rate_log(),
            transcript,
        );
        exit_span!(query_span);

        exit_span!(span);
        Ok(Self::Proof {
            commits: commit_phase_proof.commits,
            final_message: commit_phase_proof.final_message,
            query_opening_proof,
            sumcheck_proof: Some(commit_phase_proof.sumcheck_messages),
            pow_witness,
        })
    }

    /// This is a simple version of batch open:
    /// 1. Open at one point
    /// 2. All the polynomials share the same commitment and have the same
    ///    number of variables.
    /// 3. The point is already a random point generated by a sum-check.
    fn simple_batch_open(
        _pp: &Self::ProverParam,
        _polys: &[ArcMultilinearExtension<E>],
        _comm: &Self::CommitmentWithWitness,
        _point: &[E],
        _evals: &[E],
        _transcript: &mut impl Transcript<E>,
    ) -> Result<Self::Proof, Error> {
        unimplemented!()
    }

    fn verify(
        _vp: &Self::VerifierParam,
        _comm: &Self::Commitment,
        _point: &[E],
        _eval: &E,
        _proof: &Self::Proof,
        _transcript: &mut impl Transcript<E>,
    ) -> Result<(), Error> {
        unimplemented!()
    }

    fn batch_verify(
        vp: &Self::VerifierParam,
        rounds: Vec<(
            Self::Commitment,
            // for each matrix:
            Vec<(
                // its num_vars,
                usize,
                (
                    // the point,
                    Point<E>,
                    // values at the point
                    Vec<E>,
                ),
            )>,
        )>,
        proof: &Self::Proof,
        transcript: &mut impl Transcript<E>,
    ) -> Result<(), Error> {
        assert!(
            !proof.final_message.is_empty()
                && proof
                    .final_message
                    .iter()
                    .map(|final_message| { final_message.len() })
                    .chain(std::iter::once(1 << Spec::get_basecode_msg_size_log()))
                    .all_equal(),
            "final message size should be equal to 1 << Spec::get_basecode_msg_size_log()"
        );
        assert!(proof.sumcheck_proof.is_some(), "sumcheck proof must exist");
        assert_eq!(proof.query_opening_proof.len(), Spec::get_number_queries());

        // verify non trivial proof
        let total_num_polys = rounds
            .iter()
            .map(|(_, openings)| {
                openings
                    .iter()
                    .map(|(_, (_, evals))| evals.len())
                    .sum::<usize>()
            })
            .sum::<usize>();
        let batch_coeffs =
            &transcript.sample_and_append_challenge_pows(total_num_polys, b"batch coeffs");

        #[cfg(debug_assertions)]
        {
            Instrumented::<<<E as ExtensionField>::BaseField as PoseidonField>::P>::log_label(
                "batch_verify::batch_coeffs",
            );
        }

        let max_num_var = rounds
            .iter()
            .map(|(commit, openings)| {
                let max_num_var = openings
                    .iter()
                    .map(|(num_vars, _)| *num_vars)
                    .max()
                    .unwrap();
                assert_eq!(
                    commit.log2_max_codeword_size,
                    max_num_var + Spec::get_rate_log()
                );
                max_num_var
            })
            .max()
            .unwrap();
        if max_num_var < Spec::get_basecode_msg_size_log() {
            // all the matrices are trivial, so we can skip the folding
            return Ok(());
        }
        let num_rounds = max_num_var - Spec::get_basecode_msg_size_log();

        // prepare folding challenges via sumcheck round msg + FRI commitment
        let mut fold_challenges: Vec<E> = Vec::with_capacity(max_num_var);
        let commits = &proof.commits;
        let sumcheck_messages = proof.sumcheck_proof.as_ref().unwrap();
        for i in 0..num_rounds {
            transcript.append_field_element_exts(sumcheck_messages[i].evaluations.as_slice());
            fold_challenges.push(
                transcript
                    .sample_and_append_challenge(b"commit round")
                    .elements,
            );
            if i < num_rounds - 1 {
                write_digest_to_transcript(&commits[i], transcript);
            }
        }
        #[cfg(debug_assertions)]
        {
            Instrumented::<<<E as ExtensionField>::BaseField as PoseidonField>::P>::log_label(
                "batch_verify::interleaving_folding",
            );
        }
        transcript.append_field_element_exts_iter(proof.final_message.iter().flatten());

        // check pow
        let pow_bits = vp.get_pow_bits_by_level(crate::PowStrategy::FriPow);
        if pow_bits > 0 {
            assert!(transcript.check_witness(pow_bits, proof.pow_witness));
        }

        let queries: Vec<_> = transcript.sample_bits_and_append_vec(
            b"query indices",
            Spec::get_number_queries(),
            max_num_var + Spec::get_rate_log(),
        );
        #[cfg(debug_assertions)]
        {
            Instrumented::<<<E as ExtensionField>::BaseField as PoseidonField>::P>::log_label(
                "batch_verify::query_sample",
            );
        }

        // verify basefold sumcheck + FRI codeword query
        batch_verifier_query_phase::<E, Spec::EncodingScheme>(
            &vp.encoding_params,
            max_num_var,
            batch_coeffs,
            &fold_challenges,
            &queries,
            proof,
            &rounds,
        );

        #[cfg(debug_assertions)]
        {
            Instrumented::<<<E as ExtensionField>::BaseField as PoseidonField>::P>::log_label(
                "batch_verify::queries",
            );
        }

        Ok(())
    }

    fn simple_batch_verify(
        _vp: &Self::VerifierParam,
        _comm: &Self::Commitment,
        _point: &[E],
        _evals: &[E],
        _proof: &Self::Proof,
        _transcript: &mut impl Transcript<E>,
    ) -> Result<(), Error> {
        unimplemented!()
    }

    fn get_arc_mle_witness_from_commitment(
        commitment: &Self::CommitmentWithWitness,
    ) -> Vec<ArcMultilinearExtension<'static, E>> {
        commitment.polys.iter().flatten().cloned().collect_vec()
    }
}

#[cfg(test)]
mod test {
    use ff_ext::GoldilocksExt2;

    use crate::{
        basefold::Basefold,
        test_util::{run_batch_commit_open_verify, run_commit_open_verify},
    };

    use super::BasefoldRSParams;

    type PcsGoldilocksRSCode = Basefold<GoldilocksExt2, BasefoldRSParams>;

    #[test]
    fn batch_commit_open_verify_goldilocks() {
        // Both challenge and poly are over base field
        run_batch_commit_open_verify::<GoldilocksExt2, PcsGoldilocksRSCode>(10, 11, 1);
        run_batch_commit_open_verify::<GoldilocksExt2, PcsGoldilocksRSCode>(10, 11, 4);
        // TODO support all trivial proof
    }

    #[test]
    #[ignore = "For benchmarking and profiling only"]
    fn bench_basefold_batch_commit_open_verify_goldilocks() {
        {
            run_commit_open_verify::<GoldilocksExt2, PcsGoldilocksRSCode>(20, 21);
            run_batch_commit_open_verify::<GoldilocksExt2, PcsGoldilocksRSCode>(20, 21, 64);
        }
    }
}
