use crate::{
    Error, Evaluation, PolynomialCommitmentScheme,
    util::{
        arithmetic::inner_product,
        ext_to_usize,
        hash::write_digest_to_transcript,
        merkle_tree::{Poseidon2ExtMerkleMmcs, poseidon2_merkle_tree},
    },
};
use ark_std::{end_timer, start_timer};
pub use encoding::{EncodingScheme, RSCode, RSCodeDefaultSpec};
use ff_ext::ExtensionField;
use multilinear_extensions::{mle::MultilinearExtension, virtual_poly::eq_eval};
use p3::{commit::Mmcs, matrix::dense::DenseMatrix, util::log2_strict_usize};
use query_phase::{simple_batch_prover_query_phase, simple_batch_verifier_query_phase};
use structure::BasefoldProof;
pub use structure::{BasefoldSpec, Digest};
use sumcheck::macros::{entered_span, exit_span};
use transcript::Transcript;
use witness::RowMajorMatrix;

use itertools::Itertools;
use serde::{Serialize, de::DeserializeOwned};

use multilinear_extensions::{mle::FieldType, virtual_poly::build_eq_x_r_vec};

use rayon::{
    iter::IntoParallelIterator,
    prelude::{IntoParallelRefIterator, IntoParallelRefMutIterator, ParallelIterator},
};

mod structure;
pub use structure::{
    Basefold, BasefoldCommitment, BasefoldCommitmentWithWitness, BasefoldDefault, BasefoldParams,
    BasefoldProverParams, BasefoldRSParams, BasefoldVerifierParams,
};
mod commit_phase;
use commit_phase::simple_batch_commit_phase;
mod encoding;
use multilinear_extensions::virtual_poly::ArcMultilinearExtension;

mod query_phase;
// This sumcheck module is different from the mpcs::sumcheck module, in that
// it deals only with the special case of the form \sum eq(r_i)f_i().

pub enum PolyEvalsCodeword<E: ExtensionField> {
    Normal(Box<DenseMatrix<E::BaseField>>),
    TooSmall(Box<DenseMatrix<E::BaseField>>), // The polynomial is too small to apply FRI
    TooBig(usize),
}

impl<E: ExtensionField, Spec: BasefoldSpec<E>> Basefold<E, Spec>
where
    E: Serialize + DeserializeOwned,
    E::BaseField: Serialize + DeserializeOwned,
{
    /// Transpose a matrix of field elements, generic over the type of field element
    pub fn transpose_field_type<T: Send + Sync + Copy>(
        matrix: &[FieldType<E>],
    ) -> Result<Vec<FieldType<E>>, Error> {
        let transpose_fn = match matrix[0] {
            FieldType::Ext(_) => Self::get_column_ext,
            FieldType::Base(_) => Self::get_column_base,
            FieldType::Unreachable => unreachable!(),
        };

        let len = matrix[0].len();
        (0..len)
            .into_par_iter()
            .map(|i| (transpose_fn)(matrix, i))
            .collect()
    }

    fn get_column_base(
        matrix: &[FieldType<E>],
        column_index: usize,
    ) -> Result<FieldType<E>, Error> {
        Ok(FieldType::Base(
            matrix
                .par_iter()
                .map(|row| match row {
                    FieldType::Base(content) => Ok(content[column_index]),
                    _ => Err(Error::InvalidPcsParam(
                        "expected base field type".to_string(),
                    )),
                })
                .collect::<Result<Vec<E::BaseField>, Error>>()?,
        ))
    }

    fn get_column_ext(matrix: &[FieldType<E>], column_index: usize) -> Result<FieldType<E>, Error> {
        Ok(FieldType::Ext(
            matrix
                .par_iter()
                .map(|row| match row {
                    FieldType::Ext(content) => Ok(content[column_index]),
                    _ => Err(Error::InvalidPcsParam(
                        "expected ext field type".to_string(),
                    )),
                })
                .collect::<Result<Vec<E>, Error>>()?,
        ))
    }
}

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

    fn setup(poly_size: usize) -> Result<Self::Param, Error> {
        let pp = <Spec::EncodingScheme as EncodingScheme<E>>::setup(log2_strict_usize(poly_size));

        Ok(BasefoldParams { params: pp })
    }

    /// Derive the proving key and verification key from the public parameter.
    /// This step simultaneously trims the parameter for the particular size.
    fn trim(
        pp: Self::Param,
        poly_size: usize,
    ) -> Result<(Self::ProverParam, Self::VerifierParam), Error> {
        <Spec::EncodingScheme as EncodingScheme<E>>::trim(pp.params, log2_strict_usize(poly_size))
            .map(|(pp, vp)| {
                (
                    BasefoldProverParams {
                        encoding_params: pp,
                    },
                    BasefoldVerifierParams {
                        encoding_params: vp,
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
        rmm: witness::RowMajorMatrix<<E as ff_ext::ExtensionField>::BaseField>,
    ) -> Result<Self::CommitmentWithWitness, Error> {
        let span = entered_span!("to_mles", profiling_3 = true);
        let polys = rmm.to_mles();
        exit_span!(span);
        // assumptions
        // 1. there must be at least one polynomial
        // 2. all polynomials must exist in the same field type
        //    (TODO: eliminate this assumption by supporting commiting
        //     and opening mixed-type polys)
        // 3. all polynomials must have the same number of variables

        if polys.is_empty() {
            return Err(Error::InvalidPcsParam(
                "cannot batch commit to zero polynomials".to_string(),
            ));
        }

        let num_vars = polys[0].num_vars();
        let num_polys = polys.len();

        let is_base = match polys[0].evaluations() {
            FieldType::Ext(_) => false,
            FieldType::Base(_) => true,
            _ => unreachable!(),
        };

        if !polys.iter().map(|poly| poly.num_vars()).all_equal() {
            return Err(Error::InvalidPcsParam(
                "cannot batch commit to polynomials with different number of variables".to_string(),
            ));
        }
        let timer = start_timer!(|| "Basefold::batch commit");
        let encode_timer = start_timer!(|| "Basefold::batch commit::encoding and interpolations");
        let span = entered_span!("encode_codeword_and_mle", profiling_3 = true);

        let evals_codewords = Spec::EncodingScheme::encode(&pp.encoding_params, rmm);

        exit_span!(span);
        end_timer!(encode_timer);

        let span = entered_span!("build mt", profiling_3 = true);
        // build merkle tree
        let ret = match evals_codewords {
            PolyEvalsCodeword::Normal(codewords) => {
                let mmcs = poseidon2_merkle_tree::<E>();
                let (comm, codeword) = mmcs.commit_matrix(*codewords);
                let polys: Vec<ArcMultilinearExtension<E>> =
                    polys.into_iter().map(|poly| poly.into()).collect_vec();
                Self::CommitmentWithWitness {
                    pi_d_digest: comm,
                    codeword,
                    polynomials_bh_evals: polys,
                    num_vars,
                    is_base,
                    num_polys,
                }
            }
            PolyEvalsCodeword::TooSmall(rmm_padded) => {
                let mmcs = poseidon2_merkle_tree::<E>();
                let (comm, codeword) = mmcs.commit_matrix(*rmm_padded);
                let polys: Vec<ArcMultilinearExtension<E>> =
                    polys.into_iter().map(|poly| poly.into()).collect_vec();
                Self::CommitmentWithWitness {
                    pi_d_digest: comm,
                    codeword,
                    polynomials_bh_evals: polys,
                    num_vars,
                    is_base,
                    num_polys,
                }
            }
            PolyEvalsCodeword::TooBig(_) => return Err(Error::PolynomialTooLarge(num_vars)),
        };
        exit_span!(span);
        end_timer!(timer);

        Ok(ret)
    }

    fn write_commitment(
        comm: &Self::Commitment,
        transcript: &mut impl Transcript<E>,
    ) -> Result<(), Error> {
        write_digest_to_transcript(&comm.pi_d_digest(), transcript);
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
    /// The current version only supports one polynomial per commitment.
    /// Because otherwise it is complex to match the polynomials and
    /// the commitments, and because currently this high flexibility is
    /// not very useful in ceno.
    fn batch_open(
        _pp: &Self::ProverParam,
        _polys: &[ArcMultilinearExtension<E>],
        _comms: &[Self::CommitmentWithWitness],
        _points: &[Vec<E>],
        _evals: &[Evaluation<E>],
        _transcript: &mut impl Transcript<E>,
    ) -> Result<Self::Proof, Error> {
        unimplemented!()
    }

    /// This is a simple version of batch open:
    /// 1. Open at one point
    /// 2. All the polynomials share the same commitment and have the same
    ///    number of variables.
    /// 3. The point is already a random point generated by a sum-check.
    fn simple_batch_open(
        pp: &Self::ProverParam,
        polys: &[ArcMultilinearExtension<E>],
        comm: &Self::CommitmentWithWitness,
        point: &[E],
        evals: &[E],
        transcript: &mut impl Transcript<E>,
    ) -> Result<Self::Proof, Error> {
        let timer = start_timer!(|| "Basefold::batch_open");
        let num_vars = polys[0].num_vars();

        if comm.is_trivial::<Spec>() {
            let mmcs = poseidon2_merkle_tree::<E>();
            return Ok(Self::Proof::trivial(
                mmcs.get_matrices(&comm.codeword)[0].clone(),
            ));
        }

        polys
            .iter()
            .for_each(|poly| assert_eq!(poly.num_vars(), num_vars));
        assert!(num_vars >= Spec::get_basecode_msg_size_log());
        assert_eq!(comm.num_polys, polys.len());
        assert_eq!(comm.num_polys, evals.len());

        if cfg!(feature = "sanity-check") {
            evals
                .iter()
                .zip(polys)
                .for_each(|(eval, poly)| assert_eq!(&poly.evaluate(point), eval))
        }
        // evals.len() is the batch size, i.e., how many polynomials are being opened together
        let batch_coeffs = &transcript
            .sample_and_append_challenge_pows(evals.len(), b"batch coeffs")[0..evals.len()];
        let _target_sum = inner_product(evals, batch_coeffs);

        // Now the verifier has obtained the new target sum, and is able to compute the random
        // linear coefficients.
        // The remaining tasks for the prover is to prove that
        // sum_i coeffs[i] poly_evals[i] is equal to
        // the new target sum, where coeffs is computed as follows
        let (trees, commit_phase_proof) = simple_batch_commit_phase::<E, Spec>(
            &pp.encoding_params,
            point,
            batch_coeffs,
            comm,
            transcript,
            num_vars,
            num_vars - Spec::get_basecode_msg_size_log(),
        );

        let query_timer = start_timer!(|| "Basefold::open::query_phase");
        // Each entry in queried_els stores a list of triples (F, F, i) indicating the
        // position opened at each round and the two values at that round
        let query_opening_proof =
            simple_batch_prover_query_phase(transcript, comm, &trees, Spec::get_number_queries());
        end_timer!(query_timer);

        end_timer!(timer);
        Ok(Self::Proof {
            sumcheck_messages: commit_phase_proof.sumcheck_messages,
            commits: commit_phase_proof.commits,
            final_message: commit_phase_proof.final_message,
            query_opening_proof,
            sumcheck_proof: None,
            trivial_proof: None,
        })
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
        _vp: &Self::VerifierParam,
        _comms: &[Self::Commitment],
        _points: &[Vec<E>],
        _evals: &[Evaluation<E>],
        _proof: &Self::Proof,
        _transcript: &mut impl Transcript<E>,
    ) -> Result<(), Error> {
        unimplemented!()
    }

    fn simple_batch_verify(
        vp: &Self::VerifierParam,
        comm: &Self::Commitment,
        point: &[E],
        evals: &[E],
        proof: &Self::Proof,
        transcript: &mut impl Transcript<E>,
    ) -> Result<(), Error> {
        let timer = start_timer!(|| "Basefold::simple batch verify");
        let batch_size = evals.len();
        if let Some(num_polys) = comm.num_polys {
            assert_eq!(num_polys, batch_size);
        }

        if proof.is_trivial() {
            let trivial_proof = proof.trivial_proof.as_ref().unwrap();
            let mmcs = poseidon2_merkle_tree::<E>();
            let (root, _) = mmcs.commit_matrix(trivial_proof.clone());
            if comm.pi_d_digest() == root {
                return Ok(());
            } else {
                return Err(Error::MerkleRootMismatch);
            }
        }

        let num_vars = point.len();
        if let Some(comm_num_vars) = comm.num_vars() {
            assert_eq!(num_vars, comm_num_vars);
            assert!(num_vars >= Spec::get_basecode_msg_size_log());
        }
        let num_rounds = num_vars - Spec::get_basecode_msg_size_log();

        // evals.len() is the batch size, i.e., how many polynomials are being opened together
        let batch_coeffs =
            transcript.sample_and_append_challenge_pows(evals.len(), b"batch coeffs");

        let mut fold_challenges: Vec<E> = Vec::with_capacity(num_vars);
        let commits = &proof.commits;
        let sumcheck_messages = &proof.sumcheck_messages;
        for i in 0..num_rounds {
            transcript.append_field_element_exts(sumcheck_messages[i].as_slice());
            fold_challenges.push(
                transcript
                    .sample_and_append_challenge(b"commit round")
                    .elements,
            );
            if i < num_rounds - 1 {
                write_digest_to_transcript(&commits[i], transcript);
            }
        }
        let final_message = &proof.final_message;
        transcript.append_field_element_exts(final_message.as_slice());

        let queries: Vec<_> = transcript
            .sample_and_append_vec(b"query indices", Spec::get_number_queries())
            .into_iter()
            .map(|r| ext_to_usize(&r) % (1 << (num_vars + Spec::get_rate_log())))
            .collect();

        // coeff is the eq polynomial evaluated at the first challenge.len() variables
        let coeff = eq_eval(&point[..fold_challenges.len()], &fold_challenges);
        // Compute eq as the partially evaluated eq polynomial
        let mut eq = build_eq_x_r_vec(&point[fold_challenges.len()..]);
        eq.par_iter_mut().for_each(|e| *e *= coeff);

        simple_batch_verifier_query_phase::<E, Spec>(
            queries.as_slice(),
            &vp.encoding_params,
            &proof.query_opening_proof,
            sumcheck_messages,
            &fold_challenges,
            &batch_coeffs,
            num_rounds,
            num_vars,
            final_message,
            commits,
            comm,
            eq.as_slice(),
            evals,
        );
        end_timer!(timer);

        Ok(())
    }

    fn get_arc_mle_witness_from_commitment(
        commitment: &Self::CommitmentWithWitness,
    ) -> Vec<ArcMultilinearExtension<'static, E>> {
        commitment.polynomials_bh_evals.clone()
    }
}

#[cfg(test)]
mod test {
    use ff_ext::GoldilocksExt2;

    use crate::{
        basefold::Basefold,
        test_util::{run_commit_open_verify, run_simple_batch_commit_open_verify},
    };

    use super::BasefoldRSParams;

    type PcsGoldilocksRSCode = Basefold<GoldilocksExt2, BasefoldRSParams>;

    #[test]
    fn simple_batch_commit_open_verify_goldilocks() {
        // Both challenge and poly are over base field
        run_simple_batch_commit_open_verify::<GoldilocksExt2, PcsGoldilocksRSCode>(10, 11, 1);
        run_simple_batch_commit_open_verify::<GoldilocksExt2, PcsGoldilocksRSCode>(10, 11, 4);
        // Test trivial proof with small num vars
        run_simple_batch_commit_open_verify::<GoldilocksExt2, PcsGoldilocksRSCode>(4, 6, 4);
    }

    #[test]
    #[ignore = "For benchmarking and profiling only"]
    fn bench_basefold_simple_batch_commit_open_verify_goldilocks() {
        {
            run_commit_open_verify::<GoldilocksExt2, PcsGoldilocksRSCode>(20, 21);
            run_simple_batch_commit_open_verify::<GoldilocksExt2, PcsGoldilocksRSCode>(20, 21, 64);
        }
    }
}
