use crate::{
    sum_check::{
        classic::{ClassicSumCheck, Coefficients, CoefficientsProver, SumcheckProof},
        eq_xy_eval,
    },
    util::{
        arithmetic::{inner_product_three, interpolate_field_type_over_boolean_hypercube},
        ext_to_usize, log2_strict,
        merkle_tree::{Hasher, MerkleTree},
        plonky2_util::reverse_index_bits_in_place_field_type,
    },
    Error, Evaluation, PolynomialCommitmentScheme,
};
use ark_std::{end_timer, start_timer};
use basic::BasicBasefoldStrategy;
use batch_simple::BatchSimpleBasefoldStrategy;
use batch_vlmp::BatchVLMPBasefoldStrategy;
use batch_vlop::BatchVLOPBasefoldStrategy;
pub use encoding::{
    Basecode, BasecodeDefaultSpec, EncodingProverParameters, EncodingScheme, RSCode,
    RSCodeDefaultSpec,
};
use ff_ext::ExtensionField;
use itertools::Itertools;
use query_phase::{prover_query_phase, verifier_query_phase, QueryCheckStrategy};
use structure::BasefoldProof;
pub use structure::BasefoldSpec;
use transcript::Transcript;

use serde::{de::DeserializeOwned, Serialize};

use multilinear_extensions::{
    mle::{DenseMultilinearExtension, FieldType, MultilinearExtension},
    virtual_poly::build_eq_x_r_vec,
};

use rand_chacha::ChaCha8Rng;
use rayon::{
    iter::{IntoParallelIterator, IntoParallelRefMutIterator},
    prelude::{IntoParallelRefIterator, ParallelIterator},
};
pub use sumcheck::{one_level_eval_hc, one_level_interp_hc};

type SumCheck<F> = ClassicSumCheck<CoefficientsProver<F>>;

mod structure;
pub use structure::{
    Basefold, BasefoldBasecodeParams, BasefoldCommitment, BasefoldCommitmentWithData,
    BasefoldDefault, BasefoldParams, BasefoldProverParams, BasefoldRSParams,
    BasefoldVerifierParams,
};
mod commit_phase;
use commit_phase::{commit_phase, CommitPhaseStrategy};
mod encoding;
pub use encoding::{coset_fft, fft, fft_root_table};
use multilinear_extensions::virtual_poly_v2::ArcMultilinearExtension;

mod query_phase;
// This sumcheck module is different from the mpcs::sumcheck module, in that
// it deals only with the special case of the form \sum eq(r_i)f_i().
mod basic;
mod batch;
mod batch_simple;
mod batch_vlmp;
mod batch_vlop;
mod sumcheck;

enum PolyEvalsCodeword<E: ExtensionField> {
    Normal((FieldType<E>, FieldType<E>)),
    TooSmall(FieldType<E>), // The polynomial is too small to apply FRI
    TooBig(usize),
}

pub(crate) trait ProverInputs<E: ExtensionField, Spec: BasefoldSpec<E>>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    fn comms(&self) -> &[BasefoldCommitmentWithData<E, Spec>];
}

pub(crate) trait VerifierInputs<E: ExtensionField, Spec: BasefoldSpec<E>>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    fn comms(&self) -> &[BasefoldCommitment<E, Spec>];
    fn num_vars(&self) -> usize;
}

pub(crate) struct CommitPhaseInput<E: ExtensionField>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    point: Vec<E>,
    coeffs_outer: Vec<E>,
    coeffs_inner: Vec<E>,
    sumcheck_proof: Option<SumcheckProof<E, Coefficients<E>>>,
}

pub(crate) trait BasefoldStrategy<E: ExtensionField, Spec: BasefoldSpec<E>>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    type CommitPhaseStrategy: CommitPhaseStrategy<E>;
    type QueryCheckStrategy: QueryCheckStrategy<E, Spec>;
    type ProverInputs<'a>: ProverInputs<E, Spec>
    where
        Spec: 'a;
    type VerifierInputs<'a>: VerifierInputs<E, Spec>
    where
        Spec: 'a;

    /// Decide if the proof is trivial, and if so, output it.
    fn trivial_proof(prover_inputs: &Self::ProverInputs<'_>) -> Option<BasefoldProof<E, Spec>>;

    /// Generate:
    /// 1. the point to open (not necessarily the same as the original point)
    /// 2. the batching coefficients:
    ///    2.1 the outer coefficients, i.e., batching polys across different comms
    ///    2.2 the inner coefficients, i.e., batching polys inside each comm
    fn prepare_commit_phase_input(
        pp: &BasefoldProverParams<E, Spec>,
        prover_inputs: &Self::ProverInputs<'_>,
        transcript: &mut Transcript<E>,
    ) -> Result<CommitPhaseInput<E>, Error>;

    fn check_trivial_proof(
        verifier_inputs: &Self::VerifierInputs<'_>,
        proof: &BasefoldProof<E, Spec>,
        transcript: &mut Transcript<E>,
    ) -> Result<(), Error>;

    fn check_sizes(verifier_inputs: &Self::VerifierInputs<'_>);

    #[allow(clippy::type_complexity)]
    fn prepare_sumcheck_target_and_point_batching_coeffs(
        vp: &BasefoldVerifierParams<E, Spec>,
        verifier_inputs: &Self::VerifierInputs<'_>,
        proof: &BasefoldProof<E, Spec>,
        transcript: &mut Transcript<E>,
    ) -> Result<(E, Vec<E>, Vec<E>, Vec<E>), Error>;
}

impl<E: ExtensionField, Spec: BasefoldSpec<E>> Basefold<E, Spec>
where
    E: Serialize + DeserializeOwned,
    E::BaseField: Serialize + DeserializeOwned,
{
    /// Converts a polynomial to a code word, also returns the evaluations over the boolean hypercube
    /// for said polynomial
    fn get_poly_bh_evals_and_codeword(
        pp: &BasefoldProverParams<E, Spec>,
        poly: &DenseMultilinearExtension<E>,
    ) -> PolyEvalsCodeword<E> {
        // bh_evals is just a copy of poly.evals().
        // Note that this function implicitly assumes that the size of poly.evals() is a
        // power of two. Otherwise, the function crashes with index out of bound.
        let mut bh_evals = poly.evaluations().clone();
        let num_vars = poly.num_vars();
        if num_vars > pp.encoding_params.get_max_message_size_log() {
            return PolyEvalsCodeword::TooBig(num_vars);
        }

        // In this case, the polynomial is so small that the opening is trivial.
        // So we just build the Merkle tree over the polynomial evaluations.
        // No codeword is needed.
        if num_vars <= Spec::get_basecode_msg_size_log() {
            return PolyEvalsCodeword::TooSmall(bh_evals);
        }

        // Switch to coefficient form
        let mut coeffs = bh_evals.clone();
        // TODO: directly return bit-reversed version if needed.
        interpolate_field_type_over_boolean_hypercube(&mut coeffs);

        // The coefficients are originally stored in little endian,
        // i.e., the left half correspond to the coefficients not multiplied
        // by X0, and the right half are all multiplied by X0. That means
        // for every step in sum-check, the encoded message is expected to
        // left-right fold.
        // For the foldable encoding scheme, the codeword is always left-right
        // folded, but the message is not necessarily (depending on the choice
        // of encoding scheme). That means either:
        // encode(left_right_fold(msg)) = left_right_fold(encode(msg))
        // or
        // encode(even_odd_fold(msg)) = left_right_fold(encode(msg))
        // If the message is left-right folded, then we don't need to do
        // anything. But if the message is even-odd folded for this encoding
        // scheme, we need to bit-reverse it before we encode the message,
        // such that the folding of the message is consistent with the
        // evaluation of the first variable of the polynomial.
        if <Spec::EncodingScheme as EncodingScheme<E>>::message_is_even_and_odd_folding() {
            reverse_index_bits_in_place_field_type(&mut coeffs);
        }
        let mut codeword = Spec::EncodingScheme::encode(&pp.encoding_params, &coeffs);

        // The evaluations over the hypercube are used in sum-check.
        // They are bit-reversed because the hypercube is ordered in little
        // endian, so the left half of the evaluation vector are evaluated
        // at 0 for the first variable, and the right half are evaluated at
        // 1 for the first variable.
        // In each step of sum-check, we subsitute the first variable of the
        // current polynomial with the random challenge, which is equivalent
        // to a left-right folding of the evaluation vector.
        // However, the algorithms that we will use are applying even-odd
        // fold in each sum-check round (easier to program using `par_chunks`)
        // so we bit-reverse it to store the evaluations in big-endian.
        reverse_index_bits_in_place_field_type(&mut bh_evals);
        // The encoding scheme always folds the codeword in left-and-right
        // manner. However, in query phase the two folded positions are
        // always opened together, so it will be more efficient if the
        // folded positions are simultaneously sibling nodes in the Merkle
        // tree. Therefore, instead of left-and-right folding, we bit-reverse
        // the codeword to make the folding even-and-odd, i.e., adjacent
        // positions are folded.
        reverse_index_bits_in_place_field_type(&mut codeword);

        PolyEvalsCodeword::Normal((bh_evals, codeword))
    }

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

    pub(crate) fn commit_inner(
        pp: &BasefoldProverParams<E, Spec>,
        poly: &DenseMultilinearExtension<E>,
    ) -> Result<BasefoldCommitmentWithData<E, Spec>, Error>
    where
        E: Serialize + DeserializeOwned,
        E::BaseField: Serialize + DeserializeOwned,
    {
        let is_base = match poly.evaluations() {
            FieldType::Ext(_) => false,
            FieldType::Base(_) => true,
            _ => unreachable!(),
        };

        // Encode the polynomials. Simultaneously get:
        //  (1) The evaluations over the hypercube (just a clone of the input)
        //  (2) The encoding of the coefficient vector (need an interpolation)

        match Self::get_poly_bh_evals_and_codeword(pp, poly) {
            PolyEvalsCodeword::Normal((bh_evals, codeword)) => {
                let codeword_tree = MerkleTree::<E, Spec::Hasher>::from_leaves(codeword, 2);

                // All these values are stored in the `CommitmentWithData` because
                // they are useful in opening, and we don't want to recompute them.
                Ok(BasefoldCommitmentWithData {
                    codeword_tree,
                    polynomials_bh_evals: vec![bh_evals],
                    num_vars: poly.num_vars(),
                    is_base,
                    num_polys: 1,
                })
            }
            PolyEvalsCodeword::TooSmall(evals) => {
                let codeword_tree = MerkleTree::<E, Spec::Hasher>::from_leaves(evals.clone(), 2);

                // All these values are stored in the `CommitmentWithData` because
                // they are useful in opening, and we don't want to recompute them.
                Ok(BasefoldCommitmentWithData {
                    codeword_tree,
                    polynomials_bh_evals: vec![evals],
                    num_vars: poly.num_vars(),
                    is_base,
                    num_polys: 1,
                })
            }
            PolyEvalsCodeword::TooBig(num_vars) => Err(Error::PolynomialTooLarge(num_vars)),
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
    fn open_inner<Strategy: BasefoldStrategy<E, Spec>>(
        pp: &BasefoldProverParams<E, Spec>,
        prover_inputs: &Strategy::ProverInputs<'_>,
        transcript: &mut Transcript<E>,
    ) -> Result<BasefoldProof<E, Spec>, Error> {
        if let Some(proof) = Strategy::trivial_proof(prover_inputs) {
            return Ok(proof);
        }

        let timer = start_timer!(|| "Basefold::open");

        let commit_phase_input =
            Strategy::prepare_commit_phase_input(pp, prover_inputs, transcript)?;

        // 1. Committing phase. This phase runs the sum-check and
        //    the FRI protocols interleavingly. After this phase,
        //    the sum-check protocol is finished, so nothing is
        //    to return about the sum-check. However, for the FRI
        //    part, the prover needs to prepare the answers to the
        //    queries, so the prover needs the oracles and the Merkle
        //    trees built over them.
        let (trees, commit_phase_proof) = commit_phase::<E, Spec, Strategy::CommitPhaseStrategy>(
            &pp.encoding_params,
            commit_phase_input.point.as_slice(),
            commit_phase_input.coeffs_outer.as_slice(),
            commit_phase_input.coeffs_inner.as_slice(),
            prover_inputs.comms(),
            transcript,
        );

        // 2. Query phase. ---------------------------------------
        //    Compute the query indices by Fiat-Shamir.
        //    For each index, prepare the answers and the Merkle paths.
        //    Each entry in queried_els stores a list of triples
        //    (F, F, i) indicating the position opened at each round and
        //    the two values at that round

        // 2.1 Prepare the answers. These include two values in each oracle,
        //     in positions (i, i XOR 1), (i >> 1, (i >> 1) XOR 1), ...
        //     respectively.
        let query_timer = start_timer!(|| "Basefold::open::query_phase");
        let queries = prover_query_phase::<E, Spec>(
            transcript,
            prover_inputs.comms(),
            &trees,
            Spec::get_number_queries(),
        );
        end_timer!(query_timer);

        end_timer!(timer);

        // End of query phase.----------------------------------

        Ok(BasefoldProof {
            sumcheck_messages: commit_phase_proof.sumcheck_messages,
            roots: commit_phase_proof.roots,
            final_message: commit_phase_proof.final_message,
            query_result: queries,
            sumcheck_proof: commit_phase_input.sumcheck_proof,
            trivial_proof: vec![],
        })
    }

    fn verify_inner<Strategy: BasefoldStrategy<E, Spec>>(
        vp: &BasefoldVerifierParams<E, Spec>,
        verifier_inputs: &Strategy::VerifierInputs<'_>,
        proof: &BasefoldProof<E, Spec>,
        transcript: &mut Transcript<E>,
    ) -> Result<(), Error> {
        if proof.is_trivial() {
            return Strategy::check_trivial_proof(verifier_inputs, proof, transcript);
        }
        let num_vars = verifier_inputs.num_vars();
        Strategy::check_sizes(verifier_inputs);
        let num_rounds = num_vars - Spec::get_basecode_msg_size_log();

        let (target_sum, verify_point, coeffs_outer, coeffs_inner) =
            Strategy::prepare_sumcheck_target_and_point_batching_coeffs(
                vp,
                verifier_inputs,
                proof,
                transcript,
            )?;

        let mut fold_challenges: Vec<E> = Vec::with_capacity(num_vars);
        let roots = &proof.roots;
        let sumcheck_messages = &proof.sumcheck_messages;
        for i in 0..num_rounds {
            transcript.append_field_element_exts(sumcheck_messages[i].as_slice());
            fold_challenges.push(
                transcript
                    .get_and_append_challenge(b"commit round")
                    .elements,
            );
            if i < num_rounds - 1 {
                <Spec::Hasher as Hasher<E>>::write_digest_to_transcript(&roots[i], transcript);
            }
        }

        let final_message = &proof.final_message;
        transcript.append_field_element_exts(final_message.as_slice());

        let queries: Vec<_> = (0..Spec::get_number_queries())
            .map(|_| {
                ext_to_usize(
                    &transcript
                        .get_and_append_challenge(b"query indices")
                        .elements,
                ) % (1 << (num_vars + Spec::get_rate_log()))
            })
            .collect();

        // coeff is the eq polynomial evaluated at the last challenge.len() variables
        // in reverse order.
        let rev_challenges = fold_challenges.clone().into_iter().rev().collect_vec();
        let coeff = eq_xy_eval(
            &verify_point[verify_point.len() - fold_challenges.len()..],
            &rev_challenges,
        );
        // Compute eq as the partially evaluated eq polynomial
        let mut eq = build_eq_x_r_vec(&verify_point[..verify_point.len() - fold_challenges.len()]);
        eq.par_iter_mut().for_each(|e| *e *= coeff);

        verifier_query_phase::<E, Spec, Strategy::QueryCheckStrategy>(
            queries.as_slice(),
            &vp.encoding_params,
            &proof.query_result,
            sumcheck_messages,
            &fold_challenges,
            &coeffs_outer,
            &coeffs_inner,
            num_rounds,
            num_vars,
            final_message,
            roots,
            verifier_inputs.comms(),
            eq.as_slice(),
            &target_sum,
        );

        Ok(())
    }
}

impl<E: ExtensionField, Spec: BasefoldSpec<E>> PolynomialCommitmentScheme<E> for Basefold<E, Spec>
where
    E: Serialize + DeserializeOwned,
    E::BaseField: Serialize + DeserializeOwned,
{
    type Param = BasefoldParams<E, Spec>;
    type ProverParam = BasefoldProverParams<E, Spec>;
    type VerifierParam = BasefoldVerifierParams<E, Spec>;
    type CommitmentWithData = BasefoldCommitmentWithData<E, Spec>;
    type Commitment = BasefoldCommitment<E, Spec>;
    type CommitmentChunk = <Spec::Hasher as Hasher<E>>::Digest;
    type Proof = BasefoldProof<E, Spec>;
    type Rng = ChaCha8Rng;

    fn setup(poly_size: usize) -> Result<Self::Param, Error> {
        let pp = <Spec::EncodingScheme as EncodingScheme<E>>::setup(log2_strict(poly_size));

        Ok(BasefoldParams { params: pp })
    }

    /// Derive the proving key and verification key from the public parameter.
    /// This step simultaneously trims the parameter for the particular size.
    fn trim(
        pp: &Self::Param,
        poly_size: usize,
    ) -> Result<(Self::ProverParam, Self::VerifierParam), Error> {
        <Spec::EncodingScheme as EncodingScheme<E>>::trim(&pp.params, log2_strict(poly_size)).map(
            |(pp, vp)| {
                (
                    BasefoldProverParams {
                        encoding_params: pp,
                    },
                    BasefoldVerifierParams {
                        encoding_params: vp,
                    },
                )
            },
        )
    }

    fn commit(
        pp: &Self::ProverParam,
        poly: &DenseMultilinearExtension<E>,
    ) -> Result<Self::CommitmentWithData, Error> {
        let timer = start_timer!(|| "Basefold::commit");
        let ret = Self::commit_inner(pp, poly);
        end_timer!(timer);

        ret
    }

    fn batch_commit(
        pp: &Self::ProverParam,
        polys: &[DenseMultilinearExtension<E>],
    ) -> Result<Self::CommitmentWithData, Error> {
        Self::batch_commit_inner(pp, polys)
    }

    fn write_commitment(
        comm: &Self::Commitment,
        transcript: &mut Transcript<E>,
    ) -> Result<(), Error> {
        Spec::Hasher::write_digest_to_transcript(&comm.root(), transcript);
        Ok(())
    }

    fn get_pure_commitment(comm: &Self::CommitmentWithData) -> Self::Commitment {
        comm.to_commitment()
    }

    /// Open a single polynomial commitment at one point. If the given
    /// commitment with data contains more than one polynomial, this function
    /// will panic.
    fn open(
        pp: &Self::ProverParam,
        poly: &ArcMultilinearExtension<E>,
        comm: &Self::CommitmentWithData,
        point: &[E],
        eval: &E, // Opening does not need eval, except for sanity check
        transcript: &mut Transcript<E>,
    ) -> Result<Self::Proof, Error> {
        if cfg!(feature = "sanity-check") {
            assert_eq!(&poly.evaluate(point), eval);
        }

        let prover_inputs = basic::ProverInputs { poly, comm, point };

        Self::open_inner::<BasicBasefoldStrategy>(pp, &prover_inputs, transcript)
    }

    /// Open a batch of polynomial commitments at several points.
    /// The current version only supports one polynomial per commitment.
    /// Because otherwise it is complex to match the polynomials and
    /// the commitments, and because currently this high flexibility is
    /// not very useful in ceno.
    fn batch_open_vlmp(
        pp: &Self::ProverParam,
        polys: &[ArcMultilinearExtension<E>],
        comms: &[Self::CommitmentWithData],
        points: &[&[E]],
        evals: &[Evaluation<E>],
        transcript: &mut Transcript<E>,
    ) -> Result<Self::Proof, Error> {
        if cfg!(feature = "sanity-check") {
            evals.iter().for_each(|eval| {
                assert_eq!(
                    &polys[eval.poly()].evaluate(points[eval.point()]),
                    eval.value()
                )
            })
        }

        let prover_inputs = batch_vlmp::ProverInputs {
            comms,
            polys,
            points,
            evals,
        };

        Self::open_inner::<BatchVLMPBasefoldStrategy>(pp, &prover_inputs, transcript)
    }

    /// This is a simple version of batch open:
    /// 1. Open at one point
    /// 2. All the polynomials share the same commitment and have the same
    ///    number of variables.
    /// 3. The point is already a random point generated by a sum-check.
    fn simple_batch_open(
        pp: &Self::ProverParam,
        polys: &[ArcMultilinearExtension<E>],
        comm: &Self::CommitmentWithData,
        point: &[E],
        evals: &[E],
        transcript: &mut Transcript<E>,
    ) -> Result<Self::Proof, Error> {
        if cfg!(feature = "sanity-check") {
            evals
                .iter()
                .zip(polys)
                .for_each(|(eval, poly)| assert_eq!(&poly.evaluate(point), eval))
        }
        let prover_inputs = batch_simple::ProverInputs { comm, polys, point };
        Self::open_inner::<BatchSimpleBasefoldStrategy>(pp, &prover_inputs, transcript)
    }

    fn batch_open_vlop(
        pp: &Self::ProverParam,
        polys: &[&[ArcMultilinearExtension<E>]],
        comms: &[Self::CommitmentWithData],
        point: &[E],
        evals: &[&[E]],
        transcript: &mut Transcript<E>,
    ) -> Result<Self::Proof, Error> {
        if cfg!(feature = "sanity-check") {
            evals.iter().zip_eq(polys).for_each(|(evals, polys)| {
                evals.iter().zip_eq(polys.iter()).for_each(|(eval, poly)| {
                    assert_eq!(&poly.evaluate(&point[..poly.num_vars()]), eval)
                })
            })
        }

        let prover_inputs = batch_vlop::ProverInputs {
            comms,
            polys,
            point,
        };

        Self::open_inner::<BatchVLOPBasefoldStrategy>(pp, &prover_inputs, transcript)
    }

    fn verify(
        vp: &Self::VerifierParam,
        comm: &Self::Commitment,
        point: &[E],
        eval: &E,
        proof: &Self::Proof,
        transcript: &mut Transcript<E>,
    ) -> Result<(), Error> {
        let timer = start_timer!(|| "Basefold::verify");
        let verifier_inputs = basic::VerifierInputs {
            comm,
            point,
            num_vars: point.len(),
            eval: *eval,
        };
        let ret =
            Self::verify_inner::<BasicBasefoldStrategy>(vp, &verifier_inputs, proof, transcript);
        end_timer!(timer);
        ret
    }

    fn batch_verify_vlmp(
        vp: &Self::VerifierParam,
        comms: &[Self::Commitment],
        points: &[&[E]],
        evals: &[Evaluation<E>],
        proof: &Self::Proof,
        transcript: &mut Transcript<E>,
    ) -> Result<(), Error> {
        let verifier_inputs = batch_vlmp::VerifierInputs {
            comms,
            points,
            num_vars: points.iter().map(|point| point.len()).max().unwrap(),
            evals,
        };
        Self::verify_inner::<BatchVLMPBasefoldStrategy>(vp, &verifier_inputs, proof, transcript)
    }

    fn simple_batch_verify(
        vp: &Self::VerifierParam,
        comm: &Self::Commitment,
        point: &[E],
        evals: &[E],
        proof: &Self::Proof,
        transcript: &mut Transcript<E>,
    ) -> Result<(), Error> {
        let verifier_inputs = batch_simple::VerifierInputs {
            comm,
            point,
            num_vars: point.len(),
            evals,
        };
        Self::verify_inner::<BatchSimpleBasefoldStrategy>(vp, &verifier_inputs, proof, transcript)
    }

    fn batch_verify_vlop(
        vp: &Self::VerifierParam,
        comms: &[Self::Commitment],
        point: &[E],
        max_num_vars: usize,
        evals: &[&[E]],
        proof: &Self::Proof,
        transcript: &mut Transcript<E>,
    ) -> Result<(), Error> {
        let verifier_inputs = batch_vlop::VerifierInputs {
            comms,
            point,
            num_vars: max_num_vars,
            evals,
        };
        Self::verify_inner::<BatchVLOPBasefoldStrategy>(vp, &verifier_inputs, proof, transcript)
    }
}

#[cfg(test)]
mod test {
    use crate::{
        basefold::Basefold,
        test_util::{
            run_batch_vlmp_commit_open_verify, run_batch_vlop_commit_open_verify,
            run_commit_open_verify, run_simple_batch_commit_open_verify,
        },
    };
    use goldilocks::GoldilocksExt2;

    use super::{structure::BasefoldBasecodeParams, BasefoldRSParams};

    type PcsGoldilocksRSCode = Basefold<GoldilocksExt2, BasefoldRSParams>;
    type PcsGoldilocksBaseCode = Basefold<GoldilocksExt2, BasefoldBasecodeParams>;

    #[test]
    fn commit_open_verify_goldilocks() {
        for base in [true, false].into_iter() {
            // Challenge is over extension field, poly over the base field
            run_commit_open_verify::<GoldilocksExt2, PcsGoldilocksBaseCode>(base, 10, 11);
            // Test trivial proof with small num vars
            run_commit_open_verify::<GoldilocksExt2, PcsGoldilocksBaseCode>(base, 4, 6);
            // Challenge is over extension field, poly over the base field
            run_commit_open_verify::<GoldilocksExt2, PcsGoldilocksRSCode>(base, 10, 11);
            // Test trivial proof with small num vars
            run_commit_open_verify::<GoldilocksExt2, PcsGoldilocksRSCode>(base, 4, 6);
        }
    }

    #[test]
    fn simple_batch_commit_open_verify_goldilocks() {
        for base in [true, false].into_iter() {
            // Both challenge and poly are over base field
            run_simple_batch_commit_open_verify::<GoldilocksExt2, PcsGoldilocksBaseCode>(
                base, 10, 11, 1,
            );
            run_simple_batch_commit_open_verify::<GoldilocksExt2, PcsGoldilocksBaseCode>(
                base, 10, 11, 4,
            );
            // Test trivial proof with small num vars
            run_simple_batch_commit_open_verify::<GoldilocksExt2, PcsGoldilocksBaseCode>(
                base, 4, 6, 4,
            );
            // Both challenge and poly are over base field
            run_simple_batch_commit_open_verify::<GoldilocksExt2, PcsGoldilocksRSCode>(
                base, 10, 11, 1,
            );
            run_simple_batch_commit_open_verify::<GoldilocksExt2, PcsGoldilocksRSCode>(
                base, 10, 11, 4,
            );
            // Test trivial proof with small num vars
            run_simple_batch_commit_open_verify::<GoldilocksExt2, PcsGoldilocksRSCode>(
                base, 4, 6, 4,
            );
        }
    }

    #[test]
    fn batch_vlmp_commit_open_verify() {
        for base in [true, false].iter() {
            // Both challenge and poly are over base field
            run_batch_vlmp_commit_open_verify::<GoldilocksExt2, PcsGoldilocksBaseCode>(
                *base, 10, 11,
            );
            run_batch_vlmp_commit_open_verify::<GoldilocksExt2, PcsGoldilocksRSCode>(*base, 10, 11);
        }
    }

    #[test]
    fn batch_vlop_commit_open_verify() {
        for batch_inner in 1..4 {
            for batch_outer in 1..2 {
                // Both challenge and poly are over base field
                run_batch_vlop_commit_open_verify::<GoldilocksExt2, PcsGoldilocksBaseCode>(
                    true,
                    8,
                    9,
                    batch_outer,
                    batch_inner,
                );
                run_batch_vlop_commit_open_verify::<GoldilocksExt2, PcsGoldilocksRSCode>(
                    true,
                    8,
                    9,
                    batch_outer,
                    batch_inner,
                );
                run_batch_vlop_commit_open_verify::<GoldilocksExt2, PcsGoldilocksBaseCode>(
                    false,
                    8,
                    9,
                    batch_outer,
                    batch_inner,
                );
                run_batch_vlop_commit_open_verify::<GoldilocksExt2, PcsGoldilocksRSCode>(
                    false,
                    8,
                    9,
                    batch_outer,
                    batch_inner,
                );
            }
        }
    }
}
