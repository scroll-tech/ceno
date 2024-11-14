use crate::{
    Error, Evaluation, NoninteractivePCS, PolynomialCommitmentScheme,
    sum_check::{
        SumCheck as _,
        classic::{ClassicSumCheck, CoefficientsProver},
        eq_xy_eval,
    },
    util::{
        arithmetic::{inner_product_three, interpolate_field_type_over_boolean_hypercube},
        ext_to_usize,
        hash::{Digest, write_digest_to_transcript},
        log2_strict,
        merkle_tree::MerkleTree,
        plonky2_util::reverse_index_bits_in_place_field_type,
        poly_index_ext, poly_iter_ext,
    },
    validate_input,
};
use ark_std::{end_timer, start_timer};
pub use encoding::{
    Basecode, BasecodeDefaultSpec, EncodingProverParameters, EncodingScheme, RSCode,
    RSCodeDefaultSpec,
};
use ff_ext::ExtensionField;
use query_phase::{batch_verifier_query_phase, simple_batch_verifier_query_phase};
use structure::BasefoldProof;
pub use structure::BasefoldSpec;
use transcript::Transcript;

use itertools::Itertools;
use serde::{Serialize, de::DeserializeOwned};

use multilinear_extensions::{
    mle::{DenseMultilinearExtension, FieldType},
    virtual_poly::build_eq_x_r_vec,
};

use rayon::{
    iter::IntoParallelIterator,
    prelude::{IntoParallelRefIterator, IntoParallelRefMutIterator, ParallelIterator},
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
mod encoding;
pub use encoding::{coset_fft, fft, fft_root_table};
use multilinear_extensions::virtual_poly_v2::ArcMultilinearExtension;

mod query_phase;
// This sumcheck module is different from the mpcs::sumcheck module, in that
// it deals only with the special case of the form \sum eq(r_i)f_i().
mod sumcheck;

mod basic;
mod batch_simple;
mod batch_vlmp;

enum PolyEvalsCodeword<E: ExtensionField> {
    Normal((FieldType<E>, FieldType<E>)),
    TooSmall(FieldType<E>), // The polynomial is too small to apply FRI
    TooBig(usize),
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
        let mut bh_evals = poly.evaluations.clone();
        let num_vars = poly.num_vars;
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
{
    type Param = BasefoldParams<E, Spec>;
    type ProverParam = BasefoldProverParams<E, Spec>;
    type VerifierParam = BasefoldVerifierParams<E, Spec>;
    type CommitmentWithData = BasefoldCommitmentWithData<E>;
    type Commitment = BasefoldCommitment<E>;
    type CommitmentChunk = Digest<E::BaseField>;
    type Proof = BasefoldProof<E>;

    fn setup(poly_size: usize) -> Result<Self::Param, Error> {
        let pp = <Spec::EncodingScheme as EncodingScheme<E>>::setup(log2_strict(poly_size));

        Ok(BasefoldParams { params: pp })
    }

    /// Derive the proving key and verification key from the public parameter.
    /// This step simultaneously trims the parameter for the particular size.
    fn trim(
        pp: Self::Param,
        poly_size: usize,
    ) -> Result<(Self::ProverParam, Self::VerifierParam), Error> {
        <Spec::EncodingScheme as EncodingScheme<E>>::trim(pp.params, log2_strict(poly_size)).map(
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

        let is_base = match poly.evaluations {
            FieldType::Ext(_) => false,
            FieldType::Base(_) => true,
            _ => unreachable!(),
        };

        // 2. Compute and store all the layers of the Merkle tree

        // 1. Encode the polynomials. Simultaneously get:
        //  (1) The evaluations over the hypercube (just a clone of the input)
        //  (2) The encoding of the coefficient vector (need an interpolation)
        let ret = match Self::get_poly_bh_evals_and_codeword(pp, poly) {
            PolyEvalsCodeword::Normal((bh_evals, codeword)) => {
                let codeword_tree = MerkleTree::<E>::from_leaves(codeword);

                // All these values are stored in the `CommitmentWithData` because
                // they are useful in opening, and we don't want to recompute them.
                Ok(Self::CommitmentWithData {
                    codeword_tree,
                    polynomials_bh_evals: vec![bh_evals],
                    num_vars: poly.num_vars,
                    is_base,
                    num_polys: 1,
                })
            }
            PolyEvalsCodeword::TooSmall(evals) => {
                let codeword_tree = MerkleTree::<E>::from_leaves(evals.clone());

                // All these values are stored in the `CommitmentWithData` because
                // they are useful in opening, and we don't want to recompute them.
                Ok(Self::CommitmentWithData {
                    codeword_tree,
                    polynomials_bh_evals: vec![evals],
                    num_vars: poly.num_vars,
                    is_base,
                    num_polys: 1,
                })
            }
            PolyEvalsCodeword::TooBig(num_vars) => Err(Error::PolynomialTooLarge(num_vars)),
        };

        end_timer!(timer);

        ret
    }

    fn batch_commit(
        pp: &Self::ProverParam,
        polys: &[DenseMultilinearExtension<E>],
    ) -> Result<Self::CommitmentWithData, Error> {
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

        let is_base = match polys[0].evaluations {
            FieldType::Ext(_) => false,
            FieldType::Base(_) => true,
            _ => unreachable!(),
        };

        for i in 1..polys.len() {
            if polys[i].num_vars != polys[0].num_vars {
                return Err(Error::InvalidPcsParam(
                    "cannot batch commit to polynomials with different number of variables"
                        .to_string(),
                ));
            }
        }
        let timer = start_timer!(|| "Basefold::batch commit");

        let encode_timer = start_timer!(|| "Basefold::batch commit::encoding and interpolations");
        // convert each polynomial to a code word
        let evals_codewords = polys
            .par_iter()
            .map(|poly| Self::get_poly_bh_evals_and_codeword(pp, poly))
            .collect::<Vec<PolyEvalsCodeword<E>>>();
        end_timer!(encode_timer);

        // build merkle tree from leaves
        let ret = match evals_codewords[0] {
            PolyEvalsCodeword::Normal(_) => {
                let (bh_evals, codewords) = evals_codewords
                    .into_iter()
                    .map(|evals_codeword| match evals_codeword {
                        PolyEvalsCodeword::Normal((bh_evals, codeword)) => (bh_evals, codeword),
                        PolyEvalsCodeword::TooSmall(_) => {
                            unreachable!();
                        }
                        PolyEvalsCodeword::TooBig(_) => {
                            unreachable!();
                        }
                    })
                    .collect::<(Vec<_>, Vec<_>)>();
                let codeword_tree = MerkleTree::<E>::from_batch_leaves(codewords);
                Self::CommitmentWithData {
                    codeword_tree,
                    polynomials_bh_evals: bh_evals,
                    num_vars: polys[0].num_vars,
                    is_base,
                    num_polys: polys.len(),
                }
            }
            PolyEvalsCodeword::TooSmall(_) => {
                let bh_evals = evals_codewords
                    .into_iter()
                    .map(|bh_evals| match bh_evals {
                        PolyEvalsCodeword::Normal(_) => unreachable!(),
                        PolyEvalsCodeword::TooSmall(evals) => evals,
                        PolyEvalsCodeword::TooBig(_) => {
                            unreachable!();
                        }
                    })
                    .collect::<Vec<_>>();
                let codeword_tree = MerkleTree::<E>::from_batch_leaves(bh_evals.clone());
                Self::CommitmentWithData {
                    codeword_tree,
                    polynomials_bh_evals: bh_evals,
                    num_vars: polys[0].num_vars,
                    is_base,
                    num_polys: polys.len(),
                }
            }
            PolyEvalsCodeword::TooBig(num_vars) => return Err(Error::PolynomialTooLarge(num_vars)),
        };

        end_timer!(timer);

        Ok(ret)
    }

    fn write_commitment(
        comm: &Self::Commitment,
        transcript: &mut Transcript<E>,
    ) -> Result<(), Error> {
        write_digest_to_transcript(&comm.root(), transcript);
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
        _eval: &E, // Opening does not need eval, except for sanity check
        transcript: &mut Transcript<E>,
    ) -> Result<Self::Proof, Error> {
        Self::basic_open(pp, poly, comm, point, transcript)
    }

    /// Open a batch of polynomial commitments at several points.
    /// The current version only supports one polynomial per commitment.
    /// Because otherwise it is complex to match the polynomials and
    /// the commitments, and because currently this high flexibility is
    /// not very useful in ceno.
    fn batch_open(
        pp: &Self::ProverParam,
        polys: &[ArcMultilinearExtension<E>],
        comms: &[Self::CommitmentWithData],
        points: &[Vec<E>],
        evals: &[Evaluation<E>],
        transcript: &mut Transcript<E>,
    ) -> Result<Self::Proof, Error> {
        Self::batch_vlmp_open(pp, polys, comms, points, evals, transcript)
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
        Self::simple_batch_open_inner(pp, polys, comm, point, evals, transcript)
    }

    fn verify(
        vp: &Self::VerifierParam,
        comm: &Self::Commitment,
        point: &[E],
        eval: &E,
        proof: &Self::Proof,
        transcript: &mut Transcript<E>,
    ) -> Result<(), Error> {
        Self::basic_verify(vp, comm, point, eval, proof, transcript)
    }

    fn batch_verify(
        vp: &Self::VerifierParam,
        comms: &[Self::Commitment],
        points: &[Vec<E>],
        evals: &[Evaluation<E>],
        proof: &Self::Proof,
        transcript: &mut Transcript<E>,
    ) -> Result<(), Error> {
        let timer = start_timer!(|| "Basefold::batch_verify");
        // 	let key = "RAYON_NUM_THREADS";
        // 	env::set_var(key, "32");
        let comms = comms.iter().collect_vec();
        let num_vars = points.iter().map(|point| point.len()).max().unwrap();
        let num_rounds = num_vars - Spec::get_basecode_msg_size_log();
        validate_input("batch verify", num_vars, &[], points)?;
        let poly_num_vars = comms.iter().map(|c| c.num_vars().unwrap()).collect_vec();
        evals.iter().for_each(|eval| {
            assert_eq!(
                points[eval.point()].len(),
                comms[eval.poly()].num_vars().unwrap()
            );
        });
        assert!(poly_num_vars.iter().min().unwrap() >= &Spec::get_basecode_msg_size_log());
        assert!(!proof.is_trivial());

        let sumcheck_timer = start_timer!(|| "Basefold::batch_verify::initial sumcheck");
        let batch_size_log = evals.len().next_power_of_two().ilog2() as usize;
        let t = (0..batch_size_log)
            .map(|_| {
                transcript
                    .get_and_append_challenge(b"batch coeffs")
                    .elements
            })
            .collect::<Vec<_>>();

        let eq_xt =
            DenseMultilinearExtension::from_evaluations_ext_vec(t.len(), build_eq_x_r_vec(&t));
        let target_sum = inner_product_three(
            evals.iter().map(Evaluation::value),
            &evals
                .iter()
                .map(|eval| E::from(1 << (num_vars - points[eval.point()].len())))
                .collect_vec(),
            &poly_iter_ext(&eq_xt).take(evals.len()).collect_vec(),
        );

        let (new_target_sum, verify_point) = SumCheck::verify(
            &(),
            num_vars,
            2,
            target_sum,
            proof.sumcheck_proof.as_ref().unwrap(),
            transcript,
        )?;
        end_timer!(sumcheck_timer);

        // Now the goal is to use the BaseFold to check the new target sum. Note that this time
        // we only have one eq polynomial in the sum-check.
        let eq_xy_evals = points
            .iter()
            .map(|point| eq_xy_eval(&verify_point[..point.len()], point))
            .collect_vec();
        let mut coeffs = vec![E::ZERO; comms.len()];
        evals.iter().enumerate().for_each(|(i, eval)| {
            coeffs[eval.poly()] += eq_xy_evals[eval.point()] * poly_index_ext(&eq_xt, i)
        });

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
                write_digest_to_transcript(&roots[i], transcript);
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
        let query_result_with_merkle_path = proof.query_result_with_merkle_path.as_batched();

        // coeff is the eq polynomial evaluated at the last challenge.len() variables
        // in reverse order.
        let rev_challenges = fold_challenges.clone().into_iter().rev().collect_vec();
        let coeff = eq_xy_eval(
            &verify_point.as_slice()[verify_point.len() - fold_challenges.len()..],
            &rev_challenges,
        );
        // Compute eq as the partially evaluated eq polynomial
        let mut eq = build_eq_x_r_vec(
            &verify_point.as_slice()[..verify_point.len() - fold_challenges.len()],
        );
        eq.par_iter_mut().for_each(|e| *e *= coeff);

        batch_verifier_query_phase::<E, Spec>(
            queries.as_slice(),
            &vp.encoding_params,
            query_result_with_merkle_path,
            sumcheck_messages,
            &fold_challenges,
            num_rounds,
            num_vars,
            final_message,
            roots,
            &comms,
            &coeffs,
            eq.as_slice(),
            &new_target_sum,
        );
        end_timer!(timer);
        Ok(())
    }

    fn simple_batch_verify(
        vp: &Self::VerifierParam,
        comm: &Self::Commitment,
        point: &[E],
        evals: &[E],
        proof: &Self::Proof,
        transcript: &mut Transcript<E>,
    ) -> Result<(), Error> {
        let timer = start_timer!(|| "Basefold::simple batch verify");
        let batch_size = evals.len();
        if let Some(num_polys) = comm.num_polys {
            assert_eq!(num_polys, batch_size);
        }

        if proof.is_trivial() {
            let trivial_proof = &proof.trivial_proof;
            let merkle_tree = MerkleTree::from_batch_leaves(trivial_proof.clone());
            if comm.root() == merkle_tree.root() {
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
        let batch_size_log = evals.len().next_power_of_two().ilog2() as usize;
        let t = (0..batch_size_log)
            .map(|_| {
                transcript
                    .get_and_append_challenge(b"batch coeffs")
                    .elements
            })
            .collect::<Vec<_>>();
        let eq_xt = build_eq_x_r_vec(&t)[..evals.len()].to_vec();

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
                write_digest_to_transcript(&roots[i], transcript);
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
        let query_result_with_merkle_path = proof.query_result_with_merkle_path.as_simple_batched();

        // coeff is the eq polynomial evaluated at the last challenge.len() variables
        // in reverse order.
        let rev_challenges = fold_challenges.clone().into_iter().rev().collect_vec();
        let coeff = eq_xy_eval(
            &point[point.len() - fold_challenges.len()..],
            &rev_challenges,
        );
        // Compute eq as the partially evaluated eq polynomial
        let mut eq = build_eq_x_r_vec(&point[..point.len() - fold_challenges.len()]);
        eq.par_iter_mut().for_each(|e| *e *= coeff);

        simple_batch_verifier_query_phase::<E, Spec>(
            queries.as_slice(),
            &vp.encoding_params,
            query_result_with_merkle_path,
            sumcheck_messages,
            &fold_challenges,
            &eq_xt,
            num_rounds,
            num_vars,
            final_message,
            roots,
            comm,
            eq.as_slice(),
            evals,
        );
        end_timer!(timer);

        Ok(())
    }
}

impl<E: ExtensionField, Spec: BasefoldSpec<E>> NoninteractivePCS<E> for Basefold<E, Spec>
where
    E: Serialize + DeserializeOwned,
    E::BaseField: Serialize + DeserializeOwned,
{
}

#[cfg(test)]
mod test {
    use crate::{
        basefold::Basefold,
        test_util::{
            run_batch_commit_open_verify, run_commit_open_verify,
            run_simple_batch_commit_open_verify,
        },
    };
    use goldilocks::GoldilocksExt2;

    use super::{BasefoldRSParams, structure::BasefoldBasecodeParams};

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
    fn batch_commit_open_verify() {
        for base in [true, false].iter() {
            // Both challenge and poly are over base field
            run_batch_commit_open_verify::<GoldilocksExt2, PcsGoldilocksBaseCode>(*base, 10, 11);
            run_batch_commit_open_verify::<GoldilocksExt2, PcsGoldilocksRSCode>(*base, 10, 11);
        }
    }
}
