use crate::{
    sum_check::{
        classic::{ClassicSumCheck, CoefficientsProver},
        eq_xy_eval, SumCheck as _, VirtualPolynomial,
    },
    util::{
        add_polynomial_with_coeff,
        arithmetic::{
            inner_product, inner_product_three, interpolate_field_type_over_boolean_hypercube,
        },
        base_to_usize,
        expression::{Expression, Query, Rotation},
        ext_to_usize,
        hash::{new_hasher, Digest},
        log2_strict,
        merkle_tree::MerkleTree,
        multiply_poly,
        plonky2_util::reverse_index_bits_in_place_field_type,
        poly_index_ext, poly_iter_ext,
        transcript::{TranscriptRead, TranscriptWrite},
        u32_to_field,
    },
    validate_input, Error, Evaluation, NoninteractivePCS, PolynomialCommitmentScheme,
};
use ark_std::{end_timer, start_timer};
pub use encoding::{
    Basecode, BasecodeDefaultSpec, EncodingProverParameters, EncodingScheme, RSCode,
    RSCodeDefaultSpec,
};
use ff_ext::ExtensionField;
use multilinear_extensions::mle::MultilinearExtension;
use query_phase::{
    batch_prover_query_phase, batch_verifier_query_phase, prover_query_phase,
    simple_batch_prover_query_phase, simple_batch_verifier_query_phase, verifier_query_phase,
    BatchedQueriesResultWithMerklePath, QueriesResultWithMerklePath,
    SimpleBatchQueriesResultWithMerklePath,
};
use std::{borrow::BorrowMut, ops::Deref};
pub use structure::BasefoldSpec;

use itertools::Itertools;
use serde::{de::DeserializeOwned, Serialize};

use multilinear_extensions::{
    mle::{DenseMultilinearExtension, FieldType},
    virtual_poly::build_eq_x_r_vec,
};

use rand_chacha::{rand_core::RngCore, ChaCha8Rng};
use rayon::{
    iter::IntoParallelIterator,
    prelude::{IntoParallelRefIterator, IntoParallelRefMutIterator, ParallelIterator},
};
use std::borrow::Cow;

type SumCheck<F> = ClassicSumCheck<CoefficientsProver<F>>;

mod structure;
pub use structure::{
    Basefold, BasefoldBasecodeParams, BasefoldCommitment, BasefoldCommitmentWithData,
    BasefoldDefault, BasefoldParams, BasefoldProverParams, BasefoldRSParams,
    BasefoldVerifierParams,
};
mod commit_phase;
use commit_phase::{batch_commit_phase, commit_phase, simple_batch_commit_phase};
mod encoding;
pub use encoding::{coset_fft, fft, fft_root_table};
mod query_phase;
// This sumcheck module is different from the mpcs::sumcheck module, in that
// it deals only with the special case of the form \sum eq(r_i)f_i().
mod sumcheck;

impl<E: ExtensionField, Spec: BasefoldSpec<E>, Rng: RngCore> Basefold<E, Spec, Rng>
where
    E: Serialize + DeserializeOwned,
    E::BaseField: Serialize + DeserializeOwned,
{
    /// Converts a polynomial to a code word, also returns the evaluations over the boolean hypercube
    /// for said polynomial
    fn get_poly_bh_evals_and_codeword(
        pp: &BasefoldProverParams<E, Spec>,
        poly: &DenseMultilinearExtension<E>,
    ) -> (FieldType<E>, FieldType<E>) {
        // bh_evals is just a copy of poly.evals().
        // Note that this function implicitly assumes that the size of poly.evals() is a
        // power of two. Otherwise, the function crashes with index out of bound.
        let mut bh_evals = poly.evaluations.clone();
        let num_vars = poly.num_vars;
        assert!(
            num_vars <= pp.encoding_params.get_max_message_size_log(),
            "num_vars {} > pp.max_num_vars {}",
            num_vars,
            pp.encoding_params.get_max_message_size_log()
        );
        assert!(
            num_vars >= Spec::get_basecode_msg_size_log(),
            "num_vars {} < Spec::get_basecode_msg_size_log() {}",
            num_vars,
            Spec::get_basecode_msg_size_log()
        );

        // Switch to coefficient form
        let mut coeffs = bh_evals.clone();
        interpolate_field_type_over_boolean_hypercube(&mut coeffs);

        if <Spec::EncodingScheme as EncodingScheme<E>>::message_is_even_and_odd_folding() {
            reverse_index_bits_in_place_field_type(&mut coeffs);
        }
        let mut codeword = Spec::EncodingScheme::encode(&pp.encoding_params, &coeffs);

        // If using repetition code as basecode, it may be faster to use the following line of code to create the commitment and comment out the two lines above
        //        let mut codeword = evaluate_over_foldable_domain(pp.log_rate, coeffs, &pp.table);

        // The sum-check protocol starts from the first variable, but the FRI part
        // will eventually produce the evaluation at (alpha_k, ..., alpha_1), so apply
        // the bit-reversion to reverse the variable indices of the polynomial.
        // In short: store the poly and codeword in big endian
        reverse_index_bits_in_place_field_type(&mut bh_evals);
        reverse_index_bits_in_place_field_type(&mut codeword);

        (bh_evals, codeword)
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

impl<E: ExtensionField, Spec: BasefoldSpec<E>, Rng: RngCore + std::fmt::Debug>
    PolynomialCommitmentScheme<E> for Basefold<E, Spec, Rng>
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
    type Rng = ChaCha8Rng;

    fn setup(poly_size: usize, rng: &Self::Rng) -> Result<Self::Param, Error> {
        let mut seed = [0u8; 32];
        let mut rng = rng.clone();
        rng.fill_bytes(&mut seed);
        let pp = <Spec::EncodingScheme as EncodingScheme<E>>::setup(log2_strict(poly_size), seed);

        Ok(BasefoldParams { params: pp })
    }

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

        let (bh_evals, codeword) = Self::get_poly_bh_evals_and_codeword(pp, poly);

        // Compute and store all the layers of the Merkle tree
        let hasher = new_hasher::<E::BaseField>();
        let codeword_tree = MerkleTree::<E>::from_leaves(codeword, &hasher);

        end_timer!(timer);

        let is_base = match poly.evaluations {
            FieldType::Ext(_) => false,
            FieldType::Base(_) => true,
            _ => unreachable!(),
        };

        Ok(Self::CommitmentWithData {
            codeword_tree,
            polynomials_bh_evals: vec![bh_evals],
            num_vars: poly.num_vars,
            is_base,
            num_polys: 1,
        })
    }

    fn batch_commit_and_write(
        pp: &Self::ProverParam,
        polys: &[DenseMultilinearExtension<E>],
        transcript: &mut impl TranscriptWrite<Self::CommitmentChunk, E>,
    ) -> Result<Self::CommitmentWithData, Error> {
        let timer = start_timer!(|| "Basefold::batch_commit_and_write");
        let comm = Self::batch_commit(pp, polys)?;
        transcript.write_commitment(&comm.get_root_as()).unwrap();
        transcript
            .write_field_element_base(&u32_to_field::<E>(comm.num_vars as u32))
            .unwrap();
        transcript
            .write_field_element_base(&u32_to_field::<E>(comm.is_base as u32))
            .unwrap();
        transcript
            .write_field_element_base(&u32_to_field::<E>(comm.num_polys as u32))
            .unwrap();
        end_timer!(timer);
        Ok(comm)
    }

    fn batch_commit(
        pp: &Self::ProverParam,
        polys: &[DenseMultilinearExtension<E>],
    ) -> Result<Self::CommitmentWithData, Error> {
        // assumptions
        // 1. there must be at least one polynomial
        // 2. all polynomials must exist in the same field type
        // 3. all polynomials must have the same number of variables

        if polys.is_empty() {
            return Err(Error::InvalidPcsParam(
                "cannot batch commit to zero polynomials".to_string(),
            ));
        }

        for i in 1..polys.len() {
            if polys[i].num_vars != polys[0].num_vars {
                return Err(Error::InvalidPcsParam(
                    "cannot batch commit to polynomials with different number of variables"
                        .to_string(),
                ));
            }
        }

        // convert each polynomial to a code word
        let (bh_evals, codewords) = polys
            .par_iter()
            .map(|poly| Self::get_poly_bh_evals_and_codeword(pp, poly))
            .collect::<(Vec<FieldType<E>>, Vec<FieldType<E>>)>();

        // transpose the codewords, to group evaluations at the same point
        // let leaves = Self::transpose_field_type::<E>(codewords.as_slice())?;

        // build merkle tree from leaves
        let hasher = new_hasher::<E::BaseField>();
        let codeword_tree = MerkleTree::<E>::from_batch_leaves(codewords, &hasher);

        let is_base = match polys[0].evaluations {
            FieldType::Ext(_) => false,
            FieldType::Base(_) => true,
            _ => unreachable!(),
        };

        Ok(Self::CommitmentWithData {
            codeword_tree,
            polynomials_bh_evals: bh_evals,
            num_vars: polys[0].num_vars,
            is_base,
            num_polys: polys.len(),
        })
    }

    /// Open a single polynomial commitment at one point. If the given
    /// commitment with data contains more than one polynomial, this function
    /// will panic.
    fn open(
        pp: &Self::ProverParam,
        poly: &DenseMultilinearExtension<E>,
        comm: &Self::CommitmentWithData,
        point: &[E],
        _eval: &E, // Opening does not need eval, except for sanity check
        transcript: &mut impl TranscriptWrite<Self::CommitmentChunk, E>,
    ) -> Result<(), Error> {
        let hasher = new_hasher::<E::BaseField>();
        let timer = start_timer!(|| "Basefold::open");
        assert!(comm.num_vars >= Spec::get_basecode_msg_size_log());
        assert!(comm.num_polys == 1);
        let (trees, oracles) = commit_phase::<E, Spec>(
            &pp.encoding_params,
            point,
            comm,
            transcript,
            poly.num_vars,
            poly.num_vars - Spec::get_basecode_msg_size_log(),
            &hasher,
        );

        let query_timer = start_timer!(|| "Basefold::open::query_phase");
        // Each entry in queried_els stores a list of triples (F, F, i) indicating the
        // position opened at each round and the two values at that round
        let queries = prover_query_phase(transcript, comm, &oracles, Spec::get_number_queries());
        end_timer!(query_timer);

        let query_timer = start_timer!(|| "Basefold::open::build_query_result");

        let queries_with_merkle_path =
            QueriesResultWithMerklePath::from_query_result(queries, &trees, comm);
        end_timer!(query_timer);

        let query_timer = start_timer!(|| "Basefold::open::write_queries");
        queries_with_merkle_path.write_transcript(transcript);
        end_timer!(query_timer);

        end_timer!(timer);

        Ok(())
    }

    /// Open a batch of polynomial commitments at several points.
    /// The current version only supports one polynomial per commitment.
    /// Because otherwise it is complex to match the polynomials and
    /// the commitments, and because currently this high flexibility is
    /// not very useful in ceno.
    fn batch_open(
        pp: &Self::ProverParam,
        polys: &[DenseMultilinearExtension<E>],
        comms: &[Self::CommitmentWithData],
        points: &[Vec<E>],
        evals: &[Evaluation<E>],
        transcript: &mut impl TranscriptWrite<Self::CommitmentChunk, E>,
    ) -> Result<(), Error> {
        let hasher = new_hasher::<E::BaseField>();
        let timer = start_timer!(|| "Basefold::batch_open");
        let num_vars = polys.iter().map(|poly| poly.num_vars).max().unwrap();
        let min_num_vars = polys.iter().map(|p| p.num_vars).min().unwrap();
        assert!(min_num_vars >= Spec::get_basecode_msg_size_log());

        comms.iter().for_each(|comm| {
            assert!(comm.num_polys == 1);
        });

        if cfg!(feature = "sanity-check") {
            evals.iter().for_each(|eval| {
                assert_eq!(
                    &polys[eval.poly()].evaluate(&points[eval.point()]),
                    eval.value(),
                )
            })
        }

        validate_input("batch open", pp.get_max_message_size_log(), polys, points)?;

        let sumcheck_timer = start_timer!(|| "Basefold::batch_open::initial sumcheck");
        // evals.len() is the batch size, i.e., how many polynomials are being opened together
        let batch_size_log = evals.len().next_power_of_two().ilog2() as usize;
        let t = transcript.squeeze_challenges(batch_size_log);

        // Use eq(X,t) where t is random to batch the different evaluation queries.
        // Note that this is a small polynomial (only batch_size) compared to the polynomials
        // to open.
        let eq_xt =
            DenseMultilinearExtension::<E>::from_evaluations_ext_vec(t.len(), build_eq_x_r_vec(&t));
        // When this polynomial is smaller, it will be repeatedly summed over the cosets of the hypercube
        let target_sum = inner_product_three(
            evals.iter().map(Evaluation::value),
            &evals
                .iter()
                .map(|eval| E::from(1 << (num_vars - points[eval.point()].len())))
                .collect_vec(),
            &poly_iter_ext(&eq_xt).take(evals.len()).collect_vec(),
        );

        // Merge the polynomials for every point. One merged polynomial for each point.
        let merged_polys = evals.iter().zip(poly_iter_ext(&eq_xt)).fold(
            // This folding will generate a vector of |points| pairs of (scalar, polynomial)
            // The polynomials are initialized to zero, and the scalars are initialized to one
            vec![(E::ONE, Cow::<DenseMultilinearExtension<E>>::default()); points.len()],
            |mut merged_polys, (eval, eq_xt_i)| {
                // For each polynomial to open, eval.point() specifies which point it is to be opened at.
                if merged_polys[eval.point()].1.num_vars == 0 {
                    // If the accumulator for this point is still the zero polynomial,
                    // directly assign the random coefficient and the polynomial to open to
                    // this accumulator
                    merged_polys[eval.point()] = (eq_xt_i, Cow::Borrowed(&polys[eval.poly()]));
                } else {
                    // If the accumulator is unempty now, first force its scalar to 1, i.e.,
                    // make (scalar, polynomial) to (1, scalar * polynomial)
                    let coeff = merged_polys[eval.point()].0;
                    if coeff != E::ONE {
                        merged_polys[eval.point()].0 = E::ONE;
                        multiply_poly(merged_polys[eval.point()].1.to_mut().borrow_mut(), &coeff);
                    }
                    // Equivalent to merged_poly += poly * batch_coeff. Note that
                    // add_assign_mixed_with_coeff allows adding two polynomials with
                    // different variables, and the result has the same number of vars
                    // with the larger one of the two added polynomials.
                    add_polynomial_with_coeff(
                        merged_polys[eval.point()].1.to_mut().borrow_mut(),
                        &polys[eval.poly()],
                        &eq_xt_i,
                    );

                    // Note that once the scalar in the accumulator becomes ONE, it will remain
                    // to be ONE forever.
                }
                merged_polys
            },
        );

        let points = points.to_vec();
        if cfg!(feature = "sanity-check") {
            let expected_sum = merged_polys
                .iter()
                .zip(&points)
                .map(|((scalar, poly), point)| {
                    inner_product(
                        &poly_iter_ext(poly).collect_vec(),
                        build_eq_x_r_vec(point).iter(),
                    ) * scalar
                        * E::from(1 << (num_vars - poly.num_vars))
                    // When this polynomial is smaller, it will be repeatedly summed over the cosets of the hypercube
                })
                .sum::<E>();
            assert_eq!(expected_sum, target_sum);

            merged_polys.iter().enumerate().for_each(|(i, (_, poly))| {
                assert_eq!(points[i].len(), poly.num_vars);
            });
        }

        let expression = merged_polys
            .iter()
            .enumerate()
            .map(|(idx, (scalar, _))| {
                Expression::<E>::eq_xy(idx)
                    * Expression::Polynomial(Query::new(idx, Rotation::cur()))
                    * scalar
            })
            .sum();
        let sumcheck_polys: Vec<&DenseMultilinearExtension<E>> = merged_polys
            .iter()
            .map(|(_, poly)| poly.deref())
            .collect_vec();
        let virtual_poly =
            VirtualPolynomial::new(&expression, sumcheck_polys, &[], points.as_slice());

        let (challenges, merged_poly_evals) =
            SumCheck::prove(&(), num_vars, virtual_poly, target_sum, transcript)?;

        end_timer!(sumcheck_timer);

        // Now the verifier has obtained the new target sum, and is able to compute the random
        // linear coefficients, and is able to evaluate eq_xy(point) for each poly to open.
        // The remaining tasks for the prover is to prove that
        // sum_i coeffs[i] poly_evals[i] is equal to
        // the new target sum, where coeffs is computed as follows
        let eq_xy_evals = points
            .iter()
            .map(|point| eq_xy_eval(&challenges[..point.len()], point))
            .collect_vec();
        let mut coeffs = vec![E::ZERO; comms.len()];
        evals.iter().enumerate().for_each(|(i, eval)| {
            coeffs[eval.poly()] += eq_xy_evals[eval.point()] * poly_index_ext(&eq_xt, i);
        });

        if cfg!(feature = "sanity-check") {
            let poly_evals = polys
                .iter()
                .map(|poly| poly.evaluate(&challenges[..poly.num_vars]))
                .collect_vec();
            let new_target_sum = inner_product(&poly_evals, &coeffs);
            let desired_sum = merged_polys
                .iter()
                .zip(points)
                .zip(merged_poly_evals)
                .map(|(((scalar, poly), point), evals_from_sum_check)| {
                    assert_eq!(
                        evals_from_sum_check,
                        poly.evaluate(&challenges[..poly.num_vars])
                    );
                    *scalar
                        * evals_from_sum_check
                        * eq_xy_eval(point.as_slice(), &challenges[0..point.len()])
                })
                .sum::<E>();
            assert_eq!(new_target_sum, desired_sum);
        }
        // Note that the verifier can also compute these coeffs locally, so no need to pass
        // them to the transcript.

        let point = challenges;

        let (trees, oracles) = batch_commit_phase::<E, Spec>(
            &pp.encoding_params,
            &point,
            comms,
            transcript,
            num_vars,
            num_vars - Spec::get_basecode_msg_size_log(),
            coeffs.as_slice(),
            &hasher,
        );

        let query_timer = start_timer!(|| "Basefold::batch_open query phase");
        let query_result = batch_prover_query_phase(
            transcript,
            1 << (num_vars + Spec::get_rate_log()),
            comms,
            &oracles,
            Spec::get_number_queries(),
        );
        end_timer!(query_timer);

        let query_timer = start_timer!(|| "Basefold::batch_open build query result");
        let query_result_with_merkle_path =
            BatchedQueriesResultWithMerklePath::from_batched_query_result(
                query_result,
                &trees,
                comms,
            );
        end_timer!(query_timer);

        let query_timer = start_timer!(|| "Basefold::batch_open write query result");
        query_result_with_merkle_path.write_transcript(transcript);
        end_timer!(query_timer);
        end_timer!(timer);

        Ok(())
    }

    /// This is a simple version of batch open:
    /// 1. Open at one point
    /// 2. All the polynomials share the same commitment and have the same
    ///    number of variables.
    /// 3. The point is already a random point generated by a sum-check.
    fn simple_batch_open(
        pp: &Self::ProverParam,
        polys: &[DenseMultilinearExtension<E>],
        comm: &Self::CommitmentWithData,
        point: &[E],
        evals: &[E],
        transcript: &mut impl TranscriptWrite<Self::CommitmentChunk, E>,
    ) -> Result<(), Error> {
        let hasher = new_hasher::<E::BaseField>();
        let timer = start_timer!(|| "Basefold::batch_open");
        let num_vars = polys[0].num_vars;

        polys
            .iter()
            .for_each(|poly| assert_eq!(poly.num_vars, num_vars));
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
        let batch_size_log = evals.len().next_power_of_two().ilog2() as usize;
        let t = transcript.squeeze_challenges(batch_size_log);

        // Use eq(X,t) where t is random to batch the different evaluation queries.
        // Note that this is a small polynomial (only batch_size) compared to the polynomials
        // to open.
        let eq_xt = build_eq_x_r_vec(&t)[..evals.len()].to_vec();
        let _target_sum = inner_product(evals, &eq_xt);

        // Now the verifier has obtained the new target sum, and is able to compute the random
        // linear coefficients.
        // The remaining tasks for the prover is to prove that
        // sum_i coeffs[i] poly_evals[i] is equal to
        // the new target sum, where coeffs is computed as follows
        let (trees, oracles) = simple_batch_commit_phase::<E, Spec>(
            &pp.encoding_params,
            point,
            &eq_xt,
            comm,
            transcript,
            num_vars,
            num_vars - Spec::get_basecode_msg_size_log(),
            &hasher,
        );

        let query_timer = start_timer!(|| "Basefold::open::query_phase");
        // Each entry in queried_els stores a list of triples (F, F, i) indicating the
        // position opened at each round and the two values at that round
        let queries =
            simple_batch_prover_query_phase(transcript, comm, &oracles, Spec::get_number_queries());
        end_timer!(query_timer);

        let query_timer = start_timer!(|| "Basefold::open::build_query_result");

        let queries_with_merkle_path =
            SimpleBatchQueriesResultWithMerklePath::from_query_result(queries, &trees, comm);
        end_timer!(query_timer);

        let query_timer = start_timer!(|| "Basefold::open::write_queries");
        queries_with_merkle_path.write_transcript(transcript);
        end_timer!(query_timer);

        end_timer!(timer);

        Ok(())
    }

    fn read_commitments(
        _: &Self::VerifierParam,
        num_polys: usize,
        transcript: &mut impl TranscriptRead<Self::CommitmentChunk, E>,
    ) -> Result<Vec<Self::Commitment>, Error> {
        let roots = (0..num_polys)
            .map(|_| {
                let commitment = transcript.read_commitment().unwrap();
                let num_vars = base_to_usize::<E>(&transcript.read_field_element_base().unwrap());
                let is_base =
                    base_to_usize::<E>(&transcript.read_field_element_base().unwrap()) != 0;
                let num_polys = base_to_usize::<E>(&transcript.read_field_element_base().unwrap());
                (num_vars, commitment, is_base, num_polys)
            })
            .collect_vec();

        Ok(roots
            .iter()
            .map(|(num_vars, commitment, is_base, num_polys)| {
                BasefoldCommitment::new(commitment.clone(), *num_vars, *is_base, *num_polys)
            })
            .collect_vec())
    }

    fn commit_and_write(
        pp: &Self::ProverParam,
        poly: &DenseMultilinearExtension<E>,
        transcript: &mut impl TranscriptWrite<Self::CommitmentChunk, E>,
    ) -> Result<Self::CommitmentWithData, Error> {
        let comm = Self::commit(pp, poly)?;

        transcript.write_commitment(&comm.get_root_as())?;
        transcript.write_field_element_base(&u32_to_field::<E>(comm.num_vars as u32))?;
        transcript.write_field_element_base(&u32_to_field::<E>(comm.is_base as u32))?;
        transcript.write_field_element_base(&u32_to_field::<E>(comm.num_polys as u32))?;

        Ok(comm)
    }

    fn verify(
        vp: &Self::VerifierParam,
        comm: &Self::Commitment,
        point: &[E],
        eval: &E,
        transcript: &mut impl TranscriptRead<Self::CommitmentChunk, E>,
    ) -> Result<(), Error> {
        let timer = start_timer!(|| "Basefold::verify");
        assert!(comm.num_vars().unwrap() >= Spec::get_basecode_msg_size_log());
        let hasher = new_hasher::<E::BaseField>();

        let num_vars = point.len();
        if let Some(comm_num_vars) = comm.num_vars() {
            assert_eq!(num_vars, comm_num_vars);
        }
        let num_rounds = num_vars - Spec::get_basecode_msg_size_log();

        let mut fold_challenges: Vec<E> = Vec::with_capacity(num_vars);
        let mut roots = Vec::new();
        let mut sumcheck_messages = Vec::with_capacity(num_rounds);
        let sumcheck_timer = start_timer!(|| "Basefold::verify::interaction");
        for i in 0..num_rounds {
            sumcheck_messages.push(transcript.read_field_elements_ext(3).unwrap());
            fold_challenges.push(transcript.squeeze_challenge());
            if i < num_rounds - 1 {
                roots.push(transcript.read_commitment().unwrap());
            }
        }
        end_timer!(sumcheck_timer);

        let read_timer = start_timer!(|| "Basefold::verify::read transcript");
        let final_message = transcript
            .read_field_elements_ext(1 << Spec::get_basecode_msg_size_log())
            .unwrap();
        let query_challenges = transcript
            .squeeze_challenges(Spec::get_number_queries())
            .iter()
            .map(|index| ext_to_usize(index) % (1 << (num_vars + Spec::get_rate_log())))
            .collect_vec();
        let read_query_timer = start_timer!(|| "Basefold::verify::read query");
        let query_result_with_merkle_path = if comm.is_base() {
            QueriesResultWithMerklePath::read_transcript_base(
                transcript,
                num_rounds,
                Spec::get_rate_log(),
                num_vars,
                query_challenges.as_slice(),
            )
        } else {
            QueriesResultWithMerklePath::read_transcript_ext(
                transcript,
                num_rounds,
                Spec::get_rate_log(),
                num_vars,
                query_challenges.as_slice(),
            )
        };
        end_timer!(read_query_timer);
        end_timer!(read_timer);

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

        verifier_query_phase::<E, Spec>(
            &vp.encoding_params,
            &query_result_with_merkle_path,
            &sumcheck_messages,
            &fold_challenges,
            num_rounds,
            num_vars,
            &final_message,
            &roots,
            comm,
            eq.as_slice(),
            eval,
            &hasher,
        );
        end_timer!(timer);

        Ok(())
    }

    fn batch_verify(
        vp: &Self::VerifierParam,
        comms: &[Self::Commitment],
        points: &[Vec<E>],
        evals: &[Evaluation<E>],
        transcript: &mut impl TranscriptRead<Self::CommitmentChunk, E>,
    ) -> Result<(), Error> {
        let timer = start_timer!(|| "Basefold::batch_verify");
        // 	let key = "RAYON_NUM_THREADS";
        // 	env::set_var(key, "32");
        let hasher = new_hasher::<E::BaseField>();
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

        let sumcheck_timer = start_timer!(|| "Basefold::batch_verify::initial sumcheck");
        let batch_size_log = evals.len().next_power_of_two().ilog2() as usize;
        let t = transcript.squeeze_challenges(batch_size_log);

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

        let (new_target_sum, verify_point) =
            SumCheck::verify(&(), num_vars, 2, target_sum, transcript)?;
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

        // start of verify
        // read first $(num_var - 1) commitments
        let read_timer = start_timer!(|| "Basefold::verify::read transcript");
        let mut sumcheck_messages: Vec<Vec<E>> = Vec::with_capacity(num_rounds);
        let mut roots: Vec<Digest<E::BaseField>> = Vec::with_capacity(num_rounds - 1);
        let mut fold_challenges: Vec<E> = Vec::with_capacity(num_rounds);
        for i in 0..num_rounds {
            sumcheck_messages.push(transcript.read_field_elements_ext(3).unwrap());
            fold_challenges.push(transcript.squeeze_challenge());
            if i < num_rounds - 1 {
                roots.push(transcript.read_commitment().unwrap());
            }
        }
        let final_message = transcript
            .read_field_elements_ext(1 << Spec::get_basecode_msg_size_log())
            .unwrap();

        let query_challenges = transcript
            .squeeze_challenges(Spec::get_number_queries())
            .iter()
            .map(|index| ext_to_usize(index) % (1 << (num_vars + Spec::get_rate_log())))
            .collect_vec();

        let read_query_timer = start_timer!(|| "Basefold::verify::read query");
        // Here we assumed that all the commitments have the same type:
        // either all base field or all extension field. Need to handle
        // more complex case later.
        let query_result_with_merkle_path = if comms[0].is_base {
            BatchedQueriesResultWithMerklePath::read_transcript_base(
                transcript,
                num_rounds,
                Spec::get_rate_log(),
                poly_num_vars.as_slice(),
                query_challenges.as_slice(),
            )
        } else {
            BatchedQueriesResultWithMerklePath::read_transcript_ext(
                transcript,
                num_rounds,
                Spec::get_rate_log(),
                poly_num_vars.as_slice(),
                query_challenges.as_slice(),
            )
        };
        end_timer!(read_query_timer);
        end_timer!(read_timer);

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
            &vp.encoding_params,
            &query_result_with_merkle_path,
            &sumcheck_messages,
            &fold_challenges,
            num_rounds,
            num_vars,
            &final_message,
            &roots,
            &comms,
            &coeffs,
            eq.as_slice(),
            &new_target_sum,
            &hasher,
        );
        end_timer!(timer);
        Ok(())
    }

    fn simple_batch_verify(
        vp: &Self::VerifierParam,
        comm: &Self::Commitment,
        point: &[E],
        evals: &[E],
        transcript: &mut impl TranscriptRead<Self::CommitmentChunk, E>,
    ) -> Result<(), Error> {
        let timer = start_timer!(|| "Basefold::simple batch verify");
        assert!(comm.num_vars().unwrap() >= Spec::get_basecode_msg_size_log());
        let batch_size = evals.len();
        if let Some(num_polys) = comm.num_polys {
            assert_eq!(num_polys, batch_size);
        }
        let hasher = new_hasher::<E::BaseField>();

        let num_vars = point.len();
        if let Some(comm_num_vars) = comm.num_vars {
            assert_eq!(num_vars, comm_num_vars);
        }
        let num_rounds = num_vars - Spec::get_basecode_msg_size_log();

        // evals.len() is the batch size, i.e., how many polynomials are being opened together
        let batch_size_log = evals.len().next_power_of_two().ilog2() as usize;
        let t = transcript.squeeze_challenges(batch_size_log);
        let eq_xt = build_eq_x_r_vec(&t)[..evals.len()].to_vec();

        let mut fold_challenges: Vec<E> = Vec::with_capacity(num_vars);
        let mut roots = Vec::new();
        let mut sumcheck_messages = Vec::with_capacity(num_rounds);
        let sumcheck_timer = start_timer!(|| "Basefold::simple_batch_verify::interaction");
        for i in 0..num_rounds {
            sumcheck_messages.push(transcript.read_field_elements_ext(3).unwrap());
            fold_challenges.push(transcript.squeeze_challenge());
            if i < num_rounds - 1 {
                roots.push(transcript.read_commitment().unwrap());
            }
        }
        end_timer!(sumcheck_timer);

        let read_timer = start_timer!(|| "Basefold::verify::read transcript");
        let final_message = transcript
            .read_field_elements_ext(1 << Spec::get_basecode_msg_size_log())
            .unwrap();
        let query_challenges = transcript
            .squeeze_challenges(Spec::get_number_queries())
            .iter()
            .map(|index| ext_to_usize(index) % (1 << (num_vars + Spec::get_rate_log())))
            .collect_vec();
        let read_query_timer = start_timer!(|| "Basefold::verify::read query");
        let query_result_with_merkle_path = if comm.is_base() {
            SimpleBatchQueriesResultWithMerklePath::read_transcript_base(
                transcript,
                num_rounds,
                Spec::get_rate_log(),
                num_vars,
                query_challenges.as_slice(),
                batch_size,
            )
        } else {
            SimpleBatchQueriesResultWithMerklePath::read_transcript_ext(
                transcript,
                num_rounds,
                Spec::get_rate_log(),
                num_vars,
                query_challenges.as_slice(),
                batch_size,
            )
        };
        end_timer!(read_query_timer);
        end_timer!(read_timer);

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
            &vp.encoding_params,
            &query_result_with_merkle_path,
            &sumcheck_messages,
            &fold_challenges,
            &eq_xt,
            num_rounds,
            num_vars,
            &final_message,
            &roots,
            comm,
            eq.as_slice(),
            evals,
            &hasher,
        );
        end_timer!(timer);

        Ok(())
    }
}

impl<E: ExtensionField, Spec: BasefoldSpec<E>, Rng: RngCore + std::fmt::Debug> NoninteractivePCS<E>
    for Basefold<E, Spec, Rng>
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
        util::transcript::PoseidonTranscript,
    };
    use goldilocks::GoldilocksExt2;
    use rand_chacha::ChaCha8Rng;

    use super::{structure::BasefoldBasecodeParams, BasefoldRSParams};

    type PcsGoldilocksRSCode = Basefold<GoldilocksExt2, BasefoldRSParams, ChaCha8Rng>;
    type PcsGoldilocksBaseCode = Basefold<GoldilocksExt2, BasefoldBasecodeParams, ChaCha8Rng>;

    #[test]
    fn commit_open_verify_goldilocks_basecode_base() {
        // Challenge is over extension field, poly over the base field
        run_commit_open_verify::<
            GoldilocksExt2,
            PcsGoldilocksBaseCode,
            PoseidonTranscript<GoldilocksExt2>,
        >(true, 10, 11);
    }

    #[test]
    fn commit_open_verify_goldilocks_rscode_base() {
        // Challenge is over extension field, poly over the base field
        run_commit_open_verify::<
            GoldilocksExt2,
            PcsGoldilocksRSCode,
            PoseidonTranscript<GoldilocksExt2>,
        >(true, 10, 11);
    }

    #[test]
    fn commit_open_verify_goldilocks_basecode_2() {
        // Both challenge and poly are over extension field
        run_commit_open_verify::<GoldilocksExt2, PcsGoldilocksBaseCode, PoseidonTranscript<_>>(
            false, 10, 11,
        );
    }

    #[test]
    fn commit_open_verify_goldilocks_rscode_2() {
        // Both challenge and poly are over extension field
        run_commit_open_verify::<GoldilocksExt2, PcsGoldilocksRSCode, PoseidonTranscript<_>>(
            false, 10, 11,
        );
    }

    #[test]
    fn simple_batch_commit_open_verify_goldilocks_basecode_base() {
        // Both challenge and poly are over base field
        run_simple_batch_commit_open_verify::<
            GoldilocksExt2,
            PcsGoldilocksBaseCode,
            PoseidonTranscript<GoldilocksExt2>,
        >(true, 10, 11, 4);
    }

    #[test]
    fn simple_batch_commit_open_verify_goldilocks_rscode_base() {
        // Both challenge and poly are over base field
        run_simple_batch_commit_open_verify::<
            GoldilocksExt2,
            PcsGoldilocksRSCode,
            PoseidonTranscript<GoldilocksExt2>,
        >(true, 10, 11, 4);
    }

    #[test]
    fn simple_batch_commit_open_verify_goldilocks_basecode_2() {
        // Both challenge and poly are over extension field
        run_simple_batch_commit_open_verify::<
            GoldilocksExt2,
            PcsGoldilocksBaseCode,
            PoseidonTranscript<_>,
        >(false, 10, 11, 4);
    }

    #[test]
    fn simple_batch_commit_open_verify_goldilocks_rscode_2() {
        // Both challenge and poly are over extension field
        run_simple_batch_commit_open_verify::<
            GoldilocksExt2,
            PcsGoldilocksRSCode,
            PoseidonTranscript<_>,
        >(false, 10, 11, 4);
    }

    #[test]
    fn batch_commit_open_verify_goldilocks_basecode_base() {
        // Both challenge and poly are over base field
        run_batch_commit_open_verify::<
            GoldilocksExt2,
            PcsGoldilocksBaseCode,
            PoseidonTranscript<GoldilocksExt2>,
        >(true, 10, 11);
    }

    #[test]
    fn batch_commit_open_verify_goldilocks_rscode_base() {
        // Both challenge and poly are over base field
        run_batch_commit_open_verify::<
            GoldilocksExt2,
            PcsGoldilocksRSCode,
            PoseidonTranscript<GoldilocksExt2>,
        >(true, 10, 11);
    }

    #[test]
    fn batch_commit_open_verify_goldilocks_basecode_2() {
        // Both challenge and poly are over extension field
        run_batch_commit_open_verify::<GoldilocksExt2, PcsGoldilocksBaseCode, PoseidonTranscript<_>>(
            false, 10, 11,
        );
    }

    #[test]
    fn batch_commit_open_verify_goldilocks_rscode_2() {
        // Both challenge and poly are over extension field
        run_batch_commit_open_verify::<GoldilocksExt2, PcsGoldilocksRSCode, PoseidonTranscript<_>>(
            false, 10, 11,
        );
    }
}
