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
use ff_ext::ExtensionField;
use query_phase::{
    batch_query_phase, batch_verifier_query_phase, query_phase, verifier_query_phase,
    BatchedQueriesResultWithMerklePath, QueriesResultWithMerklePath,
};
use std::{borrow::BorrowMut, ops::Deref};

use itertools::Itertools;
use serde::{de::DeserializeOwned, Serialize};

use multilinear_extensions::{
    mle::{DenseMultilinearExtension, FieldType},
    virtual_poly::build_eq_x_r_vec,
};

use rand_chacha::ChaCha8Rng;
use rayon::prelude::{IntoParallelRefIterator, IntoParallelRefMutIterator, ParallelIterator};
use std::borrow::Cow;
type SumCheck<F> = ClassicSumCheck<CoefficientsProver<F>>;

mod basecode;
mod structure;
use basecode::{
    encode_field_type_rs_basecode, evaluate_over_foldable_domain_generic_basecode, get_table_aes,
};
pub use structure::{
    Basefold, BasefoldCommitment, BasefoldCommitmentWithData, BasefoldDefault,
    BasefoldDefaultParams, BasefoldExtParams, BasefoldParams, BasefoldProverParams,
    BasefoldVerifierParams,
};
mod commit_phase;
use commit_phase::{batch_commit_phase, commit_phase};
mod query_phase;
// This sumcheck module is different from the mpcs::sumcheck module, in that
// it deals only with the special case of the form \sum eq(r_i)f_i().
mod sumcheck;

impl<E: ExtensionField, V: BasefoldExtParams> PolynomialCommitmentScheme<E> for Basefold<E, V>
where
    E: Serialize + DeserializeOwned,
    E::BaseField: Serialize + DeserializeOwned,
{
    type Param = BasefoldParams<E, ChaCha8Rng>;
    type ProverParam = BasefoldProverParams<E>;
    type VerifierParam = BasefoldVerifierParams<ChaCha8Rng>;
    type CommitmentWithData = BasefoldCommitmentWithData<E>;
    type Commitment = BasefoldCommitment<E>;
    type CommitmentChunk = Digest<E::BaseField>;
    type Rng = ChaCha8Rng;

    fn setup(poly_size: usize, rng: &Self::Rng) -> Result<Self::Param, Error> {
        let log_rate = V::get_rate();
        let (table_w_weights, table) = get_table_aes::<E, _>(poly_size, log_rate, &mut rng.clone());

        Ok(BasefoldParams {
            log_rate,
            num_verifier_queries: V::get_reps(),
            max_num_vars: log2_strict(poly_size),
            table_w_weights,
            table,
            rng: rng.clone(),
        })
    }

    fn trim(param: &Self::Param) -> Result<(Self::ProverParam, Self::VerifierParam), Error> {
        Ok((
            BasefoldProverParams {
                log_rate: param.log_rate,
                table_w_weights: param.table_w_weights.clone(),
                table: param.table.clone(),
                num_verifier_queries: param.num_verifier_queries,
                max_num_vars: param.max_num_vars,
            },
            BasefoldVerifierParams {
                rng: param.rng.clone(),
                max_num_vars: param.max_num_vars,
                log_rate: param.log_rate,
                num_verifier_queries: param.num_verifier_queries,
            },
        ))
    }

    fn commit(
        pp: &Self::ProverParam,
        poly: &DenseMultilinearExtension<E>,
    ) -> Result<Self::CommitmentWithData, Error> {
        let timer = start_timer!(|| "Basefold::commit");
        // bh_evals is just a copy of poly.evals().
        // Note that this function implicitly assumes that the size of poly.evals() is a
        // power of two. Otherwise, the function crashes with index out of bound.
        let mut bh_evals = poly.evaluations.clone();
        let num_vars = log2_strict(bh_evals.len());
        assert!(num_vars <= pp.max_num_vars && num_vars >= V::get_basecode());

        // Switch to coefficient form
        let mut coeffs = bh_evals.clone();
        interpolate_field_type_over_boolean_hypercube(&mut coeffs);

        // Split the input into chunks of message size, encode each message, and return the codewords
        let basecode =
            encode_field_type_rs_basecode(&coeffs, 1 << pp.log_rate, 1 << V::get_basecode());

        // Apply the recursive definition of the BaseFold code to the list of base codewords,
        // and produce the final codeword
        let mut codeword = evaluate_over_foldable_domain_generic_basecode::<E>(
            1 << V::get_basecode(),
            coeffs.len(),
            pp.log_rate,
            basecode,
            &pp.table,
        );

        // If using repetition code as basecode, it may be faster to use the following line of code to create the commitment and comment out the two lines above
        //        let mut codeword = evaluate_over_foldable_domain(pp.log_rate, coeffs, &pp.table);

        // The sum-check protocol starts from the first variable, but the FRI part
        // will eventually produce the evaluation at (alpha_k, ..., alpha_1), so apply
        // the bit-reversion to reverse the variable indices of the polynomial.
        // In short: store the poly and codeword in big endian
        reverse_index_bits_in_place_field_type(&mut bh_evals);
        reverse_index_bits_in_place_field_type(&mut codeword);

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
            bh_evals,
            num_vars,
            is_base,
        })
    }

    fn batch_commit_and_write(
        pp: &Self::ProverParam,
        polys: &Vec<DenseMultilinearExtension<E>>,
        transcript: &mut impl TranscriptWrite<Self::CommitmentChunk, E>,
    ) -> Result<Vec<Self::CommitmentWithData>, Error> {
        let timer = start_timer!(|| "Basefold::batch_commit_and_write");
        let comms = Self::batch_commit(pp, polys)?;
        comms.iter().for_each(|comm| {
            transcript.write_commitment(&comm.get_root_as()).unwrap();
            transcript
                .write_field_element_base(&u32_to_field::<E>(comm.num_vars as u32))
                .unwrap();
            transcript
                .write_field_element_base(&u32_to_field::<E>(comm.is_base as u32))
                .unwrap();
        });
        end_timer!(timer);
        Ok(comms)
    }

    fn batch_commit(
        pp: &Self::ProverParam,
        polys: &Vec<DenseMultilinearExtension<E>>,
    ) -> Result<Vec<Self::CommitmentWithData>, Error> {
        let polys_vec: Vec<&DenseMultilinearExtension<E>> =
            polys.into_iter().map(|poly| poly).collect();
        polys_vec
            .par_iter()
            .map(|poly| Self::commit(pp, poly))
            .collect()
    }

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
        assert!(comm.num_vars >= V::get_basecode());
        let (trees, oracles) = commit_phase(
            &point,
            &comm,
            transcript,
            poly.num_vars,
            poly.num_vars - V::get_basecode(),
            &pp.table_w_weights,
            pp.log_rate,
            &hasher,
        );

        let query_timer = start_timer!(|| "Basefold::open::query_phase");
        // Each entry in queried_els stores a list of triples (F, F, i) indicating the
        // position opened at each round and the two values at that round
        let queries = query_phase(transcript, &comm, &oracles, pp.num_verifier_queries);
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

    fn batch_open(
        pp: &Self::ProverParam,
        polys: &Vec<DenseMultilinearExtension<E>>,
        comms: &Vec<Self::CommitmentWithData>,
        points: &[Vec<E>],
        evals: &[Evaluation<E>],
        transcript: &mut impl TranscriptWrite<Self::CommitmentChunk, E>,
    ) -> Result<(), Error> {
        let hasher = new_hasher::<E::BaseField>();
        let timer = start_timer!(|| "Basefold::batch_open");
        let num_vars = polys.iter().map(|poly| poly.num_vars).max().unwrap();
        let comms = comms.into_iter().collect_vec();
        let min_num_vars = polys.iter().map(|p| p.num_vars).min().unwrap();
        assert!(min_num_vars >= V::get_basecode());

        if cfg!(feature = "sanity-check") {
            evals.iter().for_each(|eval| {
                assert_eq!(
                    &polys[eval.poly()].evaluate(&points[eval.point()]),
                    eval.value(),
                )
            })
        }

        validate_input(
            "batch open",
            pp.max_num_vars,
            &polys.clone(),
            &points.to_vec(),
        )?;

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
                        build_eq_x_r_vec(&point).iter(),
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
                        * &eq_xy_eval(point.as_slice(), &challenges[0..point.len()])
                })
                .sum::<E>();
            assert_eq!(new_target_sum, desired_sum);
        }
        // Note that the verifier can also compute these coeffs locally, so no need to pass
        // them to the transcript.

        let point = challenges;

        let (trees, oracles) = batch_commit_phase(
            &point,
            comms.as_slice(),
            transcript,
            num_vars,
            num_vars - V::get_basecode(),
            &pp.table_w_weights,
            pp.log_rate,
            coeffs.as_slice(),
            &hasher,
        );

        let query_timer = start_timer!(|| "Basefold::batch_open query phase");
        let query_result = batch_query_phase(
            transcript,
            1 << (num_vars + pp.log_rate),
            comms.as_slice(),
            &oracles,
            pp.num_verifier_queries,
        );
        end_timer!(query_timer);

        let query_timer = start_timer!(|| "Basefold::batch_open build query result");
        let query_result_with_merkle_path =
            BatchedQueriesResultWithMerklePath::from_batched_query_result(
                query_result,
                &trees,
                &comms,
            );
        end_timer!(query_timer);

        let query_timer = start_timer!(|| "Basefold::batch_open write query result");
        query_result_with_merkle_path.write_transcript(transcript);
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
                (num_vars, commitment, is_base)
            })
            .collect_vec();

        Ok(roots
            .iter()
            .map(|(num_vars, commitment, is_base)| {
                BasefoldCommitment::new(commitment.clone(), *num_vars, *is_base)
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
        assert!(comm.num_vars().unwrap() >= V::get_basecode());
        let hasher = new_hasher::<E::BaseField>();

        let _field_size = 255;
        let num_vars = point.len();
        let num_rounds = num_vars - V::get_basecode();

        let mut fold_challenges: Vec<E> = Vec::with_capacity(vp.max_num_vars);
        let _size = 0;
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
            .read_field_elements_ext(1 << V::get_basecode())
            .unwrap();
        let query_challenges = transcript
            .squeeze_challenges(vp.num_verifier_queries)
            .iter()
            .map(|index| ext_to_usize(index) % (1 << (num_vars + vp.log_rate)))
            .collect_vec();
        let read_query_timer = start_timer!(|| "Basefold::verify::read query");
        let query_result_with_merkle_path = if comm.is_base() {
            QueriesResultWithMerklePath::read_transcript_base(
                transcript,
                num_rounds,
                vp.log_rate,
                num_vars,
                query_challenges.as_slice(),
            )
        } else {
            QueriesResultWithMerklePath::read_transcript_ext(
                transcript,
                num_rounds,
                vp.log_rate,
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

        verifier_query_phase(
            &query_result_with_merkle_path,
            &sumcheck_messages,
            &fold_challenges,
            num_rounds,
            num_vars,
            vp.log_rate,
            &final_message,
            &roots,
            comm,
            eq.as_slice(),
            vp.rng.clone(),
            &eval,
            &hasher,
        );
        end_timer!(timer);

        Ok(())
    }

    fn batch_verify(
        vp: &Self::VerifierParam,
        comms: &Vec<Self::Commitment>,
        points: &[Vec<E>],
        evals: &[Evaluation<E>],
        transcript: &mut impl TranscriptRead<Self::CommitmentChunk, E>,
    ) -> Result<(), Error> {
        let timer = start_timer!(|| "Basefold::batch_verify");
        // 	let key = "RAYON_NUM_THREADS";
        // 	env::set_var(key, "32");
        let hasher = new_hasher::<E::BaseField>();
        let comms = comms.into_iter().collect_vec();
        let num_vars = points.iter().map(|point| point.len()).max().unwrap();
        let num_rounds = num_vars - V::get_basecode();
        validate_input("batch verify", vp.max_num_vars, &vec![], &points.to_vec())?;
        let poly_num_vars = comms.iter().map(|c| c.num_vars().unwrap()).collect_vec();
        evals.iter().for_each(|eval| {
            assert_eq!(
                points[eval.point()].len(),
                comms[eval.poly()].num_vars().unwrap()
            );
        });
        assert!(poly_num_vars.iter().min().unwrap() >= &V::get_basecode());

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
            .read_field_elements_ext(1 << V::get_basecode())
            .unwrap();

        let query_challenges = transcript
            .squeeze_challenges(vp.num_verifier_queries)
            .iter()
            .map(|index| ext_to_usize(index) % (1 << (num_vars + vp.log_rate)))
            .collect_vec();

        let read_query_timer = start_timer!(|| "Basefold::verify::read query");
        // Here we assumed that all the commitments have the same type:
        // either all base field or all extension field. Need to handle
        // more complex case later.
        let query_result_with_merkle_path = if comms[0].is_base {
            BatchedQueriesResultWithMerklePath::read_transcript_base(
                transcript,
                num_rounds,
                vp.log_rate,
                poly_num_vars.as_slice(),
                query_challenges.as_slice(),
            )
        } else {
            BatchedQueriesResultWithMerklePath::read_transcript_ext(
                transcript,
                num_rounds,
                vp.log_rate,
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

        batch_verifier_query_phase(
            &query_result_with_merkle_path,
            &sumcheck_messages,
            &fold_challenges,
            num_rounds,
            num_vars,
            vp.log_rate,
            &final_message,
            &roots,
            &comms,
            &coeffs,
            eq.as_slice(),
            vp.rng.clone(),
            &new_target_sum,
            &hasher,
        );
        end_timer!(timer);
        Ok(())
    }
}

impl<E: ExtensionField, V: BasefoldExtParams> NoninteractivePCS<E> for Basefold<E, V>
where
    E: Serialize + DeserializeOwned,
    E::BaseField: Serialize + DeserializeOwned,
{
}

#[cfg(test)]
mod test {
    use crate::{
        basefold::Basefold,
        test_util::{run_batch_commit_open_verify, run_commit_open_verify},
        util::transcript::PoseidonTranscript,
    };
    use goldilocks::GoldilocksExt2;

    use super::BasefoldDefaultParams;

    type PcsGoldilocks = Basefold<GoldilocksExt2, BasefoldDefaultParams>;

    #[test]
    fn commit_open_verify_goldilocks_base() {
        // Challenge is over extension field, poly over the base field
        run_commit_open_verify::<GoldilocksExt2, PcsGoldilocks, PoseidonTranscript<GoldilocksExt2>>(
            true, 10, 11,
        );
    }

    #[test]
    fn commit_open_verify_goldilocks_2() {
        // Both challenge and poly are over extension field
        run_commit_open_verify::<GoldilocksExt2, PcsGoldilocks, PoseidonTranscript<_>>(
            false, 10, 11,
        );
    }

    #[test]
    fn batch_commit_open_verify_goldilocks_base() {
        // Both challenge and poly are over base field
        run_batch_commit_open_verify::<
            GoldilocksExt2,
            PcsGoldilocks,
            PoseidonTranscript<GoldilocksExt2>,
        >(true, 10, 11);
    }

    #[test]
    fn batch_commit_open_verify_goldilocks_2() {
        // Both challenge and poly are over extension field
        run_batch_commit_open_verify::<GoldilocksExt2, PcsGoldilocks, PoseidonTranscript<_>>(
            false, 10, 11,
        );
    }
}
