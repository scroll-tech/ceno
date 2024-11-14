use crate::{
    Error, Evaluation,
    basefold::{
        SumCheck,
        commit_phase::batch_commit_phase,
        inner_product_three,
        query_phase::{BatchedQueriesResultWithMerklePath, batch_prover_query_phase},
        structure::{BasefoldProof, ProofQueriesResultWithMerklePath},
    },
    sum_check::{SumCheck as _, VirtualPolynomial, eq_xy_eval},
    util::{
        add_polynomial_with_coeff,
        arithmetic::inner_product,
        expression::{Expression, Query, Rotation},
        field_type_to_ext_vec, log2_strict, multiply_poly, poly_index_ext, poly_iter_ext,
    },
    validate_input,
};
use ark_std::{end_timer, start_timer};
use ff_ext::ExtensionField;
use itertools::Itertools;
use multilinear_extensions::{
    mle::{DenseMultilinearExtension, MultilinearExtension},
    virtual_poly::build_eq_x_r_vec,
    virtual_poly_v2::ArcMultilinearExtension,
};
use serde::{Serialize, de::DeserializeOwned};
use transcript::Transcript;

use super::{Basefold, BasefoldCommitmentWithData, BasefoldProverParams, BasefoldSpec};
impl<E: ExtensionField, Spec: BasefoldSpec<E>> Basefold<E, Spec>
where
    E: Serialize + DeserializeOwned,
    E::BaseField: Serialize + DeserializeOwned,
{
    pub(crate) fn batch_vlmp_open(
        pp: &BasefoldProverParams<E, Spec>,
        polys: &[ArcMultilinearExtension<E>],
        comms: &[BasefoldCommitmentWithData<E>],
        points: &[Vec<E>],
        evals: &[Evaluation<E>],
        transcript: &mut Transcript<E>,
    ) -> Result<BasefoldProof<E>, Error> {
        let timer = start_timer!(|| "Basefold::batch_open");
        let num_vars = polys.iter().map(|poly| poly.num_vars()).max().unwrap();
        let min_num_vars = polys.iter().map(|p| p.num_vars()).min().unwrap();
        assert!(min_num_vars >= Spec::get_basecode_msg_size_log());

        comms.iter().for_each(|comm| {
            assert!(comm.num_polys == 1);
            assert!(!comm.is_trivial::<Spec>());
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
        let t = (0..batch_size_log)
            .map(|_| {
                transcript
                    .get_and_append_challenge(b"batch coeffs")
                    .elements
            })
            .collect::<Vec<_>>();

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
            vec![(E::ONE, Vec::<E>::new()); points.len()],
            |mut merged_polys, (eval, eq_xt_i)| {
                // For each polynomial to open, eval.point() specifies which point it is to be opened at.
                if merged_polys[eval.point()].1.is_empty() {
                    // If the accumulator for this point is still the zero polynomial,
                    // directly assign the random coefficient and the polynomial to open to
                    // this accumulator
                    merged_polys[eval.point()] = (
                        eq_xt_i,
                        field_type_to_ext_vec(polys[eval.poly()].evaluations()),
                    );
                } else {
                    // If the accumulator is unempty now, first force its scalar to 1, i.e.,
                    // make (scalar, polynomial) to (1, scalar * polynomial)
                    let coeff = merged_polys[eval.point()].0;
                    if coeff != E::ONE {
                        merged_polys[eval.point()].0 = E::ONE;
                        multiply_poly(&mut merged_polys[eval.point()].1, &coeff);
                    }
                    // Equivalent to merged_poly += poly * batch_coeff. Note that
                    // add_assign_mixed_with_coeff allows adding two polynomials with
                    // different variables, and the result has the same number of vars
                    // with the larger one of the two added polynomials.
                    add_polynomial_with_coeff(
                        &mut merged_polys[eval.point()].1,
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
                    inner_product(poly, build_eq_x_r_vec(point).iter())
                        * scalar
                        * E::from(1 << (num_vars - log2_strict(poly.len())))
                    // When this polynomial is smaller, it will be repeatedly summed over the cosets of the hypercube
                })
                .sum::<E>();
            assert_eq!(expected_sum, target_sum);

            merged_polys.iter().enumerate().for_each(|(i, (_, poly))| {
                assert_eq!(points[i].len(), log2_strict(poly.len()));
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
        let sumcheck_polys: Vec<DenseMultilinearExtension<E>> = merged_polys
            .iter()
            .map(|(_, poly)| {
                DenseMultilinearExtension::from_evaluations_ext_vec(
                    log2_strict(poly.len()),
                    poly.clone(),
                )
            })
            .collect_vec();
        let virtual_poly =
            VirtualPolynomial::new(&expression, sumcheck_polys.iter(), &[], points.as_slice());

        let (challenges, merged_poly_evals, sumcheck_proof) =
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
                .map(|poly| poly.evaluate(&challenges[..poly.num_vars()]))
                .collect_vec();
            let new_target_sum = inner_product(&poly_evals, &coeffs);
            let desired_sum = merged_polys
                .iter()
                .zip(points)
                .zip(merged_poly_evals)
                .map(|(((scalar, poly), point), evals_from_sum_check)| {
                    assert_eq!(
                        evals_from_sum_check,
                        DenseMultilinearExtension::from_evaluations_ext_vec(
                            log2_strict(poly.len()),
                            poly.clone()
                        )
                        .evaluate(&challenges[..log2_strict(poly.len())])
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

        let (trees, commit_phase_proof) = batch_commit_phase::<E, Spec>(
            &pp.encoding_params,
            &point,
            comms,
            transcript,
            num_vars,
            num_vars - Spec::get_basecode_msg_size_log(),
            coeffs.as_slice(),
        );

        let query_timer = start_timer!(|| "Basefold::batch_open query phase");
        let query_result = batch_prover_query_phase(
            transcript,
            1 << (num_vars + Spec::get_rate_log()),
            comms,
            &trees,
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
        end_timer!(timer);

        Ok(BasefoldProof {
            sumcheck_messages: commit_phase_proof.sumcheck_messages,
            roots: commit_phase_proof.roots,
            final_message: commit_phase_proof.final_message,
            query_result_with_merkle_path: ProofQueriesResultWithMerklePath::Batched(
                query_result_with_merkle_path,
            ),
            sumcheck_proof: Some(sumcheck_proof),
            trivial_proof: vec![],
        })
    }
}
