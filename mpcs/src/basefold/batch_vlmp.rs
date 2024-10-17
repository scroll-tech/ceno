use ark_std::{end_timer, start_timer};
use ff_ext::ExtensionField;
use itertools::Itertools;
use multilinear_extensions::{
    mle::{DenseMultilinearExtension, MultilinearExtension},
    virtual_poly::build_eq_x_r_vec,
    virtual_poly_v2::ArcMultilinearExtension,
};
use rayon::iter::{IndexedParallelIterator, IntoParallelRefMutIterator, ParallelIterator};
use serde::{de::DeserializeOwned, Serialize};
use transcript::Transcript;

use crate::{
    basefold::CommitPhaseInput,
    sum_check::{eq_xy_eval, SumCheck as _, VirtualPolynomial},
    util::{
        add_polynomial_with_coeff,
        arithmetic::inner_product,
        expression::{Expression, Query, Rotation},
        field_type_index_ext, field_type_to_ext_vec, log2_strict, multiply_poly, poly_index_ext,
        poly_iter_ext,
    },
    Error, Evaluation,
};

use super::{
    commit_phase::CommitPhaseStrategy, inner_product_three, query_phase::QueryCheckStrategy,
    structure::BasefoldProof, BasefoldCommitment, BasefoldCommitmentWithData, BasefoldProverParams,
    BasefoldSpec, BasefoldStrategy, BasefoldVerifierParams, SumCheck,
};

pub(crate) struct ProverInputs<'a, E: ExtensionField, Spec: BasefoldSpec<E>>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    pub(crate) polys: &'a [ArcMultilinearExtension<'a, E>],
    pub(crate) comms: &'a [BasefoldCommitmentWithData<E, Spec>],
    pub(crate) points: &'a [&'a [E]],
    pub(crate) evals: &'a [Evaluation<E>],
}

impl<'a, E: ExtensionField, Spec: BasefoldSpec<E>> super::ProverInputs<E, Spec>
    for ProverInputs<'a, E, Spec>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    fn comms(&self) -> &[BasefoldCommitmentWithData<E, Spec>] {
        self.comms
    }
}

pub(crate) struct VerifierInputs<'a, E: ExtensionField, Spec: BasefoldSpec<E>>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    pub(crate) comms: &'a [BasefoldCommitment<E, Spec>],
    pub(crate) points: &'a [&'a [E]],
    pub(crate) num_vars: usize,
    pub(crate) evals: &'a [Evaluation<E>],
}

impl<'a, E: ExtensionField, Spec: BasefoldSpec<E>> super::VerifierInputs<E, Spec>
    for VerifierInputs<'a, E, Spec>
where
    E::BaseField: Serialize + DeserializeOwned,
{
    fn comms(&self) -> &[BasefoldCommitment<E, Spec>] {
        self.comms
    }

    fn num_vars(&self) -> usize {
        self.num_vars
    }
}

pub(crate) struct BatchVLMPBasefoldStrategy;
impl<E: ExtensionField, Spec: BasefoldSpec<E>> BasefoldStrategy<E, Spec>
    for BatchVLMPBasefoldStrategy
where
    E::BaseField: Serialize + DeserializeOwned,
{
    type CommitPhaseStrategy = BatchVLMPCommitPhaseStrategy;
    type QueryCheckStrategy = BatchVLMPQueryCheckStrategy;
    type ProverInputs<'a> = ProverInputs<'a, E, Spec> where Spec: 'a;
    type VerifierInputs<'a> = VerifierInputs<'a, E, Spec> where Spec: 'a;

    fn trivial_proof(prover_inputs: &ProverInputs<'_, E, Spec>) -> Option<BasefoldProof<E, Spec>> {
        // The encoded polynomial should at least have the number of
        // variables of the basecode, i.e., the size of the message
        // when the protocol stops. If the polynomial is smaller
        // the protocol won't work, and saves no verifier work anyway.
        // In the current implementation, the batch vlmp case simply
        // ignores this case and crashes on trivial proof.
        prover_inputs.comms.iter().for_each(|comm| {
            assert!(!comm.is_trivial());
        });
        None
    }

    fn prepare_commit_phase_input(
        pp: &BasefoldProverParams<E, Spec>,
        prover_inputs: &ProverInputs<'_, E, Spec>,
        transcript: &mut Transcript<E>,
    ) -> Result<CommitPhaseInput<E>, Error> {
        let comms = prover_inputs.comms;
        let polys = prover_inputs.polys;
        let num_vars = polys.iter().map(|poly| poly.num_vars()).max().unwrap();
        let min_num_vars = polys.iter().map(|p| p.num_vars()).min().unwrap();
        assert!(min_num_vars >= Spec::get_basecode_msg_size_log());

        comms.iter().for_each(|comm| {
            assert!(comm.num_polys == 1);
            assert!(!comm.is_trivial());
        });

        validate_input(
            "batch open",
            pp.get_max_message_size_log(),
            polys,
            prover_inputs.points,
        )?;

        let sumcheck_timer = start_timer!(|| "Basefold::batch_open::initial sumcheck");

        let batch_size_log = polys.len().next_power_of_two().ilog2() as usize;
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

        // Merge the polynomials for every point. One merged polynomial for each point.
        let merged_polys = prover_inputs.evals.iter().zip(poly_iter_ext(&eq_xt)).fold(
            // This folding will generate a vector of |points| pairs of (scalar, polynomial)
            // The polynomials are initialized to zero, and the scalars are initialized to one
            vec![(E::ONE, Vec::<E>::new()); prover_inputs.points.len()],
            |mut merged_polys, (eval, eq_xt_i)| {
                // For each polynomial to open, eval.point() specifies which point it is to be opened at.
                if merged_polys[eval.point()].1.is_empty() {
                    // If the accumulator for this point is still the zero polynomial,
                    // directly assign the random coefficient and the polynomial to open to
                    // this accumulator
                    merged_polys[eval.point()] = (
                        eq_xt_i,
                        field_type_to_ext_vec(prover_inputs.polys[eval.poly()].evaluations()),
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

        let target_sum = merged_polys
            .iter()
            .zip(prover_inputs.points.iter())
            .map(|((scalar, poly), point)| {
                inner_product(poly, build_eq_x_r_vec(point).iter())
                    * scalar
                    * E::from(1 << (num_vars - log2_strict(poly.len())))
                // When this polynomial is smaller, it will be repeatedly summed over the cosets of the hypercube
            })
            .sum::<E>();

        if cfg!(feature = "sanity-check") {
            let expected_sum = inner_product_three(
                prover_inputs.evals.iter().map(Evaluation::value),
                &prover_inputs
                    .evals
                    .iter()
                    .map(|eval| E::from(1 << (num_vars - prover_inputs.points[eval.point()].len())))
                    .collect_vec(),
                &poly_iter_ext(&eq_xt)
                    .take(prover_inputs.evals.len())
                    .collect_vec(),
            );
            assert_eq!(target_sum, expected_sum);
            merged_polys.iter().enumerate().for_each(|(i, (_, poly))| {
                assert_eq!(prover_inputs.points[i].len(), log2_strict(poly.len()));
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
        let ys = prover_inputs
            .points
            .iter()
            .map(|point| point.to_vec())
            .collect::<Vec<_>>();
        let virtual_poly =
            VirtualPolynomial::new(&expression, sumcheck_polys.iter(), &[], ys.as_slice());

        let (challenges, merged_poly_evals, sumcheck_proof) =
            SumCheck::prove(&(), num_vars, virtual_poly, target_sum, transcript)?;

        end_timer!(sumcheck_timer);

        // Now the verifier has obtained the new target sum, and is able to compute the random
        // linear coefficients, and is able to evaluate eq_xy(point) for each poly to open.
        // The remaining tasks for the prover is to prove that
        // sum_i coeffs[i] poly_evals[i] is equal to
        // the new target sum, where coeffs is computed as follows
        let eq_xy_evals = prover_inputs
            .points
            .iter()
            .map(|point| eq_xy_eval(&challenges[..point.len()], point))
            .collect_vec();
        let mut coeffs = vec![E::ZERO; comms.len()];
        prover_inputs
            .evals
            .iter()
            .enumerate()
            .for_each(|(i, eval)| {
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
                .zip(prover_inputs.points)
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
                    *scalar * evals_from_sum_check * eq_xy_eval(point, &challenges[0..point.len()])
                })
                .sum::<E>();
            assert_eq!(new_target_sum, desired_sum);
        }
        // Note that the verifier can also compute these coeffs locally, so no need to pass
        // them to the transcript.

        let point = challenges;

        Ok(CommitPhaseInput {
            point: point.to_vec(),
            coeffs_outer: coeffs,
            coeffs_inner: vec![],
            sumcheck_proof: Some(sumcheck_proof),
        })
    }

    fn check_trivial_proof(
        _verifier_inputs: &VerifierInputs<'_, E, Spec>,
        proof: &BasefoldProof<E, Spec>,
        _transcript: &mut Transcript<E>,
    ) -> Result<(), Error> {
        assert!(!proof.is_trivial());

        Ok(())
    }

    fn check_sizes(verifier_inputs: &VerifierInputs<'_, E, Spec>) {
        let comms = verifier_inputs.comms;
        let poly_num_vars = comms.iter().map(|c| c.num_vars().unwrap()).collect_vec();
        verifier_inputs.evals.iter().for_each(|eval| {
            assert_eq!(
                verifier_inputs.points[eval.point()].len(),
                comms[eval.poly()].num_vars().unwrap()
            );
        });
        assert!(poly_num_vars.iter().min().unwrap() >= &Spec::get_basecode_msg_size_log());
    }

    fn prepare_sumcheck_target_and_point_batching_coeffs(
        _vp: &BasefoldVerifierParams<E, Spec>,
        verifier_inputs: &VerifierInputs<'_, E, Spec>,
        proof: &BasefoldProof<E, Spec>,
        transcript: &mut Transcript<E>,
    ) -> Result<(E, Vec<E>, Vec<E>, Vec<E>), Error> {
        let sumcheck_timer = start_timer!(|| "Basefold::batch_verify::initial sumcheck");
        let batch_size_log = verifier_inputs.evals.len().next_power_of_two().ilog2() as usize;
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
            verifier_inputs.evals.iter().map(Evaluation::value),
            &verifier_inputs
                .evals
                .iter()
                .map(|eval| {
                    E::from(
                        1 << (verifier_inputs.num_vars
                            - verifier_inputs.points[eval.point()].len()),
                    )
                })
                .collect_vec(),
            &poly_iter_ext(&eq_xt)
                .take(verifier_inputs.evals.len())
                .collect_vec(),
        );

        let (new_target_sum, verify_point) = SumCheck::verify(
            &(),
            verifier_inputs.num_vars,
            2,
            target_sum,
            proof.sumcheck_proof.as_ref().unwrap(),
            transcript,
        )?;
        end_timer!(sumcheck_timer);

        // Now the goal is to use the BaseFold to check the new target sum. Note that this time
        // we only have one eq polynomial in the sum-check.
        let eq_xy_evals = verifier_inputs
            .points
            .iter()
            .map(|point| eq_xy_eval(&verify_point[..point.len()], point))
            .collect_vec();
        let mut coeffs = vec![E::ZERO; verifier_inputs.comms.len()];
        verifier_inputs
            .evals
            .iter()
            .enumerate()
            .for_each(|(i, eval)| {
                coeffs[eval.poly()] += eq_xy_evals[eval.point()] * poly_index_ext(&eq_xt, i)
            });
        Ok((new_target_sum, verify_point, coeffs, vec![]))
    }
}

pub(crate) struct BatchVLMPCommitPhaseStrategy;
impl<E: ExtensionField> CommitPhaseStrategy<E> for BatchVLMPCommitPhaseStrategy
where
    E::BaseField: Serialize + DeserializeOwned,
{
    fn initial_running_oracle<Spec: BasefoldSpec<E>>(
        comms: &[BasefoldCommitmentWithData<E, Spec>],
        _coeffs_outer: &[E],
        _coeffs_inner: &[E],
    ) -> Vec<E> {
        // Initialize to zero oracle, and before each folding. All the
        // committed polynomial values are added to the oracle in the matching
        // round.
        let codeword_size = comms.iter().map(|comm| comm.codeword_size()).max().unwrap();
        vec![E::ZERO; codeword_size]
    }

    fn initial_running_evals<Spec: BasefoldSpec<E>>(
        comms: &[BasefoldCommitmentWithData<E, Spec>],
        coeffs_outer: &[E],
        _coeffs_inner: &[E],
    ) -> Vec<E> {
        let num_vars = comms.iter().map(|comm| comm.num_vars).max().unwrap();
        let build_evals_timer = start_timer!(|| "Basefold build initial sumcheck evals");
        // Unlike the FRI part, the sum-check part still follows the original procedure,
        // and linearly combine all the polynomials once for all
        let mut sum_of_all_evals_for_sumcheck = vec![E::ZERO; 1 << num_vars];
        comms.iter().enumerate().for_each(|(index, comm)| {
            sum_of_all_evals_for_sumcheck
                .par_iter_mut()
                .enumerate()
                .for_each(|(pos, r)| {
                    // Evaluating the multilinear polynomial outside of its interpolation hypercube
                    // is equivalent to repeating each element in place.
                    // Here is the tricky part: the bh_evals are stored in big endian, but we want
                    // to align the polynomials to the variable with index 0 before adding them
                    // together. So each element is repeated by
                    // sum_of_all_evals_for_sumcheck.len() / bh_evals.len() times
                    *r += field_type_index_ext(
                        &comm.polynomials_bh_evals[0],
                        pos >> (num_vars - log2_strict(comm.polynomials_bh_evals[0].len())),
                    ) * coeffs_outer[index]
                });
        });
        end_timer!(build_evals_timer);
        sum_of_all_evals_for_sumcheck
    }

    fn update_running_oracle<Spec: BasefoldSpec<E>>(
        comms: &[BasefoldCommitmentWithData<E, Spec>],
        running_oracle_len: usize,
        index: usize,
        coeffs_outer: &[E],
        _coeffs_inner: &[E],
    ) -> E {
        comms
            .iter()
            .enumerate()
            .filter(|(_, comm)| comm.codeword_size() == running_oracle_len)
            .map(|(i, comm)| {
                field_type_index_ext(&comm.get_codewords()[0], index) * coeffs_outer[i]
            })
            .sum()
    }
}

pub(crate) struct BatchVLMPQueryCheckStrategy;
impl<E: ExtensionField, Spec: BasefoldSpec<E>> QueryCheckStrategy<E, Spec>
    for BatchVLMPQueryCheckStrategy
where
    E::BaseField: Serialize + DeserializeOwned,
{
    fn initial_values(
        _query_result: &super::query_phase::BasefoldQueryResult<E, Spec>,
        _coeffs_outer: &[E],
        _coeffs_inner: &[E],
    ) -> Vec<E> {
        // Initialize the current values to zero, and before each round
        // add the matching commitments to the current values
        vec![E::ZERO, E::ZERO]
    }

    fn pre_update_values(
        query_result: &super::query_phase::BasefoldQueryResult<E, Spec>,
        coeffs_outer: &[E],
        _coeffs_inner: &[E],
        codeword_size_log: usize,
    ) -> Option<Vec<E>> {
        let matching_pairs =
            query_result.get_commitments_query_matching_size_log(codeword_size_log);

        if matching_pairs.is_empty() {
            return None;
        }

        let (left, right) = matching_pairs
            .iter()
            .map(|(index, pair)| {
                let pair = pair.as_ext();
                assert_eq!(pair.len(), 1);
                let pair = pair[0];
                (pair.0 * coeffs_outer[*index], pair.1 * coeffs_outer[*index])
            })
            .fold((E::ZERO, E::ZERO), |(s, t), (a, b)| (s + a, t + b));
        Some(vec![left, right])
    }

    fn has_update_value_at_first_round() -> bool {
        true
    }
}

fn validate_input<E: ExtensionField>(
    function: &str,
    param_num_vars: usize,
    polys: &[ArcMultilinearExtension<E>],
    points: &[&[E]],
) -> Result<(), Error> {
    let polys = polys.iter().collect_vec();
    let points = points.iter().collect_vec();
    for poly in polys.iter() {
        if param_num_vars < poly.num_vars() {
            return Err(err_too_many_variates(
                function,
                param_num_vars,
                poly.num_vars(),
            ));
        }
    }
    for point in points.iter() {
        if param_num_vars < point.len() {
            return Err(err_too_many_variates(function, param_num_vars, point.len()));
        }
    }
    Ok(())
}

fn err_too_many_variates(function: &str, upto: usize, got: usize) -> Error {
    Error::InvalidPcsParam(if function == "trim" {
        format!(
            "Too many variates to {function} (param supports variates up to {upto} but got {got})"
        )
    } else {
        format!(
            "Too many variates of poly to {function} (param supports variates up to {upto} but got {got})"
        )
    })
}
