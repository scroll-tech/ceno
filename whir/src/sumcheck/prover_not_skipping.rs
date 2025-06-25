use super::prover_single::SumcheckSingle;
use crate::error::Error;
use ff_ext::ExtensionField;
use transcript::Transcript;

pub trait SumcheckNotSkippingIOPattern<E: ExtensionField> {
    fn add_sumcheck(self, folding_factor: usize, pow_bits: f64) -> Self;
}

pub struct SumcheckProverNotSkipping<E: ExtensionField> {
    sumcheck_prover: SumcheckSingle<E>,
}

impl<E: ExtensionField> SumcheckProverNotSkipping<E> {
    // Get the coefficient of polynomial p and a list of points
    // and initialises the table of the initial polynomial
    // v(X_1, ..., X_n) = p(X_1, ... X_n) * (epsilon_1 eq_z_1(X) + epsilon_2 eq_z_2(X) ...)
    pub fn new(
        coeffs: Vec<E>,
        points: &[Vec<E>],
        combination_randomness: &[E],
        evaluations: &[E],
    ) -> Self {
        Self {
            sumcheck_prover: SumcheckSingle::new(
                coeffs,
                points,
                combination_randomness,
                evaluations,
            ),
        }
    }

    pub fn compute_sumcheck_polynomials<T: Transcript<E>>(
        &mut self,
        transcript: &mut T,
        sumcheck_polys: &mut Vec<Vec<E>>,
        folding_factor: usize,
    ) -> Result<Vec<E>, Error> {
        let mut res = Vec::with_capacity(folding_factor);

        for _ in 0..folding_factor {
            let sumcheck_poly = self.sumcheck_prover.compute_sumcheck_polynomial();
            sumcheck_polys.push(sumcheck_poly.evaluations().to_vec());
            transcript.append_field_element_exts(sumcheck_poly.evaluations());
            let folding_randomness = transcript
                .sample_and_append_challenge(b"folding_randomness")
                .elements;
            res.push(folding_randomness);

            self.sumcheck_prover
                .compress(E::ONE, &[folding_randomness], &sumcheck_poly);
        }
        Ok(res)
    }

    pub fn add_new_equality(
        &mut self,
        points: &[Vec<E>],
        combination_randomness: &[E],
        evaluations: &[E],
    ) {
        self.sumcheck_prover
            .add_new_equality(points, combination_randomness, evaluations)
    }
}

#[cfg(test)]
mod tests {
    use core::panic;

    use crate::whir::fold::expand_from_univariate;
    use ff_ext::GoldilocksExt2;
    use multilinear_extensions::{
        mle::{FieldType, MultilinearExtension},
        virtual_poly::eq_eval,
    };
    use p3::{field::FieldAlgebra, util::log2_strict_usize};
    use transcript::{BasicTranscript, Transcript};

    use crate::{
        error::Error,
        sumcheck::{proof::SumcheckPolynomial, prover_not_skipping::SumcheckProverNotSkipping},
    };

    type F = GoldilocksExt2;
    type T = BasicTranscript<F>;

    fn fix_variables(evals: &[F], folding_randomness: &[F]) -> Vec<F> {
        let mut poly = MultilinearExtension::from_evaluations_ext_vec(
            log2_strict_usize(evals.len()),
            evals.to_vec(),
        );
        poly.fix_variables_in_place(folding_randomness);
        match poly.evaluations() {
            FieldType::Ext(poly) => poly.to_vec(),
            _ => panic!("Expected FieldType::Ext"),
        }
    }

    #[test]
    fn test_e2e_short() -> Result<(), Error> {
        let num_variables = 2;
        let folding_factor = 2;
        let polynomial = (0..1 << num_variables)
            .map(F::from_canonical_u64)
            .collect::<Vec<_>>();

        // Initial stuff
        let ood_point = expand_from_univariate(F::from_canonical_u64(42), num_variables);
        let statement_point = expand_from_univariate(F::from_canonical_u64(97), num_variables);

        // All the randomness
        let [epsilon_1, epsilon_2] = [F::from_canonical_u64(15), F::from_canonical_u64(32)];

        // Prover part
        let mut transcript = T::new(b"test");
        let mut prover = SumcheckProverNotSkipping::new(
            polynomial.clone(),
            &[ood_point.clone(), statement_point.clone()],
            &[epsilon_1, epsilon_2],
            &[
                MultilinearExtension::from_evaluations_ext_vec(num_variables, polynomial.clone())
                    .evaluate(&ood_point),
                MultilinearExtension::from_evaluations_ext_vec(num_variables, polynomial.clone())
                    .evaluate(&statement_point),
            ],
        );

        let mut sumcheck_polys = Vec::new();
        let folding_randomness_1 = prover.compute_sumcheck_polynomials(
            &mut transcript,
            &mut sumcheck_polys,
            folding_factor,
        )?;

        // Compute the answers
        let folded_poly_1 = fix_variables(&polynomial, &folding_randomness_1);

        let ood_answer =
            MultilinearExtension::from_evaluations_ext_vec(num_variables, polynomial.clone())
                .evaluate(&ood_point);
        let statement_answer =
            MultilinearExtension::from_evaluations_ext_vec(num_variables, polynomial.clone())
                .evaluate(&statement_point);

        // Verifier part
        let mut transcript = T::new(b"test");
        let mut sumcheck_polys_iter = sumcheck_polys.into_iter();
        let sumcheck_poly_11: Vec<F> = sumcheck_polys_iter.next().unwrap();
        let sumcheck_poly_11 = SumcheckPolynomial::new(sumcheck_poly_11.to_vec(), 1);
        transcript.append_field_element_exts(sumcheck_poly_11.evaluations());
        let folding_randomness_11 = transcript
            .sample_and_append_challenge(b"folding_randomness")
            .elements;
        assert_eq!(folding_randomness_11, folding_randomness_1[0]);
        let sumcheck_poly_12: Vec<F> = sumcheck_polys_iter.next().unwrap();
        let sumcheck_poly_12 = SumcheckPolynomial::new(sumcheck_poly_12.to_vec(), 1);
        transcript.append_field_element_exts(sumcheck_poly_12.evaluations());
        let folding_randomness_12 = transcript
            .sample_and_append_challenge(b"folding_randomness")
            .elements;
        assert_eq!(folding_randomness_12, folding_randomness_1[1]);

        assert_eq!(
            sumcheck_poly_11.sum_over_hypercube(),
            epsilon_1 * ood_answer + epsilon_2 * statement_answer
        );

        assert_eq!(
            sumcheck_poly_12.sum_over_hypercube(),
            sumcheck_poly_11.evaluate_at_point(&[folding_randomness_11])
        );

        let full_folding = vec![folding_randomness_11, folding_randomness_12];

        let eval_coeff = folded_poly_1[0];

        assert_eq!(
            sumcheck_poly_12.evaluate_at_point(&[folding_randomness_12]),
            eval_coeff
                * (epsilon_1 * eq_eval(&full_folding, &ood_point)
                    + epsilon_2 * eq_eval(&full_folding, &statement_point))
        );

        Ok(())
    }

    #[test]
    fn test_e2e() -> Result<(), Error> {
        let num_variables = 4;
        let folding_factor = 2;
        let polynomial = (0..1 << num_variables)
            .map(F::from_canonical_u64)
            .collect::<Vec<_>>();

        // Initial stuff
        let ood_point = expand_from_univariate(F::from_canonical_u64(42), num_variables);
        let statement_point = expand_from_univariate(F::from_canonical_u64(97), num_variables);

        // All the randomness
        let [epsilon_1, epsilon_2] = [F::from_canonical_u64(15), F::from_canonical_u64(32)];
        let fold_point = vec![F::from_canonical_u64(31), F::from_canonical_u64(15)];
        let combination_randomness = vec![F::from_canonical_u64(1000)];

        // Prover part
        let mut transcript = T::new(b"test");
        let mut prover = SumcheckProverNotSkipping::new(
            polynomial.clone(),
            &[ood_point.clone(), statement_point.clone()],
            &[epsilon_1, epsilon_2],
            &[
                MultilinearExtension::from_evaluations_ext_vec(num_variables, polynomial.clone())
                    .evaluate(&ood_point),
                MultilinearExtension::from_evaluations_ext_vec(num_variables, polynomial.clone())
                    .evaluate(&statement_point),
            ],
        );

        let mut sumcheck_polys = Vec::new();
        let folding_randomness_1 = prover.compute_sumcheck_polynomials(
            &mut transcript,
            &mut sumcheck_polys,
            folding_factor,
        )?;

        let folded_poly_1 = fix_variables(&polynomial, &folding_randomness_1);
        let fold_eval = MultilinearExtension::from_evaluations_ext_vec(
            log2_strict_usize(folded_poly_1.len()),
            folded_poly_1,
        )
        .evaluate(&fold_point);
        prover.add_new_equality(&[fold_point.clone()], &combination_randomness, &[fold_eval]);

        let folding_randomness_2 = prover.compute_sumcheck_polynomials::<T>(
            &mut transcript,
            &mut sumcheck_polys,
            folding_factor,
        )?;

        // Compute the answers
        let folded_poly_1 = fix_variables(&polynomial, &folding_randomness_1);
        let folded_poly_2 = fix_variables(&folded_poly_1, &folding_randomness_2);

        let ood_answer =
            MultilinearExtension::from_evaluations_ext_vec(num_variables, polynomial.clone())
                .evaluate(&ood_point);
        let statement_answer =
            MultilinearExtension::from_evaluations_ext_vec(num_variables, polynomial.clone())
                .evaluate(&statement_point);
        let fold_answer = MultilinearExtension::from_evaluations_ext_vec(
            log2_strict_usize(folded_poly_1.len()),
            folded_poly_1,
        )
        .evaluate(&fold_point);

        let mut sumcheck_polys_iter = sumcheck_polys.into_iter();
        // Verifier part
        let mut transcript = T::new(b"test");
        let sumcheck_poly_11: Vec<F> = sumcheck_polys_iter.next().unwrap();
        let sumcheck_poly_11 = SumcheckPolynomial::new(sumcheck_poly_11.to_vec(), 1);
        transcript.append_field_element_exts(sumcheck_poly_11.evaluations());
        let folding_randomness_11 = transcript
            .sample_and_append_challenge(b"folding_randomness")
            .elements;
        assert_eq!(folding_randomness_11, folding_randomness_1[0]);
        let sumcheck_poly_12: Vec<F> = sumcheck_polys_iter.next().unwrap();
        let sumcheck_poly_12 = SumcheckPolynomial::new(sumcheck_poly_12.to_vec(), 1);
        transcript.append_field_element_exts(sumcheck_poly_12.evaluations());
        let folding_randomness_12 = transcript
            .sample_and_append_challenge(b"folding_randomness")
            .elements;
        assert_eq!(folding_randomness_12, folding_randomness_1[1]);
        let sumcheck_poly_21: Vec<F> = sumcheck_polys_iter.next().unwrap();
        let sumcheck_poly_21 = SumcheckPolynomial::new(sumcheck_poly_21.to_vec(), 1);
        transcript.append_field_element_exts(sumcheck_poly_21.evaluations());
        let folding_randomness_21 = transcript
            .sample_and_append_challenge(b"folding_randomness")
            .elements;
        assert_eq!(folding_randomness_21, folding_randomness_2[0]);
        let sumcheck_poly_22: Vec<F> = sumcheck_polys_iter.next().unwrap();
        let sumcheck_poly_22 = SumcheckPolynomial::new(sumcheck_poly_22.to_vec(), 1);
        transcript.append_field_element_exts(sumcheck_poly_22.evaluations());
        let folding_randomness_22 = transcript
            .sample_and_append_challenge(b"folding_randomness")
            .elements;
        assert_eq!(folding_randomness_22, folding_randomness_2[1]);

        assert_eq!(
            sumcheck_poly_11.sum_over_hypercube(),
            epsilon_1 * ood_answer + epsilon_2 * statement_answer
        );

        assert_eq!(
            sumcheck_poly_12.sum_over_hypercube(),
            sumcheck_poly_11.evaluate_at_point(&[folding_randomness_11])
        );

        assert_eq!(
            sumcheck_poly_21.sum_over_hypercube(),
            sumcheck_poly_12.evaluate_at_point(&[folding_randomness_12])
                + combination_randomness[0] * fold_answer
        );

        assert_eq!(
            sumcheck_poly_22.sum_over_hypercube(),
            sumcheck_poly_21.evaluate_at_point(&[folding_randomness_21])
        );

        let full_folding = vec![
            folding_randomness_11,
            folding_randomness_12,
            folding_randomness_21,
            folding_randomness_22,
        ];

        let partial_folding = vec![folding_randomness_21, folding_randomness_22];

        let eval_coeff = folded_poly_2[0];
        assert_eq!(
            sumcheck_poly_22.evaluate_at_point(&[folding_randomness_22]),
            eval_coeff
                * ((epsilon_1 * eq_eval(&full_folding, &ood_point)
                    + epsilon_2 * eq_eval(&full_folding, &statement_point))
                    + combination_randomness[0] * eq_eval(&partial_folding, &fold_point))
        );

        Ok(())
    }
}
