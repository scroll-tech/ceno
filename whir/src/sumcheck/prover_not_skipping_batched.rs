use ff_ext::ExtensionField;
use transcript::Transcript;

use crate::error::Error;

use super::prover_batched::SumcheckBatched;

pub struct SumcheckProverNotSkippingBatched<E: ExtensionField> {
    sumcheck_prover: SumcheckBatched<E>,
}

impl<E: ExtensionField> SumcheckProverNotSkippingBatched<E> {
    // Get the coefficient of polynomial p and a list of points
    // and initialises the table of the initial polynomial
    // v(X_1, ..., X_n) = p(X_1, ... X_n) * (epsilon_1 eq_z_1(X) + epsilon_2 eq_z_2(X) ...)
    pub fn new(
        coeffs: Vec<Vec<E>>,
        points: &[Vec<E>],
        poly_comb_coeff: &[E], // random coefficients for combining each poly
        evals: &[E],
    ) -> Self {
        Self {
            sumcheck_prover: SumcheckBatched::new(coeffs, points, poly_comb_coeff, evals),
        }
    }

    pub fn get_folded_polys(&self) -> Vec<E> {
        self.sumcheck_prover.get_folded_polys()
    }

    pub fn _get_folded_eqs(&self) -> Vec<E> {
        self.sumcheck_prover.get_folded_eqs()
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
}

#[cfg(test)]
mod tests {
    use ff_ext::GoldilocksExt2;
    use multilinear_extensions::{
        mle::{FieldType, MultilinearExtension},
        virtual_poly::eq_eval,
    };
    use p3::{field::FieldAlgebra, util::log2_strict_usize};
    use transcript::{BasicTranscript, Transcript};

    use crate::{
        error::Error,
        sumcheck::{
            proof::SumcheckPolynomial,
            prover_not_skipping_batched::SumcheckProverNotSkippingBatched,
        },
        whir::fold::expand_from_univariate,
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
        let polynomials = vec![
            (0..1 << num_variables).map(F::from_canonical_u64).collect(),
            (1..(1 << num_variables) + 1)
                .map(F::from_canonical_u64)
                .collect(),
        ];

        // Initial stuff
        let statement_points = vec![
            expand_from_univariate(F::from_canonical_u64(97), num_variables),
            expand_from_univariate(F::from_canonical_u64(75), num_variables),
        ];

        // Poly randomness
        let [alpha_1, alpha_2] = [F::from_canonical_u64(15), F::from_canonical_u64(32)];

        // Prover part
        let mut transcript = T::new(b"test");
        let mut prover = SumcheckProverNotSkippingBatched::new(
            polynomials.clone(),
            &statement_points,
            &[alpha_1, alpha_2],
            &[
                MultilinearExtension::from_evaluations_ext_vec(
                    num_variables,
                    polynomials[0].clone(),
                )
                .evaluate(&statement_points[0]),
                MultilinearExtension::from_evaluations_ext_vec(
                    num_variables,
                    polynomials[1].clone(),
                )
                .evaluate(&statement_points[1]),
            ],
        );
        let mut sumcheck_polys = Vec::new();

        let folding_randomness_1 = prover.compute_sumcheck_polynomials(
            &mut transcript,
            &mut sumcheck_polys,
            folding_factor,
        )?;

        // Compute the answers
        let folded_polys_1: Vec<_> = polynomials
            .iter()
            .map(|poly| fix_variables(poly, &folding_randomness_1))
            .collect();

        let statement_answers: Vec<F> = polynomials
            .iter()
            .zip(&statement_points)
            .map(|(poly, point)| {
                MultilinearExtension::from_evaluations_ext_vec(num_variables, poly.clone())
                    .evaluate(point)
            })
            .collect();

        // Verifier part
        let mut sumcheck_polys_iter = sumcheck_polys.into_iter();
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

        assert_eq!(
            sumcheck_poly_11.sum_over_hypercube(),
            alpha_1 * statement_answers[0] + alpha_2 * statement_answers[1]
        );

        assert_eq!(
            sumcheck_poly_12.sum_over_hypercube(),
            sumcheck_poly_11.evaluate_at_point(&[folding_randomness_11])
        );

        let full_folding = vec![folding_randomness_11, folding_randomness_12];

        let eval_coeff = [folded_polys_1[0][0], folded_polys_1[1][0]];

        assert_eq!(
            sumcheck_poly_12.evaluate_at_point(&[folding_randomness_12]),
            eval_coeff[0] * alpha_1 * eq_eval(&full_folding, &statement_points[0])
                + eval_coeff[1] * alpha_2 * eq_eval(&full_folding, &statement_points[1])
        );

        Ok(())
    }
}
