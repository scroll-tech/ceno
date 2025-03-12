use ff_ext::ExtensionField;
use multilinear_extensions::mle::DenseMultilinearExtension;
use nimue_pow::PoWChallenge;
use p3_field::Field;
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
        coeffs: Vec<DenseMultilinearExtension<E>>,
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

    pub fn compute_sumcheck_polynomials<T: Transcript>(
        &mut self,
        transcript: &mut T,
        folding_factor: usize,
        pow_bits: f64,
    ) -> Result<Vec<E>, Error> {
        let mut res = Vec::with_capacity(folding_factor);

        for _ in 0..folding_factor {
            let sumcheck_poly = self.sumcheck_prover.compute_sumcheck_polynomial();
            transcript.append_field_element_ext(sumcheck_poly.evaluations())?;
            let [folding_randomness]: [F; 1] = transcript.challenge_scalars()?;
            res.push(folding_randomness);

            self.sumcheck_prover
                .compress(F::ONE, &folding_randomness.into(), &sumcheck_poly);
        }

        res.reverse();
        Ok(res)
    }
}

#[cfg(test)]
mod tests {
    use goldilocks::Goldilocks;
    use multilinear_extensions::{mle::DenseMultilinearExtension, virtual_poly::eq_eval};
    use nimue::{
        Result,
        plugins::ark::{FieldChallenges, FieldIOPattern, FieldReader},
    };
    use nimue_pow::blake3::Blake3PoW;
    use transcript::Transcript;

    use crate::sumcheck::{
        proof::SumcheckPolynomial, prover_not_skipping_batched::SumcheckProverNotSkippingBatched,
    };

    type F = Goldilocks;

    #[test]
    fn test_e2e_short() -> Result<()> {
        let num_variables = 2;
        let folding_factor = 2;
        let polynomials = vec![
            DenseMultilinearExtension::new((0..1 << num_variables).map(F::from).collect()),
            DenseMultilinearExtension::new((1..(1 << num_variables) + 1).map(F::from).collect()),
        ];

        // Initial stuff
        let statement_points = vec![
            expand_from_univariate(F::from(97), num_variables),
            expand_from_univariate(F::from(75), num_variables),
        ];

        // Poly randomness
        let [alpha_1, alpha_2] = [F::from(15), F::from(32)];

        // Prover part
        let mut transcript = Transcript::new();
        let mut prover = SumcheckProverNotSkippingBatched::new(
            polynomials.clone(),
            &statement_points,
            &[alpha_1, alpha_2],
            &[
                polynomials[0].evaluate_at_extension(&statement_points[0]),
                polynomials[1].evaluate_at_extension(&statement_points[1]),
            ],
        );

        let folding_randomness_1 = prover.compute_sumcheck_polynomials::<Blake3PoW>(
            &mut transcript,
            folding_factor,
            0.,
        )?;

        // Compute the answers
        let folded_polys_1: Vec<_> = polynomials
            .iter()
            .map(|poly| poly.fold(&folding_randomness_1))
            .collect();

        let statement_answers: Vec<F> = polynomials
            .iter()
            .zip(&statement_points)
            .map(|(poly, point)| poly.evaluate(point))
            .collect();

        // Verifier part
        let mut transcript = Transcript::new();
        let sumcheck_poly_11: [F; 3] = transcript.next_scalars()?;
        let sumcheck_poly_11 = SumcheckPolynomial::new(sumcheck_poly_11.to_vec(), 1);
        let [folding_randomness_11]: [F; 1] = transcript.challenge_scalars()?;
        let sumcheck_poly_12: [F; 3] = transcript.next_scalars()?;
        let sumcheck_poly_12 = SumcheckPolynomial::new(sumcheck_poly_12.to_vec(), 1);
        let [folding_randomness_12]: [F; 1] = transcript.challenge_scalars()?;

        assert_eq!(
            sumcheck_poly_11.sum_over_hypercube(),
            alpha_1 * statement_answers[0] + alpha_2 * statement_answers[1]
        );

        assert_eq!(
            sumcheck_poly_12.sum_over_hypercube(),
            sumcheck_poly_11.evaluate_at_point(&folding_randomness_11.into())
        );

        let full_folding = vec![folding_randomness_12, folding_randomness_11];

        let eval_coeff = [folded_polys_1[0].coeffs()[0], folded_polys_1[1].coeffs()[0]];
        assert_eq!(
            sumcheck_poly_12.evaluate_at_point(&folding_randomness_12.into()),
            eval_coeff[0] * alpha_1 * eq_eval(&full_folding, &statement_points[0])
                + eval_coeff[1] * alpha_2 * eq_eval(&full_folding, &statement_points[1])
        );

        Ok(())
    }
}
