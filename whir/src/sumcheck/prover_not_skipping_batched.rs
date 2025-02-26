use ark_ff::Field;
use nimue::{plugins::ark::{FieldChallenges, FieldWriter}, ProofResult};
use nimue_pow::{PoWChallenge, PowStrategy};

use crate::poly_utils::{coeffs::CoefficientList, MultilinearPoint};

use super::prover_batched::SumcheckBatched;

pub struct SumcheckProverNotSkippingBatched<F> {
    sumcheck_prover: SumcheckBatched<F>,
}

impl<F> SumcheckProverNotSkippingBatched<F>
where
    F: Field,
{
    // Get the coefficient of polynomial p and a list of points
    // and initialises the table of the initial polynomial
    // v(X_1, ..., X_n) = p(X_1, ... X_n) * (epsilon_1 eq_z_1(X) + epsilon_2 eq_z_2(X) ...)
    pub fn new(
        coeffs: Vec<CoefficientList<F>>,
        points: &[MultilinearPoint<F>],
        poly_comb_coeff: &[F], // random coefficients for combining each poly
        evals: &[F],
    ) -> Self {
        Self {
            sumcheck_prover: SumcheckBatched::new(
                coeffs,
                points,
                poly_comb_coeff,
                evals,
            ),
        }
    }

    pub fn get_folded_polys(&self) -> Vec<F> {
        self.sumcheck_prover.get_folded_polys()
    }

    pub fn _get_folded_eqs(&self) -> Vec<F> {
        self.sumcheck_prover.get_folded_eqs()
    }

    pub fn compute_sumcheck_polynomials<S, Merlin>(
        &mut self,
        merlin: &mut Merlin,
        folding_factor: usize,
        pow_bits: f64,
    ) -> ProofResult<MultilinearPoint<F>>
    where
        S: PowStrategy,
        Merlin: FieldChallenges<F> + FieldWriter<F> + PoWChallenge,
    {
        let mut res = Vec::with_capacity(folding_factor);

        for _ in 0..folding_factor {
            let sumcheck_poly = self.sumcheck_prover.compute_sumcheck_polynomial();
            merlin.add_scalars(sumcheck_poly.evaluations())?;
            let [folding_randomness]: [F; 1] = merlin.challenge_scalars()?;
            res.push(folding_randomness);

            // Do PoW if needed
            if pow_bits > 0. {
                merlin.challenge_pow::<S>(pow_bits)?;
            }

            self.sumcheck_prover
                .compress(F::ONE, &folding_randomness.into(), &sumcheck_poly);
        }

        res.reverse();
        Ok(MultilinearPoint(res))
    }
}

#[cfg(test)]
mod tests {
    use ark_ff::Field;
    use nimue::{plugins::ark::{FieldChallenges, FieldIOPattern, FieldReader}, IOPattern, Merlin, ProofResult};
    use nimue_pow::blake3::Blake3PoW;

    use crate::{
        crypto::fields::Field64,
        poly_utils::{coeffs::CoefficientList, eq_poly_outside, MultilinearPoint},
        sumcheck::{proof::SumcheckPolynomial, prover_not_skipping_batched::SumcheckProverNotSkippingBatched},
    };

    type F = Field64;

    #[test]
    fn test_e2e_short() -> ProofResult<()> {
        let num_variables = 2;
        let folding_factor = 2;
        let polynomials = vec![
            CoefficientList::new((0..1 << num_variables).map(F::from).collect()),
            CoefficientList::new((1..(1 << num_variables) + 1).map(F::from).collect()),
        ];

        // Initial stuff
        let statement_points = vec![
            MultilinearPoint::expand_from_univariate(F::from(97), num_variables),
            MultilinearPoint::expand_from_univariate(F::from(75), num_variables),
        ];

        // Poly randomness
        let [alpha_1, alpha_2] = [F::from(15), F::from(32)];

        fn add_sumcheck_io_pattern<F>() -> IOPattern
        where
            F: Field,
            IOPattern: FieldIOPattern<F>,
        {
            IOPattern::new("test")
                .add_scalars(3, "sumcheck_poly")
                .challenge_scalars(1, "folding_randomness")
                .add_scalars(3, "sumcheck_poly")
                .challenge_scalars(1, "folding_randomness")
        }

        let iopattern = add_sumcheck_io_pattern::<F>();

        // Prover part
        let mut merlin = iopattern.to_merlin();
        let mut prover = SumcheckProverNotSkippingBatched::new(
            polynomials.clone(),
            &statement_points,
            &[alpha_1, alpha_2],
            &[
                polynomials[0].evaluate_at_extension(&statement_points[0]),
                polynomials[1].evaluate_at_extension(&statement_points[1]),
            ]
        );

        let folding_randomness_1 =
            prover.compute_sumcheck_polynomials::<Blake3PoW, Merlin>(&mut merlin, folding_factor, 0.)?;

        // Compute the answers
        let folded_polys_1: Vec<_> = polynomials.iter().map(|poly| poly.fold(&folding_randomness_1)).collect();

        let statement_answers: Vec<F> = polynomials.iter().zip(&statement_points).map(|(poly, point)|
            poly.evaluate(point)
        ).collect();

        // Verifier part
        let mut arthur = iopattern.to_arthur(merlin.transcript());
        let sumcheck_poly_11: [F; 3] = arthur.next_scalars()?;
        let sumcheck_poly_11 = SumcheckPolynomial::new(sumcheck_poly_11.to_vec(), 1);
        let [folding_randomness_11]: [F; 1] = arthur.challenge_scalars()?;
        let sumcheck_poly_12: [F; 3] = arthur.next_scalars()?;
        let sumcheck_poly_12 = SumcheckPolynomial::new(sumcheck_poly_12.to_vec(), 1);
        let [folding_randomness_12]: [F; 1] = arthur.challenge_scalars()?;

        assert_eq!(
            sumcheck_poly_11.sum_over_hypercube(),
            alpha_1 * statement_answers[0] +
            alpha_2 * statement_answers[1]
        );

        assert_eq!(
            sumcheck_poly_12.sum_over_hypercube(),
            sumcheck_poly_11.evaluate_at_point(&folding_randomness_11.into())
        );

        let full_folding = MultilinearPoint(vec![folding_randomness_12, folding_randomness_11]);

        let eval_coeff = vec![folded_polys_1[0].coeffs()[0], folded_polys_1[1].coeffs()[0]];
        assert_eq!(
            sumcheck_poly_12.evaluate_at_point(&folding_randomness_12.into()),
            eval_coeff[0] * alpha_1
                * eq_poly_outside(&full_folding, &statement_points[0])
            + eval_coeff[1] * alpha_2
                * eq_poly_outside(&full_folding, &statement_points[1])
        );

        Ok(())
    }
}
