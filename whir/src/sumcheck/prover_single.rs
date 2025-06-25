use super::proof::SumcheckPolynomial;

use ff_ext::ExtensionField;
use p3::util::log2_strict_usize;
#[cfg(feature = "parallel")]
use rayon::{join, prelude::*};

pub struct SumcheckSingle<E: ExtensionField> {
    // The evaluation of p
    evaluation_of_p: Vec<E>,
    evaluation_of_equality: Vec<E>,
    num_variables: usize,
    sum: E,
}

impl<E> SumcheckSingle<E>
where
    E: ExtensionField,
{
    // Get the coefficient of polynomial p and a list of points
    // and initialises the table of the initial polynomial
    // v(X_1, ..., X_n) = p(X_1, ... X_n) * (epsilon_1 eq_z_1(X) + epsilon_2 eq_z_2(X) ...)
    pub fn new(
        evals: Vec<E>,
        points: &[Vec<E>],
        combination_randomness: &[E],
        evaluations: &[E],
    ) -> Self {
        assert_eq!(points.len(), combination_randomness.len());
        assert_eq!(points.len(), evaluations.len());
        let num_variables = log2_strict_usize(evals.len());

        let mut prover = SumcheckSingle {
            evaluation_of_p: evals,
            evaluation_of_equality: vec![E::ZERO; 1 << num_variables],

            num_variables,
            sum: E::ZERO,
        };

        prover.add_new_equality(points, combination_randomness, evaluations);
        prover
    }

    #[cfg(not(feature = "parallel"))]
    pub(crate) fn compute_sumcheck_polynomial(&self) -> SumcheckPolynomial<E> {
        assert!(self.num_variables >= 1);

        // Compute coefficients of the quadratic result polynomial
        let eval_p_iter = self.evaluation_of_p.evals().chunks_exact(2);
        let eval_eq_iter = self.evaluation_of_equality.evals().chunks_exact(2);
        let (c0, c2) = eval_p_iter
            .zip(eval_eq_iter)
            .map(|(p_at, eq_at)| {
                // Convert evaluations to coefficients for the linear fns p and eq.
                let (p_0, p_1) = (p_at[0], p_at[1] - p_at[0]);
                let (eq_0, eq_1) = (eq_at[0], eq_at[1] - eq_at[0]);

                // Now we need to add the contribution of p(x) * eq(x)
                (p_0 * eq_0, p_1 * eq_1)
            })
            .reduce(|(a0, a2), (b0, b2)| (a0 + b0, a2 + b2))
            .unwrap_or((E::ZERO, E::ZERO));

        // Use the fact that self.sum = p(0) + p(1) = 2 * c0 + c1 + c2
        let c1 = self.sum - c0.double() - c2;

        // Evaluate the quadratic polynomial at 0, 1, 2
        let eval_0 = c0;
        let eval_1 = c0 + c1 + c2;
        let eval_2 = eval_1 + c1 + c2 + c2.double();

        SumcheckPolynomial::new(vec![eval_0, eval_1, eval_2], 1)
    }

    #[cfg(feature = "parallel")]
    pub(crate) fn compute_sumcheck_polynomial(&self) -> SumcheckPolynomial<E> {
        assert!(self.num_variables >= 1);

        // Compute coefficients of the quadratic result polynomial
        let eval_p_iter = self.evaluation_of_p.par_chunks_exact(2);
        let eval_eq_iter = self.evaluation_of_equality.par_chunks_exact(2);
        let (c0, c2) = eval_p_iter
            .zip(eval_eq_iter)
            .map(|(p_at, eq_at)| {
                // Convert evaluations to coefficients for the linear fns p and eq.
                let (p_0, p_1) = (p_at[0], p_at[1] - p_at[0]);
                let (eq_0, eq_1) = (eq_at[0], eq_at[1] - eq_at[0]);

                // Now we need to add the contribution of p(x) * eq(x)
                (p_0 * eq_0, p_1 * eq_1)
            })
            .reduce(
                || (E::ZERO, E::ZERO),
                |(a0, a2), (b0, b2)| (a0 + b0, a2 + b2),
            );

        // Use the fact that self.sum = p(0) + p(1) = 2 * coeff_0 + coeff_1 + coeff_2
        let c1 = self.sum - c0.double() - c2;

        // Evaluate the quadratic polynomial at 0, 1, 2
        let eval_0 = c0;
        let eval_1 = c0 + c1 + c2;
        let eval_2 = eval_1 + c1 + c2 + c2.double();

        SumcheckPolynomial::new(vec![eval_0, eval_1, eval_2], 1)
    }

    // Evaluate the eq function on for a given point on the hypercube, and add
    // the result multiplied by the scalar to the output.
    #[cfg(not(feature = "parallel"))]
    pub(crate) fn eval_eq(eval: &[E], out: &mut [E], scalar: E) {
        debug_assert_eq!(out.len(), 1 << eval.len());
        if let Some((&x, tail)) = eval.split_first() {
            let (low, high) = out.split_at_mut(out.len() / 2);
            let s1 = scalar * x;
            let s0 = scalar - s1;
            Self::eval_eq(tail, low, s0);
            Self::eval_eq(tail, high, s1);
        } else {
            out[0] += scalar;
        }
    }

    // Evaluate the eq function on a given point on the hypercube, and add
    // the result multiplied by the scalar to the output.
    #[cfg(feature = "parallel")]
    pub(crate) fn eval_eq(eval: &[E], out: &mut [E], scalar: E) {
        const PARALLEL_THRESHOLD: usize = 10;
        debug_assert_eq!(out.len(), 1 << eval.len());
        if let Some((&x, tail)) = eval.split_last() {
            let (low, high) = out.split_at_mut(out.len() / 2);
            // Update scalars using a single mul. Note that this causes a data dependency,
            // so for small fields it might be better to use two muls.
            // This data dependency should go away once we implement parallel point evaluation.
            let s1 = scalar * x;
            let s0 = scalar - s1;
            if tail.len() > PARALLEL_THRESHOLD {
                join(
                    || Self::eval_eq(tail, low, s0),
                    || Self::eval_eq(tail, high, s1),
                );
            } else {
                Self::eval_eq(tail, low, s0);
                Self::eval_eq(tail, high, s1);
            }
        } else {
            out[0] += scalar;
        }
    }

    pub fn add_new_equality(
        &mut self,
        points: &[Vec<E>],
        combination_randomness: &[E],
        evaluations: &[E],
    ) {
        assert_eq!(combination_randomness.len(), points.len());
        assert_eq!(combination_randomness.len(), evaluations.len());
        for (point, rand) in points.iter().zip(combination_randomness) {
            // TODO: We might want to do all points simultaneously so we
            // do only a single pass over the data.
            Self::eval_eq(point, &mut self.evaluation_of_equality, *rand);
        }

        // Update the sum
        for (rand, eval) in combination_randomness.iter().zip(evaluations.iter()) {
            self.sum += *rand * *eval;
        }
    }

    // When the folding randomness arrives, compress the table accordingly (adding the new points)
    #[cfg(not(feature = "parallel"))]
    pub fn compress(
        &mut self,
        combination_randomness: E, // Scale the initial point
        folding_randomness: &Vec<E>,
        sumcheck_poly: &SumcheckPolynomial<E>,
    ) {
        assert_eq!(folding_randomness.n_variables(), 1);
        assert!(self.num_variables >= 1);

        let randomness = folding_randomness.0[0];
        let evaluations_of_p = self
            .evaluation_of_p
            .evals()
            .chunks_exact(2)
            .map(|at| (at[1] - at[0]) * randomness + at[0])
            .collect();
        let evaluations_of_eq = self
            .evaluation_of_equality
            .evals()
            .chunks_exact(2)
            .map(|at| (at[1] - at[0]) * randomness + at[0])
            .collect();

        // Update
        self.num_variables -= 1;
        self.evaluation_of_p = MultilinearExtension::from_evaluations_ext_vec(evaluations_of_p);
        self.evaluation_of_equality =
            MultilinearExtension::from_evaluations_ext_vec(evaluations_of_eq);
        self.sum = combination_randomness * sumcheck_poly.evaluate_at_point(folding_randomness);
    }

    #[cfg(feature = "parallel")]
    pub fn compress(
        &mut self,
        combination_randomness: E, // Scale the initial point
        folding_randomness: &[E],
        sumcheck_poly: &SumcheckPolynomial<E>,
    ) {
        assert_eq!(folding_randomness.len(), 1);
        assert!(self.num_variables >= 1);

        let randomness = folding_randomness[0];
        let (evaluations_of_p, evaluations_of_eq) = join(
            || {
                self.evaluation_of_p
                    .par_chunks_exact(2)
                    .map(|at| (at[1] - at[0]) * randomness + at[0])
                    .collect()
            },
            || {
                self.evaluation_of_equality
                    .par_chunks_exact(2)
                    .map(|at| (at[1] - at[0]) * randomness + at[0])
                    .collect()
            },
        );

        // Update
        self.num_variables -= 1;
        self.evaluation_of_p = evaluations_of_p;
        self.evaluation_of_equality = evaluations_of_eq;
        self.sum = combination_randomness * sumcheck_poly.evaluate_at_point(folding_randomness);
    }
}

#[cfg(test)]
mod tests {
    use ff_ext::GoldilocksExt2;
    use multilinear_extensions::mle::MultilinearExtension;
    use p3::field::FieldAlgebra;

    use super::SumcheckSingle;

    type E = GoldilocksExt2;

    #[test]
    fn test_sumcheck_folding_factor_1() {
        let eval_point = vec![E::from_canonical_u64(10), E::from_canonical_u64(11)];
        let polynomial = vec![
            E::from_canonical_u64(1),
            E::from_canonical_u64(5),
            E::from_canonical_u64(10),
            E::from_canonical_u64(14),
        ];

        let claimed_value = MultilinearExtension::from_evaluations_ext_vec(2, polynomial.clone())
            .evaluate(&eval_point);

        let eval = MultilinearExtension::from_evaluations_ext_vec(2, polynomial.clone())
            .evaluate(&eval_point);
        let mut prover = SumcheckSingle::new(
            polynomial,
            &[eval_point],
            &[E::from_canonical_u64(1)],
            &[eval],
        );

        let poly_1 = prover.compute_sumcheck_polynomial();

        // First, check that is sums to the right value over the hypercube
        assert_eq!(poly_1.sum_over_hypercube(), claimed_value);

        let combination_randomness = E::from_canonical_u64(100101);
        let folding_randomness = vec![E::from_canonical_u64(4999)];

        prover.compress(combination_randomness, &folding_randomness, &poly_1);

        let poly_2 = prover.compute_sumcheck_polynomial();

        assert_eq!(
            poly_2.sum_over_hypercube(),
            combination_randomness * poly_1.evaluate_at_point(&folding_randomness)
        );
    }
}
