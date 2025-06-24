use ff_ext::ExtensionField;
use multilinear_extensions::mle::{FieldType, MultilinearExtension};

use crate::{utils::base_decomposition, whir::fold::LagrangePolynomialIterator};

use super::proof::SumcheckPolynomial;

pub struct SumcheckCore<F: ExtensionField> {
    // The evaluation of p
    evaluation_of_p: Vec<F>,
    evaluation_of_equality: Vec<F>,
    num_variables: usize,
}

impl<F: ExtensionField> SumcheckCore<F> {
    // Get the coefficient of polynomial p and a list of points
    // and initialises the table of the initial polynomial
    // v(X_1, ..., X_n) = p(X_1, ... X_n) * (epsilon_1 eq_z_1(X) + epsilon_2 eq_z_2(X) ...)
    pub fn new(
        coeffs: MultilinearExtension<F>, // multilinear polynomial in n variables
        points: &[Vec<F>],               // list of points, each of length n.
        combination_randomness: &[F],
    ) -> Self {
        assert_eq!(points.len(), combination_randomness.len());
        let num_variables = coeffs.num_vars();

        let mut prover = SumcheckCore {
            evaluation_of_p: match coeffs.evaluations() {
                FieldType::Base(evals) => evals
                    .iter()
                    .map(|e| F::from_ref_base(e))
                    .collect::<Vec<_>>(),
                FieldType::Ext(evals) => evals.to_vec(),
                _ => panic!("Invalid field type"),
            }, // transform coefficient form -> evaluation form
            evaluation_of_equality: vec![F::ZERO; 1 << num_variables],

            num_variables,
        };

        prover.add_new_equality(points, combination_randomness);
        prover
    }

    pub fn compute_sumcheck_polynomial(&self, folding_factor: usize) -> SumcheckPolynomial<F> {
        let two = F::ONE + F::ONE; // Enlightening

        assert!(self.num_variables >= folding_factor);

        let num_evaluation_points = 3_usize.pow(folding_factor as u32);
        let suffix_len = 1 << folding_factor;
        let prefix_len = (1 << self.num_variables) / suffix_len;

        // sets evaluation_points to the set of all {0,1,2}^folding_factor
        let evaluation_points: Vec<Vec<F>> = (0..num_evaluation_points)
            .map(|point| {
                base_decomposition(point, 3, folding_factor)
                    .into_iter()
                    .map(|v| match v {
                        0 => F::ZERO,
                        1 => F::ONE,
                        2 => two,
                        _ => unreachable!(),
                    })
                    .collect()
            })
            .collect();
        let mut evaluations = vec![F::ZERO; num_evaluation_points];

        // NOTE: This can probably be optimised a fair bit, there are a bunch of lagranges that can
        // be computed at the same time, some allocations to save ecc ecc.
        // The outer loop is over the prefixes
        for beta_prefix in 0..prefix_len {
            // Gather the evaluations that we are concerned about
            // The indexes all have the same prefix (in this loop), and loops
            // over all possible suffixes
            // indexes = [suffix_len * beta_prefix .. suffix_len * (beta_prefix + 1)].to_vec()
            let indexes: Vec<_> = (0..suffix_len)
                .map(|beta_suffix| suffix_len * beta_prefix + beta_suffix)
                .collect();
            // left_poly = self.evaluation_of_p[suffix_len * beta_prefix .. suffix_len * (beta_prefix + 1)].to_vec()
            let left_poly = MultilinearExtension::from_evaluations_ext_vec(
                folding_factor,
                indexes.iter().map(|&i| self.evaluation_of_p[i]).collect(),
            );
            let right_poly = MultilinearExtension::from_evaluations_ext_vec(
                folding_factor,
                indexes
                    .iter()
                    .map(|&i| self.evaluation_of_equality[i])
                    .collect(),
            );

            // For each evaluation point, update with the right added
            for point in 0..num_evaluation_points {
                evaluations[point] += left_poly.evaluate(&evaluation_points[point])
                    * right_poly.evaluate(&evaluation_points[point]);
            }
        }

        SumcheckPolynomial::new(evaluations, folding_factor)
    }

    pub fn add_new_equality(&mut self, points: &[Vec<F>], combination_randomness: &[F]) {
        assert_eq!(combination_randomness.len(), points.len());
        for (point, rand) in points.iter().zip(combination_randomness) {
            for (prefix, lag) in LagrangePolynomialIterator::new(point) {
                self.evaluation_of_equality[prefix] += *rand * lag;
            }
        }
    }

    // When the folding randomness arrives, compress the table accordingly (adding the new points)
    pub fn compress(
        &mut self,
        folding_factor: usize,
        combination_randomness: F, // Scale the initial point
        folding_randomness: &[F],
    ) {
        assert_eq!(folding_randomness.len(), folding_factor);
        assert!(self.num_variables >= folding_factor);

        let suffix_len = 1 << folding_factor;
        let prefix_len = (1 << self.num_variables) / suffix_len;
        let mut evaluations_of_p = Vec::with_capacity(prefix_len);
        let mut evaluations_of_eq = Vec::with_capacity(prefix_len);

        // Compress the table
        for beta_prefix in 0..prefix_len {
            let indexes: Vec<_> = (0..suffix_len)
                .map(|beta_suffix| suffix_len * beta_prefix + beta_suffix)
                .collect();

            let left_poly = MultilinearExtension::from_evaluations_ext_vec(
                folding_factor,
                indexes.iter().map(|&i| self.evaluation_of_p[i]).collect(),
            );
            let right_poly = MultilinearExtension::from_evaluations_ext_vec(
                folding_factor,
                indexes
                    .iter()
                    .map(|&i| self.evaluation_of_equality[i])
                    .collect(),
            );

            evaluations_of_p.push(left_poly.evaluate(folding_randomness));
            evaluations_of_eq
                .push(combination_randomness * right_poly.evaluate(folding_randomness));
        }

        // Update
        self.num_variables -= folding_factor;
        self.evaluation_of_p = evaluations_of_p;
        self.evaluation_of_equality = evaluations_of_eq;
    }
}
