pub mod proof;
pub mod prover_batched;
pub mod prover_core;
pub mod prover_not_skipping;
pub mod prover_not_skipping_batched;
pub mod prover_single;

#[cfg(test)]
mod tests {

    use ff_ext::{ExtensionField, GoldilocksExt2};
    use multilinear_extensions::{
        mle::{FieldType, MultilinearExtension},
        virtual_poly::eq_eval,
    };
    use p3::field::FieldAlgebra;

    use crate::whir::fold::expand_from_univariate;

    use super::prover_core::SumcheckCore;

    type F = GoldilocksExt2;

    #[test]
    fn test_sumcheck_folding_factor_1() {
        let folding_factor = 1;
        let eval_point = vec![F::from_canonical_u64(10), F::from_canonical_u64(11)];
        let polynomial = MultilinearExtension::from_evaluations_ext_vec(
            2,
            vec![
                F::from_canonical_u64(1),
                F::from_canonical_u64(5),
                F::from_canonical_u64(10),
                F::from_canonical_u64(14),
            ],
        );

        let claimed_value = polynomial.evaluate(&eval_point);

        let mut prover = SumcheckCore::new(polynomial, &[eval_point], &[F::from_canonical_u64(1)]);

        let poly_1 = prover.compute_sumcheck_polynomial(folding_factor);

        // First, check that is sums to the right value over the hypercube
        assert_eq!(poly_1.sum_over_hypercube(), claimed_value);

        let combination_randomness = F::from_canonical_u64(100101);
        let folding_randomness = vec![F::from_canonical_u64(4999)];

        prover.compress(folding_factor, combination_randomness, &folding_randomness);

        let poly_2 = prover.compute_sumcheck_polynomial(folding_factor);

        assert_eq!(
            poly_2.sum_over_hypercube(),
            combination_randomness * poly_1.evaluate_at_point(&folding_randomness)
        );
    }

    #[test]
    fn test_single_folding() {
        let num_variables = 2;
        let folding_factor = 2;
        let polynomial = MultilinearExtension::from_evaluations_ext_vec(
            2,
            vec![
                F::from_canonical_u64(1),
                F::from_canonical_u64(2),
                F::from_canonical_u64(3),
                F::from_canonical_u64(4),
            ],
        );

        let ood_point = expand_from_univariate(F::from_canonical_u64(2), num_variables);
        let statement_point = expand_from_univariate(F::from_canonical_u64(3), num_variables);

        let ood_answer = polynomial.evaluate(&ood_point);
        let statement_answer = polynomial.evaluate(&statement_point);

        let epsilon_1 = F::from_canonical_u64(10);
        let epsilon_2 = F::from_canonical_u64(100);

        let prover = SumcheckCore::new(
            polynomial.clone(),
            &[ood_point.clone(), statement_point.clone()],
            &[epsilon_1, epsilon_2],
        );

        let poly_1 = prover.compute_sumcheck_polynomial(folding_factor);

        assert_eq!(
            poly_1.sum_over_hypercube(),
            epsilon_1 * ood_answer + epsilon_2 * statement_answer
        );

        let folding_randomness = vec![F::from_canonical_u64(400000), F::from_canonical_u64(800000)];

        let poly_eval = polynomial.evaluate(&folding_randomness);
        let v_eval = epsilon_1 * eq_eval(&ood_point, &folding_randomness)
            + epsilon_2 * eq_eval(&statement_point, &folding_randomness);

        assert_eq!(
            poly_1.evaluate_at_point(&folding_randomness),
            poly_eval * v_eval
        );
    }

    #[test]
    fn test_sumcheck_folding_factor_2() {
        let num_variables = 6;
        let folding_factor = 2;
        let eval_point = vec![F::from_canonical_u64(97); num_variables];
        let polynomial = MultilinearExtension::from_evaluations_ext_vec(
            num_variables,
            (0..1 << num_variables).map(F::from_canonical_u64).collect(),
        );

        let claimed_value = polynomial.evaluate(&eval_point);

        let mut prover = SumcheckCore::new(
            polynomial.clone(),
            &[eval_point],
            &[F::from_canonical_u64(1)],
        );

        let poly_1 = prover.compute_sumcheck_polynomial(folding_factor);

        // First, check that is sums to the right value over the hypercube
        assert_eq!(poly_1.sum_over_hypercube(), claimed_value);

        let combination_randomness = [F::from_canonical_u64(293), F::from_canonical_u64(42)];
        let folding_randomness = vec![F::from_canonical_u64(335), F::from_canonical_u64(222)];

        let new_eval_point = vec![F::from_canonical_u64(32); num_variables - folding_factor];
        let folded_polynomial = polynomial.fix_variables(&folding_randomness);
        let new_fold_eval = folded_polynomial.evaluate(&new_eval_point);

        prover.compress(
            folding_factor,
            combination_randomness[0],
            &folding_randomness,
        );
        prover.add_new_equality(&[new_eval_point], &combination_randomness[1..]);

        let poly_2 = prover.compute_sumcheck_polynomial(folding_factor);

        assert_eq!(
            poly_2.sum_over_hypercube(),
            combination_randomness[0] * poly_1.evaluate_at_point(&folding_randomness)
                + combination_randomness[1] * new_fold_eval
        );

        let combination_randomness = F::from_canonical_u64(23212);
        prover.compress(folding_factor, combination_randomness, &folding_randomness);

        let poly_3 = prover.compute_sumcheck_polynomial(folding_factor);

        assert_eq!(
            poly_3.sum_over_hypercube(),
            combination_randomness * poly_2.evaluate_at_point(&folding_randomness)
        )
    }

    #[test]
    fn test_e2e() {
        let num_variables = 4;
        let folding_factor = 2;
        let polynomial = MultilinearExtension::from_evaluations_ext_vec(
            num_variables,
            (0..1 << num_variables).map(F::from_canonical_u64).collect(),
        );

        // Initial stuff
        let ood_point = expand_from_univariate(F::from_canonical_u64(42), num_variables);
        let statement_point = expand_from_univariate(F::from_canonical_u64(97), num_variables);

        // All the randomness
        let [epsilon_1, epsilon_2] = [F::from_canonical_u64(15), F::from_canonical_u64(32)];
        let folding_randomness_1 = vec![F::from_canonical_u64(11), F::from_canonical_u64(31)];
        let fold_point = vec![F::from_canonical_u64(31), F::from_canonical_u64(15)];
        let combination_randomness = [F::from_canonical_u64(31), F::from_canonical_u64(4999)];
        let folding_randomness_2 = vec![F::from_canonical_u64(97), F::from_canonical_u64(36)];

        let mut prover = SumcheckCore::new(
            polynomial.clone(),
            &[ood_point.clone(), statement_point.clone()],
            &[epsilon_1, epsilon_2],
        );

        let sumcheck_poly_1 = prover.compute_sumcheck_polynomial(folding_factor);

        let folded_poly_1 = polynomial.fix_variables(&folding_randomness_1.clone());
        prover.compress(
            folding_factor,
            combination_randomness[0],
            &folding_randomness_1,
        );
        prover.add_new_equality(&[fold_point.clone()], &combination_randomness[1..]);

        let sumcheck_poly_2 = prover.compute_sumcheck_polynomial(folding_factor);

        let ood_answer = polynomial.evaluate(&ood_point);
        let statement_answer = polynomial.evaluate(&statement_point);

        assert_eq!(
            sumcheck_poly_1.sum_over_hypercube(),
            epsilon_1 * ood_answer + epsilon_2 * statement_answer
        );

        let fold_answer = folded_poly_1.evaluate(&fold_point);

        assert_eq!(
            sumcheck_poly_2.sum_over_hypercube(),
            combination_randomness[0] * sumcheck_poly_1.evaluate_at_point(&folding_randomness_1)
                + combination_randomness[1] * fold_answer
        );

        let full_folding = [folding_randomness_1.clone(), folding_randomness_2.clone()].concat();
        let eval_coeff = match folded_poly_1
            .fix_variables(&folding_randomness_2)
            .evaluations()
        {
            FieldType::Base(evals) => {
                assert_eq!(evals.len(), 1);
                F::from_ref_base(&evals[0])
            }
            FieldType::Ext(evals) => {
                assert_eq!(evals.len(), 1);
                evals[0]
            }
            _ => panic!("Invalid folded polynomial"),
        };
        assert_eq!(
            sumcheck_poly_2.evaluate_at_point(&folding_randomness_2),
            eval_coeff
                * (combination_randomness[0]
                    * (epsilon_1 * eq_eval(&full_folding, &ood_point)
                        + epsilon_2 * eq_eval(&full_folding, &statement_point))
                    + combination_randomness[1] * eq_eval(&folding_randomness_2, &fold_point))
        )
    }

    #[test]
    fn test_e2e_larger() {
        let num_variables = 6;
        let folding_factor = 2;
        let polynomial = MultilinearExtension::from_evaluations_ext_vec(
            num_variables,
            (0..1 << num_variables).map(F::from_canonical_u64).collect(),
        );

        // Initial stuff
        let ood_point = expand_from_univariate(F::from_canonical_u64(42), num_variables);
        let statement_point = expand_from_univariate(F::from_canonical_u64(97), num_variables);

        // All the randomness
        let [epsilon_1, epsilon_2] = [F::from_canonical_u64(15), F::from_canonical_u64(32)];
        let folding_randomness_1 = vec![F::from_canonical_u64(11), F::from_canonical_u64(31)];
        let folding_randomness_2 = vec![F::from_canonical_u64(97), F::from_canonical_u64(36)];
        let folding_randomness_3 = vec![F::from_canonical_u64(11297), F::from_canonical_u64(42136)];
        let fold_point_11 = vec![
            F::from_canonical_u64(31),
            F::from_canonical_u64(15),
            F::from_canonical_u64(31),
            F::from_canonical_u64(15),
        ];
        let fold_point_12 = vec![
            F::from_canonical_u64(1231),
            F::from_canonical_u64(15),
            F::from_canonical_u64(4231),
            F::from_canonical_u64(15),
        ];
        let fold_point_2 = vec![F::from_canonical_u64(311), F::from_canonical_u64(115)];
        let combination_randomness_1 = [
            F::from_canonical_u64(1289),
            F::from_canonical_u64(3281),
            F::from_canonical_u64(10921),
        ];
        let combination_randomness_2 = [F::from_canonical_u64(3281), F::from_canonical_u64(3232)];

        let mut prover = SumcheckCore::new(
            polynomial.clone(),
            &[ood_point.clone(), statement_point.clone()],
            &[epsilon_1, epsilon_2],
        );

        let sumcheck_poly_1 = prover.compute_sumcheck_polynomial(folding_factor);

        let folded_poly_1 = polynomial.fix_variables(&folding_randomness_1.clone());
        prover.compress(
            folding_factor,
            combination_randomness_1[0],
            &folding_randomness_1,
        );
        prover.add_new_equality(
            &[fold_point_11.clone(), fold_point_12.clone()],
            &combination_randomness_1[1..],
        );

        let sumcheck_poly_2 = prover.compute_sumcheck_polynomial(folding_factor);

        let folded_poly_2 = folded_poly_1.fix_variables(&folding_randomness_2.clone());
        prover.compress(
            folding_factor,
            combination_randomness_2[0],
            &folding_randomness_2,
        );
        prover.add_new_equality(&[fold_point_2.clone()], &combination_randomness_2[1..]);

        let sumcheck_poly_3 = prover.compute_sumcheck_polynomial(folding_factor);
        let final_coeff = match folded_poly_2
            .fix_variables(&folding_randomness_3.clone())
            .evaluations()
        {
            FieldType::Base(evals) => F::from_ref_base(&evals[0]),
            FieldType::Ext(evals) => evals[0],
            _ => panic!("Invalid folded polynomial"),
        };

        // Compute all evaluations
        let ood_answer = polynomial.evaluate(&ood_point);
        let statement_answer = polynomial.evaluate(&statement_point);
        let fold_answer_11 = folded_poly_1.evaluate(&fold_point_11);
        let fold_answer_12 = folded_poly_1.evaluate(&fold_point_12);
        let fold_answer_2 = folded_poly_2.evaluate(&fold_point_2);

        assert_eq!(
            sumcheck_poly_1.sum_over_hypercube(),
            epsilon_1 * ood_answer + epsilon_2 * statement_answer
        );

        assert_eq!(
            sumcheck_poly_2.sum_over_hypercube(),
            combination_randomness_1[0] * sumcheck_poly_1.evaluate_at_point(&folding_randomness_1)
                + combination_randomness_1[1] * fold_answer_11
                + combination_randomness_1[2] * fold_answer_12
        );

        assert_eq!(
            sumcheck_poly_3.sum_over_hypercube(),
            combination_randomness_2[0] * sumcheck_poly_2.evaluate_at_point(&folding_randomness_2)
                + combination_randomness_2[1] * fold_answer_2
        );

        let full_folding = [
            folding_randomness_1.clone(),
            folding_randomness_2.clone(),
            folding_randomness_3.clone(),
        ]
        .concat();

        assert_eq!(
            sumcheck_poly_3.evaluate_at_point(&folding_randomness_3),
            final_coeff
                * (combination_randomness_2[0]
                    * (combination_randomness_1[0]
                        * (epsilon_1 * eq_eval(&full_folding, &ood_point)
                            + epsilon_2 * eq_eval(&full_folding, &statement_point))
                        + combination_randomness_1[1]
                            * eq_eval(
                                &fold_point_11,
                                &[folding_randomness_2.clone(), folding_randomness_3.clone()]
                                    .concat()
                            )
                        + combination_randomness_1[2]
                            * eq_eval(
                                &fold_point_12,
                                &[folding_randomness_2.clone(), folding_randomness_3.clone()]
                                    .concat()
                            ))
                    + combination_randomness_2[1] * eq_eval(&folding_randomness_3, &fold_point_2))
        )
    }
}
