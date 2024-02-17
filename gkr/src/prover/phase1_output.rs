use std::{ops::Add, sync::Arc};

use ark_std::{end_timer, start_timer};
use goldilocks::SmallField;
use itertools::Itertools;
use multilinear_extensions::{
    mle::DenseMultilinearExtension,
    virtual_poly::{build_eq_x_r_vec, VirtualPolynomial},
};
use simple_frontend::structs::{CellId, OutType};
use transcript::Transcript;

use crate::{
    prover::SumcheckState,
    structs::{PointAndEval, SumcheckProof},
    utils::{fix_high_variables, MatrixMLERowFirst, SubsetIndices},
};

use super::IOPProverPhase1OutputState;

impl<'a, F: SmallField> IOPProverPhase1OutputState<'a, F> {
    /// Initialize the prover. Building the powers of alpha.
    pub(super) fn prover_init_parallel(
        layer_out_poly: &'a Arc<DenseMultilinearExtension<F>>,
        subset_point_and_evals: &'a [PointAndEval<F>],
        alpha: &F,
        n_pows: usize,
        lo_num_vars: usize,
        hi_num_vars: usize,
    ) -> Self {
        let timer = start_timer!(|| "Prover init output phase 1");
        let alpha_pows = {
            let mut alpha_pows = vec![F::ONE; n_pows];
            for i in 0..n_pows.saturating_sub(1) {
                alpha_pows[i + 1] = alpha_pows[i] * alpha;
            }
            alpha_pows
        };
        end_timer!(timer);
        Self {
            layer_out_poly,
            subset_point_and_evals,
            alpha_pows,
            lo_num_vars,
            hi_num_vars,
            sumcheck_point_1: vec![],
            g1_values: vec![],
            output_points: vec![],
        }
    }

    /// Sumcheck 1: sigma = \sum_y( \sum_j f1^{(j)}(y) * g1^{(j)}(y) )
    ///     sigma = \sum_j( \alpha^j * wit_out_eval[j](rt_j || ry_j) )
    ///             + \sum_j( \alpha^{wit_out_eval[j].len() + j} * assert_const(rt || ry) )
    ///     f1^{(j)}(y) = \sum_t( eq(rt_j, t) * layers[i](t || y) )
    ///     g1^{(j)}(y) = \alpha^j copy_to[j](ry_j, y)
    ///                     or \alpha^j subset_eq[j](ry, y)
    pub(super) fn prove_and_update_state_step1_parallel(
        &mut self,
        copy_to_out: &[(OutType, Vec<CellId>)],
        transcript: &mut Transcript<F>,
    ) -> (SumcheckProof<F>, Vec<F>) {
        let timer = start_timer!(|| "Prover sumcheck output phase 1 step 1");
        // sigma = \sum_j( \alpha^j * subset[i][j](rt_j || ry_j) )
        // f1^{(j)}(y) = \sum_t( eq(rt_j, t) * layers[i](t || y) )
        // g1^{(j)}(y) = \alpha^j copy_to[j](ry_j, y)
        //                  or \alpha^j subset_eq[j](ry, y)

        // Generate random point for assert statement.
        let assert_point = (0..self.lo_num_vars + self.hi_num_vars)
            .map(|_| {
                transcript
                    .get_and_append_challenge(b"output point")
                    .elements
            })
            .collect_vec();

        let total_length = self.subset_point_and_evals.len() + 1;
        let mut f1 = Vec::with_capacity(total_length);
        let mut g1 = Vec::with_capacity(total_length);
        copy_to_out
            .iter()
            .zip(self.alpha_pows.iter())
            .for_each(|((out, copy_to), alpha_pow)| {
                let (point, point_lo_num_vars, g1_j) = match *out {
                    OutType::Witness(id) => {
                        let point_and_eval = &self.subset_point_and_evals[id as usize];
                        let point_lo_num_vars = point_and_eval.point.len() - self.hi_num_vars;
                        let lo_eq_w_p =
                            build_eq_x_r_vec(&point_and_eval.point[..point_lo_num_vars]);
                        assert!(copy_to.len() <= lo_eq_w_p.len());
                        let g1_j = copy_to.as_slice().fix_row_row_first_with_scalar(
                            &lo_eq_w_p,
                            self.lo_num_vars,
                            alpha_pow,
                        );
                        (&point_and_eval.point, point_lo_num_vars, g1_j)
                    }
                    OutType::AssertConst(_) => {
                        let lo_eq_w_p = build_eq_x_r_vec(&assert_point[..self.lo_num_vars]);
                        let g1_j = copy_to
                            .as_slice()
                            .subset_eq_with_scalar(&lo_eq_w_p, alpha_pow);
                        (&assert_point, self.lo_num_vars, g1_j)
                    }
                };

                g1.push(Arc::new(DenseMultilinearExtension::from_evaluations_vec(
                    self.lo_num_vars,
                    g1_j,
                )));

                let f1_j = fix_high_variables(&self.layer_out_poly, &point[point_lo_num_vars..]);
                f1.push(Arc::new(f1_j));

                self.output_points.push(point.clone());
            });

        // sumcheck: sigma = \sum_y( \sum_j f1^{(j)}(y) * g1^{(j)}(y) )
        let mut virtual_poly_1 = VirtualPolynomial::new(self.lo_num_vars);
        for (f1_j, g1_j) in f1.iter().zip(g1.iter()) {
            let mut tmp = VirtualPolynomial::new_from_mle(f1_j, F::ONE);
            tmp.mul_by_mle(g1_j.clone(), F::ONE);
            virtual_poly_1 = virtual_poly_1.add(&tmp);
        }

        let sumcheck_proof_1 = SumcheckState::prove(&virtual_poly_1, transcript);
        let eval_value_1 = f1
            .iter()
            .map(|f1_j| f1_j.evaluate(&sumcheck_proof_1.point))
            .collect_vec();

        self.sumcheck_point_1 = sumcheck_proof_1.point.clone();
        self.g1_values = g1
            .iter()
            .map(|g1_j| g1_j.evaluate(&sumcheck_proof_1.point))
            .collect_vec();

        end_timer!(timer);
        (sumcheck_proof_1, eval_value_1)
    }

    /// Sumcheck 2: sigma = \sum_t( \sum_j( f2^{(j)}(t) ) ) * g2(t)
    ///     sigma = \sum_j( f1^{(j)}(ry) * g1^{(j)}(ry) )
    ///     f2(t) = layers[i](t || ry)
    ///     g2^{(j)}(t) = \alpha^j copy_to[j](ry_j, ry) eq(rt_j, t)
    pub(super) fn prove_and_update_state_step2_parallel(
        &mut self,
        transcript: &mut Transcript<F>,
    ) -> (SumcheckProof<F>, F) {
        let timer = start_timer!(|| "Prover sumcheck output phase 1 step 2");
        // sigma = \sum_j( f1^{(j)}(ry) * g1^{(j)}(ry) )
        // let sigma_2 = self
        //     .f1_values
        //     .iter()
        //     .zip(self.g1_values.iter())
        //     .fold(F::ZERO, |acc, (&f1_value_j, g1_value_j)| {
        //         acc + f1_value_j * g1_value_j
        //     });
        // f2(t) = layers[i](t || ry)
        let f2 = Arc::new(self.layer_out_poly.fix_variables(&self.sumcheck_point_1));
        // g2^{(j)}(t) = \alpha^j copy_to[j](ry_j, ry) eq(rt_j, t)
        let g2 = self
            .output_points
            .iter()
            .zip(self.g1_values.iter())
            .map(|(point, &g1_value)| {
                let point_lo_num_vars = point.len() - self.hi_num_vars;
                build_eq_x_r_vec(&point[point_lo_num_vars..])
                    .into_iter()
                    .map(|eq| g1_value * eq)
                    .collect_vec()
            })
            .fold(vec![F::ZERO; 1 << self.hi_num_vars], |acc, nxt| {
                acc.into_iter()
                    .zip(nxt.into_iter())
                    .map(|(a, b)| a + b)
                    .collect_vec()
            });
        let g2 = Arc::new(DenseMultilinearExtension::from_evaluations_vec(
            self.hi_num_vars,
            g2,
        ));
        // sumcheck: sigma = \sum_t( \sum_j( g2^{(j)}(t) ) ) * f2(t)
        let mut virtual_poly_2 = VirtualPolynomial::new_from_mle(&f2, F::ONE);
        virtual_poly_2.mul_by_mle(g2, F::ONE);

        let sumcheck_proof_2 = SumcheckState::prove(&virtual_poly_2, transcript);
        // assert_eq!(sumcheck_proof_2.extract_sum(), sigma_2);
        let eval_value_2 = f2.evaluate(&sumcheck_proof_2.point);
        end_timer!(timer);
        (sumcheck_proof_2, eval_value_2)
    }
}
