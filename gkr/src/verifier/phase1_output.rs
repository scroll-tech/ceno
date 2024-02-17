use ark_std::{end_timer, start_timer};
use goldilocks::SmallField;
use itertools::Itertools;
use multilinear_extensions::virtual_poly::{build_eq_x_r_vec, eq_eval, VPAuxInfo};
use simple_frontend::structs::{CellId, OutType};
use transcript::Transcript;

use crate::{
    error::GKRError,
    structs::{PointAndEval, SumcheckProof},
    utils::{i64_to_field, MatrixMLERowFirst, SubsetIndices},
};

use super::{IOPVerifierPhase1OutputState, SumcheckState};

impl<'a, F: SmallField> IOPVerifierPhase1OutputState<'a, F> {
    pub(super) fn verifier_init_parallel(
        subset_point_and_evals: &'a [PointAndEval<F>],
        alpha: &F,
        n_pows: usize,
        lo_num_vars: usize,
        hi_num_vars: usize,
    ) -> Self {
        let timer = start_timer!(|| "Verifier init phase 1");
        let alpha_pows = {
            let mut alpha_pows = vec![F::ONE; n_pows];
            for i in 0..n_pows.saturating_sub(1) {
                alpha_pows[i + 1] = alpha_pows[i] * alpha;
            }
            alpha_pows
        };
        end_timer!(timer);
        Self {
            subset_point_and_evals,
            alpha_pows,
            lo_num_vars,
            hi_num_vars,
            g1_values: vec![],
            output_points: vec![],
            sumcheck_sigma: F::ZERO,
        }
    }

    pub(super) fn verify_and_update_state_step1_parallel(
        &mut self,
        prover_msg: (&SumcheckProof<F>, &[F]),
        copy_to_out: &[(OutType, Vec<CellId>)],
        transcript: &mut Transcript<F>,
    ) -> Result<(), GKRError> {
        let timer = start_timer!(|| "Verifier sumcheck phase 1 step 1");
        let lo_num_vars = self.lo_num_vars;

        let alpha_pows = &self.alpha_pows;
        let assert_point = (0..self.lo_num_vars + self.hi_num_vars)
            .map(|_| {
                transcript
                    .get_and_append_challenge(b"output point")
                    .elements
            })
            .collect_vec();

        let assert_eq_yj_ryj = build_eq_x_r_vec(&assert_point[..self.lo_num_vars]);

        // sigma = \sum_j( \alpha^j * subset[i][j](rt_j || ry_j) )
        let sigma_1 = copy_to_out.iter().zip(self.alpha_pows.iter()).fold(
            F::ZERO,
            |acc, ((out, copy_to), alpha_pow)| {
                let eval = match *out {
                    OutType::Witness(id) => self.subset_point_and_evals[id as usize].eval,
                    OutType::AssertConst(constant) => {
                        i64_to_field::<F>(constant)
                            * copy_to.as_slice().subset_eq_eval(&assert_eq_yj_ryj)
                    }
                };
                acc + eval * alpha_pow
            },
        );
        // Sumcheck 1: sigma = \sum_y( \sum_j f1^{(j)}(y) * g1^{(j)}(y) )
        //     f1^{(j)}(y) = \sum_t( eq(rt_j, t) * layers[i](t || y) )
        //     g1^{(j)}(y) = \alpha^j copy_to[j](ry_j, y)
        let claim_1 = SumcheckState::verify(
            sigma_1,
            &prover_msg.0,
            &VPAuxInfo {
                max_degree: 2,
                num_variables: lo_num_vars,
                phantom: std::marker::PhantomData,
            },
            transcript,
        );
        let claim1_point = claim_1.point.iter().map(|x| x.elements).collect_vec();
        let eq_y_ry = build_eq_x_r_vec(&claim1_point);
        self.g1_values = copy_to_out
            .iter()
            .zip(alpha_pows.iter())
            .map(|((out, copy_to), &alpha_pow)| match *out {
                OutType::Witness(id) => {
                    let point_and_eval = &self.subset_point_and_evals[id as usize];
                    let point_lo_num_vars = point_and_eval.point.len() - self.hi_num_vars;
                    self.output_points.push(point_and_eval.point.clone());
                    let eq_yj_ryj = build_eq_x_r_vec(&point_and_eval.point[..point_lo_num_vars]);
                    copy_to.as_slice().eval_row_first(&eq_yj_ryj, &eq_y_ry) * alpha_pow
                }
                OutType::AssertConst(_) => {
                    self.output_points.push(assert_point.clone());
                    copy_to
                        .as_slice()
                        .subset_eq2_eval(&assert_eq_yj_ryj, &eq_y_ry)
                        * alpha_pow
                }
            })
            .collect_vec();

        let f1_values = prover_msg.1.to_vec();
        let got_value_1 = f1_values
            .iter()
            .zip(self.g1_values.iter())
            .fold(F::ZERO, |acc, (&f1, g1)| acc + f1 * g1);

        end_timer!(timer);

        if claim_1.expected_evaluation != got_value_1 {
            return Err(GKRError::VerifyError("output phase1 step1 failed"));
        }

        self.sumcheck_sigma = got_value_1;
        Ok(())
    }

    pub(super) fn verify_and_update_state_step2_parallel(
        &mut self,
        prover_msg: (&SumcheckProof<F>, F),
        transcript: &mut Transcript<F>,
    ) -> Result<(), GKRError> {
        let timer = start_timer!(|| "Verifier sumcheck phase 1 step 2");
        let hi_num_vars = self.hi_num_vars;

        let g1_values = &self.g1_values;

        // sigma = \sum_j( f1^{(j)}(ry) * g1^{(j)}(ry) )
        let sigma_2 = self.sumcheck_sigma;
        // Sumcheck 2: sigma = \sum_t( \sum_j( g2^{(j)}(t) ) ) * f2(t)
        //     f2(t) = layers[i](t || ry)
        //     g2^{(j)}(t) = \alpha^j copy_to[j](ry_j, r_y) eq(rt_j, t)
        let claim_2 = SumcheckState::verify(
            sigma_2,
            &prover_msg.0,
            &VPAuxInfo {
                max_degree: 2,
                num_variables: hi_num_vars,
                phantom: std::marker::PhantomData,
            },
            transcript,
        );
        let claim2_point = claim_2.point.iter().map(|x| x.elements).collect_vec();

        let g2_values = self
            .output_points
            .iter()
            .zip(g1_values.iter())
            .map(|(point, g1_value)| {
                let point_lo_num_vars = point.len() - hi_num_vars;
                *g1_value * eq_eval(&point[point_lo_num_vars..], &claim2_point)
            })
            .collect_vec();

        let got_value_2 = g2_values.iter().fold(F::ZERO, |acc, value| acc + value) * prover_msg.1;
        end_timer!(timer);

        if claim_2.expected_evaluation != got_value_2 {
            return Err(GKRError::VerifyError("output phase1 step2 failed"));
        }
        Ok(())
    }
}
