use ark_std::{end_timer, start_timer};
use goldilocks::SmallField;
use itertools::Itertools;
use multilinear_extensions::virtual_poly::{build_eq_x_r_vec, eq_eval, VPAuxInfo};
use simple_frontend::structs::{CellId, LayerId};
use transcript::Transcript;

use crate::{
    error::GKRError,
    structs::{PointAndEval, SumcheckProof},
    utils::MatrixMLERowFirst,
};

use super::{IOPVerifierPhase1State, SumcheckState};

impl<'a, F: SmallField> IOPVerifierPhase1State<'a, F> {
    pub(super) fn verifier_init_parallel(
        next_layer_point_and_evals: &'a [PointAndEval<F>],
        subset_point_and_evals: &'a [(LayerId, PointAndEval<F>)],
        alpha: &F,
        lo_num_vars: usize,
        hi_num_vars: usize,
    ) -> Self {
        let timer = start_timer!(|| "Verifier init phase 1");
        let alpha_pows = {
            let mut alpha_pows =
                vec![F::ONE; next_layer_point_and_evals.len() + subset_point_and_evals.len()];
            for i in 0..subset_point_and_evals.len().saturating_sub(1) {
                alpha_pows[i + 1] = alpha_pows[i] * alpha;
            }
            alpha_pows
        };
        end_timer!(timer);
        Self {
            next_layer_point_and_evals,
            subset_point_and_evals,
            alpha_pows,
            lo_num_vars,
            hi_num_vars,
            f1_values: vec![],
            g1_values: vec![],
            sumcheck_sigma: F::ZERO,
        }
    }

    pub(super) fn verify_and_update_state_step1_parallel(
        &mut self,
        prover_msg: (&SumcheckProof<F>, &[F]),
        copy_to: impl Fn(&LayerId) -> &'a [CellId],
        transcript: &mut Transcript<F>,
    ) -> Result<(), GKRError> {
        let timer = start_timer!(|| "Verifier sumcheck phase 1 step 1");
        let lo_num_vars = self.lo_num_vars;
        let hi_num_vars = self.hi_num_vars;
        let next_layer_point_and_evals = &self.next_layer_point_and_evals;
        let subset_point_and_evals = &self.subset_point_and_evals;

        let alpha_pows = &self.alpha_pows;

        // sigma = \sum_j( \alpha^j * subset[i][j](rt_j || ry_j) )
        let sigma_1 = {
            let tmp = next_layer_point_and_evals
                .iter()
                .zip(alpha_pows.iter())
                .fold(F::ZERO, |acc, (point_and_eval, &alpha_pow)| {
                    acc + alpha_pow * point_and_eval.eval
                });
            subset_point_and_evals
                .iter()
                .zip(alpha_pows.iter().skip(next_layer_point_and_evals.len()))
                .fold(tmp, |acc, ((_, point_and_eval), &alpha_pow)| {
                    acc + alpha_pow * point_and_eval.eval
                })
        };
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
        self.g1_values = next_layer_point_and_evals
            .iter()
            .zip(alpha_pows.iter())
            .map(|(point_and_eval, &alpha_pow)| {
                let point_lo_num_vars = point_and_eval.point.len() - hi_num_vars;
                alpha_pow * eq_eval(&point_and_eval.point[..point_lo_num_vars], &claim1_point)
            })
            .chain(
                subset_point_and_evals
                    .iter()
                    .zip(alpha_pows.iter().skip(next_layer_point_and_evals.len()))
                    .map(|((new_layer_id, point_and_eval), &alpha_pow)| {
                        let point_lo_num_vars = point_and_eval.point.len() - hi_num_vars;
                        let eq_yj_ryj =
                            build_eq_x_r_vec(&point_and_eval.point[..point_lo_num_vars]);
                        copy_to(new_layer_id).eval_row_first(&eq_yj_ryj, &eq_y_ry) * alpha_pow
                    }),
            )
            .collect_vec();

        self.f1_values = prover_msg.1.to_vec();
        let got_value_1 = self
            .f1_values
            .iter()
            .zip(self.g1_values.iter())
            .fold(F::ZERO, |acc, (&f1, g1)| acc + f1 * g1);

        end_timer!(timer);

        if claim_1.expected_evaluation != got_value_1 {
            return Err(GKRError::VerifyError);
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
        let next_layer_point_and_evals = &self.next_layer_point_and_evals;
        let subset_point_and_evals = &self.subset_point_and_evals;

        let alpha_pows = &self.alpha_pows;
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
        let g2_values = next_layer_point_and_evals
            .iter()
            .zip(g1_values.iter())
            .zip(alpha_pows.iter())
            .map(|((point_and_eval, g1_value), &alpha_pow)| {
                let point_lo_num_vars = point_and_eval.point.len() - hi_num_vars;
                alpha_pow
                    * g1_value
                    * eq_eval(&point_and_eval.point[point_lo_num_vars..], &claim2_point)
            })
            .chain(
                subset_point_and_evals
                    .iter()
                    .zip(g1_values.iter().skip(next_layer_point_and_evals.len()))
                    .zip(alpha_pows.iter().skip(next_layer_point_and_evals.len()))
                    .map(|(((_, point_and_eval), g1_value), &alpha_pow)| {
                        let point_lo_num_vars = point_and_eval.point.len() - hi_num_vars;
                        alpha_pow
                            * g1_value
                            * eq_eval(&point_and_eval.point[point_lo_num_vars..], &claim2_point)
                    }),
            )
            .collect_vec();

        let got_value_2 = g2_values.iter().fold(F::ZERO, |acc, value| acc + value) * prover_msg.1;
        end_timer!(timer);

        if claim_2.expected_evaluation != got_value_2 {
            return Err(GKRError::VerifyError);
        }
        Ok(())
    }
}
