use ark_std::{end_timer, start_timer};
use goldilocks::SmallField;
use itertools::{chain, izip, Itertools};
use multilinear_extensions::virtual_poly::{build_eq_x_r_vec, eq_eval, VPAuxInfo};
use std::{iter, marker::PhantomData, mem};
use transcript::Transcript;

use crate::{
    circuit::EvaluateGateCIn,
    error::GKRError,
    structs::{Circuit, IOPProverStepMessage, IOPVerifierState, PointAndEval},
    utils::MatrixMLERowFirst,
};

use super::SumcheckState;

impl<F: SmallField> IOPVerifierState<F> {
    pub(super) fn verify_and_update_state_output_phase1_step1(
        &mut self,
        circuit: &Circuit<F>,
        step_msg: IOPProverStepMessage<F>,
        transcript: &mut Transcript<F>,
    ) -> Result<(), GKRError> {
        let timer = start_timer!(|| "Verifier sumcheck phase 1 step 1");
        let alpha = transcript
            .get_and_append_challenge(b"combine subset evals")
            .elements;
        let total_length = self.to_next_phase_point_and_evals.len()
            + self.subset_point_and_evals[self.layer_id as usize].len()
            + 1;
        let alpha_pows = {
            let mut alpha_pows = vec![F::ONE; total_length];
            for i in 0..total_length.saturating_sub(1) {
                alpha_pows[i + 1] = alpha_pows[i] * alpha;
            }
            alpha_pows
        };

        let lo_num_vars = circuit.layers[self.layer_id as usize].num_vars;
        let hi_num_vars = self.instance_num_vars;

        // TODO: Double check the soundness here.
        let assert_eq_yj_ryj = build_eq_x_r_vec(&self.assert_point[..lo_num_vars]);

        let mut sigma_1 = F::ZERO;
        sigma_1 += izip!(self.to_next_phase_point_and_evals.iter(), alpha_pows.iter())
            .fold(F::ZERO, |acc, (point_and_eval, alpha_pow)| {
                acc + point_and_eval.eval * alpha_pow
            });
        sigma_1 += izip!(
            self.subset_point_and_evals[self.layer_id as usize].iter(),
            alpha_pows
                .iter()
                .skip(self.to_next_phase_point_and_evals.len())
        )
        .fold(F::ZERO, |acc, ((_, point_and_eval), alpha_pow)| {
            acc + point_and_eval.eval * alpha_pow
        });
        sigma_1 += circuit
            .assert_consts
            .as_slice()
            .eval(&assert_eq_yj_ryj, &self.challenges)
            * alpha_pows.last().unwrap();

        // Sumcheck 1: sigma = \sum_y( \sum_j f1^{(j)}(y) * g1^{(j)}(y) )
        //     f1^{(j)}(y) = layers[i](rt_j || y)
        //     g1^{(j)}(y) = \alpha^j copy_to_wits_out[j](ry_j, y)
        //                     or \alpha^j assert_subset_eq[j](ry, y)
        let claim_1 = SumcheckState::verify(
            sigma_1,
            &step_msg.sumcheck_proof,
            &VPAuxInfo {
                max_degree: 2,
                num_variables: lo_num_vars,
                phantom: PhantomData,
            },
            transcript,
        );
        let claim1_point = claim_1.point.iter().map(|x| x.elements).collect_vec();
        let eq_y_ry = build_eq_x_r_vec(&claim1_point);
        self.g1_values = chain![
            izip!(self.to_next_phase_point_and_evals.iter(), alpha_pows.iter()).map(
                |(point_and_eval, alpha_pow)| {
                    let point_lo_num_vars = point_and_eval.point.len() - hi_num_vars;
                    eq_eval(&point_and_eval.point[..point_lo_num_vars], &claim1_point) * alpha_pow
                }
            ),
            izip!(
                circuit.copy_to_wits_out.iter(),
                self.subset_point_and_evals[self.layer_id as usize].iter(),
                alpha_pows
                    .iter()
                    .skip(self.to_next_phase_point_and_evals.len())
            )
            .map(|(copy_to, (_, point_and_eval), alpha_pow)| {
                let point_lo_num_vars = point_and_eval.point.len() - hi_num_vars;
                let eq_yj_ryj = build_eq_x_r_vec(&point_and_eval.point[..point_lo_num_vars]);
                copy_to.as_slice().eval_row_first(&eq_yj_ryj, &eq_y_ry) * alpha_pow
            }),
            iter::once(
                circuit
                    .assert_consts
                    .as_slice()
                    .eval_subset_eq(&assert_eq_yj_ryj, &eq_y_ry)
                    * alpha_pows.last().unwrap()
            )
        ]
        .collect_vec();

        let f1_values = step_msg.sumcheck_eval_values.to_vec();
        let got_value_1 = f1_values
            .iter()
            .zip(self.g1_values.iter())
            .fold(F::ZERO, |acc, (&f1, g1)| acc + f1 * g1);

        end_timer!(timer);
        if claim_1.expected_evaluation != got_value_1 {
            return Err(GKRError::VerifyError("output phase1 step1 failed"));
        }

        self.to_next_step_point_and_eval =
            PointAndEval::new(claim1_point, claim_1.expected_evaluation);

        Ok(())
    }

    pub(super) fn verify_and_update_state_output_phase1_step2(
        &mut self,
        _: &Circuit<F>,
        step_msg: IOPProverStepMessage<F>,
        transcript: &mut Transcript<F>,
    ) -> Result<(), GKRError> {
        let timer = start_timer!(|| "Verifier sumcheck phase 1 step 2");
        let hi_num_vars = self.instance_num_vars;

        // Sumcheck 2: sigma = \sum_t( \sum_j( g2^{(j)}(t) ) ) * f2(t)
        //     f2(t) = layers[i](t || ry)
        //     g2^{(j)}(t) = \alpha^j copy_to[j](ry_j, r_y) eq(rt_j, t)
        let claim_2 = SumcheckState::verify(
            self.to_next_step_point_and_eval.eval,
            &step_msg.sumcheck_proof,
            &VPAuxInfo {
                max_degree: 2,
                num_variables: hi_num_vars,
                phantom: PhantomData,
            },
            transcript,
        );
        let claim2_point = claim_2.point.iter().map(|x| x.elements).collect_vec();

        let output_points = chain![
            self.to_next_phase_point_and_evals.iter().map(|x| &x.point),
            self.subset_point_and_evals[self.layer_id as usize]
                .iter()
                .map(|x| &x.1.point),
            iter::once(&self.assert_point),
        ];
        let f2_value = step_msg.sumcheck_eval_values[0];
        let g2_value = output_points
            .zip(self.g1_values.iter())
            .map(|(point, g1_value)| {
                let point_lo_num_vars = point.len() - hi_num_vars;
                *g1_value * eq_eval(&point[point_lo_num_vars..], &claim2_point)
            })
            .fold(F::ZERO, |acc, value| acc + value);

        let got_value_2 = f2_value * g2_value;

        end_timer!(timer);
        if claim_2.expected_evaluation != got_value_2 {
            return Err(GKRError::VerifyError("output phase1 step2 failed"));
        }

        self.to_next_step_point_and_eval = PointAndEval::new(
            [
                mem::take(&mut self.to_next_step_point_and_eval.point),
                claim2_point,
            ]
            .concat(),
            f2_value,
        );
        self.subset_point_and_evals[self.layer_id as usize].clear();

        Ok(())
    }
}
