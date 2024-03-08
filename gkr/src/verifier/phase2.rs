use ark_std::{end_timer, start_timer};
use goldilocks::SmallField;
use itertools::{chain, izip, Itertools};
use multilinear_extensions::virtual_poly::{build_eq_x_r_vec, eq_eval, VPAuxInfo};
use std::mem;
use transcript::Transcript;

use crate::{
    circuit::{EvaluateGate1In, EvaluateGate2In, EvaluateGate3In, EvaluateGateCIn},
    error::GKRError,
    structs::{Circuit, IOPProverStepMessage, IOPVerifierState, PointAndEval},
    utils::{eq3_eval, eq4_eval, MatrixMLEColumnFirst},
};

use super::SumcheckState;

impl<F: SmallField> IOPVerifierState<F> {
    pub(super) fn verify_and_update_state_phase2_step1(
        &mut self,
        circuit: &Circuit<F>,
        step_msg: IOPProverStepMessage<F>,
        transcript: &mut Transcript<F>,
    ) -> Result<(), GKRError> {
        let timer = start_timer!(|| "Verifier sumcheck phase 2 step 1");
        let layer = &circuit.layers[self.layer_id as usize];
        let lo_out_num_vars = layer.num_vars;
        let lo_in_num_vars = layer.max_previous_num_vars;
        let hi_num_vars = self.instance_num_vars;
        let in_num_vars = lo_in_num_vars + hi_num_vars;

        self.out_point = mem::take(&mut self.to_next_step_point_and_eval.point);
        let lo_point = &self.out_point[..lo_out_num_vars];
        let hi_point = &self.out_point[lo_out_num_vars..];

        self.eq_y_ry = build_eq_x_r_vec(lo_point);

        // sigma = layers[i](rt || ry) - add_const(ry),
        let sumcheck_sigma = self.to_next_step_point_and_eval.eval
            - layer
                .add_consts
                .as_slice()
                .eval(&self.eq_y_ry, &self.challenges);

        // Sumcheck 1: sigma = \sum_{s1 || x1} f1(s1 || x1) * g1(s1 || x1) + \sum_j f1'_j(s1 || x1) * g1'_j(s1 || x1)
        //     f1(s1 || x1) = layers[i + 1](s1 || x1)
        //     g1(s1 || x1) = \sum_{s2}( \sum_{s3}( \sum_{x2}( \sum_{x3}(
        //         eq(rt, s1, s2, s3) * mul3(ry, x1, x2, x3) * layers[i + 1](s2 || x2) * layers[i + 1](s3 || x3)
        //     ) ) ) ) + \sum_{s2}( \sum_{x2}(
        //         eq(rt, s1, s2) * mul2(ry, x1, x2) * layers[i + 1](s2 || x2)
        //     ) ) + eq(rt, s1) * add(ry, x1)
        //     f1'^{(j)}(s1 || x1) = subset[j][i](s1 || x1)
        //     g1'^{(j)}(s1 || x1) = eq(rt, s1) paste_from[j](ry, x1)
        let claim_1 = SumcheckState::verify(
            sumcheck_sigma,
            &step_msg.sumcheck_proof,
            &VPAuxInfo {
                max_degree: 2,
                num_variables: in_num_vars,
                phantom: std::marker::PhantomData,
            },
            transcript,
        );
        let claim1_point = claim_1.point.iter().map(|x| x.elements).collect_vec();
        let hi_point_sc1 = &claim1_point[lo_in_num_vars..];

        let (f1_values, received_g1_values) = step_msg
            .sumcheck_eval_values
            .split_at(step_msg.sumcheck_eval_values.len() - 1);

        let hi_eq_eval = eq_eval(&hi_point, hi_point_sc1);
        self.eq_x1_rx1 = build_eq_x_r_vec(&claim1_point[..lo_in_num_vars]);
        let g1_values_iter = chain![
            received_g1_values.iter().cloned(),
            layer.paste_from.iter().map(|(_, paste_from)| {
                hi_eq_eval
                    * paste_from
                        .as_slice()
                        .eval_col_first(&self.eq_y_ry, &self.eq_x1_rx1)
            })
        ];
        let got_value_1 =
            izip!(f1_values.iter(), g1_values_iter).fold(F::ZERO, |acc, (&f1, g1)| acc + f1 * g1);

        end_timer!(timer);
        if claim_1.expected_evaluation != got_value_1 {
            return Err(GKRError::VerifyError("phase2 step1 failed"));
        }

        self.to_next_phase_point_and_evals =
            vec![PointAndEval::new_from_ref(&claim1_point, &f1_values[0])];
        izip!(layer.paste_from.iter(), f1_values.iter().skip(1)).for_each(
            |((&old_layer_id, _), &subset_value)| {
                self.subset_point_and_evals[old_layer_id as usize].push((
                    self.layer_id,
                    PointAndEval::new_from_ref(&claim1_point, &subset_value),
                ));
            },
        );
        self.to_next_step_point_and_eval = PointAndEval::new(claim1_point, received_g1_values[0]);

        Ok(())
    }

    pub(super) fn verify_and_update_state_phase2_step2(
        &mut self,
        circuit: &Circuit<F>,
        step_msg: IOPProverStepMessage<F>,
        transcript: &mut Transcript<F>,
        no_step3: bool,
    ) -> Result<(), GKRError> {
        let timer = start_timer!(|| "Verifier sumcheck phase 2 step 2");
        let layer = &circuit.layers[self.layer_id as usize];
        let lo_out_num_vars = layer.num_vars;
        let lo_in_num_vars = layer.max_previous_num_vars;
        let hi_num_vars = self.instance_num_vars;
        let in_num_vars = lo_in_num_vars + hi_num_vars;

        // sigma = g1(rs1 || rx1) - eq(rt, rs1) * add(ry, rx1)
        let sumcheck_sigma = self.to_next_step_point_and_eval.eval
            - eq_eval(
                &self.out_point[lo_out_num_vars..],
                &self.to_next_phase_point_and_evals[0].point[lo_in_num_vars..],
            ) * layer
                .adds
                .as_slice()
                .eval(&self.eq_y_ry, &self.eq_x1_rx1, &self.challenges);

        // Sumcheck 2 sigma = \sum_{s2 || x2} f2(s2 || x2) * g2(s2 || x2)
        //     f2(s2 || x2) = layers[i + 1](s2 || x2)
        //     g2(s2 || x2) = \sum_{s3}( \sum_{x3}(
        //         eq(rt, rs1, s2, s3) * mul3(ry, rx1, x2, x3) * layers[i + 1](s3 || x3)
        //     ) ) + eq(rt, rs1, s2) * mul2(ry, rx1, x2)}
        let claim_2 = SumcheckState::verify(
            sumcheck_sigma,
            &step_msg.sumcheck_proof,
            &VPAuxInfo {
                max_degree: 2,
                num_variables: in_num_vars,
                phantom: std::marker::PhantomData,
            },
            transcript,
        );
        let claim2_point = claim_2.point.iter().map(|x| x.elements).collect_vec();
        let f2_value = step_msg.sumcheck_eval_values[0];

        self.eq_x2_rx2 = build_eq_x_r_vec(&claim2_point[..lo_in_num_vars]);
        let g2_value = if no_step3 {
            eq3_eval(
                &self.out_point[lo_out_num_vars..],
                &self.to_next_phase_point_and_evals[0].point[lo_in_num_vars..],
                &claim2_point[lo_in_num_vars..],
            ) * layer.mul2s.as_slice().eval(
                &self.eq_y_ry,
                &self.eq_x1_rx1,
                &self.eq_x2_rx2,
                &self.challenges,
            )
        } else {
            step_msg.sumcheck_eval_values[1]
        };
        let got_value_2 = f2_value * g2_value;

        end_timer!(timer);
        if claim_2.expected_evaluation != got_value_2 {
            return Err(GKRError::VerifyError("phase2 step2 failed"));
        }

        self.to_next_phase_point_and_evals
            .push(PointAndEval::new_from_ref(&claim2_point, &f2_value));
        self.to_next_step_point_and_eval = PointAndEval::new(claim2_point, g2_value);
        Ok(())
    }

    pub(super) fn verify_and_update_state_phase2_step3(
        &mut self,
        circuit: &Circuit<F>,
        step_msg: IOPProverStepMessage<F>,
        transcript: &mut Transcript<F>,
    ) -> Result<(), GKRError> {
        let timer = start_timer!(|| "Verifier sumcheck phase 2 step 3");
        let layer = &circuit.layers[self.layer_id as usize];
        let lo_out_num_vars = layer.num_vars;
        let lo_in_num_vars = layer.max_previous_num_vars;
        let hi_num_vars = self.instance_num_vars;
        let in_num_vars = lo_in_num_vars + hi_num_vars;

        // sigma = g2(rs2 || rx2) - eq(rt, rs1, rs2) * mul2(ry, rx1, rx2)
        let sumcheck_sigma = self.to_next_step_point_and_eval.eval
            - eq3_eval(
                &self.out_point[lo_out_num_vars..],
                &self.to_next_phase_point_and_evals[0].point[lo_in_num_vars..],
                &self.to_next_phase_point_and_evals[1].point[lo_in_num_vars..],
            ) * layer.mul2s.as_slice().eval(
                &self.eq_y_ry,
                &self.eq_x1_rx1,
                &self.eq_x2_rx2,
                &self.challenges,
            );

        // Sumcheck 3 sigma = \sum_{s3 || x3} f3(s3 || x3) * g3(s3 || x3)
        //     f3(s3 || x3) = layers[i + 1](s3 || x3)
        //     g3(s3 || x3) = eq(rt, rs1, rs2, s3) * mul3(ry, rx1, rx2, x3)
        let claim_3 = SumcheckState::verify(
            sumcheck_sigma,
            &step_msg.sumcheck_proof,
            &VPAuxInfo {
                max_degree: 2,
                num_variables: in_num_vars,
                phantom: std::marker::PhantomData,
            },
            transcript,
        );
        let claim3_point = claim_3.point.iter().map(|x| x.elements).collect_vec();
        let eq_x3_rx3 = build_eq_x_r_vec(&claim3_point[..lo_in_num_vars]);
        let f3_value = step_msg.sumcheck_eval_values[0];
        let g3_value = eq4_eval(
            &&self.out_point[lo_out_num_vars..],
            &self.to_next_phase_point_and_evals[0].point[lo_in_num_vars..],
            &self.to_next_phase_point_and_evals[1].point[lo_in_num_vars..],
            &claim3_point[lo_in_num_vars..],
        ) * layer.mul3s.as_slice().eval(
            &self.eq_y_ry,
            &self.eq_x1_rx1,
            &self.eq_x2_rx2,
            &eq_x3_rx3,
            &self.challenges,
        );

        let got_value_3 = f3_value * g3_value;
        end_timer!(timer);
        if claim_3.expected_evaluation != got_value_3 {
            return Err(GKRError::VerifyError("phase2 step3 failed"));
        }

        self.to_next_phase_point_and_evals
            .push(PointAndEval::new_from_ref(&claim3_point, &f3_value));
        self.to_next_step_point_and_eval = PointAndEval::new(claim3_point, F::ZERO);
        Ok(())
    }
}
