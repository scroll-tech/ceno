use ark_std::{end_timer, start_timer};
use ff_ext::ExtensionField;
use itertools::{Itertools, chain, izip};
use multilinear_extensions::virtual_poly::{VPAuxInfo, build_eq_x_r_vec};
use std::{iter, mem};
use transcript::Transcript;

use crate::{
    circuit::{EvaluateGate1In, EvaluateGateCIn},
    error::GKRError,
    structs::{Circuit, IOPProverStepMessage, IOPVerifierState, PointAndEval},
    utils::MatrixMLEColumnFirst,
};

use super::SumcheckState;

impl<E: ExtensionField> IOPVerifierState<E> {
    pub(super) fn verify_and_update_state_linear_phase2_step1(
        &mut self,
        circuit: &Circuit<E>,
        step_msg: IOPProverStepMessage<E>,
        transcript: &mut Transcript<E>,
    ) -> Result<(), GKRError> {
        let timer = start_timer!(|| "Verifier sumcheck phase 2 step 1");
        let layer = &circuit.layers[self.layer_id as usize];
        let lo_out_num_vars = layer.num_vars;
        let lo_in_num_vars = layer.max_previous_num_vars;

        self.out_point = mem::take(&mut self.to_next_step_point_and_eval.point);
        let lo_point = &self.out_point[..lo_out_num_vars];

        self.eq_y_ry = build_eq_x_r_vec(lo_point);

        // sigma = layers[i](rt || ry) - add_const(ry),
        let sumcheck_sigma = self.to_next_step_point_and_eval.eval
            - layer
                .add_consts
                .as_slice()
                .eval(&self.eq_y_ry, &self.challenges);

        // Sumcheck 1: sigma = \sum_{x1} f1(x1) * g1(x1) + \sum_j f1'_j(x1) * g1'_j(x1)
        //     sigma = layers[i](rt || ry) - add_const(ry),
        //     f1(x1) = layers[i + 1](rt || x1)
        //     g1(x1) = add(ry, x1)
        //     f1'^{(j)}(x1) = subset[j][i](rt || x1)
        //     g1'^{(j)}(x1) = paste_from[j](ry, x1)
        let claim_1 = SumcheckState::verify(
            sumcheck_sigma,
            &step_msg.sumcheck_proof,
            &VPAuxInfo {
                max_degree: 2,
                num_variables: lo_in_num_vars,
                phantom: std::marker::PhantomData,
            },
            transcript,
        );
        let claim1_point = claim_1.point.iter().map(|x| x.elements).collect_vec();

        self.eq_x1_rx1 = build_eq_x_r_vec(&claim1_point[..lo_in_num_vars]);
        let g1_values_iter = chain![
            iter::once(layer.adds.as_slice().eval(
                &self.eq_y_ry,
                &self.eq_x1_rx1,
                &self.challenges
            )),
            layer.paste_from.values().map(|paste_from| {
                paste_from
                    .as_slice()
                    .eval_col_first(&self.eq_y_ry, &self.eq_x1_rx1)
            })
        ];

        let f1_values = &step_msg.sumcheck_eval_values;
        let got_value_1 =
            izip!(f1_values.iter(), g1_values_iter).fold(E::ZERO, |acc, (&f1, g1)| acc + f1 * g1);

        end_timer!(timer);
        if claim_1.expected_evaluation != got_value_1 {
            return Err(GKRError::VerifyError("phase2 step1 failed"));
        }

        let new_point = [&claim1_point, &self.out_point[lo_out_num_vars..]].concat();
        self.to_next_phase_point_and_evals =
            vec![PointAndEval::new_from_ref(&new_point, &f1_values[0])];
        izip!(layer.paste_from.iter(), f1_values.iter().skip(1)).for_each(
            |((&old_layer_id, _), &subset_value)| {
                self.subset_point_and_evals[old_layer_id as usize].push((
                    self.layer_id,
                    PointAndEval::new_from_ref(&new_point, &subset_value),
                ));
            },
        );
        self.to_next_step_point_and_eval = self.to_next_phase_point_and_evals[0].clone();

        Ok(())
    }
}
