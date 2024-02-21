use ark_std::{end_timer, start_timer};
use goldilocks::SmallField;
use itertools::Itertools;
use simple_frontend::structs::{ChallengeConst, LayerId};
use std::collections::HashMap;
use transcript::Transcript;

use crate::{
    error::GKRError,
    structs::{
        Circuit, GKRInputClaims, IOPProof, IOPVerifierState, PointAndEval, SumcheckStepType,
    },
};

mod phase1;
mod phase1_output;
mod phase2;
mod phase2_input;
mod phase2_linear;

type SumcheckState<F> = sumcheck::structs::IOPVerifierState<F>;

impl<F: SmallField> IOPVerifierState<F> {
    /// Verify process for data parallel circuits.
    pub fn verify_parallel(
        circuit: &Circuit<F>,
        challenges: &[F],
        output_evals: Vec<PointAndEval<F>>,
        wires_out_evals: Vec<PointAndEval<F>>,
        proof: IOPProof<F>,
        instance_num_vars: usize,
        transcript: &mut Transcript<F>,
    ) -> Result<GKRInputClaims<F>, GKRError> {
        let timer = start_timer!(|| "Verification");
        let challenges = circuit.generate_basefield_challenges(challenges);

        let mut verifier_state = Self::verifier_init_parallel(
            circuit.layers.len(),
            challenges,
            output_evals,
            wires_out_evals,
            instance_num_vars,
            transcript,
            circuit.layers[0].num_vars + instance_num_vars,
        );

        let mut step_proof_iter = proof.sumcheck_proofs.into_iter();
        for layer_id in 0..circuit.layers.len() {
            let timer = start_timer!(|| format!("Verify layer {}", layer_id));
            verifier_state.layer_id = layer_id as LayerId;

            let layer = &circuit.layers[layer_id as usize];
            for step in layer.sumcheck_steps.iter() {
                let step_msg = step_proof_iter
                    .next()
                    .ok_or(GKRError::VerifyError("Wrong number of step proofs"))?;
                match step {
                    SumcheckStepType::OutputPhase1Step1 => verifier_state
                        .verify_and_update_state_output_phase1_step1(
                            circuit, step_msg, transcript,
                        )?,
                    SumcheckStepType::OutputPhase1Step2 => verifier_state
                        .verify_and_update_state_output_phase1_step2(
                            circuit, step_msg, transcript,
                        )?,
                    SumcheckStepType::Phase1Step1 => verifier_state
                        .verify_and_update_state_phase1_step1(circuit, step_msg, transcript)?,
                    SumcheckStepType::Phase1Step2 => verifier_state
                        .verify_and_update_state_phase1_step2(circuit, step_msg, transcript)?,
                    SumcheckStepType::Phase2Step1 => verifier_state
                        .verify_and_update_state_phase2_step1(circuit, step_msg, transcript)?,
                    SumcheckStepType::Phase2Step2 => verifier_state
                        .verify_and_update_state_phase2_step2(
                            circuit, step_msg, transcript, false,
                        )?,
                    SumcheckStepType::Phase2Step2NoStep3 => verifier_state
                        .verify_and_update_state_phase2_step2(
                            circuit, step_msg, transcript, true,
                        )?,
                    SumcheckStepType::Phase2Step3 => verifier_state
                        .verify_and_update_state_phase2_step3(circuit, step_msg, transcript)?,
                    SumcheckStepType::LinearPhase2Step1 => verifier_state
                        .verify_and_update_state_linear_phase2_step1(
                            circuit, step_msg, transcript,
                        )?,
                    SumcheckStepType::InputPhase2Step1 => verifier_state
                        .verify_and_update_state_input_phase2_step1(
                            circuit, step_msg, transcript,
                        )?,
                }
            }
            end_timer!(timer);
        }

        end_timer!(timer);

        Ok(GKRInputClaims {
            point_and_evals: verifier_state.to_next_phase_point_and_evals,
        })
    }

    /// Initialize verifying state for data parallel circuits.
    fn verifier_init_parallel(
        n_layers: usize,
        challenges: HashMap<ChallengeConst, Vec<F::BaseField>>,
        output_evals: Vec<PointAndEval<F>>,
        wires_out_evals: Vec<PointAndEval<F>>,
        instance_num_vars: usize,
        transcript: &mut Transcript<F>,
        output_wit_num_vars: usize,
    ) -> Self {
        let mut subset_point_and_evals = vec![vec![]; n_layers];
        let to_next_step_point_and_eval = if !output_evals.is_empty() {
            output_evals.last().unwrap().clone()
        } else {
            wires_out_evals.last().unwrap().clone()
        };
        let assert_point = (0..output_wit_num_vars)
            .map(|_| {
                transcript
                    .get_and_append_challenge(b"assert_point")
                    .elements
            })
            .collect_vec();
        let to_next_phase_point_and_evals = output_evals;
        subset_point_and_evals[0] = wires_out_evals.into_iter().map(|p| (0, p)).collect();
        Self {
            to_next_phase_point_and_evals,
            subset_point_and_evals,
            to_next_step_point_and_eval,

            challenges,
            instance_num_vars,

            assert_point,
            // Default
            layer_id: 0,
            g1_values: vec![],
            out_point: vec![],
            eq_y_ry: vec![],
            eq_x1_rx1: vec![],
            eq_x2_rx2: vec![],
        }
    }
}
