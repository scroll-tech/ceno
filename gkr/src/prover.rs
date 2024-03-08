use ark_std::{end_timer, start_timer};
use ff::FromUniformBytes;
use goldilocks::SmallField;
use itertools::Itertools;
use simple_frontend::structs::LayerId;
use std::sync::Arc;
use transcript::Transcript;

use crate::structs::{
    Circuit, CircuitWitness, GKRInputClaims, IOPProof, IOPProverState, PointAndEval,
    SumcheckStepType,
};

mod phase1;
mod phase1_output;
mod phase2;
mod phase2_input;
mod phase2_linear;

#[cfg(test)]
mod test;

type SumcheckState<F> = sumcheck::structs::IOPProverState<F>;

impl<F: SmallField + FromUniformBytes<64>> IOPProverState<F> {
    /// Prove process for data parallel circuits.
    pub fn prove_parallel(
        circuit: &Circuit<F>,
        circuit_witness: &CircuitWitness<F::BaseField>,
        output_evals: Vec<PointAndEval<F>>,
        wires_out_evals: Vec<PointAndEval<F>>,
        transcript: &mut Transcript<F>,
    ) -> (IOPProof<F>, GKRInputClaims<F>) {
        let timer = start_timer!(|| "Proving");
        // TODO: Currently haven't support non-power-of-two number of instances.
        assert!(circuit_witness.n_instances == 1 << circuit_witness.instance_num_vars());

        let mut prover_state = Self::prover_init_parallel(
            circuit.layers.len(),
            output_evals,
            wires_out_evals,
            transcript,
            circuit.layers[0].num_vars + circuit_witness.instance_num_vars(),
        );

        let sumcheck_proofs = (0..circuit.layers.len() as LayerId)
            .map(|layer_id| {
                let timer = start_timer!(|| format!("Prove layer {}", layer_id));
                prover_state.layer_id = layer_id;

                let proofs = circuit.layers[layer_id as usize]
                    .sumcheck_steps
                    .iter()
                    .map(|step| match step {
                        SumcheckStepType::OutputPhase1Step1 => prover_state
                            .prove_and_update_state_output_phase1_step1(
                                circuit,
                                circuit_witness,
                                transcript,
                            ),
                        SumcheckStepType::OutputPhase1Step2 => prover_state
                            .prove_and_update_state_output_phase1_step2(
                                circuit,
                                circuit_witness,
                                transcript,
                            ),
                        SumcheckStepType::Phase1Step1 => prover_state
                            .prove_and_update_state_phase1_step1(
                                circuit,
                                circuit_witness,
                                transcript,
                            ),
                        SumcheckStepType::Phase1Step2 => prover_state
                            .prove_and_update_state_phase1_step2(
                                circuit,
                                circuit_witness,
                                transcript,
                            ),
                        SumcheckStepType::Phase2Step1 => prover_state
                            .prove_and_update_state_phase2_step1(
                                circuit,
                                circuit_witness,
                                transcript,
                            ),
                        SumcheckStepType::Phase2Step2 => prover_state
                            .prove_and_update_state_phase2_step2(
                                circuit,
                                circuit_witness,
                                transcript,
                                false,
                            ),
                        SumcheckStepType::Phase2Step2NoStep3 => prover_state
                            .prove_and_update_state_phase2_step2(
                                circuit,
                                circuit_witness,
                                transcript,
                                true,
                            ),
                        SumcheckStepType::Phase2Step3 => prover_state
                            .prove_and_update_state_phase2_step3(
                                circuit,
                                circuit_witness,
                                transcript,
                            ),
                        SumcheckStepType::LinearPhase2Step1 => prover_state
                            .prove_and_update_state_linear_phase2_step1(
                                circuit,
                                circuit_witness,
                                transcript,
                            ),
                        SumcheckStepType::InputPhase2Step1 => prover_state
                            .prove_and_update_state_input_phase2_step1(
                                circuit,
                                circuit_witness,
                                transcript,
                            ),
                    })
                    .collect_vec();
                end_timer!(timer);
                proofs
            })
            .flatten()
            .collect_vec();
        end_timer!(timer);

        (
            IOPProof { sumcheck_proofs },
            GKRInputClaims {
                point_and_evals: prover_state.to_next_phase_point_and_evals,
            },
        )
    }

    /// Initialize proving state for data parallel circuits.
    fn prover_init_parallel(
        n_layers: usize,
        output_evals: Vec<PointAndEval<F>>,
        wires_out_evals: Vec<PointAndEval<F>>,
        transcript: &mut Transcript<F>,
        output_wit_num_vars: usize,
    ) -> Self {
        let mut subset_point_and_evals = vec![vec![]; n_layers];
        let to_next_step_point = if !output_evals.is_empty() {
            output_evals.last().unwrap().point.clone()
        } else {
            wires_out_evals.last().unwrap().point.clone()
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
            to_next_step_point,

            assert_point,
            // Default
            layer_id: 0,
            layer_poly: Arc::default(),
            g1_values: vec![],
            tensor_eq_ty_rtry: vec![],
            tensor_eq_s1x1_rs1rx1: vec![],
            tensor_eq_s2x2_rs2rx2: vec![],
        }
    }
}
