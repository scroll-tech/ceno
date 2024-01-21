use std::collections::HashMap;

use ark_std::{end_timer, start_timer};
use frontend::structs::{CellId, ConstantType, LayerId};
use goldilocks::SmallField;
use itertools::Itertools;

use transcript::Transcript;

use crate::{
    error::GKRError,
    structs::{
        Circuit, GKRInputClaims, Gate1In, Gate2In, Gate3In, GateCIn, IOPProof,
        IOPProverPhase1Message, IOPProverPhase2Message, IOPVerifierState, Layer, Point,
    },
};

mod phase1;
mod phase2;
mod phase2_input;

type SumcheckState<F> = sumcheck::structs::IOPVerifierState<F>;

impl<F: SmallField> IOPVerifierState<F> {
    /// Verify process for data parallel circuits.
    pub fn verify_parallel(
        circuit: &Circuit<F>,
        challenges: &[F],
        output_evals: &[(Point<F>, F)],
        wires_out_evals: &[(Point<F>, F)],
        proof: &IOPProof<F>,
        instance_num_vars: usize,
        transcript: &mut Transcript<F>,
    ) -> Result<GKRInputClaims<F>, GKRError> {
        let timer = start_timer!(|| "Verification");
        assert_eq!(wires_out_evals.len(), circuit.copy_to_wires_out.len());

        let mut verifier_state = Self::verifier_init_parallel(output_evals, wires_out_evals);
        for layer_id in 0..circuit.layers.len() as LayerId {
            let timer = start_timer!(|| format!("Verify layer {}", layer_id));
            verifier_state.layer_id = layer_id;

            let layer = &circuit.layers[layer_id as usize];
            let (phase1_msg, phase2_msg) = &proof.sumcheck_proofs[layer_id as usize];
            let (layer_out_point, layer_out_value) = match phase1_msg {
                Some(phase1_msg) => {
                    verifier_state.verify_and_update_state_phase1_parallel(
                        layer,
                        &phase1_msg,
                        instance_num_vars,
                        transcript,
                    )?;
                    (
                        [
                            phase1_msg.sumcheck_proof_1.point.clone(),
                            phase1_msg.sumcheck_proof_2.point.clone(),
                        ]
                        .concat(),
                        phase1_msg.eval_value_2,
                    )
                }
                None => (
                    verifier_state.next_evals[0].0.clone(),
                    verifier_state.next_evals[0].1,
                ),
            };

            if circuit.is_input_layer(layer_id) {
                verifier_state.verify_and_update_state_phase2_input_parallel(
                    circuit,
                    &layer_out_point,
                    &layer_out_value,
                    &phase2_msg,
                    transcript,
                )?;
            } else {
                verifier_state.verify_and_update_state_phase2_parallel(
                    &circuit,
                    &challenges,
                    &layer_out_point,
                    &layer_out_value,
                    &phase2_msg,
                    transcript,
                )?;
            }
            end_timer!(timer);
        }

        let (_, input_phase2_msg) = proof.sumcheck_proofs.last().unwrap();
        let point = input_phase2_msg.sumcheck_proofs[0].point.clone();
        end_timer!(timer);
        Ok(GKRInputClaims {
            point,
            values: input_phase2_msg.sumcheck_eval_values[0].clone(),
        })
    }

    /// Initialize verifying state for data parallel circuits.
    fn verifier_init_parallel(
        output_evals: &[(Point<F>, F)],
        wires_out_evals: &[(Point<F>, F)],
    ) -> Self {
        let next_evals = output_evals.to_vec();
        let mut subset_evals = HashMap::new();
        subset_evals.entry(0).or_insert(
            wires_out_evals
                .to_vec()
                .into_iter()
                .enumerate()
                .map(|(i, (point, value))| (i as LayerId, point.clone(), value))
                .collect_vec(),
        );
        Self {
            layer_id: 0,
            next_evals,
            subset_evals,
        }
    }

    /// Verify the items in the i-th layer are copied to deeper layers for data
    /// parallel circuits.
    fn verify_and_update_state_phase1_parallel(
        &mut self,
        layer: &Layer<F>,
        prover_msg: &IOPProverPhase1Message<F>,
        hi_num_vars: usize,
        transcript: &mut Transcript<F>,
    ) -> Result<(), GKRError> {
        let lo_num_vars = layer.num_vars;
        let next_evals = &self.next_evals;
        let subset_evals = self.subset_evals.remove(&self.layer_id).unwrap_or(vec![]);

        let alpha = transcript.get_and_append_challenge(b"combine subset evals");

        if subset_evals.len() == 0 && next_evals.len() == 1 {
            return Ok(());
        }

        let mut verifier_phase1_state = IOPVerifierPhase1State::verifier_init_parallel(
            &next_evals,
            &subset_evals,
            &alpha.elements,
            lo_num_vars,
            hi_num_vars,
        );

        // =============================================================
        // Step 1: First step of copy constraints copied to later layers
        // =============================================================

        // TODO: Double check the correctness.
        verifier_phase1_state.verify_and_update_state_step1_parallel(
            (&prover_msg.sumcheck_proof_1, &prover_msg.eval_value_1),
            |new_layer_id| &layer.copy_to[new_layer_id],
            transcript,
        )?;

        // ==============================================================
        // Step 2: Second step of copy constraints copied to later layers
        // ==============================================================

        verifier_phase1_state.verify_and_update_state_step2_parallel(
            (&prover_msg.sumcheck_proof_2, prover_msg.eval_value_2),
            transcript,
        )
    }

    /// Verify the computation in the current layer for data parallel circuits.
    /// The number of terms depends on the gate.
    fn verify_and_update_state_phase2_parallel(
        &mut self,
        circuit: &Circuit<F>,
        challenges: &[F],
        layer_out_point: &Point<F>,
        layer_out_value: &F,
        prover_msg: &IOPProverPhase2Message<F>,
        transcript: &mut Transcript<F>,
    ) -> Result<(), GKRError> {
        self.next_evals.clear();

        let layer = &circuit.layers[self.layer_id as usize];
        let lo_out_num_vars = layer.num_vars;
        let hi_out_num_vars = layer_out_point.len() - lo_out_num_vars;

        let mut verifier_phase2_state = IOPVerifierPhase2State::verifier_init_parallel(
            layer,
            layer_out_point,
            layer_out_value,
            |c| match *c {
                ConstantType::Field(x) => x,
                ConstantType::Challenge(i) => challenges[i],
                ConstantType::Challenge2(i) => challenges[i] * challenges[i],
                ConstantType::Challenge3(i) => challenges[i] * challenges[i] * challenges[i],
                ConstantType::Challenge4(i) => {
                    let tmp = challenges[i] * challenges[i];
                    tmp * tmp
                }
            },
            hi_out_num_vars,
        );

        // =============================
        // Step 0: Assertion constraints
        // =============================

        // sigma = layers[i](rt || ry) - assert_const(ry)
        let (sumcheck_proofs, sumcheck_eval_values) = {
            if !layer.assert_consts.is_empty() {
                verifier_phase2_state.verify_and_update_state_step0_parallel(
                    (
                        &prover_msg.sumcheck_proofs[0],
                        &prover_msg.sumcheck_eval_values[0],
                    ),
                    transcript,
                )?;
                (
                    &prover_msg.sumcheck_proofs[1..],
                    &prover_msg.sumcheck_eval_values[1..],
                )
            } else {
                (
                    &prover_msg.sumcheck_proofs[..],
                    &prover_msg.sumcheck_eval_values[..],
                )
            }
        };

        // ================================================
        // Step 1: First step of arithmetic constraints and
        // copy constraints pasted from previous layers
        // ================================================

        verifier_phase2_state.verify_and_update_state_step1_parallel(
            (&sumcheck_proofs[0], &sumcheck_eval_values[0]),
            transcript,
        )?;

        // If it's the input layer, then eval_values_1 are evaluations of the wires_in and other_witnesses.
        // Otherwise it includes:
        //      - one evaluation of the next layer to be proved.
        //      - evaluations of the pasted subsets.
        //      - one evaluation of g0 to help with the sumcheck.
        let (next_f_values, subset_f_values) = sumcheck_eval_values[0]
            .split_at(sumcheck_eval_values[0].len() - 1)
            .0
            .split_at(1);

        for f_value in next_f_values {
            self.next_evals
                .push((verifier_phase2_state.sumcheck_point_1.clone(), *f_value));
        }
        layer
            .paste_from
            .iter()
            .zip(subset_f_values.iter())
            .for_each(|((&old_layer_id, _), &subset_value)| {
                self.subset_evals
                    .entry(old_layer_id)
                    .or_insert_with(Vec::new)
                    .push((
                        self.layer_id,
                        verifier_phase2_state.sumcheck_point_1.clone().clone(),
                        subset_value,
                    ));
            });

        // =============================================
        // Step 2: Second step of arithmetic constraints
        // =============================================

        if layer.mul2s.is_empty() && layer.mul3s.is_empty() {
            return Ok(());
        }

        verifier_phase2_state.verify_and_update_state_step2_parallel(
            (&sumcheck_proofs[1], &sumcheck_eval_values[1]),
            transcript,
        )?;

        self.next_evals.push((
            verifier_phase2_state.sumcheck_point_2.clone(),
            sumcheck_eval_values[1][0],
        ));

        // ============================================
        // Step 3: Third step of arithmetic constraints
        // ============================================

        if layer.mul3s.is_empty() {
            return Ok(());
        }

        verifier_phase2_state.verify_and_update_state_step3_parallel(
            (&sumcheck_proofs[2], &sumcheck_eval_values[2]),
            transcript,
        )?;
        self.next_evals.push((
            verifier_phase2_state.sumcheck_point_3.clone(),
            sumcheck_eval_values[2][0],
        ));

        Ok(())
    }

    fn verify_and_update_state_phase2_input_parallel(
        &mut self,
        circuit: &Circuit<F>,
        layer_out_point: &Point<F>,
        layer_out_value: &F,
        prover_msg: &IOPProverPhase2Message<F>,
        transcript: &mut Transcript<F>,
    ) -> Result<(), GKRError> {
        self.next_evals.clear();

        let layer = &circuit.layers[self.layer_id as usize];
        let lo_out_num_vars = layer.num_vars;
        let lo_in_num_vars = circuit.max_wires_in_num_vars;
        let hi_out_num_vars = layer_out_point.len() - lo_out_num_vars;

        let verifier_phase2_state = IOPVerifierPhase2InputState::verifier_init_parallel(
            circuit.n_wires_in,
            layer_out_point,
            *layer_out_value,
            &circuit.paste_from_in,
            layer.num_vars,
            lo_in_num_vars,
            hi_out_num_vars,
        );

        if !layer.assert_consts.is_empty()
            || !layer.add_consts.is_empty()
            || !layer.adds.is_empty()
            || !layer.mul2s.is_empty()
            || !layer.mul3s.is_empty()
        {
            return Err(GKRError::InvalidCircuit);
        }

        // ===========================================================
        // Step 1: First step of copy constraints pasted from wires_in
        // ===========================================================

        verifier_phase2_state.verify_and_update_state_input_step1_parallel(
            (
                &prover_msg.sumcheck_proofs[0],
                &prover_msg.sumcheck_eval_values[0],
            ),
            transcript,
        )?;

        Ok(())
    }
}

struct IOPVerifierPhase1State<'a, F: SmallField> {
    next_evals: &'a [(Point<F>, F)],
    subset_evals: &'a [(LayerId, Point<F>, F)],
    alpha_pows: Vec<F>,
    lo_num_vars: usize,
    hi_num_vars: usize,
    f1_values: Vec<F>,
    g1_values: Vec<F>,

    sumcheck_sigma: F,
}

struct IOPVerifierPhase2State<'a, F: SmallField> {
    layer_out_point: Point<F>,
    layer_out_value: F,

    mul3s: Vec<Gate3In<F>>,
    mul2s: Vec<Gate2In<F>>,
    adds: Vec<Gate1In<F>>,
    add_consts: Vec<GateCIn<F>>,
    assert_consts: Vec<GateCIn<F>>,
    paste_from: &'a HashMap<LayerId, Vec<CellId>>,
    lo_out_num_vars: usize,
    lo_in_num_vars: usize,
    hi_num_vars: usize,

    sumcheck_sigma: F,
    sumcheck_point_1: Point<F>,
    sumcheck_point_2: Point<F>,
    sumcheck_point_3: Point<F>,

    eq_y_ry: Vec<F>,
    eq_x1_rx1: Vec<F>,
    eq_x2_rx2: Vec<F>,
}

struct IOPVerifierPhase2InputState<'a, F: SmallField> {
    layer_out_point: &'a Point<F>,
    layer_out_value: F,
    paste_from_wires_in: Vec<(CellId, CellId)>,
    paste_from_counter_in: Vec<(CellId, CellId)>,
    paste_from_const_in: Vec<(F, CellId, CellId)>,
    lo_out_num_vars: usize,
    lo_in_num_vars: usize,
    hi_num_vars: usize,
}
