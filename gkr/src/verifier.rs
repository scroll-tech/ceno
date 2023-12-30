use std::collections::HashMap;

use ark_std::{end_timer, start_timer};
use ff::FromUniformBytes;
use frontend::structs::ConstantType;
use goldilocks::SmallField;
use itertools::Itertools;

use transcript::Transcript;

use crate::{
    circuit::EvaluateGateCIn,
    error::GKRError,
    structs::{
        Circuit, GKRInputClaims, Gate1In, Gate2In, Gate3In, GateCIn, IOPProof,
        IOPProverPhase1Message, IOPProverPhase2Message, IOPVerifierState, Layer, Point,
    },
};

mod phase1;
mod phase2;

type SumcheckState<F> = sumcheck::structs::IOPVerifierState<F>;

impl<F: SmallField + FromUniformBytes<64>> IOPVerifierState<F> {
    /// Verify process for data parallel circuits.
    pub fn verify_parallel(
        circuit: &Circuit<F>,
        challenges: &[F],
        output_point: &Point<F>,
        output_value: &F,
        wires_out_points: &[&Point<F>],
        wires_out_values: &[F],
        proof: &IOPProof<F>,
        instance_num_vars: usize,
        transcript: &mut Transcript<F>,
    ) -> Result<GKRInputClaims<F>, GKRError> {
        let timer = start_timer!(|| "Verification");
        assert_eq!(wires_out_points.len(), wires_out_values.len());
        assert_eq!(wires_out_points.len(), circuit.output_copy_to.len());

        let mut verifier_state = Self::verifier_init_parallel(
            output_point,
            output_value,
            wires_out_points,
            wires_out_values,
        );
        for layer_id in 0..circuit.layers.len() {
            let timer = start_timer!(|| format!("Verify layer {}", layer_id));
            verifier_state.layer_id = layer_id;

            let layer = &circuit.layers[layer_id];
            let (phase1_msg, phase2_msg) = &proof.sumcheck_proofs[layer_id];
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

            verifier_state.verify_and_update_state_phase2_parallel(
                &circuit,
                &challenges,
                &layer_out_point,
                &layer_out_value,
                &phase2_msg,
                transcript,
            )?;
            end_timer!(timer);
        }

        let (_, input_phase2_msg) = proof.sumcheck_proofs.last().unwrap();
        let point = input_phase2_msg
            .sumcheck_proofs
            .last()
            .unwrap()
            .point
            .clone();
        let mut values = vec![F::ZERO; verifier_state.subset_evals.len()];
        verifier_state
            .subset_evals
            .iter()
            .for_each(|(id, subset_evals)| {
                assert_eq!(subset_evals.len(), 1);
                assert_eq!(subset_evals[0].0, circuit.layers.len() - 1);
                assert_eq!(subset_evals[0].1, point);
                values[*id] = subset_evals[0].2;
            });
        end_timer!(timer);
        Ok(GKRInputClaims { point, values })
    }

    /// Initialize verifying state for data parallel circuits.
    fn verifier_init_parallel(
        output_point: &Point<F>,
        output_value: &F,
        wires_out_points: &[&Point<F>],
        wires_out_values: &[F],
    ) -> Self {
        let next_evals = vec![(output_point.clone(), *output_value)];
        let mut subset_evals = HashMap::new();
        subset_evals.entry(0usize).or_insert(
            wires_out_points
                .iter()
                .zip(wires_out_values.iter())
                .enumerate()
                .map(|(i, (&point, &value))| (i, point.clone(), value))
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
            &alpha.elements[0],
            lo_num_vars,
            hi_num_vars,
        );

        // =============================================================
        // Step 1: First step of copy constraints copied to later layers
        // =============================================================

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

        let layer = &circuit.layers[self.layer_id];
        let lo_out_num_vars = layer.num_vars;
        let hi_out_num_vars = layer_out_point.len() - lo_out_num_vars;
        let is_input_layer = self.layer_id == circuit.layers.len() - 1;

        let mut verifier_phase2_state = IOPVerifierPhase2State::verifier_init_parallel(
            layer,
            layer_out_point,
            layer_out_value,
            |c| match *c {
                ConstantType::Field(x) => x,
                ConstantType::Challenge(i) => challenges[i],
            },
            hi_out_num_vars,
            is_input_layer,
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
        let (next_f_values, subset_f_values) = if is_input_layer {
            sumcheck_eval_values[0].split_at(0)
        } else {
            sumcheck_eval_values[0]
                .split_at(sumcheck_eval_values[0].len() - 1)
                .0
                .split_at(1)
        };
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
}

struct IOPVerifierPhase1State<'a, F: SmallField> {
    next_evals: &'a [(Point<F>, F)],
    subset_evals: &'a [(usize, Point<F>, F)],
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
    is_input_layer: bool,

    mul3s: Vec<Gate3In<F>>,
    mul2s: Vec<Gate2In<F>>,
    adds: Vec<Gate1In<F>>,
    add_consts: Vec<GateCIn<F>>,
    assert_consts: Vec<GateCIn<F>>,
    paste_from: &'a HashMap<usize, Vec<usize>>,
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
