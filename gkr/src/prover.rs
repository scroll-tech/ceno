use ark_std::{end_timer, start_timer};
use ff::FromUniformBytes;
use goldilocks::SmallField;
use itertools::Itertools;
use multilinear_extensions::mle::DenseMultilinearExtension;
use simple_frontend::structs::{CellId, LayerId};
use std::{collections::HashMap, mem, sync::Arc};
use transcript::Transcript;

use crate::structs::{
    Circuit, CircuitWitness, Gate1In, Gate2In, Gate3In, IOPProof, IOPProverPhase1Message,
    IOPProverPhase2Message, IOPProverState, LayerWitness, Point, PointAndEval,
};

mod phase1;
mod phase1_output;
mod phase2;
mod phase2_input;

#[cfg(test)]
mod test;

type SumcheckState<F> = sumcheck::structs::IOPProverState<F>;

impl<F: SmallField + FromUniformBytes<64>> IOPProverState<F> {
    /// Prove process for data parallel circuits.
    pub fn prove_parallel(
        circuit: &Circuit<F>,
        circuit_witness: &CircuitWitness<F::BaseField>,
        wires_out_evals: Vec<PointAndEval<F>>,
        transcript: &mut Transcript<F>,
    ) -> IOPProof<F> {
        let timer = start_timer!(|| "Proving");
        // TODO: Currently haven't support non-power-of-two number of instances.
        assert!(circuit_witness.n_instances == 1 << circuit_witness.instance_num_vars());

        let mut prover_state = Self::prover_init_parallel(circuit_witness, wires_out_evals);

        let sumcheck_proofs = (0..circuit.layers.len() as LayerId)
            .map(|layer_id| {
                let timer = start_timer!(|| format!("Prove layer {}", layer_id));
                prover_state.layer_id = layer_id;

                let phase1_msg = if layer_id == 0 {
                    prover_state.prove_and_update_state_phase1_output_parallel(&circuit, transcript)
                } else {
                    prover_state.prove_and_update_state_phase1_parallel(&circuit, transcript)
                };

                let layer_out_point = match phase1_msg.as_ref() {
                    Some(phase1_msg) => [
                        phase1_msg.sumcheck_proof_1.point.clone(),
                        phase1_msg.sumcheck_proof_2.point.clone(),
                    ]
                    .concat(),
                    None => prover_state.next_layer_point_and_evals[0].point.clone(),
                };

                let phase2_msg = if circuit.is_input_layer(layer_id) {
                    prover_state.prove_and_update_state_phase2_input_parallel(
                        &circuit,
                        &layer_out_point,
                        transcript,
                    )
                } else {
                    prover_state.prove_and_update_state_phase2_parallel(
                        &circuit,
                        &layer_out_point,
                        transcript,
                    )
                };
                end_timer!(timer);
                (phase1_msg, phase2_msg)
            })
            .collect_vec();
        end_timer!(timer);
        IOPProof { sumcheck_proofs }
    }

    /// Initialize proving state for data parallel circuits.
    fn prover_init_parallel(
        circuit_witness: &CircuitWitness<F::BaseField>,
        wires_out_evals: Vec<PointAndEval<F>>,
    ) -> Self {
        let next_layer_point_and_evals = vec![];
        let mut subset_point_and_evals = HashMap::new();
        subset_point_and_evals.entry(0 as LayerId).or_insert(
            wires_out_evals
                .to_vec()
                .into_iter()
                .enumerate()
                .map(|(i, point_and_eval)| (i as LayerId, point_and_eval))
                .collect_vec(),
        );
        Self {
            layer_id: 0,
            next_layer_point_and_evals,
            subset_point_and_evals,
            wit_out_point_and_evals: wires_out_evals,
            circuit_witness: circuit_witness.clone(),
            // Default
            layer_out_poly: Arc::default(),
        }
    }

    /// Prove the items copied from the current layer to later layers for data parallel circuits.
    /// \sum_j( \alpha^j * subset[i][j](rt_j || ry_j) )
    ///     = \sum_y( \sum_j( \alpha^j copy_to[j](ry_j, y) \sum_t( eq(rt_j, t) * layers[i](t || y) ) ) )
    fn prove_and_update_state_phase1_parallel(
        &mut self,
        circuit: &Circuit<F>,
        transcript: &mut Transcript<F>,
    ) -> Option<IOPProverPhase1Message<F>> {
        let layer = &circuit.layers[self.layer_id as usize];
        let lo_num_vars = layer.num_vars;
        let hi_num_vars = self.circuit_witness.instance_num_vars();
        self.layer_out_poly = self
            .circuit_witness
            .layer_poly(self.layer_id, layer.num_vars);
        let next_layer_point_and_evals = &self.next_layer_point_and_evals;
        let subset_point_and_evals = self
            .subset_point_and_evals
            .remove(&self.layer_id)
            .unwrap_or(vec![]);

        if subset_point_and_evals.len() == 0 && next_layer_point_and_evals.len() == 1 {
            return None;
        }

        // TODO: Double check the correctness.
        let alpha = transcript
            .get_and_append_challenge(b"combine subset evals")
            .elements;

        let mut prover_phase1_state = IOPProverPhase1State::prover_init_parallel(
            &self.layer_out_poly,
            &next_layer_point_and_evals,
            &subset_point_and_evals,
            &alpha,
            lo_num_vars,
            hi_num_vars,
        );

        // =============================================================
        // Step 1: First step of copy constraints copied to later layers
        // =============================================================

        // TODO: Need to distinguish the output copy_to and the other layers.
        let (sumcheck_proof_1, eval_value_1) = prover_phase1_state
            .prove_and_update_state_step1_parallel(
                |new_layer_id| &layer.copy_to[new_layer_id],
                transcript,
            );

        // ==============================================================
        // Step 2: Second step of copy constraints copied to later layers
        // ==============================================================

        let (sumcheck_proof_2, eval_value_2) =
            prover_phase1_state.prove_and_update_state_step2_parallel(transcript);

        Some(IOPProverPhase1Message {
            sumcheck_proof_1,
            eval_value_1,
            sumcheck_proof_2,
            eval_value_2,
        })
    }

    /// Prove the items copied from the output layer to the output witness for data parallel circuits.
    /// \sum_j( \alpha^j * subset[i][j](rt_j || ry_j) )
    ///     = \sum_y( \sum_j( \alpha^j copy_to[j](ry_j, y) \sum_t( eq(rt_j, t) * layers[i](t || y) ) ) )
    fn prove_and_update_state_phase1_output_parallel(
        &mut self,
        circuit: &Circuit<F>,
        transcript: &mut Transcript<F>,
    ) -> Option<IOPProverPhase1Message<F>> {
        let layer = &circuit.layers[0];
        let lo_num_vars = layer.num_vars;
        let hi_num_vars = self.circuit_witness.instance_num_vars();
        self.layer_out_poly = self
            .circuit_witness
            .layer_poly(self.layer_id, layer.num_vars);
        let wit_out_point_and_evals = mem::take(&mut self.wit_out_point_and_evals);

        let alpha = transcript
            .get_and_append_challenge(b"combine subset evals")
            .elements;

        let mut prover_phase1_state = IOPProverPhase1OutputState::prover_init_parallel(
            &self.layer_out_poly,
            &wit_out_point_and_evals,
            &alpha,
            circuit.copy_to_wits_out.len() + 1,
            lo_num_vars,
            hi_num_vars,
        );

        // =============================================================
        // Step 1: First step of copy constraints copied to later layers
        // =============================================================

        let (sumcheck_proof_1, eval_value_1) = prover_phase1_state
            .prove_and_update_state_step1_parallel(
                &circuit.copy_to_wits_out,
                &circuit.assert_consts,
                transcript,
            );

        // ==============================================================
        // Step 2: Second step of copy constraints copied to later layers
        // ==============================================================

        let (sumcheck_proof_2, eval_value_2) =
            prover_phase1_state.prove_and_update_state_step2_parallel(transcript);

        Some(IOPProverPhase1Message {
            sumcheck_proof_1,
            eval_value_1,
            sumcheck_proof_2,
            eval_value_2,
        })
    }

    /// Prove the computation in the current layer for data parallel circuits.
    /// The number of terms depends on the gate.
    /// Here is an example of degree 3:
    /// layers[i](rt || ry) = \sum_{s1}( \sum_{s2}( \sum_{s3}( \sum_{x1}( \sum_{x2}( \sum_{x3}(
    ///     eq(rt, s1, s2, s3) * mul3(ry, x1, x2, x3) * layers[i + 1](s1 || x1) * layers[i + 1](s2 || x2) * layers[i + 1](s3 || x3)
    /// ) ) ) ) ) ) + sum_s1( sum_s2( sum_{x1}( sum_{x2}(
    ///     eq(rt, s1, s2) * mul2(ry, x1, x2) * layers[i + 1](s1 || x1) * layers[i + 1](s2 || x2)
    /// ) ) ) ) + \sum_{s1}( \sum_{x1}(
    ///     eq(rt, s1) * add(ry, x1) * layers[i + 1](s1 || x1)
    /// ) ) + \sum_{s1}( \sum_{x1}(
    ///      \sum_j eq(rt, s1) paste_from[j](ry, x1) * subset[j][i](s1 || x1)
    /// ) ) + add_const(ry)
    fn prove_and_update_state_phase2_parallel(
        &mut self,
        circuit: &Circuit<F>,
        layer_out_point: &Point<F>,
        transcript: &mut Transcript<F>,
    ) -> IOPProverPhase2Message<F> {
        self.next_layer_point_and_evals.clear();

        let layer = &circuit.layers[self.layer_id as usize];
        let lo_out_num_vars = layer.num_vars;
        let hi_num_vars = self.circuit_witness.instance_num_vars();

        assert!(lo_out_num_vars + hi_num_vars == layer_out_point.len());

        let mut prover_phase2_state = IOPProverPhase2State::prover_init_parallel(
            &layer,
            &layer_out_point,
            &self.circuit_witness.layers[self.layer_id as usize + 1].instances,
            self.circuit_witness.layers_ref(),
            |c| self.circuit_witness.constant(*c),
            hi_num_vars,
        );

        let mut sumcheck_proofs = vec![];
        let mut sumcheck_eval_values = vec![];

        // ================================================
        // Step 1: First step of arithmetic constraints and
        // copy constraints pasted from previous layers
        // ================================================

        let (sumcheck_proof_1, eval_values_1) = prover_phase2_state
            .prove_and_update_state_step1_parallel(
                |old_layer_id, subset_wire_id| {
                    circuit.layers[old_layer_id]
                        .copy_to
                        .get(&self.layer_id)
                        .unwrap()[subset_wire_id]
                },
                transcript,
            );

        // If the current layers are only pasted from previous layers, then it
        // constains the subset evaluations from previous layers.
        // Otherwise it includes:
        //      - one evaluation of the next layer to be proved.
        //      - evaluations of the pasted subsets.
        //      - one evaluation of g0 to help with the sumcheck.
        let (next_f_values, subset_f_values) = eval_values_1
            .split_at(eval_values_1.len() - 1)
            .0
            .split_at(1);

        for f_value in next_f_values {
            self.next_layer_point_and_evals
                .push(PointAndEval::new_from_ref(&sumcheck_proof_1.point, f_value));
        }
        layer.paste_from.iter().zip(subset_f_values).for_each(
            |((&old_layer_id, _), &subset_value)| {
                self.subset_point_and_evals
                    .entry(old_layer_id)
                    .or_insert_with(Vec::new)
                    .push((
                        self.layer_id,
                        PointAndEval::new_from_ref(
                            &prover_phase2_state.sumcheck_point_1,
                            &subset_value,
                        ),
                    ));
            },
        );

        sumcheck_proofs.push(sumcheck_proof_1);
        sumcheck_eval_values.push(eval_values_1.clone());

        // =============================================
        // Step 2: Second step of arithmetic constraints
        // =============================================

        if layer.mul2s.is_empty() && layer.mul3s.is_empty() {
            return IOPProverPhase2Message {
                sumcheck_proofs,
                sumcheck_eval_values,
            };
        }

        let (sumcheck_proof_2, eval_values_2) =
            prover_phase2_state.prove_and_update_state_step2_parallel(transcript);

        self.next_layer_point_and_evals
            .push(PointAndEval::new_from_ref(
                &sumcheck_proof_2.point,
                &eval_values_2[0],
            ));

        sumcheck_proofs.push(sumcheck_proof_2);
        sumcheck_eval_values.push(eval_values_2);

        // ============================================
        // Step 3: Third step of arithmetic constraints
        // ============================================

        if layer.mul3s.is_empty() {
            return IOPProverPhase2Message {
                sumcheck_proofs,
                sumcheck_eval_values,
            };
        }

        let (sumcheck_proof_3, eval_values_3) =
            prover_phase2_state.prove_and_update_state_step3_parallel(transcript);

        self.next_layer_point_and_evals
            .push(PointAndEval::new_from_ref(
                &sumcheck_proof_3.point,
                &eval_values_3[0],
            ));

        sumcheck_proofs.push(sumcheck_proof_3);
        sumcheck_eval_values.push(eval_values_3);

        IOPProverPhase2Message {
            sumcheck_proofs,
            sumcheck_eval_values,
        }
    }

    /// Refer to [`IOPProverState::prove_and_update_state_phase2_parallel`].
    fn prove_and_update_state_phase2_input_parallel(
        &mut self,
        circuit: &Circuit<F>,
        layer_out_point: &Point<F>,
        transcript: &mut Transcript<F>,
    ) -> IOPProverPhase2Message<F> {
        self.next_layer_point_and_evals.clear();

        let layer = &circuit.layers[self.layer_id as usize];
        let lo_out_num_vars = layer.num_vars;
        let hi_num_vars = self.circuit_witness.instance_num_vars();
        assert!(lo_out_num_vars + hi_num_vars == layer_out_point.len());

        let prover_phase2_state = IOPProverPhase2InputState::prover_init_parallel(
            &layer_out_point,
            self.circuit_witness.witness_in_ref(),
            &circuit.paste_from_wits_in,
            &circuit.paste_from_counter_in,
            layer.num_vars,
            circuit.max_wires_in_num_vars,
            hi_num_vars,
        );

        // We don't allow gates in the input layer.

        assert!(layer.adds.is_empty());
        assert!(layer.mul2s.is_empty());
        assert!(layer.mul3s.is_empty());

        // ===========================================================
        // Step 1: First step of copy constraints pasted from wires_in
        // ===========================================================

        let (sumcheck_proof_1, eval_values_1) =
            prover_phase2_state.prove_and_update_state_input_step1_parallel(transcript);

        IOPProverPhase2Message {
            sumcheck_proofs: vec![sumcheck_proof_1],
            sumcheck_eval_values: vec![eval_values_1],
        }
    }

    // TODO: Define special protocols of special layers for optimization.
}

struct IOPProverPhase1State<'a, F: SmallField> {
    layer_out_poly: &'a Arc<DenseMultilinearExtension<F>>,
    next_layer_point_and_evals: &'a [PointAndEval<F>],
    subset_point_and_evals: &'a [(LayerId, PointAndEval<F>)],
    alpha_pows: Vec<F>,
    lo_num_vars: usize,
    hi_num_vars: usize,
    sumcheck_point_1: Point<F>,
    g1_values: Vec<F>,
}

struct IOPProverPhase1OutputState<'a, F: SmallField> {
    output_points: Vec<Point<F>>,
    layer_out_poly: &'a Arc<DenseMultilinearExtension<F>>,
    subset_point_and_evals: &'a [PointAndEval<F>],
    alpha_pows: Vec<F>,
    lo_num_vars: usize,
    hi_num_vars: usize,
    sumcheck_point_1: Point<F>,
    g1_values: Vec<F>,
}

struct IOPProverPhase2State<'a, F: SmallField> {
    layer_in_poly: Arc<DenseMultilinearExtension<F>>,
    layer_in_vec: &'a [Vec<F::BaseField>],
    mul3s: Vec<Gate3In<F::BaseField>>,
    mul2s: Vec<Gate2In<F::BaseField>>,
    adds: Vec<Gate1In<F::BaseField>>,
    paste_from: &'a HashMap<LayerId, Vec<CellId>>,
    paste_from_sources: &'a [LayerWitness<F::BaseField>],
    lo_out_num_vars: usize,
    lo_in_num_vars: usize,
    hi_num_vars: usize,

    sumcheck_point_1: Point<F>,
    sumcheck_point_2: Point<F>,

    tensor_eq_ty_rtry: Vec<F>,

    eq_x1_rx1: Vec<F>,
    eq_s1_rs1: Vec<F>,
    tensor_eq_s1x1_rs1rx1: Vec<F>,

    eq_x2_rx2: Vec<F>,
    eq_s2_rs2: Vec<F>,
    tensor_eq_s2x2_rs2rx2: Vec<F>,
}

struct IOPProverPhase2InputState<'a, F: SmallField> {
    layer_out_point: &'a Point<F>,
    paste_from_wits_in: &'a [(CellId, CellId)],
    paste_from_counter_in: &'a [(usize, (CellId, CellId))],
    wits_in: &'a [LayerWitness<F::BaseField>],
    lo_out_num_vars: usize,
    lo_in_num_vars: Option<usize>,
    hi_num_vars: usize,
}
