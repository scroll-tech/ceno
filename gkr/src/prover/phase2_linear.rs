use std::sync::Arc;

use ark_std::{end_timer, start_timer};
use ff::Field;
use ff_ext::ExtensionField;
use itertools::{izip, Itertools};
use multilinear_extensions::{
    mle::DenseMultilinearExtension,
    virtual_poly::{build_eq_x_r_vec, VirtualPolynomial},
};
use transcript::Transcript;

use crate::{
    circuit::EvaluateConstant,
    structs::{Circuit, CircuitWitness, IOPProverState, IOPProverStepMessage, PointAndEval},
    utils::MultilinearExtensionFromVectors,
};

use super::SumcheckState;

// Prove the computation in the current layer for data parallel circuits.
// The number of terms depends on the gate.
// Here is an example of degree 3:
// layers[i](rt || ry) = \sum_x(
//     add(ry, x) * layers[i + 1](rt || x) + \sum_j  paste_from[j](ry, x) * subset[j][i](rt || x)
// ) + add_const(ry)
impl<E: ExtensionField> IOPProverState<E> {
    /// Sumcheck 1: sigma = \sum_{x1} f1(x1) * g1(x1) + \sum_j f1'_j(x1) * g1'_j(x1)
    ///     sigma = layers[i](rt || ry) - add_const(ry),
    ///     f1(x1) = layers[i + 1](rt || x1)
    ///     g1(x1) = add(ry, x1)
    ///     f1'^{(j)}(x1) = subset[j][i](rt || x1)
    ///     g1'^{(j)}(x1) = paste_from[j](ry, x1)
    #[tracing::instrument(skip_all, name = "prove_and_update_state_linear_phase2_step1")]
    pub(super) fn prove_and_update_state_linear_phase2_step1(
        &mut self,
        circuit: &Circuit<E>,
        circuit_witness: &CircuitWitness<E::BaseField>,
        transcript: &mut Transcript<E>,
    ) -> IOPProverStepMessage<E> {
        let timer = start_timer!(|| "Prover sumcheck phase 2 step 1");
        let layer = &circuit.layers[self.layer_id as usize];
        let lo_out_num_vars = layer.num_vars;
        let lo_in_num_vars = layer.max_previous_num_vars;
        let hi_num_vars = circuit_witness.instance_num_vars();
        let hi_point = &self.to_next_step_point[lo_out_num_vars..];

        let eq_y_ry = build_eq_x_r_vec(&self.to_next_step_point[..lo_out_num_vars]);

        let challenges = &circuit_witness.challenges;

        let f1_g1 = || {
            // f1(x1) = layers[i + 1](rt || x1)
            let layer_in_vec = circuit_witness.layers[self.layer_id as usize + 1].instances.as_slice();
            let mut f1 = layer_in_vec.mle(lo_in_num_vars, hi_num_vars);
            Arc::make_mut(&mut f1).fix_high_variables_in_place(&hi_point);

            // g1(x1) = add(ry, x1)
            let g1 = {
                let mut g1 = vec![E::ZERO; 1 << lo_in_num_vars];
                layer.adds.iter().for_each(|gate| {
                    g1[gate.idx_in[0]] += eq_y_ry[gate.idx_out] * &gate.scalar.eval(&challenges);
                });
                DenseMultilinearExtension::from_evaluations_ext_vec(lo_in_num_vars, g1)
            };
            (vec![f1], vec![g1.into()])
        };

        let (mut f1_vec, mut g1_vec) = f1_g1();

        // f1'^{(j)}(x1) = subset[j][i](rt || x1)
        // g1'^{(j)}(x1) = paste_from[j](ry, x1)
        let paste_from_sources = circuit_witness.layers_ref();
        let old_wire_id = |old_layer_id: usize, subset_wire_id: usize| -> usize {
            circuit.layers[old_layer_id].copy_to[&self.layer_id][subset_wire_id]
        };
        layer.paste_from.iter().for_each(|(&j, paste_from)| {
            let mut f1_j = vec![0.into(); 1 << (lo_in_num_vars + hi_num_vars)];
            let mut g1_j = vec![E::ZERO; 1 << lo_in_num_vars];

            paste_from
                .iter()
                .enumerate()
                .for_each(|(subset_wire_id, &new_wire_id)| {
                    for s in 0..(1 << hi_num_vars) {
                        f1_j[(s << lo_in_num_vars) ^ subset_wire_id] =
                            paste_from_sources[j as usize].instances[s][old_wire_id(j as usize, subset_wire_id)];
                    }

                    g1_j[subset_wire_id] += eq_y_ry[new_wire_id];
                });
            f1_vec.push({
                let mut f1_j = DenseMultilinearExtension::from_evaluations_vec(lo_in_num_vars + hi_num_vars, f1_j);
                f1_j.fix_high_variables_in_place(&hi_point);
                f1_j.into()
            });
            g1_vec.push(DenseMultilinearExtension::from_evaluations_ext_vec(lo_in_num_vars, g1_j).into());
        });

        // sumcheck: sigma = \sum_{x1} f1(x1) * g1(x1) + \sum_j f1'_j(x1) * g1'_j(x1)
        let mut virtual_poly_1 = VirtualPolynomial::new(lo_in_num_vars);
        for (f1_j, g1_j) in izip!(f1_vec.into_iter(), g1_vec.into_iter()) {
            let mut tmp = VirtualPolynomial::new_from_mle(f1_j, E::BaseField::ONE);
            tmp.mul_by_mle(g1_j, E::BaseField::ONE);
            virtual_poly_1.merge(&tmp);
        }

        let (sumcheck_proof_1, prover_state) = SumcheckState::prove_parallel(virtual_poly_1, transcript);
        let eval_point_1 = sumcheck_proof_1.point.clone();
        let (f1_vec, _): (Vec<_>, Vec<_>) = prover_state
            .get_mle_final_evaluations()
            .into_iter()
            .enumerate()
            .partition(|(i, _)| i % 2 == 0);
        let eval_values_f1 = f1_vec.into_iter().map(|(_, f1_j)| f1_j).collect_vec();

        let new_point = [&eval_point_1, hi_point].concat();
        self.to_next_phase_point_and_evals = vec![PointAndEval::new_from_ref(&new_point, &eval_values_f1[0])];
        izip!(layer.paste_from.iter(), eval_values_f1.iter().skip(1)).for_each(
            |((&old_layer_id, _), &subset_value)| {
                self.subset_point_and_evals[old_layer_id as usize]
                    .push((self.layer_id, PointAndEval::new_from_ref(&new_point, &subset_value)));
            },
        );
        self.to_next_step_point = new_point;
        end_timer!(timer);

        IOPProverStepMessage {
            sumcheck_proof: sumcheck_proof_1,
            sumcheck_eval_values: eval_values_f1,
        }
    }
}
