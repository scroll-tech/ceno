use ark_std::{end_timer, start_timer};
use goldilocks::SmallField;
use itertools::{izip, Itertools};
use multilinear_extensions::{
    mle::DenseMultilinearExtension,
    virtual_poly::{build_eq_x_r_vec, VirtualPolynomial},
};
use std::{ops::Add, sync::Arc};
use transcript::Transcript;

use crate::{
    prover::SumcheckState,
    structs::{Circuit, CircuitWitness, IOPProverState, IOPProverStepMessage, PointAndEval},
    utils::{ceil_log2, fix_high_variables},
};

// Prove the computation in the current layer for data parallel circuits.
// The number of terms depends on the gate.
// Here is an example of degree 3:
// layers[i](rt || ry) = \sum_x(
//     \sum_j  paste_from[j](ry, x) * subset[j][i](rt || x)
// ) + add_const(ry)
impl<F: SmallField> IOPProverState<F> {
    /// Sumcheck 1: sigma = \sum_j f1'_j(x1) * g1'_j(x1)
    ///     sigma = layers[i](rt || ry) - add_const(ry),
    ///     f1'^{(j)}(x1) = subset[j][i](rt || x1)
    ///     g1'^{(j)}(x1) = paste_from[j](ry, x1)
    pub(super) fn prove_and_update_state_input_phase2_step1(
        &mut self,
        circuit: &Circuit<F>,
        circuit_witness: &CircuitWitness<F::BaseField>,
        transcript: &mut Transcript<F>,
    ) -> IOPProverStepMessage<F> {
        let timer = start_timer!(|| "Prover sumcheck input phase 2 step 1");
        let layer = &circuit.layers[self.layer_id as usize];
        let lo_out_num_vars = layer.num_vars;
        let max_lo_in_num_vars = circuit.max_wit_in_num_vars.unwrap_or(0);
        let hi_num_vars = circuit_witness.instance_num_vars();
        let hi_point = &self.to_next_step_point[lo_out_num_vars..];

        let eq_y_ry = build_eq_x_r_vec(&self.to_next_step_point[..lo_out_num_vars]);

        let mut f_vec = vec![];
        let mut g_vec = vec![];
        let paste_from_wit_in = &circuit.paste_from_wits_in;
        let wits_in = circuit_witness.witness_in_ref();

        paste_from_wit_in
            .iter()
            .enumerate()
            .for_each(|(j, (l, r))| {
                let mut f = vec![F::ZERO; 1 << (max_lo_in_num_vars + hi_num_vars)];
                let mut g = vec![F::ZERO; 1 << max_lo_in_num_vars];

                for new_wire_id in *l..*r {
                    let subset_wire_id = new_wire_id - l;
                    for s in 0..(1 << hi_num_vars) {
                        f[(s << max_lo_in_num_vars) ^ subset_wire_id] =
                            F::from_base(&wits_in[j as usize].instances[s][subset_wire_id]);
                    }
                    g[subset_wire_id] = eq_y_ry[new_wire_id];
                }
                f_vec.push(Arc::new(fix_high_variables(
                    &Arc::new(DenseMultilinearExtension::from_evaluations_vec(
                        max_lo_in_num_vars + hi_num_vars,
                        f,
                    )),
                    &hi_point,
                )));
                g_vec.push(Arc::new(DenseMultilinearExtension::from_evaluations_vec(
                    max_lo_in_num_vars,
                    g,
                )));
            });

        let paste_from_counter_in = &circuit.paste_from_counter_in;
        for (num_vars, (l, r)) in paste_from_counter_in.iter() {
            let mut f = vec![F::ZERO; 1 << (max_lo_in_num_vars + hi_num_vars)];
            let mut g = vec![F::ZERO; 1 << max_lo_in_num_vars];

            for new_wire_id in *l..*r {
                let subset_wire_id = new_wire_id - l;
                for s in 0..(1 << hi_num_vars) {
                    f[(s << max_lo_in_num_vars) ^ subset_wire_id] =
                        F::from(((s << num_vars) ^ subset_wire_id) as u64);
                }
                g[subset_wire_id] = eq_y_ry[new_wire_id];
            }
            f_vec.push(Arc::new(fix_high_variables(
                &Arc::new(DenseMultilinearExtension::from_evaluations_vec(
                    max_lo_in_num_vars + hi_num_vars,
                    f,
                )),
                &hi_point,
            )));
            g_vec.push(Arc::new(DenseMultilinearExtension::from_evaluations_vec(
                max_lo_in_num_vars,
                g,
            )));
        }

        let mut virtual_poly = VirtualPolynomial::new(max_lo_in_num_vars);
        for (f, g) in f_vec.iter().zip(g_vec.iter()) {
            let mut tmp = VirtualPolynomial::new_from_mle(&f, F::ONE);
            tmp.mul_by_mle(g.clone(), F::ONE);
            virtual_poly = virtual_poly.add(&tmp);
        }

        let sumcheck_proofs = SumcheckState::prove(&virtual_poly, transcript);
        let eval_point = sumcheck_proofs.point.clone();
        let eval_values_f = f_vec
            .iter()
            .take(wits_in.len())
            .map(|f| f.evaluate(&eval_point))
            .collect_vec();

        self.to_next_phase_point_and_evals = izip!(paste_from_wit_in.iter(), eval_values_f.iter())
            .map(|((l, r), eval)| {
                let num_vars = ceil_log2(*r - *l);
                let point = [&eval_point[..num_vars], hi_point].concat();
                let wit_in_eval = *eval
                    * eval_point[num_vars..]
                        .iter()
                        .map(|x| F::ONE - *x)
                        .product::<F>()
                        .invert()
                        .unwrap();
                PointAndEval::new_from_ref(&point, &wit_in_eval)
            })
            .collect_vec();
        self.to_next_step_point = [&eval_point, hi_point].concat();

        end_timer!(timer);

        IOPProverStepMessage {
            sumcheck_proof: sumcheck_proofs,
            sumcheck_eval_values: eval_values_f,
        }
    }
}
