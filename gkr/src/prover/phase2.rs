use ark_std::{end_timer, start_timer};
use goldilocks::SmallField;
use itertools::{izip, Itertools};
use multilinear_extensions::{
    mle::{ArcDenseMultilinearExtension, DenseMultilinearExtension},
    virtual_poly::{build_eq_x_r_vec, VirtualPolynomial},
};
use std::sync::Arc;
use transcript::Transcript;

#[cfg(feature = "parallel")]
use rayon::iter::ParallelIterator;

use crate::{
    circuit::EvaluateConstant,
    izip_parallizable,
    structs::{Circuit, CircuitWitness, IOPProverState, IOPProverStepMessage, PointAndEval},
    utils::MultilinearExtensionFromVectors,
};

use super::SumcheckState;

// Prove the computation in the current layer for data parallel circuits.
// The number of terms depends on the gate.
// Here is an example of degree 3:
// layers[i](rt || ry) = \sum_{s1}( \sum_{s2}( \sum_{s3}( \sum_{x1}( \sum_{x2}( \sum_{x3}(
//     eq(rt, s1, s2, s3) * mul3(ry, x1, x2, x3) * layers[i + 1](s1 || x1) * layers[i + 1](s2 || x2) * layers[i + 1](s3 || x3)
// ) ) ) ) ) ) + sum_s1( sum_s2( sum_{x1}( sum_{x2}(
//     eq(rt, s1, s2) * mul2(ry, x1, x2) * layers[i + 1](s1 || x1) * layers[i + 1](s2 || x2)
// ) ) ) ) + \sum_{s1}( \sum_{x1}(
//     eq(rt, s1) * add(ry, x1) * layers[i + 1](s1 || x1)
// ) ) + \sum_{s1}( \sum_{x1}(
//      \sum_j eq(rt, s1) paste_from[j](ry, x1) * subset[j][i](s1 || x1)
// ) ) + add_const(ry)
impl<F: SmallField> IOPProverState<F> {
    /// Sumcheck 1: sigma = \sum_{s1 || x1} f1(s1 || x1) * g1(s1 || x1) + \sum_j f1'_j(s1 || x1) * g1'_j(s1 || x1)
    ///     sigma = layers[i](rt || ry) - add_const(ry),
    ///     f1(s1 || x1) = layers[i + 1](s1 || x1)
    ///     g1(s1 || x1) = \sum_{s2}( \sum_{s3}( \sum_{x2}( \sum_{x3}(
    ///         eq(rt, s1, s2, s3) * mul3(ry, x1, x2, x3) * layers[i + 1](s2 || x2) * layers[i + 1](s3 || x3)
    ///     ) ) ) ) + \sum_{s2}( \sum_{x2}(
    ///         eq(rt, s1, s2) * mul2(ry, x1, x2) * layers[i + 1](s2 || x2)
    ///     ) ) + eq(rt, s1) * add(ry, x1)
    ///     f1'^{(j)}(s1 || x1) = subset[j][i](s1 || x1)
    ///     g1'^{(j)}(s1 || x1) = eq(rt, s1) paste_from[j](ry, x1)
    #[tracing::instrument(skip_all, name = "prove_and_update_state_phase2_step1")]
    pub(super) fn prove_and_update_state_phase2_step1(
        &mut self,
        circuit: &Circuit<F>,
        circuit_witness: &CircuitWitness<F::BaseField>,
        transcript: &mut Transcript<F>,
    ) -> IOPProverStepMessage<F> {
        let timer = start_timer!(|| "Prover sumcheck phase 2 step 1");
        let layer = &circuit.layers[self.layer_id as usize];
        let lo_out_num_vars = layer.num_vars;
        let lo_in_num_vars = layer.max_previous_num_vars;
        let hi_num_vars = circuit_witness.instance_num_vars();
        let in_num_vars = lo_in_num_vars + hi_num_vars;

        self.tensor_eq_ty_rtry = build_eq_x_r_vec(&self.to_next_step_point);

        let layer_in_vec = circuit_witness.layers[self.layer_id as usize + 1]
            .instances
            .as_slice();
        self.layer_poly = layer_in_vec.mle(lo_in_num_vars, hi_num_vars);

        let challenges = &circuit_witness.challenges;

        let (mut f1_vec, mut g1_vec) = {
            // f1(s1 || x1) = layers[i + 1](s1 || x1)
            let f1 = Arc::clone(&mut self.layer_poly);

            // g1(s1 || x1) = \sum_{s2}( \sum_{s3}( \sum_{x2}( \sum_{x3}(
            //     eq(rt, s1, s2, s3) * mul3(ry, x1, x2, x3) * layers[i + 1](s2 || x2) * layers[i + 1](s3 || x3)
            // ) ) ) ) + \sum_{s2}( \sum_{x2}(
            //     eq(rt, s1, s2) * mul2(ry, x1, x2) * layers[i + 1](s2 || x2)
            // ) ) + eq(rt, s1) * add(ry, x1)
            let g1 = {
                let mut g1 = vec![F::ZERO; 1 << in_num_vars];
                layer.mul3s.iter().for_each(|gate| {
                    for s in 0..(1 << hi_num_vars) {
                        g1[(s << lo_in_num_vars) ^ gate.idx_in[0]] += self.tensor_eq_ty_rtry
                            [(s << lo_out_num_vars) ^ gate.idx_out]
                            .mul_base(&layer_in_vec[s][gate.idx_in[1]])
                            .mul_base(&layer_in_vec[s][gate.idx_in[2]])
                            .mul_base(&gate.scalar.eval(&challenges));
                    }
                });
                layer.mul2s.iter().for_each(|gate| {
                    for s in 0..(1 << hi_num_vars) {
                        g1[(s << lo_in_num_vars) ^ gate.idx_in[0]] += self.tensor_eq_ty_rtry
                            [(s << lo_out_num_vars) ^ gate.idx_out]
                            .mul_base(&layer_in_vec[s][gate.idx_in[1]])
                            .mul_base(&gate.scalar.eval(&challenges));
                    }
                });
                layer.adds.iter().for_each(|gate| {
                    for s in 0..(1 << hi_num_vars) {
                        g1[(s << lo_in_num_vars) ^ gate.idx_in[0]] += self.tensor_eq_ty_rtry
                            [(s << lo_out_num_vars) ^ gate.idx_out]
                            .mul_base(&gate.scalar.eval(&challenges));
                    }
                });
                DenseMultilinearExtension::from_evaluations_vec(in_num_vars, g1)
            };
            (vec![f1], vec![g1.into()])
        };

        // f1'^{(j)}(s1 || x1) = subset[j][i](s1 || x1)
        // g1'^{(j)}(s1 || x1) = eq(rt, s1) paste_from[j](ry, x1)
        let paste_from_sources = circuit_witness.layers_ref();
        let old_wire_id = |old_layer_id: usize, subset_wire_id: usize| -> usize {
            circuit.layers[old_layer_id].copy_to[&self.layer_id][subset_wire_id]
        };
        let (f1_vec_paste_from, g1_vec_paste_from): (
            Vec<ArcDenseMultilinearExtension<F>>,
            Vec<ArcDenseMultilinearExtension<F>>,
        ) = izip_parallizable!(&layer.paste_from)
            .map(|(j, paste_from)| {
                let mut f1_j = vec![F::ZERO; 1 << in_num_vars];
                let mut g1_j = vec![F::ZERO; 1 << in_num_vars];

                paste_from
                    .iter()
                    .enumerate()
                    .for_each(|(subset_wire_id, &new_wire_id)| {
                        for s in 0..(1 << hi_num_vars) {
                            f1_j[(s << lo_in_num_vars) ^ subset_wire_id] = F::from_base(
                                &paste_from_sources[*j as usize].instances[s]
                                    [old_wire_id(*j as usize, subset_wire_id)],
                            );
                            g1_j[(s << lo_in_num_vars) ^ subset_wire_id] +=
                                self.tensor_eq_ty_rtry[(s << lo_out_num_vars) ^ new_wire_id];
                        }
                    });
                (
                    DenseMultilinearExtension::from_evaluations_vec(in_num_vars, f1_j).into(),
                    DenseMultilinearExtension::from_evaluations_vec(in_num_vars, g1_j).into(),
                )
            })
            .unzip();

        f1_vec.extend(f1_vec_paste_from);
        g1_vec.extend(g1_vec_paste_from);

        // sumcheck: sigma = \sum_{s1 || x1} f1(s1 || x1) * g1(s1 || x1) + \sum_j f1'_j(s1 || x1) * g1'_j(s1 || x1)
        let mut virtual_poly_1 = VirtualPolynomial::new(in_num_vars);
        for (f1_j, g1_j) in f1_vec.into_iter().zip(g1_vec.into_iter()) {
            let mut tmp = VirtualPolynomial::new_from_mle(f1_j, F::ONE);
            tmp.mul_by_mle(g1_j, F::ONE);
            virtual_poly_1.merge(&tmp);
        }

        let (sumcheck_proof_1, prover_state) = SumcheckState::prove(virtual_poly_1, transcript);
        let eval_point_1 = sumcheck_proof_1.point.clone();
        let (f1_vec, g1_vec): (Vec<_>, Vec<_>) = prover_state
            .get_mle_final_evaluations()
            .into_iter()
            .enumerate()
            .partition(|(i, _)| i % 2 == 0);
        let f1_vec_len = f1_vec.len();
        // eval_values_f1
        let mut eval_values_1 = f1_vec.into_iter().map(|(_, f1_j)| f1_j).collect_vec();

        // eval_values_g1[0]
        eval_values_1.push(g1_vec[0].1);

        self.to_next_phase_point_and_evals =
            vec![PointAndEval::new_from_ref(&eval_point_1, &eval_values_1[0])];
        izip!(
            layer.paste_from.iter(),
            eval_values_1[..f1_vec_len].iter().skip(1)
        )
        .for_each(|((&old_layer_id, _), &subset_value)| {
            self.subset_point_and_evals[old_layer_id as usize].push((
                self.layer_id,
                PointAndEval::new_from_ref(&eval_point_1, &subset_value),
            ));
        });
        self.to_next_step_point = eval_point_1;
        end_timer!(timer);

        IOPProverStepMessage {
            sumcheck_proof: sumcheck_proof_1,
            sumcheck_eval_values: eval_values_1,
        }
    }

    /// Sumcheck 2 sigma = \sum_{s2 || x2} f2(s2 || x2) * g2(s2 || x2)
    ///     sigma = g1(rs1 || rx1) - eq(rt, rs1) * add(ry, rx1)
    ///     f2(s2 || x2) = layers[i + 1](s2 || x2)
    ///     g2(s2 || x2) = \sum_{s3}( \sum_{x3}(
    ///         eq(rt, rs1, s2, s3) * mul3(ry, rx1, x2, x3) * layers[i + 1](s3 || x3)
    ///     ) ) + eq(rt, rs1, s2) * mul2(ry, rx1, x2)
    #[tracing::instrument(skip_all, name = "prove_and_update_state_phase2_step2")]
    pub(super) fn prove_and_update_state_phase2_step2(
        &mut self,
        circuit: &Circuit<F>,
        circuit_witness: &CircuitWitness<F::BaseField>,
        transcript: &mut Transcript<F>,
        no_step3: bool,
    ) -> IOPProverStepMessage<F> {
        let timer = start_timer!(|| "Prover sumcheck phase 2 step 2");
        let layer = &circuit.layers[self.layer_id as usize];
        let lo_out_num_vars = layer.num_vars;
        let lo_in_num_vars = layer.max_previous_num_vars;
        let hi_num_vars = circuit_witness.instance_num_vars();

        self.tensor_eq_s1x1_rs1rx1 = build_eq_x_r_vec(&self.to_next_step_point);

        let layer_in_vec = circuit_witness.layers[self.layer_id as usize + 1]
            .instances
            .as_slice();

        let challenges = &circuit_witness.challenges;

        // f2(s2 || x2) = layers[i + 1](s2 || x2)
        let f2 = Arc::clone(&mut self.layer_poly);
        // g2(s2 || x2) = \sum_{s3}( \sum_{x3}(
        //     eq(rt, rs1, s2, s3) * mul3(ry, rx1, x2, x3) * layers[i + 1](s3 || x3)
        // ) ) + eq(rt, rs1, s2) * mul2(ry, rx1, x2)
        let g2 = {
            let mut g2 = vec![F::ZERO; 1 << f2.num_vars];
            layer.mul3s.iter().for_each(|gate| {
                for s in 0..(1 << hi_num_vars) {
                    g2[(s << lo_in_num_vars) ^ gate.idx_in[1]] += self.tensor_eq_ty_rtry
                        [(s << lo_out_num_vars) ^ gate.idx_out]
                        * self.tensor_eq_s1x1_rs1rx1[(s << lo_in_num_vars) ^ gate.idx_in[0]]
                            .mul_base(&layer_in_vec[s][gate.idx_in[2]])
                            .mul_base(&gate.scalar.eval(&challenges));
                }
            });
            layer.mul2s.iter().for_each(|gate| {
                for s in 0..(1 << hi_num_vars) {
                    g2[(s << lo_in_num_vars) ^ gate.idx_in[1]] += self.tensor_eq_ty_rtry
                        [(s << lo_out_num_vars) ^ gate.idx_out]
                        * self.tensor_eq_s1x1_rs1rx1[(s << lo_in_num_vars) ^ gate.idx_in[0]]
                            .mul_base(&gate.scalar.eval(&challenges));
                }
            });
            DenseMultilinearExtension::from_evaluations_vec(f2.num_vars, g2).into()
        };
        // sumcheck: sigma = \sum_{s2 || x2} f2(s2 || x2) * g2(s2 || x2)
        let mut virtual_poly_2 = VirtualPolynomial::new_from_mle(f2, F::ONE);
        virtual_poly_2.mul_by_mle(g2, F::ONE);
        let (sumcheck_proof_2, prover_state) = SumcheckState::prove(virtual_poly_2, transcript);

        let eval_point_2 = sumcheck_proof_2.point.clone();
        let (f2, g2): (Vec<_>, Vec<_>) = prover_state
            .get_mle_final_evaluations()
            .into_iter()
            .enumerate()
            .partition(|(i, _)| i % 2 == 0);
        let (eval_value_f2, eval_value_g2) = (f2[0].1, g2[0].1);

        self.to_next_phase_point_and_evals
            .push(PointAndEval::new_from_ref(&eval_point_2, &eval_value_f2));
        self.to_next_step_point = eval_point_2;
        end_timer!(timer);
        if no_step3 {
            IOPProverStepMessage {
                sumcheck_proof: sumcheck_proof_2,
                sumcheck_eval_values: vec![eval_value_f2],
            }
        } else {
            IOPProverStepMessage {
                sumcheck_proof: sumcheck_proof_2,
                sumcheck_eval_values: vec![eval_value_f2, eval_value_g2],
            }
        }
    }

    /// Sumcheck 3 sigma = \sum_{s3 || x3} f3(s3 || x3) * g3(s3 || x3)
    ///     sigma = g2(rs2 || rx2) - eq(rt, rs1, rs2) * mul2(ry, rx1, rx2)
    ///     f3(s3 || x3) = layers[i + 1](s3 || x3)
    ///     g3(s3 || x3) = eq(rt, rs1, rs2, s3) * mul3(ry, rx1, rx2, x3)
    #[tracing::instrument(skip_all, name = "prove_and_update_state_phase2_step3")]
    pub(super) fn prove_and_update_state_phase2_step3(
        &mut self,
        circuit: &Circuit<F>,
        circuit_witness: &CircuitWitness<F::BaseField>,
        transcript: &mut Transcript<F>,
    ) -> IOPProverStepMessage<F> {
        let timer = start_timer!(|| "Prover sumcheck phase 2 step 3");
        let layer = &circuit.layers[self.layer_id as usize];
        let lo_out_num_vars = layer.num_vars;
        let lo_in_num_vars = layer.max_previous_num_vars;
        let hi_num_vars = circuit_witness.instance_num_vars();

        self.tensor_eq_s2x2_rs2rx2 = build_eq_x_r_vec(&self.to_next_step_point);

        let challenges = &circuit_witness.challenges;

        // f3(s3 || x3) = layers[i + 1](s3 || x3)
        let f3 = Arc::clone(&self.layer_poly);

        // g3(s3 || x3) = eq(rt, rs1, rs2, s3) * mul3(ry, rx1, rx2, x3)
        let g3 = {
            let mut g3 = vec![F::ZERO; 1 << f3.num_vars];
            layer.mul3s.iter().for_each(|gate| {
                for s in 0..(1 << hi_num_vars) {
                    g3[(s << lo_in_num_vars) ^ gate.idx_in[2]] += self.tensor_eq_ty_rtry
                        [(s << lo_out_num_vars) ^ gate.idx_out]
                        * self.tensor_eq_s1x1_rs1rx1[(s << lo_in_num_vars) ^ gate.idx_in[0]]
                        * self.tensor_eq_s2x2_rs2rx2[(s << lo_in_num_vars) ^ gate.idx_in[1]]
                            .mul_base(&gate.scalar.eval(&challenges));
                }
            });
            DenseMultilinearExtension::from_evaluations_vec(f3.num_vars, g3).into()
        };
        // sumcheck: sigma = \sum_{s3 || x3} f3(s3 || x3) * g3(s3 || x3)
        let mut virtual_poly_3 = VirtualPolynomial::new_from_mle(f3, F::ONE);
        virtual_poly_3.mul_by_mle(g3, F::ONE);
        let (sumcheck_proof_3, prover_state) = SumcheckState::prove(virtual_poly_3, transcript);
        let eval_point_3 = sumcheck_proof_3.point.clone();
        let (f3, _): (Vec<_>, Vec<_>) = prover_state
            .get_mle_final_evaluations()
            .into_iter()
            .enumerate()
            .partition(|(i, _)| i % 2 == 0);
        let eval_values_3 = vec![f3[0].1];
        self.to_next_phase_point_and_evals
            .push(PointAndEval::new_from_ref(&eval_point_3, &eval_values_3[0]));
        self.to_next_step_point = eval_point_3;
        end_timer!(timer);
        IOPProverStepMessage {
            sumcheck_proof: sumcheck_proof_3,
            sumcheck_eval_values: eval_values_3,
        }
    }
}
