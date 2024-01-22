use ark_std::{end_timer, start_timer};
use goldilocks::SmallField;
use itertools::{chain, izip, Itertools};
use multilinear_extensions::{
    mle::DenseMultilinearExtension,
    virtual_poly::{build_eq_x_r_vec, VirtualPolynomial},
};
use std::{iter, mem, ops::Add, sync::Arc};
use transcript::Transcript;

use crate::{
    prover::SumcheckState,
    structs::{Circuit, CircuitWitness, IOPProverState, IOPProverStepMessage, PointAndEval},
    utils::{fix_high_variables, MatrixMLERowFirst},
};

// Prove the items copied from the output layer to the output witness for data parallel circuits.
// \sum_j( \alpha^j * subset[i][j](rt_j || ry_j) )
//     = \sum_y( \sum_j( \alpha^j (eq or copy_to[j] or assert_subset_eq)(ry_j, y) \sum_t( eq(rt_j, t) * layers[i](t || y) ) ) )
impl<F: SmallField> IOPProverState<F> {
    /// Sumcheck 1: sigma = \sum_y( \sum_j f1^{(j)}(y) * g1^{(j)}(y) )
    ///     sigma = \sum_j( \alpha^j * wit_out_eval[j](rt_j || ry_j) )
    ///             + \alpha^{wit_out_eval[j].len()} * assert_const(rt || ry) )
    ///     f1^{(j)}(y) = \sum_t( eq(rt_j, t) * layers[i](t || y) )
    ///     g1^{(j)}(y) = \alpha^j eq(ry_j, y)
    //                      or \alpha^j copy_to[j](ry_j, y)
    //                      or \alpha^j assert_subset_eq(ry, y)
    pub(super) fn prove_and_update_state_output_phase1_step1(
        &mut self,
        circuit: &Circuit<F>,
        circuit_witness: &CircuitWitness<F::BaseField>,
        transcript: &mut Transcript<F>,
    ) -> IOPProverStepMessage<F> {
        let timer = start_timer!(|| "Prover sumcheck output phase 1 step 1");
        let alpha = transcript
            .get_and_append_challenge(b"combine subset evals")
            .elements;
        let total_length = self.to_next_phase_point_and_evals.len()
            + self.subset_point_and_evals[self.layer_id as usize].len()
            + 1;
        let alpha_pows = {
            let mut alpha_pows = vec![F::ONE; total_length];
            for i in 0..total_length.saturating_sub(1) {
                alpha_pows[i + 1] = alpha_pows[i] * alpha;
            }
            alpha_pows
        };

        let lo_num_vars = circuit.layers[self.layer_id as usize].num_vars;
        let hi_num_vars = circuit_witness.instance_num_vars();
        self.layer_poly = circuit_witness.layer_poly(self.layer_id, lo_num_vars);

        // sigma = \sum_j( \alpha^j * subset[i][j](rt_j || ry_j) )
        // f1^{(j)}(y) = \sum_t( eq(rt_j, t) * layers[i](t || y) )
        // g1^{(j)}(y) = \alpha^j eq(ry_j, y)
        //                  or \alpha^j copy_to[j](ry_j, y)
        //                  or \alpha^j assert_subset_eq[j](ry, y)

        // TODO: Double check the soundness here.
        let mut f1 = Vec::with_capacity(total_length);
        let mut g1 = Vec::with_capacity(total_length);
        izip!(self.to_next_phase_point_and_evals.iter(), alpha_pows.iter()).for_each(
            |(point_and_eval, alpha_pow)| {
                let point_lo_num_vars = point_and_eval.point.len() - hi_num_vars;
                let point = &point_and_eval.point;
                let lo_eq_w_p = build_eq_x_r_vec(&point_and_eval.point[..point_lo_num_vars]);

                let f1_j = fix_high_variables(&self.layer_poly, &point[point_lo_num_vars..]);
                f1.push(Arc::new(f1_j));

                let g1_j = lo_eq_w_p
                    .into_iter()
                    .map(|eq| *alpha_pow * eq)
                    .collect_vec();

                g1.push(Arc::new(DenseMultilinearExtension::from_evaluations_vec(
                    lo_num_vars,
                    g1_j,
                )));
            },
        );

        izip!(
            circuit.copy_to_wits_out.iter(),
            self.subset_point_and_evals[self.layer_id as usize].iter(),
            alpha_pows
                .iter()
                .skip(self.to_next_phase_point_and_evals.len())
        )
        .for_each(|(copy_to, (_, point_and_eval), alpha_pow)| {
            let point_lo_num_vars = point_and_eval.point.len() - hi_num_vars;
            let point = &point_and_eval.point;
            let lo_eq_w_p = build_eq_x_r_vec(&point_and_eval.point[..point_lo_num_vars]);
            assert!(copy_to.len() <= lo_eq_w_p.len());

            let f1_j = fix_high_variables(&self.layer_poly, &point[point_lo_num_vars..]);
            f1.push(Arc::new(f1_j));

            let g1_j = copy_to.as_slice().fix_row_row_first_with_scalar(
                &lo_eq_w_p,
                lo_num_vars,
                alpha_pow,
            );

            g1.push(Arc::new(DenseMultilinearExtension::from_evaluations_vec(
                lo_num_vars,
                g1_j,
            )));
        });

        let f1_j = fix_high_variables(&self.layer_poly, &self.assert_point[lo_num_vars..]);
        f1.push(Arc::new(f1_j));

        let alpha_pow = alpha_pows.last().unwrap();
        let lo_eq_w_p = build_eq_x_r_vec(&self.assert_point[..lo_num_vars]);
        let mut g_last = vec![F::ZERO; 1 << lo_num_vars];
        circuit.assert_consts.iter().for_each(|gate| {
            g_last[gate.idx_out as usize] = lo_eq_w_p[gate.idx_out as usize] * alpha_pow;
        });

        g1.push(Arc::new(DenseMultilinearExtension::from_evaluations_vec(
            lo_num_vars,
            g_last,
        )));

        // sumcheck: sigma = \sum_y( \sum_j f1^{(j)}(y) * g1^{(j)}(y) )
        let mut virtual_poly_1 = VirtualPolynomial::new(lo_num_vars);
        for (f1_j, g1_j) in f1.iter().zip(g1.iter()) {
            let mut tmp = VirtualPolynomial::new_from_mle(f1_j, F::ONE);
            tmp.mul_by_mle(g1_j.clone(), F::ONE);
            virtual_poly_1 = virtual_poly_1.add(&tmp);
        }

        let sumcheck_proof_1 = SumcheckState::prove(&virtual_poly_1, transcript);
        let eval_value_1 = f1
            .iter()
            .map(|f1_j| f1_j.evaluate(&sumcheck_proof_1.point))
            .collect_vec();

        self.to_next_step_point = sumcheck_proof_1.point.clone();
        self.g1_values = g1
            .iter()
            .map(|g1_j| g1_j.evaluate(&sumcheck_proof_1.point))
            .collect_vec();

        end_timer!(timer);
        IOPProverStepMessage {
            sumcheck_proof: sumcheck_proof_1,
            sumcheck_eval_values: eval_value_1,
        }
    }

    /// Sumcheck 2: sigma = \sum_t( \sum_j( f2^{(j)}(t) ) ) * g2(t)
    ///     sigma = \sum_j( f1^{(j)}(ry) * g1^{(j)}(ry) )
    ///     f2(t) = layers[i](t || ry)
    ///     g2^{(j)}(t) = \alpha^j eq(ry_j, ry) eq(rt_j, t)
    //                      or \alpha^j copy_to[j](ry_j, ry) eq(rt_j, t)
    //                      or \alpha^j assert_subset_eq(ry, ry) eq(rt, t)
    pub(super) fn prove_and_update_state_output_phase1_step2(
        &mut self,
        _: &Circuit<F>,
        circuit_witness: &CircuitWitness<F::BaseField>,
        transcript: &mut Transcript<F>,
    ) -> IOPProverStepMessage<F> {
        let timer = start_timer!(|| "Prover sumcheck output phase 1 step 2");
        let hi_num_vars = circuit_witness.instance_num_vars();

        // f2(t) = layers[i](t || ry)
        let f2 = Arc::new(self.layer_poly.fix_variables(&self.to_next_step_point));

        // g2(t) = \sum_j \alpha^j (eq or copy_to[j] or assert_subset)(ry_j, ry) eq(rt_j, t)
        let output_points = chain![
            self.to_next_phase_point_and_evals.iter().map(|x| &x.point),
            self.subset_point_and_evals[self.layer_id as usize]
                .iter()
                .map(|x| &x.1.point),
            iter::once(&self.assert_point),
        ];
        let g2 = output_points
            .zip(self.g1_values.iter())
            .map(|(point, &g1_value)| {
                let point_lo_num_vars = point.len() - hi_num_vars;
                build_eq_x_r_vec(&point[point_lo_num_vars..])
                    .into_iter()
                    .map(|eq| g1_value * eq)
                    .collect_vec()
            })
            .fold(vec![F::ZERO; 1 << hi_num_vars], |acc, nxt| {
                acc.into_iter()
                    .zip(nxt.into_iter())
                    .map(|(a, b)| a + b)
                    .collect_vec()
            });
        let g2 = Arc::new(DenseMultilinearExtension::from_evaluations_vec(
            hi_num_vars,
            g2,
        ));
        // sumcheck: sigma = \sum_t( g2(t) * f2(t) )
        let mut virtual_poly_2 = VirtualPolynomial::new_from_mle(&f2, F::ONE);
        virtual_poly_2.mul_by_mle(g2, F::ONE);

        let sumcheck_proof_2 = SumcheckState::prove(&virtual_poly_2, transcript);
        let eval_value_2 = f2.evaluate(&sumcheck_proof_2.point);

        self.to_next_step_point = [
            mem::take(&mut self.to_next_step_point),
            sumcheck_proof_2.point.clone(),
        ]
        .concat();
        self.to_next_phase_point_and_evals = vec![PointAndEval::new_from_ref(
            &self.to_next_step_point,
            &eval_value_2,
        )];

        self.subset_point_and_evals[self.layer_id as usize].clear();

        end_timer!(timer);
        IOPProverStepMessage {
            sumcheck_proof: sumcheck_proof_2,
            sumcheck_eval_values: vec![eval_value_2],
        }
    }
}
