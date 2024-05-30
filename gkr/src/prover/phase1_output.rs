use ark_std::{end_timer, start_timer};
use ff::Field;
use ff_ext::ExtensionField;
use itertools::{chain, Itertools};
use multilinear_extensions::{
    mle::{ArcDenseMultilinearExtension, DenseMultilinearExtension},
    virtual_poly::{build_eq_x_r_vec, VirtualPolynomial},
};
use std::{iter, mem};
use transcript::Transcript;

use crate::{
    izip_parallizable,
    prover::SumcheckState,
    structs::{Circuit, CircuitWitness, IOPProverState, IOPProverStepMessage, PointAndEval},
    utils::MatrixMLERowFirst,
};

#[cfg(feature = "parallel")]
use rayon::iter::{IndexedParallelIterator, ParallelIterator};

// Prove the items copied from the output layer to the output witness for data parallel circuits.
// \sum_j( \alpha^j * subset[i][j](rt_j || ry_j) )
//     = \sum_y( \sum_j( \alpha^j (eq or copy_to[j] or assert_subset_eq)(ry_j, y) \sum_t( eq(rt_j, t) * layers[i](t || y) ) ) )
impl<E: ExtensionField> IOPProverState<E> {
    /// Sumcheck 1: sigma = \sum_y( \sum_j f1^{(j)}(y) * g1^{(j)}(y) )
    ///     sigma = \sum_j( \alpha^j * wit_out_eval[j](rt_j || ry_j) )
    ///             + \alpha^{wit_out_eval[j].len()} * assert_const(rt || ry) )
    ///     f1^{(j)}(y) = \sum_t( eq(rt_j, t) * layers[i](t || y) )
    ///     g1^{(j)}(y) = \alpha^j eq(ry_j, y)
    //                      or \alpha^j copy_to[j](ry_j, y)
    //                      or \alpha^j assert_subset_eq(ry, y)
    #[tracing::instrument(skip_all, name = "prove_and_update_state_output_phase1_step1")]
    pub(super) fn prove_and_update_state_output_phase1_step1(
        &mut self,
        circuit: &Circuit<E>,
        circuit_witness: &CircuitWitness<E::BaseField>,
        transcript: &mut Transcript<E>,
    ) -> IOPProverStepMessage<E> {
        let timer = start_timer!(|| "Prover sumcheck output phase 1 step 1");
        let alpha = transcript
            .get_and_append_challenge(b"combine subset evals")
            .elements;
        let total_length = self.to_next_phase_point_and_evals.len()
            + self.subset_point_and_evals[self.layer_id as usize].len()
            + 1;
        let alpha_pows = {
            let mut alpha_pows = vec![E::ONE; total_length];
            for i in 0..total_length.saturating_sub(1) {
                alpha_pows[i + 1] = alpha * &alpha_pows[i];
            }
            alpha_pows
        };

        let lo_num_vars = circuit.layers[self.layer_id as usize].num_vars;
        let hi_num_vars = circuit_witness.instance_num_vars();

        // sigma = \sum_j( \alpha^j * subset[i][j](rt_j || ry_j) )
        // f1^{(j)}(y) = \sum_t( eq(rt_j, t) * layers[i](t || y) )
        // g1^{(j)}(y) = \alpha^j eq(ry_j, y)
        //                  or \alpha^j copy_to[j](ry_j, y)
        //                  or \alpha^j assert_subset_eq[j](ry, y)
        // TODO: Double check the soundness here.
        let (mut f1, mut g1): (
            Vec<ArcDenseMultilinearExtension<E>>,
            Vec<ArcDenseMultilinearExtension<E>>,
        ) = izip_parallizable!(&self.to_next_phase_point_and_evals, &alpha_pows)
            .map(|(point_and_eval, alpha_pow)| {
                let point_lo_num_vars = point_and_eval.point.len() - hi_num_vars;
                let point = &point_and_eval.point;
                let lo_eq_w_p = build_eq_x_r_vec(&point_and_eval.point[..point_lo_num_vars]);

                let f1_j = self.phase1_layer_polys[self.layer_id as usize]
                    .fix_high_variables(&point[point_lo_num_vars..]);

                let g1_j = lo_eq_w_p
                    .into_iter()
                    .map(|eq| *alpha_pow * eq)
                    .collect_vec();
                (
                    f1_j.into(),
                    DenseMultilinearExtension::<E>::from_evaluations_ext_vec(lo_num_vars, g1_j)
                        .into(),
                )
            })
            .unzip();

        let (f1_copy_to, g1_copy_to): (
            Vec<ArcDenseMultilinearExtension<E>>,
            Vec<ArcDenseMultilinearExtension<E>>,
        ) = izip_parallizable!(
            &circuit.copy_to_wits_out,
            &self.subset_point_and_evals[self.layer_id as usize],
            &alpha_pows[self.to_next_phase_point_and_evals.len()..]
        )
        .map(|(copy_to, (_, point_and_eval), alpha_pow)| {
            let point_lo_num_vars = point_and_eval.point.len() - hi_num_vars;
            let point = &point_and_eval.point;
            let lo_eq_w_p = build_eq_x_r_vec(&point_and_eval.point[..point_lo_num_vars]);
            assert!(copy_to.len() <= lo_eq_w_p.len());

            let f1_j = self.phase1_layer_polys[self.layer_id as usize]
                .fix_high_variables(&point[point_lo_num_vars..]);

            let g1_j = copy_to.as_slice().fix_row_row_first_with_scalar(
                &lo_eq_w_p,
                lo_num_vars,
                alpha_pow,
            );

            (
                f1_j.into(),
                DenseMultilinearExtension::from_evaluations_ext_vec(lo_num_vars, g1_j).into(),
            )
        })
        .unzip();

        f1.extend(f1_copy_to);
        g1.extend(g1_copy_to);

        let f1_j = self.phase1_layer_polys[self.layer_id as usize]
            .fix_high_variables(&self.assert_point[lo_num_vars..]);
        f1.push(f1_j.into());

        let alpha_pow = alpha_pows.last().unwrap();
        let lo_eq_w_p = build_eq_x_r_vec(&self.assert_point[..lo_num_vars]);
        let mut g_last = vec![E::ZERO; 1 << lo_num_vars];
        circuit.assert_consts.iter().for_each(|gate| {
            g_last[gate.idx_out as usize] = lo_eq_w_p[gate.idx_out as usize] * alpha_pow;
        });

        g1.push(DenseMultilinearExtension::from_evaluations_ext_vec(lo_num_vars, g_last).into());

        // sumcheck: sigma = \sum_y( \sum_j f1^{(j)}(y) * g1^{(j)}(y) )
        let mut virtual_poly_1 = VirtualPolynomial::new(lo_num_vars);
        for (f1_j, g1_j) in f1.into_iter().zip(g1.into_iter()) {
            let mut tmp = VirtualPolynomial::new_from_mle(f1_j, E::BaseField::ONE);
            tmp.mul_by_mle(g1_j, E::BaseField::ONE);
            virtual_poly_1.merge(&tmp);
        }

        let (sumcheck_proof_1, prover_state) =
            SumcheckState::prove_parallel(virtual_poly_1, transcript);
        let (f1, g1): (Vec<_>, Vec<_>) = prover_state
            .get_mle_final_evaluations()
            .into_iter()
            .enumerate()
            .partition(|(i, _)| i % 2 == 0);
        let eval_value_1 = f1.into_iter().map(|(_, f1_j)| f1_j).collect_vec();

        self.to_next_step_point = sumcheck_proof_1.point.clone();
        self.g1_values = g1.into_iter().map(|(_, g1_j)| g1_j).collect_vec();

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
    #[tracing::instrument(skip_all, name = "prove_and_update_state_output_phase1_step2")]
    pub(super) fn prove_and_update_state_output_phase1_step2(
        &mut self,
        _: &Circuit<E>,
        circuit_witness: &CircuitWitness<E::BaseField>,
        transcript: &mut Transcript<E>,
    ) -> IOPProverStepMessage<E> {
        let timer = start_timer!(|| "Prover sumcheck output phase 1 step 2");
        let hi_num_vars = circuit_witness.instance_num_vars();

        // f2(t) = layers[i](t || ry)
        let f2 = self.phase1_layer_polys[self.layer_id as usize]
            .fix_variables_parallel(&self.to_next_step_point)
            .into();

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
            .fold(vec![E::ZERO; 1 << hi_num_vars], |acc, nxt| {
                acc.into_iter()
                    .zip(nxt.into_iter())
                    .map(|(a, b)| a + b)
                    .collect_vec()
            });
        let g2 = DenseMultilinearExtension::from_evaluations_ext_vec(hi_num_vars, g2);
        // sumcheck: sigma = \sum_t( g2(t) * f2(t) )
        let mut virtual_poly_2 = VirtualPolynomial::new_from_mle(f2, E::BaseField::ONE);
        virtual_poly_2.mul_by_mle(g2.into(), E::BaseField::ONE);

        let (sumcheck_proof_2, prover_state) =
            SumcheckState::prove_parallel(virtual_poly_2, transcript);
        let (mut f2, _): (Vec<_>, Vec<_>) = prover_state
            .get_mle_final_evaluations()
            .into_iter()
            .enumerate()
            .partition(|(i, _)| i % 2 == 0);
        let eval_value_2 = f2.remove(0).1;

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
