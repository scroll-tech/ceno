use ark_std::{end_timer, start_timer};
use frontend::structs::{CellId, InType};
use goldilocks::SmallField;
use itertools::Itertools;
use multilinear_extensions::virtual_poly::{build_eq_x_r_vec, eq_eval, VPAuxInfo};
use transcript::Transcript;

use crate::{
    error::GKRError,
    structs::{Point, SumcheckProof},
    utils::{
        ceil_log2, counter_eval, eq_eval_less_or_equal_than, i64_to_field,
        segment_eval_greater_than,
    },
};

use super::{IOPVerifierPhase2InputState, SumcheckState};

impl<'a, F: SmallField> IOPVerifierPhase2InputState<'a, F> {
    pub(super) fn verifier_init_parallel(
        n_wires_in: usize,
        layer_out_point: &'a Point<F>,
        layer_out_value: F,
        paste_from_in: &'a [(InType, CellId, CellId)],
        lo_out_num_vars: usize,
        lo_in_num_vars: usize,
        hi_num_vars: usize,
    ) -> Self {
        let mut paste_from_wires_in = vec![(0, 0); n_wires_in];
        paste_from_in
            .iter()
            .filter(|(ty, _, _)| matches!(*ty, InType::Wire(_)))
            .for_each(|(ty, l, r)| {
                if let InType::Wire(j) = *ty {
                    paste_from_wires_in[j as usize] = (*l, *r);
                }
            });
        let paste_from_counter_in = paste_from_in
            .iter()
            .filter(|(ty, _, _)| matches!(*ty, InType::Counter(_)))
            .map(|(ty, l, r)| {
                if let InType::Counter(_) = *ty {
                    (*l, *r)
                } else {
                    unreachable!()
                }
            })
            .collect::<Vec<_>>();
        let paste_from_const_in = paste_from_in
            .iter()
            .filter(|(ty, _, _)| matches!(*ty, InType::Constant(_)))
            .map(|(ty, l, r)| {
                if let InType::Constant(c) = *ty {
                    (i64_to_field(c), *l, *r)
                } else {
                    unreachable!()
                }
            })
            .collect::<Vec<_>>();
        Self {
            layer_out_point,
            layer_out_value,
            paste_from_wires_in,
            paste_from_counter_in,
            paste_from_const_in,
            lo_out_num_vars,
            lo_in_num_vars,
            hi_num_vars,
        }
    }

    pub(super) fn verify_and_update_state_input_step1_parallel(
        &self,
        prover_msg: (&SumcheckProof<F>, &[F]),
        transcript: &mut Transcript<F>,
    ) -> Result<(), GKRError> {
        let timer = start_timer!(|| "Verifier phase 2 input step 1");
        let lo_out_num_vars = self.lo_out_num_vars;
        let lo_in_num_vars = self.lo_in_num_vars;
        let hi_num_vars = self.hi_num_vars;
        let in_num_vars = lo_in_num_vars + hi_num_vars;
        let lo_point = &self.layer_out_point[..lo_out_num_vars];
        let hi_point = &self.layer_out_point[lo_out_num_vars..];

        let g_value_const = self
            .paste_from_const_in
            .iter()
            .map(|(c, l, r)| {
                let segment_greater_than_l_1 = if *l == 0 {
                    F::ONE
                } else {
                    segment_eval_greater_than(l - 1, lo_point)
                };
                let segment_greater_than_r_1 = segment_eval_greater_than(r - 1, lo_point);
                (*c) * (segment_greater_than_l_1 - segment_greater_than_r_1)
            })
            .sum::<F>();
        let sigma = self.layer_out_value - g_value_const;

        let claim = SumcheckState::verify(
            sigma,
            prover_msg.0,
            &VPAuxInfo {
                max_degree: 2,
                num_variables: in_num_vars,
                phantom: std::marker::PhantomData,
            },
            transcript,
        );

        let claim_point = claim.point.iter().map(|x| x.elements).collect_vec();
        let hi_point_sc1 = &claim_point[lo_in_num_vars..];
        let lo_point_sc1 = &claim_point[..lo_in_num_vars];

        let hi_eq_eval = eq_eval(hi_point, hi_point_sc1);
        let g_values = if self.paste_from_wires_in.len() == 1
            && self.paste_from_wires_in[0].0 == 0
            && self.paste_from_counter_in.len() == 0
        {
            // There is only one wire in, and it is pasted to the first layer,
            // left aligned.
            let paste_from_eval = eq_eval_less_or_equal_than(
                self.paste_from_wires_in[0].1 - 1,
                lo_point,
                lo_point_sc1,
            );
            vec![hi_eq_eval * paste_from_eval]
        } else {
            let eq_y_ry = build_eq_x_r_vec(lo_point);
            let eq_x1_rx1 = build_eq_x_r_vec(lo_point_sc1);
            self.paste_from_wires_in
                .iter()
                .chain(self.paste_from_counter_in.iter())
                .map(|(l, r)| {
                    (*l..*r)
                        .map(|i| hi_eq_eval * eq_y_ry[i] * eq_x1_rx1[i - l])
                        .sum::<F>()
                })
                .collect_vec()
        };

        let f_counter_values = self
            .paste_from_counter_in
            .iter()
            .map(|(l, r)| {
                let num_vars = ceil_log2(*r - *l);
                let point = lo_point_sc1
                    .iter()
                    .cloned()
                    .take(num_vars)
                    .chain(hi_point_sc1.iter().cloned())
                    .collect_vec();
                counter_eval(num_vars + hi_num_vars, &point)
                    * lo_point_sc1[num_vars..]
                        .iter()
                        .map(|x| F::ONE - *x)
                        .product::<F>()
            })
            .collect_vec();
        let got_value = prover_msg
            .1
            .iter()
            .chain(f_counter_values.iter())
            .zip(g_values)
            .map(|(&f, g)| f * g)
            .sum::<F>();

        end_timer!(timer);
        if claim.expected_evaluation != got_value {
            return Err(GKRError::VerifyError);
        }
        Ok(())
    }
}
