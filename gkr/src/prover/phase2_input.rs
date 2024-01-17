use std::sync::Arc;

use ark_std::{end_timer, start_timer};
use ff::FromUniformBytes;
use goldilocks::SmallField;
use multilinear_extensions::{
    mle::DenseMultilinearExtension,
    virtual_poly::{build_eq_x_r_vec, VirtualPolynomial},
};
use std::ops::Add;
use transcript::Transcript;

use crate::{
    prover::SumcheckState,
    structs::{Point, SumcheckProof},
};

use super::IOPProverPhase2InputState;

impl<'a, F: SmallField + FromUniformBytes<64>> IOPProverPhase2InputState<'a, F> {
    pub(super) fn prover_init_parallel(
        layer_out_point: &'a Point<F>,
        wires_in: &'a [Vec<Vec<F>>],
        paste_from_wires_in: &'a [(usize, usize)],
        lo_out_num_vars: usize,
        lo_in_num_vars: usize,
        hi_num_vars: usize,
    ) -> Self {
        Self {
            layer_out_point,
            paste_from_wires_in,
            wires_in,
            lo_out_num_vars,
            lo_in_num_vars,
            hi_num_vars,
        }
    }

    pub(super) fn prove_and_update_state_input_step1_parallel(
        &self,
        transcript: &mut Transcript<F>,
    ) -> (SumcheckProof<F>, Vec<F>) {
        let timer = start_timer!(|| "Prover phase 2 input step 1");
        let lo_out_num_vars = self.lo_out_num_vars;
        let lo_in_num_vars = self.lo_in_num_vars;
        let hi_num_vars = self.hi_num_vars;
        let in_num_vars = lo_in_num_vars + hi_num_vars;
        let lo_point = &self.layer_out_point[..lo_out_num_vars];
        let hi_point = &self.layer_out_point[lo_out_num_vars..];

        let eq_y_ry = build_eq_x_r_vec(lo_point);
        let eq_t_rt = build_eq_x_r_vec(hi_point);

        let mut f_vec = vec![];
        let mut g_vec = vec![];
        let paste_from_wires_in = self.paste_from_wires_in;
        let wires_in = self.wires_in;
        for (j, (l, r)) in paste_from_wires_in.iter().enumerate() {
            let mut f = vec![F::ZERO; 1 << in_num_vars];
            let mut g = vec![F::ZERO; 1 << in_num_vars];
            for s in 0..(1 << hi_num_vars) {
                for new_wire_id in *l..*r {
                    let subset_wire_id = new_wire_id - l;
                    f[(s << lo_in_num_vars) ^ subset_wire_id] = wires_in[j][s][subset_wire_id];
                    g[(s << lo_in_num_vars) ^ subset_wire_id] = eq_t_rt[s] * eq_y_ry[new_wire_id];
                }
            }
            f_vec.push(Arc::new(DenseMultilinearExtension::from_evaluations_vec(
                in_num_vars,
                f,
            )));
            g_vec.push(Arc::new(DenseMultilinearExtension::from_evaluations_vec(
                in_num_vars,
                g,
            )));
        }

        let mut virtual_poly = VirtualPolynomial::new(in_num_vars);
        for (f, g) in f_vec.iter().zip(g_vec.iter()) {
            let mut tmp = VirtualPolynomial::new_from_mle(&f, F::ONE);
            tmp.mul_by_mle(g.clone(), F::ONE);
            virtual_poly = virtual_poly.add(&tmp);
        }

        let sumcheck_proof = SumcheckState::prove(&virtual_poly, transcript);
        let eval_point = sumcheck_proof.point.clone();
        let eval_values_f = f_vec.iter().map(|f| f.evaluate(&eval_point)).collect();
        end_timer!(timer);

        (sumcheck_proof, eval_values_f)
    }
}
