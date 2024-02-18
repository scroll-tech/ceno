use std::sync::Arc;

use ark_std::{end_timer, start_timer};
use goldilocks::SmallField;
use multilinear_extensions::{
    mle::DenseMultilinearExtension,
    virtual_poly::{build_eq_x_r_vec, VirtualPolynomial},
};
use simple_frontend::structs::CellId;
use std::ops::Add;
use transcript::Transcript;

use crate::{
    prover::SumcheckState,
    structs::{LayerWitness, Point, SumcheckProof},
};

use super::IOPProverPhase2InputState;

impl<'a, F: SmallField> IOPProverPhase2InputState<'a, F> {
    pub(super) fn prover_init_parallel(
        layer_out_point: &'a Point<F>,
        wits_in: &'a [LayerWitness<F::BaseField>],
        paste_from_wits_in: &'a [(CellId, CellId)],
        paste_from_counter_in: &'a [(usize, (CellId, CellId))],
        lo_out_num_vars: usize,
        lo_in_num_vars: Option<usize>,
        hi_num_vars: usize,
    ) -> Self {
        Self {
            layer_out_point,
            paste_from_wits_in,
            paste_from_counter_in,
            wits_in,
            lo_out_num_vars,
            lo_in_num_vars,
            hi_num_vars,
        }
    }

    pub(super) fn prove_and_update_state_input_step1_parallel(
        &self,
        transcript: &mut Transcript<F>,
    ) -> (SumcheckProof<F>, Vec<F>) {
        let timer = start_timer!(|| "Prover input phase 2 step 1");
        let lo_out_num_vars = self.lo_out_num_vars;
        if self.lo_in_num_vars.is_none() {
            return (SumcheckProof::default(), vec![]);
        }
        let lo_in_num_vars = self.lo_in_num_vars.unwrap();

        let hi_num_vars = self.hi_num_vars;
        let in_num_vars = lo_in_num_vars + hi_num_vars;
        let lo_point = &self.layer_out_point[..lo_out_num_vars];
        let hi_point = &self.layer_out_point[lo_out_num_vars..];

        let eq_y_ry = build_eq_x_r_vec(lo_point);
        let eq_t_rt = build_eq_x_r_vec(hi_point);

        let mut f_vec = vec![];
        let mut g_vec = vec![];
        let paste_from_wit_in = &self.paste_from_wits_in;
        let wits_in = self.wits_in;
        for (j, (l, r)) in paste_from_wit_in.iter().enumerate() {
            let mut f = vec![F::ZERO; 1 << in_num_vars];
            let mut g = vec![F::ZERO; 1 << in_num_vars];
            for s in 0..(1 << hi_num_vars) {
                for new_wire_id in *l..*r {
                    let subset_wire_id = new_wire_id - l;
                    f[(s << lo_in_num_vars) ^ subset_wire_id] =
                        F::from_base(&wits_in[j as usize].instances[s][subset_wire_id]);
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

        let paste_from_counter_in = &self.paste_from_counter_in;
        for (num_vars, (l, r)) in paste_from_counter_in.iter() {
            let mut f = vec![F::ZERO; 1 << in_num_vars];
            let mut g = vec![F::ZERO; 1 << in_num_vars];
            for s in 0..(1 << hi_num_vars) {
                for new_wire_id in *l..*r {
                    let subset_wire_id = new_wire_id - l;
                    f[(s << lo_in_num_vars) ^ subset_wire_id] =
                        F::from(((s << num_vars) ^ subset_wire_id) as u64);
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
        let eval_values_f = f_vec
            .iter()
            .take(wits_in.len())
            .map(|f| f.evaluate(&eval_point))
            .collect();
        end_timer!(timer);

        (sumcheck_proof, eval_values_f)
    }
}
