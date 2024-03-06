use ark_std::{end_timer, start_timer};
use goldilocks::SmallField;
use itertools::Itertools;
use multilinear_extensions::virtual_poly::{build_eq_x_r_vec, eq_eval, VPAuxInfo};
use simple_frontend::structs::ConstantType;
use transcript::Transcript;

use crate::{
    circuit::{EvaluateGate1In, EvaluateGate2In, EvaluateGate3In, EvaluateGateCIn},
    error::GKRError,
    structs::{Gate1In, Gate2In, Gate3In, GateCIn, Layer, Point, SumcheckProof},
    utils::{eq3_eval, eq4_eval, MatrixMLEColumnFirst},
};

use super::{IOPVerifierPhase2State, SumcheckState};

impl<'a, F: SmallField> IOPVerifierPhase2State<'a, F> {
    pub(super) fn verifier_init_parallel(
        layer: &'a Layer<F>,
        layer_out_point: &Point<F>,
        layer_out_value: &F,
        constant: impl Fn(ConstantType<F>) -> F::BaseField,
        hi_num_vars: usize,
    ) -> Self {
        let timer = start_timer!(|| "Verifier init phase 2");
        let mul3s = layer
            .mul3s
            .iter()
            .map(|gate| Gate3In {
                idx_in: gate.idx_in,
                idx_out: gate.idx_out,
                scalar: constant(gate.scalar),
            })
            .collect_vec();
        let mul2s = layer
            .mul2s
            .iter()
            .map(|gate| Gate2In {
                idx_in: gate.idx_in,
                idx_out: gate.idx_out,
                scalar: constant(gate.scalar),
            })
            .collect_vec();
        let adds = layer
            .adds
            .iter()
            .map(|gate| Gate1In {
                idx_in: gate.idx_in,
                idx_out: gate.idx_out,
                scalar: constant(gate.scalar),
            })
            .collect_vec();
        let add_consts = layer
            .add_consts
            .iter()
            .map(|gate| GateCIn {
                idx_in: gate.idx_in,
                idx_out: gate.idx_out,
                scalar: constant(gate.scalar),
            })
            .collect_vec();
        let assert_consts = layer
            .assert_consts
            .iter()
            .map(|gate| GateCIn {
                idx_in: gate.idx_in,
                idx_out: gate.idx_out,
                scalar: constant(gate.scalar),
            })
            .collect_vec();
        let lo_out_num_vars = layer.num_vars;
        let lo_in_num_vars = layer.max_previous_num_vars;
        let eq_y_ry = build_eq_x_r_vec(&layer_out_point[..lo_out_num_vars]);
        end_timer!(timer);
        Self {
            layer_out_point: layer_out_point.clone(),
            layer_out_value: *layer_out_value,
            mul3s,
            mul2s,
            adds,
            add_consts,
            assert_consts,
            paste_from: &layer.paste_from,
            lo_out_num_vars,
            lo_in_num_vars,
            hi_num_vars,
            sumcheck_sigma: F::ZERO,
            sumcheck_point_1: vec![],
            sumcheck_point_2: vec![],
            sumcheck_point_3: vec![],
            eq_y_ry,
            eq_x1_rx1: vec![],
            eq_x2_rx2: vec![],
        }
    }

    pub(super) fn verify_and_update_state_step0_parallel(
        &mut self,
        prover_msg: (&SumcheckProof<F>, &[F]),
        transcript: &mut Transcript<F>,
    ) -> Result<(), GKRError> {
        let timer = start_timer!(|| "Verifier sumcheck phase 2 step 0");
        let lo_out_num_vars = self.lo_out_num_vars;
        let layer_out_point = &self.layer_out_point;
        let layer_out_value = self.layer_out_value;

        let assert_consts = &self.assert_consts;

        let lo_point = &layer_out_point[..lo_out_num_vars];
        let hi_point = &layer_out_point[lo_out_num_vars..];
        let eq_y_ry = &self.eq_y_ry;

        if lo_out_num_vars == 0 {
            end_timer!(timer);
            if layer_out_value != self.assert_consts.as_slice().eval(&self.eq_y_ry) {
                return Err(GKRError::VerifyError);
            }
            return Ok(());
        }

        // sigma = layers[i](rt || ry) - assert_const(ry)
        let sigma_0 = layer_out_value - assert_consts.as_slice().eval(&eq_y_ry);
        // Sumcheck 0: sigma = \sum_{x1} f0(x1) * g0(x1)
        //     f0(x1) = layers[i](rt || x1)
        //     g0(x1) = eq(ry, x1) - asserted_subset(ry, x1)
        let claim_0 = SumcheckState::verify(
            sigma_0,
            prover_msg.0,
            &VPAuxInfo {
                max_degree: 2,
                num_variables: lo_out_num_vars,
                phantom: std::marker::PhantomData,
            },
            transcript,
        );
        let claim0_point = claim_0.point.iter().map(|x| x.elements).collect_vec();
        let eq_x_rx = build_eq_x_r_vec(&claim0_point);
        let f0_value = prover_msg.1[0];
        let g0_value = eq_eval(&lo_point, &claim0_point)
            - assert_consts.as_slice().eval_subset_eq(&eq_y_ry, &eq_x_rx);

        end_timer!(timer);
        if claim_0.expected_evaluation != f0_value * g0_value {
            return Err(GKRError::VerifyError);
        }

        self.eq_y_ry = build_eq_x_r_vec(&claim0_point);
        self.layer_out_point = [claim0_point, hi_point.to_vec()].concat();
        self.layer_out_value = f0_value;
        self.sumcheck_sigma = g0_value;

        Ok(())
    }

    pub(super) fn verify_and_update_state_step1_parallel(
        &mut self,
        prover_msg: (&SumcheckProof<F>, &[F]),
        transcript: &mut Transcript<F>,
    ) -> Result<(), GKRError> {
        let timer = start_timer!(|| "Verifier sumcheck phase 2 step 1");
        let lo_out_num_vars = self.lo_out_num_vars;
        let lo_in_num_vars = self.lo_in_num_vars;
        let hi_num_vars = self.hi_num_vars;
        let in_num_vars = lo_in_num_vars + hi_num_vars;

        let adds = &self.adds;
        let add_consts = &self.add_consts;

        let hi_point = &self.layer_out_point[lo_out_num_vars..];
        let eq_y_ry = &self.eq_y_ry;

        // sigma = layers[i](rt || ry) - add_const(ry),
        // Sumcheck 1: sigma = \sum_{s1 || x1} f1(s1 || x1) * g1(s1 || x1) + \sum_j f1'_j(s1 || x1) * g1'_j(s1 || x1)
        //     f1(s1 || x1) = layers[i + 1](s1 || x1)
        //     g1(s1 || x1) = \sum_{s2}( \sum_{s3}( \sum_{x2}( \sum_{x3}(
        //         eq(rt, s1, s2, s3) * mul3(ry, x1, x2, x3) * layers[i + 1](s2 || x2) * layers[i + 1](s3 || x3)
        //     ) ) ) ) + \sum_{s2}( \sum_{x2}(
        //         eq(rt, s1, s2) * mul2(ry, x1, x2) * layers[i + 1](s2 || x2)
        //     ) ) + eq(rt, s1) * add(ry, x1)
        //     f1'^{(j)}(s1 || x1) = subset[j][i](s1 || x1)
        //     g1'^{(j)}(s1 || x1) = eq(rt, s1) paste_from[j](ry, x1)
        self.sumcheck_sigma = self.layer_out_value - add_consts.as_slice().eval(eq_y_ry);
        let claim_1 = SumcheckState::verify(
            self.sumcheck_sigma,
            prover_msg.0,
            &VPAuxInfo {
                max_degree: 2,
                num_variables: in_num_vars,
                phantom: std::marker::PhantomData,
            },
            transcript,
        );
        let claim1_point = claim_1.point.iter().map(|x| x.elements).collect_vec();
        let hi_point_sc1 = &claim1_point[lo_in_num_vars..];
        let lo_point_sc1 = &claim1_point[..lo_in_num_vars];

        self.eq_x1_rx1 = build_eq_x_r_vec(lo_point_sc1);
        let (f1_values, received_g1_values) = prover_msg.1.split_at(prover_msg.1.len() - 1);
        let g1_values = {
            let hi_eq_eval = eq_eval(&hi_point, hi_point_sc1);
            received_g1_values
                .iter()
                .cloned()
                .chain(self.paste_from.iter().map(|(_, paste_from)| {
                    hi_eq_eval
                        * paste_from
                            .as_slice()
                            .eval_col_first(&eq_y_ry, &self.eq_x1_rx1)
                }))
                .collect_vec()
        };
        let got_value_1 = f1_values
            .iter()
            .zip(g1_values.iter())
            .fold(F::ZERO, |acc, (&f1, g1)| acc + f1 * g1);
        if claim_1.expected_evaluation != got_value_1 {
            end_timer!(timer);
            return Err(GKRError::VerifyError);
        }

        self.eq_x1_rx1 = build_eq_x_r_vec(&claim1_point[..lo_in_num_vars]);
        // sigma = g1(rs1 || rx1) - eq(rt, rs1) * add(ry, rx1)
        self.sumcheck_sigma = g1_values[0]
            - eq_eval(
                &self.layer_out_point[lo_out_num_vars..],
                &claim1_point[lo_in_num_vars..],
            ) * adds.as_slice().eval(&eq_y_ry, &self.eq_x1_rx1);
        self.sumcheck_point_1 = claim1_point.clone();

        end_timer!(timer);
        Ok(())
    }

    pub(super) fn verify_and_update_state_step2_parallel(
        &mut self,
        prover_msg: (&SumcheckProof<F>, &[F]),
        transcript: &mut Transcript<F>,
    ) -> Result<(), GKRError> {
        let timer = start_timer!(|| "Verifier sumcheck phase 2 step 2");
        let lo_out_num_vars = self.lo_out_num_vars;
        let lo_in_num_vars = self.lo_in_num_vars;
        let hi_num_vars = self.hi_num_vars;
        let in_num_vars = lo_in_num_vars + hi_num_vars;

        let mul2s = &self.mul2s;

        let eq_y_ry = &self.eq_y_ry;
        let eq_x1_rx1 = &self.eq_x1_rx1;
        // Sumcheck 2 sigma = \sum_{s2 || x2} f2(s2 || x2) * g2(s2 || x2)
        //     f2(s2 || x2) = layers[i + 1](s2 || x2)
        //     g2(s2 || x2) = \sum_{s3}( \sum_{x3}(
        //         eq(rt, rs1, s2, s3) * mul3(ry, rx1, x2, x3) * layers[i + 1](s3 || x3)
        //     ) ) + eq(rt, rs1, s2) * mul2(ry, rx1, x2)}
        let claim_2 = SumcheckState::verify(
            self.sumcheck_sigma,
            prover_msg.0,
            &VPAuxInfo {
                max_degree: 2,
                num_variables: in_num_vars,
                phantom: std::marker::PhantomData,
            },
            transcript,
        );
        let claim2_point = claim_2.point.iter().map(|x| x.elements).collect_vec();
        let f2_value = prover_msg.1[0];
        let g2_value = prover_msg.1[1];
        let got_value_2 = f2_value * g2_value;

        if claim_2.expected_evaluation != got_value_2 {
            end_timer!(timer);
            return Err(GKRError::VerifyError);
        }

        self.eq_x2_rx2 = build_eq_x_r_vec(&claim2_point[..lo_in_num_vars]);
        // sigma = g2(rs2 || rx2) - eq(rt, rs1, rs2) * mul2(ry, rx1, rx2)
        self.sumcheck_sigma = g2_value
            - eq3_eval(
                &self.layer_out_point[lo_out_num_vars..],
                &self.sumcheck_point_1[lo_in_num_vars..],
                &claim2_point[lo_in_num_vars..],
            ) * mul2s.as_slice().eval(&eq_y_ry, &eq_x1_rx1, &self.eq_x2_rx2);
        self.sumcheck_point_2 = claim2_point.clone();
        end_timer!(timer);
        Ok(())
    }

    pub(super) fn verify_and_update_state_step3_parallel(
        &mut self,
        prover_msg: (&SumcheckProof<F>, &[F]),
        transcript: &mut Transcript<F>,
    ) -> Result<(), GKRError> {
        let timer = start_timer!(|| "Verifier sumcheck phase 2 step 3");
        let lo_in_num_vars = self.lo_in_num_vars;
        let hi_num_vars = self.hi_num_vars;
        let in_num_vars = lo_in_num_vars + hi_num_vars;

        let mul3s = &self.mul3s;

        let eq_y_ry = &self.eq_y_ry;
        let eq_x1_rx1 = &self.eq_x1_rx1;
        let eq_x2_rx2 = &self.eq_x2_rx2;

        // Sumcheck 3 sigma = \sum_{s3 || x3} f3(s3 || x3) * g3(s3 || x3)
        //     f3(s3 || x3) = layers[i + 1](s3 || x3)
        //     g3(s3 || x3) = eq(rt, rs1, rs2, s3) * mul3(ry, rx1, rx2, x3)
        let claim_3 = SumcheckState::verify(
            self.sumcheck_sigma,
            &prover_msg.0,
            &VPAuxInfo {
                max_degree: 2,
                num_variables: in_num_vars,
                phantom: std::marker::PhantomData,
            },
            transcript,
        );
        let claim3_point = claim_3.point.iter().map(|x| x.elements).collect_vec();
        let lo_point_sc3 = &claim3_point[..lo_in_num_vars];
        let eq_x3_rx3 = build_eq_x_r_vec(lo_point_sc3);
        let f3_value = prover_msg.1[0];
        let g3_value = eq4_eval(
            &self.layer_out_point[self.lo_out_num_vars..],
            &self.sumcheck_point_1[self.lo_in_num_vars..],
            &self.sumcheck_point_2[self.lo_in_num_vars..],
            &claim3_point[self.lo_in_num_vars..],
        ) * mul3s
            .as_slice()
            .eval(&eq_y_ry, &eq_x1_rx1, &eq_x2_rx2, &eq_x3_rx3);
        let got_value_3 = f3_value * g3_value;
        end_timer!(timer);
        if claim_3.expected_evaluation != got_value_3 {
            return Err(GKRError::VerifyError);
        }
        self.sumcheck_point_3 = claim3_point.clone();
        Ok(())
    }
}
