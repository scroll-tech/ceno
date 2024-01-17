use std::{iter, sync::Arc};

use ark_std::{end_timer, start_timer};
use ff::FromUniformBytes;
use frontend::structs::ConstantType;
use goldilocks::SmallField;
use itertools::Itertools;
use multilinear_extensions::{
    mle::DenseMultilinearExtension,
    virtual_poly::{build_eq_x_r_vec, VirtualPolynomial},
};
use std::ops::Add;
use transcript::Transcript;

use crate::{
    structs::{Gate1In, Gate2In, Gate3In, GateCIn, Layer, Point, SumcheckProof},
    utils::{fix_high_variables, tensor_product, MultilinearExtensionFromVectors},
};

use super::{IOPProverPhase2State, SumcheckState};

impl<'a, F: SmallField + FromUniformBytes<64>> IOPProverPhase2State<'a, F> {
    pub(super) fn prover_init_parallel(
        layer: &'a Layer<F>,
        layer_out_poly: &'a Arc<DenseMultilinearExtension<F>>,
        layer_out_point: &Point<F>,
        layer_out_value: F,
        layer_in_vec: &'a [Vec<F>],
        paste_from_sources: &'a [Vec<Vec<F>>],
        constant: impl Fn(&ConstantType<F>) -> F,
        hi_num_vars: usize,
    ) -> Self {
        let timer = start_timer!(|| "Prover init phase 2");
        let mul3s = layer
            .mul3s
            .iter()
            .map(|gate| Gate3In {
                idx_in1: gate.idx_in1,
                idx_in2: gate.idx_in2,
                idx_in3: gate.idx_in3,
                idx_out: gate.idx_out,
                scaler: constant(&gate.scaler),
            })
            .collect_vec();
        let mul2s = layer
            .mul2s
            .iter()
            .map(|gate| Gate2In {
                idx_in1: gate.idx_in1,
                idx_in2: gate.idx_in2,
                idx_out: gate.idx_out,
                scaler: constant(&gate.scaler),
            })
            .collect_vec();
        let adds = layer
            .adds
            .iter()
            .map(|gate| Gate1In {
                idx_in: gate.idx_in,
                idx_out: gate.idx_out,
                scaler: constant(&gate.scaler),
            })
            .collect_vec();
        let assert_consts = layer
            .assert_consts
            .iter()
            .map(|gate| GateCIn {
                idx_out: gate.idx_out,
                constant: constant(&gate.constant),
            })
            .collect_vec();
        let lo_out_num_vars = layer.num_vars;
        let lo_in_num_vars = layer.max_previous_num_vars;
        let eq_y_ry = build_eq_x_r_vec(&layer_out_point[..lo_out_num_vars]);
        let eq_t_rt = build_eq_x_r_vec(&layer_out_point[lo_out_num_vars..]);
        let tensor_eq_ty_rtry = tensor_product(&eq_t_rt, &eq_y_ry);

        let layer_in_poly = layer_in_vec.mle(lo_in_num_vars, hi_num_vars);

        end_timer!(timer);

        Self {
            layer_out_poly,
            layer_out_point: layer_out_point.clone(),
            layer_out_value,
            mul3s,
            mul2s,
            adds,
            assert_consts,
            paste_from: &layer.paste_from,
            paste_from_sources,
            lo_out_num_vars,
            lo_in_num_vars,
            hi_num_vars,
            layer_in_poly,
            layer_in_vec,
            // sumcheck_sigma: F::ZERO,
            sumcheck_point_1: vec![],
            sumcheck_point_2: vec![],
            eq_t_rt,
            eq_y_ry,
            tensor_eq_ty_rtry,
            eq_x1_rx1: vec![],
            eq_s1_rs1: vec![],
            tensor_eq_s1x1_rs1rx1: vec![],
            eq_x2_rx2: vec![],
            eq_s2_rs2: vec![],
            tensor_eq_s2x2_rs2rx2: vec![],
        }
    }

    /// Sumcheck 0: sigma = \sum_{x1} f0(x1) * g0(x1)
    ///     sigma = layers[i](rt || ry) - assert_const(ry)
    ///     f0(x1) = eq(ry, x1) - asserted_subset(ry, x1)
    ///     g0(x1) = layers[i](rt || x1)
    pub(super) fn prove_and_update_state_step0_parallel(
        &mut self,
        transcript: &mut Transcript<F>,
    ) -> (SumcheckProof<F>, Vec<F>) {
        let timer = start_timer!(|| "Prover sumcheck phase 2 step 0");

        let layer_out_poly = &self.layer_out_poly;
        let lo_out_num_vars = self.lo_out_num_vars;
        let hi_point = &self.layer_out_point[self.lo_out_num_vars..];
        let eq_y_ry = &self.eq_y_ry;
        let assert_consts = &self.assert_consts;

        if lo_out_num_vars == 0 {
            end_timer!(timer);
            return (
                SumcheckProof {
                    point: vec![],
                    proofs: vec![],
                },
                vec![],
            );
        }

        // f0(x1) = layers[i](rt || x1)
        let f0 = Arc::new(fix_high_variables(&layer_out_poly, &hi_point));
        // g0(x1) = eq(ry, x1) - asserted_subset(ry, x1)
        let g0 = {
            let mut g0 = eq_y_ry.clone();
            assert_consts.iter().for_each(|gate| {
                g0[gate.idx_out] = F::ZERO;
            });
            Arc::new(DenseMultilinearExtension::from_evaluations_vec(
                lo_out_num_vars,
                g0,
            ))
        };

        // sumcheck: sigma = \sum_{x1} f0(x1) * g0(x1)
        let mut virtual_poly_0 = VirtualPolynomial::new_from_mle(&f0, F::ONE);
        virtual_poly_0.mul_by_mle(g0.clone(), F::ONE);
        let sumcheck_proof_0 = SumcheckState::prove(&virtual_poly_0, transcript);
        let eval_value_0 = f0.evaluate(&sumcheck_proof_0.point);

        self.eq_y_ry = build_eq_x_r_vec(&sumcheck_proof_0.point);
        self.eq_t_rt = build_eq_x_r_vec(hi_point);
        self.tensor_eq_ty_rtry = tensor_product(&self.eq_t_rt, &self.eq_y_ry);
        self.layer_out_point = [sumcheck_proof_0.point.clone(), hi_point.to_vec()].concat();
        self.layer_out_value = eval_value_0;

        end_timer!(timer);

        (sumcheck_proof_0, vec![eval_value_0])
    }

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
    pub(super) fn prove_and_update_state_step1_parallel(
        &mut self,
        old_wire_id: impl Fn(usize, usize) -> usize,
        transcript: &mut Transcript<F>,
    ) -> (SumcheckProof<F>, Vec<F>) {
        let timer = start_timer!(|| "Prover sumcheck phase 2 step 1");
        let lo_out_num_vars = self.lo_out_num_vars;
        let lo_in_num_vars = self.lo_in_num_vars;
        let hi_num_vars = self.hi_num_vars;
        let in_num_vars = lo_in_num_vars + hi_num_vars;

        let mul3s = &self.mul3s;
        let mul2s = &self.mul2s;
        let adds = &self.adds;

        let tensor_eq_ty_rtry = &self.tensor_eq_ty_rtry;
        let layer_in_poly = &self.layer_in_poly;
        let layer_in_vec = self.layer_in_vec;
        // sigma = layers[i](rt || ry) - add_const(ry),
        // let sigma_1 = self.layer_out_value - add_consts.as_slice().eval(eq_y_ry);
        let (mut f1_vec, mut g1_vec) = {
            // f1(s1 || x1) = layers[i + 1](s1 || x1)
            let f1 = layer_in_poly.clone();

            // g1(s1 || x1) = \sum_{s2}( \sum_{s3}( \sum_{x2}( \sum_{x3}(
            //     eq(rt, s1, s2, s3) * mul3(ry, x1, x2, x3) * layers[i + 1](s2 || x2) * layers[i + 1](s3 || x3)
            // ) ) ) ) + \sum_{s2}( \sum_{x2}(
            //     eq(rt, s1, s2) * mul2(ry, x1, x2) * layers[i + 1](s2 || x2)
            // ) ) + eq(rt, s1) * add(ry, x1)
            let g1 = {
                let mut g1 = vec![F::ZERO; 1 << in_num_vars];
                mul3s.iter().for_each(|gate| {
                    for s in 0..(1 << hi_num_vars) {
                        g1[(s << lo_in_num_vars) ^ gate.idx_in1] += tensor_eq_ty_rtry
                            [(s << lo_out_num_vars) ^ gate.idx_out]
                            * gate.scaler
                            * layer_in_vec[s][gate.idx_in2]
                            * layer_in_vec[s][gate.idx_in3];
                    }
                });
                mul2s.iter().for_each(|gate| {
                    for s in 0..(1 << hi_num_vars) {
                        g1[(s << lo_in_num_vars) ^ gate.idx_in1] += tensor_eq_ty_rtry
                            [(s << lo_out_num_vars) ^ gate.idx_out]
                            * gate.scaler
                            * layer_in_vec[s][gate.idx_in2];
                    }
                });
                adds.iter().for_each(|gate| {
                    for s in 0..(1 << hi_num_vars) {
                        g1[(s << lo_in_num_vars) ^ gate.idx_in] +=
                            tensor_eq_ty_rtry[(s << lo_out_num_vars) ^ gate.idx_out] * gate.scaler;
                    }
                });
                Arc::new(DenseMultilinearExtension::from_evaluations_vec(
                    in_num_vars,
                    g1,
                ))
            };
            (vec![f1], vec![g1])
        };
        // f1'^{(j)}(s1 || x1) = subset[j][i](s1 || x1)
        // g1'^{(j)}(s1 || x1) = eq(rt, s1) paste_from[j](ry, x1)
        let paste_from = self.paste_from;
        let paste_from_sources = self.paste_from_sources;
        paste_from.iter().for_each(|(&j, paste_from)| {
            let mut f1_j = vec![F::ZERO; 1 << in_num_vars];
            let mut g1_j = vec![F::ZERO; 1 << in_num_vars];

            paste_from
                .iter()
                .enumerate()
                .for_each(|(subset_wire_id, &new_wire_id)| {
                    for s in 0..(1 << hi_num_vars) {
                        f1_j[(s << lo_in_num_vars) ^ subset_wire_id] =
                            paste_from_sources[j][s][old_wire_id(j, subset_wire_id)];
                        g1_j[(s << lo_in_num_vars) ^ subset_wire_id] +=
                            tensor_eq_ty_rtry[(s << lo_out_num_vars) ^ new_wire_id];
                    }
                });
            f1_vec.push(Arc::new(DenseMultilinearExtension::from_evaluations_vec(
                in_num_vars,
                f1_j,
            )));
            g1_vec.push(Arc::new(DenseMultilinearExtension::from_evaluations_vec(
                in_num_vars,
                g1_j,
            )));
        });

        // sumcheck: sigma = \sum_{s1 || x1} f1(s1 || x1) * g1(s1 || x1) + \sum_j f1'_j(s1 || x1) * g1'_j(s1 || x1)
        let mut virtual_poly_1 = VirtualPolynomial::new(in_num_vars);
        for (f1_j, g1_j) in f1_vec.iter().zip(g1_vec.iter()) {
            let mut tmp = VirtualPolynomial::new_from_mle(&f1_j, F::ONE);
            tmp.mul_by_mle(g1_j.clone(), F::ONE);
            virtual_poly_1 = virtual_poly_1.add(&tmp);
        }

        let sumcheck_proof_1 = SumcheckState::prove(&virtual_poly_1, transcript);
        // assert_eq!(sumcheck_proof_1.extract_sum(), sigma_1);
        let eval_point_1 = sumcheck_proof_1.point.clone();
        let eval_values_f1 = f1_vec
            .iter()
            .map(|f1_j| f1_j.evaluate(&eval_point_1))
            .collect_vec();

        let eval_values_1 = {
            let eval_values_g1_0 = g1_vec[0].evaluate(&eval_point_1);
            self.eq_x1_rx1 = build_eq_x_r_vec(&eval_point_1[..lo_in_num_vars]);
            self.eq_s1_rs1 = build_eq_x_r_vec(&eval_point_1[lo_in_num_vars..]);
            self.tensor_eq_s1x1_rs1rx1 = tensor_product(&self.eq_s1_rs1, &self.eq_x1_rx1);
            // sigma = g1(rs1 || rx1) - eq(rt, rs1) * add(ry, rx1)
            // self.sumcheck_sigma = eval_values_g1_0
            //     - eq_eval(
            //         &self.layer_out_point[lo_out_num_vars..],
            //         &eval_point_1[lo_in_num_vars..],
            //     ) * adds.as_slice().eval(&eq_y_ry, &self.eq_x1_rx1);

            self.sumcheck_point_1 = eval_point_1.clone();

            eval_values_f1
                .into_iter()
                .chain(iter::once(eval_values_g1_0))
                .collect_vec()
        };
        end_timer!(timer);

        (sumcheck_proof_1, eval_values_1)
    }

    /// Sumcheck 2 sigma = \sum_{s2 || x2} f2(s2 || x2) * g2(s2 || x2)
    ///     sigma = g1(rs1 || rx1) - eq(rt, rs1) * add(ry, rx1)
    ///     f2(s2 || x2) = layers[i + 1](s2 || x2)
    ///     g2(s2 || x2) = \sum_{s3}( \sum_{x3}(
    ///         eq(rt, rs1, s2, s3) * mul3(ry, rx1, x2, x3) * layers[i + 1](s3 || x3)
    ///     ) ) + eq(rt, rs1, s2) * mul2(ry, rx1, x2)
    pub(super) fn prove_and_update_state_step2_parallel(
        &mut self,
        transcript: &mut Transcript<F>,
    ) -> (SumcheckProof<F>, Vec<F>) {
        let timer = start_timer!(|| "Prover sumcheck phase 2 step 2");
        let lo_out_num_vars = self.lo_out_num_vars;
        let lo_in_num_vars = self.lo_in_num_vars;
        let hi_num_vars = self.hi_num_vars;

        let layer_in_poly = &self.layer_in_poly;
        let layer_in_vec = self.layer_in_vec;

        let mul3s = &self.mul3s;
        let mul2s = &self.mul2s;

        let tensor_eq_ty_rtry = &self.tensor_eq_ty_rtry;
        let tensor_eq_s1x1_rs1rx1 = &self.tensor_eq_s1x1_rs1rx1;

        // f2(s2 || x2) = layers[i + 1](s2 || x2)
        let f2 = layer_in_poly.clone();
        // g2(s2 || x2) = \sum_{s3}( \sum_{x3}(
        //     eq(rt, rs1, s2, s3) * mul3(ry, rx1, x2, x3) * layers[i + 1](s3 || x3)
        // ) ) + eq(rt, rs1, s2) * mul2(ry, rx1, x2)
        let g2 = {
            let mut g2 = vec![F::ZERO; 1 << f2.num_vars];
            mul3s.iter().for_each(|gate| {
                for s in 0..(1 << hi_num_vars) {
                    g2[(s << lo_in_num_vars) ^ gate.idx_in2] += tensor_eq_ty_rtry
                        [(s << lo_out_num_vars) ^ gate.idx_out]
                        * tensor_eq_s1x1_rs1rx1[(s << lo_in_num_vars) ^ gate.idx_in1]
                        * gate.scaler
                        * layer_in_vec[s][gate.idx_in3];
                }
            });
            mul2s.iter().for_each(|gate| {
                for s in 0..(1 << hi_num_vars) {
                    g2[(s << lo_in_num_vars) ^ gate.idx_in2] += tensor_eq_ty_rtry
                        [(s << lo_out_num_vars) ^ gate.idx_out]
                        * tensor_eq_s1x1_rs1rx1[(s << lo_in_num_vars) ^ gate.idx_in1]
                        * gate.scaler;
                }
            });
            Arc::new(DenseMultilinearExtension::from_evaluations_vec(
                f2.num_vars,
                g2,
            ))
        };
        // sumcheck: sigma = \sum_{s2 || x2} f2(s2 || x2) * g2(s2 || x2)
        let mut virtual_poly_2 = VirtualPolynomial::new_from_mle(&f2, F::ONE);
        virtual_poly_2.mul_by_mle(g2.clone(), F::ONE);
        let sumcheck_proof_2 = SumcheckState::prove(&virtual_poly_2, transcript);
        // assert_eq!(sumcheck_proof_2.extract_sum(), self.sumcheck_sigma);
        let eval_point_2 = sumcheck_proof_2.point.clone();
        let eval_value_f2 = f2.evaluate(&eval_point_2);
        let eval_value_g2 = g2.evaluate(&eval_point_2);

        self.eq_x2_rx2 = build_eq_x_r_vec(&eval_point_2[..lo_in_num_vars]);
        self.eq_s2_rs2 = build_eq_x_r_vec(&eval_point_2[lo_in_num_vars..]);
        self.tensor_eq_s2x2_rs2rx2 = tensor_product(&self.eq_s2_rs2, &self.eq_x2_rx2);
        // sigma = g2(rs2 || rx2) - eq(rt, rs1, rs2) * mul2(ry, rx1, rx2)
        // self.sumcheck_sigma = eval_value_g2
        //     - eq3_eval(
        //         &self.layer_out_point[lo_out_num_vars..],
        //         &self.sumcheck_point_1[lo_in_num_vars..],
        //         &eval_point_2[lo_in_num_vars..],
        //     ) * mul2s.as_slice().eval(&eq_y_ry, &eq_x1_rx1, &self.eq_x2_rx2);

        self.sumcheck_point_2 = eval_point_2.clone();
        end_timer!(timer);

        (sumcheck_proof_2, vec![eval_value_f2, eval_value_g2])
    }

    /// Sumcheck 3 sigma = \sum_{s3 || x3} f3(s3 || x3) * g3(s3 || x3)
    ///     sigma = g2(rs2 || rx2) - eq(rt, rs1, rs2) * mul2(ry, rx1, rx2)
    ///     f3(s3 || x3) = layers[i + 1](s3 || x3)
    ///     g3(s3 || x3) = eq(rt, rs1, rs2, s3) * mul3(ry, rx1, rx2, x3)
    pub(super) fn prove_and_update_state_step3_parallel(
        &mut self,
        transcript: &mut Transcript<F>,
    ) -> (SumcheckProof<F>, Vec<F>) {
        let timer = start_timer!(|| "Prover sumcheck phase 2 step 3");
        let lo_out_num_vars = self.lo_out_num_vars;
        let lo_in_num_vars = self.lo_in_num_vars;
        let hi_num_vars = self.hi_num_vars;

        let layer_in_poly = &self.layer_in_poly;

        let mul3s = &self.mul3s;

        let tensor_eq_ty_rtry = &self.tensor_eq_ty_rtry;
        let tensor_eq_s1x1_rs1rx1 = &self.tensor_eq_s1x1_rs1rx1;
        let tensor_eq_s2x2_rs2rx2 = &self.tensor_eq_s2x2_rs2rx2;

        // f3(s3 || x3) = layers[i + 1](s3 || x3)
        let f3 = layer_in_poly.clone();
        // g3(s3 || x3) = eq(rt, rs1, rs2, s3) * mul3(ry, rx1, rx2, x3)
        let g3 = {
            let mut g3 = vec![F::ZERO; 1 << f3.num_vars];
            mul3s.iter().for_each(|gate| {
                for s in 0..(1 << hi_num_vars) {
                    g3[(s << lo_in_num_vars) ^ gate.idx_in3] += tensor_eq_ty_rtry
                        [(s << lo_out_num_vars) ^ gate.idx_out]
                        * tensor_eq_s1x1_rs1rx1[(s << lo_in_num_vars) ^ gate.idx_in1]
                        * tensor_eq_s2x2_rs2rx2[(s << lo_in_num_vars) ^ gate.idx_in2]
                        * gate.scaler;
                }
            });
            Arc::new(DenseMultilinearExtension::from_evaluations_vec(
                f3.num_vars,
                g3,
            ))
        };
        // sumcheck: sigma = \sum_{s3 || x3} f3(s3 || x3) * g3(s3 || x3)
        let mut virtual_poly_3 = VirtualPolynomial::new_from_mle(&f3, F::ONE);
        virtual_poly_3.mul_by_mle(g3.clone(), F::ONE);
        let sumcheck_proof_3 = SumcheckState::prove(&virtual_poly_3, transcript);
        // assert_eq!(sumcheck_proof_3.extract_sum(), self.sumcheck_sigma);
        let eval_point_3 = sumcheck_proof_3.point.clone();
        let eval_values_3 = vec![f3.evaluate(&eval_point_3)];
        end_timer!(timer);
        (sumcheck_proof_3, eval_values_3)
    }
}
