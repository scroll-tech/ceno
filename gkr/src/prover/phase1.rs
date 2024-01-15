use std::{ops::Add, sync::Arc};

use ark_std::{end_timer, start_timer};
use frontend::structs::{CellId, LayerId};
use goldilocks::SmallField;
use itertools::Itertools;
use multilinear_extensions::{
    mle::DenseMultilinearExtension,
    virtual_poly::{build_eq_x_r_vec, VirtualPolynomial},
};
use transcript::Transcript;

use crate::{
    prover::SumcheckState,
    structs::{Point, SumcheckProof},
    utils::{fix_high_variables, MatrixMLERowFirst},
};

use super::IOPProverPhase1State;

impl<'a, F: SmallField> IOPProverPhase1State<'a, F> {
    pub(super) fn prover_init_parallel(
        layer_out_poly: &'a Arc<DenseMultilinearExtension<F>>,
        next_evals: &'a [(Point<F>, F)],
        subset_evals: &'a [(LayerId, Point<F>, F)],
        alpha: &F,
        lo_num_vars: usize,
        hi_num_vars: usize,
    ) -> Self {
        let timer = start_timer!(|| "Prover init phase 1");
        let alpha_pows = {
            let mut alpha_pows = vec![F::ONE; next_evals.len() + subset_evals.len()];
            for i in 0..subset_evals.len().saturating_sub(1) {
                alpha_pows[i + 1] = alpha_pows[i] * alpha;
            }
            alpha_pows
        };
        end_timer!(timer);
        Self {
            layer_out_poly,
            next_evals,
            subset_evals,
            alpha_pows,
            lo_num_vars,
            hi_num_vars,
            sumcheck_point_1: vec![],
            f1_values: vec![],
            g1_values: vec![],
        }
    }

    /// Sumcheck 1: sigma = \sum_y( \sum_j f1^{(j)}(y) * g1^{(j)}(y) )
    ///     sigma = \sum_j( \alpha^j * subset[i][j](rt_j || ry_j) )
    ///     f1^{(j)}(y) = \sum_t( eq(rt_j, t) * layers[i](t || y) )
    ///     g1^{(j)}(y) = \alpha^j copy_to[j](ry_j, y)
    pub(super) fn prove_and_update_state_step1_parallel(
        &mut self,
        copy_to: impl Fn(&LayerId) -> &'a [CellId],
        transcript: &mut Transcript<F>,
    ) -> (SumcheckProof<F>, Vec<F>) {
        let timer = start_timer!(|| "Prover sumcheck phase 1 step 1");
        // sigma = \sum_j( \alpha^j * subset[i][j](rt_j || ry_j) )
        // f1^{(j)}(y) = \sum_t( eq(rt_j, t) * layers[i](t || y) )
        // g1^{(j)}(y) = \alpha^j copy_to[j](ry_j, y)
        let mut sigma_1 = F::ZERO;
        let mut f1 = Vec::with_capacity(self.next_evals.len() + self.subset_evals.len());
        let mut g1 = Vec::with_capacity(self.next_evals.len() + self.subset_evals.len());
        self.next_evals.iter().zip(self.alpha_pows.iter()).for_each(
            |((point, value), &alpha_pow)| {
                sigma_1 += alpha_pow * value;
                let point_lo_num_vars = point.len() - self.hi_num_vars;

                let f1_j = fix_high_variables(&self.layer_out_poly, &point[point_lo_num_vars..]);
                f1.push(Arc::new(f1_j));

                let g1_j = build_eq_x_r_vec(&point[..point_lo_num_vars])
                    .into_iter()
                    .take(1 << self.lo_num_vars)
                    .map(|eq| alpha_pow * eq)
                    .collect_vec();
                g1.push(Arc::new(DenseMultilinearExtension::from_evaluations_vec(
                    self.lo_num_vars,
                    g1_j,
                )));
            },
        );
        self.subset_evals
            .iter()
            .zip(self.alpha_pows.iter().skip(self.next_evals.len()))
            .for_each(|((new_layer_id, point, value), alpha_pow)| {
                sigma_1 += *alpha_pow * value;
                let point_lo_num_vars = point.len() - self.hi_num_vars;
                let copy_to = copy_to(new_layer_id);
                let lo_eq_w_p = build_eq_x_r_vec(&point[..point_lo_num_vars]);

                let f1_j = fix_high_variables(&self.layer_out_poly, &point[point_lo_num_vars..]);
                f1.push(Arc::new(f1_j));

                assert!(copy_to.len() <= lo_eq_w_p.len());
                let g1_j =
                    copy_to.fix_row_row_first_with_scaler(&lo_eq_w_p, self.lo_num_vars, alpha_pow);
                g1.push(Arc::new(DenseMultilinearExtension::from_evaluations_vec(
                    self.lo_num_vars,
                    g1_j,
                )));
            });

        // sumcheck: sigma = \sum_y( \sum_j f1^{(j)}(y) * g1^{(j)}(y) )
        let mut virtual_poly_1 = VirtualPolynomial::new(self.lo_num_vars);
        for (f1_j, g1_j) in f1.iter().zip(g1.iter()) {
            let mut tmp = VirtualPolynomial::new_from_mle(f1_j, F::ONE);
            tmp.mul_by_mle(g1_j.clone(), F::ONE);
            virtual_poly_1 = virtual_poly_1.add(&tmp);
        }

        // TODO: sumecheck should have one more parameter for sigma.
        let sumcheck_proof_1 = SumcheckState::prove(&virtual_poly_1, transcript);
        // assert_eq!(sumcheck_proof_1.extract_sum(), sigma_1);
        let eval_value_1 = f1
            .iter()
            .map(|f1_j| f1_j.evaluate(&sumcheck_proof_1.point))
            .collect_vec();

        self.sumcheck_point_1 = sumcheck_proof_1.point.clone();
        self.f1_values = eval_value_1.clone();
        self.g1_values = g1
            .iter()
            .map(|g1_j| g1_j.evaluate(&sumcheck_proof_1.point))
            .collect_vec();

        end_timer!(timer);
        (sumcheck_proof_1, eval_value_1)
    }

    /// Sumcheck 2: sigma = \sum_t( \sum_j( f2^{(j)}(t) ) ) * g2(t)
    ///     sigma = \sum_j( f1^{(j)}(ry) * g1^{(j)}(ry) )
    ///     f2(t) = layers[i](t || ry)
    ///     g2^{(j)}(t) = \alpha^j copy_to[j](ry_j, ry) eq(rt_j, t)
    pub(super) fn prove_and_update_state_step2_parallel(
        &mut self,
        transcript: &mut Transcript<F>,
    ) -> (SumcheckProof<F>, F) {
        let timer = start_timer!(|| "Prover sumcheck phase 1 step 2");
        // sigma = \sum_j( f1^{(j)}(ry) * g1^{(j)}(ry) )
        // let sigma_2 = self
        //     .f1_values
        //     .iter()
        //     .zip(self.g1_values.iter())
        //     .fold(F::ZERO, |acc, (&f1_value_j, g1_value_j)| {
        //         acc + f1_value_j * g1_value_j
        //     });

        // f2(t) = layers[i](t || ry)
        let f2 = Arc::new(self.layer_out_poly.fix_variables(&self.sumcheck_point_1));
        // g2^{(j)}(t) = \alpha^j copy_to[j](ry_j, ry) eq(rt_j, t)
        let g2 = self
            .next_evals
            .iter()
            .zip(self.g1_values.iter())
            .map(|((point, _), &g1_value)| {
                let point_lo_num_vars = point.len() - self.hi_num_vars;
                build_eq_x_r_vec(&point[point_lo_num_vars..])
                    .into_iter()
                    .map(|eq| g1_value * eq)
                    .collect_vec()
            })
            .chain(
                self.subset_evals
                    .iter()
                    .zip(self.g1_values.iter().skip(self.next_evals.len()))
                    .map(|((_, point, _), &g1_value)| {
                        let point_lo_num_vars = point.len() - self.hi_num_vars;
                        build_eq_x_r_vec(&point[point_lo_num_vars..])
                            .into_iter()
                            .map(|eq| g1_value * eq)
                            .collect_vec()
                    }),
            )
            .fold(vec![F::ZERO; 1 << self.hi_num_vars], |acc, nxt| {
                acc.into_iter()
                    .zip(nxt.into_iter())
                    .map(|(a, b)| a + b)
                    .collect_vec()
            });
        let g2 = Arc::new(DenseMultilinearExtension::from_evaluations_vec(
            self.hi_num_vars,
            g2,
        ));
        // sumcheck: sigma = \sum_t( \sum_j( g2^{(j)}(t) ) ) * f2(t)
        let mut virtual_poly_2 = VirtualPolynomial::new_from_mle(&f2, F::ONE);
        virtual_poly_2.mul_by_mle(g2, F::ONE);

        let sumcheck_proof_2 = SumcheckState::prove(&virtual_poly_2, transcript);
        // assert_eq!(sumcheck_proof_2.extract_sum(), sigma_2);
        let eval_value_2 = f2.evaluate(&sumcheck_proof_2.point);
        end_timer!(timer);
        (sumcheck_proof_2, eval_value_2)
    }
}
