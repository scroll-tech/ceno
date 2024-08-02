use std::{cmp::max, marker::PhantomData};

use ark_std::iterable::Iterable;
use ff_ext::{ff::Field, ExtensionField};
use gkr::{
    structs::{Point, PointAndEval},
    util::ceil_log2,
};
use itertools::{izip, Itertools};
use multilinear_extensions::{
    mle::{IntoMLE, MultilinearExtension},
    virtual_poly::{build_eq_x_r_vec_sequential, eq_eval, VPAuxInfo},
};
use singer_utils::structs_v2::Circuit;
use sumcheck::structs::{IOPProof, IOPVerifierState};
use transcript::Transcript;

use crate::{
    error::ZKVMError, scheme::constants::NUM_PRODUCT_FANIN, structs::TowerProofs,
    utils::get_challenge_pows,
};

use super::{constants::MAINCONSTRAIN_SUMCHECK_BATCH_SIZE, utils::eval_by_expr, ZKVMProof};

pub struct ZKVMVerifier<E: ExtensionField> {
    circuit: Circuit<E>,
}

impl<E: ExtensionField> ZKVMVerifier<E> {
    pub fn new(circuit: Circuit<E>) -> Self {
        ZKVMVerifier { circuit }
    }
    pub fn verify(
        &self,
        proof: &ZKVMProof<E>,
        transcript: &mut Transcript<E>,
        num_product_fanin: usize,
        _out_evals: &PointAndEval<E>,
        challenges: &[E], // derive challenge from PCS
    ) -> Result<(), ZKVMError> {
        let (r_counts_per_instance, w_counts_per_instance) = (
            self.circuit.r_expressions.len(),
            self.circuit.w_expressions.len(),
        );
        let (log2_r_count, log2_w_count) = (
            ceil_log2(r_counts_per_instance),
            ceil_log2(w_counts_per_instance),
        );

        let num_instances = proof.num_instances;
        let log2_num_instances = ceil_log2(num_instances);

        // verify and reduce product tower sumcheck
        let tower_proofs = &proof.tower_proof;

        // check read/write set equality
        if proof.record_r_out_evals.iter().product::<E>()
            != proof.record_w_out_evals.iter().product()
        {
            // TODO add me back
            // return Err(ZKVMError::VerifyError("rw set equality check failed"));
        }
        let expected_max_round = log2_num_instances + max(log2_r_count, log2_w_count); // TODO add lookup
        let (rt_tower, record_evals) = TowerVerify::verify(
            vec![
                proof.record_r_out_evals.clone(),
                proof.record_w_out_evals.clone(),
            ],
            tower_proofs,
            expected_max_round,
            num_product_fanin,
            transcript,
        )?;
        assert!(record_evals.len() == 2, "[r_record, w_record]");

        // verify zero statement (degree > 1) + sel sumcheck
        let (rt_r, rt_w): (Vec<E>, Vec<E>) = (
            rt_tower[..log2_num_instances + log2_r_count].to_vec(),
            rt_tower[..log2_num_instances + log2_w_count].to_vec(),
        );

        let alpha_pow = get_challenge_pows(MAINCONSTRAIN_SUMCHECK_BATCH_SIZE, transcript);
        let (alpha_read, alpha_write) = (&alpha_pow[0], &alpha_pow[1]);
        let claim_sum =
            *alpha_read * (record_evals[0] - E::ONE) + *alpha_write * (record_evals[1] - E::ONE);
        let main_sel_subclaim = IOPVerifierState::verify(
            claim_sum,
            &IOPProof {
                point: vec![], // final claimed point will be derive from sumcheck protocol
                proofs: proof.main_sel_sumcheck_proofs.clone(),
            },
            &VPAuxInfo {
                max_degree: 2,
                num_variables: log2_num_instances,
                phantom: PhantomData,
            },
            transcript,
        );
        let (main_sel_eval_point, expected_evaluation) = (
            main_sel_subclaim.point.clone(),
            main_sel_subclaim.expected_evaluation,
        );
        let eq_r = build_eq_x_r_vec_sequential(&rt_r[..log2_r_count]);
        let eq_w = build_eq_x_r_vec_sequential(&rt_w[..log2_w_count]);

        let (sel_r, sel_w) = {
            // TODO sel evaluation is very costly, maybe optimize it via PCS?
            let mut sel = vec![E::BaseField::ONE; 1 << log2_num_instances];
            if num_instances < sel.len() {
                sel.splice(
                    num_instances..sel.len(),
                    std::iter::repeat(E::BaseField::ZERO),
                );
            }
            let sel = sel.into_mle();
            (
                sel.evaluate(&rt_r[log2_r_count..]),
                sel.evaluate(&rt_w[log2_w_count..]),
            )
        };
        let computed_evals = [
            // read
            *alpha_read
                * sel_r
                * ((0..r_counts_per_instance)
                    .map(|i| proof.r_records_in_evals[i] * eq_r[i])
                    .sum::<E>()
                    + eq_r[r_counts_per_instance..].iter().sum::<E>()
                    - E::ONE),
            // write non padding
            *alpha_write
                * sel_w
                * ((0..w_counts_per_instance)
                    .map(|i| proof.w_records_in_evals[i] * eq_w[i])
                    .sum::<E>()
                    + eq_w[w_counts_per_instance..].iter().sum::<E>()
                    - E::ONE),
        ]
        .iter()
        .sum::<E>();
        if computed_evals != expected_evaluation {
            // TODO add me back
            // return Err(ZKVMError::VerifyError(
            //     "main + sel evaluation verify failed",
            // ));
        }
        // verify records (degree = 1) statement, thus no sumcheck
        if self
            .circuit
            .r_expressions
            .iter()
            .chain(self.circuit.w_expressions.iter())
            .zip_eq(
                proof.r_records_in_evals[..r_counts_per_instance]
                    .iter()
                    .chain(proof.w_records_in_evals[..w_counts_per_instance].iter()),
            )
            .any(|(expr, expected_evals)| {
                eval_by_expr(&proof.wits_in_evals, challenges, &expr) != *expected_evals
            })
        {
            return Err(ZKVMError::VerifyError("record evaluate zer != 0"));
        }

        let _input_opening_point = main_sel_eval_point;

        // verify zero expression (degree = 1) statement, thus no sumcheck
        if self
            .circuit
            .assert_zero_expressions
            .iter()
            .any(|expr| eval_by_expr(&proof.wits_in_evals, challenges, &expr) != E::ZERO)
        {
            // TODO add me back
            // return Err(ZKVMError::VerifyError("zero expression != 0"));
        }

        Ok(())
    }
}

pub struct TowerVerify;

impl TowerVerify {
    // TODO review hyper parameter usage and trust less from prover
    pub fn verify<E: ExtensionField>(
        initial_evals: Vec<Vec<E>>,
        tower_proofs: &TowerProofs<E>,
        expected_max_round: usize,
        num_product_fanin: usize,
        transcript: &mut Transcript<E>,
    ) -> Result<(Point<E>, Vec<E>), ZKVMError> {
        let log2_num_product_fanin = ceil_log2(num_product_fanin);
        // sanity check
        assert!(initial_evals.len() == tower_proofs.spec_size());
        assert!(
            initial_evals
                .iter()
                .all(|evals| evals.len() == num_product_fanin)
        );

        let alpha_pows = get_challenge_pows(tower_proofs.spec_size(), transcript);
        let initial_rt: Point<E> = (0..log2_num_product_fanin)
            .map(|_| transcript.get_and_append_challenge(b"product_sum").elements)
            .collect_vec();
        // initial_claim = \sum_j alpha^j * record_{j}[rt]
        let initial_claim = izip!(initial_evals, alpha_pows.iter())
            .map(|(evals, alpha)| evals.into_mle().evaluate(&initial_rt) * alpha)
            .sum();

        // evaluation in the tower input layer
        let mut spec_input_layer_eval = vec![E::ZERO; tower_proofs.spec_size()];

        let next_rt = (0..(expected_max_round - 1)).try_fold(
            PointAndEval {
                point: initial_rt,
                eval: initial_claim,
            },
            |point_and_eval, round| {
                let (out_rt, out_claim) = (&point_and_eval.point, &point_and_eval.eval);
                let sumcheck_claim = IOPVerifierState::verify(
                    *out_claim,
                    &IOPProof {
                        point: vec![], // final claimed point will be derive from sumcheck protocol
                        proofs: tower_proofs.proofs[round].clone(),
                    },
                    &VPAuxInfo {
                        max_degree: NUM_PRODUCT_FANIN + 1, // + 1 for eq
                        num_variables: (round + 1) * log2_num_product_fanin,
                        phantom: PhantomData,
                    },
                    transcript,
                );

                // check expected_evaluation
                let rt: Point<E> = sumcheck_claim.point.iter().map(|c| c.elements).collect();
                let expected_evaluation: E = (0..tower_proofs.spec_size())
                    .map(|spec_index| {
                        eq_eval(&out_rt, &rt)
                            * alpha_pows[spec_index]
                            * tower_proofs.specs_eval[spec_index]
                                .get(round)
                                .map(|evals| evals.iter().product())
                                .unwrap_or(E::ZERO)
                    })
                    .sum();
                if expected_evaluation != sumcheck_claim.expected_evaluation {
                    return Err(ZKVMError::VerifyError("mismatch tower evaluation"));
                }

                // derive single eval
                // rt' = r_merge || rt
                // r_merge.len() == ceil_log2(num_product_fanin)
                let r_merge = (0..log2_num_product_fanin)
                    .map(|_| transcript.get_and_append_challenge(b"merge").elements)
                    .collect_vec();
                let coeffs = build_eq_x_r_vec_sequential(&r_merge);
                assert_eq!(coeffs.len(), num_product_fanin);
                let rt_prime = vec![rt, r_merge].concat();

                let spec_evals = (0..tower_proofs.spec_size())
                    .map(|spec_index| {
                        if round < tower_proofs.specs_eval[spec_index].len() {
                            // merged evaluation
                            let evals = izip!(
                                tower_proofs.specs_eval[spec_index][round].iter(),
                                coeffs.iter()
                            )
                            .map(|(a, b)| *a * b)
                            .sum::<E>();
                            // this will keep update until round > evaluation
                            spec_input_layer_eval[spec_index] = evals;
                            evals
                        } else {
                            E::ZERO
                        }
                    })
                    .collect::<Vec<E>>();
                // sum evaluation from different specs
                let next_eval = spec_evals
                    .iter()
                    .zip(alpha_pows.iter())
                    .map(|(eval, alpha)| *eval * alpha)
                    .sum();
                Ok(PointAndEval {
                    point: rt_prime,
                    eval: next_eval,
                })
            },
        )?;

        Ok((next_rt.point, spec_input_layer_eval))
    }
}
