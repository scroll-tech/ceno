use std::{cmp::max, marker::PhantomData};

use ff_ext::ExtensionField;
use gkr::{
    structs::{Point, PointAndEval},
    util::ceil_log2,
};
use itertools::{izip, Itertools};
use multilinear_extensions::{
    mle::{IntoMLE, MultilinearExtension},
    virtual_poly::{build_eq_x_r_vec_sequential, VPAuxInfo},
};
use singer_utils::structs_v2::Circuit;
use sumcheck::structs::{IOPProof, IOPVerifierState};
use transcript::Transcript;

use crate::{
    error::ZKVMError, scheme::constants::NUM_PRODUCT_FANIN, structs::TowerProofs,
    utils::get_challenge_pows,
};

use super::{constants::MAINCONSTRAIN_SUMCHECK_BATCH_SIZE, ZKVMProof};

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
        _challenges: &[E], // derive challenge from PCS
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
        let _rt = TowerVerify::verify(
            vec![
                proof.record_r_out_evals.clone(),
                proof.record_w_out_evals.clone(),
            ],
            tower_proofs,
            expected_max_round,
            num_product_fanin,
            transcript,
        )?;

        // verify zero statement (degree > 1) + sel sumcheck
        // TODO fix rt_r/rt_w to use real
        let (rt_r, rt_w): (Vec<E>, Vec<E>) = (
            (0..(log2_num_instances + log2_r_count))
                .map(|i| E::from(i as u64))
                .collect(),
            (0..(log2_num_instances + log2_w_count))
                .map(|i| E::from(i as u64))
                .collect(),
        );

        let alpha_pow = get_challenge_pows(MAINCONSTRAIN_SUMCHECK_BATCH_SIZE, transcript);
        let (alpha_read, alpha_write) = (&alpha_pow[0], &alpha_pow[1]);
        // let claim_sum = *alpha_read * (proof.record_r_sel_eval - E::ONE)
        //     + *alpha_write * (proof.record_w_sel_eval - E::ONE);
        let claim_sum = E::ONE; // TODO FIXME
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
        // TODO eval sel_r, sel_w
        let sel_r = E::ONE;
        let sel_w = E::ONE;
        let computed_evals = [
            // read non padding
            (0..r_counts_per_instance)
                .map(|i| sel_r * proof.r_records_in_evals[i] * eq_r[i] * alpha_read)
                .sum::<E>(),
            // read padding
            (r_counts_per_instance..r_counts_per_instance.next_power_of_two())
                .map(|i| sel_r * (eq_r[i] * alpha_read - E::ONE))
                .sum::<E>(),
            // write non padding
            (0..w_counts_per_instance)
                .map(|i| sel_w * proof.w_records_in_evals[i] * eq_w[i] * alpha_write)
                .sum::<E>(),
            // write padding
            (w_counts_per_instance..w_counts_per_instance.next_power_of_two())
                .map(|i| sel_w * (eq_w[i] * alpha_write - E::ONE))
                .sum::<E>(),
        ]
        .iter()
        .sum::<E>();
        if computed_evals != expected_evaluation {
            return Err(ZKVMError::VerifyError(
                "main + sel constraints verify failed",
            ));
        }
        // verify records (degree = 1) statement, thus no sumcheck
        let _input_opening_point = main_sel_eval_point;

        // verify zero expression (degree = 1) statement, thus no sumcheck
        Ok(())
    }
}

pub struct TowerVerify;

impl TowerVerify {
    pub fn verify<E: ExtensionField>(
        initial_evals: Vec<Vec<E>>,
        tower_proofs: &TowerProofs<E>,
        expected_max_round: usize,
        num_product_fanin: usize,
        transcript: &mut Transcript<E>,
    ) -> Result<Point<E>, ZKVMError> {
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

        let next_rt = (0..(expected_max_round - 1)).fold(
            PointAndEval {
                point: initial_rt,
                eval: initial_claim,
            },
            |point_and_eval, round| {
                let (_rt, out_claim) = (&point_and_eval.point, &point_and_eval.eval);
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

                // TODO check expected_evaluation
                let point: Point<E> = sumcheck_claim.point.iter().map(|c| c.elements).collect();

                // derive single eval
                // rt' = r_merge || rt
                // r_merge.len() == ceil_log2(num_product_fanin)
                let mut rt_prime = (0..log2_num_product_fanin)
                    .map(|_| transcript.get_and_append_challenge(b"merge").elements)
                    .collect_vec();
                let coeffs = build_eq_x_r_vec_sequential(&rt_prime);
                rt_prime.extend(point);
                assert_eq!(coeffs.len(), num_product_fanin);
                let spec_evals = (0..tower_proofs.spec_size()).map(|spec_index| {
                    if round < tower_proofs.specs_eval[spec_index].len() {
                        // merged evaluation
                        izip!(
                            tower_proofs.specs_eval[spec_index][round].iter(),
                            coeffs.iter()
                        )
                        .map(|(a, b)| *a * b)
                        .sum::<E>()
                    } else {
                        E::ZERO
                    }
                });
                // sum evaluation from different specs
                let next_eval = spec_evals
                    .zip(alpha_pows.iter())
                    .map(|(eval, alpha)| eval * alpha)
                    .sum();
                PointAndEval {
                    point: rt_prime,
                    eval: next_eval,
                }
            },
        );

        Ok(next_rt.point)
    }
}
