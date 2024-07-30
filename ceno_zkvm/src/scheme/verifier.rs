use std::{iter, marker::PhantomData, mem};

use ark_std::test_rng;
use ff_ext::ExtensionField;
use gkr::{structs::PointAndEval, util::ceil_log2};
use multilinear_extensions::virtual_poly::{build_eq_x_r_vec_sequential, VPAuxInfo};
use singer_utils::structs_v2::Circuit;
use sumcheck::structs::{IOPProof, IOPVerifierState};
use transcript::Transcript;

use crate::{error::ZKVMError, utils::get_challenge_pows};

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
        proof: &mut ZKVMProof<E>,
        transcript: &mut Transcript<E>,
        out_evals: &PointAndEval<E>,
        _challenges: &[E], // derive challenge from PCS
    ) -> Result<(), ZKVMError> {
        // TODO remove rng
        let mut rng = test_rng();
        let num_instances = proof.num_instances;
        let log2_num_instances = ceil_log2(num_instances);
        // verify and reduce product tower sumcheck

        // verify zero statement (degree > 1) + sel sumcheck
        // TODO fix rt_r/rt_w to use real
        let (r_counts_per_instance, w_counts_per_instance) = (
            self.circuit.r_expressions.len(),
            self.circuit.w_expressions.len(),
        );
        let (log2_r_count, log2_w_count) = (
            ceil_log2(r_counts_per_instance),
            ceil_log2(w_counts_per_instance),
        );
        let (rt_r, rt_w): (Vec<E>, Vec<E>) = (
            iter::repeat(E::random(&mut rng))
                .take(log2_num_instances + log2_r_count)
                .collect(),
            iter::repeat(E::random(&mut rng))
                .take(log2_num_instances + log2_w_count)
                .collect(),
        );

        let alpha_pow = get_challenge_pows(MAINCONSTRAIN_SUMCHECK_BATCH_SIZE, transcript);
        let (alpha_read, alpha_write) = (&alpha_pow[0], &alpha_pow[1]);
        let claim_sum = *alpha_read * (proof.out_record_r_eval - E::ONE)
            + *alpha_write * (proof.out_record_w_eval - E::ONE);
        let main_sel_subclaim = IOPVerifierState::verify(
            claim_sum,
            &IOPProof {
                point: vec![], // final claimed point will be derive from sumcheck protocol
                proofs: mem::take(&mut proof.main_sel_sumcheck_proofs),
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
            (w_counts_per_instance..w_counts_per_instance.next_power_of_two())
                .map(|i| sel_w * (eq_w[i] * alpha_write - E::ONE))
                .sum::<E>(),
        ]
        .iter()
        .sum::<E>();
        if computed_evals != expected_evaluation {
            return Err(ZKVMError::VerifyError);
        }
        // verify records (degree = 1) statement, thus no sumcheck
        let _input_opening_point = main_sel_eval_point;

        // verify zero expression (degree = 1) statement, thus no sumcheck
        Ok(())
    }
}
