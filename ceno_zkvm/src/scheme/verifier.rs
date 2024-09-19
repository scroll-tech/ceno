use std::marker::PhantomData;

use ark_std::iterable::Iterable;
use ff_ext::ExtensionField;

use itertools::{izip, Itertools};
use mpcs::PolynomialCommitmentScheme;
use multilinear_extensions::{
    mle::{IntoMLE, MultilinearExtension},
    util::ceil_log2,
    virtual_poly::{build_eq_x_r_vec_sequential, eq_eval, VPAuxInfo},
};
use sumcheck::structs::{IOPProof, IOPVerifierState};
use transcript::Transcript;

use crate::{
    error::ZKVMError,
    scheme::{
        constants::{NUM_FANIN, NUM_FANIN_LOGUP, SEL_DEGREE},
        utils::eval_by_expr_with_fixed,
    },
    structs::{Point, PointAndEval, TowerProofs, VerifyingKey, ZKVMVerifyingKey},
    utils::{get_challenge_pows, sel_eval},
};

use super::{
    constants::MAINCONSTRAIN_SUMCHECK_BATCH_SIZE, utils::eval_by_expr, ZKVMOpcodeProof, ZKVMProof,
    ZKVMTableProof,
};

pub struct ZKVMVerifier<E: ExtensionField, PCS: PolynomialCommitmentScheme<E>> {
    pub(crate) vk: ZKVMVerifyingKey<E, PCS>,
}

impl<E: ExtensionField, PCS: PolynomialCommitmentScheme<E>> ZKVMVerifier<E, PCS> {
    pub fn new(vk: ZKVMVerifyingKey<E, PCS>) -> Self {
        ZKVMVerifier { vk }
    }

    pub fn verify_proof(
        &self,
        vm_proof: ZKVMProof<E, PCS>,
        mut transcript: Transcript<E>,
    ) -> Result<bool, ZKVMError> {
        // main invariant between opcode circuits and table circuits
        let mut prod_r = E::ONE;
        let mut prod_w = E::ONE;
        let mut logup_sum = E::ZERO;

        // TODO: write fixed commitment to transcript

        for (_, (_, proof)) in vm_proof.opcode_proofs.iter() {
            PCS::write_commitment(&proof.wits_commit, &mut transcript)
                .map_err(ZKVMError::PCSError)?;
        }
        for (_, (_, proof)) in vm_proof.table_proofs.iter() {
            PCS::write_commitment(&proof.wits_commit, &mut transcript)
                .map_err(ZKVMError::PCSError)?;
        }

        // alpha, beta
        let challenges = [
            transcript.read_challenge().elements,
            transcript.read_challenge().elements,
        ];
        tracing::debug!("challenges: {:?}", challenges);

        let dummy_table_item = challenges[0];
        let mut dummy_table_item_multiplicity = 0;
        let point_eval = PointAndEval::default();
        let mut transcripts = transcript.fork(vm_proof.num_circuits());

        for (name, (i, opcode_proof)) in vm_proof.opcode_proofs {
            let transcript = &mut transcripts[i];

            let circuit_vk = self
                .vk
                .circuit_vks
                .get(&name)
                .ok_or(ZKVMError::VKNotFound(name.clone()))?;
            let _rand_point = self.verify_opcode_proof(
                &name,
                &self.vk.vp,
                circuit_vk,
                &opcode_proof,
                transcript,
                NUM_FANIN,
                &point_eval,
                &challenges,
            )?;
            tracing::info!("verified proof for opcode {}", name);

            // getting the number of dummy padding item that we used in this opcode circuit
            let num_lks = circuit_vk.get_cs().lk_expressions.len();
            let num_padded_lks_per_instance = num_lks.next_power_of_two() - num_lks;
            let num_padded_instance =
                opcode_proof.num_instances.next_power_of_two() - opcode_proof.num_instances;
            dummy_table_item_multiplicity += num_padded_lks_per_instance
                * opcode_proof.num_instances
                + num_lks.next_power_of_two() * num_padded_instance;

            prod_r *= opcode_proof.record_r_out_evals.iter().product::<E>();
            prod_w *= opcode_proof.record_w_out_evals.iter().product::<E>();

            logup_sum +=
                opcode_proof.lk_p1_out_eval * opcode_proof.lk_q1_out_eval.invert().unwrap();
            logup_sum +=
                opcode_proof.lk_p2_out_eval * opcode_proof.lk_q2_out_eval.invert().unwrap();
        }

        for (name, (i, table_proof)) in vm_proof.table_proofs {
            let transcript = &mut transcripts[i];

            let circuit_vk = self
                .vk
                .circuit_vks
                .get(&name)
                .ok_or(ZKVMError::VKNotFound(name.clone()))?;
            let _rand_point = self.verify_table_proof(
                &name,
                &self.vk.vp,
                circuit_vk,
                &table_proof,
                transcript,
                NUM_FANIN_LOGUP,
                &point_eval,
                &challenges,
            )?;
            tracing::info!("verified proof for table {}", name);

            logup_sum -= table_proof.lk_p1_out_eval * table_proof.lk_q1_out_eval.invert().unwrap();
            logup_sum -= table_proof.lk_p2_out_eval * table_proof.lk_q2_out_eval.invert().unwrap();
        }
        logup_sum -=
            E::from(dummy_table_item_multiplicity as u64) * dummy_table_item.invert().unwrap();

        // check rw_set equality across all proofs
        // TODO: enable this when we have cpu init/finalize and mem init/finalize
        // if prod_r != prod_w {
        //     return Err(ZKVMError::VerifyError("prod_r != prod_w".into()));
        // }

        // check logup relation across all proofs
        if logup_sum != E::ZERO {
            return Err(ZKVMError::VerifyError(format!(
                "logup_sum({:?}) != 0",
                logup_sum
            )));
        }

        Ok(true)
    }

    /// verify proof and return input opening point
    #[allow(clippy::too_many_arguments)]
    pub fn verify_opcode_proof(
        &self,
        name: &str,
        vp: &PCS::VerifierParam,
        circuit_vk: &VerifyingKey<E, PCS>,
        proof: &ZKVMOpcodeProof<E, PCS>,
        transcript: &mut Transcript<E>,
        num_product_fanin: usize,
        _out_evals: &PointAndEval<E>,
        challenges: &[E; 2], // derive challenge from PCS
    ) -> Result<Point<E>, ZKVMError> {
        let cs = circuit_vk.get_cs();
        let (r_counts_per_instance, w_counts_per_instance, lk_counts_per_instance) = (
            cs.r_expressions.len(),
            cs.w_expressions.len(),
            cs.lk_expressions.len(),
        );
        let (log2_r_count, log2_w_count, log2_lk_count) = (
            ceil_log2(r_counts_per_instance),
            ceil_log2(w_counts_per_instance),
            ceil_log2(lk_counts_per_instance),
        );
        let (chip_record_alpha, _) = (challenges[0], challenges[1]);

        let num_instances = proof.num_instances;
        let log2_num_instances = ceil_log2(num_instances);

        // verify and reduce product tower sumcheck
        let tower_proofs = &proof.tower_proof;

        let (rt_tower, record_evals, logup_p_evals, logup_q_evals) = TowerVerify::verify(
            vec![
                proof.record_r_out_evals.clone(),
                proof.record_w_out_evals.clone(),
            ],
            vec![vec![
                proof.lk_p1_out_eval,
                proof.lk_p2_out_eval,
                proof.lk_q1_out_eval,
                proof.lk_q2_out_eval,
            ]],
            tower_proofs,
            vec![
                log2_num_instances + log2_r_count,
                log2_num_instances + log2_w_count,
                log2_num_instances + log2_lk_count,
            ],
            num_product_fanin,
            transcript,
        )?;
        assert!(record_evals.len() == 2, "[r_record, w_record]");
        assert!(logup_q_evals.len() == 1, "[lk_q_record]");
        assert!(logup_p_evals.len() == 1, "[lk_p_record]");

        // verify LogUp witness nominator p(x) ?= constant vector 1
        // index 0 is LogUp witness for Fixed Lookup table
        if logup_p_evals[0].eval != E::ONE {
            return Err(ZKVMError::VerifyError(
                "Lookup table witness p(x) != constant 1".into(),
            ));
        }

        // verify zero statement (degree > 1) + sel sumcheck
        let (rt_r, rt_w, rt_lk): (Vec<E>, Vec<E>, Vec<E>) = (
            record_evals[0].point.clone(),
            record_evals[1].point.clone(),
            logup_q_evals[0].point.clone(),
        );

        let alpha_pow = get_challenge_pows(
            MAINCONSTRAIN_SUMCHECK_BATCH_SIZE + cs.assert_zero_sumcheck_expressions.len(),
            transcript,
        );
        let mut alpha_pow_iter = alpha_pow.iter();
        let (alpha_read, alpha_write, alpha_lk) = (
            alpha_pow_iter.next().unwrap(),
            alpha_pow_iter.next().unwrap(),
            alpha_pow_iter.next().unwrap(),
        );
        // alpha_read * (out_r[rt] - 1) + alpha_write * (out_w[rt] - 1) + alpha_lk * (out_lk_q - chip_record_alpha)
        // + 0 // 0 come from zero check
        let claim_sum = *alpha_read * (record_evals[0].eval - E::ONE)
            + *alpha_write * (record_evals[1].eval - E::ONE)
            + *alpha_lk * (logup_q_evals[0].eval - chip_record_alpha);

        let main_sel_subclaim = IOPVerifierState::verify(
            claim_sum,
            &IOPProof {
                point: vec![], // final claimed point will be derive from sumcheck protocol
                proofs: proof.main_sel_sumcheck_proofs.clone(),
            },
            &VPAuxInfo {
                // + 1 from sel_non_lc_zero_sumcheck
                max_degree: SEL_DEGREE.max(cs.max_non_lc_degree + 1),
                num_variables: log2_num_instances,
                phantom: PhantomData,
            },
            transcript,
        );
        let (input_opening_point, expected_evaluation) = (
            main_sel_subclaim
                .point
                .iter()
                .map(|c| c.elements)
                .collect_vec(),
            main_sel_subclaim.expected_evaluation,
        );
        let eq_r = build_eq_x_r_vec_sequential(&rt_r[..log2_r_count]);
        let eq_w = build_eq_x_r_vec_sequential(&rt_w[..log2_w_count]);
        let eq_lk = build_eq_x_r_vec_sequential(&rt_lk[..log2_lk_count]);

        let (sel_r, sel_w, sel_lk, sel_non_lc_zero_sumcheck) = {
            // sel(rt, t) = eq(rt, t) x sel(t)
            (
                eq_eval(&rt_r[log2_r_count..], &input_opening_point)
                    * sel_eval(num_instances, &input_opening_point),
                eq_eval(&rt_w[log2_w_count..], &input_opening_point)
                    * sel_eval(num_instances, &input_opening_point),
                eq_eval(&rt_lk[log2_lk_count..], &input_opening_point)
                    * sel_eval(num_instances, &input_opening_point),
                // only initialize when circuit got non empty assert_zero_sumcheck_expressions
                {
                    let rt_non_lc_sumcheck = rt_tower[..log2_num_instances].to_vec();
                    if !cs.assert_zero_sumcheck_expressions.is_empty() {
                        Some(
                            eq_eval(&rt_non_lc_sumcheck, &input_opening_point)
                                * sel_eval(num_instances, &rt_non_lc_sumcheck),
                        )
                    } else {
                        None
                    }
                },
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
            // write
            *alpha_write
                * sel_w
                * ((0..w_counts_per_instance)
                    .map(|i| proof.w_records_in_evals[i] * eq_w[i])
                    .sum::<E>()
                    + eq_w[w_counts_per_instance..].iter().sum::<E>()
                    - E::ONE),
            // lookup
            *alpha_lk
                * sel_lk
                * ((0..lk_counts_per_instance)
                    .map(|i| proof.lk_records_in_evals[i] * eq_lk[i])
                    .sum::<E>()
                    + chip_record_alpha
                        * (eq_lk[lk_counts_per_instance..].iter().sum::<E>() - E::ONE)),
            // degree > 1 zero exp sumcheck
            {
                // sel(rt_non_lc_sumcheck, main_sel_eval_point) * \sum_j (alpha{j} * expr(main_sel_eval_point))
                sel_non_lc_zero_sumcheck.unwrap_or(E::ZERO)
                    * cs.assert_zero_sumcheck_expressions
                        .iter()
                        .zip_eq(alpha_pow_iter)
                        .map(|(expr, alpha)| {
                            // evaluate zero expression by all wits_in_evals because they share the unique input_opening_point opening
                            *alpha * eval_by_expr(&proof.wits_in_evals, challenges, expr)
                        })
                        .sum::<E>()
            },
        ]
        .iter()
        .sum::<E>();
        if computed_evals != expected_evaluation {
            return Err(ZKVMError::VerifyError(
                "main + sel evaluation verify failed".into(),
            ));
        }
        // verify records (degree = 1) statement, thus no sumcheck
        if cs
            .r_expressions
            .iter()
            .chain(cs.w_expressions.iter())
            .chain(cs.lk_expressions.iter())
            .zip_eq(
                proof.r_records_in_evals[..r_counts_per_instance]
                    .iter()
                    .chain(proof.w_records_in_evals[..w_counts_per_instance].iter())
                    .chain(proof.lk_records_in_evals[..lk_counts_per_instance].iter()),
            )
            .any(|(expr, expected_evals)| {
                eval_by_expr(&proof.wits_in_evals, challenges, expr) != *expected_evals
            })
        {
            return Err(ZKVMError::VerifyError(
                "record evaluate != expected_evals".into(),
            ));
        }

        // verify zero expression (degree = 1) statement, thus no sumcheck
        if cs
            .assert_zero_expressions
            .iter()
            .any(|expr| eval_by_expr(&proof.wits_in_evals, challenges, expr) != E::ZERO)
        {
            // TODO add me back
            // return Err(ZKVMError::VerifyError("zero expression != 0"));
        }

        tracing::debug!(
            "[opcode {}] verify opening proof for {} polys at {:?}",
            name,
            proof.wits_in_evals.len(),
            input_opening_point
        );
        PCS::simple_batch_verify(
            vp,
            &proof.wits_commit,
            &input_opening_point,
            &proof.wits_in_evals,
            &proof.wits_opening_proof,
            transcript,
        )
        .map_err(ZKVMError::PCSError)?;

        Ok(input_opening_point)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn verify_table_proof(
        &self,
        name: &str,
        vp: &PCS::VerifierParam,
        circuit_vk: &VerifyingKey<E, PCS>,
        proof: &ZKVMTableProof<E, PCS>,
        transcript: &mut Transcript<E>,
        num_logup_fanin: usize,
        _out_evals: &PointAndEval<E>,
        challenges: &[E; 2],
    ) -> Result<Point<E>, ZKVMError> {
        let cs = circuit_vk.get_cs();
        let lk_counts_per_instance = cs.lk_table_expressions.len();
        let log2_lk_count = ceil_log2(lk_counts_per_instance);

        let num_instances = proof.num_instances;
        let log2_num_instances = ceil_log2(num_instances);

        // verify and reduce product tower sumcheck
        let tower_proofs = &proof.tower_proof;

        let expected_max_round = log2_num_instances + log2_lk_count;
        let (_, _, logup_p_evals, logup_q_evals) = TowerVerify::verify(
            vec![],
            vec![vec![
                proof.lk_p1_out_eval,
                proof.lk_p2_out_eval,
                proof.lk_q1_out_eval,
                proof.lk_q2_out_eval,
            ]],
            tower_proofs,
            vec![expected_max_round],
            num_logup_fanin,
            transcript,
        )?;
        assert!(logup_q_evals.len() == 1, "[lk_q_record]");
        assert!(logup_p_evals.len() == 1, "[lk_p_record]");
        assert_eq!(logup_p_evals[0].point, logup_q_evals[0].point);

        // verify selector layer sumcheck
        let rt_lk: Vec<E> = logup_p_evals[0].point.to_vec();

        // 2 for denominator and numerator
        let alpha_pow = get_challenge_pows(2, transcript);
        let mut alpha_pow_iter = alpha_pow.iter();
        let (alpha_lk_d, alpha_lk_n) = (
            alpha_pow_iter.next().unwrap(),
            alpha_pow_iter.next().unwrap(),
        );
        // alpha_lk * (out_lk_q - one) + alpha_lk_n * out_lk_p
        let claim_sum =
            *alpha_lk_d * (logup_q_evals[0].eval - E::ONE) + *alpha_lk_n * logup_p_evals[0].eval;
        let sel_subclaim = IOPVerifierState::verify(
            claim_sum,
            &IOPProof {
                point: vec![], // final claimed point will be derived from sumcheck protocol
                proofs: proof.sel_sumcheck_proofs.clone(),
            },
            &VPAuxInfo {
                max_degree: SEL_DEGREE.max(cs.max_non_lc_degree),
                num_variables: log2_num_instances,
                phantom: PhantomData,
            },
            transcript,
        );
        let (input_opening_point, expected_evaluation) = (
            sel_subclaim.point.iter().map(|c| c.elements).collect_vec(),
            sel_subclaim.expected_evaluation,
        );
        let eq_lk = build_eq_x_r_vec_sequential(&rt_lk[..log2_lk_count]);

        let sel_lk = eq_eval(&rt_lk[log2_lk_count..], &input_opening_point)
            * sel_eval(num_instances, &rt_lk[log2_lk_count..]);

        let computed_evals = [
            // lookup denominator
            *alpha_lk_d
                * sel_lk
                * ((0..lk_counts_per_instance)
                    .map(|i| proof.lk_d_in_evals[i] * eq_lk[i])
                    .sum::<E>()
                    + (eq_lk[lk_counts_per_instance..].iter().sum::<E>() - E::ONE)),
            *alpha_lk_n
                * sel_lk
                * ((0..lk_counts_per_instance)
                    .map(|i| proof.lk_n_in_evals[i] * eq_lk[i])
                    .sum::<E>()),
        ]
        .iter()
        .sum::<E>();
        if computed_evals != expected_evaluation {
            return Err(ZKVMError::VerifyError(
                "sel evaluation verify failed".into(),
            ));
        }
        // verify records (degree = 1) statement, thus no sumcheck
        if cs
            .lk_table_expressions
            .iter()
            .map(|lk| &lk.values)
            .chain(cs.lk_table_expressions.iter().map(|lk| &lk.multiplicity))
            .zip_eq(
                proof.lk_d_in_evals[..lk_counts_per_instance]
                    .iter()
                    .chain(proof.lk_n_in_evals[..lk_counts_per_instance].iter()),
            )
            .any(|(expr, expected_evals)| {
                eval_by_expr_with_fixed(
                    &proof.fixed_in_evals,
                    &proof.wits_in_evals,
                    challenges,
                    expr,
                ) != *expected_evals
            })
        {
            return Err(ZKVMError::VerifyError(
                "record evaluate != expected_evals".into(),
            ));
        }

        tracing::debug!(
            "[table {}] verify opening proof for {} polys at {:?}: values = {:?}, commit = {:?}",
            name,
            proof.wits_in_evals.len(),
            input_opening_point,
            proof.wits_in_evals,
            proof.wits_commit
        );
        PCS::simple_batch_verify(
            vp,
            &proof.wits_commit,
            &input_opening_point,
            &proof.wits_in_evals,
            &proof.wits_opening_proof,
            transcript,
        )
        .map_err(ZKVMError::PCSError)?;

        // TODO: verify fixed opening proof

        Ok(input_opening_point)
    }
}

pub struct TowerVerify;

pub type TowerVerifyResult<E> = Result<
    (
        Point<E>,
        Vec<PointAndEval<E>>,
        Vec<PointAndEval<E>>,
        Vec<PointAndEval<E>>,
    ),
    ZKVMError,
>;

impl TowerVerify {
    pub fn verify<E: ExtensionField>(
        prod_out_evals: Vec<Vec<E>>,
        logup_out_evals: Vec<Vec<E>>,
        tower_proofs: &TowerProofs<E>,
        expected_rounds: Vec<usize>,
        num_fanin: usize,
        transcript: &mut Transcript<E>,
    ) -> TowerVerifyResult<E> {
        // XXX to sumcheck batched product argument with logup, we limit num_product_fanin to 2
        // TODO mayber give a better naming?
        assert_eq!(num_fanin, 2);
        let num_prod_spec = prod_out_evals.len();
        let num_logup_spec = logup_out_evals.len();

        let log2_num_fanin = ceil_log2(num_fanin);
        // sanity check
        assert!(num_prod_spec == tower_proofs.prod_spec_size());
        assert!(prod_out_evals.iter().all(|evals| evals.len() == num_fanin));
        assert!(num_logup_spec == tower_proofs.logup_spec_size());
        assert!(logup_out_evals.iter().all(|evals| {
            evals.len() == 4 // [p1, p2, q1, q2]
        }));
        assert_eq!(expected_rounds.len(), num_prod_spec + num_logup_spec);

        let alpha_pows = get_challenge_pows(
            num_prod_spec + num_logup_spec * 2, /* logup occupy 2 sumcheck: numerator and denominator */
            transcript,
        );
        let initial_rt: Point<E> = (0..log2_num_fanin)
            .map(|_| transcript.get_and_append_challenge(b"product_sum").elements)
            .collect_vec();
        // initial_claim = \sum_j alpha^j * out_j[rt]
        // out_j[rt] := (record_{j}[rt])
        // out_j[rt] := (logup_p{j}[rt])
        // out_j[rt] := (logup_q{j}[rt])
        let initial_claim = izip!(prod_out_evals, alpha_pows.iter())
            .map(|(evals, alpha)| evals.into_mle().evaluate(&initial_rt) * alpha)
            .sum::<E>()
            + izip!(logup_out_evals, alpha_pows[num_prod_spec..].chunks(2))
                .map(|(evals, alpha)| {
                    let (alpha_numerator, alpha_denominator) = (&alpha[0], &alpha[1]);
                    let (p1, p2, q1, q2) = (evals[0], evals[1], evals[2], evals[3]);
                    vec![p1, p2].into_mle().evaluate(&initial_rt) * alpha_numerator
                        + vec![q1, q2].into_mle().evaluate(&initial_rt) * alpha_denominator
                })
                .sum::<E>();

        // evaluation in the tower input layer
        let mut prod_spec_input_layer_eval = vec![PointAndEval::default(); num_prod_spec];
        let mut logup_spec_p_input_layer_eval = vec![PointAndEval::default(); num_logup_spec];
        let mut logup_spec_q_input_layer_eval = vec![PointAndEval::default(); num_logup_spec];

        let expected_max_round = expected_rounds.iter().max().unwrap();

        let (next_rt, _) = (0..(expected_max_round-1)).try_fold(
            (
                PointAndEval {
                    point: initial_rt,
                    eval: initial_claim,
                },
                alpha_pows,
            ),
            |(point_and_eval, alpha_pows), round| {
                let (out_rt, out_claim) = (&point_and_eval.point, &point_and_eval.eval);
                let sumcheck_claim = IOPVerifierState::verify(
                    *out_claim,
                    &IOPProof {
                        point: vec![], // final claimed point will be derived from sumcheck protocol
                        proofs: tower_proofs.proofs[round].clone(),
                    },
                    &VPAuxInfo {
                        max_degree: NUM_FANIN + 1, // + 1 for eq
                        num_variables: (round + 1) * log2_num_fanin,
                        phantom: PhantomData,
                    },
                    transcript,
                );
                tracing::debug!("verified tower proof at layer {}/{}", round + 1, expected_max_round-1);

                // check expected_evaluation
                let rt: Point<E> = sumcheck_claim.point.iter().map(|c| c.elements).collect();
                let expected_evaluation: E = (0..num_prod_spec)
                    .zip(alpha_pows.iter())
                    .zip(expected_rounds.iter())
                    .map(|((spec_index, alpha), max_round)| {
                        eq_eval(out_rt, &rt)
                            * alpha
                            * if round < *max_round-1 {tower_proofs.prod_specs_eval[spec_index][round].iter().product()} else {
                                E::ZERO
                            }
                    })
                    .sum::<E>()
                    + (0..num_logup_spec)
                        .zip_eq(alpha_pows[num_prod_spec..].chunks(2))
                        .zip_eq(expected_rounds[num_prod_spec..].iter())
                        .map(|((spec_index, alpha), max_round)| {
                            let (alpha_numerator, alpha_denominator) = (&alpha[0], &alpha[1]);
                            eq_eval(out_rt, &rt) * if round < *max_round-1 {
                                let evals = &tower_proofs.logup_specs_eval[spec_index][round];
                                let (p1, p2, q1, q2) =
                                        (evals[0], evals[1], evals[2], evals[3]);
                                    *alpha_numerator * (p1 * q2 + p2 * q1)
                                        + *alpha_denominator * (q1 * q2)
                            } else {
                                E::ZERO
                            }
                        })
                        .sum::<E>();
                if expected_evaluation != sumcheck_claim.expected_evaluation {
                    return Err(ZKVMError::VerifyError("mismatch tower evaluation".into()));
                }

                // derive single eval
                // rt' = r_merge || rt
                // r_merge.len() == ceil_log2(num_product_fanin)
                let r_merge = (0..log2_num_fanin)
                    .map(|_| transcript.get_and_append_challenge(b"merge").elements)
                    .collect_vec();
                let coeffs = build_eq_x_r_vec_sequential(&r_merge);
                assert_eq!(coeffs.len(), num_fanin);
                let rt_prime = [rt, r_merge].concat();

                // generate next round challenge
                let next_alpha_pows = get_challenge_pows(
                    num_prod_spec + num_logup_spec * 2, // logup occupy 2 sumcheck: numerator and denominator
                    transcript,
                );
                let next_round = round + 1;
                let next_prod_spec_evals = (0..num_prod_spec)
                    .zip(next_alpha_pows.iter())
                    .zip(expected_rounds.iter())
                    .map(|((spec_index, alpha), max_round)| {
                        if round < max_round -1 {
                            // merged evaluation
                            let evals = izip!(
                                tower_proofs.prod_specs_eval[spec_index][round].iter(),
                                coeffs.iter()
                            )
                            .map(|(a, b)| *a * b)
                            .sum::<E>();
                            // this will keep update until round > evaluation
                            prod_spec_input_layer_eval[spec_index] = PointAndEval::new(rt_prime.clone(), evals);
                            if next_round < max_round -1 {
                                *alpha * evals
                            } else {
                                E::ZERO
                            }
                        } else {
                            E::ZERO
                        }
                    })
                    .sum::<E>();
                let next_logup_spec_evals = (0..num_logup_spec)
                    .zip_eq(next_alpha_pows[num_prod_spec..].chunks(2))
                    .zip_eq(expected_rounds[num_prod_spec..].iter())
                    .map(|((spec_index, alpha), max_round)| {
                        if round < max_round -1 {
                            let (alpha_numerator, alpha_denominator) = (&alpha[0], &alpha[1]);
                            // merged evaluation
                            let p_evals = izip!(
                                tower_proofs.logup_specs_eval[spec_index][round][0..2].iter(),
                                coeffs.iter()
                            )
                            .map(|(a, b)| *a * b)
                            .sum::<E>();

                            let q_evals = izip!(
                                tower_proofs.logup_specs_eval[spec_index][round][2..4].iter(),
                                coeffs.iter()
                            )
                            .map(|(a, b)| *a * b)
                            .sum::<E>();

                            // this will keep update until round > evaluation
                            logup_spec_p_input_layer_eval[spec_index] = PointAndEval::new(rt_prime.clone(), p_evals);
                            logup_spec_q_input_layer_eval[spec_index] = PointAndEval::new(rt_prime.clone(), q_evals);

                            if next_round < max_round -1 {
                                *alpha_numerator * p_evals + *alpha_denominator * q_evals
                            } else {
                                E::ZERO
                            }
                        } else {
                            E::ZERO
                        }
                    })
                    .sum::<E>();
                // sum evaluation from different specs
                let next_eval = next_prod_spec_evals + next_logup_spec_evals;
                Ok((PointAndEval {
                    point: rt_prime,
                    eval: next_eval,
                }, next_alpha_pows))
            },
        )?;

        Ok((
            next_rt.point,
            prod_spec_input_layer_eval,
            logup_spec_p_input_layer_eval,
            logup_spec_q_input_layer_eval,
        ))
    }
}
