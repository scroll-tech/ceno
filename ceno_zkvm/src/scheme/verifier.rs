use either::Either;
use ff_ext::ExtensionField;
use std::{iter, marker::PhantomData};

#[cfg(debug_assertions)]
use ff_ext::{Instrumented, PoseidonField};

use super::{ZKVMChipProof, ZKVMProof};
use crate::{
    error::ZKVMError,
    instructions::riscv::constants::{INIT_PC_IDX, SHARD_ID_IDX},
    scheme::constants::NUM_FANIN,
    structs::{ComposedConstrainSystem, PointAndEval, TowerProofs, VerifyingKey, ZKVMVerifyingKey},
};
use itertools::{Itertools, chain, interleave, izip};
use mpcs::{Point, PolynomialCommitmentScheme};
use multilinear_extensions::{
    StructuralWitIn,
    mle::IntoMLE,
    util::ceil_log2,
    utils::eval_by_expr_with_instance,
    virtual_poly::{VPAuxInfo, build_eq_x_r_vec_sequential, eq_eval},
};
use p3::field::FieldAlgebra;
use sumcheck::{
    structs::{IOPProof, IOPVerifierState},
    util::get_challenge_pows,
};
use transcript::{ForkableTranscript, Transcript};
use witness::next_pow2_instance_padding;

pub struct ZKVMVerifier<E: ExtensionField, PCS: PolynomialCommitmentScheme<E>> {
    pub vk: ZKVMVerifyingKey<E, PCS>,
}

impl<E: ExtensionField, PCS: PolynomialCommitmentScheme<E>> ZKVMVerifier<E, PCS> {
    pub fn new(vk: ZKVMVerifyingKey<E, PCS>) -> Self {
        ZKVMVerifier { vk }
    }

    pub fn into_inner(self) -> ZKVMVerifyingKey<E, PCS> {
        self.vk
    }

    /// Verify a trace from start to halt.
    #[tracing::instrument(skip_all, name = "verify_proof")]
    pub fn verify_proof(
        &self,
        vm_proof: ZKVMProof<E, PCS>,
        transcript: impl ForkableTranscript<E>,
    ) -> Result<bool, ZKVMError> {
        self.verify_proof_halt(vm_proof, transcript, true)
    }

    #[tracing::instrument(skip_all, name = "verify_proof")]
    pub fn verify_proofs(
        &self,
        vm_proofs: Vec<ZKVMProof<E, PCS>>,
        transcripts: Vec<impl ForkableTranscript<E>>,
    ) -> Result<bool, ZKVMError> {
        self.verify_proofs_halt(vm_proofs, transcripts, true)
    }

    /// Verify a trace from start to optional halt.
    pub fn verify_proof_halt(
        &self,
        vm_proof: ZKVMProof<E, PCS>,
        transcript: impl ForkableTranscript<E>,
        expect_halt: bool,
    ) -> Result<bool, ZKVMError> {
        self.verify_proofs_halt(vec![vm_proof], vec![transcript], expect_halt)
    }

    /// Verify a trace from start to optional halt.
    pub fn verify_proofs_halt(
        &self,
        vm_proofs: Vec<ZKVMProof<E, PCS>>,
        transcripts: Vec<impl ForkableTranscript<E>>,
        expect_halt: bool,
    ) -> Result<bool, ZKVMError> {
        // main invariant between opcode circuits and table circuits
        let _prod_r = E::ONE;
        let _prod_w = E::ONE;
        let _logup_sum = E::ZERO;
        vm_proofs
            .into_iter()
            .zip_eq(transcripts)
            .enumerate()
            .try_for_each(|(shard_id, (vm_proof, transcript))| {
                // require ecall/halt proof to exist, depend on whether we expect a halt.
                let has_halt = vm_proof.has_halt(&self.vk);
                if has_halt != expect_halt {
                    return Err(ZKVMError::VerifyError(
                        format!(
                            "{shard_id}th proof ecall/halt mismatch: expected {expect_halt} != {has_halt}",
                        )
                            .into(),
                    ));
                }
                // check first shard
                // check last shard

                // check init ts = 4
                // check pc match prev pc

                // TODO shard_ram_bus
                // extract shard_ram_bus.local_read, extract shard_ram_bus.local_write
                // extract shard_ram_bus.shard_ram_bus_read, extract shard_ram_bus.shard_ram_bus_write

                let _shard_ram_bus = vm_proof.raw_pi[INIT_PC_IDX].clone();
                let (prod_r, prod_w, logup_sum) = self.verify_proof_validity(shard_id, vm_proof, transcript)?;

                // check rw_set equality of shard proof
                if prod_r != prod_w {
                    return Err(ZKVMError::VerifyError(format!("{shard_id}th prod_r != prod_w").into()));
                }

                // check logup sum of shard proof
                if logup_sum != E::ZERO {
                    return Err(ZKVMError::VerifyError(
                        format!("{shard_id}th logup_sum({:?}) != 0", logup_sum).into(),
                    ));
                }

                Ok(())
            })?;
        Ok(true)
    }

    fn verify_proof_validity(
        &self,
        shard_id: usize,
        vm_proof: ZKVMProof<E, PCS>,
        mut transcript: impl ForkableTranscript<E>,
    ) -> Result<(E, E, E), ZKVMError> {
        // main invariant between opcode circuits and table circuits
        let mut prod_r = E::ONE;
        let mut prod_w = E::ONE;
        let mut logup_sum = E::ZERO;

        let pi_evals = &vm_proof.pi_evals;

        // make sure circuit index of chip proofs are
        // subset of that of self.vk.circuit_vks
        for chip_idx in vm_proof.chip_proofs.keys() {
            if *chip_idx >= self.vk.circuit_vks.len() {
                return Err(ZKVMError::VKNotFound(
                    format!(
                        "{shard_id}th shard chip index {chip_idx} not found in vk set [0..{})",
                        self.vk.circuit_vks.len()
                    )
                    .into(),
                ));
            }
        }

        // TODO fix soundness: construct raw public input by ourself and trustless from proof
        // including raw public input to transcript
        vm_proof
            .raw_pi
            .iter()
            .for_each(|v| v.iter().for_each(|v| transcript.append_field_element(v)));

        // check shard id
        assert_eq!(
            vm_proof.raw_pi[SHARD_ID_IDX],
            vec![E::BaseField::from_canonical_usize(shard_id)]
        );

        // verify constant poly(s) evaluation result match
        // we can evaluate at this moment because constant always evaluate to same value
        // non-constant poly(s) will be verified in respective (table) proof accordingly
        izip!(&vm_proof.raw_pi, pi_evals)
            .enumerate()
            .try_for_each(|(i, (raw, eval))| {
                if raw.len() == 1 && E::from(raw[0]) != *eval {
                    Err(ZKVMError::VerifyError(
                        format!("{shard_id}th shard pub input on index {i} mismatch  {raw:?} != {eval:?}").into(),
                    ))
                } else {
                    Ok(())
                }
            })?;

        // write fixed commitment to transcript
        // TODO check soundness if there is no fixed_commit but got fixed proof?
        if let Some(fixed_commit) = self.vk.fixed_commit.as_ref() {
            PCS::write_commitment(fixed_commit, &mut transcript).map_err(ZKVMError::PCSError)?;
        }

        // write (circuit_idx, num_instance) to transcript
        for (circuit_idx, proof) in &vm_proof.chip_proofs {
            transcript.append_message(&circuit_idx.to_le_bytes());
            transcript.append_message(&proof.num_instances.to_le_bytes());
        }

        // write witin commitment to transcript
        PCS::write_commitment(&vm_proof.witin_commit, &mut transcript)
            .map_err(ZKVMError::PCSError)?;

        #[cfg(debug_assertions)]
        {
            Instrumented::<<<E as ExtensionField>::BaseField as PoseidonField>::P>::log_label(
                "batch_commit",
            );
        }

        // alpha, beta
        let challenges = [
            transcript.read_challenge().elements,
            transcript.read_challenge().elements,
        ];
        tracing::trace!(
            "{shard_id}th shard challenges in verifier: {:?}",
            challenges
        );

        let dummy_table_item = challenges[0];
        let mut dummy_table_item_multiplicity = 0;
        let point_eval = PointAndEval::default();
        let mut witin_openings = Vec::with_capacity(vm_proof.chip_proofs.len());
        let mut fixed_openings = Vec::with_capacity(vm_proof.chip_proofs.len());
        for (index, proof) in &vm_proof.chip_proofs {
            assert!(proof.num_instances > 0);
            let circuit_name = &self.vk.circuit_index_to_name[index];
            let circuit_vk = &self.vk.circuit_vks[circuit_name];

            // check chip proof is well-formed
            if proof.wits_in_evals.len() != circuit_vk.get_cs().num_witin()
                || proof.fixed_in_evals.len() != circuit_vk.get_cs().num_fixed()
            {
                return Err(ZKVMError::InvalidProof(
                    format!(
                        "{shard_id}th shard witness/fixed evaluations length mismatch: ({}, {}) != ({}, {})",
                        proof.wits_in_evals.len(),
                        proof.fixed_in_evals.len(),
                        circuit_vk.get_cs().num_witin(),
                        circuit_vk.get_cs().num_fixed(),
                    )
                    .into(),
                ));
            }
            if proof.r_out_evals.len() != circuit_vk.get_cs().num_reads()
                || proof.w_out_evals.len() != circuit_vk.get_cs().num_writes()
            {
                return Err(ZKVMError::InvalidProof(
                    format!(
                        "{shard_id}th shard read/write evaluations length mismatch: ({}, {}) != ({}, {})",
                        proof.r_out_evals.len(),
                        proof.w_out_evals.len(),
                        circuit_vk.get_cs().num_reads(),
                        circuit_vk.get_cs().num_writes(),
                    )
                    .into(),
                ));
            }
            if proof.lk_out_evals.len() != circuit_vk.get_cs().num_lks() {
                return Err(ZKVMError::InvalidProof(
                    format!(
                        "{shard_id}th shard lookup evaluations length mismatch: {} != {}",
                        proof.lk_out_evals.len(),
                        circuit_vk.get_cs().num_lks(),
                    )
                    .into(),
                ));
            }

            let chip_logup_sum = proof
                .lk_out_evals
                .iter()
                .map(|evals| {
                    let (p1, p2, q1, q2) = (evals[0], evals[1], evals[2], evals[3]);
                    p1 * q1.inverse() + p2 * q2.inverse()
                })
                .sum::<E>();

            transcript.append_field_element(&E::BaseField::from_canonical_u64(*index as u64));
            if circuit_vk.get_cs().is_with_lk_table() {
                logup_sum -= chip_logup_sum;
            } else {
                // getting the number of dummy padding item that we used in this opcode circuit
                let num_lks = circuit_vk.get_cs().num_lks();
                // each padding instance contribute to (2^rotation_vars) dummy lookup padding
                let num_padded_instance = (next_pow2_instance_padding(proof.num_instances)
                    - proof.num_instances)
                    * (1 << circuit_vk.get_cs().rotation_vars().unwrap_or(0));
                // each instance contribute to (2^rotation_vars - rotated) dummy lookup padding
                let num_instance_non_selected = proof.num_instances
                    * ((1 << circuit_vk.get_cs().rotation_vars().unwrap_or(0))
                        - (circuit_vk.get_cs().rotation_subgroup_size().unwrap_or(0) + 1));
                dummy_table_item_multiplicity +=
                    num_lks * (num_padded_instance + num_instance_non_selected);

                logup_sum += chip_logup_sum;
            };
            let input_opening_point = self.verify_chip_proof(
                circuit_name,
                circuit_vk,
                proof,
                pi_evals,
                &vm_proof.raw_pi,
                &mut transcript,
                NUM_FANIN,
                &point_eval,
                &challenges,
            )?;
            if circuit_vk.get_cs().num_witin() > 0 {
                witin_openings.push((
                    input_opening_point.len(),
                    (input_opening_point.clone(), proof.wits_in_evals.clone()),
                ));
            }
            if circuit_vk.get_cs().num_fixed() > 0 {
                fixed_openings.push((
                    input_opening_point.len(),
                    (input_opening_point.clone(), proof.fixed_in_evals.clone()),
                ));
            }
            // TODO for non first shard, excluding init prod_w related tables
            prod_w *= proof.w_out_evals.iter().flatten().copied().product::<E>();
            prod_r *= proof.r_out_evals.iter().flatten().copied().product::<E>();
            tracing::debug!("{shard_id}th shard verified proof for circuit {}", circuit_name);
        }
        logup_sum -= E::from_canonical_u64(dummy_table_item_multiplicity as u64)
            * dummy_table_item.inverse();

        #[cfg(debug_assertions)]
        {
            Instrumented::<<<E as ExtensionField>::BaseField as PoseidonField>::P>::log_label(
                "tower_verify+main-sumcheck",
            );
        }

        // verify mpcs
        let mut rounds = vec![(vm_proof.witin_commit.clone(), witin_openings)];
        if let Some(fixed_commit) = self.vk.fixed_commit.as_ref() {
            rounds.push((fixed_commit.clone(), fixed_openings));
        }
        PCS::batch_verify(
            &self.vk.vp,
            rounds,
            &vm_proof.opening_proof,
            &mut transcript,
        )
        .map_err(ZKVMError::PCSError)?;

        let initial_global_state = eval_by_expr_with_instance(
            &[],
            &[],
            &[],
            pi_evals,
            &challenges,
            &self.vk.initial_global_state_expr,
        )
        .right()
        .unwrap();
        prod_w *= initial_global_state;
        let finalize_global_state = eval_by_expr_with_instance(
            &[],
            &[],
            &[],
            pi_evals,
            &challenges,
            &self.vk.finalize_global_state_expr,
        )
        .right()
        .unwrap();
        prod_r *= finalize_global_state;

        Ok((prod_r, prod_w, logup_sum))
    }

    /// verify proof and return input opening point
    #[allow(clippy::too_many_arguments)]
    pub fn verify_chip_proof(
        &self,
        _name: &str,
        circuit_vk: &VerifyingKey<E>,
        proof: &ZKVMChipProof<E>,
        pi: &[E],
        raw_pi: &[Vec<E::BaseField>],
        transcript: &mut impl Transcript<E>,
        num_product_fanin: usize,
        _out_evals: &PointAndEval<E>,
        challenges: &[E; 2], // derive challenge from PCS
    ) -> Result<Point<E>, ZKVMError> {
        let composed_cs = circuit_vk.get_cs();
        let ComposedConstrainSystem {
            zkvm_v1_css: cs,
            gkr_circuit,
        } = &composed_cs;
        let num_instances = proof.num_instances;
        let (r_counts_per_instance, w_counts_per_instance, lk_counts_per_instance) = (
            cs.r_expressions.len() + cs.r_table_expressions.len(),
            cs.w_expressions.len() + cs.w_table_expressions.len(),
            cs.lk_expressions.len() + cs.lk_table_expressions.len(),
        );
        let num_batched = r_counts_per_instance + w_counts_per_instance + lk_counts_per_instance;

        let next_pow2_instance = next_pow2_instance_padding(num_instances);
        let log2_num_instances = ceil_log2(next_pow2_instance);
        let num_var_with_rotation = log2_num_instances + composed_cs.rotation_vars().unwrap_or(0);

        // constrain log2_num_instances within max length
        cs.r_table_expressions
            .iter()
            .chain(&cs.w_table_expressions)
            .for_each(|set_table_expr| {
                // iterate through structural witins and collect max round.
                let num_vars = set_table_expr
                    .table_spec
                    .len
                    .map(ceil_log2)
                    .unwrap_or_else(|| {
                        set_table_expr
                            .table_spec
                            .structural_witins
                            .iter()
                            .map(|StructuralWitIn { witin_type, .. }| {
                                let hint_num_vars = log2_num_instances;
                                assert!((1 << hint_num_vars) <= witin_type.max_len());
                                hint_num_vars
                            })
                            .max()
                            .unwrap_or(log2_num_instances)
                    });
                assert_eq!(num_vars, log2_num_instances);
            });
        cs.lk_table_expressions.iter().for_each(|l| {
            // iterate through structural witins and collect max round.
            let num_vars = l.table_spec.len.map(ceil_log2).unwrap_or_else(|| {
                l.table_spec
                    .structural_witins
                    .iter()
                    .map(|StructuralWitIn { witin_type, .. }| {
                        let hint_num_vars = log2_num_instances;
                        assert!((1 << hint_num_vars) <= witin_type.max_len());
                        hint_num_vars
                    })
                    .max()
                    .unwrap_or(log2_num_instances)
            });
            assert_eq!(num_vars, log2_num_instances);
        });

        // verify and reduce product tower sumcheck
        let tower_proofs = &proof.tower_proof;

        let (_, record_evals, logup_p_evals, logup_q_evals) = TowerVerify::verify(
            proof
                .r_out_evals
                .iter()
                .cloned()
                .chain(proof.w_out_evals.iter().cloned())
                .collect_vec(),
            proof.lk_out_evals.clone(),
            tower_proofs,
            vec![num_var_with_rotation; num_batched],
            num_product_fanin,
            transcript,
        )?;

        if cs.lk_table_expressions.is_empty() {
            // verify LogUp witness nominator p(x) ?= constant vector 1
            logup_p_evals
                .iter()
                .try_for_each(|PointAndEval { eval, .. }| {
                    if *eval != E::ONE {
                        Err(ZKVMError::VerifyError(
                            "Lookup table witness p(x) != constant 1".into(),
                        ))
                    } else {
                        Ok(())
                    }
                })?;
        }

        debug_assert!(
            chain!(&record_evals, &logup_p_evals, &logup_q_evals)
                .map(|e| &e.point)
                .all_equal()
        );

        let num_rw_records = r_counts_per_instance + w_counts_per_instance;

        debug_assert_eq!(record_evals.len(), num_rw_records);
        debug_assert_eq!(logup_p_evals.len(), lk_counts_per_instance);
        debug_assert_eq!(logup_q_evals.len(), lk_counts_per_instance);

        let evals = record_evals
            .iter()
            // append p_evals if there got lk table expressions
            .chain(if cs.lk_table_expressions.is_empty() {
                Either::Left(iter::empty())
            } else {
                Either::Right(logup_p_evals.iter())
            })
            .chain(&logup_q_evals)
            .cloned()
            .collect_vec();

        let gkr_circuit = gkr_circuit.as_ref().unwrap();
        let (_, rt) = gkr_circuit.verify(
            num_var_with_rotation,
            proof.gkr_iop_proof.clone().unwrap(),
            &evals,
            pi,
            raw_pi,
            challenges,
            transcript,
            num_instances,
        )?;
        Ok(rt)
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
        num_variables: Vec<usize>,
        num_fanin: usize,
        transcript: &mut impl Transcript<E>,
    ) -> TowerVerifyResult<E> {
        // XXX to sumcheck batched product argument with logup, we limit num_product_fanin to 2
        // TODO mayber give a better naming?
        assert_eq!(num_fanin, 2);
        let num_prod_spec = prod_out_evals.len();
        let num_logup_spec = logup_out_evals.len();

        let log2_num_fanin = ceil_log2(num_fanin);
        // sanity check
        assert_eq!(num_prod_spec, tower_proofs.prod_spec_size());
        assert!(prod_out_evals.iter().all(|evals| evals.len() == num_fanin));
        assert_eq!(num_logup_spec, tower_proofs.logup_spec_size());
        assert!(logup_out_evals.iter().all(|evals| {
            evals.len() == 4 // [p1, p2, q1, q2]
        }));
        assert_eq!(num_variables.len(), num_prod_spec + num_logup_spec);

        let alpha_pows = get_challenge_pows(
            num_prod_spec + num_logup_spec * 2, /* logup occupy 2 sumcheck: numerator and denominator */
            transcript,
        );
        let initial_rt: Point<E> = transcript.sample_and_append_vec(b"product_sum", log2_num_fanin);
        // initial_claim = \sum_j alpha^j * out_j[rt]
        // out_j[rt] := (record_{j}[rt])
        // out_j[rt] := (logup_p{j}[rt])
        // out_j[rt] := (logup_q{j}[rt])

        // bookkeeping records of latest (point, evaluation) of each layer
        // prod argument
        let mut prod_spec_point_n_eval = prod_out_evals
            .into_iter()
            .map(|evals| {
                PointAndEval::new(initial_rt.clone(), evals.into_mle().evaluate(&initial_rt))
            })
            .collect::<Vec<_>>();
        // logup argument for p, q
        let (mut logup_spec_p_point_n_eval, mut logup_spec_q_point_n_eval) = logup_out_evals
            .into_iter()
            .map(|evals| {
                let (p1, p2, q1, q2) = (evals[0], evals[1], evals[2], evals[3]);
                (
                    PointAndEval::new(
                        initial_rt.clone(),
                        vec![p1, p2].into_mle().evaluate(&initial_rt),
                    ),
                    PointAndEval::new(
                        initial_rt.clone(),
                        vec![q1, q2].into_mle().evaluate(&initial_rt),
                    ),
                )
            })
            .unzip::<_, _, Vec<_>, Vec<_>>();
        let initial_claim = izip!(&prod_spec_point_n_eval, &alpha_pows)
            .map(|(point_n_eval, alpha)| point_n_eval.eval * *alpha)
            .sum::<E>()
            + izip!(
                interleave(&logup_spec_p_point_n_eval, &logup_spec_q_point_n_eval),
                &alpha_pows[num_prod_spec..]
            )
            .map(|(point_n_eval, alpha)| point_n_eval.eval * *alpha)
            .sum::<E>();

        let max_num_variables = num_variables.iter().max().unwrap();

        let (next_rt, _) = (0..(max_num_variables - 1)).try_fold(
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
                        proofs: tower_proofs.proofs[round].clone(),
                    },
                    &VPAuxInfo {
                        max_degree: NUM_FANIN + 1, // + 1 for eq
                        max_num_variables: (round + 1) * log2_num_fanin,
                        phantom: PhantomData,
                    },
                    transcript,
                );

                // check expected_evaluation
                let rt: Point<E> = sumcheck_claim.point.iter().map(|c| c.elements).collect();
                let expected_evaluation: E = (0..num_prod_spec)
                    .zip(alpha_pows.iter())
                    .zip(num_variables.iter())
                    .map(|((spec_index, alpha), max_round)| {
                        eq_eval(out_rt, &rt)
                            * *alpha
                            * if round < *max_round - 1 { tower_proofs.prod_specs_eval[spec_index][round].iter().copied().product() } else {
                            E::ZERO
                        }
                    })
                    .sum::<E>()
                    + (0..num_logup_spec)
                    .zip_eq(alpha_pows[num_prod_spec..].chunks(2))
                    .zip_eq(num_variables[num_prod_spec..].iter())
                    .map(|((spec_index, alpha), max_round)| {
                        let (alpha_numerator, alpha_denominator) = (&alpha[0], &alpha[1]);
                        eq_eval(out_rt, &rt) * if round < *max_round - 1 {
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
                let r_merge = transcript.sample_and_append_vec(b"merge", log2_num_fanin);
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
                    .zip(num_variables.iter())
                    .map(|((spec_index, alpha), max_round)| {
                        if round < max_round - 1 {
                            // merged evaluation
                            let evals = izip!(
                                tower_proofs.prod_specs_eval[spec_index][round].iter(),
                                coeffs.iter()
                            )
                                .map(|(a, b)| *a * *b)
                                .sum::<E>();
                            // this will keep update until round > evaluation
                            prod_spec_point_n_eval[spec_index] = PointAndEval::new(rt_prime.clone(), evals);
                            if next_round < max_round - 1 {
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
                    .zip_eq(num_variables[num_prod_spec..].iter())
                    .map(|((spec_index, alpha), max_round)| {
                        if round < max_round - 1 {
                            let (alpha_numerator, alpha_denominator) = (&alpha[0], &alpha[1]);
                            // merged evaluation
                            let p_evals = izip!(
                                tower_proofs.logup_specs_eval[spec_index][round][0..2].iter(),
                                coeffs.iter()
                            )
                                .map(|(a, b)| *a * *b)
                                .sum::<E>();

                            let q_evals = izip!(
                                tower_proofs.logup_specs_eval[spec_index][round][2..4].iter(),
                                coeffs.iter()
                            )
                                .map(|(a, b)| *a * *b)
                                .sum::<E>();

                            // this will keep update until round > evaluation
                            logup_spec_p_point_n_eval[spec_index] = PointAndEval::new(rt_prime.clone(), p_evals);
                            logup_spec_q_point_n_eval[spec_index] = PointAndEval::new(rt_prime.clone(), q_evals);

                            if next_round < max_round - 1 {
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
            prod_spec_point_n_eval,
            logup_spec_p_point_n_eval,
            logup_spec_q_point_n_eval,
        ))
    }
}
