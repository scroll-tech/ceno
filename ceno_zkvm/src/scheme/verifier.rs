use std::marker::PhantomData;

use ff_ext::ExtensionField;

#[cfg(debug_assertions)]
use ff_ext::{Instrumented, PoseidonField};

use gkr_iop::gkr::GKRClaims;
use itertools::{Itertools, chain, interleave, izip};
use mpcs::{Point, PolynomialCommitmentScheme};
use multilinear_extensions::{
    Instance, StructuralWitIn,
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

use crate::{
    error::ZKVMError,
    scheme::constants::{NUM_FANIN, NUM_FANIN_LOGUP, SEL_DEGREE},
    structs::{ComposedConstrainSystem, PointAndEval, TowerProofs, VerifyingKey, ZKVMVerifyingKey},
    utils::eval_wellform_address_vec,
};

use super::{ZKVMChipProof, ZKVMProof};

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

    /// Verify a trace from start to optional halt.
    pub fn verify_proof_halt(
        &self,
        vm_proof: ZKVMProof<E, PCS>,
        transcript: impl ForkableTranscript<E>,
        expect_halt: bool,
    ) -> Result<bool, ZKVMError> {
        // require ecall/halt proof to exist, depending whether we expect a halt.
        let has_halt = vm_proof.has_halt(&self.vk);
        if has_halt != expect_halt {
            return Err(ZKVMError::VerifyError(format!(
                "ecall/halt mismatch: expected {expect_halt} != {has_halt}",
            )));
        }

        self.verify_proof_validity(vm_proof, transcript)
    }

    fn verify_proof_validity(
        &self,
        vm_proof: ZKVMProof<E, PCS>,
        mut transcript: impl ForkableTranscript<E>,
    ) -> Result<bool, ZKVMError> {
        // main invariant between opcode circuits and table circuits
        let mut prod_r = E::ONE;
        let mut prod_w = E::ONE;
        let mut logup_sum = E::ZERO;

        let pi_evals = &vm_proof.pi_evals;

        // make sure circuit index of chip proofs are
        // subset of that of self.vk.circuit_vks
        for chip_idx in vm_proof.chip_proofs.keys() {
            if *chip_idx >= self.vk.circuit_vks.len() {
                return Err(ZKVMError::VKNotFound(format!(
                    "chip index {chip_idx} not found in vk set [0..{})",
                    self.vk.circuit_vks.len()
                )));
            }
        }

        // TODO fix soundness: construct raw public input by ourself and trustless from proof
        // including raw public input to transcript
        vm_proof
            .raw_pi
            .iter()
            .for_each(|v| v.iter().for_each(|v| transcript.append_field_element(v)));

        // verify constant poly(s) evaluation result match
        // we can evaluate at this moment because constant always evaluate to same value
        // non-constant poly(s) will be verified in respective (table) proof accordingly
        izip!(&vm_proof.raw_pi, pi_evals)
            .enumerate()
            .try_for_each(|(i, (raw, eval))| {
                if raw.len() == 1 && E::from(raw[0]) != *eval {
                    Err(ZKVMError::VerifyError(format!(
                        "pub input on index {i} mismatch  {raw:?} != {eval:?}"
                    )))
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
        tracing::trace!("challenges in verifier: {:?}", challenges);

        let dummy_table_item = challenges[0];
        let mut dummy_table_item_multiplicity = 0;
        let point_eval = PointAndEval::default();
        let mut rt_points = Vec::with_capacity(vm_proof.chip_proofs.len());
        let mut evaluations = Vec::with_capacity(vm_proof.chip_proofs.len());
        let mut witin_openings = Vec::with_capacity(vm_proof.chip_proofs.len());
        let mut fixed_openings = Vec::with_capacity(vm_proof.chip_proofs.len());
        for (index, proof) in &vm_proof.chip_proofs {
            let circuit_name = &self.vk.circuit_index_to_name[index];
            let circuit_vk = &self.vk.circuit_vks[circuit_name];

            // check chip proof is well-formed
            if proof.wits_in_evals.len() != circuit_vk.get_cs().num_witin()
                || proof.fixed_in_evals.len() != circuit_vk.get_cs().num_fixed()
            {
                return Err(ZKVMError::InvalidProof(format!(
                    "witness/fixed evaluations length mismatch: ({}, {}) != ({}, {})",
                    proof.wits_in_evals.len(),
                    proof.fixed_in_evals.len(),
                    circuit_vk.get_cs().num_witin(),
                    circuit_vk.get_cs().num_fixed(),
                )));
            }
            if proof.r_out_evals.len() != circuit_vk.get_cs().num_reads()
                || proof.w_out_evals.len() != circuit_vk.get_cs().num_writes()
            {
                return Err(ZKVMError::InvalidProof(format!(
                    "read/write evaluations length mismatch: ({}, {}) != ({}, {})",
                    proof.r_out_evals.len(),
                    proof.w_out_evals.len(),
                    circuit_vk.get_cs().num_reads(),
                    circuit_vk.get_cs().num_writes(),
                )));
            }
            if proof.lk_out_evals.len() != circuit_vk.get_cs().num_lks() {
                return Err(ZKVMError::InvalidProof(format!(
                    "lookup evaluations length mismatch: {} != {}",
                    proof.lk_out_evals.len(),
                    circuit_vk.get_cs().num_lks(),
                )));
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
            let input_opening_point = if circuit_vk.get_cs().is_opcode_circuit() {
                // getting the number of dummy padding item that we used in this opcode circuit
                let num_lks = circuit_vk.get_cs().num_lks();
                let num_padded_instance =
                    next_pow2_instance_padding(proof.num_instances) - proof.num_instances;
                dummy_table_item_multiplicity += num_lks * num_padded_instance;

                logup_sum += chip_logup_sum;
                self.verify_opcode_proof(
                    circuit_name,
                    circuit_vk,
                    proof,
                    pi_evals,
                    &mut transcript,
                    NUM_FANIN,
                    &point_eval,
                    &challenges,
                )?
            } else {
                logup_sum -= chip_logup_sum;
                self.verify_table_proof(
                    circuit_name,
                    circuit_vk,
                    proof,
                    &vm_proof.raw_pi,
                    &vm_proof.pi_evals,
                    &mut transcript,
                    NUM_FANIN_LOGUP,
                    &point_eval,
                    &challenges,
                )?
            };
            rt_points.push((*index, input_opening_point.clone()));
            evaluations.push((
                *index,
                [proof.wits_in_evals.clone(), proof.fixed_in_evals.clone()].concat(),
            ));
            witin_openings.push((
                input_opening_point.len(),
                (input_opening_point.clone(), proof.wits_in_evals.clone()),
            ));
            if !proof.fixed_in_evals.is_empty() {
                fixed_openings.push((
                    input_opening_point.len(),
                    (input_opening_point.clone(), proof.fixed_in_evals.clone()),
                ));
            }

            prod_w *= proof.w_out_evals.iter().flatten().copied().product::<E>();
            prod_r *= proof.r_out_evals.iter().flatten().copied().product::<E>();
            tracing::debug!("verified proof for circuit {}", circuit_name);
        }
        logup_sum -= E::from_canonical_u64(dummy_table_item_multiplicity as u64)
            * dummy_table_item.inverse();

        // check logup relation across all proofs
        if logup_sum != E::ZERO {
            return Err(ZKVMError::VerifyError(format!(
                "logup_sum({:?}) != 0",
                logup_sum
            )));
        }

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
        // check rw_set equality across all proofs
        if prod_r != prod_w {
            return Err(ZKVMError::VerifyError("prod_r != prod_w".into()));
        }

        Ok(true)
    }

    // TODO: unify `verify_opcode_proof` and `verify_table_proof`
    /// verify proof and return input opening point
    #[allow(clippy::too_many_arguments)]
    pub fn verify_opcode_proof(
        &self,
        _name: &str,
        circuit_vk: &VerifyingKey<E>,
        proof: &ZKVMChipProof<E>,
        pi: &[E],
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
            cs.r_expressions.len(),
            cs.w_expressions.len(),
            cs.lk_expressions.len(),
        );
        let num_batched = r_counts_per_instance + w_counts_per_instance + lk_counts_per_instance;

        let next_pow2_instance = next_pow2_instance_padding(num_instances);
        let log2_num_instances = ceil_log2(next_pow2_instance);
        let num_var_with_rotation = log2_num_instances + composed_cs.rotation_vars().unwrap_or(0);

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

        // verify LogUp witness nominator p(x) ?= constant vector 1
        // index 0 is LogUp witness for Fixed Lookup table
        if logup_p_evals[0].eval != E::ONE {
            return Err(ZKVMError::VerifyError(
                "Lookup table witness p(x) != constant 1".into(),
            ));
        }

        debug_assert!(
            chain!(&record_evals, &logup_p_evals, &logup_q_evals)
                .map(|e| &e.point)
                .all_equal()
        );

        // verify zero statement (degree > 1) + sel sumcheck
        let num_rw_records = r_counts_per_instance + w_counts_per_instance;

        debug_assert_eq!(record_evals.len(), num_rw_records);
        debug_assert_eq!(logup_p_evals.len(), lk_counts_per_instance);
        debug_assert_eq!(logup_q_evals.len(), lk_counts_per_instance);

        let gkr_circuit = gkr_circuit.as_ref().unwrap();
        let GKRClaims(opening_evaluations) = gkr_circuit.verify(
            num_var_with_rotation,
            proof.gkr_iop_proof.clone().unwrap(),
            &chain!(record_evals, logup_q_evals).collect_vec(),
            pi,
            challenges,
            transcript,
            num_instances,
        )?;
        Ok(opening_evaluations[0].point.clone())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn verify_table_proof(
        &self,
        name: &str,
        circuit_vk: &VerifyingKey<E>,
        proof: &ZKVMChipProof<E>,
        raw_pi: &[Vec<E::BaseField>],
        pi: &[E],
        transcript: &mut impl Transcript<E>,
        num_logup_fanin: usize,
        _out_evals: &PointAndEval<E>,
        challenges: &[E; 2],
    ) -> Result<Point<E>, ZKVMError> {
        let ComposedConstrainSystem {
            zkvm_v1_css: cs, ..
        } = circuit_vk.get_cs();
        debug_assert!(
            cs.r_table_expressions
                .iter()
                .zip_eq(cs.w_table_expressions.iter())
                .all(|(r, w)| r.table_spec.len == w.table_spec.len)
        );

        let log2_num_instances = next_pow2_instance_padding(proof.num_instances).ilog2() as usize;

        // in table proof, we always skip same point sumcheck for now
        // as tower sumcheck batch product argument/logup in same length
        let is_skip_same_point_sumcheck = true;

        // verify and reduce product tower sumcheck
        let tower_proofs = &proof.tower_proof;

        // NOTE: for all structural witness within same constrain system should got same hints num variable via `log2_num_instances`
        let expected_rounds = cs
            // only iterate r set, as read/write set round should match
            .r_table_expressions
            .iter()
            .flat_map(|r| {
                // iterate through structural witins and collect max round.
                let num_vars = r.table_spec.len.map(ceil_log2).unwrap_or_else(|| {
                    r.table_spec
                        .structural_witins
                        .iter()
                        .map(|StructuralWitIn { max_len, .. }| {
                            let hint_num_vars = log2_num_instances;
                            assert!((1 << hint_num_vars) <= *max_len);
                            hint_num_vars
                        })
                        .max()
                        .unwrap()
                });
                assert_eq!(num_vars, log2_num_instances);
                [num_vars, num_vars] // format: [read_round, write_round]
            })
            .chain(cs.lk_table_expressions.iter().map(|l| {
                // iterate through structural witins and collect max round.
                let num_vars = l.table_spec.len.map(ceil_log2).unwrap_or_else(|| {
                    l.table_spec
                        .structural_witins
                        .iter()
                        .map(|StructuralWitIn { max_len, .. }| {
                            let hint_num_vars = log2_num_instances;
                            assert!((1 << hint_num_vars) <= *max_len);
                            hint_num_vars
                        })
                        .max()
                        .unwrap()
                });
                assert_eq!(num_vars, log2_num_instances);
                num_vars
            }))
            .collect_vec();

        let expected_max_rounds = expected_rounds.iter().cloned().max().unwrap();
        let (rt_tower, prod_point_and_eval, logup_p_point_and_eval, logup_q_point_and_eval) =
            TowerVerify::verify(
                proof
                    .r_out_evals
                    .iter()
                    .zip(proof.w_out_evals.iter())
                    .flat_map(|(r_evals, w_evals)| [r_evals.to_vec(), w_evals.to_vec()])
                    .collect_vec(),
                proof
                    .lk_out_evals
                    .iter()
                    .map(|eval| eval.to_vec())
                    .collect_vec(),
                tower_proofs,
                expected_rounds,
                num_logup_fanin,
                transcript,
            )?;

        // TODO: return error instead of panic
        assert_eq!(
            logup_q_point_and_eval.len(),
            cs.lk_table_expressions.len(),
            "[lk_q_record] mismatch length"
        );
        assert_eq!(
            logup_p_point_and_eval.len(),
            cs.lk_table_expressions.len(),
            "[lk_p_record] mismatch length"
        );
        assert_eq!(
            prod_point_and_eval.len(),
            cs.r_table_expressions.len() + cs.w_table_expressions.len(),
            "[prod_record] mismatch length"
        );
        let num_rw_records = cs.r_table_expressions.len() + cs.w_table_expressions.len();

        // evaluate the evaluation of structural mles at input_opening_point by verifier
        let structural_evals = cs
            .r_table_expressions
            .iter()
            .map(|r| &r.table_spec)
            .chain(cs.lk_table_expressions.iter().map(|r| &r.table_spec))
            .flat_map(|table_spec| {
                table_spec
                    .structural_witins
                    .iter()
                    .map(
                        |StructuralWitIn {
                             offset,
                             multi_factor,
                             descending,
                             ..
                         }| {
                            eval_wellform_address_vec(
                                *offset as u64,
                                *multi_factor as u64,
                                &rt_tower,
                                *descending,
                            )
                        },
                    )
                    .collect_vec()
            })
            .collect_vec();

        // verify records (degree = 1) statement, thus no sumcheck
        let expected_evals = interleave(
            &cs.r_table_expressions, // r
            &cs.w_table_expressions, // w
        )
        .map(|rw| &rw.expr)
        .chain(
            cs.lk_table_expressions
                .iter()
                .flat_map(|lk| vec![&lk.multiplicity, &lk.values]), // p, q
        )
        .map(|expr| {
            eval_by_expr_with_instance(
                &proof.fixed_in_evals,
                &proof.wits_in_evals,
                &structural_evals,
                pi,
                challenges,
                expr,
            )
            .right()
            .unwrap()
        })
        .collect_vec();

        let input_opening_point = if is_skip_same_point_sumcheck {
            for (expected_eval, eval) in expected_evals.iter().zip(
                prod_point_and_eval
                    .into_iter()
                    .chain(
                        logup_p_point_and_eval
                            .into_iter()
                            .zip_eq(logup_q_point_and_eval)
                            .flat_map(|(p_point_and_eval, q_point_and_eval)| {
                                [p_point_and_eval, q_point_and_eval]
                            }),
                    )
                    .map(|point_and_eval| point_and_eval.eval),
            ) {
                if expected_eval != &eval {
                    return Err(ZKVMError::VerifyError(format!(
                        "table {name} evaluation mismatch {expected_eval:?} != {eval:?}"
                    )));
                }
            }
            rt_tower
        } else {
            assert!(proof.main_sumcheck_proofs.is_some());

            // verify opening same point layer sumcheck
            let alpha_pow = get_challenge_pows(
                cs.r_table_expressions.len()
                    + cs.w_table_expressions.len()
                    + cs.lk_table_expressions.len() * 2, // 2 for lk numerator and denominator
                transcript,
            );

            //  \sum_i alpha_{i} * (out_r_eval{i})
            //  + \sum_i alpha_{i} * (out_w_eval{i})
            //  + \sum_i alpha_{i} * (out_lk_n{i})
            //  + \sum_i alpha_{i} * (out_lk_d{i})
            let claim_sum = prod_point_and_eval
                .iter()
                .zip(alpha_pow.iter())
                .map(|(point_and_eval, alpha)| *alpha * point_and_eval.eval)
                .sum::<E>()
                + interleave(&logup_p_point_and_eval, &logup_q_point_and_eval)
                    .zip_eq(alpha_pow.iter().skip(num_rw_records))
                    .map(|(point_n_eval, alpha)| *alpha * point_n_eval.eval)
                    .sum::<E>();
            let sel_subclaim = IOPVerifierState::verify(
                claim_sum,
                &IOPProof {
                    proofs: proof.main_sumcheck_proofs.clone().unwrap(),
                },
                &VPAuxInfo {
                    max_degree: SEL_DEGREE,
                    max_num_variables: expected_max_rounds,
                    phantom: PhantomData,
                },
                transcript,
            );
            let (input_opening_point, expected_evaluation) = (
                sel_subclaim.point.iter().map(|c| c.elements).collect_vec(),
                sel_subclaim.expected_evaluation,
            );

            let computed_evals = [
                // r, w
                prod_point_and_eval
                    .into_iter()
                    .zip_eq(&expected_evals[0..num_rw_records])
                    .zip(alpha_pow.iter())
                    .map(|((point_and_eval, in_eval), alpha)| {
                        let eq = eq_eval(
                            &point_and_eval.point,
                            &input_opening_point[0..point_and_eval.point.len()],
                        );
                        // TODO times multiplication factor
                        *alpha * eq * *in_eval
                    })
                    .sum::<E>(),
                interleave(logup_p_point_and_eval, logup_q_point_and_eval)
                    .zip_eq(&expected_evals[num_rw_records..])
                    .zip_eq(alpha_pow.iter().skip(num_rw_records))
                    .map(|((point_and_eval, in_eval), alpha)| {
                        let eq = eq_eval(
                            &point_and_eval.point,
                            &input_opening_point[0..point_and_eval.point.len()],
                        );
                        // TODO times multiplication factor
                        *alpha * eq * *in_eval
                    })
                    .sum::<E>(),
            ]
            .iter()
            .copied()
            .sum::<E>();

            if computed_evals != expected_evaluation {
                return Err(ZKVMError::VerifyError(
                    "sel evaluation verify failed".into(),
                ));
            }
            input_opening_point
        };

        // assume public io is tiny vector, so we evaluate it directly without PCS
        for &Instance(idx) in cs.instance_name_map.keys() {
            let poly = raw_pi[idx].to_vec().into_mle();
            let expected_eval = poly.evaluate(&input_opening_point[..poly.num_vars()]);
            let eval = pi[idx];
            if expected_eval != eval {
                return Err(ZKVMError::VerifyError(format!(
                    "pub input on index {idx} mismatch  {expected_eval:?} != {eval:?}"
                )));
            }
            tracing::trace!(
                "[table {name}] verified public inputs on index {idx} with point {:?}",
                input_opening_point
            );
        }

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
        assert!(num_prod_spec == tower_proofs.prod_spec_size());
        assert!(prod_out_evals.iter().all(|evals| evals.len() == num_fanin));
        assert!(num_logup_spec == tower_proofs.logup_spec_size());
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

        let (next_rt, _) = (0..(max_num_variables-1)).try_fold(
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
                            * if round < *max_round-1 {tower_proofs.prod_specs_eval[spec_index][round].iter().copied().product()} else {
                                E::ZERO
                            }
                    })
                    .sum::<E>()
                    + (0..num_logup_spec)
                        .zip_eq(alpha_pows[num_prod_spec..].chunks(2))
                        .zip_eq(num_variables[num_prod_spec..].iter())
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
                let r_merge =transcript.sample_and_append_vec(b"merge", log2_num_fanin);
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
                        if round < max_round -1 {
                            // merged evaluation
                            let evals = izip!(
                                tower_proofs.prod_specs_eval[spec_index][round].iter(),
                                coeffs.iter()
                            )
                            .map(|(a, b)| *a * *b)
                            .sum::<E>();
                            // this will keep update until round > evaluation
                            prod_spec_point_n_eval[spec_index] = PointAndEval::new(rt_prime.clone(), evals);
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
                    .zip_eq(num_variables[num_prod_spec..].iter())
                    .map(|((spec_index, alpha), max_round)| {
                        if round < max_round -1 {
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
            prod_spec_point_n_eval,
            logup_spec_p_point_n_eval,
            logup_spec_q_point_n_eval,
        ))
    }
}
