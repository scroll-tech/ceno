use either::Either;
use ff_ext::{ExtensionField, SmallField};
use std::{
    iter::{self, once, repeat_n},
    marker::PhantomData,
};

#[cfg(debug_assertions)]
use ff_ext::{Instrumented, PoseidonField};

use super::{PublicValues, ZKVMChipProof, ZKVMProof};
use crate::{
    error::ZKVMError,
    instructions::riscv::constants::{
        END_PC_IDX, HEAP_LENGTH_IDX, HEAP_START_ADDR_IDX, HINT_LENGTH_IDX, HINT_START_ADDR_IDX,
        INIT_CYCLE_IDX, INIT_PC_IDX,
    },
    scheme::{
        constants::{NUM_FANIN, SEPTIC_EXTENSION_DEGREE},
        septic_curve::{SepticExtension, SepticPoint},
        utils::{assign_group_evals, derive_ecc_bridge_claims},
    },
    structs::{
        ComposedConstrainSystem, EccQuarkProof, PointAndEval, TowerProofs, VerifyingKey,
        ZKVMVerifyingKey,
    },
};
use ceno_emul::{FullTracer as Tracer, WORD_SIZE};
use gkr_iop::{
    self,
    selector::{SelectorContext, SelectorType},
};
use itertools::{Itertools, chain, interleave, izip};
use mpcs::{Point, PolynomialCommitmentScheme};
use multilinear_extensions::{
    Expression, StructuralWitIn,
    StructuralWitInType::StackedConstantSequence,
    mle::IntoMLE,
    util::ceil_log2,
    virtual_poly::{VPAuxInfo, build_eq_x_r_vec_sequential, eq_eval},
};
use p3::field::FieldAlgebra;
use sumcheck::{
    structs::{IOPProof, IOPVerifierState},
    util::get_challenge_pows,
};
use transcript::{ForkableTranscript, Transcript};
use witness::next_pow2_instance_padding;

pub use crate::structs::RV32imMemStateConfig;

pub struct ZKVMVerifier<
    E: ExtensionField,
    PCS: PolynomialCommitmentScheme<E>,
    M = RV32imMemStateConfig,
> where
    M: Clone + Default + serde::Serialize + serde::de::DeserializeOwned,
{
    pub vk: ZKVMVerifyingKey<E, PCS, M>,
}

fn bind_active_tower_eval_round<E: ExtensionField>(
    transcript: &mut impl Transcript<E>,
    tower_proofs: &TowerProofs<E>,
    num_variables: &[usize],
    num_prod_spec: usize,
    round: usize,
) {
    for (spec_index, max_round) in num_variables
        .iter()
        .copied()
        .enumerate()
        .take(num_prod_spec)
    {
        if round < max_round.saturating_sub(1) {
            transcript.append_field_element_exts(&tower_proofs.prod_specs_eval[spec_index][round]);
        }
    }

    for (global_spec_index, max_round) in num_variables
        .iter()
        .copied()
        .enumerate()
        .skip(num_prod_spec)
    {
        if round < max_round.saturating_sub(1) {
            transcript.append_field_element_exts(
                &tower_proofs.logup_specs_eval[global_spec_index - num_prod_spec][round],
            );
        }
    }
}

impl<E: ExtensionField, PCS: PolynomialCommitmentScheme<E>, M> ZKVMVerifier<E, PCS, M>
where
    M: Clone + Default + serde::Serialize + serde::de::DeserializeOwned,
{
    pub fn new(vk: ZKVMVerifyingKey<E, PCS, M>) -> Self {
        ZKVMVerifier { vk }
    }

    pub fn into_inner(self) -> ZKVMVerifyingKey<E, PCS, M> {
        self.vk
    }
}

impl<E: ExtensionField, PCS: PolynomialCommitmentScheme<E>>
    ZKVMVerifier<E, PCS, RV32imMemStateConfig>
{
    fn validate_mem_state(
        mem_state: &RV32imMemStateConfig,
        prev_heap_addr_end: Option<u32>,
        prev_hint_addr_end: Option<u32>,
        vm_proof: &ZKVMProof<E, PCS>,
    ) -> Result<(u32, u32), ZKVMError> {
        let heap_addr_start = vm_proof
            .public_values
            .query_by_index::<E>(HEAP_START_ADDR_IDX)
            .to_canonical_u64() as u32;
        let heap_len = vm_proof
            .public_values
            .query_by_index::<E>(HEAP_LENGTH_IDX)
            .to_canonical_u64() as u32;
        let next_heap_addr_end = heap_addr_start + heap_len * WORD_SIZE as u32;
        if !mem_state.heap.contains(&heap_addr_start)
            || !mem_state.heap.contains(&next_heap_addr_end)
        {
            return Err(ZKVMError::VerifyError(
                "heap continuation out of range".into(),
            ));
        }
        if let Some(prev_heap_addr_end) = prev_heap_addr_end
            && heap_addr_start != prev_heap_addr_end
        {
            return Err(ZKVMError::VerifyError("heap continuation mismatch".into()));
        }

        let hint_addr_start = vm_proof
            .public_values
            .query_by_index::<E>(HINT_START_ADDR_IDX)
            .to_canonical_u64() as u32;
        let hint_len = vm_proof
            .public_values
            .query_by_index::<E>(HINT_LENGTH_IDX)
            .to_canonical_u64() as u32;
        let next_hint_addr_end = hint_addr_start + hint_len * WORD_SIZE as u32;
        if !mem_state.hints.contains(&hint_addr_start)
            || !mem_state.hints.contains(&next_hint_addr_end)
        {
            return Err(ZKVMError::VerifyError(
                "hint continuation out of range".into(),
            ));
        }
        if let Some(prev_hint_addr_end) = prev_hint_addr_end
            && hint_addr_start != prev_hint_addr_end
        {
            return Err(ZKVMError::VerifyError("hint continuation mismatch".into()));
        }

        Ok((next_heap_addr_end, next_hint_addr_end))
    }

    #[allow(clippy::type_complexity)]
    fn split_input_opening_evals(
        circuit_vk: &VerifyingKey<E>,
        proof: &ZKVMChipProof<E>,
    ) -> Result<(Vec<E>, Vec<E>), ZKVMError> {
        let cs = circuit_vk.get_cs();
        let Some(gkr_proof) = proof.gkr_iop_proof.as_ref() else {
            return Err(ZKVMError::InvalidProof("missing gkr proof".into()));
        };
        let Some(last_layer) = gkr_proof.0.last() else {
            return Err(ZKVMError::InvalidProof("empty gkr proof layers".into()));
        };

        let evals = &last_layer.main.evals;
        let wit_len = cs.num_witin();
        let fixed_len = cs.num_fixed();
        let min_len = wit_len + fixed_len;
        if evals.len() < min_len {
            return Err(ZKVMError::InvalidProof(
                format!(
                    "insufficient main evals: {} < required {}",
                    evals.len(),
                    min_len
                )
                .into(),
            ));
        }

        let wits_in_evals = evals[..wit_len].to_vec();
        let fixed_in_evals = evals[wit_len..(wit_len + fixed_len)].to_vec();
        Ok((wits_in_evals, fixed_in_evals))
    }

    /// Verify a full zkVM trace from program entry to halt.
    ///
    /// This is the production verifier API. It treats a single proof as a
    /// complete trace starting from `vk.entry_pc`, not as an arbitrary shard
    /// segment.
    #[tracing::instrument(skip_all, name = "verify_proof")]
    pub fn verify_proof(
        &self,
        vm_proof: ZKVMProof<E, PCS>,
        transcript: impl ForkableTranscript<E>,
    ) -> Result<bool, ZKVMError> {
        self.verify_full_trace_proofs_halt(vec![vm_proof], vec![transcript], true)
    }

    /// Verify a full zkVM trace composed of one or more proofs and ending in halt.
    #[tracing::instrument(skip_all, name = "verify_proofs")]
    pub fn verify_proofs(
        &self,
        vm_proofs: Vec<ZKVMProof<E, PCS>>,
        transcripts: Vec<impl ForkableTranscript<E>>,
    ) -> Result<bool, ZKVMError> {
        self.verify_full_trace_proofs_halt(vm_proofs, transcripts, true)
    }

    /// Verify a single shard proof as a standalone segment.
    ///
    /// This is a debug-oriented API. It checks proof validity and halt/segment
    /// invariants for one shard only and intentionally skips full-trace entry
    /// and cross-shard continuation checks such as `INIT_PC == vk.entry_pc` and
    /// init_pc/heap chaining.
    pub(crate) fn verify_single_shard_segment_halt(
        &self,
        vm_proof: ZKVMProof<E, PCS>,
        transcript: impl ForkableTranscript<E>,
        expect_halt: bool,
    ) -> Result<bool, ZKVMError> {
        let has_halt = vm_proof.has_halt(&self.vk);
        if has_halt != expect_halt {
            return Err(ZKVMError::VerifyError(
                format!("shard proof ecall/halt mismatch: expected {expect_halt} != {has_halt}",)
                    .into(),
            ));
        }

        assert_eq!(
            vm_proof.public_values.query_by_index::<E>(INIT_CYCLE_IDX),
            E::BaseField::from_canonical_u64(Tracer::SUBCYCLES_PER_INSN)
        );

        let shard_id = vm_proof.public_values.shard_id as usize;
        self.verify_proof_validity(shard_id, vm_proof, transcript)?;
        Ok(true)
    }

    /// Verify a full zkVM trace composed of one or more proofs from entry to
    /// optional halt.
    pub fn verify_full_trace_proofs_halt(
        &self,
        vm_proofs: Vec<ZKVMProof<E, PCS>>,
        transcripts: Vec<impl ForkableTranscript<E>>,
        expect_halt: bool,
    ) -> Result<bool, ZKVMError> {
        if vm_proofs.is_empty() {
            return Err(ZKVMError::VerifyError("empty proof batch".into()));
        }
        let num_proofs = vm_proofs.len();
        let (_end_pc, _end_heap_addr, _end_hint_addr, shard_ec_sum) = vm_proofs
            .into_iter()
            .zip_eq(transcripts)
            // optionally halt on last chunk
            .zip_eq(iter::repeat_n(false, num_proofs - 1).chain(iter::once(expect_halt)))
            .enumerate()
            .try_fold((None, None, None, SepticPoint::<E::BaseField>::default()), |(prev_pc, prev_heap_addr_end, prev_hint_addr_end, mut shard_ec_sum), (shard_id, ((vm_proof, transcript), expect_halt))| {
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
                // each shard set init cycle = Tracer::SUBCYCLES_PER_INSN
                // to satisfy initial reads for all prev_cycle = 0 < init_cycle
                let init_cycle = vm_proof.public_values.query_by_index::<E>(INIT_CYCLE_IDX);
                let expected_init_cycle =
                    E::BaseField::from_canonical_u64(Tracer::SUBCYCLES_PER_INSN);
                if init_cycle != expected_init_cycle {
                    return Err(ZKVMError::VerifyError(
                        format!(
                            "{shard_id}th shard init_cycle mismatch: expected {expected_init_cycle:?} != {init_cycle:?}"
                        )
                        .into(),
                    ));
                }
                // check init_pc match prev end_pc
                let init_pc = vm_proof.public_values.query_by_index::<E>(INIT_PC_IDX);
                let expected_init_pc = if let Some(prev_pc) = prev_pc {
                    prev_pc
                } else {
                    E::BaseField::from_canonical_u32(self.vk.entry_pc)
                };
                if init_pc != expected_init_pc {
                    return Err(ZKVMError::VerifyError(
                        format!(
                            "{shard_id}th shard init_pc mismatch: expected {expected_init_pc:?} != {init_pc:?}"
                        )
                        .into(),
                    ));
                }
                let end_pc = vm_proof.public_values.query_by_index::<E>(END_PC_IDX);

                let (next_heap_addr_end, next_hint_addr_end) = Self::validate_mem_state(
                    &self.vk.mem_state_verifier,
                    prev_heap_addr_end,
                    prev_hint_addr_end,
                    &vm_proof,
                )?;

                // add to shard ec sum
                let shard_ec = self.verify_proof_validity(shard_id, vm_proof, transcript)?;
                shard_ec_sum = shard_ec_sum + shard_ec;

                Ok((
                    Some(end_pc),
                    Some(next_heap_addr_end),
                    Some(next_hint_addr_end),
                    shard_ec_sum,
                ))
            })?;
        // TODO check _end_heap_addr within heap range from vk
        // check shard ec_sum is_infinity
        if !shard_ec_sum.is_infinity {
            return Err(ZKVMError::VerifyError(
                "shard_ec_sum is not infinity".into(),
            ));
        }
        Ok(true)
    }

    fn verify_proof_validity(
        &self,
        shard_id: usize,
        vm_proof: ZKVMProof<E, PCS>,
        mut transcript: impl ForkableTranscript<E>,
    ) -> Result<SepticPoint<E::BaseField>, ZKVMError> {
        // main invariant between opcode circuits and table circuits
        let mut prod_r = E::ONE;
        let mut prod_w = E::ONE;
        let mut logup_sum = E::ZERO;

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

        // Include transcript-visible public values in canonical circuit order.
        // This must match prover and recursion verifier exactly.
        for (_, circuit_vk) in self.vk.circuit_vks.iter() {
            for instance_value in circuit_vk.get_cs().zkvm_v1_css.instance.iter() {
                transcript.append_field_element(
                    &vm_proof.public_values.query_by_index::<E>(instance_value.0),
                );
            }
        }

        if vm_proof.public_values.shard_id != shard_id as u32 {
            return Err(ZKVMError::VerifyError(
                format!(
                    "proof shard_id mismatch: expected {} != {}",
                    shard_id, vm_proof.public_values.shard_id
                )
                .into(),
            ));
        }

        // write fixed commitment to transcript
        // TODO check soundness if there is no fixed_commit but got fixed proof?
        if let Some(fixed_commit) = self.vk.fixed_commit.as_ref() {
            PCS::write_commitment(fixed_commit, &mut transcript).map_err(ZKVMError::PCSError)?;
        }
        if let Some(fixed_commit) = self.vk.fixed_no_omc_init_commit.as_ref() {
            PCS::write_commitment(fixed_commit, &mut transcript).map_err(ZKVMError::PCSError)?;
        }

        // write (circuit_idx, num_instance) to transcript
        for (circuit_idx, proofs) in vm_proof.chip_proofs.iter() {
            transcript.append_field_element(&E::BaseField::from_canonical_u32(*circuit_idx as u32));
            // length of proof.num_instances will be constrained in verify_chip_proof
            for num_instance in proofs.iter().flat_map(|proof| &proof.num_instances) {
                transcript.append_field_element(&E::BaseField::from_canonical_usize(*num_instance));
            }
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
        tracing::debug!(
            "{shard_id}th shard challenges in verifier: {:?}",
            challenges
        );

        let dummy_table_item = challenges[0];
        let mut dummy_table_item_multiplicity = 0;
        let point_eval = PointAndEval::default();
        let mut witin_openings = Vec::with_capacity(vm_proof.chip_proofs.len());
        let mut fixed_openings = Vec::with_capacity(vm_proof.chip_proofs.len());
        let mut shard_ec_sum = SepticPoint::<E::BaseField>::default();

        // check num proofs
        let mut num_proofs = 0;
        for (index, proofs) in &vm_proof.chip_proofs {
            let circuit_name = self.vk.circuit_index_to_name.get(index).ok_or_else(|| {
                ZKVMError::VKNotFound(
                    format!("{shard_id}th shard circuit index {index} missing from vk index map")
                        .into(),
                )
            })?;
            let circuit_vk = self.vk.circuit_vks.get(circuit_name).ok_or_else(|| {
                ZKVMError::VKNotFound(
                    format!("{shard_id}th shard circuit name {circuit_name} missing from vk")
                        .into(),
                )
            })?;
            if shard_id > 0 && circuit_vk.get_cs().with_omc_init_only() {
                return Err(ZKVMError::InvalidProof(
                    format!("{shard_id}th shard non-first shard got omc dynamic table init",)
                        .into(),
                ));
            }
            if shard_id == 0 && circuit_vk.get_cs().with_omc_init_only() && proofs.len() != 1 {
                return Err(ZKVMError::InvalidProof(
                    format!("{shard_id}th shard first shard got > 1 omc dynamic table init",)
                        .into(),
                ));
            }
            if circuit_vk.get_cs().with_omc_init_dyn() && proofs.len() > 1 {
                return Err(ZKVMError::InvalidProof(
                    format!("{shard_id}th shard got > 1 dynamic table init").into(),
                ));
            }
            num_proofs += proofs.len();
        }

        // fork transcript to support chip concurrently proved
        let mut forked_transcripts = transcript.fork(num_proofs);
        for ((index, proof), transcript) in vm_proof
            .chip_proofs
            .iter()
            .flat_map(|(index, proofs)| iter::repeat_n(index, proofs.len()).zip(proofs))
            .zip_eq(forked_transcripts.iter_mut())
        {
            let num_instance: usize = proof.num_instances.iter().sum();
            if num_instance == 0 {
                return Err(ZKVMError::InvalidProof(
                    format!("{shard_id}th shard chip {index} has zero instances").into(),
                ));
            }
            let circuit_name = self.vk.circuit_index_to_name.get(index).ok_or_else(|| {
                ZKVMError::VKNotFound(
                    format!("{shard_id}th shard circuit index {index} missing from vk index map")
                        .into(),
                )
            })?;
            let circuit_vk = self.vk.circuit_vks.get(circuit_name).ok_or_else(|| {
                ZKVMError::VKNotFound(
                    format!("{shard_id}th shard circuit name {circuit_name} missing from vk")
                        .into(),
                )
            })?;

            if circuit_name == "HeapTable" {
                let heap_len = vm_proof
                    .public_values
                    .query_by_index::<E>(HEAP_LENGTH_IDX)
                    .to_canonical_u64() as usize;
                if num_instance != heap_len {
                    return Err(ZKVMError::InvalidProof(
                        format!("heap shard length mismatch: proof {num_instance} != public value {heap_len}").into(),
                    ));
                }
            }
            if circuit_name == "HintsTable" {
                let hint_len = vm_proof
                    .public_values
                    .query_by_index::<E>(HINT_LENGTH_IDX)
                    .to_canonical_u64() as usize;
                if num_instance != hint_len {
                    return Err(ZKVMError::InvalidProof(
                        format!("hint shard length mismatch: proof {num_instance} != public value {hint_len}").into(),
                    ));
                }
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
                    let &[p1, p2, q1, q2] = evals.as_slice() else {
                        return Err(ZKVMError::InvalidProof(
                            format!(
                                "{shard_id}th shard lk_out_evals row length {} != 4",
                                evals.len()
                            )
                            .into(),
                        ));
                    };
                    Ok(p1 * q1.inverse() + p2 * q2.inverse())
                })
                .sum::<Result<E, ZKVMError>>()?;

            transcript.append_field_element(&E::BaseField::from_canonical_u64(*index as u64));

            // compute logup_sum padding
            // getting the number of dummy padding item that we used in this opcode circuit
            let num_lks = circuit_vk.get_cs().num_lks();
            // each padding instance contribute to (2^rotation_vars) dummy lookup padding
            let num_padded_instance = (next_pow2_instance_padding(num_instance) - num_instance)
                * (1 << circuit_vk.get_cs().rotation_vars().unwrap_or(0));
            // each instance contribute to (2^rotation_vars - rotated) dummy lookup padding
            let num_instance_non_selected = num_instance
                * ((1 << circuit_vk.get_cs().rotation_vars().unwrap_or(0))
                    - (circuit_vk.get_cs().rotation_subgroup_size().unwrap_or(0) + 1));
            dummy_table_item_multiplicity +=
                num_lks * (num_padded_instance + num_instance_non_selected);

            // accumulate logup_sum
            logup_sum += chip_logup_sum;

            let (input_opening_point, chip_shard_ec_sum, wits_in_evals, fixed_in_evals) = self
                .verify_chip_proof(
                    circuit_name,
                    circuit_vk,
                    proof,
                    &vm_proof.public_values,
                    transcript,
                    NUM_FANIN,
                    &point_eval,
                    &challenges,
                )?;
            if circuit_vk.get_cs().num_witin() > 0 {
                witin_openings.push((
                    input_opening_point.len(),
                    (input_opening_point.clone(), wits_in_evals),
                ));
            }
            if circuit_vk.get_cs().num_fixed() > 0 {
                fixed_openings.push((
                    input_opening_point.len(),
                    (input_opening_point.clone(), fixed_in_evals),
                ));
            }
            prod_w *= proof.w_out_evals.iter().flatten().copied().product::<E>();
            prod_r *= proof.r_out_evals.iter().flatten().copied().product::<E>();
            tracing::debug!(
                "{shard_id}th shard verified proof for circuit {}",
                circuit_name
            );
            if let Some(chip_shard_ec_sum) = chip_shard_ec_sum {
                shard_ec_sum = shard_ec_sum + chip_shard_ec_sum;
            }
        }
        logup_sum -= E::from_canonical_u64(dummy_table_item_multiplicity as u64)
            * dummy_table_item.inverse();

        #[cfg(debug_assertions)]
        {
            Instrumented::<<<E as ExtensionField>::BaseField as PoseidonField>::P>::log_label(
                "tower_verify+main-sumcheck",
            );
        }

        // merge forked transcript into transcript
        let forked_samples = forked_transcripts
            .into_iter()
            .map(|mut fork_transcript| fork_transcript.sample_vec(1)[0])
            .collect_vec();
        for sample in forked_samples {
            transcript.append_field_element_ext(&sample);
        }

        // verify mpcs
        let mut rounds = vec![(vm_proof.witin_commit.clone(), witin_openings)];

        if let Some(fixed_commit) = self.vk.fixed_commit.as_ref()
            && shard_id == 0
        {
            rounds.push((fixed_commit.clone(), fixed_openings));
        } else if let Some(fixed_commit) = self.vk.fixed_no_omc_init_commit.as_ref()
            && shard_id > 0
        {
            rounds.push((fixed_commit.clone(), fixed_openings));
        }

        PCS::batch_verify(
            &self.vk.vp,
            rounds,
            &vm_proof.opening_proof,
            &mut transcript,
        )
        .map_err(ZKVMError::PCSError)?;
        // check rw_set equality of shard proof
        if prod_r != prod_w {
            return Err(ZKVMError::VerifyError(
                format!("{shard_id}th prod_r != prod_w").into(),
            ));
        }

        // check logup sum of shard proof
        if logup_sum != E::ZERO {
            return Err(ZKVMError::VerifyError(
                format!("{shard_id}th logup_sum({:?}) != 0", logup_sum).into(),
            ));
        }

        Ok(shard_ec_sum)
    }

    /// verify proof and return input opening point
    #[allow(clippy::too_many_arguments, clippy::type_complexity)]
    pub fn verify_chip_proof(
        &self,
        _name: &str,
        circuit_vk: &VerifyingKey<E>,
        proof: &ZKVMChipProof<E>,
        public_values: &PublicValues,
        transcript: &mut impl Transcript<E>,
        num_product_fanin: usize,
        _out_evals: &PointAndEval<E>,
        challenges: &[E; 2], // derive challenge from PCS
    ) -> Result<(Point<E>, Option<SepticPoint<E::BaseField>>, Vec<E>, Vec<E>), ZKVMError> {
        let composed_cs = circuit_vk.get_cs();
        let ComposedConstrainSystem {
            zkvm_v1_css: cs,
            gkr_circuit,
        } = &composed_cs;
        let num_instances = proof.num_instances.iter().sum();
        let (r_counts_per_instance, w_counts_per_instance, lk_counts_per_instance) = (
            cs.r_expressions.len() + cs.r_table_expressions.len(),
            cs.w_expressions.len() + cs.w_table_expressions.len(),
            cs.lk_expressions.len() + cs.lk_table_expressions.len(),
        );
        let num_batched = r_counts_per_instance + w_counts_per_instance + lk_counts_per_instance;

        let next_pow2_instance = next_pow2_instance_padding(num_instances);
        let mut log2_num_instances = ceil_log2(next_pow2_instance);
        if composed_cs.has_ecc_ops() {
            // for opcode circuit with ecc ops, the mles have one extra variable
            // to store the internal partial sums for ecc additions
            log2_num_instances += 1;
        }
        let num_var_with_rotation = log2_num_instances + composed_cs.rotation_vars().unwrap_or(0);

        // constrain log2_num_instances within max length
        let check_table_spec_vars = |table_spec: &crate::circuit_builder::SetTableSpec,
                                     kind: &str|
         -> Result<(), ZKVMError> {
            let num_vars = if let Some(len) = table_spec.len {
                ceil_log2(len)
            } else {
                let mut max_vars = log2_num_instances;
                for StructuralWitIn { witin_type, .. } in &table_spec.structural_witins {
                    let hint_num_vars = log2_num_instances;
                    if (1 << hint_num_vars) > witin_type.max_len() {
                        return Err(ZKVMError::InvalidProof(
                            format!(
                                "{_name} {kind} structural witin exceeds max_len: 2^{hint_num_vars} > {}",
                                witin_type.max_len()
                            )
                            .into(),
                        ));
                    }
                    max_vars = max_vars.max(hint_num_vars);
                }
                max_vars
            };
            if num_vars != log2_num_instances {
                return Err(ZKVMError::InvalidProof(
                    format!(
                        "{_name} {kind} table num_vars mismatch: {num_vars} != {log2_num_instances}"
                    )
                    .into(),
                ));
            }
            Ok(())
        };
        for set_table_expr in cs.r_table_expressions.iter().chain(&cs.w_table_expressions) {
            check_table_spec_vars(&set_table_expr.table_spec, "r/w")?;
        }
        for l in &cs.lk_table_expressions {
            check_table_spec_vars(&l.table_spec, "lk")?;
        }

        let mut shard_ec_sum: Option<SepticPoint<E::BaseField>> = None;

        // verify and reduce product tower sumcheck
        let tower_proofs = &proof.tower_proof;

        // bind read/write/lookup out evals into transcript before deriving tower challenges
        for eval in proof
            .r_out_evals
            .iter()
            .chain(proof.w_out_evals.iter())
            .chain(proof.lk_out_evals.iter())
            .flatten()
        {
            transcript.append_field_element_ext(eval);
        }

        let (rt_tower, record_evals, logup_p_evals, logup_q_evals) = TowerVerify::verify(
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

        if composed_cs.has_ecc_ops() {
            tracing::debug!("verifying ecc proof...");
            let ecc_proof = proof
                .ecc_proof
                .as_ref()
                .ok_or_else(|| ZKVMError::InvalidProof("missing ecc proof".into()))?;
            if ecc_proof.sum.is_infinity {
                return Err(ZKVMError::InvalidProof(
                    "invalid ecc proof: infinity shard sum".into(),
                ));
            }

            EccVerifier::verify_ecc_proof(ecc_proof, transcript)?;
            tracing::debug!("ecc proof verified.");
            shard_ec_sum = Some(ecc_proof.sum.clone());
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

        let base_evals = record_evals
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

        let gkr_circuit = gkr_circuit.as_ref().ok_or_else(|| {
            ZKVMError::InvalidProof(format!("{_name} missing gkr circuit in vk").into())
        })?;
        let first_layer = gkr_circuit.layers.first().ok_or_else(|| {
            ZKVMError::InvalidProof(format!("{_name} empty gkr circuit layers").into())
        })?;
        let selector_ctxs = first_layer
            .out_sel_and_eval_exprs
            .iter()
            .map(|(selector, _)| {
                if cs.ec_final_sum.is_empty() {
                    SelectorContext::new(0, num_instances, num_var_with_rotation)
                } else if cs.r_selector.as_ref() == Some(selector) {
                    SelectorContext::new(0, proof.num_instances[0], num_var_with_rotation)
                } else if cs.w_selector.as_ref() == Some(selector) {
                    SelectorContext::new(
                        proof.num_instances[0],
                        proof.num_instances[1],
                        num_var_with_rotation,
                    )
                } else {
                    SelectorContext::new(0, num_instances, num_var_with_rotation)
                }
            })
            .collect_vec();

        let mut out_evals = vec![PointAndEval::default(); gkr_circuit.n_evaluations];
        for (idx, point_and_eval) in base_evals.into_iter().enumerate() {
            out_evals[idx] = point_and_eval;
        }

        if !first_layer.rotation_exprs.1.is_empty() {
            let rotation_proof = proof
                .rotation_proof
                .as_ref()
                .ok_or_else(|| ZKVMError::InvalidProof("missing rotation proof".into()))?
                .clone();

            let rotation_sumcheck_expression = first_layer
                .rotation_sumcheck_expression
                .as_ref()
                .ok_or_else(|| {
                    ZKVMError::InvalidProof(
                        format!("{_name} missing rotation sumcheck expression").into(),
                    )
                })?;
            let rotation_claims = gkr_iop::gkr::layer::zerocheck_layer::verify_rotation(
                num_var_with_rotation,
                first_layer.rotation_exprs.1.len(),
                rotation_sumcheck_expression,
                rotation_proof,
                first_layer.rotation_cyclic_subgroup_size,
                first_layer.rotation_cyclic_group_log2,
                &rt_tower,
                challenges,
                transcript,
            )?;

            let Some([left_group_idx, right_group_idx, point_group_idx]) =
                first_layer.rotation_selector_group_indices()
            else {
                return Err(ZKVMError::InvalidProof(
                    "rotation claims expected but selectors are missing".into(),
                ));
            };

            assign_group_evals(
                &mut out_evals,
                &first_layer.out_sel_and_eval_exprs[left_group_idx].1,
                &rotation_claims.left_evals,
                &rotation_claims.rotation_points.left,
            );
            assign_group_evals(
                &mut out_evals,
                &first_layer.out_sel_and_eval_exprs[right_group_idx].1,
                &rotation_claims.right_evals,
                &rotation_claims.rotation_points.right,
            );
            assign_group_evals(
                &mut out_evals,
                &first_layer.out_sel_and_eval_exprs[point_group_idx].1,
                &rotation_claims.target_evals,
                &rotation_claims.rotation_points.origin,
            );
        }

        if let Some(ecc_proof) = proof.ecc_proof.as_ref() {
            let Some(
                [
                    x_group_idx,
                    y_group_idx,
                    slope_group_idx,
                    x3_group_idx,
                    y3_group_idx,
                ],
            ) = first_layer.ecc_bridge_group_indices()
            else {
                return Err(ZKVMError::InvalidProof(
                    "ecc bridge claims expected but selectors are missing".into(),
                ));
            };

            let sample_r = transcript.sample_and_append_vec(b"ecc_gkr_bridge_r", 1)[0];
            let claims = derive_ecc_bridge_claims(ecc_proof, sample_r, num_var_with_rotation)?;

            assign_group_evals(
                &mut out_evals,
                &first_layer.out_sel_and_eval_exprs[x_group_idx].1,
                &claims.x_evals,
                &claims.xy_point,
            );
            assign_group_evals(
                &mut out_evals,
                &first_layer.out_sel_and_eval_exprs[y_group_idx].1,
                &claims.y_evals,
                &claims.xy_point,
            );
            assign_group_evals(
                &mut out_evals,
                &first_layer.out_sel_and_eval_exprs[slope_group_idx].1,
                &claims.s_evals,
                &claims.s_point,
            );
            assign_group_evals(
                &mut out_evals,
                &first_layer.out_sel_and_eval_exprs[x3_group_idx].1,
                &claims.x3_evals,
                &claims.x3y3_point,
            );
            assign_group_evals(
                &mut out_evals,
                &first_layer.out_sel_and_eval_exprs[y3_group_idx].1,
                &claims.y3_evals,
                &claims.x3y3_point,
            );
        }

        let pi = cs
            .instance
            .iter()
            .map(|instance| E::from(public_values.query_by_index::<E>(instance.0)))
            .collect_vec();
        let (wits_in_evals, fixed_in_evals) = Self::split_input_opening_evals(circuit_vk, proof)?;
        let gkr_iop_proof = proof.gkr_iop_proof.clone().ok_or_else(|| {
            ZKVMError::InvalidProof(format!("{_name} missing gkr iop proof").into())
        })?;
        let (_, rt) = gkr_circuit.verify(
            num_var_with_rotation,
            gkr_iop_proof,
            &out_evals,
            &pi,
            challenges,
            transcript,
            &selector_ctxs,
        )?;
        Ok((rt, shard_ec_sum, wits_in_evals, fixed_in_evals))
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
        if num_fanin != 2 {
            return Err(ZKVMError::VerifyError(
                format!("tower verify: num_fanin must be 2, got {num_fanin}").into(),
            ));
        }
        let num_prod_spec = prod_out_evals.len();
        let num_logup_spec = logup_out_evals.len();

        let log2_num_fanin = ceil_log2(num_fanin);
        if num_prod_spec != tower_proofs.prod_spec_size() {
            return Err(ZKVMError::InvalidProof(
                format!(
                    "tower verify: prod spec size mismatch: {num_prod_spec} != {}",
                    tower_proofs.prod_spec_size()
                )
                .into(),
            ));
        }
        if !prod_out_evals.iter().all(|evals| evals.len() == num_fanin) {
            return Err(ZKVMError::InvalidProof(
                format!("tower verify: prod_out_evals row length != {num_fanin}").into(),
            ));
        }
        if num_logup_spec != tower_proofs.logup_spec_size() {
            return Err(ZKVMError::InvalidProof(
                format!(
                    "tower verify: logup spec size mismatch: {num_logup_spec} != {}",
                    tower_proofs.logup_spec_size()
                )
                .into(),
            ));
        }
        if !logup_out_evals.iter().all(|evals| evals.len() == 4) {
            return Err(ZKVMError::InvalidProof(
                "tower verify: logup_out_evals row length != 4".into(),
            ));
        }
        if num_variables.len() != num_prod_spec + num_logup_spec {
            return Err(ZKVMError::InvalidProof(
                format!(
                    "tower verify: num_variables length {} != num_prod_spec {num_prod_spec} + num_logup_spec {num_logup_spec}",
                    num_variables.len()
                )
                .into(),
            ));
        }

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

        // initial claim = \sum_j alpha^j * out_j[rt]
        let initial_claim = izip!(&prod_spec_point_n_eval, &alpha_pows)
            .map(|(point_n_eval, alpha)| point_n_eval.eval * *alpha)
            .sum::<E>()
            + izip!(
                interleave(&logup_spec_p_point_n_eval, &logup_spec_q_point_n_eval),
                &alpha_pows[num_prod_spec..]
            )
            .map(|(point_n_eval, alpha)| point_n_eval.eval * *alpha)
            .sum::<E>();

        let max_num_variables = num_variables
            .iter()
            .max()
            .ok_or_else(|| ZKVMError::InvalidProof("tower verify: empty num_variables".into()))?;
        let required_rounds = max_num_variables.saturating_sub(1);
        if tower_proofs.proofs.len() < required_rounds {
            return Err(ZKVMError::InvalidProof(
                format!(
                    "tower verify: sumcheck proofs length {} < required {required_rounds}",
                    tower_proofs.proofs.len()
                )
                .into(),
            ));
        }
        for (spec_index, &max_round) in num_variables.iter().enumerate().take(num_prod_spec) {
            let needed = max_round.saturating_sub(1);
            if tower_proofs.prod_specs_eval[spec_index].len() < needed {
                return Err(ZKVMError::InvalidProof(
                    format!(
                        "tower verify: prod spec {spec_index} eval rounds {} < required {needed}",
                        tower_proofs.prod_specs_eval[spec_index].len()
                    )
                    .into(),
                ));
            }
            for (round, row) in tower_proofs.prod_specs_eval[spec_index]
                .iter()
                .enumerate()
                .take(needed)
            {
                if row.len() != num_fanin {
                    return Err(ZKVMError::InvalidProof(
                        format!(
                            "tower verify: prod spec {spec_index} round {round} row length {} != {num_fanin}",
                            row.len()
                        )
                        .into(),
                    ));
                }
            }
        }
        for (spec_index, &max_round) in num_variables[num_prod_spec..].iter().enumerate() {
            let needed = max_round.saturating_sub(1);
            if tower_proofs.logup_specs_eval[spec_index].len() < needed {
                return Err(ZKVMError::InvalidProof(
                    format!(
                        "tower verify: logup spec {spec_index} eval rounds {} < required {needed}",
                        tower_proofs.logup_specs_eval[spec_index].len()
                    )
                    .into(),
                ));
            }
            for (round, row) in tower_proofs.logup_specs_eval[spec_index]
                .iter()
                .enumerate()
                .take(needed)
            {
                if row.len() != 4 {
                    return Err(ZKVMError::InvalidProof(
                        format!(
                            "tower verify: logup spec {spec_index} round {round} row length {} != 4",
                            row.len()
                        )
                        .into(),
                    ));
                }
            }
        }

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
                let eq = eq_eval(out_rt, &rt);

                bind_active_tower_eval_round(
                    transcript,
                    tower_proofs,
                    &num_variables,
                    num_prod_spec,
                    round,
                );

                let expected_evaluation: E = (0..num_prod_spec)
                    .zip(alpha_pows.iter())
                    .zip(num_variables.iter())
                    .map(|((spec_index, alpha), max_round)| {
                        // prod'[b] = prod[0,b] * prod[1,b]
                        // prod'[out_rt] = \sum_b eq(out_rt,b) * prod'[b] = \sum_b eq(out_rt,b) * prod[0,b] * prod[1,b]
                        eq * *alpha
                            * if round < *max_round - 1 { tower_proofs.prod_specs_eval[spec_index][round].iter().copied().product() } else {
                            E::ZERO
                        }
                    })
                    .sum::<E>()
                    + (0..num_logup_spec)
                    .zip_eq(alpha_pows[num_prod_spec..].chunks(2))
                    .zip_eq(num_variables[num_prod_spec..].iter())
                    .map(|((spec_index, alpha), max_round)| {
                        // logup_q'[b] = logup_q[0,b] * logup_q[1,b]
                        // logup_p'[b] = logup_p[0,b] * logup_q[1,b] + logup_p[1,b] * logup_q[0,b]
                        // logup_p'[out_rt] = \sum_b eq(out_rt,b) * (logup_p[0,b] * logup_q[1,b] + logup_p[1,b] * logup_q[0,b])
                        // logup_q'[out_rt] = \sum_b eq(out_rt,b) * logup_q[0,b] * logup_q[1,b]
                        let (alpha_numerator, alpha_denominator) = (&alpha[0], &alpha[1]);
                        eq * if round < *max_round - 1 {
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
                        // prod'[rt,r_merge] = \sum_b eq(r_merge, b) * prod'[b,rt]
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

pub struct EccVerifier;

impl EccVerifier {
    pub fn verify_ecc_proof<E: ExtensionField>(
        proof: &EccQuarkProof<E>,
        transcript: &mut impl Transcript<E>,
    ) -> Result<(), ZKVMError> {
        let num_vars = next_pow2_instance_padding(proof.num_instances).ilog2() as usize;
        let out_rt = transcript.sample_and_append_vec(b"ecc", num_vars);
        let alpha_pows = transcript.sample_and_append_challenge_pows(
            SEPTIC_EXTENSION_DEGREE * 3 + SEPTIC_EXTENSION_DEGREE * 4,
            b"ecc_alpha",
        );
        let mut alpha_pows_iter = alpha_pows.iter();

        let sumcheck_claim = IOPVerifierState::verify(
            E::ZERO,
            &proof.zerocheck_proof,
            &VPAuxInfo {
                max_degree: 3,
                max_num_variables: num_vars,
                phantom: PhantomData,
            },
            transcript,
        );

        let required_evals_len = 3 + 7 * SEPTIC_EXTENSION_DEGREE;
        if proof.evals.len() < required_evals_len {
            return Err(ZKVMError::InvalidProof(
                format!(
                    "ecc proof evals length {} < required {required_evals_len}",
                    proof.evals.len()
                )
                .into(),
            ));
        }
        let evals = &proof.evals[3..]; // skip sel_add, sel_bypass, sel_export
        let s0: SepticExtension<E> = evals[0..][..SEPTIC_EXTENSION_DEGREE].into();
        let x0: SepticExtension<E> =
            evals[SEPTIC_EXTENSION_DEGREE..][..SEPTIC_EXTENSION_DEGREE].into();
        let y0: SepticExtension<E> =
            evals[2 * SEPTIC_EXTENSION_DEGREE..][..SEPTIC_EXTENSION_DEGREE].into();
        let x1: SepticExtension<E> =
            evals[3 * SEPTIC_EXTENSION_DEGREE..][..SEPTIC_EXTENSION_DEGREE].into();
        let y1: SepticExtension<E> =
            evals[4 * SEPTIC_EXTENSION_DEGREE..][..SEPTIC_EXTENSION_DEGREE].into();
        let x3: SepticExtension<E> =
            evals[5 * SEPTIC_EXTENSION_DEGREE..][..SEPTIC_EXTENSION_DEGREE].into();
        let y3: SepticExtension<E> =
            evals[6 * SEPTIC_EXTENSION_DEGREE..][..SEPTIC_EXTENSION_DEGREE].into();

        let rt = sumcheck_claim
            .point
            .iter()
            .map(|c| c.elements)
            .collect_vec();

        // zerocheck: 0 = s[1,b] * (x[b,0] - x[b,1]) - (y[b,0] - y[b,1])
        // zerocheck: 0 = s[1,b]^2 - x[b,0] - x[b,1] - x[1,b]
        // zerocheck: 0 = s[1,b] * (x[b,0] - x[1,b]) - (y[b,0] + y[1,b])
        // zerocheck: 0 = (x[1,b] - x[b,0]) * sel_bypass
        // zerocheck: 0 = (y[1,b] - y[b,0]) * sel_bypass
        // zerocheck: 0 = (x[1,b] - final_x) * sel_export
        // zerocheck: 0 = (y[1,b] - final_y) * sel_export
        //
        // note that they are not septic extension field elements,
        // we just want to reuse the multiply/add/sub formulas
        let v1: SepticExtension<E> = s0.clone() * (&x0 - &x1) - (&y0 - &y1);
        let v2: SepticExtension<E> = s0.square() - &x0 - &x1 - &x3;
        let v3: SepticExtension<E> = s0 * (&x0 - &x3) - (&y0 + &y3);

        let v4: SepticExtension<E> = &x3 - &x0;
        let v5: SepticExtension<E> = &y3 - &y0;

        let [v1, v2, v3, v4, v5] = [v1, v2, v3, v4, v5].map(|v| {
            v.0.into_iter()
                .zip(alpha_pows_iter.by_ref().take(SEPTIC_EXTENSION_DEGREE))
                .map(|(c, alpha)| c * *alpha)
                .collect_vec()
        });

        let sel_add_expr = SelectorType::<E>::QuarkBinaryTreeLessThan(Expression::StructuralWitIn(
            0,
            // this value doesn't matter, as we only need structural id
            StackedConstantSequence { max_value: 0 },
        ));
        let Some((expected_sel_add, _)) = sel_add_expr.evaluate(
            &out_rt,
            &rt,
            &SelectorContext {
                offset: 0,
                num_instances: proof.num_instances,
                num_vars,
            },
        ) else {
            return Err(ZKVMError::InvalidProof(
                "ecc proof: sel_add selector evaluation returned None".into(),
            ));
        };

        if proof.evals[0] != expected_sel_add {
            return Err(ZKVMError::VerifyError(
                (format!(
                    "sel_add evaluation mismatch, expected {}, got {}",
                    expected_sel_add, proof.evals[0]
                ))
                .into(),
            ));
        }

        // derive `sel_bypass = eq - sel_add - sel_last_onehot`
        let expected_sel_bypass = eq_eval(&out_rt, &rt)
            - expected_sel_add
            - (out_rt.iter().copied().product::<E>() * rt.iter().copied().product::<E>());

        if proof.evals[1] != expected_sel_bypass {
            return Err(ZKVMError::VerifyError(
                (format!(
                    "sel_bypass evaluation mismatch, expected {}, got {}",
                    expected_sel_bypass, proof.evals[1]
                ))
                .into(),
            ));
        }

        // derive `sel_export`
        let lsi_on_hypercube = once(E::ZERO)
            .chain(repeat_n(E::ONE, out_rt.len() - 1))
            .collect_vec();
        let expected_sel_export =
            eq_eval(&out_rt, &lsi_on_hypercube) * eq_eval(&rt, &lsi_on_hypercube);
        if proof.evals[2] != expected_sel_export {
            return Err(ZKVMError::VerifyError(
                (format!(
                    "sel_export evaluation mismatch, expected {}, got {}",
                    expected_sel_export, proof.evals[2]
                ))
                .into(),
            ));
        }
        let export_evaluations: E =
            x3.0.iter()
                .zip_eq(proof.sum.x.0.iter())
                .chain(y3.0.iter().zip_eq(proof.sum.y.0.iter()))
                .map(|(a, b)| *a - *b)
                .zip_eq(alpha_pows_iter.by_ref().take(SEPTIC_EXTENSION_DEGREE * 2))
                .map(|(c, alpha)| c * *alpha)
                .sum();

        let add_evaluations = vec![v1, v2, v3].into_iter().flatten().sum::<E>();
        let bypass_evaluations = vec![v4, v5].into_iter().flatten().sum::<E>();
        if sumcheck_claim.expected_evaluation
            != add_evaluations * expected_sel_add
                + bypass_evaluations * expected_sel_bypass
                + export_evaluations * expected_sel_export
        {
            return Err(ZKVMError::VerifyError(
                (format!(
                    "ecc zerocheck failed: mismatched evaluation, expected {}, got {}",
                    sumcheck_claim.expected_evaluation,
                    add_evaluations * expected_sel_add + bypass_evaluations * expected_sel_bypass
                ))
                .into(),
            ));
        }

        Ok(())
    }
}
