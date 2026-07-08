use core::borrow::{Borrow, BorrowMut};
use std::sync::Arc;

use eyre::{Result, bail};
use ff_ext::{BabyBearExt4, ExtensionField as CenoExtensionField, SmallField};
use itertools::Itertools;
use mpcs::{
    BasefoldRSParams,
    basefold::BasefoldSpec,
    jagged::{compute_q_at_assist_point, evaluate_g},
};
use multilinear_extensions::{util::ceil_log2, virtual_poly::build_eq_x_r_vec};
use openvm_circuit_primitives::utils::assert_array_eq;
use openvm_cpu_backend::CpuBackend;
use openvm_poseidon2_air::POSEIDON2_WIDTH;
use openvm_stark_backend::{
    AirRef, BaseAirWithPublicValues, FiatShamirTranscript, PartitionedBaseAir, StarkProtocolConfig,
    TranscriptHistory, interaction::InteractionBuilder, prover::AirProvingContext,
};
use openvm_stark_sdk::config::baby_bear_poseidon2::{
    BabyBearPoseidon2Config, D_EF, DIGEST_SIZE, EF, F, poseidon2_compress_with_capacity,
    poseidon2_perm,
};
use p3::{
    dft::{Radix2Dit, TwoAdicSubgroupDft},
    matrix::dense::RowMajorMatrix as P3RowMajorMatrix,
    util::reverse_bits_len,
};
use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::{
    BasedVectorSpace, Field, PrimeCharacteristicRing, PrimeField64, TwoAdicField,
    extension::BinomiallyExtendable,
};
use p3_matrix::{Matrix, bitrev::BitReversibleMatrix, dense::RowMajorMatrix};
use p3_symmetric::Permutation;
use stark_recursion_circuit_derive::AlignedBorrow;
use sumcheck::util::extrapolate_uni_poly;

use crate::{
    bus::{
        MainEvalBus, MainEvalMessage, MainGlobalPointBus, MainGlobalPointMessage,
        PcsBaseInputOpeningBus, PcsBaseInputOpeningMessage, PcsBasefoldEvalBus,
        PcsBasefoldEvalMessage, PcsBasefoldFinalExpectedBus, PcsBasefoldFinalExpectedMessage,
        PcsBasefoldFinalPointBus, PcsBasefoldFinalPointMessage, PcsBasefoldQueryBus,
        PcsBasefoldQueryMessage, PcsBasefoldQueryStage, PcsBatchAlphaBus, PcsBatchAlphaMessage,
        PcsBatchCoeffBus, PcsBatchCoeffMessage, PcsCommitHeightBus, PcsCommitHeightMessage,
        PcsCommitPhaseLeafBus, PcsCommitPhaseLeafMessage, PcsCommitmentRootBus,
        PcsCommitmentRootMessage, PcsEqProductBus, PcsEqProductMessage, PcsFinalMessageBus,
        PcsFinalMessageMessage, PcsFoldChallengeBus, PcsFoldChallengeMessage, PcsJaggedAssistHBus,
        PcsJaggedAssistHMessage, PcsJaggedAssistQBus, PcsJaggedAssistQMessage, PcsJaggedFEvalBus,
        PcsJaggedFEvalMessage, PcsOpeningEvalBus, PcsOpeningEvalMessage, PcsQuerySampleBus,
        PcsQuerySampleMessage, PcsSuffixProductBus, PcsSuffixProductMessage, PcsSumcheckInputBus,
        PcsSumcheckInputMessage, PcsSumcheckOutputBus, PcsSumcheckOutputMessage,
        PcsTranscriptExtBus, PcsTranscriptExtMessage, TranscriptBus, TranscriptBusMessage,
    },
    system::{
        AirModule, GlobalCtxCpu, PcsBaseInputLeafHashRecord, PcsBaseInputMerkleRecord,
        PcsBasefoldCommitPhaseQueryRecord, PcsBasefoldFinalClaimRecord,
        PcsBasefoldFinalCodewordRecord, PcsBasefoldFinalExpectedRecord,
        PcsBasefoldFinalPointRecord, PcsBasefoldInitialClaimRecord, PcsBasefoldQueryIndexRecord,
        PcsBasefoldQueryOpenRecord, PcsBatchCoeffRecord, PcsCommitPhaseLeafHashRecord,
        PcsCommitPhaseMerkleRecord, PcsCommitmentRootRecord, PcsEqProductKind, PcsEqProductRecord,
        PcsEqProductSource, PcsJaggedAssistHRecord, PcsJaggedAssistInputRecord,
        PcsJaggedAssistQRecord, PcsJaggedAssistRecord, PcsJaggedClaimRecord, PcsJaggedQEvalRecord,
        PcsOpeningCommitKind, PcsOpeningEvalRecord, PcsOpeningPointRecord, PcsSuffixProductRecord,
        PcsSumcheckInputRecord, PcsSumcheckRoundRecord, PcsTranscriptValueRecord, Preflight,
        RecursionField, RecursionPcs, RecursionProof, RecursionVk, TraceGenModule,
    },
    tracegen::{ModuleChip, RowMajorChip},
    utils::digests_to_poseidon2_input,
};
use recursion_circuit::{
    bus::{
        MerkleVerifyBus, MerkleVerifyBusMessage, Poseidon2CompressBus, Poseidon2CompressMessage,
        Poseidon2PermuteBus, Poseidon2PermuteMessage,
    },
    primitives::bus::{RangeCheckerBus, RangeCheckerBusMessage},
};

pub struct PcsModule {
    transcript_bus: TranscriptBus,
    main_global_point_bus: MainGlobalPointBus,
    main_eval_bus: MainEvalBus,
    basefold_query_bus: PcsBasefoldQueryBus,
    basefold_eval_bus: PcsBasefoldEvalBus,
    basefold_final_expected_bus: PcsBasefoldFinalExpectedBus,
    basefold_final_point_bus: PcsBasefoldFinalPointBus,
    transcript_ext_bus: PcsTranscriptExtBus,
    base_input_opening_bus: PcsBaseInputOpeningBus,
    final_message_bus: PcsFinalMessageBus,
    query_sample_bus: PcsQuerySampleBus,
    commitment_root_bus: PcsCommitmentRootBus,
    commit_phase_leaf_bus: PcsCommitPhaseLeafBus,
    sumcheck_input_bus: PcsSumcheckInputBus,
    sumcheck_output_bus: PcsSumcheckOutputBus,
    fold_challenge_bus: PcsFoldChallengeBus,
    batch_coeff_bus: PcsBatchCoeffBus,
    batch_alpha_bus: PcsBatchAlphaBus,
    jagged_f_eval_bus: PcsJaggedFEvalBus,
    opening_eval_bus: PcsOpeningEvalBus,
    eq_product_bus: PcsEqProductBus,
    suffix_product_bus: PcsSuffixProductBus,
    jagged_assist_h_bus: PcsJaggedAssistHBus,
    jagged_assist_q_bus: PcsJaggedAssistQBus,
    commit_height_bus: PcsCommitHeightBus,
    merkle_verify_bus: MerkleVerifyBus,
    poseidon2_permute_bus: Poseidon2PermuteBus,
    poseidon2_compress_bus: Poseidon2CompressBus,
    range_checker_bus: RangeCheckerBus,
}

pub(crate) fn collect_pcs_range_checks(preflights: &[Preflight]) -> Vec<usize> {
    preflights
        .iter()
        .flat_map(|preflight| preflight.pcs.basefold_query_indices.iter())
        .flat_map(|record| {
            record
                .query_bytes
                .iter()
                .chain(record.high_bytes.iter())
                .map(|&byte| byte as usize)
                .collect_vec()
        })
        .collect()
}

type BasefoldOpeningEvals = Vec<(RecursionField, usize)>;
type BasefoldOpening = (usize, (Vec<RecursionField>, BasefoldOpeningEvals));
type BasefoldRound = (
    mpcs::basefold::BasefoldCommitment<RecursionField>,
    Vec<BasefoldOpening>,
);
type JaggedTermSource = (usize, usize, PcsOpeningCommitKind, usize, usize, usize);

fn ensure_supported_basecode_log(basecode_log: usize) -> Result<()> {
    if basecode_log != 0 {
        bail!(
            "unsupported basefold basecode_log {basecode_log}; only basecode_log == 0 is supported"
        );
    }
    Ok(())
}

fn push_eq_product_records(
    preflight: &mut Preflight,
    kind: PcsEqProductKind,
    source: PcsEqProductSource,
    round_idx: usize,
    term_idx: usize,
    point: &[RecursionField],
    point_tidx_base: usize,
    sumcheck_idx: usize,
    point_round_base: usize,
) -> RecursionField {
    let mut acc = RecursionField::ONE;
    let mut index_acc = 0usize;
    for (bit_idx, &point_value) in point.iter().enumerate() {
        let index_bit = ((term_idx >> bit_idx) & 1) == 1;
        let factor = if index_bit {
            point_value
        } else {
            RecursionField::ONE - point_value
        };
        let acc_in = acc;
        acc *= factor;
        let index_acc_in = index_acc;
        let index_pow2 = 1usize << bit_idx;
        if index_bit {
            index_acc += index_pow2;
        }
        preflight.pcs.eq_products.push(PcsEqProductRecord {
            proof_idx: 0,
            kind,
            source,
            round_idx,
            term_idx,
            bit_idx,
            is_first: bit_idx == 0,
            is_last: bit_idx + 1 == point.len(),
            lookup_count: if bit_idx + 1 == point.len() {
                if kind == PcsEqProductKind::JaggedClaim {
                    2
                } else {
                    1
                }
            } else {
                0
            },
            point_tidx: point_tidx_base + bit_idx * D_EF,
            sumcheck_idx,
            point_round: point_round_base + bit_idx,
            index_bit,
            index_pow2,
            index_acc_in,
            index_acc_out: index_acc,
            point: point_value,
            acc_in,
            acc_out: acc,
        });
    }
    acc
}

fn push_suffix_product_records(
    preflight: &mut Preflight,
    round_idx: usize,
    term_idx: usize,
    start_coord_idx: usize,
    point: &[RecursionField],
) -> RecursionField {
    let mut acc = RecursionField::ONE;
    let factor_count = point.len().saturating_sub(start_coord_idx);
    let row_count = factor_count.max(1);
    for step_idx in 0..row_count {
        let has_factor = step_idx < factor_count;
        let coord_idx = if has_factor {
            start_coord_idx + step_idx
        } else {
            start_coord_idx
        };
        let point_value = point.get(coord_idx).copied().unwrap_or_default();
        let acc_in = acc;
        if has_factor {
            acc *= RecursionField::ONE - point_value;
        }
        preflight.pcs.suffix_products.push(PcsSuffixProductRecord {
            proof_idx: 0,
            round_idx,
            term_idx,
            coord_idx,
            step_idx,
            is_first: step_idx == 0,
            is_last: step_idx + 1 == row_count,
            has_factor,
            point: point_value,
            acc_in,
            acc_out: acc,
        });
    }
    acc
}

fn jagged_transition_weights(
    z1i: RecursionField,
    z2i: RecursionField,
    z3i: RecursionField,
    z4i: RecursionField,
) -> [(usize, usize, RecursionField, RecursionField, RecursionField); 4] {
    let (nz1, nz2, nz3, nz4) = (
        RecursionField::ONE - z1i,
        RecursionField::ONE - z2i,
        RecursionField::ONE - z3i,
        RecursionField::ONE - z4i,
    );
    let ab00 = nz1 * nz2;
    let ab01 = nz1 * z2i;
    let ab10 = z1i * nz2;
    let ab11 = z1i * z2i;
    let cd00 = nz3 * nz4;
    let cd01 = nz3 * z4i;
    let cd10 = z3i * nz4;
    let cd11 = z3i * z4i;
    [
        (
            0,
            0,
            ab00 * cd00 + ab01 * cd11 + ab11 * cd01,
            ab00 * cd01,
            ab01 * cd10 + ab11 * cd00,
        ),
        (0, 1, ab10 * cd10, ab10 * cd11, RecursionField::ZERO),
        (1, 0, ab01 * cd01, RecursionField::ZERO, ab01 * cd00),
        (
            1,
            1,
            ab00 * cd10 + ab10 * cd00 + ab11 * cd11,
            ab00 * cd11 + ab10 * cd01,
            ab11 * cd10,
        ),
    ]
}

fn jagged_backward_step(
    z1i: RecursionField,
    z2i: RecursionField,
    z3i: RecursionField,
    z4i: RecursionField,
    val: [RecursionField; 4],
) -> [RecursionField; 4] {
    let mut new_val = [RecursionField::ZERO; 4];
    for &(ci, co, w_same, w_lt1, w_lt0) in &jagged_transition_weights(z1i, z2i, z3i, z4i) {
        let v0 = val[co * 2];
        let v1 = val[co * 2 + 1];
        new_val[ci * 2] += w_same * v0 + w_lt1 * v1 + w_lt0 * v0;
        new_val[ci * 2 + 1] += w_same * v1 + w_lt1 * v1 + w_lt0 * v0;
    }
    new_val
}

fn push_jagged_assist_h_records(
    preflight: &mut Preflight,
    round_idx: usize,
    point: &[RecursionField],
    rho: &[RecursionField],
    assist_point: &[RecursionField],
    n_robp: usize,
) -> RecursionField {
    let sumcheck_idx = round_idx * 2 + 1;
    let mut val = [
        RecursionField::ZERO,
        RecursionField::ONE,
        RecursionField::ZERO,
        RecursionField::ZERO,
    ];
    for step_idx in 0..n_robp {
        let robp_idx = n_robp - 1 - step_idx;
        let has_z_row = robp_idx < point.len();
        let has_rho = robp_idx < rho.len();
        let z_row = point.get(robp_idx).copied().unwrap_or_default();
        let rho_value = rho.get(robp_idx).copied().unwrap_or_default();
        let rho_star_c = assist_point[2 * robp_idx];
        let rho_star_d = assist_point[2 * robp_idx + 1];
        let val_in = val;
        val = jagged_backward_step(z_row, rho_value, rho_star_c, rho_star_d, val);
        preflight.pcs.jagged_assist_h.push(PcsJaggedAssistHRecord {
            proof_idx: 0,
            round_idx,
            sumcheck_idx,
            step_idx,
            robp_idx,
            is_first: step_idx == 0,
            is_last: step_idx + 1 == n_robp,
            has_z_row,
            has_rho,
            z_row,
            rho: rho_value,
            rho_star_c,
            rho_star_d,
            val_in,
            val_out: val,
        });
    }
    val[0]
}

fn push_jagged_assist_q_records(
    preflight: &mut Preflight,
    round_idx: usize,
    commitment_kind: usize,
    assist_point: &[RecursionField],
    eq_col: &[RecursionField],
    cumulative_heights: &[usize],
    n_robp: usize,
) -> RecursionField {
    let sumcheck_idx = round_idx * 2 + 1;
    let num_polys = cumulative_heights.len() - 1;
    let mut q_acc = RecursionField::ZERO;
    for term_idx in 0..num_polys {
        let mut term_acc = eq_col[term_idx];
        let mut c_acc = 0usize;
        let mut d_acc = 0usize;
        for step_idx in 0..n_robp {
            let c_bit = ((cumulative_heights[term_idx] >> step_idx) & 1) == 1;
            let d_bit = ((cumulative_heights[term_idx + 1] >> step_idx) & 1) == 1;
            let bit_pow2 = 1usize << step_idx;
            let c_acc_in = c_acc;
            let d_acc_in = d_acc;
            if c_bit {
                c_acc += bit_pow2;
            }
            if d_bit {
                d_acc += bit_pow2;
            }
            let rho_star_c = assist_point[2 * step_idx];
            let rho_star_d = assist_point[2 * step_idx + 1];
            let c_factor = if c_bit {
                rho_star_c
            } else {
                RecursionField::ONE - rho_star_c
            };
            let d_factor = if d_bit {
                rho_star_d
            } else {
                RecursionField::ONE - rho_star_d
            };
            let term_acc_in = term_acc;
            term_acc *= c_factor * d_factor;
            let q_acc_in = q_acc;
            let is_last_step = step_idx + 1 == n_robp;
            if is_last_step {
                q_acc += term_acc;
            }
            preflight.pcs.jagged_assist_q.push(PcsJaggedAssistQRecord {
                proof_idx: 0,
                round_idx,
                sumcheck_idx,
                commitment_kind,
                term_idx,
                step_idx,
                robp_idx: step_idx,
                is_first: term_idx == 0 && step_idx == 0,
                is_last: term_idx + 1 == num_polys && is_last_step,
                is_first_step: step_idx == 0,
                is_last_step,
                term_is_last: term_idx + 1 == num_polys,
                eq_col: eq_col[term_idx],
                t_lo: cumulative_heights[term_idx],
                t_hi: cumulative_heights[term_idx + 1],
                c_bit,
                d_bit,
                bit_pow2,
                c_acc_in,
                c_acc_out: c_acc,
                d_acc_in,
                d_acc_out: d_acc,
                rho_star_c,
                rho_star_d,
                term_acc_in,
                term_acc_out: term_acc,
                q_acc_in,
                q_acc_out: q_acc,
            });
        }
    }
    q_acc
}

fn push_basefold_final_expected_records(
    preflight: &mut Preflight,
    rounds: &[BasefoldRound],
    final_message: &[Vec<RecursionField>],
    fold_challenges: &[RecursionField],
    basecode_log: usize,
    final_tidx: usize,
) -> Result<RecursionField> {
    let sumcheck_idx = 8_000_000;
    let mut acc = RecursionField::ZERO;
    let mut term_idx = preflight.pcs.basefold_final_expected.len();
    let mut flat_message_idx = 0usize;
    for (point_idx, (round_idx, point)) in final_message
        .iter()
        .zip(
            rounds
                .iter()
                .enumerate()
                .flat_map(|(round_idx, (_, point_evals))| {
                    point_evals
                        .iter()
                        .map(move |(_, (point, _))| (round_idx, point))
                })
                .filter(|(_, point)| point.len() >= basecode_log),
        )
        .map(|(_, point)| point)
        .enumerate()
    {
        for (coord_idx, &value) in point.iter().enumerate() {
            let source_sumcheck_idx = round_idx * 2;
            if let Some(record) = preflight
                .pcs
                .sumcheck_rounds
                .iter_mut()
                .find(|record| record.idx == source_sumcheck_idx && record.round == coord_idx)
            {
                record.fold_challenge_lookup_count += 1;
            }
            preflight
                .pcs
                .basefold_final_points
                .push(PcsBasefoldFinalPointRecord {
                    proof_idx: 0,
                    sumcheck_idx,
                    point_idx,
                    coord_idx,
                    source_sumcheck_idx,
                    source_round: coord_idx,
                    value,
                });
        }
    }
    for (point_idx, (message_row, point)) in final_message
        .iter()
        .zip(
            rounds
                .iter()
                .flat_map(|(_, point_evals)| point_evals.iter())
                .filter(|(_, (point, _))| point.len() >= basecode_log)
                .map(|(_, (point, _))| point),
        )
        .enumerate()
    {
        let num_vars_evaluated = point.len() - basecode_log;
        if num_vars_evaluated > fold_challenges.len() {
            bail!("basefold final expected point exceeds fold challenge count");
        }
        for (elem_idx, final_value) in message_row.iter().copied().enumerate() {
            let element_tidx = final_tidx + flat_message_idx * D_EF;
            let mut coeff = RecursionField::ONE;
            let start_term_idx = term_idx;
            let factor_count = num_vars_evaluated + basecode_log;
            for factor_idx in 0..factor_count {
                let is_prefix = factor_idx < num_vars_evaluated;
                let point_value = point[factor_idx];
                let (has_challenge, challenge_round, challenge, bit_value, factor) = if is_prefix {
                    let challenge_round = fold_challenges.len() - num_vars_evaluated + factor_idx;
                    let challenge = fold_challenges[challenge_round];
                    if let Some(record) = preflight.pcs.sumcheck_rounds.iter_mut().find(|record| {
                        record.idx == sumcheck_idx && record.round == challenge_round
                    }) {
                        record.fold_challenge_lookup_count += 1;
                    }
                    let xi_yi = point_value * challenge;
                    (
                        true,
                        challenge_round,
                        challenge,
                        false,
                        xi_yi + xi_yi - point_value - challenge + RecursionField::ONE,
                    )
                } else {
                    let bit_idx = factor_idx - num_vars_evaluated;
                    let bit_value = ((elem_idx >> bit_idx) & 1) == 1;
                    (
                        false,
                        0,
                        RecursionField::ZERO,
                        bit_value,
                        if bit_value {
                            point_value
                        } else {
                            RecursionField::ONE - point_value
                        },
                    )
                };
                let coeff_in = coeff;
                coeff *= factor;
                let is_elem_last = factor_idx + 1 == factor_count;
                let acc_in = acc;
                if is_elem_last {
                    acc += coeff * final_value;
                }
                preflight
                    .pcs
                    .basefold_final_expected
                    .push(PcsBasefoldFinalExpectedRecord {
                        proof_idx: 0,
                        sumcheck_idx,
                        term_idx,
                        point_idx,
                        coord_idx: factor_idx,
                        final_tidx: element_tidx,
                        is_first: term_idx == 0,
                        is_last: false,
                        is_elem_first: term_idx == start_term_idx,
                        is_elem_last,
                        has_challenge,
                        challenge_round,
                        point_value,
                        bit_value,
                        challenge,
                        final_value,
                        coeff_in,
                        coeff_out: coeff,
                        acc_in,
                        acc_out: acc,
                    });
                term_idx += 1;
            }
            flat_message_idx += 1;
        }
    }
    if let Some(last) = preflight.pcs.basefold_final_expected.last_mut() {
        last.is_last = true;
    }
    Ok(acc)
}

impl PcsModule {
    pub fn new(bus_inventory: crate::system::BusInventory) -> Self {
        Self {
            transcript_bus: bus_inventory.transcript_bus,
            main_global_point_bus: bus_inventory.main_global_point_bus,
            main_eval_bus: bus_inventory.main_eval_bus,
            basefold_query_bus: bus_inventory.pcs_basefold_query_bus,
            basefold_eval_bus: bus_inventory.pcs_basefold_eval_bus,
            basefold_final_expected_bus: bus_inventory.pcs_basefold_final_expected_bus,
            basefold_final_point_bus: bus_inventory.pcs_basefold_final_point_bus,
            transcript_ext_bus: bus_inventory.pcs_transcript_ext_bus,
            base_input_opening_bus: bus_inventory.pcs_base_input_opening_bus,
            final_message_bus: bus_inventory.pcs_final_message_bus,
            query_sample_bus: bus_inventory.pcs_query_sample_bus,
            commitment_root_bus: bus_inventory.pcs_commitment_root_bus,
            commit_phase_leaf_bus: bus_inventory.pcs_commit_phase_leaf_bus,
            sumcheck_input_bus: bus_inventory.pcs_sumcheck_input_bus,
            sumcheck_output_bus: bus_inventory.pcs_sumcheck_output_bus,
            fold_challenge_bus: bus_inventory.pcs_fold_challenge_bus,
            batch_coeff_bus: bus_inventory.pcs_batch_coeff_bus,
            batch_alpha_bus: bus_inventory.pcs_batch_alpha_bus,
            jagged_f_eval_bus: bus_inventory.pcs_jagged_f_eval_bus,
            opening_eval_bus: bus_inventory.pcs_opening_eval_bus,
            eq_product_bus: bus_inventory.pcs_eq_product_bus,
            suffix_product_bus: bus_inventory.pcs_suffix_product_bus,
            jagged_assist_h_bus: bus_inventory.pcs_jagged_assist_h_bus,
            jagged_assist_q_bus: bus_inventory.pcs_jagged_assist_q_bus,
            commit_height_bus: bus_inventory.pcs_commit_height_bus,
            merkle_verify_bus: bus_inventory.merkle_verify_bus,
            poseidon2_permute_bus: bus_inventory.poseidon2_permute_bus,
            poseidon2_compress_bus: bus_inventory.poseidon2_compress_bus,
            range_checker_bus: bus_inventory.range_checker_bus,
        }
    }

    pub fn run_preflight<TS>(
        &self,
        child_vk: &RecursionVk,
        proof: &RecursionProof,
        preflight: &mut Preflight,
        ts: &mut TS,
    ) where
        TS: FiatShamirTranscript<BabyBearPoseidon2Config>
            + TranscriptHistory<F = F, State = [F; POSEIDON2_WIDTH]>,
    {
        self.replay_preflight(child_vk, proof, preflight, ts)
            .unwrap_or_else(|err| panic!("recursion-v2 PCS preflight replay failed: {err:?}"));
    }

    fn replay_preflight<TS>(
        &self,
        child_vk: &RecursionVk,
        proof: &RecursionProof,
        preflight: &mut Preflight,
        ts: &mut TS,
    ) -> Result<()>
    where
        TS: FiatShamirTranscript<BabyBearPoseidon2Config>
            + TranscriptHistory<F = F, State = [F; POSEIDON2_WIDTH]>,
    {
        let mut rounds = Vec::new();
        let witin_openings = preflight
            .pcs
            .opening_claims
            .iter()
            .filter(|claim| !claim.wits_in_evals.is_empty())
            .map(|claim| {
                (
                    claim.input_opening_point.len(),
                    (
                        claim.input_opening_point.clone(),
                        claim.wits_in_evals.clone(),
                    ),
                )
            })
            .collect_vec();
        rounds.push((2usize, proof.witin_commit.clone(), witin_openings));

        let fixed_openings = preflight
            .pcs
            .opening_claims
            .iter()
            .filter(|claim| !claim.fixed_in_evals.is_empty())
            .map(|claim| {
                (
                    claim.input_opening_point.len(),
                    (
                        claim.input_opening_point.clone(),
                        claim.fixed_in_evals.clone(),
                    ),
                )
            })
            .collect_vec();
        if proof.public_values.shard_id == 0 {
            if let Some(fixed_commit) = child_vk.fixed_commit.as_ref() {
                rounds.push((0usize, fixed_commit.clone(), fixed_openings));
            }
        } else if let Some(fixed_commit) = child_vk.fixed_no_omc_init_commit.as_ref() {
            rounds.push((1usize, fixed_commit.clone(), fixed_openings));
        }

        if rounds.len() != proof.opening_proof.rounds.len() {
            bail!(
                "jagged proof round count mismatch: {} != {}",
                rounds.len(),
                proof.opening_proof.rounds.len()
            );
        }

        let mut inner_rounds = Vec::with_capacity(rounds.len());
        for (round_idx, ((commitment_kind, comm, openings), round_proof)) in rounds
            .into_iter()
            .zip(proof.opening_proof.rounds.iter())
            .enumerate()
        {
            let commit_kind = if round_idx == 0 {
                PcsOpeningCommitKind::Witin
            } else {
                PcsOpeningCommitKind::Fixed
            };
            let term_sources = preflight
                .pcs
                .opening_evals
                .iter()
                .enumerate()
                .filter(|(_, record)| record.commit_kind == commit_kind)
                .map(|(record_idx, record)| {
                    (
                        record_idx,
                        record.opening_idx,
                        record.commit_kind,
                        record.eval_idx,
                        record.main_idx,
                        record.main_eval_idx,
                    )
                })
                .collect_vec();
            let poly_heights = comm
                .cumulative_heights
                .windows(2)
                .map(|window| window[1] - window[0])
                .collect_vec();
            let openings = openings
                .into_iter()
                .map(|(_, (point, evals))| (point, evals))
                .collect_vec();
            let (point, evals) = flatten_padded_openings_as_native(&poly_heights, openings)?;
            let inner = self.replay_jagged_round(
                round_idx,
                commitment_kind,
                &comm,
                &point,
                &evals,
                &term_sources,
                round_proof,
                preflight,
                ts,
            )?;
            preflight
                .pcs
                .commitment_roots
                .push(PcsCommitmentRootRecord {
                    proof_idx: 0,
                    commit_major: 0,
                    commit_minor: round_idx,
                    root: digest_to_array(&inner.0.commit())?,
                    lookup_count: 0,
                });
            inner_rounds.push(inner);
        }
        self.replay_basefold(
            &inner_rounds,
            &proof.opening_proof.inner_proof,
            preflight,
            ts,
        )?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn replay_jagged_round<TS>(
        &self,
        round_idx: usize,
        commitment_kind: usize,
        comm: &<RecursionPcs as mpcs::PolynomialCommitmentScheme<RecursionField>>::Commitment,
        point: &[RecursionField],
        evals: &[RecursionField],
        term_sources: &[JaggedTermSource],
        proof: &mpcs::jagged::JaggedBatchOpenProof<
            RecursionField,
            mpcs::Basefold<RecursionField, BasefoldRSParams>,
        >,
        preflight: &mut Preflight,
        ts: &mut TS,
    ) -> Result<(
        mpcs::basefold::BasefoldCommitment<RecursionField>,
        Vec<BasefoldOpening>,
    )>
    where
        TS: FiatShamirTranscript<BabyBearPoseidon2Config>
            + TranscriptHistory<F = F, State = [F; POSEIDON2_WIDTH]>,
    {
        let num_polys = comm.cumulative_heights.len() - 1;
        if evals.len() != num_polys {
            bail!("jagged eval count mismatch: {} != {num_polys}", evals.len());
        }
        if term_sources.len() != num_polys {
            bail!(
                "jagged eval source count mismatch: {} != {num_polys}",
                term_sources.len()
            );
        }
        let total_evals = *comm.cumulative_heights.last().unwrap_or(&0);
        let log_h = comm.reshape_log_height;
        let h = 1usize << log_h;
        let w = total_evals.div_ceil(h);
        let padded_total = w * h;
        let num_giga_vars = ceil_log2(padded_total);

        let eval_tidx = ts.len();
        for (i, eval) in evals.iter().copied().enumerate() {
            ts.observe_ext(eval);
            preflight
                .pcs
                .transcript_values
                .push(PcsTranscriptValueRecord {
                    proof_idx: 0,
                    idx: round_idx * 1_000_000 + i,
                    tidx: eval_tidx + i * D_EF,
                    value: eval,
                    is_sample: false,
                    is_ext: true,
                    is_final_message: false,
                    is_query_sample: false,
                    is_batch_alpha: false,
                    is_basefold_eval: false,
                    transcript_ext_lookup_count: 0,
                    is_jagged_f_at_rho: false,
                });
        }
        let num_col_vars = ceil_log2(num_polys).max(1);
        observe_label_with_records(ts, b"z_col", preflight, round_idx * 1_000_000 + 4_000);
        let z_col_tidx = ts.len();
        let z_col = sample_vec_with_records(
            ts,
            num_col_vars,
            preflight,
            0,
            round_idx * 1_000_000 + 5_000,
        );
        for bit_idx in 0..num_col_vars {
            let tidx = z_col_tidx + bit_idx * D_EF;
            if let Some(record) = preflight
                .pcs
                .transcript_values
                .iter_mut()
                .find(|record| record.tidx == tidx)
            {
                record.transcript_ext_lookup_count += num_polys;
            }
        }
        let eq_col = build_eq_x_r_vec(&z_col);

        let max_s = point.len();
        let mut tail_zero_prod = vec![RecursionField::ONE; max_s + 1];
        for j in (0..max_s).rev() {
            tail_zero_prod[j] = tail_zero_prod[j + 1] * (RecursionField::ONE - point[j]);
        }
        let claimed_sum = (0..num_polys)
            .map(|i| {
                let h_i = comm.cumulative_heights[i + 1] - comm.cumulative_heights[i];
                let s_i = ceil_log2(h_i);
                eq_col[i] * tail_zero_prod[s_i] * evals[i]
            })
            .sum();
        let mut acc = RecursionField::ZERO;
        for i in 0..num_polys {
            let h_i = comm.cumulative_heights[i + 1] - comm.cumulative_heights[i];
            let s_i = ceil_log2(h_i);
            let eq_product = push_eq_product_records(
                preflight,
                PcsEqProductKind::JaggedClaim,
                PcsEqProductSource::Transcript,
                round_idx,
                i,
                &z_col,
                z_col_tidx,
                round_idx * 2,
                0,
            );
            let tail_product = push_suffix_product_records(preflight, round_idx, i, s_i, point);
            if eq_product != eq_col[i] {
                bail!("jagged eq product replay mismatch");
            }
            if tail_product != tail_zero_prod[s_i] {
                bail!("jagged suffix product replay mismatch");
            }
            let term = eq_col[i] * tail_zero_prod[s_i] * evals[i];
            let acc_in = acc;
            acc += term;
            let (
                opening_eval_record_idx,
                opening_idx,
                commit_kind,
                eval_idx,
                main_idx,
                main_eval_idx,
            ) = term_sources[i];
            let raw_eval = tail_zero_prod[s_i] * evals[i];
            preflight.pcs.opening_evals[opening_eval_record_idx].raw_value = raw_eval;
            preflight.pcs.jagged_claims.push(PcsJaggedClaimRecord {
                proof_idx: 0,
                round_idx,
                sumcheck_idx: round_idx * 2,
                term_idx: i,
                is_first: i == 0,
                is_last: i + 1 == num_polys,
                opening_idx,
                commit_kind,
                eval_idx,
                main_idx,
                main_eval_idx,
                eval: evals[i],
                z_col_tidx,
                eq_col: eq_col[i],
                tail_zero: tail_zero_prod[s_i],
                acc_in,
                acc_out: acc,
            });
        }
        let (rho, expected) = replay_degree2_sumcheck(
            0,
            round_idx * 2,
            claimed_sum,
            &proof.sumcheck_proof,
            num_giga_vars,
            false,
            preflight,
            ts,
        )?;

        let n_robp = num_giga_vars + usize::from(padded_total.is_power_of_two());
        let rho_row = &rho[..log_h];
        let rho_col = &rho[log_h..];
        let eq_rho_col = build_eq_x_r_vec(rho_col);
        let q_eval = eq_rho_col[..w]
            .iter()
            .zip(&proof.col_evals)
            .map(|(e, v)| *e * *v)
            .sum::<RecursionField>();
        let col_tidx = ts.len();
        for (i, eval) in proof.col_evals.iter().copied().enumerate() {
            ts.observe_ext(eval);
            preflight
                .pcs
                .transcript_values
                .push(PcsTranscriptValueRecord {
                    proof_idx: 0,
                    idx: round_idx * 1_000_000 + 10_000 + i,
                    tidx: col_tidx + i * D_EF,
                    value: eval,
                    is_sample: false,
                    is_ext: true,
                    is_final_message: false,
                    is_query_sample: false,
                    is_batch_alpha: false,
                    is_basefold_eval: true,
                    transcript_ext_lookup_count: 0,
                    is_jagged_f_at_rho: false,
                });
        }
        for bit_idx in 0..rho_col.len() {
            if let Some(record) = preflight
                .pcs
                .sumcheck_rounds
                .iter_mut()
                .find(|record| record.idx == round_idx * 2 && record.round == log_h + bit_idx)
            {
                record.fold_challenge_lookup_count += w;
            }
        }
        let f_tidx = ts.len();
        ts.observe_ext(proof.f_at_rho);
        let assist_sumcheck_idx = round_idx * 2 + 1;
        preflight
            .pcs
            .transcript_values
            .push(PcsTranscriptValueRecord {
                proof_idx: 0,
                idx: assist_sumcheck_idx,
                tidx: f_tidx,
                value: proof.f_at_rho,
                is_sample: false,
                is_ext: true,
                is_final_message: false,
                is_query_sample: false,
                is_batch_alpha: false,
                is_basefold_eval: false,
                transcript_ext_lookup_count: 0,
                is_jagged_f_at_rho: true,
            });
        preflight
            .pcs
            .jagged_assist_inputs
            .push(PcsJaggedAssistInputRecord {
                proof_idx: 0,
                round_idx,
                sumcheck_idx: assist_sumcheck_idx,
                f_tidx,
                f_at_rho: proof.f_at_rho,
            });
        let mut q_acc = RecursionField::ZERO;
        for (i, (&eq_rho_col, &col_eval)) in
            eq_rho_col[..w].iter().zip(&proof.col_evals).enumerate()
        {
            let eq_product = push_eq_product_records(
                preflight,
                PcsEqProductKind::JaggedQEval,
                PcsEqProductSource::FoldChallenge,
                round_idx,
                i,
                rho_col,
                0,
                round_idx * 2,
                log_h,
            );
            if eq_product != eq_rho_col {
                bail!("jagged q-eval eq product replay mismatch");
            }
            let acc_in = q_acc;
            q_acc += eq_rho_col * col_eval;
            preflight.pcs.jagged_q_evals.push(PcsJaggedQEvalRecord {
                proof_idx: 0,
                round_idx,
                sumcheck_idx: round_idx * 2,
                term_idx: i,
                is_first: i == 0,
                is_last: i + 1 == w,
                col_tidx: col_tidx + i * D_EF,
                col_eval,
                eq_rho_col,
                acc_in,
                acc_out: q_acc,
                q_eval,
                f_at_rho: proof.f_at_rho,
                sumcheck_final: expected,
            });
        }

        let mut z_row_padded = point.to_vec();
        z_row_padded.resize(n_robp, RecursionField::ZERO);
        let mut rho_padded = rho.clone();
        rho_padded.resize(n_robp, RecursionField::ZERO);
        let (assist_point, assist_expected) = replay_degree2_sumcheck(
            0,
            assist_sumcheck_idx,
            proof.f_at_rho,
            &proof.assist_proof,
            2 * n_robp,
            false,
            preflight,
            ts,
        )?;
        let rho_star_c = (0..n_robp).map(|i| assist_point[2 * i]).collect_vec();
        let rho_star_d = (0..n_robp).map(|i| assist_point[2 * i + 1]).collect_vec();
        for robp_idx in 0..n_robp {
            if robp_idx < rho.len()
                && let Some(record) = preflight
                    .pcs
                    .sumcheck_rounds
                    .iter_mut()
                    .find(|record| record.idx == round_idx * 2 && record.round == robp_idx)
            {
                record.fold_challenge_lookup_count += 1;
            }
            for assist_round in [2 * robp_idx, 2 * robp_idx + 1] {
                if let Some(record) = preflight.pcs.sumcheck_rounds.iter_mut().find(|record| {
                    record.idx == assist_sumcheck_idx && record.round == assist_round
                }) {
                    record.fold_challenge_lookup_count += 1 + num_polys;
                }
            }
        }
        let h_at_rho_star =
            push_jagged_assist_h_records(preflight, round_idx, point, &rho, &assist_point, n_robp);
        let native_h_at_rho_star = evaluate_g(&z_row_padded, &rho_padded, &rho_star_c, &rho_star_d);
        if h_at_rho_star != native_h_at_rho_star {
            bail!("jagged assist h replay mismatch");
        }
        let q_at_rho_star = push_jagged_assist_q_records(
            preflight,
            round_idx,
            commitment_kind,
            &assist_point,
            &eq_col,
            &comm.cumulative_heights,
            n_robp,
        );
        let native_q_at_rho_star =
            compute_q_at_assist_point(&assist_point, &eq_col, &comm.cumulative_heights, n_robp);
        if q_at_rho_star != native_q_at_rho_star {
            bail!("jagged assist q replay mismatch");
        }
        preflight.pcs.jagged_assists.push(PcsJaggedAssistRecord {
            proof_idx: 0,
            round_idx,
            sumcheck_idx: round_idx * 2 + 1,
            h_at_rho_star,
            q_at_rho_star,
            sumcheck_final: assist_expected,
        });

        Ok((
            comm.inner.clone(),
            inner_verify_openings_for_col_evals(log_h, rho_row, &proof.col_evals, col_tidx),
        ))
    }

    fn replay_basefold<TS>(
        &self,
        rounds: &[BasefoldRound],
        proof: &mpcs::basefold::structure::BasefoldProof<RecursionField>,
        preflight: &mut Preflight,
        ts: &mut TS,
    ) -> Result<()>
    where
        TS: FiatShamirTranscript<BabyBearPoseidon2Config>
            + TranscriptHistory<F = F, State = [F; POSEIDON2_WIDTH]>,
    {
        if proof.sumcheck_proof.is_none() {
            bail!("basefold sumcheck proof is missing");
        }
        let total_num_polys = rounds
            .iter()
            .flat_map(|(_, openings)| openings)
            .map(|(_, (_, evals))| evals.len())
            .sum::<usize>();
        observe_label_with_records(ts, b"batch coeffs", preflight, 2_400_000);
        let batch_coeffs = sample_challenge_pows(ts, total_num_polys, preflight);
        let max_num_var = rounds
            .iter()
            .flat_map(|(_, openings)| openings.iter().map(|(num_vars, _)| *num_vars))
            .max()
            .unwrap_or(0);
        let basecode_log = <BasefoldRSParams as mpcs::basefold::BasefoldSpec<RecursionField>>::get_basecode_msg_size_log();
        ensure_supported_basecode_log(basecode_log)?;
        if max_num_var < basecode_log {
            return Ok(());
        }
        let num_rounds = max_num_var - basecode_log;
        let sumcheck_messages = proof.sumcheck_proof.as_ref().unwrap();
        if sumcheck_messages.len() != num_rounds || proof.commits.len() != num_rounds {
            bail!("basefold round count mismatch");
        }
        let mut batch_coeffs_iter = batch_coeffs.iter().copied().enumerate();
        let mut expected_sum = RecursionField::ZERO;
        let mut term_idx = 0usize;
        for (_, openings) in rounds {
            for (num_var, (_, evals)) in openings
                .iter()
                .filter(|(num_var, _)| *num_var >= basecode_log)
            {
                let scale = RecursionField::from(F::from_usize(1 << (max_num_var - num_var)));
                for (eval, eval_tidx) in evals {
                    let (global_coeff_idx, coeff) = batch_coeffs_iter
                        .next()
                        .ok_or_else(|| eyre::eyre!("basefold missing batch coefficient"))?;
                    if let Some(record) = preflight.pcs.batch_coeffs.get_mut(global_coeff_idx) {
                        record.lookup_count += 1;
                    }
                    let acc_in = expected_sum;
                    expected_sum += coeff * *eval * scale;
                    preflight
                        .pcs
                        .basefold_initial_claims
                        .push(PcsBasefoldInitialClaimRecord {
                            proof_idx: 0,
                            sumcheck_idx: 8_000_000,
                            term_idx,
                            is_first: term_idx == 0,
                            is_last: false,
                            global_coeff_idx,
                            eval_tidx: *eval_tidx,
                            eval: *eval,
                            coeff,
                            scale,
                            acc_in,
                            acc_out: expected_sum,
                        });
                    term_idx += 1;
                }
            }
        }
        if let Some(last) = preflight.pcs.basefold_initial_claims.last_mut() {
            last.is_last = true;
        }

        let mut fold_challenges = Vec::with_capacity(num_rounds);
        let mut current_claim = expected_sum;
        for (round, msg) in sumcheck_messages.iter().enumerate() {
            if msg.evaluations.len() != 2 {
                bail!(
                    "basefold degree-2 sumcheck round {round} has {} evals",
                    msg.evaluations.len()
                );
            }
            let ev_tidx = ts.len();
            ts.observe_ext(msg.evaluations[0]);
            ts.observe_ext(msg.evaluations[1]);
            observe_label_with_records(ts, b"commit round", preflight, 3_400_000 + round * 100);
            let challenge_tidx = ts.len();
            let challenge = FiatShamirTranscript::<BabyBearPoseidon2Config>::sample_ext(ts);
            fold_challenges.push(challenge);
            let eval_1 = msg.evaluations[0];
            let eval_0 = current_claim - eval_1;
            let claim_out = extrapolate_uni_poly(eval_0, &msg.evaluations, challenge);
            preflight.pcs.sumcheck_rounds.push(PcsSumcheckRoundRecord {
                proof_idx: 0,
                idx: 8_000_000,
                round,
                is_first: round == 0,
                is_last: round + 1 == num_rounds,
                ev_tidx,
                challenge_tidx,
                ev1: msg.evaluations[0],
                ev2: msg.evaluations[1],
                claim_in: current_claim,
                claim_out,
                challenge,
                fold_challenge_lookup_count:
                    <BasefoldRSParams as BasefoldSpec<RecursionField>>::get_number_queries(),
            });
            current_claim = claim_out;
            observe_digest(
                ts,
                &proof.commits[round],
                preflight,
                3_700_000 + round * 100,
            );
        }
        let final_tidx = ts.len();
        for value in proof.final_message.iter().flatten().copied() {
            ts.observe_ext(value);
        }
        for (i, value) in proof.final_message.iter().flatten().copied().enumerate() {
            preflight
                .pcs
                .transcript_values
                .push(PcsTranscriptValueRecord {
                    proof_idx: 0,
                    idx: 4_000_000 + i,
                    tidx: final_tidx + i * D_EF,
                    value,
                    is_sample: false,
                    is_ext: true,
                    is_final_message: true,
                    is_query_sample: false,
                    is_batch_alpha: false,
                    is_basefold_eval: false,
                    transcript_ext_lookup_count: 0,
                    is_jagged_f_at_rho: false,
                });
        }
        let pow_bits = child_pow_bits();
        if pow_bits > 0 && !check_witness_with_records(ts, pow_bits, proof.pow_witness, preflight) {
            bail!("basefold pow witness check failed");
        }
        observe_label_with_records(ts, b"query indices", preflight, 6_900_000);
        let query_bits = max_num_var
            + <BasefoldRSParams as mpcs::basefold::BasefoldSpec<RecursionField>>::get_rate_log();
        let mut queries = Vec::new();
        for query_idx in 0
            ..<BasefoldRSParams as mpcs::basefold::BasefoldSpec<RecursionField>>::get_number_queries(
            )
        {
            let sample =
                sample_bits_with_record(ts, query_bits, preflight, 7_000_000 + query_idx, true);
            preflight
                .pcs
                .basefold_query_indices
                .push(PcsBasefoldQueryIndexRecord {
                    proof_idx: 0,
                    query_idx,
                    sample_tidx: sample.tidx,
                    query_bits,
                    sampled_value: RecursionField::from(sample.sampled_value),
                    query_value: sample.query_value,
                    high_value: sample.high_value,
                    query_bytes: u32_bytes(sample.query_value),
                    high_bytes: u32_bytes(sample.high_value),
                    query_bit_selectors: one_hot_32(query_bits),
                });
            queries.push(sample.query_value);
        }
        record_basefold_query_checks(
            rounds,
            proof,
            preflight,
            &batch_coeffs,
            &fold_challenges,
            &queries,
            max_num_var,
            final_tidx,
        )?;
        let final_expected = push_basefold_final_expected_records(
            preflight,
            rounds,
            &proof.final_message,
            &fold_challenges,
            basecode_log,
            final_tidx,
        )?;
        preflight
            .pcs
            .basefold_final_claims
            .push(PcsBasefoldFinalClaimRecord {
                proof_idx: 0,
                sumcheck_idx: 8_000_000,
                final_claim: current_claim,
                expected: final_expected,
            });
        Ok(())
    }
}

impl AirModule for PcsModule {
    fn num_airs(&self) -> usize {
        26
    }

    fn airs<SC: StarkProtocolConfig<F = F>>(&self) -> Vec<AirRef<SC>> {
        vec![
            Arc::new(PcsCommitmentRootAir {
                commitment_root_bus: self.commitment_root_bus,
            }) as AirRef<_>,
            Arc::new(PcsBaseInputLeafHashAir {
                poseidon2_permute_bus: self.poseidon2_permute_bus,
                base_input_opening_bus: self.base_input_opening_bus,
                merkle_verify_bus: self.merkle_verify_bus,
            }) as AirRef<_>,
            Arc::new(PcsBaseInputMerkleAir {
                poseidon2_compress_bus: self.poseidon2_compress_bus,
                merkle_verify_bus: self.merkle_verify_bus,
                commitment_root_bus: self.commitment_root_bus,
            }) as AirRef<_>,
            Arc::new(PcsCommitPhaseLeafHashAir {
                poseidon2_permute_bus: self.poseidon2_permute_bus,
                commit_phase_leaf_bus: self.commit_phase_leaf_bus,
                merkle_verify_bus: self.merkle_verify_bus,
            }) as AirRef<_>,
            Arc::new(PcsCommitPhaseMerkleAir {
                poseidon2_compress_bus: self.poseidon2_compress_bus,
                merkle_verify_bus: self.merkle_verify_bus,
                commitment_root_bus: self.commitment_root_bus,
            }) as AirRef<_>,
            Arc::new(PcsOpeningPointAir {
                main_global_point_bus: self.main_global_point_bus,
            }) as AirRef<_>,
            Arc::new(PcsBasefoldFinalPointAir {
                fold_challenge_bus: self.fold_challenge_bus,
                final_point_bus: self.basefold_final_point_bus,
            }) as AirRef<_>,
            Arc::new(PcsOpeningEvalAir {
                main_eval_bus: self.main_eval_bus,
                opening_eval_bus: self.opening_eval_bus,
            }) as AirRef<_>,
            Arc::new(PcsEqProductAir {
                transcript_ext_bus: self.transcript_ext_bus,
                fold_challenge_bus: self.fold_challenge_bus,
                eq_product_bus: self.eq_product_bus,
            }) as AirRef<_>,
            Arc::new(PcsSuffixProductAir {
                main_global_point_bus: self.main_global_point_bus,
                suffix_product_bus: self.suffix_product_bus,
            }) as AirRef<_>,
            Arc::new(PcsJaggedAssistHAir {
                main_global_point_bus: self.main_global_point_bus,
                fold_challenge_bus: self.fold_challenge_bus,
                jagged_assist_h_bus: self.jagged_assist_h_bus,
            }) as AirRef<_>,
            Arc::new(PcsJaggedAssistQAir {
                fold_challenge_bus: self.fold_challenge_bus,
                eq_product_bus: self.eq_product_bus,
                commit_height_bus: self.commit_height_bus,
                jagged_assist_q_bus: self.jagged_assist_q_bus,
            }) as AirRef<_>,
            Arc::new(PcsBasefoldQueryIndexAir {
                query_sample_bus: self.query_sample_bus,
                basefold_query_bus: self.basefold_query_bus,
                range_checker_bus: self.range_checker_bus,
            }) as AirRef<_>,
            Arc::new(PcsBasefoldQueryOpenAir {
                basefold_query_bus: self.basefold_query_bus,
                base_input_opening_bus: self.base_input_opening_bus,
                batch_coeff_bus: self.batch_coeff_bus,
            }) as AirRef<_>,
            Arc::new(PcsBasefoldCommitPhaseQueryAir {
                basefold_query_bus: self.basefold_query_bus,
                commit_phase_leaf_bus: self.commit_phase_leaf_bus,
                fold_challenge_bus: self.fold_challenge_bus,
            }) as AirRef<_>,
            Arc::new(PcsBasefoldFinalCodewordAir {
                basefold_query_bus: self.basefold_query_bus,
                final_message_bus: self.final_message_bus,
            }) as AirRef<_>,
            Arc::new(PcsTranscriptValueAir {
                transcript_bus: self.transcript_bus,
                final_message_bus: self.final_message_bus,
                query_sample_bus: self.query_sample_bus,
                batch_alpha_bus: self.batch_alpha_bus,
                basefold_eval_bus: self.basefold_eval_bus,
                transcript_ext_bus: self.transcript_ext_bus,
                jagged_f_eval_bus: self.jagged_f_eval_bus,
                final_message_lookup_count:
                    <BasefoldRSParams as BasefoldSpec<RecursionField>>::get_number_queries() + 1,
            }) as AirRef<_>,
            Arc::new(PcsBasefoldInitialClaimAir {
                basefold_eval_bus: self.basefold_eval_bus,
                batch_coeff_bus: self.batch_coeff_bus,
                sumcheck_input_bus: self.sumcheck_input_bus,
            }) as AirRef<_>,
            Arc::new(PcsJaggedAssistInputAir {
                jagged_f_eval_bus: self.jagged_f_eval_bus,
                sumcheck_input_bus: self.sumcheck_input_bus,
            }) as AirRef<_>,
            Arc::new(PcsJaggedClaimAir {
                sumcheck_input_bus: self.sumcheck_input_bus,
                opening_eval_bus: self.opening_eval_bus,
                eq_product_bus: self.eq_product_bus,
                suffix_product_bus: self.suffix_product_bus,
            }) as AirRef<_>,
            Arc::new(PcsSumcheckInputAir {
                sumcheck_input_bus: self.sumcheck_input_bus,
            }) as AirRef<_>,
            Arc::new(PcsSumcheckAir {
                sumcheck_input_bus: self.sumcheck_input_bus,
                transcript_bus: self.transcript_bus,
                sumcheck_output_bus: self.sumcheck_output_bus,
                fold_challenge_bus: self.fold_challenge_bus,
            }) as AirRef<_>,
            Arc::new(PcsBatchCoeffAir {
                batch_alpha_bus: self.batch_alpha_bus,
                batch_coeff_bus: self.batch_coeff_bus,
            }) as AirRef<_>,
            Arc::new(PcsJaggedQEvalAir {
                basefold_eval_bus: self.basefold_eval_bus,
                eq_product_bus: self.eq_product_bus,
                sumcheck_output_bus: self.sumcheck_output_bus,
            }) as AirRef<_>,
            Arc::new(PcsJaggedAssistAir {
                sumcheck_output_bus: self.sumcheck_output_bus,
                jagged_assist_h_bus: self.jagged_assist_h_bus,
                jagged_assist_q_bus: self.jagged_assist_q_bus,
            }) as AirRef<_>,
            Arc::new(PcsBasefoldFinalExpectedAir {
                fold_challenge_bus: self.fold_challenge_bus,
                final_message_bus: self.final_message_bus,
                final_point_bus: self.basefold_final_point_bus,
                final_expected_bus: self.basefold_final_expected_bus,
            }) as AirRef<_>,
            Arc::new(PcsBasefoldFinalClaimAir {
                sumcheck_output_bus: self.sumcheck_output_bus,
                final_expected_bus: self.basefold_final_expected_bus,
            }) as AirRef<_>,
        ]
    }
}

impl<SC: StarkProtocolConfig<F = F>> TraceGenModule<GlobalCtxCpu, CpuBackend<SC>> for PcsModule {
    type ModuleSpecificCtx<'a> = ();

    fn generate_proving_ctxs(
        &self,
        _child_vk: &RecursionVk,
        _proofs: &[RecursionProof],
        preflights: &[Preflight],
        _ctx: &Self::ModuleSpecificCtx<'_>,
        required_heights: Option<&[usize]>,
    ) -> Option<Vec<AirProvingContext<CpuBackend<SC>>>> {
        let mut transcript_values = preflights
            .iter()
            .enumerate()
            .flat_map(|(proof_idx, p)| {
                p.pcs
                    .transcript_values
                    .iter()
                    .cloned()
                    .map(move |mut record| {
                        record.proof_idx = proof_idx;
                        record
                    })
            })
            .collect_vec();
        transcript_values.sort_by_key(|record| (record.proof_idx, record.tidx));
        let mut sumcheck_rounds = preflights
            .iter()
            .enumerate()
            .flat_map(|(proof_idx, p)| {
                p.pcs
                    .sumcheck_rounds
                    .iter()
                    .cloned()
                    .map(move |mut record| {
                        record.proof_idx = proof_idx;
                        record
                    })
            })
            .collect_vec();
        sumcheck_rounds.sort_by_key(|record| (record.proof_idx, record.idx, record.round));
        let mut sumcheck_inputs = preflights
            .iter()
            .enumerate()
            .flat_map(|(proof_idx, p)| {
                p.pcs
                    .sumcheck_inputs
                    .iter()
                    .cloned()
                    .map(move |mut record| {
                        record.proof_idx = proof_idx;
                        record
                    })
            })
            .collect_vec();
        sumcheck_inputs.sort_by_key(|record| (record.proof_idx, record.idx));
        let mut eq_products = preflights
            .iter()
            .enumerate()
            .flat_map(|(proof_idx, p)| {
                p.pcs.eq_products.iter().cloned().map(move |mut record| {
                    record.proof_idx = proof_idx;
                    record
                })
            })
            .collect_vec();
        eq_products.sort_by_key(|record| {
            (
                record.proof_idx,
                record.kind.as_usize(),
                record.source.as_usize(),
                record.round_idx,
                record.term_idx,
                record.bit_idx,
            )
        });
        let mut suffix_products = preflights
            .iter()
            .enumerate()
            .flat_map(|(proof_idx, p)| {
                p.pcs
                    .suffix_products
                    .iter()
                    .cloned()
                    .map(move |mut record| {
                        record.proof_idx = proof_idx;
                        record
                    })
            })
            .collect_vec();
        suffix_products.sort_by_key(|record| {
            (
                record.proof_idx,
                record.round_idx,
                record.term_idx,
                record.step_idx,
            )
        });
        let mut jagged_assist_h = preflights
            .iter()
            .enumerate()
            .flat_map(|(proof_idx, p)| {
                p.pcs
                    .jagged_assist_h
                    .iter()
                    .cloned()
                    .map(move |mut record| {
                        record.proof_idx = proof_idx;
                        record
                    })
            })
            .collect_vec();
        jagged_assist_h.sort_by_key(|record| (record.proof_idx, record.round_idx, record.step_idx));
        let mut jagged_assist_q = preflights
            .iter()
            .enumerate()
            .flat_map(|(proof_idx, p)| {
                p.pcs
                    .jagged_assist_q
                    .iter()
                    .cloned()
                    .map(move |mut record| {
                        record.proof_idx = proof_idx;
                        record
                    })
            })
            .collect_vec();
        jagged_assist_q.sort_by_key(|record| {
            (
                record.proof_idx,
                record.round_idx,
                record.term_idx,
                record.step_idx,
            )
        });
        let mut basefold_initial_claims = preflights
            .iter()
            .enumerate()
            .flat_map(|(proof_idx, p)| {
                p.pcs
                    .basefold_initial_claims
                    .iter()
                    .cloned()
                    .map(move |mut record| {
                        record.proof_idx = proof_idx;
                        record
                    })
            })
            .collect_vec();
        basefold_initial_claims
            .sort_by_key(|record| (record.proof_idx, record.sumcheck_idx, record.term_idx));
        let mut jagged_assist_inputs = preflights
            .iter()
            .enumerate()
            .flat_map(|(proof_idx, p)| {
                p.pcs
                    .jagged_assist_inputs
                    .iter()
                    .cloned()
                    .map(move |mut record| {
                        record.proof_idx = proof_idx;
                        record
                    })
            })
            .collect_vec();
        jagged_assist_inputs.sort_by_key(|record| (record.proof_idx, record.sumcheck_idx));
        let mut jagged_claims = preflights
            .iter()
            .enumerate()
            .flat_map(|(proof_idx, p)| {
                p.pcs.jagged_claims.iter().cloned().map(move |mut record| {
                    record.proof_idx = proof_idx;
                    record
                })
            })
            .collect_vec();
        jagged_claims
            .sort_by_key(|record| (record.proof_idx, record.sumcheck_idx, record.term_idx));
        let mut batch_coeffs = preflights
            .iter()
            .enumerate()
            .flat_map(|(proof_idx, p)| {
                p.pcs.batch_coeffs.iter().cloned().map(move |mut record| {
                    record.proof_idx = proof_idx;
                    record
                })
            })
            .collect_vec();
        batch_coeffs.sort_by_key(|record| (record.proof_idx, record.global_coeff_idx));
        let mut jagged_q_evals = preflights
            .iter()
            .enumerate()
            .flat_map(|(proof_idx, p)| {
                p.pcs.jagged_q_evals.iter().cloned().map(move |mut record| {
                    record.proof_idx = proof_idx;
                    record
                })
            })
            .collect_vec();
        jagged_q_evals.sort_by_key(|record| (record.proof_idx, record.round_idx, record.term_idx));
        let mut jagged_assists = preflights
            .iter()
            .enumerate()
            .flat_map(|(proof_idx, p)| {
                p.pcs.jagged_assists.iter().cloned().map(move |mut record| {
                    record.proof_idx = proof_idx;
                    record
                })
            })
            .collect_vec();
        jagged_assists.sort_by_key(|record| (record.proof_idx, record.round_idx));
        let mut basefold_final_expected = preflights
            .iter()
            .enumerate()
            .flat_map(|(proof_idx, p)| {
                p.pcs
                    .basefold_final_expected
                    .iter()
                    .cloned()
                    .map(move |mut record| {
                        record.proof_idx = proof_idx;
                        record
                    })
            })
            .collect_vec();
        basefold_final_expected
            .sort_by_key(|record| (record.proof_idx, record.sumcheck_idx, record.term_idx));
        let mut basefold_final_points = preflights
            .iter()
            .enumerate()
            .flat_map(|(proof_idx, p)| {
                p.pcs
                    .basefold_final_points
                    .iter()
                    .cloned()
                    .map(move |mut record| {
                        record.proof_idx = proof_idx;
                        record
                    })
            })
            .collect_vec();
        basefold_final_points.sort_by_key(|record| {
            (
                record.proof_idx,
                record.sumcheck_idx,
                record.point_idx,
                record.coord_idx,
            )
        });
        let mut basefold_final_claims = preflights
            .iter()
            .enumerate()
            .flat_map(|(proof_idx, p)| {
                p.pcs
                    .basefold_final_claims
                    .iter()
                    .cloned()
                    .map(move |mut record| {
                        record.proof_idx = proof_idx;
                        record
                    })
            })
            .collect_vec();
        basefold_final_claims.sort_by_key(|record| (record.proof_idx, record.sumcheck_idx));
        let mut opening_points = preflights
            .iter()
            .enumerate()
            .flat_map(|(proof_idx, p)| {
                p.pcs.opening_points.iter().cloned().map(move |mut record| {
                    record.proof_idx = proof_idx;
                    record
                })
            })
            .collect_vec();
        opening_points.sort_by_key(|record| {
            (
                record.proof_idx,
                record.opening_idx,
                record.coord_idx,
                record.global_round_idx,
            )
        });
        let mut opening_evals = preflights
            .iter()
            .enumerate()
            .flat_map(|(proof_idx, p)| {
                p.pcs.opening_evals.iter().cloned().map(move |mut record| {
                    record.proof_idx = proof_idx;
                    record
                })
            })
            .collect_vec();
        opening_evals.sort_by_key(|record| {
            (
                record.proof_idx,
                record.opening_idx,
                record.commit_kind.as_usize(),
                record.eval_idx,
            )
        });
        let mut basefold_query_indices = preflights
            .iter()
            .enumerate()
            .flat_map(|(proof_idx, p)| {
                p.pcs
                    .basefold_query_indices
                    .iter()
                    .cloned()
                    .map(move |mut record| {
                        record.proof_idx = proof_idx;
                        record
                    })
            })
            .collect_vec();
        basefold_query_indices.sort_by_key(|record| (record.proof_idx, record.query_idx));
        let mut basefold_query_opens = preflights
            .iter()
            .enumerate()
            .flat_map(|(proof_idx, p)| {
                p.pcs
                    .basefold_query_opens
                    .iter()
                    .cloned()
                    .map(move |mut record| {
                        record.proof_idx = proof_idx;
                        record
                    })
            })
            .collect_vec();
        basefold_query_opens.sort_by_key(|record| {
            (
                record.proof_idx,
                record.query_idx,
                record.log2_height,
                record.opening_idx,
                record.value_idx,
                record.elem_idx,
            )
        });
        let mut basefold_commit_phase_queries = preflights
            .iter()
            .enumerate()
            .flat_map(|(proof_idx, p)| {
                p.pcs
                    .basefold_commit_phase_queries
                    .iter()
                    .cloned()
                    .map(move |mut record| {
                        record.proof_idx = proof_idx;
                        record
                    })
            })
            .collect_vec();
        basefold_commit_phase_queries
            .sort_by_key(|record| (record.proof_idx, record.query_idx, record.round));
        let mut basefold_final_codeword = preflights
            .iter()
            .enumerate()
            .flat_map(|(proof_idx, p)| {
                p.pcs
                    .basefold_final_codeword
                    .iter()
                    .cloned()
                    .map(move |mut record| {
                        record.proof_idx = proof_idx;
                        record
                    })
            })
            .collect_vec();
        basefold_final_codeword
            .sort_by_key(|record| (record.proof_idx, record.query_idx, record.final_tidx));
        let mut commitment_roots = preflights
            .iter()
            .enumerate()
            .flat_map(|(proof_idx, p)| {
                p.pcs
                    .commitment_roots
                    .iter()
                    .cloned()
                    .map(move |mut record| {
                        record.proof_idx = proof_idx;
                        record
                    })
            })
            .collect_vec();
        commitment_roots
            .sort_by_key(|record| (record.proof_idx, record.commit_major, record.commit_minor));
        let mut base_input_leaf_hashes = preflights
            .iter()
            .enumerate()
            .flat_map(|(proof_idx, p)| {
                p.pcs
                    .base_input_leaf_hashes
                    .iter()
                    .cloned()
                    .map(move |mut record| {
                        record.proof_idx = proof_idx;
                        record
                    })
            })
            .collect_vec();
        base_input_leaf_hashes.sort_by_key(|record| {
            (
                record.proof_idx,
                record.query_idx,
                record.opening_idx,
                record.block_idx,
            )
        });
        let mut base_input_merkle_rows = preflights
            .iter()
            .enumerate()
            .flat_map(|(proof_idx, p)| {
                p.pcs
                    .base_input_merkle_rows
                    .iter()
                    .cloned()
                    .map(move |mut record| {
                        record.proof_idx = proof_idx;
                        record
                    })
            })
            .collect_vec();
        base_input_merkle_rows.sort_by_key(|record| {
            (
                record.proof_idx,
                record.query_idx,
                record.opening_idx,
                record.step,
            )
        });
        let mut commit_phase_leaf_hashes = preflights
            .iter()
            .enumerate()
            .flat_map(|(proof_idx, p)| {
                p.pcs
                    .commit_phase_leaf_hashes
                    .iter()
                    .cloned()
                    .map(move |mut record| {
                        record.proof_idx = proof_idx;
                        record
                    })
            })
            .collect_vec();
        commit_phase_leaf_hashes
            .sort_by_key(|record| (record.proof_idx, record.query_idx, record.round));
        let mut commit_phase_merkle_rows = preflights
            .iter()
            .enumerate()
            .flat_map(|(proof_idx, p)| {
                p.pcs
                    .commit_phase_merkle_rows
                    .iter()
                    .cloned()
                    .map(move |mut record| {
                        record.proof_idx = proof_idx;
                        record
                    })
            })
            .collect_vec();
        commit_phase_merkle_rows.sort_by_key(|record| {
            (
                record.proof_idx,
                record.query_idx,
                record.round,
                record.step,
            )
        });

        let ctx = PcsTraceCtx {
            commitment_roots: &commitment_roots,
            base_input_leaf_hashes: &base_input_leaf_hashes,
            base_input_merkle_rows: &base_input_merkle_rows,
            commit_phase_leaf_hashes: &commit_phase_leaf_hashes,
            commit_phase_merkle_rows: &commit_phase_merkle_rows,
            opening_points: &opening_points,
            basefold_final_points: &basefold_final_points,
            opening_evals: &opening_evals,
            basefold_query_indices: &basefold_query_indices,
            basefold_query_opens: &basefold_query_opens,
            basefold_commit_phase_queries: &basefold_commit_phase_queries,
            basefold_final_codeword: &basefold_final_codeword,
            transcript_values: &transcript_values,
            basefold_initial_claims: &basefold_initial_claims,
            jagged_assist_inputs: &jagged_assist_inputs,
            eq_products: &eq_products,
            suffix_products: &suffix_products,
            jagged_assist_h: &jagged_assist_h,
            jagged_assist_q: &jagged_assist_q,
            jagged_claims: &jagged_claims,
            sumcheck_inputs: &sumcheck_inputs,
            sumcheck_rounds: &sumcheck_rounds,
            batch_coeffs: &batch_coeffs,
            jagged_q_evals: &jagged_q_evals,
            jagged_assists: &jagged_assists,
            basefold_final_expected: &basefold_final_expected,
            basefold_final_claims: &basefold_final_claims,
        };
        [
            PcsModuleChip::CommitmentRoot,
            PcsModuleChip::BaseInputLeafHash,
            PcsModuleChip::BaseInputMerkle,
            PcsModuleChip::CommitPhaseLeafHash,
            PcsModuleChip::CommitPhaseMerkle,
            PcsModuleChip::OpeningPoint,
            PcsModuleChip::BasefoldFinalPoint,
            PcsModuleChip::OpeningEval,
            PcsModuleChip::EqProduct,
            PcsModuleChip::SuffixProduct,
            PcsModuleChip::JaggedAssistH,
            PcsModuleChip::JaggedAssistQ,
            PcsModuleChip::BasefoldQueryIndex,
            PcsModuleChip::BasefoldQueryOpen,
            PcsModuleChip::BasefoldCommitPhaseQuery,
            PcsModuleChip::BasefoldFinalCodeword,
            PcsModuleChip::TranscriptValues,
            PcsModuleChip::BasefoldInitialClaim,
            PcsModuleChip::JaggedAssistInput,
            PcsModuleChip::JaggedClaim,
            PcsModuleChip::SumcheckInput,
            PcsModuleChip::Sumcheck,
            PcsModuleChip::BatchCoeff,
            PcsModuleChip::JaggedQEval,
            PcsModuleChip::JaggedAssist,
            PcsModuleChip::BasefoldFinalExpected,
            PcsModuleChip::BasefoldFinalClaim,
        ]
        .into_iter()
        .enumerate()
        .map(|(idx, chip)| {
            chip.generate_proving_ctx(
                &ctx,
                required_heights.and_then(|heights| heights.get(idx).copied()),
            )
        })
        .collect()
    }
}

#[repr(C)]
#[derive(AlignedBorrow, Debug)]
pub struct PcsCommitmentRootCols<T> {
    pub is_enabled: T,
    pub proof_idx: T,
    pub commit_major: T,
    pub commit_minor: T,
    pub lookup_count: T,
    pub root: [T; DIGEST_SIZE],
}

pub struct PcsCommitmentRootAir {
    pub commitment_root_bus: PcsCommitmentRootBus,
}

impl<F: Field> BaseAir<F> for PcsCommitmentRootAir {
    fn width(&self) -> usize {
        PcsCommitmentRootCols::<F>::width()
    }
}

impl<F: Field> BaseAirWithPublicValues<F> for PcsCommitmentRootAir {}
impl<F: Field> PartitionedBaseAir<F> for PcsCommitmentRootAir {}

impl<AB: AirBuilder + InteractionBuilder> Air<AB> for PcsCommitmentRootAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local_row = main.row_slice(0).expect("main row exists");
        let local: &PcsCommitmentRootCols<AB::Var> = (*local_row).borrow();
        builder.assert_bool(local.is_enabled);
        self.commitment_root_bus.add_key_with_lookups(
            builder,
            local.proof_idx,
            PcsCommitmentRootMessage {
                commit_major: local.commit_major.into(),
                commit_minor: local.commit_minor.into(),
                root: local.root.map(Into::into),
            },
            local.is_enabled * local.lookup_count,
        );
    }
}

#[repr(C)]
#[derive(AlignedBorrow, Debug)]
pub struct PcsBaseInputLeafHashCols<T> {
    pub is_enabled: T,
    pub proof_idx: T,
    pub query_idx: T,
    pub opening_idx: T,
    pub block_idx: T,
    pub log2_height: T,
    pub reduced_index: T,
    pub is_first: T,
    pub is_last: T,
    pub value_is_present: [T; 8],
    pub value_idx: [T; 8],
    pub elem_idx: [T; 8],
    pub values: [[T; D_EF]; 8],
    pub state_in: [T; POSEIDON2_WIDTH],
    pub input: [T; POSEIDON2_WIDTH],
    pub output_state: [T; POSEIDON2_WIDTH],
}

pub struct PcsBaseInputLeafHashAir {
    pub poseidon2_permute_bus: Poseidon2PermuteBus,
    pub base_input_opening_bus: PcsBaseInputOpeningBus,
    pub merkle_verify_bus: MerkleVerifyBus,
}

impl<F: Field> BaseAir<F> for PcsBaseInputLeafHashAir {
    fn width(&self) -> usize {
        PcsBaseInputLeafHashCols::<F>::width()
    }
}

impl<F: Field> BaseAirWithPublicValues<F> for PcsBaseInputLeafHashAir {}
impl<F: Field> PartitionedBaseAir<F> for PcsBaseInputLeafHashAir {}

impl<AB: AirBuilder + InteractionBuilder> Air<AB> for PcsBaseInputLeafHashAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local_row = main.row_slice(0).expect("main row exists");
        let next_row = main.row_slice(1).expect("next row exists");
        let local: &PcsBaseInputLeafHashCols<AB::Var> = (*local_row).borrow();
        let next: &PcsBaseInputLeafHashCols<AB::Var> = (*next_row).borrow();

        builder.assert_bool(local.is_enabled);
        builder.assert_bool(local.is_first);
        builder.assert_bool(local.is_last);
        builder
            .when(local.is_enabled * local.is_first)
            .assert_zero(local.block_idx);

        for i in 0..8 {
            builder.assert_bool(local.value_is_present[i]);
            if i > 0 {
                builder.when(local.is_enabled).assert_zero(
                    local.value_is_present[i] * (AB::Expr::ONE - local.value_is_present[i - 1]),
                );
            }
            builder.when(local.is_enabled).assert_eq(
                local.input[i],
                local.value_is_present[i] * local.values[i][0]
                    + (AB::Expr::ONE - local.value_is_present[i]) * local.state_in[i],
            );
            for limb in 1..D_EF {
                builder
                    .when(local.is_enabled * local.value_is_present[i])
                    .assert_zero(local.values[i][limb]);
            }
            self.base_input_opening_bus.receive(
                builder,
                local.proof_idx,
                PcsBaseInputOpeningMessage {
                    query_idx: local.query_idx.into(),
                    opening_idx: local.opening_idx.into(),
                    reduced_index: local.reduced_index.into(),
                    value_idx: local.value_idx[i].into(),
                    elem_idx: local.elem_idx[i].into(),
                    log2_height: local.log2_height.into(),
                    opened_value: local.values[i].map(Into::into),
                },
                local.is_enabled * local.value_is_present[i],
            );
        }
        for i in 8..POSEIDON2_WIDTH {
            builder
                .when(local.is_enabled)
                .assert_eq(local.input[i], local.state_in[i]);
        }
        for i in 0..POSEIDON2_WIDTH {
            builder
                .when(local.is_enabled * local.is_first)
                .assert_zero(local.state_in[i]);
        }

        let same_leaf = local.is_enabled * next.is_enabled * (AB::Expr::ONE - local.is_last);
        builder
            .when(same_leaf.clone())
            .assert_eq(next.query_idx, local.query_idx);
        builder
            .when(same_leaf.clone())
            .assert_eq(next.opening_idx, local.opening_idx);
        builder
            .when(same_leaf.clone())
            .assert_eq(next.block_idx, local.block_idx + AB::Expr::ONE);
        builder
            .when(same_leaf.clone())
            .assert_eq(next.log2_height, local.log2_height);
        builder
            .when(same_leaf.clone())
            .assert_eq(next.reduced_index, local.reduced_index);
        assert_array_eq(
            &mut builder.when(same_leaf),
            next.state_in,
            local.output_state,
        );

        self.poseidon2_permute_bus.lookup_key(
            builder,
            Poseidon2PermuteMessage {
                input: local.input.map(Into::into),
                output: local.output_state.map(Into::into),
            },
            local.is_enabled,
        );

        let digest = core::array::from_fn(|i| local.output_state[i].into());
        self.merkle_verify_bus.send(
            builder,
            local.proof_idx,
            MerkleVerifyBusMessage {
                merkle_idx_bit_src: local.reduced_index.into(),
                current_idx_bit_src: local.reduced_index.into(),
                total_depth: AB::Expr::ZERO,
                height: AB::Expr::ZERO,
                is_leaf: AB::Expr::ONE,
                leaf_sub_idx: AB::Expr::ZERO,
                value: digest,
                commit_major: AB::Expr::ZERO,
                commit_minor: local.opening_idx.into(),
            },
            local.is_enabled * local.is_last,
        );
    }
}

#[repr(C)]
#[derive(AlignedBorrow, Debug)]
pub struct PcsBaseInputMerkleCols<T> {
    pub is_enabled: T,
    pub proof_idx: T,
    pub query_idx: T,
    pub opening_idx: T,
    pub step: T,
    pub is_first: T,
    pub is_last: T,
    pub idx_in: T,
    pub idx_bit: T,
    pub idx_out: T,
    pub current: [T; DIGEST_SIZE],
    pub sibling: [T; DIGEST_SIZE],
    pub left: [T; DIGEST_SIZE],
    pub right: [T; DIGEST_SIZE],
    pub output: [T; DIGEST_SIZE],
}

pub struct PcsBaseInputMerkleAir {
    pub poseidon2_compress_bus: Poseidon2CompressBus,
    pub merkle_verify_bus: MerkleVerifyBus,
    pub commitment_root_bus: PcsCommitmentRootBus,
}

impl<F: Field> BaseAir<F> for PcsBaseInputMerkleAir {
    fn width(&self) -> usize {
        PcsBaseInputMerkleCols::<F>::width()
    }
}

impl<F: Field> BaseAirWithPublicValues<F> for PcsBaseInputMerkleAir {}
impl<F: Field> PartitionedBaseAir<F> for PcsBaseInputMerkleAir {}

impl<AB: AirBuilder + InteractionBuilder> Air<AB> for PcsBaseInputMerkleAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local_row = main.row_slice(0).expect("main row exists");
        let next_row = main.row_slice(1).expect("next row exists");
        let local: &PcsBaseInputMerkleCols<AB::Var> = (*local_row).borrow();
        let next: &PcsBaseInputMerkleCols<AB::Var> = (*next_row).borrow();
        builder.assert_bool(local.is_enabled);
        builder.assert_bool(local.is_first);
        builder.assert_bool(local.is_last);
        builder.assert_bool(local.idx_bit);

        builder
            .when(local.is_enabled)
            .assert_eq(local.idx_in, local.idx_bit + local.idx_out * AB::Expr::TWO);
        for i in 0..DIGEST_SIZE {
            let expected_left = local.idx_bit * local.sibling[i]
                + (AB::Expr::ONE - local.idx_bit) * local.current[i];
            let expected_right = local.idx_bit * local.current[i]
                + (AB::Expr::ONE - local.idx_bit) * local.sibling[i];
            builder
                .when(local.is_enabled)
                .assert_eq(local.left[i], expected_left);
            builder
                .when(local.is_enabled)
                .assert_eq(local.right[i], expected_right);
        }

        let same_path = local.is_enabled * next.is_enabled * (AB::Expr::ONE - local.is_last);
        builder
            .when(same_path.clone())
            .assert_eq(next.query_idx, local.query_idx);
        builder
            .when(same_path.clone())
            .assert_eq(next.opening_idx, local.opening_idx);
        builder
            .when(same_path.clone())
            .assert_eq(next.step, local.step + AB::Expr::ONE);
        builder
            .when(same_path.clone())
            .assert_eq(next.idx_in, local.idx_out);
        assert_array_eq(&mut builder.when(same_path), next.current, local.output);

        self.merkle_verify_bus.receive(
            builder,
            local.proof_idx,
            MerkleVerifyBusMessage {
                merkle_idx_bit_src: local.idx_in.into(),
                current_idx_bit_src: local.idx_in.into(),
                total_depth: AB::Expr::ZERO,
                height: AB::Expr::ZERO,
                is_leaf: AB::Expr::ONE,
                leaf_sub_idx: AB::Expr::ZERO,
                value: local.current.map(Into::into),
                commit_major: AB::Expr::ZERO,
                commit_minor: local.opening_idx.into(),
            },
            local.is_enabled * local.is_first,
        );
        self.poseidon2_compress_bus.lookup_key(
            builder,
            Poseidon2CompressMessage {
                input: digests_to_poseidon2_input(
                    local.left.map(Into::into),
                    local.right.map(Into::into),
                ),
                output: local.output.map(Into::into),
            },
            local.is_enabled,
        );
        self.commitment_root_bus.lookup_key(
            builder,
            local.proof_idx,
            PcsCommitmentRootMessage {
                commit_major: AB::Expr::ZERO,
                commit_minor: local.opening_idx.into(),
                root: local.output.map(Into::into),
            },
            local.is_enabled * local.is_last,
        );
    }
}

#[repr(C)]
#[derive(AlignedBorrow, Debug)]
pub struct PcsCommitPhaseLeafHashCols<T> {
    pub is_enabled: T,
    pub proof_idx: T,
    pub query_idx: T,
    pub round: T,
    pub leaf_idx: T,
    pub left: [T; D_EF],
    pub right: [T; D_EF],
    pub input: [T; POSEIDON2_WIDTH],
    pub output_state: [T; POSEIDON2_WIDTH],
}

pub struct PcsCommitPhaseLeafHashAir {
    pub poseidon2_permute_bus: Poseidon2PermuteBus,
    pub commit_phase_leaf_bus: PcsCommitPhaseLeafBus,
    pub merkle_verify_bus: MerkleVerifyBus,
}

impl<F: Field> BaseAir<F> for PcsCommitPhaseLeafHashAir {
    fn width(&self) -> usize {
        PcsCommitPhaseLeafHashCols::<F>::width()
    }
}

impl<F: Field> BaseAirWithPublicValues<F> for PcsCommitPhaseLeafHashAir {}
impl<F: Field> PartitionedBaseAir<F> for PcsCommitPhaseLeafHashAir {}

impl<AB: AirBuilder + InteractionBuilder> Air<AB> for PcsCommitPhaseLeafHashAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local_row = main.row_slice(0).expect("main row exists");
        let local: &PcsCommitPhaseLeafHashCols<AB::Var> = (*local_row).borrow();
        builder.assert_bool(local.is_enabled);

        for i in 0..D_EF {
            builder
                .when(local.is_enabled)
                .assert_eq(local.input[i], local.left[i]);
            builder
                .when(local.is_enabled)
                .assert_eq(local.input[D_EF + i], local.right[i]);
        }
        for i in 2 * D_EF..POSEIDON2_WIDTH {
            builder.when(local.is_enabled).assert_zero(local.input[i]);
        }

        self.commit_phase_leaf_bus.receive(
            builder,
            local.proof_idx,
            PcsCommitPhaseLeafMessage {
                query_idx: local.query_idx.into(),
                round: local.round.into(),
                leaf_idx: local.leaf_idx.into(),
                left: local.left.map(Into::into),
                right: local.right.map(Into::into),
            },
            local.is_enabled,
        );
        self.poseidon2_permute_bus.lookup_key(
            builder,
            Poseidon2PermuteMessage {
                input: local.input.map(Into::into),
                output: local.output_state.map(Into::into),
            },
            local.is_enabled,
        );
        let digest = core::array::from_fn(|i| local.output_state[i].into());
        self.merkle_verify_bus.send(
            builder,
            local.proof_idx,
            MerkleVerifyBusMessage {
                merkle_idx_bit_src: local.leaf_idx.into(),
                current_idx_bit_src: local.leaf_idx.into(),
                total_depth: AB::Expr::ZERO,
                height: AB::Expr::ZERO,
                is_leaf: AB::Expr::ONE,
                leaf_sub_idx: AB::Expr::ZERO,
                value: digest,
                commit_major: AB::Expr::from_usize(1),
                commit_minor: local.round.into(),
            },
            local.is_enabled,
        );
    }
}

#[repr(C)]
#[derive(AlignedBorrow, Debug)]
pub struct PcsCommitPhaseMerkleCols<T> {
    pub is_enabled: T,
    pub proof_idx: T,
    pub query_idx: T,
    pub round: T,
    pub step: T,
    pub is_first: T,
    pub is_last: T,
    pub idx_in: T,
    pub idx_bit: T,
    pub idx_out: T,
    pub current: [T; DIGEST_SIZE],
    pub sibling: [T; DIGEST_SIZE],
    pub left: [T; DIGEST_SIZE],
    pub right: [T; DIGEST_SIZE],
    pub output: [T; DIGEST_SIZE],
}

pub struct PcsCommitPhaseMerkleAir {
    pub poseidon2_compress_bus: Poseidon2CompressBus,
    pub merkle_verify_bus: MerkleVerifyBus,
    pub commitment_root_bus: PcsCommitmentRootBus,
}

impl<F: Field> BaseAir<F> for PcsCommitPhaseMerkleAir {
    fn width(&self) -> usize {
        PcsCommitPhaseMerkleCols::<F>::width()
    }
}

impl<F: Field> BaseAirWithPublicValues<F> for PcsCommitPhaseMerkleAir {}
impl<F: Field> PartitionedBaseAir<F> for PcsCommitPhaseMerkleAir {}

impl<AB: AirBuilder + InteractionBuilder> Air<AB> for PcsCommitPhaseMerkleAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local_row = main.row_slice(0).expect("main row exists");
        let next_row = main.row_slice(1).expect("next row exists");
        let local: &PcsCommitPhaseMerkleCols<AB::Var> = (*local_row).borrow();
        let next: &PcsCommitPhaseMerkleCols<AB::Var> = (*next_row).borrow();
        builder.assert_bool(local.is_enabled);
        builder.assert_bool(local.is_first);
        builder.assert_bool(local.is_last);
        builder.assert_bool(local.idx_bit);

        builder
            .when(local.is_enabled)
            .assert_eq(local.idx_in, local.idx_bit + local.idx_out * AB::Expr::TWO);
        for i in 0..DIGEST_SIZE {
            let expected_left = local.idx_bit * local.sibling[i]
                + (AB::Expr::ONE - local.idx_bit) * local.current[i];
            let expected_right = local.idx_bit * local.current[i]
                + (AB::Expr::ONE - local.idx_bit) * local.sibling[i];
            builder
                .when(local.is_enabled)
                .assert_eq(local.left[i], expected_left);
            builder
                .when(local.is_enabled)
                .assert_eq(local.right[i], expected_right);
        }

        let same_path = local.is_enabled * next.is_enabled * (AB::Expr::ONE - local.is_last);
        builder
            .when(same_path.clone())
            .assert_eq(next.query_idx, local.query_idx);
        builder
            .when(same_path.clone())
            .assert_eq(next.round, local.round);
        builder
            .when(same_path.clone())
            .assert_eq(next.step, local.step + AB::Expr::ONE);
        builder
            .when(same_path.clone())
            .assert_eq(next.idx_in, local.idx_out);
        assert_array_eq(&mut builder.when(same_path), next.current, local.output);

        self.merkle_verify_bus.receive(
            builder,
            local.proof_idx,
            MerkleVerifyBusMessage {
                merkle_idx_bit_src: local.idx_in.into(),
                current_idx_bit_src: local.idx_in.into(),
                total_depth: AB::Expr::ZERO,
                height: AB::Expr::ZERO,
                is_leaf: AB::Expr::ONE,
                leaf_sub_idx: AB::Expr::ZERO,
                value: local.current.map(Into::into),
                commit_major: AB::Expr::from_usize(1),
                commit_minor: local.round.into(),
            },
            local.is_enabled * local.is_first,
        );
        self.poseidon2_compress_bus.lookup_key(
            builder,
            Poseidon2CompressMessage {
                input: digests_to_poseidon2_input(
                    local.left.map(Into::into),
                    local.right.map(Into::into),
                ),
                output: local.output.map(Into::into),
            },
            local.is_enabled,
        );
        self.commitment_root_bus.lookup_key(
            builder,
            local.proof_idx,
            PcsCommitmentRootMessage {
                commit_major: AB::Expr::from_usize(1),
                commit_minor: local.round.into(),
                root: local.output.map(Into::into),
            },
            local.is_enabled * local.is_last,
        );
    }
}

#[repr(C)]
#[derive(AlignedBorrow, Debug)]
pub struct PcsOpeningPointCols<T> {
    pub is_enabled: T,
    pub proof_idx: T,
    pub opening_idx: T,
    pub coord_idx: T,
    pub global_round_idx: T,
    pub value: [T; D_EF],
}

pub struct PcsOpeningPointAir {
    pub main_global_point_bus: MainGlobalPointBus,
}

impl<F: Field> BaseAir<F> for PcsOpeningPointAir {
    fn width(&self) -> usize {
        PcsOpeningPointCols::<F>::width()
    }
}

impl<F: Field> BaseAirWithPublicValues<F> for PcsOpeningPointAir {}
impl<F: Field> PartitionedBaseAir<F> for PcsOpeningPointAir {}

impl<AB: AirBuilder + InteractionBuilder> Air<AB> for PcsOpeningPointAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local_row = main.row_slice(0).expect("main row exists");
        let local: &PcsOpeningPointCols<AB::Var> = (*local_row).borrow();
        builder.assert_bool(local.is_enabled);
        self.main_global_point_bus.lookup_key(
            builder,
            local.proof_idx,
            MainGlobalPointMessage {
                round_idx: local.global_round_idx.into(),
                value: local.value.map(Into::into),
            },
            local.is_enabled,
        );
    }
}

#[repr(C)]
#[derive(AlignedBorrow, Debug)]
pub struct PcsBasefoldFinalPointCols<T> {
    pub is_enabled: T,
    pub proof_idx: T,
    pub sumcheck_idx: T,
    pub point_idx: T,
    pub coord_idx: T,
    pub source_sumcheck_idx: T,
    pub source_round: T,
    pub value: [T; D_EF],
}

pub struct PcsBasefoldFinalPointAir {
    pub fold_challenge_bus: PcsFoldChallengeBus,
    pub final_point_bus: PcsBasefoldFinalPointBus,
}

impl<F: Field> BaseAir<F> for PcsBasefoldFinalPointAir {
    fn width(&self) -> usize {
        PcsBasefoldFinalPointCols::<F>::width()
    }
}

impl<F: Field> BaseAirWithPublicValues<F> for PcsBasefoldFinalPointAir {}
impl<F: Field> PartitionedBaseAir<F> for PcsBasefoldFinalPointAir {}

impl<AB: AirBuilder + InteractionBuilder> Air<AB> for PcsBasefoldFinalPointAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local_row = main.row_slice(0).expect("main row exists");
        let local: &PcsBasefoldFinalPointCols<AB::Var> = (*local_row).borrow();
        builder.assert_bool(local.is_enabled);
        self.fold_challenge_bus.lookup_key(
            builder,
            local.proof_idx,
            PcsFoldChallengeMessage {
                sumcheck_idx: local.source_sumcheck_idx.into(),
                round: local.source_round.into(),
                challenge: local.value.map(Into::into),
            },
            local.is_enabled,
        );
        self.final_point_bus.send(
            builder,
            local.proof_idx,
            PcsBasefoldFinalPointMessage {
                sumcheck_idx: local.sumcheck_idx.into(),
                point_idx: local.point_idx.into(),
                coord_idx: local.coord_idx.into(),
                value: local.value.map(Into::into),
            },
            local.is_enabled,
        );
    }
}

#[repr(C)]
#[derive(AlignedBorrow, Debug)]
pub struct PcsOpeningEvalCols<T> {
    pub is_enabled: T,
    pub proof_idx: T,
    pub opening_idx: T,
    pub commit_kind: T,
    pub eval_idx: T,
    pub main_idx: T,
    pub main_eval_idx: T,
    pub value: [T; D_EF],
    pub raw_value: [T; D_EF],
}

pub struct PcsOpeningEvalAir {
    pub main_eval_bus: MainEvalBus,
    pub opening_eval_bus: PcsOpeningEvalBus,
}

impl<F: Field> BaseAir<F> for PcsOpeningEvalAir {
    fn width(&self) -> usize {
        PcsOpeningEvalCols::<F>::width()
    }
}

impl<F: Field> BaseAirWithPublicValues<F> for PcsOpeningEvalAir {}
impl<F: Field> PartitionedBaseAir<F> for PcsOpeningEvalAir {}

impl<AB: AirBuilder + InteractionBuilder> Air<AB> for PcsOpeningEvalAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local_row = main.row_slice(0).expect("main row exists");
        let local: &PcsOpeningEvalCols<AB::Var> = (*local_row).borrow();
        builder.assert_bool(local.is_enabled);
        self.main_eval_bus.lookup_key(
            builder,
            local.proof_idx,
            MainEvalMessage {
                idx: local.main_idx.into(),
                eval_idx: local.main_eval_idx.into(),
                value: local.value.map(Into::into),
            },
            local.is_enabled,
        );
        self.opening_eval_bus.add_key_with_lookups(
            builder,
            local.proof_idx,
            PcsOpeningEvalMessage {
                opening_idx: local.opening_idx.into(),
                commit_kind: local.commit_kind.into(),
                eval_idx: local.eval_idx.into(),
                value: local.raw_value.map(Into::into),
            },
            local.is_enabled,
        );
    }
}

#[repr(C)]
#[derive(AlignedBorrow, Debug)]
pub struct PcsEqProductCols<T> {
    pub is_enabled: T,
    pub proof_idx: T,
    pub kind: T,
    pub source: T,
    pub round_idx: T,
    pub term_idx: T,
    pub bit_idx: T,
    pub is_first: T,
    pub is_last: T,
    pub lookup_count: T,
    pub point_tidx: T,
    pub sumcheck_idx: T,
    pub point_round: T,
    pub index_bit: T,
    pub index_pow2: T,
    pub index_acc_in: T,
    pub index_acc_out: T,
    pub point: [T; D_EF],
    pub acc_in: [T; D_EF],
    pub acc_out: [T; D_EF],
}

pub struct PcsEqProductAir {
    pub transcript_ext_bus: PcsTranscriptExtBus,
    pub fold_challenge_bus: PcsFoldChallengeBus,
    pub eq_product_bus: PcsEqProductBus,
}

impl<F: Field> BaseAir<F> for PcsEqProductAir {
    fn width(&self) -> usize {
        PcsEqProductCols::<F>::width()
    }
}

impl<F: Field> BaseAirWithPublicValues<F> for PcsEqProductAir {}
impl<F: Field> PartitionedBaseAir<F> for PcsEqProductAir {}

impl<AB> Air<AB> for PcsEqProductAir
where
    AB: AirBuilder + InteractionBuilder,
    <AB::Expr as PrimeCharacteristicRing>::PrimeSubfield: BinomiallyExtendable<{ D_EF }>,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local_row = main.row_slice(0).expect("main row exists");
        let next_row = main.row_slice(1).expect("next row exists");
        let local: &PcsEqProductCols<AB::Var> = (*local_row).borrow();
        let next: &PcsEqProductCols<AB::Var> = (*next_row).borrow();

        builder.assert_bool(local.is_enabled);
        builder.assert_bool(local.source);
        builder.assert_bool(local.is_first);
        builder.assert_bool(local.is_last);
        builder.assert_bool(local.index_bit);
        builder
            .when(local.is_enabled * (AB::Expr::ONE - local.is_last))
            .assert_zero(local.lookup_count);

        builder
            .when(local.is_enabled * local.is_first)
            .assert_zero(local.bit_idx);
        builder
            .when(local.is_enabled * local.is_first)
            .assert_one(local.index_pow2);
        builder
            .when(local.is_enabled * local.is_first)
            .assert_zero(local.index_acc_in);
        let one = core::array::from_fn(|i| {
            if i == 0 {
                AB::Expr::ONE
            } else {
                AB::Expr::ZERO
            }
        });
        assert_array_eq(
            &mut builder.when(local.is_enabled * local.is_first),
            local.acc_in,
            one.clone(),
        );

        let expected_index_acc = local.index_acc_in + local.index_bit * local.index_pow2;
        builder
            .when(local.is_enabled)
            .assert_eq(local.index_acc_out, expected_index_acc);
        builder
            .when(local.is_enabled * local.is_last)
            .assert_eq(local.index_acc_out, local.term_idx);

        let factor = core::array::from_fn(|i| {
            let point = local.point[i].into();
            let one_minus_point = if i == 0 {
                AB::Expr::ONE - point.clone()
            } else {
                -point.clone()
            };
            local.index_bit * point + (AB::Expr::ONE - local.index_bit) * one_minus_point
        });
        let expected_acc = recursion_circuit::utils::ext_field_multiply(local.acc_in, factor);
        assert_array_eq(
            &mut builder.when(local.is_enabled),
            local.acc_out,
            expected_acc,
        );

        let continues = local.is_enabled * (AB::Expr::ONE - local.is_last);
        builder
            .when_transition()
            .when(continues.clone())
            .assert_one(next.is_enabled);
        builder
            .when_transition()
            .when(continues.clone())
            .assert_eq(next.proof_idx, local.proof_idx);
        builder
            .when_transition()
            .when(continues.clone())
            .assert_eq(next.kind, local.kind);
        builder
            .when_transition()
            .when(continues.clone())
            .assert_eq(next.source, local.source);
        builder
            .when_transition()
            .when(continues.clone())
            .assert_eq(next.round_idx, local.round_idx);
        builder
            .when_transition()
            .when(continues.clone())
            .assert_eq(next.term_idx, local.term_idx);
        builder
            .when_transition()
            .when(continues.clone())
            .assert_eq(next.bit_idx, local.bit_idx + AB::Expr::ONE);
        builder
            .when_transition()
            .when(continues.clone())
            .assert_eq(next.index_pow2, local.index_pow2 * AB::Expr::TWO);
        builder
            .when_transition()
            .when(continues.clone())
            .assert_eq(next.index_acc_in, local.index_acc_out);
        assert_array_eq(
            &mut builder.when_transition().when(continues),
            next.acc_in,
            local.acc_out,
        );

        let is_transcript = AB::Expr::ONE - local.source;
        self.transcript_ext_bus.lookup_key(
            builder,
            local.proof_idx,
            PcsTranscriptExtMessage {
                tidx: local.point_tidx.into(),
                value: local.point.map(Into::into),
            },
            local.is_enabled * is_transcript,
        );
        self.fold_challenge_bus.lookup_key(
            builder,
            local.proof_idx,
            PcsFoldChallengeMessage {
                sumcheck_idx: local.sumcheck_idx.into(),
                round: local.point_round.into(),
                challenge: local.point.map(Into::into),
            },
            local.is_enabled * local.source,
        );
        self.eq_product_bus.add_key_with_lookups(
            builder,
            local.proof_idx,
            PcsEqProductMessage {
                kind: local.kind.into(),
                round_idx: local.round_idx.into(),
                term_idx: local.term_idx.into(),
                value: local.acc_out.map(Into::into),
            },
            local.is_enabled * local.lookup_count,
        );
    }
}

#[repr(C)]
#[derive(AlignedBorrow, Debug)]
pub struct PcsSuffixProductCols<T> {
    pub is_enabled: T,
    pub proof_idx: T,
    pub round_idx: T,
    pub term_idx: T,
    pub coord_idx: T,
    pub step_idx: T,
    pub is_first: T,
    pub is_last: T,
    pub has_factor: T,
    pub point: [T; D_EF],
    pub acc_in: [T; D_EF],
    pub acc_out: [T; D_EF],
}

pub struct PcsSuffixProductAir {
    pub main_global_point_bus: MainGlobalPointBus,
    pub suffix_product_bus: PcsSuffixProductBus,
}

impl<F: Field> BaseAir<F> for PcsSuffixProductAir {
    fn width(&self) -> usize {
        PcsSuffixProductCols::<F>::width()
    }
}

impl<F: Field> BaseAirWithPublicValues<F> for PcsSuffixProductAir {}
impl<F: Field> PartitionedBaseAir<F> for PcsSuffixProductAir {}

impl<AB> Air<AB> for PcsSuffixProductAir
where
    AB: AirBuilder + InteractionBuilder,
    <AB::Expr as PrimeCharacteristicRing>::PrimeSubfield: BinomiallyExtendable<{ D_EF }>,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local_row = main.row_slice(0).expect("main row exists");
        let next_row = main.row_slice(1).expect("next row exists");
        let local: &PcsSuffixProductCols<AB::Var> = (*local_row).borrow();
        let next: &PcsSuffixProductCols<AB::Var> = (*next_row).borrow();

        builder.assert_bool(local.is_enabled);
        builder.assert_bool(local.is_first);
        builder.assert_bool(local.is_last);
        builder.assert_bool(local.has_factor);
        builder
            .when(local.is_enabled * local.is_first)
            .assert_zero(local.step_idx);
        let one = core::array::from_fn(|i| {
            if i == 0 {
                AB::Expr::ONE
            } else {
                AB::Expr::ZERO
            }
        });
        assert_array_eq(
            &mut builder.when(local.is_enabled * local.is_first),
            local.acc_in,
            one.clone(),
        );

        let factor = core::array::from_fn(|i| {
            let point = local.point[i].into();
            let one_minus_point = if i == 0 {
                AB::Expr::ONE - point.clone()
            } else {
                -point.clone()
            };
            local.has_factor * one_minus_point + (AB::Expr::ONE - local.has_factor) * one[i].clone()
        });
        let expected_acc = recursion_circuit::utils::ext_field_multiply(local.acc_in, factor);
        assert_array_eq(
            &mut builder.when(local.is_enabled),
            local.acc_out,
            expected_acc,
        );

        let continues = local.is_enabled * (AB::Expr::ONE - local.is_last);
        builder
            .when_transition()
            .when(continues.clone())
            .assert_one(next.is_enabled);
        builder
            .when_transition()
            .when(continues.clone())
            .assert_eq(next.proof_idx, local.proof_idx);
        builder
            .when_transition()
            .when(continues.clone())
            .assert_eq(next.round_idx, local.round_idx);
        builder
            .when_transition()
            .when(continues.clone())
            .assert_eq(next.term_idx, local.term_idx);
        builder
            .when_transition()
            .when(continues.clone())
            .assert_eq(next.coord_idx, local.coord_idx + AB::Expr::ONE);
        builder
            .when_transition()
            .when(continues.clone())
            .assert_eq(next.step_idx, local.step_idx + AB::Expr::ONE);
        assert_array_eq(
            &mut builder.when_transition().when(continues),
            next.acc_in,
            local.acc_out,
        );

        self.main_global_point_bus.lookup_key(
            builder,
            local.proof_idx,
            MainGlobalPointMessage {
                round_idx: local.coord_idx.into(),
                value: local.point.map(Into::into),
            },
            local.is_enabled * local.has_factor,
        );
        self.suffix_product_bus.add_key_with_lookups(
            builder,
            local.proof_idx,
            PcsSuffixProductMessage {
                round_idx: local.round_idx.into(),
                term_idx: local.term_idx.into(),
                value: local.acc_out.map(Into::into),
            },
            local.is_enabled * local.is_last,
        );
    }
}

#[repr(C)]
#[derive(AlignedBorrow, Debug)]
pub struct PcsJaggedAssistHCols<T> {
    pub is_enabled: T,
    pub proof_idx: T,
    pub round_idx: T,
    pub sumcheck_idx: T,
    pub step_idx: T,
    pub robp_idx: T,
    pub is_first: T,
    pub is_last: T,
    pub has_z_row: T,
    pub has_rho: T,
    pub z_row: [T; D_EF],
    pub rho: [T; D_EF],
    pub rho_star_c: [T; D_EF],
    pub rho_star_d: [T; D_EF],
    pub val_in: [[T; D_EF]; 4],
    pub val_out: [[T; D_EF]; 4],
}

pub struct PcsJaggedAssistHAir {
    pub main_global_point_bus: MainGlobalPointBus,
    pub fold_challenge_bus: PcsFoldChallengeBus,
    pub jagged_assist_h_bus: PcsJaggedAssistHBus,
}

impl<F: Field> BaseAir<F> for PcsJaggedAssistHAir {
    fn width(&self) -> usize {
        PcsJaggedAssistHCols::<F>::width()
    }
}

impl<F: Field> BaseAirWithPublicValues<F> for PcsJaggedAssistHAir {}
impl<F: Field> PartitionedBaseAir<F> for PcsJaggedAssistHAir {}

impl<AB> Air<AB> for PcsJaggedAssistHAir
where
    AB: AirBuilder + InteractionBuilder,
    <AB::Expr as PrimeCharacteristicRing>::PrimeSubfield: BinomiallyExtendable<{ D_EF }>,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local_row = main.row_slice(0).expect("main row exists");
        let next_row = main.row_slice(1).expect("next row exists");
        let local: &PcsJaggedAssistHCols<AB::Var> = (*local_row).borrow();
        let next: &PcsJaggedAssistHCols<AB::Var> = (*next_row).borrow();

        builder.assert_bool(local.is_enabled);
        builder.assert_bool(local.is_first);
        builder.assert_bool(local.is_last);
        builder.assert_bool(local.has_z_row);
        builder.assert_bool(local.has_rho);
        builder.when(local.is_enabled).assert_eq(
            local.sumcheck_idx,
            local.round_idx + local.round_idx + AB::Expr::ONE,
        );
        builder
            .when(local.is_enabled * local.is_first)
            .assert_zero(local.step_idx);
        let zero_ext = core::array::from_fn(|_| AB::Expr::ZERO);
        let one_ext = core::array::from_fn(|i| {
            if i == 0 {
                AB::Expr::ONE
            } else {
                AB::Expr::ZERO
            }
        });
        assert_array_eq(
            &mut builder.when(local.is_enabled * (AB::Expr::ONE - local.has_z_row)),
            local.z_row,
            zero_ext.clone(),
        );
        assert_array_eq(
            &mut builder.when(local.is_enabled * (AB::Expr::ONE - local.has_rho)),
            local.rho,
            zero_ext.clone(),
        );
        assert_array_eq(
            &mut builder.when(local.is_enabled * local.is_first),
            local.val_in[0],
            zero_ext.clone(),
        );
        assert_array_eq(
            &mut builder.when(local.is_enabled * local.is_first),
            local.val_in[1],
            one_ext.clone(),
        );
        assert_array_eq(
            &mut builder.when(local.is_enabled * local.is_first),
            local.val_in[2],
            zero_ext.clone(),
        );
        assert_array_eq(
            &mut builder.when(local.is_enabled * local.is_first),
            local.val_in[3],
            zero_ext.clone(),
        );

        let one_minus = |x: [AB::Var; D_EF]| -> [AB::Expr; D_EF] {
            core::array::from_fn(|i| {
                let limb = x[i].into();
                if i == 0 { AB::Expr::ONE - limb } else { -limb }
            })
        };
        let z1 = local.z_row;
        let z2 = local.rho;
        let z3 = local.rho_star_c;
        let z4 = local.rho_star_d;
        let nz1 = one_minus(z1);
        let nz2 = one_minus(z2);
        let nz3 = one_minus(z3);
        let nz4 = one_minus(z4);
        let ab00: [AB::Expr; D_EF] =
            recursion_circuit::utils::ext_field_multiply(nz1.clone(), nz2.clone());
        let ab01: [AB::Expr; D_EF] = recursion_circuit::utils::ext_field_multiply(nz1.clone(), z2);
        let ab10: [AB::Expr; D_EF] = recursion_circuit::utils::ext_field_multiply(z1, nz2.clone());
        let ab11: [AB::Expr; D_EF] = recursion_circuit::utils::ext_field_multiply(z1, z2);
        let cd00: [AB::Expr; D_EF] =
            recursion_circuit::utils::ext_field_multiply(nz3.clone(), nz4.clone());
        let cd01: [AB::Expr; D_EF] = recursion_circuit::utils::ext_field_multiply(nz3.clone(), z4);
        let cd10: [AB::Expr; D_EF] = recursion_circuit::utils::ext_field_multiply(z3, nz4.clone());
        let cd11: [AB::Expr; D_EF] = recursion_circuit::utils::ext_field_multiply(z3, z4);

        let transitions: [(
            usize,
            usize,
            [AB::Expr; D_EF],
            [AB::Expr; D_EF],
            [AB::Expr; D_EF],
        ); 4] = [
            (
                0usize,
                0usize,
                ext_add::<AB::Expr>(
                    ext_add::<AB::Expr>(
                        recursion_circuit::utils::ext_field_multiply::<AB::Expr>(
                            ab00.clone(),
                            cd00.clone(),
                        ),
                        recursion_circuit::utils::ext_field_multiply::<AB::Expr>(
                            ab01.clone(),
                            cd11.clone(),
                        ),
                    ),
                    recursion_circuit::utils::ext_field_multiply::<AB::Expr>(
                        ab11.clone(),
                        cd01.clone(),
                    ),
                ),
                recursion_circuit::utils::ext_field_multiply::<AB::Expr>(
                    ab00.clone(),
                    cd01.clone(),
                ),
                ext_add::<AB::Expr>(
                    recursion_circuit::utils::ext_field_multiply::<AB::Expr>(
                        ab01.clone(),
                        cd10.clone(),
                    ),
                    recursion_circuit::utils::ext_field_multiply::<AB::Expr>(
                        ab11.clone(),
                        cd00.clone(),
                    ),
                ),
            ),
            (
                0usize,
                1usize,
                recursion_circuit::utils::ext_field_multiply::<AB::Expr>(
                    ab10.clone(),
                    cd10.clone(),
                ),
                recursion_circuit::utils::ext_field_multiply::<AB::Expr>(
                    ab10.clone(),
                    cd11.clone(),
                ),
                zero_ext.clone(),
            ),
            (
                1usize,
                0usize,
                recursion_circuit::utils::ext_field_multiply::<AB::Expr>(
                    ab01.clone(),
                    cd01.clone(),
                ),
                zero_ext.clone(),
                recursion_circuit::utils::ext_field_multiply::<AB::Expr>(
                    ab01.clone(),
                    cd00.clone(),
                ),
            ),
            (
                1usize,
                1usize,
                ext_add::<AB::Expr>(
                    ext_add::<AB::Expr>(
                        recursion_circuit::utils::ext_field_multiply::<AB::Expr>(
                            ab00.clone(),
                            cd10.clone(),
                        ),
                        recursion_circuit::utils::ext_field_multiply::<AB::Expr>(
                            ab10.clone(),
                            cd00.clone(),
                        ),
                    ),
                    recursion_circuit::utils::ext_field_multiply::<AB::Expr>(
                        ab11.clone(),
                        cd11.clone(),
                    ),
                ),
                ext_add::<AB::Expr>(
                    recursion_circuit::utils::ext_field_multiply::<AB::Expr>(ab00, cd11),
                    recursion_circuit::utils::ext_field_multiply::<AB::Expr>(ab10, cd01),
                ),
                recursion_circuit::utils::ext_field_multiply::<AB::Expr>(ab11, cd10),
            ),
        ];
        let mut expected: [[AB::Expr; D_EF]; 4] = core::array::from_fn(|_| zero_ext.clone());
        for (ci, co, w_same, w_lt1, w_lt0) in transitions {
            let v0 = local.val_in[co * 2];
            let v1 = local.val_in[co * 2 + 1];
            let same_v0 =
                recursion_circuit::utils::ext_field_multiply::<AB::Expr>(w_same.clone(), v0);
            let lt1_v1 =
                recursion_circuit::utils::ext_field_multiply::<AB::Expr>(w_lt1.clone(), v1);
            let lt0_v0 =
                recursion_circuit::utils::ext_field_multiply::<AB::Expr>(w_lt0.clone(), v0);
            expected[ci * 2] = ext_add::<AB::Expr>(
                expected[ci * 2].clone(),
                ext_add::<AB::Expr>(same_v0, ext_add::<AB::Expr>(lt1_v1, lt0_v0)),
            );

            let same_v1 = recursion_circuit::utils::ext_field_multiply::<AB::Expr>(w_same, v1);
            let lt1_v1 = recursion_circuit::utils::ext_field_multiply::<AB::Expr>(w_lt1, v1);
            let lt0_v0 = recursion_circuit::utils::ext_field_multiply::<AB::Expr>(w_lt0, v0);
            expected[ci * 2 + 1] = ext_add::<AB::Expr>(
                expected[ci * 2 + 1].clone(),
                ext_add::<AB::Expr>(same_v1, ext_add::<AB::Expr>(lt1_v1, lt0_v0)),
            );
        }
        for (actual, expected) in local.val_out.into_iter().zip(expected) {
            assert_array_eq(builder, actual, expected);
        }

        let continues = local.is_enabled * (AB::Expr::ONE - local.is_last);
        builder
            .when_transition()
            .when(continues.clone())
            .assert_one(next.is_enabled);
        builder
            .when_transition()
            .when(continues.clone())
            .assert_eq(next.proof_idx, local.proof_idx);
        builder
            .when_transition()
            .when(continues.clone())
            .assert_eq(next.round_idx, local.round_idx);
        builder
            .when_transition()
            .when(continues.clone())
            .assert_eq(next.sumcheck_idx, local.sumcheck_idx);
        builder
            .when_transition()
            .when(continues.clone())
            .assert_eq(next.step_idx, local.step_idx + AB::Expr::ONE);
        builder
            .when_transition()
            .when(continues.clone())
            .assert_eq(next.robp_idx + AB::Expr::ONE, local.robp_idx);
        for i in 0..4 {
            assert_array_eq(
                &mut builder.when_transition().when(continues.clone()),
                next.val_in[i],
                local.val_out[i],
            );
        }

        self.main_global_point_bus.lookup_key(
            builder,
            local.proof_idx,
            MainGlobalPointMessage {
                round_idx: local.robp_idx.into(),
                value: local.z_row.map(Into::into),
            },
            local.is_enabled * local.has_z_row,
        );
        self.fold_challenge_bus.lookup_key(
            builder,
            local.proof_idx,
            PcsFoldChallengeMessage {
                sumcheck_idx: (local.round_idx + local.round_idx).into(),
                round: local.robp_idx.into(),
                challenge: local.rho.map(Into::into),
            },
            local.is_enabled * local.has_rho,
        );
        self.fold_challenge_bus.lookup_key(
            builder,
            local.proof_idx,
            PcsFoldChallengeMessage {
                sumcheck_idx: local.sumcheck_idx.into(),
                round: (local.robp_idx + local.robp_idx).into(),
                challenge: local.rho_star_c.map(Into::into),
            },
            local.is_enabled,
        );
        self.fold_challenge_bus.lookup_key(
            builder,
            local.proof_idx,
            PcsFoldChallengeMessage {
                sumcheck_idx: local.sumcheck_idx.into(),
                round: (local.robp_idx + local.robp_idx + AB::Expr::ONE).into(),
                challenge: local.rho_star_d.map(Into::into),
            },
            local.is_enabled,
        );
        self.jagged_assist_h_bus.add_key_with_lookups(
            builder,
            local.proof_idx,
            PcsJaggedAssistHMessage {
                round_idx: local.round_idx.into(),
                value: local.val_out[0].map(Into::into),
            },
            local.is_enabled * local.is_last,
        );
    }
}

#[repr(C)]
#[derive(AlignedBorrow, Debug)]
pub struct PcsJaggedAssistQCols<T> {
    pub is_enabled: T,
    pub proof_idx: T,
    pub round_idx: T,
    pub sumcheck_idx: T,
    pub commitment_kind: T,
    pub term_idx: T,
    pub step_idx: T,
    pub robp_idx: T,
    pub is_first: T,
    pub is_last: T,
    pub is_first_step: T,
    pub is_last_step: T,
    pub term_is_last: T,
    pub eq_col: [T; D_EF],
    pub t_lo: T,
    pub t_hi: T,
    pub c_bit: T,
    pub d_bit: T,
    pub bit_pow2: T,
    pub c_acc_in: T,
    pub c_acc_out: T,
    pub d_acc_in: T,
    pub d_acc_out: T,
    pub rho_star_c: [T; D_EF],
    pub rho_star_d: [T; D_EF],
    pub term_acc_in: [T; D_EF],
    pub term_acc_out: [T; D_EF],
    pub q_acc_in: [T; D_EF],
    pub q_acc_out: [T; D_EF],
}

pub struct PcsJaggedAssistQAir {
    pub fold_challenge_bus: PcsFoldChallengeBus,
    pub eq_product_bus: PcsEqProductBus,
    pub commit_height_bus: PcsCommitHeightBus,
    pub jagged_assist_q_bus: PcsJaggedAssistQBus,
}

impl<F: Field> BaseAir<F> for PcsJaggedAssistQAir {
    fn width(&self) -> usize {
        PcsJaggedAssistQCols::<F>::width()
    }
}

impl<F: Field> BaseAirWithPublicValues<F> for PcsJaggedAssistQAir {}
impl<F: Field> PartitionedBaseAir<F> for PcsJaggedAssistQAir {}

impl<AB> Air<AB> for PcsJaggedAssistQAir
where
    AB: AirBuilder + InteractionBuilder,
    <AB::Expr as PrimeCharacteristicRing>::PrimeSubfield: BinomiallyExtendable<{ D_EF }>,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local_row = main.row_slice(0).expect("main row exists");
        let next_row = main.row_slice(1).expect("next row exists");
        let local: &PcsJaggedAssistQCols<AB::Var> = (*local_row).borrow();
        let next: &PcsJaggedAssistQCols<AB::Var> = (*next_row).borrow();

        builder.assert_bool(local.is_enabled);
        builder.assert_bool(local.is_first);
        builder.assert_bool(local.is_last);
        builder.assert_bool(local.is_first_step);
        builder.assert_bool(local.is_last_step);
        builder.assert_bool(local.term_is_last);
        builder.assert_bool(local.c_bit);
        builder.assert_bool(local.d_bit);
        builder.when(local.is_enabled).assert_eq(
            local.sumcheck_idx,
            local.round_idx + local.round_idx + AB::Expr::ONE,
        );
        builder
            .when(local.is_enabled)
            .assert_eq(local.is_last, local.is_last_step * local.term_is_last);
        builder
            .when(local.is_enabled * local.is_first)
            .assert_zero(local.term_idx);
        builder
            .when(local.is_enabled * local.is_first)
            .assert_zero(local.step_idx);
        builder
            .when(local.is_enabled * local.is_first)
            .assert_zero(local.robp_idx);
        let zero_ext = core::array::from_fn(|_| AB::Expr::ZERO);
        assert_array_eq(
            &mut builder.when(local.is_enabled * local.is_first),
            local.q_acc_in,
            zero_ext.clone(),
        );
        builder
            .when(local.is_enabled * local.is_first_step)
            .assert_zero(local.step_idx);
        builder
            .when(local.is_enabled * local.is_first_step)
            .assert_zero(local.robp_idx);
        builder
            .when(local.is_enabled * local.is_first_step)
            .assert_one(local.bit_pow2);
        builder
            .when(local.is_enabled * local.is_first_step)
            .assert_zero(local.c_acc_in);
        builder
            .when(local.is_enabled * local.is_first_step)
            .assert_zero(local.d_acc_in);
        assert_array_eq(
            &mut builder.when(local.is_enabled * local.is_first_step),
            local.term_acc_in,
            local.eq_col,
        );

        let expected_c_acc = local.c_acc_in + local.c_bit * local.bit_pow2;
        let expected_d_acc = local.d_acc_in + local.d_bit * local.bit_pow2;
        builder
            .when(local.is_enabled)
            .assert_eq(local.c_acc_out, expected_c_acc);
        builder
            .when(local.is_enabled)
            .assert_eq(local.d_acc_out, expected_d_acc);
        builder
            .when(local.is_enabled * local.is_last_step)
            .assert_eq(local.c_acc_out, local.t_lo);
        builder
            .when(local.is_enabled * local.is_last_step)
            .assert_eq(local.d_acc_out, local.t_hi);

        let ext_factor = |bit: AB::Var, point: [AB::Var; D_EF]| -> [AB::Expr; D_EF] {
            core::array::from_fn(|i| {
                let point_limb = point[i].into();
                let one_minus = if i == 0 {
                    AB::Expr::ONE - point_limb.clone()
                } else {
                    -point_limb.clone()
                };
                bit * point_limb + (AB::Expr::ONE - bit) * one_minus
            })
        };
        let c_factor = ext_factor(local.c_bit, local.rho_star_c);
        let d_factor = ext_factor(local.d_bit, local.rho_star_d);
        let factor: [AB::Expr; D_EF] =
            recursion_circuit::utils::ext_field_multiply(c_factor, d_factor);
        let expected_term_acc: [AB::Expr; D_EF] =
            recursion_circuit::utils::ext_field_multiply(local.term_acc_in, factor);
        assert_array_eq(builder, local.term_acc_out, expected_term_acc);

        let q_delta = local.term_acc_out.map(|limb| local.is_last_step * limb);
        let expected_q_acc = ext_add::<AB::Expr>(local.q_acc_in, q_delta);
        assert_array_eq(
            &mut builder.when(local.is_enabled),
            local.q_acc_out,
            expected_q_acc,
        );

        let continues = local.is_enabled * (AB::Expr::ONE - local.is_last);
        builder
            .when_transition()
            .when(continues.clone())
            .assert_one(next.is_enabled);
        builder
            .when_transition()
            .when(continues.clone())
            .assert_eq(next.proof_idx, local.proof_idx);
        builder
            .when_transition()
            .when(continues.clone())
            .assert_eq(next.round_idx, local.round_idx);
        builder
            .when_transition()
            .when(continues.clone())
            .assert_eq(next.sumcheck_idx, local.sumcheck_idx);
        builder
            .when_transition()
            .when(continues.clone())
            .assert_eq(next.commitment_kind, local.commitment_kind);

        let same_term = continues.clone() * (AB::Expr::ONE - local.is_last_step);
        builder
            .when_transition()
            .when(same_term.clone())
            .assert_eq(next.term_idx, local.term_idx);
        builder
            .when_transition()
            .when(same_term.clone())
            .assert_eq(next.step_idx, local.step_idx + AB::Expr::ONE);
        builder
            .when_transition()
            .when(same_term.clone())
            .assert_eq(next.robp_idx, local.robp_idx + AB::Expr::ONE);
        builder
            .when_transition()
            .when(same_term.clone())
            .assert_eq(next.bit_pow2, local.bit_pow2 * AB::Expr::TWO);
        builder
            .when_transition()
            .when(same_term.clone())
            .assert_eq(next.c_acc_in, local.c_acc_out);
        builder
            .when_transition()
            .when(same_term.clone())
            .assert_eq(next.d_acc_in, local.d_acc_out);
        builder
            .when_transition()
            .when(same_term.clone())
            .assert_eq(next.t_lo, local.t_lo);
        builder
            .when_transition()
            .when(same_term.clone())
            .assert_eq(next.t_hi, local.t_hi);
        assert_array_eq(
            &mut builder.when_transition().when(same_term.clone()),
            next.term_acc_in,
            local.term_acc_out,
        );
        assert_array_eq(
            &mut builder.when_transition().when(same_term),
            next.q_acc_in,
            local.q_acc_out,
        );

        let next_term = continues * local.is_last_step;
        builder
            .when_transition()
            .when(next_term.clone())
            .assert_eq(next.term_idx, local.term_idx + AB::Expr::ONE);
        builder
            .when_transition()
            .when(next_term.clone())
            .assert_one(next.is_first_step);
        assert_array_eq(
            &mut builder.when_transition().when(next_term),
            next.q_acc_in,
            local.q_acc_out,
        );

        self.eq_product_bus.lookup_key(
            builder,
            local.proof_idx,
            PcsEqProductMessage {
                kind: AB::Expr::from_usize(PcsEqProductKind::JaggedClaim.as_usize()),
                round_idx: local.round_idx.into(),
                term_idx: local.term_idx.into(),
                value: local.eq_col.map(Into::into),
            },
            local.is_enabled * local.is_first_step,
        );
        self.commit_height_bus.lookup_key(
            builder,
            local.proof_idx,
            PcsCommitHeightMessage {
                commitment_kind: local.commitment_kind.into(),
                height_idx: local.term_idx.into(),
                value: local.t_lo.into(),
            },
            local.is_enabled * local.is_first_step,
        );
        self.commit_height_bus.lookup_key(
            builder,
            local.proof_idx,
            PcsCommitHeightMessage {
                commitment_kind: local.commitment_kind.into(),
                height_idx: (local.term_idx + AB::Expr::ONE).into(),
                value: local.t_hi.into(),
            },
            local.is_enabled * local.is_first_step,
        );
        self.fold_challenge_bus.lookup_key(
            builder,
            local.proof_idx,
            PcsFoldChallengeMessage {
                sumcheck_idx: local.sumcheck_idx.into(),
                round: (local.robp_idx + local.robp_idx).into(),
                challenge: local.rho_star_c.map(Into::into),
            },
            local.is_enabled,
        );
        self.fold_challenge_bus.lookup_key(
            builder,
            local.proof_idx,
            PcsFoldChallengeMessage {
                sumcheck_idx: local.sumcheck_idx.into(),
                round: (local.robp_idx + local.robp_idx + AB::Expr::ONE).into(),
                challenge: local.rho_star_d.map(Into::into),
            },
            local.is_enabled,
        );
        self.jagged_assist_q_bus.add_key_with_lookups(
            builder,
            local.proof_idx,
            PcsJaggedAssistQMessage {
                round_idx: local.round_idx.into(),
                value: local.q_acc_out.map(Into::into),
            },
            local.is_enabled * local.is_last,
        );
    }
}

#[repr(C)]
#[derive(AlignedBorrow, Debug)]
pub struct PcsBasefoldQueryIndexCols<T> {
    pub is_enabled: T,
    pub proof_idx: T,
    pub query_idx: T,
    pub sample_tidx: T,
    pub query_bits: T,
    pub sampled_value: T,
    pub query_value: T,
    pub high_value: T,
    pub query_bytes: [T; 4],
    pub high_bytes: [T; 4],
    pub query_bit_selectors: [T; 32],
}

pub struct PcsBasefoldQueryIndexAir {
    pub query_sample_bus: PcsQuerySampleBus,
    pub basefold_query_bus: PcsBasefoldQueryBus,
    pub range_checker_bus: RangeCheckerBus,
}

impl<F: Field> BaseAir<F> for PcsBasefoldQueryIndexAir {
    fn width(&self) -> usize {
        PcsBasefoldQueryIndexCols::<F>::width()
    }
}

impl<F: Field> BaseAirWithPublicValues<F> for PcsBasefoldQueryIndexAir {}
impl<F: Field> PartitionedBaseAir<F> for PcsBasefoldQueryIndexAir {}

impl<AB: AirBuilder + InteractionBuilder> Air<AB> for PcsBasefoldQueryIndexAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local_row = main.row_slice(0).expect("main row exists");
        let local: &PcsBasefoldQueryIndexCols<AB::Var> = (*local_row).borrow();
        builder.assert_bool(local.is_enabled);

        let mut query_from_bytes = AB::Expr::ZERO;
        let mut high_from_bytes = AB::Expr::ZERO;
        let mut coeff = AB::Expr::ONE;
        for i in 0..4 {
            query_from_bytes += local.query_bytes[i] * coeff.clone();
            high_from_bytes += local.high_bytes[i] * coeff.clone();
            self.range_checker_bus.lookup_key(
                builder,
                RangeCheckerBusMessage {
                    value: local.query_bytes[i].into(),
                    max_bits: AB::Expr::from_usize(8),
                },
                local.is_enabled,
            );
            self.range_checker_bus.lookup_key(
                builder,
                RangeCheckerBusMessage {
                    value: local.high_bytes[i].into(),
                    max_bits: AB::Expr::from_usize(8),
                },
                local.is_enabled,
            );
            coeff *= AB::Expr::from_usize(256);
        }
        builder
            .when(local.is_enabled)
            .assert_eq(local.query_value, query_from_bytes);
        builder
            .when(local.is_enabled)
            .assert_eq(local.high_value, high_from_bytes);

        let mut bit_selector_sum = AB::Expr::ZERO;
        let mut query_bits_from_selectors = AB::Expr::ZERO;
        let mut two_pow_bits = AB::Expr::ZERO;
        for bit in 0..32 {
            builder.assert_bool(local.query_bit_selectors[bit]);
            bit_selector_sum += local.query_bit_selectors[bit].into();
            query_bits_from_selectors += local.query_bit_selectors[bit] * AB::Expr::from_usize(bit);
            two_pow_bits += local.query_bit_selectors[bit] * AB::Expr::from_usize(1usize << bit);
        }
        builder.when(local.is_enabled).assert_one(bit_selector_sum);
        builder
            .when(local.is_enabled)
            .assert_eq(local.query_bits, query_bits_from_selectors);
        builder.when(local.is_enabled).assert_eq(
            local.sampled_value,
            local.query_value + local.high_value * two_pow_bits,
        );

        self.query_sample_bus.lookup_key(
            builder,
            local.proof_idx,
            PcsQuerySampleMessage {
                tidx: local.sample_tidx.into(),
                value: local.sampled_value.into(),
            },
            local.is_enabled,
        );

        let query_value = core::array::from_fn(|i| {
            if i == 0 {
                local.query_value.into()
            } else {
                AB::Expr::ZERO
            }
        });
        self.basefold_query_bus.send(
            builder,
            local.proof_idx,
            PcsBasefoldQueryMessage {
                query_idx: local.query_idx.into(),
                stage: AB::Expr::from_usize(PcsBasefoldQueryStage::QueryIndex.as_usize()),
                round: AB::Expr::ZERO,
                value: query_value,
            },
            local.is_enabled,
        );
        self.basefold_query_bus.send(
            builder,
            local.proof_idx,
            PcsBasefoldQueryMessage {
                query_idx: local.query_idx.into(),
                stage: AB::Expr::from_usize(PcsBasefoldQueryStage::FinalCodewordStart.as_usize()),
                round: AB::Expr::ZERO,
                value: [AB::Expr::ZERO; D_EF],
            },
            local.is_enabled,
        );
    }
}

#[repr(C)]
#[derive(AlignedBorrow, Debug)]
pub struct PcsBasefoldQueryOpenCols<T> {
    pub is_enabled: T,
    pub proof_idx: T,
    pub query_idx: T,
    pub opening_idx: T,
    pub reduced_index: T,
    pub global_coeff_idx: T,
    pub value_idx: T,
    pub elem_idx: T,
    pub log2_height: T,
    pub is_last_for_height: T,
    pub coeff: [T; D_EF],
    pub opened_value: [T; D_EF],
    pub acc_in: [T; D_EF],
    pub acc_out: [T; D_EF],
}

pub struct PcsBasefoldQueryOpenAir {
    pub basefold_query_bus: PcsBasefoldQueryBus,
    pub base_input_opening_bus: PcsBaseInputOpeningBus,
    pub batch_coeff_bus: PcsBatchCoeffBus,
}

impl<F: Field> BaseAir<F> for PcsBasefoldQueryOpenAir {
    fn width(&self) -> usize {
        PcsBasefoldQueryOpenCols::<F>::width()
    }
}

impl<F: Field> BaseAirWithPublicValues<F> for PcsBasefoldQueryOpenAir {}
impl<F: Field> PartitionedBaseAir<F> for PcsBasefoldQueryOpenAir {}

impl<AB> Air<AB> for PcsBasefoldQueryOpenAir
where
    AB: AirBuilder + InteractionBuilder,
    <AB::Expr as PrimeCharacteristicRing>::PrimeSubfield: BinomiallyExtendable<{ D_EF }>,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local_row = main.row_slice(0).expect("main row exists");
        let local: &PcsBasefoldQueryOpenCols<AB::Var> = (*local_row).borrow();
        builder.assert_bool(local.is_enabled);
        builder.assert_bool(local.is_last_for_height);

        self.batch_coeff_bus.lookup_key(
            builder,
            local.proof_idx,
            PcsBatchCoeffMessage {
                global_coeff_idx: local.global_coeff_idx.into(),
                coeff: local.coeff.map(Into::into),
            },
            local.is_enabled,
        );

        let product = recursion_circuit::utils::ext_field_multiply(local.coeff, local.opened_value);
        let expected = ext_add(local.acc_in, product);
        assert_array_eq(&mut builder.when(local.is_enabled), local.acc_out, expected);
        self.basefold_query_bus.send(
            builder,
            local.proof_idx,
            PcsBasefoldQueryMessage {
                query_idx: local.query_idx.into(),
                stage: AB::Expr::from_usize(PcsBasefoldQueryStage::ReducedOpening.as_usize()),
                round: local.log2_height.into(),
                value: local.acc_out.map(Into::into),
            },
            local.is_enabled * local.is_last_for_height,
        );
        self.base_input_opening_bus.send(
            builder,
            local.proof_idx,
            PcsBaseInputOpeningMessage {
                query_idx: local.query_idx.into(),
                opening_idx: local.opening_idx.into(),
                reduced_index: local.reduced_index.into(),
                value_idx: local.value_idx.into(),
                elem_idx: local.elem_idx.into(),
                log2_height: local.log2_height.into(),
                opened_value: local.opened_value.map(Into::into),
            },
            local.is_enabled,
        );
    }
}

#[repr(C)]
#[derive(AlignedBorrow, Debug)]
pub struct PcsBasefoldCommitPhaseQueryCols<T> {
    pub is_enabled: T,
    pub proof_idx: T,
    pub query_idx: T,
    pub round: T,
    pub query_value: T,
    pub idx_in: T,
    pub idx_out: T,
    pub log2_height: T,
    pub is_first: T,
    pub has_reduced_opening: T,
    pub folded_idx: T,
    pub is_last: T,
    pub reduced_opening: [T; D_EF],
    pub folded_in: [T; D_EF],
    pub sibling_value: [T; D_EF],
    pub challenge: [T; D_EF],
    pub coeff: [T; D_EF],
    pub folded_out: [T; D_EF],
}

pub struct PcsBasefoldCommitPhaseQueryAir {
    pub basefold_query_bus: PcsBasefoldQueryBus,
    pub commit_phase_leaf_bus: PcsCommitPhaseLeafBus,
    pub fold_challenge_bus: PcsFoldChallengeBus,
}

impl<F: Field> BaseAir<F> for PcsBasefoldCommitPhaseQueryAir {
    fn width(&self) -> usize {
        PcsBasefoldCommitPhaseQueryCols::<F>::width()
    }
}

impl<F: Field> BaseAirWithPublicValues<F> for PcsBasefoldCommitPhaseQueryAir {}
impl<F: Field> PartitionedBaseAir<F> for PcsBasefoldCommitPhaseQueryAir {}

impl<AB> Air<AB> for PcsBasefoldCommitPhaseQueryAir
where
    AB: AirBuilder + InteractionBuilder,
    <AB::Expr as PrimeCharacteristicRing>::PrimeSubfield: BinomiallyExtendable<{ D_EF }>,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local_row = main.row_slice(0).expect("main row exists");
        let local: &PcsBasefoldCommitPhaseQueryCols<AB::Var> = (*local_row).borrow();
        let next_row = main.row_slice(1).expect("next row exists");
        let next: &PcsBasefoldCommitPhaseQueryCols<AB::Var> = (*next_row).borrow();
        builder.assert_bool(local.is_enabled);
        builder.assert_bool(local.is_first);
        builder.assert_bool(local.has_reduced_opening);
        builder.assert_bool(local.folded_idx);
        builder.assert_bool(local.is_last);

        builder.when(local.is_enabled).assert_eq(
            local.idx_in,
            local.folded_idx + local.idx_out * AB::Expr::TWO,
        );
        let same_query_next = local.is_enabled * next.is_enabled * (AB::Expr::ONE - local.is_last);
        builder
            .when(same_query_next.clone())
            .assert_eq(next.query_idx, local.query_idx);
        builder
            .when(same_query_next.clone())
            .assert_eq(next.idx_in, local.idx_out);

        let query_value = core::array::from_fn(|i| {
            if i == 0 {
                local.query_value.into()
            } else {
                AB::Expr::ZERO
            }
        });
        self.basefold_query_bus.receive(
            builder,
            local.proof_idx,
            PcsBasefoldQueryMessage {
                query_idx: local.query_idx.into(),
                stage: AB::Expr::from_usize(PcsBasefoldQueryStage::QueryIndex.as_usize()),
                round: AB::Expr::ZERO,
                value: query_value,
            },
            local.is_enabled * local.is_first,
        );
        builder
            .when(local.is_enabled * local.is_first)
            .assert_eq(local.idx_in, local.query_value);

        self.basefold_query_bus.receive(
            builder,
            local.proof_idx,
            PcsBasefoldQueryMessage {
                query_idx: local.query_idx.into(),
                stage: AB::Expr::from_usize(PcsBasefoldQueryStage::ReducedOpening.as_usize()),
                round: local.log2_height.into(),
                value: local.reduced_opening.map(Into::into),
            },
            local.is_enabled * local.has_reduced_opening,
        );
        self.fold_challenge_bus.lookup_key(
            builder,
            local.proof_idx,
            PcsFoldChallengeMessage {
                sumcheck_idx: AB::Expr::from_usize(8_000_000),
                round: local.round.into(),
                challenge: local.challenge.map(Into::into),
            },
            local.is_enabled,
        );

        let selected = ext_add(local.folded_in, local.reduced_opening);
        let left = core::array::from_fn(|i| {
            local.folded_idx * local.sibling_value[i]
                + (AB::Expr::ONE - local.folded_idx) * selected[i].clone()
        });
        let right = core::array::from_fn(|i| {
            local.folded_idx * selected[i].clone()
                + (AB::Expr::ONE - local.folded_idx) * local.sibling_value[i]
        });
        let inv_2_scalar =
            <AB::Expr as PrimeCharacteristicRing>::PrimeSubfield::from_usize(2).inverse();
        let mut inv_2 = core::array::from_fn(|_| AB::Expr::ZERO);
        inv_2[0] = AB::Expr::from_prime_subfield(inv_2_scalar);
        let leaf_left = left.clone();
        let leaf_right = right.clone();
        let sum_lr: [AB::Expr; D_EF] = ext_add(left.clone(), right.clone());
        let diff_lr: [AB::Expr; D_EF] = ext_sub(left, right);
        let lo: [AB::Expr; D_EF] = recursion_circuit::utils::ext_field_multiply(sum_lr, inv_2);
        let hi: [AB::Expr; D_EF] =
            recursion_circuit::utils::ext_field_multiply(diff_lr, local.coeff);
        let diff: [AB::Expr; D_EF] = ext_sub(hi, lo.clone());
        let folded: [AB::Expr; D_EF] = ext_add(
            lo,
            recursion_circuit::utils::ext_field_multiply(local.challenge, diff),
        );
        assert_array_eq(
            &mut builder.when(local.is_enabled),
            local.folded_out,
            folded,
        );
        self.commit_phase_leaf_bus.send(
            builder,
            local.proof_idx,
            PcsCommitPhaseLeafMessage {
                query_idx: local.query_idx.into(),
                round: local.round.into(),
                leaf_idx: local.idx_out.into(),
                left: leaf_left.map(Into::into),
                right: leaf_right.map(Into::into),
            },
            local.is_enabled,
        );
        self.basefold_query_bus.send(
            builder,
            local.proof_idx,
            PcsBasefoldQueryMessage {
                query_idx: local.query_idx.into(),
                stage: AB::Expr::from_usize(PcsBasefoldQueryStage::FinalFolded.as_usize()),
                round: AB::Expr::ZERO,
                value: local.folded_out.map(Into::into),
            },
            local.is_enabled * local.is_last,
        );
    }
}

#[repr(C)]
#[derive(AlignedBorrow, Debug)]
pub struct PcsBasefoldFinalCodewordCols<T> {
    pub is_enabled: T,
    pub proof_idx: T,
    pub query_idx: T,
    pub elem_idx: T,
    pub final_tidx: T,
    pub is_first: T,
    pub is_last: T,
    pub final_value: [T; D_EF],
    pub coeff: [T; D_EF],
    pub acc_in: [T; D_EF],
    pub acc_out: [T; D_EF],
    pub folded: [T; D_EF],
}

pub struct PcsBasefoldFinalCodewordAir {
    pub basefold_query_bus: PcsBasefoldQueryBus,
    pub final_message_bus: PcsFinalMessageBus,
}

impl<F: Field> BaseAir<F> for PcsBasefoldFinalCodewordAir {
    fn width(&self) -> usize {
        PcsBasefoldFinalCodewordCols::<F>::width()
    }
}

impl<F: Field> BaseAirWithPublicValues<F> for PcsBasefoldFinalCodewordAir {}
impl<F: Field> PartitionedBaseAir<F> for PcsBasefoldFinalCodewordAir {}

impl<AB> Air<AB> for PcsBasefoldFinalCodewordAir
where
    AB: AirBuilder + InteractionBuilder,
    <AB::Expr as PrimeCharacteristicRing>::PrimeSubfield: BinomiallyExtendable<{ D_EF }>,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local_row = main.row_slice(0).expect("main row exists");
        let next_row = main.row_slice(1).expect("next row exists");
        let local: &PcsBasefoldFinalCodewordCols<AB::Var> = (*local_row).borrow();
        let next: &PcsBasefoldFinalCodewordCols<AB::Var> = (*next_row).borrow();
        builder.assert_bool(local.is_enabled);
        builder.assert_bool(local.is_first);
        builder.assert_bool(local.is_last);
        // BasefoldRSParams has basecode_log = 0, so the final codeword is
        // reconstructed from one base-code coordinate with coefficient 1.
        builder.when(local.is_enabled).assert_zero(local.elem_idx);
        assert_array_eq(
            &mut builder.when(local.is_enabled),
            local.coeff,
            [
                AB::Expr::ONE,
                AB::Expr::ZERO,
                AB::Expr::ZERO,
                AB::Expr::ZERO,
            ],
        );
        assert_array_eq(
            &mut builder.when(local.is_enabled * local.is_first),
            local.acc_in,
            [AB::Expr::ZERO; D_EF],
        );
        self.basefold_query_bus.receive(
            builder,
            local.proof_idx,
            PcsBasefoldQueryMessage {
                query_idx: local.query_idx.into(),
                stage: AB::Expr::from_usize(PcsBasefoldQueryStage::FinalCodewordStart.as_usize()),
                round: AB::Expr::ZERO,
                value: [AB::Expr::ZERO; D_EF],
            },
            local.is_enabled * local.is_first,
        );

        self.final_message_bus.lookup_key(
            builder,
            local.proof_idx,
            PcsFinalMessageMessage {
                tidx: local.final_tidx.into(),
                value: local.final_value.map(Into::into),
            },
            local.is_enabled,
        );

        let product = recursion_circuit::utils::ext_field_multiply(local.coeff, local.final_value);
        let expected = ext_add(local.acc_in, product);
        assert_array_eq(&mut builder.when(local.is_enabled), local.acc_out, expected);
        assert_array_eq(
            &mut builder.when(local.is_enabled * local.is_last),
            local.acc_out,
            local.folded,
        );
        let continue_selector = local.is_enabled * (AB::Expr::ONE - local.is_last.into());
        builder
            .when(continue_selector.clone())
            .assert_one(next.is_enabled);
        builder
            .when(continue_selector.clone())
            .assert_eq(next.proof_idx, local.proof_idx);
        builder
            .when(continue_selector.clone())
            .assert_eq(next.query_idx, local.query_idx);
        builder.when(continue_selector.clone()).assert_eq(
            next.final_tidx,
            local.final_tidx + AB::Expr::from_usize(D_EF),
        );
        assert_array_eq(
            &mut builder.when(continue_selector),
            next.acc_in,
            local.acc_out.map(Into::into),
        );
        self.basefold_query_bus.receive(
            builder,
            local.proof_idx,
            PcsBasefoldQueryMessage {
                query_idx: local.query_idx.into(),
                stage: AB::Expr::from_usize(PcsBasefoldQueryStage::FinalFolded.as_usize()),
                round: AB::Expr::ZERO,
                value: local.folded.map(Into::into),
            },
            local.is_enabled * local.is_last,
        );
    }
}

#[repr(C)]
#[derive(AlignedBorrow, Debug)]
pub struct PcsTranscriptValueCols<T> {
    pub is_enabled: T,
    pub proof_idx: T,
    pub idx: T,
    pub tidx: T,
    pub is_sample: T,
    pub is_ext: T,
    pub is_final_message: T,
    pub is_query_sample: T,
    pub is_batch_alpha: T,
    pub is_basefold_eval: T,
    pub is_jagged_f_at_rho: T,
    pub transcript_ext_lookup_count: T,
    pub value: [T; D_EF],
}

pub struct PcsTranscriptValueAir {
    pub transcript_bus: TranscriptBus,
    pub final_message_bus: PcsFinalMessageBus,
    pub query_sample_bus: PcsQuerySampleBus,
    pub batch_alpha_bus: PcsBatchAlphaBus,
    pub basefold_eval_bus: PcsBasefoldEvalBus,
    pub transcript_ext_bus: PcsTranscriptExtBus,
    pub jagged_f_eval_bus: PcsJaggedFEvalBus,
    pub final_message_lookup_count: usize,
}

impl<F: Field> BaseAir<F> for PcsTranscriptValueAir {
    fn width(&self) -> usize {
        PcsTranscriptValueCols::<F>::width()
    }
}

impl<F: Field> BaseAirWithPublicValues<F> for PcsTranscriptValueAir {}
impl<F: Field> PartitionedBaseAir<F> for PcsTranscriptValueAir {}

impl<AB: AirBuilder + InteractionBuilder> Air<AB> for PcsTranscriptValueAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local_row = main.row_slice(0).expect("main row exists");
        let local: &PcsTranscriptValueCols<AB::Var> = (*local_row).borrow();
        builder.assert_bool(local.is_enabled);
        builder.assert_bool(local.is_sample);
        builder.assert_bool(local.is_ext);
        builder.assert_bool(local.is_final_message);
        builder.assert_bool(local.is_query_sample);
        builder.assert_bool(local.is_batch_alpha);
        builder.assert_bool(local.is_basefold_eval);
        builder.assert_bool(local.is_jagged_f_at_rho);
        builder
            .when(local.is_final_message)
            .assert_one(local.is_enabled);
        builder
            .when(local.is_final_message)
            .assert_zero(local.is_sample);
        builder
            .when(local.is_final_message)
            .assert_one(local.is_ext);
        builder
            .when(local.is_query_sample)
            .assert_one(local.is_enabled);
        builder
            .when(local.is_query_sample)
            .assert_one(local.is_sample);
        builder
            .when(local.is_query_sample)
            .assert_zero(local.is_ext);
        for i in 1..D_EF {
            builder
                .when(local.is_query_sample)
                .assert_zero(local.value[i]);
        }
        for i in 0..D_EF {
            let selector = local.is_enabled
                * if i == 0 {
                    AB::Expr::ONE
                } else {
                    local.is_ext.into()
                };
            self.transcript_bus.receive(
                builder,
                local.proof_idx,
                TranscriptBusMessage {
                    tidx: local.tidx + AB::Expr::from_usize(i),
                    value: local.value[i].into(),
                    is_sample: local.is_sample.into(),
                },
                selector,
            );
        }
        self.final_message_bus.add_key_with_lookups(
            builder,
            local.proof_idx,
            PcsFinalMessageMessage {
                tidx: local.tidx.into(),
                value: local.value.map(Into::into),
            },
            local.is_enabled
                * local.is_final_message
                * AB::Expr::from_usize(self.final_message_lookup_count),
        );
        self.query_sample_bus.add_key_with_lookups(
            builder,
            local.proof_idx,
            PcsQuerySampleMessage {
                tidx: local.tidx.into(),
                value: local.value[0].into(),
            },
            local.is_enabled * local.is_query_sample,
        );
        self.batch_alpha_bus.add_key_with_lookups(
            builder,
            local.proof_idx,
            PcsBatchAlphaMessage {
                tidx: local.tidx.into(),
                alpha: local.value.map(Into::into),
            },
            local.is_enabled * local.is_batch_alpha,
        );
        self.basefold_eval_bus.add_key_with_lookups(
            builder,
            local.proof_idx,
            PcsBasefoldEvalMessage {
                tidx: local.tidx.into(),
                value: local.value.map(Into::into),
            },
            local.is_enabled * local.is_basefold_eval * AB::Expr::from_usize(2),
        );
        self.transcript_ext_bus.add_key_with_lookups(
            builder,
            local.proof_idx,
            PcsTranscriptExtMessage {
                tidx: local.tidx.into(),
                value: local.value.map(Into::into),
            },
            local.is_enabled * local.transcript_ext_lookup_count,
        );
        self.jagged_f_eval_bus.add_key_with_lookups(
            builder,
            local.proof_idx,
            PcsJaggedFEvalMessage {
                sumcheck_idx: local.idx.into(),
                tidx: local.tidx.into(),
                value: local.value.map(Into::into),
            },
            local.is_enabled * local.is_jagged_f_at_rho,
        );
    }
}

#[repr(C)]
#[derive(AlignedBorrow, Debug)]
pub struct PcsSumcheckCols<T> {
    pub is_enabled: T,
    pub proof_idx: T,
    pub idx: T,
    pub round: T,
    pub is_first: T,
    pub is_last: T,
    pub ev_tidx: T,
    pub challenge_tidx: T,
    pub fold_challenge_lookup_count: T,
    pub ev1: [T; D_EF],
    pub ev2: [T; D_EF],
    pub claim_in: [T; D_EF],
    pub claim_out: [T; D_EF],
    pub challenge: [T; D_EF],
}

pub struct PcsSumcheckAir {
    pub sumcheck_input_bus: PcsSumcheckInputBus,
    pub transcript_bus: TranscriptBus,
    pub sumcheck_output_bus: PcsSumcheckOutputBus,
    pub fold_challenge_bus: PcsFoldChallengeBus,
}

impl<F: Field> BaseAir<F> for PcsSumcheckAir {
    fn width(&self) -> usize {
        PcsSumcheckCols::<F>::width()
    }
}

impl<F: Field> BaseAirWithPublicValues<F> for PcsSumcheckAir {}
impl<F: Field> PartitionedBaseAir<F> for PcsSumcheckAir {}

impl<AB> Air<AB> for PcsSumcheckAir
where
    AB: AirBuilder + InteractionBuilder,
    <AB::Expr as PrimeCharacteristicRing>::PrimeSubfield: BinomiallyExtendable<{ D_EF }>,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let (local_row, next_row) = (
            main.row_slice(0).expect("main row exists"),
            main.row_slice(1).expect("next row exists"),
        );
        let local: &PcsSumcheckCols<AB::Var> = (*local_row).borrow();
        let next: &PcsSumcheckCols<AB::Var> = (*next_row).borrow();

        builder.assert_bool(local.is_enabled);
        builder.assert_bool(local.is_first);
        builder.assert_bool(local.is_last);
        let same_sumcheck = local.is_enabled
            * next.is_enabled
            * (AB::Expr::ONE - next.is_first)
            * (AB::Expr::ONE - local.is_last);
        builder
            .when(same_sumcheck.clone())
            .assert_eq(next.idx, local.idx);
        builder
            .when(same_sumcheck.clone())
            .assert_eq(next.round, local.round + AB::Expr::ONE);
        assert_array_eq(
            &mut builder.when(same_sumcheck),
            local.claim_out,
            next.claim_in,
        );
        self.sumcheck_input_bus.receive(
            builder,
            local.proof_idx,
            PcsSumcheckInputMessage {
                idx: local.idx.into(),
                claim: local.claim_in.map(Into::into),
            },
            local.is_enabled * local.is_first,
        );

        let ev0 = ext_sub(local.claim_in, local.ev1);
        let claim_out = interpolate_quad_at_012(ev0, local.ev1, local.ev2, local.challenge);
        assert_array_eq(
            &mut builder.when(local.is_enabled),
            local.claim_out,
            claim_out,
        );
        self.sumcheck_output_bus.send(
            builder,
            local.proof_idx,
            PcsSumcheckOutputMessage {
                idx: local.idx.into(),
                claim: local.claim_out.map(Into::into),
            },
            local.is_enabled * local.is_last,
        );

        for i in 0..D_EF {
            self.transcript_bus.receive(
                builder,
                local.proof_idx,
                TranscriptBusMessage {
                    tidx: local.ev_tidx + AB::Expr::from_usize(i),
                    value: local.ev1[i].into(),
                    is_sample: AB::Expr::ZERO,
                },
                local.is_enabled,
            );
            self.transcript_bus.receive(
                builder,
                local.proof_idx,
                TranscriptBusMessage {
                    tidx: local.ev_tidx + AB::Expr::from_usize(D_EF + i),
                    value: local.ev2[i].into(),
                    is_sample: AB::Expr::ZERO,
                },
                local.is_enabled,
            );
            self.transcript_bus.receive(
                builder,
                local.proof_idx,
                TranscriptBusMessage {
                    tidx: local.challenge_tidx + AB::Expr::from_usize(i),
                    value: local.challenge[i].into(),
                    is_sample: AB::Expr::ONE,
                },
                local.is_enabled,
            );
        }
        self.fold_challenge_bus.add_key_with_lookups(
            builder,
            local.proof_idx,
            PcsFoldChallengeMessage {
                sumcheck_idx: local.idx.into(),
                round: local.round.into(),
                challenge: local.challenge.map(Into::into),
            },
            local.is_enabled * local.fold_challenge_lookup_count,
        );
    }
}

#[repr(C)]
#[derive(AlignedBorrow, Debug)]
pub struct PcsBasefoldInitialClaimCols<T> {
    pub is_enabled: T,
    pub proof_idx: T,
    pub sumcheck_idx: T,
    pub term_idx: T,
    pub is_first: T,
    pub is_last: T,
    pub global_coeff_idx: T,
    pub eval_tidx: T,
    pub eval: [T; D_EF],
    pub coeff: [T; D_EF],
    pub scale: [T; D_EF],
    pub acc_in: [T; D_EF],
    pub acc_out: [T; D_EF],
}

pub struct PcsBasefoldInitialClaimAir {
    pub basefold_eval_bus: PcsBasefoldEvalBus,
    pub batch_coeff_bus: PcsBatchCoeffBus,
    pub sumcheck_input_bus: PcsSumcheckInputBus,
}

impl<F: Field> BaseAir<F> for PcsBasefoldInitialClaimAir {
    fn width(&self) -> usize {
        PcsBasefoldInitialClaimCols::<F>::width()
    }
}

impl<F: Field> BaseAirWithPublicValues<F> for PcsBasefoldInitialClaimAir {}
impl<F: Field> PartitionedBaseAir<F> for PcsBasefoldInitialClaimAir {}

impl<AB> Air<AB> for PcsBasefoldInitialClaimAir
where
    AB: AirBuilder + InteractionBuilder,
    <AB::Expr as PrimeCharacteristicRing>::PrimeSubfield: BinomiallyExtendable<{ D_EF }>,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local_row = main.row_slice(0).expect("main row exists");
        let next_row = main.row_slice(1).expect("next row exists");
        let local: &PcsBasefoldInitialClaimCols<AB::Var> = (*local_row).borrow();
        let next: &PcsBasefoldInitialClaimCols<AB::Var> = (*next_row).borrow();
        builder.assert_bool(local.is_enabled);
        builder.assert_bool(local.is_first);
        builder.assert_bool(local.is_last);
        let zero = core::array::from_fn(|_| AB::Expr::ZERO);
        assert_array_eq(
            &mut builder.when(local.is_enabled * local.is_first),
            local.acc_in,
            zero,
        );

        let continues = local.is_enabled * (AB::Expr::ONE - local.is_last);
        builder
            .when_transition()
            .when(continues.clone())
            .assert_one(next.is_enabled);
        builder
            .when_transition()
            .when(continues.clone())
            .assert_eq(next.proof_idx, local.proof_idx);
        builder
            .when_transition()
            .when(continues.clone())
            .assert_eq(next.sumcheck_idx, local.sumcheck_idx);
        builder
            .when_transition()
            .when(continues)
            .assert_eq(next.term_idx, local.term_idx + AB::Expr::ONE);
        assert_array_eq(
            &mut builder
                .when_transition()
                .when(local.is_enabled * (AB::Expr::ONE - local.is_last)),
            next.acc_in,
            local.acc_out,
        );

        let coeff_eval = recursion_circuit::utils::ext_field_multiply(local.coeff, local.eval);
        let term = recursion_circuit::utils::ext_field_multiply(coeff_eval, local.scale);
        let expected_acc = ext_add(local.acc_in, term);
        assert_array_eq(
            &mut builder.when(local.is_enabled),
            local.acc_out,
            expected_acc,
        );

        self.batch_coeff_bus.lookup_key(
            builder,
            local.proof_idx,
            PcsBatchCoeffMessage {
                global_coeff_idx: local.global_coeff_idx.into(),
                coeff: local.coeff.map(Into::into),
            },
            local.is_enabled,
        );
        self.basefold_eval_bus.lookup_key(
            builder,
            local.proof_idx,
            PcsBasefoldEvalMessage {
                tidx: local.eval_tidx.into(),
                value: local.eval.map(Into::into),
            },
            local.is_enabled,
        );
        self.sumcheck_input_bus.send(
            builder,
            local.proof_idx,
            PcsSumcheckInputMessage {
                idx: local.sumcheck_idx.into(),
                claim: local.acc_out.map(Into::into),
            },
            local.is_enabled * local.is_last,
        );
    }
}

#[repr(C)]
#[derive(AlignedBorrow, Debug)]
pub struct PcsJaggedAssistInputCols<T> {
    pub is_enabled: T,
    pub proof_idx: T,
    pub round_idx: T,
    pub sumcheck_idx: T,
    pub f_tidx: T,
    pub f_at_rho: [T; D_EF],
}

pub struct PcsJaggedAssistInputAir {
    pub jagged_f_eval_bus: PcsJaggedFEvalBus,
    pub sumcheck_input_bus: PcsSumcheckInputBus,
}

impl<F: Field> BaseAir<F> for PcsJaggedAssistInputAir {
    fn width(&self) -> usize {
        PcsJaggedAssistInputCols::<F>::width()
    }
}

impl<F: Field> BaseAirWithPublicValues<F> for PcsJaggedAssistInputAir {}
impl<F: Field> PartitionedBaseAir<F> for PcsJaggedAssistInputAir {}

impl<AB: AirBuilder + InteractionBuilder> Air<AB> for PcsJaggedAssistInputAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local_row = main.row_slice(0).expect("main row exists");
        let local: &PcsJaggedAssistInputCols<AB::Var> = (*local_row).borrow();
        builder.assert_bool(local.is_enabled);
        builder.when(local.is_enabled).assert_eq(
            local.sumcheck_idx,
            local.round_idx + local.round_idx + AB::Expr::ONE,
        );
        self.jagged_f_eval_bus.lookup_key(
            builder,
            local.proof_idx,
            PcsJaggedFEvalMessage {
                sumcheck_idx: local.sumcheck_idx.into(),
                tidx: local.f_tidx.into(),
                value: local.f_at_rho.map(Into::into),
            },
            local.is_enabled,
        );
        self.sumcheck_input_bus.send(
            builder,
            local.proof_idx,
            PcsSumcheckInputMessage {
                idx: local.sumcheck_idx.into(),
                claim: local.f_at_rho.map(Into::into),
            },
            local.is_enabled,
        );
    }
}

#[repr(C)]
#[derive(AlignedBorrow, Debug)]
pub struct PcsJaggedClaimCols<T> {
    pub is_enabled: T,
    pub proof_idx: T,
    pub round_idx: T,
    pub sumcheck_idx: T,
    pub term_idx: T,
    pub is_first: T,
    pub is_last: T,
    pub opening_idx: T,
    pub commit_kind: T,
    pub eval_idx: T,
    pub main_idx: T,
    pub main_eval_idx: T,
    pub z_col_tidx: T,
    pub eval: [T; D_EF],
    pub eq_col: [T; D_EF],
    pub tail_zero: [T; D_EF],
    pub acc_in: [T; D_EF],
    pub acc_out: [T; D_EF],
}

pub struct PcsJaggedClaimAir {
    pub sumcheck_input_bus: PcsSumcheckInputBus,
    pub opening_eval_bus: PcsOpeningEvalBus,
    pub eq_product_bus: PcsEqProductBus,
    pub suffix_product_bus: PcsSuffixProductBus,
}

impl<F: Field> BaseAir<F> for PcsJaggedClaimAir {
    fn width(&self) -> usize {
        PcsJaggedClaimCols::<F>::width()
    }
}

impl<F: Field> BaseAirWithPublicValues<F> for PcsJaggedClaimAir {}
impl<F: Field> PartitionedBaseAir<F> for PcsJaggedClaimAir {}

impl<AB> Air<AB> for PcsJaggedClaimAir
where
    AB: AirBuilder + InteractionBuilder,
    <AB::Expr as PrimeCharacteristicRing>::PrimeSubfield: BinomiallyExtendable<{ D_EF }>,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local_row = main.row_slice(0).expect("main row exists");
        let next_row = main.row_slice(1).expect("next row exists");
        let local: &PcsJaggedClaimCols<AB::Var> = (*local_row).borrow();
        let next: &PcsJaggedClaimCols<AB::Var> = (*next_row).borrow();
        builder.assert_bool(local.is_enabled);
        builder.assert_bool(local.is_first);
        builder.assert_bool(local.is_last);
        builder
            .when(local.is_enabled)
            .assert_eq(local.sumcheck_idx, local.round_idx + local.round_idx);
        builder
            .when(local.is_enabled * local.is_first)
            .assert_zero(local.term_idx);
        let zero = core::array::from_fn(|_| AB::Expr::ZERO);
        assert_array_eq(
            &mut builder.when(local.is_enabled * local.is_first),
            local.acc_in,
            zero,
        );

        let continues = local.is_enabled * (AB::Expr::ONE - local.is_last);
        builder
            .when_transition()
            .when(continues.clone())
            .assert_one(next.is_enabled);
        builder
            .when_transition()
            .when(continues.clone())
            .assert_eq(next.proof_idx, local.proof_idx);
        builder
            .when_transition()
            .when(continues.clone())
            .assert_eq(next.round_idx, local.round_idx);
        builder
            .when_transition()
            .when(continues.clone())
            .assert_eq(next.sumcheck_idx, local.sumcheck_idx);
        builder
            .when_transition()
            .when(continues.clone())
            .assert_eq(next.term_idx, local.term_idx + AB::Expr::ONE);
        builder
            .when_transition()
            .when(continues.clone())
            .assert_eq(next.z_col_tidx, local.z_col_tidx);
        assert_array_eq(
            &mut builder.when_transition().when(continues),
            next.acc_in,
            local.acc_out,
        );

        let opened_eval = recursion_circuit::utils::ext_field_multiply(local.tail_zero, local.eval);
        let term = recursion_circuit::utils::ext_field_multiply(local.eq_col, opened_eval.clone());
        let expected_acc = ext_add(local.acc_in, term);
        assert_array_eq(
            &mut builder.when(local.is_enabled),
            local.acc_out,
            expected_acc,
        );

        self.sumcheck_input_bus.send(
            builder,
            local.proof_idx,
            PcsSumcheckInputMessage {
                idx: local.sumcheck_idx.into(),
                claim: local.acc_out.map(Into::into),
            },
            local.is_enabled * local.is_last,
        );
        self.eq_product_bus.lookup_key(
            builder,
            local.proof_idx,
            PcsEqProductMessage {
                kind: AB::Expr::from_usize(PcsEqProductKind::JaggedClaim.as_usize()),
                round_idx: local.round_idx.into(),
                term_idx: local.term_idx.into(),
                value: local.eq_col.map(Into::into),
            },
            local.is_enabled,
        );
        self.suffix_product_bus.lookup_key(
            builder,
            local.proof_idx,
            PcsSuffixProductMessage {
                round_idx: local.round_idx.into(),
                term_idx: local.term_idx.into(),
                value: local.tail_zero.map(Into::into),
            },
            local.is_enabled,
        );
        self.opening_eval_bus.lookup_key(
            builder,
            local.proof_idx,
            PcsOpeningEvalMessage {
                opening_idx: local.opening_idx.into(),
                commit_kind: local.commit_kind.into(),
                eval_idx: local.eval_idx.into(),
                value: opened_eval.map(Into::into),
            },
            local.is_enabled,
        );
    }
}

#[repr(C)]
#[derive(AlignedBorrow, Debug)]
pub struct PcsSumcheckInputCols<T> {
    pub is_enabled: T,
    pub proof_idx: T,
    pub idx: T,
    pub claim: [T; D_EF],
}

pub struct PcsSumcheckInputAir {
    pub sumcheck_input_bus: PcsSumcheckInputBus,
}

impl<F: Field> BaseAir<F> for PcsSumcheckInputAir {
    fn width(&self) -> usize {
        PcsSumcheckInputCols::<F>::width()
    }
}

impl<F: Field> BaseAirWithPublicValues<F> for PcsSumcheckInputAir {}
impl<F: Field> PartitionedBaseAir<F> for PcsSumcheckInputAir {}

impl<AB: AirBuilder + InteractionBuilder> Air<AB> for PcsSumcheckInputAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local_row = main.row_slice(0).expect("main row exists");
        let local: &PcsSumcheckInputCols<AB::Var> = (*local_row).borrow();
        builder.assert_bool(local.is_enabled);
        self.sumcheck_input_bus.send(
            builder,
            local.proof_idx,
            PcsSumcheckInputMessage {
                idx: local.idx.into(),
                claim: local.claim.map(Into::into),
            },
            local.is_enabled,
        );
    }
}

#[repr(C)]
#[derive(AlignedBorrow, Debug)]
pub struct PcsBatchCoeffCols<T> {
    pub is_enabled: T,
    pub proof_idx: T,
    pub global_coeff_idx: T,
    pub alpha_tidx: T,
    pub lookup_count: T,
    pub is_first: T,
    pub is_last: T,
    pub alpha: [T; D_EF],
    pub coeff: [T; D_EF],
    pub next_coeff: [T; D_EF],
}

pub struct PcsBatchCoeffAir {
    pub batch_alpha_bus: PcsBatchAlphaBus,
    pub batch_coeff_bus: PcsBatchCoeffBus,
}

impl<F: Field> BaseAir<F> for PcsBatchCoeffAir {
    fn width(&self) -> usize {
        PcsBatchCoeffCols::<F>::width()
    }
}

impl<F: Field> BaseAirWithPublicValues<F> for PcsBatchCoeffAir {}
impl<F: Field> PartitionedBaseAir<F> for PcsBatchCoeffAir {}

impl<AB> Air<AB> for PcsBatchCoeffAir
where
    AB: AirBuilder + InteractionBuilder,
    <AB::Expr as PrimeCharacteristicRing>::PrimeSubfield: BinomiallyExtendable<{ D_EF }>,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local_row = main.row_slice(0).expect("main row exists");
        let next_row = main.row_slice(1).expect("next row exists");
        let local: &PcsBatchCoeffCols<AB::Var> = (*local_row).borrow();
        let next: &PcsBatchCoeffCols<AB::Var> = (*next_row).borrow();

        builder.assert_bool(local.is_enabled);
        builder.assert_bool(local.is_first);
        builder.assert_bool(local.is_last);
        builder
            .when(local.is_enabled * local.is_first)
            .assert_zero(local.global_coeff_idx);
        let one = core::array::from_fn(|i| {
            if i == 0 {
                AB::Expr::ONE
            } else {
                AB::Expr::ZERO
            }
        });
        assert_array_eq(
            &mut builder.when(local.is_enabled * local.is_first),
            local.coeff,
            one,
        );

        let expected_next = recursion_circuit::utils::ext_field_multiply(local.coeff, local.alpha);
        assert_array_eq(
            &mut builder.when(local.is_enabled),
            local.next_coeff,
            expected_next,
        );

        let continues = local.is_enabled * (AB::Expr::ONE - local.is_last);
        builder
            .when_transition()
            .when(continues.clone())
            .assert_one(next.is_enabled);
        builder
            .when_transition()
            .when(continues.clone())
            .assert_eq(next.proof_idx, local.proof_idx);
        builder.when_transition().when(continues.clone()).assert_eq(
            next.global_coeff_idx,
            local.global_coeff_idx + AB::Expr::ONE,
        );
        builder
            .when_transition()
            .when(continues.clone())
            .assert_eq(next.alpha_tidx, local.alpha_tidx);
        assert_array_eq(
            &mut builder.when_transition().when(continues.clone()),
            next.alpha,
            local.alpha,
        );
        assert_array_eq(
            &mut builder.when_transition().when(continues),
            next.coeff,
            local.next_coeff,
        );

        self.batch_alpha_bus.lookup_key(
            builder,
            local.proof_idx,
            PcsBatchAlphaMessage {
                tidx: local.alpha_tidx.into(),
                alpha: local.alpha.map(Into::into),
            },
            local.is_enabled * local.is_first,
        );
        self.batch_coeff_bus.add_key_with_lookups(
            builder,
            local.proof_idx,
            PcsBatchCoeffMessage {
                global_coeff_idx: local.global_coeff_idx.into(),
                coeff: local.coeff.map(Into::into),
            },
            local.is_enabled * local.lookup_count,
        );
    }
}

#[repr(C)]
#[derive(AlignedBorrow, Debug)]
pub struct PcsJaggedQEvalCols<T> {
    pub is_enabled: T,
    pub proof_idx: T,
    pub round_idx: T,
    pub sumcheck_idx: T,
    pub term_idx: T,
    pub is_first: T,
    pub is_last: T,
    pub col_tidx: T,
    pub col_eval: [T; D_EF],
    pub eq_rho_col: [T; D_EF],
    pub acc_in: [T; D_EF],
    pub acc_out: [T; D_EF],
    pub q_eval: [T; D_EF],
    pub f_at_rho: [T; D_EF],
    pub sumcheck_final: [T; D_EF],
}

pub struct PcsJaggedQEvalAir {
    pub basefold_eval_bus: PcsBasefoldEvalBus,
    pub eq_product_bus: PcsEqProductBus,
    pub sumcheck_output_bus: PcsSumcheckOutputBus,
}

impl<F: Field> BaseAir<F> for PcsJaggedQEvalAir {
    fn width(&self) -> usize {
        PcsJaggedQEvalCols::<F>::width()
    }
}

impl<F: Field> BaseAirWithPublicValues<F> for PcsJaggedQEvalAir {}
impl<F: Field> PartitionedBaseAir<F> for PcsJaggedQEvalAir {}

impl<AB> Air<AB> for PcsJaggedQEvalAir
where
    AB: AirBuilder + InteractionBuilder,
    <AB::Expr as PrimeCharacteristicRing>::PrimeSubfield: BinomiallyExtendable<{ D_EF }>,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local_row = main.row_slice(0).expect("main row exists");
        let next_row = main.row_slice(1).expect("next row exists");
        let local: &PcsJaggedQEvalCols<AB::Var> = (*local_row).borrow();
        let next: &PcsJaggedQEvalCols<AB::Var> = (*next_row).borrow();
        builder.assert_bool(local.is_enabled);
        builder.assert_bool(local.is_first);
        builder.assert_bool(local.is_last);
        builder
            .when(local.is_enabled)
            .assert_eq(local.sumcheck_idx, local.round_idx + local.round_idx);
        builder
            .when(local.is_enabled * local.is_first)
            .assert_zero(local.term_idx);
        let zero = core::array::from_fn(|_| AB::Expr::ZERO);
        assert_array_eq(
            &mut builder.when(local.is_enabled * local.is_first),
            local.acc_in,
            zero,
        );

        let term = recursion_circuit::utils::ext_field_multiply(local.eq_rho_col, local.col_eval);
        let expected_acc = ext_add(local.acc_in, term);
        assert_array_eq(
            &mut builder.when(local.is_enabled),
            local.acc_out,
            expected_acc,
        );
        assert_array_eq(
            &mut builder.when(local.is_enabled * local.is_last),
            local.q_eval,
            local.acc_out,
        );

        let continues = local.is_enabled * (AB::Expr::ONE - local.is_last);
        builder
            .when_transition()
            .when(continues.clone())
            .assert_one(next.is_enabled);
        builder
            .when_transition()
            .when(continues.clone())
            .assert_eq(next.proof_idx, local.proof_idx);
        builder
            .when_transition()
            .when(continues.clone())
            .assert_eq(next.round_idx, local.round_idx);
        builder
            .when_transition()
            .when(continues.clone())
            .assert_eq(next.sumcheck_idx, local.sumcheck_idx);
        builder
            .when_transition()
            .when(continues.clone())
            .assert_eq(next.term_idx, local.term_idx + AB::Expr::ONE);
        assert_array_eq(
            &mut builder.when_transition().when(continues),
            next.acc_in,
            local.acc_out,
        );

        self.basefold_eval_bus.lookup_key(
            builder,
            local.proof_idx,
            PcsBasefoldEvalMessage {
                tidx: local.col_tidx.into(),
                value: local.col_eval.map(Into::into),
            },
            local.is_enabled,
        );
        self.eq_product_bus.lookup_key(
            builder,
            local.proof_idx,
            PcsEqProductMessage {
                kind: AB::Expr::from_usize(PcsEqProductKind::JaggedQEval.as_usize()),
                round_idx: local.round_idx.into(),
                term_idx: local.term_idx.into(),
                value: local.eq_rho_col.map(Into::into),
            },
            local.is_enabled,
        );
        let product = recursion_circuit::utils::ext_field_multiply(local.acc_out, local.f_at_rho);
        assert_array_eq(
            &mut builder.when(local.is_enabled * local.is_last),
            product,
            local.sumcheck_final,
        );
        self.sumcheck_output_bus.receive(
            builder,
            local.proof_idx,
            PcsSumcheckOutputMessage {
                idx: local.sumcheck_idx.into(),
                claim: local.sumcheck_final.map(Into::into),
            },
            local.is_enabled * local.is_last,
        );
    }
}

#[repr(C)]
#[derive(AlignedBorrow, Debug)]
pub struct PcsJaggedAssistCols<T> {
    pub is_enabled: T,
    pub proof_idx: T,
    pub round_idx: T,
    pub sumcheck_idx: T,
    pub h_at_rho_star: [T; D_EF],
    pub q_at_rho_star: [T; D_EF],
    pub sumcheck_final: [T; D_EF],
}

pub struct PcsJaggedAssistAir {
    pub sumcheck_output_bus: PcsSumcheckOutputBus,
    pub jagged_assist_h_bus: PcsJaggedAssistHBus,
    pub jagged_assist_q_bus: PcsJaggedAssistQBus,
}

impl<F: Field> BaseAir<F> for PcsJaggedAssistAir {
    fn width(&self) -> usize {
        PcsJaggedAssistCols::<F>::width()
    }
}

impl<F: Field> BaseAirWithPublicValues<F> for PcsJaggedAssistAir {}
impl<F: Field> PartitionedBaseAir<F> for PcsJaggedAssistAir {}

impl<AB> Air<AB> for PcsJaggedAssistAir
where
    AB: AirBuilder + InteractionBuilder,
    <AB::Expr as PrimeCharacteristicRing>::PrimeSubfield: BinomiallyExtendable<{ D_EF }>,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local_row = main.row_slice(0).expect("main row exists");
        let local: &PcsJaggedAssistCols<AB::Var> = (*local_row).borrow();
        builder.assert_bool(local.is_enabled);
        let product =
            recursion_circuit::utils::ext_field_multiply(local.h_at_rho_star, local.q_at_rho_star);
        assert_array_eq(
            &mut builder.when(local.is_enabled),
            product,
            local.sumcheck_final,
        );
        self.sumcheck_output_bus.receive(
            builder,
            local.proof_idx,
            PcsSumcheckOutputMessage {
                idx: local.sumcheck_idx.into(),
                claim: local.sumcheck_final.map(Into::into),
            },
            local.is_enabled,
        );
        self.jagged_assist_h_bus.lookup_key(
            builder,
            local.proof_idx,
            PcsJaggedAssistHMessage {
                round_idx: local.round_idx.into(),
                value: local.h_at_rho_star.map(Into::into),
            },
            local.is_enabled,
        );
        self.jagged_assist_q_bus.lookup_key(
            builder,
            local.proof_idx,
            PcsJaggedAssistQMessage {
                round_idx: local.round_idx.into(),
                value: local.q_at_rho_star.map(Into::into),
            },
            local.is_enabled,
        );
    }
}

#[repr(C)]
#[derive(AlignedBorrow, Debug)]
pub struct PcsBasefoldFinalExpectedCols<T> {
    pub is_enabled: T,
    pub proof_idx: T,
    pub sumcheck_idx: T,
    pub term_idx: T,
    pub point_idx: T,
    pub coord_idx: T,
    pub final_tidx: T,
    pub is_first: T,
    pub is_last: T,
    pub is_elem_first: T,
    pub is_elem_last: T,
    pub has_challenge: T,
    pub challenge_round: T,
    pub point_value: [T; D_EF],
    pub bit_value: T,
    pub challenge: [T; D_EF],
    pub final_value: [T; D_EF],
    pub coeff_in: [T; D_EF],
    pub coeff_out: [T; D_EF],
    pub acc_in: [T; D_EF],
    pub acc_out: [T; D_EF],
}

pub struct PcsBasefoldFinalExpectedAir {
    pub fold_challenge_bus: PcsFoldChallengeBus,
    pub final_message_bus: PcsFinalMessageBus,
    pub final_point_bus: PcsBasefoldFinalPointBus,
    pub final_expected_bus: PcsBasefoldFinalExpectedBus,
}

impl<F: Field> BaseAir<F> for PcsBasefoldFinalExpectedAir {
    fn width(&self) -> usize {
        PcsBasefoldFinalExpectedCols::<F>::width()
    }
}

impl<F: Field> BaseAirWithPublicValues<F> for PcsBasefoldFinalExpectedAir {}
impl<F: Field> PartitionedBaseAir<F> for PcsBasefoldFinalExpectedAir {}

impl<AB> Air<AB> for PcsBasefoldFinalExpectedAir
where
    AB: AirBuilder + InteractionBuilder,
    <AB::Expr as PrimeCharacteristicRing>::PrimeSubfield: BinomiallyExtendable<{ D_EF }>,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local_row = main.row_slice(0).expect("main row exists");
        let next_row = main.row_slice(1).expect("next row exists");
        let local: &PcsBasefoldFinalExpectedCols<AB::Var> = (*local_row).borrow();
        let next: &PcsBasefoldFinalExpectedCols<AB::Var> = (*next_row).borrow();
        builder.assert_bool(local.is_enabled);
        builder.assert_bool(local.is_first);
        builder.assert_bool(local.is_last);
        builder.assert_bool(local.is_elem_first);
        builder.assert_bool(local.is_elem_last);
        builder.assert_bool(local.has_challenge);
        builder.assert_bool(local.bit_value);

        assert_array_eq(
            &mut builder.when(local.is_enabled * local.is_first),
            local.acc_in,
            [AB::Expr::ZERO; D_EF],
        );
        assert_array_eq(
            &mut builder.when(local.is_enabled * local.is_elem_first),
            local.coeff_in,
            [
                AB::Expr::ONE,
                AB::Expr::ZERO,
                AB::Expr::ZERO,
                AB::Expr::ZERO,
            ],
        );

        self.fold_challenge_bus.lookup_key(
            builder,
            local.proof_idx,
            PcsFoldChallengeMessage {
                sumcheck_idx: local.sumcheck_idx.into(),
                round: local.challenge_round.into(),
                challenge: local.challenge.map(Into::into),
            },
            local.is_enabled * local.has_challenge,
        );
        self.final_point_bus.receive(
            builder,
            local.proof_idx,
            PcsBasefoldFinalPointMessage {
                sumcheck_idx: local.sumcheck_idx.into(),
                point_idx: local.point_idx.into(),
                coord_idx: local.coord_idx.into(),
                value: local.point_value.map(Into::into),
            },
            local.is_enabled,
        );

        let point = local.point_value.map(Into::into);
        let challenge = local.challenge.map(Into::into);
        let xi_yi: [AB::Expr; D_EF] =
            recursion_circuit::utils::ext_field_multiply(point.clone(), challenge.clone());
        let prefix_factor: [AB::Expr; D_EF] = core::array::from_fn(|i| {
            xi_yi[i].clone() + xi_yi[i].clone() - point[i].clone() - challenge[i].clone()
                + if i == 0 {
                    AB::Expr::ONE
                } else {
                    AB::Expr::ZERO
                }
        });
        let suffix_one_minus: [AB::Expr; D_EF] = ext_sub(
            [
                AB::Expr::ONE,
                AB::Expr::ZERO,
                AB::Expr::ZERO,
                AB::Expr::ZERO,
            ],
            point.clone(),
        );
        let suffix_factor: [AB::Expr; D_EF] = core::array::from_fn(|i| {
            local.bit_value.into() * point[i].clone()
                + (AB::Expr::ONE - local.bit_value.into()) * suffix_one_minus[i].clone()
        });
        let factor: [AB::Expr; D_EF] = core::array::from_fn(|i| {
            local.has_challenge.into() * prefix_factor[i].clone()
                + (AB::Expr::ONE - local.has_challenge.into()) * suffix_factor[i].clone()
        });
        let coeff_out = recursion_circuit::utils::ext_field_multiply(local.coeff_in, factor);
        assert_array_eq(
            &mut builder.when(local.is_enabled),
            local.coeff_out,
            coeff_out,
        );

        self.final_message_bus.lookup_key(
            builder,
            local.proof_idx,
            PcsFinalMessageMessage {
                tidx: local.final_tidx.into(),
                value: local.final_value.map(Into::into),
            },
            local.is_enabled * local.is_elem_last,
        );
        let contribution =
            recursion_circuit::utils::ext_field_multiply(local.coeff_out, local.final_value);
        let expected_acc: [AB::Expr; D_EF] = core::array::from_fn(|i| {
            local.acc_in[i].into() + local.is_elem_last.into() * contribution[i].clone()
        });
        assert_array_eq(
            &mut builder.when(local.is_enabled),
            local.acc_out,
            expected_acc,
        );

        let continue_selector = local.is_enabled * (AB::Expr::ONE - local.is_last.into());
        builder
            .when(continue_selector.clone())
            .assert_one(next.is_enabled);
        builder
            .when(continue_selector.clone())
            .assert_eq(next.proof_idx, local.proof_idx);
        builder
            .when(continue_selector.clone())
            .assert_eq(next.sumcheck_idx, local.sumcheck_idx);
        builder
            .when(continue_selector.clone())
            .assert_eq(next.term_idx, local.term_idx + AB::Expr::ONE);
        assert_array_eq(
            &mut builder.when(continue_selector.clone()),
            next.acc_in,
            local.acc_out.map(Into::into),
        );
        assert_array_eq(
            &mut builder.when(continue_selector * (AB::Expr::ONE - next.is_elem_first.into())),
            next.coeff_in,
            local.coeff_out.map(Into::into),
        );
        self.final_expected_bus.send(
            builder,
            local.proof_idx,
            PcsBasefoldFinalExpectedMessage {
                sumcheck_idx: local.sumcheck_idx.into(),
                expected: local.acc_out.map(Into::into),
            },
            local.is_enabled * local.is_last,
        );
    }
}

#[repr(C)]
#[derive(AlignedBorrow, Debug)]
pub struct PcsBasefoldFinalClaimCols<T> {
    pub is_enabled: T,
    pub proof_idx: T,
    pub sumcheck_idx: T,
    pub final_claim: [T; D_EF],
    pub expected: [T; D_EF],
}

pub struct PcsBasefoldFinalClaimAir {
    pub sumcheck_output_bus: PcsSumcheckOutputBus,
    pub final_expected_bus: PcsBasefoldFinalExpectedBus,
}

impl<F: Field> BaseAir<F> for PcsBasefoldFinalClaimAir {
    fn width(&self) -> usize {
        PcsBasefoldFinalClaimCols::<F>::width()
    }
}

impl<F: Field> BaseAirWithPublicValues<F> for PcsBasefoldFinalClaimAir {}
impl<F: Field> PartitionedBaseAir<F> for PcsBasefoldFinalClaimAir {}

impl<AB> Air<AB> for PcsBasefoldFinalClaimAir
where
    AB: AirBuilder + InteractionBuilder,
    <AB::Expr as PrimeCharacteristicRing>::PrimeSubfield: BinomiallyExtendable<{ D_EF }>,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local_row = main.row_slice(0).expect("main row exists");
        let local: &PcsBasefoldFinalClaimCols<AB::Var> = (*local_row).borrow();
        builder.assert_bool(local.is_enabled);
        assert_array_eq(
            &mut builder.when(local.is_enabled),
            local.final_claim,
            local.expected,
        );
        self.sumcheck_output_bus.receive(
            builder,
            local.proof_idx,
            PcsSumcheckOutputMessage {
                idx: local.sumcheck_idx.into(),
                claim: local.final_claim.map(Into::into),
            },
            local.is_enabled,
        );
        self.final_expected_bus.receive(
            builder,
            local.proof_idx,
            PcsBasefoldFinalExpectedMessage {
                sumcheck_idx: local.sumcheck_idx.into(),
                expected: local.expected.map(Into::into),
            },
            local.is_enabled,
        );
    }
}

struct PcsTraceCtx<'a> {
    commitment_roots: &'a [PcsCommitmentRootRecord],
    base_input_leaf_hashes: &'a [PcsBaseInputLeafHashRecord],
    base_input_merkle_rows: &'a [PcsBaseInputMerkleRecord],
    commit_phase_leaf_hashes: &'a [PcsCommitPhaseLeafHashRecord],
    commit_phase_merkle_rows: &'a [PcsCommitPhaseMerkleRecord],
    opening_points: &'a [PcsOpeningPointRecord],
    basefold_final_points: &'a [PcsBasefoldFinalPointRecord],
    opening_evals: &'a [PcsOpeningEvalRecord],
    eq_products: &'a [PcsEqProductRecord],
    suffix_products: &'a [PcsSuffixProductRecord],
    jagged_assist_h: &'a [PcsJaggedAssistHRecord],
    jagged_assist_q: &'a [PcsJaggedAssistQRecord],
    basefold_query_indices: &'a [PcsBasefoldQueryIndexRecord],
    basefold_query_opens: &'a [PcsBasefoldQueryOpenRecord],
    basefold_commit_phase_queries: &'a [PcsBasefoldCommitPhaseQueryRecord],
    basefold_final_codeword: &'a [PcsBasefoldFinalCodewordRecord],
    transcript_values: &'a [PcsTranscriptValueRecord],
    basefold_initial_claims: &'a [PcsBasefoldInitialClaimRecord],
    jagged_assist_inputs: &'a [PcsJaggedAssistInputRecord],
    jagged_claims: &'a [PcsJaggedClaimRecord],
    sumcheck_inputs: &'a [PcsSumcheckInputRecord],
    sumcheck_rounds: &'a [PcsSumcheckRoundRecord],
    batch_coeffs: &'a [PcsBatchCoeffRecord],
    jagged_q_evals: &'a [PcsJaggedQEvalRecord],
    jagged_assists: &'a [PcsJaggedAssistRecord],
    basefold_final_expected: &'a [PcsBasefoldFinalExpectedRecord],
    basefold_final_claims: &'a [PcsBasefoldFinalClaimRecord],
}

enum PcsModuleChip {
    CommitmentRoot,
    BaseInputLeafHash,
    BaseInputMerkle,
    CommitPhaseLeafHash,
    CommitPhaseMerkle,
    OpeningPoint,
    BasefoldFinalPoint,
    OpeningEval,
    EqProduct,
    SuffixProduct,
    JaggedAssistH,
    JaggedAssistQ,
    BasefoldQueryIndex,
    BasefoldQueryOpen,
    BasefoldCommitPhaseQuery,
    BasefoldFinalCodeword,
    TranscriptValues,
    BasefoldInitialClaim,
    JaggedAssistInput,
    JaggedClaim,
    SumcheckInput,
    Sumcheck,
    BatchCoeff,
    JaggedQEval,
    JaggedAssist,
    BasefoldFinalExpected,
    BasefoldFinalClaim,
}

impl RowMajorChip<F> for PcsModuleChip {
    type Ctx<'a> = PcsTraceCtx<'a>;

    fn generate_trace(
        &self,
        ctx: &Self::Ctx<'_>,
        required_height: Option<usize>,
    ) -> Option<RowMajorMatrix<F>> {
        match self {
            PcsModuleChip::CommitmentRoot => PcsCommitmentRootTraceGenerator
                .generate_trace(&ctx.commitment_roots, required_height),
            PcsModuleChip::BaseInputLeafHash => PcsBaseInputLeafHashTraceGenerator
                .generate_trace(&ctx.base_input_leaf_hashes, required_height),
            PcsModuleChip::BaseInputMerkle => PcsBaseInputMerkleTraceGenerator
                .generate_trace(&ctx.base_input_merkle_rows, required_height),
            PcsModuleChip::CommitPhaseLeafHash => PcsCommitPhaseLeafHashTraceGenerator
                .generate_trace(&ctx.commit_phase_leaf_hashes, required_height),
            PcsModuleChip::CommitPhaseMerkle => PcsCommitPhaseMerkleTraceGenerator
                .generate_trace(&ctx.commit_phase_merkle_rows, required_height),
            PcsModuleChip::OpeningPoint => {
                PcsOpeningPointTraceGenerator.generate_trace(&ctx.opening_points, required_height)
            }
            PcsModuleChip::BasefoldFinalPoint => PcsBasefoldFinalPointTraceGenerator
                .generate_trace(&ctx.basefold_final_points, required_height),
            PcsModuleChip::OpeningEval => {
                PcsOpeningEvalTraceGenerator.generate_trace(&ctx.opening_evals, required_height)
            }
            PcsModuleChip::EqProduct => {
                PcsEqProductTraceGenerator.generate_trace(&ctx.eq_products, required_height)
            }
            PcsModuleChip::SuffixProduct => {
                PcsSuffixProductTraceGenerator.generate_trace(&ctx.suffix_products, required_height)
            }
            PcsModuleChip::JaggedAssistH => {
                PcsJaggedAssistHTraceGenerator.generate_trace(&ctx.jagged_assist_h, required_height)
            }
            PcsModuleChip::JaggedAssistQ => {
                PcsJaggedAssistQTraceGenerator.generate_trace(&ctx.jagged_assist_q, required_height)
            }
            PcsModuleChip::BasefoldQueryIndex => PcsBasefoldQueryIndexTraceGenerator
                .generate_trace(&ctx.basefold_query_indices, required_height),
            PcsModuleChip::BasefoldQueryOpen => PcsBasefoldQueryOpenTraceGenerator
                .generate_trace(&ctx.basefold_query_opens, required_height),
            PcsModuleChip::BasefoldCommitPhaseQuery => PcsBasefoldCommitPhaseQueryTraceGenerator
                .generate_trace(&ctx.basefold_commit_phase_queries, required_height),
            PcsModuleChip::BasefoldFinalCodeword => PcsBasefoldFinalCodewordTraceGenerator
                .generate_trace(&ctx.basefold_final_codeword, required_height),
            PcsModuleChip::TranscriptValues => PcsTranscriptValueTraceGenerator
                .generate_trace(&ctx.transcript_values, required_height),
            PcsModuleChip::BasefoldInitialClaim => PcsBasefoldInitialClaimTraceGenerator
                .generate_trace(&ctx.basefold_initial_claims, required_height),
            PcsModuleChip::JaggedAssistInput => PcsJaggedAssistInputTraceGenerator
                .generate_trace(&ctx.jagged_assist_inputs, required_height),
            PcsModuleChip::JaggedClaim => {
                PcsJaggedClaimTraceGenerator.generate_trace(&ctx.jagged_claims, required_height)
            }
            PcsModuleChip::SumcheckInput => {
                PcsSumcheckInputTraceGenerator.generate_trace(&ctx.sumcheck_inputs, required_height)
            }
            PcsModuleChip::Sumcheck => {
                PcsSumcheckTraceGenerator.generate_trace(&ctx.sumcheck_rounds, required_height)
            }
            PcsModuleChip::BatchCoeff => {
                PcsBatchCoeffTraceGenerator.generate_trace(&ctx.batch_coeffs, required_height)
            }
            PcsModuleChip::JaggedQEval => {
                PcsJaggedQEvalTraceGenerator.generate_trace(&ctx.jagged_q_evals, required_height)
            }
            PcsModuleChip::JaggedAssist => {
                PcsJaggedAssistTraceGenerator.generate_trace(&ctx.jagged_assists, required_height)
            }
            PcsModuleChip::BasefoldFinalExpected => PcsBasefoldFinalExpectedTraceGenerator
                .generate_trace(&ctx.basefold_final_expected, required_height),
            PcsModuleChip::BasefoldFinalClaim => PcsBasefoldFinalClaimTraceGenerator
                .generate_trace(&ctx.basefold_final_claims, required_height),
        }
    }
}

struct PcsOpeningPointTraceGenerator;
struct PcsBasefoldFinalPointTraceGenerator;
struct PcsCommitmentRootTraceGenerator;
struct PcsBaseInputLeafHashTraceGenerator;
struct PcsBaseInputMerkleTraceGenerator;
struct PcsCommitPhaseLeafHashTraceGenerator;
struct PcsCommitPhaseMerkleTraceGenerator;
struct PcsOpeningEvalTraceGenerator;
struct PcsEqProductTraceGenerator;
struct PcsSuffixProductTraceGenerator;
struct PcsJaggedAssistHTraceGenerator;
struct PcsJaggedAssistQTraceGenerator;
struct PcsBasefoldFinalExpectedTraceGenerator;
struct PcsBasefoldQueryIndexTraceGenerator;
struct PcsBasefoldQueryOpenTraceGenerator;
struct PcsBasefoldCommitPhaseQueryTraceGenerator;
struct PcsBasefoldFinalCodewordTraceGenerator;
struct PcsTranscriptValueTraceGenerator;
struct PcsBasefoldInitialClaimTraceGenerator;
struct PcsJaggedAssistInputTraceGenerator;
struct PcsJaggedClaimTraceGenerator;
struct PcsSumcheckInputTraceGenerator;
struct PcsSumcheckTraceGenerator;
struct PcsBatchCoeffTraceGenerator;
struct PcsJaggedQEvalTraceGenerator;
struct PcsJaggedAssistTraceGenerator;
struct PcsBasefoldFinalClaimTraceGenerator;

impl RowMajorChip<F> for PcsCommitmentRootTraceGenerator {
    type Ctx<'a> = &'a [PcsCommitmentRootRecord];

    fn generate_trace(
        &self,
        records: &Self::Ctx<'_>,
        required_height: Option<usize>,
    ) -> Option<RowMajorMatrix<F>> {
        let width = PcsCommitmentRootCols::<F>::width();
        let height = trace_height(records.len(), required_height)?;
        let mut trace = vec![F::ZERO; height * width];
        for (row_idx, record) in records.iter().enumerate() {
            let row = &mut trace[row_idx * width..(row_idx + 1) * width];
            let cols: &mut PcsCommitmentRootCols<F> = row.borrow_mut();
            cols.is_enabled = F::ONE;
            cols.proof_idx = F::from_usize(record.proof_idx);
            cols.commit_major = F::from_usize(record.commit_major);
            cols.commit_minor = F::from_usize(record.commit_minor);
            cols.lookup_count = F::from_usize(record.lookup_count);
            cols.root = record.root;
        }
        Some(RowMajorMatrix::new(trace, width))
    }
}

impl RowMajorChip<F> for PcsBaseInputLeafHashTraceGenerator {
    type Ctx<'a> = &'a [PcsBaseInputLeafHashRecord];

    fn generate_trace(
        &self,
        records: &Self::Ctx<'_>,
        required_height: Option<usize>,
    ) -> Option<RowMajorMatrix<F>> {
        let width = PcsBaseInputLeafHashCols::<F>::width();
        let height = trace_height(records.len(), required_height)?;
        let mut trace = vec![F::ZERO; height * width];
        for (row_idx, record) in records.iter().enumerate() {
            let row = &mut trace[row_idx * width..(row_idx + 1) * width];
            let cols: &mut PcsBaseInputLeafHashCols<F> = row.borrow_mut();
            cols.is_enabled = F::ONE;
            cols.proof_idx = F::from_usize(record.proof_idx);
            cols.query_idx = F::from_usize(record.query_idx);
            cols.opening_idx = F::from_usize(record.opening_idx);
            cols.block_idx = F::from_usize(record.block_idx);
            cols.log2_height = F::from_usize(record.log2_height);
            cols.reduced_index = F::from_usize(record.reduced_index);
            cols.is_first = F::from_bool(record.is_first);
            cols.is_last = F::from_bool(record.is_last);
            cols.value_is_present = record.value_is_present.map(F::from_bool);
            cols.value_idx = record.value_idx.map(F::from_usize);
            cols.elem_idx = record.elem_idx.map(F::from_usize);
            cols.values = record.values.map(ext_limbs);
            cols.state_in = record.state_in;
            cols.input = record.input;
            cols.output_state = record.output_state;
        }
        Some(RowMajorMatrix::new(trace, width))
    }
}

impl RowMajorChip<F> for PcsBaseInputMerkleTraceGenerator {
    type Ctx<'a> = &'a [PcsBaseInputMerkleRecord];

    fn generate_trace(
        &self,
        records: &Self::Ctx<'_>,
        required_height: Option<usize>,
    ) -> Option<RowMajorMatrix<F>> {
        let width = PcsBaseInputMerkleCols::<F>::width();
        let height = trace_height(records.len(), required_height)?;
        let mut trace = vec![F::ZERO; height * width];
        for (row_idx, record) in records.iter().enumerate() {
            let row = &mut trace[row_idx * width..(row_idx + 1) * width];
            let cols: &mut PcsBaseInputMerkleCols<F> = row.borrow_mut();
            cols.is_enabled = F::ONE;
            cols.proof_idx = F::from_usize(record.proof_idx);
            cols.query_idx = F::from_usize(record.query_idx);
            cols.opening_idx = F::from_usize(record.opening_idx);
            cols.step = F::from_usize(record.step);
            cols.is_first = F::from_bool(record.is_first);
            cols.is_last = F::from_bool(record.is_last);
            cols.idx_in = F::from_usize(record.idx_in);
            cols.idx_bit = F::from_usize(record.idx_bit);
            cols.idx_out = F::from_usize(record.idx_out);
            cols.current = record.current;
            cols.sibling = record.sibling;
            cols.left = record.left;
            cols.right = record.right;
            cols.output = record.output;
        }
        Some(RowMajorMatrix::new(trace, width))
    }
}

impl RowMajorChip<F> for PcsCommitPhaseLeafHashTraceGenerator {
    type Ctx<'a> = &'a [PcsCommitPhaseLeafHashRecord];

    fn generate_trace(
        &self,
        records: &Self::Ctx<'_>,
        required_height: Option<usize>,
    ) -> Option<RowMajorMatrix<F>> {
        let width = PcsCommitPhaseLeafHashCols::<F>::width();
        let height = trace_height(records.len(), required_height)?;
        let mut trace = vec![F::ZERO; height * width];
        for (row_idx, record) in records.iter().enumerate() {
            let row = &mut trace[row_idx * width..(row_idx + 1) * width];
            let cols: &mut PcsCommitPhaseLeafHashCols<F> = row.borrow_mut();
            cols.is_enabled = F::ONE;
            cols.proof_idx = F::from_usize(record.proof_idx);
            cols.query_idx = F::from_usize(record.query_idx);
            cols.round = F::from_usize(record.round);
            cols.leaf_idx = F::from_usize(record.leaf_idx);
            cols.left = ext_limbs(record.left);
            cols.right = ext_limbs(record.right);
            cols.input = record.input;
            cols.output_state = record.output_state;
        }
        Some(RowMajorMatrix::new(trace, width))
    }
}

impl RowMajorChip<F> for PcsCommitPhaseMerkleTraceGenerator {
    type Ctx<'a> = &'a [PcsCommitPhaseMerkleRecord];

    fn generate_trace(
        &self,
        records: &Self::Ctx<'_>,
        required_height: Option<usize>,
    ) -> Option<RowMajorMatrix<F>> {
        let width = PcsCommitPhaseMerkleCols::<F>::width();
        let height = trace_height(records.len(), required_height)?;
        let mut trace = vec![F::ZERO; height * width];
        for (row_idx, record) in records.iter().enumerate() {
            let row = &mut trace[row_idx * width..(row_idx + 1) * width];
            let cols: &mut PcsCommitPhaseMerkleCols<F> = row.borrow_mut();
            cols.is_enabled = F::ONE;
            cols.proof_idx = F::from_usize(record.proof_idx);
            cols.query_idx = F::from_usize(record.query_idx);
            cols.round = F::from_usize(record.round);
            cols.step = F::from_usize(record.step);
            cols.is_first = F::from_bool(record.is_first);
            cols.is_last = F::from_bool(record.is_last);
            cols.idx_in = F::from_usize(record.idx_in);
            cols.idx_bit = F::from_usize(record.idx_bit);
            cols.idx_out = F::from_usize(record.idx_out);
            cols.current = record.current;
            cols.sibling = record.sibling;
            cols.left = record.left;
            cols.right = record.right;
            cols.output = record.output;
        }
        Some(RowMajorMatrix::new(trace, width))
    }
}

impl RowMajorChip<F> for PcsOpeningPointTraceGenerator {
    type Ctx<'a> = &'a [PcsOpeningPointRecord];

    fn generate_trace(
        &self,
        records: &Self::Ctx<'_>,
        required_height: Option<usize>,
    ) -> Option<RowMajorMatrix<F>> {
        let width = PcsOpeningPointCols::<F>::width();
        let height = trace_height(records.len(), required_height)?;
        let mut trace = vec![F::ZERO; height * width];
        for (row_idx, record) in records.iter().enumerate() {
            let row = &mut trace[row_idx * width..(row_idx + 1) * width];
            let cols: &mut PcsOpeningPointCols<F> = row.borrow_mut();
            cols.is_enabled = F::ONE;
            cols.proof_idx = F::from_usize(record.proof_idx);
            cols.opening_idx = F::from_usize(record.opening_idx);
            cols.coord_idx = F::from_usize(record.coord_idx);
            cols.global_round_idx = F::from_usize(record.global_round_idx);
            cols.value = ext_limbs(record.value);
        }
        Some(RowMajorMatrix::new(trace, width))
    }
}

impl RowMajorChip<F> for PcsBasefoldFinalPointTraceGenerator {
    type Ctx<'a> = &'a [PcsBasefoldFinalPointRecord];

    fn generate_trace(
        &self,
        records: &Self::Ctx<'_>,
        required_height: Option<usize>,
    ) -> Option<RowMajorMatrix<F>> {
        let width = PcsBasefoldFinalPointCols::<F>::width();
        let height = trace_height(records.len(), required_height)?;
        let mut trace = vec![F::ZERO; height * width];
        for (row_idx, record) in records.iter().enumerate() {
            let row = &mut trace[row_idx * width..(row_idx + 1) * width];
            let cols: &mut PcsBasefoldFinalPointCols<F> = row.borrow_mut();
            cols.is_enabled = F::ONE;
            cols.proof_idx = F::from_usize(record.proof_idx);
            cols.sumcheck_idx = F::from_usize(record.sumcheck_idx);
            cols.point_idx = F::from_usize(record.point_idx);
            cols.coord_idx = F::from_usize(record.coord_idx);
            cols.source_sumcheck_idx = F::from_usize(record.source_sumcheck_idx);
            cols.source_round = F::from_usize(record.source_round);
            cols.value = ext_limbs(record.value);
        }
        Some(RowMajorMatrix::new(trace, width))
    }
}

impl RowMajorChip<F> for PcsOpeningEvalTraceGenerator {
    type Ctx<'a> = &'a [PcsOpeningEvalRecord];

    fn generate_trace(
        &self,
        records: &Self::Ctx<'_>,
        required_height: Option<usize>,
    ) -> Option<RowMajorMatrix<F>> {
        let width = PcsOpeningEvalCols::<F>::width();
        let height = trace_height(records.len(), required_height)?;
        let mut trace = vec![F::ZERO; height * width];
        for (row_idx, record) in records.iter().enumerate() {
            let row = &mut trace[row_idx * width..(row_idx + 1) * width];
            let cols: &mut PcsOpeningEvalCols<F> = row.borrow_mut();
            cols.is_enabled = F::ONE;
            cols.proof_idx = F::from_usize(record.proof_idx);
            cols.opening_idx = F::from_usize(record.opening_idx);
            cols.commit_kind = F::from_usize(record.commit_kind.as_usize());
            cols.eval_idx = F::from_usize(record.eval_idx);
            cols.main_idx = F::from_usize(record.main_idx);
            cols.main_eval_idx = F::from_usize(record.main_eval_idx);
            cols.value = ext_limbs(record.value);
            cols.raw_value = ext_limbs(record.raw_value);
        }
        Some(RowMajorMatrix::new(trace, width))
    }
}

impl RowMajorChip<F> for PcsEqProductTraceGenerator {
    type Ctx<'a> = &'a [PcsEqProductRecord];

    fn generate_trace(
        &self,
        records: &Self::Ctx<'_>,
        required_height: Option<usize>,
    ) -> Option<RowMajorMatrix<F>> {
        let width = PcsEqProductCols::<F>::width();
        let height = trace_height(records.len(), required_height)?;
        let mut trace = vec![F::ZERO; height * width];
        for (row_idx, record) in records.iter().enumerate() {
            let row = &mut trace[row_idx * width..(row_idx + 1) * width];
            let cols: &mut PcsEqProductCols<F> = row.borrow_mut();
            cols.is_enabled = F::ONE;
            cols.proof_idx = F::from_usize(record.proof_idx);
            cols.kind = F::from_usize(record.kind.as_usize());
            cols.source = F::from_usize(record.source.as_usize());
            cols.round_idx = F::from_usize(record.round_idx);
            cols.term_idx = F::from_usize(record.term_idx);
            cols.bit_idx = F::from_usize(record.bit_idx);
            cols.is_first = F::from_bool(record.is_first);
            cols.is_last = F::from_bool(record.is_last);
            cols.lookup_count = F::from_usize(record.lookup_count);
            cols.point_tidx = F::from_usize(record.point_tidx);
            cols.sumcheck_idx = F::from_usize(record.sumcheck_idx);
            cols.point_round = F::from_usize(record.point_round);
            cols.index_bit = F::from_bool(record.index_bit);
            cols.index_pow2 = F::from_usize(record.index_pow2);
            cols.index_acc_in = F::from_usize(record.index_acc_in);
            cols.index_acc_out = F::from_usize(record.index_acc_out);
            cols.point = ext_limbs(record.point);
            cols.acc_in = ext_limbs(record.acc_in);
            cols.acc_out = ext_limbs(record.acc_out);
        }
        Some(RowMajorMatrix::new(trace, width))
    }
}

impl RowMajorChip<F> for PcsSuffixProductTraceGenerator {
    type Ctx<'a> = &'a [PcsSuffixProductRecord];

    fn generate_trace(
        &self,
        records: &Self::Ctx<'_>,
        required_height: Option<usize>,
    ) -> Option<RowMajorMatrix<F>> {
        let width = PcsSuffixProductCols::<F>::width();
        let height = trace_height(records.len(), required_height)?;
        let mut trace = vec![F::ZERO; height * width];
        for (row_idx, record) in records.iter().enumerate() {
            let row = &mut trace[row_idx * width..(row_idx + 1) * width];
            let cols: &mut PcsSuffixProductCols<F> = row.borrow_mut();
            cols.is_enabled = F::ONE;
            cols.proof_idx = F::from_usize(record.proof_idx);
            cols.round_idx = F::from_usize(record.round_idx);
            cols.term_idx = F::from_usize(record.term_idx);
            cols.coord_idx = F::from_usize(record.coord_idx);
            cols.step_idx = F::from_usize(record.step_idx);
            cols.is_first = F::from_bool(record.is_first);
            cols.is_last = F::from_bool(record.is_last);
            cols.has_factor = F::from_bool(record.has_factor);
            cols.point = ext_limbs(record.point);
            cols.acc_in = ext_limbs(record.acc_in);
            cols.acc_out = ext_limbs(record.acc_out);
        }
        Some(RowMajorMatrix::new(trace, width))
    }
}

impl RowMajorChip<F> for PcsJaggedAssistHTraceGenerator {
    type Ctx<'a> = &'a [PcsJaggedAssistHRecord];

    fn generate_trace(
        &self,
        records: &Self::Ctx<'_>,
        required_height: Option<usize>,
    ) -> Option<RowMajorMatrix<F>> {
        let width = PcsJaggedAssistHCols::<F>::width();
        let height = trace_height(records.len(), required_height)?;
        let mut trace = vec![F::ZERO; height * width];
        for (row_idx, record) in records.iter().enumerate() {
            let row = &mut trace[row_idx * width..(row_idx + 1) * width];
            let cols: &mut PcsJaggedAssistHCols<F> = row.borrow_mut();
            cols.is_enabled = F::ONE;
            cols.proof_idx = F::from_usize(record.proof_idx);
            cols.round_idx = F::from_usize(record.round_idx);
            cols.sumcheck_idx = F::from_usize(record.sumcheck_idx);
            cols.step_idx = F::from_usize(record.step_idx);
            cols.robp_idx = F::from_usize(record.robp_idx);
            cols.is_first = F::from_bool(record.is_first);
            cols.is_last = F::from_bool(record.is_last);
            cols.has_z_row = F::from_bool(record.has_z_row);
            cols.has_rho = F::from_bool(record.has_rho);
            cols.z_row = ext_limbs(record.z_row);
            cols.rho = ext_limbs(record.rho);
            cols.rho_star_c = ext_limbs(record.rho_star_c);
            cols.rho_star_d = ext_limbs(record.rho_star_d);
            cols.val_in = record.val_in.map(ext_limbs);
            cols.val_out = record.val_out.map(ext_limbs);
        }
        Some(RowMajorMatrix::new(trace, width))
    }
}

impl RowMajorChip<F> for PcsJaggedAssistQTraceGenerator {
    type Ctx<'a> = &'a [PcsJaggedAssistQRecord];

    fn generate_trace(
        &self,
        records: &Self::Ctx<'_>,
        required_height: Option<usize>,
    ) -> Option<RowMajorMatrix<F>> {
        let width = PcsJaggedAssistQCols::<F>::width();
        let height = trace_height(records.len(), required_height)?;
        let mut trace = vec![F::ZERO; height * width];
        for (row_idx, record) in records.iter().enumerate() {
            let row = &mut trace[row_idx * width..(row_idx + 1) * width];
            let cols: &mut PcsJaggedAssistQCols<F> = row.borrow_mut();
            cols.is_enabled = F::ONE;
            cols.proof_idx = F::from_usize(record.proof_idx);
            cols.round_idx = F::from_usize(record.round_idx);
            cols.sumcheck_idx = F::from_usize(record.sumcheck_idx);
            cols.commitment_kind = F::from_usize(record.commitment_kind);
            cols.term_idx = F::from_usize(record.term_idx);
            cols.step_idx = F::from_usize(record.step_idx);
            cols.robp_idx = F::from_usize(record.robp_idx);
            cols.is_first = F::from_bool(record.is_first);
            cols.is_last = F::from_bool(record.is_last);
            cols.is_first_step = F::from_bool(record.is_first_step);
            cols.is_last_step = F::from_bool(record.is_last_step);
            cols.term_is_last = F::from_bool(record.term_is_last);
            cols.eq_col = ext_limbs(record.eq_col);
            cols.t_lo = F::from_usize(record.t_lo);
            cols.t_hi = F::from_usize(record.t_hi);
            cols.c_bit = F::from_bool(record.c_bit);
            cols.d_bit = F::from_bool(record.d_bit);
            cols.bit_pow2 = F::from_usize(record.bit_pow2);
            cols.c_acc_in = F::from_usize(record.c_acc_in);
            cols.c_acc_out = F::from_usize(record.c_acc_out);
            cols.d_acc_in = F::from_usize(record.d_acc_in);
            cols.d_acc_out = F::from_usize(record.d_acc_out);
            cols.rho_star_c = ext_limbs(record.rho_star_c);
            cols.rho_star_d = ext_limbs(record.rho_star_d);
            cols.term_acc_in = ext_limbs(record.term_acc_in);
            cols.term_acc_out = ext_limbs(record.term_acc_out);
            cols.q_acc_in = ext_limbs(record.q_acc_in);
            cols.q_acc_out = ext_limbs(record.q_acc_out);
        }
        Some(RowMajorMatrix::new(trace, width))
    }
}

impl RowMajorChip<F> for PcsBasefoldQueryIndexTraceGenerator {
    type Ctx<'a> = &'a [PcsBasefoldQueryIndexRecord];

    fn generate_trace(
        &self,
        records: &Self::Ctx<'_>,
        required_height: Option<usize>,
    ) -> Option<RowMajorMatrix<F>> {
        let width = PcsBasefoldQueryIndexCols::<F>::width();
        let height = trace_height(records.len(), required_height)?;
        let mut trace = vec![F::ZERO; height * width];
        for (row_idx, record) in records.iter().enumerate() {
            let row = &mut trace[row_idx * width..(row_idx + 1) * width];
            let cols: &mut PcsBasefoldQueryIndexCols<F> = row.borrow_mut();
            cols.is_enabled = F::ONE;
            cols.proof_idx = F::from_usize(record.proof_idx);
            cols.query_idx = F::from_usize(record.query_idx);
            cols.sample_tidx = F::from_usize(record.sample_tidx);
            cols.query_bits = F::from_usize(record.query_bits);
            cols.sampled_value = record.sampled_value.as_bases()[0];
            cols.query_value = F::from_usize(record.query_value);
            cols.high_value = F::from_usize(record.high_value);
            cols.query_bytes = record.query_bytes.map(F::from_u8);
            cols.high_bytes = record.high_bytes.map(F::from_u8);
            cols.query_bit_selectors = record.query_bit_selectors.map(F::from_bool);
        }
        Some(RowMajorMatrix::new(trace, width))
    }
}

impl RowMajorChip<F> for PcsBasefoldQueryOpenTraceGenerator {
    type Ctx<'a> = &'a [PcsBasefoldQueryOpenRecord];

    fn generate_trace(
        &self,
        records: &Self::Ctx<'_>,
        required_height: Option<usize>,
    ) -> Option<RowMajorMatrix<F>> {
        let width = PcsBasefoldQueryOpenCols::<F>::width();
        let height = trace_height(records.len(), required_height)?;
        let mut trace = vec![F::ZERO; height * width];
        for (row_idx, record) in records.iter().enumerate() {
            let row = &mut trace[row_idx * width..(row_idx + 1) * width];
            let cols: &mut PcsBasefoldQueryOpenCols<F> = row.borrow_mut();
            cols.is_enabled = F::ONE;
            cols.proof_idx = F::from_usize(record.proof_idx);
            cols.query_idx = F::from_usize(record.query_idx);
            cols.opening_idx = F::from_usize(record.opening_idx);
            cols.reduced_index = F::from_usize(record.reduced_index);
            cols.global_coeff_idx = F::from_usize(record.global_coeff_idx);
            cols.value_idx = F::from_usize(record.value_idx);
            cols.elem_idx = F::from_usize(record.elem_idx);
            cols.log2_height = F::from_usize(record.log2_height);
            cols.is_last_for_height = F::from_bool(record.is_last_for_height);
            cols.coeff = ext_limbs(record.coeff);
            cols.opened_value = ext_limbs(record.opened_value);
            cols.acc_in = ext_limbs(record.acc_in);
            cols.acc_out = ext_limbs(record.acc_out);
        }
        Some(RowMajorMatrix::new(trace, width))
    }
}

impl RowMajorChip<F> for PcsBasefoldCommitPhaseQueryTraceGenerator {
    type Ctx<'a> = &'a [PcsBasefoldCommitPhaseQueryRecord];

    fn generate_trace(
        &self,
        records: &Self::Ctx<'_>,
        required_height: Option<usize>,
    ) -> Option<RowMajorMatrix<F>> {
        let width = PcsBasefoldCommitPhaseQueryCols::<F>::width();
        let height = trace_height(records.len(), required_height)?;
        let mut trace = vec![F::ZERO; height * width];
        for (row_idx, record) in records.iter().enumerate() {
            let row = &mut trace[row_idx * width..(row_idx + 1) * width];
            let cols: &mut PcsBasefoldCommitPhaseQueryCols<F> = row.borrow_mut();
            cols.is_enabled = F::ONE;
            cols.proof_idx = F::from_usize(record.proof_idx);
            cols.query_idx = F::from_usize(record.query_idx);
            cols.round = F::from_usize(record.round);
            cols.query_value = F::from_usize(record.query_value);
            cols.idx_in = F::from_usize(record.idx_in);
            cols.idx_out = F::from_usize(record.idx_out);
            cols.log2_height = F::from_usize(record.log2_height);
            cols.is_first = F::from_bool(record.is_first);
            cols.has_reduced_opening = F::from_bool(record.has_reduced_opening);
            cols.folded_idx = F::from_usize(record.folded_idx);
            cols.is_last = F::from_bool(record.is_last);
            cols.reduced_opening = ext_limbs(record.reduced_opening);
            cols.folded_in = ext_limbs(record.folded_in);
            cols.sibling_value = ext_limbs(record.sibling_value);
            cols.challenge = ext_limbs(record.challenge);
            cols.coeff = ext_limbs(record.coeff);
            cols.folded_out = ext_limbs(record.folded_out);
        }
        Some(RowMajorMatrix::new(trace, width))
    }
}

impl RowMajorChip<F> for PcsBasefoldFinalCodewordTraceGenerator {
    type Ctx<'a> = &'a [PcsBasefoldFinalCodewordRecord];

    fn generate_trace(
        &self,
        records: &Self::Ctx<'_>,
        required_height: Option<usize>,
    ) -> Option<RowMajorMatrix<F>> {
        let width = PcsBasefoldFinalCodewordCols::<F>::width();
        let height = trace_height(records.len(), required_height)?;
        let mut trace = vec![F::ZERO; height * width];
        for (row_idx, record) in records.iter().enumerate() {
            let row = &mut trace[row_idx * width..(row_idx + 1) * width];
            let cols: &mut PcsBasefoldFinalCodewordCols<F> = row.borrow_mut();
            cols.is_enabled = F::ONE;
            cols.proof_idx = F::from_usize(record.proof_idx);
            cols.query_idx = F::from_usize(record.query_idx);
            cols.elem_idx = F::from_usize(record.elem_idx);
            cols.final_tidx = F::from_usize(record.final_tidx);
            cols.is_first = F::from_bool(record.is_first);
            cols.is_last = F::from_bool(record.is_last);
            cols.final_value = ext_limbs(record.final_value);
            cols.coeff = ext_limbs(record.coeff);
            cols.acc_in = ext_limbs(record.acc_in);
            cols.acc_out = ext_limbs(record.acc_out);
            cols.folded = ext_limbs(record.folded);
        }
        Some(RowMajorMatrix::new(trace, width))
    }
}

impl RowMajorChip<F> for PcsBasefoldFinalExpectedTraceGenerator {
    type Ctx<'a> = &'a [PcsBasefoldFinalExpectedRecord];

    fn generate_trace(
        &self,
        records: &Self::Ctx<'_>,
        required_height: Option<usize>,
    ) -> Option<RowMajorMatrix<F>> {
        let width = PcsBasefoldFinalExpectedCols::<F>::width();
        let height = trace_height(records.len(), required_height)?;
        let mut trace = vec![F::ZERO; height * width];
        for (row_idx, record) in records.iter().enumerate() {
            let row = &mut trace[row_idx * width..(row_idx + 1) * width];
            let cols: &mut PcsBasefoldFinalExpectedCols<F> = row.borrow_mut();
            cols.is_enabled = F::ONE;
            cols.proof_idx = F::from_usize(record.proof_idx);
            cols.sumcheck_idx = F::from_usize(record.sumcheck_idx);
            cols.term_idx = F::from_usize(record.term_idx);
            cols.point_idx = F::from_usize(record.point_idx);
            cols.coord_idx = F::from_usize(record.coord_idx);
            cols.final_tidx = F::from_usize(record.final_tidx);
            cols.is_first = F::from_bool(record.is_first);
            cols.is_last = F::from_bool(record.is_last);
            cols.is_elem_first = F::from_bool(record.is_elem_first);
            cols.is_elem_last = F::from_bool(record.is_elem_last);
            cols.has_challenge = F::from_bool(record.has_challenge);
            cols.challenge_round = F::from_usize(record.challenge_round);
            cols.point_value = ext_limbs(record.point_value);
            cols.bit_value = F::from_bool(record.bit_value);
            cols.challenge = ext_limbs(record.challenge);
            cols.final_value = ext_limbs(record.final_value);
            cols.coeff_in = ext_limbs(record.coeff_in);
            cols.coeff_out = ext_limbs(record.coeff_out);
            cols.acc_in = ext_limbs(record.acc_in);
            cols.acc_out = ext_limbs(record.acc_out);
        }
        Some(RowMajorMatrix::new(trace, width))
    }
}

impl RowMajorChip<F> for PcsTranscriptValueTraceGenerator {
    type Ctx<'a> = &'a [PcsTranscriptValueRecord];

    fn generate_trace(
        &self,
        records: &Self::Ctx<'_>,
        required_height: Option<usize>,
    ) -> Option<RowMajorMatrix<F>> {
        let width = PcsTranscriptValueCols::<F>::width();
        let height = trace_height(records.len(), required_height)?;
        let mut trace = vec![F::ZERO; height * width];
        for (row_idx, record) in records.iter().enumerate() {
            let row = &mut trace[row_idx * width..(row_idx + 1) * width];
            let cols: &mut PcsTranscriptValueCols<F> = row.borrow_mut();
            cols.is_enabled = F::ONE;
            cols.proof_idx = F::from_usize(record.proof_idx);
            cols.idx = F::from_usize(record.idx);
            cols.tidx = F::from_usize(record.tidx);
            cols.is_sample = F::from_bool(record.is_sample);
            cols.is_ext = F::from_bool(record.is_ext);
            cols.is_final_message = F::from_bool(record.is_final_message);
            cols.is_query_sample = F::from_bool(record.is_query_sample);
            cols.is_batch_alpha = F::from_bool(record.is_batch_alpha);
            cols.is_basefold_eval = F::from_bool(record.is_basefold_eval);
            cols.is_jagged_f_at_rho = F::from_bool(record.is_jagged_f_at_rho);
            cols.transcript_ext_lookup_count = F::from_usize(record.transcript_ext_lookup_count);
            cols.value = ext_limbs(record.value);
        }
        Some(RowMajorMatrix::new(trace, width))
    }
}

impl RowMajorChip<F> for PcsBasefoldInitialClaimTraceGenerator {
    type Ctx<'a> = &'a [PcsBasefoldInitialClaimRecord];

    fn generate_trace(
        &self,
        records: &Self::Ctx<'_>,
        required_height: Option<usize>,
    ) -> Option<RowMajorMatrix<F>> {
        let width = PcsBasefoldInitialClaimCols::<F>::width();
        let height = trace_height(records.len(), required_height)?;
        let mut trace = vec![F::ZERO; height * width];
        for (row_idx, record) in records.iter().enumerate() {
            let row = &mut trace[row_idx * width..(row_idx + 1) * width];
            let cols: &mut PcsBasefoldInitialClaimCols<F> = row.borrow_mut();
            cols.is_enabled = F::ONE;
            cols.proof_idx = F::from_usize(record.proof_idx);
            cols.sumcheck_idx = F::from_usize(record.sumcheck_idx);
            cols.term_idx = F::from_usize(record.term_idx);
            cols.is_first = F::from_bool(record.is_first);
            cols.is_last = F::from_bool(record.is_last);
            cols.global_coeff_idx = F::from_usize(record.global_coeff_idx);
            cols.eval_tidx = F::from_usize(record.eval_tidx);
            cols.eval = ext_limbs(record.eval);
            cols.coeff = ext_limbs(record.coeff);
            cols.scale = ext_limbs(record.scale);
            cols.acc_in = ext_limbs(record.acc_in);
            cols.acc_out = ext_limbs(record.acc_out);
        }
        Some(RowMajorMatrix::new(trace, width))
    }
}

impl RowMajorChip<F> for PcsJaggedAssistInputTraceGenerator {
    type Ctx<'a> = &'a [PcsJaggedAssistInputRecord];

    fn generate_trace(
        &self,
        records: &Self::Ctx<'_>,
        required_height: Option<usize>,
    ) -> Option<RowMajorMatrix<F>> {
        let width = PcsJaggedAssistInputCols::<F>::width();
        let height = trace_height(records.len(), required_height)?;
        let mut trace = vec![F::ZERO; height * width];
        for (row_idx, record) in records.iter().enumerate() {
            let row = &mut trace[row_idx * width..(row_idx + 1) * width];
            let cols: &mut PcsJaggedAssistInputCols<F> = row.borrow_mut();
            cols.is_enabled = F::ONE;
            cols.proof_idx = F::from_usize(record.proof_idx);
            cols.round_idx = F::from_usize(record.round_idx);
            cols.sumcheck_idx = F::from_usize(record.sumcheck_idx);
            cols.f_tidx = F::from_usize(record.f_tidx);
            cols.f_at_rho = ext_limbs(record.f_at_rho);
        }
        Some(RowMajorMatrix::new(trace, width))
    }
}

impl RowMajorChip<F> for PcsJaggedClaimTraceGenerator {
    type Ctx<'a> = &'a [PcsJaggedClaimRecord];

    fn generate_trace(
        &self,
        records: &Self::Ctx<'_>,
        required_height: Option<usize>,
    ) -> Option<RowMajorMatrix<F>> {
        let width = PcsJaggedClaimCols::<F>::width();
        let height = trace_height(records.len(), required_height)?;
        let mut trace = vec![F::ZERO; height * width];
        for (row_idx, record) in records.iter().enumerate() {
            let row = &mut trace[row_idx * width..(row_idx + 1) * width];
            let cols: &mut PcsJaggedClaimCols<F> = row.borrow_mut();
            cols.is_enabled = F::ONE;
            cols.proof_idx = F::from_usize(record.proof_idx);
            cols.round_idx = F::from_usize(record.round_idx);
            cols.sumcheck_idx = F::from_usize(record.sumcheck_idx);
            cols.term_idx = F::from_usize(record.term_idx);
            cols.is_first = F::from_bool(record.is_first);
            cols.is_last = F::from_bool(record.is_last);
            cols.opening_idx = F::from_usize(record.opening_idx);
            cols.commit_kind = F::from_usize(record.commit_kind.as_usize());
            cols.eval_idx = F::from_usize(record.eval_idx);
            cols.main_idx = F::from_usize(record.main_idx);
            cols.main_eval_idx = F::from_usize(record.main_eval_idx);
            cols.z_col_tidx = F::from_usize(record.z_col_tidx);
            cols.eval = ext_limbs(record.eval);
            cols.eq_col = ext_limbs(record.eq_col);
            cols.tail_zero = ext_limbs(record.tail_zero);
            cols.acc_in = ext_limbs(record.acc_in);
            cols.acc_out = ext_limbs(record.acc_out);
        }
        Some(RowMajorMatrix::new(trace, width))
    }
}

impl RowMajorChip<F> for PcsSumcheckInputTraceGenerator {
    type Ctx<'a> = &'a [PcsSumcheckInputRecord];

    fn generate_trace(
        &self,
        records: &Self::Ctx<'_>,
        required_height: Option<usize>,
    ) -> Option<RowMajorMatrix<F>> {
        let width = PcsSumcheckInputCols::<F>::width();
        let height = trace_height(records.len(), required_height)?;
        let mut trace = vec![F::ZERO; height * width];
        for (row_idx, record) in records.iter().enumerate() {
            let row = &mut trace[row_idx * width..(row_idx + 1) * width];
            let cols: &mut PcsSumcheckInputCols<F> = row.borrow_mut();
            cols.is_enabled = F::ONE;
            cols.proof_idx = F::from_usize(record.proof_idx);
            cols.idx = F::from_usize(record.idx);
            cols.claim = ext_limbs(record.claim);
        }
        Some(RowMajorMatrix::new(trace, width))
    }
}

impl RowMajorChip<F> for PcsSumcheckTraceGenerator {
    type Ctx<'a> = &'a [PcsSumcheckRoundRecord];

    fn generate_trace(
        &self,
        records: &Self::Ctx<'_>,
        required_height: Option<usize>,
    ) -> Option<RowMajorMatrix<F>> {
        let width = PcsSumcheckCols::<F>::width();
        let height = trace_height(records.len(), required_height)?;
        let mut trace = vec![F::ZERO; height * width];
        for (row_idx, record) in records.iter().enumerate() {
            let row = &mut trace[row_idx * width..(row_idx + 1) * width];
            let cols: &mut PcsSumcheckCols<F> = row.borrow_mut();
            cols.is_enabled = F::ONE;
            cols.proof_idx = F::from_usize(record.proof_idx);
            cols.idx = F::from_usize(record.idx);
            cols.round = F::from_usize(record.round);
            cols.is_first = F::from_bool(record.is_first);
            cols.is_last = F::from_bool(record.is_last);
            cols.ev_tidx = F::from_usize(record.ev_tidx);
            cols.challenge_tidx = F::from_usize(record.challenge_tidx);
            cols.fold_challenge_lookup_count = F::from_usize(record.fold_challenge_lookup_count);
            cols.ev1 = ext_limbs(record.ev1);
            cols.ev2 = ext_limbs(record.ev2);
            cols.claim_in = ext_limbs(record.claim_in);
            cols.claim_out = ext_limbs(record.claim_out);
            cols.challenge = ext_limbs(record.challenge);
        }
        Some(RowMajorMatrix::new(trace, width))
    }
}

impl RowMajorChip<F> for PcsBatchCoeffTraceGenerator {
    type Ctx<'a> = &'a [PcsBatchCoeffRecord];

    fn generate_trace(
        &self,
        records: &Self::Ctx<'_>,
        required_height: Option<usize>,
    ) -> Option<RowMajorMatrix<F>> {
        let width = PcsBatchCoeffCols::<F>::width();
        let height = trace_height(records.len(), required_height)?;
        let mut trace = vec![F::ZERO; height * width];
        for (row_idx, record) in records.iter().enumerate() {
            let row = &mut trace[row_idx * width..(row_idx + 1) * width];
            let cols: &mut PcsBatchCoeffCols<F> = row.borrow_mut();
            cols.is_enabled = F::ONE;
            cols.proof_idx = F::from_usize(record.proof_idx);
            cols.global_coeff_idx = F::from_usize(record.global_coeff_idx);
            cols.alpha_tidx = F::from_usize(record.alpha_tidx);
            cols.lookup_count = F::from_usize(record.lookup_count);
            cols.is_first = F::from_bool(record.is_first);
            cols.is_last = F::from_bool(record.is_last);
            cols.alpha = ext_limbs(record.alpha);
            cols.coeff = ext_limbs(record.coeff);
            cols.next_coeff = ext_limbs(record.next_coeff);
        }
        Some(RowMajorMatrix::new(trace, width))
    }
}

impl RowMajorChip<F> for PcsJaggedQEvalTraceGenerator {
    type Ctx<'a> = &'a [PcsJaggedQEvalRecord];

    fn generate_trace(
        &self,
        records: &Self::Ctx<'_>,
        required_height: Option<usize>,
    ) -> Option<RowMajorMatrix<F>> {
        let width = PcsJaggedQEvalCols::<F>::width();
        let height = trace_height(records.len(), required_height)?;
        let mut trace = vec![F::ZERO; height * width];
        for (row_idx, record) in records.iter().enumerate() {
            let row = &mut trace[row_idx * width..(row_idx + 1) * width];
            let cols: &mut PcsJaggedQEvalCols<F> = row.borrow_mut();
            cols.is_enabled = F::ONE;
            cols.proof_idx = F::from_usize(record.proof_idx);
            cols.round_idx = F::from_usize(record.round_idx);
            cols.sumcheck_idx = F::from_usize(record.sumcheck_idx);
            cols.term_idx = F::from_usize(record.term_idx);
            cols.is_first = F::from_bool(record.is_first);
            cols.is_last = F::from_bool(record.is_last);
            cols.col_tidx = F::from_usize(record.col_tidx);
            cols.col_eval = ext_limbs(record.col_eval);
            cols.eq_rho_col = ext_limbs(record.eq_rho_col);
            cols.acc_in = ext_limbs(record.acc_in);
            cols.acc_out = ext_limbs(record.acc_out);
            cols.q_eval = ext_limbs(record.q_eval);
            cols.f_at_rho = ext_limbs(record.f_at_rho);
            cols.sumcheck_final = ext_limbs(record.sumcheck_final);
        }
        Some(RowMajorMatrix::new(trace, width))
    }
}

impl RowMajorChip<F> for PcsJaggedAssistTraceGenerator {
    type Ctx<'a> = &'a [PcsJaggedAssistRecord];

    fn generate_trace(
        &self,
        records: &Self::Ctx<'_>,
        required_height: Option<usize>,
    ) -> Option<RowMajorMatrix<F>> {
        let width = PcsJaggedAssistCols::<F>::width();
        let height = trace_height(records.len(), required_height)?;
        let mut trace = vec![F::ZERO; height * width];
        for (row_idx, record) in records.iter().enumerate() {
            let row = &mut trace[row_idx * width..(row_idx + 1) * width];
            let cols: &mut PcsJaggedAssistCols<F> = row.borrow_mut();
            cols.is_enabled = F::ONE;
            cols.proof_idx = F::from_usize(record.proof_idx);
            cols.round_idx = F::from_usize(record.round_idx);
            cols.sumcheck_idx = F::from_usize(record.sumcheck_idx);
            cols.h_at_rho_star = ext_limbs(record.h_at_rho_star);
            cols.q_at_rho_star = ext_limbs(record.q_at_rho_star);
            cols.sumcheck_final = ext_limbs(record.sumcheck_final);
        }
        Some(RowMajorMatrix::new(trace, width))
    }
}

impl RowMajorChip<F> for PcsBasefoldFinalClaimTraceGenerator {
    type Ctx<'a> = &'a [PcsBasefoldFinalClaimRecord];

    fn generate_trace(
        &self,
        records: &Self::Ctx<'_>,
        required_height: Option<usize>,
    ) -> Option<RowMajorMatrix<F>> {
        let width = PcsBasefoldFinalClaimCols::<F>::width();
        let height = trace_height(records.len(), required_height)?;
        let mut trace = vec![F::ZERO; height * width];
        for (row_idx, record) in records.iter().enumerate() {
            let row = &mut trace[row_idx * width..(row_idx + 1) * width];
            let cols: &mut PcsBasefoldFinalClaimCols<F> = row.borrow_mut();
            cols.is_enabled = F::ONE;
            cols.proof_idx = F::from_usize(record.proof_idx);
            cols.sumcheck_idx = F::from_usize(record.sumcheck_idx);
            cols.final_claim = ext_limbs(record.final_claim);
            cols.expected = ext_limbs(record.expected);
        }
        Some(RowMajorMatrix::new(trace, width))
    }
}

fn replay_degree2_sumcheck<TS>(
    proof_idx: usize,
    idx: usize,
    claimed_sum: RecursionField,
    proof: &sumcheck::structs::IOPProof<RecursionField>,
    num_variables: usize,
    emit_input_record: bool,
    preflight: &mut Preflight,
    ts: &mut TS,
) -> Result<(Vec<RecursionField>, RecursionField)>
where
    TS: FiatShamirTranscript<BabyBearPoseidon2Config>
        + TranscriptHistory<F = F, State = [F; POSEIDON2_WIDTH]>,
{
    if proof.proofs.len() != num_variables {
        bail!(
            "sumcheck round count mismatch: {} != {num_variables}",
            proof.proofs.len()
        );
    }
    observe_label_with_records(
        ts,
        &num_variables.to_le_bytes(),
        preflight,
        5_000_000 + idx * 10_000,
    );
    observe_label_with_records(
        ts,
        &2usize.to_le_bytes(),
        preflight,
        5_000_000 + idx * 10_000 + 10,
    );
    let mut claim = claimed_sum;
    let mut challenges = Vec::with_capacity(num_variables);
    if emit_input_record {
        preflight.pcs.sumcheck_inputs.push(PcsSumcheckInputRecord {
            proof_idx,
            idx,
            claim: claimed_sum,
        });
    }
    for round in 0..num_variables {
        let msg = &proof.proofs[round];
        if msg.evaluations.len() != 2 {
            bail!(
                "degree-2 sumcheck round {round} has {} evals",
                msg.evaluations.len()
            );
        }
        let ev_tidx = ts.len();
        ts.observe_ext(msg.evaluations[0]);
        ts.observe_ext(msg.evaluations[1]);
        observe_label_with_records(
            ts,
            b"Internal round",
            preflight,
            5_000_000 + idx * 10_000 + 100 + round * 100,
        );
        let challenge_tidx = ts.len();
        let challenge = FiatShamirTranscript::<BabyBearPoseidon2Config>::sample_ext(ts);
        let ev0 = claim - msg.evaluations[0];
        let claim_out = extrapolate_uni_poly(ev0, &msg.evaluations, challenge);
        challenges.push(challenge);
        preflight.pcs.sumcheck_rounds.push(PcsSumcheckRoundRecord {
            proof_idx,
            idx,
            round,
            is_first: round == 0,
            is_last: round + 1 == num_variables,
            ev_tidx,
            challenge_tidx,
            ev1: msg.evaluations[0],
            ev2: msg.evaluations[1],
            claim_in: claim,
            claim_out,
            challenge,
            fold_challenge_lookup_count: 0,
        });
        claim = claim_out;
    }
    Ok((challenges, claim))
}

fn flatten_padded_openings_as_native(
    poly_heights: &[usize],
    openings: Vec<(Vec<RecursionField>, Vec<RecursionField>)>,
) -> Result<(Vec<RecursionField>, Vec<RecursionField>)> {
    let max_native_point_len = poly_heights
        .iter()
        .map(|&h| ceil_log2(h))
        .max()
        .unwrap_or(0);
    let mut common_point = vec![None; max_native_point_len];
    let mut evals = Vec::with_capacity(poly_heights.len());
    let mut poly_idx = 0;
    for (point, point_evals) in openings {
        for value in point_evals {
            let height = *poly_heights
                .get(poly_idx)
                .ok_or_else(|| eyre::eyre!("jagged: too many opening evaluations"))?;
            let native_num_vars = ceil_log2(height);
            if point.len() < native_num_vars {
                bail!("jagged point length is smaller than poly num vars");
            }
            for (dst, src) in common_point.iter_mut().zip(point.iter()) {
                match dst {
                    Some(existing) if *existing != *src => {
                        bail!("jagged opening points are not prefix-compatible");
                    }
                    Some(_) => {}
                    None => *dst = Some(*src),
                }
            }
            let tail_zero_factor = point[native_num_vars..]
                .iter()
                .fold(RecursionField::ONE, |acc, r| {
                    acc * (RecursionField::ONE - *r)
                });
            if tail_zero_factor == RecursionField::ZERO {
                bail!("jagged padded opening tail factor is zero");
            }
            evals.push(value * tail_zero_factor.inverse());
            poly_idx += 1;
        }
    }
    if poly_idx != poly_heights.len() {
        bail!(
            "jagged opening eval count mismatch: {} != {}",
            poly_idx,
            poly_heights.len()
        );
    }
    let point = common_point
        .into_iter()
        .map(|value| value.ok_or_else(|| eyre::eyre!("jagged missing common opening point")))
        .collect::<Result<Vec<_>>>()?;
    Ok((point, evals))
}

fn inner_verify_openings_for_col_evals(
    log_h: usize,
    rho_row: &[RecursionField],
    col_evals: &[RecursionField],
    col_tidx: usize,
) -> Vec<BasefoldOpening> {
    col_evals
        .chunks(8)
        .enumerate()
        .map(|(chunk_idx, evals)| {
            (
                log_h,
                (
                    rho_row.to_vec(),
                    evals
                        .iter()
                        .copied()
                        .enumerate()
                        .map(|(idx, eval)| (eval, col_tidx + (chunk_idx * 8 + idx) * D_EF))
                        .collect(),
                ),
            )
        })
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn record_basefold_query_checks(
    rounds: &[BasefoldRound],
    proof: &mpcs::basefold::structure::BasefoldProof<RecursionField>,
    preflight: &mut Preflight,
    batch_coeffs: &[RecursionField],
    fold_challenges: &[RecursionField],
    queries: &[usize],
    max_num_var: usize,
    final_tidx: usize,
) -> Result<()> {
    let rate_log = <BasefoldRSParams as BasefoldSpec<RecursionField>>::get_rate_log();
    let basecode_log =
        <BasefoldRSParams as BasefoldSpec<RecursionField>>::get_basecode_msg_size_log();
    ensure_supported_basecode_log(basecode_log)?;
    if proof.final_message[0].len() != (1usize << basecode_log) {
        bail!("basefold final message width does not match basecode size");
    }
    let log2_max_codeword_size = max_num_var + rate_log;
    let rounds_len = max_num_var - basecode_log;
    if proof.query_opening_proof.len() != queries.len() {
        bail!("basefold query opening count mismatch");
    }
    if fold_challenges.len() != rounds_len || proof.commits.len() != rounds_len {
        bail!("basefold fold challenge count mismatch");
    }
    for (round, root) in proof.commits.iter().enumerate() {
        preflight
            .pcs
            .commitment_roots
            .push(PcsCommitmentRootRecord {
                proof_idx: 0,
                commit_major: 1,
                commit_minor: round,
                root: digest_to_array(root)?,
                lookup_count: queries.len(),
            });
    }

    let final_codeword = encode_small_final_message(&proof.final_message)?;
    for (query_idx, (&query, query_proof)) in queries
        .iter()
        .zip(proof.query_opening_proof.iter())
        .enumerate()
    {
        if query_proof.input_proofs.len() != rounds.len()
            || query_proof.commit_phase_openings.len() != rounds_len
        {
            bail!("basefold query proof shape mismatch");
        }
        let mut reduced_by_height =
            std::collections::BTreeMap::<usize, (RecursionField, Option<usize>)>::new();
        let mut coeff_iter = batch_coeffs.iter().copied().enumerate();

        for (opening_idx, ((commit, openings), input_proof)) in rounds
            .iter()
            .zip(query_proof.input_proofs.iter())
            .enumerate()
        {
            let bits_reduced = log2_max_codeword_size - commit.log2_max_codeword_size;
            let reduced_index = query >> bits_reduced;
            if input_proof.opened_values.len() != openings.len() {
                bail!("basefold opened-value shape mismatch");
            }
            record_base_input_mmcs(
                query_idx,
                opening_idx,
                reduced_index,
                openings,
                &input_proof.opened_values,
                &input_proof.opening_proof,
                preflight,
            )?;
            for (value_idx, ((num_var, (_, evals)), mat)) in openings
                .iter()
                .zip(input_proof.opened_values.iter())
                .enumerate()
            {
                if mat.len() != evals.len() {
                    bail!("basefold opened-value width mismatch");
                }
                let log2_height = num_var + rate_log;
                for (elem_idx, opened_value) in mat.iter().copied().enumerate() {
                    let (global_coeff_idx, coeff) = coeff_iter
                        .next()
                        .ok_or_else(|| eyre::eyre!("basefold missing batch coefficient"))?;
                    let (acc_in, last_row) = reduced_by_height
                        .get(&log2_height)
                        .copied()
                        .unwrap_or((RecursionField::ZERO, None));
                    if let Some(last_row) = last_row {
                        preflight.pcs.basefold_query_opens[last_row].is_last_for_height = false;
                    }
                    let opened_value = RecursionField::from(opened_value);
                    let acc_out = acc_in + coeff * opened_value;
                    let row_idx = preflight.pcs.basefold_query_opens.len();
                    preflight
                        .pcs
                        .basefold_query_opens
                        .push(PcsBasefoldQueryOpenRecord {
                            proof_idx: 0,
                            query_idx,
                            opening_idx,
                            reduced_index,
                            global_coeff_idx,
                            value_idx,
                            elem_idx,
                            log2_height,
                            is_last_for_height: true,
                            coeff,
                            opened_value,
                            acc_in,
                            acc_out,
                        });
                    reduced_by_height.insert(log2_height, (acc_out, Some(row_idx)));
                }
            }
        }

        let mut idx = query;
        let mut folded = RecursionField::ZERO;
        let mut log2_height = log2_max_codeword_size;
        for (round, (challenge, opening)) in fold_challenges
            .iter()
            .copied()
            .zip(query_proof.commit_phase_openings.iter())
            .enumerate()
        {
            let idx_in = idx;
            let folded_idx = idx & 1;
            let (reduced_opening, had_reduced) = reduced_by_height
                .remove(&log2_height)
                .map(|(value, _)| (value, true))
                .unwrap_or((RecursionField::ZERO, false));
            let mut leafs = [opening.sibling_value; 2];
            leafs[folded_idx] = folded + reduced_opening;
            let leaf_idx = idx >> 1;
            let coeff = verifier_folding_coeff(log2_height, leaf_idx);
            let folded_out = fold_codeword_pair(leafs, challenge, coeff);
            let leaf_state = poseidon2_hash_ext_pair(leafs[0], leafs[1]);
            let leaf_hash = leaf_state[..DIGEST_SIZE].try_into().unwrap();
            preflight
                .pcs
                .commit_phase_leaf_hashes
                .push(PcsCommitPhaseLeafHashRecord {
                    proof_idx: 0,
                    query_idx,
                    round,
                    leaf_idx,
                    left: leafs[0],
                    right: leafs[1],
                    input: ext_pair_poseidon2_input(leafs[0], leafs[1]),
                    output_state: leaf_state,
                });
            record_commit_phase_merkle_path(
                query_idx,
                round,
                leaf_idx,
                leaf_hash,
                &opening.opening_proof,
                preflight,
            );
            preflight
                .pcs
                .basefold_commit_phase_queries
                .push(PcsBasefoldCommitPhaseQueryRecord {
                    proof_idx: 0,
                    query_idx,
                    round,
                    query_value: query,
                    idx_in,
                    idx_out: idx >> 1,
                    log2_height,
                    is_first: round == 0,
                    has_reduced_opening: had_reduced,
                    reduced_opening,
                    folded_idx,
                    folded_in: folded,
                    sibling_value: opening.sibling_value,
                    challenge,
                    coeff: RecursionField::from(coeff),
                    folded_out,
                    is_last: round + 1 == rounds_len,
                });
            folded = folded_out;
            log2_height -= 1;
            idx >>= 1;
        }
        if !reduced_by_height.is_empty() {
            bail!("basefold unused reduced openings remain");
        }
        let final_index = idx;
        let final_coeffs = final_codeword_coeffs(proof.final_message[0].len(), final_index)?;
        let mut acc = RecursionField::ZERO;
        let mut flat_idx = 0usize;
        for row in &proof.final_message {
            for (elem_idx, value) in row.iter().copied().enumerate() {
                let coeff = final_coeffs[elem_idx];
                let acc_in = acc;
                acc += coeff * value;
                preflight
                    .pcs
                    .basefold_final_codeword
                    .push(PcsBasefoldFinalCodewordRecord {
                        proof_idx: 0,
                        query_idx,
                        elem_idx,
                        final_tidx: final_tidx + flat_idx * D_EF,
                        is_first: flat_idx == 0,
                        is_last: flat_idx + 1
                            == proof.final_message.iter().map(Vec::len).sum::<usize>(),
                        final_value: value,
                        coeff,
                        acc_in,
                        acc_out: acc,
                        folded,
                    });
                flat_idx += 1;
            }
        }
        if final_codeword.get(final_index).copied() != Some(acc) {
            bail!("basefold final codeword reconstruction mismatch");
        }
    }
    Ok(())
}

fn encode_small_final_message(
    final_message: &[Vec<RecursionField>],
) -> Result<Vec<RecursionField>> {
    if final_message.is_empty() {
        bail!("basefold final message is empty");
    }
    let width = final_message[0].len();
    if width == 0 || !width.is_power_of_two() || final_message.iter().any(|row| row.len() != width)
    {
        bail!("basefold final message shape mismatch");
    }
    let mut values = (0..width)
        .map(|j| final_message.iter().map(|row| row[j]).sum())
        .collect_vec();
    values.resize(
        width * (1 << <BasefoldRSParams as BasefoldSpec<RecursionField>>::get_rate_log()),
        RecursionField::ZERO,
    );
    Ok(Radix2Dit::<RecursionField>::default()
        .dft_batch(P3RowMajorMatrix::new(values, 1))
        .bit_reverse_rows()
        .to_row_major_matrix()
        .values)
}

fn final_codeword_coeffs(width: usize, final_index: usize) -> Result<Vec<RecursionField>> {
    let encoded_len =
        width * (1 << <BasefoldRSParams as BasefoldSpec<RecursionField>>::get_rate_log());
    if final_index >= encoded_len {
        bail!("basefold final codeword index out of range");
    }
    let mut coeffs = Vec::with_capacity(width);
    for elem_idx in 0..width {
        let mut values = vec![RecursionField::ZERO; encoded_len];
        values[elem_idx] = RecursionField::ONE;
        let encoded = Radix2Dit::<RecursionField>::default()
            .dft_batch(P3RowMajorMatrix::new(values, 1))
            .bit_reverse_rows()
            .to_row_major_matrix()
            .values;
        coeffs.push(encoded[final_index]);
    }
    Ok(coeffs)
}

fn verifier_folding_coeff(log2_height: usize, leaf_idx: usize) -> F {
    let g_inv = F::two_adic_generator(log2_height).inverse();
    let idx_bit_rev = reverse_bits_len(leaf_idx, log2_height - 1);
    g_inv.exp_u64(idx_bit_rev as u64) * F::from_usize(2).inverse()
}

fn fold_codeword_pair(
    leafs: [RecursionField; 2],
    challenge: RecursionField,
    coeff: F,
) -> RecursionField {
    let inv_2 = RecursionField::from(F::from_usize(2).inverse());
    let coeff = RecursionField::from(coeff);
    let lo = (leafs[0] + leafs[1]) * inv_2;
    let hi = (leafs[0] - leafs[1]) * coeff;
    lo + challenge * (hi - lo)
}

fn record_base_input_mmcs(
    query_idx: usize,
    opening_idx: usize,
    reduced_index: usize,
    openings: &[BasefoldOpening],
    opened_values: &[Vec<F>],
    proof: &[[F; DIGEST_SIZE]],
    preflight: &mut Preflight,
) -> Result<()> {
    let rate_log = <BasefoldRSParams as BasefoldSpec<RecursionField>>::get_rate_log();
    let Some((first_num_var, _)) = openings.first() else {
        bail!("base input MMCS opening is empty");
    };
    let log2_height = first_num_var + rate_log;
    if openings
        .iter()
        .any(|(num_var, _)| num_var + rate_log != log2_height)
    {
        bail!("base input mixed-height MMCS opening is not yet AIR-encoded");
    }

    let mut flat_values = Vec::new();
    for (value_idx, ((_, (_, evals)), mat)) in openings.iter().zip(opened_values).enumerate() {
        if mat.len() != evals.len() {
            bail!("base input opened-value width mismatch");
        }
        for (elem_idx, value) in mat.iter().copied().enumerate() {
            flat_values.push((value_idx, elem_idx, RecursionField::from(value)));
        }
    }
    if flat_values.is_empty() {
        bail!("base input leaf has no opened values");
    }
    if proof.is_empty() {
        bail!("base input MMCS proof path is empty");
    }

    let mut state = [F::ZERO; POSEIDON2_WIDTH];
    let num_blocks = flat_values.len().div_ceil(8);
    for block_idx in 0..num_blocks {
        let state_in = state;
        let mut input = state_in;
        let mut value_is_present = [false; 8];
        let mut value_idx = [0usize; 8];
        let mut elem_idx = [0usize; 8];
        let mut values = [RecursionField::ZERO; 8];
        for (slot, (row_idx, elem, value)) in flat_values
            .iter()
            .copied()
            .skip(block_idx * 8)
            .take(8)
            .enumerate()
        {
            value_is_present[slot] = true;
            value_idx[slot] = row_idx;
            elem_idx[slot] = elem;
            values[slot] = value;
            input[slot] = value.as_bases()[0];
        }
        state = input;
        poseidon2_perm().permute_mut(&mut state);
        preflight
            .pcs
            .base_input_leaf_hashes
            .push(PcsBaseInputLeafHashRecord {
                proof_idx: 0,
                query_idx,
                opening_idx,
                block_idx,
                log2_height,
                reduced_index,
                is_first: block_idx == 0,
                is_last: block_idx + 1 == num_blocks,
                value_is_present,
                value_idx,
                elem_idx,
                values,
                state_in,
                input,
                output_state: state,
            });
    }

    let expected_root = if let Some(root) = preflight
        .pcs
        .commitment_roots
        .iter_mut()
        .find(|record| record.commit_major == 0 && record.commit_minor == opening_idx)
    {
        root.lookup_count += 1;
        Some(root.root)
    } else {
        None
    };

    let leaf_hash = state[..DIGEST_SIZE].try_into().unwrap();
    let replayed_root = record_base_input_merkle_path(
        query_idx,
        opening_idx,
        reduced_index,
        leaf_hash,
        proof,
        preflight,
    );
    if let Some(expected_root) = expected_root
        && replayed_root != expected_root
    {
        bail!("base input MMCS root replay mismatch");
    }
    Ok(())
}

fn record_base_input_merkle_path(
    query_idx: usize,
    opening_idx: usize,
    leaf_idx: usize,
    leaf_hash: [F; DIGEST_SIZE],
    proof: &[[F; DIGEST_SIZE]],
    preflight: &mut Preflight,
) -> [F; DIGEST_SIZE] {
    let mut current = leaf_hash;
    let mut idx = leaf_idx;
    for (step, sibling) in proof.iter().copied().enumerate() {
        let idx_bit = idx & 1;
        let (left, right) = if idx_bit == 0 {
            (current, sibling)
        } else {
            (sibling, current)
        };
        let output = poseidon2_compress_with_capacity(left, right).0;
        preflight
            .pcs
            .base_input_merkle_rows
            .push(PcsBaseInputMerkleRecord {
                proof_idx: 0,
                query_idx,
                opening_idx,
                step,
                is_first: step == 0,
                is_last: step + 1 == proof.len(),
                idx_in: idx,
                idx_bit,
                idx_out: idx >> 1,
                current,
                sibling,
                left,
                right,
                output,
            });
        current = output;
        idx >>= 1;
    }
    current
}

fn digest_to_array<D>(digest: &D) -> Result<[F; DIGEST_SIZE]>
where
    D: Clone + IntoIterator<Item = F>,
{
    let values = digest.clone().into_iter().collect_vec();
    values
        .try_into()
        .map_err(|values: Vec<F>| eyre::eyre!("unexpected digest width {}", values.len()))
}

fn ext_pair_poseidon2_input(left: RecursionField, right: RecursionField) -> [F; POSEIDON2_WIDTH] {
    let mut input = [F::ZERO; POSEIDON2_WIDTH];
    input[..D_EF].copy_from_slice(left.as_bases());
    input[D_EF..2 * D_EF].copy_from_slice(right.as_bases());
    input
}

fn poseidon2_hash_ext_pair(left: RecursionField, right: RecursionField) -> [F; POSEIDON2_WIDTH] {
    let mut state = ext_pair_poseidon2_input(left, right);
    poseidon2_perm().permute_mut(&mut state);
    state
}

fn record_commit_phase_merkle_path(
    query_idx: usize,
    round: usize,
    leaf_idx: usize,
    leaf_hash: [F; DIGEST_SIZE],
    proof: &[[F; DIGEST_SIZE]],
    preflight: &mut Preflight,
) {
    let mut current = leaf_hash;
    let mut idx = leaf_idx;
    for (step, sibling) in proof.iter().copied().enumerate() {
        let idx_bit = idx & 1;
        let (left, right) = if idx_bit == 0 {
            (current, sibling)
        } else {
            (sibling, current)
        };
        let output = poseidon2_compress_with_capacity(left, right).0;
        preflight
            .pcs
            .commit_phase_merkle_rows
            .push(PcsCommitPhaseMerkleRecord {
                proof_idx: 0,
                query_idx,
                round,
                step,
                is_first: step == 0,
                is_last: step + 1 == proof.len(),
                idx_in: idx,
                idx_bit,
                idx_out: idx >> 1,
                current,
                sibling,
                left,
                right,
                output,
            });
        current = output;
        idx >>= 1;
    }
}

fn sample_vec_with_records<TS>(
    ts: &mut TS,
    n: usize,
    preflight: &mut Preflight,
    proof_idx: usize,
    idx_base: usize,
) -> Vec<RecursionField>
where
    TS: FiatShamirTranscript<BabyBearPoseidon2Config>
        + TranscriptHistory<F = F, State = [F; POSEIDON2_WIDTH]>,
{
    (0..n)
        .map(|i| {
            let tidx = ts.len();
            let value = FiatShamirTranscript::<BabyBearPoseidon2Config>::sample_ext(ts);
            preflight
                .pcs
                .transcript_values
                .push(PcsTranscriptValueRecord {
                    proof_idx,
                    idx: idx_base + i,
                    tidx,
                    value,
                    is_sample: true,
                    is_ext: true,
                    is_final_message: false,
                    is_query_sample: false,
                    is_batch_alpha: false,
                    is_basefold_eval: false,
                    transcript_ext_lookup_count: 0,
                    is_jagged_f_at_rho: false,
                });
            value
        })
        .collect()
}

fn sample_challenge_pows<TS>(
    ts: &mut TS,
    size: usize,
    preflight: &mut Preflight,
) -> Vec<RecursionField>
where
    TS: FiatShamirTranscript<BabyBearPoseidon2Config>
        + TranscriptHistory<F = F, State = [F; POSEIDON2_WIDTH]>,
{
    if size == 0 {
        return Vec::new();
    }
    let tidx = ts.len();
    let alpha = FiatShamirTranscript::<BabyBearPoseidon2Config>::sample_ext(ts);
    preflight
        .pcs
        .transcript_values
        .push(PcsTranscriptValueRecord {
            proof_idx: 0,
            idx: 2_500_000,
            tidx,
            value: alpha,
            is_sample: true,
            is_ext: true,
            is_final_message: false,
            is_query_sample: false,
            is_batch_alpha: true,
            is_basefold_eval: false,
            transcript_ext_lookup_count: 0,
            is_jagged_f_at_rho: false,
        });
    let mut out = Vec::with_capacity(size);
    let mut acc = RecursionField::ONE;
    for global_coeff_idx in 0..size {
        out.push(acc);
        let next_coeff = acc * alpha;
        preflight.pcs.batch_coeffs.push(PcsBatchCoeffRecord {
            proof_idx: 0,
            global_coeff_idx,
            alpha_tidx: tidx,
            alpha,
            coeff: acc,
            next_coeff,
            lookup_count: <BasefoldRSParams as BasefoldSpec<RecursionField>>::get_number_queries(),
            is_first: global_coeff_idx == 0,
            is_last: global_coeff_idx + 1 == size,
        });
        acc = next_coeff;
    }
    out
}

fn observe_label_with_records<TS>(
    ts: &mut TS,
    label: &[u8],
    preflight: &mut Preflight,
    idx_base: usize,
) where
    TS: FiatShamirTranscript<BabyBearPoseidon2Config>
        + TranscriptHistory<F = F, State = [F; POSEIDON2_WIDTH]>,
{
    let label_f = <BabyBearExt4 as CenoExtensionField>::BaseField::bytes_to_field_elements(label);
    let start_tidx = ts.len();
    for (i, elem) in label_f.into_iter().enumerate() {
        ts.observe(elem);
        preflight
            .pcs
            .transcript_values
            .push(PcsTranscriptValueRecord {
                proof_idx: 0,
                idx: idx_base + i,
                tidx: start_tidx + i,
                value: RecursionField::from(elem),
                is_sample: false,
                is_ext: false,
                is_final_message: false,
                is_query_sample: false,
                is_batch_alpha: false,
                is_basefold_eval: false,
                transcript_ext_lookup_count: 0,
                is_jagged_f_at_rho: false,
            });
    }
}

fn check_witness_with_records<TS>(
    ts: &mut TS,
    bits: usize,
    witness: F,
    preflight: &mut Preflight,
) -> bool
where
    TS: FiatShamirTranscript<BabyBearPoseidon2Config>
        + TranscriptHistory<F = F, State = [F; POSEIDON2_WIDTH]>,
{
    let witness_tidx = ts.len();
    ts.observe(witness);
    preflight
        .pcs
        .transcript_values
        .push(PcsTranscriptValueRecord {
            proof_idx: 0,
            idx: 6_000_000,
            tidx: witness_tidx,
            value: RecursionField::from(witness),
            is_sample: false,
            is_ext: false,
            is_final_message: false,
            is_query_sample: false,
            is_batch_alpha: false,
            is_basefold_eval: false,
            transcript_ext_lookup_count: 0,
            is_jagged_f_at_rho: false,
        });
    sample_bits_with_record(ts, bits, preflight, 6_000_001, false).query_value == 0
}

struct SampleBitsRecord {
    tidx: usize,
    sampled_value: F,
    query_value: usize,
    high_value: usize,
}

fn sample_bits_with_record<TS>(
    ts: &mut TS,
    bits: usize,
    preflight: &mut Preflight,
    idx: usize,
    is_query_sample: bool,
) -> SampleBitsRecord
where
    TS: FiatShamirTranscript<BabyBearPoseidon2Config>
        + TranscriptHistory<F = F, State = [F; POSEIDON2_WIDTH]>,
{
    assert!(bits < (u32::BITS as usize));
    assert!((1 << bits) < F::ORDER_U64);
    let tidx = ts.len();
    let value = FiatShamirTranscript::<BabyBearPoseidon2Config>::sample(ts);
    preflight
        .pcs
        .transcript_values
        .push(PcsTranscriptValueRecord {
            proof_idx: 0,
            idx,
            tidx,
            value: RecursionField::from(value),
            is_sample: true,
            is_ext: false,
            is_final_message: false,
            is_query_sample,
            is_batch_alpha: false,
            is_basefold_eval: false,
            transcript_ext_lookup_count: 0,
            is_jagged_f_at_rho: false,
        });
    let raw = value.as_canonical_u64() as usize;
    let mask = (1usize << bits) - 1;
    SampleBitsRecord {
        tidx,
        sampled_value: value,
        query_value: raw & mask,
        high_value: raw >> bits,
    }
}

fn u32_bytes(value: usize) -> [u8; 4] {
    (value as u32).to_le_bytes()
}

fn one_hot_32(index: usize) -> [bool; 32] {
    let mut out = [false; 32];
    out[index] = true;
    out
}

fn observe_digest<TS, D>(ts: &mut TS, digest: &D, preflight: &mut Preflight, idx_base: usize)
where
    TS: FiatShamirTranscript<BabyBearPoseidon2Config>
        + TranscriptHistory<F = F, State = [F; POSEIDON2_WIDTH]>,
    D: Clone + IntoIterator<Item = F>,
{
    let start_tidx = ts_len_or_zero(ts);
    for (i, value) in digest.clone().into_iter().enumerate() {
        ts.observe(value);
        preflight
            .pcs
            .transcript_values
            .push(PcsTranscriptValueRecord {
                proof_idx: 0,
                idx: idx_base + i,
                tidx: start_tidx + i,
                value: RecursionField::from(value),
                is_sample: false,
                is_ext: false,
                is_final_message: false,
                is_query_sample: false,
                is_batch_alpha: false,
                is_basefold_eval: false,
                transcript_ext_lookup_count: 0,
                is_jagged_f_at_rho: false,
            });
    }
}

fn ts_len_or_zero<TS>(ts: &TS) -> usize
where
    TS: TranscriptHistory<F = F, State = [F; POSEIDON2_WIDTH]>,
{
    ts.len()
}

fn child_pow_bits() -> usize {
    16
}

fn trace_height(len: usize, required_height: Option<usize>) -> Option<usize> {
    let num_valid_rows = len.max(1);
    if let Some(height) = required_height {
        if height < num_valid_rows {
            return None;
        }
        Some(height)
    } else {
        Some(num_valid_rows.next_power_of_two())
    }
}

fn ext_limbs(value: EF) -> [F; D_EF] {
    value.as_basis_coefficients_slice().try_into().unwrap()
}

fn ext_sub<FA>(x: [impl Into<FA>; D_EF], y: [impl Into<FA>; D_EF]) -> [FA; D_EF]
where
    FA: PrimeCharacteristicRing,
{
    let [x0, x1, x2, x3] = x.map(Into::into);
    let [y0, y1, y2, y3] = y.map(Into::into);
    [x0 - y0, x1 - y1, x2 - y2, x3 - y3]
}

fn ext_add<FA>(x: [impl Into<FA>; D_EF], y: [impl Into<FA>; D_EF]) -> [FA; D_EF]
where
    FA: PrimeCharacteristicRing,
{
    let [x0, x1, x2, x3] = x.map(Into::into);
    let [y0, y1, y2, y3] = y.map(Into::into);
    [x0 + y0, x1 + y1, x2 + y2, x3 + y3]
}

fn interpolate_quad_at_012<F, FA>(
    ev0: [FA; D_EF],
    ev1: [F; D_EF],
    ev2: [F; D_EF],
    x: [F; D_EF],
) -> [FA; D_EF]
where
    F: Into<FA> + Copy,
    FA: PrimeCharacteristicRing,
    FA::PrimeSubfield: BinomiallyExtendable<{ D_EF }>,
{
    let x = x.map(Into::into);
    let ev1 = ev1.map(Into::into);
    let ev2 = ev2.map(Into::into);
    let one = [FA::ONE, FA::ZERO, FA::ZERO, FA::ZERO];
    let inv_two = FA::from_prime_subfield(FA::PrimeSubfield::from_usize(2).inverse());

    let slope: [FA; D_EF] =
        recursion_circuit::utils::ext_field_subtract::<FA>(ev1.clone(), ev0.clone());
    let second_diff: [FA; D_EF] = recursion_circuit::utils::ext_field_add::<FA>(
        recursion_circuit::utils::ext_field_subtract::<FA>(ev2, ev1.map(|v| v.clone() + v)),
        ev0.clone(),
    )
    .map(|v| v * inv_two.clone());
    let x_minus_one: [FA; D_EF] =
        recursion_circuit::utils::ext_field_subtract::<FA>(x.clone(), one);
    recursion_circuit::utils::ext_field_add::<FA>(
        recursion_circuit::utils::ext_field_add::<FA>(
            ev0,
            recursion_circuit::utils::ext_field_multiply::<FA>(slope, x.clone()),
        ),
        recursion_circuit::utils::ext_field_multiply::<FA>(
            second_diff,
            recursion_circuit::utils::ext_field_multiply::<FA>(x, x_minus_one),
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basefold_basecode_log_zero_is_only_supported_shape() {
        ensure_supported_basecode_log(0).expect("basecode_log 0 should be supported");
        let err = ensure_supported_basecode_log(1).expect_err("basecode_log > 0 must reject");
        assert!(
            err.to_string().contains("only basecode_log == 0"),
            "unexpected error: {err}"
        );
    }
}
