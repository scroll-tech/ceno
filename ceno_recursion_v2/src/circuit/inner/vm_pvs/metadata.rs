use core::borrow::{Borrow, BorrowMut};

use ceno_zkvm::structs::VK_DIGEST_LEN;
use openvm_cpu_backend::CpuBackend;
use openvm_stark_backend::{
    BaseAirWithPublicValues, PartitionedBaseAir, interaction::InteractionBuilder,
    prover::AirProvingContext,
};
use openvm_stark_sdk::config::baby_bear_poseidon2::{
    BabyBearPoseidon2Config, D_EF, DIGEST_SIZE, F,
};
use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::PrimeCharacteristicRing;
use p3_matrix::{Matrix, dense::RowMajorMatrix};
use stark_recursion_circuit_derive::AlignedBorrow;

use crate::{
    bus::{PcsCommitHeightBus, PcsCommitHeightMessage, TranscriptBus, TranscriptBusMessage},
    circuit::inner::vm_pvs::RecursionCommitment,
    system::{Preflight, RecursionProof, RecursionVk},
    tracegen::RowMajorChip,
    utils::TranscriptLabel,
};

#[repr(C)]
#[derive(AlignedBorrow, Debug)]
pub struct VmPvsCumulativeHeightsCols<T> {
    pub proof_idx: T,
    pub is_valid: T,
    pub commitment_kind: T,
    pub height_idx: T,
    pub tidx: T,
    pub value: T,
    pub lookup_count: T,
}

pub struct VmPvsCumulativeHeightsAir {
    pub transcript_bus: TranscriptBus,
    pub commit_height_bus: PcsCommitHeightBus,
}

impl<F> BaseAir<F> for VmPvsCumulativeHeightsAir {
    fn width(&self) -> usize {
        VmPvsCumulativeHeightsCols::<u8>::width()
    }
}

impl<F> BaseAirWithPublicValues<F> for VmPvsCumulativeHeightsAir {}
impl<F> PartitionedBaseAir<F> for VmPvsCumulativeHeightsAir {}

impl<AB: AirBuilder + InteractionBuilder> Air<AB> for VmPvsCumulativeHeightsAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0).expect("main row exists");
        let local: &VmPvsCumulativeHeightsCols<AB::Var> = (*local).borrow();

        builder.assert_bool(local.is_valid);
        self.transcript_bus.receive(
            builder,
            local.proof_idx,
            TranscriptBusMessage {
                tidx: local.tidx.into(),
                value: local.value.into(),
                is_sample: AB::Expr::ZERO,
            },
            local.is_valid,
        );
        self.commit_height_bus.add_key_with_lookups(
            builder,
            local.proof_idx,
            PcsCommitHeightMessage {
                commitment_kind: local.commitment_kind.into(),
                height_idx: local.height_idx.into(),
                value: local.value.into(),
            },
            local.is_valid * local.lookup_count,
        );
    }
}

pub struct VmPvsCumulativeHeightsTraceGenerator;

impl RowMajorChip<F> for VmPvsCumulativeHeightsTraceGenerator {
    type Ctx<'a> = (&'a RecursionVk, &'a [RecursionProof], &'a [Preflight]);

    fn generate_trace(
        &self,
        ctx: &Self::Ctx<'_>,
        required_height: Option<usize>,
    ) -> Option<RowMajorMatrix<F>> {
        let (child_vk, proofs, preflights) = ctx;
        let rows = collect_rows(child_vk, proofs, preflights);
        let width = VmPvsCumulativeHeightsCols::<u8>::width();
        let height = if let Some(height) = required_height {
            if height < rows.len() {
                return None;
            }
            height
        } else {
            rows.len().max(1).next_power_of_two()
        };

        let mut trace = vec![F::ZERO; height * width];
        for (row, (proof_idx, commitment_kind, height_idx, tidx, value, lookup_count)) in
            trace.chunks_exact_mut(width).zip(rows)
        {
            let cols: &mut VmPvsCumulativeHeightsCols<F> = row.borrow_mut();
            cols.proof_idx = F::from_usize(proof_idx);
            cols.is_valid = F::ONE;
            cols.commitment_kind = F::from_usize(commitment_kind);
            cols.height_idx = F::from_usize(height_idx);
            cols.tidx = F::from_usize(tidx);
            cols.value = value;
            cols.lookup_count = F::from_usize(lookup_count);
        }
        Some(RowMajorMatrix::new(trace, width))
    }
}

pub fn generate_metadata_proving_ctx(
    child_vk: &RecursionVk,
    proofs: &[RecursionProof],
    preflights: &[Preflight],
) -> AirProvingContext<CpuBackend<BabyBearPoseidon2Config>> {
    let trace = VmPvsCumulativeHeightsTraceGenerator
        .generate_trace(&(child_vk, proofs, preflights), None)
        .expect(
            "VM PVS cumulative heights trace generation should not fail without required height",
        );
    AirProvingContext::simple_no_pis(trace)
}

fn collect_rows(
    child_vk: &RecursionVk,
    proofs: &[RecursionProof],
    preflights: &[Preflight],
) -> Vec<(usize, usize, usize, usize, F, usize)> {
    proofs
        .iter()
        .zip(preflights)
        .enumerate()
        .flat_map(|(proof_idx, (proof, preflight))| {
            let mut tidx = TranscriptLabel::Riscv.field_len()
                + VK_DIGEST_LEN * D_EF
                + child_vk
                    .circuit_vks
                    .values()
                    .map(|circuit_vk| circuit_vk.get_cs().zkvm_v1_css.instance.len())
                    .sum::<usize>();

            let mut rows = Vec::new();
            if let Some(commitment) = child_vk.fixed_commit.as_ref() {
                push_commit_cumulative_height_rows(&mut rows, proof_idx, 0, tidx, commitment);
                tidx += commitment_transcript_len(commitment);
            }
            if let Some(commitment) = child_vk.fixed_no_omc_init_commit.as_ref() {
                push_commit_cumulative_height_rows(&mut rows, proof_idx, 1, tidx, commitment);
                tidx += commitment_transcript_len(commitment);
            }
            push_commit_cumulative_height_rows(&mut rows, proof_idx, 2, tidx, &proof.witin_commit);

            let mut lookup_counts =
                std::collections::BTreeMap::<(usize, usize, usize), usize>::new();
            if proof.public_values.shard_id == 0 {
                if let Some(commitment) = child_vk.fixed_commit.as_ref() {
                    accumulate_commit_height_lookup_counts(
                        &mut lookup_counts,
                        proof_idx,
                        0,
                        commitment,
                    );
                }
            } else if let Some(commitment) = child_vk.fixed_no_omc_init_commit.as_ref() {
                accumulate_commit_height_lookup_counts(
                    &mut lookup_counts,
                    proof_idx,
                    1,
                    commitment,
                );
            }
            accumulate_commit_height_lookup_counts(
                &mut lookup_counts,
                proof_idx,
                2,
                &proof.witin_commit,
            );

            rows.into_iter()
                .filter_map(|(proof_idx, commitment_kind, height_idx, tidx)| {
                    preflight
                        .transcript
                        .values()
                        .get(tidx)
                        .copied()
                        .map(|value| {
                            let lookup_count = lookup_counts
                                .get(&(proof_idx, commitment_kind, height_idx))
                                .copied()
                                .unwrap_or_default();
                            (
                                proof_idx,
                                commitment_kind,
                                height_idx,
                                tidx,
                                value,
                                lookup_count,
                            )
                        })
                })
                .collect::<Vec<_>>()
        })
        .collect()
}

fn commitment_transcript_len(commitment: &RecursionCommitment) -> usize {
    DIGEST_SIZE + 3 + commitment.cumulative_heights.len()
}

fn accumulate_commit_height_lookup_counts(
    lookup_counts: &mut std::collections::BTreeMap<(usize, usize, usize), usize>,
    proof_idx: usize,
    commitment_kind: usize,
    commitment: &RecursionCommitment,
) {
    for term_idx in 0..commitment.cumulative_heights.len().saturating_sub(1) {
        *lookup_counts
            .entry((proof_idx, commitment_kind, term_idx))
            .or_default() += 1;
        *lookup_counts
            .entry((proof_idx, commitment_kind, term_idx + 1))
            .or_default() += 1;
    }
}

fn push_commit_cumulative_height_rows(
    rows: &mut Vec<(usize, usize, usize, usize)>,
    proof_idx: usize,
    commitment_kind: usize,
    commitment_start_tidx: usize,
    commitment: &RecursionCommitment,
) {
    let heights_start = commitment_start_tidx + DIGEST_SIZE + 3;
    for height_idx in 0..commitment.cumulative_heights.len() {
        rows.push((
            proof_idx,
            commitment_kind,
            height_idx,
            heights_start + height_idx,
        ));
    }
}
