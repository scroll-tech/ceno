use core::borrow::{Borrow, BorrowMut};

use openvm_cpu_backend::CpuBackend;
use openvm_stark_backend::{
    BaseAirWithPublicValues, PartitionedBaseAir, interaction::InteractionBuilder,
    prover::AirProvingContext,
};
use openvm_stark_sdk::config::baby_bear_poseidon2::{BabyBearPoseidon2Config, DIGEST_SIZE, F};
use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::PrimeCharacteristicRing;
use p3_matrix::{Matrix, dense::RowMajorMatrix};
use stark_recursion_circuit_derive::AlignedBorrow;

use crate::{
    bus::{TranscriptBus, TranscriptBusMessage},
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
}

pub struct VmPvsCumulativeHeightsAir {
    pub transcript_bus: TranscriptBus,
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
        for (row, (proof_idx, commitment_kind, height_idx, tidx, value)) in
            trace.chunks_exact_mut(width).zip(rows)
        {
            let cols: &mut VmPvsCumulativeHeightsCols<F> = row.borrow_mut();
            cols.proof_idx = F::from_usize(proof_idx);
            cols.is_valid = F::ONE;
            cols.commitment_kind = F::from_usize(commitment_kind);
            cols.height_idx = F::from_usize(height_idx);
            cols.tidx = F::from_usize(tidx);
            cols.value = value;
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
) -> Vec<(usize, usize, usize, usize, F)> {
    proofs
        .iter()
        .zip(preflights)
        .enumerate()
        .flat_map(|(proof_idx, (proof, preflight))| {
            let mut tidx = TranscriptLabel::Riscv.field_len()
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

            rows.into_iter()
                .filter_map(|(proof_idx, commitment_kind, height_idx, tidx)| {
                    preflight
                        .transcript
                        .values()
                        .get(tidx)
                        .copied()
                        .map(|value| (proof_idx, commitment_kind, height_idx, tidx, value))
                })
                .collect::<Vec<_>>()
        })
        .collect()
}

fn commitment_transcript_len(commitment: &RecursionCommitment) -> usize {
    DIGEST_SIZE + 3 + commitment.cumulative_heights.len()
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
