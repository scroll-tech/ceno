use ceno_zkvm::{
    instructions::riscv::constants::{LIMB_BITS, LIMB_MASK, PUBIO_DIGEST_U16_LIMBS, UINT_LIMBS},
    scheme::constants::MAX_NUM_VARIABLES,
    structs::VK_DIGEST_LEN,
};
use openvm_cpu_backend::CpuBackend;
use openvm_stark_backend::prover::AirProvingContext;
use openvm_stark_sdk::config::baby_bear_poseidon2::{
    BabyBearPoseidon2Config, D_EF, DIGEST_SIZE, EF, F,
};
use p3_field::{BasedVectorSpace, PrimeCharacteristicRing, PrimeField32};
use p3_matrix::dense::RowMajorMatrix;
use std::borrow::BorrowMut;

use crate::{
    circuit::inner::{
        ProofsType,
        vm_pvs::{
            VmPvs,
            air::{RESHAPE_LOG_HEIGHT_DIFF_BITS, VmPvsCols},
            recursion_commit_digest,
        },
    },
    system::{Preflight, RecursionProof, RecursionVk},
};

pub fn generate_proving_ctx(
    child_vk: &RecursionVk,
    proofs: &[RecursionProof],
    preflights: &[Preflight],
    proofs_type: ProofsType,
    child_is_app: bool,
    deferral_enabled: bool,
) -> AirProvingContext<CpuBackend<BabyBearPoseidon2Config>> {
    debug_assert_eq!(proofs.len(), preflights.len());
    let _ = (proofs_type, child_is_app);
    assert!(
        !deferral_enabled,
        "VmPvs real-data path currently assumes deferral is disabled"
    );

    let rows = proofs.len().max(1).next_power_of_two();
    let width = VmPvsCols::<u8>::width() + (deferral_enabled as usize);
    let mut trace = vec![F::ZERO; rows * width];

    let fixed_commit = extract_commit(child_vk.fixed_commit.as_ref().map(recursion_commit_digest));
    let fixed_no_omc_init_commit = extract_commit(
        child_vk
            .fixed_no_omc_init_commit
            .as_ref()
            .map(recursion_commit_digest),
    );

    for (row_idx, row) in trace.chunks_exact_mut(width).enumerate() {
        let (base_row, def_row) = row.split_at_mut(VmPvsCols::<u8>::width());
        let cols: &mut VmPvsCols<F> = base_row.borrow_mut();
        cols.proof_idx = F::from_usize(row_idx);

        if row_idx < proofs.len() {
            let proof = &proofs[row_idx];
            let preflight = &preflights[row_idx];
            cols.is_valid = F::ONE;
            cols.is_last = F::from_bool(row_idx + 1 == proofs.len());
            cols.has_verifier_pvs = F::ZERO;
            cols.fixed_commit_present = F::from_bool(child_vk.fixed_commit.is_some());
            cols.fixed_no_omc_init_commit_present =
                F::from_bool(child_vk.fixed_no_omc_init_commit.is_some());
            cols.lookup_challenge_alpha = ef_to_limbs(preflight.vm_pvs.lookup_challenge_alpha);
            cols.lookup_challenge_beta = ef_to_limbs(preflight.vm_pvs.lookup_challenge_beta);
            cols.lookup_challenge_alpha_tidx =
                F::from_usize(preflight.vm_pvs.lookup_challenge_alpha_tidx);
            cols.lookup_challenge_beta_tidx =
                F::from_usize(preflight.vm_pvs.lookup_challenge_beta_tidx);
            let (fixed_tidx, fixed_no_omc_tidx, witness_tidx) =
                commitment_digest_tidxs(child_vk, proof);
            cols.fixed_commit_tidx = F::from_usize(fixed_tidx);
            cols.fixed_no_omc_init_commit_tidx = F::from_usize(fixed_no_omc_tidx);
            cols.witness_commit_tidx = F::from_usize(witness_tidx);
            let fixed_meta = child_vk
                .fixed_commit
                .as_ref()
                .map(commit_fixed_metadata)
                .unwrap_or_default();
            cols.fixed_commit_log2_max_codeword_size = fixed_meta[0];
            cols.fixed_commit_reshape_log_height = fixed_meta[1];
            if let Some(commitment) = child_vk.fixed_commit.as_ref() {
                assert_reshape_log_height_capacity(commitment.reshape_log_height);
            }
            cols.fixed_commit_cumulative_heights_len = fixed_meta[2];
            let fixed_no_omc_meta = child_vk
                .fixed_no_omc_init_commit
                .as_ref()
                .map(commit_fixed_metadata)
                .unwrap_or_default();
            cols.fixed_no_omc_init_commit_log2_max_codeword_size = fixed_no_omc_meta[0];
            cols.fixed_no_omc_init_commit_reshape_log_height = fixed_no_omc_meta[1];
            if let Some(commitment) = child_vk.fixed_no_omc_init_commit.as_ref() {
                assert_reshape_log_height_capacity(commitment.reshape_log_height);
            }
            cols.fixed_no_omc_init_commit_cumulative_heights_len = fixed_no_omc_meta[2];
            let witness_meta = commit_fixed_metadata(&proof.witin_commit);
            cols.witness_commit_log2_max_codeword_size = witness_meta[0];
            cols.witness_commit_reshape_log_height = witness_meta[1];
            cols.witness_commit_reshape_log_height_diff_bits =
                reshape_log_height_diff_bits(proof.witin_commit.reshape_log_height);
            cols.witness_commit_cumulative_heights_len = witness_meta[2];
            cols.lookup_challenge_alpha_lookup_count =
                F::from_usize(preflight.vm_pvs.lookup_challenge_alpha_lookup_count);
            cols.lookup_challenge_beta_lookup_count =
                F::from_usize(preflight.vm_pvs.lookup_challenge_beta_lookup_count);
            cols.child_pvs = build_vm_pvs(fixed_commit, fixed_no_omc_init_commit, proof);
        }

        if deferral_enabled {
            def_row[0] = F::ZERO;
        }
    }

    let trace = RowMajorMatrix::new(trace, width);
    let mut public_values = vec![F::ZERO; VmPvs::<u8>::width()];
    if let (Some(first), Some(last)) = (proofs.first(), proofs.last()) {
        let pvs: &mut VmPvs<F> = public_values.as_mut_slice().borrow_mut();
        *pvs = build_vm_pvs(fixed_commit, fixed_no_omc_init_commit, first);
        pvs.exit_code = split_u32_lo_hi(last.public_values.exit_code);
        pvs.end_pc = F::from_u32(last.public_values.end_pc);
        pvs.end_cycle = F::from_u64(last.public_values.end_cycle);
        pvs.shard_count =
            aggregate_shard_count(first.public_values.shard_id, last.public_values.shard_id);
        pvs.heap_shard_len = aggregate_word_len(
            first.public_values.heap_start_addr,
            last.public_values.heap_start_addr,
            last.public_values.heap_shard_len,
        );
        pvs.hint_shard_len = aggregate_word_len(
            first.public_values.hint_start_addr,
            last.public_values.hint_start_addr,
            last.public_values.hint_shard_len,
        );

        debug_vm_pvs(child_vk, first, fixed_commit, fixed_no_omc_init_commit, pvs);
    }

    AirProvingContext {
        cached_mains: vec![],
        common_main: trace,
        public_values,
    }
}

fn debug_vm_pvs(
    child_vk: &RecursionVk,
    first: &RecursionProof,
    fixed_commit: [F; DIGEST_SIZE],
    fixed_no_omc_init_commit: [F; DIGEST_SIZE],
    aggregate_pvs: &VmPvs<F>,
) {
    if std::env::var_os("CENO_REC_V2_DEBUG_VM_PVS").is_none() {
        return;
    }

    let first_pvs = build_vm_pvs(fixed_commit, fixed_no_omc_init_commit, first);
    eprintln!(
        "rec-v2-debug module=vm_pvs source=trace row=0 first_init_pc={:#x} first_init_cycle={} child_vk_entry_pc={:#x} aggregate_init_pc={:#x} aggregate_init_cycle={} fixed_commit_eq={} fixed_no_omc_init_commit_eq={} witness_commit_eq={}",
        first.public_values.init_pc,
        first.public_values.init_cycle,
        child_vk.entry_pc,
        aggregate_pvs.init_pc.as_canonical_u32(),
        aggregate_pvs.init_cycle.as_canonical_u32(),
        first_pvs.fixed_commit == aggregate_pvs.fixed_commit,
        first_pvs.fixed_no_omc_init_commit == aggregate_pvs.fixed_no_omc_init_commit,
        first_pvs.witness_commit == aggregate_pvs.witness_commit,
    );
}

fn build_vm_pvs(
    fixed_commit: [F; DIGEST_SIZE],
    fixed_no_omc_init_commit: [F; DIGEST_SIZE],
    proof: &RecursionProof,
) -> VmPvs<F> {
    let pv = &proof.public_values;
    VmPvs {
        fixed_commit,
        fixed_no_omc_init_commit,
        witness_commit: extract_commit(Some(recursion_commit_digest(&proof.witin_commit))),
        exit_code: split_u32_lo_hi(pv.exit_code),
        init_pc: F::from_u32(pv.init_pc),
        init_cycle: F::from_u64(pv.init_cycle),
        end_pc: F::from_u32(pv.end_pc),
        end_cycle: F::from_u64(pv.end_cycle),
        shard_id: F::from_u32(pv.shard_id),
        shard_count: F::ONE,
        heap_start_addr: F::from_u32(pv.heap_start_addr),
        heap_shard_len: F::from_u32(pv.heap_shard_len),
        hint_start_addr: F::from_u32(pv.hint_start_addr),
        hint_shard_len: F::from_u32(pv.hint_shard_len),
        public_io: split_public_io_digest(pv.public_io_digest),
        shard_rw_sum: pv.shard_rw_sum.map(F::from_u32),
    }
}

fn extract_commit(commit: Option<impl IntoIterator<Item = F>>) -> [F; DIGEST_SIZE] {
    let mut out = [F::ZERO; DIGEST_SIZE];
    if let Some(commit) = commit {
        for (dst, src) in out.iter_mut().zip(commit) {
            *dst = src;
        }
    }
    out
}

fn commitment_digest_tidxs(
    child_vk: &RecursionVk,
    _proof: &RecursionProof,
) -> (usize, usize, usize) {
    let mut tidx = crate::utils::TranscriptLabel::Riscv.field_len()
        + VK_DIGEST_LEN * D_EF
        + child_vk
            .circuit_vks
            .values()
            .map(|circuit_vk| circuit_vk.get_cs().zkvm_v1_css.instance.len())
            .sum::<usize>();

    let fixed_tidx = tidx;
    if let Some(commitment) = child_vk.fixed_commit.as_ref() {
        tidx += commitment_transcript_len(commitment);
    }

    let fixed_no_omc_tidx = tidx;
    if let Some(commitment) = child_vk.fixed_no_omc_init_commit.as_ref() {
        tidx += commitment_transcript_len(commitment);
    }

    let witness_tidx = tidx;
    (fixed_tidx, fixed_no_omc_tidx, witness_tidx)
}

fn commitment_transcript_len(commitment: &super::RecursionCommitment) -> usize {
    DIGEST_SIZE + 3 + commitment.cumulative_heights.len()
}

fn commit_fixed_metadata(commitment: &super::RecursionCommitment) -> [F; 3] {
    [
        F::from_u64(commitment.inner.log2_max_codeword_size as u64),
        F::from_u64(commitment.reshape_log_height as u64),
        F::from_u64(commitment.cumulative_heights.len() as u64),
    ]
}

fn reshape_log_height_diff_bits(reshape_log_height: usize) -> [F; RESHAPE_LOG_HEIGHT_DIFF_BITS] {
    assert_reshape_log_height_capacity(reshape_log_height);
    let diff = MAX_NUM_VARIABLES - reshape_log_height;
    core::array::from_fn(|idx| F::from_bool(((diff >> idx) & 1) == 1))
}

fn assert_reshape_log_height_capacity(reshape_log_height: usize) {
    assert!(
        reshape_log_height <= MAX_NUM_VARIABLES,
        "recursion commitment reshape_log_height {reshape_log_height} exceeds max {MAX_NUM_VARIABLES}"
    );
}

fn split_u32_lo_hi(value: u32) -> [F; 2] {
    [
        F::from_u32(value & 0xffff),
        F::from_u32((value >> 16) & 0xffff),
    ]
}

fn split_public_io_digest(digest: [u32; 8]) -> [F; PUBIO_DIGEST_U16_LIMBS] {
    core::array::from_fn(|digest_limb_idx| {
        let word_idx = digest_limb_idx / UINT_LIMBS;
        let limb_idx = digest_limb_idx % UINT_LIMBS;
        F::from_u32((digest[word_idx] >> (limb_idx * LIMB_BITS)) & LIMB_MASK)
    })
}

fn ef_to_limbs(value: EF) -> [F; D_EF] {
    let mut out = [F::ZERO; D_EF];
    out.copy_from_slice(value.as_basis_coefficients_slice());
    out
}

fn aggregate_word_len(first_start: u32, last_start: u32, last_len: u32) -> F {
    let last_end = last_start
        .checked_add(
            last_len
                .checked_mul(ceno_emul::WORD_SIZE as u32)
                .expect("range overflow"),
        )
        .expect("range overflow");
    let bytes = last_end
        .checked_sub(first_start)
        .expect("non-contiguous aggregate range");
    assert_eq!(
        bytes % ceno_emul::WORD_SIZE as u32,
        0,
        "aggregate range must be word-aligned"
    );
    F::from_u32(bytes / ceno_emul::WORD_SIZE as u32)
}

fn aggregate_shard_count(first_shard_id: u32, last_shard_id: u32) -> F {
    let count = last_shard_id
        .checked_sub(first_shard_id)
        .and_then(|delta| delta.checked_add(1))
        .expect("non-contiguous aggregate shard range");
    F::from_u32(count)
}
