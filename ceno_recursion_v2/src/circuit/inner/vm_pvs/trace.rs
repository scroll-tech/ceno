use openvm_cpu_backend::CpuBackend;
use openvm_stark_backend::prover::AirProvingContext;
use openvm_stark_sdk::config::baby_bear_poseidon2::{
    BabyBearPoseidon2Config, D_EF, DIGEST_SIZE, EF, F,
};
use p3_field::{BasedVectorSpace, PrimeCharacteristicRing};
use p3_matrix::dense::RowMajorMatrix;
use std::borrow::BorrowMut;

use crate::{
    circuit::inner::{
        ProofsType,
        vm_pvs::{VmPvs, air::VmPvsCols},
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

    let fixed_commit = extract_commit(
        child_vk
            .fixed_commit
            .as_ref()
            .map(|commitment| commitment.commit.clone()),
    );
    let fixed_no_omc_init_commit = extract_commit(
        child_vk
            .fixed_no_omc_init_commit
            .as_ref()
            .map(|commitment| commitment.commit.clone()),
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
            cols.lookup_challenge_alpha = ef_to_limbs(preflight.vm_pvs.lookup_challenge_alpha);
            cols.lookup_challenge_beta = ef_to_limbs(preflight.vm_pvs.lookup_challenge_beta);
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
    }

    AirProvingContext {
        cached_mains: vec![],
        common_main: trace,
        public_values,
    }
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
        witness_commit: extract_commit(Some(proof.witin_commit.commit.clone())),
        exit_code: split_u32_lo_hi(pv.exit_code),
        init_pc: F::from_u32(pv.init_pc),
        init_cycle: F::from_u64(pv.init_cycle),
        end_pc: F::from_u32(pv.end_pc),
        end_cycle: F::from_u64(pv.end_cycle),
        shard_id: F::from_u32(pv.shard_id),
        heap_start_addr: F::from_u32(pv.heap_start_addr),
        heap_shard_len: F::from_u32(pv.heap_shard_len),
        hint_start_addr: F::from_u32(pv.hint_start_addr),
        hint_shard_len: F::from_u32(pv.hint_shard_len),
        public_io: split_u32_lo_hi(pv.public_io_digest[0]),
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

fn split_u32_lo_hi(value: u32) -> [F; 2] {
    [
        F::from_u32(value & 0xffff),
        F::from_u32((value >> 16) & 0xffff),
    ]
}

fn ef_to_limbs(value: EF) -> [F; D_EF] {
    let mut out = [F::ZERO; D_EF];
    out.copy_from_slice(value.as_basis_coefficients_slice());
    out
}
