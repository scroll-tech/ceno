use std::borrow::{Borrow, BorrowMut};

use eyre::{Result, eyre};
use openvm_cpu_backend::CpuBackend;
#[cfg(feature = "cuda")]
use openvm_cuda_backend::{GpuBackend, hash_scheme::DefaultHashScheme};
#[cfg(feature = "cuda")]
use openvm_cuda_common::stream::GpuDeviceCtx;
use openvm_stark_backend::{proof::Proof, prover::AirProvingContext};
use openvm_stark_sdk::config::baby_bear_poseidon2::{BabyBearPoseidon2Config, F};
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_matrix::dense::RowMajorMatrix;
use verify_stark::pvs::{VERIFIER_PVS_AIR_ID, VerifierBasePvs, VkCommit};

use crate::circuit::{
    inner::vm_pvs::VmPvs,
    recursive::{verifier::CenoRecursiveVerifierPvsCols, vm_pvs::CenoRecursiveVmPvsCols},
    root::verifier::CENO_VM_PVS_AIR_ID,
};

pub fn generate_verifier_pvs_ctx(
    proofs: &[Proof<BabyBearPoseidon2Config>],
    child_vk_commit: VkCommit<F>,
) -> Result<AirProvingContext<CpuBackend<BabyBearPoseidon2Config>>> {
    let first = child_verifier_pvs(proofs.first().ok_or_else(|| eyre!("no child proofs"))?)?;
    for proof in proofs {
        let pvs = child_verifier_pvs(proof)?;
        if pvs.internal_flag != first.internal_flag || pvs.recursion_flag != first.recursion_flag {
            return Err(eyre!("mixed recursive child verifier public-value levels"));
        }
    }

    let rows = proofs.len().next_power_of_two();
    let width = CenoRecursiveVerifierPvsCols::<u8>::width();
    let mut trace = vec![F::ZERO; rows * width];
    for (proof_idx, proof) in proofs.iter().enumerate() {
        let cols: &mut CenoRecursiveVerifierPvsCols<F> =
            trace[proof_idx * width..(proof_idx + 1) * width].borrow_mut();
        cols.proof_idx = F::from_usize(proof_idx);
        cols.is_valid = F::ONE;
        cols.is_last = F::from_bool(proof_idx + 1 == proofs.len());
        cols.child_pvs = *child_verifier_pvs(proof)?;
    }

    let mut public_values = first.to_vec();
    let out: &mut VerifierBasePvs<F> = public_values.as_mut_slice().borrow_mut();
    match first.internal_flag {
        f if f == F::ZERO => {
            out.internal_flag = F::ONE;
            out.leaf_vk_commit = child_vk_commit;
        }
        f if f == F::ONE => {
            out.internal_flag = F::TWO;
            out.recursion_flag = F::ONE;
            out.internal_for_leaf_vk_commit = child_vk_commit;
        }
        f if f == F::TWO => {
            out.internal_flag = F::TWO;
            out.recursion_flag = F::TWO;
            out.internal_recursive_vk_commit = child_vk_commit;
        }
        _ => return Err(eyre!("invalid child internal_flag")),
    }

    Ok(AirProvingContext {
        cached_mains: vec![],
        common_main: RowMajorMatrix::new(trace, width),
        public_values,
    })
}

pub fn generate_vm_pvs_ctx(
    proofs: &[Proof<BabyBearPoseidon2Config>],
) -> Result<AirProvingContext<CpuBackend<BabyBearPoseidon2Config>>> {
    let first = *child_vm_pvs(proofs.first().ok_or_else(|| eyre!("no child proofs"))?)?;
    let last = *child_vm_pvs(proofs.last().expect("checked non-empty"))?;
    let rows = proofs.len().next_power_of_two();
    let width = CenoRecursiveVmPvsCols::<u8>::width();
    let mut trace = vec![F::ZERO; rows * width];
    for (proof_idx, proof) in proofs.iter().enumerate() {
        let cols: &mut CenoRecursiveVmPvsCols<F> =
            trace[proof_idx * width..(proof_idx + 1) * width].borrow_mut();
        cols.proof_idx = F::from_usize(proof_idx);
        cols.is_valid = F::ONE;
        cols.is_last = F::from_bool(proof_idx + 1 == proofs.len());
        cols.child_pvs = *child_vm_pvs(proof)?;
    }

    let mut public_values = first.to_vec();
    let out: &mut VmPvs<F> = public_values.as_mut_slice().borrow_mut();
    out.exit_code = last.exit_code;
    out.end_pc = last.end_pc;
    out.end_cycle = last.end_cycle;
    out.shard_count = aggregate_shard_count(first.shard_id, last.shard_id, last.shard_count);
    out.heap_shard_len = aggregate_word_len(
        first.heap_start_addr,
        last.heap_start_addr,
        last.heap_shard_len,
    );
    out.hint_shard_len = aggregate_word_len(
        first.hint_start_addr,
        last.hint_start_addr,
        last.hint_shard_len,
    );

    let second = proofs.get(1).map(child_vm_pvs).transpose()?.copied();
    debug_recursive_vm_pvs(&first, second.as_ref(), &last, out, proofs.len());

    Ok(AirProvingContext {
        cached_mains: vec![],
        common_main: RowMajorMatrix::new(trace, width),
        public_values,
    })
}

#[cfg(feature = "cuda")]
pub fn generate_verifier_pvs_gpu_ctx(
    proofs: &[Proof<BabyBearPoseidon2Config>],
    child_vk_commit: VkCommit<F>,
    device_ctx: &GpuDeviceCtx,
) -> Result<AirProvingContext<GpuBackend>> {
    Ok(
        openvm_circuit_primitives::hybrid_chip::cpu_proving_ctx_to_gpu::<DefaultHashScheme>(
            generate_verifier_pvs_ctx(proofs, child_vk_commit)?,
            device_ctx,
        ),
    )
}

#[cfg(feature = "cuda")]
pub fn generate_vm_pvs_gpu_ctx(
    proofs: &[Proof<BabyBearPoseidon2Config>],
    device_ctx: &GpuDeviceCtx,
) -> Result<AirProvingContext<GpuBackend>> {
    Ok(
        openvm_circuit_primitives::hybrid_chip::cpu_proving_ctx_to_gpu::<DefaultHashScheme>(
            generate_vm_pvs_ctx(proofs)?,
            device_ctx,
        ),
    )
}

fn debug_recursive_vm_pvs(
    first: &VmPvs<F>,
    second: Option<&VmPvs<F>>,
    last: &VmPvs<F>,
    aggregate: &VmPvs<F>,
    proofs_len: usize,
) {
    if std::env::var_os("CENO_REC_V2_DEBUG_VM_PVS").is_none() {
        return;
    }

    eprintln!(
        "rec-v2-debug module=recursive_vm_pvs source=trace proofs_len={} first_init_pc={:#x} first_init_cycle={} aggregate_init_pc={:#x} aggregate_init_cycle={} first_static_eq={} last_exit_eq={} last_end_eq={} shard_count={} aggregate_shard_count={} heap_len={} aggregate_heap_len={} hint_len={} aggregate_hint_len={} row0_end_pc={:#x} row1_init_pc={:#x} row0_shard_id={} row0_shard_count={} row1_init_shard_id={} row0_heap_end={} row1_heap_start={} row0_hint_end={} row1_hint_start={}",
        proofs_len,
        first.init_pc.as_canonical_u32(),
        first.init_cycle.as_canonical_u32(),
        aggregate.init_pc.as_canonical_u32(),
        aggregate.init_cycle.as_canonical_u32(),
        first.fixed_commit == aggregate.fixed_commit
            && first.fixed_no_omc_init_commit == aggregate.fixed_no_omc_init_commit
            && first.witness_commit == aggregate.witness_commit
            && first.shard_id == aggregate.shard_id
            && first.heap_start_addr == aggregate.heap_start_addr
            && first.hint_start_addr == aggregate.hint_start_addr
            && first.public_io == aggregate.public_io
            && first.shard_rw_sum == aggregate.shard_rw_sum,
        last.exit_code == aggregate.exit_code,
        last.end_pc == aggregate.end_pc && last.end_cycle == aggregate.end_cycle,
        first.shard_count.as_canonical_u32(),
        aggregate.shard_count.as_canonical_u32(),
        first.heap_shard_len.as_canonical_u32(),
        aggregate.heap_shard_len.as_canonical_u32(),
        first.hint_shard_len.as_canonical_u32(),
        aggregate.hint_shard_len.as_canonical_u32(),
        first.end_pc.as_canonical_u32(),
        second
            .map(|pvs| pvs.init_pc.as_canonical_u32())
            .unwrap_or_default(),
        first.shard_id.as_canonical_u32(),
        first.shard_count.as_canonical_u32(),
        second
            .map(|pvs| pvs.shard_id.as_canonical_u32())
            .unwrap_or_default(),
        first
            .heap_start_addr
            .as_canonical_u32()
            .wrapping_add(first.heap_shard_len.as_canonical_u32() * ceno_emul::WORD_SIZE as u32),
        second
            .map(|pvs| pvs.heap_start_addr.as_canonical_u32())
            .unwrap_or_default(),
        first
            .hint_start_addr
            .as_canonical_u32()
            .wrapping_add(first.hint_shard_len.as_canonical_u32() * ceno_emul::WORD_SIZE as u32),
        second
            .map(|pvs| pvs.hint_start_addr.as_canonical_u32())
            .unwrap_or_default(),
    );
}

fn child_verifier_pvs(proof: &Proof<BabyBearPoseidon2Config>) -> Result<&VerifierBasePvs<F>> {
    proof
        .public_values
        .get(VERIFIER_PVS_AIR_ID)
        .map(|values| values.as_slice().borrow())
        .ok_or_else(|| eyre!("child proof missing verifier public values"))
}

fn child_vm_pvs(proof: &Proof<BabyBearPoseidon2Config>) -> Result<&VmPvs<F>> {
    proof
        .public_values
        .get(CENO_VM_PVS_AIR_ID)
        .map(|values| values.as_slice().borrow())
        .ok_or_else(|| eyre!("child proof missing Ceno VM public values"))
}

fn aggregate_word_len(first_start: F, last_start: F, last_len: F) -> F {
    let word_size = F::from_u32(ceno_emul::WORD_SIZE as u32);
    (last_start - first_start) / word_size + last_len
}

fn aggregate_shard_count(first_shard_id: F, last_shard_id: F, last_shard_count: F) -> F {
    last_shard_id - first_shard_id + last_shard_count
}
