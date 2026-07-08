use std::borrow::{Borrow, BorrowMut};

use eyre::{Result, eyre};
use openvm_cpu_backend::CpuBackend;
use openvm_stark_backend::{proof::Proof, prover::AirProvingContext};
use openvm_stark_sdk::config::baby_bear_poseidon2::{BabyBearPoseidon2Config, F};
use p3_field::PrimeCharacteristicRing;
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

    Ok(AirProvingContext {
        cached_mains: vec![],
        common_main: RowMajorMatrix::new(trace, width),
        public_values,
    })
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
