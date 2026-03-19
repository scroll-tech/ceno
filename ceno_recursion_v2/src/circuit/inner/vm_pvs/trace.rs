use openvm_cpu_backend::CpuBackend;
use openvm_stark_backend::prover::AirProvingContext;
use openvm_stark_sdk::config::baby_bear_poseidon2::{BabyBearPoseidon2Config, F};
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;
use std::borrow::BorrowMut;
use verify_stark::pvs::VmPvs;

use crate::{
    circuit::inner::{ProofsType, vm_pvs::air::VmPvsCols},
    system::RecursionProof,
};

pub fn generate_proving_ctx(
    proofs: &[RecursionProof],
    proofs_type: ProofsType,
    child_is_app: bool,
    deferral_enabled: bool,
) -> AirProvingContext<CpuBackend<BabyBearPoseidon2Config>> {
    // TODO(recursion-proof-bridge): populate VM PVS from RecursionProof once projection exists.
    // For now we return shape-correct zero rows and zero public values.
    let _ = (proofs, proofs_type, child_is_app, deferral_enabled);

    let rows = proofs.len().max(1).next_power_of_two();
    let width = VmPvsCols::<u8>::width() + (deferral_enabled as usize);
    let mut trace = vec![F::ZERO; rows * width];

    if rows > 0 {
        let first_row = &mut trace[..width];
        let (base_row, def_row) = first_row.split_at_mut(VmPvsCols::<u8>::width());
        let cols: &mut VmPvsCols<F> = base_row.borrow_mut();
        cols.proof_idx = F::ZERO;
        cols.is_valid = F::ONE;
        cols.is_last = F::ONE;
        cols.has_verifier_pvs = F::ZERO;
        cols.child_pvs.is_terminate = F::ONE;
        cols.child_pvs.exit_code = F::ZERO;

        if deferral_enabled {
            // deferral_flag for VmPvsAir is 0 or 2; choose 0 for the mocked VM-only case.
            def_row[0] = F::ZERO;
        }
    }

    let trace = RowMajorMatrix::new(trace, width);
    let mut public_values = vec![F::ZERO; VmPvs::<u8>::width()];
    let pvs: &mut VmPvs<F> = public_values.as_mut_slice().borrow_mut();
    pvs.is_terminate = F::ONE;
    pvs.exit_code = F::ZERO;

    AirProvingContext {
        cached_mains: vec![],
        common_main: trace,
        public_values,
    }
}
