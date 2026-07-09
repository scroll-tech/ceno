use std::borrow::{Borrow, BorrowMut};

use eyre::{Result, eyre};
use openvm_cpu_backend::CpuBackend;
#[cfg(feature = "cuda")]
use openvm_cuda_backend::{
    GenericGpuBackend, base::DeviceMatrix, hash_scheme::BabyBearBn254Poseidon2HashScheme,
};
#[cfg(feature = "cuda")]
use openvm_cuda_common::stream::GpuDeviceCtx;
use openvm_stark_backend::{proof::Proof, prover::AirProvingContext};
use openvm_stark_sdk::config::baby_bear_poseidon2::{BabyBearPoseidon2Config, DIGEST_SIZE, F};
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;
use verify_stark::pvs::{VERIFIER_PVS_AIR_ID, VerifierBasePvs};

use crate::circuit::{
    inner::vm_pvs::VmPvs,
    root::{
        RootSC,
        verifier::{CENO_VM_PVS_AIR_ID, CenoRootPublicValues, CenoRootVerifierPvsCols},
    },
};

pub fn generate_proving_ctx(
    proof: &Proof<BabyBearPoseidon2Config>,
) -> Result<AirProvingContext<CpuBackend<RootSC>>> {
    let child_verifier_pvs: &VerifierBasePvs<F> =
        proof.public_values[VERIFIER_PVS_AIR_ID].as_slice().borrow();
    let child_vm_pvs: &VmPvs<F> = proof.public_values[CENO_VM_PVS_AIR_ID].as_slice().borrow();

    if child_verifier_pvs.internal_flag != F::TWO
        || (child_verifier_pvs.recursion_flag != F::ONE
            && child_verifier_pvs.recursion_flag != F::TWO)
    {
        return Err(eyre!(
            "Ceno root proof input must be a final internal-recursive proof \
             (internal_flag=2 and recursion_flag in {{1,2}}); got internal_flag={:?}, \
             recursion_flag={:?}",
            child_verifier_pvs.internal_flag,
            child_verifier_pvs.recursion_flag,
        ));
    }

    let width = CenoRootVerifierPvsCols::<u8>::width();
    let mut trace = vec![F::ZERO; width];
    let cols: &mut CenoRootVerifierPvsCols<F> = trace.as_mut_slice().borrow_mut();
    cols.child_verifier_pvs = *child_verifier_pvs;
    cols.child_vm_pvs = *child_vm_pvs;

    let mut public_values = vec![F::ZERO; CenoRootPublicValues::<u8>::width()];
    let pvs: &mut CenoRootPublicValues<F> = public_values.as_mut_slice().borrow_mut();
    pvs.verifier_pvs = *child_verifier_pvs;
    pvs.vm_pvs = *child_vm_pvs;

    Ok(AirProvingContext {
        cached_mains: vec![],
        common_main: RowMajorMatrix::new(trace, width),
        public_values,
    })
}

pub fn root_public_values(proof: &Proof<RootSC>) -> &CenoRootPublicValues<F> {
    proof.public_values[0].as_slice().borrow()
}

pub const CENO_ROOT_DIGEST_WIDTH: usize = DIGEST_SIZE;

#[cfg(feature = "cuda")]
pub fn generate_gpu_proving_ctx(
    proof: &Proof<BabyBearPoseidon2Config>,
    device_ctx: &GpuDeviceCtx,
) -> Result<AirProvingContext<GenericGpuBackend<BabyBearBn254Poseidon2HashScheme>>> {
    use openvm_cuda_backend::data_transporter::transport_matrix_h2d_col_major;
    use openvm_stark_backend::prover::ColMajorMatrix;

    let cpu_ctx = generate_proving_ctx(proof)?;
    let col_major = ColMajorMatrix::from_row_major(&cpu_ctx.common_main);
    let common_main: DeviceMatrix<F> = transport_matrix_h2d_col_major(&col_major, device_ctx)
        .map_err(|err| eyre!("failed to transport Ceno root PVS trace to GPU: {err:?}"))?;
    Ok(AirProvingContext {
        cached_mains: Vec::new(),
        common_main,
        public_values: cpu_ctx.public_values,
    })
}
