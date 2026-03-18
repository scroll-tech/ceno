use openvm_cpu_backend::CpuBackend;
use openvm_poseidon2_air::POSEIDON2_WIDTH;
use openvm_stark_backend::prover::AirProvingContext;
use openvm_stark_sdk::config::baby_bear_poseidon2::{BabyBearPoseidon2Config, DIGEST_SIZE, F};
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;

use crate::{circuit::inner::ProofsType, system::RecursionProof};

pub fn generate_proving_ctx(
    proofs: &[RecursionProof],
    proofs_type: ProofsType,
    child_is_app: bool,
    child_dag_commit: [F; DIGEST_SIZE],
    deferral_enabled: bool,
) -> (
    AirProvingContext<CpuBackend<BabyBearPoseidon2Config>>,
    Vec<[F; POSEIDON2_WIDTH]>,
) {
    let _ = (
        proofs,
        proofs_type,
        child_is_app,
        child_dag_commit,
        deferral_enabled,
    );

    let rows = proofs.len().max(1).next_power_of_two();
    let trace = RowMajorMatrix::new(vec![F::ZERO; rows], 1);
    (AirProvingContext::simple_no_pis(trace), vec![])
}
