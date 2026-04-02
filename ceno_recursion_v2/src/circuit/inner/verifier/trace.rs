use std::borrow::BorrowMut;

use openvm_cpu_backend::CpuBackend;
use openvm_poseidon2_air::POSEIDON2_WIDTH;
use openvm_stark_backend::prover::AirProvingContext;
use openvm_stark_sdk::config::baby_bear_poseidon2::{BabyBearPoseidon2Config, DIGEST_SIZE, F};
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;
use verify_stark::pvs::{VerifierBasePvs, VerifierDefPvs};

use crate::{
    circuit::inner::{
        ProofsType,
        verifier::air::{VerifierDeferralCols, VerifierPvsCols},
    },
    system::RecursionProof,
};

///////////////////////////////////////////////////////////////////////////////
// VERIFIER PVS TRACE GENERATOR
///////////////////////////////////////////////////////////////////////////////

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
    // TODO(recursion-proof-bridge): populate verifier trace/public values from RecursionProof.
    // Any verifier-specific values not available on RecursionProof are currently zero-mocked.
    let _ = (proofs, proofs_type, child_is_app, child_dag_commit);

    let rows = proofs.len().max(1).next_power_of_two();
    let width = VerifierPvsCols::<u8>::width()
        + if deferral_enabled {
            VerifierDeferralCols::<u8>::width()
        } else {
            0
        };

    let mut trace = vec![F::ZERO; rows * width];

    if rows > 0 {
        let first_row = &mut trace[..width];
        let base_width = VerifierPvsCols::<u8>::width();
        let (base_row, def_row) = first_row.split_at_mut(base_width);

        let cols: &mut VerifierPvsCols<F> = base_row.borrow_mut();
        cols.proof_idx = F::ZERO;
        cols.is_valid = F::ONE;
        cols.has_verifier_pvs = F::ZERO;

        if deferral_enabled {
            let def_cols: &mut VerifierDeferralCols<F> = def_row.borrow_mut();
            def_cols.is_last = F::ONE;
            def_cols.child_pvs.deferral_flag = F::ZERO;
        }
    }

    let mut num_public_values = VerifierBasePvs::<u8>::width();
    if deferral_enabled {
        num_public_values += VerifierDefPvs::<u8>::width();
    }

    (
        AirProvingContext {
            cached_mains: vec![],
            common_main: RowMajorMatrix::new(trace, width),
            public_values: vec![F::ZERO; num_public_values],
        },
        vec![],
    )
}
