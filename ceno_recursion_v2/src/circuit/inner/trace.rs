use openvm_cpu_backend::CpuBackend;
#[cfg(feature = "cuda")]
use openvm_cuda_backend::GpuBackend;
use openvm_poseidon2_air::POSEIDON2_WIDTH;
use openvm_stark_backend::prover::{AirProvingContext, ProverBackend};
use openvm_stark_sdk::config::baby_bear_poseidon2::{BabyBearPoseidon2Config, DIGEST_SIZE, F};
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;
use verify_stark::pvs::DeferralPvs;

use crate::system::RecursionProof;

#[derive(Copy, Clone)]
pub enum ProofsType {
    Vm,
    Deferral,
    Mix,
    Combined,
}

// Trait that inner and compression provers use to remain generic in PB
pub trait InnerTraceGen<PB: ProverBackend> {
    fn new(deferral_enabled: bool) -> Self;
    fn generate_pre_verifier_subcircuit_ctxs(
        &self,
        proofs: &[RecursionProof],
        proofs_type: ProofsType,
        absent_trace_pvs: Option<(DeferralPvs<F>, bool)>,
        child_is_app: bool,
        child_dag_commit: PB::Commitment,
    ) -> (Vec<AirProvingContext<PB>>, Vec<[F; POSEIDON2_WIDTH]>);
    fn generate_post_verifier_subcircuit_ctxs(
        &self,
        proofs: &[RecursionProof],
        proofs_type: ProofsType,
        child_is_app: bool,
    ) -> Vec<AirProvingContext<PB>>;
}

pub struct InnerTraceGenImpl {
    pub deferral_enabled: bool,
}

impl InnerTraceGen<CpuBackend<BabyBearPoseidon2Config>> for InnerTraceGenImpl {
    fn new(deferral_enabled: bool) -> Self {
        Self { deferral_enabled }
    }

    fn generate_pre_verifier_subcircuit_ctxs(
        &self,
        proofs: &[RecursionProof],
        proofs_type: ProofsType,
        absent_trace_pvs: Option<(DeferralPvs<F>, bool)>,
        child_is_app: bool,
        child_dag_commit: [F; DIGEST_SIZE],
    ) -> (
        Vec<AirProvingContext<CpuBackend<BabyBearPoseidon2Config>>>,
        Vec<[F; POSEIDON2_WIDTH]>,
    ) {
        let _ = absent_trace_pvs;
        let (verifier_ctx, poseidon2_inputs) =
            super::verifier::generate_proving_ctx(
                proofs,
                proofs_type,
                child_is_app,
                child_dag_commit,
                self.deferral_enabled,
            );
        let vm_ctx =
            super::vm_pvs::generate_proving_ctx(proofs, proofs_type, child_is_app, self.deferral_enabled);
        // Placeholder third AIR context (deferral/unset) to preserve expected ordering.
        let idx2_ctx = zero_ctx(1);

        (vec![verifier_ctx, vm_ctx, idx2_ctx], poseidon2_inputs)
    }

    fn generate_post_verifier_subcircuit_ctxs(
        &self,
        proofs: &[RecursionProof],
        proofs_type: ProofsType,
        child_is_app: bool,
    ) -> Vec<AirProvingContext<CpuBackend<BabyBearPoseidon2Config>>> {
        let _ = (proofs, proofs_type, child_is_app);
        if self.deferral_enabled {
            // Placeholder unset contexts while deferral/unset AIRs are not locally ported.
            vec![zero_ctx(1), zero_ctx(1)]
        } else {
            vec![]
        }
    }
}

fn zero_ctx(height: usize) -> AirProvingContext<CpuBackend<BabyBearPoseidon2Config>> {
    let rows = height.max(1);
    let trace = RowMajorMatrix::new(vec![F::ZERO; rows], 1);
    AirProvingContext::simple_no_pis(trace)
}

#[cfg(feature = "cuda")]
impl InnerTraceGen<GpuBackend> for InnerTraceGenImpl {
    fn new(deferral_enabled: bool) -> Self {
        Self { deferral_enabled }
    }

    fn generate_pre_verifier_subcircuit_ctxs(
        &self,
        proofs: &[RecursionProof],
        proofs_type: ProofsType,
        absent_trace_pvs: Option<(DeferralPvs<F>, bool)>,
        child_is_app: bool,
        child_dag_commit: [F; DIGEST_SIZE],
    ) -> (
        Vec<AirProvingContext<GpuBackend>>,
        Vec<[F; POSEIDON2_WIDTH]>,
    ) {
        let _ = (
            self,
            proofs,
            proofs_type,
            absent_trace_pvs,
            child_is_app,
            child_dag_commit,
        );
        (vec![], vec![])
    }

    fn generate_post_verifier_subcircuit_ctxs(
        &self,
        proofs: &[RecursionProof],
        proofs_type: ProofsType,
        child_is_app: bool,
    ) -> Vec<AirProvingContext<GpuBackend>> {
        let _ = (self, proofs, proofs_type, child_is_app);
        vec![]
    }
}
