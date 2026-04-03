use openvm_cpu_backend::CpuBackend;
#[cfg(feature = "cuda")]
use openvm_cuda_backend::GpuBackend;
use openvm_poseidon2_air::POSEIDON2_WIDTH;
use openvm_stark_backend::{
    FiatShamirTranscript, TranscriptHistory,
    prover::{AirProvingContext, ProverBackend},
};
use openvm_stark_sdk::config::baby_bear_poseidon2::{BabyBearPoseidon2Config, DIGEST_SIZE, F};
use verify_stark::pvs::DeferralPvs;

use crate::system::{Preflight, RecursionProof, RecursionVk};

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
    fn generate_pre_verifier_subcircuit_ctxs<TS>(
        &self,
        proofs: &[RecursionProof],
        proofs_type: ProofsType,
        absent_trace_pvs: Option<(DeferralPvs<F>, bool)>,
        child_is_app: bool,
        child_vk: &RecursionVk,
        child_dag_commit: PB::Commitment,
        initial_transcript: TS,
    ) -> (
        Vec<AirProvingContext<PB>>,
        Vec<[F; POSEIDON2_WIDTH]>,
        Vec<TS>,
    )
    where
        TS: Clone
            + FiatShamirTranscript<BabyBearPoseidon2Config>
            + TranscriptHistory<F = F, State = [F; POSEIDON2_WIDTH]>;
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

    fn generate_pre_verifier_subcircuit_ctxs<TS>(
        &self,
        proofs: &[RecursionProof],
        proofs_type: ProofsType,
        absent_trace_pvs: Option<(DeferralPvs<F>, bool)>,
        child_is_app: bool,
        child_vk: &RecursionVk,
        child_dag_commit: [F; DIGEST_SIZE],
        initial_transcript: TS,
    ) -> (
        Vec<AirProvingContext<CpuBackend<BabyBearPoseidon2Config>>>,
        Vec<[F; POSEIDON2_WIDTH]>,
        Vec<TS>,
    )
    where
        TS: Clone
            + FiatShamirTranscript<BabyBearPoseidon2Config>
            + TranscriptHistory<F = F, State = [F; POSEIDON2_WIDTH]>,
    {
        let (verifier_ctx, poseidon2_inputs) = super::verifier::generate_proving_ctx(
            proofs,
            proofs_type,
            child_is_app,
            child_dag_commit,
            self.deferral_enabled,
        );
        let (preflights, per_proof_initial_transcripts): (Vec<Preflight>, Vec<TS>) = proofs
            .iter()
            .map(|proof| {
                let mut sponge = initial_transcript.clone();
                let mut preflight = Preflight::default();
                super::verifier::run_preflight(child_vk, proof, &mut preflight, &mut sponge);
                super::vm_pvs::run_preflight(child_vk, proof, &mut preflight, &mut sponge);
                (preflight, sponge)
            })
            .unzip();
        let vm_ctx = super::vm_pvs::generate_proving_ctx(
            child_vk,
            proofs,
            &preflights,
            proofs_type,
            child_is_app,
            self.deferral_enabled,
        );

        let mut poseidon2_inputs = poseidon2_inputs;
        let idx2_ctx = if self.deferral_enabled {
            let (def_pvs_ctx, def_poseidon2_inputs) = super::def_pvs::generate_proving_ctx(
                proofs,
                proofs_type,
                child_is_app,
                absent_trace_pvs,
            );
            poseidon2_inputs.extend_from_slice(&def_poseidon2_inputs);
            def_pvs_ctx
        } else {
            super::unset::generate_proving_ctx(&[], child_is_app)
        };

        (
            vec![verifier_ctx, vm_ctx, idx2_ctx],
            poseidon2_inputs,
            per_proof_initial_transcripts,
        )
    }

    fn generate_post_verifier_subcircuit_ctxs(
        &self,
        proofs: &[RecursionProof],
        proofs_type: ProofsType,
        child_is_app: bool,
    ) -> Vec<AirProvingContext<CpuBackend<BabyBearPoseidon2Config>>> {
        if !self.deferral_enabled {
            return vec![];
        }

        let (vm_unset, def_unset) = match proofs_type {
            ProofsType::Vm => (vec![], proofs.iter().enumerate().map(|(i, _)| i).collect()),
            ProofsType::Deferral => (proofs.iter().enumerate().map(|(i, _)| i).collect(), vec![]),
            ProofsType::Mix => (vec![1], vec![0]),
            ProofsType::Combined => (vec![], vec![]),
        };
        vec![
            super::unset::generate_proving_ctx(&vm_unset, child_is_app),
            super::unset::generate_proving_ctx(&def_unset, child_is_app),
        ]
    }
}

#[cfg(feature = "cuda")]
impl InnerTraceGen<GpuBackend> for InnerTraceGenImpl {
    fn new(deferral_enabled: bool) -> Self {
        Self { deferral_enabled }
    }

    fn generate_pre_verifier_subcircuit_ctxs<TS>(
        &self,
        proofs: &[RecursionProof],
        proofs_type: ProofsType,
        absent_trace_pvs: Option<(DeferralPvs<F>, bool)>,
        child_is_app: bool,
        child_vk: &RecursionVk,
        child_dag_commit: [F; DIGEST_SIZE],
        initial_transcript: TS,
    ) -> (
        Vec<AirProvingContext<GpuBackend>>,
        Vec<[F; POSEIDON2_WIDTH]>,
        Vec<TS>,
    )
    where
        TS: Clone
            + FiatShamirTranscript<BabyBearPoseidon2Config>
            + TranscriptHistory<F = F, State = [F; POSEIDON2_WIDTH]>,
    {
        let _ = (
            self,
            proofs,
            proofs_type,
            absent_trace_pvs,
            child_is_app,
            child_vk,
            child_dag_commit,
        );
        (vec![], vec![], vec![initial_transcript; proofs.len()])
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
