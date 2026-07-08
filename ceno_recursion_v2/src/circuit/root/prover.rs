use std::sync::Arc;

use eyre::{Result, eyre};
use openvm_cpu_backend::CpuBackend;
use openvm_stark_backend::{
    StarkEngine, SystemParams,
    keygen::types::{MultiStarkProvingKey, MultiStarkVerifyingKey},
    proof::Proof,
    prover::{
        AirProvingContext, CommittedTraceData, DeviceDataTransporter, DeviceMultiStarkProvingKey,
        ProverBackend, ProvingContext,
    },
};
use openvm_stark_sdk::config::{
    baby_bear_bn254_poseidon2::BabyBearBn254Poseidon2CpuEngine,
    baby_bear_poseidon2::{BabyBearPoseidon2Config, default_duplex_sponge_recorder},
};
use recursion_circuit::system::{
    AggregationSubCircuit, CachedTraceCtx, VerifierConfig, VerifierExternalData,
    VerifierSubCircuit, VerifierTraceGen,
};

use crate::circuit::{Circuit, root::CenoRootCircuit};

use super::{RootSC, trace};

pub type CenoRootCpuProver = CenoRootProver<VerifierSubCircuit<1>>;
pub type CenoRootEngine = BabyBearBn254Poseidon2CpuEngine;
pub type CenoRootProof = Proof<RootSC>;
pub type CenoRootVk = MultiStarkVerifyingKey<RootSC>;

pub struct CenoRootProver<S = VerifierSubCircuit<1>>
where
    S: AggregationSubCircuit + VerifierTraceGen<CpuBackend<RootSC>, RootSC, ()>,
{
    pk: Arc<MultiStarkProvingKey<RootSC>>,
    d_pk: DeviceMultiStarkProvingKey<CpuBackend<RootSC>>,
    vk: Arc<MultiStarkVerifyingKey<RootSC>>,
    child_vk: Arc<MultiStarkVerifyingKey<BabyBearPoseidon2Config>>,
    child_vk_pcs_data: CommittedTraceData<CpuBackend<RootSC>>,
    circuit: Arc<CenoRootCircuit<S>>,
}

impl<S> CenoRootProver<S>
where
    S: AggregationSubCircuit + VerifierTraceGen<CpuBackend<RootSC>, RootSC, ()>,
{
    pub fn new(
        child_vk: Arc<MultiStarkVerifyingKey<BabyBearPoseidon2Config>>,
        system_params: SystemParams,
    ) -> Self {
        let verifier_circuit = S::new(
            child_vk.clone(),
            VerifierConfig {
                continuations_enabled: true,
                ..Default::default()
            },
        );
        let engine = CenoRootEngine::new(system_params);
        let child_vk_pcs_data = verifier_circuit.commit_child_vk(&engine, &child_vk);
        let circuit = Arc::new(CenoRootCircuit {
            verifier_circuit: Arc::new(verifier_circuit),
            child_vk_pre_hash: child_vk.pre_hash,
        });
        let (pk, vk) = engine.keygen(&circuit.airs());
        let pk = Arc::new(pk);
        let d_pk = engine.device().transport_pk_to_device(pk.as_ref());
        Self {
            pk,
            d_pk,
            vk: Arc::new(vk),
            child_vk,
            child_vk_pcs_data,
            circuit,
        }
    }

    pub fn generate_proving_ctx(
        &self,
        proof: Proof<BabyBearPoseidon2Config>,
    ) -> Result<ProvingContext<CpuBackend<RootSC>>> {
        let root_pvs_ctx = trace::generate_proving_ctx(&proof)?;
        let poseidon2_compress_inputs = Vec::new();
        let poseidon2_permute_inputs = Vec::new();
        let range_check_inputs = Vec::new();
        let power_check_inputs = Vec::new();

        let mut external_data = VerifierExternalData {
            poseidon2_compress_inputs: &poseidon2_compress_inputs,
            poseidon2_permute_inputs: &poseidon2_permute_inputs,
            range_check_inputs: &range_check_inputs,
            power_check_inputs: &power_check_inputs,
            required_heights: None,
            final_transcript_state: None,
        };

        let subcircuit_ctxs = self
            .circuit
            .verifier_circuit
            .generate_proving_ctxs(
                &self.child_vk,
                CachedTraceCtx::PcsData(self.child_vk_pcs_data.clone()),
                &[proof],
                &mut external_data,
                &(),
                default_duplex_sponge_recorder(),
            )
            .ok_or_else(|| eyre!("failed to generate Ceno root verifier subcircuit traces"))?;

        Ok(ProvingContext {
            per_trace: core::iter::once(root_pvs_ctx)
                .chain(subcircuit_ctxs)
                .enumerate()
                .collect(),
        })
    }

    pub fn prove(&self, proof: Proof<BabyBearPoseidon2Config>) -> Result<Proof<RootSC>> {
        let ctx = self.generate_proving_ctx(proof)?;
        let engine = CenoRootEngine::new(self.pk.params.clone());
        #[cfg(debug_assertions)]
        if std::env::var_os("CENO_REC_V2_DEBUG_CONSTRAINTS").is_some() {
            continuations_v2::prover::debug_constraints(&self.circuit, &ctx, &engine);
        }
        let proof = engine.prove(&self.d_pk, ctx)?;
        engine.verify(&self.vk, &proof)?;
        Ok(proof)
    }

    pub fn verify(&self, proof: &Proof<RootSC>) -> Result<()> {
        CenoRootEngine::new(self.vk.inner.params.clone()).verify(&self.vk, proof)?;
        Ok(())
    }

    pub fn get_vk(&self) -> Arc<MultiStarkVerifyingKey<RootSC>> {
        self.vk.clone()
    }

    pub fn get_circuit(&self) -> Arc<CenoRootCircuit<S>> {
        self.circuit.clone()
    }
}

#[allow(dead_code)]
fn _trace_heights<PB: ProverBackend>(
    _ctxs: &[(usize, AirProvingContext<PB>)],
    _airs: &[openvm_stark_backend::AirRef<RootSC>],
) {
}
