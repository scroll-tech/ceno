use std::sync::Arc;

use eyre::{Result, eyre};
use openvm_cpu_backend::CpuBackend;
#[cfg(feature = "cuda")]
use openvm_cuda_backend::{
    BabyBearBn254Poseidon2GpuEngine, GenericGpuBackend,
    hash_scheme::BabyBearBn254Poseidon2HashScheme,
};
#[cfg(feature = "cuda")]
use openvm_cuda_common::stream::GpuDeviceCtx;
use openvm_stark_backend::{
    StarkEngine, StarkProtocolConfig, SystemParams,
    keygen::types::{MultiStarkProvingKey, MultiStarkVerifyingKey},
    proof::Proof,
    prover::{
        AirProvingContext, CommittedTraceData, DeviceDataTransporter, DeviceMultiStarkProvingKey,
        ProverBackend, ProverDevice, ProvingContext,
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
pub type CenoRootCpuEngine = BabyBearBn254Poseidon2CpuEngine;
pub type CenoRootEngine = CenoRootCpuEngine;
pub type CenoRootProof = Proof<RootSC>;
pub type CenoRootVk = MultiStarkVerifyingKey<RootSC>;

#[cfg(feature = "cuda")]
pub type CenoRootGpuProver = CenoRootProver<
    VerifierSubCircuit<1>,
    GenericGpuBackend<BabyBearBn254Poseidon2HashScheme>,
    BabyBearBn254Poseidon2GpuEngine,
    GpuDeviceCtx,
>;

pub struct CenoRootProver<
    S = VerifierSubCircuit<1>,
    PB = CpuBackend<RootSC>,
    E = CenoRootCpuEngine,
    DC = (),
> where
    S: AggregationSubCircuit + VerifierTraceGen<PB, RootSC, DC>,
    PB: ProverBackend<
            Val = <RootSC as StarkProtocolConfig>::F,
            Challenge = <RootSC as StarkProtocolConfig>::EF,
            Commitment = <RootSC as StarkProtocolConfig>::Digest,
        >,
    E: StarkEngine<SC = RootSC, PB = PB>,
    DC: Clone + Send + Sync,
{
    pk: Arc<MultiStarkProvingKey<RootSC>>,
    d_pk: DeviceMultiStarkProvingKey<PB>,
    vk: Arc<MultiStarkVerifyingKey<RootSC>>,
    child_vk: Arc<MultiStarkVerifyingKey<BabyBearPoseidon2Config>>,
    child_vk_pcs_data: CommittedTraceData<PB>,
    circuit: Arc<CenoRootCircuit<S>>,
    device_ctx: DC,
    _engine: std::marker::PhantomData<E>,
}

impl<S, PB, E, DC> CenoRootProver<S, PB, E, DC>
where
    S: AggregationSubCircuit + VerifierTraceGen<PB, RootSC, DC>,
    PB: ProverBackend<
            Val = <RootSC as StarkProtocolConfig>::F,
            Challenge = <RootSC as StarkProtocolConfig>::EF,
            Commitment = <RootSC as StarkProtocolConfig>::Digest,
        >,
    E: StarkEngine<SC = RootSC, PB = PB>,
    E::PD: DeviceDataTransporter<RootSC, PB>,
    PB::Matrix: Clone,
    DC: Clone + Send + Sync + From<openvm_stark_backend::EngineDeviceCtx<E>>,
    Self: CenoRootPvsCtx<PB>,
{
    pub fn new(
        child_vk: Arc<MultiStarkVerifyingKey<BabyBearPoseidon2Config>>,
        system_params: SystemParams,
    ) -> Self {
        let engine = E::new(system_params);
        let device_ctx = DC::from(engine.device().device_ctx().clone());
        let verifier_circuit = S::new(
            child_vk.clone(),
            VerifierConfig {
                continuations_enabled: true,
                ..Default::default()
            },
        );
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
            device_ctx,
            _engine: std::marker::PhantomData,
        }
    }

    pub fn generate_proving_ctx(
        &self,
        proof: Proof<BabyBearPoseidon2Config>,
    ) -> Result<ProvingContext<PB>> {
        let root_pvs_ctx = self.generate_root_pvs_ctx(&proof)?;
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
                &self.device_ctx,
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
        let engine = E::new(self.pk.params.clone());
        #[cfg(debug_assertions)]
        if std::env::var_os("CENO_REC_V2_DEBUG_CONSTRAINTS").is_some() {
            continuations_v2::prover::debug_constraints(&self.circuit, &ctx, &engine);
        }
        let proof = engine.prove(&self.d_pk, ctx)?;
        engine.verify(&self.vk, &proof)?;
        Ok(proof)
    }

    pub fn verify(&self, proof: &Proof<RootSC>) -> Result<()> {
        E::new(self.vk.inner.params.clone()).verify(&self.vk, proof)?;
        Ok(())
    }

    pub fn get_vk(&self) -> Arc<MultiStarkVerifyingKey<RootSC>> {
        self.vk.clone()
    }

    pub fn get_circuit(&self) -> Arc<CenoRootCircuit<S>> {
        self.circuit.clone()
    }
}

trait CenoRootPvsCtx<PB: ProverBackend> {
    fn generate_root_pvs_ctx(
        &self,
        proof: &Proof<BabyBearPoseidon2Config>,
    ) -> Result<AirProvingContext<PB>>;
}

impl<S> CenoRootPvsCtx<CpuBackend<RootSC>>
    for CenoRootProver<S, CpuBackend<RootSC>, CenoRootCpuEngine, ()>
where
    S: AggregationSubCircuit + VerifierTraceGen<CpuBackend<RootSC>, RootSC, ()>,
{
    fn generate_root_pvs_ctx(
        &self,
        proof: &Proof<BabyBearPoseidon2Config>,
    ) -> Result<AirProvingContext<CpuBackend<RootSC>>> {
        trace::generate_proving_ctx(proof)
    }
}

#[cfg(feature = "cuda")]
impl<S> CenoRootPvsCtx<GenericGpuBackend<BabyBearBn254Poseidon2HashScheme>>
    for CenoRootProver<
        S,
        GenericGpuBackend<BabyBearBn254Poseidon2HashScheme>,
        BabyBearBn254Poseidon2GpuEngine,
        GpuDeviceCtx,
    >
where
    S: AggregationSubCircuit
        + VerifierTraceGen<GenericGpuBackend<BabyBearBn254Poseidon2HashScheme>, RootSC, GpuDeviceCtx>,
{
    fn generate_root_pvs_ctx(
        &self,
        proof: &Proof<BabyBearPoseidon2Config>,
    ) -> Result<AirProvingContext<GenericGpuBackend<BabyBearBn254Poseidon2HashScheme>>> {
        trace::generate_gpu_proving_ctx(proof, &self.device_ctx)
    }
}

#[allow(dead_code)]
fn _trace_heights<PB: ProverBackend>(
    _ctxs: &[(usize, AirProvingContext<PB>)],
    _airs: &[openvm_stark_backend::AirRef<RootSC>],
) {
}
