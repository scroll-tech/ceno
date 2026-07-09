use std::sync::Arc;

use eyre::{Result, eyre};
use openvm_cpu_backend::CpuBackend;
#[cfg(feature = "cuda")]
use openvm_cuda_backend::{BabyBearPoseidon2GpuEngine, GpuBackend};
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
use openvm_stark_sdk::config::baby_bear_poseidon2::{
    BabyBearPoseidon2Config, BabyBearPoseidon2CpuEngine, Digest, DuplexSponge, EF, F,
    default_duplex_sponge_recorder,
};
use recursion_circuit::system::{
    AggregationSubCircuit, CachedTraceCtx, VerifierConfig, VerifierExternalData,
    VerifierSubCircuit, VerifierTraceGen,
};
use verify_stark::pvs::VkCommit;

use crate::circuit::{Circuit, recursive::CenoRecursiveCircuit};

use super::trace;

pub type CenoRecursiveCpuProver<const MAX_NUM_PROOFS: usize> =
    CenoRecursiveProver<VerifierSubCircuit<MAX_NUM_PROOFS>>;
type CenoRecursiveCpuEngine = BabyBearPoseidon2CpuEngine<DuplexSponge>;

#[cfg(feature = "cuda")]
pub type CenoRecursiveGpuProver<const MAX_NUM_PROOFS: usize> = CenoRecursiveProver<
    VerifierSubCircuit<MAX_NUM_PROOFS>,
    GpuBackend,
    BabyBearPoseidon2GpuEngine,
    GpuDeviceCtx,
>;

pub const CENO_RECURSIVE_CONSTRAINT_EVAL_AIR_ID: usize = 2;
pub const CENO_LEAF_CONSTRAINT_EVAL_AIR_ID: usize = 4;

pub struct CenoRecursiveProver<
    S,
    PB = CpuBackend<BabyBearPoseidon2Config>,
    E = CenoRecursiveCpuEngine,
    DC = (),
> where
    S: AggregationSubCircuit + VerifierTraceGen<PB, BabyBearPoseidon2Config, DC>,
    PB: ProverBackend<Val = F, Challenge = EF, Commitment = Digest>,
    E: StarkEngine<SC = BabyBearPoseidon2Config, PB = PB>,
    DC: Clone + Send + Sync,
{
    pk: Arc<MultiStarkProvingKey<BabyBearPoseidon2Config>>,
    d_pk: DeviceMultiStarkProvingKey<PB>,
    vk: Arc<MultiStarkVerifyingKey<BabyBearPoseidon2Config>>,
    child_vk: Arc<MultiStarkVerifyingKey<BabyBearPoseidon2Config>>,
    child_vk_pcs_data: CommittedTraceData<PB>,
    circuit: Arc<CenoRecursiveCircuit<S>>,
    device_ctx: DC,
    _engine: std::marker::PhantomData<E>,
}

impl<S, PB, E, DC> CenoRecursiveProver<S, PB, E, DC>
where
    S: AggregationSubCircuit + VerifierTraceGen<PB, BabyBearPoseidon2Config, DC>,
    PB: ProverBackend<Val = F, Challenge = EF, Commitment = Digest>,
    E: StarkEngine<SC = BabyBearPoseidon2Config, PB = PB>,
    E::PD: DeviceDataTransporter<BabyBearPoseidon2Config, PB>,
    PB::Matrix: Clone,
    DC: Clone + Send + Sync + From<openvm_stark_backend::EngineDeviceCtx<E>>,
    Self: CenoRecursivePvsCtx<PB>,
{
    pub fn new(
        child_vk: Arc<MultiStarkVerifyingKey<BabyBearPoseidon2Config>>,
        system_params: SystemParams,
    ) -> Self {
        Self::new_with_child_constraint_eval_air_id(
            child_vk,
            system_params,
            CENO_RECURSIVE_CONSTRAINT_EVAL_AIR_ID,
            false,
        )
    }

    pub fn new_for_ceno_leaf_child(
        child_vk: Arc<MultiStarkVerifyingKey<BabyBearPoseidon2Config>>,
        system_params: SystemParams,
    ) -> Self {
        Self::new_with_child_constraint_eval_air_id(
            child_vk,
            system_params,
            CENO_LEAF_CONSTRAINT_EVAL_AIR_ID,
            true,
        )
    }

    pub fn new_with_child_constraint_eval_air_id(
        child_vk: Arc<MultiStarkVerifyingKey<BabyBearPoseidon2Config>>,
        system_params: SystemParams,
        child_constraint_eval_air_id: usize,
        bridge_child_cached_commit: bool,
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
        let child_vk_commit = VkCommit {
            cached_commit: child_vk_pcs_data.commitment,
            vk_pre_hash: child_vk.pre_hash,
        };
        let circuit = Arc::new(CenoRecursiveCircuit {
            verifier_circuit: Arc::new(verifier_circuit),
            child_vk_commit,
            child_constraint_eval_air_id,
            bridge_child_cached_commit,
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

    pub fn prove(
        &self,
        proofs: &[Proof<BabyBearPoseidon2Config>],
    ) -> Result<Proof<BabyBearPoseidon2Config>> {
        if proofs.is_empty() {
            return Err(eyre!("no child proofs to recursively aggregate"));
        }
        if proofs.len() > self.circuit.verifier_circuit.max_num_proofs() {
            return Err(eyre!(
                "too many child proofs for recursive aggregation: {} > {}",
                proofs.len(),
                self.circuit.verifier_circuit.max_num_proofs()
            ));
        }

        let child_vk_commit = self.child_vk_commit();
        let verifier_pvs_ctx = self.generate_verifier_pvs_ctx(proofs, child_vk_commit)?;
        let vm_pvs_ctx = self.generate_vm_pvs_ctx(proofs)?;

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
                proofs,
                &mut external_data,
                &self.device_ctx,
                default_duplex_sponge_recorder(),
            )
            .ok_or_else(|| eyre!("failed to generate recursive verifier subcircuit traces"))?;

        let ctx = ProvingContext {
            per_trace: [verifier_pvs_ctx, vm_pvs_ctx]
                .into_iter()
                .chain(subcircuit_ctxs)
                .enumerate()
                .collect(),
        };
        let engine = E::new(self.pk.params.clone());
        #[cfg(debug_assertions)]
        if std::env::var_os("CENO_REC_V2_DEBUG_CONSTRAINTS").is_some() {
            continuations_v2::prover::debug_constraints(&self.circuit, &ctx, &engine);
        }
        let proof = engine.prove(&self.d_pk, ctx)?;
        engine.verify(&self.vk, &proof)?;
        Ok(proof)
    }

    pub fn get_vk(&self) -> Arc<MultiStarkVerifyingKey<BabyBearPoseidon2Config>> {
        self.vk.clone()
    }

    fn child_vk_commit(&self) -> VkCommit<F> {
        VkCommit {
            cached_commit: self.child_vk_pcs_data.commitment,
            vk_pre_hash: self.child_vk.pre_hash,
        }
    }
}

trait CenoRecursivePvsCtx<PB: ProverBackend> {
    fn generate_verifier_pvs_ctx(
        &self,
        proofs: &[Proof<BabyBearPoseidon2Config>],
        child_vk_commit: VkCommit<F>,
    ) -> Result<AirProvingContext<PB>>;

    fn generate_vm_pvs_ctx(
        &self,
        proofs: &[Proof<BabyBearPoseidon2Config>],
    ) -> Result<AirProvingContext<PB>>;
}

impl<S> CenoRecursivePvsCtx<CpuBackend<BabyBearPoseidon2Config>>
    for CenoRecursiveProver<S, CpuBackend<BabyBearPoseidon2Config>, CenoRecursiveCpuEngine, ()>
where
    S: AggregationSubCircuit
        + VerifierTraceGen<CpuBackend<BabyBearPoseidon2Config>, BabyBearPoseidon2Config, ()>,
{
    fn generate_verifier_pvs_ctx(
        &self,
        proofs: &[Proof<BabyBearPoseidon2Config>],
        child_vk_commit: VkCommit<F>,
    ) -> Result<openvm_stark_backend::prover::AirProvingContext<CpuBackend<BabyBearPoseidon2Config>>>
    {
        trace::generate_verifier_pvs_ctx(proofs, child_vk_commit)
    }

    fn generate_vm_pvs_ctx(
        &self,
        proofs: &[Proof<BabyBearPoseidon2Config>],
    ) -> Result<openvm_stark_backend::prover::AirProvingContext<CpuBackend<BabyBearPoseidon2Config>>>
    {
        trace::generate_vm_pvs_ctx(proofs)
    }
}

#[cfg(feature = "cuda")]
impl<S> CenoRecursivePvsCtx<GpuBackend>
    for CenoRecursiveProver<S, GpuBackend, BabyBearPoseidon2GpuEngine, GpuDeviceCtx>
where
    S: AggregationSubCircuit + VerifierTraceGen<GpuBackend, BabyBearPoseidon2Config, GpuDeviceCtx>,
{
    fn generate_verifier_pvs_ctx(
        &self,
        proofs: &[Proof<BabyBearPoseidon2Config>],
        child_vk_commit: VkCommit<F>,
    ) -> Result<openvm_stark_backend::prover::AirProvingContext<GpuBackend>> {
        trace::generate_verifier_pvs_gpu_ctx(proofs, child_vk_commit, &self.device_ctx)
    }

    fn generate_vm_pvs_ctx(
        &self,
        proofs: &[Proof<BabyBearPoseidon2Config>],
    ) -> Result<openvm_stark_backend::prover::AirProvingContext<GpuBackend>> {
        trace::generate_vm_pvs_gpu_ctx(proofs, &self.device_ctx)
    }
}
