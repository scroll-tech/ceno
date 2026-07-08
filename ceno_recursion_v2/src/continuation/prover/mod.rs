use std::sync::Arc;

use eyre::{Result, eyre};
use openvm_cpu_backend::CpuBackend;
use openvm_stark_backend::{
    StarkEngine, StarkProtocolConfig, keygen::types::MultiStarkVerifyingKey, proof::Proof,
    prover::ProverBackend,
};
use openvm_stark_sdk::config::{
    baby_bear_bn254_poseidon2::{BabyBearBn254Poseidon2Config, BabyBearBn254Poseidon2CpuEngine},
    baby_bear_poseidon2::{BabyBearPoseidon2Config, BabyBearPoseidon2CpuEngine, Digest, EF, F},
};

use crate::{
    circuit::{
        inner::{InnerTraceGen, InnerTraceGenImpl},
        recursive::prover::CenoRecursiveCpuProver,
        root::prover::CenoRootCpuProver,
    },
    system::{RecursionProof, RecursionVk, VerifierSubCircuit, VerifierTraceGen},
};

mod inner;

pub use inner::*;

pub type InnerCpuProver<const MAX_NUM_PROOFS: usize> = InnerAggregationProver<
    CpuBackend<BabyBearPoseidon2Config>,
    VerifierSubCircuit<MAX_NUM_PROOFS>,
    InnerTraceGenImpl,
>;

/// Proof produced by the leaf layer: a STARK proof over `SC` (BabyBear + Poseidon2).
pub type LeafProof<SC = BabyBearPoseidon2Config> = Proof<SC>;

/// Proof produced by the internal aggregation layer (same STARK config as leaf).
pub type InternalProof<SC = BabyBearPoseidon2Config> = Proof<SC>;

/// Verifying key produced for the leaf aggregation circuit.
pub type LeafVk<SC = BabyBearPoseidon2Config> =
    openvm_stark_backend::keygen::types::MultiStarkVerifyingKey<SC>;

pub type RootSC = BabyBearBn254Poseidon2Config;
pub type RootEngine = BabyBearBn254Poseidon2CpuEngine;
pub type RootVk = MultiStarkVerifyingKey<RootSC>;

/// Final root STARK proof over the BN254-friendly root config.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct RootProof {
    pub proof: Proof<RootSC>,
}

/// In-memory result for callers that need the generated root VK immediately.
#[derive(Clone)]
pub struct RootProvingOutput {
    pub root_vk: RootVk,
    pub root_proof: RootProof,
}

pub fn verify_root_proof(root_vk: &RootVk, root_proof: &RootProof) -> Result<()> {
    RootEngine::new(root_vk.inner.params.clone()).verify(root_vk, &root_proof.proof)?;
    Ok(())
}

/// Configuration for the aggregation pipeline.
#[derive(Clone)]
pub struct AggregationOptions {
    /// System parameters for the leaf-layer recursive STARK prover
    /// (log_blowup, num_queries, proof_of_work_bits).
    pub leaf_system_params: SystemParams,
    /// System parameters for the internal-layer recursive STARK prover.
    /// Defaults to `leaf_system_params` if not set.
    pub internal_system_params: Option<SystemParams>,
    /// System parameters for the root-layer BN254-friendly STARK prover.
    /// Defaults to `internal_system_params`, then `leaf_system_params`, if not set.
    pub root_system_params: Option<SystemParams>,
}

impl AggregationOptions {
    pub fn new(leaf_system_params: SystemParams) -> Self {
        Self {
            leaf_system_params,
            internal_system_params: None,
            root_system_params: None,
        }
    }

    pub fn with_internal_system_params(mut self, params: SystemParams) -> Self {
        self.internal_system_params = Some(params);
        self
    }

    pub fn with_root_system_params(mut self, params: SystemParams) -> Self {
        self.root_system_params = Some(params);
        self
    }

    fn internal_system_params(&self) -> SystemParams {
        self.internal_system_params
            .clone()
            .unwrap_or_else(|| self.leaf_system_params.clone())
    }

    fn root_system_params(&self) -> SystemParams {
        self.root_system_params
            .clone()
            .unwrap_or_else(|| self.internal_system_params())
    }
}

type CenoProof = RecursionProof;
type Engine =
    BabyBearPoseidon2CpuEngine<openvm_stark_sdk::config::baby_bear_poseidon2::DuplexSponge>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct InternalAggregationChunkPlan {
    pub internal_for_leaf_chunks: Vec<usize>,
    pub internal_recursive_initial_chunks: Vec<usize>,
    pub internal_recursive_self_layers: Vec<Vec<usize>>,
}

pub(crate) fn internal_aggregation_chunk_plan(
    leaf_proof_count: usize,
    fanin: usize,
) -> Result<InternalAggregationChunkPlan> {
    if leaf_proof_count == 0 {
        return Err(eyre!("no leaf proofs to aggregate"));
    }
    if fanin == 0 {
        return Err(eyre!("internal aggregation fanin must be non-zero"));
    }

    let internal_for_leaf_chunks = chunk_lengths(leaf_proof_count, fanin);
    let mut current_count = internal_for_leaf_chunks.len();

    let internal_recursive_initial_chunks = chunk_lengths(current_count, fanin);
    current_count = internal_recursive_initial_chunks.len();

    let mut internal_recursive_self_layers = Vec::new();
    while current_count > 1 {
        let layer = chunk_lengths(current_count, fanin);
        current_count = layer.len();
        internal_recursive_self_layers.push(layer);
    }

    Ok(InternalAggregationChunkPlan {
        internal_for_leaf_chunks,
        internal_recursive_initial_chunks,
        internal_recursive_self_layers,
    })
}

fn chunk_lengths(item_count: usize, fanin: usize) -> Vec<usize> {
    (0..item_count)
        .step_by(fanin)
        .map(|start| fanin.min(item_count - start))
        .collect()
}

pub trait RootProveInput<SC: StarkProtocolConfig<F = F, EF = EF, Digest = Digest>> {
    fn prove_root_with_child_vk(
        self,
        child_vk: Arc<LeafVk<SC>>,
        options: &AggregationOptions,
    ) -> Result<RootProvingOutput>;
}

pub trait InternalAggregateInput<SC: StarkProtocolConfig<F = F, EF = EF, Digest = Digest>>:
    Sized
{
    fn prove_internal_layers<const FANIN: usize>(
        leaf_proofs: Vec<Self>,
        leaf_vk: Arc<LeafVk<SC>>,
        options: &AggregationOptions,
    ) -> Result<(Self, Arc<LeafVk<SC>>)>;
}

impl RootProveInput<BabyBearPoseidon2Config> for Proof<BabyBearPoseidon2Config> {
    fn prove_root_with_child_vk(
        self,
        child_vk: Arc<LeafVk<BabyBearPoseidon2Config>>,
        options: &AggregationOptions,
    ) -> Result<RootProvingOutput> {
        let root_prover = CenoRootCpuProver::new(child_vk, options.root_system_params());
        let proof = root_prover.prove(self)?;
        Ok(RootProvingOutput {
            root_vk: root_prover.get_vk().as_ref().clone(),
            root_proof: RootProof { proof },
        })
    }
}

impl InternalAggregateInput<BabyBearPoseidon2Config> for Proof<BabyBearPoseidon2Config> {
    fn prove_internal_layers<const FANIN: usize>(
        leaf_proofs: Vec<Self>,
        leaf_vk: Arc<LeafVk<BabyBearPoseidon2Config>>,
        options: &AggregationOptions,
    ) -> Result<(Self, Arc<LeafVk<BabyBearPoseidon2Config>>)> {
        let plan = internal_aggregation_chunk_plan(leaf_proofs.len(), FANIN)?;

        let internal_params = options.internal_system_params();
        let internal_for_leaf = CenoRecursiveCpuProver::<FANIN>::new_for_ceno_leaf_child(
            leaf_vk,
            internal_params.clone(),
        );
        let mut i4l_proofs = Vec::with_capacity(plan.internal_for_leaf_chunks.len());
        let mut offset = 0;
        for chunk_len in plan.internal_for_leaf_chunks {
            let end = offset + chunk_len;
            i4l_proofs.push(internal_for_leaf.prove(&leaf_proofs[offset..end])?);
            offset = end;
        }

        let i4l_vk = internal_for_leaf.get_vk();
        let internal_recursive =
            CenoRecursiveCpuProver::<FANIN>::new(i4l_vk, internal_params.clone());
        let mut ir_proofs = Vec::with_capacity(plan.internal_recursive_initial_chunks.len());
        let mut offset = 0;
        for chunk_len in plan.internal_recursive_initial_chunks {
            let end = offset + chunk_len;
            ir_proofs.push(internal_recursive.prove(&i4l_proofs[offset..end])?);
            offset = end;
        }

        let mut current_proofs = ir_proofs;
        let mut current_vk = internal_recursive.get_vk();
        for layer in plan.internal_recursive_self_layers {
            let self_recursive =
                CenoRecursiveCpuProver::<FANIN>::new(current_vk, internal_params.clone());
            let mut next_proofs = Vec::with_capacity(layer.len());
            let mut offset = 0;
            for chunk_len in layer {
                let end = offset + chunk_len;
                next_proofs.push(self_recursive.prove(&current_proofs[offset..end])?);
                offset = end;
            }
            current_vk = self_recursive.get_vk();
            current_proofs = next_proofs;
        }

        match current_proofs.as_slice() {
            [proof] => Ok((proof.clone(), current_vk)),
            _ => Err(eyre!(
                "internal aggregation finished with {} proofs after self-recursive reduction",
                current_proofs.len()
            )),
        }
    }
}

/// Full recursion pipeline that aggregates N Ceno base-layer shard proofs
/// into a single compact root proof.
///
/// The pipeline has three stages:
///
/// 1. **Leaf**: Each leaf node verifies up to `LEAF_FANIN` base-layer
///    `ZKVMProof`s and produces a `LeafProof` (STARK over BabyBear).
///
/// 2. **Internal**: A tree of internal nodes aggregates child proofs
///    with fanin `INTERNAL_FANIN` until a single `InternalProof` remains.
///    Each internal node uses the same recursive circuit with
///    `ChildVkKind::RecursiveSelf`.
///
/// 3. **Root**: The final internal proof is re-proved over a BN254-friendly
///    STARK config and wrapped in a SNARK for on-chain verification.
pub struct AggProver<
    const LEAF_FANIN: usize,
    const INTERNAL_FANIN: usize,
    SC = BabyBearPoseidon2Config,
    PB = CpuBackend<SC>,
    T = InnerTraceGenImpl,
    Eg = Engine,
> where
    SC: StarkProtocolConfig<F = F, EF = EF, Digest = Digest>,
    PB: ProverBackend<Val = F, Challenge = EF, Commitment = Digest>,
    T: InnerTraceGen<PB>,
    VerifierSubCircuit<LEAF_FANIN>: VerifierTraceGen<PB, SC>,
{
    leaf_prover: InnerAggregationProver<PB, VerifierSubCircuit<LEAF_FANIN>, T, SC>,
    options: AggregationOptions,
    _engine: std::marker::PhantomData<Eg>,
}

impl<const LEAF_FANIN: usize, const INTERNAL_FANIN: usize, SC, PB, T, Eg>
    AggProver<LEAF_FANIN, INTERNAL_FANIN, SC, PB, T, Eg>
where
    SC: StarkProtocolConfig<F = F, EF = EF, Digest = Digest>,
    PB: ProverBackend<Val = F, Challenge = EF, Commitment = Digest>,
    PB::Matrix: Clone,
    PB::Commitment: Default,
    T: InnerTraceGen<PB>,
    Eg: StarkEngine<SC = SC, PB = PB>,
    VerifierSubCircuit<LEAF_FANIN>: VerifierTraceGen<PB, SC>,
    InternalProof<SC>: RootProveInput<SC> + InternalAggregateInput<SC>,
{
    /// Create a new aggregation prover from the base-layer verifying key.
    pub fn new(child_vk: Arc<RecursionVk>, options: AggregationOptions) -> Self {
        let leaf_prover = InnerAggregationProver::<PB, VerifierSubCircuit<LEAF_FANIN>, T, SC>::new::<
            Eg,
        >(child_vk, options.leaf_system_params.clone(), false, None);
        Self {
            leaf_prover,
            options,
            _engine: std::marker::PhantomData,
        }
    }

    /// Run the full recursion pipeline: leaf → internal → root.
    ///
    /// Takes all base-layer shard proofs and returns a single root proof.
    pub fn prove(&self, shard_proofs: &[CenoProof]) -> Result<RootProof> {
        Ok(self.prove_with_root_vk(shard_proofs)?.root_proof)
    }

    /// Run the full recursion pipeline and keep the generated root VK.
    pub fn prove_with_root_vk(&self, shard_proofs: &[CenoProof]) -> Result<RootProvingOutput> {
        if shard_proofs.is_empty() {
            return Err(eyre!("no shard proofs to aggregate"));
        }
        if LEAF_FANIN == 0 {
            return Err(eyre!("leaf aggregation fanin must be non-zero"));
        }

        let leaf_proofs = self.prove_leaves(shard_proofs)?;
        let (final_proof, final_vk) = self.prove_internal(leaf_proofs)?;
        self.prove_root(final_proof, final_vk)
    }

    /// Stage 1: Partition shard proofs into chunks of `LEAF_FANIN` and
    /// produce one leaf proof per chunk.
    fn prove_leaves(&self, shard_proofs: &[CenoProof]) -> Result<Vec<LeafProof<SC>>> {
        let mut leaf_proofs = Vec::new();
        for chunk in shard_proofs.chunks(LEAF_FANIN) {
            let proof = self
                .leaf_prover
                .agg_prove_no_def::<Eg>(chunk, ChildVkKind::App)?;
            leaf_proofs.push(proof);
        }
        Ok(leaf_proofs)
    }

    /// Stage 2: Tree aggregation of child proofs with fanin `INTERNAL_FANIN`.
    /// OpenVM always wraps leaf proofs through an internal-for-leaf layer and
    /// then an internal-recursive layer. Odd remainders become smaller chunks;
    /// child proofs are never duplicated to fill a fanin.
    fn prove_internal(
        &self,
        leaf_proofs: Vec<LeafProof<SC>>,
    ) -> Result<(InternalProof<SC>, Arc<LeafVk<SC>>)> {
        InternalProof::<SC>::prove_internal_layers::<INTERNAL_FANIN>(
            leaf_proofs,
            self.leaf_vk(),
            &self.options,
        )
    }

    /// Stage 3: Re-prove over the Ceno-local BN254-friendly root circuit.
    fn prove_root(
        &self,
        internal_proof: InternalProof<SC>,
        internal_vk: Arc<LeafVk<SC>>,
    ) -> Result<RootProvingOutput> {
        internal_proof.prove_root_with_child_vk(internal_vk, &self.options)
    }

    /// Access the leaf prover's verifying key.
    pub fn leaf_vk(&self) -> Arc<LeafVk<SC>> {
        self.leaf_prover.get_vk()
    }

    /// Verify a root proof against its root verifying key.
    pub fn verify_root_proof(&self, root_vk: &RootVk, root_proof: &RootProof) -> Result<()> {
        verify_root_proof(root_vk, root_proof)
    }
}
