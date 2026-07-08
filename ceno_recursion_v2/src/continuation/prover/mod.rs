use std::sync::Arc;

use continuations_v2::SC;
use eyre::{Result, eyre};
use openvm_cpu_backend::CpuBackend;
use openvm_stark_backend::proof::Proof;
use openvm_stark_sdk::config::baby_bear_poseidon2::BabyBearPoseidon2CpuEngine;

use crate::{
    circuit::inner::InnerTraceGenImpl,
    system::{RecursionProof, RecursionVk, VerifierSubCircuit},
};

mod inner;

pub use inner::*;

pub type InnerCpuProver<const MAX_NUM_PROOFS: usize> =
    InnerAggregationProver<CpuBackend<SC>, VerifierSubCircuit<MAX_NUM_PROOFS>, InnerTraceGenImpl>;

/// Proof produced by the leaf layer: a STARK proof over `SC` (BabyBear + Poseidon2).
pub type LeafProof = Proof<SC>;

/// Proof produced by the internal aggregation layer (same STARK config as leaf).
pub type InternalProof = Proof<SC>;

/// Placeholder for the final root proof that can be verified on-chain.
///
/// The root layer re-proves the last internal proof over a BN254-friendly
/// STARK config (`RootSC = BabyBearBn254Poseidon2Config`) and wraps it
/// in a SNARK (Groth16 / SWIRL). This type will be replaced with a
/// concrete SNARK proof once the root prover is implemented.
pub struct RootProof {
    pub inner_proof: InternalProof,
}

/// Configuration for the aggregation pipeline.
pub struct AggregationOptions {
    /// System parameters for the leaf-layer recursive STARK prover
    /// (log_blowup, num_queries, proof_of_work_bits).
    pub leaf_system_params: SystemParams,
    /// System parameters for the internal-layer recursive STARK prover.
    /// Defaults to `leaf_system_params` if not set.
    pub internal_system_params: Option<SystemParams>,
}

impl AggregationOptions {
    pub fn new(leaf_system_params: SystemParams) -> Self {
        Self {
            leaf_system_params,
            internal_system_params: None,
        }
    }

    pub fn with_internal_system_params(mut self, params: SystemParams) -> Self {
        self.internal_system_params = Some(params);
        self
    }

    fn internal_system_params(&self) -> SystemParams {
        self.internal_system_params
            .clone()
            .unwrap_or_else(|| self.leaf_system_params.clone())
    }
}

type CenoProof = RecursionProof;
type Engine =
    BabyBearPoseidon2CpuEngine<openvm_stark_sdk::config::baby_bear_poseidon2::DuplexSponge>;

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
pub struct AggProver<const LEAF_FANIN: usize, const INTERNAL_FANIN: usize> {
    leaf_prover: InnerCpuProver<LEAF_FANIN>,
    options: AggregationOptions,
}

impl<const LEAF_FANIN: usize, const INTERNAL_FANIN: usize> AggProver<LEAF_FANIN, INTERNAL_FANIN> {
    /// Create a new aggregation prover from the base-layer verifying key.
    pub fn new(child_vk: Arc<RecursionVk>, options: AggregationOptions) -> Self {
        let leaf_prover = InnerCpuProver::<LEAF_FANIN>::new::<Engine>(
            child_vk,
            options.leaf_system_params.clone(),
            false,
            None,
        );
        Self {
            leaf_prover,
            options,
        }
    }

    /// Run the full recursion pipeline: leaf → internal → root.
    ///
    /// Takes all base-layer shard proofs and returns a single root proof.
    pub fn prove(&self, shard_proofs: &[CenoProof]) -> Result<RootProof> {
        if shard_proofs.is_empty() {
            return Err(eyre!("no shard proofs to aggregate"));
        }

        let leaf_proofs = self.prove_leaves(shard_proofs)?;
        let final_proof = self.prove_internal(leaf_proofs)?;
        self.prove_root(final_proof)
    }

    /// Stage 1: Partition shard proofs into chunks of `LEAF_FANIN` and
    /// produce one leaf proof per chunk.
    fn prove_leaves(&self, shard_proofs: &[CenoProof]) -> Result<Vec<LeafProof>> {
        let mut leaf_proofs = Vec::new();
        for chunk in shard_proofs.chunks(LEAF_FANIN) {
            let proof = self
                .leaf_prover
                .agg_prove_no_def::<Engine>(chunk, ChildVkKind::App)?;
            leaf_proofs.push(proof);
        }
        Ok(leaf_proofs)
    }

    /// Stage 2: Tree aggregation of child proofs with fanin `INTERNAL_FANIN`
    /// until one remains.
    ///
    /// Not yet implemented — requires `ChildVkKind::RecursiveSelf` support
    /// and converting the leaf prover's own VK into a `RecursionVk`.
    fn prove_internal(&self, leaf_proofs: Vec<LeafProof>) -> Result<InternalProof> {
        if leaf_proofs.len() == 1 {
            return Ok(leaf_proofs.into_iter().next().unwrap());
        }

        let _internal_params = self.options.internal_system_params();

        // TODO: Build self-recursive inner prover with INTERNAL_FANIN that
        // verifies Proof<SC> children (not ZKVMProof). This requires:
        //   1. Converting Proof<SC> to the format InnerAggregationProver expects
        //   2. Converting the leaf prover's own VK (MultiStarkVerifyingKey<SC>)
        //      into RecursionVk so the recursive circuit can reference it
        //   3. Using ChildVkKind::RecursiveSelf in generate_proving_ctx
        //   4. Iterating: chunk current_level by INTERNAL_FANIN, prove each
        //      chunk, repeat until one proof remains
        Err(eyre!(
            "internal aggregation not yet implemented: \
             {} leaf proofs need tree reduction with fanin {}",
            leaf_proofs.len(),
            INTERNAL_FANIN,
        ))
    }

    /// Stage 3: Re-prove over BN254-friendly STARK config and wrap in SNARK.
    ///
    /// Not yet implemented — requires the root circuit (BabyBearBn254Poseidon2Config)
    /// and a SNARK wrapper (Groth16 or SWIRL).
    fn prove_root(&self, internal_proof: InternalProof) -> Result<RootProof> {
        // TODO: Implement root proving:
        //   1. Build RootCircuit that verifies one Proof<SC> over RootSC
        //   2. Prove with BabyBearBn254Poseidon2 engine
        //   3. Wrap the RootSC proof in a Groth16/SWIRL SNARK
        Ok(RootProof {
            inner_proof: internal_proof,
        })
    }

    /// Access the leaf prover's verifying key.
    pub fn leaf_vk(&self) -> Arc<openvm_stark_backend::keygen::types::MultiStarkVerifyingKey<SC>> {
        self.leaf_prover.get_vk()
    }
}
