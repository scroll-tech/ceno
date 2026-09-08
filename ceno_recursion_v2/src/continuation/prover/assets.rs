use std::sync::Arc;

use eyre::{Result, eyre};
use openvm_stark_backend::keygen::types::{MultiStarkProvingKey, MultiStarkVerifyingKey};
use openvm_stark_sdk::config::baby_bear_poseidon2::{
    BabyBearPoseidon2Config, BabyBearPoseidon2CpuEngine, DuplexSponge,
};

#[cfg(feature = "cuda")]
use crate::circuit::{recursive::prover::CenoRecursiveGpuProver, root::prover::CenoRootGpuProver};
#[cfg(feature = "cuda")]
use openvm_cuda_backend::BabyBearPoseidon2GpuEngine;

use crate::{
    circuit::{
        recursive::prover::{CenoRecursiveCpuProver, CenoRecursiveProver},
        root::prover::{CenoRootCpuProver, CenoRootProver},
    },
    system::RecursionVk,
};

use super::{
    AggregationOptions, InnerCpuProver, RecursionNodeKind, RootSC, SystemParams,
    internal_aggregation_chunk_plan,
};

type RecursivePk = MultiStarkProvingKey<BabyBearPoseidon2Config>;
type RecursiveVk = MultiStarkVerifyingKey<BabyBearPoseidon2Config>;
type RootPk = MultiStarkProvingKey<RootSC>;
type CpuEngine = BabyBearPoseidon2CpuEngine<DuplexSponge>;

/// Immutable host-side proving material for one complete recursion plan.
///
/// Device proving keys and child-VK commitments are deliberately absent. A worker creates those
/// only after binding its CUDA device, and drops them before switching circuit kind.
pub struct RecursionHostAssets<const LEAF_FANIN: usize, const INTERNAL_FANIN: usize> {
    child_vk: Arc<RecursionVk>,
    leaf_pk: Arc<RecursivePk>,
    leaf_vk: Arc<RecursiveVk>,
    leaf_bridge_pk: Arc<RecursivePk>,
    leaf_bridge_vk: Arc<RecursiveVk>,
    recursive_pks: Vec<Arc<RecursivePk>>,
    recursive_vks: Vec<Arc<RecursiveVk>>,
    root_pk: Arc<RootPk>,
    root_vk: Arc<MultiStarkVerifyingKey<RootSC>>,
}

/// Shard-independent host proving material that can be prepared before replay determines the
/// exact shard count. It is bound to one child VK, aggregation configuration, and fan-in pair.
pub struct RecursionHostAssetsTemplate<const LEAF_FANIN: usize, const INTERNAL_FANIN: usize> {
    child_vk: Arc<RecursionVk>,
    leaf_pk: Arc<RecursivePk>,
    leaf_vk: Arc<RecursiveVk>,
    leaf_bridge_pk: Arc<RecursivePk>,
    leaf_bridge_vk: Arc<RecursiveVk>,
    initial_recursive_pk: Arc<RecursivePk>,
    initial_recursive_vk: Arc<RecursiveVk>,
    initial_root_pk: Arc<RootPk>,
    initial_root_vk: Arc<MultiStarkVerifyingKey<RootSC>>,
    internal_params: SystemParams,
    root_params: SystemParams,
}

pub enum CpuRecursionProver<const LEAF_FANIN: usize, const INTERNAL_FANIN: usize> {
    Leaf(InnerCpuProver<LEAF_FANIN>),
    LeafBridge(CenoRecursiveCpuProver<INTERNAL_FANIN>),
    Recursive(CenoRecursiveCpuProver<INTERNAL_FANIN>),
    Root(CenoRootCpuProver),
}

#[cfg(feature = "cuda")]
pub enum GpuRecursionProver<const LEAF_FANIN: usize, const INTERNAL_FANIN: usize> {
    Leaf(super::InnerGpuProver<LEAF_FANIN>),
    LeafBridge(CenoRecursiveGpuProver<INTERNAL_FANIN>),
    Recursive(CenoRecursiveGpuProver<INTERNAL_FANIN>),
    Root(CenoRootGpuProver),
}

impl<const LEAF_FANIN: usize, const INTERNAL_FANIN: usize>
    RecursionHostAssets<LEAF_FANIN, INTERNAL_FANIN>
{
    pub fn new(
        child_vk: Arc<RecursionVk>,
        total_shards: usize,
        options: &AggregationOptions,
    ) -> Result<Self> {
        RecursionHostAssetsTemplate::new(child_vk, options)?.bind(total_shards)
    }
}

impl<const LEAF_FANIN: usize, const INTERNAL_FANIN: usize>
    RecursionHostAssetsTemplate<LEAF_FANIN, INTERNAL_FANIN>
{
    pub fn new(child_vk: Arc<RecursionVk>, options: &AggregationOptions) -> Result<Self> {
        if LEAF_FANIN == 0 {
            return Err(eyre!("leaf aggregation fanin must be non-zero"));
        }
        let leaf = InnerCpuProver::<LEAF_FANIN>::new::<CpuEngine>(
            child_vk.clone(),
            options.leaf_system_params.clone(),
            false,
            None,
        );
        let leaf_pk = leaf.get_pk();
        let leaf_vk = leaf.get_vk();

        let internal_params = options.internal_system_params();
        let leaf_bridge = CenoRecursiveCpuProver::<INTERNAL_FANIN>::new_for_ceno_leaf_child(
            leaf_vk.clone(),
            internal_params.clone(),
        );
        let leaf_bridge_pk = leaf_bridge.get_pk();
        let leaf_bridge_vk = leaf_bridge.get_vk();

        let initial_recursive = CenoRecursiveCpuProver::<INTERNAL_FANIN>::new(
            leaf_bridge_vk.clone(),
            internal_params.clone(),
        );
        let initial_recursive_pk = initial_recursive.get_pk();
        let initial_recursive_vk = initial_recursive.get_vk();
        let root_params = options.root_system_params();
        let initial_root =
            CenoRootCpuProver::new(initial_recursive_vk.clone(), root_params.clone());
        Ok(Self {
            child_vk,
            leaf_pk,
            leaf_vk,
            leaf_bridge_pk,
            leaf_bridge_vk,
            initial_recursive_pk,
            initial_recursive_vk,
            initial_root_pk: initial_root.get_pk(),
            initial_root_vk: initial_root.get_vk(),
            internal_params,
            root_params,
        })
    }

    pub fn bind(
        &self,
        total_shards: usize,
    ) -> Result<RecursionHostAssets<LEAF_FANIN, INTERNAL_FANIN>> {
        let leaf_count = total_shards.div_ceil(LEAF_FANIN);
        let plan = internal_aggregation_chunk_plan(leaf_count, INTERNAL_FANIN)?;
        let mut recursive_pks = Vec::with_capacity(1 + plan.internal_recursive_self_layers.len());
        let mut recursive_vks = Vec::with_capacity(recursive_pks.capacity());
        recursive_pks.push(self.initial_recursive_pk.clone());
        recursive_vks.push(self.initial_recursive_vk.clone());
        let mut recursive_vk = self.initial_recursive_vk.clone();
        for _ in &plan.internal_recursive_self_layers {
            let recursive = CenoRecursiveCpuProver::<INTERNAL_FANIN>::new(
                recursive_vk,
                self.internal_params.clone(),
            );
            recursive_pks.push(recursive.get_pk());
            recursive_vk = recursive.get_vk();
            recursive_vks.push(recursive_vk.clone());
        }

        let (root_pk, root_vk) = if plan.internal_recursive_self_layers.is_empty() {
            (self.initial_root_pk.clone(), self.initial_root_vk.clone())
        } else {
            let root = CenoRootCpuProver::new(recursive_vk, self.root_params.clone());
            (root.get_pk(), root.get_vk())
        };

        Ok(RecursionHostAssets {
            child_vk: self.child_vk.clone(),
            leaf_pk: self.leaf_pk.clone(),
            leaf_vk: self.leaf_vk.clone(),
            leaf_bridge_pk: self.leaf_bridge_pk.clone(),
            leaf_bridge_vk: self.leaf_bridge_vk.clone(),
            recursive_pks,
            recursive_vks,
            root_pk,
            root_vk,
        })
    }
}

impl<const LEAF_FANIN: usize, const INTERNAL_FANIN: usize>
    RecursionHostAssets<LEAF_FANIN, INTERNAL_FANIN>
{
    pub fn leaf_vk(&self) -> Arc<RecursiveVk> {
        self.leaf_vk.clone()
    }

    pub fn leaf_bridge_vk(&self) -> Arc<RecursiveVk> {
        self.leaf_bridge_vk.clone()
    }

    pub fn recursive_vk(&self, level: usize) -> Option<Arc<RecursiveVk>> {
        self.recursive_vks.get(level).cloned()
    }

    pub fn root_vk(&self) -> Arc<MultiStarkVerifyingKey<RootSC>> {
        self.root_vk.clone()
    }

    pub fn recursive_depth_count(&self) -> usize {
        self.recursive_pks.len()
    }

    pub fn hydrate_cpu(
        &self,
        kind: RecursionNodeKind,
    ) -> Result<CpuRecursionProver<LEAF_FANIN, INTERNAL_FANIN>> {
        Ok(match kind {
            RecursionNodeKind::Leaf => {
                CpuRecursionProver::Leaf(InnerCpuProver::from_pk::<CpuEngine>(
                    self.child_vk.clone(),
                    self.leaf_pk.clone(),
                    false,
                    None,
                ))
            }
            RecursionNodeKind::LeafBridge => {
                CpuRecursionProver::LeafBridge(CenoRecursiveProver::from_pk_for_ceno_leaf_child(
                    self.leaf_vk.clone(),
                    self.leaf_bridge_pk.clone(),
                ))
            }
            RecursionNodeKind::Recursive { level } => {
                let pk = self
                    .recursive_pks
                    .get(level)
                    .ok_or_else(|| eyre!("unplanned recursive level {level}"))?
                    .clone();
                let child_vk = if level == 0 {
                    self.leaf_bridge_vk.clone()
                } else {
                    self.recursive_vks[level - 1].clone()
                };
                CpuRecursionProver::Recursive(CenoRecursiveProver::from_pk(child_vk, pk))
            }
            RecursionNodeKind::Root => {
                let child_vk = self
                    .recursive_vks
                    .last()
                    .expect("the mandatory initial recursive layer always exists")
                    .clone();
                CpuRecursionProver::Root(CenoRootProver::from_pk(child_vk, self.root_pk.clone()))
            }
        })
    }

    /// Bind `device_id` before constructing any engine, context, commitment, or device PK.
    #[cfg(feature = "cuda")]
    pub fn hydrate_gpu_on(
        &self,
        device_id: usize,
        kind: RecursionNodeKind,
    ) -> Result<GpuRecursionProver<LEAF_FANIN, INTERNAL_FANIN>> {
        let device_id = i32::try_from(device_id).map_err(|_| eyre!("invalid CUDA device ID"))?;
        openvm_cuda_common::common::set_device_by_id(device_id)?;

        Ok(match kind {
            RecursionNodeKind::Leaf => GpuRecursionProver::Leaf(super::InnerGpuProver::from_pk::<
                BabyBearPoseidon2GpuEngine,
            >(
                self.child_vk.clone(),
                self.leaf_pk.clone(),
                false,
                None,
            )),
            RecursionNodeKind::LeafBridge => {
                GpuRecursionProver::LeafBridge(CenoRecursiveGpuProver::from_pk_for_ceno_leaf_child(
                    self.leaf_vk.clone(),
                    self.leaf_bridge_pk.clone(),
                ))
            }
            RecursionNodeKind::Recursive { level } => {
                let pk = self
                    .recursive_pks
                    .get(level)
                    .ok_or_else(|| eyre!("unplanned recursive level {level}"))?
                    .clone();
                let child_vk = if level == 0 {
                    self.leaf_bridge_vk.clone()
                } else {
                    self.recursive_vks[level - 1].clone()
                };
                GpuRecursionProver::Recursive(CenoRecursiveGpuProver::from_pk(child_vk, pk))
            }
            RecursionNodeKind::Root => {
                let child_vk = self
                    .recursive_vks
                    .last()
                    .expect("the mandatory initial recursive layer always exists")
                    .clone();
                GpuRecursionProver::Root(CenoRootGpuProver::from_pk(child_vk, self.root_pk.clone()))
            }
        })
    }
}
