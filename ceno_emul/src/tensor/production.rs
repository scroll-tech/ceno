//! Production-shape Llama-2-7B model metadata and integer reference relations.
//!
//! This module does not pretend that a synthetic fixture is the gated Meta
//! model.  It defines the canonical byte-level contract used by conversion,
//! committed-hint streaming and public IO, and supplies a deterministic sparse
//! fixture which has the production topology without allocating the model.

use std::{
    collections::BTreeMap,
    fs::File,
    io::{Read, Seek, SeekFrom},
    path::{Path, PathBuf},
    sync::{
        Mutex,
        atomic::{AtomicU64, Ordering},
    },
};

use anyhow::{Result, anyhow, ensure};
use ff_ext::{PoseidonField, SmallField};
use p3::{babybear::BabyBear, field::PrimeCharacteristicRing, symmetric::Permutation};
use tiny_keccak::{Hasher, Keccak};

use super::{
    AuthenticatedTileOpening, ProviderMetrics, TENSOR_ABI_V1, TensorFieldDigest, TensorMeta,
    TensorWitnessProvider, TileOpening, commit_tile,
    llama::{LLAMA2_7B_HIDDEN, LLAMA2_7B_INTERMEDIATE},
};

/// Development-only raw hint profile. It binds descriptor/order/arithmetic but
/// does not authenticate weights to `model_root`; committed-model acceptance
/// requires the deferred `COMMITTED_HINTS_MERKLE_V1` AIR.
pub const PRODUCTION_RAW_HINTS_UNAUTHENTICATED_V1: u32 = 2;
#[deprecated(note = "use the explicit unauthenticated raw-hints profile name")]
pub const PRODUCTION_COMMITTED_HINTS_V1: u32 = PRODUCTION_RAW_HINTS_UNAUTHENTICATED_V1;
pub const COMMITTED_HINTS_MERKLE_V1: u32 = 3;
pub const MERKLE_DIGEST_WORDS: usize = 8;
pub const MERKLE_LEAF_WORDS: usize = 20;
pub const MERKLE_STATE_WORDS: usize = 16;
const TILE_SPONGE_DOMAIN: u32 = 0x5449_4c45; // "TILE"
const LEAF_SPONGE_DOMAIN: u32 = 0x4c45_4146; // "LEAF"
const NODE_DOMAIN: u32 = 0x4e4f_4445; // "NODE"
const PAD_SPONGE_DOMAIN: u32 = 0x5041_4421; // "PAD!"
pub const PRODUCTION_MATMUL_HIDDEN_SIGNATURE_V1: u32 = 0x4d48_1000;
pub const PRODUCTION_MATMUL_INTERMEDIATE_SIGNATURE_V1: u32 = 0x4d49_2b00;
pub const MINI_MATMUL_HIDDEN_SIGNATURE_V1: u32 = 0x4d4d_00a0;
pub const MINI_MATMUL_INTERMEDIATE_SIGNATURE_V1: u32 = 0x4d4d_01b0;
/// Gate-5 compact, one-tile production signature.  It is intentionally
/// separate from the 10M model profile: it exists solely to retain the exact
/// production record topology while shrinking direct GPU E2E iterations.
pub const GATE5_SMALL_HIDDEN_SIGNATURE_V1: u32 = 0x4d47_0040;
pub const GATE5_SMALL_HIDDEN_K: usize = 64;

pub const LLAMA2_7B_LAYERS: usize = 32;
pub const LLAMA2_7B_VOCAB: usize = 32_000;
pub const LLAMA2_7B_CONTEXT: usize = 4096;
pub const LLAMA2_7B_REVISION_REQUIRED: &str = "meta-llama/Llama-2-7b-hf@<exact-hf-commit-required>";
pub const MANIFEST_VERSION_V1: u32 = 1;
pub const COMMITTED_HINTS_V1: u32 = 1;
pub const ZKLLM_FIXED_V1_QUANTIZATION: u32 = 1;
pub const PRODUCTION_K_TILE: usize = 1024;
pub const PRODUCTION_TILE_BYTES: u32 = (PRODUCTION_K_TILE * 4) as u32;
const MODEL_DOMAIN: &[u8] = b"ceno.tensor.model-manifest.v1";
const PROMPT_DOMAIN: &[u8] = b"ceno.tensor.prompt-token-ids.v1";

/// Compile-time Gate-5 diagnosis profile.  This keeps the Llama layer graph
/// and head geometry while making every arithmetic domain small enough for
/// assignment/PCS differential tests to run before the production-width E2E.
/// It is deliberately a separate profile: none of these constants may be
/// accepted by the Llama-2-7B production descriptors.
pub mod mini_llama_10m {
    use super::StaticPhysicalCall;

    pub const LAYERS: usize = 32;
    pub const HIDDEN: usize = 160;
    pub const HEADS: usize = 5;
    pub const HEAD_DIM: usize = 32;
    pub const INTERMEDIATE: usize = 432;
    pub const VOCAB: usize = 4096;
    pub const INITIAL_SEQUENCE: usize = 2;
    pub const EXTENDED_SEQUENCE: usize = 8;
    pub const PROOF_TILE_K: usize = 32;

    // Embedding + 32 transformer layers + final RMS/head. Biases are omitted,
    // matching Llama. Norm vectors are included.
    pub const PARAMETER_COUNT: usize = VOCAB * HIDDEN
        + LAYERS * (4 * HIDDEN * HIDDEN + 3 * HIDDEN * INTERMEDIATE + 2 * HIDDEN)
        + HIDDEN;

    const _: () = assert!(HIDDEN == HEADS * HEAD_DIM);
    const _: () = assert!(HIDDEN.is_multiple_of(PROOF_TILE_K));
    pub const INTERMEDIATE_TILE_COUNT: usize = INTERMEDIATE.div_ceil(PROOF_TILE_K);

    pub fn static_calls() -> Vec<StaticPhysicalCall> {
        let mut calls = Vec::with_capacity(2 * LAYERS + 2);
        calls.push(StaticPhysicalCall::Embedding);
        for layer in 0..LAYERS as u32 {
            calls.push(StaticPhysicalCall::AttentionBlock { layer });
            calls.push(StaticPhysicalCall::FfnBlock { layer });
        }
        calls.push(StaticPhysicalCall::FinalHead);
        calls
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TensorRole {
    TokenEmbedding = 1,
    InputNorm = 2,
    Query = 3,
    Key = 4,
    Value = 5,
    AttentionOutput = 6,
    PostAttentionNorm = 7,
    FfnGate = 8,
    FfnUp = 9,
    FfnDown = 10,
    FinalNorm = 11,
    LmHead = 12,
}

fn field_words(state: Vec<BabyBear>) -> TensorFieldDigest {
    std::array::from_fn(|i| state[i].to_canonical_u64() as u32)
}

/// Domain-separated Poseidon2 sponge with rate eight and capacity eight.
/// Padding binds the exact field-word length. Every serialized output word is
/// canonical (`< BabyBear::ORDER_U32`).
pub fn committed_hints_sponge_v1(domain: u32, words: &[u32]) -> TensorFieldDigest {
    let perm = BabyBear::get_default_perm();
    let mut state = vec![BabyBear::ZERO; MERKLE_STATE_WORDS];
    state[8] = BabyBear::from_u32(COMMITTED_HINTS_MERKLE_V1);
    state[9] = BabyBear::from_u32(domain);
    state[10] = BabyBear::from_u64(words.len() as u64);
    for chunk in words.chunks(8) {
        for (slot, &word) in state[..8].iter_mut().zip(chunk) {
            *slot += BabyBear::from_u32(word);
        }
        state = perm.permute(state);
    }
    // A final 1-bit field delimiter distinguishes an exact multiple of rate.
    state[words.len() % 8] += BabyBear::ONE;
    state = perm.permute(state);
    field_words(state)
}

pub fn committed_hints_tile_digest_v1(bytes: &[u8]) -> TensorFieldDigest {
    // One byte per field element keeps the byte representation canonical and
    // makes a future AIR range check direct (no host-side modular reduction).
    let words = bytes
        .iter()
        .map(|&byte| u32::from(byte))
        .collect::<Vec<_>>();
    committed_hints_sponge_v1(TILE_SPONGE_DOMAIN, &words)
}

/// Fixed-width canonical metadata for a model tile. `layer + 1` encodes Some,
/// while zero encodes None. The global leaf position/count bind tree order.
pub fn merkle_leaf_words(
    entry: &QuantizedTensorManifestEntry,
    tile_id: u32,
    tile_len: u32,
    leaf_index: u32,
    leaf_count: u32,
) -> Result<[u32; MERKLE_LEAF_WORDS]> {
    entry.validate()?;
    ensure!(tile_id < entry.tile_count(), "tile outside manifest entry");
    ensure!(leaf_index < leaf_count, "leaf outside model tree");
    let expected_len = (entry.byte_len - u64::from(tile_id) * u64::from(entry.tile_bytes))
        .min(u64::from(entry.tile_bytes)) as u32;
    ensure!(tile_len == expected_len, "noncanonical tile length");
    let layer = entry.layer.map_or(0, |layer| layer + 1);
    Ok([
        COMMITTED_HINTS_MERKLE_V1,
        MANIFEST_VERSION_V1,
        ZKLLM_FIXED_V1_QUANTIZATION,
        entry.tensor_id,
        entry.role as u32,
        layer,
        entry.rows,
        entry.columns,
        entry.byte_len as u32,
        (entry.byte_len >> 32) as u32,
        entry.tile_bytes,
        entry.tile_count(),
        tile_id,
        tile_len,
        leaf_index,
        leaf_count,
        0,
        0,
        0,
        0,
    ])
}

pub fn committed_hints_leaf_v1(
    leaf_words: &[u32; MERKLE_LEAF_WORDS],
    tile_digest: &TensorFieldDigest,
) -> TensorFieldDigest {
    let mut words = Vec::with_capacity(MERKLE_LEAF_WORDS + MERKLE_DIGEST_WORDS);
    words.extend_from_slice(leaf_words);
    words.extend_from_slice(tile_digest);
    committed_hints_sponge_v1(LEAF_SPONGE_DOMAIN, &words)
}

pub fn committed_hints_node_v1(
    left: &TensorFieldDigest,
    right: &TensorFieldDigest,
) -> TensorFieldDigest {
    let perm = BabyBear::get_default_perm();
    let mut state = left
        .iter()
        .chain(right)
        .map(|&word| BabyBear::from_u32(word))
        .collect::<Vec<_>>();
    state[15] += BabyBear::from_u32(NODE_DOMAIN);
    field_words(perm.permute(state))
}

fn padding_leaf(leaf_count: u32, index: u32) -> TensorFieldDigest {
    committed_hints_sponge_v1(PAD_SPONGE_DOMAIN, &[leaf_count, index])
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommittedHintsMerkleTreeV1 {
    levels: Vec<Vec<TensorFieldDigest>>,
    leaf_count: u32,
}

impl CommittedHintsMerkleTreeV1 {
    pub fn new(mut leaves: Vec<TensorFieldDigest>) -> Result<Self> {
        ensure!(!leaves.is_empty(), "model tree has no leaves");
        let leaf_count = u32::try_from(leaves.len())?;
        let padded = leaves.len().next_power_of_two();
        for index in leaves.len()..padded {
            leaves.push(padding_leaf(leaf_count, u32::try_from(index)?));
        }
        let mut levels = vec![leaves];
        while levels.last().unwrap().len() > 1 {
            let next = levels
                .last()
                .unwrap()
                .chunks_exact(2)
                .map(|pair| committed_hints_node_v1(&pair[0], &pair[1]))
                .collect();
            levels.push(next);
        }
        Ok(Self { levels, leaf_count })
    }

    pub fn root(&self) -> TensorFieldDigest {
        self.levels.last().unwrap()[0]
    }

    pub fn opening(&self, leaf_index: u32) -> Result<Vec<TensorFieldDigest>> {
        ensure!(leaf_index < self.leaf_count, "leaf outside model tree");
        let mut index = leaf_index as usize;
        let mut siblings = Vec::with_capacity(self.levels.len() - 1);
        for level in &self.levels[..self.levels.len() - 1] {
            siblings.push(level[index ^ 1]);
            index >>= 1;
        }
        Ok(siblings)
    }
}

pub fn verify_authenticated_opening_v1(opening: &AuthenticatedTileOpening) -> Result<()> {
    ensure!(opening.leaf_count > 0, "empty model tree");
    ensure!(
        opening.leaf_index < opening.leaf_count,
        "leaf outside model tree"
    );
    ensure!(
        opening.leaf_words[0] == COMMITTED_HINTS_MERKLE_V1,
        "wrong commitment profile"
    );
    ensure!(
        opening.leaf_words[3] == opening.opening.tensor_id,
        "leaf tensor mismatch"
    );
    ensure!(
        opening.leaf_words[12] == opening.opening.tile_id,
        "leaf tile mismatch"
    );
    ensure!(
        opening.leaf_words[13] as usize == opening.opening.bytes.len(),
        "leaf length mismatch"
    );
    ensure!(
        opening.leaf_words[14] == opening.leaf_index,
        "leaf index mismatch"
    );
    ensure!(
        opening.leaf_words[15] == opening.leaf_count,
        "leaf count mismatch"
    );
    ensure!(
        opening.leaf_words[16..] == [0; 4],
        "nonzero leaf reserved word"
    );
    ensure!(
        commit_tile(
            opening.opening.tensor_id,
            opening.opening.tile_id,
            &opening.opening.bytes
        ) == opening.opening.root,
        "artifact tile checksum mismatch"
    );
    let expected_depth = (opening.leaf_count as usize).next_power_of_two().ilog2() as usize;
    ensure!(
        opening.siblings.len() == expected_depth,
        "noncanonical authentication depth"
    );
    let tile_digest = committed_hints_tile_digest_v1(&opening.opening.bytes);
    let mut digest = committed_hints_leaf_v1(&opening.leaf_words, &tile_digest);
    let mut index = opening.leaf_index as usize;
    for sibling in &opening.siblings {
        digest = if index & 1 == 0 {
            committed_hints_node_v1(&digest, sibling)
        } else {
            committed_hints_node_v1(sibling, &digest)
        };
        index >>= 1;
    }
    ensure!(
        digest == opening.model_root,
        "model authentication root mismatch"
    );
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QuantizedTensorManifestEntry {
    pub tensor_id: u32,
    pub role: TensorRole,
    pub layer: Option<u32>,
    pub rows: u32,
    pub columns: u32,
    pub byte_len: u64,
    pub tile_bytes: u32,
    /// Ordered commitments to every canonical tile. Their list is included in
    /// the model root, so a bounded tile opening does not need the full tensor.
    pub tile_roots: Vec<[u8; 32]>,
}

impl QuantizedTensorManifestEntry {
    pub fn validate(&self) -> Result<()> {
        ensure!(self.tensor_id != 0, "tensor id zero is reserved");
        ensure!(self.rows > 0 && self.columns > 0, "empty tensor shape");
        ensure!(
            self.tile_bytes > 0 && self.tile_bytes % 4 == 0,
            "invalid tile alignment"
        );
        let expected = u64::from(self.rows)
            .checked_mul(u64::from(self.columns))
            .and_then(|x| x.checked_mul(4))
            .ok_or_else(|| anyhow!("tensor byte length overflow"))?;
        ensure!(self.byte_len == expected, "tensor byte length mismatch");
        ensure!(
            self.tile_roots.len() == self.tile_count() as usize,
            "tile-root count mismatch"
        );
        match self.role {
            TensorRole::TokenEmbedding | TensorRole::FinalNorm | TensorRole::LmHead => {
                ensure!(self.layer.is_none(), "global tensor has a layer")
            }
            _ => ensure!(
                self.layer.is_some_and(|x| x < LLAMA2_7B_LAYERS as u32),
                "invalid layer"
            ),
        }
        Ok(())
    }

    pub fn tile_count(&self) -> u32 {
        self.byte_len.div_ceil(u64::from(self.tile_bytes)) as u32
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QuantizedModelManifestV1 {
    pub model_revision: String,
    pub quantization_id: u32,
    pub entries: Vec<QuantizedTensorManifestEntry>,
}

impl QuantizedModelManifestV1 {
    pub fn validate(&self) -> Result<()> {
        ensure!(!self.model_revision.is_empty(), "model revision is empty");
        ensure!(
            self.quantization_id == ZKLLM_FIXED_V1_QUANTIZATION,
            "wrong quantization profile"
        );
        ensure!(
            self.entries.len() == 32 * 9 + 3,
            "wrong Llama-2-7B tensor count"
        );
        let mut previous = 0;
        for entry in &self.entries {
            entry.validate()?;
            ensure!(
                entry.tensor_id > previous,
                "tensor ids must be strictly ordered"
            );
            previous = entry.tensor_id;
        }
        Ok(())
    }

    pub fn root(&self) -> Result<[u8; 32]> {
        self.validate()?;
        let mut h = Keccak::v256();
        h.update(MODEL_DOMAIN);
        h.update(&MANIFEST_VERSION_V1.to_le_bytes());
        h.update(&(self.model_revision.len() as u32).to_le_bytes());
        h.update(self.model_revision.as_bytes());
        h.update(&self.quantization_id.to_le_bytes());
        h.update(&(self.entries.len() as u32).to_le_bytes());
        for e in &self.entries {
            h.update(&e.tensor_id.to_le_bytes());
            h.update(&(e.role as u32).to_le_bytes());
            h.update(&e.layer.unwrap_or(u32::MAX).to_le_bytes());
            h.update(&e.rows.to_le_bytes());
            h.update(&e.columns.to_le_bytes());
            h.update(&e.byte_len.to_le_bytes());
            h.update(&e.tile_bytes.to_le_bytes());
            h.update(&(e.tile_roots.len() as u32).to_le_bytes());
            for root in &e.tile_roots {
                h.update(root);
            }
        }
        let mut out = [0; 32];
        h.finalize(&mut out);
        Ok(out)
    }

    pub fn total_bytes(&self) -> u64 {
        self.entries.iter().map(|e| e.byte_len).sum()
    }
}

fn entry(
    id: u32,
    role: TensorRole,
    layer: Option<u32>,
    rows: usize,
    columns: usize,
    tile_bytes: u32,
    seed: u32,
) -> QuantizedTensorManifestEntry {
    let byte_len = (rows as u64) * (columns as u64) * 4;
    let tile_roots = (0..byte_len.div_ceil(u64::from(tile_bytes)))
        .map(|tile| {
            let mut h = Keccak::v256();
            h.update(b"ceno.tensor.production-shape-fixture-tile.v1");
            h.update(&seed.to_le_bytes());
            h.update(&id.to_le_bytes());
            h.update(&tile.to_le_bytes());
            let mut root = [0; 32];
            h.finalize(&mut root);
            root
        })
        .collect();
    QuantizedTensorManifestEntry {
        tensor_id: id,
        role,
        layer,
        rows: rows as u32,
        columns: columns as u32,
        byte_len,
        tile_bytes,
        tile_roots,
    }
}

/// A deterministic production-shape manifest. Roots are explicitly fixture
/// roots and must never be reported as commitments to Meta weights.
pub fn production_shape_fixture_manifest(
    tile_bytes: u32,
    seed: u32,
) -> Result<QuantizedModelManifestV1> {
    ensure!(tile_bytes > 0 && tile_bytes % 4 == 0, "invalid tile bytes");
    let mut entries = Vec::with_capacity(291);
    let mut id = 1;
    entries.push(entry(
        id,
        TensorRole::TokenEmbedding,
        None,
        LLAMA2_7B_VOCAB,
        LLAMA2_7B_HIDDEN,
        tile_bytes,
        seed,
    ));
    id += 1;
    for layer in 0..LLAMA2_7B_LAYERS as u32 {
        for (role, rows, cols) in [
            (TensorRole::InputNorm, 1, LLAMA2_7B_HIDDEN),
            (TensorRole::Query, LLAMA2_7B_HIDDEN, LLAMA2_7B_HIDDEN),
            (TensorRole::Key, LLAMA2_7B_HIDDEN, LLAMA2_7B_HIDDEN),
            (TensorRole::Value, LLAMA2_7B_HIDDEN, LLAMA2_7B_HIDDEN),
            (
                TensorRole::AttentionOutput,
                LLAMA2_7B_HIDDEN,
                LLAMA2_7B_HIDDEN,
            ),
            (TensorRole::PostAttentionNorm, 1, LLAMA2_7B_HIDDEN),
            (
                TensorRole::FfnGate,
                LLAMA2_7B_HIDDEN,
                LLAMA2_7B_INTERMEDIATE,
            ),
            (TensorRole::FfnUp, LLAMA2_7B_HIDDEN, LLAMA2_7B_INTERMEDIATE),
            (
                TensorRole::FfnDown,
                LLAMA2_7B_INTERMEDIATE,
                LLAMA2_7B_HIDDEN,
            ),
        ] {
            entries.push(entry(id, role, Some(layer), rows, cols, tile_bytes, seed));
            id += 1;
        }
    }
    entries.push(entry(
        id,
        TensorRole::FinalNorm,
        None,
        1,
        LLAMA2_7B_HIDDEN,
        tile_bytes,
        seed,
    ));
    id += 1;
    entries.push(entry(
        id,
        TensorRole::LmHead,
        None,
        LLAMA2_7B_HIDDEN,
        LLAMA2_7B_VOCAB,
        tile_bytes,
        seed,
    ));
    let manifest = QuantizedModelManifestV1 {
        model_revision: format!("fixture:{seed}:llama2-7b-production-shape"),
        quantization_id: ZKLLM_FIXED_V1_QUANTIZATION,
        entries,
    };
    manifest.validate()?;
    Ok(manifest)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LlamaPublicIoV1 {
    pub prompt_hash: [u8; 32],
    pub prompt_length: u32,
    pub model_root: [u8; 32],
    pub quantization_id: u32,
    pub output_token: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StaticPhysicalCall {
    Embedding,
    AttentionBlock { layer: u32 },
    FfnBlock { layer: u32 },
    FinalHead,
}

/// Statically generated physical order. Each item is shard-atomic; multiple
/// same-chip items selected into one shard are naturally batched by Ceno.
pub fn llama2_7b_static_calls() -> Vec<StaticPhysicalCall> {
    let mut calls = Vec::with_capacity(66);
    calls.push(StaticPhysicalCall::Embedding);
    for layer in 0..LLAMA2_7B_LAYERS as u32 {
        calls.push(StaticPhysicalCall::AttentionBlock { layer });
        calls.push(StaticPhysicalCall::FfnBlock { layer });
    }
    calls.push(StaticPhysicalCall::FinalHead);
    calls
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AtomicCallCost {
    pub call: StaticPhysicalCall,
    pub cells: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProductionMatMulSignature {
    HiddenK4096,
    IntermediateK11008,
    MiniHiddenK160,
    MiniIntermediateK432,
    Gate5SmallHiddenK64,
}

impl ProductionMatMulSignature {
    pub const fn id(self) -> u32 {
        match self {
            Self::HiddenK4096 => PRODUCTION_MATMUL_HIDDEN_SIGNATURE_V1,
            Self::IntermediateK11008 => PRODUCTION_MATMUL_INTERMEDIATE_SIGNATURE_V1,
            Self::MiniHiddenK160 => MINI_MATMUL_HIDDEN_SIGNATURE_V1,
            Self::MiniIntermediateK432 => MINI_MATMUL_INTERMEDIATE_SIGNATURE_V1,
            Self::Gate5SmallHiddenK64 => GATE5_SMALL_HIDDEN_SIGNATURE_V1,
        }
    }

    pub const fn from_id(id: u32) -> Option<Self> {
        match id {
            PRODUCTION_MATMUL_HIDDEN_SIGNATURE_V1 => Some(Self::HiddenK4096),
            PRODUCTION_MATMUL_INTERMEDIATE_SIGNATURE_V1 => Some(Self::IntermediateK11008),
            MINI_MATMUL_HIDDEN_SIGNATURE_V1 => Some(Self::MiniHiddenK160),
            MINI_MATMUL_INTERMEDIATE_SIGNATURE_V1 => Some(Self::MiniIntermediateK432),
            GATE5_SMALL_HIDDEN_SIGNATURE_V1 => Some(Self::Gate5SmallHiddenK64),
            _ => None,
        }
    }
    pub const fn k(self) -> usize {
        match self {
            Self::HiddenK4096 => LLAMA2_7B_HIDDEN,
            Self::IntermediateK11008 => LLAMA2_7B_INTERMEDIATE,
            Self::MiniHiddenK160 => mini_llama_10m::HIDDEN,
            Self::MiniIntermediateK432 => mini_llama_10m::INTERMEDIATE,
            Self::Gate5SmallHiddenK64 => GATE5_SMALL_HIDDEN_K,
        }
    }

    pub const fn proof_tile_k(self) -> usize {
        match self {
            Self::HiddenK4096 | Self::IntermediateK11008 => PRODUCTION_K_TILE,
            Self::MiniHiddenK160 | Self::MiniIntermediateK432 => mini_llama_10m::PROOF_TILE_K,
            // Gate-5 is an opt-in compact reproducer.  Its one physical row
            // intentionally matches the 64-word raw/tile record width so the
            // guest-first E2E does not pay the production K1024 setup cost.
            Self::Gate5SmallHiddenK64 => GATE5_SMALL_HIDDEN_K,
        }
    }

    pub const fn atomic_tiles(self) -> u64 {
        self.k().div_ceil(self.proof_tile_k()) as u64
    }
}

impl ProductionMatMulCellDesc {
    pub fn from_guest(desc: &ceno_rt::tensor::TensorProductionMatMulDescV1) -> Result<Self> {
        ensure!(desc.abi_version == TENSOR_ABI_V1, "unsupported tensor ABI");
        ensure!(
            desc.commitment_profile == PRODUCTION_RAW_HINTS_UNAUTHENTICATED_V1,
            "unsupported production raw-hints profile"
        );
        ensure!(
            desc.quantization_id == ZKLLM_FIXED_V1_QUANTIZATION,
            "unsupported quantization profile"
        );
        ensure!(
            desc.input_stride == 1 && desc.output_stride == 1,
            "unsupported stride"
        );
        ensure!(desc.reserved == [0; 3], "nonzero production reserved word");
        let signature = ProductionMatMulSignature::from_id(desc.signature_id)
            .ok_or_else(|| anyhow!("unsupported production MatMul signature"))?;
        let cell = Self::new(
            signature,
            desc.weight_tensor_id,
            desc.first_weight_tile,
            desc.rescale_shift,
        )?;
        ensure!(
            desc.weight_tile_count == cell.tile_count,
            "production tile count mismatch"
        );
        Ok(cell)
    }
}

/// Read exactly the descriptor's ordered sparse range and evaluate one output
/// cell. The returned roots are retained in order for the proof-side manifest
/// opening relation; no unvisited tile is requested.
pub fn execute_sparse_production_cell(
    provider: &dyn TensorWitnessProvider,
    desc: ProductionMatMulCellDesc,
    input: &[i32],
) -> Result<(i32, i64, Vec<[u8; 32]>)> {
    ensure!(
        input.len() == desc.signature.k(),
        "production input K mismatch"
    );
    let metadata = provider.metadata(desc.weight_tensor_id)?;
    ensure!(
        metadata.tile_count >= desc.first_tile_id + desc.tile_count,
        "provider tile range mismatch"
    );
    let mut weights = Vec::with_capacity(input.len());
    let mut roots = Vec::with_capacity(desc.tile_count as usize);
    for expected_tile in desc.first_tile_id..desc.first_tile_id + desc.tile_count {
        let opening = provider.read_tile(desc.weight_tensor_id, expected_tile)?;
        ensure!(
            opening.tensor_id == desc.weight_tensor_id,
            "opening tensor order mismatch"
        );
        ensure!(
            opening.tile_id == expected_tile,
            "opening tile order mismatch"
        );
        ensure!(
            commit_tile(opening.tensor_id, opening.tile_id, &opening.bytes) == opening.root,
            "opening commitment mismatch"
        );
        ensure!(opening.bytes.len() % 4 == 0, "unaligned production opening");
        weights.extend(
            opening
                .bytes
                .chunks_exact(4)
                .map(|word| i32::from_le_bytes(word.try_into().expect("four-byte word"))),
        );
        roots.push(opening.root);
    }
    ensure!(weights.len() == input.len(), "opened production K mismatch");
    let trace = signed_dot_byte_limb_rescaled(input, &weights, desc.rescale_shift)?;
    #[cfg(feature = "tensor-cuda")]
    if desc.signature == ProductionMatMulSignature::IntermediateK11008 {
        // CUDA is an execution provider only: the CPU trace below is the
        // proof-authoritative relation.  Export deliberately borrows the
        // witness, so its device buffers remain reusable after output check.
        let provider = crate::tensor::production_cuda::K11008CudaProvider::new(0)?;
        let mut witness = provider.execute(input, &weights)?;
        let gpu_sum = provider.export(&mut witness)?;
        ensure!(
            gpu_sum == trace.signed_sum,
            "K11008 CUDA result disagrees with proof relation"
        );
        ensure!(
            witness.device_words() == 2 * crate::tensor::production_cuda::K11008 + 1,
            "K11008 CUDA witness was not retained"
        );
    }
    Ok((
        i32::try_from(trace.quotient).map_err(|_| anyhow!("production output outside i32"))?,
        trace.remainder,
        roots,
    ))
}

/// Production proof path: every ordered weight tile must carry a valid
/// CommittedHintsMerkleV1 opening to the descriptor's public model root.
pub fn execute_authenticated_sparse_production_cell(
    provider: &dyn TensorWitnessProvider,
    desc: ProductionMatMulCellDesc,
    input: &[i32],
    expected_model_root: &TensorFieldDigest,
) -> Result<(i32, i64)> {
    ensure!(
        input.len() == desc.signature.k(),
        "production input K mismatch"
    );
    let mut weights = Vec::with_capacity(input.len());
    for expected_tile in desc.first_tile_id..desc.first_tile_id + desc.tile_count {
        let opening = provider.read_authenticated_tile(desc.weight_tensor_id, expected_tile)?;
        ensure!(
            opening.opening.tensor_id == desc.weight_tensor_id,
            "opening tensor order mismatch"
        );
        ensure!(
            opening.opening.tile_id == expected_tile,
            "opening tile order mismatch"
        );
        ensure!(
            &opening.model_root == expected_model_root,
            "descriptor model root mismatch"
        );
        verify_authenticated_opening_v1(&opening)?;
        weights.extend(
            opening
                .opening
                .bytes
                .chunks_exact(4)
                .map(|word| i32::from_le_bytes(word.try_into().expect("four-byte word"))),
        );
    }
    ensure!(weights.len() == input.len(), "opened production K mismatch");
    let trace = signed_dot_byte_limb_rescaled(input, &weights, desc.rescale_shift)?;
    Ok((
        i32::try_from(trace.quotient).map_err(|_| anyhow!("production output outside i32"))?,
        trace.remainder,
    ))
}

/// Descriptor for one production-width output cell. Its K tiles are internal
/// to one shard-atomic MatMul call and therefore all count against admission.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProductionMatMulCellDesc {
    pub signature: ProductionMatMulSignature,
    pub weight_tensor_id: u32,
    pub first_tile_id: u32,
    pub tile_count: u32,
    pub rescale_shift: u32,
}

impl ProductionMatMulCellDesc {
    pub fn new(
        signature: ProductionMatMulSignature,
        weight_tensor_id: u32,
        first_tile_id: u32,
        rescale_shift: u32,
    ) -> Result<Self> {
        ensure!(weight_tensor_id != 0, "tensor id zero is reserved");
        ensure!(
            matches!(rescale_shift, 16 | 20),
            "unsupported rescale shift"
        );
        let tile_count = u32::try_from(signature.atomic_tiles())?;
        first_tile_id
            .checked_add(tile_count)
            .ok_or_else(|| anyhow!("production tile range overflow"))?;
        Ok(Self {
            signature,
            weight_tensor_id,
            first_tile_id,
            tile_count,
            rescale_shift,
        })
    }

    pub fn atomic_cell_cost(self) -> u64 {
        u64::from(self.tile_count)
    }

    pub fn validate_manifest_entry(self, entry: &QuantizedTensorManifestEntry) -> Result<()> {
        entry.validate()?;
        ensure!(
            entry.tensor_id == self.weight_tensor_id,
            "descriptor tensor mismatch"
        );
        ensure!(
            entry.tile_bytes == PRODUCTION_TILE_BYTES,
            "production tile size mismatch"
        );
        let end = self
            .first_tile_id
            .checked_add(self.tile_count)
            .ok_or_else(|| anyhow!("production tile range overflow"))?;
        ensure!(
            end <= entry.tile_count(),
            "descriptor tile range outside manifest"
        );
        ensure!(
            entry.rows as usize == self.signature.k(),
            "descriptor K mismatch"
        );
        Ok(())
    }

    pub fn ensure_fits_shard(self, max_cell_per_shard: u64) -> Result<()> {
        ensure!(
            self.atomic_cell_cost() <= max_cell_per_shard,
            "atomic production MatMul exceeds shard budget"
        );
        Ok(())
    }
}

/// Greedy admission over Ceno's external cell cap. No physical call is split;
/// arithmetic K tiling remains internal to its call.
pub fn plan_atomic_shards(
    calls: &[AtomicCallCost],
    max_cells: u64,
) -> Result<Vec<Vec<AtomicCallCost>>> {
    ensure!(max_cells > 0, "shard budget must be positive");
    let mut shards: Vec<Vec<AtomicCallCost>> = Vec::new();
    let mut used = 0u64;
    for &call in calls {
        ensure!(call.cells > 0, "call cost must be positive");
        ensure!(
            call.cells <= max_cells,
            "atomic tensor call exceeds shard budget"
        );
        if used
            .checked_add(call.cells)
            .is_none_or(|next| next > max_cells)
        {
            shards.push(Vec::new());
            used = 0;
        }
        if shards.is_empty() {
            shards.push(Vec::new());
        }
        shards.last_mut().unwrap().push(call);
        used += call.cells;
    }
    Ok(shards)
}

pub fn prompt_token_hash(token_ids: &[u32]) -> Result<[u8; 32]> {
    ensure!(
        !token_ids.is_empty() && token_ids.len() <= LLAMA2_7B_CONTEXT,
        "invalid prompt length"
    );
    ensure!(
        token_ids.iter().all(|&x| x < LLAMA2_7B_VOCAB as u32),
        "token outside vocabulary"
    );
    let mut h = Keccak::v256();
    h.update(PROMPT_DOMAIN);
    h.update(&(token_ids.len() as u32).to_le_bytes());
    for token in token_ids {
        h.update(&token.to_le_bytes());
    }
    let mut out = [0; 32];
    h.finalize(&mut out);
    Ok(out)
}

/// Exact, deterministic tie-breaking: the first (lowest token id) maximum wins.
pub fn exact_argmax(logits: &[i64]) -> Result<u32> {
    ensure!(
        logits.len() == LLAMA2_7B_VOCAB,
        "LM head vocabulary mismatch"
    );
    Ok(logits
        .iter()
        .enumerate()
        .max_by(|(ia, a), (ib, b)| a.cmp(b).then_with(|| ib.cmp(ia)))
        .unwrap()
        .0 as u32)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedDotTileTrace {
    pub positive: u128,
    pub negative: u128,
    pub signed_sum: i64,
    pub positive_base256: Vec<u8>,
    pub negative_base256: Vec<u8>,
}

pub const PRODUCTION_DOT_LIMBS: usize = 10;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedDotTrace {
    pub tiles: Vec<SignedDotTileTrace>,
    pub positive: u128,
    pub negative: u128,
    pub signed_sum: i64,
    pub quotient: i64,
    pub remainder: i64,
    pub positive_cross_tile_carries: Vec<Vec<u8>>,
    pub negative_cross_tile_carries: Vec<Vec<u8>>,
}

fn base256(mut value: u128) -> Vec<u8> {
    let mut out = vec![0; 16];
    for limb in &mut out {
        *limb = value as u8;
        value >>= 8;
    }
    out
}

fn add_base256_checked(accumulator: u128, addend: u128) -> Result<(u128, Vec<u8>)> {
    let sum = accumulator
        .checked_add(addend)
        .ok_or_else(|| anyhow!("cross-tile limb overflow"))?;
    let a = base256(accumulator);
    let b = base256(addend);
    let out = base256(sum);
    let mut carries = vec![0u8; 16];
    let mut carry = 0u16;
    for i in 0..16 {
        let column = u16::from(a[i]) + u16::from(b[i]) + carry;
        ensure!(column as u8 == out[i], "cross-tile limb addition mismatch");
        carry = column >> 8;
        carries[i] = carry as u8;
    }
    ensure!(carry == 0, "cross-tile limb terminal carry");
    Ok((sum, carries))
}

/// Production-safe semantic relation for one K tile. Sign and four magnitude
/// bytes are explicit; positive and negative buckets cannot cancel in-field.
pub fn signed_dot_byte_limb_tile(input: &[i32], weights: &[i32]) -> Result<SignedDotTileTrace> {
    ensure!(
        input.len() == weights.len() && !input.is_empty(),
        "dot shape mismatch"
    );
    ensure!(
        input.len() <= PRODUCTION_K_TILE,
        "K tile exceeds production bound"
    );
    let mut positive = 0u128;
    let mut negative = 0u128;
    for (&a, &b) in input.iter().zip(weights) {
        let magnitude = u128::from(a.unsigned_abs()) * u128::from(b.unsigned_abs());
        if (a < 0) ^ (b < 0) {
            negative = negative
                .checked_add(magnitude)
                .ok_or_else(|| anyhow!("negative bucket overflow"))?;
        } else {
            positive = positive
                .checked_add(magnitude)
                .ok_or_else(|| anyhow!("positive bucket overflow"))?;
        }
    }
    let signed = i128::try_from(positive)? - i128::try_from(negative)?;
    let signed_sum =
        i64::try_from(signed).map_err(|_| anyhow!("semantic int64 accumulator overflow"))?;
    Ok(SignedDotTileTrace {
        positive,
        negative,
        signed_sum,
        positive_base256: base256(positive),
        negative_base256: base256(negative),
    })
}

/// Exact production dot relation, tiled at the AIR's K bound.  The two
/// unsigned buckets are added independently across tiles before their sole
/// signed subtraction, so neither per-product nor cross-tile cancellation can
/// wrap in BabyBear.  `shift` uses zkLLM's asymmetric half-open remainder.
pub fn signed_dot_byte_limb_rescaled(
    input: &[i32],
    weights: &[i32],
    shift: u32,
) -> Result<SignedDotTrace> {
    ensure!(
        input.len() == weights.len() && !input.is_empty(),
        "dot shape mismatch"
    );
    ensure!(
        matches!(shift, 16 | 20),
        "production shift must be Q16 or Q20"
    );
    let mut tiles = Vec::with_capacity(input.len().div_ceil(PRODUCTION_K_TILE));
    let mut positive = 0u128;
    let mut negative = 0u128;
    let mut positive_cross_tile_carries = Vec::new();
    let mut negative_cross_tile_carries = Vec::new();
    for (a, b) in input
        .chunks(PRODUCTION_K_TILE)
        .zip(weights.chunks(PRODUCTION_K_TILE))
    {
        let tile = signed_dot_byte_limb_tile(a, b)?;
        let (next_positive, positive_carries) = add_base256_checked(positive, tile.positive)?;
        let (next_negative, negative_carries) = add_base256_checked(negative, tile.negative)?;
        positive = next_positive;
        negative = next_negative;
        positive_cross_tile_carries.push(positive_carries);
        negative_cross_tile_carries.push(negative_carries);
        tiles.push(tile);
    }
    let signed_sum = i64::try_from(i128::try_from(positive)? - i128::try_from(negative)?)
        .map_err(|_| anyhow!("semantic int64 accumulator overflow"))?;
    let (quotient, remainder) = crate::tensor::zkllm_rescale(signed_sum, shift)?;
    ensure!(
        remainder >= -(1i64 << (shift - 1)) && remainder < (1i64 << (shift - 1)),
        "non-canonical remainder"
    );
    Ok(SignedDotTrace {
        tiles,
        positive,
        negative,
        signed_sum,
        quotient,
        remainder,
        positive_cross_tile_carries,
        negative_cross_tile_carries,
    })
}

struct FileTensor {
    entry: QuantizedTensorManifestEntry,
    path: PathBuf,
    file: Mutex<File>,
}
pub struct FileTensorWitnessProvider {
    tensors: BTreeMap<u32, FileTensor>,
    reads: AtomicU64,
    bytes: AtomicU64,
}

impl FileTensorWitnessProvider {
    pub fn open(manifest: &QuantizedModelManifestV1, directory: &Path) -> Result<Self> {
        manifest.validate()?;
        let mut tensors = BTreeMap::new();
        for e in &manifest.entries {
            let path = directory.join(format!("{}.i32le", e.tensor_id));
            let file = File::open(&path)?;
            ensure!(
                file.metadata()?.len() == e.byte_len,
                "tensor file length mismatch: {}",
                path.display()
            );
            tensors.insert(
                e.tensor_id,
                FileTensor {
                    entry: e.clone(),
                    path,
                    file: Mutex::new(file),
                },
            );
        }
        Ok(Self {
            tensors,
            reads: AtomicU64::new(0),
            bytes: AtomicU64::new(0),
        })
    }
}

impl TensorWitnessProvider for FileTensorWitnessProvider {
    fn metadata(&self, tensor_id: u32) -> Result<TensorMeta> {
        let t = self
            .tensors
            .get(&tensor_id)
            .ok_or_else(|| anyhow!("unknown tensor {tensor_id}"))?;
        Ok(TensorMeta {
            tensor_id,
            byte_len: t.entry.byte_len as usize,
            tile_count: t.entry.tile_count(),
        })
    }
    fn read_tile(&self, tensor_id: u32, tile_id: u32) -> Result<TileOpening> {
        let t = self
            .tensors
            .get(&tensor_id)
            .ok_or_else(|| anyhow!("unknown tensor {tensor_id}"))?;
        ensure!(tile_id < t.entry.tile_count(), "unknown tile {tile_id}");
        let offset = u64::from(tile_id) * u64::from(t.entry.tile_bytes);
        let len = (t.entry.byte_len - offset).min(u64::from(t.entry.tile_bytes)) as usize;
        let mut bytes = vec![0; len];
        let mut file = t
            .file
            .lock()
            .map_err(|_| anyhow!("poisoned tensor file {}", t.path.display()))?;
        file.seek(SeekFrom::Start(offset))?;
        file.read_exact(&mut bytes)?;
        self.reads.fetch_add(1, Ordering::Relaxed);
        self.bytes.fetch_add(len as u64, Ordering::Relaxed);
        let root = commit_tile(tensor_id, tile_id, &bytes);
        ensure!(
            root == t.entry.tile_roots[tile_id as usize],
            "tile commitment mismatch"
        );
        Ok(TileOpening {
            tensor_id,
            tile_id,
            root,
            bytes,
        })
    }
    fn metrics(&self) -> ProviderMetrics {
        ProviderMetrics {
            read_calls: self.reads.load(Ordering::Relaxed),
            bytes_read: self.bytes.load(Ordering::Relaxed),
            h2d_bytes: 0,
            d2h_bytes: 0,
        }
    }
}

/// Sparse deterministic provider for production-width proof fixtures. It owns
/// only the manifest entry and synthesizes an authenticated tile when that tile
/// is visited; no unvisited tensor bytes are allocated.
pub struct SparseProductionTileProvider {
    entry: QuantizedTensorManifestEntry,
    descriptor: ProductionMatMulCellDesc,
    seed: u32,
    reads: AtomicU64,
    bytes: AtomicU64,
    leaf_words: Vec<[u32; MERKLE_LEAF_WORDS]>,
    tree: CommittedHintsMerkleTreeV1,
}

fn sparse_fixture_tile_bytes(tensor_id: u32, tile_id: u32, len: usize, seed: u32) -> Vec<u8> {
    let words = len / 4;
    (0..words)
        .flat_map(|word| {
            let mixed = seed
                .wrapping_mul(0x9e37_79b9)
                .wrapping_add(tensor_id.wrapping_mul(0x85eb_ca6b))
                .wrapping_add(tile_id.wrapping_mul(0xc2b2_ae35))
                .wrapping_add(word as u32);
            // Keep values compact while retaining signed products and a
            // deterministic byte-level commitment.
            (((mixed % 255) as i32) - 127).to_le_bytes()
        })
        .collect()
}

pub fn sparse_production_dot_fixture(
    signature: ProductionMatMulSignature,
    tensor_id: u32,
    seed: u32,
) -> Result<(
    ProductionMatMulCellDesc,
    QuantizedTensorManifestEntry,
    SparseProductionTileProvider,
)> {
    let descriptor = ProductionMatMulCellDesc::new(signature, tensor_id, 0, 16)?;
    let byte_len = (signature.k() * 4) as u64;
    let tile_roots = (0..descriptor.tile_count)
        .map(|tile_id| {
            let offset = u64::from(tile_id) * u64::from(PRODUCTION_TILE_BYTES);
            let len = (byte_len - offset).min(u64::from(PRODUCTION_TILE_BYTES)) as usize;
            commit_tile(
                tensor_id,
                tile_id,
                &sparse_fixture_tile_bytes(tensor_id, tile_id, len, seed),
            )
        })
        .collect();
    let entry = QuantizedTensorManifestEntry {
        tensor_id,
        role: TensorRole::Query,
        layer: Some(0),
        rows: signature.k() as u32,
        columns: 1,
        byte_len,
        tile_bytes: PRODUCTION_TILE_BYTES,
        tile_roots,
    };
    descriptor.validate_manifest_entry(&entry)?;
    let provider = SparseProductionTileProvider::new(entry.clone(), descriptor, seed)?;
    Ok((descriptor, entry, provider))
}

impl SparseProductionTileProvider {
    pub fn new(
        entry: QuantizedTensorManifestEntry,
        descriptor: ProductionMatMulCellDesc,
        seed: u32,
    ) -> Result<Self> {
        descriptor.validate_manifest_entry(&entry)?;
        let leaf_count = descriptor.tile_count;
        let mut leaf_words = Vec::with_capacity(leaf_count as usize);
        let mut leaves = Vec::with_capacity(leaf_count as usize);
        for (leaf_index, tile_id) in
            (descriptor.first_tile_id..descriptor.first_tile_id + descriptor.tile_count).enumerate()
        {
            let offset = u64::from(tile_id) * u64::from(entry.tile_bytes);
            let len = (entry.byte_len - offset).min(u64::from(entry.tile_bytes)) as usize;
            let bytes = sparse_fixture_tile_bytes(entry.tensor_id, tile_id, len, seed);
            let words =
                merkle_leaf_words(&entry, tile_id, len as u32, leaf_index as u32, leaf_count)?;
            leaves.push(committed_hints_leaf_v1(
                &words,
                &committed_hints_tile_digest_v1(&bytes),
            ));
            leaf_words.push(words);
        }
        let tree = CommittedHintsMerkleTreeV1::new(leaves)?;
        Ok(Self {
            entry,
            descriptor,
            seed,
            reads: AtomicU64::new(0),
            bytes: AtomicU64::new(0),
            leaf_words,
            tree,
        })
    }

    fn visited_range(&self) -> std::ops::Range<u32> {
        self.descriptor.first_tile_id..self.descriptor.first_tile_id + self.descriptor.tile_count
    }
}

impl TensorWitnessProvider for SparseProductionTileProvider {
    fn metadata(&self, tensor_id: u32) -> Result<TensorMeta> {
        ensure!(
            tensor_id == self.entry.tensor_id,
            "unknown tensor {tensor_id}"
        );
        Ok(TensorMeta {
            tensor_id,
            byte_len: self.entry.byte_len as usize,
            tile_count: self.entry.tile_count(),
        })
    }

    fn read_tile(&self, tensor_id: u32, tile_id: u32) -> Result<TileOpening> {
        ensure!(
            tensor_id == self.entry.tensor_id,
            "unknown tensor {tensor_id}"
        );
        ensure!(
            self.visited_range().contains(&tile_id),
            "unvisited production tile"
        );
        let offset = u64::from(tile_id) * u64::from(self.entry.tile_bytes);
        let len = (self.entry.byte_len - offset).min(u64::from(self.entry.tile_bytes)) as usize;
        let bytes = sparse_fixture_tile_bytes(tensor_id, tile_id, len, self.seed);
        let root = commit_tile(tensor_id, tile_id, &bytes);
        ensure!(
            self.entry.tile_roots.get(tile_id as usize) == Some(&root),
            "sparse production tile commitment mismatch"
        );
        self.reads.fetch_add(1, Ordering::Relaxed);
        self.bytes.fetch_add(len as u64, Ordering::Relaxed);
        Ok(TileOpening {
            tensor_id,
            tile_id,
            bytes,
            root,
        })
    }

    fn read_authenticated_tile(
        &self,
        tensor_id: u32,
        tile_id: u32,
    ) -> Result<AuthenticatedTileOpening> {
        let opening = self.read_tile(tensor_id, tile_id)?;
        let leaf_index = tile_id
            .checked_sub(self.descriptor.first_tile_id)
            .ok_or_else(|| anyhow!("tile precedes authenticated range"))?;
        Ok(AuthenticatedTileOpening {
            opening,
            leaf_words: self.leaf_words[leaf_index as usize],
            leaf_index,
            leaf_count: self.descriptor.tile_count,
            siblings: self.tree.opening(leaf_index)?,
            model_root: self.tree.root(),
        })
    }

    fn metrics(&self) -> ProviderMetrics {
        ProviderMetrics {
            read_calls: self.reads.load(Ordering::Relaxed),
            bytes_read: self.bytes.load(Ordering::Relaxed),
            h2d_bytes: 0,
            d2h_bytes: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn authenticated_fixture() -> (AuthenticatedTileOpening, CommittedHintsMerkleTreeV1) {
        let tiles = [vec![1, 2, 3, 4], vec![5, 6, 7, 8], vec![9, 10, 11, 12]];
        let entry = QuantizedTensorManifestEntry {
            tensor_id: 17,
            role: TensorRole::Query,
            layer: Some(2),
            rows: 1,
            columns: 3,
            byte_len: 12,
            tile_bytes: 4,
            tile_roots: tiles
                .iter()
                .enumerate()
                .map(|(i, bytes)| commit_tile(17, i as u32, bytes))
                .collect(),
        };
        let leaves = tiles
            .iter()
            .enumerate()
            .map(|(i, bytes)| {
                let words = merkle_leaf_words(&entry, i as u32, 4, i as u32, 3).unwrap();
                committed_hints_leaf_v1(&words, &committed_hints_tile_digest_v1(bytes))
            })
            .collect();
        let tree = CommittedHintsMerkleTreeV1::new(leaves).unwrap();
        let tile_id = 1;
        let bytes = tiles[tile_id as usize].clone();
        let opening = AuthenticatedTileOpening {
            opening: TileOpening {
                tensor_id: 17,
                tile_id,
                root: commit_tile(17, tile_id, &bytes),
                bytes,
            },
            leaf_words: merkle_leaf_words(&entry, tile_id, 4, tile_id, 3).unwrap(),
            leaf_index: tile_id,
            leaf_count: 3,
            siblings: tree.opening(tile_id).unwrap(),
            model_root: tree.root(),
        };
        (opening, tree)
    }

    #[test]
    fn committed_hints_merkle_v1_vector_and_tamper_are_canonical() {
        let (opening, tree) = authenticated_fixture();
        assert_eq!(tree.root(), opening.model_root);
        assert!(
            opening
                .model_root
                .iter()
                .all(|&word| u64::from(word) < 2_013_265_921)
        );
        // Reproducible CPU vector. Keep the full digest fixed so commitment
        // parameter or packing drift is immediately visible.
        assert_eq!(
            opening.model_root,
            [
                1_974_168_301,
                990_148_332,
                1_638_887_537,
                1_860_872_973,
                1_412_822_189,
                136_956_565,
                1_537_710_210,
                232_549_160,
            ]
        );
        verify_authenticated_opening_v1(&opening).unwrap();

        let rejects = |mut candidate: AuthenticatedTileOpening,
                       mutate: fn(&mut AuthenticatedTileOpening)| {
            mutate(&mut candidate);
            assert!(verify_authenticated_opening_v1(&candidate).is_err());
        };
        rejects(opening.clone(), |x| x.leaf_words[7] ^= 1); // shape metadata
        rejects(opening.clone(), |x| x.opening.bytes[0] ^= 1); // tile
        rejects(opening.clone(), |x| x.siblings[0][0] ^= 1); // path
        rejects(opening.clone(), |x| x.model_root[0] ^= 1); // root
        rejects(opening.clone(), |x| x.leaf_index ^= 1); // order
    }

    #[test]
    fn legacy_provider_fails_closed_for_authenticated_opening() {
        let provider = crate::tensor::DeterministicTileProvider::new(7, vec![vec![0; 4]]).unwrap();
        assert!(provider.read_authenticated_tile(7, 0).is_err());
    }
    #[test]
    fn topology_manifest_is_exact_and_bound() {
        let m = production_shape_fixture_manifest(64 << 20, 7).unwrap();
        assert_eq!(m.entries.len(), 291);
        assert_eq!(m.entries.iter().filter(|e| e.layer.is_some()).count(), 288);
        assert!(m.total_bytes() > 26_000_000_000);
        assert_eq!(m.total_bytes() / 4, 6_738_415_616);
        assert_ne!(
            m.root().unwrap(),
            production_shape_fixture_manifest(64 << 20, 8)
                .unwrap()
                .root()
                .unwrap()
        );
    }
    #[test]
    fn prompt_binding_and_argmax_are_canonical() {
        let ids: Vec<_> = (0..128).collect();
        let h = prompt_token_hash(&ids).unwrap();
        let mut changed = ids.clone();
        changed[127] += 1;
        assert_ne!(h, prompt_token_hash(&changed).unwrap());
        assert!(prompt_token_hash(&[]).is_err());
        let mut logits = vec![-9; LLAMA2_7B_VOCAB];
        logits[9] = 4;
        logits[10] = 4;
        assert_eq!(exact_argmax(&logits).unwrap(), 9);
    }
    #[test]
    fn byte_limb_dot_handles_i32_edges_and_rejects_oversize() {
        let a = [i32::MIN, i32::MAX, -7, 9];
        let b = [-1, 2, -11, -3];
        let t = signed_dot_byte_limb_tile(&a, &b).unwrap();
        let expected: i64 = a
            .iter()
            .zip(b)
            .map(|(&x, y)| i64::from(x) * i64::from(y))
            .sum();
        assert_eq!(t.signed_sum, expected);
        let reconstruct = |v: &[u8]| v.iter().rev().fold(0u128, |x, &b| (x << 8) + u128::from(b));
        assert_eq!(reconstruct(&t.positive_base256), t.positive);
        assert_eq!(reconstruct(&t.negative_base256), t.negative);
        assert!(
            signed_dot_byte_limb_tile(
                &vec![1; PRODUCTION_K_TILE + 1],
                &vec![1; PRODUCTION_K_TILE + 1]
            )
            .is_err()
        );
    }
    #[test]
    fn tiled_dot_checks_four_and_eleven_tiles_and_negative_half() {
        for k in [LLAMA2_7B_HIDDEN, LLAMA2_7B_INTERMEDIATE] {
            let a = (0..k)
                .map(|i| if i % 3 == 0 { -17 } else { 23 })
                .collect::<Vec<_>>();
            let b = (0..k)
                .map(|i| if i % 5 == 0 { -31 } else { 29 })
                .collect::<Vec<_>>();
            let trace = signed_dot_byte_limb_rescaled(&a, &b, 16).unwrap();
            assert_eq!(trace.tiles.len(), k.div_ceil(PRODUCTION_K_TILE));
            assert_eq!(trace.positive_cross_tile_carries.len(), trace.tiles.len());
            assert!(
                trace
                    .positive_cross_tile_carries
                    .iter()
                    .flatten()
                    .all(|&carry| carry <= 1)
            );
            assert_eq!(
                trace.signed_sum,
                a.iter()
                    .zip(&b)
                    .map(|(&x, &y)| i64::from(x) * i64::from(y))
                    .sum()
            );
            assert_eq!(
                trace.signed_sum,
                trace.quotient * (1 << 16) + trace.remainder
            );
        }
        let half = signed_dot_byte_limb_rescaled(&[-32_768], &[1], 16).unwrap();
        assert_eq!((half.quotient, half.remainder), (0, -32_768));
        let q20 = signed_dot_byte_limb_rescaled(&[-524_288], &[1], 20).unwrap();
        assert_eq!((q20.quotient, q20.remainder), (0, -524_288));
    }
    #[test]
    fn production_constants_are_llama2_7b() {
        assert_eq!(LLAMA2_7B_HIDDEN, 4096);
        assert_eq!(crate::tensor::llama::LLAMA2_7B_HEADS, 32);
        assert_eq!(crate::tensor::llama::LLAMA2_7B_HEAD_DIM, 128);
        assert_eq!(LLAMA2_7B_INTERMEDIATE, 11008);
        let calls = llama2_7b_static_calls();
        assert_eq!(calls.len(), 66);
        assert_eq!(calls[0], StaticPhysicalCall::Embedding);
        assert_eq!(calls[65], StaticPhysicalCall::FinalHead);
        let costs = calls
            .into_iter()
            .map(|call| AtomicCallCost { call, cells: 4 })
            .collect::<Vec<_>>();
        assert_eq!(plan_atomic_shards(&costs, 16).unwrap().len(), 17);
        assert!(plan_atomic_shards(&costs, 3).is_err());
    }

    #[test]
    fn mini_llama_profile_preserves_topology_and_k32_padding() {
        use super::mini_llama_10m as mini;

        assert_eq!(mini::HIDDEN, mini::HEADS * mini::HEAD_DIM);
        assert_eq!(mini::HIDDEN / mini::PROOF_TILE_K, 5);
        assert_eq!(mini::INTERMEDIATE_TILE_COUNT, 14);
        assert_eq!(mini::PARAMETER_COUNT, 10_578_080);
        let calls = mini::static_calls();
        assert_eq!(calls.len(), 66);
        assert_eq!(calls.first(), Some(&StaticPhysicalCall::Embedding));
        assert_eq!(calls.last(), Some(&StaticPhysicalCall::FinalHead));
        for (layer, pair) in calls[1..65].chunks_exact(2).enumerate() {
            assert_eq!(
                pair,
                [
                    StaticPhysicalCall::AttentionBlock {
                        layer: layer as u32,
                    },
                    StaticPhysicalCall::FfnBlock {
                        layer: layer as u32,
                    },
                ]
            );
        }
    }

    #[test]
    fn production_descriptors_charge_tiles_and_reject_undersized_shards() {
        let hidden =
            ProductionMatMulCellDesc::new(ProductionMatMulSignature::HiddenK4096, 7, 0, 16)
                .unwrap();
        let intermediate =
            ProductionMatMulCellDesc::new(ProductionMatMulSignature::IntermediateK11008, 8, 0, 20)
                .unwrap();
        assert_eq!((hidden.tile_count, hidden.atomic_cell_cost()), (4, 4));
        assert_eq!(
            (intermediate.tile_count, intermediate.atomic_cell_cost()),
            (11, 11)
        );
        hidden.ensure_fits_shard(4).unwrap();
        intermediate.ensure_fits_shard(11).unwrap();
        assert!(hidden.ensure_fits_shard(3).is_err());
        assert!(intermediate.ensure_fits_shard(10).is_err());
    }

    #[test]
    fn sparse_provider_reads_only_visited_manifest_bound_tiles() {
        let (descriptor, entry, provider) =
            sparse_production_dot_fixture(ProductionMatMulSignature::HiddenK4096, 91, 17).unwrap();
        assert_eq!(provider.metrics(), ProviderMetrics::default());
        let opening = provider.read_tile(91, 2).unwrap();
        assert_eq!(opening.root, entry.tile_roots[2]);
        assert_eq!(provider.metrics().read_calls, 1);
        assert_eq!(
            provider.metrics().bytes_read,
            u64::from(PRODUCTION_TILE_BYTES)
        );
        assert!(provider.read_tile(91, descriptor.tile_count).is_err());
        assert!(provider.read_tile(92, 0).is_err());

        let mut bad_entry = entry.clone();
        bad_entry.tile_roots[1][0] ^= 1;
        let bad = SparseProductionTileProvider::new(bad_entry, descriptor, 17).unwrap();
        assert!(bad.read_tile(91, 1).is_err());

        let wrong_seed = SparseProductionTileProvider::new(entry, descriptor, 18).unwrap();
        assert!(wrong_seed.read_tile(91, 0).is_err());

        let (shape_descriptor, mut wrong_shape, _) =
            sparse_production_dot_fixture(ProductionMatMulSignature::HiddenK4096, 93, 17).unwrap();
        wrong_shape.rows -= 1;
        wrong_shape.byte_len -= 4;
        assert!(
            shape_descriptor
                .validate_manifest_entry(&wrong_shape)
                .is_err()
        );
    }

    fn production_guest_desc(
        signature: ProductionMatMulSignature,
        tensor_id: u32,
    ) -> ceno_rt::tensor::TensorProductionMatMulDescV1 {
        ceno_rt::tensor::TensorProductionMatMulDescV1 {
            abi_version: TENSOR_ABI_V1,
            commitment_profile: PRODUCTION_RAW_HINTS_UNAUTHENTICATED_V1,
            quantization_id: ZKLLM_FIXED_V1_QUANTIZATION,
            signature_id: signature.id(),
            input_ptr: 0x1000,
            output_ptr: 0x2000,
            weight_tensor_id: tensor_id,
            first_weight_tile: 0,
            weight_tile_count: signature.atomic_tiles() as u32,
            rescale_shift: 16,
            model_root_ptr: 0x3000,
            input_stride: 1,
            output_stride: 1,
            reserved: [0; 3],
        }
    }

    #[test]
    fn production_guest_descriptor_derives_atomic_domain_and_rejects_tampering() {
        for signature in [
            ProductionMatMulSignature::HiddenK4096,
            ProductionMatMulSignature::IntermediateK11008,
        ] {
            let guest = production_guest_desc(signature, 77);
            let desc = ProductionMatMulCellDesc::from_guest(&guest).unwrap();
            assert_eq!(desc.signature, signature);
            assert_eq!(desc.atomic_cell_cost(), signature.atomic_tiles());
            assert!(desc.ensure_fits_shard(signature.atomic_tiles()).is_ok());
            assert!(
                desc.ensure_fits_shard(signature.atomic_tiles() - 1)
                    .is_err()
            );

            let mut bad = guest;
            bad.weight_tile_count -= 1;
            assert!(ProductionMatMulCellDesc::from_guest(&bad).is_err());
            let mut bad = guest;
            bad.signature_id ^= 1;
            assert!(ProductionMatMulCellDesc::from_guest(&bad).is_err());
            let mut bad = guest;
            bad.reserved[2] = 1;
            assert!(ProductionMatMulCellDesc::from_guest(&bad).is_err());
        }
    }

    #[test]
    fn production_sparse_execution_visits_exact_order_and_binds_output() {
        let (desc, _entry, provider) =
            sparse_production_dot_fixture(ProductionMatMulSignature::HiddenK4096, 81, 23).unwrap();
        let input = (0..desc.signature.k())
            .map(|i| if i % 7 == 0 { -19 } else { 13 })
            .collect::<Vec<_>>();
        let (output, remainder, roots) =
            execute_sparse_production_cell(&provider, desc, &input).unwrap();
        assert_eq!(roots.len(), 4);
        assert_eq!(provider.metrics().read_calls, 4);
        let mut weights = Vec::new();
        for tile in 0..4 {
            weights.extend(
                sparse_fixture_tile_bytes(81, tile, PRODUCTION_TILE_BYTES as usize, 23)
                    .chunks_exact(4)
                    .map(|x| i32::from_le_bytes(x.try_into().unwrap())),
            );
        }
        let expected = signed_dot_byte_limb_rescaled(&input, &weights, 16).unwrap();
        assert_eq!(i64::from(output), expected.quotient);
        assert_eq!(remainder, expected.remainder);

        let mut wrong = desc;
        wrong.first_tile_id = 1;
        assert!(execute_sparse_production_cell(&provider, wrong, &input).is_err());
    }
}
