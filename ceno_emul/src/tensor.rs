//! Reference semantics and committed-tile source for tensor ecalls.
//!
//! These routines are deliberately integer-only. They are shared by emulator
//! execution and circuit fixture generation so rounding cannot drift.

use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Result, anyhow, bail, ensure};
use tiny_keccak::{Hasher, Keccak};

pub mod llama;
pub mod planner;
pub mod production;

pub use ceno_rt::tensor::{
    TENSOR_ABI_V1, TENSOR_ATTENTION_BLOCK_REDUCED_V1, TENSOR_ATTENTION_REDUCED_V1,
    TENSOR_FFN_BLOCK_REDUCED_V1, TENSOR_MATMUL_HIDDEN_V1, TENSOR_MATMUL_INTERMEDIATE_V1,
    TENSOR_MATMUL_V1, TENSOR_RMS_LOOKUP_V1, TensorAttentionReducedDescV1, TensorBlockReducedDescV1,
    TensorMatMulDescV1, TensorProductionMatMulDescV1, TensorRmsLookupDescV1,
};

pub const ZKLLM_FIXED_V1: u32 = 1;
/// Gate-2 circuit-native commitment profile. This deliberately binds only the
/// fixed six-word test tile; production manifests/trees are a later gate.
pub const GATE2_LINEAR_COMMITMENT_V1: u32 = 1;
pub const GATE2_LINEAR_COMMITMENT_WORDS: usize = 8;
const BABY_BEAR_MODULUS: u64 = 2_013_265_921;
const TILE_DOMAIN: &[u8] = b"ceno.tensor.tile.v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TensorMeta {
    pub tensor_id: u32,
    pub byte_len: usize,
    pub tile_count: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TileOpening {
    pub tensor_id: u32,
    pub tile_id: u32,
    pub bytes: Vec<u8>,
    pub root: [u8; 32],
}

/// Eight canonical BabyBear elements. Production model authentication uses
/// this field-native digest; the legacy byte/Keccak root remains an artifact
/// checksum and is deliberately not accepted as a proof opening.
pub type TensorFieldDigest = [u32; 8];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthenticatedTileOpening {
    pub opening: TileOpening,
    /// Canonical fixed-width leaf metadata (see `production::merkle_leaf_words`).
    pub leaf_words: [u32; 20],
    pub leaf_index: u32,
    pub leaf_count: u32,
    pub siblings: Vec<TensorFieldDigest>,
    pub model_root: TensorFieldDigest,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ProviderMetrics {
    pub read_calls: u64,
    pub bytes_read: u64,
    pub h2d_bytes: u64,
    pub d2h_bytes: u64,
}

pub trait TensorWitnessProvider: Send + Sync {
    fn metadata(&self, tensor_id: u32) -> Result<TensorMeta>;
    fn read_tile(&self, tensor_id: u32, tile_id: u32) -> Result<TileOpening>;
    /// Production-only authenticated opening. Gate-2 providers intentionally
    /// fail closed instead of fabricating an empty path.
    fn read_authenticated_tile(
        &self,
        _tensor_id: u32,
        _tile_id: u32,
    ) -> Result<AuthenticatedTileOpening> {
        bail!("provider does not implement authenticated production openings")
    }
    fn metrics(&self) -> ProviderMetrics;
}

#[derive(Debug)]
pub struct DeterministicTileProvider {
    tensor_id: u32,
    tiles: Vec<Vec<u8>>,
    read_calls: AtomicU64,
    bytes_read: AtomicU64,
    h2d_bytes: AtomicU64,
    d2h_bytes: AtomicU64,
}

impl DeterministicTileProvider {
    pub fn new(tensor_id: u32, tiles: Vec<Vec<u8>>) -> Result<Self> {
        ensure!(
            !tiles.is_empty(),
            "a committed tensor needs at least one tile"
        );
        ensure!(
            tiles.iter().all(|tile| !tile.is_empty()),
            "tiles must be nonempty"
        );
        Ok(Self {
            tensor_id,
            tiles,
            read_calls: AtomicU64::new(0),
            bytes_read: AtomicU64::new(0),
            h2d_bytes: AtomicU64::new(0),
            d2h_bytes: AtomicU64::new(0),
        })
    }

    pub fn record_transfer(&self, h2d_bytes: u64, d2h_bytes: u64) {
        self.h2d_bytes.fetch_add(h2d_bytes, Ordering::Relaxed);
        self.d2h_bytes.fetch_add(d2h_bytes, Ordering::Relaxed);
    }

    fn root_for(&self, tile_id: u32) -> Result<[u8; 32]> {
        let bytes = self
            .tiles
            .get(tile_id as usize)
            .ok_or_else(|| anyhow!("unknown tile {tile_id}"))?;
        Ok(commit_tile(self.tensor_id, tile_id, bytes))
    }
}

impl TensorWitnessProvider for DeterministicTileProvider {
    fn metadata(&self, tensor_id: u32) -> Result<TensorMeta> {
        ensure!(tensor_id == self.tensor_id, "unknown tensor {tensor_id}");
        Ok(TensorMeta {
            tensor_id,
            byte_len: self.tiles.iter().map(Vec::len).sum(),
            tile_count: self.tiles.len() as u32,
        })
    }

    fn read_tile(&self, tensor_id: u32, tile_id: u32) -> Result<TileOpening> {
        ensure!(tensor_id == self.tensor_id, "unknown tensor {tensor_id}");
        let bytes = self
            .tiles
            .get(tile_id as usize)
            .ok_or_else(|| anyhow!("unknown tile {tile_id}"))?
            .clone();
        self.read_calls.fetch_add(1, Ordering::Relaxed);
        self.bytes_read
            .fetch_add(bytes.len() as u64, Ordering::Relaxed);
        Ok(TileOpening {
            tensor_id,
            tile_id,
            root: self.root_for(tile_id)?,
            bytes,
        })
    }

    fn metrics(&self) -> ProviderMetrics {
        ProviderMetrics {
            read_calls: self.read_calls.load(Ordering::Relaxed),
            bytes_read: self.bytes_read.load(Ordering::Relaxed),
            h2d_bytes: self.h2d_bytes.load(Ordering::Relaxed),
            d2h_bytes: self.d2h_bytes.load(Ordering::Relaxed),
        }
    }
}

pub fn commit_tile(tensor_id: u32, tile_id: u32, bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak::v256();
    hasher.update(TILE_DOMAIN);
    hasher.update(&tensor_id.to_le_bytes());
    hasher.update(&tile_id.to_le_bytes());
    hasher.update(&(bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
    let mut root = [0u8; 32];
    hasher.finalize(&mut root);
    root
}

/// A domain-separated field-linear commitment used by the bounded Gate-2 AIR.
///
/// This is intentionally named as a test profile rather than a cryptographic
/// model commitment. Each output is a BabyBear element serialized as a u32, so
/// the exact relation can be constrained without adding a Keccak bus.
pub fn gate2_linear_commitment_v1(
    tensor_id: u32,
    tile_id: u32,
    weights: &[i32; 6],
) -> [u32; GATE2_LINEAR_COMMITMENT_WORDS] {
    const DOMAIN: u64 = 0x4741_5432; // "GAT2"
    std::array::from_fn(|lane| {
        let lane = lane as u64 + 1;
        let mut acc = (DOMAIN
            + 17 * GATE2_LINEAR_COMMITMENT_V1 as u64
            + 31 * tensor_id as u64
            + 43 * tile_id as u64
            + 59 * weights.len() as u64
            + 71 * lane)
            % BABY_BEAR_MODULUS;
        for (index, value) in weights.iter().enumerate() {
            let signed = i64::from(*value).rem_euclid(BABY_BEAR_MODULUS as i64) as u64;
            let coefficient = 97 + lane * 19 + index as u64 * 23;
            acc = (acc + coefficient * signed) % BABY_BEAR_MODULUS;
        }
        acc as u32
    })
}

pub fn verify_opening(opening: &TileOpening, expected_root: &[u8; 32]) -> Result<()> {
    ensure!(
        &commit_tile(opening.tensor_id, opening.tile_id, &opening.bytes) == expected_root,
        "committed tile root mismatch"
    );
    ensure!(&opening.root == expected_root, "opening root mismatch");
    Ok(())
}

/// zkLLM C++ proof-compatible signed rescaling.
///
/// Returns `(quotient, remainder)` with
/// `x = quotient * 2^shift + remainder` and
/// `-2^(shift-1) <= remainder < 2^(shift-1)`.
pub fn zkllm_rescale(x: i64, shift: u32) -> Result<(i64, i64)> {
    ensure!((1..63).contains(&shift), "rescale shift must be in 1..63");
    let scale = 1i64 << shift;
    let half = scale >> 1;
    let biased = x
        .checked_add(half)
        .ok_or_else(|| anyhow!("rescale bias overflow"))?;
    let quotient = biased.div_euclid(scale);
    let remainder = x
        .checked_sub(
            quotient
                .checked_mul(scale)
                .ok_or_else(|| anyhow!("rescale product overflow"))?,
        )
        .ok_or_else(|| anyhow!("rescale remainder overflow"))?;
    ensure!(
        (-half..half).contains(&remainder),
        "non-canonical rescale remainder"
    );
    Ok((quotient, remainder))
}

pub fn validate_rescale(x: i64, shift: u32, quotient: i64, remainder: i64) -> Result<()> {
    let (expected_q, expected_r) = zkllm_rescale(x, shift)?;
    ensure!(quotient == expected_q, "rescale quotient mismatch");
    ensure!(remainder == expected_r, "rescale remainder mismatch");
    Ok(())
}

pub fn decode_i32_le(bytes: &[u8]) -> Result<Vec<i32>> {
    ensure!(
        bytes.len().is_multiple_of(4),
        "int32 tile length is not word aligned"
    );
    Ok(bytes
        .chunks_exact(4)
        .map(|chunk| i32::from_le_bytes(chunk.try_into().unwrap()))
        .collect())
}

pub fn encode_i32_le(values: &[i32]) -> Vec<u8> {
    values
        .iter()
        .flat_map(|value| value.to_le_bytes())
        .collect()
}

/// Conservative no-wrap condition for a direct signed dot product in a field.
pub fn direct_dot_bound(max_abs_input: u64, max_abs_weight: u64, k: usize) -> Result<u128> {
    (max_abs_input as u128)
        .checked_mul(max_abs_weight as u128)
        .and_then(|value| value.checked_mul(k as u128))
        .ok_or_else(|| anyhow!("dot-product bound overflow"))
}

pub fn ensure_direct_dot_no_wrap(
    max_abs_input: u64,
    max_abs_weight: u64,
    k: usize,
    field_modulus: u64,
) -> Result<u128> {
    let bound = direct_dot_bound(max_abs_input, max_abs_weight, k)?;
    ensure!(
        bound < field_modulus as u128,
        "direct dot bound {bound} reaches field modulus {field_modulus}"
    );
    Ok(bound)
}

pub fn matmul_rescaled_i32(
    input: &[i32],
    weights: &[i32],
    m: usize,
    k: usize,
    n: usize,
    shift: u32,
) -> Result<(Vec<i32>, Vec<i64>)> {
    ensure!(input.len() == m * k, "input shape mismatch");
    ensure!(weights.len() == k * n, "weight shape mismatch");
    let mut output = Vec::with_capacity(m * n);
    let mut remainders = Vec::with_capacity(m * n);
    for row in 0..m {
        for column in 0..n {
            let mut accumulator = 0i64;
            for inner in 0..k {
                let product = (input[row * k + inner] as i64)
                    .checked_mul(weights[inner * n + column] as i64)
                    .ok_or_else(|| anyhow!("matmul product overflow"))?;
                accumulator = accumulator
                    .checked_add(product)
                    .ok_or_else(|| anyhow!("matmul accumulator overflow"))?;
            }
            let (value, remainder) = zkllm_rescale(accumulator, shift)?;
            let value =
                i32::try_from(value).map_err(|_| anyhow!("rescaled output is outside int32"))?;
            output.push(value);
            remainders.push(remainder);
        }
    }
    Ok((output, remainders))
}

pub fn execute_committed_matmul(
    provider: &dyn TensorWitnessProvider,
    desc: &TensorMatMulDescV1,
    expected_root: &[u8; 32],
    input: &[i32],
    shift: u32,
) -> Result<(Vec<i32>, Vec<i64>)> {
    ensure!(desc.abi_version == TENSOR_ABI_V1, "unsupported tensor ABI");
    ensure!(
        desc.quantization_id == ZKLLM_FIXED_V1,
        "unsupported quantization profile"
    );
    ensure!(
        desc.reserved == [0; 2],
        "reserved descriptor fields must be zero"
    );
    ensure!(
        desc.input_stride == desc.k,
        "only contiguous input is supported in v1"
    );
    ensure!(
        desc.output_stride == desc.n,
        "only contiguous output is supported in v1"
    );
    let opening = provider.read_tile(desc.weight_tensor_id, desc.weight_tile_id)?;
    let weights = decode_i32_le(&opening.bytes)?;
    match desc.flags {
        0 => verify_opening(&opening, expected_root)?,
        GATE2_LINEAR_COMMITMENT_V1 => {
            let fixed_weights: [i32; 6] = weights
                .as_slice()
                .try_into()
                .map_err(|_| anyhow!("Gate-2 commitment requires six weight words"))?;
            let expected_words = expected_root
                .chunks_exact(4)
                .map(|word| u32::from_le_bytes(word.try_into().unwrap()))
                .collect::<Vec<_>>();
            ensure!(
                expected_words
                    == gate2_linear_commitment_v1(
                        opening.tensor_id,
                        opening.tile_id,
                        &fixed_weights
                    ),
                "Gate-2 circuit commitment mismatch"
            );
        }
        profile => bail!("unsupported tensor commitment profile {profile}"),
    }
    if desc.m == 0 || desc.k == 0 || desc.n == 0 {
        bail!("zero-sized tensor signature");
    }
    matmul_rescaled_i32(
        input,
        &weights,
        desc.m as usize,
        desc.k as usize,
        desc.n as usize,
        shift,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn descriptor(tensor_id: u32, tile_id: u32) -> TensorMatMulDescV1 {
        TensorMatMulDescV1 {
            abi_version: TENSOR_ABI_V1,
            signature_id: 7,
            quantization_id: ZKLLM_FIXED_V1,
            m: 2,
            k: 3,
            n: 2,
            input_stride: 3,
            output_stride: 2,
            weight_tensor_id: tensor_id,
            weight_tile_id: tile_id,
            ..Default::default()
        }
    }

    #[test]
    fn rescale_uses_proof_compatible_ties() {
        assert_eq!(zkllm_rescale(7, 4).unwrap(), (0, 7));
        assert_eq!(zkllm_rescale(8, 4).unwrap(), (1, -8));
        assert_eq!(zkllm_rescale(-7, 4).unwrap(), (0, -7));
        assert_eq!(zkllm_rescale(-8, 4).unwrap(), (0, -8));
        assert_eq!(zkllm_rescale(-9, 4).unwrap(), (-1, 7));
        assert!(validate_rescale(-8, 4, -1, 8).is_err());
    }

    #[test]
    fn committed_tiny_matmul_and_metrics() {
        let tensor_id = 42;
        let weights = [2, -1, 3, 4, -2, 5];
        let bytes = encode_i32_le(&weights);
        let root = commit_tile(tensor_id, 0, &bytes);
        let provider = DeterministicTileProvider::new(tensor_id, vec![bytes]).unwrap();
        let input = [8, -4, 2, -8, 6, 4];
        let (output, remainders) =
            execute_committed_matmul(&provider, &descriptor(tensor_id, 0), &root, &input, 4)
                .unwrap();
        assert_eq!(output, [0, -1, 0, 3]);
        assert_eq!(remainders, [0, 2, -6, 4]);
        assert_eq!(provider.metrics().read_calls, 1);
        assert_eq!(provider.metrics().bytes_read, 24);
        provider.record_transfer(24, 16);
        assert_eq!(provider.metrics().h2d_bytes, 24);
        assert_eq!(provider.metrics().d2h_bytes, 16);
    }

    #[test]
    fn binding_and_shape_tampering_fail() {
        let bytes = encode_i32_le(&[2, -1, 3, 4, -2, 5]);
        let provider = DeterministicTileProvider::new(42, vec![bytes.clone()]).unwrap();
        let root = commit_tile(42, 0, &bytes);
        let input = [8, -4, 2, -8, 6, 4];

        let mut wrong_root = root;
        wrong_root[0] ^= 1;
        assert!(
            execute_committed_matmul(&provider, &descriptor(42, 0), &wrong_root, &input, 4)
                .is_err()
        );
        assert!(execute_committed_matmul(&provider, &descriptor(43, 0), &root, &input, 4).is_err());
        assert!(execute_committed_matmul(&provider, &descriptor(42, 1), &root, &input, 4).is_err());
        let mut bad_shape = descriptor(42, 0);
        bad_shape.k = 4;
        assert!(execute_committed_matmul(&provider, &bad_shape, &root, &input, 4).is_err());
        let tampered = encode_i32_le(&[2, -1, 3, 4, -2, 6]);
        let tampered_provider = DeterministicTileProvider::new(42, vec![tampered]).unwrap();
        assert!(
            execute_committed_matmul(&tampered_provider, &descriptor(42, 0), &root, &input, 4)
                .is_err()
        );
    }

    #[test]
    fn direct_bound_rejects_field_wrap() {
        const BABY_BEAR_MODULUS: u64 = 2_013_265_921;
        assert_eq!(
            ensure_direct_dot_no_wrap(256, 256, 3, BABY_BEAR_MODULUS).unwrap(),
            196_608
        );
        assert!(ensure_direct_dot_no_wrap(65_536, 65_536, 4096, BABY_BEAR_MODULUS).is_err());
    }

    #[test]
    fn scale_2_16_fixture_is_exact() {
        let scale = 1i32 << 16;
        let input = [scale, -(scale / 2)];
        let weights = [scale / 4, scale / 8];
        let (output, remainders) = matmul_rescaled_i32(&input, &weights, 1, 2, 1, 16).unwrap();
        assert_eq!(output, [12_288]);
        assert_eq!(remainders, [0]);
    }

    #[test]
    fn gate2_commitment_is_domain_separated_and_binds_weights() {
        let weights = [2, -1, 3, 4, -2, 5];
        let root = gate2_linear_commitment_v1(42, 0, &weights);
        assert_ne!(root, gate2_linear_commitment_v1(43, 0, &weights));
        assert_ne!(root, gate2_linear_commitment_v1(42, 1, &weights));
        let mut tampered = weights;
        tampered[5] += 1;
        assert_ne!(root, gate2_linear_commitment_v1(42, 0, &tampered));

        let bytes = encode_i32_le(&weights);
        let provider = DeterministicTileProvider::new(42, vec![bytes]).unwrap();
        let mut desc = descriptor(42, 0);
        desc.flags = GATE2_LINEAR_COMMITMENT_V1;
        let root_bytes = root.map(u32::to_le_bytes).concat();
        let root_bytes: [u8; 32] = root_bytes.try_into().unwrap();
        execute_committed_matmul(&provider, &desc, &root_bytes, &[8, -4, 2, -8, 6, 4], 4).unwrap();
        let mut bad_root = root_bytes;
        bad_root[0] ^= 1;
        assert!(
            execute_committed_matmul(&provider, &desc, &bad_root, &[8, -4, 2, -8, 6, 4], 4)
                .is_err()
        );
    }
}
