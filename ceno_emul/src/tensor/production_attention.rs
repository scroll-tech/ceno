//! Exact production-shape attention contract for the zkLLM comparison.
//!
//! The helpers in this module are coordinate oracles: they never allocate the
//! complete score/probability domain. CUDA and proof replay use the same fixed
//! dimensions, coordinate order, quotient convention, and deterministic
//! private fixture, but do not call these routines to generate their witness.

use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Result, ensure};

use super::{
    ProviderMetrics, TensorMeta, TensorWitnessProvider, TileOpening, commit_tile,
    llama::LLAMA2_7B_INTERMEDIATE, production::TensorRole,
};

pub const SEQUENCE: usize = 2048;
pub const HIDDEN: usize = 4096;
pub const HEADS: usize = 32;
pub const HEAD_DIM: usize = 128;
pub const HEADS_PER_CIRCUIT: usize = 4;
pub const CIRCUITS: usize = HEADS / HEADS_PER_CIRCUIT;
pub const Q20_SHIFT: u32 = 20;
pub const Q20_SCALE: i64 = 1 << Q20_SHIFT;
pub const SOFTMAX_LIMBS: usize = 5;
pub const HIDDEN_WORDS: usize = SEQUENCE * HIDDEN;
pub const QKV_WORDS: usize = 3 * HEADS * SEQUENCE * HEAD_DIM;
pub const CONTEXT_WORDS: usize = HEADS * SEQUENCE * HEAD_DIM;
pub const SCORE_ROWS: usize = HEADS * SEQUENCE * SEQUENCE;
pub const GROUP_SCORE_ROWS: usize = HEADS_PER_CIRCUIT * SEQUENCE * SEQUENCE;
pub const MATRIX_AXIS_BITS: usize = 11;
pub const MATRIX_GROUP_BITS: usize = 2;
pub const MATRIX_REDUCTION_BITS: usize = MATRIX_AXIS_BITS + MATRIX_GROUP_BITS;
pub const QK_MULTIPLICATIONS: u64 =
    HEADS as u64 * SEQUENCE as u64 * SEQUENCE as u64 * HEAD_DIM as u64;
pub const PV_MULTIPLICATIONS: u64 = QK_MULTIPLICATIONS;
pub const TOTAL_MULTIPLICATIONS: u64 = QK_MULTIPLICATIONS + PV_MULTIPLICATIONS;

pub const HIDDEN_BYTES: u64 = (HIDDEN_WORDS * size_of::<i32>()) as u64;
pub const QKV_BYTES: u64 = (QKV_WORDS * size_of::<i32>()) as u64;
pub const CONTEXT_BYTES: u64 = (CONTEXT_WORDS * size_of::<i32>()) as u64;
pub const ONE_HEAD_SCORE_BYTES: u64 = (SEQUENCE * SEQUENCE * size_of::<i32>()) as u64;
pub const LIMB_TILE_BYTES: u64 = (SOFTMAX_LIMBS * 128 * SEQUENCE * size_of::<u32>()) as u64;
pub const PROVIDER_SCRATCH_BUDGET_BYTES: u64 = 32 * 1024 * 1024;
pub const PROVIDER_PEAK_BUDGET_BYTES: u64 = QKV_BYTES
    + CONTEXT_BYTES
    + ONE_HEAD_SCORE_BYTES
    + LIMB_TILE_BYTES
    + PROVIDER_SCRATCH_BUDGET_BYTES;
pub const REPLAY_APPLICATION_PEAK_BUDGET_BYTES: u64 = 11_8 * 1024 * 1024 * 1024 / 10;
pub const REQUIRED_FREE_MARGIN_BYTES: u64 = 1536 * 1024 * 1024;

const _: () = assert!(QKV_WORDS == 25_165_824);
const _: () = assert!(HIDDEN_WORDS == 8_388_608);
const _: () = assert!(CONTEXT_WORDS == 8_388_608);
const _: () = assert!(GROUP_SCORE_ROWS == 1 << 24);
const _: () = assert!(SEQUENCE == 1 << MATRIX_AXIS_BITS);
const _: () = assert!(HEADS_PER_CIRCUIT == 1 << MATRIX_GROUP_BITS);
const _: () = assert!(SCORE_ROWS == 1 << 27);
const _: () = assert!(QKV_BYTES == 96 * 1024 * 1024);
const _: () = assert!(HIDDEN_BYTES == 32 * 1024 * 1024);
const _: () = assert!(CONTEXT_BYTES == 32 * 1024 * 1024);
const _: () = assert!(TOTAL_MULTIPLICATIONS == 34_359_738_368);

pub const QK_CIRCUIT_IDS: [&str; CIRCUITS] = [
    "TensorAttentionQKHeads00_03",
    "TensorAttentionQKHeads04_07",
    "TensorAttentionQKHeads08_11",
    "TensorAttentionQKHeads12_15",
    "TensorAttentionQKHeads16_19",
    "TensorAttentionQKHeads20_23",
    "TensorAttentionQKHeads24_27",
    "TensorAttentionQKHeads28_31",
];

pub const PV_CIRCUIT_IDS: [&str; CIRCUITS] = [
    "TensorAttentionPVHeads00_03",
    "TensorAttentionPVHeads04_07",
    "TensorAttentionPVHeads08_11",
    "TensorAttentionPVHeads12_15",
    "TensorAttentionPVHeads16_19",
    "TensorAttentionPVHeads20_23",
    "TensorAttentionPVHeads24_27",
    "TensorAttentionPVHeads28_31",
];

pub const PRODUCTION_PROFILE: u32 = ceno_rt::tensor::TENSOR_PROFILE_LLAMA2_7B_FULL_LAYER;
pub const WEIGHT_TILE_WORDS: usize = 1024;
const OPERATION_TENSOR_DOMAIN: u32 = 0xa500_0000;
const OPERATION_TENSOR_DOMAIN_MASK: u32 = 0xff00_0000;
const OPERATION_TENSOR_LAYER_SHIFT: u32 = 19;
const OPERATION_TENSOR_ROLE_SHIFT: u32 = 15;
const OPERATION_TENSOR_OUTPUT_MASK: u32 = (1 << OPERATION_TENSOR_ROLE_SHIFT) - 1;
const INTERNAL_PROJECTED_QKV_DOMAIN: u64 = 0xf17a_0000_0000_0000;
const INTERNAL_ATTENTION_OUTPUT_DOMAIN: u64 = 0xf17b_0000_0000_0000;

/// Assignment-local Tensor-space identities. These are deliberately outside
/// the guest handle domain: hidden import/export keep the guest identities,
/// while the attention middle binds only provider-produced intermediates.
pub fn production_internal_tensor_id(
    import_cycle: u64,
    layer: u32,
    input_tensor_id: u64,
    attention_output: bool,
) -> Result<u64> {
    ensure!(
        layer < 32,
        "production internal tensor layer outside Llama-2-7B"
    );
    let domain = if attention_output {
        INTERNAL_ATTENTION_OUTPUT_DOMAIN
    } else {
        INTERNAL_PROJECTED_QKV_DOMAIN
    };
    let payload = input_tensor_id ^ import_cycle.rotate_left(17) ^ (u64::from(layer) << 43);
    Ok(domain | (payload & 0x0000_ffff_ffff_ffff))
}

/// Compact identity for one provider-owned full-layer operation family.
/// `token_count` and `output_column_count` expand a rectangular row range;
/// dense records use one output column and one K1024 position.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProductionFullLayerOperationRecord {
    pub import_cycle: u64,
    pub layer: u32,
    pub role: TensorRole,
    pub token: u32,
    pub token_count: u32,
    pub output_column: u32,
    pub output_column_count: u32,
    pub tile: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProductionFullLayerOperationKind {
    Rms,
    DenseK4096,
    DenseK11008,
    Rope,
    Residual,
    SwiGlu,
}

impl ProductionFullLayerOperationRecord {
    pub fn validate(self) -> Result<ProductionFullLayerOperationKind> {
        ensure!(
            self.layer < 32,
            "production operation layer outside Llama-2-7B"
        );
        ensure!(
            self.token == 0 && self.token_count == SEQUENCE as u32,
            "production operation token range changed"
        );
        let full_columns = u32::try_from(match self.role {
            TensorRole::FfnGate | TensorRole::FfnUp => LLAMA2_7B_INTERMEDIATE,
            _ => HIDDEN,
        })?;
        if matches!(
            self.role,
            TensorRole::InputNorm | TensorRole::PostAttentionNorm
        ) {
            ensure!(
                self.output_column == self.tile * WEIGHT_TILE_WORDS as u32
                    && self.output_column_count == WEIGHT_TILE_WORDS as u32
                    && self.tile < 4,
                "production RMS record identity changed"
            );
            return Ok(ProductionFullLayerOperationKind::Rms);
        }
        if self.output_column_count == 1 {
            let (k, columns) = role_weight_shape(self.role)?;
            ensure!(
                usize::try_from(self.output_column)? < columns,
                "production dense output column outside role"
            );
            let tiles = k.div_ceil(WEIGHT_TILE_WORDS);
            ensure!(
                usize::try_from(self.tile)? < tiles,
                "production dense tile outside output column"
            );
            let logical_tile = self
                .output_column
                .checked_mul(u32::try_from(tiles)?)
                .and_then(|base| base.checked_add(self.tile))
                .ok_or_else(|| anyhow::anyhow!("production dense HintRef overflow"))?;
            ProductionHintRef::new(self.layer, self.role, logical_tile)?;
            return Ok(if k == HIDDEN {
                ProductionFullLayerOperationKind::DenseK4096
            } else {
                ProductionFullLayerOperationKind::DenseK11008
            });
        }
        ensure!(
            self.output_column == 0 && self.output_column_count == full_columns && self.tile == 0,
            "production pointwise operation range changed"
        );
        Ok(match self.role {
            TensorRole::Query | TensorRole::Key => ProductionFullLayerOperationKind::Rope,
            TensorRole::AttentionOutput | TensorRole::FfnDown => {
                ProductionFullLayerOperationKind::Residual
            }
            TensorRole::FfnGate => ProductionFullLayerOperationKind::SwiGlu,
            _ => anyhow::bail!("unsupported production pointwise operation role"),
        })
    }
}

pub fn validate_full_layer_operation_records(
    records: &[ProductionFullLayerOperationRecord],
) -> Result<()> {
    let mut cursor = 0usize;
    fn expect_record(
        records: &[ProductionFullLayerOperationRecord],
        cursor: &mut usize,
        expected: ProductionFullLayerOperationRecord,
    ) -> Result<()> {
        let actual = records
            .get(*cursor)
            .ok_or_else(|| anyhow::anyhow!("production operation inventory ended early"))?;
        ensure!(
            *actual == expected,
            "production operation identity/order changed at record {}",
            *cursor
        );
        actual.validate()?;
        *cursor += 1;
        Ok(())
    }
    let rms = |role, tile| ProductionFullLayerOperationRecord {
        import_cycle: 0,
        layer: 0,
        role,
        token: 0,
        token_count: SEQUENCE as u32,
        output_column: tile * WEIGHT_TILE_WORDS as u32,
        output_column_count: WEIGHT_TILE_WORDS as u32,
        tile,
    };
    let pointwise = |role, columns| ProductionFullLayerOperationRecord {
        import_cycle: 0,
        layer: 0,
        role,
        token: 0,
        token_count: SEQUENCE as u32,
        output_column: 0,
        output_column_count: columns,
        tile: 0,
    };
    fn expect_dense(
        records: &[ProductionFullLayerOperationRecord],
        cursor: &mut usize,
        role: TensorRole,
        k: usize,
        columns: usize,
    ) -> Result<()> {
        let tiles = k.div_ceil(WEIGHT_TILE_WORDS);
        for output_column in 0..columns {
            for tile in 0..tiles {
                expect_record(
                    records,
                    cursor,
                    ProductionFullLayerOperationRecord {
                        import_cycle: 0,
                        layer: 0,
                        role,
                        token: 0,
                        token_count: SEQUENCE as u32,
                        output_column: u32::try_from(output_column)?,
                        output_column_count: 1,
                        tile: u32::try_from(tile)?,
                    },
                )?;
            }
        }
        Ok(())
    }
    for tile in 0..4 {
        expect_record(records, &mut cursor, rms(TensorRole::InputNorm, tile))?;
    }
    expect_dense(records, &mut cursor, TensorRole::Query, HIDDEN, HIDDEN)?;
    expect_record(
        records,
        &mut cursor,
        pointwise(TensorRole::Query, HIDDEN as u32),
    )?;
    expect_dense(records, &mut cursor, TensorRole::Key, HIDDEN, HIDDEN)?;
    expect_record(
        records,
        &mut cursor,
        pointwise(TensorRole::Key, HIDDEN as u32),
    )?;
    expect_dense(records, &mut cursor, TensorRole::Value, HIDDEN, HIDDEN)?;
    expect_dense(
        records,
        &mut cursor,
        TensorRole::AttentionOutput,
        HIDDEN,
        HIDDEN,
    )?;
    expect_record(
        records,
        &mut cursor,
        pointwise(TensorRole::AttentionOutput, HIDDEN as u32),
    )?;
    for tile in 0..4 {
        expect_record(
            records,
            &mut cursor,
            rms(TensorRole::PostAttentionNorm, tile),
        )?;
    }
    expect_dense(
        records,
        &mut cursor,
        TensorRole::FfnGate,
        HIDDEN,
        LLAMA2_7B_INTERMEDIATE,
    )?;
    expect_dense(
        records,
        &mut cursor,
        TensorRole::FfnUp,
        HIDDEN,
        LLAMA2_7B_INTERMEDIATE,
    )?;
    expect_record(
        records,
        &mut cursor,
        pointwise(TensorRole::FfnGate, LLAMA2_7B_INTERMEDIATE as u32),
    )?;
    expect_dense(
        records,
        &mut cursor,
        TensorRole::FfnDown,
        LLAMA2_7B_INTERMEDIATE,
        HIDDEN,
    )?;
    expect_record(
        records,
        &mut cursor,
        pointwise(TensorRole::FfnDown, HIDDEN as u32),
    )?;
    ensure!(
        cursor == records.len(),
        "production operation inventory has trailing records"
    );
    Ok(())
}

/// Lazy identity for one deterministic private production-weight tile.
///
/// This is deliberately a logical identity only: guest addresses and eager
/// weight storage are not part of the full-layer contract.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProductionHintRef {
    pub profile: u32,
    pub layer: u32,
    pub role: TensorRole,
    pub tile: u32,
}

impl ProductionHintRef {
    pub fn new(layer: u32, role: TensorRole, tile: u32) -> Result<Self> {
        let hint = Self {
            profile: PRODUCTION_PROFILE,
            layer,
            role,
            tile,
        };
        hint.validate()?;
        Ok(hint)
    }

    pub fn validate(self) -> Result<()> {
        ensure!(
            self.profile == PRODUCTION_PROFILE,
            "unsupported production profile"
        );
        ensure!(self.layer < 32, "production layer outside Llama-2-7B");
        let (k, output_columns) = role_weight_shape(self.role)?;
        let tiles = if output_columns == HIDDEN && k == 1 {
            output_columns.div_ceil(WEIGHT_TILE_WORDS)
        } else {
            output_columns
                .checked_mul(k.div_ceil(WEIGHT_TILE_WORDS))
                .ok_or_else(|| anyhow::anyhow!("production HintRef tile count overflow"))?
        };
        ensure!(
            usize::try_from(self.tile)? < tiles,
            "production HintRef tile outside role tensor"
        );
        Ok(())
    }
}

pub fn role_weight_shape(role: TensorRole) -> Result<(usize, usize)> {
    Ok(match role {
        TensorRole::InputNorm | TensorRole::PostAttentionNorm => (1, HIDDEN),
        TensorRole::Query | TensorRole::Key | TensorRole::Value | TensorRole::AttentionOutput => {
            (HIDDEN, HIDDEN)
        }
        TensorRole::FfnGate | TensorRole::FfnUp => (HIDDEN, LLAMA2_7B_INTERMEDIATE),
        TensorRole::FfnDown => (LLAMA2_7B_INTERMEDIATE, HIDDEN),
        _ => anyhow::bail!("role is not part of a production transformer layer"),
    })
}

pub fn role_weight_words(role: TensorRole) -> Result<usize> {
    let (rows, columns) = role_weight_shape(role)?;
    rows.checked_mul(columns)
        .ok_or_else(|| anyhow::anyhow!("production role shape overflow"))
}

/// Deterministic hidden activation used by both the real guest and the
/// independent full-tensor integer oracle.
pub fn hidden_value(token: usize, column: usize) -> Result<i32> {
    ensure!(token < SEQUENCE, "hidden token outside production shape");
    ensure!(column < HIDDEN, "hidden column outside production shape");
    Ok(i32::try_from((token * 29 + column * 17 + 11) % 31)? - 15)
}

/// Generate a requested weight word directly from its logical HintRef.
/// Tiles are never retained as an eager dense model allocation.
pub fn hint_value(hint: ProductionHintRef, word_in_tile: usize) -> Result<i32> {
    hint.validate()?;
    ensure!(
        word_in_tile < WEIGHT_TILE_WORDS,
        "production HintRef word outside tile"
    );
    let (k, output_columns) = role_weight_shape(hint.role)?;
    let tile = usize::try_from(hint.tile)?;
    let logical_word = if k == 1 {
        tile.checked_mul(WEIGHT_TILE_WORDS)
            .and_then(|start| start.checked_add(word_in_tile))
    } else {
        let tiles_per_column = k.div_ceil(WEIGHT_TILE_WORDS);
        let output_column = tile / tiles_per_column;
        let position = tile % tiles_per_column;
        ensure!(
            output_column < output_columns,
            "production HintRef output column outside role"
        );
        ensure!(
            position * WEIGHT_TILE_WORDS + word_in_tile < k,
            "production HintRef word is deterministic tile padding"
        );
        output_column
            .checked_mul(k)
            .and_then(|start| start.checked_add(position * WEIGHT_TILE_WORDS + word_in_tile))
    }
    .ok_or_else(|| anyhow::anyhow!("production HintRef word overflow"))?;
    ensure!(
        logical_word < role_weight_words(hint.role)?,
        "production HintRef word outside role tensor"
    );
    let role = hint.role as u32 as usize;
    Ok(
        i32::try_from(
            (usize::try_from(hint.layer)? * 43 + role * 37 + logical_word * 13 + 5) % 17,
        )? - 8,
    )
}

pub fn generate_hint_tile(hint: ProductionHintRef) -> Result<Vec<i32>> {
    hint.validate()?;
    let (k, _) = role_weight_shape(hint.role)?;
    let len = if k == 1 {
        (role_weight_words(hint.role)? - usize::try_from(hint.tile)? * WEIGHT_TILE_WORDS)
            .min(WEIGHT_TILE_WORDS)
    } else {
        let position = usize::try_from(hint.tile)? % k.div_ceil(WEIGHT_TILE_WORDS);
        (k - position * WEIGHT_TILE_WORDS).min(WEIGHT_TILE_WORDS)
    };
    (0..len).map(|word| hint_value(hint, word)).collect()
}

/// Provider adapter for proof assignment of one output-column-major dense
/// operation. It decodes the full lazy identity from `tensor_id`; no weight
/// words are retained between openings.
#[derive(Debug, Default)]
pub struct ProductionLazyHintProvider {
    reads: AtomicU64,
    bytes: AtomicU64,
}

pub fn production_operation_tensor_id(
    layer: u32,
    role: TensorRole,
    output_column: u32,
) -> Result<u32> {
    ensure!(layer < 32, "production operation layer outside Llama-2-7B");
    let (_, columns) = role_weight_shape(role)?;
    ensure!(
        usize::try_from(output_column)? < columns,
        "production operation output column outside role"
    );
    ensure!(
        output_column <= OPERATION_TENSOR_OUTPUT_MASK,
        "production operation output column does not fit identity"
    );
    Ok(OPERATION_TENSOR_DOMAIN
        | (layer << OPERATION_TENSOR_LAYER_SHIFT)
        | ((role as u32) << OPERATION_TENSOR_ROLE_SHIFT)
        | output_column)
}

fn decode_operation_tensor_id(tensor_id: u32) -> Result<(u32, TensorRole, u32)> {
    ensure!(
        tensor_id & OPERATION_TENSOR_DOMAIN_MASK == OPERATION_TENSOR_DOMAIN,
        "unknown production operation tensor"
    );
    let layer = (tensor_id >> OPERATION_TENSOR_LAYER_SHIFT) & 0x1f;
    let role_id = (tensor_id >> OPERATION_TENSOR_ROLE_SHIFT) & 0xf;
    let role = match role_id {
        2 => TensorRole::InputNorm,
        3 => TensorRole::Query,
        4 => TensorRole::Key,
        5 => TensorRole::Value,
        6 => TensorRole::AttentionOutput,
        7 => TensorRole::PostAttentionNorm,
        8 => TensorRole::FfnGate,
        9 => TensorRole::FfnUp,
        10 => TensorRole::FfnDown,
        _ => anyhow::bail!("unknown production operation role"),
    };
    let output_column = tensor_id & OPERATION_TENSOR_OUTPUT_MASK;
    ensure!(
        production_operation_tensor_id(layer, role, output_column)? == tensor_id,
        "noncanonical production operation tensor identity"
    );
    Ok((layer, role, output_column))
}

impl TensorWitnessProvider for ProductionLazyHintProvider {
    fn metadata(&self, tensor_id: u32) -> Result<TensorMeta> {
        let (_, role, _) = decode_operation_tensor_id(tensor_id)?;
        let (k, _) = role_weight_shape(role)?;
        let tile_count = u32::try_from(k.div_ceil(WEIGHT_TILE_WORDS))?;
        Ok(TensorMeta {
            tensor_id,
            byte_len: k.checked_mul(size_of::<i32>()).ok_or_else(|| {
                anyhow::anyhow!("production operation tensor byte length overflow")
            })?,
            tile_count,
        })
    }

    fn read_tile(&self, tensor_id: u32, tile_id: u32) -> Result<TileOpening> {
        let (layer, role, output_column) = decode_operation_tensor_id(tensor_id)?;
        let metadata = self.metadata(tensor_id)?;
        ensure!(
            tile_id < metadata.tile_count,
            "production operation tile outside output column"
        );
        let logical_tile = output_column
            .checked_mul(metadata.tile_count)
            .and_then(|base| base.checked_add(tile_id))
            .ok_or_else(|| anyhow::anyhow!("production operation HintRef overflow"))?;
        let words = generate_hint_tile(ProductionHintRef::new(layer, role, logical_tile)?)?;
        let bytes = words
            .iter()
            .flat_map(|word| word.to_le_bytes())
            .collect::<Vec<_>>();
        let root = commit_tile(tensor_id, tile_id, &bytes);
        self.reads.fetch_add(1, Ordering::Relaxed);
        self.bytes
            .fetch_add(u64::try_from(bytes.len())?, Ordering::Relaxed);
        Ok(TileOpening {
            tensor_id,
            tile_id,
            bytes,
            root,
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

pub const SOFTMAX_CIRCUIT_IDS: [&str; CIRCUITS] = [
    "TensorAttentionSoftmaxHeads00_03",
    "TensorAttentionSoftmaxHeads04_07",
    "TensorAttentionSoftmaxHeads08_11",
    "TensorAttentionSoftmaxHeads12_15",
    "TensorAttentionSoftmaxHeads16_19",
    "TensorAttentionSoftmaxHeads20_23",
    "TensorAttentionSoftmaxHeads24_27",
    "TensorAttentionSoftmaxHeads28_31",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PackedQkv {
    Query,
    Key,
    Value,
}

/// Shared 24-variable matrix layout used by every four-head production
/// artifact.  The first 11 variables are the logical column/inner axis, the
/// next 11 are the output-row axis, and the final two select the head.  QK
/// pads its 128-wide inner axis to 2048; PV pads its 128-wide output axis to
/// 2048.  This is padding in the committed MLE, not skipped computation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AttentionMatrixKind {
    Qk,
    Pv,
}

impl AttentionMatrixKind {
    pub const fn shift(self) -> u32 {
        match self {
            Self::Qk => 16,
            Self::Pv => Q20_SHIFT,
        }
    }

    pub const fn circuit_ids(self) -> &'static [&'static str; CIRCUITS] {
        match self {
            Self::Qk => &QK_CIRCUIT_IDS,
            Self::Pv => &PV_CIRCUIT_IDS,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AttentionMatrixCoordinate {
    pub head_in_group: usize,
    pub row: usize,
    pub axis: usize,
}

impl AttentionMatrixCoordinate {
    pub fn from_physical_row(physical_row: usize) -> Result<Self> {
        ensure!(
            physical_row < GROUP_SCORE_ROWS,
            "production matrix row outside four-head artifact"
        );
        let axis = physical_row & (SEQUENCE - 1);
        let row = (physical_row >> MATRIX_AXIS_BITS) & (SEQUENCE - 1);
        let head_in_group = physical_row >> (2 * MATRIX_AXIS_BITS);
        Ok(Self {
            head_in_group,
            row,
            axis,
        })
    }

    pub const fn output_active(self, kind: AttentionMatrixKind) -> bool {
        match kind {
            AttentionMatrixKind::Qk => true,
            AttentionMatrixKind::Pv => self.axis < HEAD_DIM,
        }
    }

    pub const fn a_active(self, kind: AttentionMatrixKind) -> bool {
        match kind {
            AttentionMatrixKind::Qk => self.axis < HEAD_DIM,
            AttentionMatrixKind::Pv => true,
        }
    }

    pub const fn w_active(self, kind: AttentionMatrixKind) -> bool {
        match kind {
            AttentionMatrixKind::Qk => self.row < HEAD_DIM,
            AttentionMatrixKind::Pv => self.axis < HEAD_DIM,
        }
    }

    pub const fn global_head(self, circuit: usize) -> usize {
        circuit * HEADS_PER_CIRCUIT + self.head_in_group
    }
}

impl PackedQkv {
    pub const fn offset(self) -> usize {
        match self {
            Self::Query => 0,
            Self::Key => CONTEXT_WORDS,
            Self::Value => 2 * CONTEXT_WORDS,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AttentionCoordinate {
    pub head: usize,
    pub query: usize,
    pub key: usize,
}

impl AttentionCoordinate {
    pub fn validate(self) -> Result<()> {
        ensure!(self.head < HEADS, "attention head outside production shape");
        ensure!(
            self.query < SEQUENCE,
            "attention query outside production shape"
        );
        ensure!(
            self.key < SEQUENCE,
            "attention key outside production shape"
        );
        Ok(())
    }

    pub fn row(self) -> Result<usize> {
        self.validate()?;
        Ok((self.head * SEQUENCE + self.query) * SEQUENCE + self.key)
    }
}

/// Canonical packed `[Q,K,V][head,token,dim]` index.
pub fn qkv_index(kind: PackedQkv, head: usize, token: usize, dim: usize) -> Result<usize> {
    ensure!(head < HEADS, "QKV head outside production shape");
    ensure!(token < SEQUENCE, "QKV token outside production shape");
    ensure!(dim < HEAD_DIM, "QKV dimension outside production shape");
    Ok(kind.offset() + (head * SEQUENCE + token) * HEAD_DIM + dim)
}

pub fn context_index(head: usize, token: usize, dim: usize) -> Result<usize> {
    qkv_index(PackedQkv::Query, head, token, dim)
}

/// Replayable unauthenticated private fixture. Q and K are signed bytes. V is
/// Q20 so the published double-Q20 PV rescale has a nontrivial integer result.
pub fn fixture_value(kind: PackedQkv, head: usize, token: usize, dim: usize) -> Result<i32> {
    let index = qkv_index(kind, head, token, dim)? - kind.offset();
    let signed = i32::try_from(index % 17)? - 8;
    Ok(match kind {
        PackedQkv::Query => signed,
        PackedQkv::Key => {
            let permuted = (head * 13 + token * 7 + dim * 3) % 17;
            i32::try_from(permuted)? - 8
        }
        PackedQkv::Value => {
            let signed = i32::try_from((head * 11 + dim * 5) % 17)? - 8;
            signed * i32::try_from(Q20_SCALE)?
        }
    })
}

const ATTENTION_SOFTMAX_SCALE: f64 = 4_294_967_296.0 * 11.313_708_498_984_761;

pub fn score_at(coord: AttentionCoordinate) -> Result<i64> {
    coord.validate()?;
    (0..HEAD_DIM).try_fold(0_i64, |sum, dim| {
        let q = fixture_value(PackedQkv::Query, coord.head, coord.query, dim)?;
        let k = fixture_value(PackedQkv::Key, coord.head, coord.key, dim)?;
        sum.checked_add(i64::from(q) * i64::from(k))
            .ok_or_else(|| anyhow::anyhow!("production attention score overflow"))
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SoftmaxCell {
    pub score: i64,
    pub shift: i64,
    pub magnitude: u128,
    pub limbs: [u16; SOFTMAX_LIMBS],
    pub exp3: i64,
    pub exp4: i64,
    pub causal: bool,
    pub probability_q20: i64,
}

fn attention_shift(head: usize, query: usize) -> Result<i64> {
    let mut sum = 0.0;
    for key in 0..=query {
        sum += (score_at(AttentionCoordinate { head, query, key })? as f64
            / ATTENTION_SOFTMAX_SCALE)
            .exp();
    }
    Ok((ATTENTION_SOFTMAX_SCALE * sum.ln() + 0.5) as i64)
}

fn exp3(index: u32) -> i64 {
    (((262_144.0_f64).ln() - f64::from(index) * 256.0 / ATTENTION_SOFTMAX_SCALE).exp() + 0.5) as i64
}

fn exp4(index: u32) -> i64 {
    (((4_194_304.0_f64).ln() - f64::from(index) * 268_435_456.0 / ATTENTION_SOFTMAX_SCALE).exp()
        + 0.5) as i64
}

pub fn softmax_cell(coord: AttentionCoordinate) -> Result<SoftmaxCell> {
    let score = score_at(coord)?;
    let shift = attention_shift(coord.head, coord.query)?;
    ensure!(score <= shift, "attention shift is not an upper bound");
    let magnitude = u128::try_from(shift - score)?;
    let digit0 = u32::try_from(magnitude & 0xff)?;
    let digit1 = u32::try_from((magnitude >> 8) & 0xfffff)?;
    let digit2 = u32::try_from((magnitude >> 28) & 0xfffff)?;
    let limbs = [
        u16::try_from(digit0)?,
        u16::try_from(digit1 & 0xffff)?,
        u16::try_from(digit2 & 0xffff)?,
        u16::try_from(digit1 >> 16)?,
        u16::try_from(digit2 >> 16)?,
    ];
    ensure!(
        magnitude >> 80 == 0,
        "attention magnitude exceeds five limbs"
    );
    let exp3 = exp3(digit1);
    let exp4 = exp4(digit2);
    let causal = coord.key <= coord.query;
    let probability_q20 = if causal {
        exp3.checked_mul(exp4)
            .ok_or_else(|| anyhow::anyhow!("attention exponent product overflow"))?
    } else {
        0
    };
    Ok(SoftmaxCell {
        score,
        shift,
        magnitude,
        limbs,
        exp3,
        exp4,
        causal,
        probability_q20,
    })
}

pub fn centered_rescale(value: i128, shift: u32) -> Result<(i64, u64)> {
    let scale = 1_i128 << shift;
    let quotient = (value + (scale >> 1)).div_euclid(scale);
    let remainder = value - quotient * scale;
    ensure!(
        remainder >= -(scale >> 1) && remainder < scale >> 1,
        "noncanonical remainder"
    );
    Ok((
        i64::try_from(quotient)?,
        u64::try_from(remainder + (scale >> 1))?,
    ))
}

/// Independent coordinate oracle for exact causal PV with the two Q20
/// rescales used by zkLLM. This intentionally performs all `sequence` terms
/// when called, but campaign iteration never executes it on CPU.
pub fn context_at(head: usize, query: usize, dim: usize) -> Result<i32> {
    let _ = context_index(head, query, dim)?;
    let mut accumulator = 0_i128;
    for key in 0..SEQUENCE {
        let probability =
            i128::from(softmax_cell(AttentionCoordinate { head, query, key })?.probability_q20);
        let value = i128::from(fixture_value(PackedQkv::Value, head, key, dim)?);
        accumulator = accumulator
            .checked_add(probability * value)
            .ok_or_else(|| anyhow::anyhow!("production attention PV overflow"))?;
    }
    let (once, _) = centered_rescale(accumulator, Q20_SHIFT)?;
    let (twice, _) = centered_rescale(i128::from(once), Q20_SHIFT)?;
    Ok(i32::try_from(twice)?)
}

/// Closed form for the deterministic fixture. The CUDA kernel still evaluates
/// all 2048 PV terms; this exists only so emulator boundary bookkeeping and
/// independent verification need not run a second 17-billion-term CPU matmul.
pub fn fixture_context_value(head: usize, query: usize, dim: usize) -> Result<i32> {
    let _ = context_index(head, query, dim)?;
    let value_q20 = fixture_value(PackedQkv::Value, head, 0, dim)?;
    let value = value_q20.div_euclid(i32::try_from(Q20_SCALE)?);
    value
        .checked_mul(i32::try_from(query + 1)?)
        .ok_or_else(|| anyhow::anyhow!("production fixture context overflow"))
}

pub fn validate_device_capacity(total_bytes: u64, _free_bytes: u64) -> Result<()> {
    ensure!(
        total_bytes >= REPLAY_APPLICATION_PEAK_BUDGET_BYTES + REQUIRED_FREE_MARGIN_BYTES,
        "16-GiB production attention device is too small"
    );
    Ok(())
}
