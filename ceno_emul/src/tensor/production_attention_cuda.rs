//! Device-resident exact S2048/H4096 production-layer provider.
//!
//! One hidden upload and one hidden download are the only activation transfers.
//! Layer stages remain resident while private K1024 weight tiles reuse one
//! staging allocation. Heads and 128-query tiles stream through reusable
//! score, probability, and five-limb scratch.

use std::sync::Arc;

use anyhow::{Result, ensure};
use cudarc::{
    driver::{
        CudaContext, CudaFunction, CudaSlice, CudaStream, LaunchConfig, PushKernelArg, result,
    },
    nvrtc::compile_ptx,
};

use super::{
    llama::LLAMA2_7B_INTERMEDIATE,
    production::TensorRole,
    production_attention::{
        self, HIDDEN_WORDS, ProductionFullLayerOperationRecord, ProductionHintRef, ProductionStage,
        REQUIRED_FREE_MARGIN_BYTES, SEQUENCE, WEIGHT_TILE_WORDS,
    },
};

pub const QUERY_TILE: usize = 128;
const TILE_CELLS: usize = QUERY_TILE * SEQUENCE;
const DENSE_PANEL_COLUMNS: usize = 128;
const DENSE_PANEL_WORDS: usize = DENSE_PANEL_COLUMNS * WEIGHT_TILE_WORDS;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ProductionFullLayerCudaMetrics {
    pub setup_h2d_bytes: u64,
    pub activation_h2d_bytes: u64,
    pub activation_d2h_bytes: u64,
    pub intermediate_h2d_bytes: u64,
    pub intermediate_d2h_bytes: u64,
    pub qk_launches: u32,
    pub softmax_launches: u32,
    pub pv_launches: u32,
    pub rms_launches: u32,
    pub projection_tile_launches: u32,
    pub rope_launches: u32,
    pub residual_launches: u32,
    pub swiglu_launches: u32,
    pub allocated_bytes: u64,
    pub high_water_bytes: u64,
    pub minimum_free_bytes: u64,
}

pub struct ProductionFullLayerDeviceWitness {
    pub(crate) hidden: CudaSlice<i32>,
    pub(crate) input_norm: CudaSlice<i32>,
    pub(crate) rope_projection: CudaSlice<i32>,
    pub(crate) query: CudaSlice<i32>,
    pub(crate) key: CudaSlice<i32>,
    pub(crate) value: CudaSlice<i32>,
    pub(crate) context: CudaSlice<i32>,
    pub(crate) attention_projection: CudaSlice<i32>,
    pub(crate) attention_residual: CudaSlice<i32>,
    pub(crate) post_norm: CudaSlice<i32>,
    pub(crate) gate: CudaSlice<i32>,
    pub(crate) up: CudaSlice<i32>,
    pub(crate) swiglu: CudaSlice<i32>,
    pub(crate) down: CudaSlice<i32>,
    pub(crate) output: CudaSlice<i32>,
    pub(crate) hint_tile: CudaSlice<i32>,
    pub(crate) dense_hint_panel: CudaSlice<i32>,
    pub(crate) dense_accumulator: CudaSlice<i64>,
    pub(crate) scores: CudaSlice<i64>,
    pub(crate) shifts: CudaSlice<i64>,
    pub(crate) probabilities: CudaSlice<i64>,
    pub(crate) limbs: CudaSlice<u32>,
    metrics: ProductionFullLayerCudaMetrics,
    operation_records: Vec<ProductionFullLayerOperationRecord>,
    stage: ProductionStage,
    head_start: u32,
    head_count: u32,
}

pub type ProductionStageDeviceWitness = ProductionFullLayerDeviceWitness;

impl ProductionFullLayerDeviceWitness {
    pub fn metrics(&self) -> ProductionFullLayerCudaMetrics {
        self.metrics
    }

    pub fn operation_records(&self) -> &[ProductionFullLayerOperationRecord] {
        &self.operation_records
    }
}

pub struct ProductionFullLayerCudaProvider {
    stream: Arc<CudaStream>,
    qk: CudaFunction,
    softmax: CudaFunction,
    shift: CudaFunction,
    pv: CudaFunction,
    rms: CudaFunction,
    dense_tile: CudaFunction,
    rope: CudaFunction,
    residual: CudaFunction,
    swiglu: CudaFunction,
    setup_h2d_bytes: u64,
}

impl ProductionFullLayerCudaProvider {
    pub fn new(device: usize) -> Result<Self> {
        let context = CudaContext::new(device)?;
        let (free, total) = result::mem_get_info()?;
        production_attention::validate_device_capacity(total as u64, free as u64)?;
        let module = context.load_module(compile_ptx(CUDA_SOURCE)?)?;
        let stream = context.default_stream();
        Ok(Self {
            qk: module.load_function("production_attention_qk")?,
            shift: module.load_function("production_attention_shift")?,
            softmax: module.load_function("production_attention_softmax")?,
            pv: module.load_function("production_attention_pv")?,
            rms: module.load_function("production_full_layer_rms")?,
            dense_tile: module.load_function("production_full_layer_dense_tile")?,
            rope: module.load_function("production_full_layer_rope")?,
            residual: module.load_function("production_full_layer_residual")?,
            swiglu: module.load_function("production_full_layer_swiglu")?,
            stream,
            setup_h2d_bytes: 0,
        })
    }

    fn import_hidden_full(
        &self,
        hidden: &[i32],
        stage: ProductionStage,
        head_count: u32,
    ) -> Result<ProductionFullLayerDeviceWitness> {
        ensure!(
            hidden.len() == HIDDEN_WORDS,
            "production hidden shape mismatch"
        );
        let (_, total) = result::mem_get_info()?;
        let hidden = if stage == ProductionStage::Attention {
            self.stream.alloc_zeros::<i32>(1)?
        } else {
            self.stream.memcpy_stod(hidden)?
        };
        let active = |for_stage| for_stage == stage;
        let alloc_i32 = |len: usize, enabled: bool| {
            self.stream
                .alloc_zeros::<i32>(if enabled { len } else { 1 })
        };
        let group_words = usize::try_from(head_count)? * SEQUENCE * production_attention::HEAD_DIM;
        let fused_attention =
            active(ProductionStage::Projection) || active(ProductionStage::Attention);
        let input_norm = alloc_i32(
            HIDDEN_WORDS,
            active(ProductionStage::Projection) || active(ProductionStage::PostFfn),
        )?;
        let rope_projection = alloc_i32(group_words, active(ProductionStage::Projection))?;
        let query = alloc_i32(group_words, fused_attention)?;
        let key = alloc_i32(group_words, fused_attention)?;
        let value = alloc_i32(group_words, fused_attention)?;
        let context = if fused_attention {
            alloc_i32(group_words, true)?
        } else {
            alloc_i32(HIDDEN_WORDS, active(ProductionStage::PostFfn))?
        };
        let attention_projection = alloc_i32(HIDDEN_WORDS, active(ProductionStage::PostFfn))?;
        let attention_residual = alloc_i32(HIDDEN_WORDS, active(ProductionStage::PostFfn))?;
        let post_norm = alloc_i32(HIDDEN_WORDS, active(ProductionStage::PostFfn))?;
        let gate = alloc_i32(
            SEQUENCE * LLAMA2_7B_INTERMEDIATE,
            active(ProductionStage::PostFfn),
        )?;
        let up = alloc_i32(
            SEQUENCE * LLAMA2_7B_INTERMEDIATE,
            active(ProductionStage::PostFfn),
        )?;
        let swiglu = alloc_i32(
            SEQUENCE * LLAMA2_7B_INTERMEDIATE,
            active(ProductionStage::PostFfn),
        )?;
        let down = alloc_i32(HIDDEN_WORDS, active(ProductionStage::PostFfn))?;
        let output = alloc_i32(HIDDEN_WORDS, active(ProductionStage::PostFfn))?;
        let hint_tile = self.stream.alloc_zeros::<i32>(WEIGHT_TILE_WORDS)?;
        let dense_hint_panel = self.stream.alloc_zeros::<i32>(DENSE_PANEL_WORDS)?;
        let dense_accumulator_words = if active(ProductionStage::Projection) {
            group_words
        } else if active(ProductionStage::PostFfn) {
            SEQUENCE * LLAMA2_7B_INTERMEDIATE
        } else {
            1
        };
        let dense_accumulator = self.stream.alloc_zeros::<i64>(dense_accumulator_words)?;
        let scores =
            self.stream
                .alloc_zeros::<i64>(if fused_attention { TILE_CELLS } else { 1 })?;
        let shifts =
            self.stream
                .alloc_zeros::<i64>(if fused_attention { QUERY_TILE } else { 1 })?;
        let probabilities =
            self.stream
                .alloc_zeros::<i64>(if fused_attention { TILE_CELLS } else { 1 })?;
        let limbs = self.stream.alloc_zeros::<u32>(if fused_attention {
            production_attention::SOFTMAX_LIMBS * TILE_CELLS
        } else {
            1
        })?;
        let allocated_bytes = (hidden.len() * size_of::<i32>()
            + input_norm.len() * size_of::<i32>()
            + rope_projection.len() * size_of::<i32>()
            + query.len() * size_of::<i32>()
            + key.len() * size_of::<i32>()
            + value.len() * size_of::<i32>()
            + context.len() * size_of::<i32>()
            + attention_projection.len() * size_of::<i32>()
            + attention_residual.len() * size_of::<i32>()
            + post_norm.len() * size_of::<i32>()
            + gate.len() * size_of::<i32>()
            + up.len() * size_of::<i32>()
            + swiglu.len() * size_of::<i32>()
            + down.len() * size_of::<i32>()
            + output.len() * size_of::<i32>()
            + hint_tile.len() * size_of::<i32>()
            + dense_hint_panel.len() * size_of::<i32>()
            + dense_accumulator.len() * size_of::<i64>()
            + scores.len() * size_of::<i64>()
            + shifts.len() * size_of::<i64>()
            + probabilities.len() * size_of::<i64>()
            + limbs.len() * size_of::<u32>()) as u64;
        let (free, _) = result::mem_get_info()?;
        ensure!(
            free as u64 >= REQUIRED_FREE_MARGIN_BYTES,
            "production attention import breached the 1.5-GiB VRAM margin"
        );
        Ok(ProductionFullLayerDeviceWitness {
            hidden,
            input_norm,
            rope_projection,
            query,
            key,
            value,
            context,
            attention_projection,
            attention_residual,
            post_norm,
            gate,
            up,
            swiglu,
            down,
            output,
            hint_tile,
            dense_hint_panel,
            dense_accumulator,
            scores,
            shifts,
            probabilities,
            limbs,
            metrics: ProductionFullLayerCudaMetrics {
                setup_h2d_bytes: self.setup_h2d_bytes,
                activation_h2d_bytes: production_attention::HIDDEN_BYTES,
                allocated_bytes,
                high_water_bytes: total as u64 - free as u64,
                minimum_free_bytes: free as u64,
                ..Default::default()
            },
            operation_records: Vec::new(),
            stage: ProductionStage::Projection,
            head_start: 0,
            head_count,
        })
    }

    pub fn import_stage(
        &self,
        stage: ProductionStage,
        head_start: u32,
        head_count: u32,
        input: &[i32],
    ) -> Result<ProductionStageDeviceWitness> {
        stage.validate_range(head_start, head_count)?;
        ensure!(
            input.len() == stage.input_words(head_count)?,
            "production stage input shape changed"
        );
        let zero_hidden = vec![0; HIDDEN_WORDS];
        let hidden = match stage {
            ProductionStage::Projection => input,
            ProductionStage::Attention => &zero_hidden,
            ProductionStage::PostFfn => &input[..HIDDEN_WORDS],
        };
        let mut witness = self.import_hidden_full(hidden, stage, head_count)?;
        witness.stage = stage;
        witness.head_start = head_start;
        witness.head_count = head_count;
        match stage {
            ProductionStage::Projection => {}
            ProductionStage::Attention => {
                let group_words = usize::try_from(head_count)?
                    * production_attention::SEQUENCE
                    * production_attention::HEAD_DIM;
                self.stream
                    .memcpy_htod(&input[..group_words], &mut witness.query)?;
                self.stream
                    .memcpy_htod(&input[group_words..2 * group_words], &mut witness.key)?;
                self.stream
                    .memcpy_htod(&input[2 * group_words..], &mut witness.value)?;
                witness.metrics.activation_h2d_bytes = (input.len() * size_of::<i32>()) as u64;
                witness.metrics.intermediate_h2d_bytes = witness.metrics.activation_h2d_bytes;
            }
            ProductionStage::PostFfn => {
                self.stream
                    .memcpy_htod(&input[HIDDEN_WORDS..], &mut witness.context)?;
                witness.metrics.activation_h2d_bytes = (input.len() * size_of::<i32>()) as u64;
                witness.metrics.intermediate_h2d_bytes = production_attention::CONTEXT_BYTES;
            }
        }
        Ok(witness)
    }

    pub fn execute_stage(
        &self,
        witness: &mut ProductionStageDeviceWitness,
        layer: u32,
    ) -> Result<()> {
        match witness.stage {
            ProductionStage::Projection => {
                let substage_started = std::time::Instant::now();
                self.launch_rms(witness, layer, TensorRole::InputNorm, true)?;
                tracing::info!(
                    target: "ceno_pipeline",
                    phase = "production_execute_substage",
                    stage = ?witness.stage,
                    role = ?TensorRole::InputNorm,
                    elapsed_ms = substage_started.elapsed().as_millis(),
                    "production execute RMS substage complete"
                );
                for role in [TensorRole::Query, TensorRole::Key, TensorRole::Value] {
                    let substage_started = std::time::Instant::now();
                    self.launch_dense_range(
                        witness,
                        layer,
                        role,
                        HIDDEN_WORDS / SEQUENCE,
                        usize::try_from(witness.head_start)? * production_attention::HEAD_DIM,
                        usize::try_from(witness.head_count)? * production_attention::HEAD_DIM,
                        16,
                    )?;
                    tracing::info!(
                        target: "ceno_pipeline",
                        phase = "production_execute_substage",
                        stage = ?witness.stage,
                        ?role,
                        elapsed_ms = substage_started.elapsed().as_millis(),
                        "production execute dense substage complete"
                    );
                    if role != TensorRole::Value {
                        let rope_started = std::time::Instant::now();
                        self.launch_rope(witness, layer, role)?;
                        tracing::info!(
                            target: "ceno_pipeline",
                            phase = "production_execute_substage",
                            stage = ?witness.stage,
                            ?role,
                            elapsed_ms = rope_started.elapsed().as_millis(),
                            "production execute rope substage complete"
                        );
                    }
                }
            }
            ProductionStage::Attention => {
                for head in 0..usize::try_from(witness.head_count)? {
                    for query_start in (0..SEQUENCE).step_by(QUERY_TILE) {
                        self.launch_qk(witness, head, query_start)?;
                        self.launch_shift(witness, query_start)?;
                        self.launch_softmax(witness, query_start)?;
                        self.launch_pv(witness, head, query_start)?;
                        witness.metrics.qk_launches += 1;
                        witness.metrics.softmax_launches += 1;
                        witness.metrics.pv_launches += 1;
                    }
                }
            }
            ProductionStage::PostFfn => {
                self.launch_dense(
                    witness,
                    layer,
                    TensorRole::AttentionOutput,
                    HIDDEN_WORDS / SEQUENCE,
                    HIDDEN_WORDS / SEQUENCE,
                    16,
                )?;
                self.launch_residual(witness, layer, TensorRole::AttentionOutput)?;
                self.launch_rms(witness, layer, TensorRole::PostAttentionNorm, false)?;
                self.launch_dense(
                    witness,
                    layer,
                    TensorRole::FfnGate,
                    HIDDEN_WORDS / SEQUENCE,
                    LLAMA2_7B_INTERMEDIATE,
                    20,
                )?;
                self.launch_dense(
                    witness,
                    layer,
                    TensorRole::FfnUp,
                    HIDDEN_WORDS / SEQUENCE,
                    LLAMA2_7B_INTERMEDIATE,
                    16,
                )?;
                self.launch_swiglu(witness, layer)?;
                self.launch_dense(
                    witness,
                    layer,
                    TensorRole::FfnDown,
                    LLAMA2_7B_INTERMEDIATE,
                    HIDDEN_WORDS / SEQUENCE,
                    16,
                )?;
                self.launch_residual(witness, layer, TensorRole::FfnDown)?;
            }
        }
        for record in &witness.operation_records {
            record.validate()?;
        }
        let (free, total) = result::mem_get_info()?;
        witness.metrics.minimum_free_bytes = witness.metrics.minimum_free_bytes.min(free as u64);
        witness.metrics.high_water_bytes = witness
            .metrics
            .high_water_bytes
            .max(total as u64 - free as u64);
        ensure!(
            free as u64 >= REQUIRED_FREE_MARGIN_BYTES,
            "production stage runtime breached the 1.5-GiB VRAM margin"
        );
        Ok(())
    }

    pub fn transition_to_attention(
        &self,
        witness: &mut ProductionStageDeviceWitness,
        head_start: u32,
        head_count: u32,
    ) -> Result<()> {
        ensure!(
            witness.stage == ProductionStage::Projection
                && witness.head_start == head_start
                && witness.head_count == head_count,
            "production fused projection/attention range changed"
        );
        witness.stage = ProductionStage::Attention;
        Ok(())
    }

    fn launch_rms(
        &self,
        witness: &mut ProductionFullLayerDeviceWitness,
        layer: u32,
        role: TensorRole,
        input_stage: bool,
    ) -> Result<()> {
        for tile in 0..4u32 {
            self.stage_hint_tile(witness, ProductionHintRef::new(layer, role, tile)?)?;
            let start = tile * WEIGHT_TILE_WORDS as u32;
            let input = if input_stage {
                &witness.hidden
            } else {
                &witness.attention_residual
            };
            let output = if input_stage {
                &mut witness.input_norm
            } else {
                &mut witness.post_norm
            };
            unsafe {
                self.stream
                    .launch_builder(&self.rms)
                    .arg(input)
                    .arg(&witness.hint_tile)
                    .arg(output)
                    .arg(&start)
                    .launch(LaunchConfig::for_num_elems(
                        (SEQUENCE * WEIGHT_TILE_WORDS) as u32,
                    ))?;
            }
            witness
                .operation_records
                .push(ProductionFullLayerOperationRecord {
                    import_cycle: 0,
                    layer,
                    role,
                    token: 0,
                    token_count: SEQUENCE as u32,
                    output_column: start,
                    output_column_count: WEIGHT_TILE_WORDS as u32,
                    tile,
                });
            witness.metrics.rms_launches += 1;
        }
        Ok(())
    }

    fn launch_dense(
        &self,
        witness: &mut ProductionFullLayerDeviceWitness,
        layer: u32,
        role: TensorRole,
        k: usize,
        n: usize,
        shift: u32,
    ) -> Result<()> {
        self.launch_dense_range(witness, layer, role, k, 0, n, shift)
    }

    fn launch_dense_range(
        &self,
        witness: &mut ProductionFullLayerDeviceWitness,
        layer: u32,
        role: TensorRole,
        k: usize,
        logical_column_start: usize,
        n: usize,
        shift: u32,
    ) -> Result<()> {
        let tiles = k.div_ceil(WEIGHT_TILE_WORDS);
        for column in 0..n {
            for position in 0..tiles {
                witness
                    .operation_records
                    .push(ProductionFullLayerOperationRecord {
                        import_cycle: 0,
                        layer,
                        role,
                        token: 0,
                        token_count: SEQUENCE as u32,
                        output_column: u32::try_from(logical_column_start + column)?,
                        output_column_count: 1,
                        tile: position as u32,
                    });
            }
        }
        for column_start in (0..n).step_by(DENSE_PANEL_COLUMNS) {
            let column_count = (n - column_start).min(DENSE_PANEL_COLUMNS);
            for position in 0..tiles {
                let mut panel = vec![0; DENSE_PANEL_WORDS];
                let mut logical_words = 0usize;
                for local_column in 0..column_count {
                    let column = logical_column_start + column_start + local_column;
                    let logical_tile = column * tiles + position;
                    let tile = production_attention::generate_hint_tile(ProductionHintRef::new(
                        layer,
                        role,
                        u32::try_from(logical_tile)?,
                    )?)?;
                    logical_words += tile.len();
                    let panel_start = local_column * WEIGHT_TILE_WORDS;
                    panel[panel_start..panel_start + tile.len()].copy_from_slice(&tile);
                }
                self.stream
                    .memcpy_htod(&panel, &mut witness.dense_hint_panel)?;
                witness.metrics.setup_h2d_bytes = witness
                    .metrics
                    .setup_h2d_bytes
                    .checked_add((logical_words * size_of::<i32>()) as u64)
                    .ok_or_else(|| anyhow::anyhow!("production private-hint traffic overflow"))?;
                let k_start = position * WEIGHT_TILE_WORDS;
                let logical_k = (k - k_start).min(WEIGHT_TILE_WORDS);
                let first = position == 0;
                let last = position + 1 == tiles;
                let input: &CudaSlice<i32> = match role {
                    TensorRole::Query | TensorRole::Key | TensorRole::Value => &witness.input_norm,
                    TensorRole::AttentionOutput => &witness.context,
                    TensorRole::FfnGate | TensorRole::FfnUp => &witness.post_norm,
                    TensorRole::FfnDown => &witness.swiglu,
                    _ => unreachable!("validated dense production role"),
                };
                let output: &mut CudaSlice<i32> = match role {
                    TensorRole::Query | TensorRole::Key => &mut witness.rope_projection,
                    TensorRole::Value => &mut witness.value,
                    TensorRole::AttentionOutput => &mut witness.attention_projection,
                    TensorRole::FfnGate => &mut witness.gate,
                    TensorRole::FfnUp => &mut witness.up,
                    TensorRole::FfnDown => &mut witness.down,
                    _ => unreachable!("validated dense production role"),
                };
                unsafe {
                    self.stream
                        .launch_builder(&self.dense_tile)
                        .arg(input)
                        .arg(&witness.dense_hint_panel)
                        .arg(&mut witness.dense_accumulator)
                        .arg(output)
                        .arg(&(k as u32))
                        .arg(&(n as u32))
                        .arg(&(column_start as u32))
                        .arg(&(column_count as u32))
                        .arg(&(k_start as u32))
                        .arg(&(logical_k as u32))
                        .arg(&shift)
                        .arg(&(first as u32))
                        .arg(&(last as u32))
                        .launch(LaunchConfig::for_num_elems(
                            (SEQUENCE * column_count) as u32,
                        ))?;
                }
                witness.metrics.projection_tile_launches += 1;
            }
        }
        Ok(())
    }

    fn launch_rope(
        &self,
        witness: &mut ProductionFullLayerDeviceWitness,
        layer: u32,
        role: TensorRole,
    ) -> Result<()> {
        let pairs = witness.query.len() / 2;
        let output = match role {
            TensorRole::Query => &mut witness.query,
            TensorRole::Key => &mut witness.key,
            _ => unreachable!("RoPE is only applied to Q and K"),
        };
        unsafe {
            self.stream
                .launch_builder(&self.rope)
                .arg(&witness.rope_projection)
                .arg(output)
                .arg(&(witness.head_count * production_attention::HEAD_DIM as u32))
                .launch(LaunchConfig::for_num_elems(pairs as u32))?;
        }
        witness
            .operation_records
            .push(ProductionFullLayerOperationRecord {
                import_cycle: 0,
                layer,
                role,
                token: 0,
                token_count: SEQUENCE as u32,
                output_column: witness.head_start * production_attention::HEAD_DIM as u32,
                output_column_count: witness.head_count * production_attention::HEAD_DIM as u32,
                tile: 0,
            });
        witness.metrics.rope_launches += 1;
        Ok(())
    }

    fn launch_residual(
        &self,
        witness: &mut ProductionFullLayerDeviceWitness,
        layer: u32,
        role: TensorRole,
    ) -> Result<()> {
        let (left, right, output) = match role {
            TensorRole::AttentionOutput => (
                &witness.hidden,
                &witness.attention_projection,
                &mut witness.attention_residual,
            ),
            TensorRole::FfnDown => (
                &witness.attention_residual,
                &witness.down,
                &mut witness.output,
            ),
            _ => unreachable!("validated residual role"),
        };
        unsafe {
            self.stream
                .launch_builder(&self.residual)
                .arg(left)
                .arg(right)
                .arg(output)
                .launch(LaunchConfig::for_num_elems(HIDDEN_WORDS as u32))?;
        }
        witness
            .operation_records
            .push(ProductionFullLayerOperationRecord {
                import_cycle: 0,
                layer,
                role,
                token: 0,
                token_count: SEQUENCE as u32,
                output_column: 0,
                output_column_count: (HIDDEN_WORDS / SEQUENCE) as u32,
                tile: 0,
            });
        witness.metrics.residual_launches += 1;
        Ok(())
    }

    fn launch_swiglu(
        &self,
        witness: &mut ProductionFullLayerDeviceWitness,
        layer: u32,
    ) -> Result<()> {
        let cells = SEQUENCE * LLAMA2_7B_INTERMEDIATE;
        unsafe {
            self.stream
                .launch_builder(&self.swiglu)
                .arg(&witness.gate)
                .arg(&witness.up)
                .arg(&mut witness.swiglu)
                .launch(LaunchConfig::for_num_elems(cells as u32))?;
        }
        witness
            .operation_records
            .push(ProductionFullLayerOperationRecord {
                import_cycle: 0,
                layer,
                role: TensorRole::FfnGate,
                token: 0,
                token_count: SEQUENCE as u32,
                output_column: 0,
                output_column_count: LLAMA2_7B_INTERMEDIATE as u32,
                tile: 0,
            });
        witness.metrics.swiglu_launches += 1;
        Ok(())
    }

    /// Replace the single private-weight staging allocation with one logical
    /// K1024 tile. The caller launches and completes the corresponding layer
    /// operation before staging the next tile.
    pub fn stage_hint_tile(
        &self,
        witness: &mut ProductionFullLayerDeviceWitness,
        hint: ProductionHintRef,
    ) -> Result<usize> {
        let tile = production_attention::generate_hint_tile(hint)?;
        let logical_words = tile.len();
        let mut padded = tile;
        padded.resize(WEIGHT_TILE_WORDS, 0);
        self.stream.memcpy_htod(&padded, &mut witness.hint_tile)?;
        witness.metrics.setup_h2d_bytes = witness
            .metrics
            .setup_h2d_bytes
            .checked_add((logical_words * size_of::<i32>()) as u64)
            .ok_or_else(|| anyhow::anyhow!("production private-hint traffic overflow"))?;
        Ok(logical_words)
    }

    fn launch_qk(
        &self,
        witness: &mut ProductionFullLayerDeviceWitness,
        head: usize,
        query_start: usize,
    ) -> Result<()> {
        unsafe {
            self.stream
                .launch_builder(&self.qk)
                .arg(&witness.query)
                .arg(&witness.key)
                .arg(&mut witness.scores)
                .arg(&(head as u32))
                .arg(&witness.head_count)
                .arg(&(query_start as u32))
                .launch(LaunchConfig::for_num_elems(TILE_CELLS as u32))?;
        }
        Ok(())
    }

    fn launch_softmax(
        &self,
        witness: &mut ProductionFullLayerDeviceWitness,
        query_start: usize,
    ) -> Result<()> {
        unsafe {
            self.stream
                .launch_builder(&self.softmax)
                .arg(&witness.scores)
                .arg(&witness.shifts)
                .arg(&mut witness.probabilities)
                .arg(&mut witness.limbs)
                .arg(&(query_start as u32))
                .launch(LaunchConfig::for_num_elems(TILE_CELLS as u32))?;
        }
        Ok(())
    }

    fn launch_shift(
        &self,
        witness: &mut ProductionFullLayerDeviceWitness,
        query_start: usize,
    ) -> Result<()> {
        unsafe {
            self.stream
                .launch_builder(&self.shift)
                .arg(&witness.scores)
                .arg(&mut witness.shifts)
                .arg(&(query_start as u32))
                .launch(LaunchConfig::for_num_elems(QUERY_TILE as u32))?;
        }
        Ok(())
    }

    fn launch_pv(
        &self,
        witness: &mut ProductionFullLayerDeviceWitness,
        head: usize,
        query_start: usize,
    ) -> Result<()> {
        unsafe {
            self.stream
                .launch_builder(&self.pv)
                .arg(&witness.value)
                .arg(&witness.probabilities)
                .arg(&mut witness.context)
                .arg(&(head as u32))
                .arg(&witness.head_count)
                .arg(&(query_start as u32))
                .launch(LaunchConfig::for_num_elems(
                    (QUERY_TILE * production_attention::HEAD_DIM) as u32,
                ))?;
        }
        Ok(())
    }

    pub fn export_stage(&self, witness: &mut ProductionStageDeviceWitness) -> Result<Vec<i32>> {
        self.stream.synchronize()?;
        let output = match witness.stage {
            ProductionStage::Projection => {
                let mut output = self.stream.memcpy_dtov(&witness.query)?;
                output.extend(self.stream.memcpy_dtov(&witness.key)?);
                output.extend(self.stream.memcpy_dtov(&witness.value)?);
                output
            }
            ProductionStage::Attention => self.stream.memcpy_dtov(&witness.context)?,
            ProductionStage::PostFfn => self.stream.memcpy_dtov(&witness.output)?,
        };
        let bytes = (output.len() * size_of::<i32>()) as u64;
        witness.metrics.activation_d2h_bytes = bytes;
        if witness.stage != ProductionStage::PostFfn {
            witness.metrics.intermediate_d2h_bytes = bytes;
        }
        Ok(output)
    }
}

const CUDA_SOURCE: &str = r#"
extern "C" __device__ __forceinline__ long long centered_rescale(long long value, unsigned shift) {
    long long scale = 1ll << shift;
    long long adjusted = value + (scale >> 1);
    long long q = adjusted / scale;
    if (adjusted < 0 && adjusted % scale) --q;
    return q;
}

extern "C" __device__ __forceinline__ unsigned long long production_isqrt(
    unsigned long long value) {
    unsigned long long root = 0;
    unsigned long long bit = 1ull << 62;
    while (bit > value) bit >>= 2;
    while (bit) {
        if (value >= root + bit) {
            value -= root + bit;
            root = (root >> 1) + bit;
        } else {
            root >>= 1;
        }
        bit >>= 2;
    }
    return root;
}

extern "C" __device__ __forceinline__ int production_rms_inverse(
    unsigned long long energy) {
    unsigned long long root = production_isqrt(energy + 17592186ull);
    return (int)(((1ull << 38) + root / 2) / root);
}

extern "C" __global__ void production_full_layer_rms(
    const int *input, const int *weight, int *output, unsigned column_start) {
    unsigned cell = blockIdx.x * blockDim.x + threadIdx.x;
    if (cell >= 2048u * 1024u) return;
    unsigned token = cell / 1024u;
    unsigned local_column = cell % 1024u;
    unsigned column = column_start + local_column;
    unsigned long long energy = 0;
    for (unsigned k = 0; k < 4096u; ++k) {
        long long value = input[token * 4096u + k];
        energy += (unsigned long long)(value * value);
    }
    int inv_rms = production_rms_inverse(energy);
    long long weighted_inv = centered_rescale((long long)inv_rms * weight[local_column], 16u);
    output[token * 4096u + column] =
        (int)centered_rescale(weighted_inv * input[token * 4096u + column], 16u);
}

extern "C" __global__ void production_full_layer_dense_tile(
    const int *input, const int *weight, long long *accumulator, int *output,
    unsigned k, unsigned n, unsigned column_start, unsigned column_count,
    unsigned k_start, unsigned logical_k,
    unsigned shift, unsigned first, unsigned last) {
    unsigned cell = blockIdx.x * blockDim.x + threadIdx.x;
    if (cell >= 2048u * column_count) return;
    unsigned token = cell / column_count;
    unsigned local_column = cell % column_count;
    unsigned local_output_column = column_start + local_column;
    unsigned output_index = token * n + local_output_column;
    long long sum = first ? 0ll : accumulator[output_index];
    const int *row = input + token * k + k_start;
    const int *weight_column = weight + local_column * 1024u;
    for (unsigned i = 0; i < logical_k; ++i)
        sum += (long long)row[i] * weight_column[i];
    accumulator[output_index] = sum;
    if (last) output[output_index] = (int)centered_rescale(sum, shift);
}

extern "C" __global__ void production_full_layer_rope(
    const int *input, int *output, unsigned stride) {
    unsigned pair = blockIdx.x * blockDim.x + threadIdx.x;
    unsigned pairs_per_token = stride / 2u;
    if (pair >= 2048u * pairs_per_token) return;
    unsigned token = pair / pairs_per_token;
    unsigned within_token = pair % pairs_per_token;
    unsigned head = within_token / 64u;
    unsigned dim = within_token % 64u;
    unsigned left = token * stride + head * 128u + dim;
    unsigned right = left + 64u;
    int cos_left = 65536 - (int)((token + dim) % 17u);
    int sin_left = (int)((token * (dim + 1u)) % 31u) - 15;
    int cos_right = 65536 - (int)((token + dim + 64u) % 17u);
    int sin_right = (int)((token * (dim + 65u)) % 31u) - 15;
    output[left] = (int)centered_rescale(
        (long long)input[left] * cos_left - (long long)input[right] * sin_left, 16u);
    output[right] = (int)centered_rescale(
        (long long)input[right] * cos_right + (long long)input[left] * sin_right, 16u);
}

extern "C" __global__ void production_full_layer_residual(
    const int *left, const int *right, int *output) {
    unsigned cell = blockIdx.x * blockDim.x + threadIdx.x;
    if (cell < 2048u * 4096u) output[cell] = left[cell] + right[cell];
}

extern "C" __global__ void production_full_layer_swiglu(
    const int *gate, const int *up, int *output) {
    unsigned cell = blockIdx.x * blockDim.x + threadIdx.x;
    if (cell >= 2048u * 11008u) return;
    double value = (double)gate[cell];
    int silu = (int)llround(value * 16.0 / (1.0 + exp(-value / 4096.0)));
    output[cell] = (int)centered_rescale((long long)silu * up[cell], 16u);
}

extern "C" __device__ __forceinline__ long long centered_q20(long long value) {
    const long long scale = 1ll << 20;
    long long adjusted = value + (scale >> 1);
    long long q = adjusted / scale;
    if (adjusted < 0 && adjusted % scale) --q;
    return q;
}

extern "C" __global__ void production_attention_qk(
    const int *q, const int *k, long long *scores, unsigned head,
    unsigned head_count, unsigned query_start) {
    unsigned cell = blockIdx.x * blockDim.x + threadIdx.x;
    if (cell >= 128u * 2048u) return;
    unsigned local_query = cell / 2048u;
    unsigned key = cell % 2048u;
    unsigned query = query_start + local_query;
    unsigned stride = head_count * 128u;
    unsigned q_base = query * stride + head * 128u;
    unsigned k_base = key * stride + head * 128u;
    long long score = 0;
    #pragma unroll 4
    for (unsigned dim = 0; dim < 128u; ++dim)
        score += (long long)q[q_base + dim] * (long long)k[k_base + dim];
    scores[cell] = score;
}

extern "C" __global__ void production_attention_softmax(
    const long long *scores, const long long *shifts, long long *probabilities,
    unsigned *limbs, unsigned query_start) {
    unsigned cell = blockIdx.x * blockDim.x + threadIdx.x;
    if (cell >= 128u * 2048u) return;
    unsigned query = query_start + cell / 2048u;
    unsigned key = cell % 2048u;
    unsigned long long magnitude = (unsigned long long)(shifts[cell / 2048u] - scores[cell]);
    unsigned digit0 = (unsigned)(magnitude & 0xffu);
    unsigned digit1 = (unsigned)((magnitude >> 8u) & 0xfffffu);
    unsigned digit2 = (unsigned)((magnitude >> 28u) & 0xfffffu);
    limbs[0u * (128u * 2048u) + cell] = digit0;
    limbs[1u * (128u * 2048u) + cell] = digit1;
    limbs[2u * (128u * 2048u) + cell] = digit2;
    limbs[3u * (128u * 2048u) + cell] = (unsigned)magnitude;
    limbs[4u * (128u * 2048u) + cell] = (unsigned)shifts[cell / 2048u];
    const double scale = 4294967296.0 * 11.313708498984761;
    long long middle = (long long)(exp(log(262144.0) - (256.0 / scale) * digit1) + 0.5);
    long long high = (long long)(exp(log(4194304.0) - (268435456.0 / scale) * digit2) + 0.5);
    probabilities[cell] = key <= query ? middle * high : 0ll;
}

extern "C" __global__ void production_attention_shift(
    const long long *scores, long long *shifts, unsigned query_start) {
    unsigned local_query = blockIdx.x * blockDim.x + threadIdx.x;
    if (local_query >= 128u) return;
    const double scale = 4294967296.0 * 11.313708498984761;
    double sum = 0.0;
    for (unsigned key = 0; key <= query_start + local_query; ++key)
        sum += exp((double)scores[local_query * 2048u + key] / scale);
    shifts[local_query] = (long long)(scale * log(sum) + 0.5);
}

extern "C" __global__ void production_attention_pv(
    const int *v, const long long *probabilities, int *context,
    unsigned head, unsigned head_count, unsigned query_start) {
    unsigned output_cell = blockIdx.x * blockDim.x + threadIdx.x;
    if (output_cell >= 128u * 128u) return;
    unsigned local_query = output_cell / 128u;
    unsigned dim = output_cell % 128u;
    unsigned query = query_start + local_query;
    unsigned stride = head_count * 128u;
    unsigned v_base = head * 128u + dim;
    unsigned p_base = local_query * 2048u;
    long long accumulator = 0;
    for (unsigned key = 0; key < 2048u; ++key)
        accumulator += probabilities[p_base + key] * (long long)v[v_base + key * stride];
    long long once = centered_q20(accumulator);
    long long twice = centered_q20(once);
    context[query * stride + head * 128u + dim] = (int)twice;
}
"#;
