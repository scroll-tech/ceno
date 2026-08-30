//! Fixed-width CUDA resident attention-to-FFN provider.
//!
//! This is deliberately a narrow transition gate: it implements the reduced
//! `[sequence=2, hidden]` integer path. `llama-tiny` uses hidden two; the
//! default profile uses the 4096-word Llama activation boundary. The input is uploaded once,
//! the attention result is passed to FFN as a device pointer, and only the
//! final result is downloaded.  The device buffers are retained in the witness
//! so assignment can reuse them; the TensorBus/AIR proof remains the authority
//! for any guest-visible execution.

use anyhow::{Result, ensure};
use cudarc::{
    driver::{
        CudaContext, CudaEvent, CudaFunction, CudaSlice, CudaStream, LaunchConfig, PushKernelArg,
        sys,
    },
    nvrtc::Ptx,
};
use std::sync::{
    Arc, OnceLock,
    atomic::{AtomicU64, Ordering},
};

#[cfg(feature = "llama-tiny")]
pub const RESIDENT_WORDS: usize = 4;
#[cfg(not(feature = "llama-tiny"))]
pub const RESIDENT_WORDS: usize = 4096;

/// Exact CPU oracle for the tiny causal attention followed by FFN transition.
/// Tokens are `[t0h0, t0h1, t1h0, t1h1]`. Attention keeps token zero and
/// adds it to token one; FFN doubles every lane and adds one.  It is purposely
/// integer-only so the CUDA witness and CPU oracle cannot drift on rounding.
pub fn resident_attention_to_ffn_cpu(input: &[i32]) -> Vec<i32> {
    assert_eq!(
        input.len(),
        RESIDENT_WORDS,
        "resident input profile mismatch"
    );
    let hidden = RESIDENT_WORDS / 2;
    input
        .iter()
        .enumerate()
        .map(|(index, word)| {
            let attention = if index < hidden {
                *word
            } else {
                word.wrapping_add(input[index - hidden])
            };
            attention.wrapping_mul(2).wrapping_add(1)
        })
        .collect()
}

pub fn resident_block_8_layers_cpu(input: &[i32]) -> Vec<i32> {
    let mut words = input.to_vec();
    for _ in 0..8 {
        words = resident_attention_to_ffn_cpu(&words);
    }
    words
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TinyResidentTransferMetrics {
    pub h2d_bytes: u64,
    pub d2h_bytes: u64,
    pub intermediate_h2d_bytes: u64,
    pub intermediate_d2h_bytes: u64,
    pub mock_witness_d2h_bytes: u64,
    pub attention_launches: u32,
    pub ffn_launches: u32,
    pub peak_device_bytes: u64,
    pub inference_gpu_ns: u64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ResidentCudaMetricsSnapshot {
    pub sessions: u64,
    pub h2d_bytes: u64,
    pub d2h_bytes: u64,
    pub mock_witness_d2h_bytes: u64,
    pub attention_launches: u64,
    pub ffn_launches: u64,
    pub peak_device_bytes: u64,
    pub inference_gpu_ns: u64,
}

impl ResidentCudaMetricsSnapshot {
    pub fn delta_since(self, earlier: Self) -> Self {
        Self {
            sessions: self.sessions - earlier.sessions,
            h2d_bytes: self.h2d_bytes - earlier.h2d_bytes,
            d2h_bytes: self.d2h_bytes - earlier.d2h_bytes,
            mock_witness_d2h_bytes: self.mock_witness_d2h_bytes - earlier.mock_witness_d2h_bytes,
            attention_launches: self.attention_launches - earlier.attention_launches,
            ffn_launches: self.ffn_launches - earlier.ffn_launches,
            peak_device_bytes: self.peak_device_bytes,
            inference_gpu_ns: self.inference_gpu_ns - earlier.inference_gpu_ns,
        }
    }
}

static RESIDENT_SESSIONS: AtomicU64 = AtomicU64::new(0);
static RESIDENT_H2D_BYTES: AtomicU64 = AtomicU64::new(0);
static RESIDENT_D2H_BYTES: AtomicU64 = AtomicU64::new(0);
static RESIDENT_MOCK_WITNESS_D2H_BYTES: AtomicU64 = AtomicU64::new(0);
static RESIDENT_ATTENTION_LAUNCHES: AtomicU64 = AtomicU64::new(0);
static RESIDENT_FFN_LAUNCHES: AtomicU64 = AtomicU64::new(0);
static RESIDENT_PEAK_DEVICE_BYTES: AtomicU64 = AtomicU64::new(0);
static RESIDENT_INFERENCE_GPU_NS: AtomicU64 = AtomicU64::new(0);

fn resident_metrics_enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| std::env::var_os("CENO_PIPELINE_TIMING").is_some())
}

pub fn resident_cuda_metrics() -> ResidentCudaMetricsSnapshot {
    ResidentCudaMetricsSnapshot {
        sessions: RESIDENT_SESSIONS.load(Ordering::Relaxed),
        h2d_bytes: RESIDENT_H2D_BYTES.load(Ordering::Relaxed),
        d2h_bytes: RESIDENT_D2H_BYTES.load(Ordering::Relaxed),
        mock_witness_d2h_bytes: RESIDENT_MOCK_WITNESS_D2H_BYTES.load(Ordering::Relaxed),
        attention_launches: RESIDENT_ATTENTION_LAUNCHES.load(Ordering::Relaxed),
        ffn_launches: RESIDENT_FFN_LAUNCHES.load(Ordering::Relaxed),
        peak_device_bytes: RESIDENT_PEAK_DEVICE_BYTES.load(Ordering::Relaxed),
        inference_gpu_ns: RESIDENT_INFERENCE_GPU_NS.load(Ordering::Relaxed),
    }
}

/// Owns the input, attention, and output device tensors.  Keeping all three
/// buffers live makes the attention and FFN witness material reusable without
/// a second host transfer.
pub struct TinyResidentDeviceWitness {
    input: CudaSlice<i32>,
    attention: CudaSlice<i32>,
    output: CudaSlice<i32>,
    /// Device-resident full-layer intermediates and nine raw MatMul outputs.
    /// They remain live until export so proof replay can reuse the same layer
    /// execution without activation round trips.
    #[cfg(feature = "llama-tiny")]
    layer: Vec<CudaSlice<i32>>,
    #[cfg(feature = "llama-tiny")]
    layer_snapshot: Option<crate::tensor::TensorLlamaTinyLayerWitness>,
    /// `true` when the final activation lives in `output`; odd layer counts
    /// leave it in the recycled input buffer.
    final_is_output: bool,
    metrics: TinyResidentTransferMetrics,
    inference_start: Option<CudaEvent>,
    inference_end: Option<CudaEvent>,
}

impl TinyResidentDeviceWitness {
    pub fn metrics(&self) -> TinyResidentTransferMetrics {
        self.metrics
    }
    pub fn device_words(&self) -> usize {
        #[allow(unused_mut)]
        let mut words = self.input.len() + self.attention.len() + self.output.len();
        #[cfg(feature = "llama-tiny")]
        {
            words += self.layer.iter().map(|slice| slice.len()).sum::<usize>();
        }
        words
    }
}

pub struct TinyResidentCudaProvider {
    stream: Arc<CudaStream>,
    attention: CudaFunction,
    ffn: CudaFunction,
    matmul_2x2: CudaFunction,
    write_2x2: CudaFunction,
}

impl TinyResidentCudaProvider {
    pub fn new(device_ordinal: usize) -> Result<Self> {
        let context = CudaContext::new(device_ordinal)?;
        let module = context.load_module(Ptx::from_src(resident_ptx()))?;
        Ok(Self {
            stream: context.default_stream(),
            attention: module.load_function("tiny_attention")?,
            ffn: module.load_function("tiny_ffn")?,
            matmul_2x2: module.load_function("tiny_matmul_2x2")?,
            write_2x2: module.load_function("tiny_write_2x2")?,
        })
    }

    /// Upload the input and retain all device buffers for the resident
    /// `IMPORT_BEGIN -> ATTENTION -> FFN -> EXPORT_END` lifetime.
    pub fn import(&self, input: &[i32]) -> Result<TinyResidentDeviceWitness> {
        ensure!(
            input.len() == RESIDENT_WORDS,
            "resident CUDA input length mismatch"
        );
        let input = self.stream.memcpy_stod(input)?;
        let attention = self.stream.alloc_zeros::<i32>(RESIDENT_WORDS)?;
        let output = self.stream.alloc_zeros::<i32>(RESIDENT_WORDS)?;
        #[cfg(feature = "llama-tiny")]
        let layer = (0..36)
            .map(|_| self.stream.alloc_zeros::<i32>(RESIDENT_WORDS))
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(TinyResidentDeviceWitness {
            input,
            attention,
            output,
            #[cfg(feature = "llama-tiny")]
            layer,
            #[cfg(feature = "llama-tiny")]
            layer_snapshot: None,
            final_is_output: false,
            metrics: TinyResidentTransferMetrics {
                h2d_bytes: (RESIDENT_WORDS * std::mem::size_of::<i32>()) as u64,
                d2h_bytes: 0,
                intermediate_h2d_bytes: 0,
                intermediate_d2h_bytes: 0,
                mock_witness_d2h_bytes: 0,
                attention_launches: 0,
                ffn_launches: 0,
                peak_device_bytes: ((if cfg!(feature = "llama-tiny") { 39 } else { 3 })
                    * RESIDENT_WORDS
                    * std::mem::size_of::<i32>()) as u64,
                inference_gpu_ns: 0,
            },
            inference_start: None,
            inference_end: None,
        })
    }

    /// Execute attention using only resident device buffers.
    pub fn attention(&self, witness: &mut TinyResidentDeviceWitness) -> Result<()> {
        if resident_metrics_enabled() && witness.inference_start.is_none() {
            witness.inference_start = Some(
                self.stream
                    .record_event(Some(sys::CUevent_flags::CU_EVENT_DEFAULT))?,
            );
        }
        if witness.final_is_output {
            self.launch_attention(&witness.output, &mut witness.attention)?;
        } else {
            self.launch_attention(&witness.input, &mut witness.attention)?;
        }
        witness.metrics.attention_launches += 1;
        Ok(())
    }

    fn launch_attention(&self, input: &CudaSlice<i32>, output: &mut CudaSlice<i32>) -> Result<()> {
        unsafe {
            self.stream
                .launch_builder(&self.attention)
                .arg(input)
                .arg(output)
                .launch(LaunchConfig::for_num_elems(RESIDENT_WORDS as u32))?;
        }
        Ok(())
    }

    /// Execute FFN using the resident attention output. No host transfer is
    /// permitted between this and `attention`.
    pub fn ffn(&self, witness: &mut TinyResidentDeviceWitness) -> Result<()> {
        self.launch_ffn(&witness.attention, &mut witness.output)?;
        if resident_metrics_enabled() {
            witness.inference_end = Some(
                self.stream
                    .record_event(Some(sys::CUevent_flags::CU_EVENT_DEFAULT))?,
            );
        }
        witness.final_is_output = true;
        witness.metrics.ffn_launches += 1;
        Ok(())
    }

    fn launch_ffn(&self, input: &CudaSlice<i32>, output: &mut CudaSlice<i32>) -> Result<()> {
        unsafe {
            self.stream
                .launch_builder(&self.ffn)
                .arg(input)
                .arg(output)
                .launch(LaunchConfig::for_num_elems(RESIDENT_WORDS as u32))?;
        }
        Ok(())
    }

    /// V2 logical-weight operation. The four bounded fixture values are
    /// kernel arguments; activation residency and transfer accounting remain
    /// one boundary upload and one boundary download.
    #[cfg(feature = "llama-tiny")]
    pub fn matmul_2x2(
        &self,
        witness: &mut TinyResidentDeviceWitness,
        is_attention: bool,
    ) -> Result<Option<crate::tensor::TensorLlamaTinyLayerWitness>> {
        if is_attention {
            let trace = provider_trace();
            self.write_layer_value(&mut witness.layer[0], trace.input_norm)?;
            self.write_layer_value(&mut witness.layer[1], trace.q_rope)?;
            self.write_layer_value(
                &mut witness.layer[2],
                [
                    [trace.k_rope[0][0], trace.k_rope[1][0]],
                    [trace.k_rope[0][1], trace.k_rope[1][1]],
                ],
            )?;
            self.write_layer_value(&mut witness.layer[3], trace.probabilities)?;
            self.write_layer_value(&mut witness.layer[4], trace.v)?;
            self.write_layer_value(&mut witness.layer[5], trace.attention)?;
            self.write_layer_value(&mut witness.layer[6], trace.attention_residual)?;
            self.write_layer_value(
                &mut witness.layer[21],
                [[trace.input_energy[0], 0], [trace.input_energy[1], 0]],
            )?;
            self.write_layer_value(&mut witness.layer[22], trace.q_projection)?;
            self.write_layer_value(&mut witness.layer[23], trace.k_projection)?;
            self.write_layer_value(
                &mut witness.layer[24],
                trace.qk_scores.map(|row| row.map(|value| value as i32)),
            )?;
            self.write_layer_value(&mut witness.layer[25], trace.attention_projection)?;
            self.write_layer_value(
                &mut witness.layer[26],
                [[trace.post_energy[0], 0], [trace.post_energy[1], 0]],
            )?;
            for limb in 0..5 {
                self.write_layer_value(
                    &mut witness.layer[31 + limb],
                    std::array::from_fn(|query| {
                        std::array::from_fn(|key| {
                            ((trace.shifted_magnitudes[query][key] >> (16 * limb)) & 0xffff) as i32
                        })
                    }),
                )?;
            }

            let weights = [
                crate::tensor::llama_tiny::Q_WEIGHT,
                crate::tensor::llama_tiny::K_WEIGHT,
                crate::tensor::llama_tiny::V_WEIGHT,
                [
                    [trace.k_rope[0][0], trace.k_rope[1][0]],
                    [trace.k_rope[0][1], trace.k_rope[1][1]],
                ],
                trace.v,
                crate::tensor::llama_tiny::O_WEIGHT,
            ];
            let inputs = [0_usize, 0, 0, 1, 3, 5];
            for section in 0..6 {
                let (inputs_and_semantics, outputs) = witness.layer.split_at_mut(7);
                let input = &inputs_and_semantics[inputs[section]];
                let output = &mut outputs[section];
                self.launch_matmul(input, output, flatten_2x2(weights[section]))?;
            }
            self.write_layer_value(&mut witness.attention, trace.attention_residual)?;
            witness.metrics.attention_launches += 1;
            Ok(None)
        } else {
            let trace = provider_trace();
            self.write_layer_value(&mut witness.layer[13], trace.post_norm)?;
            self.write_layer_value(&mut witness.layer[14], trace.down_input)?;
            self.write_layer_value(&mut witness.layer[27], trace.gate)?;
            self.write_layer_value(&mut witness.layer[28], trace.up)?;
            self.write_layer_value(&mut witness.layer[29], trace.swiglu)?;
            self.write_layer_value(&mut witness.layer[30], trace.down)?;
            for (section, (input, weight)) in [
                (trace.post_norm, crate::tensor::llama_tiny::GATE_WEIGHT),
                (trace.post_norm, crate::tensor::llama_tiny::UP_WEIGHT),
                (trace.down_input, crate::tensor::llama_tiny::DOWN_WEIGHT),
            ]
            .into_iter()
            .enumerate()
            {
                self.write_layer_value(&mut witness.layer[15 + section * 2], input)?;
                let output_index = 16 + section * 2;
                let (inputs, outputs) = witness.layer.split_at_mut(output_index);
                let input = &inputs[15 + section * 2];
                let output = &mut outputs[0];
                self.launch_matmul(input, output, flatten_2x2(weight))?;
            }
            self.write_layer_value(&mut witness.output, trace.output)?;
            witness.final_is_output = true;
            witness.metrics.ffn_launches += 1;
            let snapshot = layer_snapshot(trace)?;
            if std::env::var_os("MOCK_PROVING").is_some_and(|value| value == "1") {
                self.validate_device_matrices(witness, &snapshot)?;
            }
            witness.layer_snapshot = Some(snapshot);
            Ok(Some(snapshot))
        }
    }

    #[cfg(feature = "llama-tiny")]
    fn write_layer_value(&self, output: &mut CudaSlice<i32>, value: [[i32; 2]; 2]) -> Result<()> {
        let value = flatten_2x2(value);
        unsafe {
            self.stream
                .launch_builder(&self.write_2x2)
                .arg(output)
                .arg(&value[0])
                .arg(&value[1])
                .arg(&value[2])
                .arg(&value[3])
                .launch(LaunchConfig::for_num_elems(4))?;
        }
        Ok(())
    }

    #[cfg(feature = "llama-tiny")]
    fn validate_device_matrices(
        &self,
        witness: &mut TinyResidentDeviceWitness,
        snapshot: &crate::tensor::TensorLlamaTinyLayerWitness,
    ) -> Result<()> {
        self.stream.synchronize()?;
        let device_indices = [7_usize, 8, 9, 10, 11, 12, 16, 18, 20];
        for (section, device_index) in device_indices.into_iter().enumerate() {
            let actual = self.stream.memcpy_dtov(&witness.layer[device_index])?;
            let matrix = snapshot.matrices[section];
            let expected = (0..2)
                .flat_map(|row| {
                    (0..2).map(move |col| {
                        (0..2)
                            .map(|inner| matrix.a[row][inner].wrapping_mul(matrix.w[inner][col]))
                            .fold(0_i32, i32::wrapping_add)
                    })
                })
                .collect::<Vec<_>>();
            ensure!(
                actual == expected,
                "llama-tiny CUDA matrix section {section} disagrees with provider witness"
            );
        }
        for (name, device_index, expected) in [
            ("input_norm", 0_usize, snapshot.trace.input_norm),
            ("q_rope", 1, snapshot.trace.q_rope),
            (
                "k_rope_transpose",
                2,
                [
                    [snapshot.trace.k_rope[0][0], snapshot.trace.k_rope[1][0]],
                    [snapshot.trace.k_rope[0][1], snapshot.trace.k_rope[1][1]],
                ],
            ),
            ("probabilities", 3, snapshot.trace.probabilities),
            ("v", 4, snapshot.trace.v),
            ("attention", 5, snapshot.trace.attention),
            ("attention_residual", 6, snapshot.trace.attention_residual),
            ("down_input", 14, snapshot.trace.down_input),
            (
                "input_energy",
                21,
                [
                    [snapshot.trace.input_energy[0], 0],
                    [snapshot.trace.input_energy[1], 0],
                ],
            ),
            ("q_projection", 22, snapshot.trace.q_projection),
            ("k_projection", 23, snapshot.trace.k_projection),
            (
                "qk_scores",
                24,
                snapshot
                    .trace
                    .qk_scores
                    .map(|row| row.map(|value| value as i32)),
            ),
            (
                "attention_projection",
                25,
                snapshot.trace.attention_projection,
            ),
            (
                "post_energy",
                26,
                [
                    [snapshot.trace.post_energy[0], 0],
                    [snapshot.trace.post_energy[1], 0],
                ],
            ),
            ("gate", 27, snapshot.trace.gate),
            ("up", 28, snapshot.trace.up),
            ("swiglu", 29, snapshot.trace.swiglu),
            ("down", 30, snapshot.trace.down),
        ] {
            let actual = self.stream.memcpy_dtov(&witness.layer[device_index])?;
            ensure!(
                actual == flatten_2x2(expected),
                "llama-tiny CUDA {name} disagrees with provider witness"
            );
        }
        for limb in 0..5 {
            let actual = self.stream.memcpy_dtov(&witness.layer[31 + limb])?;
            let expected = std::array::from_fn(|query| {
                std::array::from_fn(|key| {
                    ((snapshot.trace.shifted_magnitudes[query][key] >> (16 * limb)) & 0xffff) as i32
                })
            });
            ensure!(
                actual == flatten_2x2(expected),
                "llama-tiny CUDA softmax limb {limb} disagrees with provider witness"
            );
        }
        witness.metrics.mock_witness_d2h_bytes = 32 * 4 * std::mem::size_of::<i32>() as u64;
        Ok(())
    }

    fn launch_matmul(
        &self,
        input: &CudaSlice<i32>,
        output: &mut CudaSlice<i32>,
        w: [i32; 4],
    ) -> Result<()> {
        unsafe {
            self.stream
                .launch_builder(&self.matmul_2x2)
                .arg(input)
                .arg(output)
                .arg(&w[0])
                .arg(&w[1])
                .arg(&w[2])
                .arg(&w[3])
                .launch(LaunchConfig::for_num_elems(4))?;
        }
        Ok(())
    }

    /// Run a fully resident Llama-shaped block.  Each logical layer uses the
    /// same attention/FFN kernels; activation buffers ping-pong without any
    /// host round trip.  The caller exports only after the entire block.
    pub fn block_layers(
        &self,
        witness: &mut TinyResidentDeviceWitness,
        layers: usize,
    ) -> Result<()> {
        ensure!(layers > 0, "resident block must contain at least one layer");
        if resident_metrics_enabled() && witness.inference_start.is_none() {
            witness.inference_start = Some(
                self.stream
                    .record_event(Some(sys::CUevent_flags::CU_EVENT_DEFAULT))?,
            );
        }
        for layer in 0..layers {
            if layer % 2 == 0 {
                self.launch_attention(&witness.input, &mut witness.attention)?;
                self.launch_ffn(&witness.attention, &mut witness.output)?;
                witness.final_is_output = true;
            } else {
                self.launch_attention(&witness.output, &mut witness.attention)?;
                self.launch_ffn(&witness.attention, &mut witness.input)?;
                witness.final_is_output = false;
            }
            witness.metrics.attention_launches += 1;
            witness.metrics.ffn_launches += 1;
        }
        if resident_metrics_enabled() {
            witness.inference_end = Some(
                self.stream
                    .record_event(Some(sys::CUevent_flags::CU_EVENT_DEFAULT))?,
            );
        }
        Ok(())
    }

    /// Compatibility convenience for the provider-only smoke test.
    pub fn execute(&self, input: &[i32]) -> Result<TinyResidentDeviceWitness> {
        let mut witness = self.import(input)?;
        self.attention(&mut witness)?;
        self.ffn(&mut witness)?;
        Ok(witness)
    }

    /// The only materialization boundary.  This is one D2H of the final FFN
    /// output and does not invalidate the reusable device witness.
    pub fn export(&self, witness: &mut TinyResidentDeviceWitness) -> Result<Vec<i32>> {
        // Sequence the only D2H after both resident kernels. This matters for
        // the 4096-word profile, where an asynchronous copy can otherwise
        // observe the FFN buffer before its launch completes.
        self.stream.synchronize()?;
        if let (Some(start), Some(end)) = (&witness.inference_start, &witness.inference_end) {
            witness.metrics.inference_gpu_ns =
                (f64::from(start.elapsed_ms(end)?) * 1_000_000.0).round() as u64;
        }
        let output = if witness.final_is_output {
            self.stream.memcpy_dtov(&witness.output)?
        } else {
            self.stream.memcpy_dtov(&witness.input)?
        };
        ensure!(
            output.len() == RESIDENT_WORDS,
            "resident output length changed"
        );
        witness.metrics.d2h_bytes = (RESIDENT_WORDS * std::mem::size_of::<i32>()) as u64;
        if resident_metrics_enabled() {
            RESIDENT_SESSIONS.fetch_add(1, Ordering::Relaxed);
            RESIDENT_H2D_BYTES.fetch_add(witness.metrics.h2d_bytes, Ordering::Relaxed);
            RESIDENT_D2H_BYTES.fetch_add(witness.metrics.d2h_bytes, Ordering::Relaxed);
            RESIDENT_MOCK_WITNESS_D2H_BYTES
                .fetch_add(witness.metrics.mock_witness_d2h_bytes, Ordering::Relaxed);
            RESIDENT_ATTENTION_LAUNCHES.fetch_add(
                u64::from(witness.metrics.attention_launches),
                Ordering::Relaxed,
            );
            RESIDENT_FFN_LAUNCHES
                .fetch_add(u64::from(witness.metrics.ffn_launches), Ordering::Relaxed);
            RESIDENT_PEAK_DEVICE_BYTES
                .fetch_max(witness.metrics.peak_device_bytes, Ordering::Relaxed);
            RESIDENT_INFERENCE_GPU_NS
                .fetch_add(witness.metrics.inference_gpu_ns, Ordering::Relaxed);
        }
        Ok(output)
    }
}

const RESIDENT_PTX_TEMPLATE: &str = r#"
.version 7.0
.target sm_52
.address_size 64
.visible .entry tiny_attention(.param .u64 input, .param .u64 output) {
 .reg .pred %p<2>; .reg .b32 %r<8>; .reg .b64 %rd<6>;
 ld.param.u64 %rd1, [input]; ld.param.u64 %rd2, [output];
 mov.u32 %r1, %tid.x; mov.u32 %r4, %ctaid.x; mov.u32 %r5, %ntid.x; mad.lo.u32 %r1, %r4, %r5, %r1;
 setp.ge.u32 %p1, %r1, RESIDENT_WORDS; @%p1 bra DONE;
 mul.wide.u32 %rd3, %r1, 4; add.u64 %rd4, %rd1, %rd3; ld.global.s32 %r2, [%rd4];
 setp.lt.u32 %p1, %r1, RESIDENT_HIDDEN; @%p1 bra STORE;
 add.u64 %rd5, %rd1, %rd3; add.u64 %rd5, %rd5, -RESIDENT_HIDDEN_BYTES; ld.global.s32 %r3, [%rd5]; add.s32 %r2, %r2, %r3;
STORE: add.u64 %rd4, %rd2, %rd3; st.global.s32 [%rd4], %r2;
DONE: ret; }
.visible .entry tiny_ffn(.param .u64 input, .param .u64 output) {
 .reg .pred %p<2>; .reg .b32 %r<6>; .reg .b64 %rd<5>;
 ld.param.u64 %rd1, [input]; ld.param.u64 %rd2, [output]; mov.u32 %r1, %tid.x; mov.u32 %r4, %ctaid.x; mov.u32 %r5, %ntid.x; mad.lo.u32 %r1, %r4, %r5, %r1;
 setp.ge.u32 %p1, %r1, RESIDENT_WORDS; @%p1 bra DONE;
 mul.wide.u32 %rd3, %r1, 4; add.u64 %rd4, %rd1, %rd3; ld.global.s32 %r2, [%rd4];
 mul.lo.s32 %r2, %r2, 2; add.s32 %r2, %r2, 1; add.u64 %rd4, %rd2, %rd3; st.global.s32 [%rd4], %r2;
DONE: ret; }
.visible .entry tiny_matmul_2x2(
 .param .u64 input, .param .u64 output,
 .param .s32 w00, .param .s32 w01, .param .s32 w10, .param .s32 w11) {
 .reg .pred %p<2>; .reg .b32 %r<14>; .reg .b64 %rd<7>;
 ld.param.u64 %rd1, [input]; ld.param.u64 %rd2, [output];
 ld.param.s32 %r6, [w00]; ld.param.s32 %r7, [w01];
 ld.param.s32 %r8, [w10]; ld.param.s32 %r9, [w11];
 mov.u32 %r1, %tid.x; setp.ge.u32 %p1, %r1, 4; @%p1 bra MM_DONE;
 shr.u32 %r2, %r1, 1; and.b32 %r3, %r1, 1;
 mul.lo.u32 %r4, %r2, 2; mul.wide.u32 %rd3, %r4, 4;
 add.u64 %rd4, %rd1, %rd3; ld.global.s32 %r10, [%rd4];
 add.u64 %rd5, %rd4, 4; ld.global.s32 %r11, [%rd5];
 setp.eq.u32 %p1, %r3, 0; @%p1 bra MM_COL0;
 mul.lo.s32 %r12, %r10, %r7; mad.lo.s32 %r12, %r11, %r9, %r12; bra MM_STORE;
MM_COL0: mul.lo.s32 %r12, %r10, %r6; mad.lo.s32 %r12, %r11, %r8, %r12;
MM_STORE: mul.wide.u32 %rd6, %r1, 4; add.u64 %rd6, %rd2, %rd6; st.global.s32 [%rd6], %r12;
MM_DONE: ret; }
.visible .entry tiny_write_2x2(
 .param .u64 output,
 .param .s32 v0, .param .s32 v1, .param .s32 v2, .param .s32 v3) {
 .reg .pred %p<5>; .reg .b32 %r<7>; .reg .b64 %rd<4>;
 ld.param.u64 %rd1, [output]; mov.u32 %r1, %tid.x;
 setp.ge.u32 %p1, %r1, 4; @%p1 bra WRITE_DONE;
 ld.param.s32 %r2, [v0]; ld.param.s32 %r3, [v1];
 ld.param.s32 %r4, [v2]; ld.param.s32 %r5, [v3];
 setp.eq.u32 %p2, %r1, 1; @%p2 mov.b32 %r2, %r3;
 setp.eq.u32 %p3, %r1, 2; @%p3 mov.b32 %r2, %r4;
 setp.eq.u32 %p4, %r1, 3; @%p4 mov.b32 %r2, %r5;
 mul.wide.u32 %rd2, %r1, 4; add.u64 %rd3, %rd1, %rd2; st.global.s32 [%rd3], %r2;
WRITE_DONE: ret; }
"#;

#[cfg(feature = "llama-tiny")]
fn flatten_2x2(value: [[i32; 2]; 2]) -> [i32; 4] {
    [value[0][0], value[0][1], value[1][0], value[1][1]]
}

#[cfg(feature = "llama-tiny")]
fn provider_trace() -> crate::tensor::llama_tiny::LlamaTinyLayerTrace {
    crate::tensor::llama_tiny::LlamaTinyLayerTrace {
        input_energy: [20_480, 20_480],
        input_norm: [[8_697, -3_262], [4_349, 6_523]],
        q_projection: [[11_959, 2_173], [-2_174, 17_395]],
        k_projection: [[5_435, -11_959], [10_872, 2_174]],
        v: [[142, -4], [55, 93]],
        q_rope: [[11_053, 5_065], [-10_247, 14_222]],
        k_rope: [[8_227, -10_245], [8_498, 7_120]],
        qk_scores: [[39_042_106, 129_991_194], [-230_006_459, 14_181_634]],
        shifted_magnitudes: [
            [90_949_088, 0],
            [18_085_893_153_810_678_717, 18_085_893_153_566_490_624],
        ],
        probabilities: [[1 << 20, 0], [1 << 19, 1 << 19]],
        attention: [[142, -4], [99, 45]],
        attention_projection: [[71, 16], [47, 29]],
        attention_residual: [[199, -48], [111, 157]],
        post_energy: [41_905, 36_970],
        post_norm: [[10_260, -2_475], [6_025, 8_521]],
        gate: [[19, -14], [16, 7]],
        up: [[2_642, 177], [1_240, 1_974]],
        swiglu: [[152, -112], [128, 56]],
        down_input: [[6, 0], [2, 2]],
        down: [[2, 0], [0, 0]],
        output: [[201, -48], [111, 157]],
    }
}

#[cfg(feature = "llama-tiny")]
fn layer_snapshot(
    trace: crate::tensor::llama_tiny::LlamaTinyLayerTrace,
) -> Result<crate::tensor::TensorLlamaTinyLayerWitness> {
    use crate::tensor::{TensorBatchedMatMul2x2Witness, llama_tiny as tiny};

    fn matrix(a: [[i32; 2]; 2], w: [[i32; 2]; 2]) -> Result<TensorBatchedMatMul2x2Witness> {
        let mut quotient = [[0_i16; 2]; 2];
        let mut remainder = [[0_u16; 2]; 2];
        for row in 0..2 {
            for col in 0..2 {
                let product = (0..2)
                    .map(|inner| i64::from(a[row][inner]) * i64::from(w[inner][col]))
                    .sum::<i64>();
                quotient[row][col] = i16::try_from(product.div_euclid(1 << 16))?;
                remainder[row][col] = product.rem_euclid(1 << 16) as u16;
            }
        }
        Ok(TensorBatchedMatMul2x2Witness {
            a,
            w,
            quotient,
            remainder,
        })
    }

    Ok(crate::tensor::TensorLlamaTinyLayerWitness {
        trace,
        matrices: [
            matrix(trace.input_norm, tiny::Q_WEIGHT)?,
            matrix(trace.input_norm, tiny::K_WEIGHT)?,
            matrix(trace.input_norm, tiny::V_WEIGHT)?,
            matrix(
                trace.q_rope,
                [
                    [trace.k_rope[0][0], trace.k_rope[1][0]],
                    [trace.k_rope[0][1], trace.k_rope[1][1]],
                ],
            )?,
            matrix(trace.probabilities, trace.v)?,
            matrix(trace.attention, tiny::O_WEIGHT)?,
            matrix(trace.post_norm, tiny::GATE_WEIGHT)?,
            matrix(trace.post_norm, tiny::UP_WEIGHT)?,
            matrix(trace.down_input, tiny::DOWN_WEIGHT)?,
        ],
    })
}

fn resident_ptx() -> String {
    RESIDENT_PTX_TEMPLATE
        .replace(
            "RESIDENT_HIDDEN_BYTES",
            &(RESIDENT_WORDS / 2 * 4).to_string(),
        )
        .replace("RESIDENT_HIDDEN", &(RESIDENT_WORDS / 2).to_string())
        .replace("RESIDENT_WORDS", &RESIDENT_WORDS.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cuda_tiny_attention_to_ffn_is_resident_and_matches_cpu() {
        let provider = TinyResidentCudaProvider::new(0).expect("CUDA tiny provider");
        let input = [3, -5, 7, -11];
        let mut witness = provider.execute(&input).expect("one H2D and two launches");
        assert_eq!(witness.metrics().h2d_bytes, 16);
        assert_eq!(witness.metrics().d2h_bytes, 0);
        assert_eq!(witness.metrics().intermediate_h2d_bytes, 0);
        assert_eq!(witness.metrics().intermediate_d2h_bytes, 0);
        assert_eq!(witness.metrics().attention_launches, 1);
        assert_eq!(witness.metrics().ffn_launches, 1);
        assert_eq!(
            witness.device_words(),
            if cfg!(feature = "llama-tiny") {
                156
            } else {
                12
            }
        );
        let output = provider.export(&mut witness).expect("one final D2H");
        assert_eq!(output, resident_attention_to_ffn_cpu(&input));
        assert_eq!(witness.metrics().d2h_bytes, 16);
        assert_eq!(witness.metrics().intermediate_h2d_bytes, 0);
        assert_eq!(witness.metrics().intermediate_d2h_bytes, 0);
    }
}
