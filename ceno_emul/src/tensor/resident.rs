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
        self.input.len() + self.attention.len() + self.output.len()
    }
}

pub struct TinyResidentCudaProvider {
    stream: Arc<CudaStream>,
    attention: CudaFunction,
    ffn: CudaFunction,
    matmul_2x2: CudaFunction,
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
        Ok(TinyResidentDeviceWitness {
            input,
            attention,
            output,
            final_is_output: false,
            metrics: TinyResidentTransferMetrics {
                h2d_bytes: (RESIDENT_WORDS * std::mem::size_of::<i32>()) as u64,
                d2h_bytes: 0,
                intermediate_h2d_bytes: 0,
                intermediate_d2h_bytes: 0,
                attention_launches: 0,
                ffn_launches: 0,
                peak_device_bytes: (3 * RESIDENT_WORDS * std::mem::size_of::<i32>()) as u64,
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
    pub fn matmul_2x2(
        &self,
        witness: &mut TinyResidentDeviceWitness,
        weights: [[i8; 2]; 2],
        is_attention: bool,
    ) -> Result<()> {
        let w = [
            i32::from(weights[0][0]),
            i32::from(weights[0][1]),
            i32::from(weights[1][0]),
            i32::from(weights[1][1]),
        ];
        if is_attention {
            self.launch_matmul(&witness.input, &mut witness.attention, w)?;
            witness.metrics.attention_launches += 1;
        } else {
            self.launch_matmul(&witness.attention, &mut witness.output, w)?;
            witness.final_is_output = true;
            witness.metrics.ffn_launches += 1;
        }
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
"#;

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
        assert_eq!(witness.device_words(), 12);
        let output = provider.export(&mut witness).expect("one final D2H");
        assert_eq!(output, resident_attention_to_ffn_cpu(&input));
        assert_eq!(witness.metrics().d2h_bytes, 16);
        assert_eq!(witness.metrics().intermediate_h2d_bytes, 0);
        assert_eq!(witness.metrics().intermediate_d2h_bytes, 0);
    }
}
