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
    driver::{CudaContext, CudaFunction, CudaSlice, CudaStream, LaunchConfig, PushKernelArg},
    nvrtc::Ptx,
};
use std::sync::Arc;

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
}

impl TinyResidentCudaProvider {
    pub fn new(device_ordinal: usize) -> Result<Self> {
        let context = CudaContext::new(device_ordinal)?;
        let module = context.load_module(Ptx::from_src(resident_ptx()))?;
        Ok(Self {
            stream: context.default_stream(),
            attention: module.load_function("tiny_attention")?,
            ffn: module.load_function("tiny_ffn")?,
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
            },
        })
    }

    /// Execute attention using only resident device buffers.
    pub fn attention(&self, witness: &mut TinyResidentDeviceWitness) -> Result<()> {
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

    /// Run a fully resident Llama-shaped block.  Each logical layer uses the
    /// same attention/FFN kernels; activation buffers ping-pong without any
    /// host round trip.  The caller exports only after the entire block.
    pub fn block_layers(
        &self,
        witness: &mut TinyResidentDeviceWitness,
        layers: usize,
    ) -> Result<()> {
        ensure!(layers > 0, "resident block must contain at least one layer");
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
