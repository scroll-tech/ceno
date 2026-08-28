//! Tiny CUDA resident attention-to-FFN provider.
//!
//! This is deliberately a narrow transition gate: it implements the reduced
//! `[sequence=2, hidden=2]` integer path only.  The input is uploaded once,
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

pub const TINY_RESIDENT_WORDS: usize = 4;

/// Exact CPU oracle for the tiny causal attention followed by FFN transition.
/// Tokens are `[t0h0, t0h1, t1h0, t1h1]`. Attention keeps token zero and
/// adds it to token one; FFN doubles every lane and adds one.  It is purposely
/// integer-only so the CUDA witness and CPU oracle cannot drift on rounding.
pub fn tiny_attention_to_ffn_cpu(input: [i32; TINY_RESIDENT_WORDS]) -> [i32; TINY_RESIDENT_WORDS] {
    let attention = [
        input[0],
        input[1],
        input[2].wrapping_add(input[0]),
        input[3].wrapping_add(input[1]),
    ];
    attention.map(|word| word.wrapping_mul(2).wrapping_add(1))
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
        let module = context.load_module(Ptx::from_src(TINY_RESIDENT_PTX))?;
        Ok(Self {
            stream: context.default_stream(),
            attention: module.load_function("tiny_attention")?,
            ffn: module.load_function("tiny_ffn")?,
        })
    }

    /// Upload the input and retain all device buffers for the resident
    /// `IMPORT_BEGIN -> ATTENTION -> FFN -> EXPORT_END` lifetime.
    pub fn import(&self, input: [i32; TINY_RESIDENT_WORDS]) -> Result<TinyResidentDeviceWitness> {
        let input = self.stream.memcpy_stod(&input)?;
        let attention = self.stream.alloc_zeros::<i32>(TINY_RESIDENT_WORDS)?;
        let output = self.stream.alloc_zeros::<i32>(TINY_RESIDENT_WORDS)?;
        Ok(TinyResidentDeviceWitness {
            input,
            attention,
            output,
            metrics: TinyResidentTransferMetrics {
                h2d_bytes: (TINY_RESIDENT_WORDS * std::mem::size_of::<i32>()) as u64,
                d2h_bytes: 0,
                intermediate_h2d_bytes: 0,
                intermediate_d2h_bytes: 0,
                attention_launches: 0,
                ffn_launches: 0,
                peak_device_bytes: (3 * TINY_RESIDENT_WORDS * std::mem::size_of::<i32>()) as u64,
            },
        })
    }

    /// Execute attention using only resident device buffers.
    pub fn attention(&self, witness: &mut TinyResidentDeviceWitness) -> Result<()> {
        unsafe {
            self.stream
                .launch_builder(&self.attention)
                .arg(&witness.input)
                .arg(&mut witness.attention)
                .launch(LaunchConfig::for_num_elems(TINY_RESIDENT_WORDS as u32))?;
        }
        witness.metrics.attention_launches += 1;
        Ok(())
    }

    /// Execute FFN using the resident attention output. No host transfer is
    /// permitted between this and `attention`.
    pub fn ffn(&self, witness: &mut TinyResidentDeviceWitness) -> Result<()> {
        unsafe {
            self.stream
                .launch_builder(&self.ffn)
                .arg(&witness.attention)
                .arg(&mut witness.output)
                .launch(LaunchConfig::for_num_elems(TINY_RESIDENT_WORDS as u32))?;
        }
        witness.metrics.ffn_launches += 1;
        Ok(())
    }

    /// Compatibility convenience for the provider-only smoke test.
    pub fn execute(&self, input: [i32; TINY_RESIDENT_WORDS]) -> Result<TinyResidentDeviceWitness> {
        let mut witness = self.import(input)?;
        self.attention(&mut witness)?;
        self.ffn(&mut witness)?;
        Ok(witness)
    }

    /// The only materialization boundary.  This is one D2H of the final FFN
    /// output and does not invalidate the reusable device witness.
    pub fn export(
        &self,
        witness: &mut TinyResidentDeviceWitness,
    ) -> Result<[i32; TINY_RESIDENT_WORDS]> {
        let output = self.stream.memcpy_dtov(&witness.output)?;
        self.stream.synchronize()?;
        ensure!(
            output.len() == TINY_RESIDENT_WORDS,
            "tiny resident output length changed"
        );
        witness.metrics.d2h_bytes = (TINY_RESIDENT_WORDS * std::mem::size_of::<i32>()) as u64;
        Ok(output.try_into().expect("length checked"))
    }
}

const TINY_RESIDENT_PTX: &str = r#"
.version 7.0
.target sm_52
.address_size 64
.visible .entry tiny_attention(.param .u64 input, .param .u64 output) {
 .reg .pred %p<2>; .reg .b32 %r<6>; .reg .b64 %rd<6>;
 ld.param.u64 %rd1, [input]; ld.param.u64 %rd2, [output];
 mov.u32 %r1, %tid.x; setp.ge.u32 %p1, %r1, 4; @%p1 bra DONE;
 mul.wide.u32 %rd3, %r1, 4; add.u64 %rd4, %rd1, %rd3; ld.global.s32 %r2, [%rd4];
 setp.lt.u32 %p1, %r1, 2; @%p1 bra STORE;
 add.u64 %rd5, %rd1, %rd3; add.u64 %rd5, %rd5, -8; ld.global.s32 %r3, [%rd5]; add.s32 %r2, %r2, %r3;
STORE: add.u64 %rd4, %rd2, %rd3; st.global.s32 [%rd4], %r2;
DONE: ret; }
.visible .entry tiny_ffn(.param .u64 input, .param .u64 output) {
 .reg .pred %p<2>; .reg .b32 %r<4>; .reg .b64 %rd<5>;
 ld.param.u64 %rd1, [input]; ld.param.u64 %rd2, [output]; mov.u32 %r1, %tid.x;
 setp.ge.u32 %p1, %r1, 4; @%p1 bra DONE;
 mul.wide.u32 %rd3, %r1, 4; add.u64 %rd4, %rd1, %rd3; ld.global.s32 %r2, [%rd4];
 mul.lo.s32 %r2, %r2, 2; add.s32 %r2, %r2, 1; add.u64 %rd4, %rd2, %rd3; st.global.s32 [%rd4], %r2;
DONE: ret; }
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cuda_tiny_attention_to_ffn_is_resident_and_matches_cpu() {
        let provider = TinyResidentCudaProvider::new(0).expect("CUDA tiny provider");
        let input = [3, -5, 7, -11];
        let mut witness = provider.execute(input).expect("one H2D and two launches");
        assert_eq!(witness.metrics().h2d_bytes, 16);
        assert_eq!(witness.metrics().d2h_bytes, 0);
        assert_eq!(witness.metrics().intermediate_h2d_bytes, 0);
        assert_eq!(witness.metrics().intermediate_d2h_bytes, 0);
        assert_eq!(witness.metrics().attention_launches, 1);
        assert_eq!(witness.metrics().ffn_launches, 1);
        assert_eq!(witness.device_words(), 12);
        let output = provider.export(&mut witness).expect("one final D2H");
        assert_eq!(output, tiny_attention_to_ffn_cpu(input));
        assert_eq!(witness.metrics().d2h_bytes, 16);
        assert_eq!(witness.metrics().intermediate_h2d_bytes, 0);
        assert_eq!(witness.metrics().intermediate_d2h_bytes, 0);
    }
}
