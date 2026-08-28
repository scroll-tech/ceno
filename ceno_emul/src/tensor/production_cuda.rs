//! CUDA oracle for one proof-bound K11008 production cell.
//!
//! The CPU/AIR relation remains authoritative.  This provider retains its input,
//! opened weights, and raw dot result on device until the caller exports it.

use anyhow::{Result, ensure};
use cudarc::{
    driver::{CudaContext, CudaFunction, CudaSlice, CudaStream, LaunchConfig, PushKernelArg},
    nvrtc::Ptx,
};
use std::sync::Arc;

pub const K11008: usize = 11_008;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct K11008CudaMetrics {
    pub h2d_bytes: u64,
    pub d2h_bytes: u64,
    pub launches: u32,
}

pub struct K11008CudaWitness {
    input: CudaSlice<i32>,
    weights: CudaSlice<i32>,
    dot: CudaSlice<i64>,
    metrics: K11008CudaMetrics,
}
impl K11008CudaWitness {
    pub fn metrics(&self) -> K11008CudaMetrics {
        self.metrics
    }
    pub fn device_words(&self) -> usize {
        self.input.len() + self.weights.len() + self.dot.len()
    }
}

pub struct K11008CudaProvider {
    stream: Arc<CudaStream>,
    dot: CudaFunction,
}
impl K11008CudaProvider {
    pub fn new(device: usize) -> Result<Self> {
        let context = CudaContext::new(device)?;
        let module = context.load_module(Ptx::from_src(PTX))?;
        Ok(Self {
            stream: context.default_stream(),
            dot: module.load_function("k11008_dot")?,
        })
    }
    pub fn execute(&self, input: &[i32], weights: &[i32]) -> Result<K11008CudaWitness> {
        ensure!(
            input.len() == K11008 && weights.len() == K11008,
            "K11008 CUDA shape mismatch"
        );
        let input = self.stream.memcpy_stod(input)?;
        let weights = self.stream.memcpy_stod(weights)?;
        let dot = self.stream.alloc_zeros::<i64>(1)?;
        let mut w = K11008CudaWitness {
            input,
            weights,
            dot,
            metrics: K11008CudaMetrics {
                h2d_bytes: (2 * K11008 * 4) as u64,
                ..Default::default()
            },
        };
        unsafe {
            self.stream
                .launch_builder(&self.dot)
                .arg(&w.input)
                .arg(&w.weights)
                .arg(&mut w.dot)
                .launch(LaunchConfig::for_num_elems(1))?;
        }
        w.metrics.launches = 1;
        Ok(w)
    }
    pub fn export(&self, witness: &mut K11008CudaWitness) -> Result<i64> {
        let dot = self.stream.memcpy_dtov(&witness.dot)?;
        self.stream.synchronize()?;
        ensure!(dot.len() == 1, "K11008 CUDA output length changed");
        witness.metrics.d2h_bytes = 8;
        Ok(dot[0])
    }
}

const PTX: &str = r#".version 7.0
.target sm_52
.address_size 64
.visible .entry k11008_dot(.param .u64 a,.param .u64 b,.param .u64 out) {
 .reg .pred %p<2>; .reg .b32 %r<5>; .reg .b64 %rd<12>;
 ld.param.u64 %rd1,[a]; ld.param.u64 %rd2,[b]; ld.param.u64 %rd3,[out];
 mov.u64 %rd4,0; mov.u32 %r1,0;
L: setp.ge.u32 %p1,%r1,11008; @%p1 bra D;
 mul.wide.u32 %rd5,%r1,4; add.u64 %rd6,%rd1,%rd5; add.u64 %rd7,%rd2,%rd5;
 ld.global.s32 %r2,[%rd6]; ld.global.s32 %r3,[%rd7]; cvt.s64.s32 %rd8,%r2; cvt.s64.s32 %rd9,%r3;
 mul.lo.s64 %rd10,%rd8,%rd9; add.s64 %rd4,%rd4,%rd10; add.u32 %r1,%r1,1; bra L;
D: st.global.s64 [%rd3],%rd4; ret; }"#;
