#[cfg(feature = "gpu")]
pub mod add;
#[cfg(all(feature = "gpu", feature = "u16limb_circuit"))]
pub mod addi;
#[cfg(all(feature = "gpu", feature = "u16limb_circuit"))]
pub mod logic_i;
#[cfg(feature = "gpu")]
pub mod logic_r;
#[cfg(feature = "gpu")]
pub mod lw;
#[cfg(feature = "gpu")]
pub mod sub;
#[cfg(feature = "gpu")]
pub mod witgen_gpu;
