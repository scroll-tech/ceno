#[cfg(feature = "gpu")]
pub mod add;
#[cfg(all(feature = "gpu", feature = "u16limb_circuit"))]
pub mod addi;
#[cfg(all(feature = "gpu", feature = "u16limb_circuit"))]
pub mod auipc;
#[cfg(all(feature = "gpu", feature = "u16limb_circuit"))]
pub mod jal;
#[cfg(all(feature = "gpu", feature = "u16limb_circuit"))]
pub mod logic_i;
#[cfg(feature = "gpu")]
pub mod logic_r;
#[cfg(all(feature = "gpu", feature = "u16limb_circuit"))]
pub mod lui;
#[cfg(feature = "gpu")]
pub mod lw;
#[cfg(all(feature = "gpu", feature = "u16limb_circuit"))]
pub mod shift_i;
#[cfg(all(feature = "gpu", feature = "u16limb_circuit"))]
pub mod shift_r;
#[cfg(all(feature = "gpu", feature = "u16limb_circuit"))]
pub mod slt;
#[cfg(all(feature = "gpu", feature = "u16limb_circuit"))]
pub mod slti;
#[cfg(feature = "gpu")]
pub mod sub;
#[cfg(all(feature = "gpu", feature = "u16limb_circuit"))]
pub mod branch_cmp;
#[cfg(all(feature = "gpu", feature = "u16limb_circuit"))]
pub mod jalr;
#[cfg(all(feature = "gpu", feature = "u16limb_circuit"))]
pub mod sw;
#[cfg(all(feature = "gpu", feature = "u16limb_circuit"))]
pub mod sh;
#[cfg(all(feature = "gpu", feature = "u16limb_circuit"))]
pub mod sb;
#[cfg(all(feature = "gpu", feature = "u16limb_circuit"))]
pub mod branch_eq;
#[cfg(feature = "gpu")]
pub mod witgen_gpu;
