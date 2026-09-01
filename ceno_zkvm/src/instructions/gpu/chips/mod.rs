pub mod add;
#[cfg(feature = "u16limb_circuit")]
pub mod addi;
#[cfg(feature = "u16limb_circuit")]
pub mod auipc;
#[cfg(feature = "u16limb_circuit")]
pub mod branch_cmp;
#[cfg(feature = "u16limb_circuit")]
pub mod branch_eq;
#[cfg(feature = "u16limb_circuit")]
pub mod div;
#[cfg(feature = "u16limb_circuit")]
pub mod jal;
#[cfg(feature = "u16limb_circuit")]
pub mod jalr;
pub mod keccak;
#[cfg(feature = "u16limb_circuit")]
pub mod load_sub;
#[cfg(feature = "u16limb_circuit")]
pub mod logic_i;
pub mod logic_r;
#[cfg(feature = "u16limb_circuit")]
pub mod lui;
pub mod lw;
#[cfg(feature = "u16limb_circuit")]
pub mod mul;
#[cfg(not(feature = "llama-tiny"))]
pub mod production_attention_boundary;
pub mod production_attention_matrix;
pub mod production_attention_softmax;
#[cfg(feature = "u16limb_circuit")]
pub mod sb;
pub mod secp256k1;
#[cfg(feature = "u16limb_circuit")]
pub mod sh;
pub mod shard_ram;
#[cfg(feature = "u16limb_circuit")]
pub mod shift_i;
#[cfg(feature = "u16limb_circuit")]
pub mod shift_r;
#[cfg(feature = "u16limb_circuit")]
pub mod slt;
#[cfg(feature = "u16limb_circuit")]
pub mod slti;
pub mod sub;
#[cfg(feature = "u16limb_circuit")]
pub mod sw;

pub(crate) fn log_production_allocation(
    owner: &str,
    witness_bytes: usize,
    structural_bytes: usize,
) {
    #[cfg(feature = "gpu")]
    if crate::scheme::gpu::should_log_gpu_memory() {
        crate::scheme::gpu::log_gpu_device_state(&format!("production_{owner}"));
        tracing::info!(
            target: "ceno_pipeline",
            phase = "production_gpu_allocation",
            owner,
            thread_id = ?std::thread::current().id(),
            witness_bytes,
            structural_bytes,
            total_bytes = witness_bytes.saturating_add(structural_bytes),
            "production GPU allocation ownership"
        );
    }
}
