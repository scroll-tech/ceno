//! Guest ABI for Ceno tensor ecalls.

/// Local experimental ecall number for the Gate-2 tensor MatMul slice.
///
/// This intentionally does not modify the external `ceno_syscall` crate. The
/// number must move there before the ABI is declared stable.
pub const TENSOR_MATMUL_V1: u32 = 0x00ff_0001;
pub const TENSOR_RMS_LOOKUP_V1: u32 = 0x00ff_0002;
pub const TENSOR_ATTENTION_REDUCED_V1: u32 = 0x00ff_0003;
pub const TENSOR_ATTENTION_BLOCK_REDUCED_V1: u32 = 0x00ff_0004;
pub const TENSOR_FFN_BLOCK_REDUCED_V1: u32 = 0x00ff_0005;
pub const TENSOR_MATMUL_HIDDEN_V1: u32 = 0x00ff_0006;
pub const TENSOR_MATMUL_INTERMEDIATE_V1: u32 = 0x00ff_0007;
pub const TENSOR_ABI_V1: u32 = 1;

/// Statically-shaped matrix multiplication descriptor.
///
/// Addresses are RV32 guest addresses. A registered `signature_id` fixes the
/// actual shape; the dimensions are redundant values checked by the ecall.
#[repr(C, align(64))]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TensorMatMulDescV1 {
    pub abi_version: u32,
    pub flags: u32,
    pub signature_id: u32,
    pub quantization_id: u32,
    pub input_ptr: u32,
    pub output_ptr: u32,
    pub m: u32,
    pub k: u32,
    pub n: u32,
    pub input_stride: u32,
    pub output_stride: u32,
    pub weight_tensor_id: u32,
    pub weight_tile_id: u32,
    pub model_root_ptr: u32,
    pub reserved: [u32; 2],
}

const _: () = assert!(core::mem::size_of::<TensorMatMulDescV1>() == 64);
const _: () = assert!(core::mem::align_of::<TensorMatMulDescV1>() == 64);

/// Production-width, one-output-cell MatMul descriptor.
///
/// The ecall number fixes `k` (4096 or 11008). `first_weight_tile` and
/// `weight_tile_count` name the complete, ordered sparse opening range.  The
/// latter is redundant and checked so guest execution, shard admission and
/// proof assignment cannot disagree about the atomic domain.
#[repr(C, align(64))]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TensorProductionMatMulDescV1 {
    pub abi_version: u32,
    pub commitment_profile: u32,
    pub quantization_id: u32,
    pub signature_id: u32,
    pub input_ptr: u32,
    pub output_ptr: u32,
    pub weight_tensor_id: u32,
    pub first_weight_tile: u32,
    pub weight_tile_count: u32,
    pub rescale_shift: u32,
    pub model_root_ptr: u32,
    pub input_stride: u32,
    pub output_stride: u32,
    pub reserved: [u32; 3],
}

const _: () = assert!(core::mem::size_of::<TensorProductionMatMulDescV1>() == 64);
const _: () = assert!(core::mem::align_of::<TensorProductionMatMulDescV1>() == 64);

#[inline(always)]
unsafe fn tensor_production_matmul_v1(desc: &TensorProductionMatMulDescV1, ecall: u32) {
    #[cfg(target_arch = "riscv32")]
    unsafe {
        core::arch::asm!(
            "ecall",
            in("a0") desc as *const TensorProductionMatMulDescV1 as u32,
            in("t0") ecall,
        );
    }
    #[cfg(not(target_arch = "riscv32"))]
    {
        let _ = (desc, ecall);
        panic!("production tensor MatMul is only available in an RV32 guest");
    }
}

/// # Safety
/// Descriptor pointers must address the statically required guest regions.
#[inline(always)]
pub unsafe fn tensor_matmul_hidden_v1(desc: &TensorProductionMatMulDescV1) {
    unsafe { tensor_production_matmul_v1(desc, TENSOR_MATMUL_HIDDEN_V1) }
}

/// # Safety
/// Descriptor pointers must address the statically required guest regions.
#[inline(always)]
pub unsafe fn tensor_matmul_intermediate_v1(desc: &TensorProductionMatMulDescV1) {
    unsafe { tensor_production_matmul_v1(desc, TENSOR_MATMUL_INTERMEDIATE_V1) }
}

/// Invoke the experimental tensor MatMul ecall.
///
/// # Safety
///
/// Every pointer in `desc` must refer to a valid, suitably sized guest-memory
/// region for its statically registered signature.
#[inline(always)]
pub unsafe fn tensor_matmul_v1(desc: &TensorMatMulDescV1) {
    #[cfg(target_arch = "riscv32")]
    unsafe {
        core::arch::asm!(
            "ecall",
            in("a0") desc as *const TensorMatMulDescV1 as u32,
            in("t0") TENSOR_MATMUL_V1,
        );
    }
    #[cfg(not(target_arch = "riscv32"))]
    {
        let _ = desc;
        panic!("tensor_matmul_v1 is only available in an RV32 guest");
    }
}

#[repr(C, align(32))]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TensorRmsLookupDescV1 {
    pub abi_version: u32,
    pub profile_id: u32,
    pub table_id: u32,
    pub input_ptr: u32,
    pub output_ptr: u32,
    pub reserved: [u32; 3],
}

/// Gate-3's statically shaped two-token causal segmented-attention call.
///
/// This deliberately exposes every preprocessing choice used by zkLLM's
/// integer relation.  A later production descriptor may replace the fixed
/// shape, but must not make these identities implicit.
#[repr(C, align(128))]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TensorAttentionReducedDescV1 {
    pub abi_version: u32,
    pub profile_id: u32,
    pub rescale_shift_id: u32,
    pub softmax_table_id: u32,
    pub softmax_table_commitment: [u32; 8],
    pub q_ptr: u32,
    pub k_ptr: u32,
    pub v_ptr: u32,
    pub output_ptr: u32,
    pub query_start: u32,
    pub key_start: u32,
    pub valid_key_length: u32,
    pub segment_start_accumulator: [u32; 2],
    pub row_shifts: [i32; 2],
    pub reserved: [u32; 9],
}

/// Common descriptor for Gate-4's two reduced shard-atomic physical blocks.
/// `weight_roots_ptr` addresses four roots for attention and three for FFN.
#[repr(C, align(128))]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TensorBlockReducedDescV1 {
    pub abi_version: u32,
    pub profile_id: u32,
    pub signature_id: u32,
    pub quantization_id: u32,
    pub input_ptr: u32,
    pub output_ptr: u32,
    pub weight_roots_ptr: u32,
    pub weight_tensor_id: u32,
    pub table_id: u32,
    pub table_commitment: [u32; 8],
    pub layer_id: u32,
    pub reserved: [u32; 6],
}

const _: () = assert!(core::mem::size_of::<TensorBlockReducedDescV1>() == 128);
const _: () = assert!(core::mem::align_of::<TensorBlockReducedDescV1>() == 128);

const _: () = assert!(core::mem::size_of::<TensorAttentionReducedDescV1>() == 128);
const _: () = assert!(core::mem::align_of::<TensorAttentionReducedDescV1>() == 128);

/// Execute the registered two-token causal segmented-attention relation.
///
/// # Safety
/// All four pointers must address four readable/writable guest `i32` words.
#[inline(always)]
pub unsafe fn tensor_attention_reduced_v1(desc: &TensorAttentionReducedDescV1) {
    #[cfg(target_arch = "riscv32")]
    unsafe {
        core::arch::asm!(
            "ecall",
            in("a0") desc as *const TensorAttentionReducedDescV1 as u32,
            in("t0") TENSOR_ATTENTION_REDUCED_V1,
        );
    }
    #[cfg(not(target_arch = "riscv32"))]
    {
        let _ = desc;
        panic!("tensor_attention_reduced_v1 is only available in an RV32 guest");
    }
}

/// Execute the registered reduced fused attention block.
///
/// # Safety
/// Descriptor pointers must address the fixed registered X/Y/root regions.
#[inline(always)]
pub unsafe fn tensor_attention_block_reduced_v1(desc: &TensorBlockReducedDescV1) {
    #[cfg(target_arch = "riscv32")]
    unsafe {
        core::arch::asm!(
            "ecall",
            in("a0") desc as *const TensorBlockReducedDescV1 as u32,
            in("t0") TENSOR_ATTENTION_BLOCK_REDUCED_V1,
        );
    }
    #[cfg(not(target_arch = "riscv32"))]
    {
        let _ = desc;
        panic!("tensor_attention_block_reduced_v1 is only available in an RV32 guest");
    }
}

/// Execute the registered reduced fused FFN block.
///
/// # Safety
/// Descriptor pointers must address the fixed registered X/Y/root regions.
#[inline(always)]
pub unsafe fn tensor_ffn_block_reduced_v1(desc: &TensorBlockReducedDescV1) {
    #[cfg(target_arch = "riscv32")]
    unsafe {
        core::arch::asm!(
            "ecall",
            in("a0") desc as *const TensorBlockReducedDescV1 as u32,
            in("t0") TENSOR_FFN_BLOCK_REDUCED_V1,
        );
    }
    #[cfg(not(target_arch = "riscv32"))]
    {
        let _ = desc;
        panic!("tensor_ffn_block_reduced_v1 is only available in an RV32 guest");
    }
}

const _: () = assert!(core::mem::size_of::<TensorRmsLookupDescV1>() == 32);
const _: () = assert!(core::mem::align_of::<TensorRmsLookupDescV1>() == 32);

/// Apply one statically registered reduced RMS fixed-table lookup.
///
/// # Safety
/// `input_ptr` and `output_ptr` must point to readable/writable guest words.
#[inline(always)]
pub unsafe fn tensor_rms_lookup_v1(desc: &TensorRmsLookupDescV1) {
    #[cfg(target_arch = "riscv32")]
    unsafe {
        core::arch::asm!(
            "ecall",
            in("a0") desc as *const TensorRmsLookupDescV1 as u32,
            in("t0") TENSOR_RMS_LOOKUP_V1,
        );
    }
    #[cfg(not(target_arch = "riscv32"))]
    {
        let _ = desc;
        panic!("tensor_rms_lookup_v1 is only available in an RV32 guest");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn descriptor_layout_is_stable() {
        assert_eq!(core::mem::size_of::<TensorMatMulDescV1>(), 64);
        assert_eq!(core::mem::align_of::<TensorMatMulDescV1>(), 64);
        assert_eq!(core::mem::size_of::<TensorRmsLookupDescV1>(), 32);
        assert_eq!(core::mem::align_of::<TensorRmsLookupDescV1>(), 32);
        assert_eq!(core::mem::size_of::<TensorAttentionReducedDescV1>(), 128);
        assert_eq!(core::mem::align_of::<TensorAttentionReducedDescV1>(), 128);
        assert_eq!(core::mem::size_of::<TensorBlockReducedDescV1>(), 128);
        assert_eq!(core::mem::align_of::<TensorBlockReducedDescV1>(), 128);
    }
}
