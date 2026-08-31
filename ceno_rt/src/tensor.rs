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
/// Gate-5-only compact production topology reproducer.  This has the same
/// raw-ecall -> ordered tile -> finalize shape as hidden MatMul, but a small
/// K so GPU PCS iterations stay interactive.  It is not a stable ABI.
pub const TENSOR_MATMUL_GATE5_SMALL_HIDDEN_V1: u32 = 0x00ff_0008;
/// Tiny-only complete 2x2 matrix call used by the batched Tensor Core proof.
#[cfg(feature = "llama-tiny")]
pub const TENSOR_BATCHED_MATMUL_2X2_V1: u32 = 0x00ff_0009;
/// Reserved legacy lifecycle opcodes.  Resident handles deliberately do not
/// use separate begin/end calls: IMPORT_BEGIN and EXPORT_END are the bounds.
pub const TENSOR_IMPORT_BEGIN_V1: u32 = 0x00ff_000b;
pub const TENSOR_EXPORT_END_V1: u32 = 0x00ff_000c;
/// Tiny-only opaque-handle attention and FFN transitions.  These are distinct
/// from the pointer ABI: all activation bytes remain in TensorBus.
pub const TENSOR_HANDLE_ATTENTION_V1: u32 = 0x00ff_000d;
pub const TENSOR_HANDLE_FFN_V1: u32 = 0x00ff_000e;
/// Production row-boundary ABI. These distinct opcodes preserve the legacy
/// fixed-width v1/tiny ECALL circuits while sharing their descriptor layouts.
pub const TENSOR_PRODUCTION_IMPORT_BEGIN_V2: u32 = 0x00ff_000f;
pub const TENSOR_PRODUCTION_FULL_LAYER_V2: u32 = 0x00ff_0010;
pub const TENSOR_PRODUCTION_EXPORT_END_V2: u32 = 0x00ff_0011;
pub const TENSOR_ABI_V1: u32 = 1;
/// Tensor-space resident operators. Unlike v1, weight identity is logical and
/// no guest weight or hint address is accepted.
pub const TENSOR_ABI_V2: u32 = 2;
#[cfg(feature = "llama-tiny")]
pub const TENSOR_PROFILE_LLAMA_TINY: u32 = 1;
pub const TENSOR_PROFILE_LLAMA2_7B_FULL_LAYER: u32 = 2;
pub const TENSOR_LLAMA2_SEQUENCE: u32 = 2048;
pub const TENSOR_LLAMA2_HIDDEN: u32 = 4096;
pub const TENSOR_LLAMA2_HEADS: u32 = 32;
pub const TENSOR_LLAMA2_HEAD_DIM: u32 = 128;
pub const TENSOR_LLAMA2_HIDDEN_WORDS: u32 = TENSOR_LLAMA2_SEQUENCE * TENSOR_LLAMA2_HIDDEN;

/// Opaque TensorBus value identity. Device pointers never enter the guest ABI.
#[repr(C, align(8))]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct TensorHandleV1 {
    pub tensor_id: u64,
    pub version: u32,
    pub reserved: u32,
}

const _: () = assert!(core::mem::size_of::<TensorHandleV1>() == 16);

/// Explicit RAM-to-TensorBus boundary and resident-segment open. `meta_ptr`
/// identifies caller-owned shape/quantization metadata; TensorBus validates it
/// independently of RAM.
#[repr(C, align(32))]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TensorImportBeginDescV1 {
    pub abi_version: u32,
    pub flags: u32,
    pub input_ptr: u32,
    pub input_len: u32,
    pub meta_ptr: u32,
    pub meta_len: u32,
    pub output_handle_ptr: u32,
    pub reserved: u32,
}

/// Explicit TensorBus-to-RAM boundary and resident-segment close.
#[repr(C, align(32))]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TensorExportEndDescV1 {
    pub abi_version: u32,
    pub flags: u32,
    pub input_handle_ptr: u32,
    pub output_ptr: u32,
    pub output_len: u32,
    pub meta_ptr: u32,
    pub meta_len: u32,
    pub reserved: u32,
}

/// Fixed-width handle-to-handle operator descriptor.  The metadata is carried
/// explicitly so the constrained event binds the output shape/quantization.
#[repr(C, align(32))]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TensorHandleOpDescV1 {
    pub abi_version: u32,
    pub flags: u32,
    pub input_handle_ptr: u32,
    pub output_handle_ptr: u32,
    pub meta_ptr: u32,
    pub meta_len: u32,
    /// Canonical base of this resident block's guest hint window.  The
    /// current resident operators do not dereference it yet; it is bound by
    /// their fixed descriptor/RAM witness so a block cannot silently route to
    /// another block's declared window.
    pub hint_base: u32,
    pub reserved: u32,
}

const _: () = assert!(core::mem::size_of::<TensorHandleOpDescV1>() == 32);

/// Logical-weight handle operator. It deliberately occupies the same eight
/// words and uses the same attention/FFN ecall numbers as v1. Weight addresses
/// never enter the guest ABI: `(profile, layer, operator role)` selects the
/// proof-side HintRef instead.
#[repr(C, align(32))]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TensorHandleOpDescV2 {
    pub abi_version: u32,
    pub flags: u32,
    pub input_handle_ptr: u32,
    pub output_handle_ptr: u32,
    pub meta_ptr: u32,
    pub meta_len: u32,
    pub profile: u32,
    pub layer: u32,
}

const _: () = assert!(core::mem::size_of::<TensorHandleOpDescV2>() == 32);

const _: () = assert!(core::mem::size_of::<TensorImportBeginDescV1>() == 32);
const _: () = assert!(core::mem::size_of::<TensorExportEndDescV1>() == 32);

#[inline(always)]
unsafe fn tensor_segment_ecall_v1(desc: *const u8, ecall: u32) {
    #[cfg(target_arch = "riscv32")]
    unsafe {
        core::arch::asm!("ecall", in("a0") desc as u32, in("t0") ecall);
    }
    #[cfg(not(target_arch = "riscv32"))]
    {
        let _ = (desc, ecall);
        panic!("TensorBus operations are only available in an RV32 guest");
    }
}

/// Import guest RAM into TensorBus, open the resident segment, and write an
/// opaque handle at `output_handle_ptr`.
#[inline(always)]
pub unsafe fn tensor_import_begin_v1(desc: &TensorImportBeginDescV1) {
    unsafe {
        tensor_segment_ecall_v1(
            desc as *const TensorImportBeginDescV1 as *const u8,
            TENSOR_IMPORT_BEGIN_V1,
        )
    }
}

/// Materialize a TensorBus handle into guest RAM and close its resident
/// segment.
#[inline(always)]
pub unsafe fn tensor_export_end_v1(desc: &TensorExportEndDescV1) {
    unsafe {
        tensor_segment_ecall_v1(
            desc as *const TensorExportEndDescV1 as *const u8,
            TENSOR_EXPORT_END_V1,
        )
    }
}

#[inline(always)]
pub unsafe fn tensor_handle_attention_v1(desc: &TensorHandleOpDescV1) {
    unsafe {
        tensor_segment_ecall_v1(
            desc as *const TensorHandleOpDescV1 as *const u8,
            TENSOR_HANDLE_ATTENTION_V1,
        )
    }
}

#[inline(always)]
pub unsafe fn tensor_handle_ffn_v1(desc: &TensorHandleOpDescV1) {
    unsafe {
        tensor_segment_ecall_v1(
            desc as *const TensorHandleOpDescV1 as *const u8,
            TENSOR_HANDLE_FFN_V1,
        )
    }
}

#[inline(always)]
pub unsafe fn tensor_handle_attention_v2(desc: &TensorHandleOpDescV2) {
    unsafe {
        tensor_segment_ecall_v1(
            desc as *const TensorHandleOpDescV2 as *const u8,
            TENSOR_HANDLE_ATTENTION_V1,
        )
    }
}

#[inline(always)]
pub unsafe fn tensor_handle_ffn_v2(desc: &TensorHandleOpDescV2) {
    unsafe {
        tensor_segment_ecall_v1(
            desc as *const TensorHandleOpDescV2 as *const u8,
            TENSOR_HANDLE_FFN_V1,
        )
    }
}

/// Import hidden `[2048,4096]` into one atomic attention segment.
#[inline(always)]
pub unsafe fn tensor_production_import_begin_v2(desc: &TensorImportBeginDescV1) {
    unsafe {
        tensor_segment_ecall_v1(
            desc as *const TensorImportBeginDescV1 as *const u8,
            TENSOR_PRODUCTION_IMPORT_BEGIN_V2,
        )
    }
}

/// Exact Llama-2-7B S2048 full layer. All operands and outputs are Tensor-space;
/// this anchor touches only its descriptor and opaque handles in guest RAM.
#[inline(always)]
pub unsafe fn tensor_production_full_layer_v2(desc: &TensorHandleOpDescV2) {
    unsafe {
        tensor_segment_ecall_v1(
            desc as *const TensorHandleOpDescV2 as *const u8,
            TENSOR_PRODUCTION_FULL_LAYER_V2,
        )
    }
}

/// Export hidden `[2048,4096]` and close the atomic full-layer segment.
#[inline(always)]
pub unsafe fn tensor_production_export_end_v2(desc: &TensorExportEndDescV1) {
    unsafe {
        tensor_segment_ecall_v1(
            desc as *const TensorExportEndDescV1 as *const u8,
            TENSOR_PRODUCTION_EXPORT_END_V2,
        )
    }
}

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

/// Tiny-only descriptor for one complete signed-byte 2x2 matrix product.
///
/// The ecall writes the canonical Q16 quotient and remainder matrices. Shape,
/// strides, and quantization are fixed by the dedicated ecall number.
#[cfg(feature = "llama-tiny")]
#[repr(C, align(32))]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TensorBatchedMatMul2x2DescV1 {
    pub abi_version: u32,
    pub flags: u32,
    pub a_ptr: u32,
    pub w_ptr: u32,
    pub quotient_ptr: u32,
    pub remainder_ptr: u32,
    pub reserved: [u32; 2],
}

#[cfg(feature = "llama-tiny")]
const _: () = assert!(core::mem::size_of::<TensorBatchedMatMul2x2DescV1>() == 32);

/// Invoke one complete tiny 2x2 matrix product.
///
/// # Safety
/// All four pointers must address four suitably aligned guest words.
#[cfg(feature = "llama-tiny")]
#[inline(always)]
pub unsafe fn tensor_batched_matmul_2x2_v1(desc: &TensorBatchedMatMul2x2DescV1) {
    #[cfg(target_arch = "riscv32")]
    unsafe {
        core::arch::asm!(
            "ecall",
            in("a0") desc as *const TensorBatchedMatMul2x2DescV1 as u32,
            in("t0") TENSOR_BATCHED_MATMUL_2X2_V1,
        );
    }
    #[cfg(not(target_arch = "riscv32"))]
    {
        let _ = desc;
        panic!("tiny batched tensor MatMul is only available in an RV32 guest");
    }
}

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

/// # Safety
/// Descriptor pointers must address the statically required guest regions.
#[inline(always)]
pub unsafe fn tensor_matmul_gate5_small_hidden_v1(desc: &TensorProductionMatMulDescV1) {
    unsafe { tensor_production_matmul_v1(desc, TENSOR_MATMUL_GATE5_SMALL_HIDDEN_V1) }
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
