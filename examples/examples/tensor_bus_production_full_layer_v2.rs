//! Exact batch-one Llama-2-7B S2048 stage-split guest.
//!
//! `STAGE_HEADS` is the constrained attention `head_count`: build with
//! `production-heads-1` for one head, `production-heads-2` for two heads, or
//! neither feature for the default four heads. This selection must match the
//! prover registry's `HEADS_PER_CIRCUIT`; it is not an allocator hint or a
//! runtime tuning variable. Projection and attention are fused per head range
//! in one TensorBus segment. Q/K/V never receive guest addresses.

extern crate alloc;

use alloc::alloc::{Layout, alloc};
use ceno_rt::tensor::{
    TENSOR_ABI_V2, TENSOR_LLAMA2_HEAD_WORDS, TENSOR_LLAMA2_HEADS, TENSOR_LLAMA2_HIDDEN_WORDS,
    TENSOR_PRODUCTION_STAGE_ATTENTION, TENSOR_PRODUCTION_STAGE_POST_FFN,
    TENSOR_PRODUCTION_STAGE_PROJECTION, TensorHandleV1, TensorProductionExportDescV2,
    TensorProductionImportDescV2, TensorProductionStageDescV2, tensor_production_export_end_v2,
    tensor_production_head_range, tensor_production_import_begin_v2, tensor_production_stage_v2,
};

const HIDDEN_WORDS: usize = TENSOR_LLAMA2_HIDDEN_WORDS as usize;
#[cfg(all(feature = "production-heads-1", feature = "production-heads-2"))]
compile_error!("production-heads-1 and production-heads-2 are mutually exclusive");
#[cfg(feature = "production-heads-1")]
const STAGE_HEADS: u32 = 1;
#[cfg(feature = "production-heads-2")]
const STAGE_HEADS: u32 = 2;
#[cfg(not(any(feature = "production-heads-1", feature = "production-heads-2")))]
const STAGE_HEADS: u32 = 4;

static mut HIDDEN: [i32; HIDDEN_WORDS] = [0; HIDDEN_WORDS];

const INPUT_PREFIX: [i32; 4] = [-25_344, -20_992, -16_640, -12_288];

fn main() {
    let hidden_ptr = (&raw mut HIDDEN).cast::<i32>();
    for (index, value) in INPUT_PREFIX.into_iter().enumerate() {
        unsafe { hidden_ptr.add(index).write(value) };
    }
    // Context is produced exactly once in ordered, disjoint head slices before
    // post-FFN reads it. Keep it in the canonical zero-initialized heap range
    // so each first-touch export is owned by the ordinary HeapInit/ShardRAM
    // lifecycle instead of inflating the ELF-wide static-memory tables.
    let context_layout = Layout::array::<i32>(HIDDEN_WORDS).unwrap();
    let context_ptr = unsafe { alloc(context_layout).cast::<i32>() };
    assert!(!context_ptr.is_null());
    for head_start in (0..TENSOR_LLAMA2_HEADS).step_by(STAGE_HEADS as usize) {
        let offset = head_start * TENSOR_LLAMA2_HEAD_WORDS;
        unsafe {
            run_attention_segment(
                head_start,
                STAGE_HEADS,
                hidden_ptr,
                context_ptr.add(offset as usize),
            )
        };
    }
    unsafe {
        run_stage(
            TENSOR_PRODUCTION_STAGE_POST_FFN,
            0,
            TENSOR_LLAMA2_HEADS,
            hidden_ptr,
            context_ptr,
            core::ptr::null(),
            hidden_ptr,
            HIDDEN_WORDS as u32,
        )
    };
}

unsafe fn run_attention_segment(
    head_start: u32,
    head_count: u32,
    hidden: *const i32,
    context: *mut i32,
) {
    let mut imported = TensorHandleV1::default();
    let mut projected = TensorHandleV1::default();
    let mut attended = TensorHandleV1::default();
    let import = TensorProductionImportDescV2 {
        abi_version: TENSOR_ABI_V2,
        layer: 0,
        input0_ptr: hidden as u32,
        input1_ptr: 0,
        input2_ptr: 0,
        output_handle_ptr: (&raw mut imported) as *mut TensorHandleV1 as u32,
        stage: TENSOR_PRODUCTION_STAGE_PROJECTION,
        head_range: tensor_production_head_range(head_start, head_count),
    };
    let projection = TensorProductionStageDescV2 {
        abi_version: TENSOR_ABI_V2,
        layer: 0,
        input_handle_ptr: (&raw const imported) as *const TensorHandleV1 as u32,
        output_handle_ptr: (&raw mut projected) as *mut TensorHandleV1 as u32,
        stage: TENSOR_PRODUCTION_STAGE_PROJECTION,
        head_start,
        head_count,
        reserved: 0,
    };
    let attention = TensorProductionStageDescV2 {
        abi_version: TENSOR_ABI_V2,
        layer: 0,
        input_handle_ptr: (&raw const projected) as *const TensorHandleV1 as u32,
        output_handle_ptr: (&raw mut attended) as *mut TensorHandleV1 as u32,
        stage: TENSOR_PRODUCTION_STAGE_ATTENTION,
        head_start,
        head_count,
        reserved: 0,
    };
    let export = TensorProductionExportDescV2 {
        abi_version: TENSOR_ABI_V2,
        layer: 0,
        input_handle_ptr: (&raw const attended) as *const TensorHandleV1 as u32,
        output_ptr: context as u32,
        output_len: head_count * TENSOR_LLAMA2_HEAD_WORDS,
        stage: TENSOR_PRODUCTION_STAGE_ATTENTION,
        head_range: tensor_production_head_range(head_start, head_count),
        reserved: 0,
    };
    unsafe {
        tensor_production_import_begin_v2(&import);
        tensor_production_stage_v2(&projection);
        tensor_production_stage_v2(&attention);
        tensor_production_export_end_v2(&export);
    }
}

unsafe fn run_stage(
    stage: u32,
    head_start: u32,
    head_count: u32,
    input0: *const i32,
    input1: *const i32,
    input2: *const i32,
    output: *mut i32,
    output_len: u32,
) {
    let mut imported = TensorHandleV1::default();
    let mut produced = TensorHandleV1::default();
    let import = TensorProductionImportDescV2 {
        abi_version: TENSOR_ABI_V2,
        layer: 0,
        input0_ptr: input0 as u32,
        input1_ptr: input1 as u32,
        input2_ptr: input2 as u32,
        output_handle_ptr: (&raw mut imported) as *mut TensorHandleV1 as u32,
        stage,
        head_range: tensor_production_head_range(head_start, head_count),
    };
    let op = TensorProductionStageDescV2 {
        abi_version: TENSOR_ABI_V2,
        layer: 0,
        input_handle_ptr: (&raw const imported) as *const TensorHandleV1 as u32,
        output_handle_ptr: (&raw mut produced) as *mut TensorHandleV1 as u32,
        stage,
        head_start,
        head_count,
        reserved: 0,
    };
    let export = TensorProductionExportDescV2 {
        abi_version: TENSOR_ABI_V2,
        layer: 0,
        input_handle_ptr: (&raw const produced) as *const TensorHandleV1 as u32,
        output_ptr: output as u32,
        output_len,
        stage,
        head_range: tensor_production_head_range(head_start, head_count),
        reserved: 0,
    };
    unsafe {
        tensor_production_import_begin_v2(&import);
        tensor_production_stage_v2(&op);
        tensor_production_export_end_v2(&export);
    }
}
