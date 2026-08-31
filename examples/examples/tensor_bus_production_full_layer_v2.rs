//! Exact batch-one Llama-2-7B S2048 full-layer guest.

use ceno_rt::tensor::{
    TENSOR_ABI_V2, TENSOR_LLAMA2_HIDDEN_WORDS, TENSOR_PROFILE_LLAMA2_7B_FULL_LAYER,
    TensorExportEndDescV1, TensorHandleOpDescV2, TensorHandleV1, TensorImportBeginDescV1,
    tensor_production_export_end_v2, tensor_production_full_layer_v2,
    tensor_production_import_begin_v2,
};

const HIDDEN_WORDS: usize = TENSOR_LLAMA2_HIDDEN_WORDS as usize;

static mut HIDDEN: [i32; HIDDEN_WORDS] = [0; HIDDEN_WORDS];
static mut OUTPUT: [i32; HIDDEN_WORDS] = [0; HIDDEN_WORDS];

const INPUT_PREFIX: [i32; 4] = [-25_344, -20_992, -16_640, -12_288];

fn main() {
    let hidden_ptr = (&raw mut HIDDEN).cast::<i32>();
    let output_ptr = (&raw mut OUTPUT).cast::<i32>();
    for (index, value) in INPUT_PREFIX.into_iter().enumerate() {
        unsafe { hidden_ptr.add(index).write(value) };
    }
    let hidden_meta = [(HIDDEN_WORDS * 4) as u32, HIDDEN_WORDS as u32, 1, 0];
    let mut imported = TensorHandleV1::default();
    let mut attended = TensorHandleV1::default();
    let import = TensorImportBeginDescV1 {
        abi_version: TENSOR_ABI_V2,
        flags: 0,
        input_ptr: hidden_ptr as u32,
        input_len: HIDDEN_WORDS as u32,
        meta_ptr: hidden_meta.as_ptr() as u32,
        meta_len: hidden_meta.len() as u32,
        output_handle_ptr: (&raw mut imported) as *mut TensorHandleV1 as u32,
        reserved: 0,
    };
    let full_layer = TensorHandleOpDescV2 {
        abi_version: TENSOR_ABI_V2,
        flags: 0,
        input_handle_ptr: (&raw const imported) as *const TensorHandleV1 as u32,
        output_handle_ptr: (&raw mut attended) as *mut TensorHandleV1 as u32,
        meta_ptr: hidden_meta.as_ptr() as u32,
        meta_len: hidden_meta.len() as u32,
        profile: TENSOR_PROFILE_LLAMA2_7B_FULL_LAYER,
        layer: 0,
    };
    let export = TensorExportEndDescV1 {
        abi_version: TENSOR_ABI_V2,
        flags: 0,
        input_handle_ptr: (&raw const attended) as *const TensorHandleV1 as u32,
        output_ptr: output_ptr as u32,
        output_len: HIDDEN_WORDS as u32,
        meta_ptr: hidden_meta.as_ptr() as u32,
        meta_len: hidden_meta.len() as u32,
        reserved: 0,
    };

    unsafe {
        tensor_production_import_begin_v2(&import);
        tensor_production_full_layer_v2(&full_layer);
        tensor_production_export_end_v2(&export);
    }

    for (index, expected) in INPUT_PREFIX.into_iter().enumerate() {
        assert_eq!(unsafe { output_ptr.add(index).read() }, expected);
    }
}
