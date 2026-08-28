//! One default-profile (4096-word) TensorBus resident attention-to-FFN layer.
//!
//! This is a fixed-width Llama-shaped activation boundary smoke guest. It does
//! not claim model-quality Llama weights; the proof binds the resident handle
//! lifecycle and the fixed CPU/AIR integer relation used by the CUDA witness.

use ceno_rt::tensor::{
    TENSOR_ABI_V1, TensorExportEndDescV1, TensorHandleOpDescV1, TensorHandleV1,
    TensorImportBeginDescV1, tensor_export_end_v1, tensor_handle_attention_v1,
    tensor_handle_ffn_v1, tensor_import_begin_v1,
};

const WORDS: usize = 4096;

fn main() {
    let input = std::array::from_fn::<_, WORDS, _>(|index| index as i32 - 2048);
    let mut output = [0_i32; WORDS];
    let meta = [(WORDS * 4) as u32, WORDS as u32, 1, 0];
    let mut imported = TensorHandleV1::default();
    let mut attention = TensorHandleV1::default();
    let mut ffn = TensorHandleV1::default();
    let import = TensorImportBeginDescV1 {
        abi_version: TENSOR_ABI_V1,
        flags: 0,
        input_ptr: input.as_ptr() as u32,
        input_len: WORDS as u32,
        meta_ptr: meta.as_ptr() as u32,
        meta_len: meta.len() as u32,
        output_handle_ptr: (&raw mut imported) as *mut TensorHandleV1 as u32,
        reserved: 0,
    };
    let attention_op = TensorHandleOpDescV1 {
        abi_version: TENSOR_ABI_V1,
        flags: 0,
        input_handle_ptr: (&raw const imported) as *const TensorHandleV1 as u32,
        output_handle_ptr: (&raw mut attention) as *mut TensorHandleV1 as u32,
        meta_ptr: meta.as_ptr() as u32,
        meta_len: meta.len() as u32,
        reserved: [0; 2],
    };
    let ffn_op = TensorHandleOpDescV1 {
        abi_version: TENSOR_ABI_V1,
        flags: 0,
        input_handle_ptr: (&raw const attention) as *const TensorHandleV1 as u32,
        output_handle_ptr: (&raw mut ffn) as *mut TensorHandleV1 as u32,
        meta_ptr: meta.as_ptr() as u32,
        meta_len: meta.len() as u32,
        reserved: [0; 2],
    };
    let export = TensorExportEndDescV1 {
        abi_version: TENSOR_ABI_V1,
        flags: 0,
        input_handle_ptr: (&raw const ffn) as *const TensorHandleV1 as u32,
        output_ptr: output.as_mut_ptr() as u32,
        output_len: WORDS as u32,
        meta_ptr: meta.as_ptr() as u32,
        meta_len: meta.len() as u32,
        reserved: 0,
    };
    unsafe {
        tensor_import_begin_v1(&import);
        tensor_handle_attention_v1(&attention_op);
        tensor_handle_ffn_v1(&ffn_op);
        tensor_export_end_v1(&export);
    }
    assert_eq!(output[0], -4095);
    assert_eq!(output[2047], -1);
    assert_eq!(output[2048], -4095);
    assert_eq!(output[4095], 4093);
}
