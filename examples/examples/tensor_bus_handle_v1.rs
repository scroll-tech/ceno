//! Minimal fixed-width TensorBus handle ABI guest.

//! This deliberately contains two complete resident sections. It is the proof
//! harness for batched IMPORT_BEGIN/ATTENTION/FFN/EXPORT_END sections.

use ceno_rt::tensor::{
    TENSOR_ABI_V1, TensorExportEndDescV1, TensorHandleOpDescV1, TensorHandleV1,
    TensorImportBeginDescV1, tensor_export_end_v1, tensor_handle_attention_v1,
    tensor_handle_ffn_v1, tensor_import_begin_v1,
};

fn run_segment(input: [i32; 4]) -> [i32; 4] {
    let mut output = [0_i32; 4];
    // [byte_len, flattened shape, quantization id, reserved]
    let meta = [16_u32, 4, 1, 0];
    let mut handle = TensorHandleV1::default();
    let mut attention = TensorHandleV1::default();
    let mut ffn = TensorHandleV1::default();
    let import = TensorImportBeginDescV1 {
        abi_version: TENSOR_ABI_V1,
        flags: 0,
        input_ptr: input.as_ptr() as u32,
        input_len: input.len() as u32,
        meta_ptr: meta.as_ptr() as u32,
        meta_len: meta.len() as u32,
        output_handle_ptr: (&raw mut handle) as *mut TensorHandleV1 as u32,
        reserved: 0,
    };
    let export = TensorExportEndDescV1 {
        abi_version: TENSOR_ABI_V1,
        flags: 0,
        input_handle_ptr: (&raw const ffn) as *const TensorHandleV1 as u32,
        output_ptr: output.as_mut_ptr() as u32,
        output_len: output.len() as u32,
        meta_ptr: meta.as_ptr() as u32,
        meta_len: meta.len() as u32,
        reserved: 0,
    };
    let attention_op = TensorHandleOpDescV1 {
        abi_version: TENSOR_ABI_V1,
        flags: 0,
        input_handle_ptr: (&raw const handle) as *const TensorHandleV1 as u32,
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

    unsafe {
        tensor_import_begin_v1(&import);
        tensor_handle_attention_v1(&attention_op);
        tensor_handle_ffn_v1(&ffn_op);
        tensor_export_end_v1(&export);
    }
    output
}

fn main() {
    assert_eq!(run_segment([1, -2, 3, -4]), [3, -3, 9, -11]);
    assert_eq!(run_segment([-7, 8, -9, 10]), [-13, 17, -31, 37]);
}
