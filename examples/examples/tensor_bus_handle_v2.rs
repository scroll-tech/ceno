//! One complete logical-weight TensorBus segment for the stage-1 proof gate.

use ceno_rt::tensor::{
    TENSOR_ABI_V2, TensorExportEndDescV1, TensorHandleOpDescV2, TensorHandleV1,
    TensorImportBeginDescV1, tensor_export_end_v1, tensor_handle_attention_v2,
    tensor_handle_ffn_v2, tensor_import_begin_v1,
};

const TENSOR_PROFILE_LLAMA_TINY: u32 = 1;

fn main() {
    let input = [128_i32, -64, 64, 128];
    let mut output = [0_i32; 4];
    let meta = [16_u32, 4, 1, 0];
    let mut imported = TensorHandleV1::default();
    let mut handles = [TensorHandleV1::default(); 2];

    let import = TensorImportBeginDescV1 {
        abi_version: TENSOR_ABI_V2,
        flags: 0,
        input_ptr: input.as_ptr() as u32,
        input_len: input.len() as u32,
        meta_ptr: meta.as_ptr() as u32,
        meta_len: meta.len() as u32,
        output_handle_ptr: (&raw mut imported) as *mut TensorHandleV1 as u32,
        reserved: 0,
    };
    let export = TensorExportEndDescV1 {
        abi_version: TENSOR_ABI_V2,
        flags: 0,
        input_handle_ptr: (&raw const handles[1]) as *const TensorHandleV1 as u32,
        output_ptr: output.as_mut_ptr() as u32,
        output_len: output.len() as u32,
        meta_ptr: meta.as_ptr() as u32,
        meta_len: meta.len() as u32,
        reserved: 0,
    };

    unsafe {
        tensor_import_begin_v1(&import);
        for layer in 0..4 {
            let attention_op = TensorHandleOpDescV2 {
                abi_version: TENSOR_ABI_V2,
                flags: 0,
                input_handle_ptr: if layer == 0 {
                    (&raw const imported) as *const TensorHandleV1 as u32
                } else {
                    (&raw const handles[1]) as *const TensorHandleV1 as u32
                },
                output_handle_ptr: (&raw mut handles[0]) as *mut TensorHandleV1 as u32,
                meta_ptr: meta.as_ptr() as u32,
                meta_len: meta.len() as u32,
                profile: TENSOR_PROFILE_LLAMA_TINY,
                layer,
            };
            let ffn_op = TensorHandleOpDescV2 {
                input_handle_ptr: (&raw const handles[0]) as *const TensorHandleV1 as u32,
                output_handle_ptr: (&raw mut handles[1]) as *mut TensorHandleV1 as u32,
                ..attention_op
            };
            tensor_handle_attention_v2(&attention_op);
            tensor_handle_ffn_v2(&ffn_op);
        }
        tensor_export_end_v1(&export);
    }
}
