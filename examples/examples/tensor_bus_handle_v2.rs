//! Complete logical-weight TensorBus segments for the llama-tiny proof gate.

use ceno_rt::tensor::{
    TENSOR_ABI_V2, TensorExportEndDescV1, TensorHandleOpDescV2, TensorHandleV1,
    TensorImportBeginDescV1, tensor_export_end_v1, tensor_handle_attention_v2,
    tensor_handle_ffn_v2, tensor_import_begin_v1,
};

const TENSOR_PROFILE_LLAMA_TINY: u32 = 1;

fn run_segment(
    input: &[i32; 4],
    output: &mut [i32; 4],
    imported: &mut TensorHandleV1,
    handles: &mut [TensorHandleV1; 2],
    first_layer: u32,
    layer_count: u32,
) {
    let meta = [16_u32, 4, 1, 0];

    let import = TensorImportBeginDescV1 {
        abi_version: TENSOR_ABI_V2,
        flags: 0,
        input_ptr: input.as_ptr() as u32,
        input_len: input.len() as u32,
        meta_ptr: meta.as_ptr() as u32,
        meta_len: meta.len() as u32,
        output_handle_ptr: imported as *mut TensorHandleV1 as u32,
        reserved: 0,
    };
    unsafe {
        tensor_import_begin_v1(&import);
        let mut current = core::ptr::read_volatile(imported);
        for layer in first_layer..first_layer + layer_count {
            let attention_op = TensorHandleOpDescV2 {
                abi_version: TENSOR_ABI_V2,
                flags: 0,
                input_handle_ptr: (&raw const current) as *const TensorHandleV1 as u32,
                output_handle_ptr: (&raw mut handles[0]) as *mut TensorHandleV1 as u32,
                meta_ptr: meta.as_ptr() as u32,
                meta_len: meta.len() as u32,
                profile: TENSOR_PROFILE_LLAMA_TINY,
                layer,
            };
            tensor_handle_attention_v2(&attention_op);
            let attention = core::ptr::read_volatile(&handles[0]);
            let ffn_op = TensorHandleOpDescV2 {
                input_handle_ptr: (&raw const attention) as *const TensorHandleV1 as u32,
                output_handle_ptr: (&raw mut handles[1]) as *mut TensorHandleV1 as u32,
                ..attention_op
            };
            tensor_handle_ffn_v2(&ffn_op);
            current = core::ptr::read_volatile(&handles[1]);
        }
        let export = TensorExportEndDescV1 {
            abi_version: TENSOR_ABI_V2,
            flags: 0,
            input_handle_ptr: (&raw const current) as *const TensorHandleV1 as u32,
            output_ptr: output.as_mut_ptr() as u32,
            output_len: output.len() as u32,
            meta_ptr: meta.as_ptr() as u32,
            meta_len: meta.len() as u32,
            reserved: 0,
        };
        tensor_export_end_v1(&export);
    }
}

fn main() {
    let input = [128_i32, -64, 64, 128];
    #[cfg(feature = "resident-segments-2")]
    let output = {
        let mut intermediate = [0_i32; 4];
        let mut output = [0_i32; 4];
        let mut imported = [TensorHandleV1::default(); 2];
        let mut handles = [[TensorHandleV1::default(); 2]; 2];
        run_segment(
            &input,
            &mut intermediate,
            &mut imported[0],
            &mut handles[0],
            0,
            2,
        );
        run_segment(
            &intermediate,
            &mut output,
            &mut imported[1],
            &mut handles[1],
            2,
            2,
        );
        output
    };
    #[cfg(not(feature = "resident-segments-2"))]
    let output = {
        let mut output = [0_i32; 4];
        let mut imported = TensorHandleV1::default();
        let mut handles = [TensorHandleV1::default(); 2];
        run_segment(&input, &mut output, &mut imported, &mut handles, 0, 4);
        output
    };
    assert_eq!(output, [457, 55, 161, 311]);
}
