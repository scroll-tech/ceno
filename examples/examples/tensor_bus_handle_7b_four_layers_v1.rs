//! Four sequential default-profile TensorBus resident attention-to-FFN loops.
//!
//! Every loop has its own IMPORT_BEGIN and EXPORT_END boundary.  Consequently
//! the CUDA provider owns exactly one device witness per loop: it uploads once,
//! runs attention then FFN entirely on device, downloads once, and is dropped
//! before the next loop begins.

use ceno_rt::tensor::{
    TENSOR_ABI_V1, TensorExportEndDescV1, TensorHandleOpDescV1, TensorHandleV1,
    TensorImportBeginDescV1, tensor_export_end_v1, tensor_handle_attention_v1,
    tensor_handle_ffn_v1, tensor_import_begin_v1,
};

const WORDS: usize = 4096;
const LAYERS: usize = 4;

fn run_segment(seed: i32) -> [i32; WORDS] {
    let input = std::array::from_fn::<_, WORDS, _>(|index| seed.wrapping_add(index as i32 - 2048));
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
        hint_base: 0x2800_0000,
        reserved: 0,
    };
    let ffn_op = TensorHandleOpDescV1 {
        abi_version: TENSOR_ABI_V1,
        flags: 0,
        input_handle_ptr: (&raw const attention) as *const TensorHandleV1 as u32,
        output_handle_ptr: (&raw mut ffn) as *mut TensorHandleV1 as u32,
        meta_ptr: meta.as_ptr() as u32,
        meta_len: meta.len() as u32,
        hint_base: 0x2800_0000,
        reserved: 0,
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
    output
}

fn expected(seed: i32, index: usize) -> i32 {
    let input = seed.wrapping_add(index as i32 - 2048);
    let attention = if index < WORDS / 2 {
        input
    } else {
        input.wrapping_add(seed.wrapping_add(index as i32 - 2048 - WORDS as i32 / 2))
    };
    attention.wrapping_mul(2).wrapping_add(1)
}

fn main() {
    for layer in 0..LAYERS {
        let seed = (layer as i32 + 1) * 17;
        let output = run_segment(seed);
        assert_eq!(output[0], expected(seed, 0));
        assert_eq!(output[WORDS / 2 - 1], expected(seed, WORDS / 2 - 1));
        assert_eq!(output[WORDS / 2], expected(seed, WORDS / 2));
        assert_eq!(output[WORDS - 1], expected(seed, WORDS - 1));
    }
}
