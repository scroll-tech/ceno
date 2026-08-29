//! Tied-weight, production-width 32-layer resident topology guest.
//!
//! Eight complete four-layer TensorBus segments model the 32 Llama layer
//! pairs.  Each segment selects one distinct block-local hint window; its
//! eight internal operators carry the same descriptor-bound `hint_base`.
//! This routes hint windows only.  It does not yet dereference/prove weight
//! tiles, so it is not model-quality inference.

use ceno_rt::tensor::{
    TENSOR_ABI_V1, TensorExportEndDescV1, TensorHandleOpDescV1, TensorHandleV1,
    TensorImportBeginDescV1, tensor_export_end_v1, tensor_handle_attention_v1,
    tensor_handle_ffn_v1, tensor_import_begin_v1,
};

const WORDS: usize = 4096;
const BLOCKS: usize = 8;
const LAYERS_PER_BLOCK: usize = 4;
const HINT_BASES: [u32; BLOCKS] = [
    0x2800_0000,
    0x2900_0000,
    0x2a00_0000,
    0x2b00_0000,
    0x2c00_0000,
    0x2d00_0000,
    0x2e00_0000,
    0x2f00_0000,
];

fn run_block(input: &[i32; WORDS], output: &mut [i32; WORDS], hint_base: u32) {
    let meta = [(WORDS * 4) as u32, WORDS as u32, 1, 0];
    let mut handles = [TensorHandleV1::default(); 2];
    let import = TensorImportBeginDescV1 {
        abi_version: TENSOR_ABI_V1,
        flags: 0,
        input_ptr: input.as_ptr() as u32,
        input_len: WORDS as u32,
        meta_ptr: meta.as_ptr() as u32,
        meta_len: meta.len() as u32,
        output_handle_ptr: (&raw mut handles[0]) as *mut TensorHandleV1 as u32,
        reserved: 0,
    };
    unsafe {
        tensor_import_begin_v1(&import);
        for _ in 0..LAYERS_PER_BLOCK {
            let attention = TensorHandleOpDescV1 {
                abi_version: TENSOR_ABI_V1,
                flags: 0,
                input_handle_ptr: (&raw const handles[0]) as *const TensorHandleV1 as u32,
                output_handle_ptr: (&raw mut handles[1]) as *mut TensorHandleV1 as u32,
                meta_ptr: meta.as_ptr() as u32,
                meta_len: meta.len() as u32,
                hint_base,
                reserved: 0,
            };
            let ffn = TensorHandleOpDescV1 {
                abi_version: TENSOR_ABI_V1,
                flags: 0,
                input_handle_ptr: (&raw const handles[1]) as *const TensorHandleV1 as u32,
                output_handle_ptr: (&raw mut handles[0]) as *mut TensorHandleV1 as u32,
                meta_ptr: meta.as_ptr() as u32,
                meta_len: meta.len() as u32,
                hint_base,
                reserved: 0,
            };
            tensor_handle_attention_v1(&attention);
            tensor_handle_ffn_v1(&ffn);
        }
        let export = TensorExportEndDescV1 {
            abi_version: TENSOR_ABI_V1,
            flags: 0,
            input_handle_ptr: (&raw const handles[0]) as *const TensorHandleV1 as u32,
            output_ptr: output.as_mut_ptr() as u32,
            output_len: WORDS as u32,
            meta_ptr: meta.as_ptr() as u32,
            meta_len: meta.len() as u32,
            reserved: 0,
        };
        tensor_export_end_v1(&export);
    }
}

fn main() {
    let mut left = std::array::from_fn::<_, WORDS, _>(|index| index as i32 - 2048);
    let mut right = [0_i32; WORDS];
    for hint_base in HINT_BASES {
        run_block(&left, &mut right, hint_base);
        core::mem::swap(&mut left, &mut right);
    }
    // A benign ordinary operation follows all complete TensorBus segments.
    // The E2E shard budget admits it as the calibrated ninth shard.
    let checksum = left[0]
        .wrapping_add(left[WORDS / 2])
        .wrapping_add(left[WORDS - 1]);
    assert_ne!(checksum, i32::MIN);
}
