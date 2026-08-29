//! One default-profile resident block with eight attention-to-FFN layers.
//!
//! This is a fixed-width Llama-shaped activation boundary smoke guest. It does
//! not claim model-quality Llama weights; the proof binds the resident handle
//! lifecycle and the fixed CPU/AIR integer relation used by the CUDA witness.
//! TensorBus is deliberately only the import/export boundary: the guest
//! unrolls the eight handle transitions without materializing their activations.

use ceno_rt::tensor::{
    TENSOR_ABI_V1, TensorExportEndDescV1, TensorHandleOpDescV1, TensorHandleV1,
    TensorImportBeginDescV1, tensor_export_end_v1, tensor_handle_attention_v1,
    tensor_handle_ffn_v1, tensor_import_begin_v1,
};

#[cfg(feature = "llama-tiny")]
const WORDS: usize = 4;
#[cfg(not(feature = "llama-tiny"))]
const WORDS: usize = 4096;
const LAYERS: usize = 8;

fn main() {
    let input = std::array::from_fn::<_, WORDS, _>(|index| index as i32 - 2048);
    let mut output = [0_i32; WORDS];
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
        for _ in 0..LAYERS {
            let attention = TensorHandleOpDescV1 {
                abi_version: TENSOR_ABI_V1,
                flags: 0,
                input_handle_ptr: (&raw const handles[0]) as *const TensorHandleV1 as u32,
                output_handle_ptr: (&raw mut handles[1]) as *mut TensorHandleV1 as u32,
                meta_ptr: meta.as_ptr() as u32,
                meta_len: meta.len() as u32,
                reserved: [0; 2],
            };
            let ffn = TensorHandleOpDescV1 {
                abi_version: TENSOR_ABI_V1,
                flags: 0,
                input_handle_ptr: (&raw const handles[1]) as *const TensorHandleV1 as u32,
                output_handle_ptr: (&raw mut handles[0]) as *mut TensorHandleV1 as u32,
                meta_ptr: meta.as_ptr() as u32,
                meta_len: meta.len() as u32,
                reserved: [0; 2],
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
    let mut low = -2048i32;
    let mut high = (WORDS / 2) as i32 - 2048;
    for _ in 0..LAYERS {
        high = high.wrapping_add(low).wrapping_mul(2).wrapping_add(1);
        low = low.wrapping_mul(2).wrapping_add(1);
    }
    assert_eq!(output[0], low);
    assert_eq!(output[WORDS / 2], high);
}
