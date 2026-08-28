//! One proof-bound Llama-2-7B intermediate-width (K11008) tensor syscall.
//!
//! This is deliberately a single output cell: it validates the production
//! syscall/provider boundary without attempting a layer or model execution.

use ceno_rt::tensor::{TENSOR_ABI_V1, TensorProductionMatMulDescV1, tensor_matmul_intermediate_v1};

fn main() {
    let input = core::array::from_fn::<_, 11_008, _>(|i| if i % 7 == 0 { -19_i32 } else { 13 });
    let mut output = 0_i32;
    let model_root = [0_u32; 8];
    let desc = TensorProductionMatMulDescV1 {
        abi_version: TENSOR_ABI_V1,
        commitment_profile: 2,
        quantization_id: 1,
        signature_id: 0x4d49_2b00,
        input_ptr: input.as_ptr() as u32,
        output_ptr: (&mut output as *mut i32) as u32,
        weight_tensor_id: 83,
        first_weight_tile: 0,
        weight_tile_count: 11,
        rescale_shift: 16,
        model_root_ptr: model_root.as_ptr() as u32,
        input_stride: 1,
        output_stride: 1,
        reserved: [0; 3],
    };
    unsafe { tensor_matmul_intermediate_v1(&desc) };
    core::hint::black_box(output);
}
