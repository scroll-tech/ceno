//! Gate-5 compact production MatMul topology reproducer: one K64 logical
//! ecall expands into raw ordinary-memory records, one K1024 tile, and one
//! ordered finalize record.

use ceno_rt::tensor::{
    TENSOR_ABI_V1, TensorProductionMatMulDescV1, tensor_matmul_gate5_small_hidden_v1,
};

fn main() {
    let input = core::array::from_fn::<_, 64, _>(|i| if i % 7 == 0 { -19_i32 } else { 13 });
    let mut output = 0_i32;
    let model_root = [0_u32; 8];
    let desc = TensorProductionMatMulDescV1 {
        abi_version: TENSOR_ABI_V1,
        commitment_profile: 2,
        quantization_id: 1,
        signature_id: 0x4d47_0040,
        input_ptr: input.as_ptr() as u32,
        output_ptr: (&mut output as *mut i32) as u32,
        weight_tensor_id: 81,
        first_weight_tile: 0,
        weight_tile_count: 1,
        rescale_shift: 16,
        model_root_ptr: model_root.as_ptr() as u32,
        input_stride: 1,
        output_stride: 1,
        reserved: [0; 3],
    };
    unsafe { tensor_matmul_gate5_small_hidden_v1(&desc) };
    core::hint::black_box(output);
}
