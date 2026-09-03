//! Smallest application exercising the experimental Gate-2 tensor MatMul.

use ceno_rt::tensor::{TENSOR_ABI_V1, TensorMatMulDescV1, tensor_matmul_v1};

const GATE2_LINEAR_COMMITMENT_V1: u32 = 1;
const TENSOR_SIGNATURE_2X3X2: u32 = 7;
const ZKLLM_FIXED_V1: u32 = 1;

fn main() {
    let input = [1_i32, 2, 3, 4, 5, 6];
    let mut output = [0_i32; 4];
    let model_root = [
        1_243_962_083_u32,
        1_248_942_890,
        1_253_923_697,
        1_258_904_504,
        1_263_885_311,
        1_268_866_118,
        1_273_846_925,
        1_278_827_732,
    ];
    let desc = TensorMatMulDescV1 {
        abi_version: TENSOR_ABI_V1,
        flags: GATE2_LINEAR_COMMITMENT_V1,
        signature_id: TENSOR_SIGNATURE_2X3X2,
        quantization_id: ZKLLM_FIXED_V1,
        input_ptr: input.as_ptr() as u32,
        output_ptr: output.as_mut_ptr() as u32,
        m: 2,
        k: 3,
        n: 2,
        input_stride: 3,
        output_stride: 2,
        weight_tensor_id: 41,
        weight_tile_id: 0,
        model_root_ptr: model_root.as_ptr() as u32,
        reserved: [0; 2],
    };

    unsafe { tensor_matmul_v1(&desc) };
    assert_eq!(output, [4, 5, 10, 11]);
}
