//! Gate-4 reduced Llama layer expressed as two shard-atomic physical calls.

use ceno_rt::tensor::{
    TENSOR_ABI_V1, TensorBlockReducedDescV1, tensor_attention_block_reduced_v1,
    tensor_ffn_block_reduced_v1,
};

const PROFILE: u32 = 1;
const SIGNATURE: u32 = 7;
const QUANTIZATION: u32 = 1;
const TENSOR_ID: u32 = 73;
const MODULUS: i64 = 2_013_265_921;
const WEIGHTS: [i32; 6] = [65_536, 0, 0, 65_536, 0, 0];

fn commitment(tile: u32) -> [u32; 8] {
    core::array::from_fn(|lane| {
        let lane = lane as i64 + 1;
        let mut acc = 0x4741_5432_i64
            + 17 * i64::from(PROFILE)
            + 31 * i64::from(TENSOR_ID)
            + 43 * i64::from(tile)
            + 59 * 6
            + 71 * lane;
        for (index, value) in WEIGHTS.iter().enumerate() {
            acc = (acc + (97 + lane * 19 + index as i64 * 23) * i64::from(*value))
                .rem_euclid(MODULUS);
        }
        acc as u32
    })
}

fn main() {
    let input = [1i32, -2, 3, -4];
    let mut attention_output = [0i32; 4];
    let attention_roots: [[u32; 8]; 4] = core::array::from_fn(|tile| commitment(tile as u32));
    let attention = TensorBlockReducedDescV1 {
        abi_version: TENSOR_ABI_V1,
        profile_id: PROFILE,
        signature_id: SIGNATURE,
        quantization_id: QUANTIZATION,
        input_ptr: input.as_ptr() as u32,
        output_ptr: attention_output.as_mut_ptr() as u32,
        weight_roots_ptr: attention_roots.as_ptr() as u32,
        weight_tensor_id: TENSOR_ID,
        table_id: 0x4154_5401,
        table_commitment: [
            0x17d8_0ab1,
            0x05a1_1002,
            0x661c_9303,
            0x3f24_4404,
            0x019b_5505,
            0x70c2_6606,
            0x2dab_7707,
            0x4e31_8808,
        ],
        layer_id: 0,
        reserved: [0; 6],
    };
    unsafe { tensor_attention_block_reduced_v1(&attention) };

    let mut output = [0i32; 4];
    let ffn_roots: [[u32; 8]; 3] = core::array::from_fn(|index| commitment(4 + index as u32));
    let ffn = TensorBlockReducedDescV1 {
        input_ptr: attention_output.as_ptr() as u32,
        output_ptr: output.as_mut_ptr() as u32,
        weight_roots_ptr: ffn_roots.as_ptr() as u32,
        table_id: 0x4646_4e01,
        table_commitment: [
            0x51f1_0001,
            0x51f1_0002,
            0x51f1_0003,
            0x51f1_0004,
            0x51f1_0005,
            0x51f1_0006,
            0x51f1_0007,
            0x51f1_0008,
        ],
        ..attention
    };
    unsafe { tensor_ffn_block_reduced_v1(&ffn) };
    assert_eq!(output, [2, -4, 7, -10]);
}
