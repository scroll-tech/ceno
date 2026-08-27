//! Topology-faithful reduced Llama layer using seven committed Tensor MatMuls.
//!
//! Nonlinear operations stay ordinary constrained RV32 code in this bridge
//! fixture.  Dedicated primitive AIR replaces them before the profile can be
//! called zkLLM-compatible.

use ceno_rt::tensor::{
    TENSOR_ABI_V1, TensorAttentionReducedDescV1, TensorMatMulDescV1, TensorRmsLookupDescV1,
    tensor_attention_reduced_v1, tensor_matmul_v1, tensor_rms_lookup_v1,
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
            let coefficient = 97 + lane * 19 + index as i64 * 23;
            acc = (acc + coefficient * i64::from(*value)).rem_euclid(MODULUS);
        }
        acc.rem_euclid(MODULUS) as u32
    })
}

fn matmul(tile: u32, value: [i32; 4]) -> [i32; 4] {
    let input = [value[0], value[1], 0, value[2], value[3], 0];
    let mut output = [0; 4];
    let root = commitment(tile);
    let desc = TensorMatMulDescV1 {
        abi_version: TENSOR_ABI_V1,
        flags: PROFILE,
        signature_id: SIGNATURE,
        quantization_id: QUANTIZATION,
        input_ptr: input.as_ptr() as u32,
        output_ptr: output.as_mut_ptr() as u32,
        m: 2,
        k: 3,
        n: 2,
        input_stride: 3,
        output_stride: 2,
        weight_tensor_id: TENSOR_ID,
        weight_tile_id: tile,
        model_root_ptr: root.as_ptr() as u32,
        reserved: [0; 2],
    };
    unsafe { tensor_matmul_v1(&desc) };
    output
}

fn rms_lookup(input: [i32; 4]) -> [i32; 4] {
    scalar_lookup(input, 1, 0x524d_5301)
}

fn swiglu_lookup(input: [i32; 4]) -> [i32; 4] {
    scalar_lookup(input, 2, 0x5357_4701)
}

fn rope_lookup(input: [i32; 4]) -> [i32; 4] {
    // This Gate-3 table commits the reduced Q16 identity rotation
    // (cos=2^16, sin=0). General angles require the production RoPE relation.
    scalar_lookup(input, 3, 0x524f_5001)
}

fn residual_lookup(left: [i32; 4], right: [i32; 4]) -> [i32; 4] {
    // The reduced fixture bounds both operands to [-16, 15]. This injective
    // packing makes the fixed table bind both boundary values and their sum.
    let packed = core::array::from_fn(|i| (left[i] + 16) * 32 + (right[i] + 16));
    scalar_lookup(packed, 4, 0x5245_5301)
}

fn scalar_lookup(input: [i32; 4], profile_id: u32, table_id: u32) -> [i32; 4] {
    core::array::from_fn(|i| {
        let mut output = 0i32;
        let desc = TensorRmsLookupDescV1 {
            abi_version: TENSOR_ABI_V1,
            profile_id,
            table_id,
            input_ptr: &input[i] as *const i32 as u32,
            output_ptr: &mut output as *mut i32 as u32,
            reserved: [0; 3],
        };
        unsafe { tensor_rms_lookup_v1(&desc) };
        output
    })
}

fn main() {
    let input = [1, -2, 3, -4];
    // RMSNorm lookup is the identity in this fixed fixture.
    let normalized = rms_lookup(input);
    let q = rope_lookup(matmul(0, normalized));
    let k = rope_lookup(matmul(1, normalized));
    let v = matmul(2, normalized);
    // The reduced split chip follows zkLLM's pinned segmented integer path.
    // Ceno additionally binds the explicit causal mask and segment origin.
    let mut attention = [0; 4];
    let desc = TensorAttentionReducedDescV1 {
        abi_version: TENSOR_ABI_V1,
        profile_id: 1,
        rescale_shift_id: 20,
        softmax_table_id: 0x4154_5401,
        softmax_table_commitment: [
            0x17d8_0ab1,
            0x05a1_1002,
            0x661c_9303,
            0x3f24_4404,
            0x019b_5505,
            0x70c2_6606,
            0x2dab_7707,
            0x4e31_8808,
        ],
        q_ptr: q.as_ptr() as u32,
        k_ptr: k.as_ptr() as u32,
        v_ptr: v.as_ptr() as u32,
        output_ptr: attention.as_mut_ptr() as u32,
        query_start: 0,
        key_start: 0,
        valid_key_length: 2,
        segment_start_accumulator: [0; 2],
        row_shifts: [11, 25],
        reserved: [0; 9],
    };
    unsafe { tensor_attention_reduced_v1(&desc) };
    let attention_projection = matmul(3, attention);
    let attention_residual = residual_lookup(input, attention_projection);
    let post_normalized = rms_lookup(attention_residual);
    let gate = matmul(4, post_normalized);
    let up = matmul(5, post_normalized);
    // Reduced fixed lookup maps these bounded gate values to themselves; the
    // Hadamard is deliberately scaled back into the Gate-2 input range.
    let swiglu = swiglu_lookup(gate);
    let down_input = core::array::from_fn(|i| swiglu[i] * up[i] / 256);
    let down = matmul(6, down_input);
    let output = residual_lookup(attention_residual, down);
    assert_eq!(output, [2, -4, 7, -10]);
}
