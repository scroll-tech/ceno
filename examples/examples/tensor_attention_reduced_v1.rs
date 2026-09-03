//! Standalone reduced causal-attention guest for Gate-5 E2E expansion.

use ceno_rt::tensor::{TENSOR_ABI_V1, TensorAttentionReducedDescV1, tensor_attention_reduced_v1};

fn main() {
    let q = [1_i32, -2, 3, -4];
    let k = q;
    let v = q;
    let mut output = [0_i32; 4];
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
        output_ptr: output.as_mut_ptr() as u32,
        query_start: 0,
        key_start: 0,
        valid_key_length: 2,
        segment_start_accumulator: [0; 2],
        row_shifts: [11, 25],
        reserved: [0; 9],
    };
    unsafe { tensor_attention_reduced_v1(&desc) };
    core::hint::black_box(output);
}
