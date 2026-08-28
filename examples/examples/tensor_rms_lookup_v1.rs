//! Smallest standalone reduced RMS lookup guest for Gate-5 E2E expansion.

use ceno_rt::tensor::{TENSOR_ABI_V1, TensorRmsLookupDescV1, tensor_rms_lookup_v1};

fn main() {
    let input = -4_i32;
    let mut output = 0_i32;
    let desc = TensorRmsLookupDescV1 {
        abi_version: TENSOR_ABI_V1,
        profile_id: 1,
        table_id: 0x524d_5301,
        input_ptr: &input as *const i32 as u32,
        output_ptr: &mut output as *mut i32 as u32,
        reserved: [0; 3],
    };
    unsafe { tensor_rms_lookup_v1(&desc) };
    assert_eq!(output, -4);
}
