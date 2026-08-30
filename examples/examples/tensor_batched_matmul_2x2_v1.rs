//! Two complete guest calls feeding one tiny batched MatMul Core proof.

#[cfg(feature = "llama-tiny")]
use ceno_rt::tensor::{TENSOR_ABI_V1, TensorBatchedMatMul2x2DescV1, tensor_batched_matmul_2x2_v1};

#[cfg(feature = "llama-tiny")]
fn call(a: &[i32; 4], w: &[i32; 4], expected: [u32; 4]) {
    let mut quotient = [0_i32; 4];
    let mut remainder = [0_u32; 4];
    let desc = TensorBatchedMatMul2x2DescV1 {
        abi_version: TENSOR_ABI_V1,
        flags: 0,
        a_ptr: a.as_ptr() as u32,
        w_ptr: w.as_ptr() as u32,
        quotient_ptr: quotient.as_mut_ptr() as u32,
        remainder_ptr: remainder.as_mut_ptr() as u32,
        reserved: [0; 2],
    };
    unsafe { tensor_batched_matmul_2x2_v1(&desc) };
    assert_eq!(quotient, [0; 4]);
    assert_eq!(remainder, expected);
}

#[cfg(feature = "llama-tiny")]
fn main() {
    call(&[1, 2, 3, 4], &[5, 6, 7, 8], [19, 22, 43, 50]);
    call(&[2, 1, 4, 3], &[3, 5, 7, 11], [13, 21, 33, 53]);
}

#[cfg(not(feature = "llama-tiny"))]
fn main() {}
