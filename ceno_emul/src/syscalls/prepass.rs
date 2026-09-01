//! Metadata-only heavy-ECALL dispatch for the first AOT planning pass.

use crate::{Tracer, VMState};
use anyhow::Result;

use super::SyscallEffects;

pub(super) fn handle_heavy_syscall<T: Tracer>(
    vm: &mut VMState<T>,
    code: u32,
) -> Option<Result<SyscallEffects>> {
    match code {
        crate::tensor::TENSOR_PRODUCTION_IMPORT_BEGIN_V2 => {
            Some(super::tensor::prepass_production_import_begin_v2(vm))
        }
        crate::tensor::TENSOR_PRODUCTION_STAGE_V2 => {
            Some(super::tensor::prepass_production_stage_v2(vm))
        }
        crate::tensor::TENSOR_PRODUCTION_EXPORT_END_V2 => {
            Some(super::tensor::prepass_production_export_end_v2(vm))
        }
        #[cfg(feature = "llama-tiny")]
        crate::tensor::TENSOR_BATCHED_MATMUL_2X2_V1 => Some(Err(anyhow::anyhow!(
            "PureAotPrepass has no exact metadata-only stub for heavy ECALL {code:#x}"
        ))),
        crate::tensor::TENSOR_MATMUL_V1
        | crate::tensor::TENSOR_MATMUL_HIDDEN_V1
        | crate::tensor::TENSOR_MATMUL_INTERMEDIATE_V1
        | crate::tensor::TENSOR_MATMUL_GATE5_SMALL_HIDDEN_V1
        | crate::tensor::TENSOR_RMS_LOOKUP_V1
        | crate::tensor::TENSOR_ATTENTION_REDUCED_V1
        | crate::tensor::TENSOR_ATTENTION_BLOCK_REDUCED_V1
        | crate::tensor::TENSOR_FFN_BLOCK_REDUCED_V1
        | crate::tensor::TENSOR_IMPORT_BEGIN_V1
        | crate::tensor::TENSOR_EXPORT_END_V1
        | crate::tensor::TENSOR_HANDLE_ATTENTION_V1
        | crate::tensor::TENSOR_HANDLE_FFN_V1
        | super::KECCAK_PERMUTE
        | super::KECCAK_XORIN
        | super::SECP256K1_ADD
        | super::SECP256K1_DECOMPRESS
        | super::SECP256K1_DOUBLE
        | super::SECP256K1_SCALAR_INVERT
        | super::SECP256R1_ADD
        | super::SECP256R1_DECOMPRESS
        | super::SECP256R1_DOUBLE
        | super::SECP256R1_SCALAR_INVERT
        | super::SHA_EXTEND
        | super::BN254_ADD
        | super::BN254_DOUBLE
        | super::BN254_FP_ADD
        | super::BN254_FP_MUL
        | super::BN254_FP2_ADD
        | super::BN254_FP2_MUL
        | super::UINT256_MUL => Some(Err(anyhow::anyhow!(
            "PureAotPrepass has no exact metadata-only stub for heavy ECALL {code:#x}"
        ))),
        _ => None,
    }
}
