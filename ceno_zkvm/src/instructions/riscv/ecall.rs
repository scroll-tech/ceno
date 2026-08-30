mod fptower_fp;
mod fptower_fp2_add;
mod fptower_fp2_mul;
mod halt;
pub(crate) mod keccak;
mod keccak_xorin;
mod pubio_commit;
mod sha_extend;
mod tensor;
mod tensor_attention;
#[cfg(feature = "llama-tiny")]
pub mod tensor_batched_matmul;
#[cfg(feature = "llama-tiny")]
mod tensor_batched_matmul_ecall;
mod tensor_block;
mod tensor_bus;
mod tensor_production;
mod tensor_rms;
mod uint256;
mod weierstrass_add;
mod weierstrass_decompress;
mod weierstrass_double;

pub use fptower_fp::{FpAddInstruction, FpMulInstruction};
pub use fptower_fp2_add::Fp2AddInstruction;
pub use fptower_fp2_mul::Fp2MulInstruction;
pub use keccak::{KeccakCoreInstruction, KeccakEcallInstruction, KeccakInstruction};
pub use keccak_xorin::KeccakXorinInstruction;
pub use pubio_commit::PubIoCommitInstruction;
pub use sha_extend::ShaExtendInstruction;
pub use tensor::{TensorMatMulCoreInstruction, TensorMatMulEcallInstruction};
pub use tensor_attention::{
    TensorAttentionReducedCoreInstruction, TensorAttentionReducedEcallInstruction,
};
#[cfg(feature = "llama-tiny")]
pub use tensor_batched_matmul::{TensorBatchedMatMulCoreInstruction, TensorHintRefCoreInstruction};
#[cfg(feature = "llama-tiny")]
pub use tensor_batched_matmul_ecall::TensorBatchedMatMul2x2EcallInstruction;
pub use tensor_block::{
    TensorAttentionBlockReducedCoreInstruction, TensorAttentionBlockReducedEcallInstruction,
    TensorFfnBlockReducedCoreInstruction, TensorFfnBlockReducedEcallInstruction,
};
pub use tensor_bus::{
    TensorBusExportEndEcallInstruction, TensorBusHandleAttentionEcallInstruction,
    TensorBusHandleFfnEcallInstruction, TensorBusImportBeginEcallInstruction,
};
pub use tensor_production::{
    TensorMatMulGate5SmallHiddenEcallInstruction, TensorMatMulGate5SmallHiddenFinalizeInstruction,
    TensorMatMulHiddenEcallInstruction, TensorMatMulHiddenFinalizeInstruction,
    TensorMatMulIntermediateEcallInstruction, TensorMatMulIntermediateFinalizeInstruction,
    TensorProductionTileInstruction, TensorProductionTileK64Instruction,
};
pub use tensor_rms::{TensorRmsLookupCoreInstruction, TensorRmsLookupEcallInstruction};
pub use uint256::{Secp256k1InvInstruction, Secp256r1InvInstruction, Uint256MulInstruction};
pub use weierstrass_add::WeierstrassAddAssignInstruction;
pub use weierstrass_decompress::WeierstrassDecompressInstruction;
pub use weierstrass_double::WeierstrassDoubleAssignInstruction;

pub use halt::HaltInstruction;
