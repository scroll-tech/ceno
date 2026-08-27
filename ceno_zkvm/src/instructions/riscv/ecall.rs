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
mod tensor_block;
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
pub use tensor_block::{
    TensorAttentionBlockReducedCoreInstruction, TensorAttentionBlockReducedEcallInstruction,
    TensorFfnBlockReducedCoreInstruction, TensorFfnBlockReducedEcallInstruction,
};
pub use tensor_production::{
    TensorMatMulHiddenEcallInstruction, TensorMatMulHiddenFinalizeInstruction,
    TensorMatMulIntermediateEcallInstruction, TensorMatMulIntermediateFinalizeInstruction,
    TensorProductionTileInstruction,
};
pub use tensor_rms::{TensorRmsLookupCoreInstruction, TensorRmsLookupEcallInstruction};
pub use uint256::{Secp256k1InvInstruction, Secp256r1InvInstruction, Uint256MulInstruction};
pub use weierstrass_add::WeierstrassAddAssignInstruction;
pub use weierstrass_decompress::WeierstrassDecompressInstruction;
pub use weierstrass_double::WeierstrassDoubleAssignInstruction;

pub use halt::HaltInstruction;
