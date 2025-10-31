mod halt;
mod keccak;
mod weierstrass_add;
mod weierstrass_decompress;
mod weierstrass_double;

pub use keccak::KeccakInstruction;
pub use weierstrass_add::WeierstrassAddAssignInstruction;
pub use weierstrass_decompress::WeierstrassDecompressInstruction;
pub use weierstrass_double::WeierstrassDoubleAssignInstruction;

use ceno_emul::InsnKind;
pub use halt::HaltInstruction;

use super::{RIVInstruction, dummy::DummyInstruction};

pub struct EcallOp;

impl RIVInstruction for EcallOp {
    const INST_KIND: InsnKind = InsnKind::ECALL;
}
/// Unsafe. A dummy ecall circuit that ignores unimplemented functions.
pub type EcallDummy<E> = DummyInstruction<E, EcallOp>;
