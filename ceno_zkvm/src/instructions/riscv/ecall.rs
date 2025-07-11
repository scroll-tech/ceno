mod halt;
mod keccak;
pub use keccak::KeccakInstruction;

use ceno_emul::InsnKind;
pub use halt::HaltInstruction;

use super::{RIVInstruction, dummy::DummyInstruction};

pub struct EcallOp;
impl RIVInstruction for EcallOp {
    const INST_KIND: InsnKind = InsnKind::ECALL;
}
/// Unsafe. A dummy ecall circuit that ignores unimplemented functions.
pub type EcallDummy<E> = DummyInstruction<E, EcallOp>;
