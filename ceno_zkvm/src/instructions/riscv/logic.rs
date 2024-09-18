mod logic_circuit;
use logic_circuit::{LogicInstruction, LogicOp};

#[cfg(test)]
mod test;

use crate::ROMType;
use ceno_emul::InsnKind;

pub struct AndOp;
impl LogicOp for AndOp {
    const INST_KIND: InsnKind = InsnKind::AND;
    const ROM_TYPE: ROMType = ROMType::And;
}
pub type AndInstruction<E> = LogicInstruction<E, AndOp>;

pub struct OrOp;
impl LogicOp for OrOp {
    const INST_KIND: InsnKind = InsnKind::OR;
    const ROM_TYPE: ROMType = ROMType::Or;
}
pub type OrInstruction<E> = LogicInstruction<E, OrOp>;

pub struct XorOp;
impl LogicOp for XorOp {
    const INST_KIND: InsnKind = InsnKind::XOR;
    const ROM_TYPE: ROMType = ROMType::Xor;
}
pub type XorInstruction<E> = LogicInstruction<E, XorOp>;
