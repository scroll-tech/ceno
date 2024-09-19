mod logic_circuit;
use logic_circuit::{LogicInstruction, LogicOp};

#[cfg(test)]
mod test;

use crate::tables::{AndTable, OrTable, XorTable};
use ceno_emul::InsnKind;

pub struct AndOp;
impl LogicOp for AndOp {
    const INST_KIND: InsnKind = InsnKind::AND;
    type OpsTable = AndTable;
}
pub type AndInstruction<E> = LogicInstruction<E, AndOp>;

pub struct OrOp;
impl LogicOp for OrOp {
    const INST_KIND: InsnKind = InsnKind::OR;
    type OpsTable = OrTable;
}
pub type OrInstruction<E> = LogicInstruction<E, OrOp>;

pub struct XorOp;
impl LogicOp for XorOp {
    const INST_KIND: InsnKind = InsnKind::XOR;
    type OpsTable = XorTable;
}
pub type XorInstruction<E> = LogicInstruction<E, XorOp>;
