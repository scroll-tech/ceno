mod logic_circuit;
use gkr_iop::tables::ops::{AndTable, OrTable, XorTable};
use logic_circuit::{LogicInstruction, LogicOp};

#[cfg(test)]
mod test;

use ceno_emul::InsnKind;

#[derive(Default)]
pub struct AndOp;

impl LogicOp for AndOp {
    const INST_KIND: InsnKind = InsnKind::AND;
    type OpsTable = AndTable;
}
pub type AndInstruction<E> = LogicInstruction<E, AndOp>;

#[derive(Default)]
pub struct OrOp;

impl LogicOp for OrOp {
    const INST_KIND: InsnKind = InsnKind::OR;
    type OpsTable = OrTable;
}
pub type OrInstruction<E> = LogicInstruction<E, OrOp>;

#[derive(Default)]
pub struct XorOp;

impl LogicOp for XorOp {
    const INST_KIND: InsnKind = InsnKind::XOR;
    type OpsTable = XorTable;
}
pub type XorInstruction<E> = LogicInstruction<E, XorOp>;
