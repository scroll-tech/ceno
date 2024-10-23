mod logic_imm_circuit;
use logic_imm_circuit::{LogicInstruction, LogicOp};

use crate::tables::{AndTable, OrTable, XorTable};
use ceno_emul::InsnKind;

pub struct AndiOp;
impl LogicOp for AndiOp {
    const INST_KIND: InsnKind = InsnKind::ANDI;
    type OpsTable = AndTable;
}
pub type AndiInstruction<E> = LogicInstruction<E, AndiOp>;

pub struct OriOp;
impl LogicOp for OriOp {
    const INST_KIND: InsnKind = InsnKind::ORI;
    type OpsTable = OrTable;
}
pub type OriInstruction<E> = LogicInstruction<E, OriOp>;

pub struct XoriOp;
impl LogicOp for XoriOp {
    const INST_KIND: InsnKind = InsnKind::XORI;
    type OpsTable = XorTable;
}
pub type XoriInstruction<E> = LogicInstruction<E, XoriOp>;
