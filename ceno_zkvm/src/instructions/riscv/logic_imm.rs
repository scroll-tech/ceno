mod logic_imm_circuit;
use gkr_iop::tables::ops::{AndTable, OrTable, XorTable};
use logic_imm_circuit::{LogicInstruction, LogicOp};

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
