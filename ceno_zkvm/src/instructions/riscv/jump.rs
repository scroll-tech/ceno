mod auipc;
mod jal;
mod lui;

use super::RIVInstruction;
use auipc::AuipcCircuit;
use ceno_emul::InsnKind;
use jal::JalCircuit;
use lui::LuiCircuit;

#[cfg(test)]
mod test;

pub struct JalOp;
impl RIVInstruction for JalOp {
    const INST_KIND: InsnKind = InsnKind::JAL;
}
pub type JalInstruction<E> = JalCircuit<E, JalOp>;

pub struct LuiOp;
impl RIVInstruction for LuiOp {
    const INST_KIND: InsnKind = InsnKind::LUI;
}
pub type LuiInstruction<E> = LuiCircuit<E, LuiOp>;

pub struct AuipcOp;
impl RIVInstruction for AuipcOp {
    const INST_KIND: InsnKind = InsnKind::AUIPC;
}
pub type AuipcInstruction<E> = AuipcCircuit<E, AuipcOp>;
