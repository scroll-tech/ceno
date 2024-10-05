mod jal;

use super::RIVInstruction;
use ceno_emul::InsnKind;
use jal::JalCircuit;

#[cfg(test)]
mod test;

pub struct JalOp;
impl RIVInstruction for JalOp {
    const INST_KIND: InsnKind = InsnKind::JAL;
}
pub type JalInstruction<E> = JalCircuit<E, JalOp>;
