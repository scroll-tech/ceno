mod jal;

use super::RIVInstruction;
use ceno_emul::InsnKind;

// #[cfg(test)]
// mod test;

pub struct JalOp;
impl RIVInstruction for JalOp {
    const INST_KIND: InsnKind = InsnKind::JAL;
}
pub type JalInstruction<E> = jal::JalInstruction<E, JalOp>;
