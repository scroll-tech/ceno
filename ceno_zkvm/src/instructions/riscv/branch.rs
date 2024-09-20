mod beq_circuit;
use super::RIVInstruction;
use beq_circuit::BeqCircuit;
use ceno_emul::InsnKind;

#[cfg(test)]
mod test;

pub struct BeqOp;
impl RIVInstruction for BeqOp {
    const INST_KIND: InsnKind = InsnKind::BEQ;
}
pub type BeqInstruction<E> = BeqCircuit<E, BeqOp>;

pub struct BneOp;
impl RIVInstruction for BneOp {
    const INST_KIND: InsnKind = InsnKind::BNE;
}
pub type BneInstruction<E> = BeqCircuit<E, BneOp>;
