mod branch_circuit;

use super::RIVInstruction;
use branch_circuit::BranchCircuit;
use ceno_emul::InsnKind;

#[cfg(test)]
mod test;

pub struct BeqOp;
impl RIVInstruction for BeqOp {
    const INST_KIND: InsnKind = InsnKind::BEQ;
}
pub type BeqInstruction<E> = BranchCircuit<E, BeqOp>;

pub struct BneOp;
impl RIVInstruction for BneOp {
    const INST_KIND: InsnKind = InsnKind::BNE;
}
pub type BneInstruction<E> = BranchCircuit<E, BneOp>;

pub struct BltuOp;
impl RIVInstruction for BltuOp {
    const INST_KIND: InsnKind = InsnKind::BLTU;
}
pub type BltuInstruction<E> = BranchCircuit<E, BltuOp>;

pub struct BgeuOp;
impl RIVInstruction for BgeuOp {
    const INST_KIND: InsnKind = InsnKind::BGEU;
}
pub type BgeuInstruction<E> = BranchCircuit<E, BgeuOp>;

pub struct BltOp;
impl RIVInstruction for BltOp {
    const INST_KIND: InsnKind = InsnKind::BLT;
}
pub type BltInstruction<E> = BranchCircuit<E, BltOp>;

pub struct BgeOp;
impl RIVInstruction for BgeOp {
    const INST_KIND: InsnKind = InsnKind::BGE;
}
pub type BgeInstruction<E> = BranchCircuit<E, BgeOp>;
