use super::RIVInstruction;
use ceno_emul::InsnKind;

mod branch_circuit;
mod branch_circuit_v2;
#[cfg(test)]
mod test;

pub struct BeqOp;
impl RIVInstruction for BeqOp {
    const INST_KIND: InsnKind = InsnKind::BEQ;
}
#[cfg(feature = "u16limb_circuit")]
// TODO use branch_circuit_v2
pub type BeqInstruction<E> = branch_circuit::BranchCircuit<E, BeqOp>;
#[cfg(not(feature = "u16limb_circuit"))]
pub type BeqInstruction<E> = branch_circuit::BranchCircuit<E, BeqOp>;

pub struct BneOp;
impl RIVInstruction for BneOp {
    const INST_KIND: InsnKind = InsnKind::BNE;
}
#[cfg(feature = "u16limb_circuit")]
// TODO use branch_circuit_v2
pub type BneInstruction<E> = branch_circuit::BranchCircuit<E, BneOp>;
#[cfg(not(feature = "u16limb_circuit"))]
pub type BneInstruction<E> = branch_circuit::BranchCircuit<E, BneOp>;

pub struct BltuOp;
impl RIVInstruction for BltuOp {
    const INST_KIND: InsnKind = InsnKind::BLTU;
}
#[cfg(feature = "u16limb_circuit")]
// TODO use branch_circuit_v2
pub type BltuInstruction<E> = branch_circuit::BranchCircuit<E, BltuOp>;
#[cfg(not(feature = "u16limb_circuit"))]
pub type BltuInstruction<E> = branch_circuit::BranchCircuit<E, BltuOp>;

pub struct BgeuOp;
impl RIVInstruction for BgeuOp {
    const INST_KIND: InsnKind = InsnKind::BGEU;
}
#[cfg(feature = "u16limb_circuit")]
// TODO use branch_circuit_v2
pub type BgeuInstruction<E> = branch_circuit::BranchCircuit<E, BgeuOp>;
#[cfg(not(feature = "u16limb_circuit"))]
pub type BgeuInstruction<E> = branch_circuit::BranchCircuit<E, BgeuOp>;

pub struct BltOp;
impl RIVInstruction for BltOp {
    const INST_KIND: InsnKind = InsnKind::BLT;
}
#[cfg(feature = "u16limb_circuit")]
// TODO use branch_circuit_v2
pub type BltInstruction<E> = branch_circuit::BranchCircuit<E, BltOp>;
#[cfg(not(feature = "u16limb_circuit"))]
pub type BltInstruction<E> = branch_circuit_v2::BranchCircuit<E, BltOp>;

pub struct BgeOp;
impl RIVInstruction for BgeOp {
    const INST_KIND: InsnKind = InsnKind::BGE;
}
#[cfg(feature = "u16limb_circuit")]
// TODO use branch_circuit_v2
pub type BgeInstruction<E> = branch_circuit::BranchCircuit<E, BgeOp>;
#[cfg(not(feature = "u16limb_circuit"))]
pub type BgeInstruction<E> = branch_circuit_v2::BranchCircuit<E, BgeOp>;
