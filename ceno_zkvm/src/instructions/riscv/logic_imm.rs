#[cfg(not(feature = "u16limb_circuit"))]
mod logic_imm_circuit;

#[cfg(feature = "u16limb_circuit")]
mod logic_imm_circuit_v2;

#[cfg(not(feature = "u16limb_circuit"))]
pub use crate::instructions::riscv::logic_imm::logic_imm_circuit::LogicInstruction;

#[cfg(feature = "u16limb_circuit")]
pub use crate::instructions::riscv::logic_imm::logic_imm_circuit_v2::LogicInstruction;

#[cfg(test)]
mod test;

/// This trait defines a logic instruction, connecting an instruction type to a lookup table.
pub trait LogicOp {
    const INST_KIND: InsnKind;
    type OpsTable: OpsTable;
}

use gkr_iop::tables::ops::{AndTable, OrTable, XorTable};

use ceno_emul::InsnKind;
use gkr_iop::tables::OpsTable;

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
