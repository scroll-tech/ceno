mod gadget;

#[cfg(not(feature = "u16limb_circuit"))]
pub mod load;
#[cfg(not(feature = "u16limb_circuit"))]
pub mod store;

#[cfg(feature = "u16limb_circuit")]
mod load_v2;
#[cfg(feature = "u16limb_circuit")]
mod store_v2;
#[cfg(test)]
mod test;

use crate::instructions::riscv::RIVInstruction;
#[cfg(not(feature = "u16limb_circuit"))]
pub use crate::instructions::riscv::memory::load::LoadInstruction;
#[cfg(feature = "u16limb_circuit")]
pub use crate::instructions::riscv::memory::load_v2::LoadInstruction;
#[cfg(not(feature = "u16limb_circuit"))]
pub use crate::instructions::riscv::memory::store::StoreInstruction;
#[cfg(feature = "u16limb_circuit")]
pub use crate::instructions::riscv::memory::store_v2::StoreInstruction;

use ceno_emul::InsnKind;

pub struct LwOp;

impl RIVInstruction for LwOp {
    const INST_KIND: InsnKind = InsnKind::LW;
}

pub type LwInstruction<E> = LoadInstruction<E, LwOp>;

pub struct LhOp;

impl RIVInstruction for LhOp {
    const INST_KIND: InsnKind = InsnKind::LH;
}
pub type LhInstruction<E> = LoadInstruction<E, LhOp>;

pub struct LhuOp;

impl RIVInstruction for LhuOp {
    const INST_KIND: InsnKind = InsnKind::LHU;
}
pub type LhuInstruction<E> = LoadInstruction<E, LhuOp>;

pub struct LbOp;

impl RIVInstruction for LbOp {
    const INST_KIND: InsnKind = InsnKind::LB;
}
pub type LbInstruction<E> = LoadInstruction<E, LbOp>;

pub struct LbuOp;

impl RIVInstruction for LbuOp {
    const INST_KIND: InsnKind = InsnKind::LBU;
}
pub type LbuInstruction<E> = LoadInstruction<E, LbuOp>;

pub struct SWOp;

impl RIVInstruction for SWOp {
    const INST_KIND: InsnKind = InsnKind::SW;
}
pub type SwInstruction<E> = StoreInstruction<E, SWOp, 2>;

pub struct SHOp;

impl RIVInstruction for SHOp {
    const INST_KIND: InsnKind = InsnKind::SH;
}
pub type ShInstruction<E> = StoreInstruction<E, SHOp, 1>;

pub struct SBOp;

impl RIVInstruction for SBOp {
    const INST_KIND: InsnKind = InsnKind::SB;
}
pub type SbInstruction<E> = StoreInstruction<E, SBOp, 0>;
