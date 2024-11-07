//! Dummy instruction circuits for testing.
//! Support instructions that don’t have a complete implementation yet.
//! It connects all the state together (register writes, etc), but does not verify the values.
//!
//! Usage:
//! Specify an instruction with `trait RIVInstruction` and define a `DummyInstruction` like so:
//!
//!     use ceno_zkvm::instructions::riscv::{arith::AddOp, dummy::DummyInstruction};
//!
//!     type AddDummy<E> = DummyInstruction<E, AddOp>;

mod dummy_circuit;
use ceno_emul::InsnKind;
pub use dummy_circuit::DummyInstruction;

use super::RIVInstruction;

pub struct EcallOp;
impl RIVInstruction for EcallOp {
    const INST_KIND: InsnKind = InsnKind::EANY;
}
pub type EcallDummy<E> = DummyInstruction<E, EcallOp>;

#[cfg(test)]
mod test;
