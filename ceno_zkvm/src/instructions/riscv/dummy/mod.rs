mod dummy_circuit;
use dummy_circuit::DummyInstruction;

#[cfg(test)]
mod test;

use super::{arith::AddOp, branch::BeqOp};

pub type AddDummy<E> = DummyInstruction<E, AddOp>;
pub type BeqDummy<E> = DummyInstruction<E, BeqOp>;
