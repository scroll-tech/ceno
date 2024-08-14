use ff_ext::ExtensionField;

use crate::{circuit_builder::CircuitBuilder, error::ZKVMError};

pub mod riscv;

pub trait Instruction<E: ExtensionField> {
    type InstructionConfig;
    fn construct_circuit(
        circuit_builder: &mut CircuitBuilder<E>,
    ) -> Result<Self::InstructionConfig, ZKVMError>;
}
