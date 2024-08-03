use ff_ext::ExtensionField;
use singer_utils::constants::OpcodeType;

use crate::{circuit_builder::CircuitBuilder, error::ZKVMError};

pub mod riscv;

pub trait Instruction<E: ExtensionField> {
    const OPCODE: OpcodeType;
    const NAME: &'static str;
    type InstructionConfig;
    fn construct_circuit(
        circuit_builder: &mut CircuitBuilder<E>,
    ) -> Result<Self::InstructionConfig, ZKVMError>;
}
