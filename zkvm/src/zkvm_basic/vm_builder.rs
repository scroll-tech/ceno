pub(crate) mod bit_op_processor;
pub(crate) mod bytecode_checker;
pub(crate) mod global_state_checker;
pub(crate) mod hasher;
pub(crate) mod memory;
pub(crate) mod opcode_processor;
pub(crate) mod range_checker;
pub(crate) mod stack;
pub(crate) mod structs;

use frontend::structs::CircuitBuilder;
use goldilocks::SmallField;

use crate::structs::OpcodeType;

use super::structs::VMBasicBuilder;

impl<F: SmallField> VMBasicBuilder<F> {
    pub fn new() -> Self {
        todo!()
    }

    /// Add circuit for an opcode. Should create only one circuit for each
    /// opcode type.
    pub fn build(&mut self, bytecode: &[u8]) {
        self.initialize();

        let mut i = 0;
        while i < bytecode.len() {
            // convert u8 to OpcodeType
            let opcode = OpcodeType::from(bytecode[i]);
            match opcode {
                OpcodeType::Push1 => {
                    self.push1();
                    i += 1
                }
                OpcodeType::Pop => self.pop(),
                OpcodeType::Dup2 => self.dup2(),
                OpcodeType::Swap2 => self.swap2(),
                OpcodeType::Swap4 => self.swap4(),
                OpcodeType::Add => self.add(),
                OpcodeType::Gt => self.gt(),
                OpcodeType::Jumpi => self.jumpi(),
                OpcodeType::Jump => self.jump(),
                OpcodeType::Mstore => self.mstore(),
                OpcodeType::Jumpdest => self.jumpdest(),
                OpcodeType::Return => self.program_return(),
            }
        }

        self.finalize();
    }

    fn initialize(&mut self) {
        todo!()
    }

    fn finalize(&mut self) {
        todo!()
    }

    fn push1(&mut self) {
        todo!()
    }

    fn pop(&mut self) {
        todo!()
    }

    fn dup2(&mut self) {
        todo!()
    }

    fn swap2(&mut self) {
        todo!()
    }

    fn swap4(&mut self) {
        todo!()
    }

    fn add(&mut self) {
        todo!()
    }

    fn gt(&mut self) {
        todo!()
    }

    fn jumpi(&mut self) {
        todo!()
    }

    fn jump(&mut self) {
        todo!()
    }

    fn mstore(&mut self) {
        todo!()
    }

    fn jumpdest(&mut self) {
        todo!()
    }

    fn program_return(&mut self) {
        todo!()
    }
}

impl From<u8> for OpcodeType {
    fn from(value: u8) -> Self {
        match value {
            0x60 => OpcodeType::Push1,
            0x50 => OpcodeType::Pop,
            0x8d => OpcodeType::Dup2,
            0x91 => OpcodeType::Swap2,
            0x93 => OpcodeType::Swap4,
            0x01 => OpcodeType::Add,
            0x0a => OpcodeType::Gt,
            0x57 => OpcodeType::Jumpi,
            0x56 => OpcodeType::Jump,
            0x52 => OpcodeType::Mstore,
            0x5b => OpcodeType::Jumpdest,
            _ => todo!("Opcode not supported"),
        }
    }
}
