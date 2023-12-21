use goldilocks::SmallField;

use crate::{structs::OpcodeType, zkvm_basic::structs::VMBasicInterpreter};

pub(crate) mod structs;

impl<F: SmallField> VMBasicInterpreter<F> {
    pub fn new() -> Self {
        todo!()
    }

    /// Simulate the VM execution, generate the necessary information for the
    /// execution trace and the private input for proving each opcode.
    pub fn run(&mut self, bytecode: &[u8], input: &[u8]) {
        self.initialize();

        while self.program_counter < bytecode.len() {
            let opcode = OpcodeType::from(bytecode[self.program_counter]);
            self.execute_instruction(opcode);
            self.program_counter += 1;
        }

        self.finalize();
    }

    /// Initialize the VM.
    fn initialize(&mut self) {
        todo!()
    }

    fn finalize(&mut self) {
        todo!()
    }

    fn execute_instruction(&mut self, opcode: OpcodeType) {
        todo!()
    }

    fn push1(&mut self, oprand: u8) {
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
