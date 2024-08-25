use crate::Inst;

/// An instruction and its context in an execution trace. That is concrete values of registers and memory.
#[derive(Clone, Debug)]
pub struct InstValues {
    inst: Inst,

    cycle: u32,
    pc: u32,

    rs1: u32,
    rs2: u32,

    rd_before: u32,
    memory_before: u32,
}

impl InstValues {
    pub fn inst(&self) -> Inst {
        self.inst
    }

    pub fn cycle(&self) -> u32 {
        self.cycle
    }

    pub fn pc(&self) -> u32 {
        self.pc
    }

    pub fn rs1(&self) -> u32 {
        self.rs1
    }

    pub fn rs2(&self) -> u32 {
        self.rs2
    }

    pub fn rd_before(&self) -> u32 {
        self.rd_before
    }

    pub fn memory_before(&self) -> u32 {
        self.memory_before
    }

    pub fn pc_after(&self) -> u32 {
        todo!(); // Compute from the instruction and registers.
    }

    pub fn rd_after(&self) -> u32 {
        todo!(); // Compute from the instruction, registers, and memory.
    }

    pub fn memory_after(&self) -> u32 {
        todo!(); // Compute from the instruction and registers.
    }

    pub fn memory_address(&self) -> u32 {
        todo!(); // Compute from the instruction and registers.
    }
}
