use std::fmt;

use crate::{
    addr::{ByteAddr, RegIdx, WordAddr},
    rv32im::DecodedInstruction,
};

/// An instruction and its context in an execution trace. That is concrete values of registers and memory.
#[derive(Clone, Debug, Default)]
pub struct StepRecord {
    cycle: u32,
    pc: Change<ByteAddr>,
    insn_code: u32,

    rs1: (RegIdx, u32),
    rs2: (RegIdx, u32),

    rd: (RegIdx, Change<u32>),

    memory_op: (WordAddr, Change<u32>),
}

impl StepRecord {
    pub fn cycle(&self) -> u32 {
        self.cycle
    }

    pub fn pc(&self) -> Change<ByteAddr> {
        self.pc
    }

    pub fn insn_code(&self) -> u32 {
        self.insn_code
    }

    pub fn insn_decoded(&self) -> DecodedInstruction {
        DecodedInstruction::new(self.insn_code)
    }

    pub fn rs1(&self) -> (RegIdx, u32) {
        self.rs1
    }

    pub fn rs2(&self) -> (RegIdx, u32) {
        self.rs2
    }

    pub fn rd(&self) -> (RegIdx, Change<u32>) {
        self.rd
    }

    pub fn memory_op(&self) -> (WordAddr, Change<u32>) {
        self.memory_op
    }
}

#[derive(Debug, Default)]
pub struct Tracer {
    record: StepRecord,

    rs1_loaded: bool,
    rs2_loaded: bool,
    rd_stored: bool,
    memory_loaded: bool,
    memory_stored: bool,
}

impl Tracer {
    pub fn advance(&mut self) -> StepRecord {
        let record = std::mem::take(self).record;
        self.record.cycle = record.cycle + 1;
        record
    }

    pub fn store_pc(&mut self, pc: ByteAddr) {
        self.record.pc.after = pc;
    }

    pub fn fetch(&mut self, pc: WordAddr, value: u32) {
        self.record.pc.before = pc.baddr();
        self.record.insn_code = value;
    }

    pub fn load_register(&mut self, idx: usize, value: u32) {
        match (self.rs1_loaded, self.rs2_loaded) {
            (false, false) => {
                self.record.rs1 = (idx, value);
                self.rs1_loaded = true;
            }
            (true, false) => {
                self.record.rs2 = (idx, value);
                self.rs2_loaded = true;
            }
            _ => unimplemented!("Only two register reads are supported"),
        }
    }

    pub fn store_register(&mut self, idx: usize, value: Change<u32>) {
        if !self.rd_stored {
            self.record.rd = (idx, value);
            self.rd_stored = true;
        } else {
            unimplemented!("Only one register write is supported");
        }
    }

    pub fn load_memory(&mut self, addr: WordAddr, value: u32) {
        if self.memory_loaded || self.memory_stored {
            unimplemented!("Only one memory load is supported");
        }
        self.memory_loaded = true;
        self.record.memory_op = (addr, Change::new(value, value));
    }

    pub fn store_memory(&mut self, addr: WordAddr, value: Change<u32>) {
        if self.memory_stored {
            unimplemented!("Only one memory store is supported");
        }
        self.memory_stored = true;
        self.record.memory_op = (addr, value);
    }
}

#[derive(Copy, Clone, Default)]
pub struct Change<T> {
    pub before: T,
    pub after: T,
}

impl<T> Change<T> {
    pub fn new(before: T, after: T) -> Change<T> {
        Change { before, after }
    }
}

impl<T: fmt::Debug> fmt::Debug for Change<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?} -> {:?}", self.before, self.after)
    }
}
