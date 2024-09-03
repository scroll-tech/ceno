use std::{collections::HashMap, fmt, mem};

use crate::{
    addr::{ByteAddr, Cycle, RegIdx, Word, WordAddr},
    rv32im::DecodedInstruction,
    CENO_PLATFORM,
};

/// An instruction and its context in an execution trace. That is concrete values of registers and memory.
#[derive(Clone, Debug, Default)]
pub struct StepRecord {
    cycle: Cycle, // TODO: start from 1.
    pc: Change<ByteAddr>,
    insn_code: Word,

    rs1: (RegIdx, Word),
    rs2: (RegIdx, Word),

    rd: (RegIdx, Change<Word>),

    memory_op: (WordAddr, Change<Word>),
}

impl StepRecord {
    pub fn cycle(&self) -> Cycle {
        self.cycle
    }

    pub fn pc(&self) -> Change<ByteAddr> {
        self.pc
    }

    pub fn insn_code(&self) -> Word {
        self.insn_code
    }

    pub fn insn_decoded(&self) -> DecodedInstruction {
        DecodedInstruction::new(self.insn_code)
    }

    pub fn rs1(&self) -> (RegIdx, Word) {
        self.rs1
    }

    pub fn rs2(&self) -> (RegIdx, Word) {
        self.rs2
    }

    pub fn rd(&self) -> (RegIdx, Change<Word>) {
        self.rd
    }

    pub fn memory_op(&self) -> (WordAddr, Change<Word>) {
        self.memory_op
    }
}

#[derive(Debug, Default)]
struct StepActions {
    rs1_loaded: bool,
    rs2_loaded: bool,
    rd_stored: bool,
    memory_loaded: bool,
    memory_stored: bool,
}

#[derive(Debug, Default)]
pub struct Tracer {
    record: StepRecord,
    actions: StepActions,

    previous_mem_op: HashMap<WordAddr, Cycle>,
}

impl Tracer {
    pub fn advance(&mut self) -> StepRecord {
        // Reset and advance to the next cycle.
        let actions = mem::take(&mut self.actions);
        let record = mem::take(&mut self.record);
        self.record.cycle = record.cycle + 1;

        // Track this step as the origin of its memory accesses.
        let mut track_mem = |vma| self.previous_mem_op.insert(vma, record.cycle);

        if actions.rs1_loaded {
            track_mem(CENO_PLATFORM.register_vma(record.rs1.0).into());
        }
        if actions.rs2_loaded {
            track_mem(CENO_PLATFORM.register_vma(record.rs2.0).into());
        }
        if actions.rd_stored {
            track_mem(CENO_PLATFORM.register_vma(record.rd.0).into());
        }
        if actions.memory_loaded || actions.memory_stored {
            track_mem(record.memory_op.0);
        }

        record
    }

    pub fn store_pc(&mut self, pc: ByteAddr) {
        self.record.pc.after = pc;
    }

    pub fn fetch(&mut self, pc: WordAddr, value: Word) {
        self.record.pc.before = pc.baddr();
        self.record.insn_code = value;
    }

    pub fn load_register(&mut self, idx: RegIdx, value: Word) {
        match (self.actions.rs1_loaded, self.actions.rs2_loaded) {
            (false, false) => {
                self.record.rs1 = (idx, value);
                self.actions.rs1_loaded = true;
            }
            (true, false) => {
                self.record.rs2 = (idx, value);
                self.actions.rs2_loaded = true;
            }
            _ => unimplemented!("Only two register reads are supported"),
        }
    }

    pub fn store_register(&mut self, idx: RegIdx, value: Change<Word>) {
        if !self.actions.rd_stored {
            self.record.rd = (idx, value);
            self.actions.rd_stored = true;
        } else {
            unimplemented!("Only one register write is supported");
        }
    }

    pub fn load_memory(&mut self, addr: WordAddr, value: Word) {
        if self.actions.memory_loaded || self.actions.memory_stored {
            unimplemented!("Only one memory load is supported");
        }
        self.actions.memory_loaded = true;
        self.record.memory_op = (addr, Change::new(value, value));
    }

    pub fn store_memory(&mut self, addr: WordAddr, value: Change<Word>) {
        if self.actions.memory_stored {
            unimplemented!("Only one memory store is supported");
        }
        self.actions.memory_stored = true;
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
