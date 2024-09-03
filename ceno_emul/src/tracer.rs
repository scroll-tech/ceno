use std::{collections::HashMap, fmt, mem};

use crate::{
    addr::{ByteAddr, Cycle, RegIdx, Word, WordAddr},
    rv32im::DecodedInstruction,
    CENO_PLATFORM,
};

/// An instruction and its context in an execution trace. That is concrete values of registers and memory.
///
/// - Registers are assigned a VMA (virtual memory address, u32). This way they can be unified with the RAM check.
/// - It is possible that the `rs1 / rs2 / rd` **be the same**. Then, they point to the **same previous cycle**. The circuits need to handle this case.
/// - Any of `rs1 / rs2 / rd` may be `x0`. The trace handles this like any register, including the value that was _supposed_ to be stored. The circuits must handle this case, either by storing 0 or by skipping x0 operations.
/// - `cycle = 0` means initialization; that is all the special startup logic we are going to have. The RISC-V program starts at `cycle = 1`.
/// - We assume that the PC was written at `cycle - 1` so we don’t store this.
#[derive(Clone, Debug, Default)]
pub struct StepRecord {
    cycle: Cycle,
    pc: Change<ByteAddr>,
    insn_code: Word,

    rs1: Option<ReadOp>,
    rs2: Option<ReadOp>,

    rd: Option<WriteOp>,

    memory_op: Option<WriteOp>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct MemOp<T> {
    /// Virtual Memory Address.
    /// For registers, get it from `CENO_PLATFORM.register_vma(idx)`.
    pub addr: WordAddr,
    /// The Word read, or the Change<Word> to be written.
    pub value: T,
    /// The cycle when this memory address was last accessed before this operation.
    pub previous_cycle: Cycle,
}

pub type ReadOp = MemOp<Word>;
pub type WriteOp = MemOp<Change<Word>>;

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

    pub fn rs1(&self) -> Option<ReadOp> {
        self.rs1.clone()
    }

    pub fn rs2(&self) -> Option<ReadOp> {
        self.rs2.clone()
    }

    pub fn rd(&self) -> Option<WriteOp> {
        self.rd.clone()
    }

    pub fn memory_op(&self) -> Option<WriteOp> {
        self.memory_op.clone()
    }
}

#[derive(Debug, Default)]
pub struct Tracer {
    record: StepRecord,

    latest_accesses: HashMap<WordAddr, Cycle>,
}

impl Tracer {
    pub fn new() -> Tracer {
        let mut t = Tracer::default();
        t.record.cycle = 1;
        t
    }

    pub fn advance(&mut self) -> StepRecord {
        // Reset and advance to the next cycle.
        let record = mem::take(&mut self.record);
        self.record.cycle = record.cycle + 1;

        // Track this step as the origin of its memory accesses.
        let mut track_mem = |addr| self.latest_accesses.insert(addr, record.cycle);

        if let Some(ReadOp { addr, .. }) = record.rs1 {
            track_mem(addr);
        }
        if let Some(ReadOp { addr, .. }) = record.rs2 {
            track_mem(addr);
        }
        if let Some(WriteOp { addr, .. }) = record.rd {
            track_mem(addr);
        }
        if let Some(WriteOp { addr, .. }) = record.memory_op {
            track_mem(addr);
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
        let addr = CENO_PLATFORM.register_vma(idx).into();
        let previous_cycle = self.latest_accesses(addr);

        match (&self.record.rs1, &self.record.rs2) {
            (None, None) => {
                self.record.rs1 = Some(ReadOp {
                    addr,
                    value,
                    previous_cycle,
                });
            }
            (Some(_), None) => {
                self.record.rs2 = Some(ReadOp {
                    addr,
                    value,
                    previous_cycle,
                });
            }
            _ => unimplemented!("Only two register reads are supported"),
        }
    }

    pub fn store_register(&mut self, idx: RegIdx, value: Change<Word>) {
        if self.record.rd.is_some() {
            unimplemented!("Only one register write is supported");
        }

        let addr = CENO_PLATFORM.register_vma(idx).into();
        self.record.rd = Some(WriteOp {
            addr,
            value,
            previous_cycle: self.latest_accesses(addr),
        });
    }

    pub fn load_memory(&mut self, addr: WordAddr, value: Word) {
        if self.record.memory_op.is_some() {
            unimplemented!("Only one memory access is supported");
        }

        self.record.memory_op = Some(WriteOp {
            addr,
            value: Change::new(value, value),
            previous_cycle: self.latest_accesses(addr),
        });
    }

    pub fn store_memory(&mut self, addr: WordAddr, value: Change<Word>) {
        if self.record.memory_op.is_some() {
            unimplemented!("Only one memory access is supported");
        }

        self.record.memory_op = Some(WriteOp {
            addr,
            value,
            previous_cycle: self.latest_accesses(addr),
        });
    }

    fn latest_accesses(&self, addr: WordAddr) -> Cycle {
        *self.latest_accesses.get(&addr).unwrap_or(&0)
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
