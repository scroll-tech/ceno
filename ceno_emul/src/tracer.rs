use std::{collections::HashMap, fmt, mem};

use crate::{
    addr::{ByteAddr, Cycle, RegIdx, Word, WordAddr},
    rv32im::DecodedInstruction,
    Addr, CENO_PLATFORM,
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

    rs1: Option<(RegIdx, Word, Cycle)>,
    rs2: Option<(RegIdx, Word, Cycle)>,

    rd: Option<(RegIdx, Change<Word>, Cycle)>,

    memory_op: Option<(WordAddr, Change<Word>, Cycle)>,
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

    pub fn rs1(&self) -> Option<(RegIdx, Word, Cycle)> {
        self.rs1
    }

    pub fn rs2(&self) -> Option<(RegIdx, Word, Cycle)> {
        self.rs2
    }

    pub fn rd(&self) -> Option<(RegIdx, Change<Word>, Cycle)> {
        self.rd
    }

    pub fn memory_op(&self) -> Option<(WordAddr, Change<Word>, Cycle)> {
        self.memory_op
    }
}

#[derive(Debug, Default)]
pub struct Tracer {
    record: StepRecord,

    latest_accesses: HashMap<Addr, Cycle>,
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
        let mut track_mem = |vma| self.latest_accesses.insert(vma, record.cycle);

        if let Some((idx, _, _)) = record.rs1 {
            track_mem(CENO_PLATFORM.register_vma(idx));
        }
        if let Some((idx, _, _)) = record.rs2 {
            track_mem(CENO_PLATFORM.register_vma(idx));
        }
        if let Some((idx, _, _)) = record.rd {
            track_mem(CENO_PLATFORM.register_vma(idx));
        }
        if let Some((addr, _, _)) = record.memory_op {
            track_mem(addr.into());
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
        let vma = CENO_PLATFORM.register_vma(idx);
        let prev_cycle = self.latest_accesses(vma);

        match (self.record.rs1, self.record.rs2) {
            (None, None) => {
                self.record.rs1 = Some((idx, value, prev_cycle));
            }
            (Some(_), None) => {
                self.record.rs2 = Some((idx, value, prev_cycle));
            }
            _ => unimplemented!("Only two register reads are supported"),
        }
    }

    pub fn store_register(&mut self, idx: RegIdx, value: Change<Word>) {
        if self.record.rd.is_none() {
            let vma = CENO_PLATFORM.register_vma(idx);
            let prev_cycle = self.latest_accesses(vma);
            self.record.rd = Some((idx, value, prev_cycle));
        } else {
            unimplemented!("Only one register write is supported");
        }
    }

    pub fn load_memory(&mut self, addr: WordAddr, value: Word) {
        if self.record.memory_op.is_some() {
            unimplemented!("Only one memory access is supported");
        }

        let prev_cycle = self.latest_accesses(addr.into());
        self.record.memory_op = Some((addr, Change::new(value, value), prev_cycle));
    }

    pub fn store_memory(&mut self, addr: WordAddr, value: Change<Word>) {
        if self.record.memory_op.is_some() {
            unimplemented!("Only one memory access is supported");
        }

        let prev_cycle = self.latest_accesses(addr.into());
        self.record.memory_op = Some((addr, value, prev_cycle));
    }

    fn latest_accesses(&self, addr: Addr) -> Cycle {
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
