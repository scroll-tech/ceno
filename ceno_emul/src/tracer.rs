use std::{collections::HashMap, fmt, mem};

use crate::{
    CENO_PLATFORM, PC_STEP_SIZE,
    addr::{ByteAddr, Cycle, RegIdx, Word, WordAddr},
    rv32im::DecodedInstruction,
};

/// An instruction and its context in an execution trace. That is concrete values of registers and memory.
///
/// - Each instruction is divided into 4 subcycles with the operations on: rs1, rs2, rd, memory. Each op is assigned a unique `cycle + subcycle`.
///
/// - `cycle = 0` means initialization; that is all the special startup logic we are going to have. The RISC-V program starts at `cycle = 4` and each instruction increments `cycle += 4`.
///
/// - Registers are assigned a VMA (virtual memory address, u32). This way they can be unified with other kinds of memory ops.
///
/// - Any of `rs1 / rs2 / rd` **may be `x0`**. The trace handles this like any register, including the value that was _supposed_ to be stored. The circuits must handle this case: either **store `0` or skip `x0` operations**.
///
/// - Any pair of `rs1 / rs2 / rd` **may be the same**. Then, one op will point to the other op in the same instruction but a different subcycle. The circuits may follow the operations **without special handling** of repeated registers.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
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

impl<T> MemOp<T> {
    /// Get the register index of this operation.
    pub fn register_index(&self) -> RegIdx {
        CENO_PLATFORM.register_index(self.addr.into())
    }
}

pub type ReadOp = MemOp<Word>;
pub type WriteOp = MemOp<Change<Word>>;

impl StepRecord {
    pub fn new_r_instruction(
        cycle: Cycle,
        pc: ByteAddr,
        insn_code: u32,
        rs1_read: Word,
        rs2_read: Word,
        rd: Change<Word>,
        prev_cycle: Cycle,
    ) -> StepRecord {
        let pc = Change::new(pc, pc + PC_STEP_SIZE);
        StepRecord::new_insn(
            cycle,
            pc,
            insn_code,
            Some(rs1_read),
            Some(rs2_read),
            Some(rd),
            prev_cycle,
        )
    }

    pub fn new_b_instruction(
        cycle: Cycle,
        pc: Change<ByteAddr>,
        insn_code: u32,
        rs1_read: Word,
        rs2_read: Word,
        prev_cycle: Cycle,
    ) -> StepRecord {
        StepRecord::new_insn(
            cycle,
            pc,
            insn_code,
            Some(rs1_read),
            Some(rs2_read),
            None,
            prev_cycle,
        )
    }

    pub fn new_i_instruction(
        cycle: Cycle,
        pc: Change<ByteAddr>,
        insn_code: u32,
        rs1_read: Word,
        rd: Change<Word>,
        prev_cycle: Cycle,
    ) -> StepRecord {
        StepRecord::new_insn(
            cycle,
            pc,
            insn_code,
            Some(rs1_read),
            None,
            Some(rd),
            prev_cycle,
        )
    }

    pub fn new_u_instruction(
        cycle: Cycle,
        pc: ByteAddr,
        insn_code: u32,
        rd: Change<Word>,
        prev_cycle: Cycle,
    ) -> StepRecord {
        let pc = Change::new(pc, pc + PC_STEP_SIZE);
        StepRecord::new_insn(cycle, pc, insn_code, None, None, Some(rd), prev_cycle)
    }

    pub fn new_j_instruction(
        cycle: Cycle,
        pc: Change<ByteAddr>,
        insn_code: u32,
        rd: Change<Word>,
        prev_cycle: Cycle,
    ) -> StepRecord {
        StepRecord::new_insn(cycle, pc, insn_code, None, None, Some(rd), prev_cycle)
    }

    fn new_insn(
        cycle: Cycle,
        pc: Change<ByteAddr>,
        insn_code: u32,
        rs1_read: Option<Word>,
        rs2_read: Option<Word>,
        rd: Option<Change<Word>>,
        previous_cycle: Cycle,
    ) -> StepRecord {
        let insn = DecodedInstruction::new(insn_code);
        StepRecord {
            cycle,
            pc,
            insn_code,
            rs1: rs1_read.map(|rs1| ReadOp {
                addr: CENO_PLATFORM.register_vma(insn.rs1() as RegIdx).into(),
                value: rs1,
                previous_cycle,
            }),
            rs2: rs2_read.map(|rs2| ReadOp {
                addr: CENO_PLATFORM.register_vma(insn.rs2() as RegIdx).into(),
                value: rs2,
                previous_cycle,
            }),
            rd: rd.map(|rd| WriteOp {
                addr: CENO_PLATFORM.register_vma(insn.rd() as RegIdx).into(),
                value: rd,
                previous_cycle,
            }),
            memory_op: None,
        }
    }

    pub fn cycle(&self) -> Cycle {
        self.cycle
    }

    pub fn pc(&self) -> Change<ByteAddr> {
        self.pc
    }

    /// The instruction as a raw code.
    pub fn insn_code(&self) -> Word {
        self.insn_code
    }

    /// The instruction as a decoded structure.
    pub fn insn(&self) -> DecodedInstruction {
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

    pub fn is_busy_loop(&self) -> bool {
        self.pc.before == self.pc.after
    }
}

#[derive(Debug)]
pub struct Tracer {
    record: StepRecord,

    latest_accesses: HashMap<WordAddr, Cycle>,
}

impl Default for Tracer {
    fn default() -> Self {
        Self::new()
    }
}

impl Tracer {
    pub const SUBCYCLE_RS1: Cycle = 0;
    pub const SUBCYCLE_RS2: Cycle = 1;
    pub const SUBCYCLE_RD: Cycle = 2;
    pub const SUBCYCLE_MEM: Cycle = 3;
    pub const SUBCYCLES_PER_INSN: Cycle = 4;

    pub fn new() -> Tracer {
        Tracer {
            record: StepRecord {
                cycle: Self::SUBCYCLES_PER_INSN,
                ..StepRecord::default()
            },
            latest_accesses: HashMap::new(),
        }
    }

    /// Return the completed step and advance to the next cycle.
    pub fn advance(&mut self) -> StepRecord {
        let next_cycle = self.record.cycle + Self::SUBCYCLES_PER_INSN;
        mem::replace(&mut self.record, StepRecord {
            cycle: next_cycle,
            ..StepRecord::default()
        })
    }

    pub fn store_pc(&mut self, pc: ByteAddr) {
        self.record.pc.after = pc;
    }

    pub fn halt(&mut self, pc: ByteAddr) {
        let pc_addr = CENO_PLATFORM.pc_vma().into();
        self.record.pc.after = pc;
        self.track_access(pc_addr, Self::SUBCYCLES_PER_INSN);
    }

    pub fn fetch(&mut self, pc: WordAddr, value: Word) {
        self.record.pc.before = pc.baddr();
        self.record.insn_code = value;
    }

    pub fn load_register(&mut self, idx: RegIdx, value: Word) {
        let addr = CENO_PLATFORM.register_vma(idx).into();

        match (&self.record.rs1, &self.record.rs2) {
            (None, None) => {
                self.record.rs1 = Some(ReadOp {
                    addr,
                    value,
                    previous_cycle: self.track_access(addr, Self::SUBCYCLE_RS1),
                });
            }
            (Some(_), None) => {
                self.record.rs2 = Some(ReadOp {
                    addr,
                    value,
                    previous_cycle: self.track_access(addr, Self::SUBCYCLE_RS2),
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
            previous_cycle: self.track_access(addr, Self::SUBCYCLE_RD),
        });
    }

    pub fn load_memory(&mut self, addr: WordAddr, value: Word) {
        self.store_memory(addr, Change::new(value, value));
    }

    pub fn store_memory(&mut self, addr: WordAddr, value: Change<Word>) {
        if self.record.memory_op.is_some() {
            unimplemented!("Only one memory access is supported");
        }

        self.record.memory_op = Some(WriteOp {
            addr,
            value,
            previous_cycle: self.track_access(addr, Self::SUBCYCLE_MEM),
        });
    }

    /// - Return the cycle when an address was last accessed.
    /// - Return 0 if this is the first access.
    /// - Record the current instruction as the origin of the latest access.
    /// - Accesses within the same instruction are distinguished by `subcycle ∈ [0, 3]`.
    fn track_access(&mut self, addr: WordAddr, subcycle: Cycle) -> Cycle {
        self.latest_accesses
            .insert(addr, self.record.cycle + subcycle)
            .unwrap_or(0)
    }

    /// Return all the addresses that were accessed and the cycle when they were last accessed.
    pub fn final_accesses(&self) -> &HashMap<WordAddr, Cycle> {
        &self.latest_accesses
    }
}

#[derive(Copy, Clone, Default, PartialEq, Eq)]
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
