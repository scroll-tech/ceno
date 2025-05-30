use std::{
    collections::{BTreeMap, HashMap},
    fmt, mem,
};

use ceno_rt::WORD_SIZE;

use crate::{
    CENO_PLATFORM, InsnKind, Instruction, PC_STEP_SIZE, Platform,
    addr::{ByteAddr, Cycle, RegIdx, Word, WordAddr},
    encode_rv32,
    syscalls::{SyscallEffects, SyscallWitness},
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
    pub insn: Instruction,

    rs1: Option<ReadOp>,
    rs2: Option<ReadOp>,

    rd: Option<WriteOp>,

    memory_op: Option<WriteOp>,

    syscall: Option<SyscallWitness>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct MemOp<T> {
    /// Virtual Memory Address.
    /// For registers, get it from `Platform::register_vma(idx)`.
    pub addr: WordAddr,
    /// The Word read, or the Change<Word> to be written.
    pub value: T,
    /// The cycle when this memory address was last accessed before this operation.
    pub previous_cycle: Cycle,
}

impl<T> MemOp<T> {
    pub fn new_register_op(idx: RegIdx, value: T, previous_cycle: Cycle) -> MemOp<T> {
        MemOp {
            addr: Platform::register_vma(idx).into(),
            value,
            previous_cycle,
        }
    }

    /// Get the register index of this operation.
    pub fn register_index(&self) -> RegIdx {
        Platform::register_index(self.addr.into())
    }
}

pub type ReadOp = MemOp<Word>;
pub type WriteOp = MemOp<Change<Word>>;

impl StepRecord {
    pub fn new_r_instruction(
        cycle: Cycle,
        pc: ByteAddr,
        insn_code: Instruction,
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
            None,
            prev_cycle,
        )
    }

    pub fn new_b_instruction(
        cycle: Cycle,
        pc: Change<ByteAddr>,
        insn_code: Instruction,
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
            None,
            prev_cycle,
        )
    }

    pub fn new_i_instruction(
        cycle: Cycle,
        pc: Change<ByteAddr>,
        insn_code: Instruction,
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
            None,
            prev_cycle,
        )
    }

    pub fn new_im_instruction(
        cycle: Cycle,
        pc: ByteAddr,
        insn_code: Instruction,
        rs1_read: Word,
        rd: Change<Word>,
        mem_op: ReadOp,
        prev_cycle: Cycle,
    ) -> StepRecord {
        let pc = Change::new(pc, pc + PC_STEP_SIZE);
        StepRecord::new_insn(
            cycle,
            pc,
            insn_code,
            Some(rs1_read),
            None,
            Some(rd),
            Some(WriteOp {
                addr: mem_op.addr,
                value: Change {
                    before: mem_op.value,
                    after: mem_op.value,
                },
                previous_cycle: mem_op.previous_cycle,
            }),
            prev_cycle,
        )
    }

    pub fn new_u_instruction(
        cycle: Cycle,
        pc: ByteAddr,
        insn_code: Instruction,
        rd: Change<Word>,
        prev_cycle: Cycle,
    ) -> StepRecord {
        let pc = Change::new(pc, pc + PC_STEP_SIZE);
        StepRecord::new_insn(cycle, pc, insn_code, None, None, Some(rd), None, prev_cycle)
    }

    pub fn new_j_instruction(
        cycle: Cycle,
        pc: Change<ByteAddr>,
        insn_code: Instruction,
        rd: Change<Word>,
        prev_cycle: Cycle,
    ) -> StepRecord {
        StepRecord::new_insn(cycle, pc, insn_code, None, None, Some(rd), None, prev_cycle)
    }

    pub fn new_s_instruction(
        cycle: Cycle,
        pc: ByteAddr,
        insn_code: Instruction,
        rs1_read: Word,
        rs2_read: Word,
        memory_op: WriteOp,
        prev_cycle: Cycle,
    ) -> StepRecord {
        let pc = Change::new(pc, pc + PC_STEP_SIZE);
        StepRecord::new_insn(
            cycle,
            pc,
            insn_code,
            Some(rs1_read),
            Some(rs2_read),
            None,
            Some(memory_op),
            prev_cycle,
        )
    }

    /// Create a test record for an ECALL instruction that can do anything.
    pub fn new_ecall_any(cycle: Cycle, pc: ByteAddr) -> StepRecord {
        let value = 1234;
        Self::new_insn(
            cycle,
            Change::new(pc, pc + PC_STEP_SIZE),
            encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
            Some(value),
            Some(value),
            Some(Change::new(value, value)),
            Some(WriteOp {
                addr: CENO_PLATFORM.heap.start.into(),
                value: Change {
                    before: value,
                    after: value,
                },
                previous_cycle: 0,
            }),
            0,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn new_insn(
        cycle: Cycle,
        pc: Change<ByteAddr>,
        insn: Instruction,
        rs1_read: Option<Word>,
        rs2_read: Option<Word>,
        rd: Option<Change<Word>>,
        memory_op: Option<WriteOp>,
        previous_cycle: Cycle,
    ) -> StepRecord {
        StepRecord {
            cycle,
            pc,
            rs1: rs1_read.map(|rs1| ReadOp {
                addr: Platform::register_vma(insn.rs1).into(),
                value: rs1,
                previous_cycle,
            }),
            rs2: rs2_read.map(|rs2| ReadOp {
                addr: Platform::register_vma(insn.rs2).into(),
                value: rs2,
                previous_cycle,
            }),
            rd: rd.map(|rd| WriteOp {
                addr: Platform::register_vma(insn.rd_internal() as RegIdx).into(),
                value: rd,
                previous_cycle,
            }),
            insn,
            memory_op,
            syscall: None,
        }
    }

    pub fn cycle(&self) -> Cycle {
        self.cycle
    }

    pub fn pc(&self) -> Change<ByteAddr> {
        self.pc
    }

    /// The instruction as a decoded structure.
    pub fn insn(&self) -> Instruction {
        self.insn
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

    pub fn syscall(&self) -> Option<&SyscallWitness> {
        self.syscall.as_ref()
    }
}

#[derive(Debug)]
pub struct Tracer {
    record: StepRecord,

    // record each section max access address
    // (start_addr -> (start_addr, end_addr, min_access_addr, max_access_addr))
    mmio_min_max_access: Option<BTreeMap<WordAddr, (WordAddr, WordAddr, WordAddr, WordAddr)>>,
    latest_accesses: HashMap<WordAddr, Cycle>,
}

impl Default for Tracer {
    fn default() -> Self {
        Self::new(None)
    }
}

impl Tracer {
    pub const SUBCYCLE_RS1: Cycle = 0;
    pub const SUBCYCLE_RS2: Cycle = 1;
    pub const SUBCYCLE_RD: Cycle = 2;
    pub const SUBCYCLE_MEM: Cycle = 3;
    pub const SUBCYCLES_PER_INSN: Cycle = 4;

    pub fn new(platform: Option<&Platform>) -> Tracer {
        let mmio_max_access = if let Some(platform) = platform {
            let mut mmio_max_access = BTreeMap::new();
            mmio_max_access.insert(
                ByteAddr::from(platform.heap.start).waddr(),
                (
                    ByteAddr::from(platform.heap.start).waddr(),
                    ByteAddr::from(platform.heap.end).waddr(),
                    ByteAddr::from(platform.heap.end).waddr(),
                    ByteAddr::from(platform.heap.start).waddr(),
                ),
            );
            mmio_max_access.insert(
                ByteAddr::from(platform.stack.start).waddr(),
                (
                    ByteAddr::from(platform.stack.start).waddr(),
                    ByteAddr::from(platform.stack.end).waddr(),
                    ByteAddr::from(platform.stack.end).waddr(),
                    ByteAddr::from(platform.stack.start).waddr(),
                ),
            );
            mmio_max_access.insert(
                ByteAddr::from(platform.hints.start).waddr(),
                (
                    ByteAddr::from(platform.hints.start).waddr(),
                    ByteAddr::from(platform.hints.end).waddr(),
                    ByteAddr::from(platform.hints.end).waddr(),
                    ByteAddr::from(platform.hints.start).waddr(),
                ),
            );
            Some(mmio_max_access)
        } else {
            None
        };

        Tracer {
            mmio_min_max_access: mmio_max_access,
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
        mem::replace(
            &mut self.record,
            StepRecord {
                cycle: next_cycle,
                ..StepRecord::default()
            },
        )
    }

    pub fn store_pc(&mut self, pc: ByteAddr) {
        self.record.pc.after = pc;
    }

    pub fn fetch(&mut self, pc: WordAddr, value: Instruction) {
        self.record.pc.before = pc.baddr();
        self.record.insn = value;
    }

    pub fn load_register(&mut self, idx: RegIdx, value: Word) {
        let addr = Platform::register_vma(idx).into();

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

        let addr = Platform::register_vma(idx).into();
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

        // update min/max mmio access
        if let Some((_, (_, end_addr, min_addr, max_addr))) = self
            .mmio_min_max_access
            .as_mut()
            // find the MMIO region whose start address is less than or equal to the target address
            .and_then(|mmio_max_access| mmio_max_access.range_mut(..=addr).next_back())
        {
            // skip if the target address is not within the range tracked by this MMIO region
            // this condition ensures the address is within the MMIO region's end address
            if addr < *end_addr {
                // expand the max bound if the address exceeds the current max
                if addr >= *max_addr {
                    *max_addr = addr + WordAddr::from(WORD_SIZE as u32); // end is exclusive
                }
                // shrink the min bound if the address is below the current min
                if addr < *min_addr {
                    *min_addr = addr; // start is inclusive
                }
            }
        }

        self.record.memory_op = Some(WriteOp {
            addr,
            value,
            previous_cycle: self.track_access(addr, Self::SUBCYCLE_MEM),
        });
    }

    pub fn track_syscall(&mut self, effects: SyscallEffects) {
        let witness = effects.finalize(self);

        assert!(self.record.syscall.is_none(), "Only one syscall per step");
        self.record.syscall = Some(witness);
    }

    /// - Return the cycle when an address was last accessed.
    /// - Return 0 if this is the first access.
    /// - Record the current instruction as the origin of the latest access.
    /// - Accesses within the same instruction are distinguished by `subcycle ∈ [0, 3]`.
    pub fn track_access(&mut self, addr: WordAddr, subcycle: Cycle) -> Cycle {
        self.latest_accesses
            .insert(addr, self.record.cycle + subcycle)
            .unwrap_or(0)
    }

    /// Return all the addresses that were accessed and the cycle when they were last accessed.
    pub fn final_accesses(&self) -> &HashMap<WordAddr, Cycle> {
        &self.latest_accesses
    }

    /// Return the cycle of the pending instruction (after the last completed step).
    pub fn cycle(&self) -> Cycle {
        self.record.cycle
    }

    /// Return the number of instruction executed til this moment
    /// minus 1 since cycle start from Self::SUBCYCLES_PER_INSN
    pub fn executed_insts(&self) -> usize {
        (self.record.cycle / Self::SUBCYCLES_PER_INSN)
            .saturating_sub(1)
            .try_into()
            .unwrap()
    }

    /// giving a start address, return (min, max) accessed address within section
    pub fn probe_min_max_address_by_start_addr(
        &self,
        start_addr: WordAddr,
    ) -> Option<(WordAddr, WordAddr)> {
        self.mmio_min_max_access
            .as_ref()
            .and_then(|mmio_max_access| {
                mmio_max_access.range(..=start_addr).next_back().and_then(
                    |(_, &(expected_start_addr, _, min, max))| {
                        assert_eq!(
                            start_addr, expected_start_addr,
                            "please use section start for searching"
                        );
                        if start_addr == expected_start_addr && min < max {
                            Some((min, max))
                        } else {
                            None
                        }
                    },
                )
            })
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
