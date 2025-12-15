use crate::{
    CENO_PLATFORM, InsnKind, Instruction, PC_STEP_SIZE, Platform,
    addr::{ByteAddr, Cycle, RegIdx, Word, WordAddr},
    chunked_vec::ChunkedVec,
    dense_addr_space::DenseAddrSpace,
    encode_rv32,
    syscalls::{SyscallEffects, SyscallWitness},
};
use ceno_rt::WORD_SIZE;
use smallvec::SmallVec;
use std::{collections::BTreeMap, fmt, mem};

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

pub type NextAccessPair = SmallVec<[(WordAddr, Cycle); 1]>;
pub type NextCycleAccess = ChunkedVec<NextAccessPair>;
const ACCESSED_CHUNK_SIZE: usize = 1 << 20;

fn init_mmio_min_max_access(
    platform: &Platform,
) -> BTreeMap<WordAddr, (WordAddr, WordAddr, WordAddr, WordAddr)> {
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
    mmio_max_access
}

pub trait TraceDriver {
    type Record;

    const SUBCYCLE_RS1: Cycle;
    const SUBCYCLE_RS2: Cycle;
    const SUBCYCLE_RD: Cycle;
    const SUBCYCLE_MEM: Cycle;
    const SUBCYCLES_PER_INSN: Cycle;

    fn new(platform: &Platform) -> Self;

    fn advance(&mut self) -> Self::Record;

    fn is_busy_loop(record: &Self::Record) -> bool;

    fn store_pc(&mut self, pc: ByteAddr);

    fn fetch(&mut self, pc: WordAddr, value: Instruction);

    fn load_register(&mut self, idx: RegIdx, value: Word);

    fn store_register(&mut self, idx: RegIdx, value: Change<Word>);

    fn load_memory(&mut self, addr: WordAddr, value: Word);

    fn store_memory(&mut self, addr: WordAddr, value: Change<Word>);

    fn track_syscall(&mut self, effects: SyscallEffects);

    fn track_access(&mut self, addr: WordAddr, subcycle: Cycle) -> Cycle;

    fn final_accesses(&self) -> &LatestAccesses;

    fn into_next_accesses(self) -> NextCycleAccess
    where
        Self: Sized;

    fn cycle(&self) -> Cycle;

    fn executed_insts(&self) -> usize;

    fn probe_min_max_address_by_start_addr(
        &self,
        start_addr: WordAddr,
    ) -> Option<(WordAddr, WordAddr)>;
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

#[derive(Debug)]
pub struct LatestAccesses {
    store: DenseAddrSpace<Cycle>,
    len: usize,
    #[cfg(any(test, debug_assertions))]
    touched: Vec<WordAddr>,
}

impl LatestAccesses {
    fn new(platform: &Platform) -> Self {
        Self {
            store: DenseAddrSpace::new(
                WordAddr::from(0u32),
                ByteAddr::from(platform.heap.end).waddr(),
            ),
            len: 0,
            #[cfg(any(test, debug_assertions))]
            touched: Vec::new(),
        }
    }

    fn track(&mut self, addr: WordAddr, cycle: Cycle) -> Cycle {
        let prev = self
            .store
            .replace(addr, cycle)
            .unwrap_or_else(|| panic!("addr {addr:?} outside tracked address space"));
        if prev == Cycle::default() {
            self.len += 1;
            #[cfg(any(test, debug_assertions))]
            {
                self.touched.push(addr);
            }
        }
        prev
    }

    pub fn cycle(&self, addr: WordAddr) -> Cycle {
        *self
            .store
            .get_ref(addr)
            .expect("address must lie within tracked range")
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    #[cfg(any(test, debug_assertions))]
    pub fn iter(&self) -> LatestAccessIter<'_> {
        LatestAccessIter {
            accesses: self,
            idx: 0,
        }
    }

    #[cfg(any(test, debug_assertions))]
    pub fn addresses(&self) -> impl Iterator<Item = &WordAddr> + '_ {
        self.touched.iter()
    }

    #[cfg(not(any(test, debug_assertions)))]
    pub fn addresses(&self) -> std::iter::Empty<&WordAddr> {
        unimplemented!("no track touched address in release build")
    }
}

#[cfg(any(test, debug_assertions))]
pub struct LatestAccessIter<'a> {
    accesses: &'a LatestAccesses,
    idx: usize,
}

#[cfg(any(test, debug_assertions))]
impl<'a> Iterator for LatestAccessIter<'a> {
    type Item = (&'a WordAddr, &'a Cycle);

    fn next(&mut self) -> Option<Self::Item> {
        let addr = self.accesses.touched.get(self.idx)?;
        self.idx += 1;
        let cycle = self
            .accesses
            .store
            .get_ref(*addr)
            .expect("tracked address must exist");
        Some((addr, cycle))
    }
}

#[cfg(any(test, debug_assertions))]
impl<'a> IntoIterator for &'a LatestAccesses {
    type Item = (&'a WordAddr, &'a Cycle);
    type IntoIter = LatestAccessIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

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

    // keep track of each address that the cycle when they were last accessed.
    latest_accesses: LatestAccesses,

    // keep track of each cycle that accessed addresses in the future with respective future cycles.
    // format: [current cycle -> Vec<(WordAddr, Cycle)>]
    next_accesses: NextCycleAccess,
}

impl Tracer {
    pub const SUBCYCLE_RS1: Cycle = 0;
    pub const SUBCYCLE_RS2: Cycle = 1;
    pub const SUBCYCLE_RD: Cycle = 2;
    pub const SUBCYCLE_MEM: Cycle = 3;
    pub const SUBCYCLES_PER_INSN: Cycle = 4;

    pub fn new(platform: &Platform) -> Tracer {
        let mmio_max_access = init_mmio_min_max_access(platform);

        Tracer {
            mmio_min_max_access: Some(mmio_max_access),
            record: StepRecord {
                cycle: Self::SUBCYCLES_PER_INSN,
                ..StepRecord::default()
            },
            latest_accesses: LatestAccesses::new(platform),
            next_accesses: NextCycleAccess::new(ACCESSED_CHUNK_SIZE),
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
        let cur_cycle = self.record.cycle + subcycle;
        let prev_cycle = self.latest_accesses.track(addr, cur_cycle);
        self.next_accesses
            .get_or_create(prev_cycle as usize)
            .push((addr, cur_cycle));
        prev_cycle
    }

    pub fn final_accesses(&self) -> &LatestAccesses {
        &self.latest_accesses
    }

    pub fn next_accesses(self) -> NextCycleAccess {
        self.next_accesses
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

#[derive(Debug)]
pub struct PreflightTracer {
    cycle: Cycle,
    mmio_min_max_access: Option<BTreeMap<WordAddr, (WordAddr, WordAddr, WordAddr, WordAddr)>>,
    latest_accesses: LatestAccesses,
    next_accesses: NextCycleAccess,
}

impl PreflightTracer {
    pub fn new(platform: &Platform) -> Self {
        PreflightTracer {
            cycle: Tracer::SUBCYCLES_PER_INSN,
            mmio_min_max_access: Some(init_mmio_min_max_access(platform)),
            latest_accesses: LatestAccesses::new(platform),
            next_accesses: NextCycleAccess::new(ACCESSED_CHUNK_SIZE),
        }
    }

    fn update_mmio_bounds(&mut self, addr: WordAddr) {
        if let Some((_, (_, end_addr, min_addr, max_addr))) = self
            .mmio_min_max_access
            .as_mut()
            .and_then(|mmio_max_access| mmio_max_access.range_mut(..=addr).next_back())
            && addr < *end_addr
        {
            if addr >= *max_addr {
                *max_addr = addr + WordAddr::from(WORD_SIZE as u32);
            }
            if addr < *min_addr {
                *min_addr = addr;
            }
        }
    }
}

impl TraceDriver for PreflightTracer {
    type Record = ();

    const SUBCYCLE_RS1: Cycle = Tracer::SUBCYCLE_RS1;
    const SUBCYCLE_RS2: Cycle = Tracer::SUBCYCLE_RS2;
    const SUBCYCLE_RD: Cycle = Tracer::SUBCYCLE_RD;
    const SUBCYCLE_MEM: Cycle = Tracer::SUBCYCLE_MEM;
    const SUBCYCLES_PER_INSN: Cycle = Tracer::SUBCYCLES_PER_INSN;

    fn new(platform: &Platform) -> Self {
        PreflightTracer::new(platform)
    }

    fn advance(&mut self) -> Self::Record {
        self.cycle += Self::SUBCYCLES_PER_INSN;
    }

    fn is_busy_loop(_: &Self::Record) -> bool {
        false
    }

    fn store_pc(&mut self, _pc: ByteAddr) {}

    fn fetch(&mut self, _pc: WordAddr, _value: Instruction) {}

    fn load_register(&mut self, _idx: RegIdx, _value: Word) {}

    fn store_register(&mut self, _idx: RegIdx, _value: Change<Word>) {}

    fn load_memory(&mut self, addr: WordAddr, value: Word) {
        self.store_memory(addr, Change::new(value, value));
    }

    fn store_memory(&mut self, addr: WordAddr, _value: Change<Word>) {
        self.update_mmio_bounds(addr);
        self.track_access(addr, Self::SUBCYCLE_MEM);
    }

    fn track_syscall(&mut self, effects: SyscallEffects) {
        let _ = effects.finalize(self);
    }

    fn track_access(&mut self, addr: WordAddr, subcycle: Cycle) -> Cycle {
        let cur_cycle = self.cycle + subcycle;
        let prev_cycle = self.latest_accesses.track(addr, cur_cycle);
        self.next_accesses
            .get_or_create(prev_cycle as usize)
            .push((addr, cur_cycle));
        prev_cycle
    }

    fn final_accesses(&self) -> &LatestAccesses {
        &self.latest_accesses
    }

    fn into_next_accesses(self) -> NextCycleAccess {
        self.next_accesses
    }

    fn cycle(&self) -> Cycle {
        self.cycle
    }

    fn executed_insts(&self) -> usize {
        (self.cycle / Self::SUBCYCLES_PER_INSN)
            .saturating_sub(1)
            .try_into()
            .unwrap()
    }

    fn probe_min_max_address_by_start_addr(
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

impl TraceDriver for Tracer {
    type Record = StepRecord;

    const SUBCYCLE_RS1: Cycle = Tracer::SUBCYCLE_RS1;
    const SUBCYCLE_RS2: Cycle = Tracer::SUBCYCLE_RS2;
    const SUBCYCLE_RD: Cycle = Tracer::SUBCYCLE_RD;
    const SUBCYCLE_MEM: Cycle = Tracer::SUBCYCLE_MEM;
    const SUBCYCLES_PER_INSN: Cycle = Tracer::SUBCYCLES_PER_INSN;

    fn new(platform: &Platform) -> Self {
        Tracer::new(platform)
    }

    fn advance(&mut self) -> Self::Record {
        Tracer::advance(self)
    }

    fn is_busy_loop(record: &Self::Record) -> bool {
        record.is_busy_loop()
    }

    fn store_pc(&mut self, pc: ByteAddr) {
        Tracer::store_pc(self, pc)
    }

    fn fetch(&mut self, pc: WordAddr, value: Instruction) {
        Tracer::fetch(self, pc, value)
    }

    fn load_register(&mut self, idx: RegIdx, value: Word) {
        Tracer::load_register(self, idx, value)
    }

    fn store_register(&mut self, idx: RegIdx, value: Change<Word>) {
        Tracer::store_register(self, idx, value)
    }

    fn load_memory(&mut self, addr: WordAddr, value: Word) {
        Tracer::load_memory(self, addr, value)
    }

    fn store_memory(&mut self, addr: WordAddr, value: Change<Word>) {
        Tracer::store_memory(self, addr, value)
    }

    fn track_syscall(&mut self, effects: SyscallEffects) {
        Tracer::track_syscall(self, effects)
    }

    fn track_access(&mut self, addr: WordAddr, subcycle: Cycle) -> Cycle {
        Tracer::track_access(self, addr, subcycle)
    }

    fn final_accesses(&self) -> &LatestAccesses {
        Tracer::final_accesses(self)
    }

    fn into_next_accesses(self) -> NextCycleAccess {
        self.next_accesses()
    }

    fn cycle(&self) -> Cycle {
        Tracer::cycle(self)
    }

    fn executed_insts(&self) -> usize {
        Tracer::executed_insts(self)
    }

    fn probe_min_max_address_by_start_addr(
        &self,
        start_addr: WordAddr,
    ) -> Option<(WordAddr, WordAddr)> {
        Tracer::probe_min_max_address_by_start_addr(self, start_addr)
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
