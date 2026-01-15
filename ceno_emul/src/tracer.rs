use crate::{
    CENO_PLATFORM, InsnKind, Instruction, PC_STEP_SIZE, Platform,
    addr::{ByteAddr, Cycle, RegIdx, Word, WordAddr},
    dense_addr_space::DenseAddrSpace,
    encode_rv32,
    syscalls::{SyscallEffects, SyscallWitness},
};
use ceno_rt::WORD_SIZE;
use rayon::prelude::*;
use smallvec::SmallVec;
use std::{collections::BTreeMap, fmt, mem, sync::Arc};

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
    pub heap_maxtouch_addr: Change<ByteAddr>,
    pub hint_maxtouch_addr: Change<ByteAddr>,
    pub insn: Instruction,

    rs1: Option<ReadOp>,
    rs2: Option<ReadOp>,

    rd: Option<WriteOp>,

    memory_op: Option<WriteOp>,

    syscall: Option<SyscallWitness>,
}

pub type NextAccessPair = SmallVec<[(WordAddr, Cycle); 1]>;
pub type NextCycleAccess = Vec<NextAccessPair>;
const NEXT_ACCESS_PREALLOC: usize = 101_194_444;

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

pub trait Tracer {
    type Record;
    type Config;

    const SUBCYCLE_RS1: Cycle = 0;
    const SUBCYCLE_RS2: Cycle = 1;
    const SUBCYCLE_RD: Cycle = 2;
    const SUBCYCLE_MEM: Cycle = 3;
    const SUBCYCLES_PER_INSN: Cycle = 4;

    fn new(platform: &Platform, config: &Self::Config) -> Self;

    fn with_next_accesses(
        platform: &Platform,
        config: &Self::Config,
        next_accesses: Option<Arc<NextCycleAccess>>,
    ) -> Self
    where
        Self: Sized,
    {
        let _ = next_accesses;
        Self::new(platform, config)
    }

    fn advance(&mut self) -> Self::Record;

    fn is_busy_loop(&self, record: &Self::Record) -> bool;

    fn store_pc(&mut self, pc: ByteAddr);

    fn fetch(&mut self, pc: WordAddr, value: Instruction);

    fn track_mmu_maxtouch_before(&mut self);

    fn track_mmu_maxtouch_after(&mut self);

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

/// `EmptyTracer` tracks minimal metadata only.
#[derive(Debug)]
pub struct EmptyTracer {
    cycle: Cycle,
    pc: Change<ByteAddr>,
    last_kind: InsnKind,
    last_rs1: Option<Word>,
}

impl Default for EmptyTracer {
    fn default() -> Self {
        Self::new()
    }
}

impl EmptyTracer {
    pub const SUBCYCLE_RS1: Cycle = <Self as Tracer>::SUBCYCLE_RS1;
    pub const SUBCYCLE_RS2: Cycle = <Self as Tracer>::SUBCYCLE_RS2;
    pub const SUBCYCLE_RD: Cycle = <Self as Tracer>::SUBCYCLE_RD;
    pub const SUBCYCLE_MEM: Cycle = <Self as Tracer>::SUBCYCLE_MEM;
    pub const SUBCYCLES_PER_INSN: Cycle = <Self as Tracer>::SUBCYCLES_PER_INSN;

    pub fn new() -> Self {
        Self {
            cycle: <Self as Tracer>::SUBCYCLES_PER_INSN,
            pc: Change::default(),
            last_kind: InsnKind::INVALID,
            last_rs1: None,
        }
    }

    pub fn last_insn_kind(&self) -> InsnKind {
        self.last_kind
    }

    pub fn last_rs1_value(&self) -> Option<Word> {
        self.last_rs1
    }
}

impl Tracer for EmptyTracer {
    type Record = ();
    type Config = ();

    fn new(_platform: &Platform, _config: &Self::Config) -> Self {
        EmptyTracer::new()
    }

    #[inline(always)]
    fn advance(&mut self) -> Self::Record {
        self.cycle += Self::SUBCYCLES_PER_INSN;
    }

    fn is_busy_loop(&self, _: &Self::Record) -> bool {
        self.pc.before == self.pc.after
    }

    #[inline(always)]
    fn store_pc(&mut self, pc: ByteAddr) {
        self.pc.after = pc;
    }

    #[inline(always)]
    fn fetch(&mut self, pc: WordAddr, value: Instruction) {
        self.pc.before = pc.baddr();
        self.last_kind = value.kind;
        self.last_rs1 = None;
    }

    #[inline(always)]
    fn track_mmu_maxtouch_before(&mut self) {}

    #[inline(always)]
    fn track_mmu_maxtouch_after(&mut self) {}

    #[inline(always)]
    fn load_register(&mut self, idx: RegIdx, value: Word) {
        if matches!(self.last_kind, InsnKind::ECALL) && idx == Platform::reg_ecall() {
            self.last_rs1 = Some(value);
        }
    }

    #[inline(always)]
    fn store_register(&mut self, _idx: RegIdx, _value: Change<Word>) {}

    #[inline(always)]
    fn load_memory(&mut self, _addr: WordAddr, _value: Word) {}

    #[inline(always)]
    fn store_memory(&mut self, _addr: WordAddr, _value: Change<Word>) {}

    #[inline(always)]
    fn track_syscall(&mut self, _effects: SyscallEffects) {}

    #[inline(always)]
    fn track_access(&mut self, _addr: WordAddr, _subcycle: Cycle) -> Cycle {
        0
    }

    fn final_accesses(&self) -> &LatestAccesses {
        unimplemented!()
    }

    fn into_next_accesses(self) -> NextCycleAccess {
        unimplemented!()
    }

    #[inline(always)]
    fn cycle(&self) -> Cycle {
        self.cycle
    }

    fn executed_insts(&self) -> usize {
        (self.cycle() / Self::SUBCYCLES_PER_INSN)
            .saturating_sub(1)
            .try_into()
            .unwrap()
    }

    fn probe_min_max_address_by_start_addr(
        &self,
        _start_addr: WordAddr,
    ) -> Option<(WordAddr, WordAddr)> {
        None
    }
}

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
            Change::default(),
            Change::default(),
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
            Change::default(),
            Change::default(),
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
            Change::default(),
            Change::default(),
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
            Change::default(),
            Change::default(),
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
        StepRecord::new_insn(
            cycle,
            pc,
            insn_code,
            None,
            None,
            Some(rd),
            None,
            prev_cycle,
            Change::default(),
            Change::default(),
        )
    }

    pub fn new_j_instruction(
        cycle: Cycle,
        pc: Change<ByteAddr>,
        insn_code: Instruction,
        rd: Change<Word>,
        prev_cycle: Cycle,
    ) -> StepRecord {
        StepRecord::new_insn(
            cycle,
            pc,
            insn_code,
            None,
            None,
            Some(rd),
            None,
            prev_cycle,
            Change::default(),
            Change::default(),
        )
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
            Change::default(),
            Change::default(),
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
            Change::default(),
            Change::default(),
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
        heap_maxtouch_addr: Change<ByteAddr>,
        hint_maxtouch_addr: Change<ByteAddr>,
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
            heap_maxtouch_addr,
            hint_maxtouch_addr,
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

    #[inline(always)]
    pub fn is_busy_loop(&self) -> bool {
        self.pc.before == self.pc.after
    }

    pub fn syscall(&self) -> Option<&SyscallWitness> {
        self.syscall.as_ref()
    }
}

#[derive(Debug)]
pub struct FullTracer {
    record: StepRecord,

    // record each section max access address
    // (start_addr -> (start_addr, end_addr, min_access_addr, max_access_addr))
    mmio_min_max_access: Option<BTreeMap<WordAddr, (WordAddr, WordAddr, WordAddr, WordAddr)>>,
    max_heap_addr_access: ByteAddr,
    max_hint_addr_access: ByteAddr,
    platform: Platform,

    // keep track of each address that the cycle when they were last accessed.
    latest_accesses: LatestAccesses,
}

impl FullTracer {
    pub const SUBCYCLE_RS1: Cycle = <Self as Tracer>::SUBCYCLE_RS1;
    pub const SUBCYCLE_RS2: Cycle = <Self as Tracer>::SUBCYCLE_RS2;
    pub const SUBCYCLE_RD: Cycle = <Self as Tracer>::SUBCYCLE_RD;
    pub const SUBCYCLE_MEM: Cycle = <Self as Tracer>::SUBCYCLE_MEM;
    pub const SUBCYCLES_PER_INSN: Cycle = <Self as Tracer>::SUBCYCLES_PER_INSN;

    pub fn new(platform: &Platform) -> FullTracer {
        let mmio_max_access = init_mmio_min_max_access(platform);

        FullTracer {
            mmio_min_max_access: Some(mmio_max_access),
            record: StepRecord {
                cycle: Self::SUBCYCLES_PER_INSN,
                ..StepRecord::default()
            },
            platform: platform.clone(),
            latest_accesses: LatestAccesses::new(platform),
            max_heap_addr_access: ByteAddr::from(platform.heap.start),
            max_hint_addr_access: ByteAddr::from(platform.hints.start),
        }
    }

    /// Return the completed step and advance to the next cycle.
    #[inline(always)]
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

    #[inline(always)]
    pub fn store_pc(&mut self, pc: ByteAddr) {
        self.record.pc.after = pc;
    }

    #[inline(always)]
    pub fn fetch(&mut self, pc: WordAddr, value: Instruction) {
        self.record.pc.before = pc.baddr();
        self.record.insn = value;
    }

    #[inline(always)]
    pub fn track_mmu_maxtouch_before(&mut self) {
        self.record.heap_maxtouch_addr.before = self.max_heap_addr_access;
        self.record.hint_maxtouch_addr.before = self.max_hint_addr_access;
    }

    #[inline(always)]
    pub fn track_mmu_maxtouch_after(&mut self) {
        self.record.heap_maxtouch_addr.after = self.max_heap_addr_access;
        self.record.hint_maxtouch_addr.after = self.max_hint_addr_access;
    }

    #[inline(always)]
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

    #[inline(always)]
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

    #[inline(always)]
    pub fn load_memory(&mut self, addr: WordAddr, value: Word) {
        self.store_memory(addr, Change::new(value, value));
    }

    #[inline(always)]
    pub fn store_memory(&mut self, addr: WordAddr, value: Change<Word>) {
        if self.record.memory_op.is_some() {
            unimplemented!("Only one memory access is supported");
        }

        // update min/max mmio access
        if let Some((start_addr, (_, end_addr, min_addr, max_addr))) = self
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
                if start_addr.baddr().0 == self.platform.heap.start {
                    let access_end = addr + WordAddr::from(WORD_SIZE as u32);
                    let access_end_baddr = access_end.baddr();
                    if access_end_baddr > self.max_heap_addr_access {
                        self.max_heap_addr_access = access_end_baddr;
                    }
                } else if start_addr.baddr().0 == self.platform.hints.start {
                    let access_end = addr + WordAddr::from(WORD_SIZE as u32);
                    let access_end_baddr = access_end.baddr();
                    if access_end_baddr > self.max_hint_addr_access {
                        self.max_hint_addr_access = access_end_baddr;
                    }
                }
            }
        }

        self.record.memory_op = Some(WriteOp {
            addr,
            value,
            previous_cycle: self.track_access(addr, Self::SUBCYCLE_MEM),
        });
    }

    #[inline(always)]
    pub fn track_syscall(&mut self, effects: SyscallEffects) {
        let witness = effects.finalize(self);

        assert!(self.record.syscall.is_none(), "Only one syscall per step");
        self.record.syscall = Some(witness);
    }

    /// - Return the cycle when an address was last accessed.
    /// - Return 0 if this is the first access.
    /// - Record the current instruction as the origin of the latest access.
    /// - Accesses within the same instruction are distinguished by `subcycle ∈ [0, 3]`.
    #[inline(always)]
    pub fn track_access(&mut self, addr: WordAddr, subcycle: Cycle) -> Cycle {
        let cur_cycle = self.record.cycle + subcycle;
        self.latest_accesses.track(addr, cur_cycle)
    }

    pub fn final_accesses(&self) -> &LatestAccesses {
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

#[derive(Debug)]
pub struct PreflightTracer {
    cycle: Cycle,
    pc: Change<ByteAddr>,
    mmio_min_max_access: Option<BTreeMap<WordAddr, (WordAddr, WordAddr, WordAddr, WordAddr)>>,
    latest_accesses: LatestAccesses,
    next_accesses: NextCycleAccess,
    register_reads_tracked: u8,
    shard_cycle_boundaries: Arc<Vec<Cycle>>,
    current_shard_idx: usize,
    current_shard_start_cycle: Cycle,
    current_shard_end_cycle: Cycle,
    final_cycle: Cycle,
}

#[derive(Clone, Debug)]
pub struct PreflightTracerConfig {
    next_access_capacity: usize,
    shard_cycle_boundaries: Arc<Vec<Cycle>>,
    end_cycle: Cycle,
}

impl PreflightTracerConfig {
    pub fn new(
        next_access_capacity: usize,
        shard_cycle_boundaries: Arc<Vec<Cycle>>,
        end_cycle: Cycle,
    ) -> Self {
        assert!(next_access_capacity > 0);
        assert!(
            !shard_cycle_boundaries.is_empty(),
            "shard_cycle_boundaries must contain at least one entry"
        );
        Self {
            next_access_capacity,
            shard_cycle_boundaries,
            end_cycle,
        }
    }

    pub fn with_default_boundaries(next_access_capacity: usize) -> Self {
        Self::new(
            next_access_capacity,
            Arc::new(vec![FullTracer::SUBCYCLES_PER_INSN, Cycle::MAX]),
            Cycle::MAX,
        )
    }

    pub fn from_end_cycle(end_cycle: Cycle, shard_cycle_boundaries: Arc<Vec<Cycle>>) -> Self {
        let extra = PreflightTracer::SUBCYCLES_PER_INSN as Cycle;
        let needed = end_cycle.saturating_add(extra).saturating_add(1);
        let next_access_capacity = needed.try_into().unwrap_or(usize::MAX);
        Self::new(next_access_capacity, shard_cycle_boundaries, end_cycle)
    }

    pub fn capacity(&self) -> usize {
        self.next_access_capacity
    }

    pub fn shard_cycle_boundaries(&self) -> Arc<Vec<Cycle>> {
        self.shard_cycle_boundaries.clone()
    }

    pub fn end_cycle(&self) -> Cycle {
        self.end_cycle
    }
}

impl Default for PreflightTracerConfig {
    fn default() -> Self {
        Self::with_default_boundaries(NEXT_ACCESS_PREALLOC)
    }
}

impl PreflightTracer {
    pub const SUBCYCLE_RS1: Cycle = <Self as Tracer>::SUBCYCLE_RS1;
    pub const SUBCYCLE_RS2: Cycle = <Self as Tracer>::SUBCYCLE_RS2;
    pub const SUBCYCLE_RD: Cycle = <Self as Tracer>::SUBCYCLE_RD;
    pub const SUBCYCLE_MEM: Cycle = <Self as Tracer>::SUBCYCLE_MEM;
    pub const SUBCYCLES_PER_INSN: Cycle = <Self as Tracer>::SUBCYCLES_PER_INSN;

    pub fn new(platform: &Platform, config: &PreflightTracerConfig) -> Self {
        let capacity = config.capacity();
        let next_accesses = (0..capacity)
            .into_par_iter()
            .map(|_| NextAccessPair::default())
            .collect();
        let shard_cycle_boundaries = config.shard_cycle_boundaries();
        assert!(
            shard_cycle_boundaries.len() >= 2,
            "shard_cycle_boundaries must contain at least two entries"
        );
        let (current_shard_start_cycle, current_shard_end_cycle) =
            (shard_cycle_boundaries[0], shard_cycle_boundaries[1]);
        let mut tracer = PreflightTracer {
            cycle: <Self as Tracer>::SUBCYCLES_PER_INSN,
            pc: Default::default(),
            mmio_min_max_access: Some(init_mmio_min_max_access(platform)),
            latest_accesses: LatestAccesses::new(platform),
            next_accesses,
            register_reads_tracked: 0,
            shard_cycle_boundaries,
            current_shard_idx: 0,
            current_shard_start_cycle,
            current_shard_end_cycle,
            final_cycle: config.end_cycle(),
        };
        tracer.reset_register_tracking();
        assert!(
            tracer.current_shard_start_cycle < tracer.current_shard_end_cycle,
            "non-incremental shard boundary at index 0"
        );
        tracer
    }

    #[inline(always)]
    fn update_mmio_bounds(&mut self, addr: WordAddr) {
        if let Some((_, (_, end_addr, min_addr, max_addr))) = self
            .mmio_min_max_access
            .as_mut()
            .and_then(|mmio_max_access| mmio_max_access.range_mut(..=addr).next_back())
            && addr < *end_addr
        {
            // skip if the target address is not within the range tracked by this MMIO region
            // this condition ensures the address is within the MMIO region's end address
            if addr >= *max_addr {
                *max_addr = addr + WordAddr::from(WORD_SIZE as u32);
            }
            if addr < *min_addr {
                *min_addr = addr;
            }
        }
    }

    #[inline(always)]
    fn reset_register_tracking(&mut self) {
        self.register_reads_tracked = 0;
    }

    #[inline(always)]
    fn maybe_advance_shard(&mut self) {
        if self.cycle < self.current_shard_end_cycle || self.cycle >= self.final_cycle {
            return;
        }
        let len = self.shard_cycle_boundaries.len();
        let next_idx = self.current_shard_idx + 1;
        assert!(
            next_idx + 1 < len,
            "cycle {} exceeded configured shard boundaries",
            self.cycle
        );
        self.current_shard_idx = next_idx;
        self.current_shard_start_cycle = self.shard_cycle_boundaries[next_idx];
        self.current_shard_end_cycle = self.shard_cycle_boundaries[next_idx + 1];
        assert!(
            self.current_shard_start_cycle < self.current_shard_end_cycle,
            "non-incremental shard boundary at index {}",
            next_idx
        );
    }
}

impl Tracer for PreflightTracer {
    type Record = ();
    type Config = PreflightTracerConfig;

    fn new(platform: &Platform, config: &Self::Config) -> Self {
        PreflightTracer::new(platform, config)
    }

    #[inline(always)]
    fn advance(&mut self) -> Self::Record {
        self.cycle += Self::SUBCYCLES_PER_INSN;
        self.maybe_advance_shard();
        self.reset_register_tracking();
    }

    fn is_busy_loop(&self, _: &Self::Record) -> bool {
        self.pc.before == self.pc.after
    }

    #[inline(always)]
    fn store_pc(&mut self, pc: ByteAddr) {
        self.pc.after = pc;
    }

    #[inline(always)]
    fn fetch(&mut self, pc: WordAddr, _value: Instruction) {
        self.pc.before = pc.baddr();
    }

    #[inline(always)]
    fn track_mmu_maxtouch_before(&mut self) {}

    #[inline(always)]
    fn track_mmu_maxtouch_after(&mut self) {}

    #[inline(always)]
    fn load_register(&mut self, idx: RegIdx, _value: Word) {
        let addr = Platform::register_vma(idx).into();
        let subcycle = match self.register_reads_tracked {
            0 => Self::SUBCYCLE_RS1,
            1 => Self::SUBCYCLE_RS2,
            _ => unimplemented!("Only two register reads are supported"),
        };
        self.register_reads_tracked += 1;
        self.track_access(addr, subcycle);
    }

    #[inline(always)]
    fn store_register(&mut self, idx: RegIdx, _value: Change<Word>) {
        let addr = Platform::register_vma(idx).into();
        self.track_access(addr, Self::SUBCYCLE_RD);
    }

    #[inline(always)]
    fn load_memory(&mut self, addr: WordAddr, value: Word) {
        self.store_memory(addr, Change::new(value, value));
    }

    #[inline(always)]
    fn store_memory(&mut self, addr: WordAddr, _value: Change<Word>) {
        self.update_mmio_bounds(addr);
        self.track_access(addr, Self::SUBCYCLE_MEM);
    }

    #[inline(always)]
    fn track_syscall(&mut self, effects: SyscallEffects) {
        let _ = effects.finalize(self);
    }

    #[inline(always)]
    fn track_access(&mut self, addr: WordAddr, subcycle: Cycle) -> Cycle {
        let cur_cycle = self.cycle + subcycle;
        let prev_cycle = self.latest_accesses.track(addr, cur_cycle);
        // if prev_cycle < self.current_shard_start_cycle {
        let idx = prev_cycle as usize;
        self.next_accesses[idx].push((addr, cur_cycle));
        // }
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

impl Tracer for FullTracer {
    type Record = StepRecord;
    type Config = ();

    fn new(platform: &Platform, _config: &Self::Config) -> Self {
        FullTracer::new(platform)
    }

    #[inline(always)]
    fn advance(&mut self) -> Self::Record {
        FullTracer::advance(self)
    }

    #[inline(always)]
    fn is_busy_loop(&self, record: &Self::Record) -> bool {
        record.is_busy_loop()
    }

    #[inline(always)]
    fn store_pc(&mut self, pc: ByteAddr) {
        FullTracer::store_pc(self, pc)
    }

    #[inline(always)]
    fn fetch(&mut self, pc: WordAddr, value: Instruction) {
        FullTracer::fetch(self, pc, value)
    }

    fn track_mmu_maxtouch_before(&mut self) {
        FullTracer::track_mmu_maxtouch_before(self)
    }

    fn track_mmu_maxtouch_after(&mut self) {
        FullTracer::track_mmu_maxtouch_after(self)
    }

    #[inline(always)]
    fn load_register(&mut self, idx: RegIdx, value: Word) {
        FullTracer::load_register(self, idx, value)
    }

    #[inline(always)]
    fn store_register(&mut self, idx: RegIdx, value: Change<Word>) {
        FullTracer::store_register(self, idx, value)
    }

    #[inline(always)]
    fn load_memory(&mut self, addr: WordAddr, value: Word) {
        FullTracer::load_memory(self, addr, value)
    }

    #[inline(always)]
    fn store_memory(&mut self, addr: WordAddr, value: Change<Word>) {
        FullTracer::store_memory(self, addr, value)
    }

    #[inline(always)]
    fn track_syscall(&mut self, effects: SyscallEffects) {
        FullTracer::track_syscall(self, effects)
    }

    #[inline(always)]
    fn track_access(&mut self, addr: WordAddr, subcycle: Cycle) -> Cycle {
        FullTracer::track_access(self, addr, subcycle)
    }

    fn final_accesses(&self) -> &LatestAccesses {
        FullTracer::final_accesses(self)
    }

    fn into_next_accesses(self) -> NextCycleAccess {
        unimplemented!("FullTracer does not record next access metadata")
    }

    fn cycle(&self) -> Cycle {
        FullTracer::cycle(self)
    }

    fn executed_insts(&self) -> usize {
        FullTracer::executed_insts(self)
    }

    fn probe_min_max_address_by_start_addr(
        &self,
        start_addr: WordAddr,
    ) -> Option<(WordAddr, WordAddr)> {
        FullTracer::probe_min_max_address_by_start_addr(self, start_addr)
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
