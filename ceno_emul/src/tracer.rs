use crate::{
    CENO_PLATFORM, InsnKind, Instruction, PC_STEP_SIZE, Platform,
    addr::{ByteAddr, Cycle, RegIdx, Word, WordAddr},
    dense_addr_space::DenseAddrSpace,
    encode_rv32,
    syscalls::{SyscallEffects, SyscallWitness},
};
use ceno_rt::WORD_SIZE;
use rustc_hash::FxHashMap;
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

pub trait StepCellExtractor {
    fn cells_for_kind(&self, kind: InsnKind, rs1_value: Option<Word>) -> u64;

    #[inline(always)]
    fn extract_cells(&self, step: &StepRecord) -> u64 {
        self.cells_for_kind(step.insn().kind, step.rs1().map(|op| op.value))
    }
}

pub type NextAccessPair = SmallVec<[(WordAddr, Cycle); 1]>;
pub type NextCycleAccess = FxHashMap<Cycle, NextAccessPair>;

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

#[derive(Clone, Debug)]
pub struct ShardPlanBuilder {
    shard_cycle_boundaries: Vec<Cycle>,
    max_cell_per_shard: u64,
    target_cell_first_shard: u64,
    max_cycle_per_shard: Cycle,
    current_shard_start_cycle: Cycle,
    cur_cells: u64,
    cur_cycle_in_shard: Cycle,
    shard_id: usize,
    finalized: bool,
}

impl ShardPlanBuilder {
    pub fn new(max_cell_per_shard: u64, max_cycle_per_shard: Cycle) -> Self {
        let initial_cycle = FullTracer::SUBCYCLES_PER_INSN;
        ShardPlanBuilder {
            shard_cycle_boundaries: vec![initial_cycle],
            max_cell_per_shard,
            target_cell_first_shard: if max_cell_per_shard == u64::MAX {
                u64::MAX
            } else {
                max_cell_per_shard
            },
            max_cycle_per_shard,
            current_shard_start_cycle: initial_cycle,
            cur_cells: 0,
            cur_cycle_in_shard: 0,
            shard_id: 0,
            finalized: false,
        }
    }

    pub fn current_shard_start_cycle(&self) -> Cycle {
        self.current_shard_start_cycle
    }

    pub fn shard_cycle_boundaries(&self) -> &[Cycle] {
        &self.shard_cycle_boundaries
    }

    pub fn max_cycle(&self) -> Cycle {
        assert!(self.finalized, "shard plan not finalized yet");
        *self
            .shard_cycle_boundaries
            .last()
            .expect("shard boundaries must contain at least one entry")
    }

    pub fn into_cycle_boundaries(self) -> Vec<Cycle> {
        assert!(self.finalized, "shard plan not finalized yet");
        self.shard_cycle_boundaries
    }

    pub fn observe_step(&mut self, step_cycle: Cycle, step_cells: u64) {
        assert!(
            !self.finalized,
            "shard plan cannot be extended after finalization"
        );
        let target = if self.shard_id == 0 {
            self.target_cell_first_shard
        } else {
            self.max_cell_per_shard
        };

        // always include step in current shard to simplify overall logic
        self.cur_cells = self.cur_cells.saturating_add(step_cells);
        self.cur_cycle_in_shard = self
            .cur_cycle_in_shard
            .saturating_add(FullTracer::SUBCYCLES_PER_INSN);

        let cycle_limit_hit = self.max_cycle_per_shard < Cycle::MAX
            && self.cur_cycle_in_shard >= self.max_cycle_per_shard;
        let should_split = self.cur_cells >= target || cycle_limit_hit;
        if should_split {
            assert!(
                self.cur_cells > 0 || self.cur_cycle_in_shard > 0,
                "shard split before accumulating any steps"
            );
            let next_shard_cycle = step_cycle + FullTracer::SUBCYCLES_PER_INSN;
            self.push_boundary(next_shard_cycle);
            self.shard_id += 1;
            self.current_shard_start_cycle = next_shard_cycle;
            self.cur_cells = 0;
            self.cur_cycle_in_shard = 0;
        }
    }

    pub fn finalize(&mut self, max_cycle: Cycle) {
        assert!(
            !self.finalized,
            "shard plan cannot be finalized multiple times"
        );
        self.push_boundary(max_cycle);
        self.finalized = true;
    }

    fn push_boundary(&mut self, cycle: Cycle) {
        if self
            .shard_cycle_boundaries
            .last()
            .copied()
            .unwrap_or_default()
            != cycle
        {
            self.shard_cycle_boundaries.push(cycle);
        }
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

pub struct PreflightTracer {
    cycle: Cycle,
    pc: Change<ByteAddr>,
    last_kind: InsnKind,
    last_rs1: Option<Word>,
    mmio_min_max_access: Option<BTreeMap<WordAddr, (WordAddr, WordAddr, WordAddr, WordAddr)>>,
    latest_accesses: LatestAccesses,
    next_accesses: NextCycleAccess,
    register_reads_tracked: u8,
    record_next_accesses: bool,
    planner: Option<ShardPlanBuilder>,
    current_shard_start_cycle: Cycle,
    step_cell_extractor: Option<Arc<dyn StepCellExtractor>>,
}

#[derive(Clone)]
pub struct PreflightTracerConfig {
    record_next_accesses: bool,
    max_cell_per_shard: u64,
    max_cycle_per_shard: Cycle,
    step_cell_extractor: Option<Arc<dyn StepCellExtractor>>,
}

impl fmt::Debug for PreflightTracer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PreflightTracer")
            .field("cycle", &self.cycle)
            .field("pc", &self.pc)
            .field("last_kind", &self.last_kind)
            .field("last_rs1", &self.last_rs1)
            .field("mmio_min_max_access", &self.mmio_min_max_access)
            .field("latest_accesses", &self.latest_accesses)
            .field("next_accesses", &self.next_accesses)
            .field("register_reads_tracked", &self.register_reads_tracked)
            .field("record_next_accesses", &self.record_next_accesses)
            .field("planner", &self.planner)
            .field("current_shard_start_cycle", &self.current_shard_start_cycle)
            .field("step_cell_extractor", &self.step_cell_extractor.is_some())
            .finish()
    }
}

impl fmt::Debug for PreflightTracerConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PreflightTracerConfig")
            .field("record_next_accesses", &self.record_next_accesses)
            .field("max_cell_per_shard", &self.max_cell_per_shard)
            .field("max_cycle_per_shard", &self.max_cycle_per_shard)
            .field("step_cell_extractor", &self.step_cell_extractor.is_some())
            .finish()
    }
}

impl PreflightTracerConfig {
    pub fn new(
        record_next_accesses: bool,
        max_cell_per_shard: u64,
        max_cycle_per_shard: Cycle,
    ) -> Self {
        Self {
            record_next_accesses,
            max_cell_per_shard,
            max_cycle_per_shard,
            step_cell_extractor: None,
        }
    }

    pub fn record_next_accesses(&self) -> bool {
        self.record_next_accesses
    }

    pub fn max_cell_per_shard(&self) -> u64 {
        self.max_cell_per_shard
    }

    pub fn max_cycle_per_shard(&self) -> Cycle {
        self.max_cycle_per_shard
    }

    pub fn with_step_cell_extractor(mut self, extractor: Arc<dyn StepCellExtractor>) -> Self {
        self.step_cell_extractor = Some(extractor);
        self
    }

    pub fn step_cell_extractor(&self) -> Option<Arc<dyn StepCellExtractor>> {
        self.step_cell_extractor.clone()
    }
}

impl Default for PreflightTracerConfig {
    fn default() -> Self {
        Self {
            record_next_accesses: true,
            max_cell_per_shard: u64::MAX,
            max_cycle_per_shard: Cycle::MAX,
            step_cell_extractor: None,
        }
    }
}

impl PreflightTracer {
    pub const SUBCYCLE_RS1: Cycle = <Self as Tracer>::SUBCYCLE_RS1;
    pub const SUBCYCLE_RS2: Cycle = <Self as Tracer>::SUBCYCLE_RS2;
    pub const SUBCYCLE_RD: Cycle = <Self as Tracer>::SUBCYCLE_RD;
    pub const SUBCYCLE_MEM: Cycle = <Self as Tracer>::SUBCYCLE_MEM;
    pub const SUBCYCLES_PER_INSN: Cycle = <Self as Tracer>::SUBCYCLES_PER_INSN;

    pub fn last_insn_kind(&self) -> InsnKind {
        self.last_kind
    }

    pub fn last_rs1_value(&self) -> Option<Word> {
        self.last_rs1
    }

    pub fn new(platform: &Platform, config: &PreflightTracerConfig) -> Self {
        let mut max_cycle_per_shard = config.max_cycle_per_shard();
        if max_cycle_per_shard != Cycle::MAX {
            // Observe-step already accounts for the current instruction, so shrink the
            // limit by one instruction to keep shard boundaries aligned with callers.
            max_cycle_per_shard = max_cycle_per_shard.saturating_sub(Self::SUBCYCLES_PER_INSN);
        }
        let mut tracer = PreflightTracer {
            cycle: <Self as Tracer>::SUBCYCLES_PER_INSN,
            pc: Default::default(),
            last_kind: InsnKind::INVALID,
            last_rs1: None,
            mmio_min_max_access: Some(init_mmio_min_max_access(platform)),
            latest_accesses: LatestAccesses::new(platform),
            next_accesses: FxHashMap::default(),
            register_reads_tracked: 0,
            record_next_accesses: config.record_next_accesses(),
            planner: Some(ShardPlanBuilder::new(
                config.max_cell_per_shard(),
                max_cycle_per_shard,
            )),
            current_shard_start_cycle: <Self as Tracer>::SUBCYCLES_PER_INSN,
            step_cell_extractor: config.step_cell_extractor(),
        };
        tracer.reset_register_tracking();
        tracer
    }

    pub fn into_shard_plan(self) -> (ShardPlanBuilder, NextCycleAccess) {
        let Some(mut planner) = self.planner else {
            panic!("shard planner missing")
        };
        if !planner.finalized {
            planner.finalize(self.cycle);
        }
        (planner, self.next_accesses)
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
}

impl Tracer for PreflightTracer {
    type Record = ();
    type Config = PreflightTracerConfig;

    fn new(platform: &Platform, config: &Self::Config) -> Self {
        PreflightTracer::new(platform, config)
    }

    #[inline(always)]
    fn advance(&mut self) -> Self::Record {
        if let Some(planner) = self.planner.as_mut() {
            // compute whether next step should bump the cycle
            let step_cells = self
                .step_cell_extractor
                .as_ref()
                .map(|extractor| extractor.cells_for_kind(self.last_kind, self.last_rs1))
                .unwrap_or(0);
            planner.observe_step(self.cycle, step_cells);
            self.current_shard_start_cycle = planner.current_shard_start_cycle();
        }
        self.cycle += Self::SUBCYCLES_PER_INSN;
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
        let addr = Platform::register_vma(idx).into();
        let subcycle = match self.register_reads_tracked {
            0 => Self::SUBCYCLE_RS1,
            1 => Self::SUBCYCLE_RS2,
            _ => unimplemented!("Only two register reads are supported"),
        };
        self.register_reads_tracked += 1;
        if matches!(self.last_kind, InsnKind::ECALL) && idx == Platform::reg_ecall() {
            self.last_rs1 = Some(value);
        }
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
        if self.record_next_accesses && prev_cycle < self.current_shard_start_cycle {
            self.next_accesses
                .entry(prev_cycle)
                .or_default()
                .push((addr, cur_cycle));
        }
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
