use crate::{
    CENO_PLATFORM, InsnKind, Instruction, PC_STEP_SIZE, Platform,
    addr::{ByteAddr, Cycle, RegIdx, Word, WordAddr},
    dense_addr_space::DenseAddrSpace,
    encode_rv32,
    syscalls::{SyscallEffects, SyscallWitness},
};
use ceno_rt::WORD_SIZE;
use rayon::prelude::*;
use rustc_hash::FxHashMap;
use smallvec::SmallVec;
use std::{collections::BTreeMap, fmt, sync::Arc};
use strum::EnumCount;

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
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct StepRecord {
    cycle: Cycle,
    pc: Change<ByteAddr>,
    pub heap_maxtouch_addr: Change<ByteAddr>,
    pub hint_maxtouch_addr: Change<ByteAddr>,
    pub insn: Instruction,

    has_rs1: bool,
    has_rs2: bool,
    has_rd: bool,
    has_memory_op: bool,

    rs1: ReadOp,
    rs2: ReadOp,
    rd: WriteOp,
    memory_op: WriteOp,

    /// Index into the separate syscall witness storage.
    /// `u32::MAX` means no syscall for this step.
    syscall_index: u32,
}

impl StepRecord {
    /// Sentinel value indicating no syscall is associated with this step.
    pub const NO_SYSCALL: u32 = u32::MAX;
}

impl Default for StepRecord {
    fn default() -> Self {
        Self {
            cycle: 0,
            pc: Default::default(),
            heap_maxtouch_addr: Default::default(),
            hint_maxtouch_addr: Default::default(),
            insn: Default::default(),
            has_rs1: false,
            has_rs2: false,
            has_rd: false,
            has_memory_op: false,
            rs1: Default::default(),
            rs2: Default::default(),
            rd: Default::default(),
            memory_op: Default::default(),
            syscall_index: StepRecord::NO_SYSCALL,
        }
    }
}

pub type StepIndex = usize;

pub trait StepCellExtractor {
    fn cells_for_kind(&self, kind: InsnKind, rs1_value: Option<Word>) -> u64;

    fn shard_cost_model(&self) -> Option<Arc<ShardCostModel>> {
        None
    }

    #[inline(always)]
    fn extract_cells(&self, step: &StepRecord) -> u64 {
        self.cells_for_kind(step.insn().kind, step.rs1().map(|op| op.value))
    }
}

pub const SHARD_COST_BUCKETS: usize = u64::BITS as usize + 2;
const NO_CHIP: u32 = u32::MAX;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChipCostSpec {
    pub rotation: u8,
    pub trace_cells_per_row: u64,
    pub tower_peak_cells_per_row: u64,
    /// Optional scheduler-derived tower peak for every padded-size bucket.
    /// When absent, tests and compatibility callers use the linear per-row
    /// estimate above.
    pub tower_peak_cells_by_bucket: Option<Vec<u64>>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct ChipCost {
    pub trace_cells: u64,
    pub main_peak: u64,
    pub tower_peak: u64,
}

#[derive(Clone, Debug)]
pub struct ShardCostModel {
    opcode_chips: Vec<Vec<u32>>,
    ecall_chips: BTreeMap<Word, Vec<u32>>,
    chip_specs: Vec<ChipCostSpec>,
    trace_cost_table: Vec<u64>,
    main_cost_table: Vec<u64>,
    tower_cost_table: Vec<u64>,
    extension_field_degree: u64,
}

impl ShardCostModel {
    pub fn new(
        opcode_chips: Vec<Vec<usize>>,
        ecall_chips: BTreeMap<Word, Vec<usize>>,
        chip_specs: Vec<ChipCostSpec>,
        extension_field_degree: usize,
    ) -> Self {
        assert_eq!(opcode_chips.len(), InsnKind::COUNT);
        assert!(extension_field_degree > 0);
        assert!(chip_specs.len() < NO_CHIP as usize);
        assert!(
            opcode_chips
                .iter()
                .flatten()
                .chain(ecall_chips.values().flatten())
                .all(|&chip| chip < chip_specs.len()),
            "shard cost mapping references an unknown chip"
        );
        let opcode_chips = opcode_chips
            .into_iter()
            .map(|chips| chips.into_iter().map(|chip| chip as u32).collect())
            .collect();
        let ecall_chips = ecall_chips
            .into_iter()
            .map(|(code, chips)| (code, chips.into_iter().map(|chip| chip as u32).collect()))
            .collect();
        let extension_field_degree = extension_field_degree as u64;
        let table_len = chip_specs.len() * SHARD_COST_BUCKETS;
        let mut trace_cost_table = Vec::with_capacity(table_len);
        let mut main_cost_table = Vec::with_capacity(table_len);
        let mut tower_cost_table = Vec::with_capacity(table_len);
        for spec in &chip_specs {
            if let Some(tower_costs) = &spec.tower_peak_cells_by_bucket {
                assert_eq!(tower_costs.len(), SHARD_COST_BUCKETS);
            }
            for bucket in 0..SHARD_COST_BUCKETS {
                let padded_instances = match bucket {
                    0 => 0,
                    bucket if bucket == SHARD_COST_BUCKETS - 1 => u64::MAX,
                    bucket => 1u64 << (bucket - 1),
                };
                let rotation_size = 1u64.checked_shl(spec.rotation.into()).unwrap_or(u64::MAX);
                let domain_rows = padded_instances
                    .checked_mul(rotation_size)
                    .unwrap_or(u64::MAX);
                let trace_cells = domain_rows.saturating_mul(spec.trace_cells_per_row);
                let main_peak = domain_rows.saturating_mul(extension_field_degree);
                let tower_peak = spec.tower_peak_cells_by_bucket.as_ref().map_or_else(
                    || domain_rows.saturating_mul(spec.tower_peak_cells_per_row),
                    |tower_costs| tower_costs[bucket],
                );
                trace_cost_table.push(trace_cells);
                main_cost_table.push(main_peak);
                tower_cost_table.push(tower_peak);
            }
        }
        Self {
            opcode_chips,
            ecall_chips,
            chip_specs,
            trace_cost_table,
            main_cost_table,
            tower_cost_table,
            extension_field_degree,
        }
    }

    pub fn chip_count(&self) -> usize {
        self.chip_specs.len()
    }

    pub fn chips_for_step(&self, kind: InsnKind, ecall_code: Option<Word>) -> &[u32] {
        if kind == InsnKind::ECALL {
            ecall_code
                .and_then(|code| self.ecall_chips.get(&code))
                .map_or(&[], Vec::as_slice)
        } else {
            self.opcode_chips
                .get(kind as usize)
                .map_or(&[], Vec::as_slice)
        }
    }

    pub fn chip_cost(&self, chip: usize, num_instances: u64) -> ChipCost {
        let index = chip * SHARD_COST_BUCKETS + padded_size_bucket(num_instances);
        ChipCost {
            trace_cells: self.trace_cost_table[index],
            main_peak: self.main_cost_table[index],
            tower_peak: self.tower_cost_table[index],
        }
    }

    pub fn trace_cost_table(&self) -> &[u64] {
        &self.trace_cost_table
    }

    pub fn main_cost_table(&self) -> &[u64] {
        &self.main_cost_table
    }

    pub fn tower_cost_table(&self) -> &[u64] {
        &self.tower_cost_table
    }

    pub fn shard_cost(&self, num_instances: &[u64]) -> u64 {
        assert_eq!(num_instances.len(), self.chip_count());
        let (trace_total, main_total, tower_peak) = num_instances.iter().enumerate().fold(
            (0u64, 0u64, 0u64),
            |(trace, main, tower), (chip, &count)| {
                let cost = self.chip_cost(chip, count);
                (
                    trace.saturating_add(cost.trace_cells),
                    main.saturating_add(cost.main_peak),
                    tower.max(cost.tower_peak),
                )
            },
        );
        trace_total.saturating_add(main_total.max(tower_peak))
    }

    pub fn extension_field_degree(&self) -> u64 {
        self.extension_field_degree
    }
}

#[inline(always)]
fn padded_size_bucket(num_instances: u64) -> usize {
    if num_instances == 0 {
        0
    } else {
        (u64::BITS - num_instances.saturating_sub(1).leading_zeros() + 1) as usize
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

    fn new(platform: &Platform, config: Self::Config) -> Self;

    fn with_next_accesses(
        platform: &Platform,
        config: Self::Config,
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

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Hash)]
#[repr(C)]
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
                ByteAddr::from(platform.stack.end).waddr(),
            ),
            len: 0,
            #[cfg(any(test, debug_assertions))]
            touched: Vec::new(),
        }
    }

    fn track(&mut self, addr: WordAddr, cycle: Cycle) -> Cycle {
        let prev = self.store.replace_in_bounds(addr, cycle);
        if prev == Cycle::default() {
            self.len += 1;
            #[cfg(any(test, debug_assertions))]
            {
                self.touched.push(addr);
            }
        }
        prev
    }

    #[cfg_attr(
        not(all(feature = "aot-x86_64", target_arch = "x86_64", target_os = "linux")),
        allow(dead_code)
    )]
    fn cells_mut_ptr(&mut self) -> *mut Cycle {
        self.store.cells_mut_ptr()
    }

    #[cfg_attr(
        not(all(feature = "aot-x86_64", target_arch = "x86_64", target_os = "linux")),
        allow(dead_code)
    )]
    fn base(&self) -> WordAddr {
        self.store.base()
    }

    #[cfg_attr(
        not(all(feature = "aot-x86_64", target_arch = "x86_64", target_os = "linux")),
        allow(dead_code)
    )]
    fn record_native_first_touch(&mut self, addr: WordAddr) {
        self.len += 1;
        #[cfg(not(any(test, debug_assertions)))]
        let _ = addr;
        #[cfg(any(test, debug_assertions))]
        {
            self.touched.push(addr);
        }
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
    predicted_shard_costs: Vec<u64>,
    max_cell_per_shard: u64,
    target_cell_first_shard: u64,
    max_cycle_per_shard: Cycle,
    current_shard_start_cycle: Cycle,
    cur_cells: u64,
    cur_trace_cells: u64,
    cur_main_peak: u64,
    cur_tower_peak: u64,
    cost_model: Option<Arc<ShardCostModel>>,
    num_instances: Vec<u64>,
    cur_ecall_counts: BTreeMap<Word, u64>,
    cur_ecall_peak_cells: BTreeMap<Word, u64>,
    cur_cycle_in_shard: Cycle,
    cur_step_count: usize,
    max_step_shard: usize,
    shard_id: usize,
    finalized: bool,
}

impl ShardPlanBuilder {
    pub fn new(max_cell_per_shard: u64, max_cycle_per_shard: Cycle) -> Self {
        Self::new_with_cost_model(max_cell_per_shard, max_cycle_per_shard, None)
    }

    pub fn new_with_cost_model(
        max_cell_per_shard: u64,
        max_cycle_per_shard: Cycle,
        cost_model: Option<Arc<ShardCostModel>>,
    ) -> Self {
        let initial_cycle = FullTracer::SUBCYCLES_PER_INSN;
        let num_instances = vec![0; cost_model.as_ref().map_or(0, |model| model.chip_count())];
        ShardPlanBuilder {
            shard_cycle_boundaries: vec![initial_cycle],
            predicted_shard_costs: Vec::new(),
            max_cell_per_shard,
            target_cell_first_shard: max_cell_per_shard,
            max_cycle_per_shard,
            current_shard_start_cycle: initial_cycle,
            cur_cells: 0,
            cur_trace_cells: 0,
            cur_main_peak: 0,
            cur_tower_peak: 0,
            cost_model,
            num_instances,
            cur_ecall_counts: BTreeMap::new(),
            cur_ecall_peak_cells: BTreeMap::new(),
            cur_cycle_in_shard: 0,
            cur_step_count: 0,
            max_step_shard: 0,
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

    pub fn max_step_shard(&self) -> usize {
        self.max_step_shard
    }

    pub fn predicted_shard_costs(&self) -> &[u64] {
        &self.predicted_shard_costs
    }

    pub fn into_cycle_boundaries(self) -> Vec<Cycle> {
        assert!(self.finalized, "shard plan not finalized yet");
        self.shard_cycle_boundaries
    }

    pub fn observe_step(&mut self, step_cycle: Cycle, step_cells: u64) {
        self.observe_step_with_delta(step_cycle, step_cells, |planner| {
            planner.cur_cells = planner.cur_cells.saturating_add(step_cells);
        });
    }

    fn observe_ecall_step(&mut self, step_cycle: Cycle, ecall_code: Word, base_cells: u64) {
        self.observe_step_with_delta(
            step_cycle,
            self.ecall_step_delta(ecall_code, base_cells),
            |planner| planner.add_ecall_step(ecall_code, base_cells),
        );
    }

    fn observe_modeled_step(
        &mut self,
        step_cycle: Cycle,
        kind: InsnKind,
        ecall_code: Option<Word>,
    ) {
        let chips = self
            .cost_model
            .as_ref()
            .map(|model| {
                model
                    .chips_for_step(kind, ecall_code)
                    .iter()
                    .map(|&chip| chip as usize)
                    .collect::<SmallVec<[_; 2]>>()
            })
            .unwrap_or_default();
        assert!(
            !self.finalized,
            "shard plan cannot be extended after finalization"
        );
        let mut candidate = self.preview_modeled_chips(&chips);
        if self.cur_step_count > 0 && self.candidate_would_exceed_shard(candidate.3) {
            self.finish_current_shard(step_cycle);
            candidate = self.preview_modeled_chips(&chips);
        }
        for chip in chips {
            self.num_instances[chip] = self.num_instances[chip].saturating_add(1);
        }
        (
            self.cur_trace_cells,
            self.cur_main_peak,
            self.cur_tower_peak,
            self.cur_cells,
        ) = candidate;
        self.cur_cycle_in_shard = self
            .cur_cycle_in_shard
            .saturating_add(FullTracer::SUBCYCLES_PER_INSN);
        self.cur_step_count = self.cur_step_count.saturating_add(1);
        self.debug_assert_cost_invariant();
    }

    fn preview_modeled_chips(&self, chips: &[usize]) -> (u64, u64, u64, u64) {
        let model = self.cost_model.as_ref().expect("cost model missing");
        let mut trace = self.cur_trace_cells;
        let mut main = self.cur_main_peak;
        let mut tower = self.cur_tower_peak;
        for &chip in chips {
            let old = model.chip_cost(chip, self.num_instances[chip]);
            let new = model.chip_cost(chip, self.num_instances[chip].saturating_add(1));
            trace = trace.saturating_add(new.trace_cells.saturating_sub(old.trace_cells));
            main = main.saturating_add(new.main_peak.saturating_sub(old.main_peak));
            tower = tower.max(new.tower_peak);
        }
        let total = trace.saturating_add(main.max(tower));
        (trace, main, tower, total)
    }

    fn observe_step_with_delta(
        &mut self,
        step_cycle: Cycle,
        step_delta: u64,
        add_step: impl FnOnce(&mut Self),
    ) {
        assert!(
            !self.finalized,
            "shard plan cannot be extended after finalization"
        );
        if self.cur_step_count > 0 && self.step_would_exceed_shard(step_delta) {
            self.finish_current_shard(step_cycle);
        }

        add_step(self);
        self.cur_cycle_in_shard = self
            .cur_cycle_in_shard
            .saturating_add(FullTracer::SUBCYCLES_PER_INSN);
        self.cur_step_count = self.cur_step_count.saturating_add(1);
    }

    fn step_would_exceed_shard(&self, step_delta: u64) -> bool {
        self.candidate_would_exceed_shard(self.cur_cells.saturating_add(step_delta))
    }

    fn candidate_would_exceed_shard(&self, candidate_cost: u64) -> bool {
        let target = if self.shard_id == 0 {
            self.target_cell_first_shard
        } else {
            self.max_cell_per_shard
        };
        candidate_cost > target
            || self
                .cur_cycle_in_shard
                .saturating_add(FullTracer::SUBCYCLES_PER_INSN)
                >= self.max_cycle_per_shard
    }

    fn finish_current_shard(&mut self, next_shard_cycle: Cycle) {
        assert!(
            self.cur_cells > 0 || self.cur_cycle_in_shard > 0,
            "shard split before accumulating any steps"
        );
        self.record_predicted_shard_cost();
        self.push_boundary(next_shard_cycle);
        self.shard_id += 1;
        self.current_shard_start_cycle = next_shard_cycle;
        self.cur_cells = 0;
        self.cur_trace_cells = 0;
        self.cur_main_peak = 0;
        self.cur_tower_peak = 0;
        self.num_instances.fill(0);
        self.cur_ecall_counts.clear();
        self.cur_ecall_peak_cells.clear();
        self.cur_cycle_in_shard = 0;
        self.max_step_shard = self.max_step_shard.max(self.cur_step_count);
        self.cur_step_count = 0;
    }

    fn add_ecall_step(&mut self, ecall_code: Word, base_cells: u64) {
        let old_count = self
            .cur_ecall_counts
            .get(&ecall_code)
            .copied()
            .unwrap_or_default();
        let new_count = old_count.saturating_add(1);
        let old_peak = self
            .cur_ecall_peak_cells
            .get(&ecall_code)
            .copied()
            .unwrap_or_default();
        let new_peak = ecall_peak_cells(base_cells, new_count);
        self.cur_ecall_counts.insert(ecall_code, new_count);
        self.cur_ecall_peak_cells.insert(ecall_code, new_peak);
        self.cur_cells = self
            .cur_cells
            .saturating_add(new_peak.saturating_sub(old_peak));
    }

    fn ecall_step_delta(&self, ecall_code: Word, base_cells: u64) -> u64 {
        let old_count = self
            .cur_ecall_counts
            .get(&ecall_code)
            .copied()
            .unwrap_or_default();
        let old_peak = self
            .cur_ecall_peak_cells
            .get(&ecall_code)
            .copied()
            .unwrap_or_default();
        let new_peak = ecall_peak_cells(base_cells, old_count.saturating_add(1));
        new_peak.saturating_sub(old_peak)
    }

    #[cfg(test)]
    fn ecall_count(&self, ecall_code: Word) -> u64 {
        self.cur_ecall_counts
            .get(&ecall_code)
            .copied()
            .unwrap_or_default()
    }

    #[cfg(test)]
    fn ecall_peak_cells(&self, ecall_code: Word) -> u64 {
        self.cur_ecall_peak_cells
            .get(&ecall_code)
            .copied()
            .unwrap_or_default()
    }

    #[cfg(test)]
    fn cur_cells(&self) -> u64 {
        self.cur_cells
    }

    #[cfg(test)]
    fn cur_step_count(&self) -> usize {
        self.cur_step_count
    }

    #[cfg(test)]
    fn current_shard_id(&self) -> usize {
        self.shard_id
    }

    #[cfg(test)]
    fn ecall_delta_for(&self, ecall_code: Word, base_cells: u64) -> u64 {
        self.ecall_step_delta(ecall_code, base_cells)
    }

    fn reset_after_native_shard_split(&mut self) {
        self.num_instances.fill(0);
        self.cur_trace_cells = 0;
        self.cur_main_peak = 0;
        self.cur_tower_peak = 0;
        self.cur_ecall_counts.clear();
        self.cur_ecall_peak_cells.clear();
    }

    #[cfg(any(test, debug_assertions))]
    fn debug_assert_cost_invariant(&self) {
        if let Some(model) = &self.cost_model {
            let (trace, main, tower) = self.num_instances.iter().enumerate().fold(
                (0u64, 0u64, 0u64),
                |(trace, main, tower), (chip, &count)| {
                    let cost = model.chip_cost(chip, count);
                    (
                        trace.saturating_add(cost.trace_cells),
                        main.saturating_add(cost.main_peak),
                        tower.max(cost.tower_peak),
                    )
                },
            );
            let recomputed = trace.saturating_add(main.max(tower));
            debug_assert_eq!(self.cur_trace_cells, trace, "trace cost accounting drift");
            debug_assert_eq!(self.cur_main_peak, main, "main peak accounting drift");
            debug_assert_eq!(self.cur_tower_peak, tower, "tower peak accounting drift");
            debug_assert_eq!(self.cur_cells, recomputed, "shard cost accounting drift");
        }
    }

    #[cfg(not(any(test, debug_assertions)))]
    #[inline(always)]
    fn debug_assert_cost_invariant(&self) {}

    fn record_predicted_shard_cost(&mut self) {
        self.debug_assert_cost_invariant();
        tracing::debug!(
            shard_id = self.shard_id,
            predicted_cost = self.cur_cells,
            "finalized adaptive shard cost"
        );
        self.predicted_shard_costs.push(self.cur_cells);
    }

    fn padded_ecall_count(count: u64) -> u64 {
        if count <= 1 {
            count
        } else {
            count.checked_next_power_of_two().unwrap_or(u64::MAX)
        }
    }

    pub fn finalize(&mut self, max_cycle: Cycle) {
        assert!(
            !self.finalized,
            "shard plan cannot be finalized multiple times"
        );
        self.max_step_shard = self.max_step_shard.max(self.cur_step_count);
        self.record_predicted_shard_cost();
        self.cur_step_count = 0;
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

fn ecall_peak_cells(base_cells: u64, count: u64) -> u64 {
    base_cells.saturating_mul(ShardPlanBuilder::padded_ecall_count(count))
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
        let has_rs1 = rs1_read.is_some();
        let has_rs2 = rs2_read.is_some();
        let has_rd = rd.is_some();
        let has_memory_op = memory_op.is_some();
        StepRecord {
            cycle,
            pc,
            has_rs1,
            has_rs2,
            has_rd,
            has_memory_op,
            rs1: rs1_read
                .map(|rs1| ReadOp {
                    addr: Platform::register_vma(insn.rs1).into(),
                    value: rs1,
                    previous_cycle,
                })
                .unwrap_or_default(),
            rs2: rs2_read
                .map(|rs2| ReadOp {
                    addr: Platform::register_vma(insn.rs2).into(),
                    value: rs2,
                    previous_cycle,
                })
                .unwrap_or_default(),
            rd: rd
                .map(|rd| WriteOp {
                    addr: Platform::register_vma(insn.rd_internal() as RegIdx).into(),
                    value: rd,
                    previous_cycle,
                })
                .unwrap_or_default(),
            insn,
            memory_op: memory_op.unwrap_or_default(),
            syscall_index: StepRecord::NO_SYSCALL,
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
        if self.has_rs1 { Some(self.rs1) } else { None }
    }

    pub fn rs2(&self) -> Option<ReadOp> {
        if self.has_rs2 { Some(self.rs2) } else { None }
    }

    pub fn rd(&self) -> Option<WriteOp> {
        if self.has_rd { Some(self.rd) } else { None }
    }

    pub fn memory_op(&self) -> Option<WriteOp> {
        if self.has_memory_op {
            Some(self.memory_op)
        } else {
            None
        }
    }

    #[inline(always)]
    pub fn is_busy_loop(&self) -> bool {
        self.pc.before == self.pc.after
    }

    /// Returns true if this step has a syscall witness.
    pub fn has_syscall(&self) -> bool {
        self.syscall_index != Self::NO_SYSCALL
    }

    /// Look up the syscall witness from a separate store.
    /// The store is typically obtained from `FullTracer::syscall_witnesses()`.
    pub fn syscall<'a>(&self, store: &'a [SyscallWitness]) -> Option<&'a SyscallWitness> {
        if self.syscall_index == Self::NO_SYSCALL {
            None
        } else {
            Some(&store[self.syscall_index as usize])
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct FullTracerConfig {
    /// Maximum number of completed steps per shard. Internally, `FullTracer`
    /// reserves one extra slot to hold the pending (in-progress) record.
    pub max_step_shard: usize,
}

#[derive(Debug)]
pub struct FullTracer {
    records: Vec<StepRecord>,
    len: usize,
    pending_index: usize,
    pending_cycle: Cycle,

    /// Syscall witnesses stored separately (StepRecord references by index).
    syscall_witnesses: Vec<SyscallWitness>,

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

    pub fn new(platform: &Platform, config: FullTracerConfig) -> FullTracer {
        let mmio_max_access = init_mmio_min_max_access(platform);
        // Always reserve one extra slot for the pending/in-progress record. Without
        // this, a shard that executes exactly `max_step_shard` steps would panic
        // when `advance()` tries to reset the next (non-existent) slot.
        let capacity = config.max_step_shard.saturating_add(1);
        let mut records = if capacity > 0 {
            (0..capacity)
                .into_par_iter()
                .map(|_| StepRecord::default())
                .collect::<Vec<_>>()
        } else {
            Vec::new()
        };
        if records.is_empty() {
            records.push(StepRecord::default());
        }
        let mut tracer = FullTracer {
            records,
            len: 0,
            pending_index: 0,
            pending_cycle: Self::SUBCYCLES_PER_INSN,
            syscall_witnesses: Vec::new(),
            mmio_min_max_access: Some(mmio_max_access),
            platform: platform.clone(),
            latest_accesses: LatestAccesses::new(platform),
            max_heap_addr_access: ByteAddr::from(platform.heap.start),
            max_hint_addr_access: ByteAddr::from(platform.hints.start),
        };
        tracer.reset_pending_slot();
        tracer
    }

    /// Prepare the slot for the next step; panics if the preallocated capacity
    /// (from `FullTracerConfig::max_step_shard`) is exceeded.
    #[inline(always)]
    fn reset_pending_slot(&mut self) {
        if self.pending_index >= self.records.len() {
            if cfg!(debug_assertions) {
                // Allow unit/integration tests (which always build with debug assertions)
                // to auto-grow so they don't have to plumb accurate shard sizes.
                self.records.push(StepRecord::default());
            } else {
                panic!(
                    "FullTracer step buffer exhausted: recorded {} steps with capacity {}",
                    self.pending_index,
                    self.records.len()
                );
            }
        }
        self.records[self.pending_index] = StepRecord {
            cycle: self.pending_cycle,
            ..StepRecord::default()
        };
    }

    pub fn reset_step_buffer(&mut self) {
        self.len = 0;
        self.pending_index = 0;
        self.syscall_witnesses.clear();
        self.reset_pending_slot();
    }

    pub fn recorded_steps(&self) -> &[StepRecord] {
        &self.records[..self.len]
    }

    /// Returns the syscall witness store. Pass this to `StepRecord::syscall()`.
    #[inline(always)]
    pub fn syscall_witnesses(&self) -> &[SyscallWitness] {
        &self.syscall_witnesses
    }

    /// Take ownership of syscall witnesses, leaving an empty Vec for the next shard.
    /// Avoids the `to_vec()` clone when wrapping in `Arc`.
    pub fn take_syscall_witnesses(&mut self) -> Vec<SyscallWitness> {
        std::mem::take(&mut self.syscall_witnesses)
    }

    #[inline(always)]
    pub fn step_record(&self, index: StepIndex) -> &StepRecord {
        assert!(
            index < self.len,
            "step index {index} out of bounds {}",
            self.len
        );
        &self.records[index]
    }

    /// Return the completed step and advance to the next cycle.
    #[inline(always)]
    pub fn advance(&mut self) -> StepIndex {
        let idx = self.pending_index;
        let next_cycle = self.records[self.pending_index].cycle + Self::SUBCYCLES_PER_INSN;
        self.len = idx + 1;
        self.pending_cycle = next_cycle;
        self.pending_index += 1;
        self.reset_pending_slot();
        idx
    }

    #[inline(always)]
    pub fn store_pc(&mut self, pc: ByteAddr) {
        self.records[self.pending_index].pc.after = pc;
    }

    #[inline(always)]
    pub fn fetch(&mut self, pc: WordAddr, value: Instruction) {
        let record = &mut self.records[self.pending_index];
        record.pc.before = pc.baddr();
        record.insn = value;
    }

    #[inline(always)]
    pub fn track_mmu_maxtouch_before(&mut self) {
        let heap_access = self.max_heap_addr_access;
        let hint_access = self.max_hint_addr_access;
        let record = &mut self.records[self.pending_index];
        record.heap_maxtouch_addr.before = heap_access;
        record.hint_maxtouch_addr.before = hint_access;
    }

    #[inline(always)]
    pub fn track_mmu_maxtouch_after(&mut self) {
        let heap_access = self.max_heap_addr_access;
        let hint_access = self.max_hint_addr_access;
        let record = &mut self.records[self.pending_index];
        record.heap_maxtouch_addr.after = heap_access;
        record.hint_maxtouch_addr.after = hint_access;
    }

    #[inline(always)]
    pub fn load_register(&mut self, idx: RegIdx, value: Word) {
        let addr = Platform::register_vma(idx).into();
        if !self.records[self.pending_index].has_rs1 {
            let previous_cycle = self.track_access(addr, Self::SUBCYCLE_RS1);
            self.records[self.pending_index].rs1 = ReadOp {
                addr,
                value,
                previous_cycle,
            };
            self.records[self.pending_index].has_rs1 = true;
        } else if !self.records[self.pending_index].has_rs2 {
            let previous_cycle = self.track_access(addr, Self::SUBCYCLE_RS2);
            self.records[self.pending_index].rs2 = ReadOp {
                addr,
                value,
                previous_cycle,
            };
            self.records[self.pending_index].has_rs2 = true;
        } else {
            unimplemented!("Only two register reads are supported");
        }
    }

    #[inline(always)]
    pub fn store_register(&mut self, idx: RegIdx, value: Change<Word>) {
        if self.records[self.pending_index].has_rd {
            unimplemented!("Only one register write is supported");
        }

        let addr = Platform::register_vma(idx).into();
        let previous_cycle = self.track_access(addr, Self::SUBCYCLE_RD);
        self.records[self.pending_index].rd = WriteOp {
            addr,
            value,
            previous_cycle,
        };
        self.records[self.pending_index].has_rd = true;
    }

    #[inline(always)]
    pub fn load_memory(&mut self, addr: WordAddr, value: Word) {
        self.store_memory(addr, Change::new(value, value));
    }

    #[inline(always)]
    pub fn store_memory(&mut self, addr: WordAddr, value: Change<Word>) {
        if self.records[self.pending_index].has_memory_op {
            unimplemented!("Only one memory access is supported");
        }

        // Update the tracked min/max MMIO bounds so later phases only materialize
        // the actually touched address range for heap / hint regions.
        if let Some((start_addr, (_, end_addr, min_addr, max_addr))) = self
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

        let previous_cycle = self.track_access(addr, Self::SUBCYCLE_MEM);
        self.records[self.pending_index].memory_op = WriteOp {
            addr,
            value,
            previous_cycle,
        };
        self.records[self.pending_index].has_memory_op = true;
    }

    #[inline(always)]
    pub fn track_syscall(&mut self, effects: SyscallEffects) {
        let witness = effects.finalize(self);
        let record = &mut self.records[self.pending_index];
        assert!(
            record.syscall_index == StepRecord::NO_SYSCALL,
            "Only one syscall per step"
        );
        let idx = self.syscall_witnesses.len();
        self.syscall_witnesses.push(witness);
        record.syscall_index = idx as u32;
    }

    #[inline(always)]
    pub fn track_access(&mut self, addr: WordAddr, subcycle: Cycle) -> Cycle {
        // Returns the previous access cycle. Accesses within the same instruction
        // are distinguished via `subcycle ∈ [0, 3]`; the first touch of an address
        // yields `0`.
        let cur_cycle = self.records[self.pending_index].cycle + subcycle;
        self.latest_accesses.track(addr, cur_cycle)
    }

    pub fn final_accesses(&self) -> &LatestAccesses {
        &self.latest_accesses
    }

    pub fn cycle(&self) -> Cycle {
        self.pending_cycle
    }

    /// Number of executed instructions so far (discounting the init slot that
    /// starts at `SUBCYCLES_PER_INSN`).
    pub fn executed_insts(&self) -> usize {
        (self.pending_cycle / Self::SUBCYCLES_PER_INSN)
            .saturating_sub(1)
            .try_into()
            .unwrap()
    }

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
    planner: Option<ShardPlanBuilder>,
    current_shard_start_cycle: Cycle,
    config: PreflightTracerConfig,
}

#[cfg_attr(
    not(all(feature = "aot-x86_64", target_arch = "x86_64", target_os = "linux")),
    allow(dead_code)
)]
pub(crate) const NATIVE_TRACE_READ_RS1: u32 = 1 << 0;
#[cfg_attr(
    not(all(feature = "aot-x86_64", target_arch = "x86_64", target_os = "linux")),
    allow(dead_code)
)]
pub(crate) const NATIVE_TRACE_READ_RS2: u32 = 1 << 1;
#[cfg_attr(
    not(all(feature = "aot-x86_64", target_arch = "x86_64", target_os = "linux")),
    allow(dead_code)
)]
pub(crate) const NATIVE_TRACE_WRITE_RD: u32 = 1 << 2;
#[cfg_attr(
    not(all(feature = "aot-x86_64", target_arch = "x86_64", target_os = "linux")),
    allow(dead_code)
)]
pub(crate) const NATIVE_TRACE_LOAD_MEM: u32 = 1 << 3;
#[cfg_attr(
    not(all(feature = "aot-x86_64", target_arch = "x86_64", target_os = "linux")),
    allow(dead_code)
)]
pub(crate) const NATIVE_TRACE_STORE_MEM: u32 = 1 << 4;

#[cfg_attr(
    not(all(feature = "aot-x86_64", target_arch = "x86_64", target_os = "linux")),
    allow(dead_code)
)]
pub(crate) struct NativeTraceStep {
    pub pc_before: ByteAddr,
    pub pc_after: ByteAddr,
    pub kind: InsnKind,
    pub flags: u32,
    pub rs1_idx: RegIdx,
    pub rs2_idx: RegIdx,
    pub rd_idx: RegIdx,
    pub memory_addr: WordAddr,
}

#[cfg_attr(
    not(all(feature = "aot-x86_64", target_arch = "x86_64", target_os = "linux")),
    allow(dead_code)
)]
pub(crate) struct PreflightNativeTraceState {
    pub latest_cells: *mut Cycle,
    pub latest_base: WordAddr,
    pub cycle: *mut Cycle,
    pub pc_before: *mut ByteAddr,
    pub pc_after: *mut ByteAddr,
    pub last_kind: *mut InsnKind,
    pub current_shard_start_cycle: *const Cycle,
    pub planner_cur_cells: *mut u64,
    pub planner_cur_trace_cells: *mut u64,
    pub planner_cur_main_peak: *mut u64,
    pub planner_cur_tower_peak: *mut u64,
    pub planner_cur_cycle_in_shard: *mut Cycle,
    pub planner_cur_step_count: *mut usize,
    pub planner_max_step_shard: *mut usize,
    pub planner_shard_id: *mut usize,
    pub planner_max_cell_per_shard: u64,
    pub planner_target_cell_first_shard: u64,
    pub planner_max_cycle_per_shard: Cycle,
    pub planner_num_instances: *mut u64,
    pub planner_num_chips: usize,
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
            .field("planner", &self.planner)
            .field("current_shard_start_cycle", &self.current_shard_start_cycle)
            .field("config", &self.config)
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

    pub fn new(platform: &Platform, config: PreflightTracerConfig) -> Self {
        let mut planner_cycle_limit = config.max_cycle_per_shard();
        if planner_cycle_limit != Cycle::MAX {
            // Observe-step already accounts for the current instruction, so shrink the
            // limit by one instruction to keep shard boundaries aligned with callers.
            planner_cycle_limit = planner_cycle_limit.saturating_sub(Self::SUBCYCLES_PER_INSN);
        }
        let max_cell_per_shard = config.max_cell_per_shard();
        let cost_model = config
            .step_cell_extractor
            .as_ref()
            .and_then(|extractor| extractor.shard_cost_model());
        let mut tracer = PreflightTracer {
            cycle: <Self as Tracer>::SUBCYCLES_PER_INSN,
            pc: Default::default(),
            last_kind: InsnKind::INVALID,
            last_rs1: None,
            mmio_min_max_access: Some(init_mmio_min_max_access(platform)),
            latest_accesses: LatestAccesses::new(platform),
            next_accesses: FxHashMap::default(),
            register_reads_tracked: 0,
            planner: Some(ShardPlanBuilder::new_with_cost_model(
                max_cell_per_shard,
                planner_cycle_limit,
                cost_model,
            )),
            current_shard_start_cycle: <Self as Tracer>::SUBCYCLES_PER_INSN,
            config,
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

    #[cfg_attr(
        not(all(feature = "aot-x86_64", target_arch = "x86_64", target_os = "linux")),
        allow(dead_code)
    )]
    pub(crate) fn supports_direct_native_trace(&self) -> bool {
        self.planner.is_some()
    }

    #[cfg_attr(
        not(all(feature = "aot-x86_64", target_arch = "x86_64", target_os = "linux")),
        allow(dead_code)
    )]
    pub(crate) fn native_trace_state(&mut self) -> PreflightNativeTraceState {
        debug_assert!(self.supports_direct_native_trace());
        let planner = self.planner.as_mut().expect("shard planner missing");
        let planner_num_chips = planner
            .cost_model
            .as_ref()
            .map_or(0, |model| model.chip_count());
        PreflightNativeTraceState {
            latest_cells: self.latest_accesses.cells_mut_ptr(),
            latest_base: self.latest_accesses.base(),
            cycle: &mut self.cycle,
            pc_before: &mut self.pc.before,
            pc_after: &mut self.pc.after,
            last_kind: &mut self.last_kind,
            current_shard_start_cycle: &self.current_shard_start_cycle,
            planner_cur_cells: &mut planner.cur_cells,
            planner_cur_trace_cells: &mut planner.cur_trace_cells,
            planner_cur_main_peak: &mut planner.cur_main_peak,
            planner_cur_tower_peak: &mut planner.cur_tower_peak,
            planner_cur_cycle_in_shard: &mut planner.cur_cycle_in_shard,
            planner_cur_step_count: &mut planner.cur_step_count,
            planner_max_step_shard: &mut planner.max_step_shard,
            planner_shard_id: &mut planner.shard_id,
            planner_max_cell_per_shard: planner.max_cell_per_shard,
            planner_target_cell_first_shard: planner.target_cell_first_shard,
            planner_max_cycle_per_shard: planner.max_cycle_per_shard,
            planner_num_instances: planner.num_instances.as_mut_ptr(),
            planner_num_chips,
        }
    }

    #[cfg_attr(
        not(all(feature = "aot-x86_64", target_arch = "x86_64", target_os = "linux")),
        allow(dead_code)
    )]
    pub(crate) fn native_step_cells_for_kind(&self, kind: InsnKind) -> u64 {
        self.config
            .step_cell_extractor
            .as_ref()
            .map(|extractor| extractor.cells_for_kind(kind, None))
            .unwrap_or(0)
    }

    #[cfg_attr(
        not(all(feature = "aot-x86_64", target_arch = "x86_64", target_os = "linux")),
        allow(dead_code)
    )]
    pub(crate) fn shard_cost_model(&self) -> Option<Arc<ShardCostModel>> {
        self.planner
            .as_ref()
            .and_then(|planner| planner.cost_model.clone())
    }

    #[inline(always)]
    fn observe_current_step(&mut self, ecall_code: Option<Word>) {
        if let Some(planner) = self.planner.as_mut() {
            if planner.cost_model.is_some() {
                planner.observe_modeled_step(self.cycle, self.last_kind, ecall_code);
                self.current_shard_start_cycle = planner.current_shard_start_cycle();
                return;
            }
            let step_cells = self
                .config
                .step_cell_extractor
                .as_ref()
                .map(|extractor| extractor.cells_for_kind(self.last_kind, ecall_code))
                .unwrap_or(0);
            if let Some(ecall_code) = ecall_code {
                planner.observe_ecall_step(self.cycle, ecall_code, step_cells);
            } else {
                planner.observe_step(self.cycle, step_cells);
            }
            self.current_shard_start_cycle = planner.current_shard_start_cycle();
        }
    }

    #[cfg_attr(
        not(all(feature = "aot-x86_64", target_arch = "x86_64", target_os = "linux")),
        allow(dead_code)
    )]
    pub(crate) fn native_mmio_bound_ptrs(
        &mut self,
        start_addr: WordAddr,
    ) -> (*mut WordAddr, *mut WordAddr) {
        let Some((_, _, min_addr, max_addr)) = self
            .mmio_min_max_access
            .as_mut()
            .and_then(|mmio_max_access| mmio_max_access.get_mut(&start_addr))
        else {
            return (std::ptr::null_mut(), std::ptr::null_mut());
        };
        (min_addr as *mut WordAddr, max_addr as *mut WordAddr)
    }

    #[cfg_attr(
        not(all(feature = "aot-x86_64", target_arch = "x86_64", target_os = "linux")),
        allow(dead_code)
    )]
    pub(crate) fn record_native_access_side_effects(
        &mut self,
        addr: WordAddr,
        prev_cycle: Cycle,
        cur_cycle: Cycle,
    ) {
        if prev_cycle == Cycle::default() {
            self.latest_accesses.record_native_first_touch(addr);
        }
        if self.config.record_next_accesses && prev_cycle < self.current_shard_start_cycle {
            self.next_accesses
                .entry(prev_cycle)
                .or_default()
                .push((addr, cur_cycle));
        }
    }

    #[cfg_attr(
        not(all(feature = "aot-x86_64", target_arch = "x86_64", target_os = "linux")),
        allow(dead_code)
    )]
    pub(crate) fn observe_native_steps(&mut self, steps: u64) {
        debug_assert!(self.supports_direct_native_trace());
        let _ = steps;
    }

    #[cfg_attr(
        not(all(feature = "aot-x86_64", target_arch = "x86_64", target_os = "linux")),
        allow(dead_code)
    )]
    pub(crate) fn record_native_shard_split(&mut self) {
        let planner = self.planner.as_mut().expect("shard planner missing");
        let next_shard_cycle = self.cycle;
        planner.record_predicted_shard_cost();
        planner.push_boundary(next_shard_cycle);
        planner.shard_id += 1;
        planner.current_shard_start_cycle = next_shard_cycle;
        planner.max_step_shard = planner.max_step_shard.max(planner.cur_step_count);
        planner.cur_cells = 0;
        planner.reset_after_native_shard_split();
        planner.cur_cycle_in_shard = 0;
        planner.cur_step_count = 0;
        self.current_shard_start_cycle = next_shard_cycle;
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

    #[cfg_attr(
        not(all(feature = "aot-x86_64", target_arch = "x86_64", target_os = "linux")),
        allow(dead_code)
    )]
    pub(crate) fn trace_native_step(&mut self, step: NativeTraceStep) -> bool {
        self.pc.before = step.pc_before;
        self.last_kind = step.kind;
        self.last_rs1 = None;
        debug_assert!(!matches!(step.kind, InsnKind::ECALL));
        self.observe_current_step(None);

        if step.flags & NATIVE_TRACE_READ_RS1 != 0 {
            self.track_access(
                Platform::register_vma(step.rs1_idx).into(),
                Self::SUBCYCLE_RS1,
            );
        }
        if step.flags & NATIVE_TRACE_READ_RS2 != 0 {
            self.track_access(
                Platform::register_vma(step.rs2_idx).into(),
                Self::SUBCYCLE_RS2,
            );
        }
        if step.flags & NATIVE_TRACE_WRITE_RD != 0 {
            self.track_access(
                Platform::register_vma(step.rd_idx).into(),
                Self::SUBCYCLE_RD,
            );
        }
        if step.flags & NATIVE_TRACE_LOAD_MEM != 0 {
            self.track_access(step.memory_addr, Self::SUBCYCLE_MEM);
        } else if step.flags & NATIVE_TRACE_STORE_MEM != 0 {
            self.update_mmio_bounds(step.memory_addr);
            self.track_access(step.memory_addr, Self::SUBCYCLE_MEM);
        }

        self.pc.after = step.pc_after;
        self.advance();
        step.pc_before == step.pc_after
    }
}

impl Tracer for PreflightTracer {
    type Record = ();
    type Config = PreflightTracerConfig;

    fn new(platform: &Platform, config: Self::Config) -> Self {
        PreflightTracer::new(platform, config)
    }

    #[inline(always)]
    fn advance(&mut self) -> Self::Record {
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
        if !matches!(value.kind, InsnKind::ECALL) {
            self.observe_current_step(None);
        }
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
            self.observe_current_step(Some(value));
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
        if self.config.record_next_accesses && prev_cycle < self.current_shard_start_cycle {
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
    type Record = StepIndex;
    type Config = FullTracerConfig;

    fn new(platform: &Platform, config: Self::Config) -> Self {
        FullTracer::new(platform, config)
    }

    #[inline(always)]
    fn advance(&mut self) -> Self::Record {
        FullTracer::advance(self)
    }

    #[inline(always)]
    fn is_busy_loop(&self, record: &Self::Record) -> bool {
        self.step_record(*record).is_busy_loop()
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
#[repr(C)]
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

#[cfg(test)]
mod tests {
    use super::*;

    fn cost_model(specs: Vec<ChipCostSpec>) -> Arc<ShardCostModel> {
        let mut opcodes = vec![Vec::new(); InsnKind::COUNT];
        opcodes[InsnKind::ADD as usize] = vec![0];
        let mut ecalls = BTreeMap::new();
        ecalls.insert(7, vec![0]);
        Arc::new(ShardCostModel::new(opcodes, ecalls, specs, 4))
    }

    #[test]
    fn shard_cost_model_padding_rotation_and_extension_degree() {
        let model = cost_model(vec![ChipCostSpec {
            rotation: 1,
            trace_cells_per_row: 2,
            tower_peak_cells_per_row: 3,
            tower_peak_cells_by_bucket: None,
        }]);
        assert_eq!(model.extension_field_degree(), 4);
        assert_eq!(model.chip_cost(0, 0), ChipCost::default());
        assert_eq!(model.shard_cost(&[1]), 12);
        assert_eq!(model.shard_cost(&[2]), 24);
        assert_eq!(model.shard_cost(&[3]), 48);
        assert_eq!(model.shard_cost(&[4]), 48);
        assert_eq!(model.shard_cost(&[5]), 96);
    }

    #[test]
    fn shard_cost_model_selects_tower_or_main_peak() {
        let model = cost_model(vec![
            ChipCostSpec {
                rotation: 0,
                trace_cells_per_row: 2,
                tower_peak_cells_per_row: 9,
                tower_peak_cells_by_bucket: None,
            },
            ChipCostSpec {
                rotation: 0,
                trace_cells_per_row: 2,
                tower_peak_cells_per_row: 1,
                tower_peak_cells_by_bucket: None,
            },
        ]);
        assert_eq!(model.shard_cost(&[1, 0]), 11);
        assert_eq!(model.shard_cost(&[0, 1]), 6);
        // Trace and main coexist across chips, while tower is the dominant
        // single-chip task rather than the sum of both tower peaks.
        assert_eq!(model.shard_cost(&[1, 1]), 13);

        let main_dominant = cost_model(vec![
            ChipCostSpec {
                rotation: 0,
                trace_cells_per_row: 0,
                tower_peak_cells_per_row: 5,
                tower_peak_cells_by_bucket: None,
            },
            ChipCostSpec {
                rotation: 0,
                trace_cells_per_row: 0,
                tower_peak_cells_per_row: 5,
                tower_peak_cells_by_bucket: None,
            },
        ]);
        assert_eq!(main_dominant.shard_cost(&[1, 1]), 8);
    }

    #[test]
    fn shard_cost_model_uses_scheduler_tower_bucket_table() {
        let mut tower = vec![0; SHARD_COST_BUCKETS];
        tower[1] = 7;
        tower[2] = 11;
        tower[3] = 29;
        let model = cost_model(vec![ChipCostSpec {
            rotation: 0,
            trace_cells_per_row: 0,
            tower_peak_cells_per_row: u64::MAX,
            tower_peak_cells_by_bucket: Some(tower),
        }]);
        assert_eq!(model.shard_cost(&[1]), 7);
        assert_eq!(model.shard_cost(&[2]), 11);
        assert_eq!(model.shard_cost(&[3]), 29);
        assert_eq!(model.shard_cost(&[4]), 29);
    }

    #[test]
    fn modeled_native_and_ecall_steps_share_chip_counts() {
        let model = cost_model(vec![ChipCostSpec {
            rotation: 0,
            trace_cells_per_row: 1,
            tower_peak_cells_per_row: 1,
            tower_peak_cells_by_bucket: None,
        }]);
        let mut planner = ShardPlanBuilder::new_with_cost_model(100, Cycle::MAX, Some(model));
        planner.observe_modeled_step(4, InsnKind::ADD, None);
        planner.observe_modeled_step(8, InsnKind::ECALL, Some(7));
        assert_eq!(planner.num_instances, vec![2]);
        assert_eq!(planner.cur_cells(), 10);
    }

    #[derive(Debug)]
    struct OneCellPerStep;

    impl StepCellExtractor for OneCellPerStep {
        fn cells_for_kind(&self, _kind: InsnKind, _rs1_value: Option<Word>) -> u64 {
            1
        }
    }

    #[test]
    fn preflight_splits_before_tracking_current_step_accesses() {
        let config = PreflightTracerConfig::new(true, 1, Cycle::MAX)
            .with_step_cell_extractor(Arc::new(OneCellPerStep));
        let mut tracer = PreflightTracer::new(&CENO_PLATFORM, config);
        let insn = Instruction {
            kind: InsnKind::ADDI,
            ..Default::default()
        };

        tracer.fetch(0u32.into(), insn);
        tracer.load_register(1, 0);
        tracer.advance();

        tracer.fetch(WordAddr::from(PC_STEP_SIZE as u32), insn);
        tracer.load_register(1, 0);

        assert_eq!(
            tracer.planner.as_ref().unwrap().shard_cycle_boundaries(),
            &[PreflightTracer::SUBCYCLES_PER_INSN, 8]
        );
        assert_eq!(
            tracer.next_accesses.get(&4).map(SmallVec::as_slice),
            Some(&[(Platform::register_vma(1).into(), 8)][..])
        );
    }

    #[test]
    fn test_step_record_is_copy_and_compact() {
        // Verify StepRecord is Copy (this compiles only if Copy is implemented)
        fn assert_copy<T: Copy>() {}
        assert_copy::<StepRecord>();

        // Verify repr(C) compactness — should be well under 128 bytes
        let size = std::mem::size_of::<StepRecord>();
        eprintln!("StepRecord size: {} bytes", size);
        assert!(
            size <= 144,
            "StepRecord should be compact for GPU transfer: got {} bytes",
            size
        );
    }

    #[test]
    fn test_supporting_types_are_copy() {
        fn assert_copy<T: Copy>() {}
        assert_copy::<ReadOp>();
        assert_copy::<WriteOp>();
        assert_copy::<Change<Word>>();
        assert_copy::<Change<ByteAddr>>();
    }

    /// Verify exact byte offsets of StepRecord fields for CUDA struct alignment.
    /// If this test fails, the CUDA step_record.cuh header must be updated to match.
    #[test]
    fn test_step_record_layout_for_gpu() {
        use std::mem;

        macro_rules! offset_of {
            ($type:ty, $field:ident) => {{
                let val = <$type>::default();
                let base = &val as *const _ as usize;
                let field = &val.$field as *const _ as usize;
                field - base
            }};
        }

        // Sub-type sizes
        assert_eq!(mem::size_of::<Instruction>(), 12, "Instruction size");
        assert_eq!(mem::size_of::<ReadOp>(), 16, "ReadOp size");
        assert_eq!(mem::size_of::<WriteOp>(), 24, "WriteOp size");
        assert_eq!(
            mem::size_of::<Change<ByteAddr>>(),
            8,
            "Change<ByteAddr> size"
        );

        // StepRecord field offsets — these must match step_record.cuh
        assert_eq!(offset_of!(StepRecord, cycle), 0);
        assert_eq!(offset_of!(StepRecord, pc), 8);
        assert_eq!(offset_of!(StepRecord, heap_maxtouch_addr), 16);
        assert_eq!(offset_of!(StepRecord, hint_maxtouch_addr), 24);
        assert_eq!(offset_of!(StepRecord, insn), 32);
        assert_eq!(offset_of!(StepRecord, has_rs1), 44);
        assert_eq!(offset_of!(StepRecord, has_rs2), 45);
        assert_eq!(offset_of!(StepRecord, has_rd), 46);
        assert_eq!(offset_of!(StepRecord, has_memory_op), 47);
        assert_eq!(offset_of!(StepRecord, rs1), 48);
        assert_eq!(offset_of!(StepRecord, rs2), 64);
        assert_eq!(offset_of!(StepRecord, rd), 80);
        assert_eq!(offset_of!(StepRecord, memory_op), 104);
        assert_eq!(offset_of!(StepRecord, syscall_index), 128);

        // Total size
        assert_eq!(mem::size_of::<StepRecord>(), 136, "StepRecord total size");
        assert_eq!(mem::align_of::<StepRecord>(), 8, "StepRecord alignment");

        // InsnKind must be repr(u8) for CUDA compatibility
        assert_eq!(
            mem::size_of::<InsnKind>(),
            1,
            "InsnKind must be 1 byte (repr(u8))"
        );

        eprintln!(
            "StepRecord layout verified: {} bytes, {} align",
            mem::size_of::<StepRecord>(),
            mem::align_of::<StepRecord>()
        );
    }

    #[test]
    fn ecall_peak_cells_is_monotonic_and_padded() {
        let base = 7;
        let mut prev = 0;
        for count in 0..10_000 {
            let peak = ecall_peak_cells(base, count);
            assert!(peak >= prev);
            prev = peak;
        }

        assert_eq!(ecall_peak_cells(base, 0), 0);
        assert_eq!(ecall_peak_cells(base, 1), base);
        assert_eq!(ecall_peak_cells(base, 2), base * 2);
        assert_eq!(ecall_peak_cells(base, 3), base * 4);
        assert_eq!(ecall_peak_cells(base, 8192), base * 8192);
        assert_eq!(ecall_peak_cells(base, 8193), base * 16384);
    }

    #[test]
    fn ecall_boundary_crossing_charges_padded_bucket_delta() {
        let code = 0x1234;
        let base = 7;
        let mut planner = ShardPlanBuilder::new(u64::MAX, Cycle::MAX);
        for i in 0..8192 {
            planner.observe_ecall_step(FullTracer::SUBCYCLES_PER_INSN * (i + 1), code, base);
        }

        assert_eq!(planner.ecall_count(code), 8192);
        assert_eq!(planner.ecall_peak_cells(code), base * 8192);
        assert_eq!(planner.ecall_delta_for(code, base), base * 8192);
    }

    #[test]
    fn ecall_over_budget_step_splits_before_adding_step() {
        let code = 0x1234;
        let base = 1;
        let mut planner = ShardPlanBuilder::new(10, Cycle::MAX);
        for i in 0..8 {
            planner.observe_ecall_step(FullTracer::SUBCYCLES_PER_INSN * (i + 1), code, base);
        }
        planner.observe_ecall_step(FullTracer::SUBCYCLES_PER_INSN * 9, code, base);

        assert_eq!(
            planner.shard_cycle_boundaries(),
            &[FullTracer::SUBCYCLES_PER_INSN, 36]
        );
        assert_eq!(planner.current_shard_id(), 1);
        assert_eq!(planner.cur_step_count(), 1);
        assert_eq!(planner.ecall_count(code), 1);
        assert_eq!(planner.cur_cells(), base);
    }

    #[test]
    fn repeated_non_keccak_ecall_splits_at_padded_bucket_boundary() {
        let code = 0x5678;
        let base = 2;
        let mut planner = ShardPlanBuilder::new(base * 8192, Cycle::MAX);
        for i in 0..8192 {
            planner.observe_ecall_step(FullTracer::SUBCYCLES_PER_INSN * (i + 1), code, base);
        }
        planner.observe_ecall_step(FullTracer::SUBCYCLES_PER_INSN * 8193, code, base);

        assert_eq!(
            planner.shard_cycle_boundaries(),
            &[
                FullTracer::SUBCYCLES_PER_INSN,
                FullTracer::SUBCYCLES_PER_INSN * 8193
            ]
        );
        assert_eq!(planner.ecall_count(code), 1);
        assert_eq!(planner.cur_cells(), base);
    }
}
