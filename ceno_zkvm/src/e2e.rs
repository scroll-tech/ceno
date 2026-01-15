use crate::{
    error::ZKVMError,
    instructions::riscv::{
        DummyExtraConfig, InstructionDispatchBuilder, MemPadder, MmuConfig, Rv32imConfig,
    },
    scheme::{
        PublicValues, ZKVMProof,
        constants::SEPTIC_EXTENSION_DEGREE,
        hal::ProverDevice,
        mock_prover::{LkMultiplicityKey, MockProver},
        prover::ZKVMProver,
        septic_curve::SepticPoint,
        verifier::ZKVMVerifier,
    },
    state::GlobalState,
    structs::{
        ProgramParams, ZKVMConstraintSystem, ZKVMFixedTraces, ZKVMProvingKey, ZKVMVerifyingKey,
        ZKVMWitnesses,
    },
    tables::{
        MemFinalRecord, MemInitRecord, ProgramTableCircuit, ProgramTableConfig, ShardRamCircuit,
        TableCircuit,
    },
};
use ceno_emul::{
    Addr, ByteAddr, CENO_PLATFORM, Cycle, EmptyTracer, EmuContext, FullTracer, InsnKind,
    IterAddresses, NextCycleAccess, Platform, PreflightTracer, PreflightTracerConfig, Program,
    StepRecord, Tracer, VM_REG_COUNT, VMState, WORD_SIZE, Word, WordAddr,
    host_utils::read_all_messages,
};
use clap::ValueEnum;
use either::Either;
use ff_ext::{ExtensionField, SmallField};
#[cfg(debug_assertions)]
use ff_ext::{Instrumented, PoseidonField};
use gkr_iop::{RAMType, hal::ProverBackend};
#[cfg(debug_assertions)]
use itertools::MinMaxResult;
use itertools::{Itertools, chain};
use mpcs::{PolynomialCommitmentScheme, SecurityLevel};
use multilinear_extensions::util::max_usable_threads;
use rustc_hash::FxHashSet;
use serde::Serialize;
#[cfg(debug_assertions)]
use std::collections::{HashMap, HashSet};
use std::{
    collections::{BTreeMap, BTreeSet},
    marker::PhantomData,
    ops::Range,
    sync::Arc,
};
use tracing::info_span;
use transcript::BasicTranscript as Transcript;
use witness::next_pow2_instance_padding;

// default value: 16GB VRAM, each cell 4 byte, log explosion 2
pub const DEFAULT_MAX_CELLS_PER_SHARDS: u64 = (1 << 30) * 16 / 4 / 2;
pub const DEFAULT_MAX_CYCLE_PER_SHARDS: Cycle = 1 << 29;
pub const DEFAULT_CROSS_SHARD_ACCESS_LIMIT: usize = 1 << 20;
// define a relative small number to make first shard handle much less instruction
pub const DEFAULT_MAX_CELL_FIRST_SHARD: u64 = 1 << 20;

/// The polynomial commitment scheme kind
#[derive(
    Default,
    Copy,
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    ValueEnum,
    strum_macros::AsRefStr,
    strum_macros::Display,
    strum_macros::IntoStaticStr,
)]
pub enum PcsKind {
    #[default]
    Basefold,
    Whir,
}

/// The field type
#[derive(
    Default,
    Copy,
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    ValueEnum,
    strum_macros::AsRefStr,
    strum_macros::Display,
    strum_macros::IntoStaticStr,
)]
pub enum FieldType {
    #[default]
    BabyBear,
    Goldilocks,
}

#[derive(Clone)]
pub struct FullMemState<Record> {
    pub mem: Vec<Record>,
    pub io: Vec<Record>,
    pub reg: Vec<Record>,
    pub hints: Vec<Record>,
    pub stack: Vec<Record>,
    pub heap: Vec<Record>,
}

pub(crate) type InitMemState = FullMemState<MemInitRecord>;
type FinalMemState = FullMemState<MemFinalRecord>;

pub struct EmulationResult<'a> {
    pub exit_code: Option<u32>,
    pub final_mem_state: FinalMemState,
    pub pi: PublicValues,
    pub shard_ctx_builder: ShardContextBuilder,
    pub shard_cycle_boundaries: Arc<Vec<Cycle>>,
    pub executed_steps: usize,
    pub phantom: PhantomData<&'a ()>,
    // pub shard_ctxs: Vec<ShardContext<'a>>,
}

pub struct RAMRecord {
    pub ram_type: RAMType,
    // reg_id is the raw id of register, e.g. in riv32 it's range from [0, 32)
    // meaningful when RAMType::Register
    pub reg_id: u64,
    pub addr: WordAddr,
    // prev_cycle and cycle are global cycle
    pub prev_cycle: Cycle,
    pub cycle: Cycle,
    // shard_cycle is cycle in current local shard, which already offset by start cycle
    pub shard_cycle: Cycle,
    pub prev_value: Option<Word>,
    pub value: Word,
    // for global reads, `shard_id` refers to the shard that previously produced this value.
    // for global write, `shard_id` refers to current shard.
    pub shard_id: usize,
}

#[derive(Clone, Debug)]
pub struct MultiProver {
    pub prover_id: usize,
    pub max_provers: usize,
    pub max_cell_per_shard: u64,
    pub max_cycle_per_shard: Cycle,
}

impl MultiProver {
    pub fn new(
        prover_id: usize,
        max_provers: usize,
        max_cell_per_shard: u64,
        max_cycle_per_shard: Cycle,
    ) -> Self {
        assert!(prover_id < max_provers);
        Self {
            prover_id,
            max_provers,
            max_cell_per_shard,
            max_cycle_per_shard,
        }
    }
}

impl Default for MultiProver {
    fn default() -> Self {
        Self {
            prover_id: 0,
            max_provers: 1,
            max_cell_per_shard: u64::MAX,
            max_cycle_per_shard: DEFAULT_MAX_CYCLE_PER_SHARDS,
        }
    }
}

pub struct ShardContext<'a> {
    pub shard_id: usize,
    num_shards: usize,
    max_cycle: Cycle,
    pub addr_future_accesses: Arc<NextCycleAccess>,
    addr_accessed_tbs: Either<Vec<Vec<WordAddr>>, &'a mut Vec<WordAddr>>,
    read_records_tbs:
        Either<Vec<BTreeMap<WordAddr, RAMRecord>>, &'a mut BTreeMap<WordAddr, RAMRecord>>,
    write_records_tbs:
        Either<Vec<BTreeMap<WordAddr, RAMRecord>>, &'a mut BTreeMap<WordAddr, RAMRecord>>,
    pub cur_shard_cycle_range: std::ops::Range<usize>,
    pub expected_inst_per_shard: usize,
    pub max_num_cross_shard_accesses: usize,
    // shard 0: [v[0], v[1]), shard 1: [v[1], v[2]), shard 2: [v[2], v[3])
    pub prev_shard_cycle_range: Vec<Cycle>,
    pub prev_shard_heap_range: Vec<Addr>,
    pub prev_shard_hint_range: Vec<Addr>,
    pub platform: Platform,
    pub shard_heap_addr_range: Range<Addr>,
    pub shard_hint_addr_range: Range<Addr>,
}

impl<'a> Default for ShardContext<'a> {
    fn default() -> Self {
        let max_threads = max_usable_threads();
        let max_num_cross_shard_accesses = std::env::var("CENO_CROSS_SHARD_LIMIT")
            .map(|v| v.parse().unwrap_or(DEFAULT_CROSS_SHARD_ACCESS_LIMIT))
            .unwrap_or(DEFAULT_CROSS_SHARD_ACCESS_LIMIT);

        Self {
            shard_id: 0,
            num_shards: 1,
            max_cycle: Cycle::MAX,
            addr_future_accesses: Arc::new(Default::default()),
            addr_accessed_tbs: Either::Left(vec![Vec::new(); max_threads]),
            read_records_tbs: Either::Left(
                (0..max_threads)
                    .map(|_| BTreeMap::new())
                    .collect::<Vec<_>>(),
            ),
            write_records_tbs: Either::Left(
                (0..max_threads)
                    .map(|_| BTreeMap::new())
                    .collect::<Vec<_>>(),
            ),
            cur_shard_cycle_range: FullTracer::SUBCYCLES_PER_INSN as usize..usize::MAX,
            expected_inst_per_shard: usize::MAX,
            max_num_cross_shard_accesses,
            prev_shard_cycle_range: vec![],
            prev_shard_heap_range: vec![],
            prev_shard_hint_range: vec![],
            platform: CENO_PLATFORM.clone(),
            shard_heap_addr_range: CENO_PLATFORM.heap.clone(),
            shard_hint_addr_range: CENO_PLATFORM.hints.clone(),
        }
    }
}

/// `prover_id` and `num_provers` in MultiProver are exposed as arguments
/// to specify the number of physical provers in a cluster,
/// each mark with a prover_id.
/// The overall trace data is divided into shards, which are distributed evenly among the provers.
/// The number of shards are in general agnostic to number of provers.
/// Each prover is assigned n shard where n can be even empty
///
/// Shard distribution follows a balanced allocation strategy
/// for example, if there are 10 shards and 3 provers,
/// the shard counts will be distributed as 3, 3, and 4, ensuring an even workload across all provers.
impl<'a> ShardContext<'a> {
    pub fn get_forked(&mut self) -> Vec<ShardContext<'_>> {
        match (
            &mut self.read_records_tbs,
            &mut self.write_records_tbs,
            &mut self.addr_accessed_tbs,
        ) {
            (
                Either::Left(read_thread_based_record_storage),
                Either::Left(write_thread_based_record_storage),
                Either::Left(addr_accessed_tbs),
            ) => read_thread_based_record_storage
                .iter_mut()
                .zip(write_thread_based_record_storage.iter_mut())
                .zip(addr_accessed_tbs.iter_mut())
                .map(|((read, write), addr_accessed_tbs)| ShardContext {
                    shard_id: self.shard_id,
                    num_shards: self.num_shards,
                    max_cycle: self.max_cycle,
                    addr_future_accesses: self.addr_future_accesses.clone(),
                    addr_accessed_tbs: Either::Right(addr_accessed_tbs),
                    read_records_tbs: Either::Right(read),
                    write_records_tbs: Either::Right(write),
                    cur_shard_cycle_range: self.cur_shard_cycle_range.clone(),
                    expected_inst_per_shard: self.expected_inst_per_shard,
                    max_num_cross_shard_accesses: self.max_num_cross_shard_accesses,
                    prev_shard_cycle_range: self.prev_shard_cycle_range.clone(),
                    prev_shard_heap_range: self.prev_shard_heap_range.clone(),
                    prev_shard_hint_range: self.prev_shard_hint_range.clone(),
                    platform: self.platform.clone(),
                    shard_heap_addr_range: self.shard_heap_addr_range.clone(),
                    shard_hint_addr_range: self.shard_hint_addr_range.clone(),
                })
                .collect_vec(),
            _ => panic!("invalid type"),
        }
    }

    pub fn read_records(&self) -> &[BTreeMap<WordAddr, RAMRecord>] {
        match &self.read_records_tbs {
            Either::Left(m) => m,
            Either::Right(_) => panic!("undefined behaviour"),
        }
    }

    pub fn write_records(&self) -> &[BTreeMap<WordAddr, RAMRecord>] {
        match &self.write_records_tbs {
            Either::Left(m) => m,
            Either::Right(_) => panic!("undefined behaviour"),
        }
    }

    #[inline(always)]
    pub fn is_first_shard(&self) -> bool {
        self.shard_id == 0
    }

    #[inline(always)]
    pub fn is_last_shard(&self) -> bool {
        self.shard_id == self.num_shards - 1
    }

    #[inline(always)]
    pub fn is_in_current_shard(&self, cycle: Cycle) -> bool {
        self.cur_shard_cycle_range.contains(&(cycle as usize))
    }

    #[inline(always)]
    pub fn before_current_shard_cycle(&self, cycle: Cycle) -> bool {
        (cycle as usize) < self.cur_shard_cycle_range.start
    }

    #[inline(always)]
    pub fn after_current_shard_cycle(&self, cycle: Cycle) -> bool {
        (cycle as usize) >= self.cur_shard_cycle_range.end
    }

    /// Extract shard_id which produce this record by cycle
    /// NOTE prev_shard_cycle_range[0] should be 0 otherwise it will panic with subtract-overflow
    #[inline(always)]
    pub fn extract_shard_id_by_cycle(&self, cycle: Cycle) -> usize {
        self.prev_shard_cycle_range.partition_point(|&t| t <= cycle) - 1
    }

    /// Extract shard_id which produce this record by heap addr
    /// NOTE prev_shard_heap_range[0] should be 0 otherwise it will panic with subtract-overflow
    #[inline(always)]
    pub fn extract_shard_id_by_heap_addr(&self, addr: Addr) -> usize {
        self.prev_shard_heap_range.partition_point(|&a| a <= addr) - 1
    }

    /// Extract shard_id which produce this record by hint addr
    /// NOTE prev_shard_hint_range[0] should be 0 otherwise it will panic with subtract-overflow
    #[inline(always)]
    pub fn extract_shard_id_by_hint_addr(&self, addr: Addr) -> usize {
        self.prev_shard_hint_range.partition_point(|&a| a <= addr) - 1
    }

    #[inline(always)]
    pub fn aligned_prev_ts(&self, prev_cycle: Cycle) -> Cycle {
        let mut ts = prev_cycle.saturating_sub(self.current_shard_offset_cycle());
        if ts < FullTracer::SUBCYCLES_PER_INSN {
            ts = 0
        }
        ts
    }

    #[inline(always)]
    pub fn aligned_current_ts(&self, cycle: Cycle) -> Cycle {
        cycle.saturating_sub(self.current_shard_offset_cycle())
    }

    pub fn current_shard_offset_cycle(&self) -> Cycle {
        // cycle of each local shard start from Tracer::SUBCYCLES_PER_INSN
        (self.cur_shard_cycle_range.start as Cycle) - FullTracer::SUBCYCLES_PER_INSN
    }

    /// Finds the **next** future access cycle for the given address, starting from
    /// the specified current cycle.
    ///
    /// Note that the returned cycle is simply the *next* access, not necessarily
    /// the final (last) access of the address.
    ///
    /// For example, if address `0xabc` is accessed at cycles `4` and `8`,
    /// then `find_future_next_access(0xabc, 4)` returns `8`.
    #[inline(always)]
    pub fn find_future_next_access(&self, cycle: Cycle, addr: WordAddr) -> Option<Cycle> {
        self.addr_future_accesses.get(&cycle).and_then(|res| {
            if res.len() == 1 && res[0].0 == addr {
                Some(res[0].1)
            } else if res.len() > 1 {
                res.iter()
                    .find(|(m_addr, _)| *m_addr == addr)
                    .map(|(_, cycle)| *cycle)
            } else {
                None
            }
        })
    }

    #[inline(always)]
    #[allow(clippy::too_many_arguments)]
    pub fn send(
        &mut self,
        ram_type: crate::structs::RAMType,
        addr: WordAddr,
        id: u64,
        cycle: Cycle,
        prev_cycle: Cycle,
        value: Word,
        prev_value: Option<Word>,
    ) {
        if !self.is_first_shard()
            && self.is_in_current_shard(cycle)
            && self.before_current_shard_cycle(prev_cycle)
        {
            let addr_raw = addr.baddr().0;
            let is_heap = self.platform.heap.contains(&addr_raw);
            let is_hint = self.platform.hints.contains(&addr_raw);
            // 1. checking reads from the external bus
            if prev_cycle > 0 || (prev_cycle == 0 && (!is_heap && !is_hint)) {
                let prev_shard_id = self.extract_shard_id_by_cycle(prev_cycle);
                let ram_record = self
                    .read_records_tbs
                    .as_mut()
                    .right()
                    .expect("illegal type");
                ram_record.insert(
                    addr,
                    RAMRecord {
                        ram_type,
                        reg_id: id,
                        addr,
                        prev_cycle,
                        cycle,
                        shard_cycle: 0,
                        prev_value,
                        value,
                        shard_id: prev_shard_id,
                    },
                );
            } else {
                assert!(
                    prev_cycle == 0 && (is_heap || is_hint),
                    "addr {addr_raw:x} prev_cycle {prev_cycle}, is_heap {is_heap}, is_hint {is_hint}",
                );
                // 2. handle heap/hint initial reads outside the shard range.
                let prev_shard_id = if is_heap && !self.shard_heap_addr_range.contains(&addr_raw) {
                    Some(self.extract_shard_id_by_heap_addr(addr_raw))
                } else if is_hint && !self.shard_hint_addr_range.contains(&addr_raw) {
                    Some(self.extract_shard_id_by_hint_addr(addr_raw))
                } else {
                    // dynamic init in current shard, skip and do nothing
                    None
                };
                if let Some(prev_shard_id) = prev_shard_id {
                    let ram_record = self
                        .read_records_tbs
                        .as_mut()
                        .right()
                        .expect("illegal type");
                    ram_record.insert(
                        addr,
                        RAMRecord {
                            ram_type,
                            reg_id: id,
                            addr,
                            prev_cycle,
                            cycle,
                            shard_cycle: 0,
                            prev_value,
                            value,
                            shard_id: prev_shard_id,
                        },
                    );
                }
            }
        }

        // check write to external mem bus
        if let Some(future_touch_cycle) = self.find_future_next_access(cycle, addr)
            && self.after_current_shard_cycle(future_touch_cycle)
            && self.is_in_current_shard(cycle)
        {
            let shard_cycle = self.aligned_current_ts(cycle);
            let ram_record = self
                .write_records_tbs
                .as_mut()
                .right()
                .expect("illegal type");
            ram_record.insert(
                addr,
                RAMRecord {
                    ram_type,
                    reg_id: id,
                    addr,
                    prev_cycle,
                    cycle,
                    shard_cycle,
                    prev_value,
                    value,
                    shard_id: self.shard_id,
                },
            );
        }

        let addr_accessed = self
            .addr_accessed_tbs
            .as_mut()
            .right()
            .expect("illegal type");
        addr_accessed.push(addr);
    }

    /// merge addr accessed in different threads
    pub fn get_addr_accessed(&self) -> FxHashSet<WordAddr> {
        let mut merged = FxHashSet::default();
        if let Either::Left(addr_accessed_tbs) = &self.addr_accessed_tbs {
            for addrs in addr_accessed_tbs {
                merged.extend(addrs.iter().copied());
            }
        } else {
            panic!("invalid type");
        }
        merged
    }

    /// Splits a total count `num_shards` into up to `num_provers` non-empty parts, distributing as evenly as possible.
    ///
    /// # Behavior
    ///
    /// - If `num_shards == 0` or `num_provers == 0`, returns an empty vector `[]`.
    /// - If `num_shards <= num_provers`, each part will have size `1`, and the total number of parts equals `num_shards`.
    /// - Otherwise, divides `num_shards` evenly across `num_provers` parts so that:
    ///   - The first `num_shards % num_provers` parts get `base + 1` elements,
    ///   - The rest get `base` elements,
    ///     where `base = num_shards / num_provers`.
    ///
    /// This ensures that:
    /// - Every part is non-zero in size.
    /// - The sum of all parts equals `num_shards`.
    /// - The distribution is as balanced as possible (difference <= 1).
    ///
    /// # Examples
    ///
    /// ```
    /// # fn main() {
    /// use ceno_zkvm::e2e::ShardContext;
    /// assert_eq!(ShardContext::distribute_shards_into_provers(3, 2), vec![2, 1]);
    /// assert_eq!(ShardContext::distribute_shards_into_provers(4, 2), vec![2, 2]);
    /// assert_eq!(ShardContext::distribute_shards_into_provers(5, 2), vec![3, 2]);
    /// assert_eq!(ShardContext::distribute_shards_into_provers(10, 3), vec![4, 3, 3]);
    ///
    /// // When n <= m, each item gets its own shard.
    /// assert_eq!(ShardContext::distribute_shards_into_provers(1, 2), vec![1]);
    /// assert_eq!(ShardContext::distribute_shards_into_provers(2, 3), vec![1, 1]);
    /// assert_eq!(ShardContext::distribute_shards_into_provers(3, 4), vec![1, 1, 1]);
    ///
    /// // Edge cases
    /// assert_eq!(ShardContext::distribute_shards_into_provers(0, 3), Vec::<usize>::new());
    /// assert_eq!(ShardContext::distribute_shards_into_provers(5, 0), Vec::<usize>::new());
    /// # }
    /// ```
    /// # Returns
    ///
    /// A `Vec<usize>` representing the size of each part, whose total sum equals `n`.
    pub fn distribute_shards_into_provers(num_shards: usize, num_provers: usize) -> Vec<usize> {
        if num_shards == 0 || num_provers == 0 {
            return vec![];
        }

        // If there are more shards than items, just give each item its own shard
        if num_shards <= num_provers {
            return vec![1; num_shards];
        }

        let base = num_shards / num_provers;
        let remainder = num_shards % num_provers;

        (0..num_provers)
            .map(|i| if i < remainder { base + 1 } else { base })
            .collect()
    }
}

pub trait StepCellExtractor {
    fn cells_for_kind(&self, kind: InsnKind, rs1_value: Option<Word>) -> u64;

    #[inline(always)]
    fn extract_cells(&self, step: &StepRecord) -> u64 {
        self.cells_for_kind(step.insn().kind, step.rs1().map(|op| op.value))
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct ShardStepSummary {
    pub step_count: usize,
    pub first_cycle: Cycle,
    pub last_cycle: Cycle,
    pub first_pc_before: Addr,
    pub last_pc_after: Addr,
    pub first_heap_before: Addr,
    pub last_heap_after: Addr,
    pub first_hint_before: Addr,
    pub last_hint_after: Addr,
}

impl ShardStepSummary {
    fn update(&mut self, step: &StepRecord) {
        if self.step_count == 0 {
            self.first_cycle = step.cycle();
            self.first_pc_before = step.pc().before.0;
            self.first_heap_before = step.heap_maxtouch_addr.before.0;
            self.first_hint_before = step.hint_maxtouch_addr.before.0;
        }
        self.step_count += 1;
        self.last_cycle = step.cycle();
        self.last_pc_after = step.pc().after.0;
        self.last_heap_after = step.heap_maxtouch_addr.after.0;
        self.last_hint_after = step.hint_maxtouch_addr.after.0;
    }
}

pub struct ShardContextBuilder {
    pub cur_shard_id: usize,
    addr_future_accesses: Arc<NextCycleAccess>,
    max_cell_per_shard: u64,
    max_cycle_per_shard: Cycle,
    target_cell_first_shard: u64,
    prev_shard_cycle_range: Vec<Cycle>,
    prev_shard_heap_range: Vec<Addr>,
    prev_shard_hint_range: Vec<Addr>,
    platform: Platform,
    shard_cycle_boundaries: Arc<Vec<Cycle>>,
    max_cycle: Cycle,
    planner: Option<ShardPlanner>,
}

#[derive(Default)]
struct ShardPlanner {
    cur_cells: u64,
    cur_cycle_in_shard: Cycle,
    shard_id: usize,
}

impl Default for ShardContextBuilder {
    fn default() -> Self {
        ShardContextBuilder {
            cur_shard_id: 0,
            addr_future_accesses: Arc::new(Default::default()),
            max_cell_per_shard: 0,
            max_cycle_per_shard: 0,
            target_cell_first_shard: 0,
            prev_shard_cycle_range: vec![],
            prev_shard_heap_range: vec![],
            prev_shard_hint_range: vec![],
            platform: CENO_PLATFORM.clone(),
            shard_cycle_boundaries: Arc::new(vec![FullTracer::SUBCYCLES_PER_INSN]),
            max_cycle: 0,
            planner: Some(ShardPlanner::default()),
        }
    }
}

impl ShardContextBuilder {
    /// set max_cell_per_shard == u64::MAX if target for single shard
    pub fn new(multi_prover: &MultiProver, platform: Platform) -> Self {
        assert_eq!(multi_prover.max_provers, 1);
        assert_eq!(multi_prover.prover_id, 0);
        ShardContextBuilder {
            cur_shard_id: 0,
            max_cell_per_shard: multi_prover.max_cell_per_shard,
            max_cycle_per_shard: multi_prover.max_cycle_per_shard,
            target_cell_first_shard: {
                if multi_prover.max_cell_per_shard == u64::MAX {
                    u64::MAX
                } else {
                    multi_prover.max_cell_per_shard
                }
            },
            addr_future_accesses: Arc::new(Default::default()),
            prev_shard_cycle_range: vec![0],
            prev_shard_heap_range: vec![0],
            prev_shard_hint_range: vec![0],
            platform,
            shard_cycle_boundaries: Arc::new(vec![FullTracer::SUBCYCLES_PER_INSN]),
            max_cycle: 0,
            planner: Some(ShardPlanner::default()),
        }
    }

    pub fn set_addr_future_accesses(&mut self, addr_future_accesses: NextCycleAccess) {
        self.addr_future_accesses = Arc::new(addr_future_accesses);
    }

    #[inline(always)]
    pub fn observe_step_budget(&mut self, step_cycle: Cycle, step_cells: u64) {
        let should_split = {
            let planner = self
                .planner
                .as_mut()
                .expect("shard context planner already finalized");
            let target_cost_current_shard = if planner.shard_id == 0 {
                self.target_cell_first_shard
            } else {
                self.max_cell_per_shard
            };
            let next_cells = planner.cur_cells.saturating_add(step_cells);
            let next_cycle = planner
                .cur_cycle_in_shard
                .saturating_add(FullTracer::SUBCYCLES_PER_INSN);
            let cycle_limit_hit =
                self.max_cycle_per_shard < Cycle::MAX && next_cycle >= self.max_cycle_per_shard;
            let should_split = next_cells >= target_cost_current_shard || cycle_limit_hit;
            if should_split {
                assert!(
                    planner.cur_cells > 0 || planner.cur_cycle_in_shard > 0,
                    "shard split before accumulating any steps"
                );
                planner.shard_id += 1;
                planner.cur_cells = step_cells;
                planner.cur_cycle_in_shard = FullTracer::SUBCYCLES_PER_INSN;
            } else {
                planner.cur_cells = next_cells;
                planner.cur_cycle_in_shard = next_cycle;
            }
            should_split
        };
        if should_split {
            self.push_boundary(step_cycle);
        }
    }

    pub fn finalize_plan(&mut self, max_cycle: Cycle) {
        self.max_cycle = max_cycle;
        self.push_boundary(max_cycle);
        self.prev_shard_cycle_range = vec![0];
        self.prev_shard_heap_range = vec![0];
        self.prev_shard_hint_range = vec![0];
        self.cur_shard_id = 0;
        self.planner = None;
    }

    pub fn shard_cycle_boundaries(&self) -> Arc<Vec<Cycle>> {
        self.shard_cycle_boundaries.clone()
    }

    pub fn total_shards(&self) -> usize {
        self.shard_cycle_boundaries.len().saturating_sub(1)
    }

    fn push_boundary(&mut self, cycle: Cycle) {
        if self
            .shard_cycle_boundaries
            .last()
            .copied()
            .unwrap_or_default()
            != cycle
        {
            Arc::get_mut(&mut self.shard_cycle_boundaries)
                .expect("shard cycle boundaries already shared")
                .push(cycle);
        }
    }

    pub fn position_next_shard<'a>(
        &mut self,
        steps_iter: &mut impl Iterator<Item = StepRecord>,
        mut on_step: impl FnMut(StepRecord),
    ) -> Option<(ShardContext<'a>, ShardStepSummary)> {
        if self.cur_shard_id >= self.total_shards() {
            return None;
        }
        let expected_end_cycle = self
            .shard_cycle_boundaries
            .get(self.cur_shard_id + 1)
            .copied()
            .expect("missing shard boundary for shard");
        let mut summary = ShardStepSummary::default();
        loop {
            let step = match steps_iter.next() {
                Some(step) => step,
                None => break,
            };
            summary.update(&step);
            on_step(step);
            if summary.last_cycle + FullTracer::SUBCYCLES_PER_INSN == expected_end_cycle {
                break;
            }
        }

        if summary.step_count == 0 {
            return None;
        }

        assert_eq!(
            summary.last_cycle + FullTracer::SUBCYCLES_PER_INSN,
            expected_end_cycle,
            "shard {} did not end on expected boundary",
            self.cur_shard_id
        );

        if self.cur_shard_id > 0 {
            assert_eq!(
                summary.first_cycle,
                self.prev_shard_cycle_range
                    .last()
                    .copied()
                    .unwrap_or(FullTracer::SUBCYCLES_PER_INSN)
            );
            assert_eq!(
                summary.first_heap_before,
                self.prev_shard_heap_range
                    .last()
                    .copied()
                    .unwrap_or(self.platform.heap.start)
            );
            assert_eq!(
                summary.first_hint_before,
                self.prev_shard_hint_range
                    .last()
                    .copied()
                    .unwrap_or(self.platform.hints.start)
            );
        }

        let shard_ctx = ShardContext {
            shard_id: self.cur_shard_id,
            num_shards: self.total_shards(),
            max_cycle: self.max_cycle,
            cur_shard_cycle_range: summary.first_cycle as usize
                ..(summary.last_cycle + FullTracer::SUBCYCLES_PER_INSN) as usize,
            addr_future_accesses: self.addr_future_accesses.clone(),
            prev_shard_cycle_range: self.prev_shard_cycle_range.clone(),
            prev_shard_heap_range: self.prev_shard_heap_range.clone(),
            prev_shard_hint_range: self.prev_shard_hint_range.clone(),
            platform: self.platform.clone(),
            shard_heap_addr_range: summary.first_heap_before..summary.last_heap_after,
            shard_hint_addr_range: summary.first_hint_before..summary.last_hint_after,
            ..Default::default()
        };
        self.prev_shard_cycle_range
            .push(shard_ctx.cur_shard_cycle_range.end as u64);
        self.prev_shard_heap_range
            .push(shard_ctx.shard_heap_addr_range.end);
        self.prev_shard_hint_range
            .push(shard_ctx.shard_hint_addr_range.end);
        self.cur_shard_id += 1;

        Some((shard_ctx, summary))
    }
}

/// Lazily replays `StepRecord`s by re-running the VM up to the number of steps
/// recorded during the preflight execution. This keeps shard generation memory
/// usage bounded without storing the entire trace.
struct StepReplay {
    vm: VMState,
    remaining_steps: usize,
}

impl StepReplay {
    fn new(
        platform: Platform,
        program: Arc<Program>,
        init_mem_state: &InitMemState,
        remaining_steps: usize,
    ) -> Self {
        let mut vm = VMState::new(platform, program);
        for record in chain!(init_mem_state.hints.iter(), init_mem_state.io.iter()) {
            vm.init_memory(record.addr.into(), record.value);
        }
        StepReplay {
            vm,
            remaining_steps,
        }
    }
}

impl Iterator for StepReplay {
    type Item = StepRecord;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining_steps == 0 {
            return None;
        }
        match self.vm.next_step_record() {
            Ok(Some(step)) => {
                self.remaining_steps -= 1;
                Some(step)
            }
            Ok(None) => {
                self.remaining_steps = 0;
                None
            }
            Err(err) => panic!("vm exec failed during witness replay: {err:?}"),
        }
    }
}

pub fn emulate_program<'a, S: StepCellExtractor + ?Sized>(
    program: Arc<Program>,
    max_steps: usize,
    init_mem_state: &InitMemState,
    platform: &Platform,
    multi_prover: &MultiProver,
    step_cell_extractor: &S,
) -> EmulationResult<'a> {
    let InitMemState {
        mem: mem_init,
        io: io_init,
        reg: reg_init,
        hints: hints_init,
        stack: _,
        heap: _,
    } = init_mem_state;

    let mut vm: VMState<EmptyTracer> = info_span!("[ceno] emulator.new_empty_tracer")
        .in_scope(|| VMState::new_with_tracer(platform.clone(), program.clone()));

    info_span!("[ceno] emulator.init_mem").in_scope(|| {
        for record in chain!(hints_init, io_init) {
            vm.init_memory(record.addr.into(), record.value);
        }
    });

    let mut shard_ctx_builder = ShardContextBuilder::new(multi_prover, platform.clone());
    let _ = info_span!("[ceno] emulator.max_cycle_estimated").in_scope(|| {
        let mut steps = 0usize;
        loop {
            if steps >= max_steps {
                break;
            }
            match vm.next_step_record() {
                Ok(Some(_)) => {
                    steps += 1;
                    let tracer = vm.tracer();
                    let step_cycle = tracer
                        .cycle()
                        .saturating_sub(EmptyTracer::SUBCYCLES_PER_INSN);
                    let step_cells = step_cell_extractor
                        .cells_for_kind(tracer.last_insn_kind(), tracer.last_rs1_value());
                    shard_ctx_builder.observe_step_budget(step_cycle, step_cells);
                }
                Ok(None) => break,
                Err(err) => panic!("emulator trapped before halt: {err}"),
            }
        }
        vm.halted_state().map(|halt_state| halt_state.exit_code)
    });
    let max_cycle = vm.tracer().cycle();
    shard_ctx_builder.finalize_plan(max_cycle);
    let shard_cycle_boundaries = shard_ctx_builder.shard_cycle_boundaries();
    tracing::info!(
        "num_shards: {}, max_cycle {}, shard_cycle_boundaries {:?}",
        shard_ctx_builder.total_shards(),
        max_cycle,
        shard_cycle_boundaries.as_ref()
    );
    let preflight_config =
        PreflightTracerConfig::from_end_cycle(max_cycle, shard_cycle_boundaries.clone());

    let mut vm: VMState<PreflightTracer> = info_span!("[ceno] emulator.new-preflight-tracer")
        .in_scope(|| VMState::new_with_tracer_config(platform.clone(), program, preflight_config));

    for record in chain!(hints_init, io_init) {
        vm.init_memory(record.addr.into(), record.value);
    }

    let exit_code = info_span!("[ceno] emulator.preflight-execute").in_scope(|| {
        vm.iter_until_halt()
            .take(max_steps)
            .try_for_each(|step| step.map(|_| ()))
            .unwrap_or_else(|err| panic!("emulator trapped before halt: {err}"));
        vm.halted_state().map(|halt_state| halt_state.exit_code)
    });

    if platform.is_debug {
        let all_messages = read_all_messages(&vm)
            .iter()
            .map(|msg| String::from_utf8_lossy(msg).to_string())
            .collect::<Vec<_>>();

        if !all_messages.is_empty() {
            tracing::info!("========= BEGIN: I/O from guest =========");
            for msg in &all_messages {
                tracing::info!("│ {}", msg);
            }
            tracing::info!("========= END: I/O from guest =========");
        }
    }
    let final_access = vm.tracer().final_accesses();
    let end_cycle = vm.tracer().cycle();
    let insts = vm.tracer().executed_insts();
    tracing::info!("program executed {insts} instructions in {end_cycle} cycles");
    metrics::gauge!("cycles").set(insts as f64);

    // Find the final register values and cycles.
    let reg_final = reg_init
        .iter()
        .map(|rec| {
            let index = rec.addr as usize;
            if index < VM_REG_COUNT {
                let vma: WordAddr = Platform::register_vma(index).into();
                MemFinalRecord {
                    ram_type: RAMType::Register,
                    addr: rec.addr,
                    value: vm.peek_register(index),
                    init_value: rec.value,
                    cycle: final_access.cycle(vma),
                }
            } else {
                // The table is padded beyond the number of registers.
                MemFinalRecord {
                    ram_type: RAMType::Register,
                    addr: rec.addr,
                    value: 0,
                    init_value: 0,
                    cycle: 0,
                }
            }
        })
        .collect_vec();

    // Find the final memory values and cycles.
    let mem_final = mem_init
        .iter()
        .map(|rec| {
            let vma: WordAddr = rec.addr.into();
            MemFinalRecord {
                ram_type: RAMType::Memory,
                addr: rec.addr,
                value: vm.peek_memory(vma),
                init_value: rec.value,
                cycle: final_access.cycle(vma),
            }
        })
        .collect_vec();

    // Find the final public IO cycles.
    let io_final = io_init
        .iter()
        .map(|rec| MemFinalRecord {
            ram_type: RAMType::Memory,
            addr: rec.addr,
            value: rec.value,
            init_value: rec.value,
            cycle: final_access.cycle(rec.addr.into()),
        })
        .collect_vec();

    // Find the final hints IO cycles.
    let hints_final = hints_init
        .iter()
        .map(|rec| MemFinalRecord {
            ram_type: RAMType::Memory,
            addr: rec.addr,
            value: rec.value,
            init_value: rec.value,
            cycle: final_access.cycle(rec.addr.into()),
        })
        .collect_vec();

    // get stack access by min/max range
    let stack_final = if let Some((min_waddr, _)) = vm
        .tracer()
        .probe_min_max_address_by_start_addr(ByteAddr::from(platform.stack.start).waddr())
    {
        (min_waddr..ByteAddr::from(platform.stack.end).waddr())
            // stack record collect in reverse order
            .rev()
            .map(|vma| {
                let byte_addr = vma.baddr();
                MemFinalRecord {
                    ram_type: RAMType::Memory,
                    addr: byte_addr.0,
                    value: vm.peek_memory(vma),
                    init_value: 0,
                    cycle: final_access.cycle(vma),
                }
            })
            .collect_vec()
    } else {
        vec![]
    };

    // get heap access by min/max range
    let heap_start_waddr = ByteAddr::from(platform.heap.start).waddr();
    // note: min_waddr for the heap is intentionally ignored
    // as the actual starting address may be shifted due to alignment requirements
    // e.g. heap start addr 0x90000000 + 32 bytes alignment => 0x90000000 % 32 = 16 → offset = 16 bytes → moves to 0x90000010.
    let heap_final = if let Some((_, max_waddr)) = vm
        .tracer()
        .probe_min_max_address_by_start_addr(heap_start_waddr)
    {
        (heap_start_waddr..max_waddr)
            .map(|vma| {
                let byte_addr = vma.baddr();
                MemFinalRecord {
                    ram_type: RAMType::Memory,
                    addr: byte_addr.0,
                    value: vm.peek_memory(vma),
                    init_value: 0,
                    cycle: final_access.cycle(vma),
                }
            })
            .collect_vec()
    } else {
        vec![]
    };

    let pi = PublicValues::new(
        exit_code.unwrap_or(0),
        vm.program().entry,
        FullTracer::SUBCYCLES_PER_INSN,
        vm.get_pc().into(),
        end_cycle,
        multi_prover.prover_id as u32,
        platform.heap.start,
        heap_final.len() as u32,
        platform.hints.start,
        hints_final.len() as u32,
        io_init.iter().map(|rec| rec.value).collect_vec(),
        vec![0; SEPTIC_EXTENSION_DEGREE * 2], // point_at_infinity
    );

    #[cfg(debug_assertions)]
    {
        debug_memory_ranges(
            &vm,
            chain!(
                &mem_final,
                &io_final,
                &hints_final,
                &stack_final,
                &heap_final
            ),
        );
    }

    shard_ctx_builder.set_addr_future_accesses(vm.take_tracer().into_next_accesses());

    EmulationResult {
        pi,
        exit_code,
        shard_ctx_builder,
        shard_cycle_boundaries: shard_cycle_boundaries.clone(),
        executed_steps: insts,
        final_mem_state: FinalMemState {
            reg: reg_final,
            io: io_final,
            mem: mem_final,
            hints: hints_final,
            stack: stack_final,
            heap: heap_final,
        },
        phantom: PhantomData,
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
pub enum Preset {
    Ceno,
}

pub fn setup_platform(
    preset: Preset,
    program: &Program,
    stack_size: u32,
    heap_size: u32,
    pub_io_size: u32,
) -> Platform {
    setup_platform_inner(preset, program, stack_size, heap_size, pub_io_size, false)
}

pub fn setup_platform_debug(
    preset: Preset,
    program: &Program,
    stack_size: u32,
    heap_size: u32,
    pub_io_size: u32,
) -> Platform {
    setup_platform_inner(preset, program, stack_size, heap_size, pub_io_size, true)
}

fn setup_platform_inner(
    preset: Preset,
    program: &Program,
    stack_size: u32,
    heap_size: u32,
    pub_io_size: u32,
    is_debug: bool,
) -> Platform {
    let preset = match preset {
        Preset::Ceno => Platform {
            is_debug,
            ..CENO_PLATFORM.clone()
        },
    };

    let prog_data = Arc::new(program.image.keys().copied().collect::<BTreeSet<_>>());

    let stack = if preset.is_debug {
        (preset.stack.end - 0x4000 - stack_size)..(preset.stack.end)
    } else {
        // remove extra space for io for non-debug mode
        (preset.stack.end - 0x4000 - stack_size)..(preset.stack.end - 0x4000)
    };

    let heap = {
        // Detect heap as starting after program data.
        let heap_start = program.sheap;
        let heap = heap_start..heap_start + heap_size;
        // pad the total size to the next power of two.
        let mem_size = heap.iter_addresses().len();
        let pad_size = mem_size.next_power_of_two() - mem_size;
        let heap_end = heap.end as usize + pad_size * WORD_SIZE;
        assert!(
            heap_end <= u32::MAX as usize,
            "not enough space for padding; reduce heap size"
        );
        heap.start..heap_end as u32
    };

    assert!(
        pub_io_size.is_power_of_two(),
        "pub io size {pub_io_size} must be a power of two"
    );
    let platform = Platform {
        rom: program.base_address
            ..program.base_address + (program.instructions.len() * WORD_SIZE) as u32,
        prog_data,
        stack,
        heap,
        public_io: preset.public_io.start..preset.public_io.start + pub_io_size,
        ..preset
    };
    assert!(
        platform.validate(),
        "invalid platform configuration: {platform}"
    );

    platform
}

pub fn init_static_addrs(program: &Program) -> Vec<MemInitRecord> {
    let program_addrs = program
        .image
        .iter()
        .map(|(addr, value)| MemInitRecord {
            addr: *addr,
            value: *value,
        })
        .sorted_by_key(|record| record.addr)
        .collect_vec();

    assert!(
        program_addrs.len().is_power_of_two(),
        "program_addrs.len {} is not pow2",
        program_addrs.len(),
    );
    program_addrs
}

pub struct ConstraintSystemConfig<E: ExtensionField> {
    pub zkvm_cs: ZKVMConstraintSystem<E>,
    pub config: Rv32imConfig<E>,
    pub inst_dispatch_builder: InstructionDispatchBuilder,
    pub mmu_config: MmuConfig<E>,
    pub dummy_config: DummyExtraConfig<E>,
    pub prog_config: ProgramTableConfig,
}

pub fn construct_configs<E: ExtensionField>(
    program_params: ProgramParams,
) -> ConstraintSystemConfig<E> {
    let mut zkvm_cs = ZKVMConstraintSystem::new_with_platform(program_params);

    let (config, inst_dispatch_builder) = Rv32imConfig::<E>::construct_circuits(&mut zkvm_cs);
    let mmu_config = MmuConfig::<E>::construct_circuits(&mut zkvm_cs);
    let dummy_config = DummyExtraConfig::<E>::construct_circuits(&mut zkvm_cs);
    let prog_config = zkvm_cs.register_table_circuit::<ProgramTableCircuit<E>>();
    zkvm_cs.register_global_state::<GlobalState>();
    ConstraintSystemConfig {
        zkvm_cs,
        config,
        inst_dispatch_builder,
        mmu_config,
        dummy_config,
        prog_config,
    }
}

pub fn generate_fixed_traces<E: ExtensionField>(
    system_config: &ConstraintSystemConfig<E>,
    reg_init: &[MemInitRecord],
    static_mem_init: &[MemInitRecord],
    io_addrs: &[Addr],
    program: &Program,
) -> ZKVMFixedTraces<E> {
    let mut zkvm_fixed_traces = ZKVMFixedTraces::default();

    zkvm_fixed_traces.register_table_circuit::<ProgramTableCircuit<E>>(
        &system_config.zkvm_cs,
        &system_config.prog_config,
        program,
    );

    system_config
        .config
        .generate_fixed_traces(&system_config.zkvm_cs, &mut zkvm_fixed_traces);
    system_config.mmu_config.generate_fixed_traces(
        &system_config.zkvm_cs,
        &mut zkvm_fixed_traces,
        reg_init,
        static_mem_init,
        io_addrs,
    );
    system_config
        .dummy_config
        .generate_fixed_traces(&system_config.zkvm_cs, &mut zkvm_fixed_traces);

    zkvm_fixed_traces
}

pub fn generate_witness<'a, E: ExtensionField>(
    system_config: &ConstraintSystemConfig<E>,
    mut emul_result: EmulationResult<'a>,
    program: Arc<Program>,
    platform: &Platform,
    init_mem_state: &InitMemState,
    // this is for debug purpose, which only run target shard id and skip all others
    target_shard_id: Option<usize>,
) -> impl Iterator<Item = (ZKVMWitnesses<E>, ShardContext<'a>, PublicValues)> {
    let mut shard_ctx_builder = std::mem::take(&mut emul_result.shard_ctx_builder);
    assert!(
        emul_result.executed_steps > 0,
        "execution trace must contain at least one step"
    );

    let mut instrunction_dispatch_ctx = system_config.inst_dispatch_builder.to_dispatch_ctx();
    let pi_template = emul_result.pi.clone();
    let mut step_iter = StepReplay::new(
        platform.clone(),
        program.clone(),
        init_mem_state,
        emul_result.executed_steps,
    );
    std::iter::from_fn(move || {
        info_span!(
            "[ceno] app_prove.generate_witness",
            shard_id = shard_ctx_builder.cur_shard_id
        )
        .in_scope(|| {
            instrunction_dispatch_ctx.begin_shard();
            let (mut shard_ctx, shard_summary) = match shard_ctx_builder.position_next_shard(
                &mut step_iter,
                |step| instrunction_dispatch_ctx.ingest_step(step),
            ) {
                Some(result) => result,
                None => return None,
            };

            let mut zkvm_witness = ZKVMWitnesses::default();
            let mut pi = pi_template.clone();
            tracing::debug!(
                "{}th shard collect {} steps, cycles range {:?}, heap_addr_range {:x} - {:x}, hint_addr_range {:x} - {:x}",
                shard_ctx.shard_id,
                shard_summary.step_count,
                shard_ctx.cur_shard_cycle_range,
                shard_ctx.shard_heap_addr_range.start,
                shard_ctx.shard_heap_addr_range.end,
                shard_ctx.shard_hint_addr_range.start,
                shard_ctx.shard_hint_addr_range.end,
            );

            let current_shard_offset_cycle = shard_ctx.current_shard_offset_cycle();
            let current_shard_end_cycle = shard_summary.last_cycle + FullTracer::SUBCYCLES_PER_INSN
                - current_shard_offset_cycle;
            let current_shard_init_pc = if shard_ctx.is_first_shard() {
                program.entry
            } else {
                shard_summary.first_pc_before
            };
            let current_shard_end_pc = shard_summary.last_pc_after;

            pi.init_pc = current_shard_init_pc;
            pi.init_cycle = FullTracer::SUBCYCLES_PER_INSN;
            pi.shard_id = shard_ctx.shard_id as u32;
            pi.end_pc = current_shard_end_pc;
            pi.end_cycle = current_shard_end_cycle;
            pi.heap_start_addr = shard_ctx.shard_heap_addr_range.start;
            pi.heap_shard_len = (shard_ctx.shard_heap_addr_range.end
                - shard_ctx.shard_heap_addr_range.start)
                / (WORD_SIZE as u32);
            pi.hint_start_addr = shard_ctx.shard_hint_addr_range.start;
            pi.hint_shard_len = (shard_ctx.shard_hint_addr_range.end
                - shard_ctx.shard_hint_addr_range.start)
                / (WORD_SIZE as u32);

            if let Some(target_shard_id) = target_shard_id {
                if shard_ctx.shard_id < target_shard_id {
                    tracing::debug!("{}th shard skipped", shard_ctx.shard_id);
                    return Some((zkvm_witness, shard_ctx, pi));
                } else if shard_ctx.shard_id > target_shard_id {
                    tracing::debug!("{}th shard skipped", shard_ctx.shard_id);
                    return None;
                }
            }

            let time = std::time::Instant::now();
            system_config
                .config
                .assign_opcode_circuit(
                    &system_config.zkvm_cs,
                    &mut shard_ctx,
                    &mut instrunction_dispatch_ctx,
                    &mut zkvm_witness,
                )
                .unwrap();
            tracing::debug!("assign_opcode_circuit finish in {:?}", time.elapsed());
            let time = std::time::Instant::now();
            system_config
                .dummy_config
                .assign_opcode_circuit(
                    &system_config.zkvm_cs,
                    &mut shard_ctx,
                    &instrunction_dispatch_ctx,
                    &mut zkvm_witness,
                )
                .unwrap();
            tracing::debug!("assign_dummy_config finish in {:?}", time.elapsed());
            zkvm_witness.finalize_lk_multiplicities();

            // Memory record routing (per address / waddr)
            //
            // Legend:
            //   init shard  = where the "initialization record" happens
            //   rw shard    = shards that read/write the address
            //   later rw?   = whether there is any rw in shards > current shard
            // Chip(s):
            // - LocalFinalize = local finalize circuit
            // - ShardRAM      = shard ram circuit
            // - ShardRAM+LF   = both
            //
            // Root
            // └─ Is the init record in shard 0?
            // ├─ YES: Static initialized memory (init only exists in shard 0)
            // │  └─ Where does the rw happen (relative to current shard)?
            // │     ├─ rw only in shard 0
            // │     │  ├─ later rw? NO  (no rw in >0)      -> LocalFinalize
            // │     │  └─ later rw? YES (rw in >0 exists)  -> ShardRAM
            // │     │
            // │     └─ rw occurs in current shard (current shard may be >0)
            // │        ├─ later rw? NO  (no rw in later)   -> ShardRAM + LocalFinalize
            // │        └─ later rw? YES (rw continues)     -> ShardRAM
            // │
            // └─ NO: Dynamic init across shards (init can happen in any shard)
            // └─ Is the init record in the current shard?
            // ├─ YES: init in current shard
            // │  ├─ later rw? NO  -> LocalFinalize
            // │  └─ later rw? YES -> ShardRAM
            // │
            // └─ NO: init in a previous shard
            // ├─ later rw? NO  -> ShardRAM + LocalFinalize
            // └─ later rw? YES -> ShardRAM

            let time = std::time::Instant::now();
            system_config
                .config
                .assign_table_circuit(&system_config.zkvm_cs, &mut zkvm_witness)
                .unwrap();
            tracing::debug!("assign_table_circuit finish in {:?}", time.elapsed());

            if shard_ctx.is_first_shard() {
                let time = std::time::Instant::now();
                system_config
                    .mmu_config
                    .assign_init_table_circuit(
                        &system_config.zkvm_cs,
                        &mut zkvm_witness,
                        &pi,
                        &emul_result.final_mem_state.reg,
                        &emul_result.final_mem_state.mem,
                        &emul_result.final_mem_state.io,
                        &emul_result.final_mem_state.stack,
                    )
                    .unwrap();
                tracing::debug!("assign_init_table_circuit finish in {:?}", time.elapsed());
            } else {
                system_config
                    .mmu_config
                    .assign_init_table_circuit(
                        &system_config.zkvm_cs,
                        &mut zkvm_witness,
                        &pi,
                        &[],
                        &[],
                        &[],
                        &[],
                    )
                    .unwrap();
            }

            let time = std::time::Instant::now();
            system_config
                .mmu_config
                .assign_dynamic_init_table_circuit(
                    &system_config.zkvm_cs,
                    &mut zkvm_witness,
                    &pi,
                    &emul_result.final_mem_state.hints,
                    &emul_result.final_mem_state.heap,
                )
                .unwrap();
            tracing::debug!(
                "assign_dynamic_init_table_circuit finish in {:?}",
                time.elapsed()
            );
            let time = std::time::Instant::now();
            system_config
                .mmu_config
                .assign_continuation_circuit(
                    &system_config.zkvm_cs,
                    &shard_ctx,
                    &mut zkvm_witness,
                    &pi,
                    &emul_result.final_mem_state.reg,
                    &emul_result.final_mem_state.mem,
                    &emul_result.final_mem_state.io,
                    &emul_result.final_mem_state.hints,
                    &emul_result.final_mem_state.stack,
                    &emul_result.final_mem_state.heap,
                )
                .unwrap();
            tracing::debug!("assign_continuation_circuit finish in {:?}", time.elapsed());

            let time = std::time::Instant::now();
            zkvm_witness
                .assign_table_circuit::<ProgramTableCircuit<E>>(
                    &system_config.zkvm_cs,
                    &system_config.prog_config,
                    &program,
                )
                .unwrap();
            tracing::debug!("assign_table_circuit finish in {:?}", time.elapsed());

            if let Some(shard_ram_witnesses) =
                zkvm_witness.get_witness(&ShardRamCircuit::<E>::name())
            {
                let time = std::time::Instant::now();
                let shard_ram_ec_sum: SepticPoint<E::BaseField> = shard_ram_witnesses
                    .iter()
                    .filter(|shard_ram_witness| shard_ram_witness.num_instances[0] > 0)
                    .map(|shard_ram_witness| {
                        ShardRamCircuit::<E>::extract_ec_sum(
                            &system_config.mmu_config.ram_bus_circuit,
                            &shard_ram_witness.witness_rmms[0],
                        )
                    })
                    .sum();

                let xy = shard_ram_ec_sum
                    .x
                    .0
                    .iter()
                    .chain(shard_ram_ec_sum.y.0.iter());
                for (f, v) in xy.zip_eq(pi.shard_rw_sum.as_mut_slice()) {
                    *v = f.to_canonical_u64() as u32;
                }
                tracing::debug!("update pi shard_rw_sum finish in {:?}", time.elapsed());
            }

            Some((zkvm_witness, shard_ctx, pi))
        })
    })
}

// Encodes useful early return points of the e2e pipeline
#[derive(Default, Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub enum Checkpoint {
    PrepE2EProving,
    PrepWitnessGen,
    PrepVerify,
    #[default]
    Complete,
}

// Currently handles state required by the sanity check in `bin/e2e.rs`
// Future cases would require this to be an enum
pub type IntermediateState<E, PCS> = (Option<ZKVMProof<E, PCS>>, Option<ZKVMVerifyingKey<E, PCS>>);

/// Context construct from a program and given platform
pub struct E2EProgramCtx<E: ExtensionField> {
    pub program: Arc<Program>,
    pub platform: Platform,
    pub multi_prover: MultiProver,
    pub static_addrs: Vec<MemInitRecord>,
    pub pubio_len: usize,
    pub system_config: ConstraintSystemConfig<E>,
    pub reg_init: Vec<MemInitRecord>,
    pub io_init: Vec<MemInitRecord>,
    pub zkvm_fixed_traces: ZKVMFixedTraces<E>,
}

/// end-to-end pipeline result, stopping at a certain checkpoint
pub struct E2ECheckpointResult<E: ExtensionField, PCS: PolynomialCommitmentScheme<E>> {
    /// The proof generated by the pipeline, if any
    pub proofs: Option<Vec<ZKVMProof<E, PCS>>>,
    /// The verifying key generated by the pipeline, if any
    pub vk: Option<ZKVMVerifyingKey<E, PCS>>,
    /// The next step to run after the checkpoint
    next_step: Option<Box<dyn FnOnce()>>,
}

impl<E: ExtensionField, PCS: PolynomialCommitmentScheme<E>> E2ECheckpointResult<E, PCS> {
    pub fn next_step(self) {
        if let Some(next_step) = self.next_step {
            next_step();
        }
    }
}

/// Set up a program with the given platform
pub fn setup_program<E: ExtensionField>(
    program: Program,
    platform: Platform,
    multi_prover: MultiProver,
) -> E2EProgramCtx<E> {
    let static_addrs = init_static_addrs(&program);
    let pubio_len = platform.public_io.iter_addresses().len();
    let program_params = ProgramParams {
        platform: platform.clone(),
        program_size: next_pow2_instance_padding(program.instructions.len()),
        static_memory_len: static_addrs.len(),
        pubio_len,
    };
    let system_config = construct_configs::<E>(program_params);
    let reg_init = system_config.mmu_config.initial_registers();
    let io_init = MemPadder::new_mem_records_uninit(platform.public_io.clone(), pubio_len);

    // Generate fixed traces
    let zkvm_fixed_traces = generate_fixed_traces(
        &system_config,
        &reg_init,
        &static_addrs,
        &io_init.iter().map(|rec| rec.addr).collect_vec(),
        &program,
    );

    E2EProgramCtx {
        program: Arc::new(program),
        platform,
        multi_prover,
        static_addrs,
        pubio_len,
        system_config,
        reg_init,
        io_init,
        zkvm_fixed_traces,
    }
}

impl<E: ExtensionField> E2EProgramCtx<E> {
    pub fn keygen<PCS: PolynomialCommitmentScheme<E> + 'static>(
        self,
        max_num_variables: usize,
        security_level: SecurityLevel,
    ) -> (ZKVMProvingKey<E, PCS>, ZKVMVerifyingKey<E, PCS>) {
        let pcs_param =
            PCS::setup(1 << max_num_variables, security_level).expect("Basefold PCS setup");
        let (pp, vp) = PCS::trim(pcs_param, 1 << max_num_variables).expect("Basefold trim");
        let mut pk = self
            .system_config
            .zkvm_cs
            .clone()
            .key_gen::<PCS>(
                pp.clone(),
                vp.clone(),
                self.program.entry,
                self.zkvm_fixed_traces.clone(),
            )
            .expect("keygen failed");
        let vk = pk.get_vk_slow();
        pk.set_program_ctx(self);
        (pk, vk)
    }

    pub fn keygen_with_pb<
        PCS: PolynomialCommitmentScheme<E> + 'static,
        PB: ProverBackend<E = E, Pcs = PCS> + 'static,
    >(
        self,
        pb: &PB,
    ) -> (ZKVMProvingKey<E, PCS>, ZKVMVerifyingKey<E, PCS>) {
        let mut pk = self
            .system_config
            .zkvm_cs
            .clone()
            .key_gen::<PCS>(
                pb.get_pp().clone(),
                pb.get_vp().clone(),
                self.program.entry,
                self.zkvm_fixed_traces.clone(),
            )
            .expect("keygen failed");
        let vk = pk.get_vk_slow();
        pk.set_program_ctx(self);
        (pk, vk)
    }

    /// Setup init mem state
    pub fn setup_init_mem(&self, hints: &[u32], public_io: &[u32]) -> InitMemState {
        let mut io_init = self.io_init.clone();
        MemPadder::init_mem_records(&mut io_init, public_io);
        let hint_init = MemPadder::new_mem_records(
            self.platform.hints.clone(),
            hints.len().next_power_of_two(),
            hints,
        );

        InitMemState {
            mem: self.static_addrs.clone(),
            reg: self.reg_init.clone(),
            io: io_init,
            hints: hint_init,
            // stack/heap both init value 0 and range is dynamic
            stack: vec![],
            heap: vec![],
        }
    }
}

// Runs end-to-end pipeline, stopping at a certain checkpoint and yielding useful state.
//
// The return type is a pair of:
// 1. Explicit state
// 2. A no-input-no-ouptut closure
//
// (2.) is useful when you want to setup a certain action and run it
// elsewhere (i.e, in a benchmark)
// (1.) is useful for exposing state which must be further combined with
// state external to this pipeline (e.g, sanity check in bin/e2e.rs)

#[allow(clippy::too_many_arguments)]
pub fn run_e2e_with_checkpoint<
    E: ExtensionField + LkMultiplicityKey + serde::de::DeserializeOwned,
    PCS: PolynomialCommitmentScheme<E> + Serialize + 'static,
    PB: ProverBackend<E = E, Pcs = PCS> + 'static,
    PD: ProverDevice<PB> + 'static,
>(
    device: PD,
    program: Program,
    platform: Platform,
    multi_prover: MultiProver,
    hints: &[u32],
    public_io: &[u32],
    max_steps: usize,
    checkpoint: Checkpoint,
    // for debug purpose
    target_shard_id: Option<usize>,
) -> E2ECheckpointResult<E, PCS> {
    let start = std::time::Instant::now();
    let ctx = setup_program::<E>(program, platform, multi_prover);
    tracing::debug!("setup_program done in {:?}", start.elapsed());

    // Keygen
    let start = std::time::Instant::now();
    let (pk, vk) = ctx.keygen_with_pb(device.get_pb());
    tracing::debug!("keygen done in {:?}", start.elapsed());

    // New with prover
    let prover = ZKVMProver::new(pk.into(), device);

    let start = std::time::Instant::now();
    let init_full_mem = prover.setup_init_mem(hints, public_io);
    tracing::debug!("setup_init_mem done in {:?}", start.elapsed());

    // Generate witness
    let is_mock_proving = std::env::var("MOCK_PROVING").is_ok();
    if let Checkpoint::PrepE2EProving = checkpoint {
        return E2ECheckpointResult {
            proofs: None,
            vk: Some(vk),
            next_step: Some(Box::new(move || {
                _ = run_e2e_proof::<E, _, _, _>(
                    &prover,
                    &init_full_mem,
                    max_steps,
                    is_mock_proving,
                    target_shard_id,
                )
            })),
        };
    }

    // Emulate program
    let start = std::time::Instant::now();
    let emul_result = emulate_program(
        prover.pk.program_ctx.as_ref().unwrap().program.clone(),
        max_steps,
        &init_full_mem,
        &prover.pk.program_ctx.as_ref().unwrap().platform,
        &prover.pk.program_ctx.as_ref().unwrap().multi_prover,
        &prover.pk.program_ctx.as_ref().unwrap().system_config.config,
    );
    tracing::debug!("emulate done in {:?}", start.elapsed());

    // Clone some emul_result fields before consuming
    let exit_code = emul_result.exit_code;

    if let Checkpoint::PrepWitnessGen = checkpoint {
        return E2ECheckpointResult {
            proofs: None,
            vk: Some(vk),
            next_step: Some(Box::new(move || {
                // When we run e2e and halt before generate_witness, this implies we are going to
                // benchmark generate_witness performance. So we skip mock proving check on
                // `generate_witness` to avoid it affecting the benchmark result.
                _ = generate_witness(
                    &prover.pk.program_ctx.as_ref().unwrap().system_config,
                    emul_result,
                    prover.pk.program_ctx.as_ref().unwrap().program.clone(),
                    &prover.pk.program_ctx.as_ref().unwrap().platform,
                    &init_full_mem,
                    target_shard_id,
                )
            })),
        };
    }

    let zkvm_proofs = create_proofs_streaming(
        emul_result,
        &prover,
        is_mock_proving,
        target_shard_id,
        &init_full_mem,
    );

    if target_shard_id.is_some() {
        // skip verify as the proof are in-completed
        return E2ECheckpointResult {
            proofs: Some(zkvm_proofs),
            vk: Some(vk),
            next_step: None,
        };
    }

    let verifier = ZKVMVerifier::new(vk.clone());

    if let Checkpoint::PrepVerify = checkpoint {
        return E2ECheckpointResult {
            proofs: Some(zkvm_proofs.clone()),
            vk: Some(vk),
            next_step: Some(Box::new(move || {
                run_e2e_verify(&verifier, zkvm_proofs, exit_code, max_steps)
            })),
        };
    }

    let start = std::time::Instant::now();
    run_e2e_verify(&verifier, zkvm_proofs.clone(), exit_code, max_steps);
    tracing::debug!("verified in {:?}", start.elapsed());

    E2ECheckpointResult {
        proofs: Some(zkvm_proofs),
        vk: Some(vk),
        next_step: None,
    }
}

// Runs program emulation + witness generation + proving
#[tracing::instrument(skip_all, name = "run_e2e_proof", fields(profiling_1), level = "trace")]
#[allow(clippy::too_many_arguments)]
pub fn run_e2e_proof<
    E: ExtensionField + LkMultiplicityKey,
    PCS: PolynomialCommitmentScheme<E> + Serialize + 'static,
    PB: ProverBackend<E = E, Pcs = PCS> + 'static,
    PD: ProverDevice<PB> + 'static,
>(
    prover: &ZKVMProver<E, PCS, PB, PD>,
    init_full_mem: &InitMemState,
    max_steps: usize,
    is_mock_proving: bool,
    // for debug purpose
    target_shard_id: Option<usize>,
) -> Vec<ZKVMProof<E, PCS>> {
    let ctx = prover.pk.program_ctx.as_ref().unwrap();
    // Emulate program
    let emul_result = emulate_program(
        ctx.program.clone(),
        max_steps,
        init_full_mem,
        &ctx.platform,
        &ctx.multi_prover,
        &ctx.system_config.config,
    );
    create_proofs_streaming(
        emul_result,
        prover,
        is_mock_proving,
        target_shard_id,
        init_full_mem,
    )
}

/// defines a lightweight CPU -> GPU pipeline for witness generation and proof creation.
/// This enables overlapped execution such that while the GPU is proving shard `i`,
/// the CPU is already generating the witness for shard `i+1`.
///
/// With `channel::bounded(0)` the pipeline behaves as a strict rendezvous:
/// - CPU generates the next witness while GPU is proving the current one.
/// - Once the CPU finishes generating `wN`, it blocks on `send(wN)`
///   until the GPU finishes proving `wN–1` and calls `recv()`.
///
/// This ensures:
///   - At most **one** witness on the GPU, and
///   - At most **one** fully-generated witness waiting in CPU memory,
///     keeping memory usage strictly bounded (2 witnesses max).
///
/// Timeline with bounded(0):
///
/// CPU gen(w1)→gen(w2)→wait→gen(w3)→wait, while GPU wait→prove(w1)→prove(w2)→prove(w3)→prove(w4).
///
/// CPU never runs ahead more than one witness, but CPU/GPU still overlap fully.
///
/// This improves total proving throughput by hiding CPU witness generation latency
/// behind GPU proof execution.
///
/// in pure CPU mode, the pipeline is disabled and the prover falls back to
/// fully sequential execution. Witness generation and proof creation run
/// one after another with no overlap.
fn create_proofs_streaming<
    E: ExtensionField + LkMultiplicityKey,
    PCS: PolynomialCommitmentScheme<E> + Serialize + 'static,
    PB: ProverBackend<E = E, Pcs = PCS> + 'static,
    PD: ProverDevice<PB> + 'static,
>(
    emulation_result: EmulationResult,
    prover: &ZKVMProver<E, PCS, PB, PD>,
    is_mock_proving: bool,
    target_shard_id: Option<usize>,
    init_mem_state: &InitMemState,
) -> Vec<ZKVMProof<E, PCS>> {
    let ctx = prover.pk.program_ctx.as_ref().unwrap();
    let proofs = info_span!("[ceno] app_prove.inner").in_scope(|| {
        #[cfg(feature = "gpu")]
        {
            use crossbeam::channel;
            let (tx, rx) = channel::bounded(0);
            std::thread::scope(|s| {
                // pipeline cpu/gpu workload
                // cpu producer
                s.spawn({
                    move || {
                        let wit_iter = generate_witness(
                            &ctx.system_config,
                            emulation_result,
                            ctx.program.clone(),
                            &ctx.platform,
                            init_mem_state,
                            target_shard_id,
                        );

                        let wit_iter = if let Some(target_shard_id) = target_shard_id {
                            Box::new(wit_iter.skip(target_shard_id)) as Box<dyn Iterator<Item = _>>
                        } else {
                            Box::new(wit_iter)
                        };

                        for proof_input in wit_iter {
                            if tx.send(proof_input).is_err() {
                                tracing::warn!(
                                    "witness consumer dropped; stopping witness generation early"
                                );
                                break;
                            }
                        }
                    }
                });

                // gpu consumer
                {
                    let mut proofs = Vec::new();
                    let mut proof_err = None;
                    let mut rx = rx;
                    while let Ok((zkvm_witness, shard_ctx, pi)) = rx.recv() {
                        if is_mock_proving {
                            MockProver::assert_satisfied_full(
                                &shard_ctx,
                                &ctx.system_config.zkvm_cs,
                                ctx.zkvm_fixed_traces.clone(),
                                &zkvm_witness,
                                &pi,
                                &ctx.program,
                            );
                            tracing::info!("Mock proving passed");
                        }

                        let transcript = Transcript::new(b"riscv");
                        let start = std::time::Instant::now();
                        match prover.create_proof(&shard_ctx, zkvm_witness, pi, transcript) {
                            Ok(zkvm_proof) => {
                                tracing::debug!(
                                    "{}th shard proof created in {:?}",
                                    shard_ctx.shard_id,
                                    start.elapsed()
                                );
                                proofs.push(zkvm_proof);
                            }
                            Err(err) => {
                                proof_err = Some(err);
                                break;
                            }
                        }
                    }
                    drop(rx);
                    if let Some(err) = proof_err {
                        panic!("create_proof failed: {err:?}");
                    }
                    proofs
                }
            })
        }

        #[cfg(not(feature = "gpu"))]
        {
            // Generate witness
            let wit_iter = generate_witness(
                &ctx.system_config,
                emulation_result,
                ctx.program.clone(),
                &ctx.platform,
                init_mem_state,
                target_shard_id,
            );

            let wit_iter = if let Some(target_shard_id) = target_shard_id {
                Box::new(wit_iter.skip(target_shard_id)) as Box<dyn Iterator<Item = _>>
            } else {
                Box::new(wit_iter)
            };

            wit_iter
                .map(|(zkvm_witness, shard_ctx, pi)| {
                    if is_mock_proving {
                        MockProver::assert_satisfied_full(
                            &shard_ctx,
                            &ctx.system_config.zkvm_cs,
                            ctx.zkvm_fixed_traces.clone(),
                            &zkvm_witness,
                            &pi,
                            &ctx.program,
                        );
                        tracing::info!("Mock proving passed");
                    }

                    let transcript = Transcript::new(b"riscv");
                    let start = std::time::Instant::now();
                    let zkvm_proof = prover
                        .create_proof(&shard_ctx, zkvm_witness, pi, transcript)
                        .expect("create_proof failed");
                    tracing::debug!(
                        "{}th shard proof created in {:?}",
                        shard_ctx.shard_id,
                        start.elapsed()
                    );
                    // only show e2e stats in cpu mode
                    tracing::info!("e2e proof stat: {}", zkvm_proof);
                    zkvm_proof
                })
                .collect_vec()
        }
    });
    metrics::gauge!("num_shards").set(proofs.len() as f64);

    // Currently, due to mixed usage with other GPU backends,
    // we need to trim ceno-gpu's memory pool while still retaining 424MB.
    // Once the GPU backend is unified, skipping this trim
    // could improve performance by a few seconds.
    #[cfg(feature = "gpu")]
    {
        use gkr_iop::gpu::gpu_prover::*;

        info_span!("[ceno] trim_gpu_mem_pool").in_scope(|| {
            let cuda_hal = get_cuda_hal().unwrap();
            cuda_hal.inner().trim_mem_pool().unwrap();
            cuda_hal.inner().synchronize().unwrap();
        });
    };

    proofs
}

pub fn run_e2e_verify<E: ExtensionField, PCS: PolynomialCommitmentScheme<E>>(
    verifier: &ZKVMVerifier<E, PCS>,
    zkvm_proofs: Vec<ZKVMProof<E, PCS>>,
    exit_code: Option<u32>,
    max_steps: usize,
) {
    let transcripts = (0..zkvm_proofs.len())
        .map(|_| Transcript::new(b"riscv"))
        .collect_vec();
    assert!(
        verifier
            .verify_proofs_halt(zkvm_proofs, transcripts, exit_code.is_some())
            .expect("verify proof return with error"),
    );
    match exit_code {
        Some(0) => tracing::info!("exit code 0. Success."),
        Some(code) => tracing::error!("exit code {}. Failure.", code),
        None => tracing::error!("Unfinished execution. max_steps={:?}.", max_steps),
    }
}

#[cfg(debug_assertions)]
fn debug_memory_ranges<'a, T: Tracer, I: Iterator<Item = &'a MemFinalRecord>>(
    vm: &VMState<T>,
    mem_final: I,
) {
    let accessed_addrs = vm
        .tracer()
        .final_accesses()
        .iter()
        .filter(|&(_, cycle)| *cycle != 0)
        .map(|(&addr, _)| addr.baddr())
        .filter(|addr| vm.platform().can_read(addr.0))
        .collect_vec();

    let handled_addrs = mem_final
        .filter(|rec| rec.cycle != 0)
        .map(|rec| ByteAddr(rec.addr))
        .collect::<HashSet<_>>();

    tracing::trace!(
        "Memory range (accessed): {:?}",
        format_segments(vm.platform(), accessed_addrs.iter().copied())
    );
    tracing::trace!(
        "Memory range (handled):  {:?}",
        format_segments(vm.platform(), handled_addrs.iter().copied())
    );

    for addr in &accessed_addrs {
        assert!(handled_addrs.contains(addr), "unhandled addr: {:?}", addr);
    }
}

#[cfg(debug_assertions)]
fn format_segments(
    platform: &Platform,
    addrs: impl Iterator<Item = ByteAddr>,
) -> HashMap<String, MinMaxResult<ByteAddr>> {
    addrs
        .into_grouping_map_by(|addr| format_segment(platform, addr.0))
        .minmax()
}

#[cfg(debug_assertions)]
fn format_segment(platform: &Platform, addr: u32) -> String {
    format!(
        "{}{}",
        if platform.can_read(addr) { "R" } else { "-" },
        if platform.can_write(addr) { "W" } else { "-" },
    )
}

pub fn verify<E: ExtensionField, PCS: PolynomialCommitmentScheme<E> + serde::Serialize>(
    zkvm_proofs: Vec<ZKVMProof<E, PCS>>,
    verifier: &ZKVMVerifier<E, PCS>,
) -> Result<(), ZKVMError> {
    #[cfg(debug_assertions)]
    {
        Instrumented::<<<E as ExtensionField>::BaseField as PoseidonField>::P>::clear_metrics();
    }
    let transcripts = (0..zkvm_proofs.len())
        .map(|_| Transcript::new(b"riscv"))
        .collect_vec();
    let has_halt = zkvm_proofs.last().unwrap().has_halt(&verifier.vk);
    verifier.verify_proofs_halt(zkvm_proofs, transcripts, has_halt)?;
    // print verification statistics such as hash count
    #[cfg(debug_assertions)]
    {
        tracing::debug!(
            "instrumented metrics\n{}",
            Instrumented::<<<E as ExtensionField>::BaseField as PoseidonField>::P>::format_metrics(
            )
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::e2e::{MultiProver, ShardContextBuilder, StepCellExtractor};
    use ceno_emul::{CENO_PLATFORM, Cycle, FullTracer, InsnKind, StepRecord, Word};
    use itertools::Itertools;

    struct UniformStepExtractor;

    impl StepCellExtractor for &UniformStepExtractor {
        fn cells_for_kind(&self, _kind: InsnKind, _rs1_value: Option<Word>) -> u64 {
            1
        }
    }

    #[test]
    fn test_single_prover_shard_ctx() {
        for (name, max_cycle_per_shard, executed_instruction, expected_shard) in [
            ("1 shard", 1 << 6, (1 << 6) / 4 - 1, 1),
            (
                "max inst + 10, split to 2 shard",
                1 << 6,
                (1 << 6) / 4 + 10,
                2,
            ),
        ] {
            test_single_shard_ctx_helper(
                name,
                max_cycle_per_shard,
                executed_instruction,
                expected_shard,
            );
        }
    }

    fn test_single_shard_ctx_helper(
        name: &str,
        max_cycle_per_shard: Cycle,
        executed_instruction: usize,
        expected_shard: usize,
    ) {
        let mut shard_ctx_builder = ShardContextBuilder::new(
            &MultiProver::new(0, 1, u64::MAX, max_cycle_per_shard),
            CENO_PLATFORM.clone(),
        );
        let steps = (0..executed_instruction)
            .map(|i| {
                StepRecord::new_ecall_any(FullTracer::SUBCYCLES_PER_INSN * (i + 1) as u64, 0.into())
            })
            .collect_vec();
        for step in &steps {
            shard_ctx_builder.observe_step_budget(
                step.cycle().saturating_sub(FullTracer::SUBCYCLES_PER_INSN),
                (&UniformStepExtractor {}).extract_cells(step),
            );
        }
        let max_cycle = steps
            .last()
            .map(|step| step.cycle() + FullTracer::SUBCYCLES_PER_INSN)
            .unwrap_or(FullTracer::SUBCYCLES_PER_INSN);
        shard_ctx_builder.finalize_plan(max_cycle);
        let mut steps_iter = steps.into_iter();
        let shard_ctx = std::iter::from_fn(|| {
            shard_ctx_builder
                .position_next_shard(&mut steps_iter, |_| {})
                .map(|(ctx, _)| ctx)
        })
        .collect_vec();

        assert_eq!(shard_ctx.len(), expected_shard, "{name} test case failed");
        assert_eq!(
            shard_ctx.first().unwrap().cur_shard_cycle_range.start,
            4,
            "{name} test case failed"
        );
        assert_eq!(
            shard_ctx.last().unwrap().cur_shard_cycle_range.end,
            executed_instruction * 4 + 4,
            "{name} test case failed"
        );
        if shard_ctx.len() > 1 {
            for pair in shard_ctx.windows(2) {
                assert_eq!(
                    pair[0].cur_shard_cycle_range.end, pair[1].cur_shard_cycle_range.start,
                    "{name} test case failed"
                );
            }
        }
    }
}
