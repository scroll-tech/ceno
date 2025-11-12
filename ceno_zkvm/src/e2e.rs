use crate::{
    error::ZKVMError,
    instructions::riscv::{DummyExtraConfig, MemPadder, MmuConfig, Rv32imConfig},
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
    Addr, ByteAddr, CENO_PLATFORM, Cycle, EmuContext, InsnKind, IterAddresses, NextCycleAccess,
    Platform, Program, StepRecord, Tracer, VMState, WORD_SIZE, Word, WordAddr,
    host_utils::read_all_messages,
};
use clap::ValueEnum;
use either::Either;
use ff_ext::{ExtensionField, SmallField};
#[cfg(debug_assertions)]
use ff_ext::{Instrumented, PoseidonField};
use gkr_iop::{RAMType, hal::ProverBackend};
use itertools::{Itertools, MinMaxResult, chain};
use mpcs::{PolynomialCommitmentScheme, SecurityLevel};
use multilinear_extensions::util::max_usable_threads;
use rustc_hash::FxHashSet;
use serde::Serialize;
use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    sync::Arc,
};
use transcript::BasicTranscript as Transcript;
use witness::next_pow2_instance_padding;

pub const DEFAULT_MIN_CYCLE_PER_SHARDS: Cycle = 1 << 24;
pub const DEFAULT_MAX_CYCLE_PER_SHARDS: Cycle = 1 << 27;
pub const DEFAULT_CROSS_SHARD_ACCESS_LIMIT: usize = 1 << 20;

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

pub struct FullMemState<Record> {
    pub mem: Vec<Record>,
    pub io: Vec<Record>,
    pub reg: Vec<Record>,
    pub hints: Vec<Record>,
    pub stack: Vec<Record>,
    pub heap: Vec<Record>,
}

type InitMemState = FullMemState<MemInitRecord>;
type FinalMemState = FullMemState<MemFinalRecord>;

pub struct EmulationResult<'a> {
    pub exit_code: Option<u32>,
    pub all_records: Vec<StepRecord>,
    pub final_mem_state: FinalMemState,
    pub pi: PublicValues,
    pub shard_ctxs: Vec<ShardContext<'a>>,
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
    pub min_cycle_per_shard: Cycle,
    pub max_cycle_per_shard: Cycle,
}

impl MultiProver {
    pub fn new(
        prover_id: usize,
        max_provers: usize,
        min_cycle_per_shard: Cycle,
        max_cycle_per_shard: Cycle,
    ) -> Self {
        assert!(prover_id < max_provers);
        Self {
            prover_id,
            max_provers,
            min_cycle_per_shard,
            max_cycle_per_shard,
        }
    }
}

impl Default for MultiProver {
    fn default() -> Self {
        Self {
            prover_id: 0,
            max_provers: 1,
            min_cycle_per_shard: DEFAULT_MIN_CYCLE_PER_SHARDS,
            max_cycle_per_shard: DEFAULT_MAX_CYCLE_PER_SHARDS,
        }
    }
}

pub struct ShardContext<'a> {
    shard_id: usize,
    num_shards: usize,
    max_cycle: Cycle,
    addr_future_accesses: Arc<NextCycleAccess>,
    // this is only updated in first shard
    addr_accessed_thread_based_first_shard:
        Either<Vec<FxHashSet<WordAddr>>, &'a mut FxHashSet<WordAddr>>,
    read_records_tbs:
        Either<Vec<BTreeMap<WordAddr, RAMRecord>>, &'a mut BTreeMap<WordAddr, RAMRecord>>,
    write_records_tbs:
        Either<Vec<BTreeMap<WordAddr, RAMRecord>>, &'a mut BTreeMap<WordAddr, RAMRecord>>,
    pub cur_shard_cycle_range: std::ops::Range<usize>,
    pub expected_inst_per_shard: usize,
    pub max_num_cross_shard_accesses: usize,
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
            addr_accessed_thread_based_first_shard: Either::Left(
                (0..max_threads)
                    .map(|_| Default::default())
                    .collect::<Vec<_>>(),
            ),
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
            cur_shard_cycle_range: Tracer::SUBCYCLES_PER_INSN as usize..usize::MAX,
            expected_inst_per_shard: usize::MAX,
            max_num_cross_shard_accesses,
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
    pub fn new(
        multi_prover: MultiProver,
        executed_instructions: usize,
        addr_future_accesses: NextCycleAccess,
    ) -> Vec<Self> {
        let min_cycle_per_shard = multi_prover.min_cycle_per_shard;
        let max_cycle_per_shard = multi_prover.max_cycle_per_shard;
        assert!(
            min_cycle_per_shard < max_cycle_per_shard,
            "invalid input: min_cycle_per_shard {min_cycle_per_shard} >= max_cycle_per_shard {max_cycle_per_shard}"
        );
        let subcycle_per_insn = Tracer::SUBCYCLES_PER_INSN as usize;
        let max_threads = max_usable_threads();

        let max_num_cross_shard_accesses = std::env::var("CENO_CROSS_SHARD_LIMIT")
            .map(|v| v.parse().unwrap_or(DEFAULT_CROSS_SHARD_ACCESS_LIMIT))
            .unwrap_or(DEFAULT_CROSS_SHARD_ACCESS_LIMIT);

        // strategies
        // 0. set cur_num_shards = num_provers
        // 1. split instructions evenly by cur_num_shards
        // 2. stop if min_inst <= shard instructions < max_inst
        // 3.1 if shard instructions >= max_inst, update cur_num_shards += 1 then goes to 1
        // 3.2 if shard instructions < min_inst, update cur_num_shards -= 1 then goes to 1
        const MAX_ITER: usize = 1000;
        let mut num_shards = multi_prover.max_provers;
        let mut last_shard_count = None;
        let mut expected_inst_per_shard = 0;
        for _ in 0..MAX_ITER {
            expected_inst_per_shard = executed_instructions.div_ceil(num_shards);
            let expected_cycle_per_shard = expected_inst_per_shard * subcycle_per_insn;
            if (min_cycle_per_shard as usize..max_cycle_per_shard as usize)
                .contains(&expected_cycle_per_shard)
            {
                break;
            }

            if expected_cycle_per_shard >= max_cycle_per_shard as usize {
                num_shards += 1;
            } else if expected_cycle_per_shard < min_cycle_per_shard as usize {
                if num_shards == 1 {
                    break;
                }
                num_shards -= 1;
            }

            // Detect oscillation (no progress)
            if let Some(last_shard_count) = last_shard_count
                && last_shard_count == num_shards
            {
                panic!(
                    "no convergence detected: shard count stuck at {num_shards}, \
                 per-shard={expected_inst_per_shard}"
                );
            }

            last_shard_count = Some(num_shards);
        }

        // generated shards belong to this prover id
        let prover_id_shards_mapping =
            Self::distribute_shards_into_provers(num_shards, multi_prover.max_provers);
        assert!(multi_prover.prover_id < prover_id_shards_mapping.len());

        let max_cycle = (executed_instructions + 1) * subcycle_per_insn; // cycle start from subcycle_per_insn
        let addr_future_accesses = Arc::new(addr_future_accesses);

        // sum for all shards before prover id
        let start = prover_id_shards_mapping
            .iter()
            .take(multi_prover.prover_id)
            .sum::<usize>();
        // length of shards belong to prover id
        let shard_len = prover_id_shards_mapping[multi_prover.prover_id];
        tracing::info!(
            "total num_shards {num_shards}, num_shards belong to this prover: {shard_len}, multi-prover {:?}",
            multi_prover
        );
        let end = start + shard_len;
        (start..end)
            .map(|shard_id| {
                let cur_shard_cycle_range = (shard_id * expected_inst_per_shard * subcycle_per_insn
                    + subcycle_per_insn)
                    ..((shard_id + 1) * expected_inst_per_shard * subcycle_per_insn
                        + subcycle_per_insn)
                        .min(max_cycle);
                ShardContext {
                    shard_id,
                    num_shards,
                    max_cycle: max_cycle as Cycle,
                    addr_future_accesses: addr_future_accesses.clone(),
                    addr_accessed_thread_based_first_shard: Either::Left(
                        (0..max_threads)
                            .map(|_| Default::default())
                            .collect::<Vec<_>>(),
                    ),
                    // TODO with_capacity optimisation
                    read_records_tbs: Either::Left(
                        (0..max_threads)
                            .map(|_| BTreeMap::new())
                            .collect::<Vec<_>>(),
                    ),
                    // TODO with_capacity optimisation
                    write_records_tbs: Either::Left(
                        (0..max_threads)
                            .map(|_| BTreeMap::new())
                            .collect::<Vec<_>>(),
                    ),
                    cur_shard_cycle_range,
                    expected_inst_per_shard,
                    max_num_cross_shard_accesses,
                }
            })
            .collect_vec()
    }

    pub fn get_forked(&mut self) -> Vec<ShardContext<'_>> {
        match (
            &mut self.read_records_tbs,
            &mut self.write_records_tbs,
            &mut self.addr_accessed_thread_based_first_shard,
        ) {
            (
                Either::Left(read_thread_based_record_storage),
                Either::Left(write_thread_based_record_storage),
                Either::Left(addr_accessed_thread_based_first_shard),
            ) => read_thread_based_record_storage
                .iter_mut()
                .zip(write_thread_based_record_storage.iter_mut())
                .zip(addr_accessed_thread_based_first_shard.iter_mut())
                .map(
                    |((read, write), addr_accessed_thread_based_first_shard)| ShardContext {
                        shard_id: self.shard_id,
                        num_shards: self.num_shards,
                        max_cycle: self.max_cycle,
                        addr_future_accesses: self.addr_future_accesses.clone(),
                        addr_accessed_thread_based_first_shard: Either::Right(
                            addr_accessed_thread_based_first_shard,
                        ),
                        read_records_tbs: Either::Right(read),
                        write_records_tbs: Either::Right(write),
                        cur_shard_cycle_range: self.cur_shard_cycle_range.clone(),
                        expected_inst_per_shard: self.expected_inst_per_shard,
                        max_num_cross_shard_accesses: self.max_num_cross_shard_accesses,
                    },
                )
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

    #[inline(always)]
    pub fn extract_shard_id(&self, cycle: Cycle) -> usize {
        let subcycle_per_insn = Tracer::SUBCYCLES_PER_INSN;
        let per_shard_cycles =
            (self.expected_inst_per_shard as u64).saturating_mul(subcycle_per_insn);
        ((cycle.saturating_sub(subcycle_per_insn)) / per_shard_cycles) as usize
    }

    #[inline(always)]
    pub fn aligned_prev_ts(&self, prev_cycle: Cycle) -> Cycle {
        let mut ts = prev_cycle.saturating_sub(self.current_shard_offset_cycle());
        if ts < Tracer::SUBCYCLES_PER_INSN {
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
        (self.cur_shard_cycle_range.start as Cycle) - Tracer::SUBCYCLES_PER_INSN
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
        self.addr_future_accesses
            .get(cycle as usize)
            .and_then(|res| {
                if res.len() == 1 {
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
        // check read from external mem bus
        // exclude first shard
        if self.before_current_shard_cycle(prev_cycle)
            && self.is_in_current_shard(cycle)
            && !self.is_first_shard()
        {
            let prev_shard_id = self.extract_shard_id(prev_cycle);
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

        if self.is_first_shard() {
            let addr_accessed = self
                .addr_accessed_thread_based_first_shard
                .as_mut()
                .right()
                .expect("illegal type");
            addr_accessed.insert(addr);
        }
    }

    /// merge map from different thread, which keep the largest cycle when matched same address
    pub fn get_addr_accessed_first_shard(&self) -> FxHashSet<WordAddr> {
        let mut merged = FxHashSet::default();
        let addr_accessed_thread_based_first_shard =
            match &self.addr_accessed_thread_based_first_shard {
                Either::Left(addr_accessed_thread_based_first_shard) => {
                    addr_accessed_thread_based_first_shard
                }
                Either::Right(_) => panic!("invalid type"),
            };

        for s in addr_accessed_thread_based_first_shard {
            merged.extend(s);
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

pub fn emulate_program<'a>(
    program: Arc<Program>,
    max_steps: usize,
    init_mem_state: &InitMemState,
    platform: &Platform,
    multi_prover: &MultiProver,
) -> EmulationResult<'a> {
    let InitMemState {
        mem: mem_init,
        io: io_init,
        reg: reg_init,
        hints: hints_init,
        stack: _,
        heap: _,
    } = init_mem_state;

    let mut vm: VMState = VMState::new(platform.clone(), program);

    for record in chain!(hints_init, io_init) {
        vm.init_memory(record.addr.into(), record.value);
    }

    let all_records_result: Result<Vec<StepRecord>, _> =
        vm.iter_until_halt().take(max_steps).collect();

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
    let all_records = all_records_result.expect("vm exec failed");

    // Find the exit code from the HALT step, if halting at all.
    let exit_code = all_records
        .iter()
        .rev()
        .find(|record| {
            record.insn().kind == InsnKind::ECALL
                && record.rs1().unwrap().value == Platform::ecall_halt()
        })
        .and_then(|halt_record| halt_record.rs2())
        .map(|rs2| rs2.value);

    let final_access = vm.tracer().final_accesses();
    let end_cycle = vm.tracer().cycle();
    let insts = vm.tracer().executed_insts();
    tracing::info!("program executed {insts} instructions in {end_cycle} cycles");

    let pi = PublicValues::new(
        exit_code.unwrap_or(0),
        vm.program().entry,
        Tracer::SUBCYCLES_PER_INSN,
        vm.get_pc().into(),
        end_cycle,
        multi_prover.prover_id as u32,
        io_init.iter().map(|rec| rec.value).collect_vec(),
        vec![0; SEPTIC_EXTENSION_DEGREE * 2], // point_at_infinity
    );

    // Find the final register values and cycles.
    let reg_final = reg_init
        .iter()
        .map(|rec| {
            let index = rec.addr as usize;
            if index < VMState::REG_COUNT {
                let vma: WordAddr = Platform::register_vma(index).into();
                MemFinalRecord {
                    ram_type: RAMType::Register,
                    addr: rec.addr,
                    value: vm.peek_register(index),
                    init_value: rec.value,
                    cycle: *final_access.get(&vma).unwrap_or(&0),
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
                cycle: *final_access.get(&vma).unwrap_or(&0),
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
            cycle: *final_access.get(&rec.addr.into()).unwrap_or(&0),
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
            cycle: *final_access.get(&rec.addr.into()).unwrap_or(&0),
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
                    cycle: *final_access.get(&vma).unwrap_or(&0),
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
                    cycle: *final_access.get(&vma).unwrap_or(&0),
                }
            })
            .collect_vec()
    } else {
        vec![]
    };

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

    let shard_ctxs = ShardContext::new(
        multi_prover.clone(),
        insts,
        vm.take_tracer().next_accesses(),
    );

    EmulationResult {
        pi,
        exit_code,
        all_records,
        shard_ctxs,
        final_mem_state: FinalMemState {
            reg: reg_final,
            io: io_final,
            mem: mem_final,
            hints: hints_final,
            stack: stack_final,
            heap: heap_final,
        },
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
            ..CENO_PLATFORM
        },
    };

    let prog_data = program.image.keys().copied().collect::<BTreeSet<_>>();

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

pub struct ConstraintSystemConfig<'a, E: ExtensionField> {
    pub zkvm_cs: ZKVMConstraintSystem<E>,
    pub config: Rv32imConfig<E>,
    pub mmu_config: MmuConfig<'a, E>,
    pub dummy_config: DummyExtraConfig<E>,
    pub prog_config: ProgramTableConfig,
}

pub fn construct_configs<'a, E: ExtensionField>(
    program_params: ProgramParams,
) -> ConstraintSystemConfig<'a, E> {
    let mut zkvm_cs = ZKVMConstraintSystem::new_with_platform(program_params);

    let config = Rv32imConfig::<E>::construct_circuits(&mut zkvm_cs);
    let mmu_config = MmuConfig::<E>::construct_circuits(&mut zkvm_cs);
    let dummy_config = DummyExtraConfig::<E>::construct_circuits(&mut zkvm_cs);
    let prog_config = zkvm_cs.register_table_circuit::<ProgramTableCircuit<E>>();
    zkvm_cs.register_global_state::<GlobalState>();
    ConstraintSystemConfig {
        zkvm_cs,
        config,
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
    program: &Program,
) -> impl Iterator<Item = (ZKVMWitnesses<E>, ShardContext<'a>, PublicValues)> {
    let shard_ctxs = std::mem::take(&mut emul_result.shard_ctxs);
    assert!(!shard_ctxs.is_empty());
    let mut all_records = std::mem::take(&mut emul_result.all_records);
    assert!(!all_records.is_empty());

    tracing::debug!(
        "first shard cycle range {:?}",
        shard_ctxs[0].cur_shard_cycle_range
    );
    // clean up all records before first shard start cycle, as it's not belong to current prover
    let start = all_records.iter().position(|step| {
        shard_ctxs[0]
            .cur_shard_cycle_range
            .contains(&(step.cycle() as usize))
    });

    if let Some(start) = start {
        tracing::debug!("drop {} records as not belong to current shard", start);
        // Drop everything before `start` efficiently
        let tail = all_records.split_off(start);
        all_records = tail;
    }

    let pi = std::mem::take(&mut emul_result.pi);
    shard_ctxs.into_iter().map(move |mut shard_ctx| {
        // assume public io clone low cost
        let mut pi = pi.clone();
        let n = all_records
            .iter()
            .take_while(|step| shard_ctx.is_in_current_shard(step.cycle()))
            .count();
        let mut filtered_steps = all_records.split_off(n); // moves pointer boundary, no mem shift
        std::mem::swap(&mut all_records, &mut filtered_steps);

        tracing::debug!("{}th shard collect {n} steps", shard_ctx.shard_id);
        let current_shard_offset_cycle = shard_ctx.current_shard_offset_cycle();
        let current_shard_end_cycle = filtered_steps.last().unwrap().cycle()
            + Tracer::SUBCYCLES_PER_INSN
            - current_shard_offset_cycle;
        let current_shard_init_pc = if shard_ctx.is_first_shard() {
            program.entry
        } else {
            filtered_steps[0].pc().before.0
        };
        let current_shard_end_pc = filtered_steps.last().unwrap().pc().after.0;

        let mut zkvm_witness = ZKVMWitnesses::default();
        // assign opcode circuits
        let dummy_records = system_config
            .config
            .assign_opcode_circuit(
                &system_config.zkvm_cs,
                &mut shard_ctx,
                &mut zkvm_witness,
                filtered_steps,
            )
            .unwrap();
        system_config
            .dummy_config
            .assign_opcode_circuit(
                &system_config.zkvm_cs,
                &mut shard_ctx,
                &mut zkvm_witness,
                dummy_records,
            )
            .unwrap();
        zkvm_witness.finalize_lk_multiplicities();

        // assign table circuits
        system_config
            .config
            .assign_table_circuit(&system_config.zkvm_cs, &mut zkvm_witness)
            .unwrap();

        if shard_ctx.is_first_shard() {
            // assign init table on first shard
            system_config
                .mmu_config
                .assign_init_table_circuit(
                    &system_config.zkvm_cs,
                    &mut zkvm_witness,
                    &emul_result.final_mem_state.reg,
                    &emul_result.final_mem_state.mem,
                    &emul_result.final_mem_state.io,
                    &emul_result.final_mem_state.hints,
                    &emul_result.final_mem_state.stack,
                    &emul_result.final_mem_state.heap,
                )
                .unwrap();
        } else {
            // empty assignment
            system_config
                .mmu_config
                .assign_init_table_circuit(
                    &system_config.zkvm_cs,
                    &mut zkvm_witness,
                    &[],
                    &[],
                    &[],
                    &[],
                    &[],
                    &[],
                )
                .unwrap();
        }

        // assign continuation circuit
        system_config
            .mmu_config
            .assign_continuation_circuit(
                &system_config.zkvm_cs,
                &shard_ctx,
                &mut zkvm_witness,
                &emul_result.final_mem_state.reg,
                &emul_result.final_mem_state.mem,
                &emul_result.final_mem_state.io,
                &emul_result.final_mem_state.hints,
                &emul_result.final_mem_state.stack,
                &emul_result.final_mem_state.heap,
            )
            .unwrap();

        // assign program circuit
        zkvm_witness
            .assign_table_circuit::<ProgramTableCircuit<E>>(
                &system_config.zkvm_cs,
                &system_config.prog_config,
                program,
            )
            .unwrap();

        pi.init_pc = current_shard_init_pc;
        pi.init_cycle = Tracer::SUBCYCLES_PER_INSN;
        pi.shard_id = shard_ctx.shard_id as u32;
        pi.end_pc = current_shard_end_pc;
        pi.end_cycle = current_shard_end_cycle;
        // set shard ram bus expected output to pi
        let shard_ram_witnesses = zkvm_witness.get_circuit_witness(&ShardRamCircuit::<E>::name());

        if let Some(shard_ram_witnesses) = shard_ram_witnesses {
            let shard_ram_digest: SepticPoint<E::BaseField> = shard_ram_witnesses
                .iter()
                .filter(|shard_ram_witness| shard_ram_witness.num_instances[0] > 0)
                .map(|shard_ram_witness| {
                    ShardRamCircuit::<E>::extract_ec_sum(
                        &system_config.mmu_config.ram_bus_circuit,
                        &shard_ram_witness.witness_rmms[0],
                    )
                })
                .sum();

            let xy = shard_ram_digest
                .x
                .0
                .iter()
                .chain(shard_ram_digest.y.0.iter());
            for (f, v) in xy.zip_eq(pi.shard_rw_sum.as_mut_slice()) {
                *v = f.to_canonical_u64() as u32;
            }
        }

        (zkvm_witness, shard_ctx, pi)
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
pub struct E2EProgramCtx<'a, E: ExtensionField> {
    pub program: Arc<Program>,
    pub platform: Platform,
    pub multi_prover: MultiProver,
    pub static_addrs: Vec<MemInitRecord>,
    pub pubio_len: usize,
    pub system_config: ConstraintSystemConfig<'a, E>,
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
pub fn setup_program<'a, E: ExtensionField>(
    program: Program,
    platform: Platform,
    multi_prover: MultiProver,
) -> E2EProgramCtx<'a, E> {
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

impl<E: ExtensionField> E2EProgramCtx<'_, E> {
    pub fn keygen<PCS: PolynomialCommitmentScheme<E> + 'static>(
        &self,
        max_num_variables: usize,
        security_level: SecurityLevel,
    ) -> (ZKVMProvingKey<E, PCS>, ZKVMVerifyingKey<E, PCS>) {
        let pcs_param =
            PCS::setup(1 << max_num_variables, security_level).expect("Basefold PCS setup");
        let (pp, vp) = PCS::trim(pcs_param, 1 << max_num_variables).expect("Basefold trim");
        let pk = self
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
        (pk, vk)
    }

    pub fn keygen_with_pb<
        PCS: PolynomialCommitmentScheme<E> + 'static,
        PB: ProverBackend<E = E, Pcs = PCS> + 'static,
    >(
        &self,
        pb: &PB,
    ) -> (ZKVMProvingKey<E, PCS>, ZKVMVerifyingKey<E, PCS>) {
        let pk = self
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
) -> E2ECheckpointResult<E, PCS> {
    let start = std::time::Instant::now();
    let ctx = setup_program::<E>(program, platform, multi_prover);
    tracing::debug!("setup_program done in {:?}", start.elapsed());

    // Keygen
    let start = std::time::Instant::now();
    let (pk, vk) = ctx.keygen_with_pb(device.get_pb());
    tracing::debug!("keygen done in {:?}", start.elapsed());

    let start = std::time::Instant::now();
    let init_full_mem = ctx.setup_init_mem(hints, public_io);
    tracing::debug!("setup_init_mem done in {:?}", start.elapsed());

    // Generate witness
    let is_mock_proving = std::env::var("MOCK_PROVING").is_ok();
    if let Checkpoint::PrepE2EProving = checkpoint {
        return E2ECheckpointResult {
            proofs: None,
            vk: Some(vk),
            next_step: Some(Box::new(move || {
                _ = run_e2e_proof::<E, _, _, _>(
                    &ctx,
                    device,
                    &init_full_mem,
                    pk,
                    max_steps,
                    is_mock_proving,
                )
            })),
        };
    }

    // Emulate program
    let start = std::time::Instant::now();
    let emul_result = emulate_program(
        ctx.program.clone(),
        max_steps,
        &init_full_mem,
        &ctx.platform,
        &ctx.multi_prover,
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
                _ = generate_witness(&ctx.system_config, emul_result, &ctx.program)
            })),
        };
    }

    let prover = ZKVMProver::new(pk, device);

    let zkvm_witness = generate_witness(&ctx.system_config, emul_result, &ctx.program);

    let zkvm_proofs = zkvm_witness
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

            // Run proof phase
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
            tracing::info!("e2e proof stat: {}", zkvm_proof);
            zkvm_proof
        })
        .collect_vec();

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
#[allow(clippy::too_many_arguments)]
pub fn run_e2e_proof<
    E: ExtensionField + LkMultiplicityKey,
    PCS: PolynomialCommitmentScheme<E> + 'static,
    PB: ProverBackend<E = E, Pcs = PCS> + 'static,
    PD: ProverDevice<PB>,
>(
    ctx: &E2EProgramCtx<E>,
    device: PD,
    init_full_mem: &InitMemState,
    pk: ZKVMProvingKey<E, PCS>,
    max_steps: usize,
    is_mock_proving: bool,
) -> Vec<ZKVMProof<E, PCS>> {
    // Emulate program
    let emul_result = emulate_program(
        ctx.program.clone(),
        max_steps,
        init_full_mem,
        &ctx.platform,
        &ctx.multi_prover,
    );

    // Generate witness
    let zkvm_witness = generate_witness(&ctx.system_config, emul_result, &ctx.program);

    // proving
    let prover = ZKVMProver::new(pk, device);

    zkvm_witness
        .map(|(zkvm_witness, shard_ctx, pi)| {
            if is_mock_proving {
                if shard_ctx.num_shards > 1 {
                    todo!("support mock proving on more than 1 shard")
                }
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
            prover
                .create_proof(&shard_ctx, zkvm_witness, pi, transcript)
                .expect("create_proof failed")
        })
        .collect_vec()
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

fn debug_memory_ranges<'a, I: Iterator<Item = &'a MemFinalRecord>>(vm: &VMState, mem_final: I) {
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

fn format_segments(
    platform: &Platform,
    addrs: impl Iterator<Item = ByteAddr>,
) -> HashMap<String, MinMaxResult<ByteAddr>> {
    addrs
        .into_grouping_map_by(|addr| format_segment(platform, addr.0))
        .minmax()
}

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
    use crate::e2e::{MultiProver, ShardContext};
    use ceno_emul::{Cycle, NextCycleAccess};

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
        let shard_ctx = ShardContext::new(
            MultiProver::new(0, 1, 1 << 3, max_cycle_per_shard),
            executed_instruction,
            NextCycleAccess::default(),
        );
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

    #[test]
    fn test_multi_prover_shard_ctx() {
        for (name, num_shards, num_prover, expected_num_shards_of_provers) in [
            ("2 provers", 7, 2, vec![4, 3]),
            ("2 provers", 10, 3, vec![4, 3, 3]),
        ] {
            test_multi_shard_ctx_helper(
                name,
                num_shards,
                num_prover,
                expected_num_shards_of_provers,
            );
        }
    }

    fn test_multi_shard_ctx_helper(
        name: &str,
        num_shards: usize,
        num_prover: usize,
        expected_num_shards_of_provers: Vec<usize>,
    ) {
        let max_cycle_per_shard = (1 << 8) * 4;
        let executed_instruction = (1 << 8) * num_shards - 10; // this will be split into num_shards
        for (prover_id, expected_shard) in (0..num_prover).zip(expected_num_shards_of_provers) {
            let shard_ctx = ShardContext::new(
                MultiProver::new(prover_id, num_prover, 1 << 3, max_cycle_per_shard),
                executed_instruction,
                NextCycleAccess::default(),
            );
            assert_eq!(shard_ctx.len(), expected_shard, "{name} test case failed");
        }
    }
}
