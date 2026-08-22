use crate::{
    CENO_PLATFORM, InsnKind, Instruction, PC_STEP_SIZE, Platform,
    addr::{ByteAddr, Cycle, RegIdx, Word, WordAddr},
    dense_addr_space::DenseAddrSpace,
    encode_rv32,
    syscalls::{SyscallEffects, SyscallWitness},
};
use ceno_rt::WORD_SIZE;
use rayon::prelude::*;
#[cfg(debug_assertions)]
use rustc_hash::FxHashMap;
use smallvec::SmallVec;
use std::{
    collections::BTreeMap,
    fmt,
    sync::Arc,
    time::{Duration, Instant},
};
use strum::{EnumCount, IntoEnumIterator};
use tiny_keccak::{Hasher, Keccak};

fn instruction_reads_rs1(kind: InsnKind) -> bool {
    use crate::rv32im::InsnFormat::{B, I, R, S};
    !matches!(kind, InsnKind::ECALL | InsnKind::INVALID)
        && matches!(crate::rv32im::InsnFormat::from(kind), R | I | S | B)
}

fn instruction_reads_rs2(kind: InsnKind) -> bool {
    use crate::rv32im::InsnFormat::{B, R, S};
    matches!(crate::rv32im::InsnFormat::from(kind), R | S | B)
}

fn instruction_writes_rd(kind: InsnKind) -> bool {
    !matches!(kind, InsnKind::ECALL | InsnKind::INVALID)
        && matches!(
            crate::rv32im::InsnFormat::from(kind),
            crate::rv32im::InsnFormat::R
                | crate::rv32im::InsnFormat::I
                | crate::rv32im::InsnFormat::U
                | crate::rv32im::InsnFormat::J
        )
}

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

    /// Cross-shard successor annotations for RS1 | RS2 | RD | MEM.
    /// This occupies the former tail padding; `StepRecord` remains 136 bytes.
    future_access_mask: u8,
    _padding: [u8; 3],
}

impl StepRecord {
    /// Sentinel value indicating no syscall is associated with this step.
    pub const NO_SYSCALL: u32 = u32::MAX;
    pub const FUTURE_ACCESS_RS1: u8 = 1 << 0;
    pub const FUTURE_ACCESS_RS2: u8 = 1 << 1;
    pub const FUTURE_ACCESS_RD: u8 = 1 << 2;
    pub const FUTURE_ACCESS_MEM: u8 = 1 << 3;

    pub(crate) const L1_POISON_WORD: u32 = 0xa5a5_a5a5;
    pub(crate) const L1_POISON_CYCLE: Cycle = 0xa5a5_a5a5_a5a5_a5a5;

    pub(crate) fn l1_skeleton(
        cycle: Cycle,
        pc: Change<ByteAddr>,
        insn: Instruction,
        memory_addr: Option<WordAddr>,
    ) -> Self {
        let poison_change = Change {
            before: Self::L1_POISON_WORD,
            after: Self::L1_POISON_WORD,
        };
        let poison_read = ReadOp {
            addr: 0.into(),
            value: Self::L1_POISON_WORD,
            previous_cycle: Self::L1_POISON_CYCLE,
        };
        let poison_write = WriteOp {
            addr: 0.into(),
            value: poison_change,
            previous_cycle: Self::L1_POISON_CYCLE,
        };
        let has_rs1 = instruction_reads_rs1(insn.kind);
        let has_rs2 = instruction_reads_rs2(insn.kind);
        let has_rd = instruction_writes_rd(insn.kind);
        let has_memory_op = memory_addr.is_some();
        Self {
            cycle,
            pc,
            heap_maxtouch_addr: Change {
                before: Self::L1_POISON_WORD.into(),
                after: Self::L1_POISON_WORD.into(),
            },
            hint_maxtouch_addr: Change {
                before: Self::L1_POISON_WORD.into(),
                after: Self::L1_POISON_WORD.into(),
            },
            insn,
            has_rs1,
            has_rs2,
            has_rd,
            has_memory_op,
            rs1: ReadOp {
                addr: if has_rs1 {
                    Platform::register_vma(insn.rs1).into()
                } else {
                    0.into()
                },
                ..poison_read
            },
            rs2: ReadOp {
                addr: if has_rs2 {
                    Platform::register_vma(insn.rs2).into()
                } else {
                    0.into()
                },
                ..poison_read
            },
            rd: WriteOp {
                addr: if has_rd {
                    Platform::register_vma(insn.rd_internal() as RegIdx).into()
                } else {
                    0.into()
                },
                ..poison_write
            },
            memory_op: WriteOp {
                addr: memory_addr.unwrap_or_default(),
                ..poison_write
            },
            syscall_index: Self::L1_POISON_WORD,
            future_access_mask: 0xa5,
            _padding: [0xa5; 3],
        }
    }

    pub(crate) fn l1_disabled_fields_are_poisoned(&self) -> bool {
        let poisoned_change = |value: Change<Word>| {
            value.before == Self::L1_POISON_WORD && value.after == Self::L1_POISON_WORD
        };
        self.heap_maxtouch_addr.before.0 == Self::L1_POISON_WORD
            && self.heap_maxtouch_addr.after.0 == Self::L1_POISON_WORD
            && self.hint_maxtouch_addr.before.0 == Self::L1_POISON_WORD
            && self.hint_maxtouch_addr.after.0 == Self::L1_POISON_WORD
            && self.rs1.value == Self::L1_POISON_WORD
            && self.rs1.previous_cycle == Self::L1_POISON_CYCLE
            && self.rs2.value == Self::L1_POISON_WORD
            && self.rs2.previous_cycle == Self::L1_POISON_CYCLE
            && poisoned_change(self.rd.value)
            && self.rd.previous_cycle == Self::L1_POISON_CYCLE
            && poisoned_change(self.memory_op.value)
            && self.memory_op.previous_cycle == Self::L1_POISON_CYCLE
            && self.syscall_index == Self::L1_POISON_WORD
            && self.future_access_mask == 0xa5
            && self._padding == [0xa5; 3]
    }

    pub(crate) fn l2_values(
        cycle: Cycle,
        pc: Change<ByteAddr>,
        insn: Instruction,
        memory_addr: Option<WordAddr>,
        rs1_value: Word,
        rs2_value: Word,
        rd_value: Change<Word>,
        memory_value: Option<Change<Word>>,
    ) -> Self {
        let mut record = Self::l1_skeleton(cycle, pc, insn, memory_addr);
        if record.has_rs1 {
            record.rs1.value = rs1_value;
        }
        if record.has_rs2 {
            record.rs2.value = rs2_value;
        }
        if record.has_rd {
            record.rd.value = rd_value;
        }
        if let Some(memory_value) = memory_value {
            record.memory_op.value = memory_value;
        }
        record
    }

    pub(crate) fn l3_registers(
        cycle: Cycle,
        pc: Change<ByteAddr>,
        insn: Instruction,
        memory_addr: Option<WordAddr>,
        rs1_value: Word,
        rs2_value: Word,
        rd_value: Change<Word>,
        memory_value: Option<Change<Word>>,
        register_previous_cycles: [Cycle; 3],
    ) -> Self {
        let mut record = Self::l2_values(
            cycle,
            pc,
            insn,
            memory_addr,
            rs1_value,
            rs2_value,
            rd_value,
            memory_value,
        );
        if record.has_rs1 {
            record.rs1.previous_cycle = register_previous_cycles[0];
        }
        if record.has_rs2 {
            record.rs2.previous_cycle = register_previous_cycles[1];
        }
        if record.has_rd {
            record.rd.previous_cycle = register_previous_cycles[2];
        }
        record
    }

    pub(crate) fn l4_memory(
        cycle: Cycle,
        pc: Change<ByteAddr>,
        insn: Instruction,
        memory_addr: Option<WordAddr>,
        rs1_value: Word,
        rs2_value: Word,
        rd_value: Change<Word>,
        memory_value: Option<Change<Word>>,
        register_previous_cycles: [Cycle; 3],
        memory_previous_cycle: Option<Cycle>,
        heap_maxtouch_addr: Change<ByteAddr>,
        hint_maxtouch_addr: Change<ByteAddr>,
    ) -> Self {
        let mut record = Self::l3_registers(
            cycle,
            pc,
            insn,
            memory_addr,
            rs1_value,
            rs2_value,
            rd_value,
            memory_value,
            register_previous_cycles,
        );
        record.heap_maxtouch_addr = heap_maxtouch_addr;
        record.hint_maxtouch_addr = hint_maxtouch_addr;
        if let Some(previous_cycle) = memory_previous_cycle {
            record.memory_op.previous_cycle = previous_cycle;
        }
        record
    }

    pub(crate) fn l2_later_fields_are_poisoned(&self) -> bool {
        self.heap_maxtouch_addr.before.0 == Self::L1_POISON_WORD
            && self.heap_maxtouch_addr.after.0 == Self::L1_POISON_WORD
            && self.hint_maxtouch_addr.before.0 == Self::L1_POISON_WORD
            && self.hint_maxtouch_addr.after.0 == Self::L1_POISON_WORD
            && self.rs1.previous_cycle == Self::L1_POISON_CYCLE
            && self.rs2.previous_cycle == Self::L1_POISON_CYCLE
            && self.rd.previous_cycle == Self::L1_POISON_CYCLE
            && self.memory_op.previous_cycle == Self::L1_POISON_CYCLE
            && self.syscall_index == Self::L1_POISON_WORD
            && self.future_access_mask == 0xa5
            && self._padding == [0xa5; 3]
    }

    pub(crate) fn l3_later_fields_are_poisoned(&self) -> bool {
        self.heap_maxtouch_addr.before.0 == Self::L1_POISON_WORD
            && self.heap_maxtouch_addr.after.0 == Self::L1_POISON_WORD
            && self.hint_maxtouch_addr.before.0 == Self::L1_POISON_WORD
            && self.hint_maxtouch_addr.after.0 == Self::L1_POISON_WORD
            && self.memory_op.previous_cycle == Self::L1_POISON_CYCLE
            && self.syscall_index == Self::L1_POISON_WORD
            && self.future_access_mask == 0xa5
            && self._padding == [0xa5; 3]
    }

    pub(crate) fn l4_later_fields_are_poisoned(&self) -> bool {
        self.syscall_index == Self::L1_POISON_WORD
            && self.future_access_mask == 0xa5
            && self._padding == [0xa5; 3]
    }

    pub(crate) fn l5_later_fields_are_poisoned(&self) -> bool {
        self.syscall_index == Self::L1_POISON_WORD && self._padding == [0xa5; 3]
    }

    /// Finish the private layered representation after its exceptional side
    /// stream has been decoded. Ordinary instructions use `NO_SYSCALL`.
    pub(crate) fn complete_l6(
        &mut self,
        syscall_index: Option<u32>,
        ecall_code: Option<(Word, Cycle)>,
        ecall_arg0: Option<(Word, Cycle)>,
    ) {
        self.syscall_index = syscall_index.unwrap_or(Self::NO_SYSCALL);
        if let Some((value, previous_cycle)) = ecall_code {
            self.rs1 = ReadOp {
                addr: Platform::register_vma(Platform::reg_ecall()).into(),
                value,
                previous_cycle,
            };
            self.has_rs1 = true;
        }
        if let Some((value, previous_cycle)) = ecall_arg0 {
            self.rs2 = ReadOp {
                addr: Platform::register_vma(Platform::reg_arg0()).into(),
                value,
                previous_cycle,
            };
            self.has_rs2 = true;
        }
        if !self.has_rs1 {
            self.rs1 = ReadOp::default();
        }
        if !self.has_rs2 {
            self.rs2 = ReadOp::default();
        }
        if !self.has_rd {
            self.rd = WriteOp::default();
        }
        if !self.has_memory_op {
            self.memory_op = WriteOp::default();
        }
        self._padding = [0; 3];
    }
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
            future_access_mask: 0,
            _padding: [0; 3],
        }
    }
}

pub type StepIndex = usize;

/// Why a replay engine returned control to its Rust consumer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReplayStopReason {
    ShardBoundary,
    BufferFull,
    Halt,
    Syscall,
    DynamicFallback,
    Trap,
    Error,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReplayChunk {
    pub records: usize,
    pub stop_reason: ReplayStopReason,
}

/// Common lifecycle for interpreter and native witness replay engines.
pub trait ReplayEngine {
    fn begin_shard(&mut self, expected_steps: usize);
    fn replay_chunk(&mut self) -> ReplayChunk;
    fn finish_shard(&mut self);
}

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
    fingerprint: [u8; 32],
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
        let opcode_chips: Vec<Vec<u32>> = opcode_chips
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
                let domain_rows = padded_instances.saturating_mul(rotation_size);
                let trace_cells = domain_rows.saturating_mul(spec.trace_cells_per_row);
                // Batched main sumcheck keeps one half-domain extension-field
                // fold buffer for every witness, structural-witness, and fixed
                // MLE. `trace_cells_per_row` is exactly that MLE count.
                let main_peak = (domain_rows / 2)
                    .saturating_mul(spec.trace_cells_per_row)
                    .saturating_mul(extension_field_degree);
                let tower_peak = spec.tower_peak_cells_by_bucket.as_ref().map_or_else(
                    || domain_rows.saturating_mul(spec.tower_peak_cells_per_row),
                    |tower_costs| tower_costs[bucket],
                );
                trace_cost_table.push(trace_cells);
                main_cost_table.push(main_peak);
                tower_cost_table.push(tower_peak);
            }
        }
        let fingerprint = shard_cost_model_fingerprint(
            &opcode_chips,
            &ecall_chips,
            &chip_specs,
            &trace_cost_table,
            &main_cost_table,
            &tower_cost_table,
            extension_field_degree,
        );
        Self {
            opcode_chips,
            ecall_chips,
            chip_specs,
            trace_cost_table,
            main_cost_table,
            tower_cost_table,
            extension_field_degree,
            fingerprint,
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

    pub fn fingerprint(&self) -> [u8; 32] {
        self.fingerprint
    }
}

fn shard_cost_model_fingerprint(
    opcode_chips: &[Vec<u32>],
    ecall_chips: &BTreeMap<Word, Vec<u32>>,
    chip_specs: &[ChipCostSpec],
    trace_cost_table: &[u64],
    main_cost_table: &[u64],
    tower_cost_table: &[u64],
    extension_field_degree: u64,
) -> [u8; 32] {
    fn update_u64(hasher: &mut Keccak, value: u64) {
        hasher.update(&value.to_le_bytes());
    }
    fn update_u32_slice(hasher: &mut Keccak, values: &[u32]) {
        update_u64(hasher, values.len() as u64);
        for &value in values {
            hasher.update(&value.to_le_bytes());
        }
    }
    fn update_u64_slice(hasher: &mut Keccak, values: &[u64]) {
        update_u64(hasher, values.len() as u64);
        for &value in values {
            update_u64(hasher, value);
        }
    }

    let mut hasher = Keccak::v256();
    hasher.update(b"ceno-shard-cost-model-v1");
    update_u64(&mut hasher, opcode_chips.len() as u64);
    for chips in opcode_chips {
        update_u32_slice(&mut hasher, chips);
    }
    update_u64(&mut hasher, ecall_chips.len() as u64);
    for (&code, chips) in ecall_chips {
        hasher.update(&code.to_le_bytes());
        update_u32_slice(&mut hasher, chips);
    }
    update_u64(&mut hasher, chip_specs.len() as u64);
    for spec in chip_specs {
        hasher.update(&[spec.rotation]);
        update_u64(&mut hasher, spec.trace_cells_per_row);
        update_u64(&mut hasher, spec.tower_peak_cells_per_row);
        match &spec.tower_peak_cells_by_bucket {
            Some(costs) => {
                hasher.update(&[1]);
                update_u64_slice(&mut hasher, costs);
            }
            None => hasher.update(&[0]),
        }
    }
    update_u64_slice(&mut hasher, trace_cost_table);
    update_u64_slice(&mut hasher, main_cost_table);
    update_u64_slice(&mut hasher, tower_cost_table);
    update_u64(&mut hasher, extension_field_degree);
    let mut fingerprint = [0u8; 32];
    hasher.finalize(&mut fingerprint);
    fingerprint
}

#[inline(always)]
fn padded_size_bucket(num_instances: u64) -> usize {
    if num_instances == 0 {
        0
    } else {
        (u64::BITS - num_instances.saturating_sub(1).leading_zeros() + 1) as usize
    }
}

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
#[repr(C)]
pub struct NextAccessEvent {
    pub source_cycle: Cycle,
    pub target_cycle: Cycle,
    pub address: WordAddr,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum PatchRamClass {
    Register = 0,
    Memory = 1,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum PatchSourceLane {
    Rs1 = 0,
    Rs2 = 1,
    Rd = 2,
    Memory = 3,
    SyscallRegister = 4,
    SyscallMemory = 5,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct CrossShardPatch {
    pub source_cycle: Cycle,
    pub target_cycle: Cycle,
    pub address: WordAddr,
    pub prior_value: Word,
    pub source_shard: u32,
    pub target_shard: u32,
    pub ram_class: PatchRamClass,
    pub source_lane: PatchSourceLane,
    pub syscall_op_index: u16,
    pub syscall_witness_index: u32,
}

#[derive(Debug)]
pub struct CombinedPreflightCapture {
    pub ranges: Vec<crate::GpuReplayTypedRange>,
    pub syscall_witnesses: Vec<SyscallWitness>,
    pub patches: Vec<CrossShardPatch>,
    pub initialization_events: Vec<NextAccessEvent>,
}

impl NextAccessEvent {
    pub fn new(source_cycle: Cycle, target_cycle: Cycle, address: WordAddr) -> Self {
        Self {
            source_cycle,
            target_cycle,
            address,
        }
    }
}

fn radix_sort_next_access_events(events: &mut Vec<NextAccessEvent>) {
    if events.len() < 2 {
        return;
    }
    let mut scratch = vec![NextAccessEvent::default(); events.len()];
    let mut counts = vec![0usize; 1 << 16];
    let max_address = events.iter().map(|event| event.address.0).max().unwrap();
    let address_passes = (u32::BITS - max_address.leading_zeros()).div_ceil(16);
    let max_source = events.iter().map(|event| event.source_cycle).max().unwrap();
    let source_passes = (Cycle::BITS - max_source.leading_zeros()).div_ceil(16);

    let mut pass = |digit: &dyn Fn(&NextAccessEvent) -> usize| {
        counts.fill(0);
        for event in events.iter() {
            counts[digit(event)] += 1;
        }
        let mut offset = 0;
        for count in &mut counts {
            let next = offset + *count;
            *count = offset;
            offset = next;
        }
        for event in events.iter() {
            let key = digit(event);
            scratch[counts[key]] = *event;
            counts[key] += 1;
        }
        std::mem::swap(events, &mut scratch);
    };

    // `(source_cycle, address)` is logically unique, so the tertiary target
    // cannot affect the order of valid events. Sorting this unique prefix also
    // places invalid duplicates next to each other for validation below.
    for word in 0..address_passes {
        let shift = word * 16;
        pass(&|event| ((event.address.0 >> shift) & 0xffff) as usize);
    }

    for word in 0..source_passes {
        let shift = word * 16;
        pass(&|event| ((event.source_cycle >> shift) & 0xffff) as usize);
    }
}

/// Canonical, source-ordered cross-shard access tape.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NextAccessTape {
    initialization: Vec<NextAccessEvent>,
    events: Vec<NextAccessEvent>,
    #[cfg(debug_assertions)]
    oracle: FxHashMap<Cycle, NextAccessPair>,
}

impl NextAccessTape {
    pub fn from_unsorted(mut events: Vec<NextAccessEvent>) -> Self {
        let event_count = events.len();
        let started = Instant::now();
        radix_sort_next_access_events(&mut events);
        let sort_time = started.elapsed();
        assert!(
            events
                .iter()
                .all(|event| event.target_cycle > event.source_cycle)
        );
        for pair in events.windows(2) {
            assert!(
                (pair[0].source_cycle, pair[0].address, pair[0].target_cycle)
                    <= (pair[1].source_cycle, pair[1].address, pair[1].target_cycle),
                "next-access tape is not canonically ordered"
            );
            assert_ne!(
                (pair[0].source_cycle, pair[0].address),
                (pair[1].source_cycle, pair[1].address),
                "duplicate logical next-access event"
            );
        }
        let split = events.partition_point(|event| event.source_cycle == 0);
        let non_initial = events.split_off(split);
        tracing::info!(
            "next-access tape finalized {event_count} events in {:?}; sort={:?}, initialization={}, non_initial={}",
            started.elapsed(),
            sort_time,
            events.len(),
            non_initial.len()
        );
        #[cfg(debug_assertions)]
        let oracle: FxHashMap<Cycle, NextAccessPair> =
            events
                .iter()
                .chain(&non_initial)
                .fold(FxHashMap::default(), |mut oracle, event| {
                    oracle
                        .entry(event.source_cycle)
                        .or_default()
                        .push((event.address, event.target_cycle));
                    oracle
                });
        Self {
            initialization: events,
            events: non_initial,
            #[cfg(debug_assertions)]
            oracle,
        }
    }

    pub fn initialization_events(&self) -> &[NextAccessEvent] {
        &self.initialization
    }

    pub fn events(&self) -> &[NextAccessEvent] {
        &self.events
    }

    pub fn len(&self) -> usize {
        self.initialization.len() + self.events.len()
    }

    pub fn is_empty(&self) -> bool {
        self.initialization.is_empty() && self.events.is_empty()
    }

    #[cfg(debug_assertions)]
    fn oracle_has(&self, cycle: Cycle, address: WordAddr) -> bool {
        self.oracle
            .get(&cycle)
            .is_some_and(|pairs| pairs.iter().any(|pair| pair.0 == address))
    }
}

/// Compatibility aliases retained while downstream callers migrate to the tape.
pub type NextAccessPair = SmallVec<[(WordAddr, Cycle); 1]>;
pub type NextCycleAccess = NextAccessTape;

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

    /// Whether VM memory operations update packed latest-access stamps.
    /// Diagnostic execution tracers may disable this while preserving values.
    const TRACK_MEMORY_ACCESSES: bool = true;

    fn track_memory_accesses(&self) -> bool {
        Self::TRACK_MEMORY_ACCESSES
    }

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

    fn load_memory(&mut self, addr: WordAddr, value: Word, previous_cycle: Cycle);

    fn store_memory(&mut self, addr: WordAddr, value: Change<Word>, previous_cycle: Cycle);

    fn track_syscall(&mut self, effects: SyscallEffects);

    fn track_access(&mut self, addr: WordAddr, subcycle: Cycle) -> Cycle;

    fn final_register_accesses(&self) -> &LatestAccesses;

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
    fn new(_platform: &Platform) -> Self {
        let last_register: WordAddr = Platform::register_vma(32).into();
        Self {
            // Include the internal x0 sink at register slot 32.
            store: DenseAddrSpace::new(WordAddr::from(0u32), last_register + 1usize),
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
    pub fn addresses(&self) -> impl Iterator<Item = WordAddr> + '_ {
        self.touched.iter().copied()
    }

    #[cfg(not(any(test, debug_assertions)))]
    pub fn addresses(&self) -> impl Iterator<Item = WordAddr> + '_ {
        self.store.non_default_addresses()
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
    replay_range_capacity: usize,
    replay_range_start: usize,
    replay_range_len: usize,
    replay_range_sequence: u32,
    replay_family_counts: [usize; InsnKind::COUNT],
    replay_fallback_count: usize,
    replay_unsupported_count: usize,
    replay_descriptors: Vec<crate::GpuReplayRangeDescriptor>,
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
            replay_range_capacity: 256 * 1024,
            replay_range_start: 0,
            replay_range_len: 0,
            replay_range_sequence: 0,
            replay_family_counts: [0; InsnKind::COUNT],
            replay_fallback_count: 0,
            replay_unsupported_count: 0,
            replay_descriptors: Vec::new(),
            finalized: false,
        }
    }

    pub fn set_replay_range_capacity(&mut self, capacity: usize) {
        assert!(capacity > 0, "GPU replay range capacity must be nonzero");
        assert_eq!(
            self.replay_range_len, 0,
            "GPU replay capacity cannot change after counting starts"
        );
        self.replay_range_capacity = capacity;
    }

    pub fn replay_descriptors(&self) -> &[crate::GpuReplayRangeDescriptor] {
        assert!(self.finalized, "shard plan not finalized yet");
        &self.replay_descriptors
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

    pub fn into_replay_plan(self) -> (Vec<Cycle>, Vec<crate::GpuReplayRangeDescriptor>) {
        assert!(self.finalized, "shard plan not finalized yet");
        (self.shard_cycle_boundaries, self.replay_descriptors)
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
        self.record_replay_step(kind);
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
        self.flush_replay_range();
        self.record_predicted_shard_cost();
        self.push_boundary(next_shard_cycle);
        self.shard_id += 1;
        self.replay_range_start = 0;
        self.replay_range_sequence = 0;
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

    fn record_replay_step(&mut self, kind: InsnKind) {
        if kind == InsnKind::ECALL {
            self.replay_fallback_count = self
                .replay_fallback_count
                .checked_add(1)
                .expect("GPU replay fallback count overflow");
        } else if crate::gpu_typed_kind_spec(kind).is_some() {
            let count = &mut self.replay_family_counts[kind as usize];
            *count = count
                .checked_add(1)
                .expect("GPU replay family count overflow");
        } else {
            self.replay_unsupported_count = self
                .replay_unsupported_count
                .checked_add(1)
                .expect("GPU replay unsupported count overflow");
        }
        self.replay_range_len = self
            .replay_range_len
            .checked_add(1)
            .expect("GPU replay range length overflow");
        if self.replay_range_len == self.replay_range_capacity {
            self.flush_replay_range();
        }
    }

    fn record_admitted_native_block(
        &mut self,
        histogram: &[u32; InsnKind::COUNT],
        ordered_kinds: &[InsnKind],
    ) {
        let block_len = histogram
            .iter()
            .try_fold(0usize, |sum, &count| sum.checked_add(count as usize))
            .expect("AOT replay block length overflow");
        assert_eq!(
            block_len,
            ordered_kinds.len(),
            "AOT replay block histogram length mismatch"
        );
        let remaining = self.replay_range_capacity - self.replay_range_len;
        if block_len > remaining {
            for &kind in ordered_kinds {
                self.record_replay_step(kind);
            }
            return;
        }
        for (index, &count) in histogram.iter().enumerate() {
            let count = count as usize;
            let kind = InsnKind::iter()
                .nth(index)
                .expect("AOT replay histogram kind index out of bounds");
            if kind == InsnKind::ECALL {
                self.replay_fallback_count = self
                    .replay_fallback_count
                    .checked_add(count)
                    .expect("GPU replay fallback count overflow");
            } else if crate::gpu_typed_kind_spec(kind).is_some() {
                self.replay_family_counts[index] = self.replay_family_counts[index]
                    .checked_add(count)
                    .expect("GPU replay family count overflow");
            } else {
                self.replay_unsupported_count = self
                    .replay_unsupported_count
                    .checked_add(count)
                    .expect("GPU replay unsupported count overflow");
            }
        }
        self.replay_range_len = self
            .replay_range_len
            .checked_add(block_len)
            .expect("GPU replay range length overflow");
        if self.replay_range_len == self.replay_range_capacity {
            self.flush_replay_range();
        }
    }

    fn flush_replay_range(&mut self) {
        if self.replay_range_len == 0 {
            return;
        }
        let descriptor = crate::GpuReplayRangeDescriptor {
            shard_id: u32::try_from(self.shard_id).expect("GPU replay shard id exceeds u32"),
            sequence: self.replay_range_sequence,
            range_start: u32::try_from(self.replay_range_start)
                .expect("GPU replay range start exceeds u32"),
            range_len: u32::try_from(self.replay_range_len)
                .expect("GPU replay range length exceeds u32"),
            family_counts: self.replay_family_counts,
            fallback_count: self.replay_fallback_count,
            unsupported_count: self.replay_unsupported_count,
        };
        assert_eq!(
            descriptor.checked_total(),
            Some(self.replay_range_len),
            "GPU replay descriptor count mismatch"
        );
        self.replay_descriptors.push(descriptor);
        #[cfg(all(feature = "aot-x86_64", target_arch = "x86_64", target_os = "linux"))]
        if crate::aot::aot_native_diagnostic_only() && self.replay_descriptors.len() == 1 {
            let descriptor = &self.replay_descriptors[0];
            crate::aot::aot_native_diagnostic_boundary(
                "FIRST_REPLAY_DESCRIPTOR",
                "FLUSHED",
                &format!(
                    "vector_len={},vector_ptr={:p},first_ptr={:p},shard={},sequence={},range_start={},range_len={},checked_total={:?},auipc_index={},auipc_count={},fallback={},unsupported={},family_counts={:?}",
                    self.replay_descriptors.len(),
                    self.replay_descriptors.as_ptr(),
                    descriptor,
                    descriptor.shard_id,
                    descriptor.sequence,
                    descriptor.range_start,
                    descriptor.range_len,
                    descriptor.checked_total(),
                    InsnKind::AUIPC as usize,
                    descriptor.family_counts[InsnKind::AUIPC as usize],
                    descriptor.fallback_count,
                    descriptor.unsupported_count,
                    descriptor.family_counts,
                ),
            );
        }
        self.replay_range_start = self
            .replay_range_start
            .checked_add(self.replay_range_len)
            .expect("GPU replay range start overflow");
        self.replay_range_len = 0;
        self.replay_range_sequence = self
            .replay_range_sequence
            .checked_add(1)
            .expect("GPU replay range sequence overflow");
        self.replay_family_counts.fill(0);
        self.replay_fallback_count = 0;
        self.replay_unsupported_count = 0;
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
        self.flush_replay_range();
        self.flush_replay_range();
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
            future_access_mask: 0,
            _padding: [0; 3],
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

    /// Stable association used by compact witness journals.
    pub fn syscall_index(&self) -> Option<u32> {
        (self.syscall_index != Self::NO_SYSCALL).then_some(self.syscall_index)
    }

    pub fn remap_syscall_index(
        &mut self,
        global_base: u32,
        shard_syscall_count: usize,
    ) -> Result<(), &'static str> {
        let Some(index) = self.syscall_index() else {
            return Ok(());
        };
        let local = index
            .checked_sub(global_base)
            .ok_or("syscall witness index precedes shard store")?;
        if local as usize >= shard_syscall_count {
            return Err("syscall witness index exceeds shard store");
        }
        self.syscall_index = local;
        Ok(())
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

    #[inline(always)]
    pub fn future_access_mask(&self) -> u8 {
        self.future_access_mask
    }

    pub(crate) fn set_future_access_mask(&mut self, mask: u8) {
        self.future_access_mask |= mask;
    }

    pub(crate) fn clear_future_access_mask(&mut self) {
        self.future_access_mask = 0;
    }

    #[inline(always)]
    pub fn has_future_access(&self, bit: u8) -> bool {
        self.future_access_mask & bit != 0
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct FullTracerConfig {
    /// Maximum number of completed steps per shard. Internally, `FullTracer`
    /// reserves one extra slot to hold the pending (in-progress) record. A zero
    /// value leaves the buffer dynamically sized for standalone VM execution.
    pub max_step_shard: usize,
}

#[derive(Debug)]
pub struct FullTracer {
    records: Vec<StepRecord>,
    len: usize,
    pending_index: usize,
    pending_cycle: Cycle,
    allow_step_buffer_growth: bool,

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
    next_accesses: Arc<NextAccessTape>,
    next_access_cursor: usize,
}

/// Configuration for the compact, chunked witness replay producer.
///
/// This tracer is intentionally internal to replay.  It does not replace
/// [`FullTracer`] as the CPU/debug reference and it does not expose a new
/// serialized journal format.
#[derive(Clone, Copy, Debug)]
pub struct GpuReplayTracerConfig {
    pub chunk_capacity: usize,
}

impl Default for GpuReplayTracerConfig {
    fn default() -> Self {
        Self {
            chunk_capacity: 256 * 1024,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GpuReplayFallbackRecord {
    pub ordinal: u32,
    pub record: StepRecord,
}

/// A sealed producer chunk. Chunks and records are ordered by
/// `(sequence, ordinal)` and never receive concurrent appends.
#[derive(Debug)]
pub struct GpuReplayChunk {
    pub sequence: u32,
    pub shard_start_cycle: Cycle,
    pub typed: Vec<Option<crate::GpuTypedSoaArena>>,
    pub fallback: Vec<GpuReplayFallbackRecord>,
}

impl GpuReplayChunk {
    fn empty(sequence: u32, shard_start_cycle: Cycle) -> Self {
        Self {
            sequence,
            shard_start_cycle,
            // Ownership placeholder only. It must not allocate a replacement
            // family vector while both warmed owners are outside the tracer.
            typed: Vec::new(),
            fallback: Vec::new(),
        }
    }

    fn from_descriptor(
        descriptor: &crate::GpuReplayRangeDescriptor,
        shard_start_cycle: Cycle,
    ) -> Self {
        let typed = InsnKind::iter()
            .zip(descriptor.family_counts)
            .map(|(kind, rows)| {
                (rows > 0).then(|| {
                    crate::GpuTypedSoaArena::new_with_range(kind, rows, descriptor.range_start)
                        .unwrap()
                })
            })
            .collect();
        Self {
            sequence: descriptor.sequence,
            shard_start_cycle,
            typed,
            fallback: Vec::with_capacity(descriptor.fallback_count),
        }
    }

    fn warmed(
        family_capacities: [usize; InsnKind::COUNT],
        fallback_capacity: usize,
        shard_start_cycle: Cycle,
    ) -> Self {
        Self {
            sequence: 0,
            shard_start_cycle,
            typed: InsnKind::iter()
                .zip(family_capacities)
                .map(|(kind, rows)| {
                    (rows > 0)
                        .then(|| crate::GpuTypedSoaArena::new_with_range(kind, rows, 0).unwrap())
                })
                .collect(),
            fallback: Vec::with_capacity(fallback_capacity),
        }
    }

    fn reset_from_descriptor(
        &mut self,
        descriptor: &crate::GpuReplayRangeDescriptor,
        shard_start_cycle: Cycle,
    ) {
        self.sequence = descriptor.sequence;
        self.shard_start_cycle = shard_start_cycle;
        for ((kind, arena), required) in InsnKind::iter()
            .zip(&mut self.typed)
            .zip(descriptor.family_counts)
        {
            if required == 0 {
                if let Some(arena) = arena {
                    arena.reset_for_range(descriptor.range_start);
                }
                continue;
            }
            let arena = arena
                .as_mut()
                .unwrap_or_else(|| panic!("warmed range missing {kind:?} family"));
            assert!(
                arena.capacity() >= required,
                "warmed family capacity regressed"
            );
            arena.reset_for_range(descriptor.range_start);
        }
        self.fallback.clear();
        assert!(self.fallback.capacity() >= descriptor.fallback_count);
    }

    fn reset_empty(&mut self, shard_start_cycle: Cycle) {
        self.shard_start_cycle = shard_start_cycle;
        for arena in self.typed.iter_mut().flatten() {
            arena.reset_for_range(arena.range_start());
        }
        self.fallback.clear();
    }

    pub fn len(&self) -> usize {
        self.typed
            .iter()
            .flatten()
            .map(crate::GpuTypedSoaArena::len)
            .sum::<usize>()
            + self.fallback.len()
    }

    pub fn is_empty(&self) -> bool {
        self.typed
            .iter()
            .flatten()
            .all(crate::GpuTypedSoaArena::is_empty)
            && self.fallback.is_empty()
    }
}

/// Single-writer compact replay tracer.
///
/// Ordinary instructions are emitted directly into compact chunks. ECALLs are
/// deliberately retained in the sparse fallback lane until their consumers
/// have compact typed inputs. Queueing/worker ownership lives above this type;
/// `take_sealed_chunks` is the chunk-boundary handoff seam.
#[derive(Debug)]
pub struct GpuReplayTracer {
    config: GpuReplayTracerConfig,
    pending: StepRecord,
    current: GpuReplayChunk,
    sealed: Vec<GpuReplayChunk>,
    recyclable: Option<GpuReplayChunk>,
    range_descriptors: Arc<Vec<crate::GpuReplayRangeDescriptor>>,
    next_range_descriptor: usize,
    ordinal: usize,
    shard_start_cycle: Cycle,
    latest_accesses: LatestAccesses,
    next_accesses: Arc<NextAccessTape>,
    next_access_cursor: usize,
    syscall_witnesses: Vec<SyscallWitness>,
    mmio_min_max_access: Option<BTreeMap<WordAddr, (WordAddr, WordAddr, WordAddr, WordAddr)>>,
    max_heap_addr_access: ByteAddr,
    max_hint_addr_access: ByteAddr,
    platform: Platform,
    #[cfg(all(feature = "aot-x86_64", target_arch = "x86_64", target_os = "linux"))]
    native_kinds: [crate::gpu_typed_ingress::GpuTypedNativeKindState; InsnKind::COUNT],
    #[cfg(all(feature = "aot-x86_64", target_arch = "x86_64", target_os = "linux"))]
    native_error: u32,
}

impl GpuReplayTracer {
    pub fn new(platform: &Platform, config: GpuReplayTracerConfig) -> Self {
        assert!(
            config.chunk_capacity > 0,
            "GPU replay chunks cannot be empty"
        );
        let shard_start_cycle = FullTracer::SUBCYCLES_PER_INSN;
        Self {
            config,
            pending: StepRecord {
                cycle: shard_start_cycle,
                ..StepRecord::default()
            },
            current: GpuReplayChunk::empty(0, shard_start_cycle),
            sealed: Vec::new(),
            recyclable: None,
            range_descriptors: Arc::new(Vec::new()),
            next_range_descriptor: 0,
            ordinal: 0,
            shard_start_cycle,
            latest_accesses: LatestAccesses::new(platform),
            next_accesses: Arc::new(NextAccessTape::default()),
            next_access_cursor: 0,
            syscall_witnesses: Vec::new(),
            mmio_min_max_access: Some(init_mmio_min_max_access(platform)),
            max_heap_addr_access: ByteAddr::from(platform.heap.start),
            max_hint_addr_access: ByteAddr::from(platform.hints.start),
            platform: platform.clone(),
            #[cfg(all(feature = "aot-x86_64", target_arch = "x86_64", target_os = "linux"))]
            native_kinds: [crate::gpu_typed_ingress::GpuTypedNativeKindState::default();
                InsnKind::COUNT],
            #[cfg(all(feature = "aot-x86_64", target_arch = "x86_64", target_os = "linux"))]
            native_error: 0,
        }
    }

    #[cfg(all(feature = "aot-x86_64", target_arch = "x86_64", target_os = "linux"))]
    pub(crate) fn prepare_native_range(&mut self) -> GpuReplayNativeTraceState {
        assert!(
            self.current.len() <= 262_144,
            "GPU replay native range exceeds 262144 rows"
        );
        self.native_error = 0;
        for (index, slot) in self.native_kinds.iter_mut().enumerate() {
            *slot = self.current.typed[index]
                .as_mut()
                .map_or_else(Default::default, crate::GpuTypedSoaArena::native_state);
        }
        let events = self.next_accesses.events();
        GpuReplayNativeTraceState {
            kinds: self.native_kinds.as_mut_ptr(),
            kind_count: InsnKind::COUNT,
            ordinal: &mut self.ordinal,
            pending_cycle: &mut self.pending.cycle,
            latest_cells: self.latest_accesses.cells_mut_ptr(),
            latest_base: self.latest_accesses.base(),
            latest_len: &mut self.latest_accesses.len,
            max_heap_addr_access: &mut self.max_heap_addr_access,
            max_hint_addr_access: &mut self.max_hint_addr_access,
            next_access_events: events.as_ptr(),
            next_access_len: events.len(),
            next_access_cursor: &mut self.next_access_cursor,
            error: &mut self.native_error,
        }
    }

    #[cfg(all(feature = "aot-x86_64", target_arch = "x86_64", target_os = "linux"))]
    pub(crate) fn sync_native_range(&mut self) -> Result<(), String> {
        if self.native_error != 0 {
            let code = self.native_error & 0xff;
            let kind_index = (self.native_error >> 8) as usize;
            let message = match code {
                1 => "GPU replay native emitter rejected the instruction kind",
                2 => "GPU replay native emitter rejected the arena sentinel",
                3 => "GPU replay native emitter exceeded an arena capacity",
                4 => "GPU replay native emitter rejected the arena layout",
                5 => "GPU replay native emitter rejected a next-access event",
                6 => "GPU replay native emitter rejected the compact ordinal range",
                7 => "GPU replay native emitter rejected the compact PC range",
                8 => "GPU replay native emitter rejected a compact predecessor cycle",
                9 => "GPU replay native emitter rejected the compact future-access mask",
                _ => "GPU replay native emitter reported an unknown ABI error",
            };
            let state = self
                .native_kinds
                .get(kind_index)
                .copied()
                .unwrap_or_default();
            let kind = InsnKind::iter().nth(kind_index);
            return Err(format!(
                "{message}: code={code}, kind={kind:?}, kind_index={kind_index}, capacity={}, cursor={}, layout={}, sentinel={:#010x}, range_start={}, pc_base={:#010x}, ordinal={}",
                state.capacity,
                state.cursor,
                state.layout,
                state.sentinel,
                state.range_start,
                state.pc_base,
                self.ordinal,
            ));
        }
        for (index, state) in self.native_kinds.iter().enumerate() {
            match self.current.typed[index].as_mut() {
                Some(arena) => arena.sync_native_state(state).map_err(str::to_owned)?,
                None if state.capacity == 0 && state.cursor == 0 => {}
                None => return Err("GPU replay native emitter used an absent family".to_owned()),
            }
        }
        if self.current.len() > self.config.chunk_capacity || self.current.len() > 262_144 {
            return Err("GPU replay native range row bound exceeded".to_owned());
        }
        Ok(())
    }

    fn seal_current(&mut self) {
        if self.current.is_empty() {
            return;
        }
        let descriptor = &self.range_descriptors[self.next_range_descriptor];
        let shard_id = descriptor.shard_id;
        let sequence = descriptor.sequence;
        assert_eq!(descriptor.sequence, self.current.sequence);
        assert_eq!(descriptor.checked_total(), Some(self.current.len()));
        for (arena, expected) in self.current.typed.iter().zip(descriptor.family_counts) {
            assert_eq!(
                arena.as_ref().map_or(0, crate::GpuTypedSoaArena::len),
                expected
            );
        }
        assert_eq!(self.current.fallback.len(), descriptor.fallback_count);
        self.next_range_descriptor += 1;
        let next = self.recyclable.take().map_or_else(
            || GpuReplayChunk::empty(sequence + 1, self.shard_start_cycle),
            |mut next| {
                if let Some(descriptor) = self
                    .range_descriptors
                    .get(self.next_range_descriptor)
                    .filter(|next| next.shard_id == shard_id)
                {
                    next.reset_from_descriptor(descriptor, self.shard_start_cycle);
                }
                next
            },
        );
        self.sealed.push(std::mem::replace(&mut self.current, next));
    }

    pub fn install_range_descriptors(
        &mut self,
        descriptors: Arc<Vec<crate::GpuReplayRangeDescriptor>>,
    ) {
        assert_eq!(
            self.ordinal, 0,
            "GPU replay plan installed after execution started"
        );
        assert!(!descriptors.is_empty(), "GPU replay plan has no ranges");
        assert_eq!(descriptors[0].shard_id, 0);
        assert_eq!(descriptors[0].sequence, 0);
        self.range_descriptors = descriptors;
        self.next_range_descriptor = 0;
        let mut family_capacities = [0usize; InsnKind::COUNT];
        let mut fallback_capacity = 0usize;
        for descriptor in self.range_descriptors.iter() {
            for (capacity, required) in family_capacities.iter_mut().zip(descriptor.family_counts) {
                *capacity = (*capacity).max(required);
            }
            fallback_capacity = fallback_capacity.max(descriptor.fallback_count);
        }
        let mut first =
            GpuReplayChunk::warmed(family_capacities, fallback_capacity, self.shard_start_cycle);
        first.reset_from_descriptor(&self.range_descriptors[0], self.shard_start_cycle);
        self.current = first;
        self.recyclable = Some(GpuReplayChunk::warmed(
            family_capacities,
            fallback_capacity,
            self.shard_start_cycle,
        ));
        #[cfg(all(feature = "aot-x86_64", target_arch = "x86_64", target_os = "linux"))]
        if crate::aot::aot_native_diagnostic_only() {
            let descriptor = &self.range_descriptors[0];
            let arena = self.current.typed[InsnKind::AUIPC as usize].as_ref();
            crate::aot::aot_native_diagnostic_boundary(
                "FIRST_REPLAY_DESCRIPTOR",
                "INSTALLED",
                &format!(
                    "arc_ptr={:p},vector_len={},vector_ptr={:p},first_ptr={:p},shard={},sequence={},range_start={},range_len={},checked_total={:?},auipc_index={},auipc_count={},arena_present={},arena_capacity={},arena_len={},fallback={},unsupported={},family_counts={:?}",
                    Arc::as_ptr(&self.range_descriptors),
                    self.range_descriptors.len(),
                    self.range_descriptors.as_ptr(),
                    descriptor,
                    descriptor.shard_id,
                    descriptor.sequence,
                    descriptor.range_start,
                    descriptor.range_len,
                    descriptor.checked_total(),
                    InsnKind::AUIPC as usize,
                    descriptor.family_counts[InsnKind::AUIPC as usize],
                    arena.is_some(),
                    arena.map_or(0, crate::GpuTypedSoaArena::capacity),
                    arena.map_or(0, crate::GpuTypedSoaArena::len),
                    descriptor.fallback_count,
                    descriptor.unsupported_count,
                    descriptor.family_counts,
                ),
            );
        }
    }

    pub fn finish_chunks(&mut self) {
        self.seal_current();
    }

    /// Seal the previous shard and start a new ordinal domain while retaining
    /// predecessor state and the next-access cursor.
    pub fn start_shard(&mut self) {
        self.finish_chunks();
        self.shard_start_cycle = self.pending.cycle;
        self.ordinal = 0;
        self.syscall_witnesses.clear();
        let descriptor = &self.range_descriptors[self.next_range_descriptor];
        assert_eq!(descriptor.sequence, 0);
        assert_eq!(
            self.current.typed.len(),
            InsnKind::COUNT,
            "GPU replay shard transition lost a warmed CPU owner"
        );
        assert!(
            self.recyclable.is_some(),
            "GPU replay shard transition did not recover both warmed CPU owners"
        );
        self.current
            .reset_from_descriptor(descriptor, self.shard_start_cycle);
    }

    pub fn take_sealed_chunks(&mut self) -> Vec<GpuReplayChunk> {
        std::mem::take(&mut self.sealed)
    }

    pub fn recycle_range(&mut self, range: crate::GpuReplayTypedRange) {
        let mut recycled = GpuReplayChunk {
            sequence: range.sequence,
            shard_start_cycle: self.shard_start_cycle,
            typed: range.typed,
            fallback: range.fallback,
        };
        if self.current.typed.is_empty() {
            let current_shard_id = self
                .next_range_descriptor
                .checked_sub(1)
                .map(|index| self.range_descriptors[index].shard_id);
            if let Some(descriptor) = self
                .range_descriptors
                .get(self.next_range_descriptor)
                .filter(|descriptor| Some(descriptor.shard_id) == current_shard_id)
            {
                recycled.reset_from_descriptor(descriptor, self.shard_start_cycle);
            } else {
                recycled.reset_empty(self.shard_start_cycle);
            }
            self.current = recycled;
        } else {
            assert!(self.recyclable.is_none(), "GPU replay range recycled twice");
            self.recyclable = Some(recycled);
        }
    }

    pub fn syscall_witnesses(&self) -> &[SyscallWitness] {
        &self.syscall_witnesses
    }

    pub fn take_syscall_witnesses(&mut self) -> Vec<SyscallWitness> {
        std::mem::take(&mut self.syscall_witnesses)
    }

    pub fn max_heap_addr_access(&self) -> ByteAddr {
        self.max_heap_addr_access
    }

    pub fn max_hint_addr_access(&self) -> ByteAddr {
        self.max_hint_addr_access
    }

    pub fn remaining_chunk_capacity(&self) -> usize {
        self.config
            .chunk_capacity
            .saturating_sub(self.current.len())
    }

    fn checked_cycle(cycle: Cycle) -> u32 {
        u32::try_from(cycle).expect("GPU replay predecessor cycle exceeds u32")
    }

    fn annotate_pending(&mut self) {
        let start = self.pending.cycle;
        let end = start + FullTracer::SUBCYCLES_PER_INSN;
        while let Some(event) = self
            .next_accesses
            .events()
            .get(self.next_access_cursor)
            .copied()
        {
            assert!(
                event.source_cycle >= start,
                "GPU replay skipped next-access event"
            );
            if event.source_cycle >= end {
                break;
            }
            let subcycle = event.source_cycle - start;
            let bit = match subcycle {
                FullTracer::SUBCYCLE_RS1
                    if self.pending.has_rs1 && self.pending.rs1.addr == event.address =>
                {
                    StepRecord::FUTURE_ACCESS_RS1
                }
                FullTracer::SUBCYCLE_RS2
                    if self.pending.has_rs2 && self.pending.rs2.addr == event.address =>
                {
                    StepRecord::FUTURE_ACCESS_RS2
                }
                FullTracer::SUBCYCLE_RD
                    if self.pending.has_rd && self.pending.rd.addr == event.address =>
                {
                    StepRecord::FUTURE_ACCESS_RD
                }
                FullTracer::SUBCYCLE_MEM
                    if self.pending.has_memory_op
                        && self.pending.memory_op.addr == event.address =>
                {
                    StepRecord::FUTURE_ACCESS_MEM
                }
                FullTracer::SUBCYCLE_RD if self.pending.has_syscall() => {
                    self.annotate_syscall(event.address, true);
                    0
                }
                FullTracer::SUBCYCLE_MEM if self.pending.has_syscall() => {
                    self.annotate_syscall(event.address, false);
                    0
                }
                _ => panic!("GPU replay access/tape mismatch"),
            };
            self.pending.future_access_mask |= bit;
            self.next_access_cursor += 1;
        }
    }

    fn annotate_syscall(&mut self, address: WordAddr, registers: bool) {
        let witness = &mut self.syscall_witnesses[self.pending.syscall_index as usize];
        let (ops, masks) = if registers {
            (&witness.reg_ops, &mut witness.reg_future_access)
        } else {
            (&witness.mem_ops, &mut witness.mem_future_access)
        };
        let index = ops
            .iter()
            .rposition(|op| op.addr == address)
            .expect("GPU replay syscall access/tape address mismatch");
        masks[index] = 1;
    }

    fn update_mmio_bounds(&mut self, addr: WordAddr) {
        let Some((start_addr, (_, end_addr, min_addr, max_addr))) = self
            .mmio_min_max_access
            .as_mut()
            .and_then(|bounds| bounds.range_mut(..=addr).next_back())
        else {
            return;
        };
        if addr >= *end_addr {
            return;
        }
        *min_addr = (*min_addr).min(addr);
        *max_addr = (*max_addr).max(addr + WordAddr::from(WORD_SIZE as u32));
        let access_end = (addr + WordAddr::from(WORD_SIZE as u32)).baddr();
        if start_addr.baddr().0 == self.platform.heap.start {
            self.max_heap_addr_access = self.max_heap_addr_access.max(access_end);
        } else if start_addr.baddr().0 == self.platform.hints.start {
            self.max_hint_addr_access = self.max_hint_addr_access.max(access_end);
        }
    }
}

#[cfg(all(feature = "aot-x86_64", target_arch = "x86_64", target_os = "linux"))]
pub(crate) struct GpuReplayNativeTraceState {
    pub kinds: *mut crate::gpu_typed_ingress::GpuTypedNativeKindState,
    pub kind_count: usize,
    pub ordinal: *mut usize,
    pub pending_cycle: *mut Cycle,
    pub latest_cells: *mut Cycle,
    pub latest_base: WordAddr,
    pub latest_len: *mut usize,
    pub max_heap_addr_access: *mut ByteAddr,
    pub max_hint_addr_access: *mut ByteAddr,
    pub next_access_events: *const NextAccessEvent,
    pub next_access_len: usize,
    pub next_access_cursor: *mut usize,
    pub error: *mut u32,
}

#[cfg(all(feature = "aot-x86_64", target_arch = "x86_64", target_os = "linux"))]
pub(crate) struct FullTracerNativeTraceState {
    pub records: *mut StepRecord,
    pub len: *mut usize,
    pub pending_index: *mut usize,
    pub pending_cycle: *mut Cycle,
    pub latest_cells: *mut Cycle,
    pub latest_base: WordAddr,
    pub latest_len: *mut usize,
    pub max_heap_addr_access: *mut ByteAddr,
    pub max_hint_addr_access: *mut ByteAddr,
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
            allow_step_buffer_growth: config.max_step_shard == 0 || cfg!(debug_assertions),
            syscall_witnesses: Vec::new(),
            mmio_min_max_access: Some(mmio_max_access),
            platform: platform.clone(),
            latest_accesses: LatestAccesses::new(platform),
            next_accesses: Arc::new(NextAccessTape::default()),
            next_access_cursor: 0,
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
            if self.allow_step_buffer_growth {
                // Standalone VM execution and debug tests do not need to plumb
                // an accurate shard capacity.
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

    #[cfg(test)]
    pub(crate) fn apply_next_access_events_for_test(&mut self, events: &[NextAccessEvent]) {
        self.next_accesses = Arc::new(NextAccessTape::from_unsorted(events.to_vec()));
        self.next_access_cursor = 0;
        for record in &mut self.records[..self.len] {
            record.future_access_mask = 0;
        }
        for witness in &mut self.syscall_witnesses {
            witness.reg_future_access.fill(0);
            witness.mem_future_access.fill(0);
        }
        for event in events {
            if event.source_cycle == 0 {
                continue;
            }
            let ordinal = ((event.source_cycle - Self::SUBCYCLES_PER_INSN)
                / Self::SUBCYCLES_PER_INSN) as usize;
            self.annotate_event(ordinal, *event);
        }
    }

    pub fn record_buffer_bytes(&self) -> usize {
        self.records.capacity() * std::mem::size_of::<StepRecord>()
    }

    #[cfg(all(feature = "aot-x86_64", target_arch = "x86_64", target_os = "linux"))]
    pub(crate) fn native_trace_state(&mut self) -> FullTracerNativeTraceState {
        FullTracerNativeTraceState {
            records: self.records.as_mut_ptr(),
            len: &mut self.len,
            pending_index: &mut self.pending_index,
            pending_cycle: &mut self.pending_cycle,
            latest_cells: self.latest_accesses.cells_mut_ptr(),
            latest_base: self.latest_accesses.base(),
            latest_len: &mut self.latest_accesses.len,
            max_heap_addr_access: &mut self.max_heap_addr_access,
            max_hint_addr_access: &mut self.max_hint_addr_access,
        }
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
    pub fn load_memory(&mut self, addr: WordAddr, value: Word, previous_cycle: Cycle) {
        self.store_memory(addr, Change::new(value, value), previous_cycle);
    }

    #[inline(always)]
    pub fn store_memory(&mut self, addr: WordAddr, value: Change<Word>, previous_cycle: Cycle) {
        if self.records[self.pending_index].has_memory_op {
            unimplemented!("Only one memory access is supported");
        }

        // Update the tracked min/max MMIO bounds so later phases only materialize
        // the actually touched address range for heap / hint regions.
        if let Some((start_addr, (_, end_addr, min_addr, max_addr))) = self
            .mmio_min_max_access
            .as_mut()
            .and_then(|mmio_max_access| mmio_max_access.range_mut(..=addr).next_back())
        {
            if addr < *end_addr {
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
        }

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

    pub fn final_register_accesses(&self) -> &LatestAccesses {
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

    fn annotate_syscall_event(
        &mut self,
        witness_index: usize,
        address: WordAddr,
        register_ops: bool,
    ) {
        let ops = if register_ops {
            &self.syscall_witnesses[witness_index].reg_ops
        } else {
            &self.syscall_witnesses[witness_index].mem_ops
        };
        let index = ops
            .iter()
            .rposition(|op| op.addr == address)
            .unwrap_or_else(|| panic!("FullTracer syscall access/tape address mismatch"));
        let masks = if register_ops {
            &mut self.syscall_witnesses[witness_index].reg_future_access
        } else {
            &mut self.syscall_witnesses[witness_index].mem_future_access
        };
        masks[index] = 1;
    }

    fn annotate_event(&mut self, record_index: usize, event: NextAccessEvent) {
        #[cfg(debug_assertions)]
        assert!(
            self.next_accesses
                .oracle_has(event.source_cycle, event.address),
            "cursor missed debug next-access oracle"
        );
        let record = self.records[record_index];
        let subcycle = event
            .source_cycle
            .checked_sub(record.cycle)
            .expect("next-access event precedes its replay record");
        let mask = match subcycle {
            Self::SUBCYCLE_RS1 if record.has_rs1 && record.rs1.addr == event.address => {
                StepRecord::FUTURE_ACCESS_RS1
            }
            Self::SUBCYCLE_RS2 if record.has_rs2 && record.rs2.addr == event.address => {
                StepRecord::FUTURE_ACCESS_RS2
            }
            Self::SUBCYCLE_RD if record.has_rd && record.rd.addr == event.address => {
                StepRecord::FUTURE_ACCESS_RD
            }
            Self::SUBCYCLE_MEM
                if record.has_memory_op && record.memory_op.addr == event.address =>
            {
                StepRecord::FUTURE_ACCESS_MEM
            }
            Self::SUBCYCLE_RD if record.syscall_index != StepRecord::NO_SYSCALL => {
                self.annotate_syscall_event(record.syscall_index as usize, event.address, true);
                0
            }
            Self::SUBCYCLE_MEM if record.syscall_index != StepRecord::NO_SYSCALL => {
                self.annotate_syscall_event(record.syscall_index as usize, event.address, false);
                0
            }
            _ => panic!(
                "FullTracer access/tape mismatch at cycle {} for address {:?}",
                event.source_cycle, event.address
            ),
        };
        self.records[record_index].future_access_mask |= mask;
    }

    /// Apply the sorted next-access tape to a newly completed record range.
    ///
    /// Source cycles map directly to replay records, so this work is proportional
    /// to the number of cross-shard events rather than the number of instructions.
    pub fn annotate_recorded_steps(&mut self, start_index: usize) {
        assert!(start_index <= self.len);
        if start_index == self.len {
            return;
        }
        let chunk_start_cycle = self.records[start_index].cycle;
        let chunk_end_cycle = self.records[self.len - 1].cycle + Self::SUBCYCLES_PER_INSN;
        while let Some(event) = self
            .next_accesses
            .events()
            .get(self.next_access_cursor)
            .copied()
        {
            assert!(
                event.source_cycle >= chunk_start_cycle,
                "FullTracer skipped next-access event {:?} before replay chunk starting at {}",
                event,
                chunk_start_cycle
            );
            if event.source_cycle >= chunk_end_cycle {
                break;
            }
            let record_offset = usize::try_from(
                (event.source_cycle - chunk_start_cycle) / Self::SUBCYCLES_PER_INSN,
            )
            .expect("next-access record offset does not fit usize");
            self.annotate_event(start_index + record_offset, event);
            self.next_access_cursor += 1;
        }
    }

    pub fn assert_next_accesses_consumed(&self) {
        assert_eq!(
            self.next_access_cursor,
            self.next_accesses.events().len(),
            "FullTracer consumed {} of {} non-initial next-access events",
            self.next_access_cursor,
            self.next_accesses.events().len()
        );
    }

    pub fn assert_next_accesses_consumed_through(&self, end_cycle: Cycle) {
        assert!(
            self.next_accesses
                .events()
                .get(self.next_access_cursor)
                .is_none_or(|event| event.source_cycle >= end_cycle),
            "FullTracer left a next-access event before shard end cycle {end_cycle}"
        );
    }
}

pub struct PreflightTracer {
    cycle: Cycle,
    pc: Change<ByteAddr>,
    last_kind: InsnKind,
    last_rs1: Option<Word>,
    mmio_min_max_access: Option<BTreeMap<WordAddr, (WordAddr, WordAddr, WordAddr, WordAddr)>>,
    latest_accesses: LatestAccesses,
    next_access_events: Vec<NextAccessEvent>,
    next_access_capacity: Option<usize>,
    next_access_growths: usize,
    next_access_growth_bytes: usize,
    next_access_growth_time: Duration,
    register_reads_tracked: u8,
    planner: Option<ShardPlanBuilder>,
    current_shard_start_cycle: Cycle,
    replay_shard_previews: Vec<crate::GpuShardPreview>,
    preview_heap_start: ByteAddr,
    preview_hint_start: ByteAddr,
    platform_heap_start: ByteAddr,
    platform_hint_start: ByteAddr,
    defer_mmio_bounds: bool,
    #[cfg(all(feature = "aot-x86_64", target_arch = "x86_64", target_os = "linux"))]
    combined_capture: Option<PreflightCombinedCapture>,
    config: PreflightTracerConfig,
}

#[cfg(all(feature = "aot-x86_64", target_arch = "x86_64", target_os = "linux"))]
struct PreflightCombinedCapture {
    typed: Vec<Option<crate::GpuTypedSoaArena>>,
    native_kinds: [crate::gpu_typed_ingress::GpuTypedNativeKindState; InsnKind::COUNT],
    ordinal: usize,
    pending_cycle: Cycle,
    register_latest: LatestAccesses,
    max_heap_addr_access: ByteAddr,
    max_hint_addr_access: ByteAddr,
    event_cursor: usize,
    error: u32,
    sealed: Vec<crate::GpuReplayTypedRange>,
    descriptor_cursor: usize,
    range_capacity: usize,
    pending: StepRecord,
    fallback: Vec<GpuReplayFallbackRecord>,
    syscall_witnesses: Vec<SyscallWitness>,
    patches: Vec<CrossShardPatch>,
    initialization_events: Vec<NextAccessEvent>,
    patches_resolved: bool,
}

#[cfg(all(feature = "aot-x86_64", target_arch = "x86_64", target_os = "linux"))]
impl PreflightCombinedCapture {
    fn new(platform: &Platform, range_capacity: usize) -> Self {
        let scratch_capacity = range_capacity
            .checked_mul(2)
            .expect("combined capture scratch capacity overflow");
        Self {
            typed: InsnKind::iter()
                .map(|kind| crate::GpuTypedSoaArena::new(kind, scratch_capacity))
                .collect(),
            native_kinds: [crate::gpu_typed_ingress::GpuTypedNativeKindState::default();
                InsnKind::COUNT],
            ordinal: 0,
            pending_cycle: FullTracer::SUBCYCLES_PER_INSN,
            register_latest: LatestAccesses::new(platform),
            max_heap_addr_access: ByteAddr::from(platform.heap.start),
            max_hint_addr_access: ByteAddr::from(platform.hints.start),
            event_cursor: 0,
            error: 0,
            sealed: Vec::new(),
            descriptor_cursor: 0,
            range_capacity,
            pending: StepRecord {
                cycle: FullTracer::SUBCYCLES_PER_INSN,
                heap_maxtouch_addr: Change::new(
                    ByteAddr::from(platform.heap.start),
                    ByteAddr::from(platform.heap.start),
                ),
                hint_maxtouch_addr: Change::new(
                    ByteAddr::from(platform.hints.start),
                    ByteAddr::from(platform.hints.start),
                ),
                ..StepRecord::default()
            },
            fallback: Vec::new(),
            syscall_witnesses: Vec::new(),
            patches: Vec::new(),
            initialization_events: Vec::new(),
            patches_resolved: false,
        }
    }

    fn shard_for_cycle(boundaries: &[Cycle], cycle: Cycle) -> Result<u32, &'static str> {
        if boundaries.first().copied() != Some(FullTracer::SUBCYCLES_PER_INSN) {
            return Err("deferred patch shard boundaries have invalid start");
        }
        let shard = boundaries.partition_point(|boundary| *boundary <= cycle);
        if shard == 0 || shard >= boundaries.len() {
            return Err("deferred patch cycle is outside finalized shard boundaries");
        }
        u32::try_from(shard - 1).map_err(|_| "deferred patch shard exceeds u32")
    }

    fn resolve_patches(
        &mut self,
        events: &[NextAccessEvent],
        boundaries: &[Cycle],
    ) -> Result<(), &'static str> {
        if self.patches_resolved {
            return Err("combined capture deferred patches resolved multiple times");
        }
        let mut events = events.to_vec();
        events
            .sort_unstable_by_key(|event| (event.source_cycle, event.address, event.target_cycle));
        for pair in events.windows(2) {
            if (pair[0].source_cycle, pair[0].address) == (pair[1].source_cycle, pair[1].address) {
                return Err("duplicate deferred patch source/address");
            }
        }
        for event in events {
            if event.target_cycle <= event.source_cycle {
                return Err("deferred patch target does not follow source");
            }
            if event.source_cycle == 0 {
                Self::shard_for_cycle(boundaries, event.target_cycle)?;
                self.initialization_events.push(event);
                continue;
            }
            let ordinal = event
                .source_cycle
                .checked_sub(FullTracer::SUBCYCLES_PER_INSN)
                .ok_or("deferred patch source precedes first instruction")?
                / FullTracer::SUBCYCLES_PER_INSN;
            let ordinal =
                u32::try_from(ordinal).map_err(|_| "deferred patch ordinal exceeds u32")?;
            let (mask, lane, ram_class) = match event.source_cycle % 4 {
                FullTracer::SUBCYCLE_RS1 => (
                    StepRecord::FUTURE_ACCESS_RS1,
                    PatchSourceLane::Rs1,
                    PatchRamClass::Register,
                ),
                FullTracer::SUBCYCLE_RS2 => (
                    StepRecord::FUTURE_ACCESS_RS2,
                    PatchSourceLane::Rs2,
                    PatchRamClass::Register,
                ),
                FullTracer::SUBCYCLE_RD => (
                    StepRecord::FUTURE_ACCESS_RD,
                    PatchSourceLane::Rd,
                    PatchRamClass::Register,
                ),
                FullTracer::SUBCYCLE_MEM => (
                    StepRecord::FUTURE_ACCESS_MEM,
                    PatchSourceLane::Memory,
                    PatchRamClass::Memory,
                ),
                _ => unreachable!(),
            };
            let mut matches = 0;
            let mut prior_value = 0;
            for arena in self
                .sealed
                .iter_mut()
                .flat_map(|range| range.typed.iter_mut().flatten())
            {
                if let Some(value) =
                    arena.patch_future_access_checked(ordinal, mask, event.address)?
                {
                    matches += 1;
                    prior_value = value;
                }
            }
            let mut resolved_lane = lane;
            let mut resolved_class = ram_class;
            let mut syscall_op_index = u16::MAX;
            let mut syscall_witness_index = u32::MAX;
            for fallback in self
                .sealed
                .iter_mut()
                .flat_map(|range| range.fallback.iter_mut())
                .filter(|record| record.ordinal == ordinal)
            {
                matches += 1;
                let record = &mut fallback.record;
                let subcycle = event.source_cycle - record.cycle;
                match subcycle {
                    FullTracer::SUBCYCLE_RS1
                        if record.has_rs1 && record.rs1.addr == event.address =>
                    {
                        record.future_access_mask |= StepRecord::FUTURE_ACCESS_RS1;
                        prior_value = record.rs1.value;
                    }
                    FullTracer::SUBCYCLE_RS2
                        if record.has_rs2 && record.rs2.addr == event.address =>
                    {
                        record.future_access_mask |= StepRecord::FUTURE_ACCESS_RS2;
                        prior_value = record.rs2.value;
                    }
                    FullTracer::SUBCYCLE_RD if record.has_rd && record.rd.addr == event.address => {
                        record.future_access_mask |= StepRecord::FUTURE_ACCESS_RD;
                        prior_value = record.rd.value.after;
                    }
                    FullTracer::SUBCYCLE_MEM
                        if record.has_memory_op && record.memory_op.addr == event.address =>
                    {
                        record.future_access_mask |= StepRecord::FUTURE_ACCESS_MEM;
                        prior_value = record.memory_op.value.after;
                    }
                    FullTracer::SUBCYCLE_RD if record.syscall_index != StepRecord::NO_SYSCALL => {
                        let witness = &mut self.syscall_witnesses[record.syscall_index as usize];
                        let index = witness
                            .reg_ops
                            .iter()
                            .rposition(|op| op.addr == event.address)
                            .ok_or("deferred patch syscall register address missing")?;
                        witness.reg_future_access[index] = 1;
                        prior_value = witness.reg_ops[index].value.after;
                        resolved_lane = PatchSourceLane::SyscallRegister;
                        syscall_op_index = u16::try_from(index)
                            .map_err(|_| "deferred patch syscall operation exceeds u16")?;
                        syscall_witness_index = record.syscall_index;
                    }
                    FullTracer::SUBCYCLE_MEM if record.syscall_index != StepRecord::NO_SYSCALL => {
                        let witness = &mut self.syscall_witnesses[record.syscall_index as usize];
                        let index = witness
                            .mem_ops
                            .iter()
                            .rposition(|op| op.addr == event.address)
                            .ok_or("deferred patch syscall memory address missing")?;
                        witness.mem_future_access[index] = 1;
                        prior_value = witness.mem_ops[index].value.after;
                        resolved_lane = PatchSourceLane::SyscallMemory;
                        resolved_class = PatchRamClass::Memory;
                        syscall_op_index = u16::try_from(index)
                            .map_err(|_| "deferred patch syscall operation exceeds u16")?;
                        syscall_witness_index = record.syscall_index;
                    }
                    _ => return Err("deferred patch does not match sparse source record"),
                }
            }
            if matches != 1 {
                return Err("deferred patch source ordinal does not resolve exactly once");
            }
            let source_shard = Self::shard_for_cycle(boundaries, event.source_cycle)?;
            let target_shard = Self::shard_for_cycle(boundaries, event.target_cycle)?;
            if source_shard >= target_shard {
                return Err("deferred patch does not cross a shard boundary");
            }
            self.patches.push(CrossShardPatch {
                source_cycle: event.source_cycle,
                target_cycle: event.target_cycle,
                address: event.address,
                prior_value,
                source_shard,
                target_shard,
                ram_class: resolved_class,
                source_lane: resolved_lane,
                syscall_op_index,
                syscall_witness_index,
            });
        }
        self.patches_resolved = true;
        Ok(())
    }

    fn native_state(&mut self) -> GpuReplayNativeTraceState {
        self.error = 0;
        for (index, slot) in self.native_kinds.iter_mut().enumerate() {
            *slot = self.typed[index]
                .as_mut()
                .map_or_else(Default::default, crate::GpuTypedSoaArena::native_state);
        }
        GpuReplayNativeTraceState {
            kinds: self.native_kinds.as_mut_ptr(),
            kind_count: InsnKind::COUNT,
            ordinal: &mut self.ordinal,
            pending_cycle: &mut self.pending_cycle,
            latest_cells: self.register_latest.cells_mut_ptr(),
            latest_base: self.register_latest.base(),
            latest_len: &mut self.register_latest.len,
            max_heap_addr_access: &mut self.max_heap_addr_access,
            max_hint_addr_access: &mut self.max_hint_addr_access,
            next_access_events: std::ptr::null(),
            next_access_len: 0,
            next_access_cursor: &mut self.event_cursor,
            error: &mut self.error,
        }
    }

    fn sync_native(&mut self) -> Result<(), &'static str> {
        if self.error != 0 {
            return Err("combined preflight native capture reported an ABI or cursor error");
        }
        for (index, state) in self.native_kinds.iter().enumerate() {
            match self.typed[index].as_mut() {
                Some(arena) => arena.sync_native_state(state)?,
                None if state.capacity == 0 && state.cursor == 0 => {}
                None => return Err("combined preflight capture used an absent family"),
            }
        }
        Ok(())
    }

    fn seal_available(
        &mut self,
        descriptors: &[crate::GpuReplayRangeDescriptor],
    ) -> Result<(), &'static str> {
        self.sync_native()?;
        while let Some(descriptor) = descriptors.get(self.descriptor_cursor) {
            if descriptor.range_len as usize > self.range_capacity {
                return Err("combined capture descriptor exceeds 262144-row range bound");
            }
            if descriptor.unsupported_count != 0 {
                return Err("combined preflight unsupported fallback capture is not implemented");
            }
            if self
                .typed
                .iter()
                .zip(descriptor.family_counts)
                .any(|(arena, rows)| arena.as_ref().map_or(0, crate::GpuTypedSoaArena::len) < rows)
            {
                break;
            }
            if self.fallback.len() < descriptor.fallback_count {
                break;
            }
            let typed = self
                .typed
                .iter_mut()
                .zip(descriptor.family_counts)
                .map(|(arena, rows)| {
                    if rows == 0 {
                        Ok(None)
                    } else {
                        arena
                            .as_mut()
                            .ok_or("combined capture descriptor names absent family")?
                            .drain_prefix(rows)
                            .map(Some)
                    }
                })
                .collect::<Result<Vec<_>, _>>()?;
            let fallback = self
                .fallback
                .drain(..descriptor.fallback_count)
                .collect::<Vec<_>>();
            self.sealed.push(crate::GpuReplayTypedRange {
                sequence: descriptor.sequence,
                typed,
                fallback,
            });
            self.descriptor_cursor += 1;
        }
        for (index, arena) in self.typed.iter_mut().enumerate() {
            if let Some(arena) = arena {
                self.native_kinds[index] = arena.native_state();
            }
        }
        Ok(())
    }
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
    pub memory_previous_cycle: Cycle,
}

#[cfg_attr(
    not(all(feature = "aot-x86_64", target_arch = "x86_64", target_os = "linux")),
    allow(dead_code)
)]
pub(crate) struct PreflightNativeTraceState {
    pub latest_cells: *mut Cycle,
    pub latest_base: WordAddr,
    pub latest_len: *mut usize,
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
    pub replay_range_len: *mut usize,
    pub replay_family_counts: *mut usize,
    pub replay_fallback_count: *mut usize,
    pub replay_unsupported_count: *mut usize,
    pub replay_range_capacity: usize,
}

#[derive(Clone)]
pub struct PreflightTracerConfig {
    record_next_accesses: bool,
    max_cell_per_shard: u64,
    max_cycle_per_shard: Cycle,
    step_cell_extractor: Option<Arc<dyn StepCellExtractor>>,
    replay_range_capacity: usize,
    combined_capture: bool,
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
            .field("next_access_events", &self.next_access_events)
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
            .field("replay_range_capacity", &self.replay_range_capacity)
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
            replay_range_capacity: 256 * 1024,
            combined_capture: false,
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

    pub fn with_replay_range_capacity(mut self, capacity: usize) -> Self {
        assert!(capacity > 0, "GPU replay range capacity must be nonzero");
        self.replay_range_capacity = capacity;
        self
    }

    pub fn with_combined_capture(mut self, enabled: bool) -> Self {
        self.combined_capture = enabled;
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
            replay_range_capacity: 256 * 1024,
            combined_capture: false,
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

    pub fn last_pc_change(&self) -> Change<ByteAddr> {
        self.pc
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
        let mut planner = ShardPlanBuilder::new_with_cost_model(
            max_cell_per_shard,
            planner_cycle_limit,
            cost_model,
        );
        planner.set_replay_range_capacity(config.replay_range_capacity);
        let mut tracer = PreflightTracer {
            cycle: <Self as Tracer>::SUBCYCLES_PER_INSN,
            pc: Default::default(),
            last_kind: InsnKind::INVALID,
            last_rs1: None,
            mmio_min_max_access: Some(init_mmio_min_max_access(platform)),
            latest_accesses: LatestAccesses::new(platform),
            next_access_events: Vec::new(),
            next_access_capacity: None,
            next_access_growths: 0,
            next_access_growth_bytes: 0,
            next_access_growth_time: Duration::ZERO,
            register_reads_tracked: 0,
            planner: Some(planner),
            current_shard_start_cycle: <Self as Tracer>::SUBCYCLES_PER_INSN,
            replay_shard_previews: Vec::new(),
            preview_heap_start: ByteAddr::from(platform.heap.start),
            preview_hint_start: ByteAddr::from(platform.hints.start),
            platform_heap_start: ByteAddr::from(platform.heap.start),
            platform_hint_start: ByteAddr::from(platform.hints.start),
            defer_mmio_bounds: false,
            #[cfg(all(feature = "aot-x86_64", target_arch = "x86_64", target_os = "linux"))]
            combined_capture: config
                .combined_capture
                .then(|| PreflightCombinedCapture::new(platform, config.replay_range_capacity)),
            config,
        };
        tracer.reset_register_tracking();
        tracer
    }

    #[cfg(all(feature = "aot-x86_64", target_arch = "x86_64", target_os = "linux"))]
    pub(crate) fn combined_capture_enabled(&self) -> bool {
        self.combined_capture.is_some()
    }

    #[cfg(all(feature = "aot-x86_64", target_arch = "x86_64", target_os = "linux"))]
    pub(crate) fn prepare_combined_capture_native(&mut self) -> Option<GpuReplayNativeTraceState> {
        self.combined_capture
            .as_mut()
            .map(PreflightCombinedCapture::native_state)
    }

    #[cfg(all(feature = "aot-x86_64", target_arch = "x86_64", target_os = "linux"))]
    pub(crate) fn sync_combined_capture(&mut self) -> Result<(), &'static str> {
        let descriptors = self
            .planner
            .as_ref()
            .expect("shard planner missing")
            .replay_descriptors
            .clone();
        if let Some(capture) = self.combined_capture.as_mut() {
            capture.seal_available(&descriptors)?;
        }
        Ok(())
    }

    #[cfg(all(
        test,
        feature = "aot-x86_64",
        target_arch = "x86_64",
        target_os = "linux"
    ))]
    pub(crate) fn finish_combined_capture_for_test(
        &mut self,
    ) -> Result<
        (
            &[crate::GpuReplayTypedRange],
            &[SyscallWitness],
            &[CrossShardPatch],
            &[NextAccessEvent],
        ),
        &'static str,
    > {
        let planner = self.planner.as_mut().expect("shard planner missing");
        if !planner.finalized {
            planner.finalize(self.cycle);
        }
        self.sync_combined_capture()?;
        let boundaries = self
            .planner
            .as_ref()
            .expect("shard planner missing")
            .shard_cycle_boundaries()
            .to_vec();
        let events = self.next_access_events.clone();
        if let Some(capture) = self.combined_capture.as_mut()
            && !capture.patches_resolved
        {
            capture.resolve_patches(&events, &boundaries)?;
        }
        let capture = self
            .combined_capture
            .as_ref()
            .expect("combined capture missing");
        Ok((
            &capture.sealed,
            &capture.syscall_witnesses,
            &capture.patches,
            &capture.initialization_events,
        ))
    }

    #[cfg(all(
        test,
        feature = "aot-x86_64",
        target_arch = "x86_64",
        target_os = "linux"
    ))]
    pub(crate) fn raw_next_access_events_for_test(&self) -> &[NextAccessEvent] {
        &self.next_access_events
    }

    pub fn into_shard_plan(
        self,
    ) -> (
        ShardPlanBuilder,
        NextCycleAccess,
        Vec<crate::GpuShardPreview>,
    ) {
        let (planner, next_accesses, previews, _) = self
            .into_shard_plan_with_capture()
            .expect("combined preflight capture finalization failed");
        (planner, next_accesses, previews)
    }

    pub fn into_shard_plan_with_capture(
        mut self,
    ) -> Result<
        (
            ShardPlanBuilder,
            NextCycleAccess,
            Vec<crate::GpuShardPreview>,
            Option<CombinedPreflightCapture>,
        ),
        &'static str,
    > {
        if self
            .planner
            .as_ref()
            .is_some_and(|planner| self.replay_shard_previews.len() <= planner.shard_id)
        {
            self.capture_shard_preview(self.cycle);
        }
        let Some(mut planner) = self.planner else {
            panic!("shard planner missing")
        };
        if !planner.finalized {
            planner.finalize(self.cycle);
        }
        #[cfg(all(feature = "aot-x86_64", target_arch = "x86_64", target_os = "linux"))]
        let capture = if let Some(mut capture) = self.combined_capture.take() {
            capture.seal_available(&planner.replay_descriptors)?;
            if !capture.patches_resolved {
                capture
                    .resolve_patches(&self.next_access_events, planner.shard_cycle_boundaries())?;
            }
            if capture.descriptor_cursor != planner.replay_descriptors.len() {
                return Err("combined preflight capture did not seal every descriptor");
            }
            Some(CombinedPreflightCapture {
                ranges: capture.sealed,
                syscall_witnesses: capture.syscall_witnesses,
                patches: capture.patches,
                initialization_events: capture.initialization_events,
            })
        } else {
            None
        };
        #[cfg(not(all(feature = "aot-x86_64", target_arch = "x86_64", target_os = "linux")))]
        let capture = None;
        Ok((
            planner,
            NextAccessTape::from_unsorted(self.next_access_events),
            self.replay_shard_previews,
            capture,
        ))
    }

    fn mmio_region_end(&self, start: ByteAddr) -> ByteAddr {
        self.mmio_min_max_access
            .as_ref()
            .and_then(|regions| regions.get(&start.waddr()))
            .map_or(start, |(_, _, _, max)| max.baddr())
    }

    fn capture_shard_preview(&mut self, cycle_end: Cycle) {
        let heap_end = self.mmio_region_end(self.platform_heap_start);
        let hint_end = self.mmio_region_end(self.platform_hint_start);
        self.replay_shard_previews.push(crate::GpuShardPreview {
            shard_id: u32::try_from(self.replay_shard_previews.len())
                .expect("GPU preview shard id exceeds u32"),
            cycle_start: self.current_shard_start_cycle,
            cycle_end,
            heap_start: self.preview_heap_start.0,
            heap_end: heap_end.0,
            hint_start: self.preview_hint_start.0,
            hint_end: hint_end.0,
        });
        self.preview_heap_start = heap_end;
        self.preview_hint_start = hint_end;
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
    #[inline(always)]
    pub(crate) fn track_direct_syscall_memory(&mut self, addr: WordAddr, previous_cycle: Cycle) {
        self.record_memory_access(addr, previous_cycle);
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
            latest_len: &mut self.latest_accesses.len,
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
            replay_range_len: &mut planner.replay_range_len,
            replay_family_counts: planner.replay_family_counts.as_mut_ptr(),
            replay_fallback_count: &mut planner.replay_fallback_count,
            replay_unsupported_count: &mut planner.replay_unsupported_count,
            replay_range_capacity: planner.replay_range_capacity,
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
        let mut split = false;
        let mut next_start = self.current_shard_start_cycle;
        if let Some(planner) = self.planner.as_mut() {
            let old_shard = planner.shard_id;
            if planner.cost_model.is_some() {
                planner.observe_modeled_step(self.cycle, self.last_kind, ecall_code);
            } else {
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
            }
            split = planner.shard_id != old_shard;
            next_start = planner.current_shard_start_cycle();
        }
        if split {
            self.capture_shard_preview(self.cycle);
        }
        self.current_shard_start_cycle = next_start;
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

    #[cfg(all(feature = "aot-x86_64", target_arch = "x86_64", target_os = "linux"))]
    pub(crate) fn begin_deferred_mmio_bounds(&mut self) {
        assert!(
            self.config.record_next_accesses,
            "deferred MMIO bounds require first-access events"
        );
        self.defer_mmio_bounds = true;
    }

    #[cfg(all(feature = "aot-x86_64", target_arch = "x86_64", target_os = "linux"))]
    pub(crate) fn finish_deferred_mmio_bounds(&mut self) {
        if !self.defer_mmio_bounds {
            return;
        }
        self.defer_mmio_bounds = false;

        let Some(regions) = self.mmio_min_max_access.as_mut() else {
            return;
        };
        let mut bounds = regions.values().copied().collect::<Vec<_>>();
        for (start_addr, end_addr, min_addr, max_addr) in &mut bounds {
            *min_addr = *end_addr;
            *max_addr = *start_addr;
        }
        for event in self
            .next_access_events
            .iter()
            .filter(|event| event.source_cycle == 0)
        {
            for (start_addr, end_addr, min_addr, max_addr) in &mut bounds {
                if event.address >= *start_addr && event.address < *end_addr {
                    *min_addr = (*min_addr).min(event.address);
                    *max_addr = (*max_addr).max(event.address + 1usize);
                    break;
                }
            }
        }
        for ((_, region), bounds) in regions.iter_mut().zip(bounds) {
            *region = bounds;
        }

        // Native production preflight captures shard boundaries while MMIO
        // bound writes are deferred.  Reconstruct each monotonic shard-local
        // heap/hint maximum from the same authoritative first-touch events
        // used above, keyed by the cycle at which the address was first used.
        let heap_region = regions
            .get(&self.platform_heap_start.waddr())
            .map(|&(start, end, _, _)| (start, end));
        let hint_region = regions
            .get(&self.platform_hint_start.waddr())
            .map(|&(start, end, _, _)| (start, end));
        if let (Some((heap_start, heap_limit)), Some((hint_start, hint_limit))) =
            (heap_region, hint_region)
        {
            let region_end_at = |start: WordAddr, limit: WordAddr, cycle_end: Cycle| {
                self.next_access_events
                    .iter()
                    .filter(|event| {
                        event.source_cycle == 0
                            && event.target_cycle < cycle_end
                            && event.address >= start
                            && event.address < limit
                    })
                    .fold(start, |end, event| end.max(event.address + 1usize))
                    .baddr()
                    .0
            };
            let mut previous_heap_end = heap_start.baddr().0;
            let mut previous_hint_end = hint_start.baddr().0;
            for preview in &mut self.replay_shard_previews {
                preview.heap_start = previous_heap_end;
                preview.heap_end = region_end_at(heap_start, heap_limit, preview.cycle_end);
                preview.hint_start = previous_hint_end;
                preview.hint_end = region_end_at(hint_start, hint_limit, preview.cycle_end);
                previous_heap_end = preview.heap_end;
                previous_hint_end = preview.hint_end;
            }
            self.preview_heap_start = ByteAddr(previous_heap_end);
            self.preview_hint_start = ByteAddr(previous_hint_end);
        }
    }

    #[cfg(all(feature = "aot-x86_64", target_arch = "x86_64", target_os = "linux"))]
    pub(crate) fn record_native_first_touch(&mut self, addr: WordAddr) {
        self.latest_accesses.record_native_first_touch(addr);
    }

    fn push_next_access_event(&mut self, event: NextAccessEvent) {
        if self.next_access_capacity == Some(self.next_access_events.len()) {
            let (old_capacity, new_capacity) = self.grow_next_access_tape();
            tracing::warn!(
                "AOT next-access tape grew from {old_capacity} to {new_capacity} events"
            );
        }
        self.next_access_events.push(event);
    }

    #[inline(always)]
    fn record_memory_access(&mut self, addr: WordAddr, previous_cycle: Cycle) {
        let current_cycle = self.cycle + Self::SUBCYCLE_MEM;
        if self.config.record_next_accesses && previous_cycle < self.current_shard_start_cycle {
            self.push_next_access_event(NextAccessEvent::new(previous_cycle, current_cycle, addr));
        }
    }

    fn grow_next_access_tape(&mut self) -> (usize, usize) {
        let started = Instant::now();
        let old_capacity = self.next_access_events.capacity();
        let target_capacity = old_capacity
            .saturating_mul(2)
            .max(self.next_access_events.len().saturating_add(4096));
        self.next_access_events
            .reserve_exact(target_capacity - self.next_access_events.len());
        let new_capacity = self.next_access_events.capacity();
        self.next_access_capacity = Some(new_capacity);
        self.next_access_growths = self.next_access_growths.saturating_add(1);
        self.next_access_growth_bytes = self.next_access_growth_bytes.saturating_add(
            new_capacity
                .saturating_sub(old_capacity)
                .saturating_mul(std::mem::size_of::<NextAccessEvent>()),
        );
        self.next_access_growth_time = self
            .next_access_growth_time
            .saturating_add(started.elapsed());
        (old_capacity, new_capacity)
    }

    #[cfg(all(feature = "aot-x86_64", target_arch = "x86_64", target_os = "linux"))]
    pub(crate) fn prepare_native_next_access_tape(&mut self, capacity: usize) {
        assert!(capacity >= self.next_access_events.len());
        self.next_access_events
            .reserve_exact(capacity - self.next_access_events.len());
        self.next_access_capacity = Some(self.next_access_events.capacity());
    }

    #[cfg(all(feature = "aot-x86_64", target_arch = "x86_64", target_os = "linux"))]
    pub(crate) fn native_next_access_ptrs(
        &mut self,
    ) -> (*mut NextAccessEvent, *mut NextAccessEvent) {
        let base = self.next_access_events.as_mut_ptr();
        let cursor = unsafe { base.add(self.next_access_events.len()) };
        let end = unsafe { base.add(self.next_access_events.capacity()) };
        (cursor, end)
    }

    #[cfg(all(feature = "aot-x86_64", target_arch = "x86_64", target_os = "linux"))]
    pub(crate) unsafe fn sync_native_next_access_tape(&mut self, cursor: *mut NextAccessEvent) {
        let len = unsafe { cursor.offset_from(self.next_access_events.as_mut_ptr()) };
        assert!(len >= 0 && len as usize <= self.next_access_events.capacity());
        unsafe { self.next_access_events.set_len(len as usize) };
    }

    #[cfg(all(feature = "aot-x86_64", target_arch = "x86_64", target_os = "linux"))]
    pub(crate) fn grow_native_next_access_tape(&mut self) -> (usize, usize) {
        self.grow_next_access_tape()
    }

    #[cfg(all(feature = "aot-x86_64", target_arch = "x86_64", target_os = "linux"))]
    pub(crate) fn next_access_tape_stats(&self) -> (usize, usize, usize, usize, Duration) {
        (
            self.next_access_events.len(),
            self.next_access_events.capacity(),
            self.next_access_growths,
            self.next_access_growth_bytes,
            self.next_access_growth_time,
        )
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
    pub(crate) fn record_admitted_native_block(
        &mut self,
        histogram: &[u32; InsnKind::COUNT],
        ordered_kinds: &[InsnKind],
    ) {
        self.planner
            .as_mut()
            .expect("shard planner missing")
            .record_admitted_native_block(histogram, ordered_kinds);
    }

    #[cfg_attr(
        not(all(feature = "aot-x86_64", target_arch = "x86_64", target_os = "linux")),
        allow(dead_code)
    )]
    pub(crate) fn record_native_shard_split(&mut self) {
        self.capture_shard_preview(self.cycle);
        let planner = self.planner.as_mut().expect("shard planner missing");
        let next_shard_cycle = self.cycle;
        planner.flush_replay_range();
        planner.record_predicted_shard_cost();
        planner.push_boundary(next_shard_cycle);
        planner.shard_id += 1;
        planner.replay_range_start = 0;
        planner.replay_range_sequence = 0;
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
        if self.defer_mmio_bounds {
            return;
        }
        if let Some((_, (_, end_addr, min_addr, max_addr))) = self
            .mmio_min_max_access
            .as_mut()
            .and_then(|mmio_max_access| mmio_max_access.range_mut(..=addr).next_back())
        {
            if addr >= *end_addr {
                return;
            }
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
            self.record_memory_access(step.memory_addr, step.memory_previous_cycle);
        } else if step.flags & NATIVE_TRACE_STORE_MEM != 0 {
            self.update_mmio_bounds(step.memory_addr);
            self.record_memory_access(step.memory_addr, step.memory_previous_cycle);
        }

        self.pc.after = step.pc_after;
        self.advance();
        step.pc_before == step.pc_after
    }
}

impl Tracer for PreflightTracer {
    type Record = ();
    type Config = PreflightTracerConfig;

    fn track_memory_accesses(&self) -> bool {
        true
    }

    fn new(platform: &Platform, config: Self::Config) -> Self {
        PreflightTracer::new(platform, config)
    }

    #[inline(always)]
    fn advance(&mut self) -> Self::Record {
        #[cfg(all(feature = "aot-x86_64", target_arch = "x86_64", target_os = "linux"))]
        if self.last_kind == InsnKind::ECALL {
            if let Some(capture) = self.combined_capture.as_mut() {
                capture.fallback.push(GpuReplayFallbackRecord {
                    ordinal: u32::try_from(capture.ordinal)
                        .expect("combined capture ordinal exceeds u32"),
                    record: capture.pending,
                });
                capture.ordinal += 1;
                capture.pending_cycle += Self::SUBCYCLES_PER_INSN;
                capture.pending = StepRecord {
                    cycle: capture.pending_cycle,
                    heap_maxtouch_addr: Change::new(
                        capture.max_heap_addr_access,
                        capture.max_heap_addr_access,
                    ),
                    hint_maxtouch_addr: Change::new(
                        capture.max_hint_addr_access,
                        capture.max_hint_addr_access,
                    ),
                    ..StepRecord::default()
                };
            }
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
        #[cfg(all(feature = "aot-x86_64", target_arch = "x86_64", target_os = "linux"))]
        if let Some(capture) = self.combined_capture.as_mut() {
            capture.pending.pc.after = pc;
        }
    }

    #[inline(always)]
    fn fetch(&mut self, pc: WordAddr, value: Instruction) {
        self.pc.before = pc.baddr();
        self.last_kind = value.kind;
        self.last_rs1 = None;
        #[cfg(all(feature = "aot-x86_64", target_arch = "x86_64", target_os = "linux"))]
        if let Some(capture) = self.combined_capture.as_mut() {
            capture.pending.cycle = capture.pending_cycle;
            capture.pending.heap_maxtouch_addr =
                Change::new(capture.max_heap_addr_access, capture.max_heap_addr_access);
            capture.pending.hint_maxtouch_addr =
                Change::new(capture.max_hint_addr_access, capture.max_hint_addr_access);
            capture.pending.pc.before = pc.baddr();
            capture.pending.insn = value;
        }
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
        let previous_cycle = self.track_access(addr, subcycle);
        #[cfg(all(feature = "aot-x86_64", target_arch = "x86_64", target_os = "linux"))]
        if let Some(capture) = self.combined_capture.as_mut() {
            let op = ReadOp {
                addr,
                value,
                previous_cycle,
            };
            if subcycle == Self::SUBCYCLE_RS1 {
                capture.pending.rs1 = op;
                capture.pending.has_rs1 = true;
            } else {
                capture.pending.rs2 = op;
                capture.pending.has_rs2 = true;
            }
        }
    }

    #[inline(always)]
    fn store_register(&mut self, idx: RegIdx, value: Change<Word>) {
        let addr = Platform::register_vma(idx).into();
        let previous_cycle = self.track_access(addr, Self::SUBCYCLE_RD);
        #[cfg(all(feature = "aot-x86_64", target_arch = "x86_64", target_os = "linux"))]
        if let Some(capture) = self.combined_capture.as_mut() {
            capture.pending.rd = WriteOp {
                addr,
                value,
                previous_cycle,
            };
            capture.pending.has_rd = true;
        }
    }

    #[inline(always)]
    fn load_memory(&mut self, addr: WordAddr, value: Word, previous_cycle: Cycle) {
        self.store_memory(addr, Change::new(value, value), previous_cycle);
    }

    #[inline(always)]
    fn store_memory(&mut self, addr: WordAddr, value: Change<Word>, previous_cycle: Cycle) {
        self.update_mmio_bounds(addr);
        self.record_memory_access(addr, previous_cycle);
        #[cfg(all(feature = "aot-x86_64", target_arch = "x86_64", target_os = "linux"))]
        if let Some(capture) = self.combined_capture.as_mut() {
            capture.pending.memory_op = WriteOp {
                addr,
                value,
                previous_cycle,
            };
            capture.pending.has_memory_op = true;
        }
    }

    #[inline(always)]
    fn track_syscall(&mut self, mut effects: SyscallEffects) {
        for op in effects.iter_mem_ops_mut() {
            self.record_memory_access(op.addr, op.previous_cycle);
        }
        let witness = effects.finalize(self);
        #[cfg(all(feature = "aot-x86_64", target_arch = "x86_64", target_os = "linux"))]
        if let Some(capture) = self.combined_capture.as_mut() {
            let index = capture.syscall_witnesses.len();
            capture.syscall_witnesses.push(witness);
            let syscall_index =
                u32::try_from(index).expect("combined capture syscall witness index exceeds u32");
            capture.pending.syscall_index = syscall_index;
        }
    }

    #[inline(always)]
    fn track_access(&mut self, addr: WordAddr, subcycle: Cycle) -> Cycle {
        let cur_cycle = self.cycle + subcycle;
        let prev_cycle = self.latest_accesses.track(addr, cur_cycle);
        if self.config.record_next_accesses && prev_cycle < self.current_shard_start_cycle {
            self.push_next_access_event(NextAccessEvent::new(prev_cycle, cur_cycle, addr));
        }
        prev_cycle
    }

    fn final_register_accesses(&self) -> &LatestAccesses {
        &self.latest_accesses
    }

    fn into_next_accesses(self) -> NextCycleAccess {
        NextAccessTape::from_unsorted(self.next_access_events)
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

    fn with_next_accesses(
        platform: &Platform,
        config: Self::Config,
        next_accesses: Option<Arc<NextCycleAccess>>,
    ) -> Self {
        let mut tracer = FullTracer::new(platform, config);
        tracer.next_accesses = next_accesses.unwrap_or_default();
        tracer
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
    fn load_memory(&mut self, addr: WordAddr, value: Word, previous_cycle: Cycle) {
        FullTracer::load_memory(self, addr, value, previous_cycle)
    }

    #[inline(always)]
    fn store_memory(&mut self, addr: WordAddr, value: Change<Word>, previous_cycle: Cycle) {
        FullTracer::store_memory(self, addr, value, previous_cycle)
    }

    #[inline(always)]
    fn track_syscall(&mut self, effects: SyscallEffects) {
        FullTracer::track_syscall(self, effects)
    }

    #[inline(always)]
    fn track_access(&mut self, addr: WordAddr, subcycle: Cycle) -> Cycle {
        FullTracer::track_access(self, addr, subcycle)
    }

    fn final_register_accesses(&self) -> &LatestAccesses {
        FullTracer::final_register_accesses(self)
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

impl Tracer for GpuReplayTracer {
    type Record = GpuReplayStep;
    type Config = GpuReplayTracerConfig;

    fn new(platform: &Platform, config: Self::Config) -> Self {
        Self::new(platform, config)
    }

    fn with_next_accesses(
        platform: &Platform,
        config: Self::Config,
        next_accesses: Option<Arc<NextCycleAccess>>,
    ) -> Self {
        let mut tracer = Self::new(platform, config);
        tracer.next_accesses = next_accesses.unwrap_or_default();
        tracer
    }

    #[inline(always)]
    fn advance(&mut self) -> Self::Record {
        self.annotate_pending();
        let busy_loop = self.pending.is_busy_loop();
        let ordinal = u32::try_from(self.ordinal).expect("GPU replay ordinal exceeds u32");
        #[cfg(all(feature = "aot-x86_64", target_arch = "x86_64", target_os = "linux"))]
        if crate::aot::aot_native_diagnostic_only() && self.ordinal == 0 {
            let kind_index = self.pending.insn.kind as usize;
            let descriptor = self.range_descriptors.get(self.next_range_descriptor);
            let arena = self.current.typed.get(kind_index).and_then(Option::as_ref);
            crate::aot::aot_native_diagnostic_boundary(
                "FIRST_REPLAY_ADVANCE",
                "OBSERVE",
                &format!(
                    "ordinal={},pending_pc_before={:#010x},pending_pc_after={:#010x},pending_kind={:?},kind_index={},current_sequence={},next_descriptor_index={},descriptor_ptr={:p},descriptor_shard={},descriptor_sequence={},descriptor_range_start={},descriptor_range_len={},descriptor_kind_count={},arena_present={},arena_capacity={},arena_len={},install_before_callback={}",
                    ordinal,
                    self.pending.pc.before.0,
                    self.pending.pc.after.0,
                    self.pending.insn.kind,
                    kind_index,
                    self.current.sequence,
                    self.next_range_descriptor,
                    descriptor.map_or(
                        std::ptr::null::<crate::GpuReplayRangeDescriptor>(),
                        |value| { value as *const _ }
                    ),
                    descriptor.map_or(u32::MAX, |value| value.shard_id),
                    descriptor.map_or(u32::MAX, |value| value.sequence),
                    descriptor.map_or(u32::MAX, |value| value.range_start),
                    descriptor.map_or(u32::MAX, |value| value.range_len),
                    descriptor.map_or(0, |value| value.family_counts[kind_index]),
                    arena.is_some(),
                    arena.map_or(0, crate::GpuTypedSoaArena::capacity),
                    arena.map_or(0, crate::GpuTypedSoaArena::len),
                    !self.range_descriptors.is_empty(),
                ),
            );
        }
        if self.pending.insn.kind == InsnKind::ECALL {
            self.current.fallback.push(GpuReplayFallbackRecord {
                ordinal,
                record: self.pending,
            });
        } else {
            self.current.typed[self.pending.insn.kind as usize]
                .as_mut()
                .expect("GPU replay kind absent from exact descriptor")
                .push_step(ordinal, &self.pending)
                .expect("GPU replay typed cursor overflow");
        }
        self.ordinal += 1;
        if self.current.len() == self.config.chunk_capacity {
            self.seal_current();
        }
        let cycle = self.shard_start_cycle + self.ordinal as Cycle * FullTracer::SUBCYCLES_PER_INSN;
        self.pending = StepRecord {
            cycle,
            ..StepRecord::default()
        };
        GpuReplayStep { ordinal, busy_loop }
    }

    #[inline(always)]
    fn is_busy_loop(&self, record: &Self::Record) -> bool {
        record.busy_loop
    }

    #[inline(always)]
    fn store_pc(&mut self, pc: ByteAddr) {
        self.pending.pc.after = pc;
    }

    #[inline(always)]
    fn fetch(&mut self, pc: WordAddr, value: Instruction) {
        self.pending.pc.before = pc.baddr();
        self.pending.insn = value;
    }

    fn track_mmu_maxtouch_before(&mut self) {
        self.pending.heap_maxtouch_addr.before = self.max_heap_addr_access;
        self.pending.hint_maxtouch_addr.before = self.max_hint_addr_access;
    }

    fn track_mmu_maxtouch_after(&mut self) {
        self.pending.heap_maxtouch_addr.after = self.max_heap_addr_access;
        self.pending.hint_maxtouch_addr.after = self.max_hint_addr_access;
    }

    #[inline(always)]
    fn load_register(&mut self, idx: RegIdx, value: Word) {
        let addr = Platform::register_vma(idx).into();
        if !self.pending.has_rs1 {
            self.pending.rs1 = ReadOp {
                addr,
                value,
                previous_cycle: self.track_access(addr, Self::SUBCYCLE_RS1),
            };
            self.pending.has_rs1 = true;
        } else if !self.pending.has_rs2 {
            self.pending.rs2 = ReadOp {
                addr,
                value,
                previous_cycle: self.track_access(addr, Self::SUBCYCLE_RS2),
            };
            self.pending.has_rs2 = true;
        } else {
            unimplemented!("Only two register reads are supported");
        }
    }

    #[inline(always)]
    fn store_register(&mut self, idx: RegIdx, value: Change<Word>) {
        assert!(!self.pending.has_rd, "Only one register write is supported");
        let addr = Platform::register_vma(idx).into();
        self.pending.rd = WriteOp {
            addr,
            value,
            previous_cycle: self.track_access(addr, Self::SUBCYCLE_RD),
        };
        self.pending.has_rd = true;
    }

    #[inline(always)]
    fn load_memory(&mut self, addr: WordAddr, value: Word, previous_cycle: Cycle) {
        self.store_memory(addr, Change::new(value, value), previous_cycle);
    }

    #[inline(always)]
    fn store_memory(&mut self, addr: WordAddr, value: Change<Word>, previous_cycle: Cycle) {
        assert!(
            !self.pending.has_memory_op,
            "Only one memory access is supported"
        );
        self.update_mmio_bounds(addr);
        self.pending.memory_op = WriteOp {
            addr,
            value,
            previous_cycle,
        };
        self.pending.has_memory_op = true;
    }

    #[inline(always)]
    fn track_syscall(&mut self, effects: SyscallEffects) {
        let witness = effects.finalize(self);
        assert!(!self.pending.has_syscall(), "Only one syscall per step");
        self.pending.syscall_index = u32::try_from(self.syscall_witnesses.len())
            .expect("GPU replay syscall witness index exceeds u32");
        self.syscall_witnesses.push(witness);
    }

    #[inline(always)]
    fn track_access(&mut self, addr: WordAddr, subcycle: Cycle) -> Cycle {
        self.latest_accesses
            .track(addr, self.pending.cycle + subcycle)
    }

    fn final_register_accesses(&self) -> &LatestAccesses {
        &self.latest_accesses
    }

    fn into_next_accesses(self) -> NextCycleAccess {
        unimplemented!("GpuReplayTracer consumes next-access metadata")
    }

    fn cycle(&self) -> Cycle {
        self.pending.cycle
    }

    fn executed_insts(&self) -> usize {
        (self.pending.cycle / Self::SUBCYCLES_PER_INSN)
            .saturating_sub(1)
            .try_into()
            .expect("GPU replay instruction count exceeds usize")
    }

    fn probe_min_max_address_by_start_addr(
        &self,
        start_addr: WordAddr,
    ) -> Option<(WordAddr, WordAddr)> {
        self.mmio_min_max_access.as_ref().and_then(|bounds| {
            bounds.range(..=start_addr).next_back().and_then(
                |(_, &(expected_start_addr, _, min, max))| {
                    assert_eq!(start_addr, expected_start_addr);
                    (min < max).then_some((min, max))
                },
            )
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GpuReplayStep {
    pub ordinal: u32,
    busy_loop: bool,
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
    fn shard_cost_model_fingerprint_covers_planner_inputs() {
        let spec = ChipCostSpec {
            rotation: 1,
            trace_cells_per_row: 2,
            tower_peak_cells_per_row: 3,
            tower_peak_cells_by_bucket: None,
        };
        let base = cost_model(vec![spec.clone()]);
        let duplicate = cost_model(vec![spec.clone()]);
        assert_eq!(base.fingerprint(), duplicate.fingerprint());

        let mut opcodes = vec![Vec::new(); InsnKind::COUNT];
        opcodes[InsnKind::SUB as usize] = vec![0];
        let mut ecalls = BTreeMap::new();
        ecalls.insert(7, vec![0]);
        let remapped = ShardCostModel::new(opcodes, ecalls.clone(), vec![spec.clone()], 4);
        assert_ne!(base.fingerprint(), remapped.fingerprint());

        let changed_spec = ShardCostModel::new(
            vec![Vec::new(); InsnKind::COUNT],
            ecalls.clone(),
            vec![ChipCostSpec {
                trace_cells_per_row: 4,
                ..spec.clone()
            }],
            4,
        );
        assert_ne!(base.fingerprint(), changed_spec.fingerprint());

        let changed_ecall = ShardCostModel::new(
            vec![Vec::new(); InsnKind::COUNT],
            BTreeMap::from([(8, vec![0])]),
            vec![spec.clone()],
            4,
        );
        assert_ne!(base.fingerprint(), changed_ecall.fingerprint());

        let changed_extension =
            ShardCostModel::new(vec![Vec::new(); InsnKind::COUNT], ecalls, vec![spec], 2);
        assert_ne!(base.fingerprint(), changed_extension.fingerprint());
    }

    #[test]
    fn shard_cost_model_counts_every_batched_main_fold_mle() {
        let model = cost_model(vec![ChipCostSpec {
            rotation: 0,
            trace_cells_per_row: 9,
            tower_peak_cells_per_row: 0,
            tower_peak_cells_by_bucket: None,
        }]);

        assert_eq!(model.chip_cost(0, 0).main_peak, 0);
        assert_eq!(model.chip_cost(0, 1).main_peak, 0);
        // Nine MLEs each allocate a half-domain Ext4 fold buffer.
        assert_eq!(model.chip_cost(0, 2).main_peak, 9 * 4);
        assert_eq!(model.chip_cost(0, 3).main_peak, 9 * 2 * 4);
        assert_eq!(model.chip_cost(0, 4).main_peak, 9 * 2 * 4);
        assert_eq!(model.chip_cost(0, 5).main_peak, 9 * 4 * 4);
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
        assert_eq!(model.shard_cost(&[2, 0]), 22);
        assert_eq!(model.shard_cost(&[0, 2]), 12);
        // Trace and main coexist across chips, while tower is the dominant
        // single-chip task rather than the sum of both tower peaks.
        assert_eq!(model.shard_cost(&[2, 2]), 26);

        let main_dominant = cost_model(vec![
            ChipCostSpec {
                rotation: 0,
                trace_cells_per_row: 2,
                tower_peak_cells_per_row: 5,
                tower_peak_cells_by_bucket: None,
            },
            ChipCostSpec {
                rotation: 0,
                trace_cells_per_row: 2,
                tower_peak_cells_per_row: 5,
                tower_peak_cells_by_bucket: None,
            },
        ]);
        assert_eq!(main_dominant.shard_cost(&[2, 2]), 24);
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
        assert_eq!(planner.cur_cells(), 6);
    }

    #[derive(Debug)]
    struct OneCellPerStep;

    impl StepCellExtractor for OneCellPerStep {
        fn cells_for_kind(&self, _kind: InsnKind, _rs1_value: Option<Word>) -> u64 {
            1
        }
    }

    #[test]
    fn next_access_tape_sorts_full_canonical_key() {
        let events = vec![
            NextAccessEvent::new(1 << 40, (1 << 40) + 9, 7u32.into()),
            NextAccessEvent::new(8, 30, 9u32.into()),
            NextAccessEvent::new(0, 12, 3u32.into()),
            NextAccessEvent::new(8, 20, 2u32.into()),
            NextAccessEvent::new(1 << 32, (1 << 32) + 4, 1u32.into()),
        ];
        let tape = NextAccessTape::from_unsorted(events);

        assert_eq!(
            tape.initialization_events(),
            &[NextAccessEvent::new(0, 12, 3u32.into())]
        );
        assert_eq!(
            tape.events(),
            &[
                NextAccessEvent::new(8, 20, 2u32.into()),
                NextAccessEvent::new(8, 30, 9u32.into()),
                NextAccessEvent::new(1 << 32, (1 << 32) + 4, 1u32.into()),
                NextAccessEvent::new(1 << 40, (1 << 40) + 9, 7u32.into()),
            ]
        );
    }

    #[test]
    fn full_tracer_defers_next_access_annotation_until_chunk_completion() {
        let address: WordAddr = Platform::register_vma(1).into();
        let source_cycle = FullTracer::SUBCYCLES_PER_INSN + FullTracer::SUBCYCLE_RS1;
        let tape = NextAccessTape::from_unsorted(vec![NextAccessEvent::new(
            source_cycle,
            source_cycle + FullTracer::SUBCYCLES_PER_INSN,
            address,
        )]);
        let mut tracer = FullTracer::new(&CENO_PLATFORM, FullTracerConfig { max_step_shard: 1 });
        tracer.next_accesses = Arc::new(tape);

        tracer.load_register(1, 7);
        tracer.advance();
        assert_eq!(tracer.records[0].future_access_mask(), 0);

        tracer.annotate_recorded_steps(0);
        assert!(tracer.records[0].has_future_access(StepRecord::FUTURE_ACCESS_RS1));
        tracer.assert_next_accesses_consumed();
    }

    #[test]
    fn chunk_annotation_marks_final_matching_syscall_op() {
        let address = WordAddr::from(17);
        let source_cycle = FullTracer::SUBCYCLES_PER_INSN + FullTracer::SUBCYCLE_RD;
        let tape = NextAccessTape::from_unsorted(vec![NextAccessEvent::new(
            source_cycle,
            source_cycle + FullTracer::SUBCYCLES_PER_INSN,
            address,
        )]);
        let mut tracer = FullTracer::new(&CENO_PLATFORM, FullTracerConfig { max_step_shard: 1 });
        tracer.next_accesses = Arc::new(tape);
        tracer.syscall_witnesses.push(SyscallWitness {
            reg_ops: vec![
                WriteOp {
                    addr: address,
                    value: Change::new(1, 2),
                    previous_cycle: 0,
                },
                WriteOp {
                    addr: address,
                    value: Change::new(2, 3),
                    previous_cycle: source_cycle,
                },
            ],
            reg_future_access: vec![0; 2],
            ..Default::default()
        });
        tracer.records[0].syscall_index = 0;
        tracer.advance();

        tracer.annotate_recorded_steps(0);
        assert_eq!(tracer.syscall_witnesses[0].reg_future_access, vec![0, 1]);
        tracer.assert_next_accesses_consumed();
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
        let tape = NextAccessTape::from_unsorted(tracer.next_access_events);
        assert_eq!(
            tape.events(),
            &[NextAccessEvent::new(4, 8, Platform::register_vma(1).into())]
        );
    }

    #[test]
    fn preflight_next_access_tape_grows_past_trained_capacity() {
        let mut tracer = PreflightTracer::new(&CENO_PLATFORM, PreflightTracerConfig::default());
        tracer.next_access_capacity = Some(0);

        tracer.push_next_access_event(NextAccessEvent::new(4, 8, WordAddr::from(1)));

        assert_eq!(tracer.next_access_events.len(), 1);
        assert!(tracer.next_access_events.capacity() >= 4096);
        assert_eq!(tracer.next_access_growths, 1);
        assert!(tracer.next_access_growth_bytes >= 4096 * std::mem::size_of::<NextAccessEvent>());
        assert_eq!(
            tracer.next_access_capacity,
            Some(tracer.next_access_events.capacity())
        );
    }

    #[test]
    fn i061_l8_replay_keeps_exactly_two_warmed_nonaliasing_owners() {
        fn fingerprint(chunk: &GpuReplayChunk) -> ((usize, usize), (usize, usize), (usize, usize)) {
            let add = chunk.typed[InsnKind::ADD as usize].as_ref().unwrap();
            let add_ptr = if add.is_compact() {
                add.payload_bytes().as_ptr() as usize
            } else {
                add.fields()[0].as_ptr() as usize
            };
            (
                (chunk.typed.as_ptr() as usize, chunk.typed.capacity()),
                (add_ptr, add.capacity()),
                (chunk.fallback.as_ptr() as usize, chunk.fallback.capacity()),
            )
        }

        let mut counts = [0; InsnKind::COUNT];
        counts[InsnKind::ADD as usize] = 2;
        let descriptors = Arc::new(vec![
            crate::GpuReplayRangeDescriptor {
                shard_id: 0,
                sequence: 0,
                range_start: 0,
                range_len: 3,
                family_counts: counts,
                fallback_count: 1,
                unsupported_count: 0,
            },
            crate::GpuReplayRangeDescriptor {
                shard_id: 0,
                sequence: 1,
                range_start: 3,
                range_len: 3,
                family_counts: counts,
                fallback_count: 1,
                unsupported_count: 0,
            },
        ]);
        let mut tracer = GpuReplayTracer::new(&CENO_PLATFORM, GpuReplayTracerConfig::default());
        tracer.install_range_descriptors(descriptors);

        let first = fingerprint(&tracer.current);
        let second = fingerprint(tracer.recyclable.as_ref().unwrap());
        assert_eq!(
            (first.0.1, first.1.1, first.2.1),
            (second.0.1, second.1.1, second.2.1)
        );
        assert_ne!(first.0.0, second.0.0);
        assert_ne!(first.1.0, second.1.0);
        assert_ne!(first.2.0, second.2.0);

        let first_owner = std::mem::replace(
            &mut tracer.current,
            GpuReplayChunk::empty(0, FullTracer::SUBCYCLES_PER_INSN),
        );
        let second_owner = tracer.recyclable.take().unwrap();
        assert!(tracer.current.typed.is_empty());
        assert!(tracer.recyclable.is_none());
        tracer.recycle_range(crate::GpuReplayTypedRange {
            sequence: first_owner.sequence,
            typed: first_owner.typed,
            fallback: first_owner.fallback,
        });
        tracer.recycle_range(crate::GpuReplayTypedRange {
            sequence: second_owner.sequence,
            typed: second_owner.typed,
            fallback: second_owner.fallback,
        });

        assert_eq!(fingerprint(&tracer.current), first);
        assert_eq!(fingerprint(tracer.recyclable.as_ref().unwrap()), second);
    }

    #[test]
    fn i061_l8_cross_shard_recycle_stays_empty_until_start_shard() {
        fn fingerprint(chunk: &GpuReplayChunk) -> ((usize, usize), (usize, usize), (usize, usize)) {
            let add = chunk.typed[InsnKind::ADD as usize].as_ref().unwrap();
            let add_ptr = if add.is_compact() {
                add.payload_bytes().as_ptr() as usize
            } else {
                add.fields()[0].as_ptr() as usize
            };
            (
                (chunk.typed.as_ptr() as usize, chunk.typed.capacity()),
                (add_ptr, add.capacity()),
                (chunk.fallback.as_ptr() as usize, chunk.fallback.capacity()),
            )
        }

        let mut counts = [0; InsnKind::COUNT];
        counts[InsnKind::ADD as usize] = 2;
        let descriptors = Arc::new(vec![
            crate::GpuReplayRangeDescriptor {
                shard_id: 0,
                sequence: 0,
                range_start: 0,
                range_len: 2,
                family_counts: counts,
                fallback_count: 0,
                unsupported_count: 0,
            },
            crate::GpuReplayRangeDescriptor {
                shard_id: 1,
                sequence: 0,
                range_start: 17,
                range_len: 2,
                family_counts: counts,
                fallback_count: 0,
                unsupported_count: 0,
            },
        ]);
        let mut tracer = GpuReplayTracer::new(&CENO_PLATFORM, GpuReplayTracerConfig::default());
        tracer.install_range_descriptors(descriptors);

        let first_owner = std::mem::replace(
            &mut tracer.current,
            GpuReplayChunk::empty(0, FullTracer::SUBCYCLES_PER_INSN),
        );
        let second_owner = tracer.recyclable.take().unwrap();
        let first = fingerprint(&first_owner);
        let second = fingerprint(&second_owner);
        tracer.next_range_descriptor = 1;

        tracer.recycle_range(crate::GpuReplayTypedRange {
            sequence: first_owner.sequence,
            typed: first_owner.typed,
            fallback: first_owner.fallback,
        });
        let add = tracer.current.typed[InsnKind::ADD as usize]
            .as_ref()
            .unwrap();
        assert!(tracer.current.is_empty());
        assert_ne!(
            add.range_start(),
            17,
            "recycle initialized the next shard descriptor before start_shard"
        );

        tracer.recycle_range(crate::GpuReplayTypedRange {
            sequence: second_owner.sequence,
            typed: second_owner.typed,
            fallback: second_owner.fallback,
        });
        tracer.start_shard();

        assert_eq!(
            tracer.current.typed[InsnKind::ADD as usize]
                .as_ref()
                .unwrap()
                .range_start(),
            17
        );
        assert_eq!(fingerprint(&tracer.current), first);
        assert_eq!(fingerprint(tracer.recyclable.as_ref().unwrap()), second);
    }

    #[cfg(all(feature = "aot-x86_64", target_arch = "x86_64", target_os = "linux"))]
    #[test]
    fn deferred_mmio_bounds_rebuild_from_first_access_events() {
        let mut tracer = PreflightTracer::new(
            &CENO_PLATFORM,
            PreflightTracerConfig::new(true, u64::MAX, Cycle::MAX),
        );
        let heap_start = ByteAddr(CENO_PLATFORM.heap.start).waddr();
        let stack_start = ByteAddr(CENO_PLATFORM.stack.start).waddr();
        let hints_start = ByteAddr(CENO_PLATFORM.hints.start).waddr();
        let accesses = [
            heap_start + 3usize,
            heap_start + 9usize,
            stack_start + 2usize,
            stack_start + 7usize,
            hints_start + 5usize,
        ];

        tracer.begin_deferred_mmio_bounds();
        for (index, address) in accesses.into_iter().enumerate() {
            tracer.push_next_access_event(NextAccessEvent::new(
                0,
                8 + index as Cycle * PreflightTracer::SUBCYCLES_PER_INSN,
                address,
            ));
        }
        tracer.finish_deferred_mmio_bounds();

        assert_eq!(
            tracer.probe_min_max_address_by_start_addr(heap_start),
            Some((heap_start + 3usize, heap_start + 10usize))
        );
        assert_eq!(
            tracer.probe_min_max_address_by_start_addr(stack_start),
            Some((stack_start + 2usize, stack_start + 8usize))
        );
        assert_eq!(
            tracer.probe_min_max_address_by_start_addr(hints_start),
            Some((hints_start + 5usize, hints_start + 6usize))
        );
    }

    #[cfg(all(feature = "aot-x86_64", target_arch = "x86_64", target_os = "linux"))]
    #[test]
    fn i049_deferred_mmio_repair_advances_pending_preview_starts() {
        let mut tracer = PreflightTracer::new(
            &CENO_PLATFORM,
            PreflightTracerConfig::new(true, u64::MAX, Cycle::MAX),
        );
        let heap_start = ByteAddr(CENO_PLATFORM.heap.start).waddr();
        let hint_start = ByteAddr(CENO_PLATFORM.hints.start).waddr();

        tracer.begin_deferred_mmio_bounds();
        tracer.push_next_access_event(NextAccessEvent::new(0, 8, heap_start + 3usize));
        tracer.push_next_access_event(NextAccessEvent::new(0, 8, hint_start + 2usize));
        tracer.capture_shard_preview(12);
        tracer.current_shard_start_cycle = 12;
        tracer.push_next_access_event(NextAccessEvent::new(0, 16, heap_start + 9usize));
        tracer.push_next_access_event(NextAccessEvent::new(0, 16, hint_start + 5usize));

        tracer.finish_deferred_mmio_bounds();
        tracer.capture_shard_preview(20);

        let first = tracer.replay_shard_previews[0];
        let second = tracer.replay_shard_previews[1];
        assert_eq!(second.heap_start, first.heap_end);
        assert_eq!(second.hint_start, first.hint_end);
        assert_eq!(second.heap_end, (heap_start + 10usize).baddr().0);
        assert_eq!(second.hint_end, (hint_start + 6usize).baddr().0);
    }

    #[cfg(all(feature = "aot-x86_64", target_arch = "x86_64", target_os = "linux"))]
    #[test]
    fn i049_deferred_patch_initialization_boundary_and_rejections() {
        fn capture_with_one_add() -> PreflightCombinedCapture {
            let mut capture = PreflightCombinedCapture::new(&CENO_PLATFORM, 2);
            let step = StepRecord::new_r_instruction(
                4,
                ByteAddr(CENO_PLATFORM.pc_base()),
                crate::encode_rv32(InsnKind::ADD, 1, 2, 3, 0),
                11,
                22,
                Change::new(0, 33),
                0,
            );
            let mut add = crate::GpuTypedSoaArena::new(InsnKind::ADD, 1).unwrap();
            add.push_step(0, &step).unwrap();
            let mut typed = (0..InsnKind::COUNT).map(|_| None).collect::<Vec<_>>();
            typed[InsnKind::ADD as usize] = Some(add);
            capture.sealed.push(crate::GpuReplayTypedRange {
                sequence: 0,
                typed,
                fallback: Vec::new(),
            });
            capture
        }

        let boundaries = [4, 8, 12, 16];
        let rd = Platform::register_vma(3).into();
        let mut valid = capture_with_one_add();
        valid
            .resolve_patches(
                &[
                    NextAccessEvent::new(0, 12, WordAddr(99)),
                    NextAccessEvent::new(6, 12, rd),
                ],
                &boundaries,
            )
            .unwrap();
        assert_eq!(valid.initialization_events.len(), 1);
        assert_eq!(valid.patches.len(), 1);
        assert_eq!(
            (valid.patches[0].source_shard, valid.patches[0].target_shard),
            (0, 2)
        );
        assert_eq!(valid.patches[0].prior_value, 33);

        let mut duplicate = capture_with_one_add();
        assert_eq!(
            duplicate.resolve_patches(
                &[
                    NextAccessEvent::new(6, 8, rd),
                    NextAccessEvent::new(6, 12, rd),
                ],
                &boundaries,
            ),
            Err("duplicate deferred patch source/address")
        );

        let mut order = capture_with_one_add();
        assert_eq!(
            order.resolve_patches(&[NextAccessEvent::new(6, 6, rd)], &boundaries),
            Err("deferred patch target does not follow source")
        );

        let mut missing = capture_with_one_add();
        assert_eq!(
            missing.resolve_patches(&[NextAccessEvent::new(10, 12, rd)], &boundaries,),
            Err("deferred patch source ordinal does not resolve exactly once")
        );

        let mut capacity = PreflightCombinedCapture::new(&CENO_PLATFORM, 2);
        let _ = capacity.native_state();
        let descriptor = crate::GpuReplayRangeDescriptor {
            shard_id: 0,
            sequence: 0,
            range_start: 0,
            range_len: 3,
            family_counts: [0; InsnKind::COUNT],
            fallback_count: 0,
            unsupported_count: 0,
        };
        assert_eq!(
            capacity.seal_available(&[descriptor]),
            Err("combined capture descriptor exceeds 262144-row range bound")
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
        assert_eq!(
            mem::offset_of!(Instruction, kind),
            0,
            "Instruction.kind offset"
        );
        assert_eq!(
            mem::offset_of!(Instruction, rs1),
            1,
            "Instruction.rs1 offset"
        );
        assert_eq!(
            mem::offset_of!(Instruction, rs2),
            2,
            "Instruction.rs2 offset"
        );
        assert_eq!(mem::offset_of!(Instruction, rd), 3, "Instruction.rd offset");
        assert_eq!(
            mem::offset_of!(Instruction, imm),
            4,
            "Instruction.imm offset"
        );
        assert_eq!(
            mem::offset_of!(Instruction, raw),
            8,
            "Instruction.raw offset"
        );
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
        assert_eq!(offset_of!(StepRecord, future_access_mask), 132);

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
