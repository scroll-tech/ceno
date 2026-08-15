use crate::{Cycle, StepRecord, SyscallWitness, Word, WriteOp};
use std::{
    fmt, mem,
    time::{Duration, Instant},
};
use tiny_keccak::{Hasher, Keccak};

pub const COMPACT_SHARD_JOURNAL_MAGIC: u64 = u64::from_le_bytes(*b"CENOJNL1");
pub const COMPACT_SHARD_JOURNAL_VERSION: u32 = 1;
const FUTURE_ACCESS_BIT: u32 = 1 << 31;
const CYCLE_MASK: u32 = FUTURE_ACCESS_BIT - 1;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(transparent)]
pub struct CompactArenaKind(pub u32);
impl CompactArenaKind {
    pub const OPCODES: Self = Self(1);
    pub const REGISTER_READS: Self = Self(2);
    pub const REGISTER_WRITES: Self = Self(3);
    pub const MEMORY_ACCESSES: Self = Self(4);
    pub const SYSCALLS: Self = Self(5);
    pub const SYSCALL_ACCESSES: Self = Self(6);
    pub const PUBLIC_VALUES: Self = Self(7);
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct CompactArenaDescriptorV1 {
    pub kind: u32,
    pub record_size: u32,
    pub record_align: u32,
    pub reserved: u32,
    pub byte_offset: u64,
    pub record_count: u64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct CompactShardSummaryV1 {
    pub shard_id: u32,
    pub reserved: u32,
    pub start_cycle: Cycle,
    pub end_cycle: Cycle,
    pub step_count: u64,
    pub first_pc: Word,
    pub last_pc: Word,
    pub heap_start: Word,
    pub heap_end: Word,
    pub hint_start: Word,
    pub hint_end: Word,
}

/// Cycle is derived as `summary.start_cycle + opcode_index * 4`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct CompactOpcodeRecordV1 {
    pub pc_before: Word,
    pub raw_instruction: Word,
    pub syscall_index: u32,
}

/// Register address and subcycle are derived from the instruction and arena order.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct CompactRegisterReadV1 {
    pub predecessor_and_flags: u32,
    pub value: Word,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct CompactRegisterWriteV1 {
    pub predecessor_and_flags: u32,
    pub value_before: Word,
    pub value_after: Word,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct CompactMemoryAccessV1 {
    pub predecessor_and_flags: u32,
    pub address: Word,
    pub value_before: Word,
    pub value_after: Word,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct CompactSyscallRecordV1 {
    pub opcode_index: u32,
    pub witness_index: u32,
    pub register_access_start: u32,
    pub register_access_count: u32,
    pub memory_access_start: u32,
    pub memory_access_count: u32,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct CompactSyscallAccessV1 {
    pub predecessor_and_flags: u32,
    pub address: Word,
    pub value_before: Word,
    pub value_after: Word,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompactShardJournalV1 {
    pub magic: u64,
    pub version: u32,
    pub header_size: u32,
    pub layout_fingerprint: [u8; 32],
    pub summary: CompactShardSummaryV1,
    pub arenas: [CompactArenaDescriptorV1; 7],
    pub opcodes: Vec<CompactOpcodeRecordV1>,
    pub register_reads: Vec<CompactRegisterReadV1>,
    pub register_writes: Vec<CompactRegisterWriteV1>,
    pub memory_accesses: Vec<CompactMemoryAccessV1>,
    pub syscalls: Vec<CompactSyscallRecordV1>,
    pub syscall_accesses: Vec<CompactSyscallAccessV1>,
    pub public_values: Vec<u32>,
    pub packing_time: Duration,
}

impl Default for CompactShardJournalV1 {
    fn default() -> Self {
        Self {
            magic: COMPACT_SHARD_JOURNAL_MAGIC,
            version: COMPACT_SHARD_JOURNAL_VERSION,
            header_size: mem::size_of::<CompactShardSummaryV1>() as u32,
            layout_fingerprint: compact_journal_layout_fingerprint(),
            summary: CompactShardSummaryV1::default(),
            arenas: [CompactArenaDescriptorV1::default(); 7],
            opcodes: Vec::new(),
            register_reads: Vec::new(),
            register_writes: Vec::new(),
            memory_accesses: Vec::new(),
            syscalls: Vec::new(),
            syscall_accesses: Vec::new(),
            public_values: Vec::new(),
            packing_time: Duration::ZERO,
        }
    }
}

impl CompactShardJournalV1 {
    pub fn byte_len(&self) -> usize {
        self.opcodes.len() * mem::size_of::<CompactOpcodeRecordV1>()
            + self.register_reads.len() * mem::size_of::<CompactRegisterReadV1>()
            + self.register_writes.len() * mem::size_of::<CompactRegisterWriteV1>()
            + self.memory_accesses.len() * mem::size_of::<CompactMemoryAccessV1>()
            + self.syscalls.len() * mem::size_of::<CompactSyscallRecordV1>()
            + self.syscall_accesses.len() * mem::size_of::<CompactSyscallAccessV1>()
            + self.public_values.len() * mem::size_of::<u32>()
    }

    pub fn bytes_per_step(&self) -> f64 {
        self.byte_len() as f64 / self.summary.step_count.max(1) as f64
    }

    pub fn validate_descriptors(&self) -> Result<(), JournalValidationError> {
        if self.magic != COMPACT_SHARD_JOURNAL_MAGIC
            || self.version != COMPACT_SHARD_JOURNAL_VERSION
        {
            return Err(JournalValidationError("journal magic/version mismatch"));
        }
        if self.layout_fingerprint != compact_journal_layout_fingerprint() {
            return Err(JournalValidationError(
                "journal layout fingerprint mismatch",
            ));
        }
        if self.arenas != descriptors(self) {
            return Err(JournalValidationError("malformed arena descriptor"));
        }
        Ok(())
    }

    pub fn validate_against(
        &self,
        legacy: &LegacyWitnessRecordSink,
        witnesses: &[SyscallWitness],
    ) -> Result<(), JournalValidationError> {
        self.validate_descriptors()?;
        if self.opcodes.len() != legacy.steps.len()
            || self.summary.step_count != legacy.steps.len() as u64
        {
            return Err(JournalValidationError("opcode/summary count mismatch"));
        }
        let mut reads = 0;
        let mut writes = 0;
        let mut memory = 0;
        for (index, (opcode, step)) in self.opcodes.iter().zip(&legacy.steps).enumerate() {
            if *opcode != pack_opcode(step)
                || step.cycle() != self.summary.start_cycle + index as u64 * 4
                || step.pc().after.0
                    != self
                        .opcodes
                        .get(index + 1)
                        .map_or(self.summary.last_pc, |next| next.pc_before)
            {
                return Err(JournalValidationError("opcode field/order mismatch"));
            }
            for (slot, op) in [step.rs1(), step.rs2()]
                .into_iter()
                .enumerate()
                .filter_map(|(slot, op)| op.map(|op| (slot, op)))
            {
                let expected = CompactRegisterReadV1 {
                    predecessor_and_flags: pack_predecessor(
                        op.previous_cycle,
                        step.has_future_access(1 << slot),
                    ),
                    value: op.value,
                };
                if self.register_reads.get(reads) != Some(&expected) {
                    return Err(JournalValidationError("register read mismatch"));
                }
                reads += 1;
            }
            if let Some(op) = step.rd() {
                let expected = CompactRegisterWriteV1 {
                    predecessor_and_flags: pack_predecessor(
                        op.previous_cycle,
                        step.has_future_access(StepRecord::FUTURE_ACCESS_RD),
                    ),
                    value_before: op.value.before,
                    value_after: op.value.after,
                };
                if self.register_writes.get(writes) != Some(&expected) {
                    return Err(JournalValidationError("register write mismatch"));
                }
                writes += 1;
            }
            if let Some(op) = step.memory_op() {
                let expected =
                    pack_memory(op, step.has_future_access(StepRecord::FUTURE_ACCESS_MEM));
                if self.memory_accesses.get(memory) != Some(&expected) {
                    return Err(JournalValidationError("memory access mismatch"));
                }
                memory += 1;
            }
        }
        if (reads, writes, memory)
            != (
                self.register_reads.len(),
                self.register_writes.len(),
                self.memory_accesses.len(),
            )
        {
            return Err(JournalValidationError("typed access count mismatch"));
        }
        validate_syscalls(self, witnesses)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct JournalValidationError(pub &'static str);
impl fmt::Display for JournalValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}
impl std::error::Error for JournalValidationError {}

pub trait WitnessRecordSink {
    fn begin_shard(&mut self, shard_id: u32);
    fn record_step(&mut self, step: &StepRecord);
    fn record_syscalls(&mut self, witnesses: &[SyscallWitness]);
    fn record_public_values(&mut self, words: &[u32]);
    fn finish_shard(&mut self);
}

#[derive(Default)]
pub struct LegacyWitnessRecordSink {
    steps: Vec<StepRecord>,
}
impl WitnessRecordSink for LegacyWitnessRecordSink {
    fn begin_shard(&mut self, _: u32) {
        self.steps.clear();
    }
    fn record_step(&mut self, step: &StepRecord) {
        self.steps.push(*step);
    }
    fn record_syscalls(&mut self, _: &[SyscallWitness]) {}
    fn record_public_values(&mut self, _: &[u32]) {}
    fn finish_shard(&mut self) {}
}

#[derive(Default)]
pub struct CompactWitnessRecordSink {
    pub journal: CompactShardJournalV1,
    started: Option<Instant>,
}
impl WitnessRecordSink for CompactWitnessRecordSink {
    fn begin_shard(&mut self, shard_id: u32) {
        self.journal = CompactShardJournalV1::default();
        self.journal.summary.shard_id = shard_id;
        self.started = Some(Instant::now());
    }
    fn record_step(&mut self, step: &StepRecord) {
        if self.journal.opcodes.is_empty() {
            self.journal.summary.start_cycle = step.cycle();
            self.journal.summary.first_pc = step.pc().before.0;
            self.journal.summary.heap_start = step.heap_maxtouch_addr.before.0;
            self.journal.summary.hint_start = step.hint_maxtouch_addr.before.0;
        }
        self.journal.summary.end_cycle = step.cycle() + 4;
        self.journal.summary.last_pc = step.pc().after.0;
        self.journal.summary.heap_end = step.heap_maxtouch_addr.after.0;
        self.journal.summary.hint_end = step.hint_maxtouch_addr.after.0;
        self.journal.opcodes.push(pack_opcode(step));
        for (slot, op) in [step.rs1(), step.rs2()]
            .into_iter()
            .enumerate()
            .filter_map(|(slot, op)| op.map(|op| (slot, op)))
        {
            self.journal.register_reads.push(CompactRegisterReadV1 {
                predecessor_and_flags: pack_predecessor(
                    op.previous_cycle,
                    step.has_future_access(1 << slot),
                ),
                value: op.value,
            });
        }
        if let Some(op) = step.rd() {
            self.journal.register_writes.push(CompactRegisterWriteV1 {
                predecessor_and_flags: pack_predecessor(
                    op.previous_cycle,
                    step.has_future_access(StepRecord::FUTURE_ACCESS_RD),
                ),
                value_before: op.value.before,
                value_after: op.value.after,
            });
        }
        if let Some(op) = step.memory_op() {
            self.journal.memory_accesses.push(pack_memory(
                op,
                step.has_future_access(StepRecord::FUTURE_ACCESS_MEM),
            ));
        }
    }
    fn record_syscalls(&mut self, witnesses: &[SyscallWitness]) {
        for (opcode_index, opcode) in self
            .journal
            .opcodes
            .iter()
            .enumerate()
            .filter(|(_, op)| op.syscall_index != StepRecord::NO_SYSCALL)
        {
            let witness = &witnesses[opcode.syscall_index as usize];
            let register_access_start = self.journal.syscall_accesses.len() as u32;
            self.journal.syscall_accesses.extend(
                witness
                    .reg_ops
                    .iter()
                    .zip(&witness.reg_future_access)
                    .map(|(op, &future)| pack_syscall_access(op, future != 0)),
            );
            let memory_access_start = self.journal.syscall_accesses.len() as u32;
            self.journal.syscall_accesses.extend(
                witness
                    .mem_ops
                    .iter()
                    .zip(&witness.mem_future_access)
                    .map(|(op, &future)| pack_syscall_access(op, future != 0)),
            );
            self.journal.syscalls.push(CompactSyscallRecordV1 {
                opcode_index: opcode_index as u32,
                witness_index: opcode.syscall_index,
                register_access_start,
                register_access_count: witness.reg_ops.len() as u32,
                memory_access_start,
                memory_access_count: witness.mem_ops.len() as u32,
            });
        }
    }
    fn record_public_values(&mut self, words: &[u32]) {
        self.journal.public_values.extend_from_slice(words);
    }
    fn finish_shard(&mut self) {
        self.journal.summary.step_count = self.journal.opcodes.len() as u64;
        self.journal.arenas = descriptors(&self.journal);
        self.journal.packing_time = self.started.take().map_or(Duration::ZERO, |t| t.elapsed());
    }
}

fn pack_opcode(step: &StepRecord) -> CompactOpcodeRecordV1 {
    CompactOpcodeRecordV1 {
        pc_before: step.pc().before.0,
        raw_instruction: step.insn().raw,
        syscall_index: step.syscall_index().unwrap_or(StepRecord::NO_SYSCALL),
    }
}
fn pack_predecessor(cycle: Cycle, future: bool) -> u32 {
    let cycle = u32::try_from(cycle).expect("compact predecessor cycle exceeds u32");
    assert!(
        cycle <= CYCLE_MASK,
        "compact predecessor cycle exceeds 31 bits"
    );
    cycle | if future { FUTURE_ACCESS_BIT } else { 0 }
}
fn pack_memory(op: WriteOp, future: bool) -> CompactMemoryAccessV1 {
    CompactMemoryAccessV1 {
        predecessor_and_flags: pack_predecessor(op.previous_cycle, future),
        address: op.addr.0,
        value_before: op.value.before,
        value_after: op.value.after,
    }
}
fn pack_syscall_access(op: &WriteOp, future: bool) -> CompactSyscallAccessV1 {
    CompactSyscallAccessV1 {
        predecessor_and_flags: pack_predecessor(op.previous_cycle, future),
        address: op.addr.0,
        value_before: op.value.before,
        value_after: op.value.after,
    }
}

fn validate_syscalls(
    journal: &CompactShardJournalV1,
    witnesses: &[SyscallWitness],
) -> Result<(), JournalValidationError> {
    if journal.syscalls.len() != witnesses.len() {
        return Err(JournalValidationError("syscall association count mismatch"));
    }
    for (record, witness) in journal.syscalls.iter().zip(witnesses) {
        if record.witness_index as usize >= witnesses.len()
            || record.register_access_count as usize != witness.reg_ops.len()
            || record.memory_access_count as usize != witness.mem_ops.len()
        {
            return Err(JournalValidationError("syscall record mismatch"));
        }
        let mut expected = witness
            .reg_ops
            .iter()
            .zip(&witness.reg_future_access)
            .map(|(op, &f)| pack_syscall_access(op, f != 0))
            .chain(
                witness
                    .mem_ops
                    .iter()
                    .zip(&witness.mem_future_access)
                    .map(|(op, &f)| pack_syscall_access(op, f != 0)),
            );
        let start = record.register_access_start as usize;
        let end =
            start + record.register_access_count as usize + record.memory_access_count as usize;
        if !journal.syscall_accesses[start..end]
            .iter()
            .copied()
            .eq(&mut expected)
        {
            return Err(JournalValidationError("syscall access mismatch"));
        }
    }
    Ok(())
}

fn descriptor(
    kind: CompactArenaKind,
    offset: usize,
    count: usize,
    size: usize,
    align: usize,
) -> CompactArenaDescriptorV1 {
    CompactArenaDescriptorV1 {
        kind: kind.0,
        record_size: size as u32,
        record_align: align as u32,
        reserved: 0,
        byte_offset: offset as u64,
        record_count: count as u64,
    }
}
fn descriptors(j: &CompactShardJournalV1) -> [CompactArenaDescriptorV1; 7] {
    let mut offset = 0;
    macro_rules! arena {
        ($kind:expr, $field:ident, $ty:ty) => {{
            let d = descriptor(
                $kind,
                offset,
                j.$field.len(),
                mem::size_of::<$ty>(),
                mem::align_of::<$ty>(),
            );
            offset += j.$field.len() * mem::size_of::<$ty>();
            d
        }};
    }
    let result = [
        arena!(CompactArenaKind::OPCODES, opcodes, CompactOpcodeRecordV1),
        arena!(
            CompactArenaKind::REGISTER_READS,
            register_reads,
            CompactRegisterReadV1
        ),
        arena!(
            CompactArenaKind::REGISTER_WRITES,
            register_writes,
            CompactRegisterWriteV1
        ),
        arena!(
            CompactArenaKind::MEMORY_ACCESSES,
            memory_accesses,
            CompactMemoryAccessV1
        ),
        arena!(CompactArenaKind::SYSCALLS, syscalls, CompactSyscallRecordV1),
        arena!(
            CompactArenaKind::SYSCALL_ACCESSES,
            syscall_accesses,
            CompactSyscallAccessV1
        ),
        arena!(CompactArenaKind::PUBLIC_VALUES, public_values, u32),
    ];
    let _ = offset;
    result
}

pub fn compact_journal_layout_fingerprint() -> [u8; 32] {
    let mut h = Keccak::v256();
    h.update(b"ceno-compact-shard-journal-v1-typed");
    for value in [
        mem::size_of::<CompactArenaDescriptorV1>(),
        mem::size_of::<CompactShardSummaryV1>(),
        mem::size_of::<CompactOpcodeRecordV1>(),
        mem::size_of::<CompactRegisterReadV1>(),
        mem::size_of::<CompactRegisterWriteV1>(),
        mem::size_of::<CompactMemoryAccessV1>(),
        mem::size_of::<CompactSyscallRecordV1>(),
        mem::size_of::<CompactSyscallAccessV1>(),
    ] {
        h.update(&(value as u64).to_le_bytes());
    }
    let mut out = [0; 32];
    h.finalize(&mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ByteAddr, Change, FullTracer, InsnKind, ReadOp, WordAddr, encode_rv32};
    fn sample() -> StepRecord {
        StepRecord::new_im_instruction(
            4,
            ByteAddr(0x1000),
            encode_rv32(InsnKind::LW, 1, 0, 2, 8),
            7,
            Change::new(3, 9),
            ReadOp {
                addr: WordAddr(0x20),
                value: 11,
                previous_cycle: 1,
            },
            0,
        )
    }
    #[test]
    fn typed_abi_layout_is_stable() {
        assert_eq!(mem::size_of::<CompactOpcodeRecordV1>(), 12);
        assert_eq!(mem::size_of::<CompactRegisterReadV1>(), 8);
        assert_eq!(mem::size_of::<CompactRegisterWriteV1>(), 12);
        assert_eq!(mem::size_of::<CompactMemoryAccessV1>(), 16);
        assert_ne!(compact_journal_layout_fingerprint(), [0; 32]);
    }
    #[test]
    fn compact_sink_matches_legacy() {
        let step = sample();
        let mut legacy = LegacyWitnessRecordSink::default();
        let mut compact = CompactWitnessRecordSink::default();
        legacy.begin_shard(0);
        compact.begin_shard(0);
        legacy.record_step(&step);
        compact.record_step(&step);
        compact.record_public_values(&[1, 2, 3]);
        legacy.finish_shard();
        compact.finish_shard();
        compact.journal.validate_against(&legacy, &[]).unwrap();
        assert_eq!(
            compact.journal.summary.start_cycle,
            FullTracer::SUBCYCLES_PER_INSN
        );
    }
    #[test]
    fn representative_records_fit_volume_gate() {
        let mut sink = CompactWitnessRecordSink::default();
        sink.begin_shard(0);
        sink.record_step(&sample());
        sink.finish_shard();
        assert_eq!(sink.journal.byte_len(), 48);
        assert!(sink.journal.bytes_per_step() <= 48.0);
    }
    #[test]
    fn malformed_descriptor_is_rejected() {
        let mut sink = CompactWitnessRecordSink::default();
        sink.begin_shard(0);
        sink.finish_shard();
        sink.journal.arenas[0].record_size += 1;
        assert_eq!(
            sink.journal.validate_descriptors().unwrap_err().0,
            "malformed arena descriptor"
        );
    }
}
