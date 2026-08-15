use crate::{Cycle, StepRecord, Word};
use std::{
    fmt, mem,
    time::{Duration, Instant},
};
use tiny_keccak::{Hasher, Keccak};

pub const COMPACT_SHARD_JOURNAL_MAGIC: u64 = u64::from_le_bytes(*b"CENOJNL1");
pub const COMPACT_SHARD_JOURNAL_VERSION: u32 = 1;

/// Device-facing arena tag. This is deliberately not a Rust enum: unknown tags
/// can be rejected without invoking an invalid enum discriminant on the host or GPU.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(transparent)]
pub struct CompactArenaKind(pub u32);

impl CompactArenaKind {
    pub const OPCODES: Self = Self(1);
    pub const ACCESS_EDGES: Self = Self(2);
    pub const SYSCALLS: Self = Self(3);
}

/// Relocatable arena metadata. `byte_offset` is relative to the journal payload,
/// never a host or device pointer, so a future device lease can bind it safely.
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

/// One opcode occurrence. Register indices and access presence are packed into
/// explicit integer fields; no Rust enum representation crosses the ABI.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct CompactOpcodeRecordV1 {
    pub cycle: Cycle,
    pub pc_before: Word,
    pub pc_after: Word,
    pub heap_before: Word,
    pub heap_after: Word,
    pub hint_before: Word,
    pub hint_after: Word,
    pub raw_instruction: Word,
    pub immediate: i32,
    pub syscall_index: u32,
    /// bits 0..7 kind, 8..15 rs1, 16..23 rs2, 24..31 rd
    pub opcode_meta: u32,
    /// bits 0..3 access presence, 8..11 cross-shard future access
    pub access_meta: u32,
}

/// One actual architectural access, emitted exactly once.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct CompactAccessEdgeV1 {
    pub cycle: Cycle,
    pub predecessor_cycle: Cycle,
    pub address: Word,
    pub value_before: Word,
    pub value_after: Word,
    /// 0=RS1, 1=RS2, 2=RD, 3=memory.
    pub slot: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompactShardJournalV1 {
    pub magic: u64,
    pub version: u32,
    pub header_size: u32,
    pub layout_fingerprint: [u8; 32],
    pub summary: CompactShardSummaryV1,
    pub arenas: [CompactArenaDescriptorV1; 3],
    pub opcodes: Vec<CompactOpcodeRecordV1>,
    pub access_edges: Vec<CompactAccessEdgeV1>,
    /// Reserved compact precompile arena. M1 validates associations; later
    /// special-chip milestones define its typed payload without changing V1 headers.
    pub syscalls: Vec<u8>,
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
            arenas: [CompactArenaDescriptorV1::default(); 3],
            opcodes: Vec::new(),
            access_edges: Vec::new(),
            syscalls: Vec::new(),
            packing_time: Duration::ZERO,
        }
    }
}

impl CompactShardJournalV1 {
    pub fn byte_len(&self) -> usize {
        self.opcodes.len() * mem::size_of::<CompactOpcodeRecordV1>()
            + self.access_edges.len() * mem::size_of::<CompactAccessEdgeV1>()
            + self.syscalls.len()
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
        let expected = [
            descriptor(
                CompactArenaKind::OPCODES,
                0,
                self.opcodes.len(),
                mem::size_of::<CompactOpcodeRecordV1>(),
                mem::align_of::<CompactOpcodeRecordV1>(),
            ),
            descriptor(
                CompactArenaKind::ACCESS_EDGES,
                (self.opcodes.len() * mem::size_of::<CompactOpcodeRecordV1>()) as u64,
                self.access_edges.len(),
                mem::size_of::<CompactAccessEdgeV1>(),
                mem::align_of::<CompactAccessEdgeV1>(),
            ),
            descriptor(
                CompactArenaKind::SYSCALLS,
                (self.opcodes.len() * mem::size_of::<CompactOpcodeRecordV1>()
                    + self.access_edges.len() * mem::size_of::<CompactAccessEdgeV1>())
                    as u64,
                self.syscalls.len(),
                1,
                1,
            ),
        ];
        if self.arenas != expected {
            return Err(JournalValidationError("malformed arena descriptor"));
        }
        Ok(())
    }

    pub fn validate_against(
        &self,
        legacy: &LegacyWitnessRecordSink,
        syscall_count: usize,
    ) -> Result<(), JournalValidationError> {
        self.validate_descriptors()?;
        if self.opcodes.len() != legacy.steps.len() {
            return Err(JournalValidationError("opcode count mismatch"));
        }
        if self.summary.step_count != legacy.steps.len() as u64 {
            return Err(JournalValidationError("summary step count mismatch"));
        }
        let mut edge = 0;
        for (opcode, step) in self.opcodes.iter().zip(&legacy.steps) {
            if *opcode != pack_opcode(step) {
                return Err(JournalValidationError("opcode field mismatch"));
            }
            for expected in pack_accesses(step) {
                if self.access_edges.get(edge) != Some(&expected) {
                    return Err(JournalValidationError("access edge mismatch"));
                }
                edge += 1;
            }
        }
        if edge != self.access_edges.len() {
            return Err(JournalValidationError("access edge count mismatch"));
        }
        let associated = self
            .opcodes
            .iter()
            .filter(|r| r.syscall_index != StepRecord::NO_SYSCALL)
            .count();
        if associated != syscall_count {
            return Err(JournalValidationError("syscall association count mismatch"));
        }
        Ok(())
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
        self.journal.access_edges.extend(pack_accesses(step));
    }
    fn finish_shard(&mut self) {
        self.journal.summary.step_count = self.journal.opcodes.len() as u64;
        let opcode_bytes = self.journal.opcodes.len() * mem::size_of::<CompactOpcodeRecordV1>();
        let edge_bytes = self.journal.access_edges.len() * mem::size_of::<CompactAccessEdgeV1>();
        self.journal.arenas = [
            descriptor(
                CompactArenaKind::OPCODES,
                0,
                self.journal.opcodes.len(),
                mem::size_of::<CompactOpcodeRecordV1>(),
                mem::align_of::<CompactOpcodeRecordV1>(),
            ),
            descriptor(
                CompactArenaKind::ACCESS_EDGES,
                opcode_bytes as u64,
                self.journal.access_edges.len(),
                mem::size_of::<CompactAccessEdgeV1>(),
                mem::align_of::<CompactAccessEdgeV1>(),
            ),
            descriptor(
                CompactArenaKind::SYSCALLS,
                (opcode_bytes + edge_bytes) as u64,
                self.journal.syscalls.len(),
                1,
                1,
            ),
        ];
        self.journal.packing_time = self.started.take().map_or(Duration::ZERO, |t| t.elapsed());
    }
}

fn descriptor(
    kind: CompactArenaKind,
    byte_offset: u64,
    count: usize,
    size: usize,
    align: usize,
) -> CompactArenaDescriptorV1 {
    CompactArenaDescriptorV1 {
        kind: kind.0,
        record_size: size as u32,
        record_align: align as u32,
        reserved: 0,
        byte_offset,
        record_count: count as u64,
    }
}

fn pack_opcode(step: &StepRecord) -> CompactOpcodeRecordV1 {
    let insn = step.insn();
    let presence = (step.rs1().is_some() as u32)
        | ((step.rs2().is_some() as u32) << 1)
        | ((step.rd().is_some() as u32) << 2)
        | ((step.memory_op().is_some() as u32) << 3);
    CompactOpcodeRecordV1 {
        cycle: step.cycle(),
        pc_before: step.pc().before.0,
        pc_after: step.pc().after.0,
        heap_before: step.heap_maxtouch_addr.before.0,
        heap_after: step.heap_maxtouch_addr.after.0,
        hint_before: step.hint_maxtouch_addr.before.0,
        hint_after: step.hint_maxtouch_addr.after.0,
        raw_instruction: insn.raw,
        immediate: insn.imm,
        syscall_index: step.syscall_index().unwrap_or(StepRecord::NO_SYSCALL),
        opcode_meta: (insn.kind as u32)
            | ((insn.rs1 as u32) << 8)
            | ((insn.rs2 as u32) << 16)
            | ((insn.rd as u32) << 24),
        access_meta: presence | ((step.future_access_mask() as u32) << 8),
    }
}

fn pack_accesses(step: &StepRecord) -> impl Iterator<Item = CompactAccessEdgeV1> {
    let base = step.cycle();
    [
        step.rs1().map(|op| CompactAccessEdgeV1 {
            cycle: base,
            predecessor_cycle: op.previous_cycle,
            address: op.addr.0,
            value_before: op.value,
            value_after: op.value,
            slot: 0,
        }),
        step.rs2().map(|op| CompactAccessEdgeV1 {
            cycle: base + 1,
            predecessor_cycle: op.previous_cycle,
            address: op.addr.0,
            value_before: op.value,
            value_after: op.value,
            slot: 1,
        }),
        step.rd().map(|op| CompactAccessEdgeV1 {
            cycle: base + 2,
            predecessor_cycle: op.previous_cycle,
            address: op.addr.0,
            value_before: op.value.before,
            value_after: op.value.after,
            slot: 2,
        }),
        step.memory_op().map(|op| CompactAccessEdgeV1 {
            cycle: base + 3,
            predecessor_cycle: op.previous_cycle,
            address: op.addr.0,
            value_before: op.value.before,
            value_after: op.value.after,
            slot: 3,
        }),
    ]
    .into_iter()
    .flatten()
}

pub fn compact_journal_layout_fingerprint() -> [u8; 32] {
    let mut h = Keccak::v256();
    h.update(b"ceno-compact-shard-journal-v1");
    for value in [
        mem::size_of::<CompactArenaDescriptorV1>(),
        mem::align_of::<CompactArenaDescriptorV1>(),
        mem::size_of::<CompactShardSummaryV1>(),
        mem::align_of::<CompactShardSummaryV1>(),
        mem::size_of::<CompactOpcodeRecordV1>(),
        mem::align_of::<CompactOpcodeRecordV1>(),
        mem::size_of::<CompactAccessEdgeV1>(),
        mem::align_of::<CompactAccessEdgeV1>(),
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

    #[test]
    fn abi_layout_is_stable_and_pointer_free() {
        assert_eq!(mem::size_of::<CompactArenaDescriptorV1>(), 32);
        assert_eq!(mem::size_of::<CompactOpcodeRecordV1>(), 56);
        assert_eq!(mem::size_of::<CompactAccessEdgeV1>(), 32);
        assert_eq!(mem::align_of::<CompactAccessEdgeV1>(), 8);
        assert_ne!(compact_journal_layout_fingerprint(), [0; 32]);
    }

    #[test]
    fn compact_sink_matches_every_legacy_step_field() {
        let step = StepRecord::new_im_instruction(
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
        );
        let mut legacy = LegacyWitnessRecordSink::default();
        let mut compact = CompactWitnessRecordSink::default();
        legacy.begin_shard(0);
        compact.begin_shard(0);
        legacy.record_step(&step);
        compact.record_step(&step);
        legacy.finish_shard();
        compact.finish_shard();
        compact.journal.validate_against(&legacy, 0).unwrap();
        assert_eq!(
            compact.journal.summary.start_cycle,
            FullTracer::SUBCYCLES_PER_INSN
        );
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
