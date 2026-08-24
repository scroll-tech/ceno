use crate::{InsnKind, StepRecord};
use std::mem::MaybeUninit;
use strum::{EnumCount, IntoEnumIterator};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GpuShardPreview {
    pub shard_id: u32,
    pub cycle_start: u64,
    pub cycle_end: u64,
    pub heap_start: u32,
    pub heap_end: u32,
    pub hint_start: u32,
    pub hint_end: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum GpuTypedLayout {
    R,
    I,
    Branch,
    Jal,
    Jalr,
    Load,
    Store,
    U,
}

pub(crate) const GPU_TYPED_NATIVE_MAX_FIELDS: usize = 13;
pub(crate) const GPU_TYPED_NATIVE_SENTINEL: u32 = 0x4750_5544;
pub(crate) const GPU_COMPACT_NATIVE_SENTINEL: u32 = 0x4930_3530;
pub(crate) const GPU_COMPACT_CYCLE_BITS: usize = 32;
const GPU_COMPACT_TAIL_PADDING: usize = 31;

fn compact_source_enabled_from(source_override: Option<&std::ffi::OsStr>) -> bool {
    match source_override {
        None => true,
        Some(value) if value == std::ffi::OsStr::new("1") => true,
        Some(value) if value == std::ffi::OsStr::new("0") => false,
        Some(value) => panic!("CENO_I050_COMPACT_SOURCE must be 0 or 1, got {:?}", value),
    }
}

pub fn i050_compact_source_enabled() -> bool {
    let source_override = std::env::var_os("CENO_I050_COMPACT_SOURCE");
    compact_source_enabled_from(source_override.as_deref())
}

/// Stable, pointer-only ABI for one preallocated typed-SoA family. Native AOT
/// updates only `cursor` and the pointed-to field storage.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub(crate) struct GpuTypedNativeKindState {
    pub fields: [*mut u32; GPU_TYPED_NATIVE_MAX_FIELDS],
    pub capacity: u32,
    pub cursor: u32,
    pub layout: u32,
    pub sentinel: u32,
    pub range_start: u32,
    pub pc_base: u32,
}

impl Default for GpuTypedNativeKindState {
    fn default() -> Self {
        Self {
            fields: [std::ptr::null_mut(); GPU_TYPED_NATIVE_MAX_FIELDS],
            capacity: 0,
            cursor: 0,
            layout: u32::MAX,
            sentinel: GPU_TYPED_NATIVE_SENTINEL,
            range_start: 0,
            pc_base: 0,
        }
    }
}

impl GpuTypedLayout {
    pub const fn words(self) -> usize {
        match self {
            Self::R => 11,
            Self::Store => 12,
            Self::I | Self::Branch => 9,
            Self::Jal => 8,
            Self::Jalr => 10,
            Self::Load => 13,
            // U-type instructions still perform the circuit's implicit x0
            // read.  Preserve its previous timestamp so the GPU can witness
            // the same ReadRS1/AssertLt row as the CPU path.
            Self::U => 8,
        }
    }

    pub const fn bytes(self) -> usize {
        self.words() * size_of::<u32>()
    }

    pub const fn compact_bytes(self) -> usize {
        match self {
            Self::R | Self::Load | Self::Store => 33,
            Self::I | Self::Branch | Self::Jalr => 25,
            Self::Jal => 17,
            Self::U => 21,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GpuTypedKindSpec {
    pub layout: GpuTypedLayout,
    pub send_arity: u8,
}

/// Maximum number of address sends owned by one sparse/fallback instruction.
/// Keccak is the widest established sparse producer (two register sends plus
/// fifty memory-word sends).  Reserving this for every fallback instruction is
/// deliberately conservative; the observed device prefix remains authoritative.
pub const MAX_SPARSE_ADDRESS_SENDS_PER_STEP: u32 = 52;

/// Continuation EC records are produced into their own buffer and never claim
/// slots in the shared observed-address arena.
pub const CONTINUATION_ADDRESS_SEND_BOUND: u32 = 0;

pub const fn gpu_typed_kind_spec(kind: InsnKind) -> Option<GpuTypedKindSpec> {
    use GpuTypedLayout as Layout;
    use InsnKind::*;

    let (layout, send_arity) = match kind {
        ADD | SUB | XOR | OR | AND | SLL | SRL | SRA | SLT | SLTU | MUL | MULH | MULHSU | MULHU
        | DIV | DIVU | REM | REMU => (Layout::R, 3),
        ADDI | XORI | ORI | ANDI | SLLI | SRLI | SRAI | SLTI | SLTIU => (Layout::I, 2),
        BEQ | BNE | BLT | BGE | BLTU | BGEU => (Layout::Branch, 2),
        JAL => (Layout::Jal, 1),
        JALR => (Layout::Jalr, 2),
        LB | LH | LW | LBU | LHU => (Layout::Load, 3),
        SB | SH | SW => (Layout::Store, 3),
        #[cfg(feature = "u16limb_circuit")]
        LUI | AUIPC => (Layout::U, 2),
        INVALID | ECALL => return None,
    };
    Some(GpuTypedKindSpec { layout, send_arity })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GpuReplayRangeDescriptor {
    pub shard_id: u32,
    pub sequence: u32,
    pub range_start: u32,
    pub range_len: u32,
    pub family_counts: [usize; InsnKind::COUNT],
    pub fallback_count: usize,
    pub unsupported_count: usize,
}

impl GpuReplayRangeDescriptor {
    pub fn checked_total(&self) -> Option<usize> {
        self.family_counts
            .iter()
            .try_fold(0usize, |sum, count| sum.checked_add(*count))?
            .checked_add(self.fallback_count)?
            .checked_add(self.unsupported_count)
    }

    pub fn conservative_address_reservation(&self) -> Option<u32> {
        if self.unsupported_count != 0 {
            return None;
        }
        let ordinary =
            self.family_counts
                .iter()
                .enumerate()
                .try_fold(0u64, |sum, (kind, count)| {
                    let kind = InsnKind::iter().nth(kind)?;
                    let arity =
                        gpu_typed_kind_spec(kind).map_or(0, |spec| u64::from(spec.send_arity));
                    sum.checked_add((*count as u64).checked_mul(arity)?)
                })?;
        let sparse = u64::try_from(self.fallback_count)
            .ok()?
            .checked_mul(u64::from(MAX_SPARSE_ADDRESS_SENDS_PER_STEP))?;
        u32::try_from(ordinary.checked_add(sparse)?).ok()
    }

    /// Exact fused-launch source capacity derived from preflight family counts.
    pub fn fused_payload_bytes(&self, compact: bool) -> Option<usize> {
        InsnKind::iter()
            .zip(self.family_counts)
            .try_fold(0usize, |total, (kind, rows)| {
                if rows == 0 {
                    return Some(total);
                }
                let spec = gpu_typed_kind_spec(kind)?;
                let row_bytes = if compact {
                    spec.layout.compact_bytes()
                } else {
                    spec.layout.bytes()
                };
                total.checked_add(rows.checked_mul(row_bytes)?)
            })
    }

    /// Exact number of nonempty fused work descriptors for this replay range.
    pub fn fused_work_items(&self) -> Option<usize> {
        InsnKind::iter()
            .zip(self.family_counts)
            .try_fold(0usize, |total, (kind, rows)| {
                let present = usize::from(rows != 0 && gpu_typed_kind_spec(kind).is_some());
                total.checked_add(present)
            })
    }
}

/// Exact field-major storage for one instruction kind in one replay range.
/// Every field owns a fixed boxed slice, so writes cannot grow or reallocate.
#[derive(Debug)]
pub struct GpuTypedSoaArena {
    kind: InsnKind,
    layout: GpuTypedLayout,
    fields: Vec<Box<[u32]>>,
    // Spare compact capacity is intentionally uninitialized. Direct native
    // emission writes complete rows before publishing them; safe readers are
    // restricted to the initialized `len`-row prefix.
    compact: Option<Box<[MaybeUninit<u8>]>>,
    range_start: u32,
    pc_base: u32,
    len: usize,
}

impl GpuTypedSoaArena {
    pub fn new(kind: InsnKind, rows: usize) -> Option<Self> {
        Self::new_with_range(kind, rows, 0)
    }

    pub(crate) fn new_with_range(kind: InsnKind, rows: usize, range_start: u32) -> Option<Self> {
        Self::new_with_mode(kind, rows, range_start, i050_compact_source_enabled())
    }

    /// Internal compact-first replay constructor. Unlike the retained I050
    /// environment switch, layered L7 selects the byte representation as part
    /// of its cache identity and must never allocate the field-SoA oracle.
    pub(crate) fn new_compact_with_range(
        kind: InsnKind,
        rows: usize,
        range_start: u32,
    ) -> Option<Self> {
        Self::new_with_mode(kind, rows, range_start, true)
    }

    fn new_with_mode(kind: InsnKind, rows: usize, range_start: u32, compact: bool) -> Option<Self> {
        let layout = gpu_typed_kind_spec(kind)?.layout;
        let fields = if compact {
            Vec::new()
        } else {
            (0..layout.words())
                .map(|_| vec![0u32; rows].into_boxed_slice())
                .collect()
        };
        let compact = compact.then(|| {
            let bytes = rows
                .checked_mul(layout.compact_bytes())
                .unwrap()
                .checked_add(GPU_COMPACT_TAIL_PADDING)
                .unwrap();
            Box::<[u8]>::new_uninit_slice(bytes)
        });
        Some(Self {
            kind,
            layout,
            fields,
            compact,
            range_start,
            pc_base: 0,
            len: 0,
        })
    }

    pub fn kind(&self) -> InsnKind {
        self.kind
    }

    pub fn layout(&self) -> GpuTypedLayout {
        self.layout
    }

    pub fn capacity(&self) -> usize {
        self.compact.as_ref().map_or_else(
            || self.fields.first().map_or(0, |field| field.len()),
            |compact| (compact.len() - GPU_COMPACT_TAIL_PADDING) / self.layout.compact_bytes(),
        )
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub(crate) fn reset_for_range(&mut self, range_start: u32) {
        self.range_start = range_start;
        self.pc_base = 0;
        self.len = 0;
    }

    pub fn fields(&self) -> &[Box<[u32]>] {
        &self.fields
    }

    pub fn is_compact(&self) -> bool {
        self.compact.is_some()
    }

    pub fn payload_bytes(&self) -> &[u8] {
        if let Some(compact) = &self.compact {
            let bytes = self.len * self.layout.compact_bytes();
            // SAFETY: `len` advances only after complete row stores.
            unsafe { std::slice::from_raw_parts(compact.as_ptr().cast::<u8>(), bytes) }
        } else {
            &[]
        }
    }

    pub fn range_start(&self) -> u32 {
        self.range_start
    }

    pub fn pc_base(&self) -> u32 {
        self.pc_base
    }

    pub fn compact_opcode(&self) -> u32 {
        match self.layout {
            GpuTypedLayout::R => 0x33,
            GpuTypedLayout::I => 0x13,
            GpuTypedLayout::Branch => 0x63,
            GpuTypedLayout::Jal => 0x6f,
            GpuTypedLayout::Jalr => 0x67,
            GpuTypedLayout::Load => 0x03,
            GpuTypedLayout::Store => 0x23,
            GpuTypedLayout::U => match self.kind {
                #[cfg(feature = "u16limb_circuit")]
                InsnKind::LUI => 0x37,
                #[cfg(feature = "u16limb_circuit")]
                InsnKind::AUIPC => 0x17,
                _ => unreachable!("non-U kind has U compact layout"),
            },
        }
    }

    pub fn pc_bounds(&self) -> Result<Option<(u32, u32)>, &'static str> {
        if let Some(compact) = &self.compact {
            let stride = self.layout.compact_bytes();
            // SAFETY: only the initialized `len`-row prefix is read.
            let compact = unsafe {
                std::slice::from_raw_parts(compact.as_ptr().cast::<u8>(), self.len * stride)
            };
            let mut min = u32::MAX;
            let mut max = 0u32;
            for row in 0..self.len {
                let source = &compact[row * stride..(row + 1) * stride];
                let pc = self
                    .pc_base
                    .checked_add(read_compact_bits(source, 18, 20)? << 2)
                    .ok_or("compact PC overflow")?;
                min = min.min(pc);
                max = max.max(pc);
            }
            Ok((min <= max).then_some((min, max)))
        } else {
            Ok(self.fields.get(1).and_then(|pcs| {
                let min = pcs[..self.len].iter().copied().min()?;
                let max = pcs[..self.len].iter().copied().max()?;
                Some((min, max))
            }))
        }
    }

    pub(crate) fn native_state(&mut self) -> GpuTypedNativeKindState {
        let mut state = GpuTypedNativeKindState {
            capacity: u32::try_from(self.capacity()).expect("typed replay capacity exceeds u32"),
            cursor: u32::try_from(self.len).expect("typed replay cursor exceeds u32"),
            layout: self.layout as u32,
            sentinel: if self.is_compact() {
                GPU_COMPACT_NATIVE_SENTINEL
            } else {
                GPU_TYPED_NATIVE_SENTINEL
            },
            range_start: self.range_start,
            pc_base: self.pc_base,
            ..GpuTypedNativeKindState::default()
        };
        if let Some(compact) = &mut self.compact {
            state.fields[0] = compact.as_mut_ptr().cast::<u32>();
        } else {
            for (dst, field) in state.fields.iter_mut().zip(&mut self.fields) {
                *dst = field.as_mut_ptr();
            }
        }
        state
    }

    pub(crate) fn sync_native_state(
        &mut self,
        state: &GpuTypedNativeKindState,
    ) -> Result<(), &'static str> {
        let expected_sentinel = if self.is_compact() {
            GPU_COMPACT_NATIVE_SENTINEL
        } else {
            GPU_TYPED_NATIVE_SENTINEL
        };
        if state.sentinel != expected_sentinel {
            return Err("typed replay native sentinel mismatch");
        }
        if state.layout != self.layout as u32 {
            return Err("typed replay native layout mismatch");
        }
        if state.capacity as usize != self.capacity() || state.cursor > state.capacity {
            return Err("typed replay native cursor/capacity mismatch");
        }
        if state.range_start != self.range_start {
            return Err("typed replay native range start changed");
        }
        if let Some(compact) = &self.compact {
            if state.fields[0] != compact.as_ptr().cast_mut().cast::<u32>() {
                return Err("compact replay native pointer changed");
            }
            self.pc_base = state.pc_base;
        } else {
            for (pointer, field) in state.fields.iter().zip(&self.fields) {
                if *pointer != field.as_ptr().cast_mut() {
                    return Err("typed replay native field pointer changed");
                }
            }
        }
        self.len = state.cursor as usize;
        Ok(())
    }

    pub fn push_step(&mut self, ordinal: u32, record: &StepRecord) -> Result<(), &'static str> {
        if self.len >= self.capacity() {
            return Err("typed replay cursor exceeded exact capacity");
        }
        let row = self.len;
        if self.is_compact() {
            self.pack_compact_step(row, ordinal, record)?;
            self.len += 1;
            return Ok(());
        }
        let words = typed_words(self.layout, ordinal, record);
        if words.len() != self.fields.len() {
            return Err("typed replay layout width mismatch");
        }
        for (field, value) in self.fields.iter_mut().zip(words) {
            field[row] = value;
        }
        self.len += 1;
        Ok(())
    }

    fn pack_compact_step(
        &mut self,
        row: usize,
        ordinal: u32,
        record: &StepRecord,
    ) -> Result<(), &'static str> {
        let local_ordinal = ordinal
            .checked_sub(self.range_start)
            .ok_or("compact ordinal precedes range")?;
        if local_ordinal >= 1 << 18 {
            return Err("compact ordinal exceeds range width");
        }
        let pc = record.pc().before.0;
        if self.pc_base == 0 {
            self.pc_base = pc & !((1 << 22) - 1);
        }
        let pc_offset = pc
            .checked_sub(self.pc_base)
            .filter(|offset| offset & 3 == 0 && offset >> 2 < 1 << 20)
            .ok_or("compact PC exceeds aligned window")?
            >> 2;
        let raw = record.insn().raw;
        let mut values = Vec::with_capacity(10);
        values.extend([(local_ordinal, 18), (pc_offset, 20), (raw >> 7, 25)]);
        let rs1 = record.rs1().unwrap_or_default();
        let rs2 = record.rs2().unwrap_or_default();
        let rd = record.rd().unwrap_or_default();
        let memory = record.memory_op().unwrap_or_default();
        fn append_access(
            values: &mut Vec<(u32, usize)>,
            cycle: u64,
            value: u32,
        ) -> Result<(), &'static str> {
            let cycle = u32::try_from(cycle).map_err(|_| "compact access cycle exceeds u32")?;
            values.extend([(cycle, GPU_COMPACT_CYCLE_BITS), (value, 32)]);
            Ok(())
        }
        match self.layout {
            GpuTypedLayout::R => {
                append_access(&mut values, rs1.previous_cycle, rs1.value)?;
                append_access(&mut values, rs2.previous_cycle, rs2.value)?;
                append_access(&mut values, rd.previous_cycle, rd.value.before)?;
            }
            GpuTypedLayout::I | GpuTypedLayout::Jalr => {
                append_access(&mut values, rs1.previous_cycle, rs1.value)?;
                append_access(&mut values, rd.previous_cycle, rd.value.before)?;
            }
            GpuTypedLayout::Branch => {
                append_access(&mut values, rs1.previous_cycle, rs1.value)?;
                append_access(&mut values, rs2.previous_cycle, rs2.value)?;
            }
            GpuTypedLayout::Jal => append_access(&mut values, rd.previous_cycle, rd.value.before)?,
            GpuTypedLayout::Load => {
                append_access(&mut values, rs1.previous_cycle, rs1.value)?;
                append_access(&mut values, rd.previous_cycle, rd.value.before)?;
                append_access(&mut values, memory.previous_cycle, memory.value.before)?;
            }
            GpuTypedLayout::Store => {
                append_access(&mut values, rs1.previous_cycle, rs1.value)?;
                append_access(&mut values, rs2.previous_cycle, rs2.value)?;
                append_access(&mut values, memory.previous_cycle, memory.value.before)?;
            }
            GpuTypedLayout::U => {
                let cycle = u32::try_from(rs1.previous_cycle).map_err(|_| "compact x0 cycle")?;
                values.push((cycle, GPU_COMPACT_CYCLE_BITS));
                append_access(&mut values, rd.previous_cycle, rd.value.before)?;
            }
        }
        values.push((u32::from(record.future_access_mask()), 4));
        let stride = self.layout.compact_bytes();
        let destination = &mut self.compact.as_mut().unwrap()[row * stride..(row + 1) * stride];
        destination.fill(MaybeUninit::new(0));
        // SAFETY: the complete row was initialized immediately above.
        let destination = unsafe {
            std::slice::from_raw_parts_mut(destination.as_mut_ptr().cast::<u8>(), stride)
        };
        let mut bit = 0usize;
        for (value, width) in values {
            write_compact_bits(destination, bit, width, value)?;
            bit += width;
        }
        if bit > stride * 8 {
            return Err("compact record exceeds layout stride");
        }
        Ok(())
    }
}

#[cfg(test)]
const fn compact_mask_bit(layout: GpuTypedLayout) -> usize {
    match layout {
        GpuTypedLayout::R | GpuTypedLayout::Load | GpuTypedLayout::Store => 255,
        GpuTypedLayout::I | GpuTypedLayout::Branch | GpuTypedLayout::Jalr => 191,
        GpuTypedLayout::Jal => 127,
        GpuTypedLayout::U => 159,
    }
}

fn write_compact_bits(
    destination: &mut [u8],
    bit: usize,
    width: usize,
    value: u32,
) -> Result<(), &'static str> {
    if width > 32 || bit + width > destination.len() * 8 || (width < 32 && value >= 1 << width) {
        return Err("compact bit field overflow");
    }
    for offset in 0..width {
        let target = bit + offset;
        let mask = 1u8 << (target & 7);
        if value >> offset & 1 != 0 {
            destination[target >> 3] |= mask;
        } else {
            destination[target >> 3] &= !mask;
        }
    }
    Ok(())
}

fn read_compact_bits(source: &[u8], bit: usize, width: usize) -> Result<u32, &'static str> {
    if width > 32 || bit + width > source.len() * 8 {
        return Err("compact bit field read overflow");
    }
    let mut value = 0u32;
    for offset in 0..width {
        value |= u32::from(source[(bit + offset) >> 3] >> ((bit + offset) & 7) & 1) << offset;
    }
    Ok(value)
}

fn typed_words(layout: GpuTypedLayout, ordinal: u32, record: &StepRecord) -> Vec<u32> {
    let pc = record.pc();
    let insn = record.insn();
    let rs1 = record.rs1().unwrap_or_default();
    let rs2 = record.rs2().unwrap_or_default();
    let rd = record.rd().unwrap_or_default();
    let memory_op = record.memory_op().unwrap_or_default();
    let common = [ordinal, pc.before.0, insn.raw];
    let rs1 = [u32::try_from(rs1.previous_cycle).unwrap(), rs1.value];
    let rs2 = [u32::try_from(rs2.previous_cycle).unwrap(), rs2.value];
    let rd = [
        u32::try_from(rd.previous_cycle).unwrap(),
        rd.value.before,
        rd.value.after,
    ];
    let memory = [
        u32::try_from(memory_op.previous_cycle).unwrap(),
        memory_op.addr.0,
        memory_op.value.before,
    ];
    let mut words = Vec::with_capacity(layout.words());
    words.extend(common);
    match layout {
        GpuTypedLayout::R => {
            words.extend(rs1);
            words.extend(rs2);
            words.extend(rd);
        }
        GpuTypedLayout::I => {
            words.extend(rs1);
            words.extend(rd);
        }
        GpuTypedLayout::Branch => {
            words.push(pc.after.0);
            words.extend(rs1);
            words.extend(rs2);
        }
        GpuTypedLayout::Jal => {
            words.push(pc.after.0);
            words.extend(rd);
        }
        GpuTypedLayout::Jalr => {
            words.push(pc.after.0);
            words.extend(rs1);
            words.extend(rd);
        }
        GpuTypedLayout::Load => {
            words.extend(rs1);
            words.extend(rd);
            words.extend(memory);
            words.push(memory_op.value.after);
        }
        GpuTypedLayout::Store => {
            words.extend(rs1);
            words.extend(rs2);
            words.extend(memory);
            words.push(memory_op.value.after);
        }
        GpuTypedLayout::U => {
            words.push(rs1[0]);
            words.extend(rd);
        }
    }
    words.push(u32::from(record.future_access_mask()) << 8);
    words
}

#[cfg(test)]
mod i017_tests {
    use super::*;
    use crate::{ByteAddr, Change, ReadOp, WordAddr, WriteOp, encode_rv32};

    fn record(layout: GpuTypedLayout) -> StepRecord {
        let cycle = 40;
        let pc = ByteAddr(0x1000);
        let previous_cycle = 7;
        match layout {
            GpuTypedLayout::R => StepRecord::new_r_instruction(
                cycle,
                pc,
                encode_rv32(InsnKind::ADD, 1, 2, 3, 0),
                0x11,
                0x22,
                Change::new(0x33, 0x44),
                previous_cycle,
            ),
            GpuTypedLayout::I => StepRecord::new_i_instruction(
                cycle,
                Change::new(pc, ByteAddr(0x1004)),
                encode_rv32(InsnKind::ADDI, 1, 0, 3, 9),
                0x11,
                Change::new(0x33, 0x44),
                previous_cycle,
            ),
            GpuTypedLayout::Branch => StepRecord::new_b_instruction(
                cycle,
                Change::new(pc, ByteAddr(0x1080)),
                encode_rv32(InsnKind::BEQ, 1, 2, 0, 0x80),
                0x11,
                0x22,
                previous_cycle,
            ),
            GpuTypedLayout::Jal => StepRecord::new_j_instruction(
                cycle,
                Change::new(pc, ByteAddr(0x1080)),
                encode_rv32(InsnKind::JAL, 0, 0, 3, 0x80),
                Change::new(0x33, 0x44),
                previous_cycle,
            ),
            GpuTypedLayout::Jalr => StepRecord::new_i_instruction(
                cycle,
                Change::new(pc, ByteAddr(0x1080)),
                encode_rv32(InsnKind::JALR, 1, 0, 3, 8),
                0x11,
                Change::new(0x33, 0x44),
                previous_cycle,
            ),
            GpuTypedLayout::Load => StepRecord::new_im_instruction(
                cycle,
                pc,
                encode_rv32(InsnKind::LW, 1, 0, 3, 8),
                0x11,
                Change::new(0x33, 0x44),
                ReadOp {
                    addr: WordAddr(0x88),
                    value: 0x55,
                    previous_cycle: 6,
                },
                previous_cycle,
            ),
            GpuTypedLayout::Store => StepRecord::new_s_instruction(
                cycle,
                pc,
                encode_rv32(InsnKind::SW, 1, 2, 0, 8),
                0x11,
                0x22,
                WriteOp {
                    addr: WordAddr(0x88),
                    value: Change::new(0x55, 0x66),
                    previous_cycle: 6,
                },
                previous_cycle,
            ),
            GpuTypedLayout::U => {
                #[cfg(feature = "u16limb_circuit")]
                {
                    // Production U-type replay carries the implicit x0 read
                    // emitted by the compute trace path.
                    StepRecord::new_i_instruction(
                        cycle,
                        Change::new(pc, ByteAddr(0x1004)),
                        encode_rv32(InsnKind::LUI, 0, 0, 3, 0x12000),
                        0,
                        Change::new(0x33, 0x44),
                        previous_cycle,
                    )
                }
                #[cfg(not(feature = "u16limb_circuit"))]
                panic!("U layout is disabled without u16limb_circuit")
            }
        }
    }

    #[test]
    fn i017_layout_width_arity_and_kind_coverage_are_exact() {
        let widths = [
            (GpuTypedLayout::R, 11, 44),
            (GpuTypedLayout::I, 9, 36),
            (GpuTypedLayout::Branch, 9, 36),
            (GpuTypedLayout::Jal, 8, 32),
            (GpuTypedLayout::Jalr, 10, 40),
            (GpuTypedLayout::Load, 13, 52),
            (GpuTypedLayout::Store, 12, 48),
            (GpuTypedLayout::U, 8, 32),
        ];
        for (layout, words, bytes) in widths {
            assert_eq!(layout.words(), words);
            assert_eq!(layout.bytes(), bytes);
        }
        assert_eq!(GpuTypedLayout::R.compact_bytes(), 33);
        assert_eq!(GpuTypedLayout::I.compact_bytes(), 25);
        assert_eq!(GpuTypedLayout::Branch.compact_bytes(), 25);
        assert_eq!(GpuTypedLayout::Jal.compact_bytes(), 17);
        assert_eq!(GpuTypedLayout::Jalr.compact_bytes(), 25);
        assert_eq!(GpuTypedLayout::Load.compact_bytes(), 33);
        assert_eq!(GpuTypedLayout::Store.compact_bytes(), 33);
        assert_eq!(GpuTypedLayout::U.compact_bytes(), 21);

        for kind in InsnKind::iter() {
            match kind {
                InsnKind::INVALID | InsnKind::ECALL => {
                    assert_eq!(gpu_typed_kind_spec(kind), None)
                }
                _ => {
                    let spec = gpu_typed_kind_spec(kind).expect("ordinary kind must be typed");
                    assert!(matches!(spec.send_arity, 1..=3));
                    assert_eq!(
                        spec.send_arity,
                        match spec.layout {
                            GpuTypedLayout::Jal => 1,
                            GpuTypedLayout::I
                            | GpuTypedLayout::Branch
                            | GpuTypedLayout::Jalr
                            | GpuTypedLayout::U => 2,
                            GpuTypedLayout::R | GpuTypedLayout::Load | GpuTypedLayout::Store => 3,
                        }
                    );
                }
            }
        }
    }

    #[test]
    fn i050_compact_source_round_trips_every_layout_and_exact_width() {
        let cases = [
            (GpuTypedLayout::R, InsnKind::ADD),
            (GpuTypedLayout::I, InsnKind::ADDI),
            (GpuTypedLayout::Branch, InsnKind::BEQ),
            (GpuTypedLayout::Jal, InsnKind::JAL),
            (GpuTypedLayout::Jalr, InsnKind::JALR),
            (GpuTypedLayout::Load, InsnKind::LW),
            (GpuTypedLayout::Store, InsnKind::SW),
            #[cfg(feature = "u16limb_circuit")]
            (GpuTypedLayout::U, InsnKind::LUI),
        ];
        for (layout, kind) in cases {
            let step = record(layout);
            let range_start = 17;
            let ordinal = 19;
            let mut arena = GpuTypedSoaArena::new_with_mode(kind, 1, range_start, true).unwrap();
            arena.push_step(ordinal, &step).unwrap();
            assert!(arena.is_compact());
            assert!(arena.fields().is_empty());
            assert_eq!(arena.payload_bytes().len(), layout.compact_bytes());
            let source = arena.payload_bytes();
            let mut bit = 0usize;
            let mut take = |width| {
                let value = read_compact_bits(source, bit, width).unwrap();
                bit += width;
                value
            };
            assert_eq!(take(18), ordinal - range_start);
            assert_eq!(arena.pc_base() + (take(20) << 2), step.pc().before.0);
            assert_eq!((take(25) << 7) | (step.insn().raw & 0x7f), step.insn().raw);
            let rs1 = step.rs1().unwrap_or_default();
            let rs2 = step.rs2().unwrap_or_default();
            let rd = step.rd().unwrap_or_default();
            let memory = step.memory_op().unwrap_or_default();
            let mut check_access = |cycle: u64, value: u32| {
                assert_eq!(take(GPU_COMPACT_CYCLE_BITS), u32::try_from(cycle).unwrap());
                assert_eq!(take(32), value);
            };
            match layout {
                GpuTypedLayout::R => {
                    check_access(rs1.previous_cycle, rs1.value);
                    check_access(rs2.previous_cycle, rs2.value);
                    check_access(rd.previous_cycle, rd.value.before);
                }
                GpuTypedLayout::I | GpuTypedLayout::Jalr => {
                    check_access(rs1.previous_cycle, rs1.value);
                    check_access(rd.previous_cycle, rd.value.before);
                }
                GpuTypedLayout::Branch => {
                    check_access(rs1.previous_cycle, rs1.value);
                    check_access(rs2.previous_cycle, rs2.value);
                }
                GpuTypedLayout::Jal => check_access(rd.previous_cycle, rd.value.before),
                GpuTypedLayout::Load => {
                    check_access(rs1.previous_cycle, rs1.value);
                    check_access(rd.previous_cycle, rd.value.before);
                    check_access(memory.previous_cycle, memory.value.before);
                }
                GpuTypedLayout::Store => {
                    check_access(rs1.previous_cycle, rs1.value);
                    check_access(rs2.previous_cycle, rs2.value);
                    check_access(memory.previous_cycle, memory.value.before);
                }
                GpuTypedLayout::U => {
                    assert_eq!(
                        take(GPU_COMPACT_CYCLE_BITS),
                        u32::try_from(rs1.previous_cycle).unwrap()
                    );
                    assert_eq!(
                        take(GPU_COMPACT_CYCLE_BITS),
                        u32::try_from(rd.previous_cycle).unwrap()
                    );
                    assert_eq!(take(32), rd.value.before);
                }
            }
            assert_eq!(take(4), u32::from(step.future_access_mask()));
            assert_eq!(bit, compact_mask_bit(layout) + 4);
            assert!(source[bit.div_ceil(8)..].iter().all(|byte| *byte == 0));
        }
    }

    #[test]
    fn i050_compact_source_preserves_absolute_cycles_past_27_bits() {
        let shard_offset = 1u64 << 27;
        let ordinal = 10;
        let previous_cycle = shard_offset + 7;
        let step = StepRecord::new_r_instruction(
            shard_offset + u64::from(ordinal) * 4,
            ByteAddr(0x1000),
            encode_rv32(InsnKind::OR, 1, 2, 3, 0),
            0x11,
            0x22,
            Change::new(0x33, 0x44),
            previous_cycle,
        );
        let mut arena = GpuTypedSoaArena::new_with_mode(InsnKind::OR, 1, 0, true).unwrap();
        arena.push_step(ordinal, &step).unwrap();

        let source = arena.payload_bytes();
        assert_eq!(
            read_compact_bits(source, 63, 32).unwrap(),
            previous_cycle as u32
        );
        assert_eq!(
            read_compact_bits(source, 127, 32).unwrap(),
            previous_cycle as u32
        );
        assert_eq!(
            read_compact_bits(source, 191, 32).unwrap(),
            previous_cycle as u32
        );
    }

    #[test]
    fn i050_compact_source_rejects_out_of_range_inputs() {
        let step = record(GpuTypedLayout::R);
        let mut arena = GpuTypedSoaArena::new_with_mode(InsnKind::ADD, 1, 10, true).unwrap();
        assert_eq!(
            arena.push_step(9, &step),
            Err("compact ordinal precedes range")
        );
        let mut arena = GpuTypedSoaArena::new_with_mode(InsnKind::ADD, 1, 0, true).unwrap();
        assert_eq!(
            arena.push_step(1 << 18, &step),
            Err("compact ordinal exceeds range width")
        );
    }

    #[test]
    fn i017_field_major_packing_matches_cpu_reference_for_every_layout() {
        let cases = [
            (GpuTypedLayout::R, InsnKind::ADD),
            (GpuTypedLayout::I, InsnKind::ADDI),
            (GpuTypedLayout::Branch, InsnKind::BEQ),
            (GpuTypedLayout::Jal, InsnKind::JAL),
            (GpuTypedLayout::Jalr, InsnKind::JALR),
            (GpuTypedLayout::Load, InsnKind::LW),
            (GpuTypedLayout::Store, InsnKind::SW),
            #[cfg(feature = "u16limb_circuit")]
            (GpuTypedLayout::U, InsnKind::LUI),
        ];
        for (layout, kind) in cases {
            let step = record(layout);
            let expected = typed_words(layout, 19, &step);
            assert_eq!(expected.len(), layout.words());
            let mut arena = GpuTypedSoaArena::new(kind, 1).unwrap();
            arena.push_step(19, &step).unwrap();
            let packed: Vec<_> = arena.fields().iter().map(|field| field[0]).collect();
            assert_eq!(packed, expected, "layout {layout:?}");
            assert_eq!(packed[0], 19);
            assert_eq!(packed[1], 0x1000);
            assert_eq!(packed[2], step.insn().raw);
            assert_eq!(*packed.last().unwrap(), 0);
            if layout == GpuTypedLayout::Store {
                assert_eq!(packed[9], 0x55, "store memory before value");
                assert_eq!(packed[10], 0x66, "store memory after value");
            }
            if layout == GpuTypedLayout::U {
                assert_eq!(packed[3], previous_cycle_for_u(&step));
            }
        }
    }

    fn previous_cycle_for_u(step: &StepRecord) -> u32 {
        u32::try_from(step.rs1().expect("U-type implicit x0 read").previous_cycle).unwrap()
    }

    #[test]
    fn i017_exact_cursor_capacity_pointer_stability_and_determinism() {
        let step = record(GpuTypedLayout::R);
        let mut first = GpuTypedSoaArena::new(InsnKind::ADD, 2).unwrap();
        let pointers: Vec<_> = first.fields().iter().map(|field| field.as_ptr()).collect();
        first.push_step(3, &step).unwrap();
        first.push_step(4, &step).unwrap();
        assert_eq!(first.len(), first.capacity());
        assert_eq!(
            pointers,
            first
                .fields()
                .iter()
                .map(|field| field.as_ptr())
                .collect::<Vec<_>>()
        );
        assert_eq!(
            first.push_step(5, &step),
            Err("typed replay cursor exceeded exact capacity")
        );

        let mut second = GpuTypedSoaArena::new(InsnKind::ADD, 2).unwrap();
        second.push_step(3, &step).unwrap();
        second.push_step(4, &step).unwrap();
        assert_eq!(first.fields(), second.fields());
        assert!(GpuTypedSoaArena::new(InsnKind::INVALID, 1).is_none());
        assert!(GpuTypedSoaArena::new(InsnKind::ECALL, 1).is_none());
    }

    #[test]
    fn i017_descriptor_totals_and_conservative_address_bounds_fail_closed() {
        let mut descriptor = GpuReplayRangeDescriptor {
            shard_id: 0,
            sequence: 0,
            range_start: 0,
            range_len: 3,
            family_counts: [0; InsnKind::COUNT],
            fallback_count: 1,
            unsupported_count: 0,
        };
        descriptor.family_counts[InsnKind::ADD as usize] = 1;
        descriptor.family_counts[InsnKind::JAL as usize] = 1;
        assert_eq!(descriptor.checked_total(), Some(3));
        assert_eq!(
            descriptor.conservative_address_reservation(),
            Some(3 + 1 + MAX_SPARSE_ADDRESS_SENDS_PER_STEP)
        );

        descriptor.unsupported_count = 1;
        assert_eq!(descriptor.conservative_address_reservation(), None);
        descriptor.unsupported_count = 0;
        descriptor.family_counts[InsnKind::ADD as usize] = usize::MAX;
        assert_eq!(descriptor.checked_total(), None);
        assert_eq!(descriptor.conservative_address_reservation(), None);
        assert_eq!(CONTINUATION_ADDRESS_SEND_BOUND, 0);
        descriptor.family_counts[InsnKind::ADD as usize] = 1;
        assert_eq!(
            descriptor.fused_payload_bytes(true),
            Some(GpuTypedLayout::R.compact_bytes() + GpuTypedLayout::Jal.compact_bytes())
        );
        assert_eq!(descriptor.fused_work_items(), Some(2));
    }

    #[test]
    fn i061_l8_packed_source_is_default_with_explicit_soa_oracle_override() {
        assert!(compact_source_enabled_from(None));
        assert!(compact_source_enabled_from(Some(std::ffi::OsStr::new("1"))));
        assert!(!compact_source_enabled_from(Some(std::ffi::OsStr::new(
            "0"
        ))));
    }

    #[test]
    #[should_panic(expected = "CENO_I050_COMPACT_SOURCE must be 0 or 1")]
    fn i061_l8_invalid_compact_source_override_fails_closed() {
        compact_source_enabled_from(Some(std::ffi::OsStr::new("invalid")));
    }
}
