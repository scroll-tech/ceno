use crate::{InsnKind, StepRecord, WordAddr};
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
}

impl Default for GpuTypedNativeKindState {
    fn default() -> Self {
        Self {
            fields: [std::ptr::null_mut(); GPU_TYPED_NATIVE_MAX_FIELDS],
            capacity: 0,
            cursor: 0,
            layout: u32::MAX,
            sentinel: GPU_TYPED_NATIVE_SENTINEL,
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
}

/// Exact field-major storage for one instruction kind in one replay range.
/// Every field owns a fixed boxed slice, so writes cannot grow or reallocate.
#[derive(Debug)]
pub struct GpuTypedSoaArena {
    kind: InsnKind,
    layout: GpuTypedLayout,
    fields: Vec<Box<[u32]>>,
    len: usize,
}

impl GpuTypedSoaArena {
    pub fn new(kind: InsnKind, rows: usize) -> Option<Self> {
        let layout = gpu_typed_kind_spec(kind)?.layout;
        let fields = (0..layout.words())
            .map(|_| vec![0u32; rows].into_boxed_slice())
            .collect();
        Some(Self {
            kind,
            layout,
            fields,
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
        self.fields.first().map_or(0, |field| field.len())
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn fields(&self) -> &[Box<[u32]>] {
        &self.fields
    }

    pub(crate) fn patch_future_access(
        &mut self,
        ordinal: u32,
        mask: u8,
    ) -> Result<bool, &'static str> {
        let ordinals = &self.fields[0][..self.len];
        let Ok(row) = ordinals.binary_search(&ordinal) else {
            return Ok(false);
        };
        let mask_field = self
            .fields
            .last_mut()
            .ok_or("typed replay arena has no future-access field")?;
        mask_field[row] |= u32::from(mask) << 8;
        Ok(true)
    }

    pub(crate) fn patch_future_access_checked(
        &mut self,
        ordinal: u32,
        mask: u8,
        address: WordAddr,
    ) -> Result<Option<u32>, &'static str> {
        let ordinals = &self.fields[0][..self.len];
        let Ok(row) = ordinals.binary_search(&ordinal) else {
            return Ok(None);
        };
        let raw = self.fields[2][row];
        let (expected_address, prior_value) = match (self.layout, mask) {
            (GpuTypedLayout::R, StepRecord::FUTURE_ACCESS_RS1)
            | (GpuTypedLayout::I, StepRecord::FUTURE_ACCESS_RS1)
            | (GpuTypedLayout::Load, StepRecord::FUTURE_ACCESS_RS1) => {
                (WordAddr(((raw >> 15) & 31) << 6), self.fields[4][row])
            }
            (GpuTypedLayout::Branch, StepRecord::FUTURE_ACCESS_RS1)
            | (GpuTypedLayout::Jalr, StepRecord::FUTURE_ACCESS_RS1) => {
                (WordAddr(((raw >> 15) & 31) << 6), self.fields[5][row])
            }
            (GpuTypedLayout::Store, StepRecord::FUTURE_ACCESS_RS1) => {
                (WordAddr(((raw >> 15) & 31) << 6), self.fields[4][row])
            }
            (GpuTypedLayout::U, StepRecord::FUTURE_ACCESS_RS1) => (WordAddr(0), 0),
            (GpuTypedLayout::R, StepRecord::FUTURE_ACCESS_RS2) => {
                (WordAddr(((raw >> 20) & 31) << 6), self.fields[6][row])
            }
            (GpuTypedLayout::Branch, StepRecord::FUTURE_ACCESS_RS2) => {
                (WordAddr(((raw >> 20) & 31) << 6), self.fields[7][row])
            }
            (GpuTypedLayout::Store, StepRecord::FUTURE_ACCESS_RS2) => {
                (WordAddr(((raw >> 20) & 31) << 6), self.fields[6][row])
            }
            (GpuTypedLayout::R, StepRecord::FUTURE_ACCESS_RD) => {
                (WordAddr(((raw >> 7) & 31) << 6), self.fields[9][row])
            }
            (GpuTypedLayout::I, StepRecord::FUTURE_ACCESS_RD)
            | (GpuTypedLayout::Load, StepRecord::FUTURE_ACCESS_RD) => {
                (WordAddr(((raw >> 7) & 31) << 6), self.fields[7][row])
            }
            (GpuTypedLayout::Jal, StepRecord::FUTURE_ACCESS_RD)
            | (GpuTypedLayout::U, StepRecord::FUTURE_ACCESS_RD) => {
                (WordAddr(((raw >> 7) & 31) << 6), self.fields[6][row])
            }
            (GpuTypedLayout::Jalr, StepRecord::FUTURE_ACCESS_RD) => {
                (WordAddr(((raw >> 7) & 31) << 6), self.fields[8][row])
            }
            (GpuTypedLayout::Load, StepRecord::FUTURE_ACCESS_MEM) => {
                (WordAddr(self.fields[9][row]), self.fields[11][row])
            }
            (GpuTypedLayout::Store, StepRecord::FUTURE_ACCESS_MEM) => {
                (WordAddr(self.fields[8][row]), self.fields[10][row])
            }
            _ => return Err("deferred patch lane is invalid for typed layout"),
        };
        // Unit-constructed `Instruction`s intentionally carry raw=0. Real
        // decoded guest instructions carry the raw word used to validate
        // register addresses; memory addresses are explicit in every layout.
        if expected_address != address
            && (raw != 0 || mask == StepRecord::FUTURE_ACCESS_MEM)
        {
            return Err("deferred patch address does not match typed source row");
        }
        let mask_field = self
            .fields
            .last_mut()
            .ok_or("typed replay arena has no future-access field")?;
        mask_field[row] |= u32::from(mask) << 8;
        Ok(Some(prior_value))
    }

    pub(crate) fn drain_prefix(&mut self, rows: usize) -> Result<Self, &'static str> {
        if rows > self.len {
            return Err("typed replay drain exceeds populated rows");
        }
        let mut exact = Self::new(self.kind, rows).ok_or("typed replay kind has no layout")?;
        for (dst, src) in exact.fields.iter_mut().zip(&mut self.fields) {
            dst.copy_from_slice(&src[..rows]);
            src.copy_within(rows..self.len, 0);
        }
        exact.len = rows;
        self.len -= rows;
        Ok(exact)
    }

    pub(crate) fn native_state(&mut self) -> GpuTypedNativeKindState {
        let mut state = GpuTypedNativeKindState {
            capacity: u32::try_from(self.capacity()).expect("typed replay capacity exceeds u32"),
            cursor: u32::try_from(self.len).expect("typed replay cursor exceeds u32"),
            layout: self.layout as u32,
            ..GpuTypedNativeKindState::default()
        };
        for (dst, field) in state.fields.iter_mut().zip(&mut self.fields) {
            *dst = field.as_mut_ptr();
        }
        state
    }

    pub(crate) fn sync_native_state(
        &mut self,
        state: &GpuTypedNativeKindState,
    ) -> Result<(), &'static str> {
        if state.sentinel != GPU_TYPED_NATIVE_SENTINEL {
            return Err("typed replay native sentinel mismatch");
        }
        if state.layout != self.layout as u32 {
            return Err("typed replay native layout mismatch");
        }
        if state.capacity as usize != self.capacity() || state.cursor > state.capacity {
            return Err("typed replay native cursor/capacity mismatch");
        }
        for (pointer, field) in state.fields.iter().zip(&self.fields) {
            if *pointer != field.as_ptr().cast_mut() {
                return Err("typed replay native field pointer changed");
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
    fn i049_combined_capture_drains_prefix_and_patches_by_ordinal() {
        let mut arena = GpuTypedSoaArena::new(InsnKind::ADD, 3).unwrap();
        let step = record(GpuTypedLayout::R);
        arena.push_step(4, &step).unwrap();
        arena.push_step(9, &step).unwrap();
        arena.push_step(12, &step).unwrap();

        let mut first = arena.drain_prefix(2).unwrap();
        assert_eq!(first.fields()[0].as_ref(), &[4, 9]);
        assert_eq!(&arena.fields()[0][..arena.len()], &[12]);
        assert!(first
            .patch_future_access(9, StepRecord::FUTURE_ACCESS_RD)
            .unwrap());
        assert!(!first
            .patch_future_access(12, StepRecord::FUTURE_ACCESS_RD)
            .unwrap());
        assert_eq!(
            first.fields().last().unwrap()[1],
            u32::from(StepRecord::FUTURE_ACCESS_RD) << 8
        );
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
    }
}
