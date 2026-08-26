use super::*;

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
    pub(super) fn empty(sequence: u32, shard_start_cycle: Cycle) -> Self {
        Self {
            sequence,
            shard_start_cycle,
            // Ownership placeholder only. It must not allocate a replacement
            // family vector while both warmed owners are outside the tracer.
            typed: Vec::new(),
            fallback: Vec::new(),
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
    pub(super) current: GpuReplayChunk,
    sealed: Vec<GpuReplayChunk>,
    pub(super) recyclable: Option<GpuReplayChunk>,
    retain_complete_shard: bool,
    range_descriptors: Arc<Vec<crate::GpuReplayRangeDescriptor>>,
    pub(super) next_range_descriptor: usize,
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
            retain_complete_shard: false,
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
        let next_descriptor = self.range_descriptors.get(self.next_range_descriptor);
        let next = self.recyclable.take().map_or_else(
            || {
                next_descriptor
                    .filter(|next| self.retain_complete_shard && next.shard_id == shard_id)
                    .map_or_else(
                        || GpuReplayChunk::empty(sequence + 1, self.shard_start_cycle),
                        |descriptor| {
                            let mut next = GpuReplayChunk::warmed(
                                descriptor.family_counts,
                                descriptor.fallback_count,
                                self.shard_start_cycle,
                            );
                            next.reset_from_descriptor(descriptor, self.shard_start_cycle);
                            next
                        },
                    )
            },
            |mut next| {
                if let Some(descriptor) = next_descriptor.filter(|next| next.shard_id == shard_id) {
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

    /// Permit CPU replay to retain every range in one prepared shard while GPU
    /// assignment of that shard remains gated by the preceding proof.
    pub fn enable_retained_shard_mode(&mut self) {
        assert_eq!(
            self.ordinal, 0,
            "retained shard mode enabled after replay started"
        );
        self.retain_complete_shard = true;
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
            let next_descriptor = self.range_descriptors.get(self.next_range_descriptor);
            let current_shard_id = self
                .next_range_descriptor
                .checked_sub(1)
                .map(|index| self.range_descriptors[index].shard_id);
            if let Some(descriptor) = next_descriptor.filter(|descriptor| {
                self.retain_complete_shard || Some(descriptor.shard_id) == current_shard_id
            }) {
                recycled.reset_from_descriptor(descriptor, self.shard_start_cycle);
            } else {
                recycled.reset_empty(self.shard_start_cycle);
            }
            self.current = recycled;
        } else if self.recyclable.is_none() {
            self.recyclable = Some(recycled);
        } else {
            assert!(
                self.retain_complete_shard,
                "GPU replay range recycled twice"
            );
            // Retained mode may allocate one owner per range while a full
            // CPU-prepared shard waits for GPU assignment. Keep the two
            // globally warmed owners and release the extras after use.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retained_recycling_warms_first_owner_across_shards() {
        let mut counts = [0; InsnKind::COUNT];
        counts[InsnKind::ADDI as usize] = 1;
        let descriptors = Arc::new(vec![
            crate::GpuReplayRangeDescriptor {
                shard_id: 0,
                sequence: 0,
                range_start: 0,
                range_len: 1,
                family_counts: counts,
                fallback_count: 0,
                unsupported_count: 0,
            },
            crate::GpuReplayRangeDescriptor {
                shard_id: 1,
                sequence: 0,
                range_start: 1,
                range_len: 1,
                family_counts: counts,
                fallback_count: 0,
                unsupported_count: 0,
            },
        ]);
        let mut tracer = GpuReplayTracer::new(&CENO_PLATFORM, GpuReplayTracerConfig::default());
        tracer.install_range_descriptors(descriptors);
        tracer.enable_retained_shard_mode();

        let first = std::mem::replace(
            &mut tracer.current,
            GpuReplayChunk::empty(1, tracer.shard_start_cycle),
        );
        let second = tracer.recyclable.take().unwrap();
        tracer.next_range_descriptor = 1;
        tracer.recycle_range(crate::GpuReplayTypedRange {
            sequence: first.sequence,
            typed: first.typed,
            fallback: first.fallback,
        });
        tracer.recycle_range(crate::GpuReplayTypedRange {
            sequence: second.sequence,
            typed: second.typed,
            fallback: second.fallback,
        });

        tracer.start_shard();
        assert_eq!(tracer.current.sequence, 0);
        assert_eq!(tracer.current.typed.len(), InsnKind::COUNT);
        assert!(tracer.recyclable.is_some());
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
