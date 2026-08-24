//! Rust callbacks entered by generated AOT code for fallback and trace state.

use super::*;

#[inline(always)]
pub(super) unsafe extern "C" fn aot_exec_one<T: Tracer>(
    context: *mut c_void,
    pc: u32,
    next_pc: *mut u32,
) -> u32 {
    aot_native_callback_event(&AOT_NATIVE_CALLBACK_FALLBACK, "fallback");
    let fallback_started = Instant::now();
    let context = unsafe { &mut *(context as *mut AotRuntimeContext) };
    if context.trace_mode == AOT_TRACE_MODE_GPU_REPLAY_DIRECT {
        let replay_vm = unsafe { &mut *(context.vm as *mut VMState<crate::GpuReplayTracer>) };
        if let Err(message) = replay_vm.tracer_mut().sync_native_range() {
            LAST_AOT_ERROR.with(|slot| *slot.borrow_mut() = Some(anyhow!(message)));
            return AOT_STATUS_ERROR;
        }
        if !matches!(
            context.fallback_reason,
            AOT_FALLBACK_ECALL | AOT_FALLBACK_EXCEPTIONAL
        ) {
            LAST_AOT_ERROR.with(|slot| {
                *slot.borrow_mut() = Some(anyhow!(
                    "GPU_REPLAY_DIRECT rejected fallback category {}",
                    context.fallback_reason
                ))
            });
            return AOT_STATUS_ERROR;
        }
    }
    let vm = unsafe { &mut *(context.vm as *mut VMState<T>) };
    context.fallback_steps += 1;
    let reason = if context.fallback_reason == AOT_FALLBACK_DYNAMIC_PC
        && context.fallback_recovery_reason != 0
    {
        context.fallback_recovery_reason
    } else {
        context.fallback_reason
    };
    if reason != AOT_FALLBACK_DYNAMIC_PC {
        context.fallback_recovery_reason = reason;
    }
    match reason {
        AOT_FALLBACK_DYNAMIC_PC => context.fallback_dynamic_pc += 1,
        AOT_FALLBACK_MEMORY_GUARD => context.fallback_memory_guard += 1,
        AOT_FALLBACK_ECALL => {
            context.fallback_ecall += 1;
            let code = vm.peek_register(Platform::reg_ecall());
            unsafe { &mut *context.fallback_ecall_codes }
                .entry(code)
                .and_modify(|count| *count += 1)
                .or_insert(1);
        }
        AOT_FALLBACK_EXCEPTIONAL => context.fallback_exceptional += 1,
        other => {
            LAST_AOT_ERROR.with(|slot| {
                *slot.borrow_mut() = Some(anyhow!("unknown AOT fallback reason {other}"))
            });
            context.fallback_time_ns = context
                .fallback_time_ns
                .saturating_add(fallback_started.elapsed().as_nanos() as u64);
            return AOT_STATUS_ERROR;
        }
    }
    if vm.halted() {
        unsafe {
            *next_pc = vm.get_pc().0;
        }
        context.fallback_time_ns = context
            .fallback_time_ns
            .saturating_add(fallback_started.elapsed().as_nanos() as u64);
        return AOT_STATUS_HALTED;
    }

    let pc = ByteAddr(pc);
    vm.set_pc(pc);
    let result = (|| -> Result<()> {
        let Some(insn) = vm.fetch(pc.waddr()) else {
            vm.trap(TrapCause::InstructionAccessFault)?;
            bail!(
                "Fatal: could not fetch instruction at pc={pc:?}, ELF does not have instructions there."
            );
        };
        crate::rv32im::step_fetched(vm, &insn)?;
        let step = vm.tracer_mut().advance();
        if vm.tracer().is_busy_loop(&step) && !vm.halted() {
            bail!("Stuck in loop {}", "{}");
        }
        Ok(())
    })();

    if matches!(
        context.trace_mode,
        AOT_TRACE_MODE_PREFLIGHT_DIRECT | AOT_TRACE_MODE_PREFLIGHT_CAPTURE_DIRECT
    ) {
        let preflight_vm = unsafe { &mut *(context.vm as *mut VMState<PreflightTracer>) };
        (context.preflight_event_cursor, context.preflight_event_end) =
            preflight_vm.tracer_mut().native_next_access_ptrs();
        let shard_start = unsafe { *context.preflight_current_shard_start };
        if shard_start != context.preflight_register_shard_start {
            context.preflight_register_touched_mask = 0;
            context.preflight_register_shard_start = shard_start;
            context.preflight_memory_shard_start_ordinal = shard_start >> 2;
        }
    }

    let status = match result {
        Ok(()) => {
            unsafe {
                *next_pc = vm.get_pc().0;
            }
            if vm.halted() {
                AOT_STATUS_HALTED
            } else {
                AOT_STATUS_CONTINUE
            }
        }
        Err(err) => {
            unsafe {
                *next_pc = vm.get_pc().0;
            }
            LAST_AOT_ERROR.with(|slot| *slot.borrow_mut() = Some(err));
            AOT_STATUS_ERROR
        }
    };
    if context.trace_mode == AOT_TRACE_MODE_GPU_REPLAY_DIRECT && status != AOT_STATUS_ERROR {
        let replay_vm = unsafe { &mut *(context.vm as *mut VMState<crate::GpuReplayTracer>) };
        let state = replay_vm.tracer_mut().prepare_native_range();
        context.gpu_replay_kinds = state.kinds;
        context.gpu_replay_kind_count = state.kind_count;
        context.gpu_replay_ordinal = state.ordinal;
        context.gpu_replay_pending_cycle = state.pending_cycle;
        context.gpu_replay_latest_cells = state.latest_cells;
        context.gpu_replay_latest_base = state.latest_base.0;
        context.gpu_replay_latest_len = state.latest_len;
        context.gpu_replay_max_heap = state.max_heap_addr_access;
        context.gpu_replay_max_hint = state.max_hint_addr_access;
        context.gpu_replay_events = state.next_access_events;
        context.gpu_replay_events_len = state.next_access_len;
        context.gpu_replay_event_cursor = state.next_access_cursor;
        context.gpu_replay_error = state.error;
    }
    context.fallback_time_ns = context
        .fallback_time_ns
        .saturating_add(fallback_started.elapsed().as_nanos() as u64);
    status
}

/// Stable symbol for benchmark-only, value-only Pure AOT syscalls.
#[unsafe(no_mangle)]
#[inline(never)]
pub(super) unsafe extern "C" fn ceno_aot_pure_ecall_callback(
    raw_context: *mut c_void,
    pc: u32,
    next_pc: *mut u32,
) -> u32 {
    let fallback_started = Instant::now();
    let context = unsafe { &mut *(raw_context as *mut AotRuntimeContext) };
    if context.fallback_reason == AOT_FALLBACK_ECALL
        && !matches!(
            context.trace_mode,
            AOT_TRACE_MODE_COMPACT_EXCEPTIONAL_L6C | AOT_TRACE_MODE_COMPACT_CLOSURE_L7
        )
    {
        let code = unsafe { *context.registers.add(Platform::reg_ecall() as usize) };
        let arg0 = unsafe { *context.registers.add(Platform::reg_arg0() as usize) };
        let arg1 = unsafe { *context.registers.add(Platform::reg_arg1() as usize) };
        if let Some(index) = pure_ecall_index(code) {
            if unsafe {
                crate::syscalls::pure::execute(
                    code,
                    context.registers,
                    context.memory_cells,
                    context.memory_base_word,
                    context.memory_end_word,
                    context.pure_double_cache,
                )
            } {
                if matches!(
                    context.trace_mode,
                    AOT_TRACE_MODE_FUTURE_ACCESS_L5 | AOT_TRACE_MODE_COMPACT_FUTURE_ACCESS_L5C
                ) {
                    let (registers, memory) =
                        crate::syscalls::pure::future_access_addresses(code, arg0, arg1)
                            .expect("successful pure syscall must have an L5 access description");
                    let vm = unsafe { &mut *(context.vm as *mut VMState<PureAotTracer>) };
                    vm.tracer_mut()
                        .record_layered_syscall_addresses(registers, memory);
                }
                context.fallback_steps += 1;
                context.fallback_ecall += 1;
                unsafe {
                    (*context.pure_ecall_counts)[index] += 1;
                    *next_pc = pc.wrapping_add(PC_STEP_SIZE as u32);
                }
                context.fallback_time_ns = context
                    .fallback_time_ns
                    .saturating_add(fallback_started.elapsed().as_nanos() as u64);
                return AOT_STATUS_CONTINUE;
            }
        }
    }
    unsafe { aot_exec_one::<PureAotTracer>(raw_context, pc, next_pc) }
}

pub(super) fn layered_memory_value(context: &AotRuntimeContext, addr: WordAddr) -> Option<Word> {
    addr.0
        .checked_sub(context.memory_base_word)
        .filter(|_| addr.0 < context.memory_end_word)
        .map(|index| unsafe { *context.memory_cells.add(index as usize) as u32 })
}

pub(super) fn layered_memory_previous_cycle(
    context: &AotRuntimeContext,
    addr: WordAddr,
) -> Option<Cycle> {
    addr.0
        .checked_sub(context.memory_base_word)
        .filter(|_| addr.0 < context.memory_end_word)
        .map(|index| unsafe { *context.memory_cells.add(index as usize) })
        .map(|cell| crate::dense_addr_space::PackedMemory::decode_stamp((cell >> 32) as u32))
}

unsafe fn write_compact_values_fallback(
    context: &mut AotRuntimeContext,
    cursor: usize,
    pc: u32,
    pc_after: u32,
    insn: Instruction,
    memory_addr: Option<WordAddr>,
    rs1: Word,
    rs2: Word,
    rd_before: Word,
    memory_before: Option<Word>,
) {
    let byte_cursor = unsafe { *context.compact_bytes_cursor };
    let mut destination = unsafe {
        context
            .fulltracer_records
            .cast::<u8>()
            .add(byte_cursor)
            .cast::<u32>()
    };
    let mut write = |value: u32| unsafe {
        destination.write_unaligned(value);
        destination = destination.add(1);
    };
    write(u32::try_from(cursor).expect("L2C ordinal exceeds u32"));
    write(pc);
    write(pc_after);
    write(memory_addr.map_or(COMPACT_SKELETON_NO_MEMORY, |addr| addr.0));
    if native_step_reads_rs1(insn.kind) {
        write(rs1);
    }
    if native_step_reads_rs2(insn.kind) {
        write(rs2);
    }
    if native_step_writes_rd(insn.kind) {
        write(rd_before);
    }
    if native_step_loads_memory(insn.kind) || native_step_stores_memory(insn.kind) {
        write(memory_before.expect("L2C memory row has no before value"));
    }
    unsafe {
        *context.compact_bytes_cursor = byte_cursor + compact_values_row_size(insn);
    }
}

pub(super) struct CompactRegistersPacker {
    chunks: [u64; 4],
    bit: usize,
}

impl CompactRegistersPacker {
    fn new() -> Self {
        Self {
            chunks: [0; 4],
            bit: 0,
        }
    }

    fn push(&mut self, value: u32, width: usize) {
        debug_assert!(width <= 32);
        debug_assert!(width == 32 || u64::from(value) < 1u64 << width);
        let chunk = self.bit / 64;
        let shift = self.bit % 64;
        self.chunks[chunk] |= u64::from(value) << shift;
        if shift + width > 64 {
            self.chunks[chunk + 1] |= u64::from(value) >> (64 - shift);
        }
        self.bit += width;
    }

    unsafe fn commit(self, destination: *mut u8, byte_len: usize) {
        debug_assert_eq!(self.bit.div_ceil(8), byte_len);
        let mut offset = 0;
        for chunk in self.chunks.iter().take(byte_len / 8) {
            unsafe {
                destination
                    .add(offset)
                    .cast::<u64>()
                    .write_unaligned(*chunk)
            };
            offset += 8;
        }
        let remainder = byte_len - offset;
        let tail = self.chunks[byte_len / 8];
        if remainder >= 4 {
            unsafe {
                destination
                    .add(offset)
                    .cast::<u32>()
                    .write_unaligned(tail as u32)
            };
            offset += 4;
        }
        if remainder & 2 != 0 {
            unsafe {
                destination
                    .add(offset)
                    .cast::<u16>()
                    .write_unaligned((tail >> (offset % 8 * 8)) as u16)
            };
            offset += 2;
        }
        if remainder & 1 != 0 {
            unsafe {
                destination
                    .add(offset)
                    .write((tail >> (offset % 8 * 8)) as u8)
            };
        }
    }
}

unsafe fn write_compact_registers_fallback(
    context: &mut AotRuntimeContext,
    pc: u32,
    pc_after: u32,
    insn: Instruction,
    rs1: Word,
    rs2: Word,
    rd_before: Word,
    memory_before: Option<Word>,
    register_previous: [Cycle; 3],
    memory_previous: Option<Cycle>,
) -> Result<()> {
    let future_l5 = matches!(
        context.trace_mode,
        AOT_TRACE_MODE_COMPACT_FUTURE_ACCESS_L5C
            | AOT_TRACE_MODE_COMPACT_EXCEPTIONAL_L6C
            | AOT_TRACE_MODE_COMPACT_CLOSURE_L7
    );
    let memory_l4 = context.trace_mode == AOT_TRACE_MODE_COMPACT_MEMORY_L4C || future_l5;
    let pc_offset = pc
        .checked_sub(context.program_base)
        .filter(|offset| offset % PC_STEP_SIZE as u32 == 0)
        .map(|offset| offset / PC_STEP_SIZE as u32)
        .filter(|offset| *offset < 1 << COMPACT_REGISTERS_PC_BITS)
        .ok_or_else(|| anyhow!("L3C PC exceeds aligned 20-bit program window"))?;
    for (enabled, previous) in [
        native_step_reads_rs1(insn.kind),
        native_step_reads_rs2(insn.kind),
        native_step_writes_rd(insn.kind),
    ]
    .into_iter()
    .zip(register_previous)
    {
        if enabled && previous >= 1 << COMPACT_REGISTERS_CYCLE_BITS {
            bail!("L3C predecessor cycle exceeds 27-bit compact width");
        }
    }
    if memory_l4
        && memory_previous.is_some_and(|previous| previous >= 1 << COMPACT_REGISTERS_CYCLE_BITS)
    {
        bail!("L4C memory predecessor cycle exceeds 27-bit compact width");
    }
    let mut packer = CompactRegistersPacker::new();
    packer.push(pc_offset, COMPACT_REGISTERS_PC_BITS);
    packer.push(insn.raw >> 7, COMPACT_REGISTERS_RAW_BITS);
    for (enabled, previous, value) in [
        (native_step_reads_rs1(insn.kind), register_previous[0], rs1),
        (native_step_reads_rs2(insn.kind), register_previous[1], rs2),
        (
            native_step_writes_rd(insn.kind),
            register_previous[2],
            rd_before,
        ),
    ] {
        if enabled {
            packer.push(previous as u32, COMPACT_REGISTERS_CYCLE_BITS);
            packer.push(value, 32);
        }
    }
    if native_step_loads_memory(insn.kind) || native_step_stores_memory(insn.kind) {
        packer.push(
            memory_before.ok_or_else(|| anyhow!("L3C memory row has no before value"))?,
            32,
        );
        if memory_l4 {
            packer.push(
                memory_previous.expect("L4C memory row has no predecessor") as u32,
                COMPACT_REGISTERS_CYCLE_BITS,
            );
        }
    }
    if insn.kind == InsnKind::ECALL {
        packer.push(pc_after, 32);
        if memory_l4 {
            packer.push(unsafe { (*context.fulltracer_max_heap).0 }, 32);
            packer.push(unsafe { (*context.fulltracer_max_hint).0 }, 32);
        }
    }
    if future_l5 {
        let cycle = unsafe { *context.fulltracer_pending_cycle };
        let mut accesses = [(0, WordAddr(0), 0); 4];
        let mut access_count = 0;
        if native_step_reads_rs1(insn.kind) {
            accesses[access_count] = (
                crate::FullTracer::SUBCYCLE_RS1,
                Platform::register_vma(insn.rs1).into(),
                crate::StepRecord::FUTURE_ACCESS_RS1,
            );
            access_count += 1;
        }
        if native_step_reads_rs2(insn.kind) {
            accesses[access_count] = (
                crate::FullTracer::SUBCYCLE_RS2,
                Platform::register_vma(insn.rs2).into(),
                crate::StepRecord::FUTURE_ACCESS_RS2,
            );
            access_count += 1;
        }
        if native_step_writes_rd(insn.kind) {
            accesses[access_count] = (
                crate::FullTracer::SUBCYCLE_RD,
                Platform::register_vma(insn.rd_internal() as RegIdx).into(),
                crate::StepRecord::FUTURE_ACCESS_RD,
            );
            access_count += 1;
        }
        if let Some(address) = (native_step_loads_memory(insn.kind)
            || native_step_stores_memory(insn.kind))
        .then(|| ByteAddr(rs1.wrapping_add(insn.imm as u32)).waddr())
        {
            accesses[access_count] = (
                crate::FullTracer::SUBCYCLE_MEM,
                address,
                crate::StepRecord::FUTURE_ACCESS_MEM,
            );
            access_count += 1;
        }
        let vm = unsafe { &mut *(context.vm as *mut VMState<PureAotTracer>) };
        let mask = vm
            .tracer_mut()
            .consume_compact_row_future_accesses(cycle, &accesses[..access_count]);
        for (enabled, bit) in [
            (
                native_step_reads_rs1(insn.kind),
                crate::StepRecord::FUTURE_ACCESS_RS1,
            ),
            (
                native_step_reads_rs2(insn.kind),
                crate::StepRecord::FUTURE_ACCESS_RS2,
            ),
            (
                native_step_writes_rd(insn.kind),
                crate::StepRecord::FUTURE_ACCESS_RD,
            ),
            (
                native_step_loads_memory(insn.kind) || native_step_stores_memory(insn.kind),
                crate::StepRecord::FUTURE_ACCESS_MEM,
            ),
        ] {
            if enabled {
                packer.push(u32::from(mask & bit != 0), 1);
            }
        }
    }
    let byte_cursor = unsafe { *context.compact_bytes_cursor };
    let row_size = if future_l5 {
        compact_future_access_row_size(insn)
    } else if memory_l4 {
        compact_memory_row_size(insn)
    } else {
        compact_registers_row_size(insn)
    };
    unsafe {
        packer.commit(
            context.fulltracer_records.cast::<u8>().add(byte_cursor),
            row_size,
        );
        *context.compact_bytes_cursor = byte_cursor + row_size;
    }
    Ok(())
}

/// Scalar L7 ordinary fallback writes the retained GPU packed-AoS family
/// directly. Admission is a one-row transaction: validate first, pack into the
/// unpublished row, and publish the family cursor only after the final store.
unsafe fn write_l7_compact_fallback(
    context: &mut AotRuntimeContext,
    pc: u32,
    insn: Instruction,
    rs1: Word,
    rs2: Word,
    rd_before: Word,
    memory_before: Option<Word>,
    memory_previous: Option<Cycle>,
) -> Result<()> {
    let spec = crate::gpu_typed_kind_spec(insn.kind)
        .ok_or_else(|| anyhow!("L7 scalar ordinary kind has no compact family"))?;
    let kind_index = insn.kind as usize;
    if context.gpu_replay_kinds.is_null() || kind_index >= context.gpu_replay_kind_count {
        bail!("L7 scalar compact family is absent");
    }
    let state = unsafe { &mut *context.gpu_replay_kinds.add(kind_index) };
    if state.sentinel != crate::gpu_typed_ingress::GPU_COMPACT_NATIVE_SENTINEL
        || state.layout != spec.layout as u32
        || state.fields[0].is_null()
    {
        bail!("L7 scalar compact family state mismatch");
    }
    let row = state.cursor;
    if row >= state.capacity {
        bail!("L7 scalar compact family capacity exceeded");
    }
    let ordinal = unsafe { *context.gpu_replay_ordinal };
    let local_ordinal = u32::try_from(ordinal)?
        .checked_sub(state.range_start)
        .filter(|ordinal| *ordinal < 1 << 18)
        .ok_or_else(|| anyhow!("L7 scalar compact ordinal exceeds range"))?;
    if state.pc_base == 0 {
        state.pc_base = pc & !((1 << 22) - 1);
    }
    let pc_offset = pc
        .checked_sub(state.pc_base)
        .filter(|offset| offset & 3 == 0 && offset >> 2 < 1 << 20)
        .map(|offset| offset >> 2)
        .ok_or_else(|| anyhow!("L7 scalar compact PC exceeds aligned window"))?;
    let cycle = unsafe { *context.gpu_replay_pending_cycle };
    let latest = context.gpu_replay_latest_cells;
    let access = |reg: RegIdx, subcycle: Cycle, value: Word| -> Result<(u32, Word)> {
        // L7 borrows PureAotTracer's dense 32-register predecessor array, not
        // GpuReplayTracer's address-indexed latest-cell domain.
        let index = reg as usize;
        let cell = unsafe { latest.add(index) };
        let previous = unsafe { *cell };
        if previous == 0 {
            unsafe { *context.gpu_replay_latest_len += 1 };
        }
        unsafe { *cell = cycle + subcycle };
        Ok((u32::try_from(previous)?, value))
    };
    let rs1_access = native_step_reads_rs1(insn.kind)
        .then(|| access(insn.rs1, crate::FullTracer::SUBCYCLE_RS1, rs1))
        .transpose()?;
    let rs2_access = native_step_reads_rs2(insn.kind)
        .then(|| access(insn.rs2, crate::FullTracer::SUBCYCLE_RS2, rs2))
        .transpose()?;
    let rd_access = native_step_writes_rd(insn.kind)
        .then(|| {
            access(
                insn.rd_internal() as RegIdx,
                crate::FullTracer::SUBCYCLE_RD,
                rd_before,
            )
        })
        .transpose()?;

    let mut accesses = [(0, WordAddr(0), 0); 4];
    let mut access_count = 0;
    for (enabled, subcycle, address, bit) in [
        (
            native_step_reads_rs1(insn.kind),
            crate::FullTracer::SUBCYCLE_RS1,
            Platform::register_vma(insn.rs1).into(),
            crate::StepRecord::FUTURE_ACCESS_RS1,
        ),
        (
            native_step_reads_rs2(insn.kind),
            crate::FullTracer::SUBCYCLE_RS2,
            Platform::register_vma(insn.rs2).into(),
            crate::StepRecord::FUTURE_ACCESS_RS2,
        ),
        (
            native_step_writes_rd(insn.kind),
            crate::FullTracer::SUBCYCLE_RD,
            Platform::register_vma(insn.rd_internal() as RegIdx).into(),
            crate::StepRecord::FUTURE_ACCESS_RD,
        ),
    ] {
        if enabled {
            accesses[access_count] = (subcycle, address, bit);
            access_count += 1;
        }
    }
    if native_step_loads_memory(insn.kind) || native_step_stores_memory(insn.kind) {
        accesses[access_count] = (
            crate::FullTracer::SUBCYCLE_MEM,
            ByteAddr(rs1.wrapping_add(insn.imm as u32)).waddr(),
            crate::StepRecord::FUTURE_ACCESS_MEM,
        );
        access_count += 1;
    }
    let vm = unsafe { &mut *(context.vm as *mut VMState<PureAotTracer>) };
    let mask = vm
        .tracer_mut()
        .consume_compact_row_future_accesses(cycle, &accesses[..access_count]);

    let mut packer = CompactRegistersPacker::new();
    packer.push(local_ordinal, 18);
    packer.push(pc_offset, 20);
    packer.push(insn.raw >> 7, 25);
    let push_access = |packer: &mut CompactRegistersPacker, access: (u32, Word)| {
        packer.push(access.0, 27);
        packer.push(access.1, 32);
    };
    match spec.layout {
        crate::gpu_typed_ingress::GpuTypedLayout::R => {
            push_access(&mut packer, rs1_access.unwrap());
            push_access(&mut packer, rs2_access.unwrap());
            push_access(&mut packer, rd_access.unwrap());
        }
        crate::gpu_typed_ingress::GpuTypedLayout::I
        | crate::gpu_typed_ingress::GpuTypedLayout::Jalr => {
            push_access(&mut packer, rs1_access.unwrap());
            push_access(&mut packer, rd_access.unwrap());
        }
        crate::gpu_typed_ingress::GpuTypedLayout::Branch => {
            push_access(&mut packer, rs1_access.unwrap());
            push_access(&mut packer, rs2_access.unwrap());
        }
        crate::gpu_typed_ingress::GpuTypedLayout::Jal => {
            push_access(&mut packer, rd_access.unwrap())
        }
        crate::gpu_typed_ingress::GpuTypedLayout::Load => {
            push_access(&mut packer, rs1_access.unwrap());
            push_access(&mut packer, rd_access.unwrap());
            push_access(
                &mut packer,
                (
                    u32::try_from(memory_previous.expect("L7 load predecessor"))?,
                    memory_before.expect("L7 load value"),
                ),
            );
        }
        crate::gpu_typed_ingress::GpuTypedLayout::Store => {
            push_access(&mut packer, rs1_access.unwrap());
            push_access(&mut packer, rs2_access.unwrap());
            push_access(
                &mut packer,
                (
                    u32::try_from(memory_previous.expect("L7 store predecessor"))?,
                    memory_before.expect("L7 store value"),
                ),
            );
        }
        crate::gpu_typed_ingress::GpuTypedLayout::U => {
            // The retained typed oracle represents U-family's implicit x0
            // lane as cycle-only, without an accompanying value lane.
            packer.push(rs1_access.expect("L7 U implicit x0 access").0, 27);
            push_access(&mut packer, rd_access.unwrap());
        }
    }
    packer.push(u32::from(mask), 4);
    let stride = spec.layout.compact_bytes();
    unsafe {
        packer.commit(
            state.fields[0].cast::<u8>().add(row as usize * stride),
            stride,
        );
    }
    state.cursor = row + 1;
    Ok(())
}

/// Private layered fallback: execute with the L0 value lane, then publish the
/// completed step's fields into the pre-reserved generic buffer.
#[unsafe(no_mangle)]
#[inline(never)]
pub(super) unsafe extern "C" fn ceno_aot_skeleton_l1_callback(
    raw_context: *mut c_void,
    pc: u32,
    next_pc: *mut u32,
) -> u32 {
    let context = unsafe { &mut *(raw_context as *mut AotRuntimeContext) };
    let insn_index = pc.wrapping_sub(context.program_base) as usize / PC_STEP_SIZE;
    let insn = unsafe { *context.instructions.add(insn_index) };
    let rs1_value = unsafe { *context.registers.add(insn.rs1 as usize) };
    let rs2_value = unsafe { *context.registers.add(insn.rs2 as usize) };
    let rd = insn.rd_internal() as usize;
    let rd_before = unsafe { *context.registers.add(rd) };
    let memory_addr = (native_step_loads_memory(insn.kind) || native_step_stores_memory(insn.kind))
        .then(|| ByteAddr(rs1_value.wrapping_add(insn.imm as u32)).waddr());
    let memory_before = memory_addr.and_then(|addr| layered_memory_value(context, addr));
    let layered_memory = matches!(
        context.trace_mode,
        AOT_TRACE_MODE_COMPACT_MEMORY_L4C
            | AOT_TRACE_MODE_COMPACT_FUTURE_ACCESS_L5C
            | AOT_TRACE_MODE_COMPACT_EXCEPTIONAL_L6C
            | AOT_TRACE_MODE_COMPACT_CLOSURE_L7
            | AOT_TRACE_MODE_MEMORY_L4
            | AOT_TRACE_MODE_FUTURE_ACCESS_L5
    );
    let memory_previous_cycle = if layered_memory {
        memory_addr.and_then(|addr| layered_memory_previous_cycle(context, addr))
    } else {
        None
    };
    let bounds_before = if layered_memory {
        Some(unsafe { (*context.fulltracer_max_heap, *context.fulltracer_max_hint) })
    } else {
        None
    };
    let status = unsafe { ceno_aot_pure_ecall_callback(raw_context, pc, next_pc) };
    if status != AOT_STATUS_ERROR {
        let cursor = unsafe { *context.fulltracer_pending_index };
        let cycle = unsafe { *context.fulltracer_pending_cycle };
        if matches!(
            context.trace_mode,
            AOT_TRACE_MODE_COMPACT_EXCEPTIONAL_L6C | AOT_TRACE_MODE_COMPACT_CLOSURE_L7
        ) && insn.kind == InsnKind::ECALL
        {
            let vm = unsafe { &mut *(context.vm as *mut VMState<PureAotTracer>) };
            vm.tracer_mut().finish_compact_l6_ecall();
        }
        if context.trace_mode == AOT_TRACE_MODE_COMPACT_CLOSURE_L7 && insn.kind != InsnKind::ECALL {
            if let Err(err) = unsafe {
                write_l7_compact_fallback(
                    context,
                    pc,
                    insn,
                    rs1_value,
                    rs2_value,
                    rd_before,
                    memory_before,
                    memory_previous_cycle,
                )
            } {
                LAST_AOT_ERROR.with(|slot| *slot.borrow_mut() = Some(err));
                return AOT_STATUS_ERROR;
            }
            unsafe {
                *context.fulltracer_pending_index = cursor + 1;
                *context.fulltracer_pending_cycle = cycle + crate::FullTracer::SUBCYCLES_PER_INSN;
                *context.fulltracer_len = cursor + 1;
            }
            return status;
        }
        if context.trace_mode == AOT_TRACE_MODE_COMPACT_SKELETON_L1C {
            let record = CompactSkeletonRecord::new(cursor, pc, unsafe { *next_pc }, memory_addr);
            unsafe {
                context
                    .fulltracer_records
                    .cast::<CompactSkeletonRecord>()
                    .add(cursor)
                    .write(record);
                *context.fulltracer_pending_index = cursor + 1;
                *context.fulltracer_pending_cycle = cycle + crate::FullTracer::SUBCYCLES_PER_INSN;
                *context.fulltracer_len = cursor + 1;
            }
            return status;
        }
        if context.trace_mode == AOT_TRACE_MODE_COMPACT_VALUES_L2C {
            unsafe {
                write_compact_values_fallback(
                    context,
                    cursor,
                    pc,
                    *next_pc,
                    insn,
                    memory_addr,
                    rs1_value,
                    rs2_value,
                    rd_before,
                    memory_before,
                );
                *context.fulltracer_pending_index = cursor + 1;
                *context.fulltracer_pending_cycle = cycle + crate::FullTracer::SUBCYCLES_PER_INSN;
                *context.fulltracer_len = cursor + 1;
            }
            return status;
        }
        let mut register_previous = [crate::StepRecord::L1_POISON_CYCLE; 3];
        if matches!(
            context.trace_mode,
            AOT_TRACE_MODE_COMPACT_REGISTERS_L3C
                | AOT_TRACE_MODE_COMPACT_MEMORY_L4C
                | AOT_TRACE_MODE_COMPACT_FUTURE_ACCESS_L5C
                | AOT_TRACE_MODE_COMPACT_EXCEPTIONAL_L6C
                | AOT_TRACE_MODE_COMPACT_CLOSURE_L7
                | AOT_TRACE_MODE_REGISTERS_L3
                | AOT_TRACE_MODE_MEMORY_L4
                | AOT_TRACE_MODE_FUTURE_ACCESS_L5
        ) {
            let latest = context.fulltracer_latest_cells;
            if native_step_reads_rs1(insn.kind) {
                let cell = unsafe { latest.add(insn.rs1 as usize) };
                register_previous[0] = unsafe { *cell };
                unsafe { *cell = cycle + crate::FullTracer::SUBCYCLE_RS1 };
            }
            if native_step_reads_rs2(insn.kind) {
                let cell = unsafe { latest.add(insn.rs2 as usize) };
                register_previous[1] = unsafe { *cell };
                unsafe { *cell = cycle + crate::FullTracer::SUBCYCLE_RS2 };
            }
            if native_step_writes_rd(insn.kind) {
                let cell = unsafe { latest.add(insn.rd_internal() as usize) };
                register_previous[2] = unsafe { *cell };
                unsafe { *cell = cycle + crate::FullTracer::SUBCYCLE_RD };
            }
        }
        if matches!(
            context.trace_mode,
            AOT_TRACE_MODE_COMPACT_REGISTERS_L3C
                | AOT_TRACE_MODE_COMPACT_MEMORY_L4C
                | AOT_TRACE_MODE_COMPACT_FUTURE_ACCESS_L5C
                | AOT_TRACE_MODE_COMPACT_EXCEPTIONAL_L6C
                | AOT_TRACE_MODE_COMPACT_CLOSURE_L7
        ) {
            if let Err(err) = unsafe {
                write_compact_registers_fallback(
                    context,
                    pc,
                    *next_pc,
                    insn,
                    rs1_value,
                    rs2_value,
                    rd_before,
                    memory_before,
                    register_previous,
                    memory_previous_cycle,
                )
            } {
                LAST_AOT_ERROR.with(|slot| *slot.borrow_mut() = Some(err));
                return AOT_STATUS_ERROR;
            }
            unsafe {
                *context.fulltracer_pending_index = cursor + 1;
                *context.fulltracer_pending_cycle = cycle + crate::FullTracer::SUBCYCLES_PER_INSN;
                *context.fulltracer_len = cursor + 1;
            }
            return status;
        }
        let record = if matches!(
            context.trace_mode,
            AOT_TRACE_MODE_VALUES_L2
                | AOT_TRACE_MODE_REGISTERS_L3
                | AOT_TRACE_MODE_MEMORY_L4
                | AOT_TRACE_MODE_FUTURE_ACCESS_L5
        ) {
            let rd_after = unsafe { *context.registers.add(rd) };
            let memory_value = memory_addr
                .and_then(|addr| layered_memory_value(context, addr))
                .zip(memory_before)
                .map(|(after, before)| Change::new(before, after));
            if layered_memory {
                let (heap_before, hint_before) = bounds_before
                    .expect("L4 fallback must snapshot heap/hint bounds before execution");
                crate::StepRecord::l4_memory(
                    cycle,
                    Change::new(pc.into(), unsafe { *next_pc }.into()),
                    insn,
                    memory_addr,
                    rs1_value,
                    rs2_value,
                    Change::new(rd_before, rd_after),
                    memory_value,
                    register_previous,
                    memory_previous_cycle,
                    Change::new(heap_before, unsafe { *context.fulltracer_max_heap }),
                    Change::new(hint_before, unsafe { *context.fulltracer_max_hint }),
                )
            } else if context.trace_mode == AOT_TRACE_MODE_REGISTERS_L3 {
                crate::StepRecord::l3_registers(
                    cycle,
                    Change::new(pc.into(), unsafe { *next_pc }.into()),
                    insn,
                    memory_addr,
                    rs1_value,
                    rs2_value,
                    Change::new(rd_before, rd_after),
                    memory_value,
                    register_previous,
                )
            } else {
                crate::StepRecord::l2_values(
                    cycle,
                    Change::new(pc.into(), unsafe { *next_pc }.into()),
                    insn,
                    memory_addr,
                    rs1_value,
                    rs2_value,
                    Change::new(rd_before, rd_after),
                    memory_value,
                )
            }
        } else {
            crate::StepRecord::l1_skeleton(
                cycle,
                Change::new(pc.into(), unsafe { *next_pc }.into()),
                insn,
                memory_addr,
            )
        };
        unsafe {
            context.fulltracer_records.add(cursor).write(record);
            *context.fulltracer_pending_index = cursor + 1;
            *context.fulltracer_pending_cycle = cycle + crate::FullTracer::SUBCYCLES_PER_INSN;
            *context.fulltracer_len = cursor + 1;
        }
    }
    status
}

/// Stable symbol covering the Rust fallback path, including syscall bodies.
#[unsafe(no_mangle)]
#[inline(never)]
pub(super) unsafe extern "C" fn ceno_aot_preflight_fallback_callback(
    raw_context: *mut c_void,
    pc: u32,
    next_pc: *mut u32,
) -> u32 {
    let fallback_started = Instant::now();
    let context = unsafe { &mut *(raw_context as *mut AotRuntimeContext) };
    let vm = unsafe { &mut *(context.vm as *mut VMState<PreflightTracer>) };
    invalidate_preflight_bucket_cache(context);
    if context.trace_mode != AOT_TRACE_MODE_PREFLIGHT_CAPTURE_DIRECT
        && context.fallback_reason == AOT_FALLBACK_ECALL
    {
        let code = unsafe { *context.registers.add(Platform::reg_ecall() as usize) };
        let arg0 = unsafe { *context.registers.add(Platform::reg_arg0() as usize) };
        let arg1 = unsafe { *context.registers.add(Platform::reg_arg1() as usize) };
        if let (Some(index), Some(plan)) = (
            pure_ecall_index(code),
            crate::syscalls::pure::access_plan(code, arg0, arg1),
        ) {
            let executed = unsafe {
                crate::syscalls::pure::execute(
                    code,
                    context.registers,
                    context.memory_cells,
                    context.memory_base_word,
                    context.memory_end_word,
                    context.pure_double_cache,
                )
            };
            if executed {
                let pc = ByteAddr(pc);
                vm.set_pc(pc);
                let insn = vm
                    .fetch(pc.waddr())
                    .expect("direct syscall PC must belong to the compiled program");
                debug_assert_eq!(insn.kind, InsnKind::ECALL);
                let loaded_code = vm
                    .load_register(Platform::reg_ecall())
                    .expect("register load cannot fail");
                debug_assert_eq!(loaded_code, code);
                vm.finish_direct_preflight_syscall(plan);

                context.fallback_steps += 1;
                context.fallback_ecall += 1;
                unsafe {
                    (*context.pure_ecall_counts)[index] += 1;
                    *next_pc = vm.get_pc().0;
                }
                (context.preflight_event_cursor, context.preflight_event_end) =
                    vm.tracer_mut().native_next_access_ptrs();
                let shard_start = unsafe { *context.preflight_current_shard_start };
                if shard_start != context.preflight_register_shard_start {
                    context.preflight_register_touched_mask = 0;
                    context.preflight_register_shard_start = shard_start;
                    context.preflight_memory_shard_start_ordinal = shard_start >> 2;
                }
                context.fallback_time_ns = context
                    .fallback_time_ns
                    .saturating_add(fallback_started.elapsed().as_nanos() as u64);
                return AOT_STATUS_CONTINUE;
            }
        }
    }
    unsafe { aot_exec_one::<PreflightTracer>(raw_context, pc, next_pc) }
}

pub(super) unsafe extern "C" fn aot_trace_native_compute<T: Tracer>(
    context: *mut AotRuntimeContext,
) -> u32 {
    aot_native_callback_event(&AOT_NATIVE_CALLBACK_TRACE, "trace");
    let context = unsafe { &mut *context };
    let vm = unsafe { &mut *(context.vm as *mut VMState<T>) };
    if vm.halted() {
        context.trace_next_pc = vm.get_pc().0;
        return AOT_STATUS_HALTED;
    }

    let pc = ByteAddr(context.trace_pc);
    vm.set_pc(pc);
    let result = (|| -> Result<()> {
        let idx = pc.0.wrapping_sub(context.program_base) / PC_STEP_SIZE as u32;
        let insn = unsafe { *context.instructions.add(idx as usize) };
        if aot_native_diagnostic_only() && AOT_NATIVE_CALLBACK_TRACE.load(Ordering::Relaxed) == 1 {
            aot_native_diagnostic_boundary(
                "FIRST_CALLBACK_CONTEXT",
                "OBSERVE",
                &format!(
                    "callback_ordinal=0,trace_pc={:#010x},trace_next_pc={:#010x},raw_trace_kind={},program_pc={:#010x},program_kind={:?},mode={}",
                    context.trace_pc,
                    context.trace_next_pc,
                    context.trace_kind,
                    pc.0,
                    insn.kind,
                    context.trace_mode,
                ),
            );
        }
        vm.trace_fetch_known(pc.waddr(), insn);
        if !supports_native_compute(insn.kind)
            && !supports_native_control_flow(insn.kind)
            && !supports_native_memory(insn.kind)
        {
            bail!(
                "AOT native trace helper received unsupported instruction {:?} at pc={:#010x}",
                insn.kind,
                pc.0
            );
        }

        if native_step_reads_rs1(insn.kind) {
            vm.tracer_mut()
                .load_register(insn.rs1, context.trace_rs1_value);
        }
        if native_step_reads_rs2(insn.kind) {
            vm.tracer_mut()
                .load_register(insn.rs2, context.trace_rs2_value);
        }
        if native_step_writes_rd(insn.kind) {
            vm.tracer_mut().store_register(
                insn.rd_internal() as _,
                Change {
                    before: context.trace_rd_before,
                    after: context.trace_rd_after,
                },
            );
        }
        if native_step_loads_memory(insn.kind) {
            #[cfg(any(test, debug_assertions))]
            {
                if context.memory_prev_stamp == 0 {
                    vm.record_native_memory_first_touch(WordAddr(context.trace_mem_addr));
                }
            }
            let previous_cycle = crate::dense_addr_space::PackedMemory::decode_stamp(
                context.memory_prev_stamp as u32,
            );
            vm.tracer_mut().load_memory(
                WordAddr(context.trace_mem_addr),
                context.trace_mem_after,
                previous_cycle,
            );
        }
        if native_step_stores_memory(insn.kind) {
            #[cfg(any(test, debug_assertions))]
            {
                if context.memory_prev_stamp == 0 {
                    vm.record_native_memory_first_touch(WordAddr(context.trace_mem_addr));
                }
            }
            let previous_cycle = crate::dense_addr_space::PackedMemory::decode_stamp(
                context.memory_prev_stamp as u32,
            );
            vm.tracer_mut().store_memory(
                WordAddr(context.trace_mem_addr),
                Change {
                    before: context.trace_mem_before,
                    after: context.trace_mem_after,
                },
                previous_cycle,
            );
        }
        vm.set_pc(ByteAddr(context.trace_next_pc));
        vm.on_normal_end(&insn);
        let step = vm.tracer_mut().advance();
        if context.trace_next_pc == context.trace_pc
            && vm.tracer().is_busy_loop(&step)
            && !vm.halted()
        {
            bail!("Stuck in loop {}", "{}");
        }
        Ok(())
    })();

    match result {
        Ok(()) => AOT_STATUS_CONTINUE,
        Err(err) => {
            context.trace_next_pc = vm.get_pc().0;
            LAST_AOT_ERROR.with(|slot| *slot.borrow_mut() = Some(err));
            AOT_STATUS_ERROR
        }
    }
}

pub(super) fn invalidate_preflight_bucket_cache(context: &mut AotRuntimeContext) {
    context.preflight_bucket_generation = context.preflight_bucket_generation.wrapping_add(1);
    if context.preflight_bucket_generation == 0 {
        if !context.preflight_bucket_generations.is_null() {
            let generations = unsafe {
                std::slice::from_raw_parts_mut(
                    context.preflight_bucket_generations,
                    context.preflight_num_chips,
                )
            };
            generations.fill(0);
        }
        context.preflight_bucket_generation = 1;
    }
}

pub(super) unsafe extern "C" fn aot_trace_native_preflight(context: *mut AotRuntimeContext) -> u32 {
    aot_native_callback_event(&AOT_NATIVE_CALLBACK_TRACE, "trace");
    let context = unsafe { &mut *context };
    let vm = unsafe { &mut *(context.vm as *mut VMState<PreflightTracer>) };
    if vm.halted() {
        context.trace_next_pc = vm.get_pc().0;
        return AOT_STATUS_HALTED;
    }

    let step = NativeTraceStep {
        pc_before: ByteAddr(context.trace_pc),
        pc_after: ByteAddr(context.trace_next_pc),
        kind: native_trace_kind(context.trace_kind),
        flags: context.trace_flags,
        rs1_idx: context.trace_rs1_idx as RegIdx,
        rs2_idx: context.trace_rs2_idx as RegIdx,
        rd_idx: context.trace_rd_idx as RegIdx,
        memory_addr: WordAddr(context.trace_mem_addr),
        memory_previous_cycle: crate::dense_addr_space::PackedMemory::decode_stamp(
            context.memory_prev_stamp as u32,
        ),
    };
    let busy_loop = vm.trace_preflight_native_step(step);
    if busy_loop && !vm.halted() {
        context.trace_next_pc = vm.get_pc().0;
        LAST_AOT_ERROR.with(|slot| *slot.borrow_mut() = Some(anyhow!("Stuck in loop {}", "{}")));
        AOT_STATUS_ERROR
    } else {
        AOT_STATUS_CONTINUE
    }
}

#[unsafe(no_mangle)]
#[inline(never)]
pub(super) unsafe extern "C" fn ceno_aot_preflight_direct_callback(
    context: *mut AotRuntimeContext,
) -> u32 {
    aot_native_callback_event(&AOT_NATIVE_CALLBACK_PREFLIGHT, "preflight-direct");
    let context = unsafe { &mut *context };
    let diagnostic_variant = match context.preflight_helper_kind {
        AOT_PREFLIGHT_HELPER_DIAGNOSTIC_ADAPTIVE_ENTRY => Some(("COMMIT_ENTRY", "adaptive_exact")),
        AOT_PREFLIGHT_HELPER_DIAGNOSTIC_ADAPTIVE_EXIT => Some(("COMMIT_EXIT", "adaptive_exact")),
        AOT_PREFLIGHT_HELPER_DIAGNOSTIC_BLOCK_PLAN_ENTRY => Some(("COMMIT_ENTRY", "block_plan")),
        AOT_PREFLIGHT_HELPER_DIAGNOSTIC_BLOCK_PLAN_EXIT => Some(("COMMIT_EXIT", "block_plan")),
        _ => None,
    };
    if let Some((phase, variant)) = diagnostic_variant {
        aot_plan_commit_diagnostic_state(phase, variant, context);
        return AOT_STATUS_CONTINUE;
    }
    invalidate_preflight_bucket_cache(context);
    let vm = unsafe { &mut *(context.vm as *mut VMState<PreflightTracer>) };
    if !context.preflight_event_cursor.is_null() {
        unsafe {
            vm.tracer_mut()
                .sync_native_next_access_tape(context.preflight_event_cursor)
        };
    }
    if vm.halted() {
        context.trace_next_pc = vm.get_pc().0;
        return AOT_STATUS_HALTED;
    }

    let status = match context.preflight_helper_kind {
        AOT_PREFLIGHT_HELPER_SYNC => {
            vm.tracer_mut()
                .observe_native_steps(context.preflight_pending_steps);
            context.preflight_pending_steps = 0;
            AOT_STATUS_CONTINUE
        }
        AOT_PREFLIGHT_HELPER_BUSY_LOOP => {
            vm.tracer_mut()
                .observe_native_steps(context.preflight_pending_steps);
            context.preflight_pending_steps = 0;
            context.trace_next_pc = vm.get_pc().0;
            LAST_AOT_ERROR
                .with(|slot| *slot.borrow_mut() = Some(anyhow!("Stuck in loop {}", "{}")));
            AOT_STATUS_ERROR
        }
        AOT_PREFLIGHT_HELPER_CALLBACK => {
            vm.tracer_mut()
                .observe_native_steps(context.preflight_pending_steps);
            context.preflight_pending_steps = 0;
            unsafe { aot_trace_native_preflight(context as *mut AotRuntimeContext) }
        }
        AOT_PREFLIGHT_HELPER_SHARD_SPLIT => {
            let specialized_count = context
                .preflight_pending_specialized
                .checked_sub(1)
                .map(|count| count as usize);
            let adaptive_descriptor = (!context.preflight_block_cost_descriptors.is_null()
                && specialized_count.is_none()
                && context.preflight_pending_block != usize::MAX)
                .then(|| unsafe {
                    *context
                        .preflight_block_cost_descriptors
                        .add(context.preflight_pending_block)
                });
            if let Some(count) = specialized_count {
                let counts = unsafe {
                    std::slice::from_raw_parts_mut(
                        context.preflight_num_instances,
                        context.preflight_num_chips,
                    )
                };
                for index in 0..count {
                    let chip = context.preflight_pending_chips[index] as usize;
                    counts[chip] =
                        counts[chip].saturating_sub(context.preflight_pending_deltas[index]);
                }
            } else if let Some(descriptor) = adaptive_descriptor {
                // Restore the accepted shard's counts before finalizing it;
                // the native entry speculatively stored this block's candidate.
                let counts = unsafe {
                    std::slice::from_raw_parts_mut(
                        context.preflight_num_instances,
                        context.preflight_num_chips,
                    )
                };
                let contributions = unsafe {
                    std::slice::from_raw_parts(
                        context
                            .preflight_chip_contributions
                            .add(descriptor.contribution_offset as usize),
                        descriptor.contribution_count as usize,
                    )
                };
                for contribution in contributions {
                    counts[contribution.chip_index as usize] = counts
                        [contribution.chip_index as usize]
                        .saturating_sub(contribution.instance_delta);
                }
            }
            vm.tracer_mut().record_native_shard_split();
            if let Err(message) = vm.tracer_mut().sync_combined_capture() {
                LAST_AOT_ERROR.with(|slot| *slot.borrow_mut() = Some(anyhow!(message)));
                return AOT_STATUS_ERROR;
            }
            if let Some(count) = specialized_count {
                let counts = unsafe {
                    std::slice::from_raw_parts_mut(
                        context.preflight_num_instances,
                        context.preflight_num_chips,
                    )
                };
                for index in 0..count {
                    counts[context.preflight_pending_chips[index] as usize] =
                        context.preflight_pending_deltas[index];
                }
                unsafe {
                    *context.preflight_planner_cur_trace_cells = context.preflight_pending_trace;
                    *context.preflight_planner_cur_main_peak = context.preflight_pending_main;
                    *context.preflight_planner_cur_tower_peak = context.preflight_pending_tower;
                    *context.preflight_planner_cur_cells =
                        context.preflight_pending_trace.saturating_add(
                            context
                                .preflight_pending_main
                                .max(context.preflight_pending_tower),
                        );
                }
                context.preflight_pending_specialized = 0;
                context.preflight_pending_block = usize::MAX;
            } else if let Some(descriptor) = adaptive_descriptor {
                let counts = unsafe {
                    std::slice::from_raw_parts_mut(
                        context.preflight_num_instances,
                        context.preflight_num_chips,
                    )
                };
                let contributions = unsafe {
                    std::slice::from_raw_parts(
                        context
                            .preflight_chip_contributions
                            .add(descriptor.contribution_offset as usize),
                        descriptor.contribution_count as usize,
                    )
                };
                for contribution in contributions {
                    counts[contribution.chip_index as usize] = contribution.instance_delta;
                }
                unsafe {
                    *context.preflight_planner_cur_trace_cells = descriptor.standalone_trace_cells;
                    *context.preflight_planner_cur_main_peak = descriptor.standalone_main_peak;
                    *context.preflight_planner_cur_tower_peak = descriptor.standalone_tower_peak;
                    *context.preflight_planner_cur_cells =
                        descriptor.standalone_trace_cells.saturating_add(
                            descriptor
                                .standalone_main_peak
                                .max(descriptor.standalone_tower_peak),
                        );
                }
                context.preflight_pending_block = usize::MAX;
            }
            AOT_STATUS_CONTINUE
        }
        AOT_PREFLIGHT_HELPER_REPLAY_BLOCK_CUT => {
            let block_index = context.preflight_pending_block;
            if context.preflight_block_kind_histograms.is_null()
                || block_index >= context.preflight_block_kind_histogram_count
            {
                LAST_AOT_ERROR.with(|slot| {
                    *slot.borrow_mut() = Some(anyhow!(
                        "AOT replay block metadata index {block_index} is out of bounds"
                    ))
                });
                AOT_STATUS_ERROR
            } else {
                let descriptor =
                    unsafe { &*context.preflight_block_kind_histograms.add(block_index) };
                let instructions = unsafe {
                    std::slice::from_raw_parts(
                        context
                            .instructions
                            .add(descriptor.instruction_offset as usize),
                        descriptor.instruction_count as usize,
                    )
                };
                let ordered_kinds = instructions
                    .iter()
                    .map(|instruction| instruction.kind)
                    .collect::<Vec<_>>();
                vm.tracer_mut()
                    .record_admitted_native_block(&descriptor.counts, &ordered_kinds);
                if let Err(message) = vm.tracer_mut().sync_combined_capture() {
                    LAST_AOT_ERROR.with(|slot| *slot.borrow_mut() = Some(anyhow!(message)));
                    return AOT_STATUS_ERROR;
                }
                context.preflight_pending_block = usize::MAX;
                AOT_STATUS_CONTINUE
            }
        }
        AOT_PREFLIGHT_HELPER_FIRST_TOUCH => {
            vm.tracer_mut()
                .record_native_first_touch(WordAddr(context.preflight_event_addr));
            AOT_STATUS_CONTINUE
        }
        AOT_PREFLIGHT_HELPER_MEMORY_FIRST_TOUCH => {
            #[cfg(any(test, debug_assertions))]
            vm.record_native_memory_first_touch(WordAddr(context.preflight_event_addr));
            AOT_STATUS_CONTINUE
        }
        AOT_PREFLIGHT_HELPER_GROW_TAPE => {
            let (old_capacity, new_capacity) = vm.tracer_mut().grow_native_next_access_tape();
            tracing::warn!(
                "AOT next-access tape grew from {old_capacity} to {new_capacity} events"
            );
            AOT_STATUS_CONTINUE
        }
        other => {
            LAST_AOT_ERROR.with(|slot| {
                *slot.borrow_mut() = Some(anyhow!("unknown AOT Preflight helper kind {other}"))
            });
            AOT_STATUS_ERROR
        }
    };
    (context.preflight_event_cursor, context.preflight_event_end) =
        vm.tracer_mut().native_next_access_ptrs();
    let shard_start = unsafe { *context.preflight_current_shard_start };
    if shard_start != context.preflight_register_shard_start {
        context.preflight_register_touched_mask = 0;
        context.preflight_register_shard_start = shard_start;
        context.preflight_memory_shard_start_ordinal = shard_start >> 2;
    }
    status
}
