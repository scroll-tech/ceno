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
            AOT_FALLBACK_DYNAMIC_PC | AOT_FALLBACK_ECALL | AOT_FALLBACK_EXCEPTIONAL
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
        if context.trace_mode == AOT_TRACE_MODE_PREFLIGHT_DIRECT {
            let idx = pc.0.wrapping_sub(context.program_base) / PC_STEP_SIZE as u32;
            let insn = unsafe { *context.instructions.add(idx as usize) };
            let ecall_code = (insn.kind == InsnKind::ECALL)
                .then(|| unsafe { *context.registers.add(Platform::reg_ecall() as usize) });
            let preflight_vm = unsafe { &mut *(context.vm as *mut VMState<PreflightTracer>) };
            preflight_vm
                .tracer_mut()
                .prepare_native_fallback_shard_start(insn.kind, ecall_code);
        }
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

    if context.trace_mode == AOT_TRACE_MODE_PREFLIGHT_DIRECT {
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
    if context.fallback_reason == AOT_FALLBACK_ECALL {
        let code = unsafe { *context.registers.add(Platform::reg_ecall() as usize) };
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

pub(super) unsafe extern "C" fn ceno_aot_preflight_fallback_callback(
    raw_context: *mut c_void,
    pc: u32,
    next_pc: *mut u32,
) -> u32 {
    let fallback_started = Instant::now();
    let context = unsafe { &mut *(raw_context as *mut AotRuntimeContext) };
    let vm = unsafe { &mut *(context.vm as *mut VMState<PreflightTracer>) };
    invalidate_preflight_bucket_cache(context);
    if context.fallback_reason == AOT_FALLBACK_ECALL {
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
