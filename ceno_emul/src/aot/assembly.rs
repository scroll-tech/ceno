//! Generated x86-64 assembly and static instruction classification.

use super::*;

#[cfg(test)]
pub(super) fn write_assembly_with_planner(
    path: &Path,
    program: &Program,
    blocks: &[BasicBlock],
    emission_order: &[u32],
    trace_style: AssemblyTraceStyle,
    planner_metadata: Option<&AotPlannerMetadata>,
) -> Result<()> {
    validate_emission_order(blocks, emission_order)?;
    write_assembly_part(
        path,
        program,
        blocks,
        emission_order,
        trace_style,
        planner_metadata,
        true,
    )
}

#[allow(clippy::too_many_arguments)]
pub(super) fn write_assembly_part(
    path: &Path,
    program: &Program,
    blocks: &[BasicBlock],
    emission_order: &[u32],
    trace_style: AssemblyTraceStyle,
    planner_metadata: Option<&AotPlannerMetadata>,
    emit_control: bool,
) -> Result<()> {
    let mut labels = BTreeMap::new();
    for block in blocks {
        labels.insert(
            block.start_pc,
            format!("ceno_aot_bb_{:08x}", block.start_pc),
        );
    }

    let mut file = fs::File::create(path).context("create AOT assembly")?;
    writeln!(file, ".text")?;
    if emit_control {
        writeln!(file, ".globl ceno_aot_entry")?;
        writeln!(file, ".type ceno_aot_entry, @function")?;
        writeln!(file, "ceno_aot_entry:")?;
        writeln!(file, "    pushq %rbx")?;
        writeln!(file, "    pushq %r12")?;
        writeln!(file, "    pushq %r13")?;
        writeln!(file, "    pushq %r14")?;
        writeln!(file, "    pushq %r15")?;
        writeln!(file, "    pushq %rbp")?;
        writeln!(file, "    subq $88, %rsp")?;
        writeln!(file, "    movq %rdi, %r12")?;
        writeln!(file, "    movq %rsi, 72(%rsp)")?;
        writeln!(file, "    movq {AOT_CTX_REGISTERS_OFFSET}(%r12), %r13")?;
        if !trace_style.is_pure() {
            writeln!(file, "    movq %rdx, %r14")?;
        }
        writeln!(file, "    movq %rcx, %rbp")?;
        // Keep the preflight tape cursor in a callee-saved register. The executed
        // step output pointer is cold and fits in the otherwise-unused final stack
        // slot.
        writeln!(file, "    movq %r8, 48(%rsp)")?;
        if trace_style.is_pure() {
            emit_reload_pure_memory_state(&mut file)?;
        } else {
            writeln!(
                file,
                "    movq {AOT_CTX_PREFLIGHT_EVENT_CURSOR_OFFSET}(%r12), %rbx"
            )?;
        }
        writeln!(file, "    movl %r9d, %r15d")?;
        writeln!(file, "    movq $0, 0(%rsp)")?;
        writeln!(file, "    movl %r15d, 8(%rsp)")?;
        writeln!(
            file,
            "    movq {AOT_CTX_PREFLIGHT_REGISTER_TOUCHED_MASK_OFFSET}(%r12), %rax"
        )?;
        writeln!(file, "    movq %rax, 56(%rsp)")?;
        emit_global_hidden_symbol(&mut file, "ceno_aot_dispatch")?;
        writeln!(file, "    movq 0(%rsp), %rax")?;
        writeln!(file, "    cmpq %rbp, %rax")?;
        writeln!(file, "    jae ceno_aot_done")?;
        emit_dispatch_tree(&mut file, blocks, &labels, 0, blocks.len())?;
    }
    let blocks_by_pc = blocks
        .iter()
        .enumerate()
        .map(|(index, block)| (block.start_pc, (index, block)))
        .collect::<BTreeMap<_, _>>();
    for (emission_index, block_pc) in emission_order.iter().enumerate() {
        let &(block_idx, block) = blocks_by_pc
            .get(block_pc)
            .expect("validated emission block must exist");
        let next_block_pc = emission_order.get(emission_index + 1).copied();
        let label = labels.get(&block.start_pc).expect("block label must exist");
        emit_assembly_profile_symbol(
            &mut file,
            &format!("ceno_aot_bb_{:08x}_guards", block.start_pc),
        )?;
        writeln!(file, ".globl {label}")?;
        writeln!(file, ".hidden {label}")?;
        writeln!(file, ".type {label}, @function")?;
        writeln!(file, "{label}:")?;
        // Reaching a native block leader ends any Rust fallback recovery run.
        writeln!(
            file,
            "    movl $0, {AOT_CTX_FALLBACK_RECOVERY_REASON_OFFSET}(%r12)"
        )?;
        let block_plan = if trace_style.uses_preflight_block_plan() {
            preflight_block_plan_kind(program, block)?
        } else {
            None
        };
        let memory_access_count = preflight_block_memory_access_count(program, block)?;
        let hoist_memory_regions =
            matches!(block_plan, Some(PreflightBlockPlanKind::MemoryExactAccess))
                && trace_style.preflight_feature_enabled(PreflightFeature::MmioBounds)
                && memory_access_count <= 32;
        let pure_block_plan = if trace_style.uses_pure_block_admission() {
            preflight_block_plan_kind(program, block)?
        } else {
            None
        };
        let pure_counted_block = trace_style.uses_pure_block_admission()
            && block_supports_adaptive_cost_plan(program, block)?;
        let pure_admitted_block = pure_counted_block || pure_block_plan.is_some();
        if pure_admitted_block {
            emit_pure_block_budget_guard(&mut file, block)?;
        }
        if let Some(kind) = pure_block_plan {
            if kind == PreflightBlockPlanKind::MemoryExactAccess {
                emit_pure_block_memory_fast_path_guard(&mut file, program, block)?;
            }
        }
        if pure_admitted_block {
            writeln!(
                file,
                "    addq ${}, 0(%rsp)",
                block_instruction_count(block)
            )?;
        }
        let adaptive_exact_access_plan = block_plan.is_none()
            && trace_style.uses_preflight_block_plan()
            && block_supports_adaptive_cost_plan(program, block)?;
        if block_plan.is_none()
            && !adaptive_exact_access_plan
            && trace_style.uses_preflight_block_plan()
        {
            let reason = if instruction_at(program, block.start_pc)?.kind == InsnKind::ECALL {
                AOT_FALLBACK_ECALL
            } else {
                AOT_FALLBACK_EXCEPTIONAL
            };
            emit_call_current_pc(&mut file, reason, trace_style)?;
            writeln!(file, "    jmp ceno_aot_dispatch")?;
            continue;
        }
        if adaptive_exact_access_plan {
            emit_preflight_direct_block_budget_guard(&mut file, block)?;
            if trace_style.preflight_feature_enabled(PreflightFeature::EventCapacity) {
                emit_preflight_direct_block_event_capacity_guard(
                    &mut file,
                    program,
                    block_idx,
                    block,
                    PreflightAccessMode::BlockAtomic,
                )?;
            }
            emit_assembly_profile_symbol(
                &mut file,
                &format!("ceno_aot_bb_{:08x}_accounting", block.start_pc),
            )?;
            emit_preflight_adaptive_block_plan_entry(
                &mut file,
                block_idx,
                block,
                planner_metadata,
            )?;
            emit_assembly_profile_symbol(
                &mut file,
                &format!("ceno_aot_bb_{:08x}_register_first_checks", block.start_pc),
            )?;
            if trace_style.preflight_feature_enabled(PreflightFeature::RegisterLatest) {
                emit_preflight_direct_block_access_entry(
                    &mut file,
                    program,
                    block_idx,
                    block,
                    trace_style.preflight_feature_enabled(PreflightFeature::RegisterEvents),
                )?;
            }
        }
        if block_plan.is_some() {
            emit_preflight_direct_block_budget_guard(&mut file, block)?;
            if matches!(block_plan, Some(PreflightBlockPlanKind::MemoryExactAccess)) {
                emit_preflight_direct_block_memory_fast_path_guard(
                    &mut file,
                    program,
                    block,
                    hoist_memory_regions,
                )?;
            }
            if trace_style.preflight_feature_enabled(PreflightFeature::EventCapacity) {
                emit_preflight_direct_block_event_capacity_guard(
                    &mut file,
                    program,
                    block_idx,
                    block,
                    PreflightAccessMode::BlockAtomic,
                )?;
            }
            emit_assembly_profile_symbol(
                &mut file,
                &format!("ceno_aot_bb_{:08x}_accounting", block.start_pc),
            )?;
            emit_preflight_adaptive_block_plan_entry(
                &mut file,
                block_idx,
                block,
                planner_metadata,
            )?;
            if block_plan.is_some() {
                emit_assembly_profile_symbol(
                    &mut file,
                    &format!("ceno_aot_bb_{:08x}_register_first_checks", block.start_pc),
                )?;
                if trace_style.preflight_feature_enabled(PreflightFeature::RegisterLatest) {
                    emit_preflight_direct_block_access_entry(
                        &mut file,
                        program,
                        block_idx,
                        block,
                        trace_style.preflight_feature_enabled(PreflightFeature::RegisterEvents),
                    )?;
                }
            }
            // The entry guards make this block atomic with respect to Rust
            // fallback. Reserve its executed-step count once, as Pure AOT
            // does, and publish tracked cycle/step state at block exit.
            writeln!(
                file,
                "    addq ${}, 0(%rsp)",
                block_instruction_count(block)
            )?;
        }
        let registers_resident =
            !cfg!(debug_assertions) && (block_plan.is_some() || pure_admitted_block);
        let memory_cells_resident =
            registers_resident && memory_access_count != 0 && !trace_style.is_pure();
        if registers_resident {
            writeln!(file, "    movq %r13, %r10")?;
        }
        if memory_cells_resident {
            writeln!(file, "    movq {AOT_CTX_MEMORY_CELLS_OFFSET}(%r12), %r11")?;
            writeln!(
                file,
                "    movl {AOT_CTX_MEMORY_BASE_WORD_OFFSET}(%r12), %eax"
            )?;
            writeln!(file, "    negq %rax")?;
            writeln!(file, "    leaq (%r11,%rax,8), %r11")?;
            writeln!(
                file,
                "    movq {AOT_CTX_MEMORY_START_ORDINAL_OFFSET}(%r12), %r15"
            )?;
            writeln!(file, "    addq 0(%rsp), %r15")?;
            writeln!(file, "    subq ${}, %r15", block_instruction_count(block))?;
        }
        let mut pc = block.start_pc;
        let mut memory_access_index = 0usize;
        let mut last_profile_region = None;
        while pc < block.end_pc {
            let insn = instruction_at(program, pc)?;
            if trace_style == AssemblyTraceStyle::GpuReplayDirect {
                let resume_label = format!("ceno_aot_gpu_resume_{pc:08x}");
                writeln!(file, ".globl {resume_label}")?;
                writeln!(file, ".hidden {resume_label}")?;
                writeln!(file, ".type {resume_label}, @function")?;
                writeln!(file, "{resume_label}:")?;
            }
            let current_memory_access_index =
                if native_opcode_family(insn.kind) == Some(NativeOpcodeFamily::Memory) {
                    let index = memory_access_index;
                    memory_access_index += 1;
                    Some(index)
                } else {
                    None
                };
            let step_trace_style = if trace_style.is_preflight_production() {
                trace_style
            } else if pure_block_plan.is_some() {
                AssemblyTraceStyle::PureBlock
            } else if pure_counted_block {
                AssemblyTraceStyle::PureCountedBlock
            } else if matches!(block_plan, Some(PreflightBlockPlanKind::RegisterOnly)) {
                AssemblyTraceStyle::PreflightAdmittedRegisterBlock
            } else if matches!(block_plan, Some(PreflightBlockPlanKind::MemoryExactAccess))
                || adaptive_exact_access_plan
            {
                AssemblyTraceStyle::PreflightAdmittedMemoryBlock
            } else if trace_style.uses_preflight_block_plan() {
                AssemblyTraceStyle::PreflightScalar
            } else {
                trace_style
            };
            let region = if native_opcode_family(insn.kind) == Some(NativeOpcodeFamily::Memory) {
                "memory"
            } else {
                "guest"
            };
            if last_profile_region != Some(region) {
                emit_assembly_profile_symbol(
                    &mut file,
                    &format!("ceno_aot_bb_{:08x}_{region}_{pc:08x}", block.start_pc),
                )?;
                last_profile_region = Some(region);
            }
            let reserved_block_step =
                (pure_admitted_block || block_plan.is_some()).then_some(ReservedBlockStep {
                    remaining_after: ((block.end_pc - pc - PC_STEP_SIZE as u32)
                        / PC_STEP_SIZE as u32) as u64,
                    cycle_offset: (pc - block.start_pc) as u64,
                    memory_guard_hoisted: matches!(
                        block_plan,
                        Some(PreflightBlockPlanKind::MemoryExactAccess)
                    ),
                    memory_region_index: hoist_memory_regions
                        .then_some(current_memory_access_index)
                        .flatten(),
                    registers_resident,
                    memory_cells_resident,
                    memory_ordinal_resident: memory_cells_resident,
                });
            emit_instruction_body(
                &mut file,
                program,
                pc,
                insn,
                step_trace_style,
                reserved_block_step,
            )?;
            pc = pc.wrapping_add(PC_STEP_SIZE as u32);
        }
        if let Some(prev_pc) = pc.checked_sub(PC_STEP_SIZE as u32) {
            let insn = instruction_at(program, prev_pc)?;
            if block_plan.is_some() {
                emit_preflight_direct_block_trace_exit(&mut file, block)?;
                emit_preflight_direct_execution_metadata(&mut file, prev_pc, insn)?;
                if trace_style.preflight_feature_enabled(PreflightFeature::RegisterLatest) {
                    emit_assembly_profile_symbol(
                        &mut file,
                        &format!("ceno_aot_bb_{:08x}_register_latest_commit", block.start_pc),
                    )?;
                    emit_preflight_direct_block_register_access_exit(&mut file, program, block)?;
                }
                emit_assembly_profile_symbol(
                    &mut file,
                    &format!("ceno_aot_bb_{:08x}_plan_commit", block.start_pc),
                )?;
                if block_idx == 0 && aot_native_diagnostic_only() {
                    emit_preflight_plan_commit_diagnostic(
                        &mut file,
                        AOT_PREFLIGHT_HELPER_DIAGNOSTIC_BLOCK_PLAN_ENTRY,
                    )?;
                }
                emit_preflight_direct_block_plan_exit(&mut file, block)?;
                if block_idx == 0 && aot_native_diagnostic_only() {
                    emit_preflight_plan_commit_diagnostic(
                        &mut file,
                        AOT_PREFLIGHT_HELPER_DIAGNOSTIC_BLOCK_PLAN_EXIT,
                    )?;
                }
                emit_assembly_profile_symbol(
                    &mut file,
                    &format!("ceno_aot_bb_{:08x}_guards_exit", block.start_pc),
                )?;
                emit_preflight_direct_busy_loop_guard(&mut file, prev_pc)?;
            } else if adaptive_exact_access_plan {
                if trace_style.preflight_feature_enabled(PreflightFeature::RegisterLatest) {
                    emit_assembly_profile_symbol(
                        &mut file,
                        &format!("ceno_aot_bb_{:08x}_register_latest_commit", block.start_pc),
                    )?;
                    emit_preflight_direct_block_register_access_exit(&mut file, program, block)?;
                }
                emit_assembly_profile_symbol(
                    &mut file,
                    &format!("ceno_aot_bb_{:08x}_plan_commit", block.start_pc),
                )?;
                if block_idx == 0 && aot_native_diagnostic_only() {
                    emit_preflight_plan_commit_diagnostic(
                        &mut file,
                        AOT_PREFLIGHT_HELPER_DIAGNOSTIC_ADAPTIVE_ENTRY,
                    )?;
                }
                emit_preflight_direct_block_plan_exit(&mut file, block)?;
                if block_idx == 0 && aot_native_diagnostic_only() {
                    emit_preflight_plan_commit_diagnostic(
                        &mut file,
                        AOT_PREFLIGHT_HELPER_DIAGNOSTIC_ADAPTIVE_EXIT,
                    )?;
                }
                emit_assembly_profile_symbol(
                    &mut file,
                    &format!("ceno_aot_bb_{:08x}_guards_exit", block.start_pc),
                )?;
                emit_preflight_direct_busy_loop_guard(&mut file, prev_pc)?;
            }
            emit_successor_jump(&mut file, program, &labels, next_block_pc, prev_pc, insn)?;
        }
    }
    if emit_control {
        emit_assembly_profile_symbol(&mut file, "ceno_aot_dynamic_fallback")?;
        emit_global_hidden_symbol(&mut file, "ceno_aot_dynamic")?;
        if trace_style == AssemblyTraceStyle::GpuReplayDirect {
            let fallback_label = ".L_gpu_replay_dynamic_fallback";
            writeln!(file, "    movl %r15d, %eax")?;
            writeln!(file, "    subl ${:#010x}, %eax", program.base_address)?;
            writeln!(file, "    testl $3, %eax")?;
            writeln!(file, "    jne {fallback_label}")?;
            writeln!(
                file,
                "    cmpl ${}, %eax",
                program.instructions.len() * PC_STEP_SIZE
            )?;
            writeln!(file, "    jae {fallback_label}")?;
            writeln!(file, "    shrl $2, %eax")?;
            writeln!(file, "    leaq ceno_aot_gpu_resume_table(%rip), %rdx")?;
            writeln!(file, "    movq (%rdx,%rax,8), %rax")?;
            writeln!(file, "    testq %rax, %rax")?;
            writeln!(file, "    je {fallback_label}")?;
            writeln!(file, "    jmp *%rax")?;
            writeln!(file, "{fallback_label}:")?;
            emit_call_current_pc(&mut file, AOT_FALLBACK_DYNAMIC_PC, trace_style)?;
            writeln!(file, "    jmp ceno_aot_dispatch")?;
        } else {
            emit_call_current_pc(&mut file, AOT_FALLBACK_DYNAMIC_PC, trace_style)?;
            writeln!(file, "    jmp ceno_aot_dispatch")?;
        }
        emit_global_hidden_symbol(&mut file, "ceno_aot_memory_guard")?;
        emit_call_current_pc(&mut file, AOT_FALLBACK_MEMORY_GUARD, trace_style)?;
        writeln!(file, "    jmp ceno_aot_dispatch")?;
        emit_global_hidden_symbol(&mut file, "ceno_aot_exceptional")?;
        emit_call_current_pc(&mut file, AOT_FALLBACK_EXCEPTIONAL, trace_style)?;
        writeln!(file, "    jmp ceno_aot_dispatch")?;
        emit_global_hidden_symbol(&mut file, "ceno_aot_done")?;
        if !trace_style.is_pure() {
            emit_sync_preflight_direct(&mut file)?;
            emit_flush_preflight_event_cursor(&mut file)?;
        }
        writeln!(file, "    movq {AOT_CTX_PC_OFFSET}(%r12), %rdx")?;
        writeln!(file, "    movl %r15d, (%rdx)")?;
        writeln!(file, "    movq 0(%rsp), %rax")?;
        writeln!(file, "    movq 48(%rsp), %rdx")?;
        writeln!(file, "    movq %rax, (%rdx)")?;
        writeln!(file, "    movl ${AOT_STATUS_HALTED}, %eax")?;
        writeln!(file, "    jmp ceno_aot_return")?;
        emit_global_hidden_symbol(&mut file, "ceno_aot_error")?;
        if !trace_style.is_pure() {
            emit_flush_preflight_event_cursor(&mut file)?;
        }
        writeln!(file, "    movq {AOT_CTX_PC_OFFSET}(%r12), %rdx")?;
        writeln!(file, "    movl %r15d, (%rdx)")?;
        writeln!(file, "    movq 0(%rsp), %rax")?;
        writeln!(file, "    movq 48(%rsp), %rdx")?;
        writeln!(file, "    movq %rax, (%rdx)")?;
        writeln!(file, "    movl ${AOT_STATUS_ERROR}, %eax")?;
        emit_global_hidden_symbol(&mut file, "ceno_aot_return")?;
        writeln!(file, "    addq $88, %rsp")?;
        writeln!(file, "    popq %rbp")?;
        writeln!(file, "    popq %r15")?;
        writeln!(file, "    popq %r14")?;
        writeln!(file, "    popq %r13")?;
        writeln!(file, "    popq %r12")?;
        writeln!(file, "    popq %rbx")?;
        writeln!(file, "    ret")?;
        if trace_style == AssemblyTraceStyle::GpuReplayDirect {
            emit_fulltracer_shared_recorder(&mut file)?;
        }
        if trace_style == AssemblyTraceStyle::GpuReplayDirect || trace_style.is_preflight_direct() {
            emit_gpu_replay_shared_recorder(&mut file)?;
        }
        if trace_style == AssemblyTraceStyle::GpuReplayDirect {
            let compiled = blocks
                .iter()
                .flat_map(|block| (block.start_pc..block.end_pc).step_by(PC_STEP_SIZE))
                .collect::<BTreeSet<_>>();
            writeln!(file, ".section .data.rel.ro.local,\"aw\",@progbits")?;
            writeln!(file, ".p2align 3")?;
            writeln!(file, ".hidden ceno_aot_gpu_resume_table")?;
            writeln!(file, "ceno_aot_gpu_resume_table:")?;
            for index in 0..program.instructions.len() {
                let pc = program
                    .base_address
                    .wrapping_add((index * PC_STEP_SIZE) as u32);
                if compiled.contains(&pc) {
                    writeln!(file, "    .quad ceno_aot_gpu_resume_{pc:08x}")?;
                } else {
                    writeln!(file, "    .quad 0")?;
                }
            }
            writeln!(file, ".text")?;
        }
    }
    writeln!(file, ".section .note.GNU-stack,\"\",@progbits")?;
    Ok(())
}

pub(super) fn emit_assembly_profile_symbol(mut file: impl Write, name: &str) -> Result<()> {
    writeln!(file, ".type {name}, @function")?;
    writeln!(file, "{name}:")?;
    Ok(())
}

pub(super) fn emit_global_hidden_symbol(mut file: impl Write, name: &str) -> Result<()> {
    writeln!(file, ".globl {name}")?;
    writeln!(file, ".hidden {name}")?;
    writeln!(file, ".type {name}, @function")?;
    writeln!(file, "{name}:")?;
    Ok(())
}

pub(super) fn emit_dispatch_tree(
    file: &mut impl Write,
    blocks: &[BasicBlock],
    labels: &BTreeMap<u32, String>,
    start: usize,
    end: usize,
) -> Result<()> {
    if start >= end {
        writeln!(file, "    jmp ceno_aot_dynamic")?;
        return Ok(());
    }

    if end - start <= 8 {
        for block in &blocks[start..end] {
            let label = labels.get(&block.start_pc).expect("block label must exist");
            writeln!(file, "    cmpl ${:#010x}, %r15d", block.start_pc)?;
            writeln!(file, "    je {label}")?;
        }
        writeln!(file, "    jmp ceno_aot_dynamic")?;
        return Ok(());
    }

    let mid = start + (end - start) / 2;
    let block = &blocks[mid];
    let label = labels.get(&block.start_pc).expect("block label must exist");
    let lower_label = format!(".L_dispatch_lower_{start}_{end}");

    writeln!(file, "    cmpl ${:#010x}, %r15d", block.start_pc)?;
    writeln!(file, "    jb {lower_label}")?;
    writeln!(file, "    je {label}")?;
    emit_dispatch_tree(file, blocks, labels, mid + 1, end)?;
    writeln!(file, "{lower_label}:")?;
    emit_dispatch_tree(file, blocks, labels, start, mid)?;
    Ok(())
}

pub(super) fn emit_call_one(
    mut file: impl Write,
    pc: u32,
    reason: u32,
    trace_style: AssemblyTraceStyle,
) -> Result<()> {
    if !trace_style.is_pure() {
        emit_sync_preflight_direct(&mut file)?;
        emit_flush_preflight_event_cursor(&mut file)?;
    }
    writeln!(
        file,
        "    movl ${reason}, {AOT_CTX_FALLBACK_REASON_OFFSET}(%r12)"
    )?;
    writeln!(file, "    leaq 8(%rsp), %rdx")?;
    writeln!(file, "    movq %r12, %rdi")?;
    writeln!(file, "    movl ${pc:#010x}, %esi")?;
    writeln!(file, "    call *72(%rsp)")?;
    if trace_style.is_pure() {
        emit_reload_pure_memory_state(&mut file)?;
    } else {
        emit_reload_preflight_event_cursor(&mut file)?;
    }
    emit_after_step(&mut file)?;
    Ok(())
}

pub(super) fn emit_call_current_pc(
    mut file: impl Write,
    reason: u32,
    trace_style: AssemblyTraceStyle,
) -> Result<()> {
    if !trace_style.is_pure() {
        emit_sync_preflight_direct(&mut file)?;
        emit_flush_preflight_event_cursor(&mut file)?;
    }
    writeln!(
        file,
        "    movl ${reason}, {AOT_CTX_FALLBACK_REASON_OFFSET}(%r12)"
    )?;
    writeln!(file, "    leaq 8(%rsp), %rdx")?;
    writeln!(file, "    movq %r12, %rdi")?;
    writeln!(file, "    movl %r15d, %esi")?;
    writeln!(file, "    call *72(%rsp)")?;
    if trace_style.is_pure() {
        emit_reload_pure_memory_state(&mut file)?;
    } else {
        emit_reload_preflight_event_cursor(&mut file)?;
    }
    emit_after_step(&mut file)?;
    Ok(())
}

pub(super) fn emit_after_step(mut file: impl Write) -> Result<()> {
    writeln!(file, "    cmpl ${AOT_STATUS_ERROR}, %eax")?;
    writeln!(file, "    je ceno_aot_error")?;
    writeln!(file, "    incq 0(%rsp)")?;
    writeln!(file, "    movl 8(%rsp), %r15d")?;
    writeln!(file, "    cmpl ${AOT_STATUS_HALTED}, %eax")?;
    writeln!(file, "    je ceno_aot_done")?;
    writeln!(file, "    movq 0(%rsp), %rax")?;
    writeln!(file, "    cmpq %rbp, %rax")?;
    writeln!(file, "    jae ceno_aot_done")?;
    Ok(())
}

pub(super) fn emit_reload_pure_memory_state(mut file: impl Write) -> Result<()> {
    writeln!(file, "    movq {AOT_CTX_MEMORY_CELLS_OFFSET}(%r12), %rbx")?;
    writeln!(
        file,
        "    movl {AOT_CTX_MEMORY_BASE_WORD_OFFSET}(%r12), %r14d"
    )?;
    writeln!(
        file,
        "    movl {AOT_CTX_MEMORY_END_WORD_OFFSET}(%r12), %edx"
    )?;
    writeln!(file, "    subl %r14d, %edx")?;
    writeln!(file, "    shll $2, %r14d")?;
    writeln!(file, "    shll $2, %edx")?;
    writeln!(file, "    movl %edx, 64(%rsp)")?;
    Ok(())
}

pub(super) fn emit_fulltracer_shared_recorder(mut file: impl Write) -> Result<()> {
    writeln!(
        file,
        r#"
.macro FULLTRACER_ACCESS op_offset, previous_offset, subcycle, done_label
    movl %edx, \op_offset(%r10)
    movq {AOT_CTX_FULLTRACER_LATEST_CELLS_OFFSET}(%r12), %r8
    movl %edx, %ecx
    subl {AOT_CTX_FULLTRACER_LATEST_BASE_OFFSET}(%r12), %ecx
    movq (%r8,%rcx,8), %r9
    leaq \subcycle(%rax), %rsi
    movq %rsi, (%r8,%rcx,8)
    movq %r9, \previous_offset(%r10)
    testq %r9, %r9
    jne \done_label
    movq {AOT_CTX_FULLTRACER_LATEST_LEN_OFFSET}(%r12), %r8
    incq (%r8)
\done_label:
.endm

.globl ceno_aot_fulltracer_emit_step
.hidden ceno_aot_fulltracer_emit_step
.type ceno_aot_fulltracer_emit_step, @function
ceno_aot_fulltracer_emit_step:
    movq {AOT_CTX_FULLTRACER_RECORDS_OFFSET}(%r12), %r10
    movq {AOT_CTX_FULLTRACER_PENDING_INDEX_OFFSET}(%r12), %r8
    movq (%r8), %rcx
    imulq $136, %rcx, %r9
    addq %r9, %r10
    movq {AOT_CTX_FULLTRACER_PENDING_CYCLE_OFFSET}(%r12), %r8
    movq (%r8), %rax
    movq %rax, 0(%r10)
    movl {AOT_CTX_TRACE_PC_OFFSET}(%r12), %ecx
    movl %ecx, 8(%r10)
    movl {AOT_CTX_TRACE_NEXT_PC_OFFSET}(%r12), %ecx
    movl %ecx, 12(%r10)
    movq {AOT_CTX_FULLTRACER_MAX_HEAP_OFFSET}(%r12), %r8
    movl (%r8), %ecx
    movl %ecx, 16(%r10)
    movl %ecx, 20(%r10)
    movq {AOT_CTX_FULLTRACER_MAX_HINT_OFFSET}(%r12), %r8
    movl (%r8), %ecx
    movl %ecx, 24(%r10)
    movl %ecx, 28(%r10)

    movl {AOT_CTX_TRACE_PC_OFFSET}(%r12), %ecx
    subl {AOT_CTX_PROGRAM_BASE_OFFSET}(%r12), %ecx
    shrl $2, %ecx
    imulq $12, %rcx, %rcx
    movq {AOT_CTX_INSTRUCTIONS_OFFSET}(%r12), %r8
    addq %rcx, %r8
    movq 0(%r8), %rcx
    movq %rcx, 32(%r10)
    movl 8(%r8), %ecx
    movl %ecx, 40(%r10)
    movl $0, 44(%r10)
    movl $-1, 128(%r10)
    movl $0, 132(%r10)

    movl {AOT_CTX_TRACE_FLAGS_OFFSET}(%r12), %edi
    testl ${NATIVE_TRACE_READ_RS1}, %edi
    je .L_fulltracer_rs1_skip
    movb $1, 44(%r10)
    movl {AOT_CTX_TRACE_RS1_IDX_OFFSET}(%r12), %edx
    shll $6, %edx
    movl {AOT_CTX_TRACE_RS1_VALUE_OFFSET}(%r12), %ecx
    movl %ecx, 52(%r10)
    FULLTRACER_ACCESS 48, 56, 0, .L_fulltracer_rs1_done
.L_fulltracer_rs1_skip:
    testl ${NATIVE_TRACE_READ_RS2}, %edi
    je .L_fulltracer_rs2_skip
    movb $1, 45(%r10)
    movl {AOT_CTX_TRACE_RS2_IDX_OFFSET}(%r12), %edx
    shll $6, %edx
    movl {AOT_CTX_TRACE_RS2_VALUE_OFFSET}(%r12), %ecx
    movl %ecx, 68(%r10)
    FULLTRACER_ACCESS 64, 72, 1, .L_fulltracer_rs2_done
.L_fulltracer_rs2_skip:
    testl ${NATIVE_TRACE_WRITE_RD}, %edi
    je .L_fulltracer_rd_skip
    movb $1, 46(%r10)
    movl {AOT_CTX_TRACE_RD_IDX_OFFSET}(%r12), %edx
    shll $6, %edx
    movl {AOT_CTX_TRACE_RD_BEFORE_OFFSET}(%r12), %ecx
    movl %ecx, 84(%r10)
    movl {AOT_CTX_TRACE_RD_AFTER_OFFSET}(%r12), %ecx
    movl %ecx, 88(%r10)
    FULLTRACER_ACCESS 80, 96, 2, .L_fulltracer_rd_done
.L_fulltracer_rd_skip:
    testl $24, %edi
    je .L_fulltracer_mem_skip
    movb $1, 47(%r10)
    movl {AOT_CTX_TRACE_MEM_ADDR_OFFSET}(%r12), %edx
    movl {AOT_CTX_TRACE_MEM_BEFORE_OFFSET}(%r12), %ecx
    movl %ecx, 108(%r10)
    movl {AOT_CTX_TRACE_MEM_AFTER_OFFSET}(%r12), %ecx
    movl %ecx, 112(%r10)
    movl %edx, 104(%r10)
    movq {AOT_CTX_MEMORY_PREV_STAMP_OFFSET}(%r12), %rcx
    leaq 3(,%rcx,4), %rsi
    testl %ecx, %ecx
    cmovzq %rcx, %rsi
    movq %rsi, 120(%r10)

    leal (,%rdx,4), %esi
    leal 4(%rsi), %ecx
    cmpl {AOT_CTX_HEAP_START_OFFSET}(%r12), %esi
    jb .L_fulltracer_heap_done
    cmpl {AOT_CTX_HEAP_END_OFFSET}(%r12), %esi
    jae .L_fulltracer_heap_done
    movq {AOT_CTX_FULLTRACER_MAX_HEAP_OFFSET}(%r12), %r8
    cmpl (%r8), %ecx
    jbe .L_fulltracer_heap_done
    movl %ecx, (%r8)
.L_fulltracer_heap_done:
    cmpl {AOT_CTX_HINTS_START_OFFSET}(%r12), %esi
    jb .L_fulltracer_hint_done
    cmpl {AOT_CTX_HINTS_END_OFFSET}(%r12), %esi
    jae .L_fulltracer_hint_done
    movq {AOT_CTX_FULLTRACER_MAX_HINT_OFFSET}(%r12), %r8
    cmpl (%r8), %ecx
    jbe .L_fulltracer_hint_done
    movl %ecx, (%r8)
.L_fulltracer_hint_done:
    movq {AOT_CTX_FULLTRACER_MAX_HEAP_OFFSET}(%r12), %r8
    movl (%r8), %ecx
    movl %ecx, 20(%r10)
    movq {AOT_CTX_FULLTRACER_MAX_HINT_OFFSET}(%r12), %r8
    movl (%r8), %ecx
    movl %ecx, 28(%r10)
.L_fulltracer_mem_skip:
    movq {AOT_CTX_FULLTRACER_PENDING_INDEX_OFFSET}(%r12), %r8
    movq (%r8), %rcx
    incq %rcx
    movq %rcx, (%r8)
    movq {AOT_CTX_FULLTRACER_LEN_OFFSET}(%r12), %r8
    movq %rcx, (%r8)
    movq {AOT_CTX_FULLTRACER_PENDING_CYCLE_OFFSET}(%r12), %r8
    addq $4, (%r8)
    movq {AOT_CTX_FULLTRACER_RECORDS_OFFSET}(%r12), %r10
    imulq $136, %rcx, %r9
    addq %r9, %r10
    movq (%r8), %rax
    movq %rax, 0(%r10)
    movl $0, 44(%r10)
    movl $-1, 128(%r10)
    movl $0, 132(%r10)
    ret
"#
    )?;
    writeln!(file, r#""#)?;
    Ok(())
}

pub(super) fn emit_gpu_replay_shared_recorder(mut file: impl Write) -> Result<()> {
    writeln!(
        file,
        r#"
.macro GPU_REPLAY_WRITE field, source
    movq (\field*8)(%r10), %r8
    movl \source, (%r8,%rcx,4)
.endm

.macro GPU_REPLAY_ACCESS index_offset, subcycle, scratch_offset
    movl \index_offset(%r12), %edx
    movq {AOT_CTX_GPU_REPLAY_LATEST_CELLS_OFFSET}(%r12), %r8
    shll $6, %edx
    movl %edx, %r9d
    subl {AOT_CTX_GPU_REPLAY_LATEST_BASE_OFFSET}(%r12), %r9d
    movq (%r8,%r9,8), %r11
    movq %rax, %rsi
    addq $\subcycle, %rsi
    movq %rsi, (%r8,%r9,8)
    movl %r11d, \scratch_offset(%rsp)
    testq %r11, %r11
    jne .L_gpu_replay_access_done_\@
    movq {AOT_CTX_GPU_REPLAY_LATEST_LEN_OFFSET}(%r12), %r8
    incq (%r8)
.L_gpu_replay_access_done_\@:
.endm

.globl ceno_aot_gpu_replay_emit_step
.hidden ceno_aot_gpu_replay_emit_step
.type ceno_aot_gpu_replay_emit_step, @function
ceno_aot_gpu_replay_emit_step:
    subq $48, %rsp
    movl $0, 0(%rsp)
    movl $0, 4(%rsp)
    movl $0, 8(%rsp)
    movl $0, 12(%rsp)
    movl $0, 16(%rsp)

    movl {AOT_CTX_TRACE_KIND_OFFSET}(%r12), %eax
    cmpq {AOT_CTX_GPU_REPLAY_KIND_COUNT_OFFSET}(%r12), %rax
    jae .L_gpu_replay_bad_kind
    imulq $128, %rax, %rax
    movq {AOT_CTX_GPU_REPLAY_KINDS_OFFSET}(%r12), %r10
    addq %rax, %r10
    cmpl ${gpu_sentinel}, 116(%r10)
    je .L_gpu_replay_sentinel_ok
    cmpl ${gpu_compact_sentinel}, 116(%r10)
    jne .L_gpu_replay_bad_sentinel
.L_gpu_replay_sentinel_ok:
    movl 108(%r10), %ecx
    cmpl 104(%r10), %ecx
    jae .L_gpu_replay_capacity
    cmpl $7, 112(%r10)
    ja .L_gpu_replay_bad_layout

    movq {AOT_CTX_GPU_REPLAY_PENDING_CYCLE_OFFSET}(%r12), %r8
    movq (%r8), %rax
    movl {AOT_CTX_TRACE_FLAGS_OFFSET}(%r12), %edi
    testl ${NATIVE_TRACE_READ_RS1}, %edi
    je .L_gpu_replay_rs1_done
    GPU_REPLAY_ACCESS {AOT_CTX_TRACE_RS1_IDX_OFFSET}, 0, 0
.L_gpu_replay_rs1_done:
    testl ${NATIVE_TRACE_READ_RS2}, %edi
    je .L_gpu_replay_rs2_done
    GPU_REPLAY_ACCESS {AOT_CTX_TRACE_RS2_IDX_OFFSET}, 1, 4
.L_gpu_replay_rs2_done:
    testl ${NATIVE_TRACE_WRITE_RD}, %edi
    je .L_gpu_replay_rd_done
    GPU_REPLAY_ACCESS {AOT_CTX_TRACE_RD_IDX_OFFSET}, 2, 8
.L_gpu_replay_rd_done:
    testl $24, %edi
    je .L_gpu_replay_mem_done
    movq {AOT_CTX_MEMORY_PREV_STAMP_OFFSET}(%r12), %r11
    leaq 3(,%r11,4), %rsi
    testl %r11d, %r11d
    cmovzq %r11, %rsi
    movl %esi, 12(%rsp)
    movl {AOT_CTX_TRACE_MEM_ADDR_OFFSET}(%r12), %edx
    leal (,%rdx,4), %esi
    leal 4(%rsi), %r9d
    cmpl {AOT_CTX_HEAP_START_OFFSET}(%r12), %esi
    jb .L_gpu_replay_heap_done
    cmpl {AOT_CTX_HEAP_END_OFFSET}(%r12), %esi
    jae .L_gpu_replay_heap_done
    movq {AOT_CTX_GPU_REPLAY_MAX_HEAP_OFFSET}(%r12), %r8
    cmpl (%r8), %r9d
    jbe .L_gpu_replay_heap_done
    movl %r9d, (%r8)
.L_gpu_replay_heap_done:
    cmpl {AOT_CTX_HINTS_START_OFFSET}(%r12), %esi
    jb .L_gpu_replay_mem_done
    cmpl {AOT_CTX_HINTS_END_OFFSET}(%r12), %esi
    jae .L_gpu_replay_mem_done
    movq {AOT_CTX_GPU_REPLAY_MAX_HINT_OFFSET}(%r12), %r8
    cmpl (%r8), %r9d
    jbe .L_gpu_replay_mem_done
    movl %r9d, (%r8)
.L_gpu_replay_mem_done:

    movq {AOT_CTX_GPU_REPLAY_EVENT_CURSOR_OFFSET}(%r12), %r8
    movq (%r8), %rsi
.L_gpu_replay_event_loop:
    cmpq {AOT_CTX_GPU_REPLAY_EVENTS_LEN_OFFSET}(%r12), %rsi
    jae .L_gpu_replay_events_done
    leaq (%rsi,%rsi,2), %r9
    shlq $3, %r9
    addq {AOT_CTX_GPU_REPLAY_EVENTS_OFFSET}(%r12), %r9
    movq 0(%r9), %r11
    cmpq %rax, %r11
    jb .L_gpu_replay_bad_event
    leaq 4(%rax), %rdx
    cmpq %rdx, %r11
    jae .L_gpu_replay_events_done
    subq %rax, %r11
    movl 16(%r9), %edx
    cmpl $0, %r11d
    je .L_gpu_replay_event_rs1
    cmpl $1, %r11d
    je .L_gpu_replay_event_rs2
    cmpl $2, %r11d
    je .L_gpu_replay_event_rd
    cmpl $3, %r11d
    jne .L_gpu_replay_bad_event
    testl $24, %edi
    je .L_gpu_replay_bad_event
    cmpl {AOT_CTX_TRACE_MEM_ADDR_OFFSET}(%r12), %edx
    jne .L_gpu_replay_bad_event
    jmp .L_gpu_replay_event_match
.L_gpu_replay_event_rs1:
    testl ${NATIVE_TRACE_READ_RS1}, %edi
    je .L_gpu_replay_bad_event
    movl {AOT_CTX_TRACE_RS1_IDX_OFFSET}(%r12), %r9d
    shll $6, %r9d
    cmpl %r9d, %edx
    jne .L_gpu_replay_bad_event
    jmp .L_gpu_replay_event_match
.L_gpu_replay_event_rs2:
    testl ${NATIVE_TRACE_READ_RS2}, %edi
    je .L_gpu_replay_bad_event
    movl {AOT_CTX_TRACE_RS2_IDX_OFFSET}(%r12), %r9d
    shll $6, %r9d
    cmpl %r9d, %edx
    jne .L_gpu_replay_bad_event
    jmp .L_gpu_replay_event_match
.L_gpu_replay_event_rd:
    testl ${NATIVE_TRACE_WRITE_RD}, %edi
    je .L_gpu_replay_bad_event
    movl {AOT_CTX_TRACE_RD_IDX_OFFSET}(%r12), %r9d
    shll $6, %r9d
    cmpl %r9d, %edx
    jne .L_gpu_replay_bad_event
.L_gpu_replay_event_match:
    btsl %r11d, 16(%rsp)
    incq %rsi
    jmp .L_gpu_replay_event_loop
.L_gpu_replay_events_done:
    movq {AOT_CTX_GPU_REPLAY_EVENT_CURSOR_OFFSET}(%r12), %r8
    movq %rsi, (%r8)

    cmpl ${gpu_compact_sentinel}, 116(%r10)
    je .L_gpu_replay_compact

    movq {AOT_CTX_GPU_REPLAY_ORDINAL_OFFSET}(%r12), %r8
    movl (%r8), %edx
    GPU_REPLAY_WRITE 0, %edx
    movl {AOT_CTX_TRACE_PC_OFFSET}(%r12), %edx
    GPU_REPLAY_WRITE 1, %edx
    subl {AOT_CTX_PROGRAM_BASE_OFFSET}(%r12), %edx
    shrl $2, %edx
    imulq $12, %rdx, %rdx
    addq {AOT_CTX_INSTRUCTIONS_OFFSET}(%r12), %rdx
    movl 8(%rdx), %edx
    GPU_REPLAY_WRITE 2, %edx

    movl 112(%r10), %edx
    cmpl $0, %edx
    je .L_gpu_replay_layout_r
    cmpl $1, %edx
    je .L_gpu_replay_layout_i
    cmpl $2, %edx
    je .L_gpu_replay_layout_branch
    cmpl $3, %edx
    je .L_gpu_replay_layout_jal
    cmpl $4, %edx
    je .L_gpu_replay_layout_jalr
    cmpl $5, %edx
    je .L_gpu_replay_layout_load
    cmpl $6, %edx
    je .L_gpu_replay_layout_store
    jmp .L_gpu_replay_layout_u
.L_gpu_replay_layout_r:
    movl 0(%rsp), %edx
    GPU_REPLAY_WRITE 3, %edx
    movl {AOT_CTX_TRACE_RS1_VALUE_OFFSET}(%r12), %edx
    GPU_REPLAY_WRITE 4, %edx
    movl 4(%rsp), %edx
    GPU_REPLAY_WRITE 5, %edx
    movl {AOT_CTX_TRACE_RS2_VALUE_OFFSET}(%r12), %edx
    GPU_REPLAY_WRITE 6, %edx
    movl 8(%rsp), %edx
    GPU_REPLAY_WRITE 7, %edx
    movl {AOT_CTX_TRACE_RD_BEFORE_OFFSET}(%r12), %edx
    GPU_REPLAY_WRITE 8, %edx
    movl {AOT_CTX_TRACE_RD_AFTER_OFFSET}(%r12), %edx
    GPU_REPLAY_WRITE 9, %edx
    movl $10, %edx
    jmp .L_gpu_replay_write_mask
.L_gpu_replay_layout_i:
    movl 0(%rsp), %edx
    GPU_REPLAY_WRITE 3, %edx
    movl {AOT_CTX_TRACE_RS1_VALUE_OFFSET}(%r12), %edx
    GPU_REPLAY_WRITE 4, %edx
    movl 8(%rsp), %edx
    GPU_REPLAY_WRITE 5, %edx
    movl {AOT_CTX_TRACE_RD_BEFORE_OFFSET}(%r12), %edx
    GPU_REPLAY_WRITE 6, %edx
    movl {AOT_CTX_TRACE_RD_AFTER_OFFSET}(%r12), %edx
    GPU_REPLAY_WRITE 7, %edx
    movl $8, %edx
    jmp .L_gpu_replay_write_mask
.L_gpu_replay_layout_branch:
    movl {AOT_CTX_TRACE_NEXT_PC_OFFSET}(%r12), %edx
    GPU_REPLAY_WRITE 3, %edx
    movl 0(%rsp), %edx
    GPU_REPLAY_WRITE 4, %edx
    movl {AOT_CTX_TRACE_RS1_VALUE_OFFSET}(%r12), %edx
    GPU_REPLAY_WRITE 5, %edx
    movl 4(%rsp), %edx
    GPU_REPLAY_WRITE 6, %edx
    movl {AOT_CTX_TRACE_RS2_VALUE_OFFSET}(%r12), %edx
    GPU_REPLAY_WRITE 7, %edx
    movl $8, %edx
    jmp .L_gpu_replay_write_mask
.L_gpu_replay_layout_jal:
    movl {AOT_CTX_TRACE_NEXT_PC_OFFSET}(%r12), %edx
    GPU_REPLAY_WRITE 3, %edx
    movl 8(%rsp), %edx
    GPU_REPLAY_WRITE 4, %edx
    movl {AOT_CTX_TRACE_RD_BEFORE_OFFSET}(%r12), %edx
    GPU_REPLAY_WRITE 5, %edx
    movl {AOT_CTX_TRACE_RD_AFTER_OFFSET}(%r12), %edx
    GPU_REPLAY_WRITE 6, %edx
    movl $7, %edx
    jmp .L_gpu_replay_write_mask
.L_gpu_replay_layout_jalr:
    movl {AOT_CTX_TRACE_NEXT_PC_OFFSET}(%r12), %edx
    GPU_REPLAY_WRITE 3, %edx
    movl 0(%rsp), %edx
    GPU_REPLAY_WRITE 4, %edx
    movl {AOT_CTX_TRACE_RS1_VALUE_OFFSET}(%r12), %edx
    GPU_REPLAY_WRITE 5, %edx
    movl 8(%rsp), %edx
    GPU_REPLAY_WRITE 6, %edx
    movl {AOT_CTX_TRACE_RD_BEFORE_OFFSET}(%r12), %edx
    GPU_REPLAY_WRITE 7, %edx
    movl {AOT_CTX_TRACE_RD_AFTER_OFFSET}(%r12), %edx
    GPU_REPLAY_WRITE 8, %edx
    movl $9, %edx
    jmp .L_gpu_replay_write_mask
.L_gpu_replay_layout_load:
    movl 0(%rsp), %edx
    GPU_REPLAY_WRITE 3, %edx
    movl {AOT_CTX_TRACE_RS1_VALUE_OFFSET}(%r12), %edx
    GPU_REPLAY_WRITE 4, %edx
    movl 8(%rsp), %edx
    GPU_REPLAY_WRITE 5, %edx
    movl {AOT_CTX_TRACE_RD_BEFORE_OFFSET}(%r12), %edx
    GPU_REPLAY_WRITE 6, %edx
    movl {AOT_CTX_TRACE_RD_AFTER_OFFSET}(%r12), %edx
    GPU_REPLAY_WRITE 7, %edx
    movl 12(%rsp), %edx
    GPU_REPLAY_WRITE 8, %edx
    movl {AOT_CTX_TRACE_MEM_ADDR_OFFSET}(%r12), %edx
    GPU_REPLAY_WRITE 9, %edx
    movl {AOT_CTX_TRACE_MEM_BEFORE_OFFSET}(%r12), %edx
    GPU_REPLAY_WRITE 10, %edx
    movl {AOT_CTX_TRACE_MEM_AFTER_OFFSET}(%r12), %edx
    GPU_REPLAY_WRITE 11, %edx
    movl $12, %edx
    jmp .L_gpu_replay_write_mask
.L_gpu_replay_layout_store:
    movl 0(%rsp), %edx
    GPU_REPLAY_WRITE 3, %edx
    movl {AOT_CTX_TRACE_RS1_VALUE_OFFSET}(%r12), %edx
    GPU_REPLAY_WRITE 4, %edx
    movl 4(%rsp), %edx
    GPU_REPLAY_WRITE 5, %edx
    movl {AOT_CTX_TRACE_RS2_VALUE_OFFSET}(%r12), %edx
    GPU_REPLAY_WRITE 6, %edx
    movl 12(%rsp), %edx
    GPU_REPLAY_WRITE 7, %edx
    movl {AOT_CTX_TRACE_MEM_ADDR_OFFSET}(%r12), %edx
    GPU_REPLAY_WRITE 8, %edx
    movl {AOT_CTX_TRACE_MEM_BEFORE_OFFSET}(%r12), %edx
    GPU_REPLAY_WRITE 9, %edx
    movl {AOT_CTX_TRACE_MEM_AFTER_OFFSET}(%r12), %edx
    GPU_REPLAY_WRITE 10, %edx
    movl $11, %edx
    jmp .L_gpu_replay_write_mask
.L_gpu_replay_layout_u:
    movl 0(%rsp), %edx
    GPU_REPLAY_WRITE 3, %edx
    movl 8(%rsp), %edx
    GPU_REPLAY_WRITE 4, %edx
    movl {AOT_CTX_TRACE_RD_BEFORE_OFFSET}(%r12), %edx
    GPU_REPLAY_WRITE 5, %edx
    movl {AOT_CTX_TRACE_RD_AFTER_OFFSET}(%r12), %edx
    GPU_REPLAY_WRITE 6, %edx
    movl $7, %edx
.L_gpu_replay_write_mask:
    movl 16(%rsp), %edi
    shll $8, %edi
    movq (%r10,%rdx,8), %r8
    movl %edi, (%r8,%rcx,4)
    incl %ecx
    movl %ecx, 108(%r10)
    movq {AOT_CTX_GPU_REPLAY_ORDINAL_OFFSET}(%r12), %r8
    incq (%r8)
    movq {AOT_CTX_GPU_REPLAY_PENDING_CYCLE_OFFSET}(%r12), %r8
    addq $4, (%r8)
    movl ${AOT_STATUS_CONTINUE}, %eax
    addq $48, %rsp
    ret

.L_gpu_replay_compact:
    movl 112(%r10), %edx
    cmpl $0, %edx
    je .L_gpu_compact_stride_33
    cmpl $3, %edx
    je .L_gpu_compact_stride_17
    cmpl $7, %edx
    je .L_gpu_compact_stride_21
    cmpl $5, %edx
    je .L_gpu_compact_stride_33
    cmpl $6, %edx
    je .L_gpu_compact_stride_33
    imulq $25, %rcx, %r9
    jmp .L_gpu_compact_pointer
.L_gpu_compact_stride_33:
    imulq $33, %rcx, %r9
    jmp .L_gpu_compact_pointer
.L_gpu_compact_stride_17:
    imulq $17, %rcx, %r9
    jmp .L_gpu_compact_pointer
.L_gpu_compact_stride_21:
    imulq $21, %rcx, %r9
.L_gpu_compact_pointer:
    addq 0(%r10), %r9
    movq {AOT_CTX_GPU_REPLAY_ORDINAL_OFFSET}(%r12), %r8
    movl (%r8), %edx
    subl 120(%r10), %edx
    cmpl $262144, %edx
    jae .L_gpu_replay_bad_compact_range
    movl %edx, 20(%rsp)

    movl {AOT_CTX_TRACE_PC_OFFSET}(%r12), %edx
    testl %ecx, %ecx
    jne .L_gpu_compact_have_pc_base
    movl %edx, %r8d
    andl $0xffc00000, %r8d
    movl %r8d, 124(%r10)
.L_gpu_compact_have_pc_base:
    subl 124(%r10), %edx
    testl $3, %edx
    jne .L_gpu_replay_bad_compact_pc
    cmpl $0x400000, %edx
    jae .L_gpu_replay_bad_compact_pc
    shrl $2, %edx
    movl %edx, 24(%rsp)

    movl {AOT_CTX_TRACE_PC_OFFSET}(%r12), %edx
    subl {AOT_CTX_PROGRAM_BASE_OFFSET}(%r12), %edx
    shrl $2, %edx
    imulq $12, %rdx, %rdx
    addq {AOT_CTX_INSTRUCTIONS_OFFSET}(%r12), %rdx
    movl 8(%rdx), %edx
    shrl $7, %edx
    movl %edx, 28(%rsp)

    movl 112(%r10), %edx
    cmpl $3, %edx
    je .L_gpu_compact_jal_tail
    cmpl $7, %edx
    je .L_gpu_compact_u_first

    movl 0(%rsp), %edx
    movl %edx, 32(%rsp)
    movl {AOT_CTX_TRACE_RS1_VALUE_OFFSET}(%r12), %edx
    movl %edx, 36(%rsp)

    movl 112(%r10), %edx
    cmpl $1, %edx
    je .L_gpu_compact_second_rd
    cmpl $4, %edx
    je .L_gpu_compact_second_rd
    cmpl $5, %edx
    je .L_gpu_compact_second_rd
    movl 4(%rsp), %edx
    movl %edx, 40(%rsp)
    movl {AOT_CTX_TRACE_RS2_VALUE_OFFSET}(%r12), %edx
    movl %edx, 44(%rsp)
    movl 112(%r10), %edx
    cmpl $2, %edx
    je .L_gpu_compact_pack_2
    jmp .L_gpu_compact_third_memory_or_rd

.L_gpu_compact_second_rd:
    movl 8(%rsp), %edx
    movl %edx, 40(%rsp)
    movl {AOT_CTX_TRACE_RD_BEFORE_OFFSET}(%r12), %edx
    movl %edx, 44(%rsp)
    movl 112(%r10), %edx
    cmpl $5, %edx
    jne .L_gpu_compact_pack_2

.L_gpu_compact_third_memory_or_rd:
    movl 112(%r10), %edx
    cmpl $0, %edx
    je .L_gpu_compact_third_rd
    movl 12(%rsp), %edx
    jmp .L_gpu_compact_third_cycle
.L_gpu_compact_third_rd:
    movl 8(%rsp), %edx
.L_gpu_compact_third_cycle:
    movl %edx, 0(%rsp)
    movl 112(%r10), %edx
    cmpl $0, %edx
    jne .L_gpu_compact_third_memory_value
    movl {AOT_CTX_TRACE_RD_BEFORE_OFFSET}(%r12), %edx
    jmp .L_gpu_compact_third_value
.L_gpu_compact_third_memory_value:
    movl {AOT_CTX_TRACE_MEM_BEFORE_OFFSET}(%r12), %edx
.L_gpu_compact_third_value:
    movl %edx, 4(%rsp)
    jmp .L_gpu_compact_pack_3

.L_gpu_compact_jal_tail:
    movl 8(%rsp), %edx
    movl %edx, 32(%rsp)
    movl {AOT_CTX_TRACE_RD_BEFORE_OFFSET}(%r12), %edx
    movl %edx, 36(%rsp)
    jmp .L_gpu_compact_pack_1

.L_gpu_compact_u_tail:
    movl 8(%rsp), %edx
    movl %edx, 40(%rsp)
    movl {AOT_CTX_TRACE_RD_BEFORE_OFFSET}(%r12), %edx
    movl %edx, 44(%rsp)
    jmp .L_gpu_compact_pack_u

.L_gpu_compact_u_first:
    movl 0(%rsp), %edx
    movl %edx, 32(%rsp)
    jmp .L_gpu_compact_u_tail

.L_gpu_compact_pack_3:
    movl 0(%rsp), %edx
    movl 4(%rsp), %esi
    call .L_gpu_compact_pack_common
    movl 40(%rsp), %r8d
    shrl $1, %r8d
    movl 44(%rsp), %r11d
    shlq $31, %r11
    orq %r11, %r8
    movl %edx, %r11d
    andl $1, %r11d
    shlq $63, %r11
    orq %r11, %r8
    movq %r8, 16(%r9)
    shrl $1, %edx
    shlq $31, %rsi
    orq %rsi, %rdx
    movl 16(%rsp), %edi
    cmpl $16, %edi
    jae .L_gpu_replay_bad_compact_mask
    movl %edi, %r8d
    andl $1, %r8d
    shlq $63, %r8
    orq %r8, %rdx
    movq %rdx, 24(%r9)
    shrl $1, %edi
    movb %dil, 32(%r9)
    jmp .L_gpu_compact_commit

.L_gpu_compact_pack_2:
    call .L_gpu_compact_pack_common
    movl 40(%rsp), %r8d
    shrl $1, %r8d
    movl 44(%rsp), %r11d
    shlq $31, %r11
    orq %r11, %r8
    movl 16(%rsp), %edi
    cmpl $16, %edi
    jae .L_gpu_replay_bad_compact_mask
    movl %edi, %r11d
    andl $1, %r11d
    shlq $63, %r11
    orq %r11, %r8
    movq %r8, 16(%r9)
    shrl $1, %edi
    movb %dil, 24(%r9)
    jmp .L_gpu_compact_commit

.L_gpu_compact_pack_1:
    movl 16(%rsp), %edi
    cmpl $16, %edi
    jae .L_gpu_replay_bad_compact_mask
    movl %edi, %eax
    andl $1, %eax
    movl %eax, 40(%rsp)
    call .L_gpu_compact_pack_common
    shrl $1, %edi
    movb %dil, 16(%r9)
    jmp .L_gpu_compact_commit

.L_gpu_compact_pack_u:
    movl 20(%rsp), %r8d
    movl 24(%rsp), %r11d
    shlq $18, %r11
    orq %r11, %r8
    movl 28(%rsp), %r11d
    shlq $38, %r11
    orq %r11, %r8
    movl 32(%rsp), %r11d
    andl $1, %r11d
    shlq $63, %r11
    orq %r11, %r8
    movq %r8, 0(%r9)
    movl 32(%rsp), %r8d
    shrl $1, %r8d
    movl 40(%rsp), %r11d
    shlq $31, %r11
    orq %r11, %r8
    movl 44(%rsp), %r11d
    andl $1, %r11d
    shlq $63, %r11
    orq %r11, %r8
    movq %r8, 8(%r9)
    movl 44(%rsp), %r8d
    shrl $1, %r8d
    movl 16(%rsp), %edi
    cmpl $16, %edi
    jae .L_gpu_replay_bad_compact_mask
    shlq $31, %rdi
    orq %rdi, %r8
    movl %r8d, 16(%r9)
    shrq $32, %r8
    movb %r8b, 20(%r9)
    jmp .L_gpu_compact_commit

// Assemble the common 63-bit prefix and first access into two fixed stores.
// Input access cycle/value live at 32/36(%rsp).
.L_gpu_compact_pack_common:
    movl 28(%rsp), %r8d
    movl 32(%rsp), %r11d
    shlq $18, %r11
    orq %r11, %r8
    movl 36(%rsp), %r11d
    shlq $38, %r11
    orq %r11, %r8
    movl 40(%rsp), %r11d
    andl $1, %r11d
    shlq $63, %r11
    orq %r11, %r8
    movq %r8, 0(%r9)
    movl 40(%rsp), %r8d
    shrl $1, %r8d
    movl 44(%rsp), %r11d
    shlq $31, %r11
    orq %r11, %r8
    movl 48(%rsp), %r11d
    andl $1, %r11d
    shlq $63, %r11
    orq %r11, %r8
    movq %r8, 8(%r9)
    ret

.L_gpu_compact_commit:
    movl 108(%r10), %ecx
    incl %ecx
    movl %ecx, 108(%r10)
    movq {AOT_CTX_GPU_REPLAY_ORDINAL_OFFSET}(%r12), %r8
    incq (%r8)
    movq {AOT_CTX_GPU_REPLAY_PENDING_CYCLE_OFFSET}(%r12), %r8
    addq $4, (%r8)
    movl ${AOT_STATUS_CONTINUE}, %eax
    addq $48, %rsp
    ret

.L_gpu_replay_bad_kind:
    movl $1, %edx
    jmp .L_gpu_replay_error
.L_gpu_replay_bad_sentinel:
    movl $2, %edx
    jmp .L_gpu_replay_error
.L_gpu_replay_capacity:
    movl $3, %edx
    jmp .L_gpu_replay_error
.L_gpu_replay_bad_layout:
    movl $4, %edx
    jmp .L_gpu_replay_error
.L_gpu_replay_bad_event:
    movl $5, %edx
    jmp .L_gpu_replay_error
.L_gpu_replay_bad_compact_range:
    movl $6, %edx
    jmp .L_gpu_replay_error
.L_gpu_replay_bad_compact_pc:
    movl $7, %edx
    jmp .L_gpu_replay_error
.L_gpu_replay_bad_compact_cycle:
    movl $8, %edx
    jmp .L_gpu_replay_error
.L_gpu_replay_bad_compact_mask:
    movl $9, %edx
.L_gpu_replay_error:
    movl {AOT_CTX_TRACE_KIND_OFFSET}(%r12), %r11d
    shll $8, %r11d
    orl %r11d, %edx
    movq {AOT_CTX_GPU_REPLAY_ERROR_OFFSET}(%r12), %r8
    movl %edx, (%r8)
    movl ${AOT_STATUS_ERROR}, %eax
    addq $48, %rsp
    ret
"#,
        gpu_sentinel = crate::gpu_typed_ingress::GPU_TYPED_NATIVE_SENTINEL,
        gpu_compact_sentinel = crate::gpu_typed_ingress::GPU_COMPACT_NATIVE_SENTINEL,
    )?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(super) fn emit_after_native_step(
    mut file: impl Write,
    pc: u32,
    program: &Program,
    insn: Instruction,
    trace_style: AssemblyTraceStyle,
    preflight_memory_bounds_updated: bool,
    preflight_memory_event_updated: bool,
    reserved_block_step: Option<ReservedBlockStep>,
) -> Result<()> {
    if matches!(
        trace_style,
        AssemblyTraceStyle::PureBlock | AssemblyTraceStyle::PureCountedBlock
    ) {
        return Ok(());
    }
    if trace_style.is_pure() {
        writeln!(file, "    incq 0(%rsp)")?;
        writeln!(file, "    movq 0(%rsp), %rax")?;
        writeln!(file, "    cmpq %rbp, %rax")?;
        writeln!(file, "    jae ceno_aot_done")?;
        return Ok(());
    }

    if trace_style.is_preflight_direct() {
        let batched_block =
            reserved_block_step.is_some() && trace_style.uses_preflight_block_plan();
        if !batched_block {
            writeln!(file, "    movl {AOT_CTX_TRACE_NEXT_PC_OFFSET}(%r12), %r15d")?;
            writeln!(file, "    movl %r15d, 8(%rsp)")?;
        }
        emit_preflight_direct_step_static(
            &mut file,
            pc,
            insn,
            preflight_memory_bounds_updated,
            preflight_memory_event_updated,
            if trace_style.uses_preflight_block_plan() {
                PreflightAccessMode::BlockAtomic
            } else {
                PreflightAccessMode::Exact
            },
            matches!(trace_style, AssemblyTraceStyle::PreflightScalar),
            reserved_block_step.map(|step| step.cycle_offset),
            trace_style,
        )?;
        if !batched_block {
            emit_after_step(&mut file)?;
        }
        return Ok(());
    }

    if trace_style == AssemblyTraceStyle::GpuReplayDirect {
        let callback_label = format!(".L_fulltracer_callback_{pc:x}");
        let fulltracer_label = format!(".L_fulltracer_direct_{pc:x}");
        let gpu_replay_label = format!(".L_gpu_replay_direct_{pc:x}");
        let done_label = format!(".L_fulltracer_direct_done_{pc:x}");
        writeln!(file, "    movl {AOT_CTX_TRACE_NEXT_PC_OFFSET}(%r12), %r15d")?;
        writeln!(file, "    movl %r15d, 8(%rsp)")?;
        writeln!(
            file,
            "    cmpl ${AOT_TRACE_MODE_FULLTRACER_DIRECT}, {AOT_CTX_TRACE_MODE_OFFSET}(%r12)"
        )?;
        writeln!(file, "    je {fulltracer_label}")?;
        if trace_style == AssemblyTraceStyle::GpuReplayDirect {
            writeln!(
                file,
                "    cmpl ${AOT_TRACE_MODE_GPU_REPLAY_DIRECT}, {AOT_CTX_TRACE_MODE_OFFSET}(%r12)"
            )?;
            writeln!(file, "    je {gpu_replay_label}")?;
        }
        writeln!(file, "    jmp {callback_label}")?;
        writeln!(file, "{fulltracer_label}:")?;
        emit_native_trace_metadata(&mut file, pc, program, insn)?;
        writeln!(file, "    call ceno_aot_fulltracer_emit_step")?;
        writeln!(file, "    movl ${AOT_STATUS_CONTINUE}, %eax")?;
        writeln!(file, "    jmp {done_label}")?;
        writeln!(file, "{gpu_replay_label}:")?;
        emit_native_trace_metadata(&mut file, pc, program, insn)?;
        writeln!(file, "    call ceno_aot_gpu_replay_emit_step")?;
        writeln!(file, "    jmp {done_label}")?;
        writeln!(file, "{callback_label}:")?;
        emit_native_trace_metadata(&mut file, pc, program, insn)?;
        writeln!(file, "    movq %r12, %rdi")?;
        writeln!(file, "    call *%r14")?;
        writeln!(file, "{done_label}:")?;
        emit_after_step(&mut file)?;
        return Ok(());
    }

    let no_trace_label = format!(".L_after_native_no_trace_{pc:x}");
    let direct_label = format!(".L_after_native_direct_{pc:x}");
    let callback_label = format!(".L_after_native_callback_{pc:x}");
    let done_label = format!(".L_after_native_done_{pc:x}");
    writeln!(file, "    movl {AOT_CTX_TRACE_NEXT_PC_OFFSET}(%r12), %r15d")?;
    writeln!(file, "    movl %r15d, 8(%rsp)")?;
    writeln!(file, "    testq %r14, %r14")?;
    writeln!(file, "    je {no_trace_label}")?;
    writeln!(
        file,
        "    cmpl ${AOT_TRACE_MODE_PREFLIGHT_DIRECT}, {AOT_CTX_TRACE_MODE_OFFSET}(%r12)"
    )?;
    writeln!(file, "    je {direct_label}")?;
    writeln!(file, "    jmp {callback_label}")?;
    writeln!(file, "{callback_label}:")?;
    emit_native_trace_metadata(&mut file, pc, program, insn)?;
    writeln!(file, "    movq %r12, %rdi")?;
    emit_flush_preflight_event_cursor(&mut file)?;
    writeln!(file, "    call *%r14")?;
    emit_reload_preflight_event_cursor(&mut file)?;
    writeln!(file, "    jmp {done_label}")?;
    writeln!(file, "{no_trace_label}:")?;
    writeln!(file, "    movl ${AOT_STATUS_CONTINUE}, %eax")?;
    writeln!(file, "    jmp {done_label}")?;
    writeln!(file, "{direct_label}:")?;
    emit_preflight_direct_step_static(
        &mut file,
        pc,
        insn,
        false,
        false,
        PreflightAccessMode::Exact,
        true,
        None,
        AssemblyTraceStyle::PreflightScalar,
    )?;
    writeln!(file, "{done_label}:")?;
    emit_after_step(&mut file)?;
    Ok(())
}

pub(super) fn emit_sync_preflight_direct(mut file: impl Write) -> Result<()> {
    writeln!(
        file,
        "    cmpl ${AOT_TRACE_MODE_PREFLIGHT_DIRECT}, {AOT_CTX_TRACE_MODE_OFFSET}(%r12)"
    )?;
    writeln!(file, "    jne 1f")?;
    writeln!(
        file,
        "    cmpq $0, {AOT_CTX_PREFLIGHT_PENDING_STEPS_OFFSET}(%r12)"
    )?;
    writeln!(file, "    je 1f")?;
    writeln!(
        file,
        "    movl ${AOT_PREFLIGHT_HELPER_SYNC}, {AOT_CTX_PREFLIGHT_HELPER_KIND_OFFSET}(%r12)"
    )?;
    writeln!(file, "    movq %r12, %rdi")?;
    emit_flush_preflight_event_cursor(&mut file)?;
    writeln!(file, "    call *%r14")?;
    emit_reload_preflight_event_cursor(&mut file)?;
    writeln!(file, "    cmpl ${AOT_STATUS_ERROR}, %eax")?;
    writeln!(file, "    je ceno_aot_error")?;
    writeln!(file, "1:")?;
    Ok(())
}

pub(super) fn emit_flush_preflight_event_cursor(mut file: impl Write) -> Result<()> {
    writeln!(
        file,
        "    movq %rbx, {AOT_CTX_PREFLIGHT_EVENT_CURSOR_OFFSET}(%r12)"
    )?;
    writeln!(
        file,
        "    movq 56(%rsp), %rax\n    movq %rax, {AOT_CTX_PREFLIGHT_REGISTER_TOUCHED_MASK_OFFSET}(%r12)"
    )?;
    Ok(())
}

pub(super) fn emit_reload_preflight_event_cursor(mut file: impl Write) -> Result<()> {
    writeln!(
        file,
        "    movq {AOT_CTX_PREFLIGHT_EVENT_CURSOR_OFFSET}(%r12), %rbx"
    )?;
    writeln!(
        file,
        "    movq {AOT_CTX_PREFLIGHT_REGISTER_TOUCHED_MASK_OFFSET}(%r12), %rcx\n    movq %rcx, 56(%rsp)"
    )?;
    Ok(())
}

pub(super) fn block_instruction_count(block: &BasicBlock) -> u64 {
    ((block.end_pc - block.start_pc) / PC_STEP_SIZE as u32) as u64
}

#[derive(Clone, Copy)]
pub(super) struct ReservedBlockStep {
    remaining_after: u64,
    cycle_offset: u64,
    memory_guard_hoisted: bool,
    memory_region_index: Option<usize>,
    registers_resident: bool,
    memory_cells_resident: bool,
    memory_ordinal_resident: bool,
}

#[derive(Clone, Copy)]
pub(super) enum PreflightAccessMode {
    Exact,
    BlockAtomic,
}

#[derive(Clone, Copy)]
pub(super) struct PreflightBlockAccess {
    addr: u32,
    cycle_offset: u64,
}

#[derive(Clone, Copy)]
pub(super) struct PreflightMemoryGuardAccess {
    pc: u32,
    insn: Instruction,
    region_index: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum PreflightBlockPlanKind {
    RegisterOnly,
    MemoryExactAccess,
}

#[cfg(test)]
pub(super) fn block_supports_preflight_block_plan(
    program: &Program,
    block: &BasicBlock,
) -> Result<bool> {
    Ok(matches!(
        preflight_block_plan_kind(program, block)?,
        Some(PreflightBlockPlanKind::RegisterOnly)
    ))
}

pub(super) fn preflight_block_plan_kind(
    program: &Program,
    block: &BasicBlock,
) -> Result<Option<PreflightBlockPlanKind>> {
    let mut has_memory = false;
    let mut written_regs = BTreeSet::new();
    let mut pc = block.start_pc;
    while pc < block.end_pc {
        let insn = instruction_at(program, pc)?;
        match native_opcode_family(insn.kind) {
            Some(NativeOpcodeFamily::Compute) => {}
            Some(NativeOpcodeFamily::ControlFlow) => {
                if matches!(insn.kind, InsnKind::JALR) {
                    return Ok(None);
                }
            }
            Some(NativeOpcodeFamily::Memory) => {
                has_memory = true;
                if written_regs.contains(&insn.rs1) {
                    return Ok(None);
                }
            }
            None => return Ok(None),
        }
        if native_step_writes_rd(insn.kind) {
            written_regs.insert(insn.rd_internal() as RegIdx);
        }
        pc = pc.wrapping_add(PC_STEP_SIZE as u32);
    }
    Ok(Some(if has_memory {
        PreflightBlockPlanKind::MemoryExactAccess
    } else {
        PreflightBlockPlanKind::RegisterOnly
    }))
}

/// Adaptive costing depends only on the statically known opcode mix. Blocks
/// whose memory address is computed inside the block can therefore retain
/// exact per-step access tracking while still using a block-entry cost guard.
/// Truly dynamic control flow and unsupported instructions stay on the Rust
/// fallback path.
pub(super) fn block_supports_adaptive_cost_plan(
    program: &Program,
    block: &BasicBlock,
) -> Result<bool> {
    let mut pc = block.start_pc;
    while pc < block.end_pc {
        let insn = instruction_at(program, pc)?;
        if native_opcode_family(insn.kind).is_none() {
            return Ok(false);
        }
        pc = pc.wrapping_add(PC_STEP_SIZE as u32);
    }
    Ok(true)
}

pub(super) fn preflight_static_register_accesses(
    insn: Instruction,
) -> Vec<(u32, PreflightSubcycle)> {
    let mut accesses = Vec::new();
    if native_step_reads_rs1(insn.kind) {
        accesses.push((insn.rs1 as u32, PreflightSubcycle::Rs1));
    }
    if native_step_reads_rs2(insn.kind) {
        accesses.push((insn.rs2 as u32, PreflightSubcycle::Rs2));
    }
    if native_step_writes_rd(insn.kind) {
        accesses.push((insn.rd_internal(), PreflightSubcycle::Rd));
    }
    accesses
}

pub(super) fn preflight_register_bit(reg_idx: u32) -> u64 {
    1u64 << reg_idx
}

pub(super) fn initial_preflight_register_touched_mask(
    latest_cells: *const Cycle,
    current_shard_start: *const Cycle,
) -> (u64, Cycle) {
    if latest_cells.is_null() || current_shard_start.is_null() {
        return (0, 0);
    }
    let shard_start = unsafe { *current_shard_start };
    let mut mask = 0u64;
    for reg_idx in 0..VMState::<PreflightTracer>::REG_COUNT as u32 {
        let addr = reg_idx << 6;
        let cycle = unsafe { *latest_cells.add(addr as usize) };
        if cycle != 0 && cycle >= shard_start {
            mask |= preflight_register_bit(reg_idx);
        }
    }
    (mask, shard_start)
}

pub(super) fn preflight_block_first_accesses(
    program: &Program,
    block: &BasicBlock,
) -> Result<Vec<PreflightBlockAccess>> {
    let mut first_accesses = BTreeMap::new();
    let mut pc = block.start_pc;
    while pc < block.end_pc {
        let insn = instruction_at(program, pc)?;
        let insn_cycle_offset = (pc - block.start_pc) as u64;
        for (reg_idx, subcycle) in preflight_static_register_accesses(insn) {
            let addr = reg_idx << 6;
            first_accesses
                .entry(addr)
                .or_insert(insn_cycle_offset + subcycle.value());
        }
        pc = pc.wrapping_add(PC_STEP_SIZE as u32);
    }
    Ok(first_accesses
        .into_iter()
        .map(|(addr, cycle_offset)| PreflightBlockAccess { addr, cycle_offset })
        .collect())
}

pub(super) fn preflight_block_last_accesses(
    program: &Program,
    block: &BasicBlock,
) -> Result<Vec<PreflightBlockAccess>> {
    let mut last_accesses = BTreeMap::new();
    let mut pc = block.start_pc;
    while pc < block.end_pc {
        let insn = instruction_at(program, pc)?;
        let insn_cycle_offset = (pc - block.start_pc) as u64;
        for (reg_idx, subcycle) in preflight_static_register_accesses(insn) {
            last_accesses.insert(reg_idx << 6, insn_cycle_offset + subcycle.value());
        }
        pc = pc.wrapping_add(PC_STEP_SIZE as u32);
    }
    Ok(last_accesses
        .into_iter()
        .map(|(addr, cycle_offset)| PreflightBlockAccess { addr, cycle_offset })
        .collect())
}

pub(super) fn build_aot_block_kind_histograms(
    program: &Program,
    blocks: &[BasicBlock],
) -> Result<Vec<AotBlockKindHistogram>> {
    blocks
        .iter()
        .map(|block| {
            let instruction_offset =
                usize::try_from((block.start_pc - program.base_address) / PC_STEP_SIZE as u32)?;
            let instruction_count = usize::try_from(block_instruction_count(block))?;
            let instructions = program
                .instructions
                .get(instruction_offset..instruction_offset + instruction_count)
                .ok_or_else(|| anyhow!("AOT block instruction range is out of bounds"))?;
            let mut counts = [0u32; InsnKind::COUNT];
            for instruction in instructions {
                counts[instruction.kind as usize] = counts[instruction.kind as usize]
                    .checked_add(1)
                    .ok_or_else(|| anyhow!("AOT block kind histogram overflow"))?;
            }
            Ok(AotBlockKindHistogram {
                counts,
                instruction_offset: u32::try_from(instruction_offset)?,
                instruction_count: u32::try_from(instruction_count)?,
            })
        })
        .collect()
}

pub(super) fn build_aot_block_cost_descriptors(
    program: &Program,
    blocks: &[BasicBlock],
    model: &ShardCostModel,
) -> Result<AotPlannerMetadata> {
    let mut descriptors = Vec::with_capacity(blocks.len());
    let mut contributions = Vec::new();
    let mut counts = vec![0u64; model.chip_count()];
    for block in blocks {
        let offset = contributions.len();
        // Compilation/setup only: a dense chip-indexed array avoids sorting
        // and guarantees stable descriptor order. Execution touches only the
        // resulting sparse descriptor, never a map.
        counts.fill(0);
        let mut pc = block.start_pc;
        while pc < block.end_pc {
            let insn = instruction_at(program, pc)?;
            for &chip in model.chips_for_step(insn.kind, None) {
                let chip = chip as usize;
                counts[chip] = counts[chip].saturating_add(1);
            }
            pc = pc.wrapping_add(PC_STEP_SIZE as u32);
        }
        let mut standalone_trace_cells = 0u64;
        let mut standalone_main_peak = 0u64;
        let mut standalone_tower_peak = 0u64;
        for (chip, &count) in counts.iter().enumerate().filter(|(_, count)| **count != 0) {
            let cost = model.chip_cost(chip, count);
            standalone_trace_cells = standalone_trace_cells.saturating_add(cost.trace_cells);
            standalone_main_peak = standalone_main_peak.saturating_add(cost.main_peak);
            standalone_tower_peak = standalone_tower_peak.max(cost.tower_peak);
            contributions.push(AotChipContribution {
                chip_index: chip as u32,
                cost_row_byte_offset: (chip
                    * SHARD_COST_BUCKETS
                    * std::mem::size_of::<AotAdditiveCost>())
                    as u32,
                instance_delta: count,
            });
        }
        descriptors.push(AotBlockCostDescriptor {
            contribution_offset: offset as u32,
            contribution_count: (contributions.len() - offset) as u32,
            standalone_trace_cells,
            standalone_main_peak,
            standalone_tower_peak,
        });
    }
    Ok(AotPlannerMetadata {
        descriptors,
        contributions,
    })
}

pub(super) fn emit_preflight_direct_block_budget_guard(
    mut file: impl Write,
    block: &BasicBlock,
) -> Result<()> {
    let block_steps = block_instruction_count(block);
    writeln!(file, "    movq 0(%rsp), %rax")?;
    writeln!(file, "    addq ${block_steps}, %rax")?;
    writeln!(file, "    cmpq %rbp, %rax")?;
    writeln!(file, "    ja ceno_aot_exceptional")?;
    Ok(())
}

pub(super) fn emit_pure_block_budget_guard(mut file: impl Write, block: &BasicBlock) -> Result<()> {
    let block_steps = block_instruction_count(block);
    writeln!(file, "    movq 0(%rsp), %rax")?;
    writeln!(file, "    addq ${block_steps}, %rax")?;
    writeln!(file, "    cmpq %rbp, %rax")?;
    // If the limit ends inside this block, execute one exact fallback step and
    // dispatch again. This preserves the existing instruction-limit contract.
    writeln!(file, "    ja ceno_aot_exceptional")?;
    Ok(())
}

pub(super) fn emit_rollback_reserved_block_steps(
    mut file: impl Write,
    reserved_step: Option<ReservedBlockStep>,
) -> Result<()> {
    if let Some(step) = reserved_step {
        writeln!(file, "    subq ${}, 0(%rsp)", step.remaining_after + 1)?;
    }
    Ok(())
}

pub(super) fn emit_restore_reserved_block_steps(
    mut file: impl Write,
    reserved_step: Option<ReservedBlockStep>,
) -> Result<()> {
    if let Some(step) = reserved_step.filter(|step| step.remaining_after != 0) {
        writeln!(file, "    addq ${}, 0(%rsp)", step.remaining_after)?;
    }
    Ok(())
}

pub(super) fn emit_pure_block_memory_fast_path_guard(
    mut file: impl Write,
    program: &Program,
    block: &BasicBlock,
) -> Result<()> {
    let mut pc = block.start_pc;
    while pc < block.end_pc {
        let insn = instruction_at(program, pc)?;
        if native_opcode_family(insn.kind) == Some(NativeOpcodeFamily::Memory) {
            writeln!(file, "    movl {}(%r13), %eax", insn.rs1 as usize * 4)?;
            writeln!(file, "    leal {}(%rax), %edx", insn.imm)?;
            match insn.kind {
                InsnKind::LH | InsnKind::LHU | InsnKind::SH => {
                    writeln!(file, "    testl $1, %edx")?;
                    writeln!(file, "    jne ceno_aot_memory_guard")?;
                }
                InsnKind::LW | InsnKind::SW => {
                    writeln!(file, "    testl $3, %edx")?;
                    writeln!(file, "    jne ceno_aot_memory_guard")?;
                }
                _ => {}
            }
            writeln!(file, "    subl %r14d, %edx")?;
            writeln!(file, "    cmpl 64(%rsp), %edx")?;
            writeln!(file, "    jae ceno_aot_memory_guard")?;
        }
        pc = pc.wrapping_add(PC_STEP_SIZE as u32);
    }
    Ok(())
}

pub(super) fn preflight_block_event_capacity(
    program: &Program,
    block: &BasicBlock,
    access_mode: PreflightAccessMode,
) -> Result<usize> {
    let mut memory_accesses = 0usize;
    let mut exact_register_accesses = 0usize;
    let mut pc = block.start_pc;
    while pc < block.end_pc {
        let insn = instruction_at(program, pc)?;
        exact_register_accesses += preflight_static_register_accesses(insn).len();
        memory_accesses += usize::from(
            native_step_loads_memory(insn.kind) || native_step_stores_memory(insn.kind),
        );
        pc = pc.wrapping_add(PC_STEP_SIZE as u32);
    }
    Ok(memory_accesses
        + match access_mode {
            PreflightAccessMode::Exact => exact_register_accesses,
            PreflightAccessMode::BlockAtomic => {
                preflight_block_first_accesses(program, block)?.len()
            }
        })
}

pub(super) fn preflight_block_memory_access_count(
    program: &Program,
    block: &BasicBlock,
) -> Result<usize> {
    let mut count = 0usize;
    let mut pc = block.start_pc;
    while pc < block.end_pc {
        let insn = instruction_at(program, pc)?;
        count += usize::from(
            native_step_loads_memory(insn.kind) || native_step_stores_memory(insn.kind),
        );
        pc = pc.wrapping_add(PC_STEP_SIZE as u32);
    }
    Ok(count)
}

pub(super) fn emit_preflight_direct_block_event_capacity_guard(
    mut file: impl Write,
    program: &Program,
    block_idx: usize,
    block: &BasicBlock,
    access_mode: PreflightAccessMode,
) -> Result<()> {
    let event_capacity = preflight_block_event_capacity(program, block, access_mode)?;
    if event_capacity == 0 {
        return Ok(());
    }
    writeln!(file, ".L_preflight_block_capacity_retry_{block_idx}:")?;
    writeln!(file, "    leaq {}(%rbx), %rax", event_capacity * 24)?;
    writeln!(
        file,
        "    cmpq {AOT_CTX_PREFLIGHT_EVENT_END_OFFSET}(%r12), %rax"
    )?;
    writeln!(file, "    jbe .L_preflight_block_capacity_ok_{block_idx}")?;
    emit_flush_preflight_event_cursor(&mut file)?;
    writeln!(
        file,
        "    movl ${AOT_PREFLIGHT_HELPER_GROW_TAPE}, {AOT_CTX_PREFLIGHT_HELPER_KIND_OFFSET}(%r12)"
    )?;
    writeln!(file, "    movq %r12, %rdi")?;
    writeln!(file, "    call *%r14")?;
    writeln!(file, "    cmpl ${AOT_STATUS_ERROR}, %eax")?;
    writeln!(file, "    je ceno_aot_error")?;
    emit_reload_preflight_event_cursor(&mut file)?;
    writeln!(
        file,
        "    jmp .L_preflight_block_capacity_retry_{block_idx}"
    )?;
    writeln!(file, ".L_preflight_block_capacity_ok_{block_idx}:")?;
    Ok(())
}

pub(super) fn emit_preflight_direct_block_memory_fast_path_guard(
    mut file: impl Write,
    program: &Program,
    block: &BasicBlock,
    record_regions: bool,
) -> Result<()> {
    writeln!(file, "    movq %r13, %r10")?;
    if record_regions {
        writeln!(file, "    xorq %r11, %r11")?;
    }
    let mut accesses = Vec::new();
    let mut pc = block.start_pc;
    let mut memory_access_index = 0usize;
    while pc < block.end_pc {
        let insn = instruction_at(program, pc)?;
        if matches!(
            native_opcode_family(insn.kind),
            Some(NativeOpcodeFamily::Memory)
        ) {
            accesses.push(PreflightMemoryGuardAccess {
                pc,
                insn,
                region_index: memory_access_index,
            });
            memory_access_index += 1;
        }
        pc = pc.wrapping_add(PC_STEP_SIZE as u32);
    }

    let mut word_groups = BTreeMap::<(u8, u32), Vec<PreflightMemoryGuardAccess>>::new();
    for access in &accesses {
        if matches!(access.insn.kind, InsnKind::LW | InsnKind::SW) {
            word_groups
                .entry((access.insn.rs1, access.insn.imm as u32 & 3))
                .or_default()
                .push(*access);
        }
    }
    let grouped_indices = word_groups
        .values()
        .filter(|group| group.len() >= 2)
        .flat_map(|group| group.iter().map(|access| access.region_index))
        .collect::<BTreeSet<_>>();
    for (group_index, group) in word_groups
        .values()
        .filter(|group| group.len() >= 2)
        .enumerate()
    {
        emit_preflight_direct_memory_fast_path_group_guard(
            &mut file,
            block.start_pc,
            group_index,
            group,
            record_regions,
        )?;
    }
    for access in accesses {
        if grouped_indices.contains(&access.region_index) {
            continue;
        }
        emit_preflight_direct_memory_fast_path_guard(
            &mut file,
            access.pc,
            access.insn,
            record_regions.then_some(access.region_index),
        )?;
    }
    if record_regions {
        writeln!(file, "    movq %r11, 64(%rsp)")?;
    }
    Ok(())
}

pub(super) fn emit_preflight_direct_memory_fast_path_group_guard(
    mut file: impl Write,
    block_pc: u32,
    group_index: usize,
    accesses: &[PreflightMemoryGuardAccess],
    record_regions: bool,
) -> Result<()> {
    debug_assert!(accesses.len() >= 2);
    debug_assert!(
        accesses
            .iter()
            .all(|access| matches!(access.insn.kind, InsnKind::LW | InsnKind::SW))
    );
    let rs1 = accesses[0].insn.rs1;
    debug_assert!(accesses.iter().all(|access| access.insn.rs1 == rs1));
    let min_imm = accesses.iter().map(|access| access.insn.imm).min().unwrap();
    let max_imm = accesses.iter().map(|access| access.insn.imm).max().unwrap();
    let heap_ok_label = format!(".L_block_memory_group_heap_ok_{block_pc:x}_{group_index}");
    let stack_ok_label = format!(".L_block_memory_group_stack_ok_{block_pc:x}_{group_index}");
    let hints_ok_label = format!(".L_block_memory_group_hints_ok_{block_pc:x}_{group_index}");
    let done_label = format!(".L_block_memory_group_done_{block_pc:x}_{group_index}");

    writeln!(file, "    movl {}(%r10), %eax", rs1 as usize * 4)?;
    writeln!(file, "    leal {min_imm}(%rax), %edx")?;
    writeln!(file, "    testl $3, %edx")?;
    writeln!(file, "    jne ceno_aot_memory_guard")?;
    writeln!(file, "    leal {max_imm}(%rax), %ecx")?;
    // If the affine interval wraps the 32-bit guest address space, use the
    // scalar guard for the whole block.
    writeln!(file, "    cmpl %edx, %ecx")?;
    writeln!(file, "    jb ceno_aot_memory_guard")?;
    for (start_offset, end_offset, label) in [
        (
            AOT_CTX_HEAP_START_OFFSET,
            AOT_CTX_HEAP_END_OFFSET,
            &heap_ok_label,
        ),
        (
            AOT_CTX_STACK_START_OFFSET,
            AOT_CTX_STACK_END_OFFSET,
            &stack_ok_label,
        ),
        (
            AOT_CTX_HINTS_START_OFFSET,
            AOT_CTX_HINTS_END_OFFSET,
            &hints_ok_label,
        ),
    ] {
        writeln!(file, "    cmpl {start_offset}(%r12), %edx")?;
        writeln!(file, "    jb 1f")?;
        writeln!(file, "    cmpl {end_offset}(%r12), %ecx")?;
        writeln!(file, "    jb {label}")?;
        writeln!(file, "1:")?;
    }
    writeln!(file, "    shrl $2, %edx")?;
    writeln!(file, "    shrl $2, %ecx")?;
    writeln!(
        file,
        "    cmpl {AOT_CTX_MEMORY_BASE_WORD_OFFSET}(%r12), %edx"
    )?;
    writeln!(file, "    jb ceno_aot_memory_guard")?;
    writeln!(
        file,
        "    cmpl {AOT_CTX_MEMORY_END_WORD_OFFSET}(%r12), %ecx"
    )?;
    writeln!(file, "    jb {done_label}")?;
    writeln!(file, "    jmp ceno_aot_memory_guard")?;

    for (label, region) in [
        (&heap_ok_label, 1u64),
        (&stack_ok_label, 2u64),
        (&hints_ok_label, 3u64),
    ] {
        writeln!(file, "{label}:")?;
        if record_regions {
            let mask = accesses.iter().fold(0u64, |mask, access| {
                mask | (region << (access.region_index * 2))
            });
            writeln!(file, "    movabsq ${mask:#018x}, %rdi")?;
            writeln!(file, "    orq %rdi, %r11")?;
        }
        writeln!(file, "    jmp {done_label}")?;
    }
    writeln!(file, "{done_label}:")?;
    Ok(())
}

pub(super) fn emit_preflight_direct_memory_fast_path_guard(
    mut file: impl Write,
    pc: u32,
    insn: Instruction,
    region_index: Option<usize>,
) -> Result<()> {
    let heap_ok_label = format!(".L_block_memory_heap_ok_{pc:x}");
    let stack_ok_label = format!(".L_block_memory_stack_ok_{pc:x}");
    let hints_ok_label = format!(".L_block_memory_hints_ok_{pc:x}");
    let done_label = format!(".L_block_memory_guard_done_{pc:x}");

    writeln!(file, "    movl {}(%r10), %eax", insn.rs1 as usize * 4)?;
    writeln!(file, "    leal {}(%rax), %edx", insn.imm)?;
    match insn.kind {
        InsnKind::LH | InsnKind::LHU | InsnKind::SH => {
            writeln!(file, "    testl $1, %edx")?;
            writeln!(file, "    jne ceno_aot_memory_guard")?;
        }
        InsnKind::LW | InsnKind::SW => {
            writeln!(file, "    testl $3, %edx")?;
            writeln!(file, "    jne ceno_aot_memory_guard")?;
        }
        _ => {}
    }
    emit_native_range_check(
        &mut file,
        AOT_CTX_HEAP_START_OFFSET,
        AOT_CTX_HEAP_END_OFFSET,
        &heap_ok_label,
    )?;
    emit_native_range_check(
        &mut file,
        AOT_CTX_STACK_START_OFFSET,
        AOT_CTX_STACK_END_OFFSET,
        &stack_ok_label,
    )?;
    emit_native_range_check(
        &mut file,
        AOT_CTX_HINTS_START_OFFSET,
        AOT_CTX_HINTS_END_OFFSET,
        &hints_ok_label,
    )?;
    writeln!(file, "    movl %edx, %eax")?;
    writeln!(file, "    shrl $2, %eax")?;
    writeln!(
        file,
        "    cmpl {AOT_CTX_MEMORY_BASE_WORD_OFFSET}(%r12), %eax"
    )?;
    writeln!(file, "    jb ceno_aot_memory_guard")?;
    writeln!(
        file,
        "    cmpl {AOT_CTX_MEMORY_END_WORD_OFFSET}(%r12), %eax"
    )?;
    writeln!(file, "    jb {done_label}")?;
    writeln!(file, "    jmp ceno_aot_memory_guard")?;
    for (label, region) in [
        (&heap_ok_label, 1u8),
        (&stack_ok_label, 2u8),
        (&hints_ok_label, 3u8),
    ] {
        writeln!(file, "{label}:")?;
        if let Some(index) = region_index {
            let bit = index * 2;
            if region & 1 != 0 {
                writeln!(file, "    btsq ${bit}, %r11")?;
            }
            if region & 2 != 0 {
                writeln!(file, "    btsq ${}, %r11", bit + 1)?;
            }
        }
        writeln!(file, "    jmp {done_label}")?;
    }
    writeln!(file, "{done_label}:")?;
    Ok(())
}

pub(super) fn emit_preflight_direct_block_access_entry(
    mut file: impl Write,
    program: &Program,
    block_idx: usize,
    block: &BasicBlock,
    emit_events: bool,
) -> Result<()> {
    let accesses = preflight_block_first_accesses(program, block)?;
    if accesses.is_empty() {
        return Ok(());
    }
    let register_mask = accesses.iter().fold(0u64, |mask, access| {
        mask | preflight_register_bit(access.addr >> 6)
    });
    if !emit_events {
        let all_seen_label = format!(".L_preflight_block_latest_all_seen_{block_idx}");
        writeln!(file, "    movq 56(%rsp), %rax")?;
        writeln!(file, "    movl ${}, %ecx", register_mask as u32)?;
        writeln!(file, "    andl %ecx, %eax")?;
        writeln!(file, "    cmpl %ecx, %eax")?;
        writeln!(file, "    je {all_seen_label}")?;
        writeln!(
            file,
            "    movq {AOT_CTX_PREFLIGHT_LATEST_CELLS_OFFSET}(%r12), %rdx"
        )?;
        writeln!(file, "    xorq %rdi, %rdi")?;
        for (access_idx, access) in accesses.iter().enumerate() {
            let done_label = format!(".L_preflight_block_latest_seen_{block_idx}_{access_idx}");
            let offset = access.addr as u64 * std::mem::size_of::<Cycle>() as u64;
            writeln!(file, "    cmpq $0, {offset}(%rdx)")?;
            writeln!(file, "    jne {done_label}")?;
            if cfg!(debug_assertions) {
                writeln!(
                    file,
                    "    movl ${}, {AOT_CTX_PREFLIGHT_EVENT_ADDR_OFFSET}(%r12)",
                    access.addr
                )?;
                writeln!(
                    file,
                    "    movl ${AOT_PREFLIGHT_HELPER_FIRST_TOUCH}, {AOT_CTX_PREFLIGHT_HELPER_KIND_OFFSET}(%r12)"
                )?;
                emit_flush_preflight_event_cursor(&mut file)?;
                writeln!(file, "    movq %r12, %rdi")?;
                writeln!(file, "    call *%r14")?;
                emit_reload_preflight_event_cursor(&mut file)?;
                writeln!(file, "    cmpl ${AOT_STATUS_ERROR}, %eax")?;
                writeln!(file, "    je ceno_aot_error")?;
                writeln!(
                    file,
                    "    movq {AOT_CTX_PREFLIGHT_LATEST_CELLS_OFFSET}(%r12), %rdx"
                )?;
                writeln!(file, "    xorq %rdi, %rdi")?;
            } else {
                writeln!(file, "    incq %rdi")?;
            }
            writeln!(file, "{done_label}:")?;
        }
        if !cfg!(debug_assertions) {
            writeln!(
                file,
                "    movq {AOT_CTX_PREFLIGHT_LATEST_LEN_OFFSET}(%r12), %rsi"
            )?;
            writeln!(file, "    addq %rdi, (%rsi)")?;
        }
        writeln!(file, "    movl ${}, %eax", register_mask as u32)?;
        writeln!(file, "    orq %rax, 56(%rsp)")?;
        writeln!(file, "{all_seen_label}:")?;
        return Ok(());
    }
    let all_touched_label = format!(".L_preflight_block_access_all_touched_{block_idx}");

    writeln!(file, "    movq 56(%rsp), %rax")?;
    writeln!(file, "    movabsq ${register_mask:#018x}, %rcx")?;
    writeln!(file, "    andq %rcx, %rax")?;
    writeln!(file, "    cmpq %rcx, %rax")?;
    writeln!(file, "    je {all_touched_label}")?;
    writeln!(
        file,
        "    movq {AOT_CTX_PREFLIGHT_LATEST_CELLS_OFFSET}(%r12), %rdx"
    )?;
    writeln!(
        file,
        "    movq {AOT_CTX_PREFLIGHT_CYCLE_OFFSET}(%r12), %rax"
    )?;
    writeln!(file, "    movq (%rax), %r8")?;
    writeln!(
        file,
        "    movq {AOT_CTX_PREFLIGHT_CURRENT_SHARD_START_OFFSET}(%r12), %rax"
    )?;
    writeln!(file, "    movq (%rax), %r10")?;

    writeln!(file, "    xorq %rdi, %rdi")?;
    for (access_idx, access) in accesses.iter().enumerate() {
        let done_label = format!(".L_preflight_block_access_done_{block_idx}_{access_idx}");
        let offset = access.addr as u64 * std::mem::size_of::<Cycle>() as u64;
        emit_assembly_profile_symbol(
            &mut file,
            &format!("ceno_aot_bb_{block_idx}_register_first_check_{access_idx}"),
        )?;
        writeln!(file, "    movq {offset}(%rdx), %r11")?;
        // Zero is the uninitialized sentinel, and every shard starts after cycle zero,
        // so the unsigned shard-start comparison also covers first touches.
        writeln!(file, "    cmpq %r10, %r11")?;
        writeln!(file, "    jae {done_label}")?;
        emit_assembly_profile_symbol(
            &mut file,
            &format!("ceno_aot_bb_{block_idx}_register_tape_append_{access_idx}"),
        )?;
        writeln!(file, "    movq %r8, %rax")?;
        writeln!(file, "    addq ${}, %rax", access.cycle_offset)?;
        writeln!(file, "    movq %r11, 0(%rbx)")?;
        writeln!(file, "    movq %rax, 8(%rbx)")?;
        writeln!(file, "    movl ${}, 16(%rbx)", access.addr)?;
        writeln!(file, "    addq $24, %rbx")?;
        writeln!(file, "    testq %r11, %r11")?;
        writeln!(file, "    jne {done_label}")?;
        if cfg!(debug_assertions) {
            writeln!(
                file,
                "    movl ${}, {AOT_CTX_PREFLIGHT_EVENT_ADDR_OFFSET}(%r12)",
                access.addr
            )?;
            writeln!(
                file,
                "    movl ${AOT_PREFLIGHT_HELPER_FIRST_TOUCH}, {AOT_CTX_PREFLIGHT_HELPER_KIND_OFFSET}(%r12)"
            )?;
            emit_flush_preflight_event_cursor(&mut file)?;
            writeln!(file, "    movq %r12, %rdi")?;
            writeln!(file, "    call *%r14")?;
            emit_reload_preflight_event_cursor(&mut file)?;
            writeln!(file, "    cmpl ${AOT_STATUS_ERROR}, %eax")?;
            writeln!(file, "    je ceno_aot_error")?;
            emit_preflight_direct_access_cache_load(&mut file)?;
            writeln!(file, "    xorq %rdi, %rdi")?;
        } else {
            writeln!(file, "    incq %rdi")?;
        }
        writeln!(file, "{done_label}:")?;
    }
    emit_assembly_profile_symbol(
        &mut file,
        &format!("ceno_aot_bb_{block_idx}_register_first_publish"),
    )?;
    if !cfg!(debug_assertions) {
        writeln!(
            file,
            "    movq {AOT_CTX_PREFLIGHT_LATEST_LEN_OFFSET}(%r12), %rsi"
        )?;
        writeln!(file, "    addq %rdi, (%rsi)")?;
    }
    writeln!(file, "    movabsq ${register_mask:#018x}, %rax")?;
    writeln!(file, "    orq %rax, 56(%rsp)")?;
    writeln!(file, "{all_touched_label}:")?;
    Ok(())
}

pub(super) fn emit_preflight_direct_block_register_access_exit(
    mut file: impl Write,
    program: &Program,
    block: &BasicBlock,
) -> Result<()> {
    let accesses = preflight_block_last_accesses(program, block)?;
    if accesses.is_empty() {
        return Ok(());
    }
    let block_cycles = block_instruction_count(block) * PC_STEP_SIZE as u64;
    writeln!(
        file,
        "    movq {AOT_CTX_PREFLIGHT_LATEST_CELLS_OFFSET}(%r12), %rdx"
    )?;
    writeln!(
        file,
        "    movq {AOT_CTX_PREFLIGHT_CYCLE_OFFSET}(%r12), %rax"
    )?;
    writeln!(file, "    movq (%rax), %r8")?;
    for access in accesses {
        let offset = access.addr as u64 * std::mem::size_of::<Cycle>() as u64;
        let from_end = block_cycles - access.cycle_offset;
        writeln!(file, "    leaq -{from_end}(%r8), %rax")?;
        writeln!(file, "    movq %rax, {offset}(%rdx)")?;
    }
    Ok(())
}

pub(super) fn emit_preflight_specialized_cost_contribution(
    mut file: impl Write,
    block_idx: usize,
    contribution_idx: usize,
    contribution: &AotChipContribution,
    has_lzcnt: bool,
    has_bucket_cache: bool,
) -> Result<()> {
    let done_label = format!(".L_preflight_cost_contribution_done_{block_idx}_{contribution_idx}");
    writeln!(file, "    movl ${}, %eax", contribution.chip_index)?;
    writeln!(
        file,
        "    movq {AOT_CTX_PREFLIGHT_NUM_INSTANCES_OFFSET}(%r12), %rdi"
    )?;
    writeln!(file, "    leaq (%rdi,%rax,8), %rsi")?;
    writeln!(file, "    movq (%rsi), %r9")?;
    writeln!(file, "    movq %r9, %r11")?;
    writeln!(file, "    addq ${}, %r11", contribution.instance_delta)?;
    writeln!(file, "    movq %r11, (%rsi)")?;
    if has_lzcnt {
        writeln!(file, "    leaq -1(%r9), %rdx")?;
        writeln!(file, "    lzcntq %rdx, %rdx")?;
        writeln!(file, "    movq $65, %r8")?;
        writeln!(file, "    subq %rdx, %r8")?;
        writeln!(file, "    testq %r9, %r9")?;
        writeln!(file, "    cmovz %r9, %r8")?;
        writeln!(file, "    movq %r8, %rdx")?;
        writeln!(file, "    leaq -1(%r11), %r9")?;
        writeln!(file, "    lzcntq %r9, %r9")?;
        writeln!(file, "    negq %r9")?;
        writeln!(file, "    addq $65, %r9")?;
        if has_bucket_cache {
            writeln!(file, "    leaq -1(%r9), %r8")?;
            writeln!(file, "    movq $1, %rdi")?;
            writeln!(file, "    shlxq %r8, %rdi, %r8")?;
            writeln!(file, "    incq %r8")?;
            writeln!(
                file,
                "    movq {AOT_CTX_PREFLIGHT_BUCKET_CEILINGS_OFFSET}(%r12), %rdi"
            )?;
            writeln!(file, "    movq %r8, (%rdi,%rax,8)")?;
            writeln!(
                file,
                "    movq {AOT_CTX_PREFLIGHT_BUCKET_GENERATIONS_OFFSET}(%r12), %rdi"
            )?;
            writeln!(
                file,
                "    movq {AOT_CTX_PREFLIGHT_BUCKET_GENERATION_OFFSET}(%r12), %r8"
            )?;
            writeln!(file, "    movq %r8, (%rdi,%rax,8)")?;
        }
    } else {
        writeln!(file, "    movq %r9, %rdx")?;
        writeln!(file, "    decq %rdx")?;
        writeln!(file, "    orq $1, %rdx")?;
        writeln!(file, "    bsrq %rdx, %rdx")?;
        writeln!(file, "    addq $2, %rdx")?;
        writeln!(file, "    movq $1, %r8")?;
        writeln!(file, "    cmpq $1, %r9")?;
        writeln!(file, "    cmovbe %r8, %rdx")?;
        writeln!(file, "    xorq %r8, %r8")?;
        writeln!(file, "    testq %r9, %r9")?;
        writeln!(file, "    cmovz %r8, %rdx")?;
        writeln!(file, "    movq %r11, %r9")?;
        writeln!(file, "    decq %r9")?;
        writeln!(file, "    orq $1, %r9")?;
        writeln!(file, "    bsrq %r9, %r9")?;
        writeln!(file, "    addq $2, %r9")?;
        writeln!(file, "    cmpq $1, %r11")?;
        writeln!(file, "    movq $1, %r8")?;
        writeln!(file, "    cmovbe %r8, %r9")?;
    }
    writeln!(file, "    cmpq %r9, %rdx")?;
    writeln!(file, "    je {done_label}")?;
    writeln!(file, "    movq $1, 80(%rsp)")?;
    writeln!(
        file,
        "    movq {AOT_CTX_PREFLIGHT_COST_TABLE_OFFSET}(%r12), %rdi"
    )?;
    writeln!(
        file,
        "    addq ${}, %rdi",
        contribution.cost_row_byte_offset
    )?;
    writeln!(file, "    movq %rdx, %r8")?;
    writeln!(file, "    shlq $4, %r8")?;
    writeln!(file, "    movq %r9, %rax")?;
    writeln!(file, "    shlq $4, %rax")?;
    writeln!(file, "    movdqu (%rdi,%r8), %xmm1")?;
    writeln!(file, "    movdqu (%rdi,%rax), %xmm2")?;
    writeln!(file, "    psubq %xmm1, %xmm2")?;
    writeln!(file, "    paddq %xmm2, %xmm0")?;
    writeln!(
        file,
        "    movq {AOT_CTX_PREFLIGHT_TOWER_COST_TABLE_OFFSET}(%r12), %rdi"
    )?;
    writeln!(
        file,
        "    addq ${}, %rdi",
        contribution.cost_row_byte_offset / 2
    )?;
    writeln!(file, "    movq (%rdi,%r9,8), %rax")?;
    writeln!(file, "    movq 32(%rsp), %r8")?;
    writeln!(file, "    cmpq %r8, %rax")?;
    writeln!(file, "    cmovaq %rax, %r8")?;
    writeln!(file, "    movq %r8, 32(%rsp)")?;
    writeln!(file, "{done_label}:")?;
    Ok(())
}

pub(super) fn emit_preflight_adaptive_block_plan_entry(
    mut file: impl Write,
    block_idx: usize,
    block: &BasicBlock,
    planner_metadata: Option<&AotPlannerMetadata>,
) -> Result<()> {
    let specialized_descriptor = planner_metadata
        .map(|metadata| {
            let descriptor = &metadata.descriptors[block_idx];
            (descriptor, metadata.contributions_for(descriptor))
        })
        .filter(|(_, contributions)| contributions.len() <= 2);
    let loop_label = format!(".L_preflight_cost_loop_{block_idx}");
    let loop_done_label = format!(".L_preflight_cost_loop_done_{block_idx}");
    let contribution_done_label = format!(".L_preflight_cost_contribution_done_{block_idx}");
    let unchanged_label = format!(".L_preflight_cost_unchanged_{block_idx}");
    let accept_label = format!(".L_preflight_cost_accept_{block_idx}");
    let first_shard_label = format!(".L_preflight_cost_first_shard_{block_idx}");
    let target_done_label = format!(".L_preflight_cost_target_done_{block_idx}");
    let split_label = format!(".L_preflight_cost_split_{block_idx}");
    let done_label = format!(".L_preflight_cost_done_{block_idx}");
    let bucket_scan_label = format!(".L_preflight_bucket_scan_{block_idx}");
    let bucket_scan_done_label = format!(".L_preflight_bucket_scan_done_{block_idx}");
    let bucket_fast_label = format!(".L_preflight_bucket_fast_{block_idx}");
    let bucket_slow_label = format!(".L_preflight_bucket_slow_{block_idx}");
    let bucket_rollback_label = format!(".L_preflight_bucket_rollback_{block_idx}");
    let block_cycles = block_instruction_count(block) * PC_STEP_SIZE as u64;
    let descriptor_offset = block_idx * std::mem::size_of::<AotBlockCostDescriptor>();
    let has_lzcnt = std::is_x86_feature_detected!("lzcnt");
    let has_bucket_cache = has_lzcnt && std::is_x86_feature_detected!("bmi2");

    if has_bucket_cache {
        if let Some((_, contributions)) = specialized_descriptor {
            // The common one/two-chip case embeds immutable descriptor fields
            // directly in the artifact and has no descriptor-table scan.
            writeln!(
                file,
                "    movq {AOT_CTX_PREFLIGHT_BUCKET_GENERATION_OFFSET}(%r12), %r8"
            )?;
            writeln!(
                file,
                "    movq {AOT_CTX_PREFLIGHT_BUCKET_GENERATIONS_OFFSET}(%r12), %rsi"
            )?;
            writeln!(
                file,
                "    movq {AOT_CTX_PREFLIGHT_NUM_INSTANCES_OFFSET}(%r12), %rdx"
            )?;
            writeln!(
                file,
                "    movq {AOT_CTX_PREFLIGHT_BUCKET_CEILINGS_OFFSET}(%r12), %r11"
            )?;
            for (index, contribution) in contributions.iter().enumerate() {
                let fail_label = format!(".L_preflight_bucket_special_fail_{block_idx}_{index}");
                writeln!(file, "    movl ${}, %eax", contribution.chip_index)?;
                writeln!(file, "    cmpq %r8, (%rsi,%rax,8)")?;
                writeln!(file, "    jne {fail_label}")?;
                writeln!(file, "    movq (%rdx,%rax,8), %r9")?;
                writeln!(file, "    addq ${}, %r9", contribution.instance_delta)?;
                writeln!(file, "    cmpq (%r11,%rax,8), %r9")?;
                writeln!(file, "    jae {fail_label}")?;
                writeln!(file, "    movq %r9, (%rdx,%rax,8)")?;
            }
            writeln!(file, "    jmp {unchanged_label}")?;
            for (index, _) in contributions.iter().enumerate() {
                let fail_label = format!(".L_preflight_bucket_special_fail_{block_idx}_{index}");
                writeln!(file, "{fail_label}:")?;
                for contribution in &contributions[..index] {
                    writeln!(file, "    movl ${}, %eax", contribution.chip_index)?;
                    writeln!(
                        file,
                        "    subq ${}, (%rdx,%rax,8)",
                        contribution.instance_delta
                    )?;
                }
                writeln!(file, "    jmp {bucket_slow_label}")?;
            }
            writeln!(file, "{bucket_slow_label}:")?;
        } else {
            // Most blocks do not cross a power-of-two cost bucket. Prove that
            // first, then update only instance counts. Rust callbacks advance a
            // generation so chips they may have changed retry the exact path.
            writeln!(
                file,
                "    movq {AOT_CTX_PREFLIGHT_BLOCK_COST_DESCRIPTORS_OFFSET}(%r12), %r10"
            )?;
            writeln!(file, "    movl {descriptor_offset}(%r10), %eax")?;
            writeln!(file, "    movl {}(%r10), %ecx", descriptor_offset + 4)?;
            writeln!(file, "    shlq $4, %rax")?;
            writeln!(
                file,
                "    addq {AOT_CTX_PREFLIGHT_CHIP_CONTRIBUTIONS_OFFSET}(%r12), %rax"
            )?;
            writeln!(file, "    movq %rax, %r10")?;
            writeln!(
                file,
                "    movq {AOT_CTX_PREFLIGHT_BUCKET_GENERATION_OFFSET}(%r12), %r8"
            )?;
            writeln!(
                file,
                "    movq {AOT_CTX_PREFLIGHT_BUCKET_GENERATIONS_OFFSET}(%r12), %rsi"
            )?;
            writeln!(
                file,
                "    movq {AOT_CTX_PREFLIGHT_NUM_INSTANCES_OFFSET}(%r12), %rdx"
            )?;
            writeln!(
                file,
                "    movq {AOT_CTX_PREFLIGHT_BUCKET_CEILINGS_OFFSET}(%r12), %r11"
            )?;
            writeln!(file, "    testl %ecx, %ecx")?;
            writeln!(file, "    je {bucket_scan_done_label}")?;
            writeln!(file, "{bucket_scan_label}:")?;
            writeln!(file, "    movl (%r10), %eax")?;
            writeln!(file, "    cmpq %r8, (%rsi,%rax,8)")?;
            writeln!(file, "    jne {bucket_slow_label}")?;
            writeln!(file, "    movq (%rdx,%rax,8), %r9")?;
            writeln!(file, "    addq 8(%r10), %r9")?;
            writeln!(file, "    cmpq (%r11,%rax,8), %r9")?;
            writeln!(file, "    jae {bucket_slow_label}")?;
            writeln!(file, "    movq %r9, (%rdx,%rax,8)")?;
            writeln!(file, "    addq $16, %r10")?;
            writeln!(file, "    decl %ecx")?;
            writeln!(file, "    jne {bucket_scan_label}")?;
            writeln!(file, "{bucket_scan_done_label}:")?;
            writeln!(file, "{bucket_fast_label}:")?;
            writeln!(file, "    jmp {unchanged_label}")?;
            writeln!(file, "{bucket_slow_label}:")?;
            writeln!(
                file,
                "    movq {AOT_CTX_PREFLIGHT_BLOCK_COST_DESCRIPTORS_OFFSET}(%r12), %rsi"
            )?;
            writeln!(file, "    movl {descriptor_offset}(%rsi), %eax")?;
            writeln!(file, "    shlq $4, %rax")?;
            writeln!(
                file,
                "    addq {AOT_CTX_PREFLIGHT_CHIP_CONTRIBUTIONS_OFFSET}(%r12), %rax"
            )?;
            writeln!(file, "    movq %rax, %rsi")?;
            writeln!(file, "    cmpq %r10, %rsi")?;
            writeln!(file, "    je {bucket_rollback_label}_done")?;
            writeln!(file, "{bucket_rollback_label}:")?;
            writeln!(file, "    movl (%rsi), %eax")?;
            writeln!(file, "    movq 8(%rsi), %r9")?;
            writeln!(
                file,
                "    movq {AOT_CTX_PREFLIGHT_NUM_INSTANCES_OFFSET}(%r12), %rdi"
            )?;
            writeln!(file, "    subq %r9, (%rdi,%rax,8)")?;
            writeln!(file, "    addq $16, %rsi")?;
            writeln!(file, "    cmpq %r10, %rsi")?;
            writeln!(file, "    jne {bucket_rollback_label}")?;
            writeln!(file, "{bucket_rollback_label}_done:")?;
        }
    }

    // Speculatively update all affected chip counts while accumulating trace
    // and main deltas and the largest absolute tower peak. The only loop
    // branch depends on descriptor size; bucket selection and max use cmov.
    writeln!(file, "    pxor %xmm0, %xmm0")?;
    writeln!(file, "    movq $0, 80(%rsp)")?;
    writeln!(
        file,
        "    movq {AOT_CTX_PREFLIGHT_PLANNER_CUR_TOWER_OFFSET}(%r12), %rax"
    )?;
    writeln!(file, "    movq (%rax), %rax")?;
    writeln!(file, "    movq %rax, 32(%rsp)")?;
    if let Some((_, contributions)) = specialized_descriptor {
        for (index, contribution) in contributions.iter().enumerate() {
            emit_preflight_specialized_cost_contribution(
                &mut file,
                block_idx,
                index,
                contribution,
                has_lzcnt,
                has_bucket_cache,
            )?;
        }
    } else {
        writeln!(
            file,
            "    movq {AOT_CTX_PREFLIGHT_BLOCK_COST_DESCRIPTORS_OFFSET}(%r12), %r10"
        )?;
        writeln!(file, "    movl {descriptor_offset}(%r10), %eax")?;
        writeln!(file, "    movl {}(%r10), %ecx", descriptor_offset + 4)?;
        writeln!(file, "    shlq $4, %rax")?;
        writeln!(
            file,
            "    addq {AOT_CTX_PREFLIGHT_CHIP_CONTRIBUTIONS_OFFSET}(%r12), %rax"
        )?;
        writeln!(file, "    movq %rax, %r10")?;
        writeln!(file, "    testl %ecx, %ecx")?;
        writeln!(file, "    je {loop_done_label}")?;
        writeln!(file, "{loop_label}:")?;
        writeln!(file, "    movl (%r10), %eax")?;
        writeln!(file, "    movl 4(%r10), %edx")?;
        writeln!(file, "    movq %rdx, 40(%rsp)")?;
        writeln!(file, "    movq 8(%r10), %r11")?;
        writeln!(
            file,
            "    movq {AOT_CTX_PREFLIGHT_NUM_INSTANCES_OFFSET}(%r12), %rdi"
        )?;
        writeln!(file, "    leaq (%rdi,%rax,8), %rsi")?;
        writeln!(file, "    movq (%rsi), %r9")?;
        writeln!(file, "    addq %r9, %r11")?;
        writeln!(file, "    movq %r11, (%rsi)")?;
        if has_lzcnt {
            writeln!(file, "    leaq -1(%r9), %rdx")?;
            writeln!(file, "    lzcntq %rdx, %rdx")?;
            writeln!(file, "    movq $65, %r8")?;
            writeln!(file, "    subq %rdx, %r8")?;
            writeln!(file, "    testq %r9, %r9")?;
            writeln!(file, "    cmovz %r9, %r8")?;
            writeln!(file, "    movq %r8, %rdx")?;
            writeln!(file, "    leaq -1(%r11), %r9")?;
            writeln!(file, "    lzcntq %r9, %r9")?;
            writeln!(file, "    negq %r9")?;
            writeln!(file, "    addq $65, %r9")?;
            if has_bucket_cache {
                writeln!(file, "    leaq -1(%r9), %r8")?;
                writeln!(file, "    movq $1, %rdi")?;
                writeln!(file, "    shlxq %r8, %rdi, %r8")?;
                writeln!(file, "    incq %r8")?;
                writeln!(
                    file,
                    "    movq {AOT_CTX_PREFLIGHT_BUCKET_CEILINGS_OFFSET}(%r12), %rdi"
                )?;
                writeln!(file, "    movq %r8, (%rdi,%rax,8)")?;
                writeln!(
                    file,
                    "    movq {AOT_CTX_PREFLIGHT_BUCKET_GENERATIONS_OFFSET}(%r12), %rdi"
                )?;
                writeln!(
                    file,
                    "    movq {AOT_CTX_PREFLIGHT_BUCKET_GENERATION_OFFSET}(%r12), %r8"
                )?;
                writeln!(file, "    movq %r8, (%rdi,%rax,8)")?;
            }
        } else {
            writeln!(file, "    movq %r9, %rdx")?;
            writeln!(file, "    decq %rdx")?;
            writeln!(file, "    orq $1, %rdx")?;
            writeln!(file, "    bsrq %rdx, %rdx")?;
            writeln!(file, "    addq $2, %rdx")?;
            writeln!(file, "    movq $1, %r8")?;
            writeln!(file, "    cmpq $1, %r9")?;
            writeln!(file, "    cmovbe %r8, %rdx")?;
            writeln!(file, "    xorq %r8, %r8")?;
            writeln!(file, "    testq %r9, %r9")?;
            writeln!(file, "    cmovz %r8, %rdx")?;
            writeln!(file, "    movq %r11, %r9")?;
            writeln!(file, "    decq %r9")?;
            writeln!(file, "    orq $1, %r9")?;
            writeln!(file, "    bsrq %r9, %r9")?;
            writeln!(file, "    addq $2, %r9")?;
            writeln!(file, "    cmpq $1, %r11")?;
            writeln!(file, "    movq $1, %r8")?;
            writeln!(file, "    cmovbe %r8, %r9")?;
        }
        writeln!(file, "    cmpq %r9, %rdx")?;
        writeln!(file, "    je {contribution_done_label}")?;
        writeln!(file, "    movq $1, 80(%rsp)")?;
        // Point at this chip's precomputed cost-table row. Keeping the row
        // offset in the descriptor avoids two serialized multiplies per chip.
        writeln!(
            file,
            "    movq {AOT_CTX_PREFLIGHT_COST_TABLE_OFFSET}(%r12), %rdi"
        )?;
        writeln!(file, "    movq 40(%rsp), %r8")?;
        writeln!(file, "    addq %r8, %rdi")?;
        // Trace and main are adjacent table lanes. Accumulate both deltas in one
        // SIMD register, avoiding four scalar loads and stack updates per chip.
        writeln!(file, "    movq %rdx, %r8")?;
        writeln!(file, "    shlq $4, %r8")?;
        writeln!(file, "    movq %r9, %rax")?;
        writeln!(file, "    shlq $4, %rax")?;
        writeln!(file, "    movdqu (%rdi,%r8), %xmm1")?;
        writeln!(file, "    movdqu (%rdi,%rax), %xmm2")?;
        writeln!(file, "    psubq %xmm1, %xmm2")?;
        writeln!(file, "    paddq %xmm2, %xmm0")?;
        // Tower tasks do not coexist across chips: retain only the largest new
        // absolute per-chip peak, rather than summing tower deltas.
        writeln!(
            file,
            "    movq {AOT_CTX_PREFLIGHT_TOWER_COST_TABLE_OFFSET}(%r12), %rdi"
        )?;
        writeln!(file, "    movq 40(%rsp), %r8")?;
        writeln!(file, "    shrq $1, %r8")?;
        writeln!(file, "    addq %r8, %rdi")?;
        writeln!(file, "    movq (%rdi,%r9,8), %rax")?;
        writeln!(file, "    movq 32(%rsp), %r8")?;
        writeln!(file, "    cmpq %r8, %rax")?;
        writeln!(file, "    cmovaq %rax, %r8")?;
        writeln!(file, "    movq %r8, 32(%rsp)")?;
        writeln!(file, "{contribution_done_label}:")?;
        writeln!(file, "    addq $16, %r10")?;
        writeln!(file, "    decl %ecx")?;
        writeln!(file, "    jne {loop_label}")?;
    }
    writeln!(file, "{loop_done_label}:")?;
    writeln!(file, "    cmpq $0, 80(%rsp)")?;
    writeln!(file, "    je {unchanged_label}")?;
    writeln!(file, "    movdqu %xmm0, 16(%rsp)")?;
    // candidate = trace_total + max(main_total, tower_peak)
    writeln!(
        file,
        "    movq {AOT_CTX_PREFLIGHT_PLANNER_CUR_TRACE_OFFSET}(%r12), %rax"
    )?;
    writeln!(file, "    movq (%rax), %r9")?;
    writeln!(file, "    addq 16(%rsp), %r9")?;
    writeln!(file, "    movq %r9, 16(%rsp)")?;
    writeln!(
        file,
        "    movq {AOT_CTX_PREFLIGHT_PLANNER_CUR_MAIN_OFFSET}(%r12), %rax"
    )?;
    writeln!(file, "    movq (%rax), %r11")?;
    writeln!(file, "    addq 24(%rsp), %r11")?;
    writeln!(file, "    movq %r11, 24(%rsp)")?;
    writeln!(file, "    movq 32(%rsp), %r8")?;
    writeln!(file, "    cmpq %r8, %r11")?;
    writeln!(file, "    cmovbq %r8, %r11")?;
    writeln!(file, "    addq %r11, %r9")?;
    writeln!(
        file,
        "    movq {AOT_CTX_PREFLIGHT_PLANNER_CUR_STEP_COUNT_OFFSET}(%r12), %r10"
    )?;
    writeln!(file, "    cmpq $0, (%r10)")?;
    writeln!(file, "    je {accept_label}")?;
    writeln!(
        file,
        "    movq {AOT_CTX_PREFLIGHT_PLANNER_SHARD_ID_OFFSET}(%r12), %r10"
    )?;
    writeln!(file, "    cmpq $0, (%r10)")?;
    writeln!(file, "    je {first_shard_label}")?;
    writeln!(
        file,
        "    movq {AOT_CTX_PREFLIGHT_MAX_CELL_PER_SHARD_OFFSET}(%r12), %r10"
    )?;
    writeln!(file, "    jmp {target_done_label}")?;
    writeln!(file, "{first_shard_label}:")?;
    writeln!(
        file,
        "    movq {AOT_CTX_PREFLIGHT_TARGET_CELL_FIRST_SHARD_OFFSET}(%r12), %r10"
    )?;
    writeln!(file, "{target_done_label}:")?;
    writeln!(file, "    cmpq %r10, %r9")?;
    writeln!(file, "    ja {split_label}")?;
    writeln!(
        file,
        "    movq {AOT_CTX_PREFLIGHT_PLANNER_CUR_CYCLE_OFFSET}(%r12), %r10"
    )?;
    writeln!(file, "    movq (%r10), %r11")?;
    writeln!(file, "    addq ${block_cycles}, %r11")?;
    writeln!(
        file,
        "    cmpq {AOT_CTX_PREFLIGHT_MAX_CYCLE_PER_SHARD_OFFSET}(%r12), %r11"
    )?;
    writeln!(file, "    jae {split_label}")?;
    writeln!(file, "{accept_label}:")?;
    writeln!(
        file,
        "    movq {AOT_CTX_PREFLIGHT_PLANNER_CUR_CELLS_OFFSET}(%r12), %rax"
    )?;
    writeln!(file, "    movq %r9, (%rax)")?;
    writeln!(
        file,
        "    movq {AOT_CTX_PREFLIGHT_PLANNER_CUR_TRACE_OFFSET}(%r12), %rax"
    )?;
    writeln!(file, "    movq 16(%rsp), %r8")?;
    writeln!(file, "    movq %r8, (%rax)")?;
    writeln!(
        file,
        "    movq {AOT_CTX_PREFLIGHT_PLANNER_CUR_MAIN_OFFSET}(%r12), %rax"
    )?;
    writeln!(file, "    movq 24(%rsp), %r8")?;
    writeln!(file, "    movq %r8, (%rax)")?;
    writeln!(
        file,
        "    movq {AOT_CTX_PREFLIGHT_PLANNER_CUR_TOWER_OFFSET}(%r12), %rax"
    )?;
    writeln!(file, "    movq 32(%rsp), %r8")?;
    writeln!(file, "    movq %r8, (%rax)")?;
    writeln!(file, "    jmp {done_label}")?;
    writeln!(file, "{unchanged_label}:")?;
    writeln!(
        file,
        "    movq {AOT_CTX_PREFLIGHT_PLANNER_CUR_STEP_COUNT_OFFSET}(%r12), %r10"
    )?;
    writeln!(file, "    cmpq $0, (%r10)")?;
    writeln!(file, "    je {done_label}")?;
    writeln!(
        file,
        "    movq {AOT_CTX_PREFLIGHT_PLANNER_CUR_CYCLE_OFFSET}(%r12), %r10"
    )?;
    writeln!(file, "    movq (%r10), %r11")?;
    writeln!(file, "    addq ${block_cycles}, %r11")?;
    writeln!(
        file,
        "    cmpq {AOT_CTX_PREFLIGHT_MAX_CYCLE_PER_SHARD_OFFSET}(%r12), %r11"
    )?;
    writeln!(file, "    jae {split_label}")?;
    writeln!(file, "    jmp {done_label}")?;
    writeln!(file, "{split_label}:")?;
    if let Some((descriptor, contributions)) = specialized_descriptor {
        writeln!(
            file,
            "    movq ${}, {AOT_CTX_PREFLIGHT_PENDING_SPECIALIZED_OFFSET}(%r12)",
            contributions.len() + 1
        )?;
        for (index, contribution) in contributions.iter().enumerate() {
            writeln!(
                file,
                "    movl ${}, {}(%r12)",
                contribution.chip_index,
                AOT_CTX_PREFLIGHT_PENDING_CHIPS_OFFSET + index * std::mem::size_of::<u32>()
            )?;
            writeln!(file, "    movabsq ${}, %rax", contribution.instance_delta)?;
            writeln!(
                file,
                "    movq %rax, {}(%r12)",
                AOT_CTX_PREFLIGHT_PENDING_DELTAS_OFFSET + index * std::mem::size_of::<u64>()
            )?;
        }
        for (offset, value) in [
            (
                AOT_CTX_PREFLIGHT_PENDING_TRACE_OFFSET,
                descriptor.standalone_trace_cells,
            ),
            (
                AOT_CTX_PREFLIGHT_PENDING_MAIN_OFFSET,
                descriptor.standalone_main_peak,
            ),
            (
                AOT_CTX_PREFLIGHT_PENDING_TOWER_OFFSET,
                descriptor.standalone_tower_peak,
            ),
        ] {
            writeln!(file, "    movabsq ${value}, %rax")?;
            writeln!(file, "    movq %rax, {offset}(%r12)")?;
        }
    }
    writeln!(
        file,
        "    movq ${block_idx}, {AOT_CTX_PREFLIGHT_PENDING_BLOCK_OFFSET}(%r12)"
    )?;
    writeln!(
        file,
        "    movl ${AOT_PREFLIGHT_HELPER_SHARD_SPLIT}, {AOT_CTX_PREFLIGHT_HELPER_KIND_OFFSET}(%r12)"
    )?;
    writeln!(file, "    movq %r12, %rdi")?;
    emit_flush_preflight_event_cursor(&mut file)?;
    writeln!(file, "    call *%r14")?;
    emit_reload_preflight_event_cursor(&mut file)?;
    writeln!(file, "    cmpl ${AOT_STATUS_ERROR}, %eax")?;
    writeln!(file, "    je ceno_aot_error")?;
    writeln!(file, "{done_label}:")?;
    Ok(())
}

pub(super) fn emit_preflight_plan_commit_diagnostic(
    mut file: impl Write,
    helper_kind: u32,
) -> Result<()> {
    // Keep the native entry's SysV stack alignment and preserve the semantic
    // helper kind. No caller-saved register or condition flag is live here.
    writeln!(file, "    subq $16, %rsp")?;
    writeln!(
        file,
        "    movl {AOT_CTX_PREFLIGHT_HELPER_KIND_OFFSET}(%r12), %eax"
    )?;
    writeln!(file, "    movl %eax, 0(%rsp)")?;
    writeln!(
        file,
        "    movl ${helper_kind}, {AOT_CTX_PREFLIGHT_HELPER_KIND_OFFSET}(%r12)"
    )?;
    writeln!(file, "    movq %r12, %rdi")?;
    writeln!(file, "    call *%r14")?;
    writeln!(file, "    movl 0(%rsp), %ecx")?;
    writeln!(
        file,
        "    movl %ecx, {AOT_CTX_PREFLIGHT_HELPER_KIND_OFFSET}(%r12)"
    )?;
    writeln!(file, "    addq $16, %rsp")?;
    Ok(())
}

pub(super) fn emit_preflight_direct_block_plan_exit(
    mut file: impl Write,
    block: &BasicBlock,
) -> Result<()> {
    let block_steps = block_instruction_count(block);
    let block_cycles = block_steps * PC_STEP_SIZE as u64;
    writeln!(
        file,
        "    movq {AOT_CTX_PREFLIGHT_PLANNER_CUR_CYCLE_OFFSET}(%r12), %rax"
    )?;
    writeln!(file, "    addq ${block_cycles}, (%rax)")?;
    writeln!(
        file,
        "    movq {AOT_CTX_PREFLIGHT_PLANNER_CUR_STEP_COUNT_OFFSET}(%r12), %rax"
    )?;
    writeln!(file, "    addq ${block_steps}, (%rax)")?;
    Ok(())
}

pub(super) fn emit_preflight_direct_block_trace_exit(
    mut file: impl Write,
    block: &BasicBlock,
) -> Result<()> {
    let block_steps = block_instruction_count(block);
    let block_cycles = block_steps * PC_STEP_SIZE as u64;
    writeln!(
        file,
        "    movq {AOT_CTX_PREFLIGHT_CYCLE_OFFSET}(%r12), %rax"
    )?;
    writeln!(file, "    addq ${block_cycles}, (%rax)")?;
    writeln!(
        file,
        "    addq ${block_steps}, {AOT_CTX_PREFLIGHT_PENDING_STEPS_OFFSET}(%r12)"
    )?;
    writeln!(file, "    movl {AOT_CTX_TRACE_NEXT_PC_OFFSET}(%r12), %r15d")?;
    writeln!(file, "    movl %r15d, 8(%rsp)")?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(super) fn emit_preflight_direct_step_static(
    mut file: impl Write,
    pc: u32,
    insn: Instruction,
    preflight_memory_bounds_updated: bool,
    preflight_memory_event_updated: bool,
    access_mode: PreflightAccessMode,
    check_busy_loop: bool,
    block_cycle_offset: Option<u64>,
    trace_style: AssemblyTraceStyle,
) -> Result<()> {
    let has_memory_access =
        native_step_loads_memory(insn.kind) || native_step_stores_memory(insn.kind);
    if trace_style.preflight_feature_enabled(PreflightFeature::MmioBounds)
        && has_memory_access
        && !preflight_memory_bounds_updated
    {
        writeln!(file, "    movl {AOT_CTX_TRACE_MEM_ADDR_OFFSET}(%r12), %eax")?;
        emit_preflight_direct_memory_bounds(&mut file, "%eax")?;
    }

    match access_mode {
        PreflightAccessMode::Exact => {
            let register_latest =
                trace_style.preflight_feature_enabled(PreflightFeature::RegisterLatest);
            let register_events =
                trace_style.preflight_feature_enabled(PreflightFeature::RegisterEvents);
            let memory_events =
                trace_style.preflight_feature_enabled(PreflightFeature::MemoryEvents);
            if register_latest || memory_events {
                emit_preflight_direct_access_cache_load(&mut file)?;
            }

            if native_step_loads_memory(insn.kind) {
                if register_latest && native_step_reads_rs1(insn.kind) {
                    emit_preflight_direct_register_access_cached(
                        &mut file,
                        insn.rs1 as u32,
                        PreflightSubcycle::Rs1,
                        register_events,
                    )?;
                }
                if memory_events {
                    writeln!(file, "    movl {AOT_CTX_TRACE_MEM_ADDR_OFFSET}(%r12), %eax")?;
                    emit_preflight_direct_memory_access_cached(
                        &mut file,
                        pc,
                        "%eax",
                        block_cycle_offset.unwrap_or(0),
                        None,
                        "%r11",
                        "%r10",
                        false,
                        false,
                    )?;
                }
                if register_latest && native_step_writes_rd(insn.kind) {
                    emit_preflight_direct_register_access_cached(
                        &mut file,
                        insn.rd_internal(),
                        PreflightSubcycle::Rd,
                        register_events,
                    )?;
                }
            } else {
                if register_latest {
                    for (reg_idx, subcycle) in preflight_static_register_accesses(insn) {
                        emit_preflight_direct_register_access_cached(
                            &mut file,
                            reg_idx,
                            subcycle,
                            register_events,
                        )?;
                    }
                }
                if has_memory_access && memory_events {
                    writeln!(file, "    movl {AOT_CTX_TRACE_MEM_ADDR_OFFSET}(%r12), %eax")?;
                    emit_preflight_direct_memory_access_cached(
                        &mut file,
                        pc,
                        "%eax",
                        block_cycle_offset.unwrap_or(0),
                        None,
                        "%r11",
                        "%r10",
                        false,
                        false,
                    )?;
                }
            }
        }
        PreflightAccessMode::BlockAtomic => {
            if has_memory_access
                && trace_style.preflight_feature_enabled(PreflightFeature::MemoryEvents)
                && !preflight_memory_event_updated
            {
                emit_preflight_direct_memory_shard_cache_load(&mut file)?;
                writeln!(file, "    movl {AOT_CTX_TRACE_MEM_ADDR_OFFSET}(%r12), %eax")?;
                emit_preflight_direct_memory_access_cached(
                    &mut file,
                    pc,
                    "%eax",
                    block_cycle_offset.unwrap_or(0),
                    None,
                    "%r11",
                    "%r10",
                    false,
                    false,
                )?;
            }
        }
    }

    if block_cycle_offset.is_none() {
        emit_preflight_direct_execution_metadata(&mut file, pc, insn)?;
        writeln!(
            file,
            "    movq {AOT_CTX_PREFLIGHT_CYCLE_OFFSET}(%r12), %rax"
        )?;
        writeln!(file, "    addq $4, (%rax)")?;
        writeln!(
            file,
            "    incq {AOT_CTX_PREFLIGHT_PENDING_STEPS_OFFSET}(%r12)"
        )?;
    }
    if check_busy_loop {
        emit_preflight_direct_busy_loop_guard(&mut file, pc)?;
    }
    if block_cycle_offset.is_none() {
        writeln!(file, "    movl ${AOT_STATUS_CONTINUE}, %eax")?;
    }
    Ok(())
}

pub(super) fn emit_preflight_direct_execution_metadata(
    mut file: impl Write,
    pc: u32,
    insn: Instruction,
) -> Result<()> {
    writeln!(
        file,
        "    movq {AOT_CTX_PREFLIGHT_PC_BEFORE_OFFSET}(%r12), %rax"
    )?;
    writeln!(file, "    movl ${pc:#010x}, (%rax)")?;
    writeln!(
        file,
        "    movq {AOT_CTX_PREFLIGHT_PC_AFTER_OFFSET}(%r12), %rax"
    )?;
    writeln!(file, "    movl {AOT_CTX_TRACE_NEXT_PC_OFFSET}(%r12), %ecx")?;
    writeln!(file, "    movl %ecx, (%rax)")?;
    writeln!(
        file,
        "    movq {AOT_CTX_PREFLIGHT_LAST_KIND_OFFSET}(%r12), %rax"
    )?;
    writeln!(file, "    movb ${}, (%rax)", insn.kind as u8)?;
    Ok(())
}

pub(super) fn emit_preflight_direct_busy_loop_guard(mut file: impl Write, pc: u32) -> Result<()> {
    let done_label = format!(".L_preflight_busy_loop_done_{pc:x}");
    writeln!(
        file,
        "    cmpl ${pc:#010x}, {AOT_CTX_TRACE_NEXT_PC_OFFSET}(%r12)"
    )?;
    writeln!(file, "    jne {done_label}")?;
    writeln!(
        file,
        "    movl ${AOT_PREFLIGHT_HELPER_BUSY_LOOP}, {AOT_CTX_PREFLIGHT_HELPER_KIND_OFFSET}(%r12)"
    )?;
    writeln!(file, "    movq %r12, %rdi")?;
    emit_flush_preflight_event_cursor(&mut file)?;
    writeln!(file, "    call *%r14")?;
    emit_reload_preflight_event_cursor(&mut file)?;
    writeln!(file, "    cmpl ${AOT_STATUS_ERROR}, %eax")?;
    writeln!(file, "    je ceno_aot_error")?;
    writeln!(file, "    cmpl ${AOT_STATUS_HALTED}, %eax")?;
    writeln!(file, "    je ceno_aot_done")?;
    writeln!(file, "{done_label}:")?;
    Ok(())
}

pub(super) fn emit_preflight_direct_memory_bounds(
    mut file: impl Write,
    addr_reg: &str,
) -> Result<()> {
    emit_preflight_direct_memory_bound_region(
        &mut file,
        addr_reg,
        AOT_CTX_PREFLIGHT_HEAP_START_WORD_OFFSET,
        AOT_CTX_PREFLIGHT_HEAP_END_WORD_OFFSET,
        AOT_CTX_PREFLIGHT_HEAP_MIN_OFFSET,
        AOT_CTX_PREFLIGHT_HEAP_MAX_OFFSET,
    )?;
    emit_preflight_direct_memory_bound_region(
        &mut file,
        addr_reg,
        AOT_CTX_PREFLIGHT_STACK_START_WORD_OFFSET,
        AOT_CTX_PREFLIGHT_STACK_END_WORD_OFFSET,
        AOT_CTX_PREFLIGHT_STACK_MIN_OFFSET,
        AOT_CTX_PREFLIGHT_STACK_MAX_OFFSET,
    )?;
    emit_preflight_direct_memory_bound_region(
        &mut file,
        addr_reg,
        AOT_CTX_PREFLIGHT_HINTS_START_WORD_OFFSET,
        AOT_CTX_PREFLIGHT_HINTS_END_WORD_OFFSET,
        AOT_CTX_PREFLIGHT_HINTS_MIN_OFFSET,
        AOT_CTX_PREFLIGHT_HINTS_MAX_OFFSET,
    )?;
    Ok(())
}

pub(super) fn emit_preflight_direct_memory_bound_region(
    mut file: impl Write,
    addr_reg: &str,
    start_offset: usize,
    end_offset: usize,
    min_ptr_offset: usize,
    max_ptr_offset: usize,
) -> Result<()> {
    writeln!(file, "    movl {addr_reg}, %r9d")?;
    writeln!(file, "    cmpl {start_offset}(%r12), %r9d")?;
    writeln!(file, "    jb 1f")?;
    writeln!(file, "    cmpl {end_offset}(%r12), %r9d")?;
    writeln!(file, "    jae 1f")?;
    writeln!(file, "    movq {min_ptr_offset}(%r12), %rdx")?;
    writeln!(file, "    testq %rdx, %rdx")?;
    writeln!(file, "    je 2f")?;
    writeln!(file, "    cmpl (%rdx), %r9d")?;
    writeln!(file, "    jae 2f")?;
    writeln!(file, "    movl %r9d, (%rdx)")?;
    writeln!(file, "2:")?;
    writeln!(file, "    movq {max_ptr_offset}(%r12), %rdx")?;
    writeln!(file, "    testq %rdx, %rdx")?;
    writeln!(file, "    je 1f")?;
    writeln!(file, "    cmpl (%rdx), %r9d")?;
    writeln!(file, "    jb 1f")?;
    writeln!(file, "    leal 1(%r9d), %ecx")?;
    writeln!(file, "    movl %ecx, (%rdx)")?;
    writeln!(file, "1:")?;
    Ok(())
}

pub(super) fn emit_preflight_direct_memory_bound_known_region(
    mut file: impl Write,
    addr_reg: &str,
    min_ptr_offset: usize,
    max_ptr_offset: usize,
) -> Result<()> {
    writeln!(file, "    movq {min_ptr_offset}(%r12), %rax")?;
    writeln!(file, "    testq %rax, %rax")?;
    writeln!(file, "    je 1f")?;
    writeln!(file, "    cmpl (%rax), {addr_reg}")?;
    writeln!(file, "    jae 1f")?;
    writeln!(file, "    movl {addr_reg}, (%rax)")?;
    writeln!(file, "1:")?;
    writeln!(file, "    movq {max_ptr_offset}(%r12), %rax")?;
    writeln!(file, "    testq %rax, %rax")?;
    writeln!(file, "    je 2f")?;
    writeln!(file, "    cmpl (%rax), {addr_reg}")?;
    writeln!(file, "    jb 2f")?;
    writeln!(file, "    leal 1({addr_reg}), %ecx")?;
    writeln!(file, "    movl %ecx, (%rax)")?;
    writeln!(file, "2:")?;
    Ok(())
}

#[derive(Clone, Copy)]
pub(super) enum PreflightSubcycle {
    Rs1,
    Rs2,
    Rd,
}

impl PreflightSubcycle {
    fn value(self) -> u64 {
        match self {
            PreflightSubcycle::Rs1 => 0,
            PreflightSubcycle::Rs2 => 1,
            PreflightSubcycle::Rd => 2,
        }
    }
}

pub(super) fn emit_preflight_direct_access_cache_load(mut file: impl Write) -> Result<()> {
    writeln!(
        file,
        "    movq {AOT_CTX_PREFLIGHT_LATEST_CELLS_OFFSET}(%r12), %rdx"
    )?;
    writeln!(
        file,
        "    movq {AOT_CTX_PREFLIGHT_CYCLE_OFFSET}(%r12), %rsi"
    )?;
    writeln!(file, "    movq (%rsi), %r8")?;
    writeln!(
        file,
        "    movq {AOT_CTX_PREFLIGHT_CURRENT_SHARD_START_OFFSET}(%r12), %rsi"
    )?;
    writeln!(file, "    movq (%rsi), %r10")?;
    Ok(())
}

pub(super) fn emit_preflight_direct_memory_shard_cache_load(mut file: impl Write) -> Result<()> {
    writeln!(
        file,
        "    movq {AOT_CTX_PREFLIGHT_CURRENT_SHARD_START_OFFSET}(%r12), %rsi"
    )?;
    writeln!(file, "    movq (%rsi), %r10")?;
    Ok(())
}

pub(super) fn emit_preflight_direct_event_append(
    mut file: impl Write,
    source_reg: &str,
    target_reg: &str,
    addr_reg: &str,
    first_touch_helper: u32,
) -> Result<()> {
    writeln!(file, "    movq {source_reg}, 0(%rbx)")?;
    writeln!(file, "    movq {target_reg}, 8(%rbx)")?;
    writeln!(file, "    movl {addr_reg}, 16(%rbx)")?;
    writeln!(file, "    addq $24, %rbx")?;
    writeln!(file, "    testq {source_reg}, {source_reg}")?;
    writeln!(file, "    jne 4f")?;
    if cfg!(debug_assertions) {
        writeln!(
            file,
            "    movl ${first_touch_helper}, {AOT_CTX_PREFLIGHT_HELPER_KIND_OFFSET}(%r12)"
        )?;
        writeln!(file, "    movq %r12, %rdi")?;
        emit_flush_preflight_event_cursor(&mut file)?;
        writeln!(file, "    call *%r14")?;
        emit_reload_preflight_event_cursor(&mut file)?;
        writeln!(file, "    cmpl ${AOT_STATUS_ERROR}, %eax")?;
        writeln!(file, "    je ceno_aot_error")?;
        emit_preflight_direct_access_cache_load(&mut file)?;
    } else if first_touch_helper != AOT_PREFLIGHT_HELPER_MEMORY_FIRST_TOUCH {
        writeln!(
            file,
            "    movq {AOT_CTX_PREFLIGHT_LATEST_LEN_OFFSET}(%r12), %rsi"
        )?;
        writeln!(file, "    incq (%rsi)")?;
    }
    writeln!(file, "4:")?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(super) fn emit_preflight_direct_memory_access_cached(
    mut file: impl Write,
    pc: u32,
    addr_reg: &str,
    cycle_offset: u64,
    prev_stamp_reg: Option<&str>,
    prev_work_reg: &str,
    shard_start_reg: &str,
    prev_is_ordinal: bool,
    addr_is_dense_index: bool,
) -> Result<()> {
    let event_label = format!(".L_preflight_memory_event_{pc:x}");
    let done_label = format!(".L_preflight_memory_event_done_{pc:x}");
    if let Some(prev_stamp_reg) = prev_stamp_reg {
        if prev_stamp_reg != prev_work_reg {
            writeln!(file, "    movq {prev_stamp_reg}, {prev_work_reg}")?;
        }
    } else {
        writeln!(
            file,
            "    movq {AOT_CTX_MEMORY_PREV_STAMP_OFFSET}(%r12), {prev_work_reg}"
        )?;
    }
    if !prev_is_ordinal {
        writeln!(file, "    shlq $2, {prev_work_reg}")?;
    }
    writeln!(file, "    cmpq {shard_start_reg}, {prev_work_reg}")?;
    writeln!(file, "    jb {event_label}")?;
    writeln!(file, ".pushsection .text.unlikely,\"ax\",@progbits")?;
    writeln!(file, "{event_label}:")?;
    let event_prev_work_reg = if prev_work_reg == "%rcx" {
        writeln!(file, "    movq %rcx, %rdi")?;
        "%rdi"
    } else {
        prev_work_reg
    };
    writeln!(file, "    movl {addr_reg}, %ecx")?;
    if addr_is_dense_index {
        writeln!(
            file,
            "    addl {AOT_CTX_MEMORY_BASE_WORD_OFFSET}(%r12), %ecx"
        )?;
    }
    writeln!(file, "    movq {AOT_CTX_PREFLIGHT_CYCLE_OFFSET}(%r12), %r9")?;
    writeln!(file, "    movq (%r9), %r9")?;
    writeln!(file, "    addq ${}, %r9", cycle_offset + 3)?;
    if prev_is_ordinal {
        writeln!(file, "    shlq $2, {event_prev_work_reg}")?;
    }
    writeln!(
        file,
        "    testq {event_prev_work_reg}, {event_prev_work_reg}"
    )?;
    writeln!(file, "    je 1f")?;
    writeln!(file, "    orq $3, {event_prev_work_reg}")?;
    writeln!(file, "1:")?;
    writeln!(
        file,
        "    movl %ecx, {AOT_CTX_PREFLIGHT_EVENT_ADDR_OFFSET}(%r12)"
    )?;
    emit_preflight_direct_event_append(
        &mut file,
        event_prev_work_reg,
        "%r9",
        "%ecx",
        AOT_PREFLIGHT_HELPER_MEMORY_FIRST_TOUCH,
    )?;
    writeln!(file, "    jmp {done_label}")?;
    writeln!(file, ".popsection")?;
    writeln!(file, "{done_label}:")?;
    Ok(())
}

pub(super) fn emit_preflight_direct_register_access_cached(
    mut file: impl Write,
    reg_idx: u32,
    subcycle: PreflightSubcycle,
    emit_event: bool,
) -> Result<()> {
    let addr = reg_idx << 6;
    let offset = addr as u64 * std::mem::size_of::<Cycle>() as u64;
    writeln!(file, "    movq %r8, %rax")?;
    writeln!(file, "    addq ${}, %rax", subcycle.value())?;
    writeln!(file, "    movq {offset}(%rdx), %r11")?;
    writeln!(file, "    movq %rax, {offset}(%rdx)")?;
    if !emit_event {
        return Ok(());
    }
    // Zero is the uninitialized sentinel, and every shard starts after cycle zero,
    // so the unsigned shard-start comparison also covers first touches.
    writeln!(file, "    cmpq %r10, %r11")?;
    writeln!(file, "    jae 2f")?;
    writeln!(
        file,
        "    movl ${addr}, {AOT_CTX_PREFLIGHT_EVENT_ADDR_OFFSET}(%r12)"
    )?;
    emit_preflight_direct_event_append(
        &mut file,
        "%r11",
        "%rax",
        &format!("${addr}"),
        AOT_PREFLIGHT_HELPER_FIRST_TOUCH,
    )?;
    writeln!(file, "2:")?;
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum NativeOpcodeFamily {
    Compute,
    ControlFlow,
    Memory,
}

pub(super) fn native_opcode_family(kind: InsnKind) -> Option<NativeOpcodeFamily> {
    if supports_native_compute(kind) {
        Some(NativeOpcodeFamily::Compute)
    } else if supports_native_control_flow(kind) {
        Some(NativeOpcodeFamily::ControlFlow)
    } else if supports_native_memory(kind) {
        Some(NativeOpcodeFamily::Memory)
    } else {
        None
    }
}

pub(super) fn emit_instruction_body(
    mut file: impl Write,
    program: &Program,
    pc: u32,
    insn: Instruction,
    trace_style: AssemblyTraceStyle,
    reserved_block_step: Option<ReservedBlockStep>,
) -> Result<()> {
    match native_opcode_family(insn.kind) {
        Some(NativeOpcodeFamily::Compute) => emit_native_compute(
            &mut file,
            pc,
            program,
            insn,
            trace_style,
            reserved_block_step,
        ),
        Some(NativeOpcodeFamily::ControlFlow) => emit_native_control_flow(
            &mut file,
            pc,
            program,
            insn,
            trace_style,
            reserved_block_step,
        ),
        Some(NativeOpcodeFamily::Memory) => emit_native_memory(
            &mut file,
            pc,
            program,
            insn,
            trace_style,
            reserved_block_step,
        ),
        None => emit_call_one(
            &mut file,
            pc,
            if insn.kind == InsnKind::ECALL {
                AOT_FALLBACK_ECALL
            } else {
                AOT_FALLBACK_EXCEPTIONAL
            },
            trace_style,
        ),
    }
}

pub(super) fn supports_native_compute(kind: InsnKind) -> bool {
    let base_supported = matches!(
        kind,
        InsnKind::ADD
            | InsnKind::SUB
            | InsnKind::XOR
            | InsnKind::OR
            | InsnKind::AND
            | InsnKind::SLL
            | InsnKind::SRL
            | InsnKind::SRA
            | InsnKind::SLT
            | InsnKind::SLTU
            | InsnKind::MUL
            | InsnKind::MULH
            | InsnKind::MULHSU
            | InsnKind::MULHU
            | InsnKind::DIV
            | InsnKind::DIVU
            | InsnKind::REM
            | InsnKind::REMU
            | InsnKind::ADDI
            | InsnKind::XORI
            | InsnKind::ORI
            | InsnKind::ANDI
            | InsnKind::SLLI
            | InsnKind::SRLI
            | InsnKind::SRAI
            | InsnKind::SLTI
            | InsnKind::SLTIU
    );
    #[cfg(feature = "u16limb_circuit")]
    let feature_supported = matches!(kind, InsnKind::LUI | InsnKind::AUIPC);
    #[cfg(not(feature = "u16limb_circuit"))]
    let feature_supported = false;
    base_supported || feature_supported
}

pub(super) fn supports_native_control_flow(kind: InsnKind) -> bool {
    matches!(
        kind,
        InsnKind::BEQ
            | InsnKind::BNE
            | InsnKind::BLT
            | InsnKind::BGE
            | InsnKind::BLTU
            | InsnKind::BGEU
            | InsnKind::JAL
            | InsnKind::JALR
    )
}

pub(super) fn supports_native_memory(kind: InsnKind) -> bool {
    matches!(
        kind,
        InsnKind::LB
            | InsnKind::LH
            | InsnKind::LW
            | InsnKind::LBU
            | InsnKind::LHU
            | InsnKind::SB
            | InsnKind::SH
            | InsnKind::SW
    )
}

pub(super) fn native_compute_reads_rs2(kind: InsnKind) -> bool {
    matches!(
        kind,
        InsnKind::ADD
            | InsnKind::SUB
            | InsnKind::XOR
            | InsnKind::OR
            | InsnKind::AND
            | InsnKind::SLL
            | InsnKind::SRL
            | InsnKind::SRA
            | InsnKind::SLT
            | InsnKind::SLTU
            | InsnKind::MUL
            | InsnKind::MULH
            | InsnKind::MULHSU
            | InsnKind::MULHU
            | InsnKind::DIV
            | InsnKind::DIVU
            | InsnKind::REM
            | InsnKind::REMU
    )
}

pub(super) fn native_step_reads_rs1(kind: InsnKind) -> bool {
    supports_native_compute(kind)
        || matches!(
            kind,
            InsnKind::BEQ
                | InsnKind::BNE
                | InsnKind::BLT
                | InsnKind::BGE
                | InsnKind::BLTU
                | InsnKind::BGEU
                | InsnKind::JALR
                | InsnKind::LB
                | InsnKind::LH
                | InsnKind::LW
                | InsnKind::LBU
                | InsnKind::LHU
                | InsnKind::SB
                | InsnKind::SH
                | InsnKind::SW
        )
}

pub(super) fn native_step_reads_rs2(kind: InsnKind) -> bool {
    native_compute_reads_rs2(kind)
        || matches!(
            kind,
            InsnKind::BEQ
                | InsnKind::BNE
                | InsnKind::BLT
                | InsnKind::BGE
                | InsnKind::BLTU
                | InsnKind::BGEU
                | InsnKind::SB
                | InsnKind::SH
                | InsnKind::SW
        )
}

pub(super) fn native_step_writes_rd(kind: InsnKind) -> bool {
    let base_writes_rd = matches!(
        kind,
        InsnKind::ADD
            | InsnKind::SUB
            | InsnKind::XOR
            | InsnKind::OR
            | InsnKind::AND
            | InsnKind::SLL
            | InsnKind::SRL
            | InsnKind::SRA
            | InsnKind::SLT
            | InsnKind::SLTU
            | InsnKind::MUL
            | InsnKind::MULH
            | InsnKind::MULHSU
            | InsnKind::MULHU
            | InsnKind::DIV
            | InsnKind::DIVU
            | InsnKind::REM
            | InsnKind::REMU
            | InsnKind::ADDI
            | InsnKind::XORI
            | InsnKind::ORI
            | InsnKind::ANDI
            | InsnKind::SLLI
            | InsnKind::SRLI
            | InsnKind::SRAI
            | InsnKind::SLTI
            | InsnKind::SLTIU
            | InsnKind::JAL
            | InsnKind::JALR
            | InsnKind::LB
            | InsnKind::LH
            | InsnKind::LW
            | InsnKind::LBU
            | InsnKind::LHU
    );
    #[cfg(feature = "u16limb_circuit")]
    let feature_writes_rd = matches!(kind, InsnKind::LUI | InsnKind::AUIPC);
    #[cfg(not(feature = "u16limb_circuit"))]
    let feature_writes_rd = false;
    base_writes_rd || feature_writes_rd
}

pub(super) fn native_step_loads_memory(kind: InsnKind) -> bool {
    matches!(
        kind,
        InsnKind::LB | InsnKind::LH | InsnKind::LW | InsnKind::LBU | InsnKind::LHU
    )
}

pub(super) fn native_step_stores_memory(kind: InsnKind) -> bool {
    matches!(kind, InsnKind::SB | InsnKind::SH | InsnKind::SW)
}

pub(super) fn native_trace_flags(insn: Instruction) -> u32 {
    let mut flags = 0;
    if native_step_reads_rs1(insn.kind) {
        flags |= NATIVE_TRACE_READ_RS1;
    }
    if native_step_reads_rs2(insn.kind) {
        flags |= NATIVE_TRACE_READ_RS2;
    }
    if native_step_writes_rd(insn.kind) {
        flags |= NATIVE_TRACE_WRITE_RD;
    }
    if native_step_loads_memory(insn.kind) {
        flags |= NATIVE_TRACE_LOAD_MEM;
    }
    if native_step_stores_memory(insn.kind) {
        flags |= NATIVE_TRACE_STORE_MEM;
    }
    flags
}

pub(super) fn emit_native_trace_metadata(
    mut file: impl Write,
    pc: u32,
    program: &Program,
    insn: Instruction,
) -> Result<()> {
    writeln!(
        file,
        "    movl ${:#010x}, {AOT_CTX_TRACE_FLAGS_OFFSET}(%r12)",
        native_trace_flags(insn)
    )?;
    writeln!(
        file,
        "    movl ${}, {AOT_CTX_TRACE_RS1_IDX_OFFSET}(%r12)",
        insn.rs1
    )?;
    writeln!(
        file,
        "    movl ${}, {AOT_CTX_TRACE_RS2_IDX_OFFSET}(%r12)",
        insn.rs2
    )?;
    writeln!(
        file,
        "    movl ${}, {AOT_CTX_TRACE_RD_IDX_OFFSET}(%r12)",
        insn.rd_internal()
    )?;
    writeln!(
        file,
        "    movl ${}, {AOT_CTX_TRACE_KIND_OFFSET}(%r12)",
        insn.kind as u8
    )?;
    let insn_idx = (pc.wrapping_sub(program.base_address) / PC_STEP_SIZE as u32) as usize;
    writeln!(
        file,
        "    movq {AOT_CTX_PREFLIGHT_STEP_CELLS_TABLE_OFFSET}(%r12), %rax"
    )?;
    writeln!(file, "    testq %rax, %rax")?;
    writeln!(file, "    je 1f")?;
    writeln!(file, "    movq {}(%rax), %rax", insn_idx * 8)?;
    writeln!(
        file,
        "    movq %rax, {AOT_CTX_PREFLIGHT_STEP_CELLS_OFFSET}(%r12)"
    )?;
    writeln!(file, "    jmp 2f")?;
    writeln!(file, "1:")?;
    writeln!(
        file,
        "    movq $0, {AOT_CTX_PREFLIGHT_STEP_CELLS_OFFSET}(%r12)"
    )?;
    writeln!(file, "2:")?;
    Ok(())
}

pub(super) fn native_trace_kind(kind: u32) -> InsnKind {
    match kind as u8 {
        x if x == InsnKind::ADD as u8 => InsnKind::ADD,
        x if x == InsnKind::SUB as u8 => InsnKind::SUB,
        x if x == InsnKind::XOR as u8 => InsnKind::XOR,
        x if x == InsnKind::OR as u8 => InsnKind::OR,
        x if x == InsnKind::AND as u8 => InsnKind::AND,
        x if x == InsnKind::SLL as u8 => InsnKind::SLL,
        x if x == InsnKind::SRL as u8 => InsnKind::SRL,
        x if x == InsnKind::SRA as u8 => InsnKind::SRA,
        x if x == InsnKind::SLT as u8 => InsnKind::SLT,
        x if x == InsnKind::SLTU as u8 => InsnKind::SLTU,
        x if x == InsnKind::ADDI as u8 => InsnKind::ADDI,
        x if x == InsnKind::XORI as u8 => InsnKind::XORI,
        x if x == InsnKind::ORI as u8 => InsnKind::ORI,
        x if x == InsnKind::ANDI as u8 => InsnKind::ANDI,
        x if x == InsnKind::SLLI as u8 => InsnKind::SLLI,
        x if x == InsnKind::SRLI as u8 => InsnKind::SRLI,
        x if x == InsnKind::SRAI as u8 => InsnKind::SRAI,
        x if x == InsnKind::SLTI as u8 => InsnKind::SLTI,
        x if x == InsnKind::SLTIU as u8 => InsnKind::SLTIU,
        x if x == InsnKind::BEQ as u8 => InsnKind::BEQ,
        x if x == InsnKind::BNE as u8 => InsnKind::BNE,
        x if x == InsnKind::BLT as u8 => InsnKind::BLT,
        x if x == InsnKind::BGE as u8 => InsnKind::BGE,
        x if x == InsnKind::BLTU as u8 => InsnKind::BLTU,
        x if x == InsnKind::BGEU as u8 => InsnKind::BGEU,
        x if x == InsnKind::JAL as u8 => InsnKind::JAL,
        x if x == InsnKind::JALR as u8 => InsnKind::JALR,
        x if x == InsnKind::MUL as u8 => InsnKind::MUL,
        x if x == InsnKind::MULH as u8 => InsnKind::MULH,
        x if x == InsnKind::MULHSU as u8 => InsnKind::MULHSU,
        x if x == InsnKind::MULHU as u8 => InsnKind::MULHU,
        x if x == InsnKind::DIV as u8 => InsnKind::DIV,
        x if x == InsnKind::DIVU as u8 => InsnKind::DIVU,
        x if x == InsnKind::REM as u8 => InsnKind::REM,
        x if x == InsnKind::REMU as u8 => InsnKind::REMU,
        x if x == InsnKind::LB as u8 => InsnKind::LB,
        x if x == InsnKind::LH as u8 => InsnKind::LH,
        x if x == InsnKind::LW as u8 => InsnKind::LW,
        x if x == InsnKind::LBU as u8 => InsnKind::LBU,
        x if x == InsnKind::LHU as u8 => InsnKind::LHU,
        #[cfg(feature = "u16limb_circuit")]
        x if x == InsnKind::LUI as u8 => InsnKind::LUI,
        #[cfg(feature = "u16limb_circuit")]
        x if x == InsnKind::AUIPC as u8 => InsnKind::AUIPC,
        x if x == InsnKind::SB as u8 => InsnKind::SB,
        x if x == InsnKind::SH as u8 => InsnKind::SH,
        x if x == InsnKind::SW as u8 => InsnKind::SW,
        _ => InsnKind::INVALID,
    }
}

pub(super) fn emit_native_next_pc_immediate(
    mut file: impl Write,
    next_pc: u32,
    trace_style: AssemblyTraceStyle,
) -> Result<()> {
    if trace_style.carries_next_pc_in_register() {
        writeln!(file, "    movl ${next_pc:#010x}, %r15d")?;
    } else {
        writeln!(
            file,
            "    movl ${next_pc:#010x}, {AOT_CTX_TRACE_NEXT_PC_OFFSET}(%r12)"
        )?;
    }
    Ok(())
}

pub(super) fn emit_native_next_pc_register(
    mut file: impl Write,
    next_pc_reg: &str,
    trace_style: AssemblyTraceStyle,
) -> Result<()> {
    if trace_style.carries_next_pc_in_register() {
        writeln!(file, "    movl {next_pc_reg}, %r15d")?;
    } else {
        writeln!(
            file,
            "    movl {next_pc_reg}, {AOT_CTX_TRACE_NEXT_PC_OFFSET}(%r12)"
        )?;
    }
    Ok(())
}

pub(super) fn emit_native_compute(
    mut file: impl Write,
    pc: u32,
    program: &Program,
    insn: Instruction,
    trace_style: AssemblyTraceStyle,
    reserved_block_step: Option<ReservedBlockStep>,
) -> Result<()> {
    let execution_reserved = if trace_style == AssemblyTraceStyle::GpuReplayDirect {
        None
    } else {
        reserved_block_step
    };
    let rd = insn.rd_internal();
    if !execution_reserved.is_some_and(|step| step.registers_resident) {
        writeln!(file, "    movq %r13, %r10")?;
    }
    writeln!(file, "    movl {}(%r10), %eax", insn.rs1 as usize * 4)?;
    if trace_style.needs_callback_values() {
        writeln!(
            file,
            "    movl %eax, {AOT_CTX_TRACE_RS1_VALUE_OFFSET}(%r12)"
        )?;
    }
    if native_compute_reads_rs2(insn.kind) {
        writeln!(file, "    movl {}(%r10), %ecx", insn.rs2 as usize * 4)?;
        if trace_style.needs_callback_values() {
            writeln!(
                file,
                "    movl %ecx, {AOT_CTX_TRACE_RS2_VALUE_OFFSET}(%r12)"
            )?;
        }
    } else if trace_style.needs_callback_values() {
        writeln!(file, "    movl $0, {AOT_CTX_TRACE_RS2_VALUE_OFFSET}(%r12)")?;
    }
    if trace_style.needs_callback_values() {
        writeln!(file, "    movl {}(%r10), %edx", rd as usize * 4)?;
        writeln!(
            file,
            "    movl %edx, {AOT_CTX_TRACE_RD_BEFORE_OFFSET}(%r12)"
        )?;
    }
    match insn.kind {
        InsnKind::ADD => writeln!(file, "    addl %ecx, %eax")?,
        InsnKind::SUB => writeln!(file, "    subl %ecx, %eax")?,
        InsnKind::XOR => writeln!(file, "    xorl %ecx, %eax")?,
        InsnKind::OR => writeln!(file, "    orl %ecx, %eax")?,
        InsnKind::AND => writeln!(file, "    andl %ecx, %eax")?,
        InsnKind::SLL => writeln!(file, "    shll %cl, %eax")?,
        InsnKind::SRL => writeln!(file, "    shrl %cl, %eax")?,
        InsnKind::SRA => writeln!(file, "    sarl %cl, %eax")?,
        InsnKind::SLT => {
            writeln!(file, "    cmpl %ecx, %eax")?;
            writeln!(file, "    setl %al")?;
            writeln!(file, "    movzbl %al, %eax")?;
        }
        InsnKind::SLTU => {
            writeln!(file, "    cmpl %ecx, %eax")?;
            writeln!(file, "    setb %al")?;
            writeln!(file, "    movzbl %al, %eax")?;
        }
        InsnKind::MUL => writeln!(file, "    imull %ecx, %eax")?,
        InsnKind::MULH => {
            writeln!(file, "    imull %ecx")?;
            writeln!(file, "    movl %edx, %eax")?;
        }
        InsnKind::MULHSU => {
            writeln!(file, "    movslq %eax, %rax")?;
            writeln!(file, "    movl %ecx, %ecx")?;
            writeln!(file, "    imulq %rcx, %rax")?;
            writeln!(file, "    sarq $32, %rax")?;
        }
        InsnKind::MULHU => {
            writeln!(file, "    mull %ecx")?;
            writeln!(file, "    movl %edx, %eax")?;
        }
        InsnKind::DIV => emit_native_signed_div(&mut file, pc, SignedDivOp::Quotient)?,
        InsnKind::REM => emit_native_signed_div(&mut file, pc, SignedDivOp::Remainder)?,
        InsnKind::DIVU => emit_native_unsigned_div(&mut file, pc, UnsignedDivOp::Quotient)?,
        InsnKind::REMU => emit_native_unsigned_div(&mut file, pc, UnsignedDivOp::Remainder)?,
        InsnKind::ADDI => writeln!(file, "    addl ${:#010x}, %eax", insn.imm as u32)?,
        InsnKind::XORI => writeln!(file, "    xorl ${:#010x}, %eax", insn.imm as u32)?,
        InsnKind::ORI => writeln!(file, "    orl ${:#010x}, %eax", insn.imm as u32)?,
        InsnKind::ANDI => writeln!(file, "    andl ${:#010x}, %eax", insn.imm as u32)?,
        InsnKind::SLLI => writeln!(file, "    shll ${}, %eax", insn.imm as u32 & 0x1f)?,
        InsnKind::SRLI => writeln!(file, "    shrl ${}, %eax", insn.imm as u32 & 0x1f)?,
        InsnKind::SRAI => writeln!(file, "    sarl ${}, %eax", insn.imm as u32 & 0x1f)?,
        InsnKind::SLTI => {
            writeln!(file, "    cmpl ${:#010x}, %eax", insn.imm as u32)?;
            writeln!(file, "    setl %al")?;
            writeln!(file, "    movzbl %al, %eax")?;
        }
        InsnKind::SLTIU => {
            writeln!(file, "    cmpl ${:#010x}, %eax", insn.imm as u32)?;
            writeln!(file, "    setb %al")?;
            writeln!(file, "    movzbl %al, %eax")?;
        }
        #[cfg(feature = "u16limb_circuit")]
        InsnKind::LUI => writeln!(file, "    movl ${:#010x}, %eax", insn.imm as u32)?,
        #[cfg(feature = "u16limb_circuit")]
        InsnKind::AUIPC => writeln!(
            file,
            "    movl ${:#010x}, %eax",
            pc.wrapping_add(insn.imm as u32)
        )?,
        _ => unreachable!("unsupported native compute instruction: {:?}", insn.kind),
    }
    writeln!(file, "    movl %eax, {}(%r10)", rd as usize * 4)?;
    if trace_style.needs_callback_values() {
        writeln!(file, "    movl %eax, {AOT_CTX_TRACE_RD_AFTER_OFFSET}(%r12)")?;
        writeln!(
            file,
            "    movl ${pc:#010x}, {AOT_CTX_TRACE_PC_OFFSET}(%r12)"
        )?;
    }
    if execution_reserved.is_none_or(|step| step.remaining_after == 0) {
        emit_native_next_pc_immediate(
            &mut file,
            pc.wrapping_add(PC_STEP_SIZE as u32),
            trace_style,
        )?;
    }
    emit_after_native_step(
        &mut file,
        pc,
        program,
        insn,
        trace_style,
        false,
        false,
        reserved_block_step,
    )?;
    Ok(())
}

#[derive(Clone, Copy)]
pub(super) enum SignedDivOp {
    Quotient,
    Remainder,
}

pub(super) fn emit_native_signed_div(mut file: impl Write, pc: u32, op: SignedDivOp) -> Result<()> {
    let zero_label = format!(".L_signed_div_zero_{pc:x}");
    let overflow_label = format!(".L_signed_div_overflow_{pc:x}");
    let done_label = format!(".L_signed_div_done_{pc:x}");

    writeln!(file, "    testl %ecx, %ecx")?;
    writeln!(file, "    je {zero_label}")?;
    writeln!(file, "    cmpl $0xffffffff, %ecx")?;
    writeln!(file, "    jne 1f")?;
    writeln!(file, "    cmpl $0x80000000, %eax")?;
    writeln!(file, "    je {overflow_label}")?;
    writeln!(file, "1:")?;
    writeln!(file, "    cltd")?;
    writeln!(file, "    idivl %ecx")?;
    if matches!(op, SignedDivOp::Remainder) {
        writeln!(file, "    movl %edx, %eax")?;
    }
    writeln!(file, "    jmp {done_label}")?;
    writeln!(file, "{zero_label}:")?;
    if matches!(op, SignedDivOp::Quotient) {
        writeln!(file, "    movl $0xffffffff, %eax")?;
    }
    writeln!(file, "    jmp {done_label}")?;
    writeln!(file, "{overflow_label}:")?;
    match op {
        SignedDivOp::Quotient => writeln!(file, "    movl $0x80000000, %eax")?,
        SignedDivOp::Remainder => writeln!(file, "    xorl %eax, %eax")?,
    }
    writeln!(file, "{done_label}:")?;
    Ok(())
}

#[derive(Clone, Copy)]
pub(super) enum UnsignedDivOp {
    Quotient,
    Remainder,
}

pub(super) fn emit_native_unsigned_div(
    mut file: impl Write,
    pc: u32,
    op: UnsignedDivOp,
) -> Result<()> {
    let zero_label = format!(".L_unsigned_div_zero_{pc:x}");
    let done_label = format!(".L_unsigned_div_done_{pc:x}");

    writeln!(file, "    testl %ecx, %ecx")?;
    writeln!(file, "    je {zero_label}")?;
    writeln!(file, "    xorl %edx, %edx")?;
    writeln!(file, "    divl %ecx")?;
    if matches!(op, UnsignedDivOp::Remainder) {
        writeln!(file, "    movl %edx, %eax")?;
    }
    writeln!(file, "    jmp {done_label}")?;
    writeln!(file, "{zero_label}:")?;
    if matches!(op, UnsignedDivOp::Quotient) {
        writeln!(file, "    movl $0xffffffff, %eax")?;
    }
    writeln!(file, "{done_label}:")?;
    Ok(())
}

pub(super) fn emit_native_control_flow(
    mut file: impl Write,
    pc: u32,
    program: &Program,
    insn: Instruction,
    trace_style: AssemblyTraceStyle,
    reserved_block_step: Option<ReservedBlockStep>,
) -> Result<()> {
    let execution_reserved = if trace_style == AssemblyTraceStyle::GpuReplayDirect {
        None
    } else {
        reserved_block_step
    };
    if !execution_reserved.is_some_and(|step| step.registers_resident) {
        writeln!(file, "    movq %r13, %r10")?;
    }
    if trace_style.needs_callback_values() {
        writeln!(
            file,
            "    movl ${pc:#010x}, {AOT_CTX_TRACE_PC_OFFSET}(%r12)"
        )?;
        writeln!(file, "    movl $0, {AOT_CTX_TRACE_RS1_VALUE_OFFSET}(%r12)")?;
        writeln!(file, "    movl $0, {AOT_CTX_TRACE_RS2_VALUE_OFFSET}(%r12)")?;
        writeln!(file, "    movl $0, {AOT_CTX_TRACE_RD_BEFORE_OFFSET}(%r12)")?;
        writeln!(file, "    movl $0, {AOT_CTX_TRACE_RD_AFTER_OFFSET}(%r12)")?;
    }

    if insn.kind == InsnKind::JAL {
        let rd = insn.rd_internal();
        if trace_style.needs_callback_values() {
            writeln!(file, "    movl {}(%r10), %edx", rd as usize * 4)?;
            writeln!(
                file,
                "    movl %edx, {AOT_CTX_TRACE_RD_BEFORE_OFFSET}(%r12)"
            )?;
        }
        writeln!(
            file,
            "    movl ${:#010x}, %eax",
            pc.wrapping_add(PC_STEP_SIZE as u32)
        )?;
        writeln!(file, "    movl %eax, {}(%r10)", rd as usize * 4)?;
        if trace_style.needs_callback_values() {
            writeln!(file, "    movl %eax, {AOT_CTX_TRACE_RD_AFTER_OFFSET}(%r12)")?;
        }
        emit_native_next_pc_immediate(&mut file, branch_target(pc, insn)?, trace_style)?;
    } else if insn.kind == InsnKind::JALR {
        let slow_label = format!(".L_jalr_slow_{pc:x}");
        let done_label = format!(".L_jalr_done_{pc:x}");
        let rd = insn.rd_internal();
        writeln!(file, "    movl {}(%r10), %eax", insn.rs1 as usize * 4)?;
        if trace_style.needs_callback_values() {
            writeln!(
                file,
                "    movl %eax, {AOT_CTX_TRACE_RS1_VALUE_OFFSET}(%r12)"
            )?;
        }
        writeln!(file, "    leal {}(%rax), %edx", insn.imm)?;
        writeln!(file, "    andl $0xfffffffe, %edx")?;
        writeln!(file, "    testl $3, %edx")?;
        writeln!(file, "    jne {slow_label}")?;
        emit_native_next_pc_register(&mut file, "%edx", trace_style)?;
        if trace_style.needs_callback_values() {
            writeln!(file, "    movl {}(%r10), %edx", rd as usize * 4)?;
            writeln!(
                file,
                "    movl %edx, {AOT_CTX_TRACE_RD_BEFORE_OFFSET}(%r12)"
            )?;
        }
        writeln!(
            file,
            "    movl ${:#010x}, %eax",
            pc.wrapping_add(PC_STEP_SIZE as u32)
        )?;
        writeln!(file, "    movl %eax, {}(%r10)", rd as usize * 4)?;
        if trace_style.needs_callback_values() {
            writeln!(file, "    movl %eax, {AOT_CTX_TRACE_RD_AFTER_OFFSET}(%r12)")?;
        }
        emit_after_native_step(
            &mut file,
            pc,
            program,
            insn,
            trace_style,
            false,
            false,
            reserved_block_step,
        )?;
        writeln!(file, "    jmp {done_label}")?;
        writeln!(file, "{slow_label}:")?;
        emit_rollback_reserved_block_steps(&mut file, execution_reserved)?;
        emit_call_one(&mut file, pc, AOT_FALLBACK_EXCEPTIONAL, trace_style)?;
        emit_restore_reserved_block_steps(&mut file, execution_reserved)?;
        writeln!(file, "{done_label}:")?;
        return Ok(());
    } else {
        let target_pc = branch_target(pc, insn)?;
        let fallthrough_pc = pc.wrapping_add(PC_STEP_SIZE as u32);
        let taken_label = format!(".L_branch_taken_{pc:x}");
        let done_label = format!(".L_branch_done_{pc:x}");
        writeln!(file, "    movl {}(%r10), %eax", insn.rs1 as usize * 4)?;
        if trace_style.needs_callback_values() {
            writeln!(
                file,
                "    movl %eax, {AOT_CTX_TRACE_RS1_VALUE_OFFSET}(%r12)"
            )?;
        }
        writeln!(file, "    movl {}(%r10), %ecx", insn.rs2 as usize * 4)?;
        if trace_style.needs_callback_values() {
            writeln!(
                file,
                "    movl %ecx, {AOT_CTX_TRACE_RS2_VALUE_OFFSET}(%r12)"
            )?;
        }
        writeln!(file, "    cmpl %ecx, %eax")?;
        match insn.kind {
            InsnKind::BEQ => writeln!(file, "    je {taken_label}")?,
            InsnKind::BNE => writeln!(file, "    jne {taken_label}")?,
            InsnKind::BLT => writeln!(file, "    jl {taken_label}")?,
            InsnKind::BGE => writeln!(file, "    jge {taken_label}")?,
            InsnKind::BLTU => writeln!(file, "    jb {taken_label}")?,
            InsnKind::BGEU => writeln!(file, "    jae {taken_label}")?,
            _ => unreachable!(
                "unsupported native control-flow instruction: {:?}",
                insn.kind
            ),
        }
        emit_native_next_pc_immediate(&mut file, fallthrough_pc, trace_style)?;
        writeln!(file, "    jmp {done_label}")?;
        writeln!(file, "{taken_label}:")?;
        emit_native_next_pc_immediate(&mut file, target_pc, trace_style)?;
        writeln!(file, "{done_label}:")?;
    }

    emit_after_native_step(
        &mut file,
        pc,
        program,
        insn,
        trace_style,
        false,
        false,
        reserved_block_step,
    )?;
    Ok(())
}

pub(super) fn emit_native_memory(
    mut file: impl Write,
    pc: u32,
    program: &Program,
    insn: Instruction,
    trace_style: AssemblyTraceStyle,
    reserved_block_step: Option<ReservedBlockStep>,
) -> Result<()> {
    let execution_reserved = if trace_style == AssemblyTraceStyle::GpuReplayDirect {
        None
    } else {
        reserved_block_step
    };
    let slow_label = format!(".L_memory_slow_{pc:x}");
    let done_label = format!(".L_memory_done_{pc:x}");
    let heap_ok_label = format!(".L_memory_heap_ok_{pc:x}");
    let stack_ok_label = format!(".L_memory_stack_ok_{pc:x}");
    let hints_ok_label = format!(".L_memory_hints_ok_{pc:x}");
    let dense_ok_label = format!(".L_memory_dense_ok_{pc:x}");
    let body_label = format!(".L_memory_body_{pc:x}");
    let rd = insn.rd_internal();
    let tracks_memory_latest = !trace_style.is_pure()
        && trace_style.preflight_feature_enabled(PreflightFeature::MemoryLatest);
    let tracks_mmio_bounds = !trace_style.is_pure()
        && trace_style.preflight_feature_enabled(PreflightFeature::MmioBounds);
    let emits_memory_event_early = !cfg!(debug_assertions)
        && execution_reserved.is_some()
        && trace_style.uses_preflight_block_plan()
        && trace_style.preflight_feature_enabled(PreflightFeature::MemoryEvents);
    let memory_guard_hoisted = execution_reserved
        .map(|step| step.memory_guard_hoisted)
        .unwrap_or(false);
    let encoded_memory_region = execution_reserved.and_then(|step| step.memory_region_index);
    let memory_cells_resident = execution_reserved.is_some_and(|step| step.memory_cells_resident);
    let memory_ordinal_resident =
        execution_reserved.is_some_and(|step| step.memory_ordinal_resident);
    let memory_cells = if trace_style.is_pure() {
        "%rbx"
    } else {
        "%r11"
    };

    if !trace_style.is_pure() && !memory_cells_resident {
        writeln!(file, "    movq {AOT_CTX_MEMORY_CELLS_OFFSET}(%r12), %r11")?;
    }
    if trace_style.needs_callback_values() {
        writeln!(
            file,
            "    movl ${pc:#010x}, {AOT_CTX_TRACE_PC_OFFSET}(%r12)"
        )?;
    }
    if execution_reserved.is_none_or(|step| step.remaining_after == 0) {
        emit_native_next_pc_immediate(
            &mut file,
            pc.wrapping_add(PC_STEP_SIZE as u32),
            trace_style,
        )?;
    }
    if trace_style.needs_callback_values() {
        writeln!(file, "    movl $0, {AOT_CTX_TRACE_RS2_VALUE_OFFSET}(%r12)")?;
        writeln!(file, "    movl $0, {AOT_CTX_TRACE_RD_BEFORE_OFFSET}(%r12)")?;
        writeln!(file, "    movl $0, {AOT_CTX_TRACE_RD_AFTER_OFFSET}(%r12)")?;
    }
    if !execution_reserved.is_some_and(|step| step.registers_resident) {
        writeln!(file, "    movq %r13, %r10")?;
    }
    writeln!(file, "    movl {}(%r10), %eax", insn.rs1 as usize * 4)?;
    if trace_style.needs_callback_values() {
        writeln!(
            file,
            "    movl %eax, {AOT_CTX_TRACE_RS1_VALUE_OFFSET}(%r12)"
        )?;
    }
    writeln!(file, "    leal {}(%rax), %edx", insn.imm)?;
    if trace_style != AssemblyTraceStyle::PureBlock && !memory_guard_hoisted {
        match insn.kind {
            InsnKind::LH | InsnKind::LHU | InsnKind::SH => {
                writeln!(file, "    testl $1, %edx")?;
                writeln!(file, "    jne {slow_label}")?;
            }
            InsnKind::LW | InsnKind::SW => {
                writeln!(file, "    testl $3, %edx")?;
                writeln!(file, "    jne {slow_label}")?;
            }
            _ => {}
        }
    }
    if trace_style == AssemblyTraceStyle::PureBlock {
        // Alignment and dense-memory membership were checked once at block
        // entry, using bases that this block cannot overwrite.
    } else if trace_style.is_pure() {
        // Value-only execution does not maintain heap/stack/hints extrema, so
        // one unsigned dense-memory check is sufficient. Traced modes retain
        // exact region classification and bounds updates below.
        writeln!(file, "    subl %r14d, %edx")?;
        writeln!(file, "    cmpl 64(%rsp), %edx")?;
        writeln!(file, "    jae {slow_label}")?;
    } else if tracks_mmio_bounds && encoded_memory_region.is_none() {
        emit_native_range_check(
            &mut file,
            AOT_CTX_HEAP_START_OFFSET,
            AOT_CTX_HEAP_END_OFFSET,
            &heap_ok_label,
        )?;
        emit_native_range_check(
            &mut file,
            AOT_CTX_STACK_START_OFFSET,
            AOT_CTX_STACK_END_OFFSET,
            &stack_ok_label,
        )?;
        emit_native_range_check(
            &mut file,
            AOT_CTX_HINTS_START_OFFSET,
            AOT_CTX_HINTS_END_OFFSET,
            &hints_ok_label,
        )?;
        writeln!(file, "    movl %edx, %eax")?;
        writeln!(file, "    shrl $2, %eax")?;
        writeln!(
            file,
            "    cmpl {AOT_CTX_MEMORY_BASE_WORD_OFFSET}(%r12), %eax"
        )?;
        writeln!(file, "    jb {slow_label}")?;
        writeln!(
            file,
            "    cmpl {AOT_CTX_MEMORY_END_WORD_OFFSET}(%r12), %eax"
        )?;
        writeln!(file, "    jb {dense_ok_label}")?;
        writeln!(file, "    jmp {slow_label}")?;

        emit_native_memory_region_entry(
            &mut file,
            &heap_ok_label,
            &body_label,
            trace_style,
            AOT_CTX_PREFLIGHT_HEAP_MIN_OFFSET,
            AOT_CTX_PREFLIGHT_HEAP_MAX_OFFSET,
        )?;
        emit_native_memory_region_entry(
            &mut file,
            &stack_ok_label,
            &body_label,
            trace_style,
            AOT_CTX_PREFLIGHT_STACK_MIN_OFFSET,
            AOT_CTX_PREFLIGHT_STACK_MAX_OFFSET,
        )?;
        emit_native_memory_region_entry(
            &mut file,
            &hints_ok_label,
            &body_label,
            trace_style,
            AOT_CTX_PREFLIGHT_HINTS_MIN_OFFSET,
            AOT_CTX_PREFLIGHT_HINTS_MAX_OFFSET,
        )?;

        writeln!(file, "{dense_ok_label}:")?;
    } else if !memory_guard_hoisted {
        writeln!(file, "    movl %edx, %eax")?;
        writeln!(file, "    shrl $2, %eax")?;
        writeln!(
            file,
            "    cmpl {AOT_CTX_MEMORY_BASE_WORD_OFFSET}(%r12), %eax"
        )?;
        writeln!(file, "    jb {slow_label}")?;
        writeln!(
            file,
            "    cmpl {AOT_CTX_MEMORY_END_WORD_OFFSET}(%r12), %eax"
        )?;
        writeln!(file, "    jae {slow_label}")?;
    }
    if trace_style.is_pure() {
        if trace_style == AssemblyTraceStyle::PureBlock {
            writeln!(file, "    subl %r14d, %edx")?;
        }
        if matches!(insn.kind, InsnKind::LW | InsnKind::SW) {
            // Word accesses are already aligned, and neither operation needs
            // a byte-lane shift or an address mask.
        } else {
            writeln!(file, "    movl %edx, %r8d")?;
            // Variable 32-bit shifts mask the count to five bits, so after
            // multiplying the byte address by eight the upper address bits
            // cannot affect the selected byte lane.
            writeln!(file, "    shll $3, %r8d")?;
            writeln!(file, "    andl $0xfffffffc, %edx")?;
        }
    } else {
        if !matches!(insn.kind, InsnKind::LW | InsnKind::SW) {
            writeln!(file, "    movl %edx, %r8d")?;
            writeln!(file, "    andl $3, %r8d")?;
            writeln!(file, "    shll $3, %r8d")?;
        }
        writeln!(file, "    shrl $2, %edx")?;
        if should_publish_trace_memory_address(
            trace_style,
            tracks_mmio_bounds,
            emits_memory_event_early,
        ) {
            writeln!(file, "    movl %edx, {AOT_CTX_TRACE_MEM_ADDR_OFFSET}(%r12)")?;
        }
        if let Some(region_index) = encoded_memory_region {
            emit_preflight_direct_encoded_memory_region(&mut file, pc, region_index, &body_label)?;
        }
    }

    writeln!(file, "{body_label}:")?;
    if !trace_style.is_pure() && !memory_cells_resident {
        writeln!(
            file,
            "    subl {AOT_CTX_MEMORY_BASE_WORD_OFFSET}(%r12), %edx"
        )?;
    }
    writeln!(file, "    movl %edx, %esi")?;
    if trace_style.is_pure() {
        writeln!(file, "    movl ({memory_cells},%rsi,2), %eax")?;
    } else if tracks_memory_latest {
        writeln!(file, "    movq ({memory_cells},%rsi,8), %rax")?;
        writeln!(file, "    movq %rax, %rcx")?;
        writeln!(file, "    shrq $32, %rcx")?;
        if emits_memory_event_early {
            emit_preflight_direct_memory_access_cached(
                &mut file,
                pc,
                "%esi",
                execution_reserved
                    .map(|step| step.cycle_offset)
                    .unwrap_or(0),
                Some("%rcx"),
                "%rcx",
                &format!("{AOT_CTX_PREFLIGHT_MEMORY_SHARD_START_ORDINAL_OFFSET}(%r12)"),
                true,
                !memory_cells_resident,
            )?;
        } else {
            writeln!(
                file,
                "    movq %rcx, {AOT_CTX_MEMORY_PREV_STAMP_OFFSET}(%r12)"
            )?;
        }
    } else {
        writeln!(file, "    movl ({memory_cells},%rsi,8), %eax")?;
    }
    match insn.kind {
        InsnKind::LB | InsnKind::LH | InsnKind::LW | InsnKind::LBU | InsnKind::LHU => {
            writeln!(file, "    movl %eax, %r9d")?;
            if trace_style.needs_callback_values() {
                writeln!(
                    file,
                    "    movl %eax, {AOT_CTX_TRACE_MEM_BEFORE_OFFSET}(%r12)"
                )?;
                writeln!(
                    file,
                    "    movl %eax, {AOT_CTX_TRACE_MEM_AFTER_OFFSET}(%r12)"
                )?;
                writeln!(file, "    movl {}(%r10), %ecx", rd as usize * 4)?;
                writeln!(
                    file,
                    "    movl %ecx, {AOT_CTX_TRACE_RD_BEFORE_OFFSET}(%r12)"
                )?;
            }
            if insn.kind != InsnKind::LW {
                writeln!(file, "    movl %r8d, %ecx")?;
                writeln!(file, "    shrl %cl, %eax")?;
            }
            match insn.kind {
                InsnKind::LB => writeln!(file, "    movsbl %al, %eax")?,
                InsnKind::LH => writeln!(file, "    movswl %ax, %eax")?,
                InsnKind::LW => {}
                InsnKind::LBU => writeln!(file, "    movzbl %al, %eax")?,
                InsnKind::LHU => writeln!(file, "    movzwl %ax, %eax")?,
                _ => unreachable!("unsupported native load instruction: {:?}", insn.kind),
            }
            writeln!(file, "    movl %eax, {}(%r10)", rd as usize * 4)?;
            if trace_style.needs_callback_values() {
                writeln!(file, "    movl %eax, {AOT_CTX_TRACE_RD_AFTER_OFFSET}(%r12)")?;
            }
        }
        InsnKind::SB | InsnKind::SH | InsnKind::SW => {
            writeln!(file, "    movl {}(%r10), %r9d", insn.rs2 as usize * 4)?;
            if trace_style.needs_callback_values() {
                writeln!(
                    file,
                    "    movl %r9d, {AOT_CTX_TRACE_RS2_VALUE_OFFSET}(%r12)"
                )?;
            }
            if trace_style.needs_callback_values() {
                writeln!(
                    file,
                    "    movl %eax, {AOT_CTX_TRACE_MEM_BEFORE_OFFSET}(%r12)"
                )?;
            }
            match insn.kind {
                InsnKind::SB => {
                    writeln!(file, "    andl $0xff, %r9d")?;
                    writeln!(file, "    movl %r8d, %ecx")?;
                    writeln!(file, "    shll %cl, %r9d")?;
                    writeln!(file, "    movl $0xff, %edx")?;
                    writeln!(file, "    shll %cl, %edx")?;
                    writeln!(file, "    notl %edx")?;
                    writeln!(file, "    andl %edx, %eax")?;
                    writeln!(file, "    orl %r9d, %eax")?;
                }
                InsnKind::SH => {
                    writeln!(file, "    andl $0xffff, %r9d")?;
                    writeln!(file, "    movl %r8d, %ecx")?;
                    writeln!(file, "    shll %cl, %r9d")?;
                    writeln!(file, "    movl $0xffff, %edx")?;
                    writeln!(file, "    shll %cl, %edx")?;
                    writeln!(file, "    notl %edx")?;
                    writeln!(file, "    andl %edx, %eax")?;
                    writeln!(file, "    orl %r9d, %eax")?;
                }
                InsnKind::SW => {
                    writeln!(file, "    movl %r9d, %eax")?;
                }
                _ => unreachable!("unsupported native store instruction: {:?}", insn.kind),
            }
            if trace_style.needs_callback_values() {
                writeln!(
                    file,
                    "    movl %eax, {AOT_CTX_TRACE_MEM_AFTER_OFFSET}(%r12)"
                )?;
            }
        }
        _ => unreachable!("unsupported native memory instruction: {:?}", insn.kind),
    }
    if trace_style.is_pure() || !tracks_memory_latest {
        if !native_step_loads_memory(insn.kind) {
            // Update only the value half; pure execution deliberately leaves
            // the packed latest-access half untouched.
            let scale = if trace_style.is_pure() { 2 } else { 8 };
            writeln!(file, "    movl %eax, ({memory_cells},%rsi,{scale})")?;
        }
    } else {
        if memory_ordinal_resident {
            let instruction_index = execution_reserved
                .expect("resident memory ordinal requires a reserved block")
                .cycle_offset
                / PC_STEP_SIZE as u64;
            writeln!(file, "    leaq {instruction_index}(%r15), %rcx")?;
        } else {
            writeln!(
                file,
                "    movq {AOT_CTX_MEMORY_START_ORDINAL_OFFSET}(%r12), %rcx"
            )?;
            writeln!(file, "    addq 0(%rsp), %rcx")?;
            if let Some(step) = execution_reserved {
                writeln!(file, "    subq ${}, %rcx", step.remaining_after + 1)?;
            }
        }
        writeln!(file, "    shlq $32, %rcx")?;
        if native_step_loads_memory(insn.kind) {
            writeln!(file, "    movl %r9d, %eax")?;
        }
        writeln!(file, "    orq %rax, %rcx")?;
        writeln!(file, "    movq %rcx, ({memory_cells},%rsi,8)")?;
    }
    emit_after_native_step(
        &mut file,
        pc,
        program,
        insn,
        trace_style,
        tracks_mmio_bounds,
        emits_memory_event_early,
        reserved_block_step,
    )?;
    // Keep the valid-access path contiguous. The per-PC callback stub lives in
    // a cold section and jumps back only when an alignment or range guard
    // actually fails.
    writeln!(file, ".pushsection .text.unlikely,\"ax\",@progbits")?;
    writeln!(file, "{slow_label}:")?;
    emit_rollback_reserved_block_steps(&mut file, execution_reserved)?;
    emit_call_one(&mut file, pc, AOT_FALLBACK_MEMORY_GUARD, trace_style)?;
    emit_restore_reserved_block_steps(&mut file, execution_reserved)?;
    writeln!(file, "    jmp {done_label}")?;
    writeln!(file, ".popsection")?;
    writeln!(file, "{done_label}:")?;
    Ok(())
}

pub(super) fn should_publish_trace_memory_address(
    trace_style: AssemblyTraceStyle,
    tracks_mmio_bounds: bool,
    emits_memory_event_early: bool,
) -> bool {
    trace_style.needs_callback_values()
        || tracks_mmio_bounds
        || (trace_style.preflight_feature_enabled(PreflightFeature::MemoryEvents)
            && !emits_memory_event_early)
}

pub(super) fn emit_native_memory_region_entry(
    mut file: impl Write,
    label: &str,
    body_label: &str,
    trace_style: AssemblyTraceStyle,
    min_ptr_offset: usize,
    max_ptr_offset: usize,
) -> Result<()> {
    writeln!(file, "{label}:")?;
    writeln!(file, "    movl %edx, %r8d")?;
    writeln!(file, "    andl $3, %r8d")?;
    writeln!(file, "    shll $3, %r8d")?;
    writeln!(file, "    shrl $2, %edx")?;
    if !trace_style.is_pure() {
        writeln!(file, "    movl %edx, {AOT_CTX_TRACE_MEM_ADDR_OFFSET}(%r12)")?;
    }
    if trace_style.is_preflight_direct() {
        emit_preflight_direct_memory_bound_known_region(
            &mut file,
            "%edx",
            min_ptr_offset,
            max_ptr_offset,
        )?;
    }
    writeln!(file, "    jmp {body_label}")?;
    Ok(())
}

pub(super) fn emit_preflight_direct_encoded_memory_region(
    mut file: impl Write,
    pc: u32,
    region_index: usize,
    body_label: &str,
) -> Result<()> {
    let heap_label = format!(".L_memory_encoded_heap_{pc:x}");
    let stack_label = format!(".L_memory_encoded_stack_{pc:x}");
    let hints_label = format!(".L_memory_encoded_hints_{pc:x}");
    writeln!(file, "    movq 64(%rsp), %rax")?;
    if region_index != 0 {
        writeln!(file, "    shrq ${}, %rax", region_index * 2)?;
    }
    writeln!(file, "    andl $3, %eax")?;
    writeln!(file, "    cmpl $1, %eax")?;
    writeln!(file, "    je {heap_label}")?;
    writeln!(file, "    cmpl $2, %eax")?;
    writeln!(file, "    je {stack_label}")?;
    writeln!(file, "    cmpl $3, %eax")?;
    writeln!(file, "    je {hints_label}")?;
    writeln!(file, "    jmp {body_label}")?;
    for (label, min_offset, max_offset) in [
        (
            heap_label,
            AOT_CTX_PREFLIGHT_HEAP_MIN_OFFSET,
            AOT_CTX_PREFLIGHT_HEAP_MAX_OFFSET,
        ),
        (
            stack_label,
            AOT_CTX_PREFLIGHT_STACK_MIN_OFFSET,
            AOT_CTX_PREFLIGHT_STACK_MAX_OFFSET,
        ),
        (
            hints_label,
            AOT_CTX_PREFLIGHT_HINTS_MIN_OFFSET,
            AOT_CTX_PREFLIGHT_HINTS_MAX_OFFSET,
        ),
    ] {
        writeln!(file, "{label}:")?;
        emit_preflight_direct_memory_bound_known_region(&mut file, "%edx", min_offset, max_offset)?;
        writeln!(file, "    jmp {body_label}")?;
    }
    Ok(())
}

pub(super) fn emit_native_range_check(
    mut file: impl Write,
    start_offset: usize,
    end_offset: usize,
    ok_label: &str,
) -> Result<()> {
    writeln!(file, "    cmpl {start_offset}(%r12), %edx")?;
    writeln!(file, "    jb 1f")?;
    writeln!(file, "    cmpl {end_offset}(%r12), %edx")?;
    writeln!(file, "    jb {ok_label}")?;
    writeln!(file, "1:")?;
    Ok(())
}

pub(super) fn emit_successor_jump(
    mut file: impl Write,
    program: &Program,
    labels: &BTreeMap<u32, String>,
    next_block_pc: Option<u32>,
    pc: u32,
    insn: Instruction,
) -> Result<()> {
    let successors = static_successors(program, pc, insn)?;
    let adjacent = next_block_pc.filter(|next| successors.contains(next));
    for &successor in successors
        .iter()
        .filter(|successor| Some(**successor) != adjacent)
    {
        if let Some(label) = labels.get(&successor) {
            writeln!(file, "    cmpl ${successor:#010x}, %r15d")?;
            writeln!(file, "    je {label}")?;
        }
    }
    if let Some(adjacent) = adjacent {
        if is_static_conditional_branch(insn.kind) {
            writeln!(file, "    cmpl ${adjacent:#010x}, %r15d")?;
            writeln!(file, "    jne ceno_aot_dispatch")?;
        }
        return Ok(());
    }
    writeln!(file, "    jmp ceno_aot_dispatch")?;
    Ok(())
}
