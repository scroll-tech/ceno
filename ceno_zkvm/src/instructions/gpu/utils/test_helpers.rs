// ---------------------------------------------------------------------------
// GPU correctness test helpers
// ---------------------------------------------------------------------------

#[cfg(test)]
pub fn compact_records_from_steps(
    steps: &[ceno_emul::StepRecord],
) -> Vec<ceno_emul::GpuReplayOrdinaryRecord> {
    steps
        .iter()
        .enumerate()
        .map(|(ordinal, step)| {
            let mut record = ceno_emul::GpuReplayOrdinaryRecord {
                ordinal: ordinal as u32,
                pc_before: step.pc().before.0,
                pc_after: step.pc().after.0,
                raw_instruction: test_raw_instruction(&step.insn()),
                flags: (step.future_access_mask() as u32)
                    << ceno_emul::GpuReplayOrdinaryRecord::FUTURE_ACCESS_SHIFT,
                ..Default::default()
            };
            if let Some(rs1) = step.rs1() {
                record.rs1 = ceno_emul::GpuReplayRead {
                    previous_cycle: rs1.previous_cycle as u32,
                    value: rs1.value,
                };
                record.flags |= ceno_emul::GpuReplayOrdinaryRecord::HAS_RS1;
            }
            if let Some(rs2) = step.rs2() {
                record.rs2 = ceno_emul::GpuReplayRead {
                    previous_cycle: rs2.previous_cycle as u32,
                    value: rs2.value,
                };
                record.flags |= ceno_emul::GpuReplayOrdinaryRecord::HAS_RS2;
            }
            if let Some(rd) = step.rd() {
                record.rd = ceno_emul::GpuReplayWrite {
                    previous_cycle: rd.previous_cycle as u32,
                    value_before: rd.value.before,
                    value_after: rd.value.after,
                };
                record.flags |= ceno_emul::GpuReplayOrdinaryRecord::HAS_RD;
            }
            if let Some(memory) = step.memory_op() {
                record.memory = ceno_emul::GpuReplayMemory {
                    previous_cycle: memory.previous_cycle as u32,
                    address: memory.addr.0,
                    value_before: memory.value.before,
                    value_after: memory.value.after,
                };
                record.flags |= ceno_emul::GpuReplayOrdinaryRecord::HAS_MEMORY;
            }
            record
        })
        .collect()
}

#[cfg(test)]
fn test_raw_instruction(insn: &ceno_emul::Instruction) -> u32 {
    use ceno_emul::InsnKind::*;
    if insn.raw != 0 {
        return insn.raw;
    }
    let rs1 = (insn.rs1 as u32) << 15;
    let rs2 = (insn.rs2 as u32) << 20;
    let rd = (insn.rd as u32) << 7;
    let r = |funct7: u32, funct3: u32| funct7 << 25 | rs2 | rs1 | funct3 << 12 | rd | 0x33;
    let i = |opcode: u32, funct3: u32| {
        ((insn.imm as u32) & 0xfff) << 20 | rs1 | funct3 << 12 | rd | opcode
    };
    let s = |funct3: u32| {
        let imm = (insn.imm as u32) & 0xfff;
        (imm >> 5) << 25 | rs2 | rs1 | funct3 << 12 | (imm & 0x1f) << 7 | 0x23
    };
    let b = |funct3: u32| {
        let imm = (insn.imm as u32) & 0x1fff;
        ((imm >> 12) & 1) << 31
            | ((imm >> 5) & 0x3f) << 25
            | rs2
            | rs1
            | funct3 << 12
            | ((imm >> 1) & 0xf) << 8
            | ((imm >> 11) & 1) << 7
            | 0x63
    };
    match insn.kind {
        ADD => r(0, 0),
        SUB => r(0x20, 0),
        SLL => r(0, 1),
        SLT => r(0, 2),
        SLTU => r(0, 3),
        XOR => r(0, 4),
        SRL => r(0, 5),
        SRA => r(0x20, 5),
        OR => r(0, 6),
        AND => r(0, 7),
        MUL => r(1, 0),
        MULH => r(1, 1),
        MULHSU => r(1, 2),
        MULHU => r(1, 3),
        DIV => r(1, 4),
        DIVU => r(1, 5),
        REM => r(1, 6),
        REMU => r(1, 7),
        ADDI => i(0x13, 0),
        SLTI => i(0x13, 2),
        SLTIU => i(0x13, 3),
        XORI => i(0x13, 4),
        ORI => i(0x13, 6),
        ANDI => i(0x13, 7),
        SLLI => i(0x13, 1),
        SRLI => i(0x13, 5),
        SRAI => (0x20 << 25) | ((insn.imm as u32) & 0x1f) << 20 | rs1 | 5 << 12 | rd | 0x13,
        JALR => i(0x67, 0),
        LW => i(0x03, 2),
        LH => i(0x03, 1),
        LHU => i(0x03, 5),
        LB => i(0x03, 0),
        LBU => i(0x03, 4),
        SW => s(2),
        SH => s(1),
        SB => s(0),
        BEQ => b(0),
        BNE => b(1),
        BLT => b(4),
        BGE => b(5),
        BLTU => b(6),
        BGEU => b(7),
        LUI => (insn.imm as u32 & 0xfffff000) | rd | 0x37,
        AUIPC => (insn.imm as u32 & 0xfffff000) | rd | 0x17,
        JAL => {
            let imm = (insn.imm as u32) & 0x1f_ffff;
            ((imm >> 20) & 1) << 31
                | ((imm >> 1) & 0x3ff) << 21
                | ((imm >> 11) & 1) << 20
                | ((imm >> 12) & 0xff) << 12
                | rd
                | 0x6f
        }
        _ => panic!("test compact encoder does not support {:?}", insn.kind),
    }
}

#[cfg(test)]
pub fn compact_records_as_bytes(records: &[ceno_emul::GpuReplayOrdinaryRecord]) -> &[u8] {
    unsafe {
        std::slice::from_raw_parts(
            records.as_ptr() as *const u8,
            std::mem::size_of_val(records),
        )
    }
}

/// Compare GPU column-major witness data against CPU row-major reference.
/// Panics with detailed mismatch info if any element differs.
#[cfg(test)]
pub fn assert_witness_colmajor_eq<F: std::fmt::Debug + PartialEq>(
    gpu_colmajor: &[F],
    cpu_rowmajor: &[F],
    n_rows: usize,
    n_cols: usize,
) {
    assert_eq!(
        gpu_colmajor.len(),
        cpu_rowmajor.len(),
        "Size mismatch: gpu={} cpu={}",
        gpu_colmajor.len(),
        cpu_rowmajor.len()
    );
    let mut mismatches = 0;
    for row in 0..n_rows {
        for col in 0..n_cols {
            let gpu_val = &gpu_colmajor[col * n_rows + row];
            let cpu_val = &cpu_rowmajor[row * n_cols + col];
            if gpu_val != cpu_val {
                if mismatches < 10 {
                    eprintln!("Mismatch at row={row}, col={col}: GPU={gpu_val:?}, CPU={cpu_val:?}");
                }
                mismatches += 1;
            }
        }
    }
    assert_eq!(mismatches, 0, "Found {mismatches} mismatches");
}

/// Run `try_gpu_assign_instances` + `flush_shared_ec_buffers`, then assert
/// witness, LK multiplicity, addr_accessed, and read/write records all match
/// the CPU reference in `cpu_ctx`.
#[cfg(test)]
pub fn assert_full_gpu_pipeline<
    E: ff_ext::ExtensionField,
    I: crate::instructions::Instruction<E, InsnType = ceno_emul::InsnKind>,
>(
    config: &I::InstructionConfig,
    steps: &[ceno_emul::StepRecord],
    kind: crate::instructions::gpu::dispatch::GpuWitgenKind,
    cpu_rmms: &crate::tables::RMMCollections<E::BaseField>,
    cpu_lkm: &gkr_iop::utils::lk_multiplicity::Multiplicity<u64>,
    cpu_ctx: &crate::e2e::ShardContext,
    num_witin: usize,
    num_structural_witin: usize,
) {
    let indices: Vec<usize> = (0..steps.len()).collect();

    let mut gpu_ctx = crate::e2e::ShardContext::default();
    let result = crate::instructions::gpu::dispatch::try_gpu_assign_instances::<E, I>(
        config,
        &mut gpu_ctx,
        num_witin,
        num_structural_witin,
        steps,
        &indices,
        kind,
    )
    .unwrap();
    // Skip pipeline comparison if GPU witgen is not enabled (CENO_GPU_ENABLE_WITGEN=0)
    let Some((gpu_rmms, gpu_lkm)) = result else {
        eprintln!("GPU witgen not enabled, skipping full pipeline comparison");
        return;
    };

    // Single-chip test has no `assign_continuation`, so force the D2H to
    // populate `gpu_ctx.addr_accessed` for the comparison below.
    crate::instructions::gpu::cache::set_force_flush_d2h(true);
    let flush_result = crate::instructions::gpu::cache::flush_shared_ec_buffers(&mut gpu_ctx);
    crate::instructions::gpu::cache::set_force_flush_d2h(false);
    flush_result.unwrap();

    assert_eq!(
        gpu_rmms[0].values(),
        cpu_rmms[0].values(),
        "witness mismatch"
    );
    assert_eq!(
        flatten_lk_for_test(&gpu_lkm),
        flatten_lk_for_test(cpu_lkm),
        "LK multiplicity mismatch"
    );
    assert_eq!(
        gpu_ctx.get_addr_accessed(),
        cpu_ctx.get_addr_accessed(),
        "addr_accessed mismatch"
    );
    assert_eq!(
        flatten_records_for_test(gpu_ctx.read_records()),
        flatten_records_for_test(cpu_ctx.read_records()),
        "read_records mismatch"
    );
    assert_eq!(
        flatten_records_for_test(gpu_ctx.write_records()),
        flatten_records_for_test(cpu_ctx.write_records()),
        "write_records mismatch"
    );
}

#[cfg(test)]
fn flatten_lk_for_test(
    m: &gkr_iop::utils::lk_multiplicity::Multiplicity<u64>,
) -> Vec<Vec<(u64, usize)>> {
    m.iter()
        .map(|table| {
            let mut entries: Vec<_> = table.iter().map(|(k, v)| (*k, *v)).collect();
            entries.sort_unstable();
            entries
        })
        .collect()
}

#[cfg(test)]
fn flatten_records_for_test(
    records: &[std::collections::BTreeMap<ceno_emul::WordAddr, crate::e2e::RAMRecord>],
) -> Vec<(ceno_emul::WordAddr, u64, u64, usize)> {
    records
        .iter()
        .flat_map(|table| {
            table
                .iter()
                .map(|(addr, r)| (*addr, r.prev_cycle, r.cycle, r.shard_id))
        })
        .collect()
}
