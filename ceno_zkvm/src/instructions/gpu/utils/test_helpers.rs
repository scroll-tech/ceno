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
                raw_instruction: step.insn().raw,
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
    I: crate::instructions::Instruction<E>,
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
