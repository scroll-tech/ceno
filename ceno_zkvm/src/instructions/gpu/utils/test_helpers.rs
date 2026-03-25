// ---------------------------------------------------------------------------
// GPU correctness test helpers
// ---------------------------------------------------------------------------

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
    // Skip pipeline comparison if GPU witgen is not enabled (CENO_GPU_ENABLE_WITGEN unset)
    let Some((gpu_rmms, gpu_lkm)) = result else {
        eprintln!("GPU witgen not enabled, skipping full pipeline comparison");
        return;
    };

    crate::instructions::gpu::cache::flush_shared_ec_buffers(&mut gpu_ctx).unwrap();

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
