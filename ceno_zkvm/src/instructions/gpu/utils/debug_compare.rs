/// Debug comparison functions for GPU witness generation.
///
/// These functions compare GPU-produced results against CPU baselines
/// to validate correctness. Activated by environment variables:
/// All comparisons are activated by setting `CENO_GPU_DEBUG_COMPARE_WITGEN=1`.
/// This enables: LK multiplicity, witness matrix, shardram records, and EC point comparison.
use ceno_emul::{StepIndex, StepRecord, WordAddr};
use ceno_gpu::common::witgen::types::{GpuRamRecordSlot, GpuShardRamRecord};
use ff_ext::ExtensionField;
use gkr_iop::{RAMType, tables::LookupTable, utils::lk_multiplicity::Multiplicity};
use p3::field::FieldAlgebra;
use std::cell::Cell;
use witness::RowMajorMatrix;

use crate::{
    e2e::ShardContext,
    error::ZKVMError,
    instructions::{Instruction, cpu_collect_lk_and_shardram, cpu_collect_shardram},
    structs::ZKVMWitnesses,
};

use crate::instructions::gpu::dispatch::{GpuWitgenKind, set_force_cpu_path};

pub(crate) fn debug_compare_final_lk<E: ExtensionField, I: Instruction<E>>(
    config: &I::InstructionConfig,
    shard_ctx: &ShardContext,
    num_witin: usize,
    num_structural_witin: usize,
    shard_steps: &[StepRecord],
    step_indices: &[StepIndex],
    kind: GpuWitgenKind,
    mixed_lk: &Multiplicity<u64>,
) -> Result<(), ZKVMError> {
    if !crate::instructions::gpu::config::is_debug_compare_enabled() {
        return Ok(());
    }

    // Compare against cpu_assign_instances (the true baseline using assign_instance)
    let mut cpu_ctx = shard_ctx.new_empty_like();
    let (_, cpu_assign_lk) = crate::instructions::cpu_assign_instances::<E, I>(
        config,
        &mut cpu_ctx,
        num_witin,
        num_structural_witin,
        shard_steps,
        step_indices,
    )?;
    tracing::info!("[GPU lk debug] kind={kind:?} comparing mixed_lk vs cpu_assign_instances lk");
    log_lk_diff(kind, &cpu_assign_lk, mixed_lk);
    Ok(())
}

pub(crate) fn log_lk_diff(
    kind: GpuWitgenKind,
    cpu_lk: &Multiplicity<u64>,
    actual_lk: &Multiplicity<u64>,
) {
    let limit: usize = 16;

    let mut total_diffs = 0usize;
    for (table_idx, (cpu_table, actual_table)) in cpu_lk.iter().zip(actual_lk.iter()).enumerate() {
        let mut keys = cpu_table
            .keys()
            .chain(actual_table.keys())
            .copied()
            .collect::<Vec<_>>();
        keys.sort_unstable();
        keys.dedup();

        let mut table_diffs = Vec::new();
        for key in keys {
            let cpu_count = cpu_table.get(&key).copied().unwrap_or(0);
            let actual_count = actual_table.get(&key).copied().unwrap_or(0);
            if cpu_count != actual_count {
                table_diffs.push((key, cpu_count, actual_count));
            }
        }

        if !table_diffs.is_empty() {
            total_diffs += table_diffs.len();
            tracing::error!(
                "[GPU lk debug] kind={kind:?} table={} diff_count={}",
                lookup_table_name(table_idx),
                table_diffs.len()
            );
            for (key, cpu_count, actual_count) in table_diffs.into_iter().take(limit) {
                tracing::error!(
                    "[GPU lk debug] kind={kind:?} table={} key={} cpu={} gpu={}",
                    lookup_table_name(table_idx),
                    key,
                    cpu_count,
                    actual_count
                );
            }
        }
    }

    if total_diffs == 0 {
        tracing::info!("[GPU lk debug] kind={kind:?} CPU/GPU lookup multiplicities match");
    }
}

pub(crate) fn debug_compare_witness<E: ExtensionField, I: Instruction<E>>(
    config: &I::InstructionConfig,
    shard_ctx: &ShardContext,
    num_witin: usize,
    num_structural_witin: usize,
    shard_steps: &[StepRecord],
    step_indices: &[StepIndex],
    kind: GpuWitgenKind,
    gpu_witness: &RowMajorMatrix<E::BaseField>,
) -> Result<(), ZKVMError> {
    if !crate::instructions::gpu::config::is_debug_compare_enabled() {
        return Ok(());
    }

    let mut cpu_ctx = shard_ctx.new_empty_like();
    let (cpu_rmms, _) = crate::instructions::cpu_assign_instances::<E, I>(
        config,
        &mut cpu_ctx,
        num_witin,
        num_structural_witin,
        shard_steps,
        step_indices,
    )?;
    let cpu_witness = &cpu_rmms[0];
    let cpu_vals = cpu_witness.values();
    let gpu_vals = gpu_witness.values();
    if cpu_vals == gpu_vals {
        return Ok(());
    }

    let limit: usize = 16;
    let cpu_num_cols = cpu_witness.n_col();
    let cpu_num_rows = cpu_vals.len() / cpu_num_cols;
    let mut mismatches = 0usize;
    for row in 0..cpu_num_rows {
        for col in 0..cpu_num_cols {
            let idx = row * cpu_num_cols + col;
            if cpu_vals[idx] != gpu_vals[idx] {
                mismatches += 1;
                if mismatches <= limit {
                    tracing::error!(
                        "[GPU witness debug] kind={kind:?} row={} col={} cpu={:?} gpu={:?}",
                        row,
                        col,
                        cpu_vals[idx],
                        gpu_vals[idx]
                    );
                }
            }
        }
    }
    tracing::error!(
        "[GPU witness debug] kind={kind:?} total_mismatches={}",
        mismatches
    );
    Ok(())
}

pub(crate) fn debug_compare_shardram<E: ExtensionField, I: Instruction<E>>(
    config: &I::InstructionConfig,
    shard_ctx: &ShardContext,
    shard_steps: &[StepRecord],
    step_indices: &[StepIndex],
    kind: GpuWitgenKind,
) -> Result<(), ZKVMError> {
    if !crate::instructions::gpu::config::is_debug_compare_enabled() {
        return Ok(());
    }

    let mut cpu_ctx = shard_ctx.new_empty_like();
    let _ = cpu_collect_lk_and_shardram::<E, I>(config, &mut cpu_ctx, shard_steps, step_indices)?;

    let mut mixed_ctx = shard_ctx.new_empty_like();
    let _ = cpu_collect_shardram::<E, I>(config, &mut mixed_ctx, shard_steps, step_indices)?;

    let cpu_addr = cpu_ctx.get_addr_accessed();
    let mixed_addr = mixed_ctx.get_addr_accessed();
    if cpu_addr != mixed_addr {
        tracing::error!(
            "[GPU shard debug] kind={kind:?} addr_accessed cpu={} gpu={}",
            cpu_addr.len(),
            mixed_addr.len()
        );
    }

    let cpu_reads = flatten_ram_records(cpu_ctx.read_records());
    let mixed_reads = flatten_ram_records(mixed_ctx.read_records());
    if cpu_reads != mixed_reads {
        log_ram_record_diff(kind, "read_records", &cpu_reads, &mixed_reads);
    }

    let cpu_writes = flatten_ram_records(cpu_ctx.write_records());
    let mixed_writes = flatten_ram_records(mixed_ctx.write_records());
    if cpu_writes != mixed_writes {
        log_ram_record_diff(kind, "write_records", &cpu_writes, &mixed_writes);
    }

    Ok(())
}

/// Compare GPU shard context vs CPU shard context, field by field.
///
/// Both paths are independent and produce equivalent ShardContext state:
///   CPU path:  cpu_collect_shardram -> addr_accessed + write_records + read_records
///   GPU path:  compact_records -> shard records (gpu_ec_records)
///              ram_slots WAS_SENT -> addr_accessed
///              (write_records and read_records stay empty for GPU EC kernels)
///
/// This function builds both independently and compares:
///   A. addr_accessed sets
///   B. shard records (sorted, normalized to ShardRamRecord)
///   C. EC points (nonce + SepticPoint x,y)
///
/// Activated by CENO_GPU_DEBUG_COMPARE_WITGEN=1.
pub(crate) fn debug_compare_shard_ec<E: ExtensionField, I: Instruction<E>>(
    compact_records: &[GpuShardRamRecord],
    ram_slots: &[GpuRamRecordSlot],
    config: &I::InstructionConfig,
    shard_ctx: &ShardContext,
    shard_steps: &[StepRecord],
    step_indices: &[StepIndex],
    kind: GpuWitgenKind,
) {
    if !crate::instructions::gpu::config::is_debug_compare_enabled() {
        return;
    }

    use crate::{
        scheme::septic_curve::{SepticExtension, SepticPoint},
        tables::{ECPoint, ShardRamRecord},
    };
    use ff_ext::{PoseidonField, SmallField};

    let limit: usize = 16;

    // ========== Build CPU shard context (independent, isolated) ==========
    let mut cpu_ctx = shard_ctx.new_empty_like();
    if let Err(e) = cpu_collect_shardram::<E, I>(config, &mut cpu_ctx, shard_steps, step_indices) {
        tracing::error!("[GPU EC debug] kind={kind:?} CPU shardram records failed: {e:?}");
        return;
    }

    let perm = <E::BaseField as PoseidonField>::get_default_perm();

    // CPU: addr_accessed
    let cpu_addr = cpu_ctx.get_addr_accessed();

    // CPU: shard records (BTreeMap -> ShardRamRecord + ECPoint)
    let mut cpu_entries: Vec<(ShardRamRecord, ECPoint<E>)> = Vec::new();
    for records in cpu_ctx.write_records() {
        for (vma, record) in records {
            let rec: ShardRamRecord = (vma, record, true).into();
            let ec = rec.to_ec_point::<E, _>(&perm);
            cpu_entries.push((rec, ec));
        }
    }
    for records in cpu_ctx.read_records() {
        for (vma, record) in records {
            let rec: ShardRamRecord = (vma, record, false).into();
            let ec = rec.to_ec_point::<E, _>(&perm);
            cpu_entries.push((rec, ec));
        }
    }
    cpu_entries.sort_by_key(|(r, _)| (r.addr, r.is_to_write_set as u8, r.ram_type as u8));

    // ========== Build GPU shard context (independent, from D2H data only) ==========

    // GPU: addr_accessed (from ram_slots WAS_SENT flags)
    let gpu_addr: rustc_hash::FxHashSet<WordAddr> = ram_slots
        .iter()
        .filter(|s| s.flags & (1 << 4) != 0)
        .map(|s| WordAddr(s.addr))
        .collect();

    // GPU: shard records (compact_records -> ShardRamRecord + ECPoint)
    let mut gpu_entries: Vec<(ShardRamRecord, ECPoint<E>)> = compact_records
        .iter()
        .map(|g| {
            let rec = ShardRamRecord {
                addr: g.addr,
                ram_type: if g.ram_type == 1 {
                    RAMType::Register
                } else {
                    RAMType::Memory
                },
                value: g.value,
                shard: g.shard,
                local_clk: g.local_clk,
                global_clk: g.global_clk,
                is_to_write_set: g.is_to_write_set != 0,
            };
            let x = SepticExtension(g.point_x.map(|v| E::BaseField::from_canonical_u32(v)));
            let y = SepticExtension(g.point_y.map(|v| E::BaseField::from_canonical_u32(v)));
            let point = SepticPoint::from_affine(x, y);
            let ec = ECPoint::<E> {
                nonce: g.nonce,
                point,
            };
            (rec, ec)
        })
        .collect();
    gpu_entries.sort_by_key(|(r, _)| (r.addr, r.is_to_write_set as u8, r.ram_type as u8));

    // ========== Compare A: addr_accessed ==========
    if cpu_addr != gpu_addr {
        let cpu_only: Vec<_> = cpu_addr.difference(&gpu_addr).collect();
        let gpu_only: Vec<_> = gpu_addr.difference(&cpu_addr).collect();
        tracing::error!(
            "[GPU EC debug] kind={kind:?} ADDR_ACCESSED MISMATCH: cpu={} gpu={} \
             cpu_only={} gpu_only={}",
            cpu_addr.len(),
            gpu_addr.len(),
            cpu_only.len(),
            gpu_only.len()
        );
        for (i, addr) in cpu_only.iter().enumerate() {
            if i >= limit {
                break;
            }
            tracing::error!(
                "[GPU EC debug] kind={kind:?} addr_accessed CPU-only: {}",
                addr.0
            );
        }
        for (i, addr) in gpu_only.iter().enumerate() {
            if i >= limit {
                break;
            }
            tracing::error!(
                "[GPU EC debug] kind={kind:?} addr_accessed GPU-only: {}",
                addr.0
            );
        }
    }

    // ========== Compare B+C: shard records + EC points ==========

    // Check counts
    if cpu_entries.len() != gpu_entries.len() {
        tracing::error!(
            "[GPU EC debug] kind={kind:?} RECORD COUNT MISMATCH: cpu={} gpu={}",
            cpu_entries.len(),
            gpu_entries.len()
        );
        let cpu_keys: std::collections::BTreeSet<_> = cpu_entries
            .iter()
            .map(|(r, _)| (r.addr, r.is_to_write_set))
            .collect();
        let gpu_keys: std::collections::BTreeSet<_> = gpu_entries
            .iter()
            .map(|(r, _)| (r.addr, r.is_to_write_set))
            .collect();
        let mut logged = 0usize;
        for key in cpu_keys.difference(&gpu_keys) {
            if logged >= limit {
                break;
            }
            tracing::error!(
                "[GPU EC debug] kind={kind:?} CPU-only: addr={} is_write={}",
                key.0,
                key.1
            );
            logged += 1;
        }
        for key in gpu_keys.difference(&cpu_keys) {
            if logged >= limit {
                break;
            }
            tracing::error!(
                "[GPU EC debug] kind={kind:?} GPU-only: addr={} is_write={}",
                key.0,
                key.1
            );
            logged += 1;
        }
    }

    // Check GPU duplicates (BTreeMap deduplicates, atomicAdd doesn't)
    let mut gpu_dup_count = 0usize;
    for w in gpu_entries.windows(2) {
        if w[0].0.addr == w[1].0.addr
            && w[0].0.is_to_write_set == w[1].0.is_to_write_set
            && w[0].0.ram_type == w[1].0.ram_type
        {
            gpu_dup_count += 1;
            if gpu_dup_count <= limit {
                tracing::error!(
                    "[GPU EC debug] kind={kind:?} GPU DUPLICATE: addr={} is_write={} ram_type={:?}",
                    w[0].0.addr,
                    w[0].0.is_to_write_set,
                    w[0].0.ram_type
                );
            }
        }
    }

    // Merge-walk sorted lists
    let mut ci = 0usize;
    let mut gi = 0usize;
    let mut record_mismatches = 0usize;
    let mut ec_mismatches = 0usize;
    let mut matched = 0usize;

    while ci < cpu_entries.len() && gi < gpu_entries.len() {
        let (cr, ce) = &cpu_entries[ci];
        let (gr, ge) = &gpu_entries[gi];
        let ck = (cr.addr, cr.is_to_write_set as u8, cr.ram_type as u8);
        let gk = (gr.addr, gr.is_to_write_set as u8, gr.ram_type as u8);

        match ck.cmp(&gk) {
            std::cmp::Ordering::Less => {
                if record_mismatches < limit {
                    tracing::error!(
                        "[GPU EC debug] kind={kind:?} MISSING in GPU: addr={} is_write={} ram={:?} val={} shard={} clk={}",
                        cr.addr,
                        cr.is_to_write_set,
                        cr.ram_type,
                        cr.value,
                        cr.shard,
                        cr.global_clk
                    );
                }
                record_mismatches += 1;
                ci += 1;
                continue;
            }
            std::cmp::Ordering::Greater => {
                if record_mismatches < limit {
                    tracing::error!(
                        "[GPU EC debug] kind={kind:?} EXTRA in GPU: addr={} is_write={} ram={:?} val={} shard={} clk={}",
                        gr.addr,
                        gr.is_to_write_set,
                        gr.ram_type,
                        gr.value,
                        gr.shard,
                        gr.global_clk
                    );
                }
                record_mismatches += 1;
                gi += 1;
                continue;
            }
            std::cmp::Ordering::Equal => {}
        }

        // Keys match -- compare record fields
        let mut field_diff = false;
        for (name, cv, gv) in [
            ("value", cr.value as u64, gr.value as u64),
            ("shard", cr.shard, gr.shard),
            ("local_clk", cr.local_clk, gr.local_clk),
            ("global_clk", cr.global_clk, gr.global_clk),
        ] {
            if cv != gv {
                field_diff = true;
                if record_mismatches < limit {
                    tracing::error!(
                        "[GPU EC debug] kind={kind:?} addr={} {name}: cpu={cv} gpu={gv}",
                        cr.addr
                    );
                }
            }
        }
        if field_diff {
            record_mismatches += 1;
        }

        // Compare EC points
        let mut ec_diff = false;
        if ce.nonce != ge.nonce {
            ec_diff = true;
            if ec_mismatches < limit {
                tracing::error!(
                    "[GPU EC debug] kind={kind:?} addr={} nonce: cpu={} gpu={}",
                    cr.addr,
                    ce.nonce,
                    ge.nonce
                );
            }
        }
        for j in 0..7 {
            let cv = ce.point.x.0[j].to_canonical_u64() as u32;
            let gv = ge.point.x.0[j].to_canonical_u64() as u32;
            if cv != gv {
                ec_diff = true;
                if ec_mismatches < limit {
                    tracing::error!(
                        "[GPU EC debug] kind={kind:?} addr={} x[{j}]: cpu={cv} gpu={gv}",
                        cr.addr
                    );
                }
            }
        }
        for j in 0..7 {
            let cv = ce.point.y.0[j].to_canonical_u64() as u32;
            let gv = ge.point.y.0[j].to_canonical_u64() as u32;
            if cv != gv {
                ec_diff = true;
                if ec_mismatches < limit {
                    tracing::error!(
                        "[GPU EC debug] kind={kind:?} addr={} y[{j}]: cpu={cv} gpu={gv}",
                        cr.addr
                    );
                }
            }
        }
        if ec_diff {
            ec_mismatches += 1;
        }

        matched += 1;
        ci += 1;
        gi += 1;
    }

    // Remaining unmatched
    while ci < cpu_entries.len() {
        if record_mismatches < limit {
            let (cr, _) = &cpu_entries[ci];
            tracing::error!(
                "[GPU EC debug] kind={kind:?} MISSING in GPU (tail): addr={} is_write={} val={}",
                cr.addr,
                cr.is_to_write_set,
                cr.value
            );
        }
        record_mismatches += 1;
        ci += 1;
    }
    while gi < gpu_entries.len() {
        if record_mismatches < limit {
            let (gr, _) = &gpu_entries[gi];
            tracing::error!(
                "[GPU EC debug] kind={kind:?} EXTRA in GPU (tail): addr={} is_write={} val={}",
                gr.addr,
                gr.is_to_write_set,
                gr.value
            );
        }
        record_mismatches += 1;
        gi += 1;
    }

    // ========== Summary ==========
    let addr_ok = cpu_addr == gpu_addr;
    if addr_ok && record_mismatches == 0 && ec_mismatches == 0 && gpu_dup_count == 0 {
        tracing::info!(
            "[GPU EC debug] kind={kind:?} ALL MATCH: {} records, {} addr_accessed, EC points OK",
            matched,
            cpu_addr.len()
        );
    } else {
        tracing::error!(
            "[GPU EC debug] kind={kind:?} MISMATCH: matched={matched} record_diffs={record_mismatches} \
             ec_diffs={ec_mismatches} gpu_dups={gpu_dup_count} addr_ok={addr_ok} \
             (cpu_records={} gpu_records={} cpu_addrs={} gpu_addrs={})",
            cpu_entries.len(),
            gpu_entries.len(),
            cpu_addr.len(),
            gpu_addr.len()
        );
    }
}

pub(crate) fn flatten_ram_records(
    records: &[std::collections::BTreeMap<ceno_emul::WordAddr, crate::e2e::RAMRecord>],
) -> Vec<(u32, u64, u64, u64, u64, Option<u32>, u32, usize)> {
    let mut flat = Vec::new();
    for table in records {
        for (addr, record) in table {
            flat.push((
                addr.0,
                record.reg_id,
                record.prev_cycle,
                record.cycle,
                record.shard_cycle,
                record.prev_value,
                record.value,
                record.shard_id,
            ));
        }
    }
    flat
}

pub(crate) fn log_ram_record_diff(
    kind: GpuWitgenKind,
    label: &str,
    cpu_records: &[(u32, u64, u64, u64, u64, Option<u32>, u32, usize)],
    mixed_records: &[(u32, u64, u64, u64, u64, Option<u32>, u32, usize)],
) {
    let limit: usize = 16;
    tracing::error!(
        "[GPU shard debug] kind={kind:?} {} cpu={} gpu={}",
        label,
        cpu_records.len(),
        mixed_records.len()
    );
    let max_len = cpu_records.len().max(mixed_records.len());
    let mut logged = 0usize;
    for idx in 0..max_len {
        let cpu = cpu_records.get(idx);
        let gpu = mixed_records.get(idx);
        if cpu != gpu {
            tracing::error!(
                "[GPU shard debug] kind={kind:?} {} idx={} cpu={:?} gpu={:?}",
                label,
                idx,
                cpu,
                gpu
            );
            logged += 1;
            if logged >= limit {
                break;
            }
        }
    }
}

pub(crate) fn lookup_table_name(table_idx: usize) -> &'static str {
    match table_idx {
        x if x == LookupTable::Dynamic as usize => "Dynamic",
        x if x == LookupTable::DoubleU8 as usize => "DoubleU8",
        x if x == LookupTable::And as usize => "And",
        x if x == LookupTable::Or as usize => "Or",
        x if x == LookupTable::Xor as usize => "Xor",
        x if x == LookupTable::Ltu as usize => "Ltu",
        x if x == LookupTable::Pow as usize => "Pow",
        x if x == LookupTable::Instruction as usize => "Instruction",
        _ => "Unknown",
    }
}

/// Debug comparison for keccak GPU witgen.
/// Runs the CPU path and compares LK / witness / shardram records.
///
/// Activated by CENO_GPU_DEBUG_COMPARE_WITGEN=1.
#[cfg(feature = "gpu")]
pub(crate) fn debug_compare_keccak<E: ExtensionField>(
    config: &crate::instructions::riscv::ecall::keccak::EcallKeccakConfig<E>,
    shard_ctx: &ShardContext,
    num_witin: usize,
    num_structural_witin: usize,
    steps: &[StepRecord],
    step_indices: &[StepIndex],
    gpu_lk: &Multiplicity<u64>,
    gpu_witin: &RowMajorMatrix<E::BaseField>,
    gpu_addrs: &[u32],
) -> Result<(), ZKVMError> {
    let enabled = crate::instructions::gpu::config::is_debug_compare_enabled();
    let want_lk = enabled;
    let want_witness = enabled;
    let want_shard = enabled;

    if !want_lk && !want_witness && !want_shard {
        return Ok(());
    }

    // Guard against recursion: is_gpu_witgen_enabled() uses OnceLock so env var
    // manipulation doesn't work. Use a thread-local flag instead.
    thread_local! {
        static IN_DEBUG_COMPARE: Cell<bool> = const { Cell::new(false) };
    }
    if IN_DEBUG_COMPARE.with(|f| f.get()) {
        return Ok(());
    }
    IN_DEBUG_COMPARE.with(|f| f.set(true));

    tracing::info!("[GPU keccak debug] running CPU baseline for comparison");

    // Run CPU path via assign_instances. The IN_DEBUG_COMPARE guard prevents
    // gpu_assign_keccak_instances (in chips/keccak.rs) from calling debug_compare_keccak again,
    // so it will produce the GPU result, which is then returned without
    // re-entering this function. We need assign_instances (not cpu_assign_instances)
    // because keccak has rotation matrices and 3 structural columns.
    //
    // To force the CPU path, we use is_force_cpu_path() by setting the env var.
    let mut cpu_ctx = shard_ctx.new_empty_like();
    let (cpu_rmms, cpu_lk) = {
        use crate::instructions::riscv::ecall::keccak::KeccakInstruction;
        // Set force-CPU flag so gpu_assign_keccak_instances returns None
        set_force_cpu_path(true);
        let result =
            <KeccakInstruction<E> as crate::instructions::Instruction<E>>::assign_instances(
                config,
                &mut cpu_ctx,
                num_witin,
                num_structural_witin,
                steps,
                step_indices,
            );
        set_force_cpu_path(false);
        IN_DEBUG_COMPARE.with(|f| f.set(false));
        result?
    };

    let kind = GpuWitgenKind::Keccak;

    if want_lk {
        tracing::info!("[GPU keccak debug] comparing LK multiplicities");
        log_lk_diff(kind, &cpu_lk, gpu_lk);
    }

    if want_witness {
        let limit: usize = 16;
        let cpu_witin = &cpu_rmms[0];
        let gpu_vals = gpu_witin.values();
        let cpu_vals = cpu_witin.values();
        let mut diffs = 0usize;
        for (i, (g, c)) in gpu_vals.iter().zip(cpu_vals.iter()).enumerate() {
            if g != c {
                if diffs < limit {
                    let row = i / num_witin;
                    let col = i % num_witin;
                    tracing::error!(
                        "[GPU keccak witness] row={} col={} gpu={:?} cpu={:?}",
                        row,
                        col,
                        g,
                        c
                    );
                }
                diffs += 1;
            }
        }
        if diffs == 0 {
            tracing::info!(
                "[GPU keccak debug] witness matrices match ({} elements)",
                gpu_vals.len()
            );
        } else {
            tracing::error!(
                "[GPU keccak debug] witness mismatch: {} diffs out of {}",
                diffs,
                gpu_vals.len()
            );
        }
    }

    if want_shard {
        // Compare addr_accessed: GPU entries were D2H'd from the shared buffer
        // delta (before/after kernel launch) and passed in as gpu_addrs.
        let cpu_addr = cpu_ctx.get_addr_accessed();
        let gpu_addr_set: rustc_hash::FxHashSet<WordAddr> =
            gpu_addrs.iter().map(|&a| WordAddr(a)).collect();

        if cpu_addr.len() != gpu_addr_set.len() {
            tracing::error!(
                "[GPU keccak shard] addr_accessed count mismatch: cpu={} gpu={}",
                cpu_addr.len(),
                gpu_addr_set.len()
            );
        }
        let mut missing_from_gpu = 0usize;
        let mut extra_in_gpu = 0usize;
        let limit = 16usize;
        for addr in &cpu_addr {
            if !gpu_addr_set.contains(addr) {
                if missing_from_gpu < limit {
                    tracing::error!("[GPU keccak shard] addr {} in CPU but not GPU", addr.0);
                }
                missing_from_gpu += 1;
            }
        }
        for &addr in gpu_addrs {
            if !cpu_addr.contains(&WordAddr(addr)) {
                if extra_in_gpu < limit {
                    tracing::error!("[GPU keccak shard] addr {} in GPU but not CPU", addr);
                }
                extra_in_gpu += 1;
            }
        }
        if missing_from_gpu == 0 && extra_in_gpu == 0 {
            tracing::info!(
                "[GPU keccak shard] addr_accessed matches: {} entries",
                cpu_addr.len()
            );
        } else {
            tracing::error!(
                "[GPU keccak shard] addr_accessed diff: missing_from_gpu={} extra_in_gpu={}",
                missing_from_gpu,
                extra_in_gpu
            );
        }
    }

    Ok(())
}

/// Compare ShardContext records between CPU and GPU paths (e2e shard-level debug).
pub(crate) fn log_shard_ctx_diff(kind: &str, cpu: &ShardContext, gpu: &ShardContext) {
    let cpu_addr = cpu.get_addr_accessed();
    let gpu_addr = gpu.get_addr_accessed();
    if cpu_addr != gpu_addr {
        tracing::error!(
            "[GPU e2e debug] {} addr_accessed cpu={} gpu={}",
            kind,
            cpu_addr.len(),
            gpu_addr.len()
        );
    }

    let cpu_reads = flatten_ram_records(cpu.read_records());
    let gpu_reads = flatten_ram_records(gpu.read_records());
    if cpu_reads != gpu_reads {
        tracing::error!(
            "[GPU e2e debug] {} read_records cpu={} gpu={}",
            kind,
            cpu_reads.len(),
            gpu_reads.len()
        );
    }

    let cpu_writes = flatten_ram_records(cpu.write_records());
    let gpu_writes = flatten_ram_records(gpu.write_records());
    if cpu_writes != gpu_writes {
        tracing::error!(
            "[GPU e2e debug] {} write_records cpu={} gpu={}",
            kind,
            cpu_writes.len(),
            gpu_writes.len()
        );
    }
}

/// Compare combined LK multiplicities between CPU and GPU witnesses (e2e shard-level debug).
pub(crate) fn log_combined_lk_diff<E: ExtensionField>(
    cpu_witness: &ZKVMWitnesses<E>,
    gpu_witness: &ZKVMWitnesses<E>,
) {
    let cpu_combined = cpu_witness.combined_lk_mlt().expect("cpu combined_lk_mlt");
    let gpu_combined = gpu_witness.combined_lk_mlt().expect("gpu combined_lk_mlt");

    let table_names = [
        "Dynamic",
        "DoubleU8",
        "And",
        "Or",
        "Xor",
        "Ltu",
        "Pow",
        "Instruction",
    ];

    let mut total_diffs = 0usize;
    for (table_idx, (cpu_table, gpu_table)) in
        cpu_combined.iter().zip(gpu_combined.iter()).enumerate()
    {
        let mut keys: Vec<u64> = cpu_table.keys().chain(gpu_table.keys()).copied().collect();
        keys.sort_unstable();
        keys.dedup();

        let mut table_diffs = 0usize;
        for &key in &keys {
            let cpu_count = cpu_table.get(&key).copied().unwrap_or(0);
            let gpu_count = gpu_table.get(&key).copied().unwrap_or(0);
            if cpu_count != gpu_count {
                table_diffs += 1;
                if table_diffs <= 8 {
                    let name = table_names.get(table_idx).unwrap_or(&"Unknown");
                    tracing::error!(
                        "[GPU e2e debug] combined_lk table={} key={} cpu={} gpu={}",
                        name,
                        key,
                        cpu_count,
                        gpu_count
                    );
                }
            }
        }
        total_diffs += table_diffs;
        if table_diffs > 8 {
            let name = table_names.get(table_idx).unwrap_or(&"Unknown");
            tracing::error!(
                "[GPU e2e debug] combined_lk table={} total_diffs={} (showing first 8)",
                name,
                table_diffs
            );
        }
    }

    let cpu_lk_keys: std::collections::BTreeSet<_> = cpu_witness.lk_mlts().keys().collect();
    let gpu_lk_keys: std::collections::BTreeSet<_> = gpu_witness.lk_mlts().keys().collect();
    if cpu_lk_keys != gpu_lk_keys {
        tracing::error!(
            "[GPU e2e debug] lk_mlts key mismatch: cpu_only={:?} gpu_only={:?}",
            cpu_lk_keys.difference(&gpu_lk_keys).collect::<Vec<_>>(),
            gpu_lk_keys.difference(&cpu_lk_keys).collect::<Vec<_>>(),
        );
    }
    for name in cpu_lk_keys.intersection(&gpu_lk_keys) {
        let cpu_lk = cpu_witness.lk_mlts().get(*name).unwrap();
        let gpu_lk = gpu_witness.lk_mlts().get(*name).unwrap();
        let mut chip_diffs = 0usize;
        for (t_idx, (ct, gt)) in cpu_lk.iter().zip(gpu_lk.iter()).enumerate() {
            let mut ks: Vec<u64> = ct.keys().chain(gt.keys()).copied().collect();
            ks.sort_unstable();
            ks.dedup();
            for &k in &ks {
                let cv = ct.get(&k).copied().unwrap_or(0);
                let gv = gt.get(&k).copied().unwrap_or(0);
                if cv != gv {
                    chip_diffs += 1;
                    if chip_diffs <= 4 {
                        let tname = table_names.get(t_idx).unwrap_or(&"Unknown");
                        tracing::error!(
                            "[GPU e2e debug] per_chip_lk chip={} table={} key={} cpu={} gpu={}",
                            name,
                            tname,
                            k,
                            cv,
                            gv
                        );
                    }
                }
            }
        }
        if chip_diffs > 0 {
            total_diffs += chip_diffs;
            tracing::error!(
                "[GPU e2e debug] per_chip_lk chip={} total_diffs={}",
                name,
                chip_diffs
            );
        }
    }

    if total_diffs == 0 {
        tracing::info!(
            "[GPU e2e debug] combined_lk_mlt + per_chip_lk: CPU/GPU match (tables={}, chips={})",
            cpu_combined.len(),
            cpu_lk_keys.len()
        );
    } else {
        tracing::error!(
            "[GPU e2e debug] TOTAL LK DIFFS = {} (combined + per-chip)",
            total_diffs
        );
    }
}
