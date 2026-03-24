/// Device-to-host conversion functions for GPU witness generation.
///
/// This module handles:
/// - Type aliases for GPU buffer types
/// - D2H transfer of witness matrices (transpose + copy)
/// - D2H transfer of lookup counter buffers
/// - D2H transfer of compact EC records
/// - Conversion between host and GPU shard RAM record formats
/// - Batch EC point computation on GPU for continuation circuits
use ceno_emul::WordAddr;
use ceno_gpu::{
    Buffer, CudaHal, bb31::CudaHalBB31, common::transpose::matrix_transpose,
};
use ceno_gpu::common::witgen::types::{CompactEcResult, GpuRamRecordSlot, GpuShardRamRecord};
use ff_ext::ExtensionField;
use gkr_iop::{RAMType, tables::LookupTable, utils::lk_multiplicity::Multiplicity};
use p3::field::FieldAlgebra;
use rustc_hash::FxHashMap;
use tracing::info_span;
use witness::{InstancePaddingStrategy, RowMajorMatrix};

use crate::{
    e2e::{RAMRecord, ShardContext},
    error::ZKVMError,
};

pub(crate) type WitBuf = ceno_gpu::common::BufferImpl<
    'static,
    <ff_ext::BabyBearExt4 as ExtensionField>::BaseField,
>;
pub(crate) type LkBuf = ceno_gpu::common::BufferImpl<'static, u32>;
pub(crate) type RamBuf = ceno_gpu::common::BufferImpl<'static, u32>;
pub(crate) type WitResult = ceno_gpu::common::witgen::types::GpuWitnessResult<WitBuf>;
pub(crate) type LkResult = ceno_gpu::common::witgen::types::GpuLookupCountersResult<LkBuf>;
pub(crate) type CompactEcBuf = ceno_gpu::common::witgen::types::CompactEcResult<RamBuf>;

/// CPU-side lightweight scan of GPU-produced RAM record slots.
///
/// Reconstructs BTreeMap read/write records and addr_accessed from the GPU output,
/// replacing the previous `collect_shardram()` CPU loop.
pub(crate) fn gpu_collect_shard_records(
    shard_ctx: &mut ShardContext,
    slots: &[GpuRamRecordSlot],
) {
    let current_shard_id = shard_ctx.shard_id;

    for slot in slots {
        // Check was_sent flag (bit 4): this slot corresponds to a send() call
        if slot.flags & (1 << 4) != 0 {
            shard_ctx.push_addr_accessed(WordAddr(slot.addr));
        }

        // Check active flag (bit 0): this slot has a read or write record
        if slot.flags & 1 == 0 {
            continue;
        }

        let ram_type = match (slot.flags >> 5) & 0x7 {
            1 => RAMType::Register,
            2 => RAMType::Memory,
            _ => continue,
        };
        let has_prev_value = slot.flags & (1 << 3) != 0;
        let prev_value = if has_prev_value { Some(slot.prev_value) } else { None };
        let addr = WordAddr(slot.addr);

        // Insert read record (bit 1)
        if slot.flags & (1 << 1) != 0 {
            shard_ctx.insert_read_record(
                addr,
                RAMRecord {
                    ram_type,
                    reg_id: slot.reg_id as u64,
                    addr,
                    prev_cycle: slot.prev_cycle,
                    cycle: slot.cycle,
                    shard_cycle: 0,
                    prev_value,
                    value: slot.value,
                    shard_id: slot.read_shard_id as usize,
                },
            );
        }

        // Insert write record (bit 2)
        if slot.flags & (1 << 2) != 0 {
            shard_ctx.insert_write_record(
                addr,
                RAMRecord {
                    ram_type,
                    reg_id: slot.reg_id as u64,
                    addr,
                    prev_cycle: slot.prev_cycle,
                    cycle: slot.cycle,
                    shard_cycle: slot.shard_cycle,
                    prev_value,
                    value: slot.value,
                    shard_id: current_shard_id,
                },
            );
        }
    }
}

/// D2H the compact EC result: read count, then partial-D2H only that many records.
pub(crate) fn gpu_compact_ec_d2h(
    compact: &CompactEcResult<RamBuf>,
) -> Result<Vec<GpuShardRamRecord>, ZKVMError> {
    // D2H the count (1 u32)
    let count_vec: Vec<u32> = compact.count_buf.to_vec().map_err(|e| {
        ZKVMError::InvalidWitness(format!("compact_count D2H failed: {e}").into())
    })?;
    let count = count_vec[0] as usize;
    if count == 0 {
        return Ok(vec![]);
    }

    // Partial D2H: only transfer the first `count` records (not the full allocation)
    let record_u32s = std::mem::size_of::<GpuShardRamRecord>() / 4; // 26
    let total_u32s = count * record_u32s;
    let buf_vec: Vec<u32> = compact.buffer.to_vec_n(total_u32s).map_err(|e| {
        ZKVMError::InvalidWitness(format!("compact_out D2H failed: {e}").into())
    })?;

    let records: Vec<GpuShardRamRecord> = unsafe {
        let ptr = buf_vec.as_ptr() as *const GpuShardRamRecord;
        std::slice::from_raw_parts(ptr, count).to_vec()
    };
    tracing::debug!("GPU EC compact D2H: {} active records ({} bytes)", count, total_u32s * 4);
    Ok(records)
}

/// Batch compute EC points for continuation circuit ShardRamRecords on GPU.
///
/// Converts ShardRamRecords to GPU format, launches the `batch_continuation_ec`
/// kernel to compute Poseidon2 + SepticCurve on device, and converts results
/// back to ShardRamInput (with EC points).
///
/// Returns (write_inputs, read_inputs) maintaining the write-before-read ordering
/// invariant required by ShardRamCircuit::assign_instances.
pub fn gpu_batch_continuation_ec<E: ExtensionField>(
    write_records: &[(crate::tables::ShardRamRecord, &'static str)],
    read_records: &[(crate::tables::ShardRamRecord, &'static str)],
) -> Result<
    (
        Vec<crate::tables::ShardRamInput<E>>,
        Vec<crate::tables::ShardRamInput<E>>,
    ),
    ZKVMError,
> {
    use crate::tables::ShardRamInput;
    use gkr_iop::gpu::get_cuda_hal;

    let hal = get_cuda_hal().map_err(|e| {
        ZKVMError::InvalidWitness(format!("GPU not available for batch EC: {e}").into())
    })?;

    let total = write_records.len() + read_records.len();
    if total == 0 {
        return Ok((vec![], vec![]));
    }

    // Convert ShardRamRecords to GpuShardRamRecord format
    let mut gpu_records: Vec<GpuShardRamRecord> = Vec::with_capacity(total);
    for (rec, _name) in write_records.iter().chain(read_records.iter()) {
        gpu_records.push(shard_ram_record_to_gpu(rec));
    }

    // GPU batch EC computation
    let result = info_span!("gpu_batch_ec", n = total).in_scope(|| {
        hal.witgen.batch_continuation_ec(&gpu_records)
    }).map_err(|e| {
        ZKVMError::InvalidWitness(format!("GPU batch EC failed: {e}").into())
    })?;

    // Convert back to ShardRamInput, split into writes and reads
    let mut write_inputs = Vec::with_capacity(write_records.len());
    let mut read_inputs = Vec::with_capacity(read_records.len());

    for (i, gpu_rec) in result.iter().enumerate() {
        let (rec, name) = if i < write_records.len() {
            (&write_records[i].0, write_records[i].1)
        } else {
            let ri = i - write_records.len();
            (&read_records[ri].0, read_records[ri].1)
        };

        let ec_point = gpu_shard_ram_record_to_ec_point::<E>(gpu_rec);
        let input = ShardRamInput {
            name,
            record: rec.clone(),
            ec_point,
        };

        if i < write_records.len() {
            write_inputs.push(input);
        } else {
            read_inputs.push(input);
        }
    }

    Ok((write_inputs, read_inputs))
}

/// Convert a ShardRamRecord to GpuShardRamRecord (metadata only, EC fields zeroed).
pub(crate) fn shard_ram_record_to_gpu(rec: &crate::tables::ShardRamRecord) -> GpuShardRamRecord {
    GpuShardRamRecord {
        addr: rec.addr,
        ram_type: match rec.ram_type {
            RAMType::Register => 1,
            RAMType::Memory => 2,
            _ => 0,
        },
        value: rec.value,
        _pad0: 0,
        shard: rec.shard,
        local_clk: rec.local_clk,
        global_clk: rec.global_clk,
        is_to_write_set: if rec.is_to_write_set { 1 } else { 0 },
        nonce: 0,
        point_x: [0; 7],
        point_y: [0; 7],
    }
}

/// Convert a GPU-computed GpuShardRamRecord to ECPoint.
pub(crate) fn gpu_shard_ram_record_to_ec_point<E: ExtensionField>(
    gpu_rec: &GpuShardRamRecord,
) -> crate::tables::ECPoint<E> {
    use crate::scheme::septic_curve::{SepticExtension, SepticPoint};

    let mut point_x_arr = [E::BaseField::ZERO; 7];
    let mut point_y_arr = [E::BaseField::ZERO; 7];
    for j in 0..7 {
        point_x_arr[j] = E::BaseField::from_canonical_u32(gpu_rec.point_x[j]);
        point_y_arr[j] = E::BaseField::from_canonical_u32(gpu_rec.point_y[j]);
    }

    let x = SepticExtension(point_x_arr);
    let y = SepticExtension(point_y_arr);
    let point = SepticPoint::from_affine(x, y);

    crate::tables::ECPoint {
        nonce: gpu_rec.nonce,
        point,
    }
}

pub(crate) fn gpu_lk_counters_to_multiplicity(counters: LkResult) -> Result<Multiplicity<u64>, ZKVMError> {
    let mut tables: [FxHashMap<u64, usize>; 8] = Default::default();

    // Dynamic: D2H + direct FxHashMap construction (no LkMultiplicity)
    info_span!("lk_dynamic_d2h").in_scope(|| {
        let counts: Vec<u32> = counters.dynamic.to_vec().map_err(|e| {
            ZKVMError::InvalidWitness(format!("GPU dynamic lk D2H failed: {e}").into())
        })?;
        let nnz = counts.iter().filter(|&&c| c != 0).count();
        let map = &mut tables[LookupTable::Dynamic as usize];
        map.reserve(nnz);
        for (key, &count) in counts.iter().enumerate() {
            if count != 0 {
                map.insert(key as u64, count as usize);
            }
        }
        Ok::<(), ZKVMError>(())
    })?;

    // Dense tables: same pattern, skip None
    info_span!("lk_dense_d2h").in_scope(|| {
        let dense: &[(LookupTable, &Option<RamBuf>)] = &[
            (LookupTable::DoubleU8, &counters.double_u8),
            (LookupTable::And, &counters.and_table),
            (LookupTable::Or, &counters.or_table),
            (LookupTable::Xor, &counters.xor_table),
            (LookupTable::Ltu, &counters.ltu_table),
            (LookupTable::Pow, &counters.pow_table),
        ];
        for &(table, ref buf_opt) in dense {
            if let Some(buf) = buf_opt {
                let counts: Vec<u32> = buf.to_vec().map_err(|e| {
                    ZKVMError::InvalidWitness(
                        format!("GPU {:?} lk D2H failed: {e}", table).into(),
                    )
                })?;
                let nnz = counts.iter().filter(|&&c| c != 0).count();
                let map = &mut tables[table as usize];
                map.reserve(nnz);
                for (key, &count) in counts.iter().enumerate() {
                    if count != 0 {
                        map.insert(key as u64, count as usize);
                    }
                }
            }
        }
        Ok::<(), ZKVMError>(())
    })?;

    // Fetch (Instruction table)
    if let Some(fetch_buf) = counters.fetch {
        info_span!("lk_fetch_d2h").in_scope(|| {
            let base_pc = counters.fetch_base_pc;
            let counts = fetch_buf.to_vec().map_err(|e| {
                ZKVMError::InvalidWitness(format!("GPU fetch lk D2H failed: {e}").into())
            })?;
            let nnz = counts.iter().filter(|&&c| c != 0).count();
            let map = &mut tables[LookupTable::Instruction as usize];
            map.reserve(nnz);
            for (slot_idx, &count) in counts.iter().enumerate() {
                if count != 0 {
                    let pc = base_pc as u64 + (slot_idx as u64) * 4;
                    map.insert(pc, count as usize);
                }
            }
            Ok::<(), ZKVMError>(())
        })?;
    }

    Ok(Multiplicity(tables))
}

/// Convert GPU device buffer (column-major) to RowMajorMatrix via GPU transpose + D2H copy.
///
/// GPU witgen kernels output column-major layout for better memory coalescing.
/// This function transposes to row-major on GPU before copying to host.
pub(crate) fn gpu_witness_to_rmm<E: ExtensionField>(
    hal: &CudaHalBB31,
    gpu_result: ceno_gpu::common::witgen::types::GpuWitnessResult<
        ceno_gpu::common::BufferImpl<'static, <ff_ext::BabyBearExt4 as ExtensionField>::BaseField>,
    >,
    num_rows: usize,
    num_cols: usize,
    padding: InstancePaddingStrategy,
) -> Result<RowMajorMatrix<E::BaseField>, ZKVMError> {
    // Transpose from column-major to row-major on GPU.
    // Column-major (num_rows x num_cols) is stored as num_cols groups of num_rows elements,
    // which is equivalent to a (num_cols x num_rows) row-major matrix.
    // Transposing with cols=num_rows, rows=num_cols produces (num_rows x num_cols) row-major.
    let mut rmm_buffer = hal
        .alloc_elems_on_device(num_rows * num_cols, false, None)
        .map_err(|e| {
            ZKVMError::InvalidWitness(format!("GPU alloc for transpose failed: {e}").into())
        })?;
    matrix_transpose::<CudaHalBB31, ff_ext::BabyBearExt4, _>(
        &hal.inner,
        &mut rmm_buffer,
        &gpu_result.device_buffer,
        num_rows,
        num_cols,
    )
    .map_err(|e| ZKVMError::InvalidWitness(format!("GPU transpose failed: {e}").into()))?;

    let gpu_data: Vec<<ff_ext::BabyBearExt4 as ExtensionField>::BaseField> = rmm_buffer
        .to_vec()
        .map_err(|e| ZKVMError::InvalidWitness(format!("GPU D2H copy failed: {e}").into()))?;

    // Safety: BabyBear is the only supported GPU field, and E::BaseField must match
    let data: Vec<E::BaseField> = unsafe {
        let mut data = std::mem::ManuallyDrop::new(gpu_data);
        Vec::from_raw_parts(
            data.as_mut_ptr() as *mut E::BaseField,
            data.len(),
            data.capacity(),
        )
    };

    Ok(RowMajorMatrix::<E::BaseField>::new_by_values(
        data, num_cols, padding,
    ))
}
