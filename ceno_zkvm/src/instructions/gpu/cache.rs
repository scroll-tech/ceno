/// Device buffer caching for GPU witness generation.
///
/// Manages thread-local caches for shard step data and shard metadata
/// device buffers, avoiding redundant host-to-device transfers within
/// the same shard.
use ceno_emul::{StepRecord, WordAddr};
use ceno_gpu::{
    Buffer, CudaHal, CudaSlice,
    bb31::{CudaHalBB31, ShardDeviceBuffers},
    common::witgen::types::{GpuShardRamRecord, GpuShardScalars},
};
use rayon::prelude::*;
use std::cell::RefCell;
use tracing::info_span;

use crate::{e2e::ShardContext, error::ZKVMError};

/// Packed next-access entry (16 bytes, u128-aligned).
/// Stores (cycle, addr, next_cycle) with 40-bit cycles for GPU bulk H2D upload.
/// Must be layout-compatible with CUDA `PackedNextAccessEntry` in shard_helpers.cuh.
#[repr(C, align(16))]
#[derive(Debug, Clone, Copy, Default)]
struct PackedNextAccessEntry {
    cycles_lo: u32,
    addr: u32,
    nexts_lo: u32,
    cycles_hi: u8,
    nexts_hi: u8,
    _reserved: u16,
}

impl PackedNextAccessEntry {
    #[inline]
    fn new(cycle: u64, addr: u32, next_cycle: u64) -> Self {
        Self {
            cycles_lo: cycle as u32,
            addr,
            nexts_lo: next_cycle as u32,
            cycles_hi: (cycle >> 32) as u8,
            nexts_hi: (next_cycle >> 32) as u8,
            _reserved: 0,
        }
    }
}

impl Eq for PackedNextAccessEntry {}

impl PartialEq for PackedNextAccessEntry {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.cycles_hi == other.cycles_hi
            && self.cycles_lo == other.cycles_lo
            && self.addr == other.addr
    }
}

impl Ord for PackedNextAccessEntry {
    #[inline]
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        (self.cycles_hi, self.cycles_lo, self.addr).cmp(&(
            other.cycles_hi,
            other.cycles_lo,
            other.addr,
        ))
    }
}

impl PartialOrd for PackedNextAccessEntry {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// Cached shard_steps device buffer with metadata for logging.
struct ShardStepsCache {
    host_ptr: usize,
    byte_len: usize,
    shard_id: usize,
    n_steps: usize,
    device_buf: CudaSlice<u8>,
}

// Thread-local cache for shard_steps device buffer. Invalidated when shard changes.
thread_local! {
    static SHARD_STEPS_DEVICE: RefCell<Option<ShardStepsCache>> =
        const { RefCell::new(None) };
}

/// Upload shard_steps to GPU, reusing cached device buffer if the same data.
pub(crate) fn upload_shard_steps_cached(
    hal: &CudaHalBB31,
    shard_steps: &[StepRecord],
    shard_id: usize,
) -> Result<(), ZKVMError> {
    let ptr = shard_steps.as_ptr() as usize;
    let byte_len = shard_steps.len() * std::mem::size_of::<StepRecord>();

    SHARD_STEPS_DEVICE.with(|cache| {
        let mut cache = cache.borrow_mut();
        if let Some(c) = cache.as_ref() {
            if c.host_ptr == ptr && c.byte_len == byte_len {
                return Ok(()); // cache hit
            }
        }
        // Cache miss: upload
        let mb = byte_len as f64 / (1024.0 * 1024.0);
        tracing::info!(
            "[GPU witgen] uploading shard_steps: shard_id={}, n_steps={}, {:.2} MB",
            shard_id,
            shard_steps.len(),
            mb,
        );
        let bytes: &[u8] =
            unsafe { std::slice::from_raw_parts(shard_steps.as_ptr() as *const u8, byte_len) };
        let device_buf = hal.inner.htod_copy_stream(None, bytes).map_err(|e| {
            ZKVMError::InvalidWitness(format!("shard_steps H2D failed: {e}").into())
        })?;
        *cache = Some(ShardStepsCache {
            host_ptr: ptr,
            byte_len,
            shard_id,
            n_steps: shard_steps.len(),
            device_buf,
        });
        Ok(())
    })
}

/// Borrow the cached device buffer for kernel launch.
/// Panics if `upload_shard_steps_cached` was not called first.
pub(crate) fn with_cached_shard_steps<R>(f: impl FnOnce(&CudaSlice<u8>) -> R) -> R {
    SHARD_STEPS_DEVICE.with(|cache| {
        let cache = cache.borrow();
        let c = cache.as_ref().expect("shard_steps not uploaded");
        f(&c.device_buf)
    })
}

/// Invalidate the cached shard_steps device buffer.
/// Call this when shard processing is complete to free GPU memory.
pub fn invalidate_shard_steps_cache() {
    SHARD_STEPS_DEVICE.with(|cache| {
        let mut cache = cache.borrow_mut();
        if let Some(c) = cache.as_ref() {
            let mb = c.byte_len as f64 / (1024.0 * 1024.0);
            tracing::info!(
                "[GPU witgen] releasing shard_steps cache: shard_id={}, n_steps={}, {:.2} MB",
                c.shard_id,
                c.n_steps,
                mb,
            );
        }
        *cache = None;
    });
}

/// Cached shard metadata device buffers for GPU shard records.
/// Invalidated when shard_id changes; shared across all kernel invocations in one shard.
struct ShardMetadataCache {
    shard_id: usize,
    device_bufs: ShardDeviceBuffers,
    /// Total number of cross-shard next-access entries (constant across shards).
    next_access_count: u32,
    /// Shared EC record buffer (owns the GPU memory, pointer stored in device_bufs).
    shared_ec_buf: Option<ceno_gpu::common::buffer::BufferImpl<'static, u32>>,
    /// Shared EC record count buffer (single u32 counter).
    shared_ec_count: Option<ceno_gpu::common::buffer::BufferImpl<'static, u32>>,
    /// Shared addr_accessed buffer (u32 word addresses).
    shared_addr_buf: Option<ceno_gpu::common::buffer::BufferImpl<'static, u32>>,
    /// Shared addr_accessed count buffer (single u32 counter).
    shared_addr_count: Option<ceno_gpu::common::buffer::BufferImpl<'static, u32>>,
}

thread_local! {
    static SHARD_META_CACHE: RefCell<Option<ShardMetadataCache>> =
        const { RefCell::new(None) };
}

/// Per-shard accumulator for compact shard RAM records produced by GPU kernels.
/// Each record is GPU_SHARD_RAM_RECORD_SIZE bytes (GpuShardRamRecord).
/// Accumulated during opcode circuit assignment, consumed by assign_shared_circuit.
thread_local! {
    static COMPACT_SHARD_RECORDS: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
}

/// Append raw compact shard records from a GPU kernel D2H transfer.
pub fn append_compact_shard_records(raw_bytes: &[u8]) {
    COMPACT_SHARD_RECORDS.with(|cell| {
        cell.borrow_mut().extend_from_slice(raw_bytes);
    });
}

/// Take all accumulated compact shard records, leaving the buffer empty.
pub fn take_compact_shard_records() -> Vec<u8> {
    COMPACT_SHARD_RECORDS.with(|cell| std::mem::take(&mut *cell.borrow_mut()))
}

/// Returns true if compact shard records have been accumulated.
pub fn has_compact_shard_records() -> bool {
    COMPACT_SHARD_RECORDS.with(|cell| !cell.borrow().is_empty())
}

/// Size of a single GpuShardRamRecord in bytes (must match CUDA struct).
const GPU_SHARD_RAM_RECORD_SIZE: usize = 104;

/// Take accumulated compact shard records and convert to ShardRamInput.
/// Returns (writes, reads) pre-partitioned. Empty if no records accumulated.
pub fn take_and_convert_compact_shard_records<E: ff_ext::ExtensionField>() -> (
    Vec<crate::tables::ShardRamInput<E>>,
    Vec<crate::tables::ShardRamInput<E>>,
) {
    let raw = take_compact_shard_records();
    if raw.is_empty() {
        return (vec![], vec![]);
    }
    convert_compact_shard_records::<E>(&raw)
}

/// Convert raw GPU EC record bytes to ShardRamInput.
/// The raw bytes are from `GpuShardRamRecord` structs (104 bytes each).
/// EC points are already computed on GPU — no Poseidon2/SepticCurve needed.
/// Returns (writes, reads) pre-partitioned using parallel iteration.
fn convert_compact_shard_records<E: ff_ext::ExtensionField>(
    raw: &[u8],
) -> (
    Vec<crate::tables::ShardRamInput<E>>,
    Vec<crate::tables::ShardRamInput<E>>,
) {
    use crate::{
        scheme::septic_curve::{SepticExtension, SepticPoint},
        tables::{ECPoint, ShardRamInput, ShardRamRecord},
    };
    use p3::field::FieldAlgebra;

    assert!(raw.len().is_multiple_of(GPU_SHARD_RAM_RECORD_SIZE));
    let count = raw.len() / GPU_SHARD_RAM_RECORD_SIZE;

    #[inline(always)]
    fn convert_record<E: ff_ext::ExtensionField>(raw: &[u8], i: usize) -> ShardRamInput<E> {
        use crate::{
            scheme::septic_curve::{SepticExtension, SepticPoint},
            tables::{ECPoint, ShardRamInput, ShardRamRecord},
        };
        use gkr_iop::RAMType;
        use p3::field::FieldAlgebra;

        let base = i * GPU_SHARD_RAM_RECORD_SIZE;
        let r = &raw[base..base + GPU_SHARD_RAM_RECORD_SIZE];

        // Layout matches GpuShardRamRecord (104 bytes, #[repr(C)]):
        //   0: addr(u32), 4: ram_type(u32), 8: value(u32), 12: _pad(u32),
        //   16: shard(u64), 24: local_clk(u64), 32: global_clk(u64),
        //   40: is_to_write_set(u32), 44: nonce(u32),
        //   48: point_x[7](u32×7), 76: point_y[7](u32×7)
        let addr = u32::from_le_bytes(r[0..4].try_into().unwrap());
        let ram_type_val = u32::from_le_bytes(r[4..8].try_into().unwrap());
        let value = u32::from_le_bytes(r[8..12].try_into().unwrap());
        let shard = u64::from_le_bytes(r[16..24].try_into().unwrap());
        let local_clk = u64::from_le_bytes(r[24..32].try_into().unwrap());
        let global_clk = u64::from_le_bytes(r[32..40].try_into().unwrap());
        let is_to_write_set = u32::from_le_bytes(r[40..44].try_into().unwrap()) != 0;
        let nonce = u32::from_le_bytes(r[44..48].try_into().unwrap());

        let mut point_x_arr = [E::BaseField::ZERO; 7];
        let mut point_y_arr = [E::BaseField::ZERO; 7];
        for j in 0..7 {
            point_x_arr[j] = E::BaseField::from_canonical_u32(u32::from_le_bytes(
                r[48 + j * 4..52 + j * 4].try_into().unwrap(),
            ));
            point_y_arr[j] = E::BaseField::from_canonical_u32(u32::from_le_bytes(
                r[76 + j * 4..80 + j * 4].try_into().unwrap(),
            ));
        }

        let record = ShardRamRecord {
            addr,
            ram_type: if ram_type_val == 1 {
                RAMType::Register
            } else {
                RAMType::Memory
            },
            value,
            shard,
            local_clk,
            global_clk,
            is_to_write_set,
        };

        ShardRamInput {
            name: if is_to_write_set {
                "current_shard_external_write"
            } else {
                "current_shard_external_read"
            },
            record,
            ec_point: ECPoint {
                nonce,
                point: SepticPoint::from_affine(
                    SepticExtension(point_x_arr),
                    SepticExtension(point_y_arr),
                ),
            },
        }
    }

    (0..count)
        .into_par_iter()
        .map(|i| convert_record::<E>(raw, i))
        .partition(|input| input.record.is_to_write_set)
}

/// Build sorted packed next-access entries from the cross-shard HashMap.
/// Called once on the first shard; the result is uploaded to GPU and reused.
fn build_sorted_next_accesses(shard_ctx: &ShardContext) -> Vec<PackedNextAccessEntry> {
    info_span!("next_access_presort").in_scope(|| {
        let next_accesses = &shard_ctx.addr_future_accesses;
        let total: usize = next_accesses.values().map(|pairs| pairs.len()).sum();
        let mut entries = Vec::with_capacity(total);
        for (cycle, pairs) in next_accesses.iter() {
            for &(addr, next_cycle) in pairs.iter() {
                entries.push(PackedNextAccessEntry::new(*cycle, addr.0, next_cycle));
            }
        }
        let len = entries.len();
        info_span!("next_access_par_sort", n = len).in_scope(|| {
            entries.par_sort_unstable();
        });
        tracing::info!(
            "[GPU] sorted {} next-access entries ({:.2} MB)",
            len,
            len * 16 / (1024 * 1024)
        );
        entries
    })
}

/// Build and cache shard metadata device buffers for GPU shard records.
///
/// Next-access device buffers are global and identical across all shards,
/// so they are uploaded once and reused via move. Only per-shard data (scalars +
/// prev_shard_ranges) is re-uploaded when the shard changes.
pub(crate) fn ensure_shard_metadata_cached(
    hal: &CudaHalBB31,
    shard_ctx: &ShardContext,
    n_total_steps: usize,
) -> Result<(), ZKVMError> {
    let shard_id = shard_ctx.shard_id;
    SHARD_META_CACHE.with(|cache| {
        let mut cache = cache.borrow_mut();
        if let Some(c) = cache.as_ref() {
            if c.shard_id == shard_id {
                return Ok(()); // cache hit
            }
        }

        // Move next-access device buffer + count from previous cache (reuse across shards).
        // Next-access data is global — identical across all shards — so we reuse, not re-upload.
        let (existing_next_access, prev_next_access_count) = match cache.take() {
            Some(c) => {
                let count = c.next_access_count;
                let ShardDeviceBuffers {
                    next_access_packed,
                    scalars: _,
                    prev_shard_cycle_range: _,
                    prev_shard_heap_range: _,
                    prev_shard_hint_range: _,
                    gpu_ec_shard_id: _,
                    shared_ec_out_ptr: _,
                    shared_ec_count_ptr: _,
                    shared_addr_out_ptr: _,
                    shared_addr_count_ptr: _,
                    shared_ec_capacity: _,
                    shared_addr_capacity: _,
                } = c.device_bufs;
                (Some(next_access_packed), count)
            }
            None => (None, 0),
        };

        let (next_access_packed_device, next_access_count) = if let Some(buf) = existing_next_access
        {
            (buf, prev_next_access_count) // Reuse existing GPU memory
        } else {
            // First shard: build sorted packed next-access entries from HashMap and H2D upload
            let sorted = build_sorted_next_accesses(shard_ctx);
            let count = sorted.len() as u32;
            let device = info_span!("next_access_h2d").in_scope(|| -> Result<_, ZKVMError> {
                let packed_bytes: &[u8] = if sorted.is_empty() {
                    &[0u8; 16] // sentinel for empty
                } else {
                    unsafe {
                        std::slice::from_raw_parts(
                            sorted.as_ptr() as *const u8,
                            sorted.len() * std::mem::size_of::<PackedNextAccessEntry>(),
                        )
                    }
                };
                let buf = hal
                    .inner
                    .htod_copy_stream(None, packed_bytes)
                    .map_err(|e| {
                        ZKVMError::InvalidWitness(format!("next_access_packed H2D: {e}").into())
                    })?;
                let next_access_device = ceno_gpu::common::buffer::BufferImpl::new(buf);
                let mb = packed_bytes.len() as f64 / (1024.0 * 1024.0);
                tracing::info!(
                    "[GPU shard] next-access uploaded once: {} entries, {:.2} MB (packed)",
                    sorted.len(),
                    mb,
                );
                Ok(next_access_device)
            })?;
            (device, count)
        };

        // Per-shard: always re-upload scalars + prev_shard_ranges
        let scalars = GpuShardScalars {
            shard_cycle_start: shard_ctx.cur_shard_cycle_range.start as u64,
            shard_cycle_end: shard_ctx.cur_shard_cycle_range.end as u64,
            shard_offset_cycle: shard_ctx.current_shard_offset_cycle(),
            shard_id: shard_id as u32,
            heap_start: shard_ctx.platform.heap.start,
            heap_end: shard_ctx.platform.heap.end,
            hint_start: shard_ctx.platform.hints.start,
            hint_end: shard_ctx.platform.hints.end,
            shard_heap_start: shard_ctx.shard_heap_addr_range.start,
            shard_heap_end: shard_ctx.shard_heap_addr_range.end,
            shard_hint_start: shard_ctx.shard_hint_addr_range.start,
            shard_hint_end: shard_ctx.shard_hint_addr_range.end,
            next_access_count,
            num_prev_shards: shard_ctx.prev_shard_cycle_range.len() as u32,
            num_prev_heap_ranges: shard_ctx.prev_shard_heap_range.len() as u32,
            num_prev_hint_ranges: shard_ctx.prev_shard_hint_range.len() as u32,
        };

        let (scalars_device, pscr_device, pshr_device, pshi_device) =
            tracing::info_span!("shard_scalars_h2d").in_scope(|| -> Result<_, ZKVMError> {
                let scalars_bytes: &[u8] = unsafe {
                    std::slice::from_raw_parts(
                        &scalars as *const GpuShardScalars as *const u8,
                        std::mem::size_of::<GpuShardScalars>(),
                    )
                };
                let scalars_device =
                    hal.inner
                        .htod_copy_stream(None, scalars_bytes)
                        .map_err(|e| {
                            ZKVMError::InvalidWitness(
                                format!("shard scalars H2D failed: {e}").into(),
                            )
                        })?;

                let pscr = &shard_ctx.prev_shard_cycle_range;
                let pscr_device = hal
                    .alloc_u64_from_host(if pscr.is_empty() { &[0u64] } else { pscr }, None)
                    .map_err(|e| {
                        ZKVMError::InvalidWitness(format!("pscr H2D failed: {e}").into())
                    })?;

                let pshr = &shard_ctx.prev_shard_heap_range;
                let pshr_device = hal
                    .alloc_u32_from_host(if pshr.is_empty() { &[0u32] } else { pshr }, None)
                    .map_err(|e| {
                        ZKVMError::InvalidWitness(format!("pshr H2D failed: {e}").into())
                    })?;

                let pshi = &shard_ctx.prev_shard_hint_range;
                let pshi_device = hal
                    .alloc_u32_from_host(if pshi.is_empty() { &[0u32] } else { pshi }, None)
                    .map_err(|e| {
                        ZKVMError::InvalidWitness(format!("pshi H2D failed: {e}").into())
                    })?;

                Ok((scalars_device, pscr_device, pshr_device, pshi_device))
            })?;

        tracing::info!(
            "[GPU shard] shard_id={}: per-shard scalars updated",
            shard_id,
        );

        // Allocate shared EC/addr compact buffers for this shard.
        //
        // EC records: cross-shard only (sparse subset of RAM ops).
        //   104 bytes each (26 u32s). Cap at 16M entries ≈ 1.6 GB.
        // Addr records: every gpu_send() emits one (dense).
        //   4 bytes each (1 u32). Cap at 256M entries ≈ 1 GB.
        let max_ops_per_step = 52u64; // keccak worst case
        let total_ops_estimate = n_total_steps as u64 * max_ops_per_step;
        let ec_capacity = total_ops_estimate.min(16 * 1024 * 1024) as usize;
        let ec_u32s = ec_capacity * 26; // 26 u32s per GpuShardRamRecord (104 bytes)
        let addr_capacity = total_ops_estimate.min(256 * 1024 * 1024) as usize;

        let shared_ec_buf = hal
            .witgen
            .alloc_u32_zeroed(ec_u32s, None)
            .map_err(|e| ZKVMError::InvalidWitness(format!("shared_ec_buf alloc: {e}").into()))?;
        let shared_ec_count = hal
            .witgen
            .alloc_u32_zeroed(1, None)
            .map_err(|e| ZKVMError::InvalidWitness(format!("shared_ec_count alloc: {e}").into()))?;
        let shared_addr_buf = hal
            .witgen
            .alloc_u32_zeroed(addr_capacity, None)
            .map_err(|e| ZKVMError::InvalidWitness(format!("shared_addr_buf alloc: {e}").into()))?;
        let shared_addr_count = hal.witgen.alloc_u32_zeroed(1, None).map_err(|e| {
            ZKVMError::InvalidWitness(format!("shared_addr_count alloc: {e}").into())
        })?;

        let shared_ec_out_ptr = shared_ec_buf.device_ptr() as u64;
        let shared_ec_count_ptr = shared_ec_count.device_ptr() as u64;
        let shared_addr_out_ptr = shared_addr_buf.device_ptr() as u64;
        let shared_addr_count_ptr = shared_addr_count.device_ptr() as u64;

        tracing::info!(
            "[GPU shard] shard_id={}: shared buffers allocated: ec_capacity={}, addr_capacity={}",
            shard_id,
            ec_capacity,
            addr_capacity,
        );

        *cache = Some(ShardMetadataCache {
            shard_id,
            next_access_count,
            device_bufs: ShardDeviceBuffers {
                scalars: scalars_device,
                next_access_packed: next_access_packed_device,
                prev_shard_cycle_range: pscr_device,
                prev_shard_heap_range: pshr_device,
                prev_shard_hint_range: pshi_device,
                gpu_ec_shard_id: Some(shard_id as u64),
                shared_ec_out_ptr,
                shared_ec_count_ptr,
                shared_addr_out_ptr,
                shared_addr_count_ptr,
                shared_ec_capacity: ec_capacity as u32,
                shared_addr_capacity: addr_capacity as u32,
            },
            shared_ec_buf: Some(shared_ec_buf),
            shared_ec_count: Some(shared_ec_count),
            shared_addr_buf: Some(shared_addr_buf),
            shared_addr_count: Some(shared_addr_count),
        });
        Ok(())
    })
}

/// Borrow the cached shard device buffers for kernel launch.
pub(crate) fn with_cached_shard_meta<R>(f: impl FnOnce(&ShardDeviceBuffers) -> R) -> R {
    SHARD_META_CACHE.with(|cache| {
        let cache = cache.borrow();
        let c = cache.as_ref().expect("shard metadata not uploaded");
        f(&c.device_bufs)
    })
}

/// Borrow both cached device buffers (shard_steps + shard_meta) in one call.
/// Eliminates the nested `with_cached_shard_steps(|s| with_cached_shard_meta(|m| ...))` pattern.
pub(crate) fn with_cached_gpu_ctx<R>(
    f: impl FnOnce(&CudaSlice<u8>, &ShardDeviceBuffers) -> R,
) -> R {
    SHARD_STEPS_DEVICE.with(|steps_cache| {
        let steps = steps_cache.borrow();
        let s = steps.as_ref().expect("shard_steps not uploaded");
        SHARD_META_CACHE.with(|meta_cache| {
            let meta = meta_cache.borrow();
            let m = meta.as_ref().expect("shard metadata not uploaded");
            f(&s.device_buf, &m.device_bufs)
        })
    })
}

/// Invalidate the shard metadata cache (call when shard processing is complete).
pub fn invalidate_shard_meta_cache() {
    SHARD_META_CACHE.with(|cache| {
        *cache.borrow_mut() = None;
    });
}

/// Take ownership of shared EC and addr_accessed device buffers from the cache.
///
/// Returns (shared_ec_buf, ec_count, shared_addr_buf, addr_count) or None if unavailable.
/// The cache is invalidated after this call — must be called at most once per shard.
pub fn take_shared_device_buffers() -> Option<SharedDeviceBufferSet> {
    SHARD_META_CACHE.with(|cache| {
        let mut cache = cache.borrow_mut();
        let c = cache.as_mut()?;

        let ec_buf = c.shared_ec_buf.take()?;
        let ec_count = c.shared_ec_count.take()?;
        let addr_buf = c.shared_addr_buf.take()?;
        let addr_count = c.shared_addr_count.take()?;

        Some(SharedDeviceBufferSet {
            ec_buf,
            ec_count,
            addr_buf,
            addr_count,
        })
    })
}

/// Shared device buffers taken from the shard metadata cache.
pub struct SharedDeviceBufferSet {
    pub ec_buf: ceno_gpu::common::buffer::BufferImpl<'static, u32>,
    pub ec_count: ceno_gpu::common::buffer::BufferImpl<'static, u32>,
    pub addr_buf: ceno_gpu::common::buffer::BufferImpl<'static, u32>,
    pub addr_count: ceno_gpu::common::buffer::BufferImpl<'static, u32>,
}

/// Read the current shared addr count from device (single u32 D2H).
/// Used by debug comparison to snapshot count before/after a kernel.
#[cfg(feature = "gpu")]
pub(crate) fn read_shared_addr_count() -> usize {
    SHARD_META_CACHE.with(|cache| {
        let cache = cache.borrow();
        let c = cache.as_ref().expect("shard metadata not cached");
        let buf = c
            .shared_addr_count
            .as_ref()
            .expect("shared_addr_count not allocated");
        let v: Vec<u32> = buf.to_vec().expect("shared_addr_count D2H failed");
        v[0] as usize
    })
}

/// Read a range of addr entries [start..end) from the shared addr buffer.
#[cfg(feature = "gpu")]
pub(crate) fn read_shared_addr_range(start: usize, end: usize) -> Vec<u32> {
    if start >= end {
        return Vec::new();
    }
    SHARD_META_CACHE.with(|cache| {
        let cache = cache.borrow();
        let c = cache.as_ref().expect("shard metadata not cached");
        let buf = c
            .shared_addr_buf
            .as_ref()
            .expect("shared_addr_buf not allocated");
        let all: Vec<u32> = buf.to_vec_n(end).expect("shared_addr_buf D2H failed");
        all[start..end].to_vec()
    })
}

/// Batch D2H of shared EC records and addr_accessed buffers after all kernel invocations.
///
/// Called once per shard after all opcode `gpu_assign_instances_inner` calls complete.
/// Transfers accumulated EC records and addresses from shared GPU buffers into `shard_ctx`.
///
/// If the shared buffers have already been taken by `take_shared_device_buffers`
/// (for the full GPU pipeline), this is a no-op.
pub fn flush_shared_ec_buffers(shard_ctx: &mut ShardContext) -> Result<(), ZKVMError> {
    SHARD_META_CACHE.with(|cache| {
        let cache = cache.borrow();
        let c = match cache.as_ref() {
            Some(c) => c,
            None => return Ok(()), // cache already invalidated — no-op
        };

        // If buffers have been taken by take_shared_device_buffers, skip D2H
        let ec_count_buf = match c.shared_ec_count.as_ref() {
            Some(b) => b,
            None => {
                tracing::debug!(
                    "[GPU shard] flush_shared_ec_buffers: buffers already taken, no-op"
                );
                return Ok(());
            }
        };
        let ec_count_vec: Vec<u32> = ec_count_buf
            .to_vec()
            .map_err(|e| ZKVMError::InvalidWitness(format!("shared_ec_count D2H: {e}").into()))?;
        let ec_count = ec_count_vec[0] as usize;
        let ec_capacity = c.device_bufs.shared_ec_capacity as usize;

        assert!(
            ec_count <= ec_capacity,
            "GPU shared EC buffer overflow: count={} > capacity={}. \
             Increase ec_capacity in ensure_shard_metadata_cached.",
            ec_count,
            ec_capacity,
        );

        if ec_count > 0 {
            // D2H EC records (only the active portion)
            let ec_buf = c.shared_ec_buf.as_ref().unwrap();
            let ec_u32s = ec_count * 26; // 26 u32s per GpuShardRamRecord
            let raw_u32: Vec<u32> = ec_buf
                .to_vec_n(ec_u32s)
                .map_err(|e| ZKVMError::InvalidWitness(format!("shared_ec_buf D2H: {e}").into()))?;
            let raw_bytes = unsafe {
                std::slice::from_raw_parts(raw_u32.as_ptr() as *const u8, raw_u32.len() * 4)
            };
            tracing::info!(
                "[GPU shard] flush_shared_ec_buffers: {} EC records, {:.2} MB",
                ec_count,
                raw_bytes.len() as f64 / (1024.0 * 1024.0),
            );
            append_compact_shard_records(raw_bytes);
        }

        // D2H addr_accessed count
        let addr_count_buf = c
            .shared_addr_count
            .as_ref()
            .ok_or_else(|| ZKVMError::InvalidWitness("shared_addr_count not allocated".into()))?;
        let addr_count_vec: Vec<u32> = addr_count_buf
            .to_vec()
            .map_err(|e| ZKVMError::InvalidWitness(format!("shared_addr_count D2H: {e}").into()))?;
        let addr_count = addr_count_vec[0] as usize;
        let addr_capacity = c.device_bufs.shared_addr_capacity as usize;

        assert!(
            addr_count <= addr_capacity,
            "GPU shared addr buffer overflow: count={} > capacity={}",
            addr_count,
            addr_capacity,
        );

        if addr_count > 0 {
            let addr_buf = c.shared_addr_buf.as_ref().unwrap();
            let addrs: Vec<u32> = addr_buf.to_vec_n(addr_count).map_err(|e| {
                ZKVMError::InvalidWitness(format!("shared_addr_buf D2H: {e}").into())
            })?;
            tracing::info!(
                "[GPU shard] flush_shared_ec_buffers: {} addr_accessed, {:.2} MB",
                addr_count,
                addr_count as f64 * 4.0 / (1024.0 * 1024.0),
            );
            let mut forked = shard_ctx.get_forked();
            let thread_ctx = &mut forked[0];
            for &addr in &addrs {
                thread_ctx.push_addr_accessed(WordAddr(addr));
            }
        }

        Ok(())
    })
}
