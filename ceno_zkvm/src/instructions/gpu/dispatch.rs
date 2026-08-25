/// GPU witness generation dispatcher for the proving pipeline.
///
/// This module provides `try_gpu_assign_instances` which:
/// 1. Runs the GPU kernel to fill the witness matrix (fast)
/// 2. Runs a lightweight CPU loop to collect lk and shardram without witness replay
/// 3. Returns the GPU-generated witness + CPU-collected lk and shardram
use ceno_emul::{
    FullTracer, GpuReplayRangeDescriptor, GpuReplayShardArenas, GpuReplayTypedRange,
    GpuTypedSoaArena, InsnKind, StepIndex, StepRecord, WordAddr,
};
use ceno_gpu::{
    Buffer,
    bb31::CudaHalBB31,
    common::{
        buffer::BufferImpl,
        witgen::types::{
            FusedRangeWorkItem, GpuRamRecordSlot, GpuShardRamRecord, GpuWitnessResult,
        },
    },
};
use ff_ext::ExtensionField;
use gkr_iop::utils::lk_multiplicity::Multiplicity;
use p3::field::PrimeCharacteristicRing as FieldAlgebra;
use std::{
    any::{Any, TypeId},
    cell::{Cell, RefCell},
    collections::HashMap,
};
use strum::{EnumCount, IntoEnumIterator};
use tracing::info_span;
use witness::{DeviceMatrixLayout, RowMajorMatrix};

use super::{
    config::{gpu_witgen_enabled, is_kind_disabled, should_materialize_witness_on_gpu},
    utils::debug_compare::{
        debug_compare_final_lk, debug_compare_shard_ec, debug_compare_shardram,
        debug_compare_witness,
    },
};
use crate::{
    e2e::ShardContext,
    error::ZKVMError,
    instructions::{Instruction, cpu_collect_lk_and_shardram, cpu_collect_shardram},
    tables::RMMCollections,
    witness::LkMultiplicity,
};

const PACKED_PRODUCER_COUNT_BITS: u32 = 24;
const PRODUCER_PRIORITY_ROW_BITS: u32 = 23;

fn packed_producer_total(kind: InsnKind, rows: usize) -> u32 {
    let rows = u32::try_from(rows).expect("producer total exceeds u32");
    assert!(
        rows < (1 << PRODUCER_PRIORITY_ROW_BITS),
        "producer total exceeds packed priority row range"
    );
    let order = kind as u32;
    assert!(order < (1 << (31 - 25)));
    (order << PACKED_PRODUCER_COUNT_BITS) | rows
}

#[derive(Debug, Clone, Copy)]
pub enum GpuWitgenKind {
    Add,
    Sub,
    LogicR(u32), // 0=AND, 1=OR, 2=XOR
    LogicI(u32), // 0=AND, 1=OR, 2=XOR
    Addi,
    Lui,
    Auipc,
    Jal,
    ShiftR(u32),    // 0=SLL, 1=SRL, 2=SRA
    ShiftI(u32),    // 0=SLLI, 1=SRLI, 2=SRAI
    Slt(u32),       // 1=SLT(signed), 0=SLTU(unsigned)
    Slti(u32),      // 1=SLTI(signed), 0=SLTIU(unsigned)
    BranchEq(u32),  // 1=BEQ, 0=BNE
    BranchCmp(u32), // 1=signed (BLT/BGE), 0=unsigned (BLTU/BGEU)
    Jalr,
    Sw,
    Sh,
    Sb,
    LoadSub { load_width: u32, is_signed: u32 },
    Mul(u32), // 0=MUL, 1=MULH, 2=MULHU, 3=MULHSU
    Div(u32), // 0=DIV, 1=DIVU, 2=REM, 3=REMU
    Lw,
    Keccak,
    ShardRam,
}

impl GpuWitgenKind {
    fn fused_abi(self) -> (u32, u32, u32) {
        match self {
            Self::Add => (0, 0, 0),
            Self::Sub => (1, 0, 0),
            Self::LogicR(v) => (2, v, 0),
            Self::LogicI(v) => (3, v, 0),
            Self::Addi => (4, 0, 0),
            Self::Lui => (5, 0, 0),
            Self::Auipc => (6, 0, 0),
            Self::Jal => (7, 0, 0),
            Self::ShiftR(v) => (8, v, 0),
            Self::ShiftI(v) => (9, v, 0),
            Self::Slt(v) => (10, v, 0),
            Self::Slti(v) => (11, v, 0),
            Self::BranchEq(v) => (12, v, 0),
            Self::BranchCmp(v) => (13, v, 0),
            Self::Jalr => (14, 0, 0),
            Self::Sw => (15, 0, 0),
            Self::Sh => (16, 0, 0),
            Self::Sb => (17, 0, 0),
            Self::LoadSub {
                load_width,
                is_signed,
            } => (18, load_width, is_signed),
            Self::Mul(v) => (19, v, 0),
            Self::Div(v) => (20, v, 0),
            // The u16-limb circuit has an explicit imm_sign column.  The
            // fused CUDA ABI uses arg0 to keep that column in the layout.
            Self::Lw => (21, u32::from(cfg!(feature = "u16limb_circuit")), 0),
            Self::Keccak | Self::ShardRam => panic!("sparse kind has no fused ABI"),
        }
    }
}

// Re-exports from device_cache module for external callers (e2e.rs, structs.rs).
pub use super::cache::{
    SharedDeviceBufferSet, flush_shared_ec_buffers, invalidate_shard_meta_cache,
    invalidate_shard_steps_cache, take_shared_device_buffers,
};
use super::{
    cache::{
        begin_gpu_shard_session, ensure_compact_shard_metadata_cached, take_shared_lk_counters,
        with_cached_gpu_ctx_opt,
    },
    utils::d2h::{
        CompactEcBuf, LkResult, RamBuf, WitResult, gpu_collect_shard_records, gpu_compact_ec_d2h,
        gpu_lk_counters_to_multiplicity, gpu_witness_to_rmm, gpu_witness_to_rmm_d2h,
    },
};

/// Transfer and materialize the lookup counters accumulated across this shard.
pub fn flush_shared_lk_counters() -> Result<Option<Multiplicity<u64>>, ZKVMError> {
    let Some(counters) = take_shared_lk_counters() else {
        return Ok(None);
    };
    info_span!("gpu_shard_lk_d2h")
        .in_scope(|| gpu_lk_counters_to_multiplicity(counters))
        .map(Some)
}

thread_local! {
    /// Thread-local flag to force CPU path (used by debug comparison code).
    static FORCE_CPU_PATH: Cell<bool> = const { Cell::new(false) };
    static FUSED_INGRESS: RefCell<Option<FusedIngressState>> = const { RefCell::new(None) };
    static FUSED_ASSIGNMENTS: RefCell<HashMap<TypeId, Box<dyn Any>>> = RefCell::new(HashMap::new());
}

fn abort_fused_session() {
    FUSED_INGRESS.with(|slot| {
        slot.borrow_mut().take();
    });
    FUSED_ASSIGNMENTS.with(|cache| cache.borrow_mut().clear());
}

fn validate_fused_assignment_cache_disjoint(
    owners: &std::collections::HashSet<TypeId>,
) -> Result<(), ZKVMError> {
    FUSED_ASSIGNMENTS.with(|cache| {
        if cache.borrow().keys().any(|owner| owners.contains(owner)) {
            Err(ZKVMError::InvalidWitness(
                "fused assignment owner collides with cached assignment".into(),
            ))
        } else {
            Ok(())
        }
    })
}

fn publish_fused_assignments(finalized: Vec<(TypeId, Box<dyn Any>)>) -> Result<(), ZKVMError> {
    FUSED_ASSIGNMENTS.with(|cache| {
        let mut cache = cache.borrow_mut();
        if finalized.iter().any(|(owner, _)| cache.contains_key(owner)) {
            return Err(ZKVMError::InvalidWitness(
                "fused assignment owner collides before cache publication".into(),
            ));
        }
        for (owner, assignment) in finalized {
            let std::collections::hash_map::Entry::Vacant(entry) = cache.entry(owner) else {
                unreachable!("fused assignment cache changed during publication")
            };
            entry.insert(assignment);
        }
        Ok(())
    })
}

type Bb = <ff_ext::BabyBearExt4 as ExtensionField>::BaseField;

struct FusedRegistration {
    owner: TypeId,
    kind: InsnKind,
    tag: u32,
    arg0: u32,
    arg1: u32,
    num_cols: usize,
    num_col_entries: usize,
    mem_max_bits: Option<u32>,
    rows: usize,
    output: Option<BufferImpl<'static, Bb>>,
    cols: BufferImpl<'static, u32>,
    finalize: Option<Box<dyn FnOnce(BufferImpl<'static, Bb>) -> Result<Box<dyn Any>, ZKVMError>>>,
}

struct FusedIngressState {
    arenas: GpuReplayShardArenas,
    fetch: (u32, usize),
    reserved_addresses: u32,
    registrations: Vec<FusedRegistration>,
    launched: bool,
    provisional: Option<ProvisionalFusedSession>,
    drained_host_slots: [Option<GpuReplayTypedRange>; 2],
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ProvisionalShardIdentity {
    shard_id: usize,
    cycle_range: std::ops::Range<usize>,
    platform_heap: std::ops::Range<u32>,
    platform_hints: std::ops::Range<u32>,
    heap_range: std::ops::Range<u32>,
    hint_range: std::ops::Range<u32>,
    prev_cycles: Vec<u64>,
    prev_heaps: Vec<u32>,
    prev_hints: Vec<u32>,
}

impl ProvisionalShardIdentity {
    fn from_context(ctx: &ShardContext) -> Self {
        Self {
            shard_id: ctx.shard_id,
            cycle_range: ctx.cur_shard_cycle_range.clone(),
            platform_heap: ctx.platform.heap.clone(),
            platform_hints: ctx.platform.hints.clone(),
            heap_range: ctx.shard_heap_addr_range.clone(),
            hint_range: ctx.shard_hint_addr_range.clone(),
            prev_cycles: ctx.prev_shard_cycle_range.clone(),
            prev_heaps: ctx.prev_shard_heap_range.clone(),
            prev_hints: ctx.prev_shard_hint_range.clone(),
        }
    }
}

struct ProvisionalFusedSession {
    identity: ProvisionalShardIdentity,
    pointers: [u64; 9],
    launcher: ceno_gpu::common::witgen::typed_ingress::FusedRangeLauncher,
    producer_bases: [usize; InsnKind::COUNT],
    expected_ranges: usize,
    expected_descriptors: Vec<GpuReplayRangeDescriptor>,
    compact_source: bool,
    expected_payload_bytes: u64,
    observed_payload_bytes: u64,
    submitted_ranges: usize,
    registration_pointers: Vec<(u64, u64)>,
    host_slots: [Option<GpuReplayTypedRange>; 2],
    host_fingerprints: [Option<HostOwnerFingerprint>; 2],
    device_fingerprint: ([u64; 2], usize, u64, usize),
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct HostOwnerFingerprint {
    typed_vec: (u64, usize),
    family_ptrs: [u64; InsnKind::COUNT],
    family_capacities: [usize; InsnKind::COUNT],
    fallback: (u64, usize),
}

fn host_owner_fingerprint(range: &GpuReplayTypedRange) -> HostOwnerFingerprint {
    let mut family_ptrs = [0u64; InsnKind::COUNT];
    let mut family_capacities = [0usize; InsnKind::COUNT];
    for (index, arena) in range.typed.iter().enumerate() {
        if let Some(arena) = arena {
            family_ptrs[index] = if arena.is_compact() {
                arena.payload_bytes().as_ptr() as u64
            } else {
                arena
                    .fields()
                    .first()
                    .map_or(0, |field| field.as_ptr() as u64)
            };
            family_capacities[index] = arena.capacity();
        }
    }
    HostOwnerFingerprint {
        typed_vec: (range.typed.as_ptr() as u64, range.typed.capacity()),
        family_ptrs,
        family_capacities,
        fallback: (range.fallback.as_ptr() as u64, range.fallback.capacity()),
    }
}

pub(crate) fn install_compact_replay_arenas(arenas: GpuReplayShardArenas) {
    let mut min_pc = u32::MAX;
    let mut max_pc = 0;
    let mut reserved_addresses = ceno_emul::CONTINUATION_ADDRESS_SEND_BOUND;
    for range in &arenas.ranges {
        for arena in range.typed.iter().flatten() {
            reserved_addresses = reserved_addresses
                .checked_add(
                    u32::try_from(arena.len())
                        .expect("typed row count exceeds u32")
                        .checked_mul(u32::from(
                            ceno_emul::gpu_typed_kind_spec(arena.kind())
                                .unwrap()
                                .send_arity,
                        ))
                        .expect("ordinary address reservation overflow"),
                )
                .expect("shard address reservation overflow");
            if let Some((arena_min, arena_max)) = arena
                .pc_bounds()
                .expect("compact replay PC source is malformed")
            {
                min_pc = min_pc.min(arena_min);
                max_pc = max_pc.max(arena_max);
            }
        }
    }
    reserved_addresses = reserved_addresses
        .checked_add(
            u32::try_from(arenas.fallback.len())
                .expect("fallback row count exceeds u32")
                .checked_mul(ceno_emul::MAX_SPARSE_ADDRESS_SENDS_PER_STEP)
                .expect("sparse address reservation overflow"),
        )
        .expect("shard address reservation overflow");
    let fetch_params = if min_pc <= max_pc {
        (min_pc, ((max_pc - min_pc) / 4 + 1) as usize)
    } else {
        (0, 1)
    };
    FUSED_INGRESS.with(|slot| {
        assert!(
            slot.borrow().is_none(),
            "compact replay arenas already installed"
        );
        *slot.borrow_mut() = Some(FusedIngressState {
            arenas,
            fetch: fetch_params,
            reserved_addresses,
            registrations: Vec::new(),
            launched: false,
            provisional: None,
            drained_host_slots: [None, None],
        });
    });
}

fn validate_provisional_range_payload(
    range: &GpuReplayTypedRange,
    descriptor: &GpuReplayRangeDescriptor,
    compact_source: bool,
) -> Result<usize, ZKVMError> {
    if range.sequence != descriptor.sequence {
        return Err(ZKVMError::InvalidWitness(
            "provisional range/descriptor sequence mismatch".into(),
        ));
    }
    if !range.fallback.is_empty() {
        return Err(ZKVMError::InvalidWitness(
            "provisional range fallback was not drained before GPU handoff".into(),
        ));
    }
    if range.typed.len() != InsnKind::COUNT {
        return Err(ZKVMError::InvalidWitness(
            "provisional range family vector length mismatch".into(),
        ));
    }
    let mut observed = 0usize;
    for ((kind, expected_rows), arena) in InsnKind::iter()
        .zip(descriptor.family_counts)
        .zip(&range.typed)
    {
        let actual_rows = arena.as_ref().map_or(0, GpuTypedSoaArena::len);
        if actual_rows != expected_rows {
            return Err(ZKVMError::InvalidWitness(
                format!(
                    "provisional family row mismatch: kind={kind:?}, expected={expected_rows}, observed={actual_rows}"
                )
                .into(),
            ));
        }
        let Some(arena) = arena else {
            continue;
        };
        if arena.kind() != kind || arena.range_start() != descriptor.range_start {
            return Err(ZKVMError::InvalidWitness(
                format!("provisional family identity mismatch: kind={kind:?}").into(),
            ));
        }
        if arena.is_compact() != compact_source {
            return Err(ZKVMError::InvalidWitness(
                format!(
                    "provisional family storage mode mismatch: kind={kind:?}, expected_compact={compact_source}"
                )
                .into(),
            ));
        }
        let spec = ceno_emul::gpu_typed_kind_spec(kind).ok_or_else(|| {
            ZKVMError::InvalidWitness(
                format!("unsupported provisional family: kind={kind:?}").into(),
            )
        })?;
        let row_bytes = if compact_source {
            spec.layout.compact_bytes()
        } else {
            spec.layout.bytes()
        };
        let expected_bytes = expected_rows
            .checked_mul(row_bytes)
            .ok_or_else(|| ZKVMError::InvalidWitness("provisional family byte overflow".into()))?;
        let actual_bytes = initialized_typed_bytes(arena).ok_or_else(|| {
            ZKVMError::InvalidWitness("provisional initialized-prefix byte overflow".into())
        })?;
        if actual_bytes != expected_bytes {
            return Err(ZKVMError::InvalidWitness(
                format!(
                    "provisional family byte mismatch: kind={kind:?}, expected={expected_bytes}, observed={actual_bytes}"
                )
                .into(),
            ));
        }
        observed = observed
            .checked_add(actual_bytes)
            .ok_or_else(|| ZKVMError::InvalidWitness("provisional range byte overflow".into()))?;
    }
    let expected = descriptor
        .fused_payload_bytes(compact_source)
        .ok_or_else(|| {
            ZKVMError::InvalidWitness("invalid provisional descriptor payload".into())
        })?;
    if observed != expected {
        return Err(ZKVMError::InvalidWitness(
            format!(
                "provisional descriptor byte mismatch: expected={expected}, observed={observed}"
            )
            .into(),
        ));
    }
    Ok(observed)
}

pub(crate) fn begin_provisional_fused_session(
    family_totals: [usize; InsnKind::COUNT],
    reserved_addresses: u32,
    expected_descriptors: &[GpuReplayRangeDescriptor],
    compact_source: bool,
    stage_capacity: usize,
    work_capacity: usize,
    fetch: (u32, usize),
    preview: &ShardContext,
) -> Result<(), ZKVMError> {
    let result = (|| {
        let expected_ranges = expected_descriptors.len();
        if expected_ranges == 0 {
            return Err(ZKVMError::InvalidWitness(
                "provisional fused session requires a nonempty shard".into(),
            ));
        }
        let mut descriptor_family_totals = [0usize; InsnKind::COUNT];
        let mut expected_payload_bytes = 0u64;
        for (sequence, descriptor) in expected_descriptors.iter().enumerate() {
            if descriptor.shard_id
                != u32::try_from(preview.shard_id).map_err(|_| {
                    ZKVMError::InvalidWitness("provisional shard id exceeds u32".into())
                })?
                || descriptor.sequence as usize != sequence
                || descriptor.unsupported_count != 0
                || descriptor.checked_total()
                    != Some(usize::try_from(descriptor.range_len).map_err(|_| {
                        ZKVMError::InvalidWitness("provisional range length exceeds usize".into())
                    })?)
            {
                return Err(ZKVMError::InvalidWitness(
                    "invalid provisional descriptor identity or closure".into(),
                ));
            }
            for (total, count) in descriptor_family_totals
                .iter_mut()
                .zip(descriptor.family_counts)
            {
                *total = total.checked_add(count).ok_or_else(|| {
                    ZKVMError::InvalidWitness("provisional family total overflow".into())
                })?;
            }
            expected_payload_bytes = expected_payload_bytes
                .checked_add(
                    u64::try_from(descriptor.fused_payload_bytes(compact_source).ok_or_else(
                        || ZKVMError::InvalidWitness("invalid provisional descriptor bytes".into()),
                    )?)
                    .map_err(|_| {
                        ZKVMError::InvalidWitness("provisional descriptor bytes exceed u64".into())
                    })?,
                )
                .ok_or_else(|| {
                    ZKVMError::InvalidWitness("provisional payload total overflow".into())
                })?;
        }
        if descriptor_family_totals != family_totals {
            return Err(ZKVMError::InvalidWitness(
                "provisional descriptor family totals mismatch".into(),
            ));
        }
        FUSED_INGRESS.with(|slot| {
            if slot.borrow().is_some() {
                return Err(ZKVMError::InvalidWitness(
                    "overlapping fused shard session".into(),
                ));
            }
            *slot.borrow_mut() = Some(FusedIngressState {
                arenas: GpuReplayShardArenas::provisional(family_totals),
                fetch,
                reserved_addresses,
                registrations: Vec::new(),
                launched: false,
                provisional: None,
                drained_host_slots: [None, None],
            });
            Ok(())
        })?;
        let hal = gkr_iop::gpu::get_cuda_hal().map_err(|e| {
            ZKVMError::InvalidWitness(
                format!("CUDA unavailable for provisional session: {e}").into(),
            )
        })?;
        let logical_steps = (preview.cur_shard_cycle_range.end
            - preview.cur_shard_cycle_range.start)
            / FullTracer::SUBCYCLES_PER_INSN as usize;
        ensure_compact_shard_metadata_cached(
            &hal,
            preview,
            logical_steps,
            fetch,
            reserved_addresses,
        )?;
        super::cache::set_reserved_address_capacity(reserved_addresses);
        let pointers = super::cache::cached_shard_pointer_fingerprint();
        let launcher = ceno_gpu::common::witgen::typed_ingress::FusedRangeLauncher::new(
            hal.inner.clone(),
            stage_capacity,
            work_capacity,
        )
        .map_err(|e| ZKVMError::InvalidWitness(format!("provisional launcher init: {e}").into()))?;
        let device_fingerprint = launcher.storage_fingerprint();
        FUSED_INGRESS.with(|slot| {
            slot.borrow_mut().as_mut().unwrap().provisional = Some(ProvisionalFusedSession {
                identity: ProvisionalShardIdentity::from_context(preview),
                pointers,
                launcher,
                producer_bases: [0; InsnKind::COUNT],
                expected_ranges,
                expected_descriptors: expected_descriptors.to_vec(),
                compact_source,
                expected_payload_bytes,
                observed_payload_bytes: 0,
                submitted_ranges: 0,
                registration_pointers: Vec::new(),
                host_slots: [None, None],
                host_fingerprints: [None, None],
                device_fingerprint,
            });
        });
        Ok(())
    })();
    if result.is_err() {
        abort_fused_session();
    }
    result
}

pub(crate) fn seal_provisional_fused_session() -> Result<(), ZKVMError> {
    let result = FUSED_INGRESS.with(|slot| {
        let mut borrowed = slot.borrow_mut();
        let state = borrowed.as_mut().ok_or_else(|| {
            ZKVMError::InvalidWitness("missing provisional session at registration seal".into())
        })?;
        let pointers = state
            .registrations
            .iter()
            .map(|registration| {
                (
                    registration.output.as_ref().unwrap().device_ptr() as u64,
                    registration.cols.device_ptr() as u64,
                )
            })
            .collect::<Vec<_>>();
        if pointers.is_empty() {
            return Err(ZKVMError::InvalidWitness(
                "provisional session has no registrations".into(),
            ));
        }
        let session = state.provisional.as_mut().unwrap();
        if !session.registration_pointers.is_empty() {
            return Err(ZKVMError::InvalidWitness(
                "provisional registrations sealed twice".into(),
            ));
        }
        session.registration_pointers = pointers;
        Ok(())
    });
    if result.is_err() {
        abort_fused_session();
    }
    result
}

fn initialized_typed_bytes(arena: &GpuTypedSoaArena) -> Option<usize> {
    if arena.is_empty() {
        return Some(0);
    }
    if arena.is_compact() {
        Some(arena.payload_bytes().len())
    } else {
        arena.fields().iter().try_fold(0usize, |sum, _| {
            sum.checked_add(arena.len().checked_mul(std::mem::size_of::<u32>())?)
        })
    }
}

pub(crate) fn submit_provisional_fused_range(
    range: GpuReplayTypedRange,
) -> Result<Option<GpuReplayTypedRange>, ZKVMError> {
    use ceno_gpu::common::witgen::types::MAX_TS_BITS;
    let result = FUSED_INGRESS.with(|slot| -> Result<Option<GpuReplayTypedRange>, ZKVMError> {
        let mut borrowed = slot.borrow_mut();
        let state = borrowed
            .as_mut()
            .ok_or_else(|| ZKVMError::InvalidWitness("provisional range without session".into()))?;
        let mut registration_for_kind = [usize::MAX; InsnKind::COUNT];
        for (index, registration) in state.registrations.iter().enumerate() {
            registration_for_kind[registration.kind as usize] = index;
        }
        let session = state.provisional.as_mut().ok_or_else(|| {
            ZKVMError::InvalidWitness("range submitted to non-provisional session".into())
        })?;
        let descriptor = session
            .expected_descriptors
            .get(session.submitted_ranges)
            .ok_or_else(|| {
                ZKVMError::InvalidWitness("provisional range exceeds descriptor schedule".into())
            })?;
        let byte_len =
            validate_provisional_range_payload(&range, descriptor, session.compact_source)?;
        let fill_slot = session.launcher.next_slot_index();
        if session.host_slots[fill_slot].is_some() {
            return Err(ZKVMError::InvalidWitness(
                "CPU fill attempted to overwrite an unrecycled GPU slot".into(),
            ));
        }
        let fingerprint = host_owner_fingerprint(&range);
        if let Some(expected) = &session.host_fingerprints[fill_slot] {
            if expected != &fingerprint {
                return Err(ZKVMError::InvalidWitness(
                    "warmed CPU owner pointer/capacity fingerprint changed".into(),
                ));
            }
        } else {
            if let Some(other) = &session.host_fingerprints[fill_slot ^ 1]
                && (other.family_capacities != fingerprint.family_capacities
                    || other.fallback.1 != fingerprint.fallback.1)
            {
                return Err(ZKVMError::InvalidWitness(
                    "warmed CPU owners have different family capacities".into(),
                ));
            }
            session.host_fingerprints[fill_slot] = Some(fingerprint);
        }
        if session.launcher.storage_fingerprint() != session.device_fingerprint {
            return Err(ZKVMError::InvalidWitness(
                "fused device pointer/capacity fingerprint changed".into(),
            ));
        }
        session.host_slots[fill_slot] = Some(range);
        let range = session.host_slots[fill_slot].as_ref().unwrap();
        if range.sequence as usize != session.submitted_ranges {
            return Err(ZKVMError::InvalidWitness(
                "provisional range sequence mismatch".into(),
            ));
        }
        let mem_max_bits = state
            .registrations
            .iter()
            .filter_map(|r| r.mem_max_bits)
            .next()
            .unwrap_or(32);
        let registrations = &state.registrations;
        let producer_bases = &mut session.producer_bases;
        let launcher = &mut session.launcher;
        let mut compact_families = [&[][..]; InsnKind::COUNT * 13];
        let mut family_count = 0usize;
        let mut work = [FusedRangeWorkItem::default(); InsnKind::COUNT];
        let mut work_count = 0usize;
        let mut cursor = 0usize;
        for arena in range
            .typed
            .iter()
            .flatten()
            .filter(|arena| !arena.is_empty())
        {
            let arena: &GpuTypedSoaArena = arena;
            let index = registration_for_kind[arena.kind() as usize];
            if index == usize::MAX {
                return Err(ZKVMError::InvalidWitness(
                    "missing provisional registration".into(),
                ));
            }
            let registration = &registrations[index];
            let mut offsets = [0u32; 13];
            if arena.is_compact() {
                offsets[0] = u32::try_from(cursor).map_err(|_| {
                    ZKVMError::InvalidWitness("typed compact offset exceeds u32".into())
                })?;
                let bytes = arena.payload_bytes();
                compact_families[family_count] = bytes;
                family_count += 1;
                cursor = cursor.checked_add(bytes.len()).ok_or_else(|| {
                    ZKVMError::InvalidWitness("typed compact cursor overflow".into())
                })?;
            } else {
                for (field_index, field) in arena.fields().iter().enumerate() {
                    offsets[field_index] = u32::try_from(cursor).map_err(|_| {
                        ZKVMError::InvalidWitness("typed field offset exceeds u32".into())
                    })?;
                    let bytes = unsafe {
                        std::slice::from_raw_parts(
                            field.as_ptr().cast::<u8>(),
                            arena
                                .len()
                                .checked_mul(std::mem::size_of::<u32>())
                                .ok_or_else(|| {
                                    ZKVMError::InvalidWitness("typed field byte overflow".into())
                                })?,
                        )
                    };
                    compact_families[family_count] = bytes;
                    family_count += 1;
                    cursor = cursor.checked_add(bytes.len()).ok_or_else(|| {
                        ZKVMError::InvalidWitness("typed field cursor overflow".into())
                    })?;
                }
            }
            let producer_base = producer_bases[arena.kind() as usize];
            producer_bases[arena.kind() as usize] += arena.len();
            work[work_count] = FusedRangeWorkItem {
                tag: registration.tag,
                layout: arena.layout() as u32,
                row_count: u32::try_from(arena.len()).unwrap(),
                producer_base: u32::try_from(producer_base).unwrap(),
                producer_total: packed_producer_total(arena.kind(), registration.rows),
                num_cols: u32::try_from(registration.num_cols).unwrap(),
                arg0: registration.arg0,
                arg1: registration.arg1,
                num_col_entries: u32::try_from(registration.num_col_entries).unwrap(),
                input_fields: offsets,
                compact_stride: if arena.is_compact() {
                    u32::try_from(arena.layout().compact_bytes()).unwrap()
                } else {
                    0
                },
                range_start: arena.range_start(),
                pc_base: arena.pc_base(),
                compact_opcode: arena.compact_opcode(),
                output_ptr: registration.output.as_ref().unwrap().device_ptr() as u64,
                cols_ptr: registration.cols.device_ptr() as u64,
            };
            work_count += 1;
        }
        if cursor != byte_len || work_count == 0 {
            return Err(ZKVMError::InvalidWitness(
                "typed direct-source descriptor closure mismatch".into(),
            ));
        }
        super::cache::with_cached_shard_meta(|shard| {
            let launched_slot = launcher.launch_direct(
                &compact_families[..family_count],
                &work[..work_count],
                (session.identity.cycle_range.start as u64)
                    .saturating_sub(FullTracer::SUBCYCLES_PER_INSN),
                MAX_TS_BITS,
                mem_max_bits,
                shard,
            )?;
            if launched_slot != fill_slot {
                return Err(ceno_gpu::HalError::InvalidInput(
                    "CPU/GPU fused slot identity mismatch".into(),
                ));
            }
            Ok(())
        })
        .map_err(|e| ZKVMError::InvalidWitness(format!("provisional range launch: {e}").into()))?;
        session.observed_payload_bytes = session
            .observed_payload_bytes
            .checked_add(u64::try_from(byte_len).map_err(|_| {
                ZKVMError::InvalidWitness("provisional observed bytes exceed u64".into())
            })?)
            .ok_or_else(|| {
                ZKVMError::InvalidWitness("provisional observed byte total overflow".into())
            })?;
        session.submitted_ranges += 1;
        let recycled = if session.submitted_ranges >= 2 {
            let recyclable = session.launcher.wait_next_slot_recyclable().map_err(|e| {
                ZKVMError::InvalidWitness(format!("provisional slot recycle: {e}").into())
            })?;
            session.host_slots[recyclable].take()
        } else {
            None
        };
        Ok(recycled)
    });
    if result.is_err() {
        abort_fused_session();
    }
    result
}

fn finish_provisional_fused_session(shard_ctx: &ShardContext) -> Result<(), ZKVMError> {
    let mut state = FUSED_INGRESS
        .with(|slot| slot.borrow_mut().take())
        .ok_or_else(|| ZKVMError::InvalidWitness("missing provisional fused session".into()))?;
    let mut session = state.provisional.take().unwrap();
    let canonical_identity = ProvisionalShardIdentity::from_context(shard_ctx);
    if session.identity != canonical_identity {
        return Err(ZKVMError::InvalidWitness(
            format!(
                "provisional/canonical shard scalar mismatch: provisional={:?}, canonical={canonical_identity:?}",
                session.identity
            )
            .into(),
        ));
    }
    if session.pointers != super::cache::cached_shard_pointer_fingerprint() {
        return Err(ZKVMError::InvalidWitness(
            "provisional/canonical shard pointer mismatch".into(),
        ));
    }
    let canonical_registration_pointers = state
        .registrations
        .iter()
        .map(|registration| {
            (
                registration.output.as_ref().unwrap().device_ptr() as u64,
                registration.cols.device_ptr() as u64,
            )
        })
        .collect::<Vec<_>>();
    if session.registration_pointers != canonical_registration_pointers {
        return Err(ZKVMError::InvalidWitness(
            "provisional/canonical output pointer mismatch".into(),
        ));
    }
    if session.launcher.storage_fingerprint() != session.device_fingerprint {
        return Err(ZKVMError::InvalidWitness(
            "fused device fingerprint changed before final drain".into(),
        ));
    }
    if session.submitted_ranges != session.expected_ranges
        || session.observed_payload_bytes != session.expected_payload_bytes
    {
        return Err(ZKVMError::InvalidWitness(
            format!(
                "provisional payload closure mismatch: descriptors={}, submitted={}, expected_bytes={}, observed_bytes={}",
                session.expected_ranges,
                session.submitted_ranges,
                session.expected_payload_bytes,
                session.observed_payload_bytes
            )
            .into(),
        ));
    }
    tracing::info!(
        shard_id = shard_ctx.shard_id,
        source_mode = if session.compact_source {
            "packed"
        } else {
            "soa"
        },
        descriptors = session.expected_ranges,
        expected_payload_bytes = session.expected_payload_bytes,
        observed_payload_bytes = session.observed_payload_bytes,
        "fused ordinary descriptor payload closure"
    );
    if session.expected_ranges >= 2 {
        let [Some(first), Some(second)] = &session.host_fingerprints else {
            return Err(ZKVMError::InvalidWitness(
                "provisional session did not observe exactly two warmed CPU owners".into(),
            ));
        };
        if first.typed_vec.0 == second.typed_vec.0
            || first
                .family_ptrs
                .iter()
                .zip(second.family_ptrs)
                .zip(first.family_capacities)
                .any(|((&left, right), capacity)| capacity != 0 && left == right)
            || (first.fallback.1 != 0 && first.fallback.0 == second.fallback.0)
        {
            return Err(ZKVMError::InvalidWitness(
                "provisional CPU owners alias storage".into(),
            ));
        }
    }
    let drained_host_slots = std::mem::take(&mut session.host_slots);
    let launch_count = session
        .launcher
        .finish()
        .map_err(|e| ZKVMError::InvalidWitness(format!("provisional drain: {e}").into()))?;
    if launch_count as usize != session.expected_ranges
        || session.submitted_ranges != session.expected_ranges
    {
        return Err(ZKVMError::InvalidWitness(
            "provisional descriptor/launch mismatch".into(),
        ));
    }
    tracing::info!(
        shard_id = shard_ctx.shard_id,
        descriptors = session.expected_ranges,
        launches = launch_count,
        "fused ordinary range schedule complete"
    );
    tracing::info!(
        tracer = "GpuReplayTracer",
        native_mode = "GPU_REPLAY_DIRECT",
        descriptors = session.expected_ranges,
        launches = launch_count,
        ordinary_callbacks = 0u64,
        fallback_categories = "ecall,exceptional",
        "GPU_REPLAY_DIRECT runtime marker"
    );
    for registration in &state.registrations {
        if session.producer_bases[registration.kind as usize] != registration.rows {
            return Err(ZKVMError::InvalidWitness(
                format!(
                    "{:?} provisional producer coverage mismatch",
                    registration.kind
                )
                .into(),
            ));
        }
    }
    let drained_owner_count = drained_host_slots.iter().flatten().count();
    if drained_owner_count != 1 {
        return Err(ZKVMError::InvalidWitness(
            format!("provisional final drain recovered {drained_owner_count} owners, expected 1")
                .into(),
        ));
    }
    let mut owners = std::collections::HashSet::with_capacity(state.registrations.len());
    if state
        .registrations
        .iter()
        .any(|registration| !owners.insert(registration.owner))
    {
        return Err(ZKVMError::InvalidWitness(
            "duplicate provisional assignment owner".into(),
        ));
    }
    if let Err(error) = validate_fused_assignment_cache_disjoint(&owners) {
        abort_fused_session();
        return Err(error);
    }
    let mut finalized_assignments = Vec::with_capacity(state.registrations.len());
    for mut registration in state.registrations.drain(..) {
        let finalized =
            match registration.finalize.take().unwrap()(registration.output.take().unwrap()) {
                Ok(finalized) => finalized,
                Err(error) => {
                    abort_fused_session();
                    return Err(error);
                }
            };
        finalized_assignments.push((registration.owner, finalized));
    }
    if let Err(error) = publish_fused_assignments(finalized_assignments) {
        abort_fused_session();
        return Err(error);
    }
    state.drained_host_slots = drained_host_slots;
    state.launched = true;
    FUSED_INGRESS.with(|slot| *slot.borrow_mut() = Some(state));
    Ok(())
}

pub(crate) fn clear_compact_replay_arenas() -> [Option<GpuReplayTypedRange>; 2] {
    let recovered = FUSED_INGRESS.with(|slot| {
        if let Some(state) = slot.borrow_mut().take() {
            assert!(state.launched, "typed replay ranges were not launched");
            assert!(
                state.registrations.is_empty(),
                "fused registrations were not finalized"
            );
            state.drained_host_slots
        } else {
            [None, None]
        }
    });
    FUSED_ASSIGNMENTS.with(|cache| {
        assert!(
            cache.borrow().is_empty(),
            "fused assignment cache not empty"
        )
    });
    recovered
}

pub(crate) fn prepare_fused_assignment<
    E: ExtensionField,
    I: Instruction<E, InsnType = InsnKind> + 'static,
>(
    config: &I::InstructionConfig,
    num_witin: usize,
    num_structural_witin: usize,
    expected_rows: usize,
    kind: GpuWitgenKind,
) -> Result<(), ZKVMError> {
    if !FUSED_INGRESS.with(|slot| slot.borrow().is_some()) {
        return Ok(());
    }
    if TypeId::of::<E::BaseField>() != TypeId::of::<Bb>() {
        return Err(ZKVMError::InvalidWitness(
            "typed fused ingress requires BabyBear".into(),
        ));
    }
    let kinds = I::inst_kinds();
    if kinds.len() != 1 {
        return Err(ZKVMError::InvalidWitness(
            format!(
                "{} owns {} instruction kinds in fused ingress",
                I::name(),
                kinds.len()
            )
            .into(),
        ));
    }
    let insn_kind = kinds[0];
    if FUSED_INGRESS.with(|slot| {
        slot.borrow().as_ref().is_some_and(|state| {
            state.provisional.is_some()
                && state
                    .registrations
                    .iter()
                    .any(|r| r.owner == TypeId::of::<I>())
        })
    }) {
        return Ok(());
    }
    let planned_rows = FUSED_INGRESS.with(|slot| {
        slot.borrow()
            .as_ref()
            .unwrap()
            .arenas
            .family_total(insn_kind)
    });
    if expected_rows != planned_rows {
        return Err(ZKVMError::InvalidWitness(
            format!(
                "{} typed rows {planned_rows} != expected rows {expected_rows}",
                I::name()
            )
            .into(),
        ));
    }
    if expected_rows == 0 {
        let raw_witin =
            RowMajorMatrix::<E::BaseField>::new(0, num_witin.max(1), I::padding_strategy());
        let raw_structural = RowMajorMatrix::<E::BaseField>::new(
            0,
            num_structural_witin.max(1),
            I::padding_strategy(),
        );
        FUSED_ASSIGNMENTS.with(|cache| {
            cache.borrow_mut().insert(
                TypeId::of::<I>(),
                Box::new(([raw_witin, raw_structural], Multiplicity::<u64>::default())),
            );
        });
        return Ok(());
    }

    macro_rules! map_config {
        ($ty:ty, $extract:path) => {{
            let typed = unsafe { &*(config as *const I::InstructionConfig as *const $ty) };
            let map = $extract(typed, num_witin);
            let num_cols = map.num_cols as usize;
            let flat = map.to_flat();
            let entries = flat.len();
            (
                flat.into_iter().collect::<Vec<u32>>(),
                num_cols,
                entries,
                None,
            )
        }};
        ($ty:ty, $extract:path, mem) => {{
            let typed = unsafe { &*(config as *const I::InstructionConfig as *const $ty) };
            let mem = typed.memory_addr.max_bits as u32;
            let map = $extract(typed, num_witin);
            let num_cols = map.num_cols as usize;
            let flat = map.to_flat();
            let entries = flat.len();
            (
                flat.into_iter().collect::<Vec<u32>>(),
                num_cols,
                entries,
                Some(mem),
            )
        }};
    }

    let (cols, map_num_cols, num_col_entries, mem_max_bits) = match kind {
        GpuWitgenKind::Add => map_config!(
            crate::instructions::riscv::arith::ArithConfig<E>,
            super::chips::add::extract_add_column_map
        ),
        GpuWitgenKind::Sub => map_config!(
            crate::instructions::riscv::arith::ArithConfig<E>,
            super::chips::sub::extract_sub_column_map
        ),
        GpuWitgenKind::LogicR(_) => map_config!(
            crate::instructions::riscv::logic::logic_circuit::LogicConfig<E>,
            super::chips::logic_r::extract_logic_r_column_map
        ),
        GpuWitgenKind::LogicI(_) => map_config!(
            crate::instructions::riscv::logic_imm::logic_imm_circuit_v2::LogicConfig<E>,
            super::chips::logic_i::extract_logic_i_column_map
        ),
        GpuWitgenKind::Addi => map_config!(
            crate::instructions::riscv::arith_imm::arith_imm_circuit_v2::InstructionConfig<E>,
            super::chips::addi::extract_addi_column_map
        ),
        GpuWitgenKind::Lui => map_config!(
            crate::instructions::riscv::lui::LuiConfig<E>,
            super::chips::lui::extract_lui_column_map
        ),
        GpuWitgenKind::Auipc => map_config!(
            crate::instructions::riscv::auipc::AuipcConfig<E>,
            super::chips::auipc::extract_auipc_column_map
        ),
        GpuWitgenKind::Jal => map_config!(
            crate::instructions::riscv::jump::jal_v2::JalConfig<E>,
            super::chips::jal::extract_jal_column_map
        ),
        GpuWitgenKind::ShiftR(_) => map_config!(
            crate::instructions::riscv::shift::shift_circuit_v2::ShiftRTypeConfig<E>,
            super::chips::shift_r::extract_shift_r_column_map
        ),
        GpuWitgenKind::ShiftI(_) => map_config!(
            crate::instructions::riscv::shift::shift_circuit_v2::ShiftImmConfig<E>,
            super::chips::shift_i::extract_shift_i_column_map
        ),
        GpuWitgenKind::Slt(_) => map_config!(
            crate::instructions::riscv::slt::slt_circuit_v2::SetLessThanConfig<E>,
            super::chips::slt::extract_slt_column_map
        ),
        GpuWitgenKind::Slti(_) => map_config!(
            crate::instructions::riscv::slti::slti_circuit_v2::SetLessThanImmConfig<E>,
            super::chips::slti::extract_slti_column_map
        ),
        GpuWitgenKind::BranchEq(_) => map_config!(
            crate::instructions::riscv::branch::branch_circuit_v2::BranchConfig<E>,
            super::chips::branch_eq::extract_branch_eq_column_map
        ),
        GpuWitgenKind::BranchCmp(_) => map_config!(
            crate::instructions::riscv::branch::branch_circuit_v2::BranchConfig<E>,
            super::chips::branch_cmp::extract_branch_cmp_column_map
        ),
        GpuWitgenKind::Jalr => map_config!(
            crate::instructions::riscv::jump::jalr_v2::JalrConfig<E>,
            super::chips::jalr::extract_jalr_column_map
        ),
        GpuWitgenKind::Sw => {
            map_config!(crate::instructions::riscv::memory::store_v2::StoreConfig<E, 2>, super::chips::sw::extract_sw_column_map, mem)
        }
        GpuWitgenKind::Sh => {
            map_config!(crate::instructions::riscv::memory::store_v2::StoreConfig<E, 1>, super::chips::sh::extract_sh_column_map, mem)
        }
        GpuWitgenKind::Sb => {
            map_config!(crate::instructions::riscv::memory::store_v2::StoreConfig<E, 0>, super::chips::sb::extract_sb_column_map, mem)
        }
        GpuWitgenKind::LoadSub { .. } => map_config!(
            crate::instructions::riscv::memory::load_v2::LoadConfig<E>,
            super::chips::load_sub::extract_load_sub_column_map,
            mem
        ),
        GpuWitgenKind::Mul(_) => map_config!(
            crate::instructions::riscv::mulh::mulh_circuit_v2::MulhConfig<E>,
            super::chips::mul::extract_mul_column_map
        ),
        GpuWitgenKind::Div(_) => map_config!(
            crate::instructions::riscv::div::div_circuit_v2::DivRemConfig<E>,
            super::chips::div::extract_div_column_map
        ),
        GpuWitgenKind::Lw => map_config!(
            crate::instructions::riscv::memory::load_v2::LoadConfig<E>,
            super::chips::lw::extract_lw_column_map,
            mem
        ),
        GpuWitgenKind::Keccak | GpuWitgenKind::ShardRam => {
            return Err(ZKVMError::InvalidWitness(
                "sparse circuit entered fused ordinary registry".into(),
            ));
        }
    };
    if map_num_cols != num_witin {
        return Err(ZKVMError::InvalidWitness(
            format!(
                "{} configured {} columns, expected {num_witin}",
                I::name(),
                map_num_cols
            )
            .into(),
        ));
    }
    let hal = gkr_iop::gpu::get_cuda_hal().map_err(|e| {
        ZKVMError::InvalidWitness(format!("CUDA unavailable for fused registration: {e}").into())
    })?;
    let output = hal
        .witgen
        .alloc_elems_on_device(expected_rows * num_witin, true, None)
        .map_err(|e| ZKVMError::InvalidWitness(format!("fused output alloc: {e}").into()))?;
    let cols = hal
        .witgen
        .alloc_u32_from_host(&cols, None)
        .map_err(|e| ZKVMError::InvalidWitness(format!("fused columns upload: {e}").into()))?;
    let mut structural = RowMajorMatrix::<E::BaseField>::new(
        expected_rows,
        num_structural_witin.max(1),
        I::padding_strategy(),
    );
    for row in structural.iter_mut() {
        *row.last_mut().unwrap() = E::BaseField::ONE;
    }
    structural.padding_by_strategy();
    let finalize = Box::new(move |output: BufferImpl<'static, Bb>| {
        let witness = GpuWitnessResult {
            device_buffer: output,
            num_rows: expected_rows,
            num_cols: num_witin,
            layout: DeviceMatrixLayout::ColMajor,
        };
        let mut main =
            gpu_witness_to_rmm::<E>(witness, expected_rows, num_witin, I::padding_strategy())?;
        main.padding_by_strategy();
        Ok(Box::new(([main, structural], Multiplicity::<u64>::default())) as Box<dyn Any>)
    });
    let (tag, arg0, arg1) = kind.fused_abi();
    FUSED_INGRESS.with(|slot| {
        slot.borrow_mut()
            .as_mut()
            .unwrap()
            .registrations
            .push(FusedRegistration {
                owner: TypeId::of::<I>(),
                kind: insn_kind,
                tag,
                arg0,
                arg1,
                num_cols: num_witin,
                num_col_entries,
                mem_max_bits,
                rows: expected_rows,
                output: Some(output),
                cols,
                finalize: Some(finalize),
            });
    });
    Ok(())
}

pub(crate) fn launch_fused_assignments(shard_ctx: &ShardContext) -> Result<(), ZKVMError> {
    use ceno_gpu::common::witgen::{typed_ingress::FusedRangeLauncher, types::MAX_TS_BITS};
    if FUSED_INGRESS.with(|slot| {
        slot.borrow()
            .as_ref()
            .is_some_and(|state| state.provisional.is_some())
    }) {
        let result = finish_provisional_fused_session(shard_ctx);
        if result.is_err() {
            abort_fused_session();
        }
        return result;
    }
    let Some(mut state) = FUSED_INGRESS.with(|slot| slot.borrow_mut().take()) else {
        return Ok(());
    };
    if state.launched {
        return Err(ZKVMError::InvalidWitness(
            "fused ingress launched twice".into(),
        ));
    }
    let mut registration_for_kind = [usize::MAX; InsnKind::COUNT];
    for (index, registration) in state.registrations.iter().enumerate() {
        let slot = &mut registration_for_kind[registration.kind as usize];
        if *slot != usize::MAX {
            return Err(ZKVMError::InvalidWitness(
                format!("duplicate fused owner for {:?}", registration.kind).into(),
            ));
        }
        *slot = index;
    }
    for kind in <InsnKind as strum::IntoEnumIterator>::iter() {
        if state.arenas.family_total(kind) != 0
            && registration_for_kind[kind as usize] == usize::MAX
        {
            return Err(ZKVMError::InvalidWitness(
                format!("missing fused registration for {kind:?}").into(),
            ));
        }
    }
    let mem_max_bits = state
        .registrations
        .iter()
        .filter_map(|r| r.mem_max_bits)
        .next()
        .unwrap_or(32);
    if state
        .registrations
        .iter()
        .filter_map(|r| r.mem_max_bits)
        .any(|bits| bits != mem_max_bits)
    {
        return Err(ZKVMError::InvalidWitness(
            "inconsistent fused memory bounds".into(),
        ));
    }
    let hal = gkr_iop::gpu::get_cuda_hal().map_err(|e| {
        ZKVMError::InvalidWitness(format!("CUDA unavailable for fused launch: {e}").into())
    })?;
    let logical_steps = (shard_ctx.cur_shard_cycle_range.end
        - shard_ctx.cur_shard_cycle_range.start)
        / FullTracer::SUBCYCLES_PER_INSN as usize;
    ensure_compact_shard_metadata_cached(
        &hal,
        shard_ctx,
        logical_steps,
        state.fetch,
        state.reserved_addresses,
    )?;
    super::cache::set_reserved_address_capacity(state.reserved_addresses);
    let stage_capacity = state
        .arenas
        .ranges
        .iter()
        .map(|range| {
            range
                .typed
                .iter()
                .flatten()
                .try_fold(0usize, |sum, arena| {
                    let bytes = if arena.is_compact() {
                        arena.payload_bytes().len()
                    } else {
                        arena.fields().iter().try_fold(0usize, |sum, field| {
                            sum.checked_add(field.len().checked_mul(std::mem::size_of::<u32>())?)
                        })?
                    };
                    sum.checked_add(bytes)
                })
                .expect("installed fused payload capacity overflow")
        })
        .max()
        .ok_or_else(|| ZKVMError::InvalidWitness("installed fused shard has no ranges".into()))?;
    let work_capacity = state
        .arenas
        .ranges
        .iter()
        .map(|range| range.typed.iter().flatten().count())
        .max()
        .ok_or_else(|| ZKVMError::InvalidWitness("installed fused shard has no ranges".into()))?;
    let mut launcher = FusedRangeLauncher::new(hal.inner.clone(), stage_capacity, work_capacity)
        .map_err(|e| ZKVMError::InvalidWitness(format!("fused launcher init: {e}").into()))?;
    let mut producer_bases = [0usize; InsnKind::COUNT];
    super::cache::with_cached_shard_meta(|shard| -> Result<(), ZKVMError> {
        for range in &state.arenas.ranges {
            let mut sources = [&[][..]; InsnKind::COUNT * 13];
            let mut source_count = 0usize;
            let mut work = [FusedRangeWorkItem::default(); InsnKind::COUNT];
            let mut work_count = 0usize;
            let mut cursor = 0usize;
            for arena in range.typed.iter().flatten() {
                let registration =
                    &state.registrations[registration_for_kind[arena.kind() as usize]];
                let mut offsets = [0u32; 13];
                if arena.is_compact() {
                    offsets[0] = u32::try_from(cursor).map_err(|_| {
                        ZKVMError::InvalidWitness("compact offset exceeds u32".into())
                    })?;
                    let bytes = arena.payload_bytes();
                    sources[source_count] = bytes;
                    source_count += 1;
                    cursor = cursor.checked_add(bytes.len()).ok_or_else(|| {
                        ZKVMError::InvalidWitness("typed compact cursor overflow".into())
                    })?;
                } else {
                    for (field_index, field) in arena.fields().iter().enumerate() {
                        offsets[field_index] = u32::try_from(cursor).map_err(|_| {
                            ZKVMError::InvalidWitness("typed field offset exceeds u32".into())
                        })?;
                        let bytes = unsafe {
                            std::slice::from_raw_parts(
                                field.as_ptr().cast::<u8>(),
                                std::mem::size_of_val(field.as_ref()),
                            )
                        };
                        sources[source_count] = bytes;
                        source_count += 1;
                        cursor = cursor.checked_add(bytes.len()).ok_or_else(|| {
                            ZKVMError::InvalidWitness("typed field cursor overflow".into())
                        })?;
                    }
                }
                let producer_base = producer_bases[arena.kind() as usize];
                producer_bases[arena.kind() as usize] += arena.len();
                work[work_count] = FusedRangeWorkItem {
                    tag: registration.tag,
                    layout: arena.layout() as u32,
                    row_count: u32::try_from(arena.len()).expect("typed row count exceeds u32"),
                    producer_base: u32::try_from(producer_base).expect("producer base exceeds u32"),
                    producer_total: packed_producer_total(arena.kind(), registration.rows),
                    num_cols: u32::try_from(registration.num_cols)
                        .expect("column count exceeds u32"),
                    arg0: registration.arg0,
                    arg1: registration.arg1,
                    num_col_entries: u32::try_from(registration.num_col_entries)
                        .expect("column map exceeds u32"),
                    input_fields: offsets,
                    compact_stride: if arena.is_compact() {
                        u32::try_from(arena.layout().compact_bytes()).unwrap()
                    } else {
                        0
                    },
                    range_start: arena.range_start(),
                    pc_base: arena.pc_base(),
                    compact_opcode: arena.compact_opcode(),
                    output_ptr: registration.output.as_ref().unwrap().device_ptr() as u64,
                    cols_ptr: registration.cols.device_ptr() as u64,
                };
                work_count += 1;
            }
            if cursor == 0 || work_count == 0 {
                return Err(ZKVMError::InvalidWitness(
                    "typed direct-source descriptor closure mismatch".into(),
                ));
            }
            launcher
                .launch_direct(
                    &sources[..source_count],
                    &work[..work_count],
                    shard_ctx.current_shard_offset_cycle(),
                    MAX_TS_BITS,
                    mem_max_bits,
                    shard,
                )
                .map_err(|e| {
                    ZKVMError::InvalidWitness(format!("fused range launch: {e}").into())
                })?;
        }
        Ok(())
    })?;
    let launch_count = launcher
        .finish()
        .map_err(|e| ZKVMError::InvalidWitness(format!("fused range drain: {e}").into()))?;
    if launch_count as usize != state.arenas.ranges.len() {
        return Err(ZKVMError::InvalidWitness(
            "fused descriptor/launch mismatch".into(),
        ));
    }
    tracing::info!(
        shard_id = shard_ctx.shard_id,
        descriptors = state.arenas.ranges.len(),
        launches = launch_count,
        "fused ordinary range schedule complete"
    );
    tracing::info!(
        tracer = "GpuReplayTracer",
        native_mode = "GPU_REPLAY_DIRECT",
        descriptors = state.arenas.ranges.len(),
        launches = launch_count,
        ordinary_callbacks = 0u64,
        fallback_categories = "ecall,exceptional",
        "GPU_REPLAY_DIRECT runtime marker"
    );
    for registration in &state.registrations {
        if producer_bases[registration.kind as usize] != registration.rows {
            return Err(ZKVMError::InvalidWitness(
                format!("{:?} producer coverage mismatch", registration.kind).into(),
            ));
        }
    }
    let mut owners = std::collections::HashSet::with_capacity(state.registrations.len());
    if state
        .registrations
        .iter()
        .any(|registration| !owners.insert(registration.owner))
    {
        return Err(ZKVMError::InvalidWitness(
            "duplicate fused assignment cache owner".into(),
        ));
    }
    if let Err(error) = validate_fused_assignment_cache_disjoint(&owners) {
        abort_fused_session();
        return Err(error);
    }
    let mut finalized_assignments = Vec::with_capacity(state.registrations.len());
    for mut registration in state.registrations.drain(..) {
        let output = registration.output.take().unwrap();
        let finalized = match registration.finalize.take().unwrap()(output) {
            Ok(finalized) => finalized,
            Err(error) => {
                abort_fused_session();
                return Err(error);
            }
        };
        finalized_assignments.push((registration.owner, finalized));
    }
    if let Err(error) = publish_fused_assignments(finalized_assignments) {
        abort_fused_session();
        return Err(error);
    }
    state.launched = true;
    FUSED_INGRESS.with(|slot| *slot.borrow_mut() = Some(state));
    Ok(())
}

/// Force the current thread to use CPU path for all GPU witgen calls.
/// Used by debug comparison code in e2e.rs to run a CPU-only reference.
pub fn set_force_cpu_path(force: bool) {
    FORCE_CPU_PATH.with(|f| f.set(force));
}

pub(crate) fn is_force_cpu_path() -> bool {
    FORCE_CPU_PATH.with(|f| f.get())
}

pub(crate) fn is_fused_ingress_active() -> bool {
    FUSED_INGRESS.with(|slot| slot.borrow().is_some())
}

/// Try to run GPU witness generation for the given instruction.
/// Returns `Ok(Some(...))` if GPU was used, `Ok(None)` if GPU is unavailable (caller should fallback to CPU).
///
/// # Safety invariant
///
/// The caller **must** ensure that `I::InstructionConfig` matches `kind`:
/// - `GpuWitgenKind::Add` requires `I` to be `ArithInstruction` (config = `ArithConfig<E>`)
/// - `GpuWitgenKind::Lw`  requires `I` to be `LoadInstruction`  (config = `LoadConfig<E>`)
///
/// Violating this will cause undefined behavior via pointer cast in [`gpu_fill_witness`].
pub(crate) fn try_gpu_assign_instances<
    E: ExtensionField,
    I: Instruction<E, InsnType = ceno_emul::InsnKind> + 'static,
>(
    config: &I::InstructionConfig,
    shard_ctx: &mut ShardContext,
    num_witin: usize,
    num_structural_witin: usize,
    shard_steps: &[StepRecord],
    step_indices: &[StepIndex],
    kind: GpuWitgenKind,
) -> Result<Option<(RMMCollections<E::BaseField>, Multiplicity<u64>)>, ZKVMError> {
    use gkr_iop::gpu::get_cuda_hal;

    if !gpu_witgen_enabled() || is_force_cpu_path() {
        return Ok(None);
    }

    if !I::GPU_LK_SHARDRAM {
        return Ok(None);
    }

    if is_kind_disabled(kind) {
        return Ok(None);
    }

    if FUSED_INGRESS.with(|slot| slot.borrow().is_some()) {
        return FUSED_ASSIGNMENTS.with(|cache| {
            let cached = cache
                .borrow_mut()
                .remove(&TypeId::of::<I>())
                .unwrap_or_else(|| panic!("missing fused assignment for {}", I::name()));
            let assignment = cached
                .downcast::<(RMMCollections<E::BaseField>, Multiplicity<u64>)>()
                .unwrap_or_else(|_| panic!("fused assignment type mismatch for {}", I::name()));
            Ok(Some(*assignment))
        });
    }
    let total_instances = step_indices.len();
    if total_instances == 0 {
        // Empty: just return empty matrices
        let num_witin = num_witin.max(1);
        let num_structural_witin = num_structural_witin.max(1);
        let raw_witin = RowMajorMatrix::<E::BaseField>::new(0, num_witin, I::padding_strategy());
        let raw_structural =
            RowMajorMatrix::<E::BaseField>::new(0, num_structural_witin, I::padding_strategy());
        let lk = LkMultiplicity::default();
        return Ok(Some((
            [raw_witin, raw_structural],
            lk.into_finalize_result(),
        )));
    }

    // GPU only supports BabyBear field
    if std::any::TypeId::of::<E::BaseField>()
        != std::any::TypeId::of::<<ff_ext::BabyBearExt4 as ExtensionField>::BaseField>()
    {
        return Ok(None);
    }

    let hal = match get_cuda_hal() {
        Ok(hal) => hal,
        Err(_) => return Ok(None), // GPU not available, fallback to CPU
    };

    tracing::debug!("[GPU witgen] {:?} with {} instances", kind, total_instances);
    info_span!("gpu_witgen", kind = ?kind, n = total_instances).in_scope(|| {
        gpu_assign_instances_inner::<E, I>(
            config,
            shard_ctx,
            num_witin,
            num_structural_witin,
            shard_steps,
            step_indices,
            kind,
            &hal,
        )
        .map(Some)
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum GpuFillMode {
    AssignWithSideEffects,
}

impl GpuFillMode {
    fn from_optional_ctx(
        shard_ctx: Option<&ShardContext>,
        shard_steps: Option<&[StepRecord]>,
    ) -> Self {
        match (shard_ctx, shard_steps) {
            (Some(_), Some(_)) => Self::AssignWithSideEffects,
            (Some(_), None) | (None, Some(_)) => {
                panic!("gpu_fill_witness requires shard_ctx and shard_steps to be both present");
            }
            (None, None) => panic!("gpu_fill_witness requires shard context"),
        }
    }

    fn binds_shard_side_effects(self) -> bool {
        matches!(self, Self::AssignWithSideEffects)
    }
}

fn gpu_assign_instances_inner<E: ExtensionField, I: Instruction<E>>(
    config: &I::InstructionConfig,
    shard_ctx: &mut ShardContext,
    num_witin: usize,
    num_structural_witin: usize,
    shard_steps: &[StepRecord],
    step_indices: &[StepIndex],
    kind: GpuWitgenKind,
    hal: &CudaHalBB31,
) -> Result<(RMMCollections<E::BaseField>, Multiplicity<u64>), ZKVMError> {
    let num_structural_witin = num_structural_witin.max(1);
    let total_instances = step_indices.len();
    let materialize_initial_witness = should_materialize_witness_on_gpu()
        || crate::instructions::gpu::config::is_debug_compare_enabled();

    // Step 1: GPU fills witness matrix (+ LK counters + shard records for merged kinds)
    let (
        gpu_witness,
        gpu_lk_counters,
        shard_lk_accumulated,
        gpu_ram_slots,
        gpu_compact_ec,
        gpu_compact_addr,
    ) = info_span!("gpu_kernel").in_scope(|| {
        let fetch_params = compute_fetch_params(shard_steps, step_indices);
        gpu_fill_witness::<E, I>(
            hal,
            config,
            Some(shard_ctx),
            num_witin,
            Some(shard_steps),
            step_indices,
            None,
            kind,
            shard_ctx.current_shard_offset_cycle(),
            fetch_params,
        )
    })?;

    // Step 2: Collect lk and shardram
    // Priority: GPU shard records > CPU shard records > full CPU lk and shardram
    //
    // Keccak never enters this function (it has `gpu_assign_keccak_inner`).
    // Guard defensively in case the enum value is ever passed here by mistake.
    let is_standard_kind = !matches!(kind, GpuWitgenKind::Keccak | GpuWitgenKind::ShardRam);

    let lk_multiplicity = if gpu_lk_counters.is_some() && is_standard_kind {
        let lk_multiplicity = if shard_lk_accumulated {
            Multiplicity::default()
        } else {
            info_span!("gpu_lk_d2h")
                .in_scope(|| gpu_lk_counters_to_multiplicity(gpu_lk_counters.unwrap()))?
        };

        if gpu_compact_ec.is_none() && gpu_compact_addr.is_none() && is_standard_kind {
            // Shared buffer path: EC records + addr_accessed accumulated on device
            // in shared buffers across all kernel invocations. Skip per-kernel D2H.
            // Data will be consumed in batch by assign_shared_circuit.
        } else if gpu_compact_ec.is_some() && is_standard_kind {
            // GPU EC path: compact records already have EC points computed on device.
            // D2H only the active records (much smaller than full N*3 slot buffer).
            info_span!("gpu_ec_shard").in_scope(|| {
                let compact = gpu_compact_ec.unwrap();
                let compact_records =
                    info_span!("compact_d2h").in_scope(|| gpu_compact_ec_d2h(&compact))?;

                // D2H ram_slots lazily (only for debug or fallback).
                // Avoid the 68 MB D2H in the common case.
                let ram_slots_d2h = || -> Result<Vec<GpuRamRecordSlot>, ZKVMError> {
                    if let Some(ref ram_buf) = gpu_ram_slots {
                        let sv: Vec<u32> = ram_buf.to_vec().map_err(|e| {
                            ZKVMError::InvalidWitness(format!("ram_slots D2H failed: {e}").into())
                        })?;
                        Ok(unsafe {
                            let ptr = sv.as_ptr() as *const GpuRamRecordSlot;
                            let len = sv.len() * 4 / std::mem::size_of::<GpuRamRecordSlot>();
                            std::slice::from_raw_parts(ptr, len).to_vec()
                        })
                    } else {
                        Ok(vec![])
                    }
                };

                // D2H compact addr_accessed (GPU-side compaction via atomicAdd).
                // Much smaller than full ram_slots D2H (4 bytes/addr vs 48 bytes/slot).
                info_span!("compact_addr_d2h").in_scope(|| -> Result<(), ZKVMError> {
                    if let Some(ref ca) = gpu_compact_addr {
                        let count_vec: Vec<u32> = ca.count_buf.to_vec().map_err(|e| {
                            ZKVMError::InvalidWitness(
                                format!("compact_addr_count D2H failed: {e}").into(),
                            )
                        })?;
                        let n = count_vec[0] as usize;
                        if n > 0 {
                            let addrs: Vec<u32> = ca.buffer.to_vec_n(n).map_err(|e| {
                                ZKVMError::InvalidWitness(
                                    format!("compact_addr D2H failed: {e}").into(),
                                )
                            })?;
                            let mut forked = shard_ctx.get_forked();
                            let thread_ctx = &mut forked[0];
                            for &addr in &addrs {
                                thread_ctx.push_addr_accessed(WordAddr(addr));
                            }
                        }
                    } else {
                        // Fallback: D2H full ram_slots for addr_accessed
                        let slots = ram_slots_d2h()?;
                        let mut forked = shard_ctx.get_forked();
                        let thread_ctx = &mut forked[0];
                        for slot in &slots {
                            if slot.flags & (1 << 4) != 0 {
                                thread_ctx.push_addr_accessed(WordAddr(slot.addr));
                            }
                        }
                    }
                    Ok(())
                })?;

                // Debug: compare GPU shard_ctx vs CPU shard_ctx independently
                if crate::instructions::gpu::config::is_debug_compare_enabled() {
                    let slots = ram_slots_d2h()?;
                    debug_compare_shard_ec::<E, I>(
                        &compact_records,
                        &slots,
                        config,
                        shard_ctx,
                        shard_steps,
                        step_indices,
                        kind,
                    );
                }

                // Accumulate compact shard records for assign_shared_circuit
                let raw_bytes = unsafe {
                    std::slice::from_raw_parts(
                        compact_records.as_ptr() as *const u8,
                        compact_records.len() * std::mem::size_of::<GpuShardRamRecord>(),
                    )
                };
                super::cache::append_compact_shard_records(raw_bytes);

                Ok::<(), ZKVMError>(())
            })?;
        } else if gpu_ram_slots.is_some() && is_standard_kind {
            // GPU shard records path (no EC): D2H + lightweight CPU scan
            info_span!("gpu_shard_records").in_scope(|| {
                let ram_buf = gpu_ram_slots.unwrap();
                let slot_bytes: Vec<u32> = ram_buf.to_vec().map_err(|e| {
                    ZKVMError::InvalidWitness(format!("ram_slots D2H failed: {e}").into())
                })?;
                let slots: &[GpuRamRecordSlot] = unsafe {
                    std::slice::from_raw_parts(
                        slot_bytes.as_ptr() as *const GpuRamRecordSlot,
                        slot_bytes.len() * 4 / std::mem::size_of::<GpuRamRecordSlot>(),
                    )
                };
                let mut forked = shard_ctx.get_forked();
                let thread_ctx = &mut forked[0];
                gpu_collect_shard_records(thread_ctx, slots);
                Ok::<(), ZKVMError>(())
            })?;
        } else {
            // CPU: collect shard records only (send/addr_accessed).
            info_span!("cpu_shard_records").in_scope(|| {
                let _ = cpu_collect_shardram::<E, I>(config, shard_ctx, shard_steps, step_indices)?;
                Ok::<(), ZKVMError>(())
            })?;
        }
        lk_multiplicity
    } else {
        // GPU LK counters missing or unverified — fall back to full CPU lk and shardram
        info_span!("cpu_lk_shardram").in_scope(|| {
            cpu_collect_lk_and_shardram::<E, I>(config, shard_ctx, shard_steps, step_indices)
        })?
    };
    debug_compare_final_lk::<E, I>(
        config,
        shard_ctx,
        num_witin,
        num_structural_witin,
        shard_steps,
        step_indices,
        kind,
        &lk_multiplicity,
    )?;
    debug_compare_shardram::<E, I>(config, shard_ctx, shard_steps, step_indices, kind)?;

    // Step 3: Build structural witness (just selector = ONE)
    let mut raw_structural = RowMajorMatrix::<E::BaseField>::new(
        total_instances,
        num_structural_witin,
        I::padding_strategy(),
    );
    for row in raw_structural.iter_mut() {
        *row.last_mut().unwrap() = E::BaseField::ONE;
    }
    raw_structural.padding_by_strategy();

    // Step 4: Keep witness on device only when cache policy keeps device backing.
    // In debug mode or cache-none mode, do transpose + D2H to build host-backed RMM.
    let mut raw_witin = if !materialize_initial_witness {
        RowMajorMatrix::<E::BaseField>::empty()
    } else if crate::instructions::gpu::config::is_debug_compare_enabled()
        || !should_materialize_witness_on_gpu()
    {
        info_span!("transpose_d2h", rows = total_instances, cols = num_witin).in_scope(|| {
            gpu_witness_to_rmm_d2h::<E>(
                hal,
                gpu_witness,
                total_instances,
                num_witin,
                I::padding_strategy(),
            )
        })?
    } else {
        gpu_witness_to_rmm::<E>(
            gpu_witness,
            total_instances,
            num_witin,
            I::padding_strategy(),
        )?
    };
    if materialize_initial_witness {
        raw_witin.padding_by_strategy();
        debug_compare_witness::<E, I>(
            config,
            shard_ctx,
            num_witin,
            num_structural_witin,
            shard_steps,
            step_indices,
            kind,
            &raw_witin,
        )?;
    }

    Ok(([raw_witin, raw_structural], lk_multiplicity))
}

// Type aliases and D2H conversion functions live in super::utils::d2h.

/// Compute fetch counter parameters from step data.
pub(crate) fn compute_fetch_params(
    shard_steps: &[StepRecord],
    step_indices: &[StepIndex],
) -> (u32, usize) {
    let mut min_pc = u32::MAX;
    let mut max_pc = 0u32;
    for &idx in step_indices {
        let pc = shard_steps[idx].pc().before.0;
        min_pc = min_pc.min(pc);
        max_pc = max_pc.max(pc);
    }
    if min_pc > max_pc {
        return (0, 0);
    }
    let fetch_base_pc = min_pc;
    let fetch_num_slots = ((max_pc - min_pc) / 4 + 1) as usize;
    (fetch_base_pc, fetch_num_slots)
}

/// GPU kernel dispatch based on instruction kind.
/// All kinds return witness + LK counters (merged into single GPU kernel).
fn gpu_fill_witness<E: ExtensionField, I: Instruction<E>>(
    hal: &CudaHalBB31,
    config: &I::InstructionConfig,
    shard_ctx: Option<&ShardContext>,
    num_witin: usize,
    shard_steps: Option<&[StepRecord]>,
    step_indices: &[StepIndex],
    cached_step_indices: Option<&BufferImpl<'static, u32>>,
    kind: GpuWitgenKind,
    shard_offset: u64,
    fetch_params: (u32, usize),
) -> Result<
    (
        WitResult,
        Option<LkResult>,
        bool,
        Option<RamBuf>,
        Option<CompactEcBuf>,
        Option<CompactEcBuf>,
    ),
    ZKVMError,
> {
    let fill_mode = GpuFillMode::from_optional_ctx(shard_ctx, shard_steps);
    if let (Some(shard_ctx), Some(shard_steps)) = (shard_ctx, shard_steps) {
        // Ensure shard-scoped GPU raw data is ready for this kernel dispatch.
        let _session = info_span!("begin_shard_session")
            .in_scope(|| begin_gpu_shard_session(hal, shard_ctx, shard_steps))?;
    }

    // Convert step_indices from usize to u32 for GPU.
    let indices_u32: Vec<u32> = if cached_step_indices.is_none() {
        info_span!("indices_u32", n = step_indices.len())
            .in_scope(|| step_indices.iter().map(|&i| i as u32).collect())
    } else {
        Vec::new()
    };

    // Helper to split GpuWitgenFullResult into witness, lookup ownership,
    // shard records, and compact outputs.
    macro_rules! split_full {
        ($result:expr) => {{
            let full = $result?;
            Ok((
                full.witness,
                Some(full.lk_counters),
                full.shard_lk_accumulated,
                full.ram_slots,
                full.compact_ec,
                full.compact_addr,
            ))
        }};
    }

    // Compute fetch params for all GPU kinds (LK counters are merged into all kernels)
    let (fetch_base_pc, fetch_num_slots) = fetch_params;

    match kind {
        GpuWitgenKind::Add => {
            let arith_config = unsafe {
                &*(config as *const I::InstructionConfig
                    as *const crate::instructions::riscv::arith::ArithConfig<E>)
            };
            let col_map = info_span!("col_map")
                .in_scope(|| super::chips::add::extract_add_column_map(arith_config, num_witin));
            info_span!("hal_witgen_add").in_scope(|| {
                with_cached_gpu_ctx_opt(
                    fill_mode.binds_shard_side_effects(),
                    |gpu_records, shard_bufs| {
                        split_full!(
                            hal.witgen
                                .witgen_add(
                                    &col_map,
                                    gpu_records,
                                    &indices_u32,
                                    step_indices.len(),
                                    cached_step_indices,
                                    shard_offset,
                                    fetch_base_pc,
                                    fetch_num_slots,
                                    false,
                                    None,
                                    shard_bufs,
                                )
                                .map_err(|e| {
                                    ZKVMError::InvalidWitness(
                                        format!("GPU witgen_add failed: {e:?}").into(),
                                    )
                                })
                        )
                    },
                )
            })
        }
        GpuWitgenKind::Sub => {
            let arith_config = unsafe {
                &*(config as *const I::InstructionConfig
                    as *const crate::instructions::riscv::arith::ArithConfig<E>)
            };
            let col_map = info_span!("col_map")
                .in_scope(|| super::chips::sub::extract_sub_column_map(arith_config, num_witin));
            info_span!("hal_witgen_sub").in_scope(|| {
                with_cached_gpu_ctx_opt(
                    fill_mode.binds_shard_side_effects(),
                    |gpu_records, shard_bufs| {
                        split_full!(
                            hal.witgen
                                .witgen_sub(
                                    &col_map,
                                    gpu_records,
                                    &indices_u32,
                                    step_indices.len(),
                                    cached_step_indices,
                                    shard_offset,
                                    fetch_base_pc,
                                    fetch_num_slots,
                                    false,
                                    None,
                                    shard_bufs,
                                )
                                .map_err(|e| {
                                    ZKVMError::InvalidWitness(
                                        format!("GPU witgen_sub failed: {e:?}").into(),
                                    )
                                })
                        )
                    },
                )
            })
        }
        GpuWitgenKind::LogicR(logic_kind) => {
            let logic_config = unsafe {
                &*(config as *const I::InstructionConfig
                    as *const crate::instructions::riscv::logic::logic_circuit::LogicConfig<E>)
            };
            let col_map = info_span!("col_map").in_scope(|| {
                super::chips::logic_r::extract_logic_r_column_map(logic_config, num_witin)
            });
            info_span!("hal_witgen_logic_r").in_scope(|| {
                with_cached_gpu_ctx_opt(
                    fill_mode.binds_shard_side_effects(),
                    |gpu_records, shard_bufs| {
                        split_full!(
                            hal.witgen
                                .witgen_logic_r(
                                    &col_map,
                                    gpu_records,
                                    &indices_u32,
                                    step_indices.len(),
                                    cached_step_indices,
                                    shard_offset,
                                    logic_kind,
                                    fetch_base_pc,
                                    fetch_num_slots,
                                    false,
                                    None,
                                    shard_bufs,
                                )
                                .map_err(|e| {
                                    ZKVMError::InvalidWitness(
                                        format!("GPU witgen_logic_r failed: {e:?}").into(),
                                    )
                                })
                        )
                    },
                )
            })
        }

        GpuWitgenKind::LogicI(logic_kind) => {
            let logic_config = unsafe {
                &*(config as *const I::InstructionConfig
                    as *const crate::instructions::riscv::logic_imm::logic_imm_circuit_v2::LogicConfig<E>)
            };
            let col_map = info_span!("col_map").in_scope(|| {
                super::chips::logic_i::extract_logic_i_column_map(logic_config, num_witin)
            });
            info_span!("hal_witgen_logic_i").in_scope(|| {
                with_cached_gpu_ctx_opt(
                    fill_mode.binds_shard_side_effects(),
                    |gpu_records, shard_bufs| {
                        split_full!(
                            hal.witgen
                                .witgen_logic_i(
                                    &col_map,
                                    gpu_records,
                                    &indices_u32,
                                    step_indices.len(),
                                    cached_step_indices,
                                    shard_offset,
                                    logic_kind,
                                    fetch_base_pc,
                                    fetch_num_slots,
                                    false,
                                    None,
                                    shard_bufs,
                                )
                                .map_err(|e| {
                                    ZKVMError::InvalidWitness(
                                        format!("GPU witgen_logic_i failed: {e:?}").into(),
                                    )
                                })
                        )
                    },
                )
            })
        }

        GpuWitgenKind::Addi => {
            let addi_config = unsafe {
                &*(config as *const I::InstructionConfig
                    as *const crate::instructions::riscv::arith_imm::arith_imm_circuit_v2::InstructionConfig<E>)
            };
            let col_map = info_span!("col_map")
                .in_scope(|| super::chips::addi::extract_addi_column_map(addi_config, num_witin));
            info_span!("hal_witgen_addi").in_scope(|| {
                with_cached_gpu_ctx_opt(
                    fill_mode.binds_shard_side_effects(),
                    |gpu_records, shard_bufs| {
                        split_full!(
                            hal.witgen
                                .witgen_addi(
                                    &col_map,
                                    gpu_records,
                                    &indices_u32,
                                    step_indices.len(),
                                    cached_step_indices,
                                    shard_offset,
                                    fetch_base_pc,
                                    fetch_num_slots,
                                    false,
                                    None,
                                    shard_bufs,
                                )
                                .map_err(|e| {
                                    ZKVMError::InvalidWitness(
                                        format!("GPU witgen_addi failed: {e:?}").into(),
                                    )
                                })
                        )
                    },
                )
            })
        }

        GpuWitgenKind::Lui => {
            let lui_config = unsafe {
                &*(config as *const I::InstructionConfig
                    as *const crate::instructions::riscv::lui::LuiConfig<E>)
            };
            let col_map = info_span!("col_map")
                .in_scope(|| super::chips::lui::extract_lui_column_map(lui_config, num_witin));
            info_span!("hal_witgen_lui").in_scope(|| {
                with_cached_gpu_ctx_opt(
                    fill_mode.binds_shard_side_effects(),
                    |gpu_records, shard_bufs| {
                        split_full!(
                            hal.witgen
                                .witgen_lui(
                                    &col_map,
                                    gpu_records,
                                    &indices_u32,
                                    step_indices.len(),
                                    cached_step_indices,
                                    shard_offset,
                                    fetch_base_pc,
                                    fetch_num_slots,
                                    false,
                                    None,
                                    shard_bufs,
                                )
                                .map_err(|e| {
                                    ZKVMError::InvalidWitness(
                                        format!("GPU witgen_lui failed: {e}").into(),
                                    )
                                })
                        )
                    },
                )
            })
        }

        GpuWitgenKind::Auipc => {
            let auipc_config = unsafe {
                &*(config as *const I::InstructionConfig
                    as *const crate::instructions::riscv::auipc::AuipcConfig<E>)
            };
            let col_map = info_span!("col_map").in_scope(|| {
                super::chips::auipc::extract_auipc_column_map(auipc_config, num_witin)
            });
            info_span!("hal_witgen_auipc").in_scope(|| {
                with_cached_gpu_ctx_opt(
                    fill_mode.binds_shard_side_effects(),
                    |gpu_records, shard_bufs| {
                        split_full!(
                            hal.witgen
                                .witgen_auipc(
                                    &col_map,
                                    gpu_records,
                                    &indices_u32,
                                    step_indices.len(),
                                    cached_step_indices,
                                    shard_offset,
                                    fetch_base_pc,
                                    fetch_num_slots,
                                    false,
                                    None,
                                    shard_bufs,
                                )
                                .map_err(|e| {
                                    ZKVMError::InvalidWitness(
                                        format!("GPU witgen_auipc failed: {e}").into(),
                                    )
                                })
                        )
                    },
                )
            })
        }

        GpuWitgenKind::Jal => {
            let jal_config = unsafe {
                &*(config as *const I::InstructionConfig
                    as *const crate::instructions::riscv::jump::jal_v2::JalConfig<E>)
            };
            let col_map = info_span!("col_map")
                .in_scope(|| super::chips::jal::extract_jal_column_map(jal_config, num_witin));
            info_span!("hal_witgen_jal").in_scope(|| {
                with_cached_gpu_ctx_opt(
                    fill_mode.binds_shard_side_effects(),
                    |gpu_records, shard_bufs| {
                        split_full!(
                            hal.witgen
                                .witgen_jal(
                                    &col_map,
                                    gpu_records,
                                    &indices_u32,
                                    step_indices.len(),
                                    cached_step_indices,
                                    shard_offset,
                                    fetch_base_pc,
                                    fetch_num_slots,
                                    false,
                                    None,
                                    shard_bufs,
                                )
                                .map_err(|e| {
                                    ZKVMError::InvalidWitness(
                                        format!("GPU witgen_jal failed: {e}").into(),
                                    )
                                })
                        )
                    },
                )
            })
        }

        GpuWitgenKind::ShiftR(shift_kind) => {
            let shift_config = unsafe {
                &*(config as *const I::InstructionConfig
                    as *const crate::instructions::riscv::shift::shift_circuit_v2::ShiftRTypeConfig<
                        E,
                    >)
            };
            let col_map = info_span!("col_map").in_scope(|| {
                super::chips::shift_r::extract_shift_r_column_map(shift_config, num_witin)
            });
            info_span!("hal_witgen_shift_r").in_scope(|| {
                with_cached_gpu_ctx_opt(
                    fill_mode.binds_shard_side_effects(),
                    |gpu_records, shard_bufs| {
                        split_full!(
                            hal.witgen
                                .witgen_shift_r(
                                    &col_map,
                                    gpu_records,
                                    &indices_u32,
                                    step_indices.len(),
                                    cached_step_indices,
                                    shard_offset,
                                    shift_kind,
                                    fetch_base_pc,
                                    fetch_num_slots,
                                    false,
                                    None,
                                    shard_bufs,
                                )
                                .map_err(|e| {
                                    ZKVMError::InvalidWitness(
                                        format!("GPU witgen_shift_r failed: {e}").into(),
                                    )
                                })
                        )
                    },
                )
            })
        }

        GpuWitgenKind::ShiftI(shift_kind) => {
            let shift_config = unsafe {
                &*(config as *const I::InstructionConfig
                    as *const crate::instructions::riscv::shift::shift_circuit_v2::ShiftImmConfig<
                        E,
                    >)
            };
            let col_map = info_span!("col_map").in_scope(|| {
                super::chips::shift_i::extract_shift_i_column_map(shift_config, num_witin)
            });
            info_span!("hal_witgen_shift_i").in_scope(|| {
                with_cached_gpu_ctx_opt(
                    fill_mode.binds_shard_side_effects(),
                    |gpu_records, shard_bufs| {
                        split_full!(
                            hal.witgen
                                .witgen_shift_i(
                                    &col_map,
                                    gpu_records,
                                    &indices_u32,
                                    step_indices.len(),
                                    cached_step_indices,
                                    shard_offset,
                                    shift_kind,
                                    fetch_base_pc,
                                    fetch_num_slots,
                                    false,
                                    None,
                                    shard_bufs,
                                )
                                .map_err(|e| {
                                    ZKVMError::InvalidWitness(
                                        format!("GPU witgen_shift_i failed: {e}").into(),
                                    )
                                })
                        )
                    },
                )
            })
        }

        GpuWitgenKind::Slt(is_signed) => {
            let slt_config = unsafe {
                &*(config as *const I::InstructionConfig
                    as *const crate::instructions::riscv::slt::slt_circuit_v2::SetLessThanConfig<E>)
            };
            let col_map = info_span!("col_map")
                .in_scope(|| super::chips::slt::extract_slt_column_map(slt_config, num_witin));
            info_span!("hal_witgen_slt").in_scope(|| {
                with_cached_gpu_ctx_opt(
                    fill_mode.binds_shard_side_effects(),
                    |gpu_records, shard_bufs| {
                        split_full!(
                            hal.witgen
                                .witgen_slt(
                                    &col_map,
                                    gpu_records,
                                    &indices_u32,
                                    step_indices.len(),
                                    cached_step_indices,
                                    shard_offset,
                                    is_signed,
                                    fetch_base_pc,
                                    fetch_num_slots,
                                    false,
                                    None,
                                    shard_bufs,
                                )
                                .map_err(|e| {
                                    ZKVMError::InvalidWitness(
                                        format!("GPU witgen_slt failed: {e}").into(),
                                    )
                                })
                        )
                    },
                )
            })
        }

        GpuWitgenKind::Slti(is_signed) => {
            let slti_config = unsafe {
                &*(config as *const I::InstructionConfig
                    as *const crate::instructions::riscv::slti::slti_circuit_v2::SetLessThanImmConfig<E>)
            };
            let col_map = info_span!("col_map")
                .in_scope(|| super::chips::slti::extract_slti_column_map(slti_config, num_witin));
            info_span!("hal_witgen_slti").in_scope(|| {
                with_cached_gpu_ctx_opt(
                    fill_mode.binds_shard_side_effects(),
                    |gpu_records, shard_bufs| {
                        split_full!(
                            hal.witgen
                                .witgen_slti(
                                    &col_map,
                                    gpu_records,
                                    &indices_u32,
                                    step_indices.len(),
                                    cached_step_indices,
                                    shard_offset,
                                    is_signed,
                                    fetch_base_pc,
                                    fetch_num_slots,
                                    false,
                                    None,
                                    shard_bufs,
                                )
                                .map_err(|e| {
                                    ZKVMError::InvalidWitness(
                                        format!("GPU witgen_slti failed: {e}").into(),
                                    )
                                })
                        )
                    },
                )
            })
        }

        GpuWitgenKind::BranchEq(is_beq) => {
            let branch_config = unsafe {
                &*(config as *const I::InstructionConfig
                    as *const crate::instructions::riscv::branch::branch_circuit_v2::BranchConfig<
                        E,
                    >)
            };
            let col_map = info_span!("col_map").in_scope(|| {
                super::chips::branch_eq::extract_branch_eq_column_map(branch_config, num_witin)
            });
            info_span!("hal_witgen_branch_eq").in_scope(|| {
                with_cached_gpu_ctx_opt(
                    fill_mode.binds_shard_side_effects(),
                    |gpu_records, shard_bufs| {
                        split_full!(
                            hal.witgen
                                .witgen_branch_eq(
                                    &col_map,
                                    gpu_records,
                                    &indices_u32,
                                    step_indices.len(),
                                    cached_step_indices,
                                    shard_offset,
                                    is_beq,
                                    fetch_base_pc,
                                    fetch_num_slots,
                                    false,
                                    None,
                                    shard_bufs,
                                )
                                .map_err(|e| {
                                    ZKVMError::InvalidWitness(
                                        format!("GPU witgen_branch_eq failed: {e}").into(),
                                    )
                                })
                        )
                    },
                )
            })
        }

        GpuWitgenKind::BranchCmp(is_signed) => {
            let branch_config = unsafe {
                &*(config as *const I::InstructionConfig
                    as *const crate::instructions::riscv::branch::branch_circuit_v2::BranchConfig<
                        E,
                    >)
            };
            let col_map = info_span!("col_map").in_scope(|| {
                super::chips::branch_cmp::extract_branch_cmp_column_map(branch_config, num_witin)
            });
            info_span!("hal_witgen_branch_cmp").in_scope(|| {
                with_cached_gpu_ctx_opt(
                    fill_mode.binds_shard_side_effects(),
                    |gpu_records, shard_bufs| {
                        split_full!(
                            hal.witgen
                                .witgen_branch_cmp(
                                    &col_map,
                                    gpu_records,
                                    &indices_u32,
                                    step_indices.len(),
                                    cached_step_indices,
                                    shard_offset,
                                    is_signed,
                                    fetch_base_pc,
                                    fetch_num_slots,
                                    false,
                                    None,
                                    shard_bufs,
                                )
                                .map_err(|e| {
                                    ZKVMError::InvalidWitness(
                                        format!("GPU witgen_branch_cmp failed: {e}").into(),
                                    )
                                })
                        )
                    },
                )
            })
        }

        GpuWitgenKind::Jalr => {
            let jalr_config = unsafe {
                &*(config as *const I::InstructionConfig
                    as *const crate::instructions::riscv::jump::jalr_v2::JalrConfig<E>)
            };
            let col_map = info_span!("col_map")
                .in_scope(|| super::chips::jalr::extract_jalr_column_map(jalr_config, num_witin));
            info_span!("hal_witgen_jalr").in_scope(|| {
                with_cached_gpu_ctx_opt(
                    fill_mode.binds_shard_side_effects(),
                    |gpu_records, shard_bufs| {
                        split_full!(
                            hal.witgen
                                .witgen_jalr(
                                    &col_map,
                                    gpu_records,
                                    &indices_u32,
                                    step_indices.len(),
                                    cached_step_indices,
                                    shard_offset,
                                    fetch_base_pc,
                                    fetch_num_slots,
                                    false,
                                    None,
                                    shard_bufs,
                                )
                                .map_err(|e| {
                                    ZKVMError::InvalidWitness(
                                        format!("GPU witgen_jalr failed: {e}").into(),
                                    )
                                })
                        )
                    },
                )
            })
        }

        GpuWitgenKind::Sw => {
            let sw_config = unsafe {
                &*(config as *const I::InstructionConfig
                    as *const crate::instructions::riscv::memory::store_v2::StoreConfig<E, 2>)
            };
            let mem_max_bits = sw_config.memory_addr.max_bits as u32;
            let col_map = info_span!("col_map")
                .in_scope(|| super::chips::sw::extract_sw_column_map(sw_config, num_witin));
            info_span!("hal_witgen_sw").in_scope(|| {
                with_cached_gpu_ctx_opt(
                    fill_mode.binds_shard_side_effects(),
                    |gpu_records, shard_bufs| {
                        split_full!(
                            hal.witgen
                                .witgen_sw(
                                    &col_map,
                                    gpu_records,
                                    &indices_u32,
                                    step_indices.len(),
                                    cached_step_indices,
                                    shard_offset,
                                    mem_max_bits,
                                    fetch_base_pc,
                                    fetch_num_slots,
                                    false,
                                    None,
                                    shard_bufs,
                                )
                                .map_err(|e| {
                                    ZKVMError::InvalidWitness(
                                        format!("GPU witgen_sw failed: {e}").into(),
                                    )
                                })
                        )
                    },
                )
            })
        }

        GpuWitgenKind::Sh => {
            let sh_config = unsafe {
                &*(config as *const I::InstructionConfig
                    as *const crate::instructions::riscv::memory::store_v2::StoreConfig<E, 1>)
            };
            let mem_max_bits = sh_config.memory_addr.max_bits as u32;
            let col_map = info_span!("col_map")
                .in_scope(|| super::chips::sh::extract_sh_column_map(sh_config, num_witin));
            info_span!("hal_witgen_sh").in_scope(|| {
                with_cached_gpu_ctx_opt(
                    fill_mode.binds_shard_side_effects(),
                    |gpu_records, shard_bufs| {
                        split_full!(
                            hal.witgen
                                .witgen_sh(
                                    &col_map,
                                    gpu_records,
                                    &indices_u32,
                                    step_indices.len(),
                                    cached_step_indices,
                                    shard_offset,
                                    mem_max_bits,
                                    fetch_base_pc,
                                    fetch_num_slots,
                                    false,
                                    None,
                                    shard_bufs,
                                )
                                .map_err(|e| {
                                    ZKVMError::InvalidWitness(
                                        format!("GPU witgen_sh failed: {e}").into(),
                                    )
                                })
                        )
                    },
                )
            })
        }

        GpuWitgenKind::Sb => {
            let sb_config = unsafe {
                &*(config as *const I::InstructionConfig
                    as *const crate::instructions::riscv::memory::store_v2::StoreConfig<E, 0>)
            };
            let mem_max_bits = sb_config.memory_addr.max_bits as u32;
            let col_map = info_span!("col_map")
                .in_scope(|| super::chips::sb::extract_sb_column_map(sb_config, num_witin));
            info_span!("hal_witgen_sb").in_scope(|| {
                with_cached_gpu_ctx_opt(
                    fill_mode.binds_shard_side_effects(),
                    |gpu_records, shard_bufs| {
                        split_full!(
                            hal.witgen
                                .witgen_sb(
                                    &col_map,
                                    gpu_records,
                                    &indices_u32,
                                    step_indices.len(),
                                    cached_step_indices,
                                    shard_offset,
                                    mem_max_bits,
                                    fetch_base_pc,
                                    fetch_num_slots,
                                    false,
                                    None,
                                    shard_bufs,
                                )
                                .map_err(|e| {
                                    ZKVMError::InvalidWitness(
                                        format!("GPU witgen_sb failed: {e}").into(),
                                    )
                                })
                        )
                    },
                )
            })
        }

        GpuWitgenKind::LoadSub {
            load_width,
            is_signed,
        } => {
            let load_config = unsafe {
                &*(config as *const I::InstructionConfig
                    as *const crate::instructions::riscv::memory::load_v2::LoadConfig<E>)
            };
            let col_map = info_span!("col_map").in_scope(|| {
                super::chips::load_sub::extract_load_sub_column_map(load_config, num_witin)
            });
            let mem_max_bits = load_config.memory_addr.max_bits as u32;
            info_span!("hal_witgen_load_sub").in_scope(|| {
                with_cached_gpu_ctx_opt(
                    fill_mode.binds_shard_side_effects(),
                    |gpu_records, shard_bufs| {
                        split_full!(
                            hal.witgen
                                .witgen_load_sub(
                                    &col_map,
                                    gpu_records,
                                    &indices_u32,
                                    step_indices.len(),
                                    cached_step_indices,
                                    shard_offset,
                                    load_width,
                                    is_signed,
                                    mem_max_bits,
                                    fetch_base_pc,
                                    fetch_num_slots,
                                    false,
                                    None,
                                    shard_bufs,
                                )
                                .map_err(|e| {
                                    ZKVMError::InvalidWitness(
                                        format!("GPU witgen_load_sub failed: {e}").into(),
                                    )
                                })
                        )
                    },
                )
            })
        }

        GpuWitgenKind::Mul(mul_kind) => {
            let mul_config = unsafe {
                &*(config as *const I::InstructionConfig
                    as *const crate::instructions::riscv::mulh::mulh_circuit_v2::MulhConfig<E>)
            };
            let col_map = info_span!("col_map")
                .in_scope(|| super::chips::mul::extract_mul_column_map(mul_config, num_witin));
            info_span!("hal_witgen_mul").in_scope(|| {
                with_cached_gpu_ctx_opt(
                    fill_mode.binds_shard_side_effects(),
                    |gpu_records, shard_bufs| {
                        split_full!(
                            hal.witgen
                                .witgen_mul(
                                    &col_map,
                                    gpu_records,
                                    &indices_u32,
                                    step_indices.len(),
                                    cached_step_indices,
                                    shard_offset,
                                    mul_kind,
                                    fetch_base_pc,
                                    fetch_num_slots,
                                    false,
                                    None,
                                    shard_bufs,
                                )
                                .map_err(|e| {
                                    ZKVMError::InvalidWitness(
                                        format!("GPU witgen_mul failed: {e}").into(),
                                    )
                                })
                        )
                    },
                )
            })
        }

        GpuWitgenKind::Div(div_kind) => {
            let div_config = unsafe {
                &*(config as *const I::InstructionConfig
                    as *const crate::instructions::riscv::div::div_circuit_v2::DivRemConfig<E>)
            };
            let col_map = info_span!("col_map")
                .in_scope(|| super::chips::div::extract_div_column_map(div_config, num_witin));
            info_span!("hal_witgen_div").in_scope(|| {
                with_cached_gpu_ctx_opt(
                    fill_mode.binds_shard_side_effects(),
                    |gpu_records, shard_bufs| {
                        split_full!(
                            hal.witgen
                                .witgen_div(
                                    &col_map,
                                    gpu_records,
                                    &indices_u32,
                                    step_indices.len(),
                                    cached_step_indices,
                                    shard_offset,
                                    div_kind,
                                    fetch_base_pc,
                                    fetch_num_slots,
                                    false,
                                    None,
                                    shard_bufs,
                                )
                                .map_err(|e| {
                                    ZKVMError::InvalidWitness(
                                        format!("GPU witgen_div failed: {e}").into(),
                                    )
                                })
                        )
                    },
                )
            })
        }
        GpuWitgenKind::Lw => {
            let load_config = unsafe {
                &*(config as *const I::InstructionConfig
                    as *const crate::instructions::riscv::memory::load_v2::LoadConfig<E>)
            };
            #[cfg(not(feature = "u16limb_circuit"))]
            let load_config = unsafe {
                &*(config as *const I::InstructionConfig
                    as *const crate::instructions::riscv::memory::load::LoadConfig<E>)
            };
            let mem_max_bits = load_config.memory_addr.max_bits as u32;
            let col_map = info_span!("col_map")
                .in_scope(|| super::chips::lw::extract_lw_column_map(load_config, num_witin));
            info_span!("hal_witgen_lw").in_scope(|| {
                with_cached_gpu_ctx_opt(
                    fill_mode.binds_shard_side_effects(),
                    |gpu_records, shard_bufs| {
                        split_full!(
                            hal.witgen
                                .witgen_lw(
                                    &col_map,
                                    gpu_records,
                                    &indices_u32,
                                    step_indices.len(),
                                    cached_step_indices,
                                    shard_offset,
                                    mem_max_bits,
                                    fetch_base_pc,
                                    fetch_num_slots,
                                    false,
                                    None,
                                    shard_bufs,
                                )
                                .map_err(|e| {
                                    ZKVMError::InvalidWitness(
                                        format!("GPU witgen_lw failed: {e}").into(),
                                    )
                                })
                        )
                    },
                )
            })
        }
        GpuWitgenKind::Keccak => {
            unreachable!("keccak uses gpu_assign_keccak_instances, not try_gpu_assign_instances")
        }
        GpuWitgenKind::ShardRam => {
            unreachable!("shard ram uses its own replay path, not try_gpu_assign_instances")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_typed() -> Vec<Option<GpuTypedSoaArena>> {
        (0..InsnKind::COUNT).map(|_| None).collect()
    }

    #[test]
    fn packed_producer_total_preserves_count_and_kind_priority() {
        let add = packed_producer_total(InsnKind::ADD, 123);
        let sub = packed_producer_total(InsnKind::SUB, 123);
        assert_eq!(add & 0x00ff_ffff, 123);
        assert_eq!(sub & 0x00ff_ffff, 123);
        assert_eq!(add >> PACKED_PRODUCER_COUNT_BITS, InsnKind::ADD as u32);
        assert_eq!(sub >> PACKED_PRODUCER_COUNT_BITS, InsnKind::SUB as u32);
        assert_ne!(add, sub);
    }

    #[test]
    fn lw_fused_abi_preserves_the_u16_imm_sign_column() {
        let (_, has_imm_sign, _) = GpuWitgenKind::Lw.fused_abi();
        assert_eq!(has_imm_sign, u32::from(cfg!(feature = "u16limb_circuit")));
    }

    #[test]
    fn cpu_dispatch_reserves_typed_plus_conservative_sparse_capacity_once() {
        FUSED_INGRESS.with(|slot| assert!(slot.borrow().is_none()));
        let mut add = GpuTypedSoaArena::new(InsnKind::ADD, 1).unwrap();
        add.push_step(0, &StepRecord::default()).unwrap();
        let mut typed = empty_typed();
        typed[InsnKind::ADD as usize] = Some(add);
        let arenas = GpuReplayShardArenas::from_ranges(vec![GpuReplayTypedRange {
            sequence: 0,
            typed,
            fallback: vec![ceno_emul::GpuReplayFallbackRecord {
                ordinal: 1,
                record: StepRecord::new_ecall_any(4, ceno_emul::ByteAddr(0x1000)),
            }],
        }]);
        assert_eq!(arenas.family_total(InsnKind::ADD), 1);
        assert_eq!(arenas.fallback.len(), 1);

        install_compact_replay_arenas(arenas);
        FUSED_INGRESS.with(|slot| {
            let state = slot.borrow();
            let state = state.as_ref().unwrap();
            assert_eq!(
                state.reserved_addresses,
                3 + ceno_emul::MAX_SPARSE_ADDRESS_SENDS_PER_STEP
            );
            assert_eq!(state.arenas.family_total(InsnKind::ADD), 1);
        });
        FUSED_INGRESS.with(|slot| {
            slot.borrow_mut().take();
        });
    }

    #[test]
    fn submit_error_clears_fused_thread_local_state() {
        abort_fused_session();
        install_compact_replay_arenas(GpuReplayShardArenas::provisional([0; InsnKind::COUNT]));
        FUSED_ASSIGNMENTS.with(|cache| {
            cache.borrow_mut().insert(TypeId::of::<u8>(), Box::new(7u8));
        });

        let error = submit_provisional_fused_range(GpuReplayTypedRange {
            sequence: 0,
            typed: empty_typed(),
            fallback: Vec::new(),
        })
        .unwrap_err();
        assert!(format!("{error:?}").contains("non-provisional session"));
        FUSED_INGRESS.with(|slot| assert!(slot.borrow().is_none()));
        FUSED_ASSIGNMENTS.with(|cache| assert!(cache.borrow().is_empty()));
    }

    #[test]
    fn zero_row_and_nonzero_assignment_owners_merge_and_drain() {
        abort_fused_session();
        let zero_row_owner = TypeId::of::<u8>();
        let nonzero_owner = TypeId::of::<u16>();
        FUSED_ASSIGNMENTS.with(|cache| {
            cache
                .borrow_mut()
                .insert(zero_row_owner, Box::new("zero-row"));
        });

        let nonzero_owners = std::collections::HashSet::from([nonzero_owner]);
        validate_fused_assignment_cache_disjoint(&nonzero_owners).unwrap();
        publish_fused_assignments(vec![(nonzero_owner, Box::new(17u32))]).unwrap();
        FUSED_ASSIGNMENTS.with(|cache| assert_eq!(cache.borrow().len(), 2));

        let colliding_owners = std::collections::HashSet::from([zero_row_owner]);
        assert!(validate_fused_assignment_cache_disjoint(&colliding_owners).is_err());
        assert!(publish_fused_assignments(vec![(zero_row_owner, Box::new(99u32))]).is_err());

        FUSED_ASSIGNMENTS.with(|cache| {
            let mut cache = cache.borrow_mut();
            assert_eq!(
                *cache
                    .remove(&zero_row_owner)
                    .unwrap()
                    .downcast::<&str>()
                    .unwrap(),
                "zero-row"
            );
            assert_eq!(
                *cache
                    .remove(&nonzero_owner)
                    .unwrap()
                    .downcast::<u32>()
                    .unwrap(),
                17
            );
            assert!(cache.is_empty());
        });
        FUSED_ASSIGNMENTS.with(|cache| {
            assert!(
                cache.borrow().is_empty(),
                "fused assignment cache not empty"
            )
        });
    }

    #[test]
    fn direct_source_uses_only_initialized_nonempty_prefixes() {
        let mut add = GpuTypedSoaArena::new(InsnKind::ADD, 4).unwrap();
        add.push_step(0, &StepRecord::default()).unwrap();
        assert_eq!(add.capacity(), 4);
        assert_eq!(add.len(), 1);
        let initialized_add_bytes = if add.is_compact() {
            add.layout().compact_bytes()
        } else {
            add.layout().bytes()
        };
        assert_eq!(initialized_typed_bytes(&add), Some(initialized_add_bytes));

        let sub = GpuTypedSoaArena::new(InsnKind::SUB, 7).unwrap();
        assert_eq!(sub.capacity(), 7);
        assert!(sub.is_empty());
        assert_eq!(initialized_typed_bytes(&sub), Some(0));

        let mut typed = empty_typed();
        typed[InsnKind::ADD as usize] = Some(add);
        typed[InsnKind::SUB as usize] = Some(sub);
        let bytes = typed
            .iter()
            .flatten()
            .filter(|arena| !arena.is_empty())
            .try_fold(0usize, |sum, arena| {
                sum.checked_add(initialized_typed_bytes(arena)?)
            });
        assert_eq!(bytes, Some(initialized_add_bytes));
    }

    #[cfg(feature = "u16limb_circuit")]
    #[test]
    fn compact_and_field_soa_fused_assignments_match_every_layout() {
        use ceno_emul::{
            ByteAddr, Change, GpuReplayTypedRange, ReadOp, WordAddr, WriteOp, encode_rv32,
        };
        use ceno_gpu::{Buffer, common::BufferImpl};
        use ff_ext::BabyBearExt4;
        use p3::babybear::BabyBear;

        use crate::{
            instructions::{
                Instruction,
                riscv::{
                    AddInstruction, JalInstruction, JalrInstruction, LwInstruction, SwInstruction,
                    arith_imm::AddiInstruction, branch::BeqInstruction, lui::LuiInstruction,
                },
            },
            structs::{ProgramParams, ZKVMConstraintSystem, ZKVMWitnesses},
        };

        type E = BabyBearExt4;
        type MatrixSnapshot = (String, usize, usize, usize, Vec<BabyBear>);

        assert!(
            super::super::config::gpu_witgen_enabled(),
            "GPU witness generation is required"
        );
        assert!(!super::super::config::is_debug_compare_enabled());

        fn with_raw(mut insn: ceno_emul::Instruction, raw: u32) -> ceno_emul::Instruction {
            insn.raw = raw;
            insn
        }

        let steps = vec![
            StepRecord::new_r_instruction(
                4,
                ByteAddr(0x1000),
                with_raw(encode_rv32(InsnKind::ADD, 1, 2, 3, 0), 0x0020_81b3),
                0x11,
                0x22,
                Change::new(0x33, 0x33),
                0,
            ),
            StepRecord::new_i_instruction(
                8,
                Change::new(ByteAddr(0x1004), ByteAddr(0x1008)),
                with_raw(encode_rv32(InsnKind::ADDI, 1, 0, 3, 9), 0x0090_8193),
                0x11,
                Change::new(0x33, 0x1a),
                0,
            ),
            StepRecord::new_b_instruction(
                12,
                Change::new(ByteAddr(0x1008), ByteAddr(0x1010)),
                with_raw(encode_rv32(InsnKind::BEQ, 1, 2, 0, 8), 0x0020_8463),
                0x22,
                0x22,
                0,
            ),
            StepRecord::new_j_instruction(
                16,
                Change::new(ByteAddr(0x100c), ByteAddr(0x1018)),
                with_raw(encode_rv32(InsnKind::JAL, 0, 0, 3, 12), 0x00c0_01ef),
                Change::new(0x33, 0x1010),
                0,
            ),
            StepRecord::new_i_instruction(
                20,
                Change::new(ByteAddr(0x1010), ByteAddr(0x1020)),
                with_raw(encode_rv32(InsnKind::JALR, 1, 0, 3, 8), 0x0080_81e7),
                0x1018,
                Change::new(0x33, 0x1014),
                0,
            ),
            StepRecord::new_im_instruction(
                24,
                ByteAddr(0x1014),
                with_raw(encode_rv32(InsnKind::LW, 1, 0, 3, 8), 0x0080_a183),
                0x0400_0000,
                Change::new(0x33, 0x4433_2211),
                ReadOp {
                    addr: WordAddr(0x0100_0002),
                    value: 0x4433_2211,
                    previous_cycle: 0,
                },
                0,
            ),
            StepRecord::new_s_instruction(
                28,
                ByteAddr(0x1018),
                with_raw(encode_rv32(InsnKind::SW, 1, 2, 0, 12), 0x0020_a623),
                0x0400_0000,
                0x8877_6655,
                WriteOp {
                    addr: WordAddr(0x0100_0003),
                    value: Change::new(0, 0x8877_6655),
                    previous_cycle: 0,
                },
                0,
            ),
            StepRecord::new_i_instruction(
                32,
                Change::new(ByteAddr(0x101c), ByteAddr(0x1020)),
                with_raw(encode_rv32(InsnKind::LUI, 0, 0, 3, 0x12000), 0x0001_21b7),
                0,
                Change::new(0x33, 0x12000),
                0,
            ),
        ];

        fn arenas(steps: &[StepRecord], compact: bool) -> GpuReplayShardArenas {
            let mut typed: Vec<Option<GpuTypedSoaArena>> =
                (0..InsnKind::COUNT).map(|_| None).collect();
            for (ordinal, step) in steps.iter().enumerate() {
                let arena = typed[step.insn().kind as usize].get_or_insert_with(|| {
                    if compact {
                        GpuTypedSoaArena::new(step.insn().kind, 1)
                    } else {
                        GpuTypedSoaArena::new_field_soa_oracle(step.insn().kind, 1)
                    }
                    .unwrap()
                });
                arena.push_step(ordinal as u32, step).unwrap();
            }
            GpuReplayShardArenas::from_ranges(vec![GpuReplayTypedRange {
                sequence: 0,
                typed,
                fallback: Vec::new(),
            }])
        }

        fn snapshot_matrix(
            name: &str,
            role: usize,
            matrix: &witness::RowMajorMatrix<BabyBear>,
        ) -> MatrixSnapshot {
            let values = if let Some(device) =
                matrix.device_backing_ref::<BufferImpl<'static, BabyBear>>()
            {
                device.to_vec().unwrap()
            } else {
                matrix.values().to_vec()
            };
            (
                format!("{name}:{role}"),
                matrix.num_instances(),
                matrix.height(),
                matrix.width(),
                values,
            )
        }

        fn flatten_lk(multiplicity: &Multiplicity<u64>) -> Vec<Vec<(u64, usize)>> {
            multiplicity
                .iter()
                .map(|table| {
                    let mut entries: Vec<_> =
                        table.iter().map(|(&key, &count)| (key, count)).collect();
                    entries.sort_unstable();
                    entries
                })
                .collect()
        }

        fn run(
            steps: &[StepRecord],
            arenas: GpuReplayShardArenas,
        ) -> (
            Vec<MatrixSnapshot>,
            Vec<Vec<(u64, usize)>>,
            (Vec<u32>, Vec<u32>, Vec<u32>),
        ) {
            let mut cs = ZKVMConstraintSystem::<E>::new_with_platform(ProgramParams::default());
            let add = cs.register_opcode_circuit::<AddInstruction<E>>();
            let addi = cs.register_opcode_circuit::<AddiInstruction<E>>();
            let beq = cs.register_opcode_circuit::<BeqInstruction<E>>();
            let jal = cs.register_opcode_circuit::<JalInstruction<E>>();
            let jalr = cs.register_opcode_circuit::<JalrInstruction<E>>();
            let lw = cs.register_opcode_circuit::<LwInstruction<E>>();
            let sw = cs.register_opcode_circuit::<SwInstruction<E>>();
            let lui = cs.register_opcode_circuit::<LuiInstruction<E>>();

            install_compact_replay_arenas(arenas);
            macro_rules! prepare {
                ($instruction:ty, $config:expr, $kind:expr) => {{
                    let chip = cs.get_cs(&<$instruction>::name()).unwrap();
                    prepare_fused_assignment::<E, $instruction>(
                        $config,
                        chip.zkvm_v1_css.num_witin as usize,
                        chip.zkvm_v1_css.num_structural_witin as usize,
                        1,
                        $kind,
                    )
                    .unwrap();
                }};
            }
            prepare!(AddInstruction<E>, &add, GpuWitgenKind::Add);
            prepare!(AddiInstruction<E>, &addi, GpuWitgenKind::Addi);
            prepare!(BeqInstruction<E>, &beq, GpuWitgenKind::BranchEq(1));
            prepare!(JalInstruction<E>, &jal, GpuWitgenKind::Jal);
            prepare!(JalrInstruction<E>, &jalr, GpuWitgenKind::Jalr);
            prepare!(LwInstruction<E>, &lw, GpuWitgenKind::Lw);
            prepare!(SwInstruction<E>, &sw, GpuWitgenKind::Sw);
            prepare!(LuiInstruction<E>, &lui, GpuWitgenKind::Lui);

            let mut shard_ctx = ShardContext::default();
            shard_ctx.cur_shard_cycle_range = 4..36;
            launch_fused_assignments(&shard_ctx).unwrap();

            let mut witness = ZKVMWitnesses::<E>::default();
            macro_rules! assign {
                ($instruction:ty, $config:expr) => {
                    witness
                        .assign_opcode_circuit::<$instruction>(
                            &cs,
                            &mut shard_ctx,
                            $config,
                            steps,
                            &[],
                        )
                        .unwrap();
                };
            }
            assign!(AddInstruction<E>, &add);
            assign!(AddiInstruction<E>, &addi);
            assign!(BeqInstruction<E>, &beq);
            assign!(JalInstruction<E>, &jal);
            assign!(JalrInstruction<E>, &jalr);
            assign!(LwInstruction<E>, &lw);
            assign!(SwInstruction<E>, &sw);
            assign!(LuiInstruction<E>, &lui);
            clear_compact_replay_arenas();

            let lk = flush_shared_lk_counters().unwrap().unwrap();
            let shared = take_shared_device_buffers().unwrap();
            let counts = shared.ec_count.to_vec().unwrap();
            let ec_words = counts[0] as usize
                * std::mem::size_of::<ceno_gpu::common::witgen::types::GpuShardRamRecord>()
                / std::mem::size_of::<u32>();
            let ec = shared.ec_buf.to_vec_n(ec_words).unwrap();
            let addr_count = shared.addr_count.to_vec().unwrap()[0] as usize;
            let mut addresses = shared.addr_buf.to_vec_n(addr_count).unwrap();
            addresses.sort_unstable();
            addresses.dedup();
            let emissions = shared.emission_expected.to_vec().unwrap();
            invalidate_shard_meta_cache();

            let matrices = witness
                .witnesses
                .iter()
                .flat_map(|(name, inputs)| {
                    inputs.iter().flat_map(move |input| {
                        input
                            .witness_rmms
                            .iter()
                            .enumerate()
                            .map(move |(role, matrix)| snapshot_matrix(name, role, matrix))
                    })
                })
                .collect();
            (matrices, flatten_lk(&lk), (ec, addresses, emissions))
        }

        let typed = run(&steps, arenas(&steps, false));
        let compact = run(&steps, arenas(&steps, true));
        assert_eq!(compact, typed);
    }
}
