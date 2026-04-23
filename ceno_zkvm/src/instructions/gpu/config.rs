/// GPU witgen path-control helpers: kind tags, verified-kind queries, and
/// environment-variable disable switches.
///
/// Environment variables (3 total):
/// - `CENO_GPU_ENABLE_WITGEN` — opt-in GPU witgen (default: CPU)
/// - `CENO_GPU_DISABLE_WITGEN_KINDS=add,sub,keccak,...` — per-kind disable (comma-separated tags)
/// - `CENO_GPU_DEBUG_COMPARE_WITGEN` — enable GPU vs CPU comparison for all chips (witness, LK, shard, EC)
use super::dispatch::GpuWitgenKind;
use ceno_gpu::common::{CacheLevel, get_gpu_cache_level};

pub(crate) fn kind_tag(kind: GpuWitgenKind) -> &'static str {
    match kind {
        GpuWitgenKind::Add => "add",
        GpuWitgenKind::Sub => "sub",
        GpuWitgenKind::LogicR(_) => "logic_r",
        GpuWitgenKind::Lw => "lw",
        GpuWitgenKind::LogicI(_) => "logic_i",
        GpuWitgenKind::Addi => "addi",
        GpuWitgenKind::Lui => "lui",
        GpuWitgenKind::Auipc => "auipc",
        GpuWitgenKind::Jal => "jal",
        GpuWitgenKind::ShiftR(_) => "shift_r",
        GpuWitgenKind::ShiftI(_) => "shift_i",
        GpuWitgenKind::Slt(_) => "slt",
        GpuWitgenKind::Slti(_) => "slti",
        GpuWitgenKind::BranchEq(_) => "branch_eq",
        GpuWitgenKind::BranchCmp(_) => "branch_cmp",
        GpuWitgenKind::Jalr => "jalr",
        GpuWitgenKind::Sw => "sw",
        GpuWitgenKind::Sh => "sh",
        GpuWitgenKind::Sb => "sb",
        GpuWitgenKind::LoadSub { .. } => "load_sub",
        GpuWitgenKind::Mul(_) => "mul",
        GpuWitgenKind::Div(_) => "div",
        GpuWitgenKind::Keccak => "keccak",
        GpuWitgenKind::ShardRam => "shard_ram",
    }
}

/// Check if a specific GPU witgen kind is disabled via `CENO_GPU_DISABLE_WITGEN_KINDS` env var.
///
/// Format: `CENO_GPU_DISABLE_WITGEN_KINDS=add,sub,keccak,lw` (comma-separated kind tags)
///
/// This covers all chips including keccak.
pub(crate) fn is_kind_disabled(kind: GpuWitgenKind) -> bool {
    thread_local! {
        static DISABLED: std::cell::OnceCell<Vec<String>> = const { std::cell::OnceCell::new() };
    }
    DISABLED.with(|cell| {
        let disabled = cell.get_or_init(|| {
            std::env::var("CENO_GPU_DISABLE_WITGEN_KINDS")
                .ok()
                .map(|s| s.split(',').map(|t| t.trim().to_lowercase()).collect())
                .unwrap_or_default()
        });
        if disabled.is_empty() {
            return false;
        }
        let tag = kind_tag(kind);
        disabled.iter().any(|d| d == tag)
    })
}

/// Set `CENO_GPU_ENABLE_WITGEN=1` to opt in; default disabled.
pub(crate) fn is_gpu_witgen_enabled() -> bool {
    use std::sync::OnceLock;
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| {
        let val = std::env::var("CENO_GPU_ENABLE_WITGEN").ok();
        let enabled = matches!(val.as_deref(), Some("1"));
        eprintln!(
            "[GPU witgen] CENO_GPU_ENABLE_WITGEN={:?} → enabled={}",
            val, enabled
        );
        enabled
    })
}

/// Whether initial witness assignment should materialize a GPU-backed trace RMM.
///
/// This is independent from the later retention policy:
/// - with GPU witgen off, witness is materialized in CPU form as before
/// - with GPU witgen on, witness is first produced as device-backed so commit
///   can consume the col-major GPU trace directly without a D2H/H2D round-trip
pub(crate) fn should_materialize_witness_on_gpu() -> bool {
    is_gpu_witgen_enabled()
}

/// Whether the initial opcode-assignment pass should eagerly materialize the
/// witness RMM/device backing.
///
/// In cache-none + GPU-witgen mode we keep only replay metadata plus the
/// shard-resident raw GPU state, and all witness materialization is deferred to
/// commit / chip proof / opening replay.
pub(crate) fn should_materialize_witness_on_initial_assign() -> bool {
    should_materialize_witness_on_gpu() && should_retain_witness_device_backing_after_commit()
}

/// Whether replayable witness device backing should remain resident after commit.
///
/// Policy:
/// - `GPU_WITGEN=0`: no special retention
/// - `GPU_WITGEN=1` and `CACHE_LEVEL > 0`: keep device backing resident
/// - `GPU_WITGEN=1` and `CACHE_LEVEL = 0`: clear after commit and regenerate on
///   demand from shard-resident raw data during chip proof / PCS open
pub(crate) fn should_retain_witness_device_backing_after_commit() -> bool {
    is_gpu_witgen_enabled() && !matches!(get_gpu_cache_level(), CacheLevel::None)
}

/// Set `CENO_GPU_DEBUG_COMPARE_WITGEN=1` to enable GPU vs CPU comparison; default disabled.
pub(crate) fn is_debug_compare_enabled() -> bool {
    use std::sync::OnceLock;
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| {
        let val = std::env::var("CENO_GPU_DEBUG_COMPARE_WITGEN").ok();
        matches!(val.as_deref(), Some("1"))
    })
}
