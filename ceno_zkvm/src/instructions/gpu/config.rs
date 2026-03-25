/// GPU witgen path-control helpers: kind tags, verified-kind queries, and
/// environment-variable disable switches.
///
/// Environment variables (3 total):
/// - `CENO_GPU_ENABLE_WITGEN` — opt-in GPU witgen (default: CPU)
/// - `CENO_GPU_DISABLE_WITGEN_KINDS=add,sub,keccak,...` — per-kind disable (comma-separated tags)
/// - `CENO_GPU_DEBUG_COMPARE_WITGEN` — enable GPU vs CPU comparison for all chips (witness, LK, shard, EC)
use super::dispatch::GpuWitgenKind;

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

/// Returns true if GPU witgen is enabled via `CENO_GPU_ENABLE_WITGEN` env var.
/// Default is disabled (CPU witgen). Set `CENO_GPU_ENABLE_WITGEN=1` to opt in.
/// The value is cached at first access.
pub(crate) fn is_gpu_witgen_enabled() -> bool {
    use std::sync::OnceLock;
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| {
        let val = std::env::var_os("CENO_GPU_ENABLE_WITGEN");
        let enabled = val.is_some();
        eprintln!(
            "[GPU witgen] CENO_GPU_ENABLE_WITGEN={:?} → enabled={}",
            val, enabled
        );
        enabled
    })
}

/// Returns true if `CENO_GPU_DEBUG_COMPARE_WITGEN` is set (any value).
/// When enabled, GPU vs CPU comparison runs for ALL categories:
/// witness, LK multiplicity, shard records, EC points, and E2E shard context.
pub(crate) fn is_debug_compare_enabled() -> bool {
    use std::sync::OnceLock;
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| std::env::var_os("CENO_GPU_DEBUG_COMPARE_WITGEN").is_some())
}
