/// GPU witgen path-control helpers: kind tags, verified-kind queries, and
/// environment-variable disable switches.
///
/// Extracted from `witgen_gpu.rs` — pure code move, no behavioural changes.
use super::witgen_gpu::GpuWitgenKind;

pub(crate) fn kind_tag(kind: GpuWitgenKind) -> &'static str {
    match kind {
        GpuWitgenKind::Add => "add",
        GpuWitgenKind::Sub => "sub",
        GpuWitgenKind::LogicR(_) => "logic_r",
        GpuWitgenKind::Lw => "lw",
        #[cfg(feature = "u16limb_circuit")]
        GpuWitgenKind::LogicI(_) => "logic_i",
        #[cfg(feature = "u16limb_circuit")]
        GpuWitgenKind::Addi => "addi",
        #[cfg(feature = "u16limb_circuit")]
        GpuWitgenKind::Lui => "lui",
        #[cfg(feature = "u16limb_circuit")]
        GpuWitgenKind::Auipc => "auipc",
        #[cfg(feature = "u16limb_circuit")]
        GpuWitgenKind::Jal => "jal",
        #[cfg(feature = "u16limb_circuit")]
        GpuWitgenKind::ShiftR(_) => "shift_r",
        #[cfg(feature = "u16limb_circuit")]
        GpuWitgenKind::ShiftI(_) => "shift_i",
        #[cfg(feature = "u16limb_circuit")]
        GpuWitgenKind::Slt(_) => "slt",
        #[cfg(feature = "u16limb_circuit")]
        GpuWitgenKind::Slti(_) => "slti",
        #[cfg(feature = "u16limb_circuit")]
        GpuWitgenKind::BranchEq(_) => "branch_eq",
        #[cfg(feature = "u16limb_circuit")]
        GpuWitgenKind::BranchCmp(_) => "branch_cmp",
        #[cfg(feature = "u16limb_circuit")]
        GpuWitgenKind::Jalr => "jalr",
        #[cfg(feature = "u16limb_circuit")]
        GpuWitgenKind::Sw => "sw",
        #[cfg(feature = "u16limb_circuit")]
        GpuWitgenKind::Sh => "sh",
        #[cfg(feature = "u16limb_circuit")]
        GpuWitgenKind::Sb => "sb",
        #[cfg(feature = "u16limb_circuit")]
        GpuWitgenKind::LoadSub { .. } => "load_sub",
        #[cfg(feature = "u16limb_circuit")]
        GpuWitgenKind::Mul(_) => "mul",
        #[cfg(feature = "u16limb_circuit")]
        GpuWitgenKind::Div(_) => "div",
        GpuWitgenKind::Keccak => "keccak",
    }
}

/// Returns true if the GPU CUDA kernel for this kind has been verified to produce
/// correct LK multiplicity counters matching the CPU baseline.
/// Unverified kinds fall back to CPU full side effects (GPU still handles witness).
///
/// Override with `CENO_GPU_DISABLE_LK_KINDS=add,sub,...` to force specific kinds
/// back to CPU LK (for binary-search debugging).
/// Set `CENO_GPU_DISABLE_LK_KINDS=all` to disable GPU LK for ALL kinds.
pub(crate) fn kind_has_verified_lk(kind: GpuWitgenKind) -> bool {
    if is_lk_kind_disabled(kind) {
        return false;
    }
    match kind {
        // Phase B verified (Add/Sub/LogicR/Lw)
        GpuWitgenKind::Add => true,
        GpuWitgenKind::Sub => true,
        GpuWitgenKind::LogicR(_) => true,
        GpuWitgenKind::Lw => true,
        // Phase C verified via debug_compare_final_lk
        #[cfg(feature = "u16limb_circuit")]
        GpuWitgenKind::Addi => true,
        #[cfg(feature = "u16limb_circuit")]
        GpuWitgenKind::LogicI(_) => true,
        #[cfg(feature = "u16limb_circuit")]
        GpuWitgenKind::Lui => true,
        #[cfg(feature = "u16limb_circuit")]
        GpuWitgenKind::Slti(_) => true,
        #[cfg(feature = "u16limb_circuit")]
        GpuWitgenKind::BranchEq(_) => true,
        #[cfg(feature = "u16limb_circuit")]
        GpuWitgenKind::BranchCmp(_) => true,
        #[cfg(feature = "u16limb_circuit")]
        GpuWitgenKind::Sw => true,
        // Phase C CUDA kernel fixes applied
        #[cfg(feature = "u16limb_circuit")]
        GpuWitgenKind::ShiftI(_) => true,
        #[cfg(feature = "u16limb_circuit")]
        GpuWitgenKind::Auipc => true,
        #[cfg(feature = "u16limb_circuit")]
        GpuWitgenKind::Jal => true,
        #[cfg(feature = "u16limb_circuit")]
        GpuWitgenKind::Jalr => true,
        #[cfg(feature = "u16limb_circuit")]
        GpuWitgenKind::Sb => true,
        // Remaining kinds enabled
        #[cfg(feature = "u16limb_circuit")]
        GpuWitgenKind::ShiftR(_) => true,
        #[cfg(feature = "u16limb_circuit")]
        GpuWitgenKind::Slt(_) => true,
        #[cfg(feature = "u16limb_circuit")]
        GpuWitgenKind::Sh => true,
        #[cfg(feature = "u16limb_circuit")]
        GpuWitgenKind::LoadSub { .. } => true,
        #[cfg(feature = "u16limb_circuit")]
        GpuWitgenKind::Mul(_) => true,
        #[cfg(feature = "u16limb_circuit")]
        GpuWitgenKind::Div(_) => true,
        // Keccak has its own dispatch path with its own LK handling.
        GpuWitgenKind::Keccak => false,
        #[cfg(not(feature = "u16limb_circuit"))]
        _ => false,
    }
}

/// Returns true if GPU shard records are verified for this kind.
/// Set CENO_GPU_DISABLE_SHARD_KINDS=all to force ALL kinds back to CPU shard path.
pub(crate) fn kind_has_verified_shard(kind: GpuWitgenKind) -> bool {
    // Global kill switch: force pure CPU shard path for baseline testing
    if std::env::var_os("CENO_GPU_CPU_SHARD").is_some() {
        return false;
    }
    if is_shard_kind_disabled(kind) {
        return false;
    }
    match kind {
        GpuWitgenKind::Add
        | GpuWitgenKind::Sub
        | GpuWitgenKind::LogicR(_)
        | GpuWitgenKind::Lw => true,
        #[cfg(feature = "u16limb_circuit")]
        GpuWitgenKind::LogicI(_)
        | GpuWitgenKind::Addi
        | GpuWitgenKind::Lui
        | GpuWitgenKind::Auipc
        | GpuWitgenKind::Jal
        | GpuWitgenKind::ShiftR(_)
        | GpuWitgenKind::ShiftI(_)
        | GpuWitgenKind::Slt(_)
        | GpuWitgenKind::Slti(_)
        | GpuWitgenKind::BranchEq(_)
        | GpuWitgenKind::BranchCmp(_)
        | GpuWitgenKind::Jalr
        | GpuWitgenKind::Sw
        | GpuWitgenKind::Sh
        | GpuWitgenKind::Sb
        | GpuWitgenKind::LoadSub { .. }
        | GpuWitgenKind::Mul(_)
        | GpuWitgenKind::Div(_) => true,
        // Keccak has its own dispatch path, never enters try_gpu_assign_instances.
        GpuWitgenKind::Keccak => false,
        #[cfg(not(feature = "u16limb_circuit"))]
        _ => false,
    }
}

/// Check if GPU LK is disabled for a specific kind via CENO_GPU_DISABLE_LK_KINDS env var.
/// Format: CENO_GPU_DISABLE_LK_KINDS=add,sub,lw (comma-separated kind tags)
/// Special value: CENO_GPU_DISABLE_LK_KINDS=all (disables GPU LK for ALL kinds)
pub(crate) fn is_lk_kind_disabled(kind: GpuWitgenKind) -> bool {
    thread_local! {
        static DISABLED: std::cell::OnceCell<Vec<String>> = const { std::cell::OnceCell::new() };
    }
    DISABLED.with(|cell| {
        let disabled = cell.get_or_init(|| {
            std::env::var("CENO_GPU_DISABLE_LK_KINDS")
                .ok()
                .map(|s| s.split(',').map(|t| t.trim().to_lowercase()).collect())
                .unwrap_or_default()
        });
        if disabled.is_empty() {
            return false;
        }
        if disabled.iter().any(|d| d == "all") {
            return true;
        }
        let tag = kind_tag(kind);
        disabled.iter().any(|d| d == tag)
    })
}

/// Check if GPU shard records are disabled for a specific kind via env var.
pub(crate) fn is_shard_kind_disabled(kind: GpuWitgenKind) -> bool {
    thread_local! {
        static DISABLED: std::cell::OnceCell<Vec<String>> = const { std::cell::OnceCell::new() };
    }
    DISABLED.with(|cell| {
        let disabled = cell.get_or_init(|| {
            std::env::var("CENO_GPU_DISABLE_SHARD_KINDS")
                .ok()
                .map(|s| s.split(',').map(|t| t.trim().to_lowercase()).collect())
                .unwrap_or_default()
        });
        if disabled.is_empty() {
            return false;
        }
        if disabled.iter().any(|d| d == "all") {
            return true;
        }
        let tag = kind_tag(kind);
        disabled.iter().any(|d| d == tag)
    })
}

/// Check if a specific GPU witgen kind is disabled via CENO_GPU_DISABLE_KINDS env var.
/// Format: CENO_GPU_DISABLE_KINDS=add,sub,lw (comma-separated kind tags)
pub(crate) fn is_kind_disabled(kind: GpuWitgenKind) -> bool {
    thread_local! {
        static DISABLED: std::cell::OnceCell<Vec<String>> = const { std::cell::OnceCell::new() };
    }
    DISABLED.with(|cell| {
        let disabled = cell.get_or_init(|| {
            std::env::var("CENO_GPU_DISABLE_KINDS")
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

/// Returns true if GPU witgen is globally disabled via CENO_GPU_DISABLE_WITGEN env var.
/// The value is cached at first access so it's immune to runtime env var manipulation.
pub(crate) fn is_gpu_witgen_disabled() -> bool {
    use std::sync::OnceLock;
    static DISABLED: OnceLock<bool> = OnceLock::new();
    *DISABLED.get_or_init(|| {
        let val = std::env::var_os("CENO_GPU_DISABLE_WITGEN");
        let disabled = val.is_some();
        // Use eprintln to bypass tracing filters — always visible on stderr
        eprintln!(
            "[GPU witgen] CENO_GPU_DISABLE_WITGEN={:?} → disabled={}",
            val, disabled
        );
        disabled
    })
}
