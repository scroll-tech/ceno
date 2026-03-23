//! Shared column-map extraction helpers for GPU witness generation.
//!
//! Each GPU column-map extractor (`add.rs`, `sub.rs`, …) reads `WitIn.id`
//! fields from a circuit config and packs them into a `#[repr(C)]` struct
//! for the CUDA kernel.  The base instruction fields (pc, ts, rs1, rs2, rd,
//! mem timestamps) are identical across instruction formats — these helpers
//! eliminate the duplication.

use ff_ext::ExtensionField;
use gkr_iop::gadgets::AssertLtConfig;
use multilinear_extensions::WitIn;

use crate::{
    instructions::riscv::insn_base::{ReadMEM, ReadRS1, ReadRS2, StateInOut, WriteMEM, WriteRD},
    uint::UIntLimbs,
};

// ---------------------------------------------------------------------------
// StateInOut
// ---------------------------------------------------------------------------

/// Extract `(pc, ts)` from a non-branching `StateInOut`.
#[inline]
pub fn extract_state<E: ExtensionField>(vm: &StateInOut<E>) -> (u32, u32) {
    (vm.pc.id as u32, vm.ts.id as u32)
}

/// Extract `(pc, next_pc, ts)` from a branching `StateInOut`.
#[inline]
pub fn extract_state_branching<E: ExtensionField>(vm: &StateInOut<E>) -> (u32, u32, u32) {
    (
        vm.pc.id as u32,
        vm.next_pc.expect("branching StateInOut must have next_pc").id as u32,
        vm.ts.id as u32,
    )
}

// ---------------------------------------------------------------------------
// Register reads / writes
// ---------------------------------------------------------------------------

/// Extract `(id, prev_ts, lt_diff[2])` from a `ReadRS1`.
#[inline]
pub fn extract_rs1<E: ExtensionField>(rs1: &ReadRS1<E>) -> (u32, u32, [u32; 2]) {
    (
        rs1.id.id as u32,
        rs1.prev_ts.id as u32,
        extract_lt_diff(&rs1.lt_cfg),
    )
}

/// Extract `(id, prev_ts, lt_diff[2])` from a `ReadRS2`.
#[inline]
pub fn extract_rs2<E: ExtensionField>(rs2: &ReadRS2<E>) -> (u32, u32, [u32; 2]) {
    (
        rs2.id.id as u32,
        rs2.prev_ts.id as u32,
        extract_lt_diff(&rs2.lt_cfg),
    )
}

/// Extract `(id, prev_ts, prev_val[2], lt_diff[2])` from a `WriteRD`.
#[inline]
pub fn extract_rd<E: ExtensionField>(rd: &WriteRD<E>) -> (u32, u32, [u32; 2], [u32; 2]) {
    let prev_val = extract_uint_limbs::<E, 2, _, _>(&rd.prev_value, "WriteRD prev_value");
    (
        rd.id.id as u32,
        rd.prev_ts.id as u32,
        prev_val,
        extract_lt_diff(&rd.lt_cfg),
    )
}

// ---------------------------------------------------------------------------
// Memory reads / writes
// ---------------------------------------------------------------------------

/// Extract `(prev_ts, lt_diff[2])` from a `ReadMEM`.
#[inline]
pub fn extract_read_mem<E: ExtensionField>(mem: &ReadMEM<E>) -> (u32, [u32; 2]) {
    (mem.prev_ts.id as u32, extract_lt_diff(&mem.lt_cfg))
}

/// Extract `(prev_ts, lt_diff[2])` from a `WriteMEM`.
#[inline]
pub fn extract_write_mem(mem: &WriteMEM) -> (u32, [u32; 2]) {
    (mem.prev_ts.id as u32, extract_lt_diff(&mem.lt_cfg))
}

// ---------------------------------------------------------------------------
// Primitive helpers
// ---------------------------------------------------------------------------

/// Extract the two diff-limb column IDs from an `AssertLtConfig`.
#[inline]
pub fn extract_lt_diff(lt: &AssertLtConfig) -> [u32; 2] {
    let d = &lt.0.diff;
    assert_eq!(d.len(), 2, "Expected 2 AssertLt diff limbs, got {}", d.len());
    [d[0].id as u32, d[1].id as u32]
}

/// Extract `N` limb column IDs from a `UIntLimbs` via `wits_in()`.
#[inline]
pub fn extract_uint_limbs<E: ExtensionField, const N: usize, const M: usize, const C: usize>(
    u: &UIntLimbs<M, C, E>,
    label: &str,
) -> [u32; N] {
    let limbs = u.wits_in().unwrap_or_else(|| panic!("{label} should have WitIn limbs"));
    assert_eq!(limbs.len(), N, "Expected {N} limbs for {label}, got {}", limbs.len());
    std::array::from_fn(|i| limbs[i].id as u32)
}

/// Extract `N` carry column IDs from a `UIntLimbs`'s carries.
#[inline]
pub fn extract_carries<E: ExtensionField, const N: usize, const M: usize, const C: usize>(
    u: &UIntLimbs<M, C, E>,
    label: &str,
) -> [u32; N] {
    let carries = u
        .carries
        .as_ref()
        .unwrap_or_else(|| panic!("{label} should have carries"));
    assert_eq!(carries.len(), N, "Expected {N} carries for {label}, got {}", carries.len());
    std::array::from_fn(|i| carries[i].id as u32)
}

/// Extract `N` column IDs from a `&[WitIn]` slice (e.g. byte decomposition).
#[inline]
pub fn extract_wit_ids<const N: usize>(wits: &[WitIn], label: &str) -> [u32; N] {
    assert_eq!(
        wits.len(),
        N,
        "Expected {N} WitIn entries for {label}, got {}",
        wits.len()
    );
    std::array::from_fn(|i| wits[i].id as u32)
}

// ---------------------------------------------------------------------------
// Test helper
// ---------------------------------------------------------------------------

#[cfg(test)]
pub fn validate_column_map(flat: &[u32], num_cols: u32) {
    for (i, &col) in flat.iter().enumerate() {
        assert!(
            col < num_cols,
            "Column index {i}: value {col} out of range (num_cols = {num_cols})"
        );
    }
    let mut seen = std::collections::HashSet::new();
    for &col in flat {
        assert!(seen.insert(col), "Duplicate column ID: {col}");
    }
}
