use ceno_gpu::common::witgen::types::BranchCmpColumnMap;
use ff_ext::ExtensionField;

use crate::instructions::{
    gpu::utils::column_map::{
        extract_rs1, extract_rs2, extract_state_branching, extract_uint_limbs,
    },
    riscv::branch::branch_circuit_v2::BranchConfig,
};

/// Extract column map from a constructed BranchConfig (BLT/BGE/BLTU/BGEU variant).
pub fn extract_branch_cmp_column_map<E: ExtensionField>(
    config: &BranchConfig<E>,
    num_witin: usize,
) -> BranchCmpColumnMap {
    let rs1_limbs = extract_uint_limbs::<E, 2, _, _>(&config.read_rs1, "read_rs1");
    let rs2_limbs = extract_uint_limbs::<E, 2, _, _>(&config.read_rs2, "read_rs2");

    let lt_config = config.uint_lt_config.as_ref().unwrap();
    let cmp_lt = lt_config.cmp_lt.id as u32;
    let a_msb_f = lt_config.a_msb_f.id as u32;
    let b_msb_f = lt_config.b_msb_f.id as u32;
    let diff_marker: [u32; 2] = [
        lt_config.diff_marker[0].id as u32,
        lt_config.diff_marker[1].id as u32,
    ];
    let diff_val = lt_config.diff_val.id as u32;

    let (pc, next_pc, ts) = extract_state_branching(&config.b_insn.vm_state);
    let (rs1_id, rs1_prev_ts, rs1_lt_diff) = extract_rs1(&config.b_insn.rs1);
    let (rs2_id, rs2_prev_ts, rs2_lt_diff) = extract_rs2(&config.b_insn.rs2);
    let imm = config.b_insn.imm.id as u32;

    BranchCmpColumnMap {
        rs1_limbs,
        rs2_limbs,
        cmp_lt,
        a_msb_f,
        b_msb_f,
        diff_marker,
        diff_val,
        pc,
        next_pc,
        ts,
        rs1_id,
        rs1_prev_ts,
        rs1_lt_diff,
        rs2_id,
        rs2_prev_ts,
        rs2_lt_diff,
        imm,
        num_cols: num_witin as u32,
    }
}
