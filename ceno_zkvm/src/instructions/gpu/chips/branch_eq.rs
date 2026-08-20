use ceno_gpu::common::witgen::types::BranchEqColumnMap;
use ff_ext::ExtensionField;

use crate::instructions::{
    gpu::utils::column_map::{
        extract_rs1, extract_rs2, extract_state_branching, extract_uint_limbs,
    },
    riscv::branch::branch_circuit_v2::BranchConfig,
};

/// Extract column map from a constructed BranchConfig (BEQ/BNE variant).
pub fn extract_branch_eq_column_map<E: ExtensionField>(
    config: &BranchConfig<E>,
    num_witin: usize,
) -> BranchEqColumnMap {
    let rs1_limbs = extract_uint_limbs::<E, 2, _, _>(&config.read_rs1, "read_rs1");
    let rs2_limbs = extract_uint_limbs::<E, 2, _, _>(&config.read_rs2, "read_rs2");

    let branch_taken = config.eq_branch_taken_bit.as_ref().unwrap().id as u32;
    let diff_inv_marker: [u32; 2] = {
        let markers = config.eq_diff_inv_marker.as_ref().unwrap();
        [markers[0].id as u32, markers[1].id as u32]
    };

    let (pc, next_pc, ts) = extract_state_branching(&config.b_insn.vm_state);
    let (rs1_id, rs1_prev_ts, rs1_lt_diff) = extract_rs1(&config.b_insn.rs1);
    let (rs2_id, rs2_prev_ts, rs2_lt_diff) = extract_rs2(&config.b_insn.rs2);
    let imm = config.b_insn.imm.id as u32;

    BranchEqColumnMap {
        rs1_limbs,
        rs2_limbs,
        branch_taken,
        diff_inv_marker,
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
