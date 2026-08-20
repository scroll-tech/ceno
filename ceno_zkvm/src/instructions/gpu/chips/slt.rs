use ceno_gpu::common::witgen::types::SltColumnMap;
use ff_ext::ExtensionField;

use crate::instructions::{
    gpu::utils::column_map::{
        extract_rd, extract_rs1, extract_rs2, extract_state, extract_uint_limbs,
    },
    riscv::slt::slt_circuit_v2::SetLessThanConfig,
};

/// Extract column map from a constructed SetLessThanConfig (SLT/SLTU).
pub fn extract_slt_column_map<E: ExtensionField>(
    config: &SetLessThanConfig<E>,
    num_witin: usize,
) -> SltColumnMap {
    let rs1_limbs = extract_uint_limbs::<E, 2, _, _>(&config.rs1_read, "rs1_read");
    let rs2_limbs = extract_uint_limbs::<E, 2, _, _>(&config.rs2_read, "rs2_read");

    // UIntLimbsLT comparison gadget
    let cmp_lt = config.uint_lt_config.cmp_lt.id as u32;
    let a_msb_f = config.uint_lt_config.a_msb_f.id as u32;
    let b_msb_f = config.uint_lt_config.b_msb_f.id as u32;
    let diff_marker: [u32; 2] = [
        config.uint_lt_config.diff_marker[0].id as u32,
        config.uint_lt_config.diff_marker[1].id as u32,
    ];
    let diff_val = config.uint_lt_config.diff_val.id as u32;

    let (pc, ts) = extract_state(&config.r_insn.vm_state);
    let (rs1_id, rs1_prev_ts, rs1_lt_diff) = extract_rs1(&config.r_insn.rs1);
    let (rs2_id, rs2_prev_ts, rs2_lt_diff) = extract_rs2(&config.r_insn.rs2);
    let (rd_id, rd_prev_ts, rd_prev_val, rd_lt_diff) = extract_rd(&config.r_insn.rd);

    SltColumnMap {
        rs1_limbs,
        rs2_limbs,
        cmp_lt,
        a_msb_f,
        b_msb_f,
        diff_marker,
        diff_val,
        pc,
        ts,
        rs1_id,
        rs1_prev_ts,
        rs1_lt_diff,
        rs2_id,
        rs2_prev_ts,
        rs2_lt_diff,
        rd_id,
        rd_prev_ts,
        rd_prev_val,
        rd_lt_diff,
        num_cols: num_witin as u32,
    }
}
