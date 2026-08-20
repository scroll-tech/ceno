use ceno_gpu::common::witgen::types::SltiColumnMap;
use ff_ext::ExtensionField;

use crate::instructions::{
    gpu::utils::column_map::{extract_rd, extract_rs1, extract_state, extract_uint_limbs},
    riscv::slti::slti_circuit_v2::SetLessThanImmConfig,
};

/// Extract column map from a constructed SetLessThanImmConfig (SLTI/SLTIU).
pub fn extract_slti_column_map<E: ExtensionField>(
    config: &SetLessThanImmConfig<E>,
    num_witin: usize,
) -> SltiColumnMap {
    let rs1_limbs = extract_uint_limbs::<E, 2, _, _>(&config.rs1_read, "rs1_read");
    let imm = config.imm.id as u32;
    let imm_sign = config.imm_sign.id as u32;

    // UIntLimbsLT comparison gadget
    let cmp_lt = config.uint_lt_config.cmp_lt.id as u32;
    let a_msb_f = config.uint_lt_config.a_msb_f.id as u32;
    let b_msb_f = config.uint_lt_config.b_msb_f.id as u32;
    let diff_marker: [u32; 2] = [
        config.uint_lt_config.diff_marker[0].id as u32,
        config.uint_lt_config.diff_marker[1].id as u32,
    ];
    let diff_val = config.uint_lt_config.diff_val.id as u32;

    let (pc, ts) = extract_state(&config.i_insn.vm_state);
    let (rs1_id, rs1_prev_ts, rs1_lt_diff) = extract_rs1(&config.i_insn.rs1);
    let (rd_id, rd_prev_ts, rd_prev_val, rd_lt_diff) = extract_rd(&config.i_insn.rd);

    SltiColumnMap {
        rs1_limbs,
        imm,
        imm_sign,
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
        rd_id,
        rd_prev_ts,
        rd_prev_val,
        rd_lt_diff,
        num_cols: num_witin as u32,
    }
}
