use ceno_gpu::common::witgen::types::ShiftIColumnMap;
use ff_ext::ExtensionField;

use crate::instructions::{
    gpu::utils::column_map::{extract_rd, extract_rs1, extract_state, extract_uint_limbs},
    riscv::shift::shift_circuit_v2::ShiftImmConfig,
};

/// Extract column map from a constructed ShiftImmConfig (I-type: SLLI/SRLI/SRAI).
pub fn extract_shift_i_column_map<E: ExtensionField>(
    config: &ShiftImmConfig<E>,
    num_witin: usize,
) -> ShiftIColumnMap {
    let (pc, ts) = extract_state(&config.i_insn.vm_state);
    let (rs1_id, rs1_prev_ts, rs1_lt_diff) = extract_rs1(&config.i_insn.rs1);
    let (rd_id, rd_prev_ts, rd_prev_val, rd_lt_diff) = extract_rd(&config.i_insn.rd);

    let rs1_bytes = extract_uint_limbs::<E, 4, _, _>(&config.rs1_read, "rs1_read");
    let rd_bytes = extract_uint_limbs::<E, 4, _, _>(&config.rd_written, "rd_written");
    let imm = config.imm.id as u32;

    // ShiftBase
    let bit_shift_marker: [u32; 8] =
        std::array::from_fn(|i| config.shift_base_config.bit_shift_marker[i].id as u32);
    let limb_shift_marker: [u32; 4] =
        std::array::from_fn(|i| config.shift_base_config.limb_shift_marker[i].id as u32);
    let bit_multiplier_left = config.shift_base_config.bit_multiplier_left.id as u32;
    let bit_multiplier_right = config.shift_base_config.bit_multiplier_right.id as u32;
    let b_sign = config.shift_base_config.b_sign.id as u32;
    let bit_shift_carry: [u32; 4] =
        std::array::from_fn(|i| config.shift_base_config.bit_shift_carry[i].id as u32);

    ShiftIColumnMap {
        pc,
        ts,
        rs1_id,
        rs1_prev_ts,
        rs1_lt_diff,
        rd_id,
        rd_prev_ts,
        rd_prev_val,
        rd_lt_diff,
        rs1_bytes,
        rd_bytes,
        imm,
        bit_shift_marker,
        limb_shift_marker,
        bit_multiplier_left,
        bit_multiplier_right,
        b_sign,
        bit_shift_carry,
        num_cols: num_witin as u32,
    }
}
