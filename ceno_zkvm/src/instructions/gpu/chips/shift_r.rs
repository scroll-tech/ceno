use ceno_gpu::common::witgen::types::ShiftRColumnMap;
use ff_ext::ExtensionField;

use crate::instructions::{
    gpu::utils::column_map::{
        extract_rd, extract_rs1, extract_rs2, extract_state, extract_uint_limbs,
    },
    riscv::shift::shift_circuit_v2::ShiftRTypeConfig,
};

/// Extract column map from a constructed ShiftRTypeConfig (R-type: SLL/SRL/SRA).
pub fn extract_shift_r_column_map<E: ExtensionField>(
    config: &ShiftRTypeConfig<E>,
    num_witin: usize,
) -> ShiftRColumnMap {
    let (pc, ts) = extract_state(&config.r_insn.vm_state);
    let (rs1_id, rs1_prev_ts, rs1_lt_diff) = extract_rs1(&config.r_insn.rs1);
    let (rs2_id, rs2_prev_ts, rs2_lt_diff) = extract_rs2(&config.r_insn.rs2);
    let (rd_id, rd_prev_ts, rd_prev_val, rd_lt_diff) = extract_rd(&config.r_insn.rd);

    let rs1_bytes = extract_uint_limbs::<E, 4, _, _>(&config.rs1_read, "rs1_read");
    let rs2_bytes = extract_uint_limbs::<E, 4, _, _>(&config.rs2_read, "rs2_read");
    let rd_bytes = extract_uint_limbs::<E, 4, _, _>(&config.rd_written, "rd_written");

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

    ShiftRColumnMap {
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
        rs1_bytes,
        rs2_bytes,
        rd_bytes,
        bit_shift_marker,
        limb_shift_marker,
        bit_multiplier_left,
        bit_multiplier_right,
        b_sign,
        bit_shift_carry,
        num_cols: num_witin as u32,
    }
}
