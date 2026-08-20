use ceno_gpu::common::witgen::types::LogicRColumnMap;
use ff_ext::ExtensionField;

use crate::instructions::{
    gpu::utils::column_map::{
        extract_rd, extract_rs1, extract_rs2, extract_state, extract_uint_limbs,
    },
    riscv::logic::logic_circuit::LogicConfig,
};

/// Extract column map from a constructed LogicConfig (R-type: AND/OR/XOR).
pub fn extract_logic_r_column_map<E: ExtensionField>(
    config: &LogicConfig<E>,
    num_witin: usize,
) -> LogicRColumnMap {
    let (pc, ts) = extract_state(&config.r_insn.vm_state);
    let (rs1_id, rs1_prev_ts, rs1_lt_diff) = extract_rs1(&config.r_insn.rs1);
    let (rs2_id, rs2_prev_ts, rs2_lt_diff) = extract_rs2(&config.r_insn.rs2);
    let (rd_id, rd_prev_ts, rd_prev_val, rd_lt_diff) = extract_rd(&config.r_insn.rd);

    let rs1_bytes = extract_uint_limbs::<E, 4, _, _>(&config.rs1_read, "rs1_read");
    let rs2_bytes = extract_uint_limbs::<E, 4, _, _>(&config.rs2_read, "rs2_read");
    let rd_bytes = extract_uint_limbs::<E, 4, _, _>(&config.rd_written, "rd_written");

    LogicRColumnMap {
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
        num_cols: num_witin as u32,
    }
}
