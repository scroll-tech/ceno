use ceno_gpu::common::witgen::types::LogicIColumnMap;
use ff_ext::ExtensionField;

use crate::instructions::{
    gpu::utils::column_map::{extract_rd, extract_rs1, extract_state, extract_uint_limbs},
    riscv::logic_imm::logic_imm_circuit_v2::LogicConfig,
};

/// Extract column map from a constructed LogicConfig (I-type v2: ANDI/ORI/XORI).
pub fn extract_logic_i_column_map<E: ExtensionField>(
    config: &LogicConfig<E>,
    num_witin: usize,
) -> LogicIColumnMap {
    let im = &config.i_insn;

    let (pc, ts) = extract_state(&im.vm_state);
    let (rs1_id, rs1_prev_ts, rs1_lt_diff) = extract_rs1(&im.rs1);
    let (rd_id, rd_prev_ts, rd_prev_val, rd_lt_diff) = extract_rd(&im.rd);

    let rs1_bytes = extract_uint_limbs::<E, 4, _, _>(&config.rs1_read, "rs1_read");
    let rd_bytes = extract_uint_limbs::<E, 4, _, _>(&config.rd_written, "rd_written");
    let imm_lo_bytes = extract_uint_limbs::<E, 2, _, _>(&config.imm_lo, "imm_lo");
    let imm_hi_bytes = extract_uint_limbs::<E, 2, _, _>(&config.imm_hi, "imm_hi");

    LogicIColumnMap {
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
        imm_lo_bytes,
        imm_hi_bytes,
        num_cols: num_witin as u32,
    }
}
