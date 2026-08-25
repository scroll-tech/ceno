use ceno_gpu::common::witgen::types::AddiColumnMap;
use ff_ext::ExtensionField;

use crate::instructions::{
    gpu::utils::column_map::{
        extract_carries, extract_rd, extract_rs1, extract_state, extract_uint_limbs,
    },
    riscv::arith_imm::arith_imm_circuit_v2::InstructionConfig,
};

/// Extract column map from a constructed InstructionConfig (ADDI v2).
pub fn extract_addi_column_map<E: ExtensionField>(
    config: &InstructionConfig<E>,
    num_witin: usize,
) -> AddiColumnMap {
    let im = &config.i_insn;

    let (pc, ts) = extract_state(&im.vm_state);
    let (rs1_id, rs1_prev_ts, rs1_lt_diff) = extract_rs1(&im.rs1);
    let (rd_id, rd_prev_ts, rd_prev_val, rd_lt_diff) = extract_rd(&im.rd);

    let rs1_limbs = extract_uint_limbs::<E, 2, _, _>(&config.rs1_read, "rs1_read");
    let imm = config.imm.id as u32;
    let imm_sign = config.imm_sign.id as u32;
    let rd_carries = extract_carries::<E, 2, _, _>(&config.rd_written, "rd_written");

    AddiColumnMap {
        pc,
        ts,
        rs1_id,
        rs1_prev_ts,
        rs1_lt_diff,
        rd_id,
        rd_prev_ts,
        rd_prev_val,
        rd_lt_diff,
        rs1_limbs,
        imm,
        imm_sign,
        rd_carries,
        num_cols: num_witin as u32,
    }
}
