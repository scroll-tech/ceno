use ceno_gpu::common::witgen::types::LuiColumnMap;
use ff_ext::ExtensionField;

use crate::instructions::{
    gpu::utils::column_map::{extract_rd, extract_rs1, extract_state},
    riscv::lui::LuiConfig,
};

/// Extract column map from a constructed LuiConfig.
pub fn extract_lui_column_map<E: ExtensionField>(
    config: &LuiConfig<E>,
    num_witin: usize,
) -> LuiColumnMap {
    let im = &config.i_insn;

    let (pc, ts) = extract_state(&im.vm_state);
    let (rs1_id, rs1_prev_ts, rs1_lt_diff) = extract_rs1(&im.rs1);
    let (rd_id, rd_prev_ts, rd_prev_val, rd_lt_diff) = extract_rd(&im.rd);

    // LUI-specific: rd bytes (skip byte 0) + imm
    let rd_bytes: [u32; 3] = [
        config.rd_written[0].id as u32,
        config.rd_written[1].id as u32,
        config.rd_written[2].id as u32,
    ];
    let imm = config.imm.id as u32;

    LuiColumnMap {
        pc,
        ts,
        rs1_id,
        rs1_prev_ts,
        rs1_lt_diff,
        rd_id,
        rd_prev_ts,
        rd_prev_val,
        rd_lt_diff,
        rd_bytes,
        imm,
        num_cols: num_witin as u32,
    }
}
