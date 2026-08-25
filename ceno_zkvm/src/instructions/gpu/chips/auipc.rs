use ceno_gpu::common::witgen::types::AuipcColumnMap;
use ff_ext::ExtensionField;

use crate::instructions::{
    gpu::utils::column_map::{extract_rd, extract_rs1, extract_state, extract_uint_limbs},
    riscv::auipc::AuipcConfig,
};

/// Extract column map from a constructed AuipcConfig.
pub fn extract_auipc_column_map<E: ExtensionField>(
    config: &AuipcConfig<E>,
    num_witin: usize,
) -> AuipcColumnMap {
    let im = &config.i_insn;

    let (pc, ts) = extract_state(&im.vm_state);
    let (rs1_id, rs1_prev_ts, rs1_lt_diff) = extract_rs1(&im.rs1);
    let (rd_id, rd_prev_ts, rd_prev_val, rd_lt_diff) = extract_rd(&im.rd);

    let rd_bytes = extract_uint_limbs::<E, 4, _, _>(&config.rd_written, "rd_written");
    let pc_limbs: [u32; 2] = [config.pc_limbs[0].id as u32, config.pc_limbs[1].id as u32];
    let imm_limbs: [u32; 3] = [
        config.imm_limbs[0].id as u32,
        config.imm_limbs[1].id as u32,
        config.imm_limbs[2].id as u32,
    ];

    AuipcColumnMap {
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
        pc_limbs,
        imm_limbs,
        num_cols: num_witin as u32,
    }
}
