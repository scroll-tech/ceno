use ceno_gpu::common::witgen::types::JalrColumnMap;
use ff_ext::ExtensionField;

use crate::instructions::{
    gpu::utils::column_map::{
        extract_rd, extract_rs1, extract_state_branching, extract_uint_limbs, extract_wit_ids,
    },
    riscv::jump::jalr_v2::JalrConfig,
};

/// Extract column map from a constructed JalrConfig.
pub fn extract_jalr_column_map<E: ExtensionField>(
    config: &JalrConfig<E>,
    num_witin: usize,
) -> JalrColumnMap {
    let im = &config.i_insn;

    let (pc, next_pc, ts) = extract_state_branching(&im.vm_state);
    let (rs1_id, rs1_prev_ts, rs1_lt_diff) = extract_rs1(&im.rs1);
    let (rd_id, rd_prev_ts, rd_prev_val, rd_lt_diff) = extract_rd(&im.rd);

    let rs1_limbs = extract_uint_limbs::<E, 2, _, _>(&config.rs1_read, "rs1_read");
    let imm = config.imm.id as u32;
    let imm_sign = config.imm_sign.id as u32;
    let jump_pc_addr = extract_uint_limbs::<E, 2, _, _>(&config.jump_pc_addr.addr, "jump_pc_addr");
    let jump_pc_addr_bit =
        extract_wit_ids::<2>(&config.jump_pc_addr.low_bits, "jump_pc_addr low_bits");

    // rd_high
    let rd_high = config.rd_high.id as u32;

    JalrColumnMap {
        pc,
        next_pc,
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
        jump_pc_addr,
        jump_pc_addr_bit,
        rd_high,
        num_cols: num_witin as u32,
    }
}
