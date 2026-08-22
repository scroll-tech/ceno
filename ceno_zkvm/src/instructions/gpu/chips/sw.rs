use ceno_gpu::common::witgen::types::SwColumnMap;
use ff_ext::ExtensionField;

use crate::instructions::{
    gpu::utils::column_map::{
        extract_rs1, extract_rs2, extract_state, extract_uint_limbs, extract_write_mem,
    },
    riscv::memory::store_v2::StoreConfig,
};

/// Extract column map from a constructed StoreConfig (SW variant, N_ZEROS=2).
pub fn extract_sw_column_map<E: ExtensionField>(
    config: &StoreConfig<E, 2>,
    num_witin: usize,
) -> SwColumnMap {
    let sm = &config.s_insn;

    let (pc, ts) = extract_state(&sm.vm_state);
    let (rs1_id, rs1_prev_ts, rs1_lt_diff) = extract_rs1(&sm.rs1);
    let (rs2_id, rs2_prev_ts, rs2_lt_diff) = extract_rs2(&sm.rs2);
    let (mem_prev_ts, mem_lt_diff) = extract_write_mem(&sm.mem_write);

    let rs1_limbs = extract_uint_limbs::<E, 2, _, _>(&config.rs1_read, "rs1_read");
    let rs2_limbs = extract_uint_limbs::<E, 2, _, _>(&config.rs2_read, "rs2_read");
    let imm = config.imm.id as u32;
    let imm_sign = config.imm_sign.id as u32;
    let prev_mem_val =
        extract_uint_limbs::<E, 2, _, _>(&config.prev_memory_value, "prev_memory_value");
    let mem_addr = extract_uint_limbs::<E, 2, _, _>(&config.memory_addr.addr, "memory_addr");

    SwColumnMap {
        pc,
        ts,
        rs1_id,
        rs1_prev_ts,
        rs1_lt_diff,
        rs2_id,
        rs2_prev_ts,
        rs2_lt_diff,
        mem_prev_ts,
        mem_lt_diff,
        rs1_limbs,
        rs2_limbs,
        imm,
        imm_sign,
        prev_mem_val,
        mem_addr,
        num_cols: num_witin as u32,
    }
}
