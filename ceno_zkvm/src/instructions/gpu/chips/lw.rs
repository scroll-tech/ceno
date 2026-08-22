use ceno_gpu::common::witgen::types::LwColumnMap;
use ff_ext::ExtensionField;

use crate::instructions::gpu::utils::column_map::{
    extract_rd, extract_read_mem, extract_rs1, extract_state, extract_uint_limbs,
};

#[cfg(not(feature = "u16limb_circuit"))]
use crate::instructions::riscv::memory::load::LoadConfig;
#[cfg(feature = "u16limb_circuit")]
use crate::instructions::riscv::memory::load_v2::LoadConfig;

/// Extract column map from a constructed LoadConfig (LW variant).
pub fn extract_lw_column_map<E: ExtensionField>(
    config: &LoadConfig<E>,
    num_witin: usize,
) -> LwColumnMap {
    let im = &config.im_insn;

    let (pc, ts) = extract_state(&im.vm_state);
    let (rs1_id, rs1_prev_ts, rs1_lt_diff) = extract_rs1(&im.rs1);
    let (rd_id, rd_prev_ts, rd_prev_val, rd_lt_diff) = extract_rd(&im.rd);
    let (mem_prev_ts, mem_lt_diff) = extract_read_mem(&im.mem_read);

    let rs1_limbs = extract_uint_limbs::<E, 2, _, _>(&config.rs1_read, "rs1_read");
    let imm = config.imm.id as u32;
    #[cfg(feature = "u16limb_circuit")]
    let imm_sign = Some(config.imm_sign.id as u32);
    #[cfg(not(feature = "u16limb_circuit"))]
    let imm_sign = None;
    let mem_addr_limbs = extract_uint_limbs::<E, 2, _, _>(&config.memory_addr.addr, "memory_addr");
    let mem_read_limbs = extract_uint_limbs::<E, 2, _, _>(&config.memory_read, "memory_read");

    LwColumnMap {
        pc,
        ts,
        rs1_id,
        rs1_prev_ts,
        rs1_lt_diff,
        rd_id,
        rd_prev_ts,
        rd_prev_val,
        rd_lt_diff,
        mem_prev_ts,
        mem_lt_diff,
        rs1_limbs,
        imm,
        imm_sign,
        mem_addr_limbs,
        mem_read_limbs,
        num_cols: num_witin as u32,
    }
}
