use ceno_gpu::common::witgen::types::SbColumnMap;
use ff_ext::ExtensionField;

use crate::instructions::{
    gpu::utils::column_map::{
        extract_rs1, extract_rs2, extract_state, extract_uint_limbs, extract_write_mem,
    },
    riscv::memory::store_v2::StoreConfig,
};

/// Extract column map from a constructed StoreConfig (SB variant, N_ZEROS=0).
pub fn extract_sb_column_map<E: ExtensionField>(
    config: &StoreConfig<E, 0>,
    num_witin: usize,
) -> SbColumnMap {
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

    // SB-specific: 2 low_bits (bit_0, bit_1)
    assert_eq!(
        config.memory_addr.low_bits.len(),
        2,
        "SB should have 2 low_bits"
    );
    let mem_addr_bit_0 = config.memory_addr.low_bits[0].id as u32;
    let mem_addr_bit_1 = config.memory_addr.low_bits[1].id as u32;

    // MemWordUtil fields (SB has N_ZEROS=0 so these exist)
    let mem_word_util = config
        .next_memory_value
        .as_ref()
        .expect("SB must have next_memory_value (MemWordUtil)");
    assert_eq!(mem_word_util.prev_limb_bytes.len(), 2);
    let prev_limb_bytes: [u32; 2] = [
        mem_word_util.prev_limb_bytes[0].id as u32,
        mem_word_util.prev_limb_bytes[1].id as u32,
    ];
    assert_eq!(mem_word_util.rs2_limb_bytes.len(), 1);
    let rs2_limb_byte = mem_word_util.rs2_limb_bytes[0].id as u32;
    let expected_limb = mem_word_util
        .expected_limb
        .as_ref()
        .expect("SB must have expected_limb")
        .id as u32;

    SbColumnMap {
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
        mem_addr_bit_0,
        mem_addr_bit_1,
        prev_limb_bytes,
        rs2_limb_byte,
        expected_limb,
        num_cols: num_witin as u32,
    }
}
