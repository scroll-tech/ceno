use ceno_gpu::common::witgen::types::LoadSubColumnMap;
use ff_ext::ExtensionField;

use crate::instructions::{
    gpu::utils::column_map::{
        extract_rd, extract_read_mem, extract_rs1, extract_state, extract_uint_limbs,
    },
    riscv::memory::load_v2::LoadConfig,
};

/// Extract column map from a constructed LoadConfig for sub-word loads (LH/LHU/LB/LBU).
pub fn extract_load_sub_column_map<E: ExtensionField>(
    config: &LoadConfig<E>,
    num_witin: usize,
) -> LoadSubColumnMap {
    let im = &config.im_insn;

    let (pc, ts) = extract_state(&im.vm_state);
    let (rs1_id, rs1_prev_ts, rs1_lt_diff) = extract_rs1(&im.rs1);
    let (rd_id, rd_prev_ts, rd_prev_val, rd_lt_diff) = extract_rd(&im.rd);
    let (mem_prev_ts, mem_lt_diff) = extract_read_mem(&im.mem_read);

    let rs1_limbs = extract_uint_limbs::<E, 2, _, _>(&config.rs1_read, "rs1_read");
    let imm = config.imm.id as u32;
    let imm_sign = config.imm_sign.id as u32;
    let mem_addr = extract_uint_limbs::<E, 2, _, _>(&config.memory_addr.addr, "memory_addr");
    let mem_read = extract_uint_limbs::<E, 2, _, _>(&config.memory_read, "memory_read");

    // Infer variant from config: LB/LBU have 2 low_bits, LH/LHU have 1.
    let low_bits = &config.memory_addr.low_bits;
    let is_byte = low_bits.len() == 2;

    let addr_bit_1 = if is_byte {
        low_bits[1].id as u32
    } else {
        assert_eq!(low_bits.len(), 1, "LH/LHU should have 1 low_bit");
        low_bits[0].id as u32
    };

    let target_limb = config
        .target_limb
        .expect("sub-word loads must have target_limb")
        .id as u32;

    // LB/LBU: addr_bit_0, target_byte, dummy_byte
    let (addr_bit_0, target_byte, dummy_byte) = if is_byte {
        let bytes = config
            .target_limb_bytes
            .as_ref()
            .expect("LB/LBU must have target_limb_bytes");
        assert_eq!(bytes.len(), 2);
        (
            Some(low_bits[0].id as u32),
            Some(bytes[0].id as u32),
            Some(bytes[1].id as u32),
        )
    } else {
        (None, None, None)
    };

    // Signed loads have signed_extend_config
    let msb = config
        .signed_extend_config
        .as_ref()
        .map(|sec| sec.msb().id as u32);

    LoadSubColumnMap {
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
        mem_addr,
        mem_read,
        addr_bit_1,
        target_limb,
        addr_bit_0,
        target_byte,
        dummy_byte,
        msb,
        num_cols: num_witin as u32,
    }
}
