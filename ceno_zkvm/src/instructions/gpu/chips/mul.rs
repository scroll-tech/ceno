use ceno_gpu::common::witgen::types::MulColumnMap;
use ff_ext::ExtensionField;

use crate::instructions::{
    gpu::utils::column_map::{
        extract_rd, extract_rs1, extract_rs2, extract_state, extract_uint_limbs,
    },
    riscv::mulh::mulh_circuit_v2::MulhConfig,
};

/// Extract column map from a constructed MulhConfig.
/// mul_kind: 0=MUL, 1=MULH, 2=MULHU, 3=MULHSU
pub fn extract_mul_column_map<E: ExtensionField>(
    config: &MulhConfig<E>,
    num_witin: usize,
) -> MulColumnMap {
    let (pc, ts) = extract_state(&config.r_insn.vm_state);
    let (rs1_id, rs1_prev_ts, rs1_lt_diff) = extract_rs1(&config.r_insn.rs1);
    let (rs2_id, rs2_prev_ts, rs2_lt_diff) = extract_rs2(&config.r_insn.rs2);
    let (rd_id, rd_prev_ts, rd_prev_val, rd_lt_diff) = extract_rd(&config.r_insn.rd);

    let rs1_limbs = extract_uint_limbs::<E, 2, _, _>(&config.rs1_read, "rs1_read");
    let rs2_limbs = extract_uint_limbs::<E, 2, _, _>(&config.rs2_read, "rs2_read");
    let rd_low: [u32; 2] = [config.rd_low[0].id as u32, config.rd_low[1].id as u32];

    // MULH/MULHU/MULHSU have rd_high + extensions; MUL does not.
    let (rd_high, rs1_ext, rs2_ext) = match config.rd_high.as_ref() {
        Some(h) => (
            Some([h[0].id as u32, h[1].id as u32]),
            Some(config.rs1_ext.expect("MULH variants must have rs1_ext").id as u32),
            Some(config.rs2_ext.expect("MULH variants must have rs2_ext").id as u32),
        ),
        None => (None, None, None),
    };

    MulColumnMap {
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
        rs1_limbs,
        rs2_limbs,
        rd_low,
        rd_high,
        rs1_ext,
        rs2_ext,
        num_cols: num_witin as u32,
    }
}
