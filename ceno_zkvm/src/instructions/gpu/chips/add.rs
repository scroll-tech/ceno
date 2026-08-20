use ceno_gpu::common::witgen::types::AddColumnMap;
use ff_ext::ExtensionField;

use crate::instructions::{
    gpu::utils::column_map::{
        extract_carries, extract_rd, extract_rs1, extract_rs2, extract_state, extract_uint_limbs,
    },
    riscv::arith::ArithConfig,
};

/// Extract column map from a constructed ArithConfig (ADD variant).
///
/// This reads all WitIn.id values from the config tree and packs them
/// into an AddColumnMap suitable for GPU kernel dispatch.
pub fn extract_add_column_map<E: ExtensionField>(
    config: &ArithConfig<E>,
    num_witin: usize,
) -> AddColumnMap {
    let (pc, ts) = extract_state(&config.r_insn.vm_state);
    let (rs1_id, rs1_prev_ts, rs1_lt_diff) = extract_rs1(&config.r_insn.rs1);
    let (rs2_id, rs2_prev_ts, rs2_lt_diff) = extract_rs2(&config.r_insn.rs2);
    let (rd_id, rd_prev_ts, rd_prev_val, rd_lt_diff) = extract_rd(&config.r_insn.rd);

    let rs1_limbs = extract_uint_limbs::<E, 2, _, _>(&config.rs1_read, "rs1_read");
    let rs2_limbs = extract_uint_limbs::<E, 2, _, _>(&config.rs2_read, "rs2_read");
    let rd_carries = extract_carries::<E, 2, _, _>(&config.rd_written, "rd_written");

    AddColumnMap {
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
        rd_carries,
        num_cols: num_witin as u32,
    }
}
