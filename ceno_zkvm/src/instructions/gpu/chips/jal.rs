use ceno_gpu::common::witgen::types::JalColumnMap;
use ff_ext::ExtensionField;

use crate::instructions::{
    gpu::utils::column_map::{extract_rd, extract_state_branching, extract_uint_limbs},
    riscv::jump::jal_v2::JalConfig,
};

/// Extract column map from a constructed JalConfig.
pub fn extract_jal_column_map<E: ExtensionField>(
    config: &JalConfig<E>,
    num_witin: usize,
) -> JalColumnMap {
    let jm = &config.j_insn;

    let (pc, next_pc, ts) = extract_state_branching(&jm.vm_state);
    let (rd_id, rd_prev_ts, rd_prev_val, rd_lt_diff) = extract_rd(&jm.rd);
    let rd_bytes = extract_uint_limbs::<E, 4, _, _>(&config.rd_written, "rd_written");

    JalColumnMap {
        pc,
        next_pc,
        ts,
        rd_id,
        rd_prev_ts,
        rd_prev_val,
        rd_lt_diff,
        rd_bytes,
        num_cols: num_witin as u32,
    }
}
