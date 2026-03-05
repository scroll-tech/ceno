use ceno_gpu::common::witgen_types::JalColumnMap;
use ff_ext::ExtensionField;

use crate::instructions::riscv::jump::jal_v2::JalConfig;

/// Extract column map from a constructed JalConfig.
pub fn extract_jal_column_map<E: ExtensionField>(
    config: &JalConfig<E>,
    num_witin: usize,
) -> JalColumnMap {
    let jm = &config.j_insn;

    // StateInOut (J-type: has next_pc)
    let pc = jm.vm_state.pc.id as u32;
    let next_pc = jm.vm_state.next_pc.expect("JAL must have next_pc").id as u32;
    let ts = jm.vm_state.ts.id as u32;

    // WriteRD
    let rd_id = jm.rd.id.id as u32;
    let rd_prev_ts = jm.rd.prev_ts.id as u32;
    let rd_prev_val: [u32; 2] = {
        let l = jm.rd.prev_value.wits_in().expect("rd prev_value WitIns");
        assert_eq!(l.len(), 2);
        [l[0].id as u32, l[1].id as u32]
    };
    let rd_lt_diff: [u32; 2] = {
        let d = &jm.rd.lt_cfg.0.diff;
        assert_eq!(d.len(), 2);
        [d[0].id as u32, d[1].id as u32]
    };

    // JAL-specific: rd u8 bytes
    let rd_bytes: [u32; 4] = {
        let l = config.rd_written.wits_in().expect("rd_written UInt8 WitIns");
        assert_eq!(l.len(), 4);
        [l[0].id as u32, l[1].id as u32, l[2].id as u32, l[3].id as u32]
    };

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        circuit_builder::{CircuitBuilder, ConstraintSystem},
        instructions::{Instruction, riscv::jump::JalInstruction},
        structs::ProgramParams,
    };
    use ff_ext::BabyBearExt4;

    type E = BabyBearExt4;

    #[test]
    fn test_extract_jal_column_map() {
        let mut cs = ConstraintSystem::<E>::new(|| "test_jal");
        let mut cb = CircuitBuilder::new(&mut cs);
        let config =
            JalInstruction::<E>::construct_circuit(&mut cb, &ProgramParams::default()).unwrap();

        let col_map = extract_jal_column_map(&config, cb.cs.num_witin as usize);
        let flat = col_map.to_flat();

        for (i, &col) in flat.iter().enumerate() {
            assert!(
                (col as usize) < col_map.num_cols as usize,
                "Column {} (index {}) out of range: {} >= {}",
                i, col, col, col_map.num_cols
            );
        }
        let mut seen = std::collections::HashSet::new();
        for &col in &flat {
            assert!(seen.insert(col), "Duplicate column ID: {}", col);
        }
    }
}
