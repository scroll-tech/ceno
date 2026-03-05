use ceno_gpu::common::witgen_types::LogicIColumnMap;
use ff_ext::ExtensionField;

use crate::instructions::riscv::logic_imm::logic_imm_circuit_v2::LogicConfig;

/// Extract column map from a constructed LogicConfig (I-type v2: ANDI/ORI/XORI).
pub fn extract_logic_i_column_map<E: ExtensionField>(
    config: &LogicConfig<E>,
    num_witin: usize,
) -> LogicIColumnMap {
    let im = &config.i_insn;

    // StateInOut
    let pc = im.vm_state.pc.id as u32;
    let ts = im.vm_state.ts.id as u32;

    // ReadRS1
    let rs1_id = im.rs1.id.id as u32;
    let rs1_prev_ts = im.rs1.prev_ts.id as u32;
    let rs1_lt_diff: [u32; 2] = {
        let d = &im.rs1.lt_cfg.0.diff;
        assert_eq!(d.len(), 2);
        [d[0].id as u32, d[1].id as u32]
    };

    // WriteRD
    let rd_id = im.rd.id.id as u32;
    let rd_prev_ts = im.rd.prev_ts.id as u32;
    let rd_prev_val: [u32; 2] = {
        let l = im.rd.prev_value.wits_in().expect("rd prev_value WitIns");
        assert_eq!(l.len(), 2);
        [l[0].id as u32, l[1].id as u32]
    };
    let rd_lt_diff: [u32; 2] = {
        let d = &im.rd.lt_cfg.0.diff;
        assert_eq!(d.len(), 2);
        [d[0].id as u32, d[1].id as u32]
    };

    // rs1 u8 bytes
    let rs1_bytes: [u32; 4] = {
        let l = config.rs1_read.wits_in().expect("rs1_read WitIns");
        assert_eq!(l.len(), 4);
        [l[0].id as u32, l[1].id as u32, l[2].id as u32, l[3].id as u32]
    };

    // rd u8 bytes
    let rd_bytes: [u32; 4] = {
        let l = config.rd_written.wits_in().expect("rd_written WitIns");
        assert_eq!(l.len(), 4);
        [l[0].id as u32, l[1].id as u32, l[2].id as u32, l[3].id as u32]
    };

    // imm_lo u8 bytes (UIntLimbs<16,8> = 2 x u8)
    let imm_lo_bytes: [u32; 2] = {
        let l = config.imm_lo.wits_in().expect("imm_lo WitIns");
        assert_eq!(l.len(), 2);
        [l[0].id as u32, l[1].id as u32]
    };

    // imm_hi u8 bytes (UIntLimbs<16,8> = 2 x u8)
    let imm_hi_bytes: [u32; 2] = {
        let l = config.imm_hi.wits_in().expect("imm_hi WitIns");
        assert_eq!(l.len(), 2);
        [l[0].id as u32, l[1].id as u32]
    };

    LogicIColumnMap {
        pc,
        ts,
        rs1_id,
        rs1_prev_ts,
        rs1_lt_diff,
        rd_id,
        rd_prev_ts,
        rd_prev_val,
        rd_lt_diff,
        rs1_bytes,
        rd_bytes,
        imm_lo_bytes,
        imm_hi_bytes,
        num_cols: num_witin as u32,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        circuit_builder::{CircuitBuilder, ConstraintSystem},
        instructions::{Instruction, riscv::logic_imm::AndiInstruction},
        structs::ProgramParams,
    };
    use ff_ext::BabyBearExt4;

    type E = BabyBearExt4;

    #[test]
    fn test_extract_logic_i_column_map() {
        let mut cs = ConstraintSystem::<E>::new(|| "test_logic_i");
        let mut cb = CircuitBuilder::new(&mut cs);
        let config =
            AndiInstruction::<E>::construct_circuit(&mut cb, &ProgramParams::default()).unwrap();

        let col_map = extract_logic_i_column_map(&config, cb.cs.num_witin as usize);
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
