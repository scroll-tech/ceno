use ceno_gpu::common::witgen_types::AuipcColumnMap;
use ff_ext::ExtensionField;

use crate::instructions::riscv::auipc::AuipcConfig;

/// Extract column map from a constructed AuipcConfig.
pub fn extract_auipc_column_map<E: ExtensionField>(
    config: &AuipcConfig<E>,
    num_witin: usize,
) -> AuipcColumnMap {
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

    // AUIPC-specific
    let rd_bytes: [u32; 4] = {
        let l = config.rd_written.wits_in().expect("rd_written UInt8 WitIns");
        assert_eq!(l.len(), 4);
        [l[0].id as u32, l[1].id as u32, l[2].id as u32, l[3].id as u32]
    };
    let pc_limbs: [u32; 2] = [
        config.pc_limbs[0].id as u32,
        config.pc_limbs[1].id as u32,
    ];
    let imm_limbs: [u32; 3] = [
        config.imm_limbs[0].id as u32,
        config.imm_limbs[1].id as u32,
        config.imm_limbs[2].id as u32,
    ];

    AuipcColumnMap {
        pc,
        ts,
        rs1_id,
        rs1_prev_ts,
        rs1_lt_diff,
        rd_id,
        rd_prev_ts,
        rd_prev_val,
        rd_lt_diff,
        rd_bytes,
        pc_limbs,
        imm_limbs,
        num_cols: num_witin as u32,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        circuit_builder::{CircuitBuilder, ConstraintSystem},
        instructions::{Instruction, riscv::auipc::AuipcInstruction},
        structs::ProgramParams,
    };
    use ff_ext::BabyBearExt4;

    type E = BabyBearExt4;

    #[test]
    fn test_extract_auipc_column_map() {
        let mut cs = ConstraintSystem::<E>::new(|| "test_auipc");
        let mut cb = CircuitBuilder::new(&mut cs);
        let config =
            AuipcInstruction::<E>::construct_circuit(&mut cb, &ProgramParams::default()).unwrap();

        let col_map = extract_auipc_column_map(&config, cb.cs.num_witin as usize);
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
