use ceno_gpu::common::witgen::types::ShardRamColumnMap;
use ff_ext::ExtensionField;

use crate::tables::ShardRamConfig;

/// Extract column map from a constructed ShardRamConfig.
///
/// This reads all WitIn.id values from the config and packs them
/// into a ShardRamColumnMap suitable for GPU kernel dispatch.
pub fn extract_shard_ram_column_map<E: ExtensionField>(
    config: &ShardRamConfig<E>,
    num_witin: usize,
) -> ShardRamColumnMap {
    let addr = config.addr.id as u32;
    let is_ram_register = config.is_ram_register.id as u32;

    let value_limbs = config
        .value
        .wits_in()
        .expect("value should have WitIn limbs");
    assert_eq!(value_limbs.len(), 2, "Expected 2 value limbs");
    let value = [value_limbs[0].id as u32, value_limbs[1].id as u32];

    let shard = config.shard.id as u32;
    let global_clk = config.global_clk.id as u32;
    let local_clk = config.local_clk.id as u32;
    let nonce = config.nonce.id as u32;
    let is_global_write = config.is_global_write.id as u32;

    let mut x = [0u32; 7];
    let mut y = [0u32; 7];
    let mut slope = [0u32; 7];
    for i in 0..7 {
        x[i] = config.x[i].id as u32;
        y[i] = config.y[i].id as u32;
        slope[i] = config.slope[i].id as u32;
    }

    // Poseidon2 columns: p3_cols are contiguous, followed by post_linear_layer_cols
    let poseidon2_base_col = config.perm_config.p3_cols[0].id as u32;
    let num_p3_cols = config.perm_config.p3_cols.len() as u32;
    let num_post_linear = config.perm_config.post_linear_layer_cols.len() as u32;
    let num_poseidon2_cols = num_p3_cols + num_post_linear;

    // Verify contiguity: p3_cols should be contiguous
    for (i, col) in config.perm_config.p3_cols.iter().enumerate() {
        debug_assert_eq!(
            col.id as u32,
            poseidon2_base_col + i as u32,
            "p3_cols not contiguous at index {}",
            i
        );
    }
    // post_linear_layer_cols should be contiguous after p3_cols
    let post_base = poseidon2_base_col + num_p3_cols;
    for (i, col) in config.perm_config.post_linear_layer_cols.iter().enumerate() {
        debug_assert_eq!(
            col.id as u32,
            post_base + i as u32,
            "post_linear_layer_cols not contiguous at index {}",
            i
        );
    }

    ShardRamColumnMap {
        addr,
        is_ram_register,
        value,
        shard,
        global_clk,
        local_clk,
        nonce,
        is_global_write,
        x,
        y,
        slope,
        poseidon2_base_col,
        num_poseidon2_cols,
        num_p3_cols,
        num_cols: num_witin as u32,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        circuit_builder::{CircuitBuilder, ConstraintSystem},
        structs::ProgramParams,
        tables::{ShardRamCircuit, TableCircuit},
    };
    use ff_ext::BabyBearExt4;

    type E = BabyBearExt4;

    #[test]
    fn test_extract_shard_ram_column_map() {
        let mut cs = ConstraintSystem::<E>::new(|| "test");
        let mut cb = CircuitBuilder::new(&mut cs);
        let (config, _gkr_circuit) =
            ShardRamCircuit::<E>::build_gkr_iop_circuit(&mut cb, &ProgramParams::default())
                .unwrap();

        let col_map = extract_shard_ram_column_map(&config, cb.cs.num_witin as usize);
        let flat = col_map.to_flat();

        // Basic columns should be in range
        // (excluding poseidon2 meta entries which are counts, not column IDs)
        for (i, &col) in flat[..30].iter().enumerate() {
            assert!(
                (col as usize) < col_map.num_cols as usize,
                "Column {} (flat index {}) out of range: {} >= {}",
                col,
                i,
                col,
                col_map.num_cols
            );
        }

        // Check uniqueness of actual column IDs (first 30 entries)
        let mut seen = std::collections::HashSet::new();
        for &col in &flat[..30] {
            assert!(seen.insert(col), "Duplicate column ID: {}", col);
        }

        // Verify Poseidon2 column counts are reasonable
        assert_eq!(col_map.num_p3_cols, 299, "Expected 299 p3 cols");
        assert_eq!(
            col_map.num_poseidon2_cols, 344,
            "Expected 344 total Poseidon2 cols"
        );
    }
}
