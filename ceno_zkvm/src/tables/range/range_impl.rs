//! The implementation of range tables. No generics.

use ff_ext::{ExtensionField, SmallField};
use rayon::iter::{IndexedParallelIterator, ParallelIterator};
use std::collections::HashMap;
use witness::{InstancePaddingStrategy, RowMajorMatrix};

use crate::{
    circuit_builder::{CircuitBuilder, SetTableSpec},
    error::ZKVMError,
    expression::{StructuralWitIn, ToExpr, WitIn},
    set_val,
    structs::ROMType,
};

#[derive(Clone, Debug)]
pub struct RangeTableConfig {
    range: StructuralWitIn,
    mlt: WitIn,
}

impl RangeTableConfig {
    pub fn construct_circuit<E: ExtensionField>(
        cb: &mut CircuitBuilder<E>,
        rom_type: ROMType,
        table_len: usize,
    ) -> Result<Self, ZKVMError> {
        let range = cb.create_structural_witin(|| "structural range witin", table_len, 0, 1, false);
        let mlt = cb.create_witin(|| "mlt");

        let record_exprs = vec![range.expr()];

        cb.lk_table_record(
            || "record",
            SetTableSpec {
                len: Some(table_len),
                structural_witins: vec![range],
            },
            rom_type,
            record_exprs,
            mlt.expr(),
        )?;

        Ok(Self { range, mlt })
    }

    pub fn assign_instances<F: SmallField>(
        &self,
        num_witin: usize,
        num_structural_witin: usize,
        multiplicity: &HashMap<u64, usize>,
        content: Vec<u64>,
        length: usize,
    ) -> Result<[RowMajorMatrix<F>; 2], ZKVMError> {
        let mut witness: RowMajorMatrix<F> =
            RowMajorMatrix::<F>::new(length, num_witin, InstancePaddingStrategy::Default);
        let mut structural_witness = RowMajorMatrix::<F>::new(
            length,
            num_structural_witin,
            InstancePaddingStrategy::Default,
        );

        let mut mlts = vec![0; length];
        for (idx, mlt) in multiplicity {
            mlts[*idx as usize] = *mlt;
        }

        witness
            .par_rows_mut()
            .zip(structural_witness.par_rows_mut())
            .zip(mlts)
            .zip(content)
            .for_each(|(((row, structural_row), mlt), i)| {
                set_val!(row, self.mlt, F::from_u64(mlt as u64));
                set_val!(structural_row, self.range, F::from_u64(i));
            });

        Ok([witness, structural_witness])
    }
}
