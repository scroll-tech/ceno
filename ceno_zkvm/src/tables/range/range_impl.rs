//! The implementation of range tables. No generics.

use ff_ext::ExtensionField;
use goldilocks::SmallField;
use rayon::iter::{IndexedParallelIterator, IntoParallelIterator, ParallelIterator};
use std::collections::HashMap;

use crate::{
    circuit_builder::{CircuitBuilder, SetTableSpec},
    error::ZKVMError,
    expression::{StructuralWitIn, ToExpr, WitIn},
    instructions::InstancePaddingStrategy,
    scheme::constants::MIN_PAR_SIZE,
    set_val,
    structs::ROMType,
    witness::RowMajorMatrix,
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
        let range = cb.create_structural_witin(|| "structural range witin", table_len, 0, 1);
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
    ) -> Result<RowMajorMatrix<F>, ZKVMError> {
        let mut witness = RowMajorMatrix::<F>::new(
            length,
            num_witin + num_structural_witin,
            InstancePaddingStrategy::Default,
        );

        let mut mlts = vec![0; length];
        for (idx, mlt) in multiplicity {
            mlts[*idx as usize] = *mlt;
        }

        let offset_range = StructuralWitIn {
            id: self.range.id + (num_witin as u16),
            ..self.range
        };

        witness
            .par_iter_mut()
            .with_min_len(MIN_PAR_SIZE)
            .zip(mlts.into_par_iter())
            .zip(content.into_par_iter())
            .for_each(|((row, mlt), i)| {
                set_val!(row, self.mlt, F::from(mlt as u64));
                set_val!(row, offset_range, F::from(i));
            });

        Ok(witness)
    }
}
