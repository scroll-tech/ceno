//! The implementation of range tables. No generics.

use ff_ext::ExtensionField;
use goldilocks::SmallField;
use rayon::iter::{IndexedParallelIterator, IntoParallelIterator, ParallelIterator};
use std::{collections::HashMap, mem::MaybeUninit};

use crate::{
    circuit_builder::CircuitBuilder,
    error::ZKVMError,
    expression::{Expression, Fixed, ToExpr, WitIn},
    scheme::constants::MIN_PAR_SIZE,
    set_fixed_val, set_val,
    structs::ROMType,
    witness::RowMajorMatrix,
};

#[derive(Clone, Debug)]
pub struct RangeTableConfig {
    fixed: Fixed,
    mlt: WitIn,
}

impl RangeTableConfig {
    pub fn construct_circuit<E: ExtensionField>(
        cb: &mut CircuitBuilder<E>,
        rom_type: ROMType,
    ) -> Result<Self, ZKVMError> {
        let fixed = cb.create_fixed(|| "fixed")?;
        let mlt = cb.create_witin(|| "mlt")?;

        let rlc_record = cb.rlc_chip_record(vec![
            (rom_type as usize).into(),
            Expression::Fixed(fixed.clone()),
        ]);

        cb.lk_table_record(|| "record", rlc_record, mlt.expr())?;

        Ok(Self { fixed, mlt })
    }

    pub fn generate_fixed_traces<F: SmallField>(
        &self,
        num_fixed: usize,
        content: Vec<u64>,
    ) -> RowMajorMatrix<F> {
        let mut fixed = RowMajorMatrix::<F>::new(content.len(), num_fixed);

        // Fill the padding with zeros, if any.
        fixed.par_iter_mut().skip(content.len()).for_each(|row| {
            set_fixed_val!(row, self.fixed, F::ZERO);
        });

        fixed
            .par_iter_mut()
            .with_min_len(MIN_PAR_SIZE)
            .zip(content.into_par_iter())
            .for_each(|(row, i)| {
                set_fixed_val!(row, self.fixed, F::from(i));
            });

        fixed
    }

    pub fn assign_instances<F: SmallField>(
        &self,
        num_witin: usize,
        multiplicity: &HashMap<u64, usize>,
        length: usize,
    ) -> Result<RowMajorMatrix<F>, ZKVMError> {
        let mut witness = RowMajorMatrix::<F>::new(length, num_witin);

        let mut mlts = vec![0; length];
        for (idx, mlt) in multiplicity {
            mlts[*idx as usize] = *mlt;
        }

        // Fill the padding with zeros, if any.
        witness.par_iter_mut().skip(length).for_each(|row| {
            set_val!(row, self.mlt, F::ZERO);
        });

        witness
            .par_iter_mut()
            .with_min_len(MIN_PAR_SIZE)
            .zip(mlts.into_par_iter())
            .for_each(|(row, mlt)| {
                set_val!(row, self.mlt, F::from(mlt as u64));
            });

        Ok(witness)
    }
}
