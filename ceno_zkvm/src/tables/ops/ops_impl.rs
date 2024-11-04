//! The implementation of ops tables. No generics.

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
pub struct OpTableConfig {
    abc: [Fixed; 3],
    mlt: WitIn,
}

impl OpTableConfig {
    pub fn construct_circuit<E: ExtensionField>(
        cb: &mut CircuitBuilder<E>,
        rom_type: ROMType,
        table_len: usize,
    ) -> Result<Self, ZKVMError> {
        let abc = [
            cb.create_fixed(|| "a")?,
            cb.create_fixed(|| "b")?,
            cb.create_fixed(|| "c")?,
        ];
        let mlt = cb.create_witin(|| "mlt");

        let rlc_record = cb.rlc_chip_record(vec![
            (rom_type as usize).into(),
            Expression::Fixed(abc[0]),
            Expression::Fixed(abc[1]),
            Expression::Fixed(abc[2]),
        ]);

        cb.lk_table_record(|| "record", table_len, rlc_record, mlt.expr())?;

        Ok(Self { abc, mlt })
    }

    pub fn generate_fixed_traces<F: SmallField>(
        &self,
        num_fixed: usize,
        content: Vec<[u64; 3]>,
    ) -> RowMajorMatrix<F> {
        let mut fixed = RowMajorMatrix::<F>::new(content.len(), num_fixed);

        fixed
            .par_iter_mut()
            .with_min_len(MIN_PAR_SIZE)
            .zip(content.into_par_iter())
            .for_each(|(row, abc)| {
                for (col, val) in self.abc.iter().zip(abc.iter()) {
                    set_fixed_val!(row, *col, F::from(*val));
                }
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
