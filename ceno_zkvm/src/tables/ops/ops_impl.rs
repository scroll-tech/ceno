//! The implementation of ops tables. No generics.

use ff_ext::{ExtensionField, SmallField};
use gkr_iop::error::CircuitBuilderError;
use itertools::Itertools;
use rayon::iter::{IndexedParallelIterator, ParallelIterator};
use std::collections::HashMap;
use witness::{InstancePaddingStrategy, RowMajorMatrix, set_fixed_val, set_val};

use crate::{
    circuit_builder::{CircuitBuilder, SetTableSpec},
    structs::ROMType,
};
use multilinear_extensions::{Expression, Fixed, ToExpr, WitIn};

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
    ) -> Result<Self, CircuitBuilderError> {
        let abc = [
            cb.create_fixed(|| "a")?,
            cb.create_fixed(|| "b")?,
            cb.create_fixed(|| "c")?,
        ];
        let mlt = cb.create_witin(|| "mlt");

        let record_exprs = abc.into_iter().map(|f| Expression::Fixed(f)).collect_vec();

        cb.lk_table_record(
            || "record",
            SetTableSpec {
                len: Some(table_len),
                structural_witins: vec![],
            },
            rom_type,
            record_exprs,
            mlt.expr(),
        )?;

        Ok(Self { abc, mlt })
    }

    pub fn generate_fixed_traces<F: SmallField>(
        &self,
        num_fixed: usize,
        content: Vec<[u64; 3]>,
    ) -> RowMajorMatrix<F> {
        let mut fixed =
            RowMajorMatrix::<F>::new(content.len(), num_fixed, InstancePaddingStrategy::Default);

        fixed.par_rows_mut().zip(content).for_each(|(row, abc)| {
            for (col, val) in self.abc.iter().zip(abc.iter()) {
                set_fixed_val!(row, *col, F::from_v(*val));
            }
        });

        fixed
    }

    pub fn assign_instances<F: SmallField>(
        &self,
        num_witin: usize,
        num_structural_witin: usize,
        multiplicity: &HashMap<u64, usize>,
        length: usize,
    ) -> Result<[RowMajorMatrix<F>; 2], CircuitBuilderError> {
        assert_eq!(num_structural_witin, 0);
        let mut witness =
            RowMajorMatrix::<F>::new(length, num_witin, InstancePaddingStrategy::Default);

        let mut mlts = vec![0; length];
        for (idx, mlt) in multiplicity {
            mlts[*idx as usize] = *mlt;
        }

        witness.par_rows_mut().zip(mlts).for_each(|(row, mlt)| {
            set_val!(row, self.mlt, F::from_v(mlt as u64));
        });

        Ok([witness, RowMajorMatrix::empty()])
    }
}
