//! The implementation of range tables. No generics.

use ff_ext::{ExtensionField, SmallField};
use gkr_iop::{error::CircuitBuilderError, tables::LookupTable};
use rayon::iter::{IndexedParallelIterator, IntoParallelRefIterator, ParallelIterator};
use std::collections::HashMap;
use witness::{InstancePaddingStrategy, RowMajorMatrix, set_val};

use crate::{
    circuit_builder::{CircuitBuilder, SetTableSpec},
    structs::ROMType,
};
use multilinear_extensions::{StructuralWitIn, StructuralWitInType, ToExpr, WitIn};

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
    ) -> Result<Self, CircuitBuilderError> {
        let range = cb.create_structural_witin(
            || "structural range witin",
            StructuralWitInType::EqualDistanceSequence {
                max_len: table_len,
                offset: 0,
                multi_factor: 1,
                descending: false,
            },
        );
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
    ) -> Result<[RowMajorMatrix<F>; 2], CircuitBuilderError> {
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
                set_val!(row, self.mlt, F::from_canonical_u64(mlt as u64));
                set_val!(structural_row, self.range, F::from_canonical_u64(i));
            });

        Ok([witness, structural_witness])
    }
}

#[derive(Clone, Debug)]
pub struct DynamicRangeTableConfig {
    range: StructuralWitIn,
    bits: StructuralWitIn,
    mlt: WitIn,
}

impl DynamicRangeTableConfig {
    pub fn construct_circuit<E: ExtensionField>(
        cb: &mut CircuitBuilder<E>,
        max_bits: usize,
    ) -> Result<Self, CircuitBuilderError> {
        let range = cb.create_structural_witin(
            || "structural range witin",
            StructuralWitInType::StackedIncrementalSequence { max_bits },
        );
        let bits = cb.create_structural_witin(
            || "structural bits witin",
            StructuralWitInType::StackedConstantSequence {
                max_value: max_bits,
            },
        );
        let mlt = cb.create_witin(|| "mlt");

        let record_exprs = vec![range.expr(), bits.expr()];

        cb.lk_table_record(
            || "record",
            SetTableSpec {
                len: Some(1 << (max_bits + 1)),
                structural_witins: vec![range],
            },
            LookupTable::Dynamic,
            record_exprs,
            mlt.expr(),
        )?;

        Ok(Self { range, bits, mlt })
    }

    pub fn assign_instances<F: SmallField>(
        &self,
        num_witin: usize,
        num_structural_witin: usize,
        multiplicity: &HashMap<u64, usize>,
        max_bits: usize,
    ) -> Result<[RowMajorMatrix<F>; 2], CircuitBuilderError> {
        let length = 1 << (max_bits + 1);
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

        let range_content = std::iter::once(F::ZERO)
            .chain((0..=max_bits).flat_map(|i| (0..(1 << i)).map(|j| F::from_canonical_usize(j))))
            .collect::<Vec<_>>();
        let bits_content =
            std::iter::once(F::ZERO)
                .chain((0..=max_bits).flat_map(|i| {
                    std::iter::repeat_n(i, 1 << i).map(|j| F::from_canonical_usize(j))
                }))
                .collect::<Vec<_>>();

        witness
            .par_rows_mut()
            .zip(structural_witness.par_rows_mut())
            .zip(mlts.par_iter())
            .zip(range_content.par_iter())
            .zip(bits_content.par_iter())
            .for_each(|((((row, structural_row), mlt), i), b)| {
                set_val!(row, self.mlt, F::from_canonical_u64(*mlt as u64));
                set_val!(structural_row, self.range, i);
                set_val!(structural_row, self.bits, b);
            });

        Ok([witness, structural_witness])
    }
}
