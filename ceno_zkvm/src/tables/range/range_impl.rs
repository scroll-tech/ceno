//! The implementation of range tables. No generics.

use ff_ext::{ExtensionField, SmallField};
use gkr_iop::{error::CircuitBuilderError, tables::LookupTable};
use rayon::iter::{IndexedParallelIterator, IntoParallelRefIterator, ParallelIterator};
use std::collections::HashMap;
use witness::{InstancePaddingStrategy, RowMajorMatrix, set_val};

use crate::{
    circuit_builder::{CircuitBuilder, SetTableSpec},
    structs::{ROMType, WitnessId},
};
use multilinear_extensions::{
    StructuralWitIn, StructuralWitInType, StructuralWitInType::EqualDistanceSequence, ToExpr, WitIn,
};

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
                structural_witins: vec![range, bits],
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
        let selector_witin = StructuralWitIn {
            id: num_structural_witin as WitnessId - 1,
            // type doesn't matter
            witin_type: EqualDistanceSequence {
                max_len: 0,
                offset: 0,
                multi_factor: 0,
                descending: false,
            },
        }; // last witin id is selector

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
                structural_row[selector_witin.id as usize] = F::ONE;
            });

        Ok([witness, structural_witness])
    }
}

#[derive(Clone, Debug)]
pub struct DoubleRangeTableConfig {
    range_a: StructuralWitIn,
    range_a_bits: usize,
    range_b: StructuralWitIn,
    range_b_bits: usize,
    mlt: WitIn,
}

impl DoubleRangeTableConfig {
    pub fn construct_circuit<E: ExtensionField>(
        cb: &mut CircuitBuilder<E>,
        rom_type: ROMType,
        range_a_bits: usize,
        range_b_bits: usize,
    ) -> Result<Self, CircuitBuilderError> {
        let range_a = cb.create_structural_witin(
            || "structural range witin a",
            StructuralWitInType::InnerRepeatingIncrementalSequence {
                k: range_a_bits,
                n: range_a_bits + range_b_bits,
            },
        );
        let range_b = cb.create_structural_witin(
            || "structural range witin b",
            StructuralWitInType::OuterRepeatingIncrementalSequence {
                k: range_a_bits,
                n: range_a_bits + range_b_bits,
            },
        );
        let mlt = cb.create_witin(|| "mlt");

        let record_exprs = vec![range_a.expr(), range_b.expr()];

        cb.lk_table_record(
            || "record",
            SetTableSpec {
                len: Some(1 << (range_a_bits + range_b_bits)),
                structural_witins: vec![range_a, range_b],
            },
            rom_type,
            record_exprs,
            mlt.expr(),
        )?;

        Ok(Self {
            range_a,
            range_a_bits,
            range_b,
            range_b_bits,
            mlt,
        })
    }

    pub fn assign_instances<F: SmallField>(
        &self,
        num_witin: usize,
        num_structural_witin: usize,
        multiplicity: &HashMap<u64, usize>,
    ) -> Result<[RowMajorMatrix<F>; 2], CircuitBuilderError> {
        let length = 1 << (self.range_a_bits + self.range_b_bits);
        let mut witness: RowMajorMatrix<F> =
            RowMajorMatrix::<F>::new(length, num_witin, InstancePaddingStrategy::Default);
        let mut structural_witness = RowMajorMatrix::<F>::new(
            length,
            num_structural_witin,
            InstancePaddingStrategy::Default,
        );
        let selector_witin = StructuralWitIn {
            id: num_structural_witin as WitnessId - 1,
            // type doesn't matter
            witin_type: EqualDistanceSequence {
                max_len: 0,
                offset: 0,
                multi_factor: 0,
                descending: false,
            },
        }; // last witin id is selector

        let mut mlts = vec![0; length];
        for (idx, mlt) in multiplicity {
            mlts[*idx as usize] = *mlt;
        }

        witness
            .par_rows_mut()
            .zip(structural_witness.par_rows_mut())
            .zip(mlts.par_iter().enumerate())
            .for_each(|((row, structural_row), (idx, mlt))| {
                let a = idx >> self.range_a_bits;
                let b = idx & ((1 << self.range_a_bits) - 1);
                set_val!(row, self.mlt, F::from_canonical_u64(*mlt as u64));
                set_val!(structural_row, self.range_a, F::from_canonical_usize(a));
                set_val!(structural_row, self.range_b, F::from_canonical_usize(b));
                structural_row[selector_witin.id as usize] = F::ONE;
            });

        Ok([witness, structural_witness])
    }
}
