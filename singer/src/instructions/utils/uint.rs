use std::marker::PhantomData;

use frontend::structs::{CellId, CircuitBuilder, ConstantType};
use goldilocks::SmallField;
use itertools::Itertools;

use crate::{constants::RANGE_CHIP_BIT_WIDTH, error::ZKVMError};

use super::UInt;

pub(in crate::instructions) mod add_sub;
pub(in crate::instructions) mod cmp;

impl<const M: usize, const C: usize> TryFrom<&[usize]> for UInt<M, C> {
    type Error = ZKVMError;
    fn try_from(values: &[usize]) -> Result<Self, Self::Error> {
        if values.len() != Self::N_OPRAND_CELLS {
            return Err(ZKVMError::CircuitError);
        }
        Ok(Self {
            values: values.to_vec(),
        })
    }
}

impl<const M: usize, const C: usize> TryFrom<Vec<usize>> for UInt<M, C> {
    type Error = ZKVMError;
    fn try_from(values: Vec<usize>) -> Result<Self, Self::Error> {
        let values = values.as_slice().try_into()?;
        Ok(values)
    }
}

impl<const M: usize, const C: usize> UInt<M, C> {
    pub(in crate::instructions) const N_OPRAND_CELLS: usize = (M + C - 1) / C;

    const N_CARRY_CELLS: usize = Self::N_OPRAND_CELLS;
    const N_CARRY_NO_OVERFLOW_CELLS: usize = Self::N_OPRAND_CELLS - 1;
    pub(in crate::instructions) const N_RANGE_CHECK_CELLS: usize =
        Self::N_OPRAND_CELLS * (C + RANGE_CHIP_BIT_WIDTH - 1) / RANGE_CHIP_BIT_WIDTH;
    pub(in crate::instructions) const N_RANGE_CHECK_NO_OVERFLOW_CELLS: usize =
        (Self::N_OPRAND_CELLS - 1) * (C + RANGE_CHIP_BIT_WIDTH - 1) / RANGE_CHIP_BIT_WIDTH;

    pub(in crate::instructions) fn values(&self) -> &[CellId] {
        &self.values
    }

    pub(in crate::instructions) fn from_range_values<F: SmallField>(
        circuit_builder: &mut CircuitBuilder<F>,
        range_values: &[CellId],
    ) -> Result<Self, ZKVMError> {
        let mut values = if C <= M {
            convert_decomp(circuit_builder, range_values, RANGE_CHIP_BIT_WIDTH, C, true)
        } else {
            convert_decomp(circuit_builder, range_values, RANGE_CHIP_BIT_WIDTH, M, true)
        };
        while values.len() < Self::N_OPRAND_CELLS {
            values.push(circuit_builder.create_cell());
        }
        Self::try_from(values)
    }

    pub(in crate::instructions) fn from_bytes_big_endien<F: SmallField>(
        circuit_builder: &mut CircuitBuilder<F>,
        bytes: &[CellId],
    ) -> Result<Self, ZKVMError> {
        if C <= M {
            convert_decomp(circuit_builder, bytes, 8, C, true).try_into()
        } else {
            convert_decomp(circuit_builder, bytes, 8, M, true).try_into()
        }
    }

    pub(in crate::instructions) fn assert_eq<F: SmallField>(
        &self,
        circuit_builder: &mut CircuitBuilder<F>,
        other: &Self,
    ) {
        for i in 0..self.values.len() {
            let diff = circuit_builder.create_cell();
            circuit_builder.add(diff, self.values[i], ConstantType::Field(F::ONE));
            circuit_builder.add(diff, other.values[i], ConstantType::Field(-F::ONE));
            circuit_builder.assert_const(diff, &F::ZERO);
        }
    }

    pub(in crate::instructions) fn assert_eq_range_values<F: SmallField>(
        &self,
        circuit_builder: &mut CircuitBuilder<F>,
        range_values: &[CellId],
    ) {
        let values = if C <= M {
            convert_decomp(circuit_builder, range_values, RANGE_CHIP_BIT_WIDTH, C, true)
        } else {
            convert_decomp(circuit_builder, range_values, RANGE_CHIP_BIT_WIDTH, M, true)
        };
        let length = self.values.len().min(values.len());
        for i in 0..length {
            let diff = circuit_builder.create_cell();
            circuit_builder.add(diff, self.values[i], ConstantType::Field(F::ONE));
            circuit_builder.add(diff, values[i], ConstantType::Field(-F::ONE));
            circuit_builder.assert_const(diff, &F::ZERO);
        }
        for i in length..values.len() {
            circuit_builder.assert_const(values[i], &F::ZERO);
        }
        for i in length..self.values.len() {
            circuit_builder.assert_const(self.values[i], &F::ZERO);
        }
    }
}

pub(in crate::instructions) struct UIntAddSub<UInt> {
    _phantom: PhantomData<UInt>,
}
pub(in crate::instructions) struct UIntCmp<UInt> {
    _phantom: PhantomData<UInt>,
}

/// Big-endian bytes to little-endien field values. We don't require
/// `BIG_BIT_WIDTH` % `SMALL_BIT_WIDTH` == 0 because we assume `small_values`
/// can be splitted into chunks with size ceil(BIG_BIT_WIDTH / SMALL_BIT_WIDTH).
/// Each chunk is converted to a value with BIG_BIT_WIDTH bits.
fn convert_decomp<F: SmallField>(
    circuit_builder: &mut CircuitBuilder<F>,
    small_values: &[CellId],
    small_bit_width: usize,
    big_bit_width: usize,
    is_little_endian: bool,
) -> Vec<CellId> {
    let small_values = if is_little_endian {
        small_values.to_vec()
    } else {
        small_values.iter().rev().map(|x: &usize| *x).collect_vec()
    };
    let chunk_size = (big_bit_width + small_bit_width - 1) / small_bit_width;
    let small_len = small_values.len();
    let values = (0..small_len)
        .step_by(chunk_size)
        .map(|j| {
            let tmp = circuit_builder.create_cell();
            for k in j..(j + chunk_size).min(small_len) {
                let k = k as usize;
                circuit_builder.add(
                    tmp,
                    small_values[k],
                    ConstantType::Field(F::from((1 as u64) << j * small_bit_width)),
                );
            }
            tmp
        })
        .collect_vec();
    values
}
