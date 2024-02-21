use ff::Field;
use itertools::Itertools;
use std::marker::PhantomData;

use gkr::utils::ceil_log2;
use goldilocks::SmallField;
use simple_frontend::structs::{CellId, CircuitBuilder};

use crate::{
    constants::{EVM_STACK_BIT_WIDTH, RANGE_CHIP_BIT_WIDTH, VALUE_BIT_WIDTH},
    error::ZKVMError,
};

/// Unsigned integer with `M` bits. C denotes the cell bit width.
#[derive(Clone, Debug)]
pub(crate) struct UInt<const M: usize, const C: usize> {
    values: Vec<CellId>,
}

pub(crate) type UInt64 = UInt<64, VALUE_BIT_WIDTH>;
pub(crate) type PCUInt = UInt64;
pub(crate) type TSUInt = UInt<56, 56>;
pub(crate) type StackUInt = UInt<{ EVM_STACK_BIT_WIDTH as usize }, { VALUE_BIT_WIDTH as usize }>;

pub(crate) mod add_sub;
pub(crate) mod cmp;

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
    pub(crate) const N_OPRAND_CELLS: usize = (M + C - 1) / C;

    const N_CARRY_CELLS: usize = Self::N_OPRAND_CELLS;
    const N_CARRY_NO_OVERFLOW_CELLS: usize = Self::N_OPRAND_CELLS - 1;
    pub(crate) const N_RANGE_CHECK_CELLS: usize =
        Self::N_OPRAND_CELLS * (C + RANGE_CHIP_BIT_WIDTH - 1) / RANGE_CHIP_BIT_WIDTH;
    pub(crate) const N_RANGE_CHECK_NO_OVERFLOW_CELLS: usize =
        (Self::N_OPRAND_CELLS - 1) * (C + RANGE_CHIP_BIT_WIDTH - 1) / RANGE_CHIP_BIT_WIDTH;

    pub(crate) fn values(&self) -> &[CellId] {
        &self.values
    }

    pub(crate) fn from_range_values<F: SmallField>(
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

    pub(crate) fn from_bytes_big_endien<F: SmallField>(
        circuit_builder: &mut CircuitBuilder<F>,
        bytes: &[CellId],
    ) -> Result<Self, ZKVMError> {
        if C <= M {
            convert_decomp(circuit_builder, bytes, 8, C, true).try_into()
        } else {
            convert_decomp(circuit_builder, bytes, 8, M, true).try_into()
        }
    }

    pub(crate) fn assert_eq<F: SmallField>(
        &self,
        circuit_builder: &mut CircuitBuilder<F>,
        other: &Self,
    ) {
        for i in 0..self.values.len() {
            let diff = circuit_builder.create_cell();
            circuit_builder.add(diff, self.values[i], F::BaseField::ONE);
            circuit_builder.add(diff, other.values[i], -F::BaseField::ONE);
            circuit_builder.assert_const(diff, 0);
        }
    }

    pub(crate) fn assert_eq_range_values<F: SmallField>(
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
            circuit_builder.add(diff, self.values[i], F::BaseField::ONE);
            circuit_builder.add(diff, values[i], -F::BaseField::ONE);
            circuit_builder.assert_const(diff, 0);
        }
        for i in length..values.len() {
            circuit_builder.assert_const(values[i], 0);
        }
        for i in length..self.values.len() {
            circuit_builder.assert_const(self.values[i], 0);
        }
    }

    /// Generate (0, 1, ...,  size)
    pub(crate) fn counter_vector<F: SmallField>(size: usize) -> Vec<F> {
        let num_vars = ceil_log2(size);
        let tensor = |a: &[F], b: Vec<F>| {
            let mut res = vec![F::ZERO; a.len() * b.len()];
            for i in 0..b.len() {
                for j in 0..a.len() {
                    res[i * a.len() + j] = b[i] * a[j];
                }
            }
            res
        };
        let counter = (0..(1 << C)).map(|x| F::from(x as u64)).collect_vec();
        let (di, mo) = (num_vars / C, num_vars % C);
        let mut res = (0..(1 << mo)).map(|x| F::from(x as u64)).collect_vec();
        for _ in 0..di {
            res = tensor(&counter, res);
        }
        res
    }
}

pub(crate) struct UIntAddSub<UInt> {
    _phantom: PhantomData<UInt>,
}
pub(crate) struct UIntCmp<UInt> {
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
                    F::BaseField::from((1 as u64) << j * small_bit_width),
                );
            }
            tmp
        })
        .collect_vec();
    values
}

#[cfg(test)]
mod test {
    use crate::utils::uint::convert_decomp;

    use super::UInt;
    use goldilocks::Goldilocks;
    use simple_frontend::structs::CircuitBuilder;

    #[test]
    fn test_uint() {
        // M = 256 is the number of bits for unsigned integer
        // C = 63 is the cell bit width
        type Uint256_63 = UInt<256, 63>;
        assert_eq!(Uint256_63::N_OPRAND_CELLS, 5);
        assert_eq!(Uint256_63::N_CARRY_CELLS, 5);
        assert_eq!(Uint256_63::N_CARRY_NO_OVERFLOW_CELLS, 4);
        assert_eq!(Uint256_63::N_RANGE_CHECK_CELLS, 24);
        assert_eq!(Uint256_63::N_RANGE_CHECK_NO_OVERFLOW_CELLS, 19);
        let u_int = Uint256_63::try_from(vec![1, 2, 3, 4, 5]);
        assert_eq!(u_int.unwrap().values, vec![1, 2, 3, 4, 5]);
        // TODO: implement tests for methods in UInt
        // they mostly depend on convert_decomp which will be tested separately
    }

    #[test]
    fn test_convert_decomp() {
        let mut circuit_builder = CircuitBuilder::<Goldilocks>::new();
        let small_values: Vec<usize> = vec![1; 64];
        let values = convert_decomp(&mut circuit_builder, &small_values, 1, 2, true);
        let vec: Vec<usize> = (0..=31).collect();
        assert_eq!(values, vec);
        // this test will fail if small_len * small_bit_width exceeds
        //      the field's max bit size
        // e.g.
        // let values = convert_decomp(&mut circuit_builder,
        //                                 &small_values,
        //                                 2,
        //                                 2,
        //                                 true);
    }
}
