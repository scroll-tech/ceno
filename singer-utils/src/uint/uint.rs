use crate::{
    constants::{BYTE_BIT_WIDTH, RANGE_CHIP_BIT_WIDTH},
    error::UtilError,
    uint::util::{add_one_to_big_num, convert_decomp, pad_cells},
};
use ff_ext::ExtensionField;
use goldilocks::SmallField;
use simple_frontend::structs::{CellId, CircuitBuilder};
use sumcheck::util::ceil_log2;

#[derive(Clone)]
/// Unsigned integer with `M` total bits. `C` denotes the cell bit width.
/// Represented in little endian form.
pub struct UInt<const M: usize, const C: usize> {
    pub values: Vec<CellId>,
}

impl<const M: usize, const C: usize> UInt<M, C> {
    /// Return the `UInt` underlying cell id's
    pub fn values(&self) -> &[CellId] {
        &self.values
    }

    /// Builds a `UInt` instance from a set of cells that represent `RANGE_VALUES`
    /// assumes range_values are represented in little endian form
    pub fn from_range_values<E: ExtensionField>(
        circuit_builder: &mut CircuitBuilder<E>,
        range_values: &[CellId],
    ) -> Result<Self, UtilError> {
        Self::from_different_sized_cell_values(
            circuit_builder,
            range_values,
            RANGE_CHIP_BIT_WIDTH,
            true,
        )
    }

    /// Builds a `UInt` instance from a set of cells that represent big-endian `BYTE_VALUES`
    pub fn from_bytes_big_endian<E: ExtensionField>(
        circuit_builder: &mut CircuitBuilder<E>,
        bytes: &[CellId],
    ) -> Result<Self, UtilError> {
        Self::from_bytes(circuit_builder, bytes, false)
    }

    /// Builds a `UInt` instance from a set of cells that represent little-endian `BYTE_VALUES`
    pub fn from_bytes_little_endian<E: ExtensionField>(
        circuit_builder: &mut CircuitBuilder<E>,
        bytes: &[CellId],
    ) -> Result<Self, UtilError> {
        Self::from_bytes(circuit_builder, bytes, true)
    }

    /// Builds a `UInt` instance from a set of cells that represent `BYTE_VALUES`
    pub fn from_bytes<E: ExtensionField>(
        circuit_builder: &mut CircuitBuilder<E>,
        bytes: &[CellId],
        is_little_endian: bool,
    ) -> Result<Self, UtilError> {
        Self::from_different_sized_cell_values(
            circuit_builder,
            bytes,
            BYTE_BIT_WIDTH,
            is_little_endian,
        )
    }

    /// Builds a `UInt` instance from a set of cell values of a certain `CELL_WIDTH`
    fn from_different_sized_cell_values<E: ExtensionField>(
        circuit_builder: &mut CircuitBuilder<E>,
        cell_values: &[CellId],
        cell_width: usize,
        is_little_endian: bool,
    ) -> Result<Self, UtilError> {
        let mut values = convert_decomp(
            circuit_builder,
            cell_values,
            cell_width,
            Self::MAX_CELL_BIT_WIDTH,
            is_little_endian,
        )?;
        debug_assert!(values.len() <= Self::N_OPERAND_CELLS);
        pad_cells(circuit_builder, &mut values, Self::N_OPERAND_CELLS);
        values.try_into()
    }

    /// Generate ((0)_{2^C}, (1)_{2^C}, ..., (size - 1)_{2^C})
    pub fn counter_vector<F: SmallField>(size: usize) -> Vec<Vec<F>> {
        let num_vars = ceil_log2(size);
        let number_of_limbs = (num_vars + C - 1) / C;
        let cell_modulo = F::from(1 << C);

        let mut res = vec![vec![F::ZERO; number_of_limbs]];

        for i in 1..size {
            res.push(add_one_to_big_num(cell_modulo, &res[i - 1]));
        }

        res
    }
}

/// Construct `UInt` from `Vec<CellId>`
impl<const M: usize, const C: usize> TryFrom<Vec<CellId>> for UInt<M, C> {
    type Error = UtilError;

    fn try_from(values: Vec<CellId>) -> Result<Self, Self::Error> {
        if values.len() != Self::N_OPERAND_CELLS {
            return Err(UtilError::UIntError(format!(
                "cannot construct UInt<{}, {}> from {} cells, requires {} cells",
                M,
                C,
                values.len(),
                Self::N_OPERAND_CELLS
            )));
        }

        Ok(Self { values })
    }
}

/// Construct `UInt` from `$[CellId]`
impl<const M: usize, const C: usize> TryFrom<&[CellId]> for UInt<M, C> {
    type Error = UtilError;

    fn try_from(values: &[CellId]) -> Result<Self, Self::Error> {
        values.to_vec().try_into()
    }
}

// #[cfg(test)]
// mod tests {
//     use crate::uint::uint::UInt;
//     use gkr::structs::{Circuit, CircuitWitness};
//     use goldilocks::{Goldilocks, GoldilocksExt2};
//     use itertools::Itertools;
//     use simple_frontend::structs::CircuitBuilder;

//     #[test]
//     fn test_uint_from_cell_ids() {
//         // 33 total bits and each cells holds just 4 bits
//         // to hold all 33 bits without truncations, we'd need 9 cells
//         // 9 * 4 = 36 > 33
//         type UInt33 = UInt<33, 4>;
//         assert!(UInt33::try_from(vec![1, 2, 3, 4, 5, 6, 7, 8, 9]).is_ok());
//         assert!(UInt33::try_from(vec![1, 2, 3]).is_err());
//         assert!(UInt33::try_from(vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10]).is_err());
//     }

//     #[test]
//     fn test_uint_from_different_sized_cell_values() {
//         // build circuit
//         let mut circuit_builder = CircuitBuilder::<GoldilocksExt2>::new();
//         let (_, small_values) = circuit_builder.create_witness_in(8);
//         type UInt30 = UInt<30, 6>;
//         let uint_instance =
//             UInt30::from_different_sized_cell_values(&mut circuit_builder, &small_values, 2, true)
//                 .unwrap();
//         circuit_builder.configure();
//         let circuit = Circuit::new(&circuit_builder);

//         // input
//         // we start with cells of bit width 2 (8 of them)
//         // 11 00 10 11 01 10 01 01 (bit representation)
//         //  3  0  2  3  1  2  1  1 (field representation)
//         //
//         // repacking into cells of bit width 6
//         // 110010 110110 010100
//         // since total bit = 30 then expect 5 cells ( 30 / 6)
//         // since we have 3 cells, we need to pad with 2 more
//         // hence expected output:
//         // 100011 100111 000101 000000 000000(bit representation)
//         //     35     39      5      0      0

//         let witness_values = vec![3, 0, 2, 3, 1, 2, 1, 1]
//             .into_iter()
//             .map(|v| Goldilocks::from(v))
//             .collect_vec();
//         let circuit_witness = {
//             let challenges = vec![GoldilocksExt2::from(2)];
//             let mut circuit_witness = CircuitWitness::new(&circuit, challenges);
//             circuit_witness.add_instance(&circuit, vec![witness_values]);
//             circuit_witness
//         };
//         circuit_witness.check_correctness(&circuit);

//         let output = circuit_witness.output_layer_witness_ref().instances[0].to_vec();
//         assert_eq!(
//             &output[..5],
//             vec![35, 39, 5, 0, 0]
//                 .into_iter()
//                 .map(|v| Goldilocks::from(v))
//                 .collect_vec()
//         );

//         // padding to power of 2
//         assert_eq!(
//             &output[5..],
//             vec![0, 0, 0]
//                 .into_iter()
//                 .map(|v| Goldilocks::from(v))
//                 .collect_vec()
//         );
//     }

//     #[test]
//     fn test_counter_vector() {
//         // each limb has 5 bits so all number from 0..3 should require only 1 limb
//         type UInt30 = UInt<30, 5>;
//         let res = UInt30::counter_vector::<Goldilocks>(3);
//         assert_eq!(
//             res,
//             vec![
//                 vec![Goldilocks::from(0)],
//                 vec![Goldilocks::from(1)],
//                 vec![Goldilocks::from(2)]
//             ]
//         );

//         // each limb has a single bit, number from 0..5 should require 3 limbs each
//         type UInt50 = UInt<50, 1>;
//         let res = UInt50::counter_vector::<Goldilocks>(5);
//         assert_eq!(
//             res,
//             vec![
//                 // 0
//                 vec![
//                     Goldilocks::from(0),
//                     Goldilocks::from(0),
//                     Goldilocks::from(0)
//                 ],
//                 // 1
//                 vec![
//                     Goldilocks::from(1),
//                     Goldilocks::from(0),
//                     Goldilocks::from(0)
//                 ],
//                 // 2
//                 vec![
//                     Goldilocks::from(0),
//                     Goldilocks::from(1),
//                     Goldilocks::from(0)
//                 ],
//                 // 3
//                 vec![
//                     Goldilocks::from(1),
//                     Goldilocks::from(1),
//                     Goldilocks::from(0)
//                 ],
//                 // 4
//                 vec![
//                     Goldilocks::from(0),
//                     Goldilocks::from(0),
//                     Goldilocks::from(1)
//                 ],
//             ]
//         );
//     }
// }
