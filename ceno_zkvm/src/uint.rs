mod arithmetic;
mod constants;
pub mod util;

use crate::{
    circuit_builder::CircuitBuilder,
    error::{UtilError, ZKVMError},
    expression::{Expression, ToExpr, WitIn},
    utils::add_one_to_big_num,
};
use ark_std::iterable::Iterable;
use constants::BYTE_BIT_WIDTH;
use ff_ext::ExtensionField;
use goldilocks::SmallField;
pub use strum::IntoEnumIterator;
use strum_macros::EnumIter;
use sumcheck::util::ceil_log2;

#[derive(Clone, EnumIter, Debug)]
pub enum UintLimb<E: ExtensionField> {
    WitIn(Vec<WitIn>),
    Expression(Vec<Expression<E>>),
}

#[derive(Clone, Debug)]
/// Unsigned integer with `M` total bits. `C` denotes the cell bit width.
/// Represented in little endian form.
pub struct UInt<const M: usize, const C: usize, E: ExtensionField> {
    pub limbs: UintLimb<E>,
    // We don't need `overflow` witness since the last element of `carries` represents it.
    pub carries: Option<Vec<WitIn>>,
}

impl<const M: usize, const C: usize, E: ExtensionField> UInt<M, C, E> {
    pub fn new<NR: Into<String>, N: FnOnce() -> NR>(
        name_fn: N,
        circuit_builder: &mut CircuitBuilder<E>,
    ) -> Result<Self, ZKVMError> {
        circuit_builder.namespace(name_fn, |cb| {
            Ok(UInt {
                limbs: UintLimb::WitIn(
                    (0..Self::NUM_CELLS)
                        .map(|i| {
                            let w = cb.create_witin(|| format!("limb_{i}"))?;
                            cb.assert_ux::<_, _, C>(|| format!("limb_{i}_in_{C}"), w.expr())?;
                            Ok(w)
                        })
                        .collect::<Result<Vec<WitIn>, ZKVMError>>()?,
                ),
                carries: None,
            })
        })
    }

    pub fn new_limb_as_expr() -> Self {
        Self {
            limbs: UintLimb::Expression(Vec::new()),
            carries: None,
        }
    }

    /// If current limbs are Expression, this function will create witIn and replace the limbs
    pub fn replace_limbs_with_witin<NR: Into<String>, N: FnOnce() -> NR>(
        &mut self,
        name_fn: N,
        circuit_builder: &mut CircuitBuilder<E>,
    ) -> Result<(), ZKVMError> {
        if let UintLimb::Expression(_) = self.limbs {
            circuit_builder.namespace(name_fn, |cb| {
                self.limbs = UintLimb::WitIn(
                    (0..Self::NUM_CELLS)
                        .map(|i| {
                            let w = cb.create_witin(|| format!("limb_{i}"))?;
                            cb.assert_ux::<_, _, C>(|| format!("limb_{i}_in_{C}"), w.expr())?;
                            Ok(w)
                        })
                        .collect::<Result<Vec<WitIn>, ZKVMError>>()?,
                );
                Ok(())
            })?;
        }
        Ok(())
    }

    // Create witIn for carries
    pub fn create_carry_witin<NR: Into<String>, N: FnOnce() -> NR>(
        &mut self,
        name_fn: N,
        circuit_builder: &mut CircuitBuilder<E>,
    ) -> Result<(), ZKVMError> {
        if self.carries.is_none() {
            circuit_builder.namespace(name_fn, |cb| {
                self.carries = Some(
                    (0..Self::NUM_CELLS)
                        .map(|i| {
                            let c = cb.create_witin(|| format!("carry_{i}"))?;
                            cb.assert_ux::<_, _, C>(|| format!("carry_{i}_in_{C}"), c.expr())?;
                            Ok(c)
                        })
                        .collect::<Result<Vec<WitIn>, ZKVMError>>()?,
                );
                Ok(())
            })?;
        }
        Ok(())
    }

    /// Return if the limbs are in Expression form or not.
    pub fn is_expr(&self) -> bool {
        matches!(&self.limbs, UintLimb::Expression(_))
    }

    /// Return the `UInt` underlying cell id's
    pub fn wits_in(&self) -> Option<&[WitIn]> {
        match &self.limbs {
            UintLimb::WitIn(c) => Some(c),
            _ => None,
        }
    }

    /// Builds a `UInt` instance from a set of cells that represent `RANGE_VALUES`
    /// assumes range_values are represented in little endian form
    pub fn from_range_wits_in(
        _circuit_builder: &mut CircuitBuilder<E>,
        _range_values: &[WitIn],
    ) -> Result<Self, UtilError> {
        // Self::from_different_sized_cell_values(
        //     circuit_builder,
        //     range_values,
        //     RANGE_CHIP_BIT_WIDTH,
        //     true,
        // )
        todo!()
    }

    /// Builds a `UInt` instance from a set of cells that represent big-endian `BYTE_VALUES`
    pub fn from_bytes_big_endian(
        circuit_builder: &mut CircuitBuilder<E>,
        bytes: &[WitIn],
    ) -> Result<Self, UtilError> {
        Self::from_bytes(circuit_builder, bytes, false)
    }

    /// Builds a `UInt` instance from a set of cells that represent little-endian `BYTE_VALUES`
    pub fn from_bytes_little_endian(
        circuit_builder: &mut CircuitBuilder<E>,
        bytes: &[WitIn],
    ) -> Result<Self, UtilError> {
        Self::from_bytes(circuit_builder, bytes, true)
    }

    /// Builds a `UInt` instance from a set of cells that represent `BYTE_VALUES`
    pub fn from_bytes(
        circuit_builder: &mut CircuitBuilder<E>,
        bytes: &[WitIn],
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
    fn from_different_sized_cell_values(
        _circuit_builder: &mut CircuitBuilder<E>,
        _wits_in: &[WitIn],
        _cell_width: usize,
        _is_little_endian: bool,
    ) -> Result<Self, UtilError> {
        todo!()
        // let mut values = convert_decomp(
        //     circuit_builder,
        //     wits_in,
        //     cell_width,
        //     Self::MAX_CELL_BIT_WIDTH,
        //     is_little_endian,
        // )?;
        // debug_assert!(values.len() <= Self::NUM_CELLS);
        // pad_cells(circuit_builder, &mut values, Self::NUM_CELLS);
        // values.try_into()
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
impl<const M: usize, const C: usize, E: ExtensionField> TryFrom<Vec<WitIn>> for UInt<M, C, E> {
    type Error = UtilError;

    fn try_from(limbs: Vec<WitIn>) -> Result<Self, Self::Error> {
        if limbs.len() != Self::NUM_CELLS {
            return Err(UtilError::UIntError(format!(
                "cannot construct UInt<{}, {}> from {} cells, requires {} cells",
                M,
                C,
                limbs.len(),
                Self::NUM_CELLS
            )));
        }

        Ok(Self {
            limbs: UintLimb::WitIn(limbs),
            carries: None,
        })
    }
}

/// Construct `UInt` from `$[CellId]`
impl<const M: usize, const C: usize, E: ExtensionField> TryFrom<&[WitIn]> for UInt<M, C, E> {
    type Error = UtilError;

    fn try_from(values: &[WitIn]) -> Result<Self, Self::Error> {
        values.to_vec().try_into()
    }
}

impl<E: ExtensionField, const M: usize, const C: usize> ToExpr<E> for UInt<M, C, E> {
    type Output = Vec<Expression<E>>;
    fn expr(&self) -> Vec<Expression<E>> {
        match &self.limbs {
            UintLimb::WitIn(limbs) => limbs
                .iter()
                .map(ToExpr::expr)
                .collect::<Vec<Expression<E>>>(),
            UintLimb::Expression(e) => e.clone(),
        }
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
