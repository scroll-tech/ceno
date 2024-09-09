mod arithmetic;
mod constants;
pub mod util;

use crate::{
    circuit_builder::CircuitBuilder,
    error::{UtilError, ZKVMError},
    expression::{Expression, ToExpr, WitIn},
    utils::add_one_to_big_num,
    witness::LkMultiplicity,
};
use ark_std::iterable::Iterable;
use constants::BYTE_BIT_WIDTH;
use ff::Field;
use ff_ext::ExtensionField;
use goldilocks::SmallField;
use itertools::Itertools;
use std::{
    mem::{self, MaybeUninit},
    ops::Index,
};
pub use strum::IntoEnumIterator;
use strum_macros::EnumIter;
use sumcheck::util::ceil_log2;

#[derive(Clone, EnumIter, Debug)]
pub enum UintLimb<E: ExtensionField> {
    WitIn(Vec<WitIn>),
    Expression(Vec<Expression<E>>),
}

impl<E: ExtensionField> UintLimb<E> {
    pub fn iter(&self) -> impl Iterator<Item = &WitIn> {
        match self {
            UintLimb::WitIn(vec) => vec.iter(),
            _ => unimplemented!(),
        }
    }
}

impl<E: ExtensionField> Index<usize> for UintLimb<E> {
    type Output = WitIn;

    fn index(&self, index: usize) -> &Self::Output {
        match self {
            UintLimb::WitIn(vec) => &vec[index],
            _ => unimplemented!(),
        }
    }
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
        Self::new_maybe_unchecked(name_fn, circuit_builder, true)
    }

    pub fn new_unchecked<NR: Into<String>, N: FnOnce() -> NR>(
        name_fn: N,
        circuit_builder: &mut CircuitBuilder<E>,
    ) -> Result<Self, ZKVMError> {
        Self::new_maybe_unchecked(name_fn, circuit_builder, false)
    }

    fn new_maybe_unchecked<NR: Into<String>, N: FnOnce() -> NR>(
        name_fn: N,
        circuit_builder: &mut CircuitBuilder<E>,
        is_check: bool,
    ) -> Result<Self, ZKVMError> {
        circuit_builder.namespace(name_fn, |cb| {
            Ok(UInt {
                limbs: UintLimb::WitIn(
                    (0..Self::NUM_CELLS)
                        .map(|i| {
                            let w = cb.create_witin(|| format!("limb_{i}"))?;
                            if is_check {
                                cb.assert_ux::<_, _, C>(|| format!("limb_{i}_in_{C}"), w.expr())?;
                            }
                            // skip range check
                            Ok(w)
                        })
                        .collect::<Result<Vec<WitIn>, ZKVMError>>()?,
                ),
                carries: None,
            })
        })
    }

    /// this fn does not create new witness
    pub fn new_from_limbs(limbs: &[WitIn]) -> Self {
        assert!(limbs.len() == Self::NUM_CELLS);
        UInt {
            limbs: UintLimb::WitIn(
                (0..Self::NUM_CELLS)
                    .map(|i| limbs[i])
                    .collect::<Vec<WitIn>>(),
            ),
            carries: None,
        }
    }

    /// expr_limbs is little endian order
    pub fn new_as_empty() -> Self {
        Self {
            limbs: UintLimb::Expression(vec![]),
            carries: None,
        }
    }

    /// expr_limbs is little endian order
    pub fn create_witin_from_exprs(
        circuit_builder: &mut CircuitBuilder<E>,
        expr_limbs: Vec<Expression<E>>,
    ) -> Self {
        assert_eq!(expr_limbs.len(), Self::NUM_CELLS);
        let limbs = (0..Self::NUM_CELLS)
            .map(|i| {
                let w = circuit_builder.create_witin(|| "wit for limb").unwrap();
                circuit_builder
                    .assert_ux::<_, _, C>(|| "range check", w.expr())
                    .unwrap();
                circuit_builder
                    .require_zero(
                        || "create_witin_from_expr",
                        w.expr() - expr_limbs[i].clone(),
                    )
                    .unwrap();
                w
            })
            .collect_vec();
        Self {
            limbs: UintLimb::WitIn(limbs),
            carries: None,
        }
    }

    pub fn assign_limbs(
        &self,
        instance: &mut [MaybeUninit<E::BaseField>],
        limbs_values: Vec<E::BaseField>,
    ) {
        assert!(
            limbs_values.len() <= Self::NUM_CELLS,
            "assign input length mismatch. input_len={}, NUM_CELLS={}",
            limbs_values.len(),
            Self::NUM_CELLS
        );
        if let UintLimb::WitIn(wires) = &self.limbs {
            for (wire, limb) in wires.iter().zip(
                limbs_values
                    .into_iter()
                    .chain(std::iter::repeat(E::BaseField::ZERO)),
            ) {
                instance[wire.id as usize] = MaybeUninit::new(limb);
            }
        }
    }

    pub fn assign_carries(
        &self,
        instance: &mut [MaybeUninit<E::BaseField>],
        carry_values: Vec<E::BaseField>,
    ) {
        assert!(
            carry_values.len()
                <= self
                    .carries
                    .as_ref()
                    .map(|carries| carries.len())
                    .unwrap_or_default(),
            "assign input length mismatch",
        );
        if let Some(carries) = &self.carries {
            for (wire, carry) in carries.iter().zip(
                carry_values
                    .into_iter()
                    .chain(std::iter::repeat(E::BaseField::ZERO)),
            ) {
                instance[wire.id as usize] = MaybeUninit::new(carry);
            }
        }
    }

    /// conversion is needed for lt/ltu
    /// TODO: add general conversion between any two limb sizes C1 <-> C2
    pub fn from_u8_limbs(
        circuit_builder: &mut CircuitBuilder<E>,
        x: &UInt<M, 8, E>,
    ) -> UInt<M, C, E> {
        assert!(C % 8 == 0, "we only support multiple of 8 limb sizes");
        assert!(x.carries.is_none());
        let k = C / 8;
        let shift_pows = {
            let mut shift_pows = Vec::with_capacity(k);
            shift_pows.push(Expression::Constant(E::BaseField::ONE));
            (0..k - 1).for_each(|_| {
                shift_pows.push(shift_pows.last().unwrap().clone() * (1 << 8).into())
            });
            shift_pows
        };
        let combined_limbs = x
            .limbs
            .iter()
            .collect_vec()
            .chunks(k)
            .map(|chunk| {
                chunk
                    .iter()
                    .zip(shift_pows.iter())
                    .map(|(limb, shift)| shift.clone() * limb.expr())
                    .reduce(|a, b| a + b)
                    .unwrap()
            })
            .collect_vec();
        UInt::<M, C, E>::create_witin_from_exprs(circuit_builder, combined_limbs)
    }

    pub fn to_u8_limbs(circuit_builder: &mut CircuitBuilder<E>, x: UInt<M, C, E>) -> UInt<M, 8, E> {
        assert!(C % 8 == 0, "we only support multiple of 8 limb sizes");
        assert!(x.carries.is_none());
        let k = C / 8;
        let shift_pows = {
            let mut shift_pows = Vec::with_capacity(k);
            shift_pows.push(Expression::Constant(E::BaseField::ONE));
            (0..k - 1).for_each(|_| {
                shift_pows.push(shift_pows.last().unwrap().clone() * (1 << 8).into())
            });
            shift_pows
        };
        let split_limbs = x
            .limbs
            .iter()
            .flat_map(|large_limb| {
                let limbs = (0..k)
                    .map(|_| {
                        let w = circuit_builder.create_witin(|| "").unwrap();
                        circuit_builder.assert_byte(|| "", w.expr()).unwrap();
                        w.expr()
                    })
                    .collect_vec();
                let combined_limb = limbs
                    .iter()
                    .zip(shift_pows.iter())
                    .map(|(limb, shift)| shift.clone() * limb.clone())
                    .reduce(|a, b| a + b)
                    .unwrap();

                circuit_builder
                    .require_zero(|| "zero check", large_limb.expr() - combined_limb)
                    .unwrap();
                limbs
            })
            .collect_vec();
        UInt::<M, 8, E>::create_witin_from_exprs(circuit_builder, split_limbs)
    }

    pub fn new_from_exprs_unchecked(expr_limbs: Vec<Expression<E>>) -> Result<Self, ZKVMError> {
        let n = Self {
            limbs: UintLimb::Expression(expr_limbs),
            carries: None,
        };
        Ok(n)
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
        with_overflow: bool,
    ) -> Result<(), ZKVMError> {
        if self.carries.is_none() {
            circuit_builder.namespace(name_fn, |cb| {
                let carries_len = if with_overflow {
                    Self::NUM_CELLS
                } else {
                    Self::NUM_CELLS - 1
                };
                self.carries = Some(
                    (0..carries_len)
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

pub struct UIntValue<T: Into<u64> + Copy> {
    #[allow(dead_code)]
    val: T,
    pub limbs: Vec<u16>,
}

// TODO generalize to support non 16 bit limbs
// TODO optimize api with fixed size array
impl<T: Into<u64> + Copy> UIntValue<T> {
    const LIMBS: usize = {
        let u16_bytes = (u16::BITS / 8) as usize;
        mem::size_of::<T>() / u16_bytes
    };

    #[allow(dead_code)]
    pub fn new(val: T, lkm: &mut LkMultiplicity) -> Self {
        let uint = UIntValue::<T> {
            val,
            limbs: Self::split_to_u16(val),
        };
        Self::assert_u16(&uint.limbs, lkm);
        uint
    }

    pub fn new_unchecked(val: T) -> Self {
        UIntValue::<T> {
            val,
            limbs: Self::split_to_u16(val),
        }
    }

    fn assert_u16(v: &[u16], lkm: &mut LkMultiplicity) {
        v.iter().for_each(|v| {
            lkm.assert_ux::<16>(*v as u64);
        })
    }

    fn split_to_u16(value: T) -> Vec<u16> {
        let value: u64 = value.into(); // Convert to u64 for generality
        (0..Self::LIMBS)
            .scan(value, |acc, _| {
                let limb = (*acc & 0xFFFF) as u16;
                *acc >>= 16;
                Some(limb)
            })
            .collect_vec()
    }

    pub fn as_u16_limbs(&self) -> &[u16] {
        &self.limbs
    }

    pub fn u16_fields<F: SmallField>(&self) -> Vec<F> {
        self.limbs.iter().map(|v| F::from(*v as u64)).collect_vec()
    }

    pub fn add(
        &self,
        rhs: &Self,
        lkm: &mut LkMultiplicity,
        with_overflow: bool,
    ) -> (Vec<u16>, Vec<bool>) {
        let res = self.as_u16_limbs().iter().zip(rhs.as_u16_limbs()).fold(
            vec![],
            |mut acc, (a_limb, b_limb)| {
                let (a, b) = a_limb.overflowing_add(*b_limb);
                if let Some((_, prev_carry)) = acc.last() {
                    let (e, d) = a.overflowing_add(*prev_carry as u16);
                    acc.push((e, b || d));
                } else {
                    acc.push((a, b));
                }
                // range check
                if let Some((limb, _)) = acc.last() {
                    lkm.assert_ux::<16>(*limb as u64);
                };
                acc
            },
        );
        let (limbs, mut carries): (Vec<u16>, Vec<bool>) = res.into_iter().unzip();
        if !with_overflow {
            carries.resize(carries.len() - 1, false);
        }
        carries.iter().for_each(|c| lkm.assert_ux::<16>(*c as u64));
        (limbs, carries)
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
