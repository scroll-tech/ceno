mod arithmetic;
pub mod constants;
mod logic;
pub mod util;

use crate::{
    chip_handler::{MemoryExpr, RegisterExpr},
    circuit_builder::CircuitBuilder,
    error::{UtilError, ZKVMError},
    expression::{Expression, ToExpr, WitIn},
    gadgets::AssertLTConfig,
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
    borrow::Cow,
    mem::{self, MaybeUninit},
    ops::Index,
};
pub use strum::IntoEnumIterator;
use strum_macros::EnumIter;
use sumcheck::util::ceil_log2;
use util::max_carry_word_for_multiplication;

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
pub struct UIntLimbs<const M: usize, const C: usize, E: ExtensionField> {
    pub limbs: UintLimb<E>,
    // We don't need `overflow` witness since the last element of `carries` represents it.
    pub carries: Option<Vec<WitIn>>,
    // for carry range check using lt tricks
    pub carries_auxiliary_lt_config: Option<Vec<AssertLTConfig>>,
}

impl<const M: usize, const C: usize, E: ExtensionField> UIntLimbs<M, C, E> {
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
            Ok(UIntLimbs {
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
                carries_auxiliary_lt_config: None,
            })
        })
    }

    /// accepts a vector of externally instantiated witnesses and carries,
    /// delegating the responsibility for range checking to the caller.
    pub fn from_witins_unchecked(
        limbs: Vec<WitIn>,
        carries: Option<Vec<WitIn>>,
        carries_auxiliary_lt_config: Option<Vec<AssertLTConfig>>,
    ) -> Self {
        assert!(limbs.len() == Self::NUM_CELLS);
        if let Some(carries) = &carries {
            let diff = limbs.len() - carries.len();
            assert!(
                diff == 0 || diff == 1, // diff = 1 imply no overflow
                "invalid witness: limb.len() {}, carries.len() {}",
                limbs.len(),
                carries.len()
            );
        }
        UIntLimbs {
            limbs: UintLimb::WitIn(limbs),
            carries,
            carries_auxiliary_lt_config,
        }
    }

    /// take vector of primative type and instantiate witnesses
    pub fn from_const_unchecked<T: Into<u64>>(limbs: Vec<T>) -> Self {
        assert!(limbs.len() == Self::NUM_CELLS);
        UIntLimbs {
            limbs: UintLimb::Expression(
                limbs
                    .into_iter()
                    .take(Self::NUM_CELLS)
                    .map(|limb| Expression::Constant(E::BaseField::from(limb.into())))
                    .collect::<Vec<Expression<E>>>(),
            ),
            carries: None,
            carries_auxiliary_lt_config: None,
        }
    }

    /// expr_limbs is little endian order
    pub fn new_as_empty() -> Self {
        Self {
            limbs: UintLimb::Expression(vec![]),
            carries: None,
            carries_auxiliary_lt_config: None,
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
            carries_auxiliary_lt_config: None,
        }
    }

    pub fn assign_value<T: Into<u64> + Default + From<u32> + Copy>(
        &self,
        instance: &mut [MaybeUninit<E::BaseField>],
        value: Value<T>,
    ) {
        self.assign_limbs(instance, value.as_u16_limbs())
    }

    pub fn assign_add_outcome(&self, instance: &mut [MaybeUninit<E::BaseField>], value: &ValueAdd) {
        self.assign_limbs(instance, &value.limbs);
        self.assign_carries(instance, &value.carries);
    }

    pub fn assign_mul_outcome(
        &self,
        instance: &mut [MaybeUninit<E::BaseField>],
        lkm: &mut LkMultiplicity,
        value: &ValueMul,
    ) -> Result<(), ZKVMError> {
        self.assign_limbs(instance, &value.limbs);
        self.assign_carries(instance, &value.carries);
        self.assign_carries_auxiliary(instance, lkm, &value.carries, value.max_carry_value)
    }

    pub fn assign_limbs(&self, instance: &mut [MaybeUninit<E::BaseField>], limbs_values: &[u16]) {
        assert!(
            limbs_values.len() <= Self::NUM_CELLS,
            "assign input length mismatch. input_len={}, NUM_CELLS={}",
            limbs_values.len(),
            Self::NUM_CELLS
        );
        if let UintLimb::WitIn(wires) = &self.limbs {
            for (wire, limb) in wires.iter().zip(
                limbs_values
                    .iter()
                    .map(|v| E::BaseField::from(*v as u64))
                    .chain(std::iter::repeat(E::BaseField::ZERO)),
            ) {
                instance[wire.id as usize] = MaybeUninit::new(limb);
            }
        }
    }

    pub fn assign_carries<T: Into<u64> + Copy>(
        &self,
        instance: &mut [MaybeUninit<E::BaseField>],
        carry_values: &[T],
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
                    .iter()
                    .map(|v| E::BaseField::from(Into::<u64>::into(*v)))
                    .chain(std::iter::repeat(E::BaseField::ZERO)),
            ) {
                instance[wire.id as usize] = MaybeUninit::new(carry);
            }
        }
    }

    pub fn assign_carries_auxiliary<T: Into<u64> + Copy>(
        &self,
        instance: &mut [MaybeUninit<E::BaseField>],
        lkm: &mut LkMultiplicity,
        carry_values: &[T],
        max_carry: u64,
    ) -> Result<(), ZKVMError> {
        assert!(
            carry_values.len()
                <= self
                    .carries
                    .as_ref()
                    .map(|carries| carries.len())
                    .unwrap_or_default(),
            "assign input length mismatch",
        );
        if let Some(carries_auxiliary_lt_config) = &self.carries_auxiliary_lt_config {
            // constrain carry range
            for (lt_config, carry) in carries_auxiliary_lt_config.iter().zip_eq(carry_values) {
                lt_config.assign_instance(instance, lkm, Into::<u64>::into(*carry), max_carry)?;
            }
        }
        Ok(())
    }

    /// conversion is needed for lt/ltu
    /// TODO: add general conversion between any two limb sizes C1 <-> C2
    pub fn from_u8_limbs(x: &UIntLimbs<M, 8, E>) -> Result<UIntLimbs<M, C, E>, ZKVMError> {
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
        UIntLimbs::<M, C, E>::from_exprs_unchecked(combined_limbs)
    }

    pub fn to_u8_limbs(
        circuit_builder: &mut CircuitBuilder<E>,
        x: UIntLimbs<M, C, E>,
    ) -> UIntLimbs<M, 8, E> {
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
        UIntLimbs::<M, 8, E>::create_witin_from_exprs(circuit_builder, split_limbs)
    }

    pub fn from_exprs_unchecked(expr_limbs: Vec<Expression<E>>) -> Result<Self, ZKVMError> {
        let n = Self {
            limbs: UintLimb::Expression(
                expr_limbs
                    .into_iter()
                    .chain(std::iter::repeat(Expression::ZERO))
                    .take(Self::NUM_CELLS)
                    .collect_vec(),
            ),
            carries: None,
            carries_auxiliary_lt_config: None,
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
    fn alloc_carry_unchecked<NR: Into<String>, N: FnOnce() -> NR>(
        &mut self,
        name_fn: N,
        circuit_builder: &mut CircuitBuilder<E>,
        with_overflow: bool,
        num_carries: usize,
    ) -> Result<(), ZKVMError> {
        if self.carries.is_none() {
            circuit_builder.namespace(name_fn, |cb| {
                let carries_len = if with_overflow {
                    num_carries
                } else {
                    num_carries - 1
                };
                self.carries = Some(
                    (0..carries_len)
                        .map(|i| {
                            let c = cb.create_witin(|| format!("carry_{i}"))?;
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

    /// Return the `UIntLimbs` underlying cell id's
    pub fn wits_in(&self) -> Option<&[WitIn]> {
        match &self.limbs {
            UintLimb::WitIn(c) => Some(c),
            _ => None,
        }
    }

    /// Builds a `UIntLimbs` instance from a set of cells that represent `RANGE_VALUES`
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

    /// Builds a `UIntLimbs` instance from a set of cells that represent big-endian `BYTE_VALUES`
    pub fn from_bytes_big_endian(
        circuit_builder: &mut CircuitBuilder<E>,
        bytes: &[WitIn],
    ) -> Result<Self, UtilError> {
        Self::from_bytes(circuit_builder, bytes, false)
    }

    /// Builds a `UIntLimbs` instance from a set of cells that represent little-endian `BYTE_VALUES`
    pub fn from_bytes_little_endian(
        circuit_builder: &mut CircuitBuilder<E>,
        bytes: &[WitIn],
    ) -> Result<Self, UtilError> {
        Self::from_bytes(circuit_builder, bytes, true)
    }

    /// Builds a `UIntLimbs` instance from a set of cells that represent `BYTE_VALUES`
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

    /// Builds a `UIntLimbs` instance from a set of cell values of a certain `CELL_WIDTH`
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
        let number_of_limbs = num_vars.div_ceil(C);
        let cell_modulo = F::from(1 << C);

        let mut res = vec![vec![F::ZERO; number_of_limbs]];

        for i in 1..size {
            res.push(add_one_to_big_num(cell_modulo, &res[i - 1]));
        }

        res
    }

    /// Get an Expression<E> from the limbs, unsafe if Uint value exceeds field limit
    pub fn value(&self) -> Expression<E> {
        let base = Expression::from(1 << C);
        self.expr()
            .into_iter()
            .rev()
            .reduce(|sum, limb| sum * base.clone() + limb)
            .unwrap()
    }

    /// split into 2 UIntLimbs with each taking half size of limbs
    pub fn as_lo_hi<const M2: usize>(
        &self,
    ) -> Result<(UIntLimbs<M2, C, E>, UIntLimbs<M2, C, E>), ZKVMError> {
        assert!(M == 2 * M2);
        let mut self_lo = self.expr();
        let self_hi = self_lo.split_off(self_lo.len() / 2);
        Ok((
            UIntLimbs::from_exprs_unchecked(self_lo)?,
            UIntLimbs::from_exprs_unchecked(self_hi)?,
        ))
    }
}

/// Construct `UIntLimbs` from `Vec<CellId>`
impl<const M: usize, const C: usize, E: ExtensionField> TryFrom<Vec<WitIn>> for UIntLimbs<M, C, E> {
    type Error = UtilError;

    fn try_from(limbs: Vec<WitIn>) -> Result<Self, Self::Error> {
        if limbs.len() != Self::NUM_CELLS {
            return Err(UtilError::UIntError(format!(
                "cannot construct UIntLimbs<{}, {}> from {} cells, requires {} cells",
                M,
                C,
                limbs.len(),
                Self::NUM_CELLS
            )));
        }

        Ok(Self {
            limbs: UintLimb::WitIn(limbs),
            carries: None,
            carries_auxiliary_lt_config: None,
        })
    }
}

/// Construct `UIntLimbs` from `$[CellId]`
impl<const M: usize, const C: usize, E: ExtensionField> TryFrom<&[WitIn]> for UIntLimbs<M, C, E> {
    type Error = UtilError;

    fn try_from(values: &[WitIn]) -> Result<Self, Self::Error> {
        values.to_vec().try_into()
    }
}

impl<E: ExtensionField, const M: usize, const C: usize> ToExpr<E> for UIntLimbs<M, C, E> {
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

impl<E: ExtensionField> UIntLimbs<32, 16, E> {
    /// Return a value suitable for register read/write. From [u16; 2] limbs.
    pub fn register_expr(&self) -> RegisterExpr<E> {
        let u16_limbs = self.expr();
        u16_limbs.try_into().expect("two limbs with M=32 and C=16")
    }

    /// Return a value suitable for memory read/write. From [u16; 2] limbs
    pub fn memory_expr(&self) -> MemoryExpr<E> {
        let u16_limbs = self.expr();
        u16_limbs.try_into().expect("two limbs with M=32 and C=16")
    }
}

impl<E: ExtensionField> UIntLimbs<32, 8, E> {
    /// Return a value suitable for register read/write. From [u8; 4] limbs.
    pub fn register_expr(&self) -> RegisterExpr<E> {
        let u8_limbs = self.expr();
        let u16_limbs = u8_limbs
            .chunks(2)
            .map(|chunk| {
                let (a, b) = (chunk[0].clone(), chunk[1].clone());
                a + b * 256.into()
            })
            .collect_vec();
        u16_limbs.try_into().expect("four limbs with M=32 and C=8")
    }
}

/// A struct holding intermediate results of arithmetic add operations from Value
pub struct ValueAdd {
    pub limbs: Vec<u16>,
    pub carries: Vec<u16>,
}

/// A struct holding intermediate results of arithmetic mul operations from Value
pub struct ValueMul {
    pub limbs: Vec<u16>,
    pub carries: Vec<u64>,
    pub max_carry_value: u64,
}

impl ValueMul {
    pub fn as_hi_value<T: Into<u64> + From<u32> + Copy + Default>(&self) -> Value<T> {
        Value::<T>::from_limb_slice_unchecked(self.as_hi_limb_slice())
    }

    pub fn as_hi_limb_slice(&self) -> &[u16] {
        &self.limbs[self.limbs.len() / 2..]
    }
}

pub struct Value<'a, T: Into<u64> + From<u32> + Copy + Default> {
    #[allow(dead_code)]
    val: T,
    pub limbs: Cow<'a, [u16]>,
}

// TODO generalize to support non 16 bit limbs
// TODO optimize api with fixed size array
impl<'a, T: Into<u64> + From<u32> + Copy + Default> Value<'a, T> {
    const M: usize = { mem::size_of::<T>() * 8 };

    const C: usize = 16;

    const LIMBS: usize = (Self::M + 15) / 16;

    pub fn new(val: T, lkm: &mut LkMultiplicity) -> Self {
        let uint = Value::<T> {
            val,
            limbs: Cow::Owned(Self::split_to_u16(val)),
        };
        Self::assert_u16(&uint.limbs, lkm);
        uint
    }

    pub fn new_unchecked(val: T) -> Self {
        Value::<T> {
            val,
            limbs: Cow::Owned(Self::split_to_u16(val)),
        }
    }

    pub fn from_limb_unchecked(limbs: Vec<u16>) -> Self {
        Value::<T> {
            val: limbs
                .iter()
                .rev()
                .fold(0u32, |acc, &v| acc * (1 << 16) + v as u32)
                .into(),
            limbs: Cow::Owned(limbs),
        }
    }

    pub fn from_limb_slice_unchecked(limbs: &'a [u16]) -> Self {
        Value::<T> {
            val: limbs
                .iter()
                .rev()
                .fold(0u32, |acc, &v| acc * (1 << 16) + v as u32)
                .into(),
            limbs: Cow::Borrowed(limbs),
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

    /// Convert the limbs to a u64 value
    pub fn as_u64(&self) -> u64 {
        self.val.into()
    }

    /// Convert the limbs to a u32 value
    pub fn as_u32(&self) -> u32 {
        self.as_u64() as u32
    }

    pub fn u16_fields<F: SmallField>(&self) -> Vec<F> {
        self.limbs.iter().map(|v| F::from(*v as u64)).collect_vec()
    }

    pub fn add(&self, rhs: &Self, lkm: &mut LkMultiplicity, with_overflow: bool) -> ValueAdd {
        let res = self.as_u16_limbs().iter().zip(rhs.as_u16_limbs()).fold(
            vec![],
            |mut acc, (a_limb, b_limb)| {
                let (a, b) = a_limb.overflowing_add(*b_limb);
                if let Some((_, prev_carry)) = acc.last() {
                    let (e, d) = a.overflowing_add(*prev_carry);
                    acc.push((e, (b || d) as u16));
                } else {
                    acc.push((a, b as u16));
                }
                // range check
                if let Some((limb, _)) = acc.last() {
                    lkm.assert_ux::<16>(*limb as u64);
                };
                acc
            },
        );
        let (limbs, mut carries): (Vec<u16>, Vec<u16>) = res.into_iter().unzip();
        if !with_overflow {
            carries.resize(carries.len() - 1, 0);
        }
        ValueAdd { limbs, carries }
    }

    pub fn mul(&self, rhs: &Self, lkm: &mut LkMultiplicity, with_overflow: bool) -> ValueMul {
        self.internal_mul(rhs, lkm, with_overflow, false)
    }

    pub fn mul_hi(&self, rhs: &Self, lkm: &mut LkMultiplicity, with_overflow: bool) -> ValueMul {
        self.internal_mul(rhs, lkm, with_overflow, true)
    }

    #[allow(clippy::type_complexity)]
    pub fn mul_add(
        &self,
        mul: &Self,
        addend: &Self,
        lkm: &mut LkMultiplicity,
        with_overflow: bool,
    ) -> (ValueAdd, ValueMul) {
        let mul_result = self.internal_mul(mul, lkm, with_overflow, false);
        let add_result = addend.add(
            &Self::from_limb_unchecked(mul_result.limbs.clone()),
            lkm,
            with_overflow,
        );
        (add_result, mul_result)
    }

    fn internal_mul(
        &self,
        mul: &Self,
        lkm: &mut LkMultiplicity,
        with_overflow: bool,
        with_hi_limbs: bool,
    ) -> ValueMul {
        let a_limbs = self.as_u16_limbs();
        let b_limbs = mul.as_u16_limbs();

        let num_limbs = if !with_hi_limbs {
            a_limbs.len()
        } else {
            2 * a_limbs.len()
        };
        let mut c_limbs = vec![0u16; num_limbs];
        let mut carries = vec![0u64; num_limbs];
        let mut tmp = vec![0u64; num_limbs];
        a_limbs.iter().enumerate().for_each(|(i, &a_limb)| {
            b_limbs.iter().enumerate().for_each(|(j, &b_limb)| {
                let idx = i + j;
                if idx < num_limbs {
                    tmp[idx] += a_limb as u64 * b_limb as u64;
                }
            })
        });

        tmp.iter()
            .zip(c_limbs.iter_mut())
            .enumerate()
            .for_each(|(i, (tmp, limb))| {
                // tmp + prev_carry - carry * Self::LIMB_BASE_MUL
                let mut tmp = *tmp;
                if i > 0 {
                    tmp += carries[i - 1];
                }
                // update carry
                carries[i] = tmp >> Self::C;
                // update limb with only lsb 16 bit
                *limb = tmp as u16;
            });

        if !with_overflow {
            // If the outcome overflows, `with_overflow` can't be false
            assert_eq!(carries[carries.len() - 1], 0, "incorrect overflow flag");
            carries.resize(carries.len() - 1, 0);
        }

        // range check
        c_limbs.iter().for_each(|c| lkm.assert_ux::<16>(*c as u64));

        ValueMul {
            limbs: c_limbs,
            carries,
            max_carry_value: max_carry_word_for_multiplication(2, Self::M, Self::C),
        }
    }
}

#[cfg(test)]
mod tests {

    mod value {
        use crate::{Value, witness::LkMultiplicity};
        #[test]
        fn test_add() {
            let a = Value::new_unchecked(1u32);
            let b = Value::new_unchecked(2u32);
            let mut lkm = LkMultiplicity::default();

            let ret = a.add(&b, &mut lkm, true);
            assert_eq!(ret.limbs[0], 3);
            assert_eq!(ret.limbs[1], 0);
            assert_eq!(ret.carries[0], 0);
            assert_eq!(ret.carries[1], 0);
        }

        #[test]
        fn test_add_carry() {
            let a = Value::new_unchecked(u16::MAX as u32);
            let b = Value::new_unchecked(2u32);
            let mut lkm = LkMultiplicity::default();

            let ret = a.add(&b, &mut lkm, true);
            assert_eq!(ret.limbs[0], 1);
            assert_eq!(ret.limbs[1], 1);
            assert_eq!(ret.carries[0], 1);
            assert_eq!(ret.carries[1], 0);
        }

        #[test]
        fn test_mul() {
            let a = Value::new_unchecked(1u32);
            let b = Value::new_unchecked(2u32);
            let mut lkm = LkMultiplicity::default();

            let ret = a.mul(&b, &mut lkm, true);
            assert_eq!(ret.limbs[0], 2);
            assert_eq!(ret.limbs[1], 0);
            assert_eq!(ret.carries[0], 0);
            assert_eq!(ret.carries[1], 0);
        }

        #[test]
        fn test_mul_carry() {
            let a = Value::new_unchecked(u16::MAX as u32);
            let b = Value::new_unchecked(2u32);
            let mut lkm = LkMultiplicity::default();

            let ret = a.mul(&b, &mut lkm, true);
            assert_eq!(ret.limbs[0], u16::MAX - 1);
            assert_eq!(ret.limbs[1], 1);
            assert_eq!(ret.carries[0], 1);
            assert_eq!(ret.carries[1], 0);
        }

        #[test]
        fn test_mul_overflow() {
            let a = Value::new_unchecked(u32::MAX / 2 + 1);
            let b = Value::new_unchecked(2u32);
            let mut lkm = LkMultiplicity::default();

            let ret = a.mul(&b, &mut lkm, true);
            assert_eq!(ret.limbs[0], 0);
            assert_eq!(ret.limbs[1], 0);
            assert_eq!(ret.carries[0], 0);
            assert_eq!(ret.carries[1], 1);
        }
    }
}
