use std::{fmt::Display, mem::MaybeUninit};

use crate::{
    circuit_builder::CircuitBuilder,
    error::ZKVMError,
    expression::{Expression, ToExpr, WitIn},
    gadgets::IsLtConfig,
    set_val,
    utils::i64_to_base,
    witness::LkMultiplicity,
    Value,
};
use ceno_emul::{SWord, Word};
use ff_ext::ExtensionField;
use goldilocks::SmallField;
use itertools::Itertools;

use super::constants::{UInt, UINT_LIMBS, VALUE_BIT_WIDTH};

#[derive(Clone)]
pub struct IsEqualConfig {
    pub is_equal_per_limb: Vec<WitIn>,
    pub diff_inv_per_limb: Vec<WitIn>,
    pub diff_inv: WitIn,
    pub is_equal: WitIn,
}

#[derive(Clone)]
pub struct MsbConfig {
    pub msb: WitIn,
    pub high_limb_no_msb: WitIn,
}

pub struct MsbInput<'a> {
    pub limbs: &'a [u8],
}

impl MsbInput<'_> {
    pub fn assign<F: SmallField>(
        &self,
        instance: &mut [MaybeUninit<F>],
        config: &MsbConfig,
        lk_multiplicity: &mut LkMultiplicity,
    ) -> (u8, u8) {
        let n_limbs = self.limbs.len();
        assert!(n_limbs > 0);
        let mut high_limb = self.limbs[n_limbs - 1];
        let msb = (high_limb >> 7) & 1;
        set_val!(instance, config.msb, { i64_to_base::<F>(msb as i64) });
        high_limb &= 0b0111_1111;
        set_val!(instance, config.high_limb_no_msb, {
            i64_to_base::<F>(high_limb as i64)
        });
        lk_multiplicity.lookup_and_byte(high_limb as u64, 0b0111_1111);
        (msb, high_limb)
    }
}

#[derive(Clone)]
pub struct UIntLtuConfig {
    pub indexes: Vec<WitIn>,
    pub acc_indexes: Vec<WitIn>,
    pub byte_diff_inv: WitIn,
    pub lhs_ne_byte: WitIn,
    pub rhs_ne_byte: WitIn,
    pub is_ltu: WitIn,
}

pub struct UIntLtuInput<'a> {
    pub lhs_limbs: &'a [u8],
    pub rhs_limbs: &'a [u8],
}

impl UIntLtuInput<'_> {
    pub fn assign<F: SmallField>(
        &self,
        instance: &mut [MaybeUninit<F>],
        config: &UIntLtuConfig,
        lk_multiplicity: &mut LkMultiplicity,
    ) -> bool {
        let mut idx = 0;
        let mut flag: bool = false;
        for (i, (&lhs, &rhs)) in self
            .lhs_limbs
            .iter()
            .zip(self.rhs_limbs.iter())
            .enumerate()
            .rev()
        {
            if lhs != rhs {
                idx = i;
                flag = true;
                break;
            }
        }
        config.indexes.iter().for_each(|witin| {
            set_val!(instance, witin, { i64_to_base::<F>(0) });
        });
        set_val!(instance, config.indexes[idx], {
            i64_to_base::<F>(flag as i64)
        });
        //        (0..config.indexes.len()).for_each(|i| {
        //            if i == idx {
        //                lk_multiplicity.assert_ux::<1>(0);
        //            } else {
        //                lk_multiplicity.assert_ux::<1>(flag as u64);
        //            }
        //        });
        // this corresponds to assert_bit of index_sum
        // lk_multiplicity.assert_ux::<1>(flag as u64);
        config.acc_indexes.iter().enumerate().for_each(|(id, wit)| {
            if id <= idx {
                set_val!(instance, wit, { i64_to_base::<F>(flag as i64) });
            } else {
                set_val!(instance, wit, 0);
            }
        });
        let lhs_ne_byte = i64_to_base::<F>(self.lhs_limbs[idx] as i64);
        let rhs_ne_byte = i64_to_base::<F>(self.rhs_limbs[idx] as i64);
        set_val!(instance, config.lhs_ne_byte, lhs_ne_byte);
        set_val!(instance, config.rhs_ne_byte, rhs_ne_byte);
        set_val!(instance, config.byte_diff_inv, {
            if flag {
                (lhs_ne_byte - rhs_ne_byte).invert().unwrap()
            } else {
                F::ONE
            }
        });
        let is_ltu = self.lhs_limbs[idx] < self.rhs_limbs[idx];
        lk_multiplicity.lookup_ltu_byte(self.lhs_limbs[idx] as u64, self.rhs_limbs[idx] as u64);
        set_val!(instance, config.is_ltu, { i64_to_base::<F>(is_ltu as i64) });
        is_ltu
    }
}

#[derive(Clone)]
pub struct UIntLtConfig {
    pub lhs_msb: MsbConfig,
    pub rhs_msb: MsbConfig,
    pub msb_is_equal: WitIn,
    pub msb_diff_inv: WitIn,
    pub is_ltu: UIntLtuConfig,
    pub is_lt: WitIn,
}

pub struct UIntLtInput<'a> {
    pub lhs_limbs: &'a [u8],
    pub rhs_limbs: &'a [u8],
}

impl UIntLtInput<'_> {
    pub fn assign<F: SmallField>(
        &self,
        instance: &mut [MaybeUninit<F>],
        config: &UIntLtConfig,
        lk_multiplicity: &mut LkMultiplicity,
    ) -> bool {
        let n_limbs = self.lhs_limbs.len();
        let lhs_msb_input = MsbInput {
            limbs: self.lhs_limbs,
        };
        let (lhs_msb, lhs_high_limb_no_msb) =
            lhs_msb_input.assign(instance, &config.lhs_msb, lk_multiplicity);
        let rhs_msb_input = MsbInput {
            limbs: self.rhs_limbs,
        };
        let (rhs_msb, rhs_high_limb_no_msb) =
            rhs_msb_input.assign(instance, &config.rhs_msb, lk_multiplicity);

        let mut lhs_limbs_no_msb = self.lhs_limbs.iter().copied().collect_vec();
        lhs_limbs_no_msb[n_limbs - 1] = lhs_high_limb_no_msb;

        let mut rhs_limbs_no_msb = self.rhs_limbs.iter().copied().collect_vec();
        rhs_limbs_no_msb[n_limbs - 1] = rhs_high_limb_no_msb;

        let ltu_input = UIntLtuInput {
            lhs_limbs: &lhs_limbs_no_msb,
            rhs_limbs: &rhs_limbs_no_msb,
        };
        let is_ltu = ltu_input.assign::<F>(instance, &config.is_ltu, lk_multiplicity);

        let msb_is_equal = lhs_msb == rhs_msb;
        let msb_diff_inv = if msb_is_equal {
            0
        } else {
            lhs_msb as i64 - rhs_msb as i64
        };
        set_val!(instance, config.msb_is_equal, {
            i64_to_base::<F>(msb_is_equal as i64)
        });
        set_val!(instance, config.msb_diff_inv, {
            i64_to_base::<F>(msb_diff_inv)
        });

        // is_lt = a_s\cdot (1-b_s)+eq(a_s,b_s)\cdot ltu(a_{<s},b_{<s})$
        let is_lt = lhs_msb * (1 - rhs_msb) + msb_is_equal as u8 * is_ltu as u8;
        set_val!(instance, config.is_lt, { i64_to_base::<F>(is_lt as i64) });
        // lk_multiplicity.assert_ux::<1>(is_lt as u64);

        assert!(is_lt == 0 || is_lt == 1);
        is_lt > 0
    }
}

#[allow(dead_code)]
#[derive(Debug)]
pub struct SignedLtConfig {
    is_lt: IsLtConfig,
    is_lhs_neg: IsLtConfig,
    is_rhs_neg: IsLtConfig,
}

impl SignedLtConfig {
    const MAX_SINGED_C_MAX: u64 = (1 << (VALUE_BIT_WIDTH - 1)) - 1; // e.g. i16::MAX

    pub fn expr<E: ExtensionField>(&self) -> Expression<E> {
        self.is_lt.expr()
    }

    pub fn construct_circuit<
        E: ExtensionField,
        NR: Into<String> + Display + Clone,
        N: FnOnce() -> NR,
    >(
        cb: &mut CircuitBuilder<E>,
        name_fn: N,
        lhs: &UInt<E>,
        rhs: &UInt<E>,
        assert_less_than: Option<bool>,
    ) -> Result<Self, ZKVMError> {
        cb.namespace(name_fn, |cb| {
            // Extract the sign bit.
            let is_lhs_neg = IsLtConfig::construct_circuit(
                cb,
                || "lhs_msb",
                Expression::Constant(Self::MAX_SINGED_C_MAX.into()),
                lhs.limbs.iter().last().unwrap().expr(), // msb limb
                None,
                1,
            )?;
            let is_rhs_neg = IsLtConfig::construct_circuit(
                cb,
                || "rhs_msb",
                Expression::Constant(Self::MAX_SINGED_C_MAX.into()),
                rhs.limbs.iter().last().unwrap().expr(), // msb limb
                None,
                1,
            )?;

            // Convert two's complement representation into field arithmetic.
            // Example: 0xFFFF_FFFF = 2^32 - 1  -->  shift  -->  -1
            let neg_shift = -Expression::Constant((1_u64 << UInt::<E>::M).into());
            let lhs_value = lhs.value() + is_lhs_neg.expr() * neg_shift.clone();
            let rhs_value = rhs.value() + is_rhs_neg.expr() * neg_shift;

            let u_lt = IsLtConfig::construct_circuit(
                cb,
                || "lhs<rhs",
                lhs_value,
                rhs_value,
                assert_less_than,
                UINT_LIMBS,
            )?;

            Ok(SignedLtConfig {
                is_lt: u_lt,
                is_lhs_neg,
                is_rhs_neg,
            })
        })
    }

    pub fn assign_instance<E: ExtensionField>(
        &self,
        instance: &mut [MaybeUninit<E::BaseField>],
        lkm: &mut LkMultiplicity,
        lhs: Word,
        rhs: Word,
    ) -> Result<(), ZKVMError> {
        let lhs_value = Value::new_unchecked(lhs);
        let rhs_value = Value::new_unchecked(rhs);
        self.is_lhs_neg.assign_instance(
            instance,
            lkm,
            Self::MAX_SINGED_C_MAX,
            *lhs_value.limbs.last().unwrap() as u64,
        )?;
        self.is_rhs_neg.assign_instance(
            instance,
            lkm,
            Self::MAX_SINGED_C_MAX,
            *rhs_value.limbs.last().unwrap() as u64,
        )?;

        self.is_lt
            .assign_instance_signed(instance, lkm, lhs as SWord, rhs as SWord)?;
        Ok(())
    }
}
