use std::{fmt::Display, mem::MaybeUninit};

use ff_ext::ExtensionField;
use goldilocks::SmallField;
use itertools::Itertools;

use crate::{
    chip_handler::utils::pows_expr,
    circuit_builder::CircuitBuilder,
    error::ZKVMError,
    expression::{Expression, ToExpr, WitIn},
    set_val,
    witness::LkMultiplicity,
};

#[derive(Debug, Clone)]
pub struct IsLtConfig {
    pub is_lt: Option<WitIn>,
    pub diff: Vec<WitIn>,
    pub max_num_u16_limbs: usize,
}

impl IsLtConfig {
    pub fn expr<E: ExtensionField>(&self) -> Expression<E> {
        self.is_lt.unwrap().expr()
    }

    pub fn construct_circuit<
        E: ExtensionField,
        NR: Into<String> + Display + Clone,
        N: FnOnce() -> NR,
    >(
        cb: &mut CircuitBuilder<E>,
        name_fn: N,
        lhs: Expression<E>,
        rhs: Expression<E>,
        assert_less_than: Option<bool>,
        max_num_u16_limbs: usize,
    ) -> Result<Self, ZKVMError> {
        assert!(max_num_u16_limbs >= 1);
        cb.namespace(
            || "less_than",
            |cb| {
                let name = name_fn();
                let (is_lt, is_lt_expr) = if let Some(lt) = assert_less_than {
                    (
                        None,
                        if lt {
                            Expression::ONE
                        } else {
                            Expression::ZERO
                        },
                    )
                } else {
                    let is_lt = cb.create_witin(|| format!("{name} is_lt witin"))?;
                    cb.assert_bit(|| "is_lt_bit", is_lt.expr())?;
                    (Some(is_lt), is_lt.expr())
                };

                let mut witin_u16 = |var_name: String| -> Result<WitIn, ZKVMError> {
                    cb.namespace(
                        || format!("var {var_name}"),
                        |cb| {
                            let witin = cb.create_witin(|| var_name.to_string())?;
                            cb.assert_ux::<_, _, 16>(|| name.clone(), witin.expr())?;
                            Ok(witin)
                        },
                    )
                };

                let diff = (0..max_num_u16_limbs)
                    .map(|i| witin_u16(format!("diff_{i}")))
                    .collect::<Result<Vec<WitIn>, _>>()?;

                let pows = pows_expr((1 << u16::BITS).into(), diff.len());

                let diff_expr = diff
                    .iter()
                    .zip_eq(pows)
                    .map(|(record, beta)| beta * record.expr())
                    .reduce(|a, b| a + b)
                    .expect("reduce error");

                let range = (1 << (max_num_u16_limbs * u16::BITS as usize)).into();

                cb.require_equal(|| name.clone(), lhs - rhs, diff_expr - is_lt_expr * range)?;

                Ok(IsLtConfig {
                    is_lt,
                    diff,
                    max_num_u16_limbs,
                })
            },
        )
    }

    pub fn cal_diff(is_lt: bool, max_num_u16_limbs: usize, lhs: u64, rhs: u64) -> u64 {
        (if is_lt {
            1u64 << (u16::BITS as usize * max_num_u16_limbs)
        } else {
            0
        } + lhs
            - rhs)
    }

    pub fn assign_instance<F: SmallField>(
        &self,
        instance: &mut [MaybeUninit<F>],
        lkm: &mut LkMultiplicity,
        lhs: u64,
        rhs: u64,
    ) -> Result<(), ZKVMError> {
        let is_lt = if let Some(is_lt_wit) = self.is_lt {
            let is_lt = lhs < rhs;
            set_val!(instance, is_lt_wit, is_lt as u64);
            is_lt
        } else {
            // assert is_lt == true
            true
        };
        let diff = Self::cal_diff(is_lt, self.max_num_u16_limbs, lhs, rhs);
        self.diff.iter().enumerate().for_each(|(i, wit)| {
            // extract the 16 bit limb from diff and assign to instance
            let val = (diff >> (i * u16::BITS as usize)) & 0xffff;
            lkm.assert_ux::<16>(val);
            set_val!(instance, wit, val);
        });
        Ok(())
    }
}
