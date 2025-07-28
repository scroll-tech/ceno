use std::fmt::Display;

use ceno_emul::{SWord, Word};
use ff_ext::ExtensionField;
use gkr_iop::error::CircuitBuilderError;

use crate::{
    Value,
    circuit_builder::CircuitBuilder,
    gadgets::InnerLtConfig,
    instructions::riscv::constants::{UINT_LIMBS, UInt},
    witness::{LkMultiplicity, set_val},
};
use ff_ext::FieldInto;
use multilinear_extensions::{Expression, ToExpr, WitIn};

use super::SignedExtendConfig;

#[derive(Debug)]
pub struct AssertSignedLtConfig<E> {
    config: InnerSignedLtConfig<E>,
}

impl<E: ExtensionField> AssertSignedLtConfig<E> {
    pub fn construct_circuit<NR: Into<String> + Display + Clone, N: FnOnce() -> NR>(
        cb: &mut CircuitBuilder<E>,
        name_fn: N,
        lhs: &UInt<E>,
        rhs: &UInt<E>,
    ) -> Result<Self, CircuitBuilderError> {
        cb.namespace(
            || "assert_signed_lt",
            |cb| {
                let name = name_fn();
                let config =
                    InnerSignedLtConfig::construct_circuit(cb, name, lhs, rhs, Expression::ONE)?;
                Ok(Self { config })
            },
        )
    }

    pub fn assign_instance(
        &self,
        instance: &mut [E::BaseField],
        lkm: &mut LkMultiplicity,
        lhs: SWord,
        rhs: SWord,
    ) -> Result<(), CircuitBuilderError> {
        self.config.assign_instance(instance, lkm, lhs, rhs)?;
        Ok(())
    }
}

#[derive(Debug)]
pub struct SignedLtConfig<E> {
    is_lt: WitIn,
    config: InnerSignedLtConfig<E>,
}

impl<E: ExtensionField> SignedLtConfig<E> {
    pub fn expr(&self) -> Expression<E> {
        self.is_lt.expr()
    }

    pub fn construct_circuit<NR: Into<String> + Display + Clone, N: FnOnce() -> NR>(
        cb: &mut CircuitBuilder<E>,
        name_fn: N,
        lhs: &UInt<E>,
        rhs: &UInt<E>,
    ) -> Result<Self, CircuitBuilderError> {
        cb.namespace(
            || "is_signed_lt",
            |cb| {
                let name = name_fn();
                let is_lt = cb.create_witin(|| format!("{name} is_signed_lt witin"));
                cb.assert_bit(|| "is_lt_bit", is_lt.expr())?;
                let config =
                    InnerSignedLtConfig::construct_circuit(cb, name, lhs, rhs, is_lt.expr())?;

                Ok(SignedLtConfig { is_lt, config })
            },
        )
    }

    pub fn assign_instance(
        &self,
        instance: &mut [E::BaseField],
        lkm: &mut LkMultiplicity,
        lhs: SWord,
        rhs: SWord,
    ) -> Result<(), CircuitBuilderError> {
        set_val!(instance, self.is_lt, (lhs < rhs) as u64);
        self.config
            .assign_instance(instance, lkm, lhs as SWord, rhs as SWord)?;
        Ok(())
    }
}

#[derive(Debug)]
struct InnerSignedLtConfig<E> {
    is_lhs_neg: SignedExtendConfig<E>,
    is_rhs_neg: SignedExtendConfig<E>,
    config: InnerLtConfig,
}

impl<E: ExtensionField> InnerSignedLtConfig<E> {
    pub fn construct_circuit<NR: Into<String> + Display + Clone>(
        cb: &mut CircuitBuilder<E>,
        name: NR,
        lhs: &UInt<E>,
        rhs: &UInt<E>,
        is_lt_expr: Expression<E>,
    ) -> Result<Self, CircuitBuilderError> {
        // Extract the sign bit.
        let is_lhs_neg = lhs.is_negative(cb)?;
        let is_rhs_neg = rhs.is_negative(cb)?;

        // Convert to field arithmetic.
        let lhs_value = lhs.to_field_expr(is_lhs_neg.expr());
        let rhs_value = rhs.to_field_expr(is_rhs_neg.expr());
        let config = InnerLtConfig::construct_circuit(
            cb,
            format!("{name} (lhs < rhs)"),
            lhs_value,
            rhs_value,
            is_lt_expr,
            UINT_LIMBS,
        )?;

        Ok(Self {
            is_lhs_neg,
            is_rhs_neg,
            config,
        })
    }

    pub fn assign_instance(
        &self,
        instance: &mut [E::BaseField],
        lkm: &mut LkMultiplicity,
        lhs: SWord,
        rhs: SWord,
    ) -> Result<(), CircuitBuilderError> {
        let lhs_value = Value::new_unchecked(lhs as Word);
        let rhs_value = Value::new_unchecked(rhs as Word);
        self.is_lhs_neg.assign_instance(
            instance,
            lkm,
            *lhs_value.as_u16_limbs().last().unwrap() as u64,
        )?;
        self.is_rhs_neg.assign_instance(
            instance,
            lkm,
            *rhs_value.as_u16_limbs().last().unwrap() as u64,
        )?;

        self.config
            .assign_instance_i64(instance, lkm, lhs as i64, rhs as i64)?;
        Ok(())
    }
}
