use std::{fmt::Display, mem::MaybeUninit};

use ff_ext::ExtensionField;

use crate::{
    circuit_builder::CircuitBuilder,
    error::ZKVMError,
    expression::Expression,
    instructions::riscv::constants::{UInt, UINT_LIMBS},
    witness::LkMultiplicity,
    Value,
};

use super::{IsLtConfig, IsZeroConfig};

/// divide gadget
#[derive(Debug, Clone)]
pub struct DivConfig<E: ExtensionField, const ALLOW_ZERO_DIVISOR: bool> {
    pub dividend: UInt<E>,
    pub divisor: UInt<E>,
    pub(crate) quotient: UInt<E>,
    pub remainder: UInt<E>,

    pub intermediate_mul: UInt<E>,
    pub remainder_lt: IsLtConfig,
    is_zero: Option<IsZeroConfig>,
}

impl<E: ExtensionField, const ALLOW_ZERO_DIVISOR: bool> DivConfig<E, ALLOW_ZERO_DIVISOR> {
    /// giving divisor, quotient, and remainder
    /// deriving dividend and respective constrains
    pub fn construct_circuit<NR: Into<String> + Display + Clone, N: FnOnce() -> NR>(
        circuit_builder: &mut CircuitBuilder<E>,
        name_fn: N,
    ) -> Result<Self, ZKVMError> {
        circuit_builder.namespace(name_fn, |cb| {
            // quotient = dividend / divisor + remainder => dividend = divisor * quotient + r
            let mut divisor = UInt::new(|| "divisor", cb)?;
            let mut quotient = UInt::new(|| "quotient", cb)?;
            let remainder = UInt::new(|| "remainder", cb)?;
            let (dividend, intermediate_mul) =
                divisor.mul_add(|| "", cb, &mut quotient, &remainder, true)?;

            // ALLOW_ZERO_DIVISOR == false, we force remainder must be less than divisor
            // by setting `assert_less_than` to true, and this also reduce a witness (is_lt)
            let (is_zero, remainder_lt) = if !ALLOW_ZERO_DIVISOR {
                let lt = cb.less_than(
                    || "remainder < divisor",
                    remainder.value(),
                    divisor.value(),
                    Some(true),
                    UINT_LIMBS,
                )?;
                (None, lt)
            } else {
                // Here, it's a normal divison case
                let is_zero =
                    IsZeroConfig::construct_circuit(cb, || "divisor_zero_check", divisor.value())?;

                let quotient_value = quotient.value();
                cb.condition_require_equal(
                    || "is_quotient_zero",
                    is_zero.expr(),
                    quotient_value.clone(),
                    ((1 << UInt::<E>::M) - 1).into(),
                    quotient_value,
                )
                .unwrap();

                let lt = IsLtConfig::construct_circuit(
                    cb,
                    || "remainder < divisor?",
                    remainder.value(),
                    divisor.value(),
                    None,
                    UINT_LIMBS,
                )?;

                // TODO: we don't need conditional require once we have signed version of IsLtConfig
                // When divisor is zero, remainder is -1 implies "remainder > divisor" aka. lt.expr() == 0
                // otherwise lt.expr() == 1
                cb.condition_require_equal(
                    || "remainder < divisor when non-zero divisor",
                    is_zero.expr(),
                    Expression::from(1),
                    is_zero.expr() - lt.expr(),
                    lt.expr() - is_zero.expr(),
                )
                .unwrap();

                (Some(is_zero), lt)
            };

            Ok(Self {
                dividend,
                divisor,
                quotient,
                remainder,
                intermediate_mul,
                remainder_lt,
                is_zero,
            })
        })
    }

    pub fn assign_instance<'a>(
        &self,
        instance: &mut [MaybeUninit<E::BaseField>],
        lkm: &mut LkMultiplicity,
        divisor: &Value<'a, u32>,
        quotient: &Value<'a, u32>,
        remainder: &Value<'a, u32>,
    ) -> Result<(), ZKVMError> {
        self.divisor.assign_limbs(instance, divisor.as_u16_limbs());
        self.quotient
            .assign_limbs(instance, quotient.as_u16_limbs());
        self.remainder
            .assign_limbs(instance, remainder.as_u16_limbs());

        let (dividend, intermediate) = divisor.mul_add(quotient, remainder, lkm, true);
        self.remainder_lt
            .assign_instance(instance, lkm, remainder.as_u64(), divisor.as_u64())?;
        self.intermediate_mul
            .assign_mul_outcome(instance, lkm, &intermediate)?;
        self.dividend.assign_add_outcome(instance, &dividend);

        if self.is_zero.is_some() {
            self.is_zero
                .as_ref()
                .unwrap()
                .assign_instance(instance, divisor.as_u64().into())?;
        }
        Ok(())
    }
}
