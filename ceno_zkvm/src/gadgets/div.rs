use std::{fmt::Display, mem::MaybeUninit};

use ff_ext::ExtensionField;

use crate::{
    circuit_builder::CircuitBuilder,
    error::ZKVMError,
    instructions::riscv::constants::{UInt, UINT_LIMBS},
    witness::LkMultiplicity,
    Value,
};

use super::IsLtConfig;

/// divide gadget
#[derive(Debug, Clone)]
pub struct DivConfig<E: ExtensionField> {
    pub dividend: UInt<E>,
    pub divisor: UInt<E>,
    pub(crate) quotient: UInt<E>,
    pub remainder: UInt<E>,

    pub intermediate_mul: UInt<E>,
    pub r_lt: IsLtConfig,
}

impl<E: ExtensionField> DivConfig<E> {
    /// giving divisor, quotient, and remainder
    /// deriving dividend and respective constrains
    pub fn construct_circuit<NR: Into<String> + Display + Clone, N: FnOnce() -> NR>(
        circuit_builder: &mut CircuitBuilder<E>,
        name_fn: N,
    ) -> Result<Self, ZKVMError> {
        circuit_builder.namespace(name_fn, |cb| {
            // quotient = dividend / divisor + remainder => dividend = divisor * quotient + r
            let mut divisor = UInt::new_unchecked(|| "divisor", cb)?;
            let mut quotient = UInt::new(|| "quotient", cb)?;
            let remainder = UInt::new(|| "remainder", cb)?;

            let (dividend, intermediate_mul) =
                divisor.mul_add(|| "", cb, &mut quotient, &remainder, true)?;

            // remainder range check
            let r_lt = cb.less_than(
                || "remainder < divisor",
                remainder.value(),
                divisor.value(),
                None,
                UINT_LIMBS,
            )?;
            Ok(Self {
                dividend,
                divisor,
                quotient,
                remainder,
                intermediate_mul,
                r_lt,
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
        self.r_lt
            .assign_instance(instance, lkm, remainder.as_u64(), divisor.as_u64())?;
        self.intermediate_mul
            .assign_mul_outcome(instance, lkm, &intermediate)?;
        self.dividend.assign_add_outcome(instance, &dividend);
        Ok(())
    }
}
