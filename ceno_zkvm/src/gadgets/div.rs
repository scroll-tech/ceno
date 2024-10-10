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
    pub r_lt: IsLtConfig,
    pub intermediate_mul: UInt<E>,
}

impl<E: ExtensionField> DivConfig<E> {
    /// giving divisor, quotient, and remainder
    /// deriving dividend and respective constrains
    /// NOTE once divisor is zero, then constrain will always failed
    pub fn construct_circuit<NR: Into<String> + Display + Clone, N: FnOnce() -> NR>(
        circuit_builder: &mut CircuitBuilder<E>,
        name_fn: N,
        divisor: &mut UInt<E>,
        quotient: &mut UInt<E>,
        remainder: &UInt<E>,
    ) -> Result<Self, ZKVMError> {
        circuit_builder.namespace(name_fn, |cb| {
            let (dividend, intermediate_mul) =
                divisor.mul_add(|| "divisor * outcome + r", cb, quotient, remainder, true)?;

            let r_lt = IsLtConfig::construct_circuit(
                cb,
                || "remainder < divisor",
                remainder.value(),
                divisor.value(),
                Some(true),
                UINT_LIMBS,
            )?;

            Ok(Self {
                dividend,
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
        let (dividend, intermediate) = divisor.mul_add(quotient, remainder, lkm, true);
        self.r_lt
            .assign_instance(instance, lkm, remainder.as_u64(), divisor.as_u64())?;
        self.intermediate_mul
            .assign_mul_outcome(instance, lkm, &intermediate)?;
        self.dividend.assign_add_outcome(instance, &dividend);
        Ok(())
    }
}
