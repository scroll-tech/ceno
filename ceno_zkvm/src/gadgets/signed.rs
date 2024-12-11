use std::{fmt::Display, mem::MaybeUninit};

use ff_ext::ExtensionField;

use crate::{
    Value,
    circuit_builder::CircuitBuilder,
    error::ZKVMError,
    expression::Expression,
    instructions::riscv::constants::{BIT_WIDTH, UInt},
    witness::LkMultiplicity,
};

use super::SignedExtendConfig;

/// Interprets a `UInt` value as a 2s-complement signed value.
///
/// Uses 1 `WitIn` to represent the most sigificant bit of the value.
pub struct Signed<E: ExtensionField> {
    pub is_negative: SignedExtendConfig<E>,
    val: Expression<E>,
}

impl<E: ExtensionField> Signed<E> {
    pub fn construct_circuit<NR: Into<String> + Display + Clone, N: FnOnce() -> NR>(
        cb: &mut CircuitBuilder<E>,
        name_fn: N,
        unsigned_val: &UInt<E>,
    ) -> Result<Self, ZKVMError> {
        cb.namespace(name_fn, |cb| {
            let is_negative = unsigned_val.is_negative(cb)?;
            let val = unsigned_val.value() - (is_negative.expr() << BIT_WIDTH);

            Ok(Self { is_negative, val })
        })
    }

    pub fn assign_instance(
        &self,
        instance: &mut [MaybeUninit<E::BaseField>],
        lkm: &mut LkMultiplicity,
        val: &Value<u32>,
    ) -> Result<i32, ZKVMError> {
        self.is_negative.assign_instance(
            instance,
            lkm,
            *val.as_u16_limbs().last().unwrap() as u64,
        )?;
        let signed_val = val.as_u32() as i32;

        Ok(signed_val)
    }

    pub fn expr(&self) -> Expression<E> {
        self.val.clone()
    }
}
