use std::mem::MaybeUninit;

use ff::Field;
use ff_ext::ExtensionField;

use crate::{
    circuit_builder::CircuitBuilder,
    error::ZKVMError,
    expression::{Expression, ToExpr, WitIn},
    set_val,
    witness::LkMultiplicity,
};

pub struct IsZeroConfig {
    is_zero: WitIn,
}

impl IsZeroConfig {
    pub fn expr<E: ExtensionField>(&self) -> Expression<E> {
        self.is_zero.expr()
    }

    pub fn construct_circuit<E: ExtensionField>(
        cb: &mut CircuitBuilder<E>,
        x: Expression<E>,
    ) -> Result<Self, ZKVMError> {
        let is_zero = cb.create_witin(|| "is_zero")?;

        // TODO: constraint.

        Ok(IsZeroConfig { is_zero })
    }

    pub fn assign_instance<E: ExtensionField>(
        &self,
        instance: &mut [MaybeUninit<<E as ExtensionField>::BaseField>],
        lk_multiplicity: &mut LkMultiplicity,
        x: &<E as ExtensionField>::BaseField,
    ) -> Result<(), ZKVMError> {
        set_val!(
            instance,
            self.is_zero,
            if x.is_zero_vartime() {
                E::BaseField::ONE
            } else {
                E::BaseField::ZERO
            }
        );

        Ok(())
    }
}
