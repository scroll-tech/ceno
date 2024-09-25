use std::mem::MaybeUninit;

use ff_ext::ExtensionField;
use goldilocks::SmallField;

use crate::{
    circuit_builder::CircuitBuilder,
    error::ZKVMError,
    expression::{Expression, ToExpr, WitIn},
    set_val,
};

pub struct IsZeroConfig {
    is_zero: WitIn,
    inverse: WitIn,
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
        let inverse = cb.create_witin(|| "inv")?;

        // x==0 => is_zero=1
        cb.require_one(|| "is_zero_1", is_zero.expr() + x.clone() * inverse.expr())?;

        // x!=0 => is_zero=0
        cb.require_zero(|| "is_zero_0", is_zero.expr() * x.clone())?;

        Ok(IsZeroConfig { is_zero, inverse })
    }

    pub fn assign_instance<F: SmallField>(
        &self,
        instance: &mut [MaybeUninit<F>],
        x: F,
    ) -> Result<(), ZKVMError> {
        let (is_zero, inverse) = if x.is_zero_vartime() {
            (F::ONE, F::ZERO)
        } else {
            (F::ZERO, x.invert().expect("not zero"))
        };

        set_val!(instance, self.is_zero, is_zero);
        set_val!(instance, self.inverse, inverse);

        Ok(())
    }
}

pub struct IsEqualConfig(IsZeroConfig);

impl IsEqualConfig {
    pub fn expr<E: ExtensionField>(&self) -> Expression<E> {
        self.0.expr()
    }

    pub fn construct_circuit<E: ExtensionField>(
        cb: &mut CircuitBuilder<E>,
        a: Expression<E>,
        b: Expression<E>,
    ) -> Result<Self, ZKVMError> {
        Ok(IsEqualConfig(IsZeroConfig::construct_circuit(cb, a - b)?))
    }

    pub fn assign_instance<F: SmallField>(
        &self,
        instance: &mut [MaybeUninit<F>],
        a: F,
        b: F,
    ) -> Result<(), ZKVMError> {
        self.0.assign_instance(instance, a - b)
    }
}
