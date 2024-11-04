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
    is_zero: Option<WitIn>,
    inverse: WitIn,
}

impl IsZeroConfig {
    pub fn expr<E: ExtensionField>(&self) -> Expression<E> {
        self.is_zero.map(|wit| wit.expr()).unwrap_or(0.into())
    }

    pub fn construct_circuit<E: ExtensionField, NR: Into<String>, N: FnOnce() -> NR>(
        cb: &mut CircuitBuilder<E>,
        name_fn: N,
        x: Expression<E>,
    ) -> Result<Self, ZKVMError> {
        Self::construct(cb, name_fn, x, false)
    }

    pub fn construct_non_zero<E: ExtensionField, NR: Into<String>, N: FnOnce() -> NR>(
        cb: &mut CircuitBuilder<E>,
        name_fn: N,
        x: Expression<E>,
    ) -> Result<Self, ZKVMError> {
        Self::construct(cb, name_fn, x, true)
    }

    fn construct<E: ExtensionField, NR: Into<String>, N: FnOnce() -> NR>(
        cb: &mut CircuitBuilder<E>,
        name_fn: N,
        x: Expression<E>,
        assert_non_zero: bool,
    ) -> Result<Self, ZKVMError> {
        cb.namespace(name_fn, |cb| {
            let (is_zero, is_zero_expr) = if assert_non_zero {
                (None, 0.into())
            } else {
                let is_zero = cb.create_witin(|| "is_zero");

                // x!=0 => is_zero=0
                cb.require_zero(|| "is_zero_0", is_zero.expr() * x.clone())?;

                (Some(is_zero), is_zero.expr())
            };
            let inverse = cb.create_witin(|| "inv");

            // x==0 => is_zero=1
            cb.require_one(|| "is_zero_1", is_zero_expr + x.clone() * inverse.expr())?;

            Ok(IsZeroConfig { is_zero, inverse })
        })
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

        if let Some(wit) = self.is_zero {
            set_val!(instance, wit, is_zero);
        }
        set_val!(instance, self.inverse, inverse);

        Ok(())
    }
}

pub struct IsEqualConfig(IsZeroConfig);

impl IsEqualConfig {
    pub fn expr<E: ExtensionField>(&self) -> Expression<E> {
        self.0.expr()
    }

    pub fn construct_circuit<E: ExtensionField, NR: Into<String>, N: FnOnce() -> NR>(
        cb: &mut CircuitBuilder<E>,
        name_fn: N,
        a: Expression<E>,
        b: Expression<E>,
    ) -> Result<Self, ZKVMError> {
        Ok(IsEqualConfig(IsZeroConfig::construct_circuit(
            cb,
            name_fn,
            a - b,
        )?))
    }

    pub fn construct_non_equal<E: ExtensionField, NR: Into<String>, N: FnOnce() -> NR>(
        cb: &mut CircuitBuilder<E>,
        name_fn: N,
        a: Expression<E>,
        b: Expression<E>,
    ) -> Result<Self, ZKVMError> {
        Ok(IsEqualConfig(IsZeroConfig::construct_non_zero(
            cb,
            name_fn,
            a - b,
        )?))
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
