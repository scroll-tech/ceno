use ff_ext::ExtensionField;
use itertools::izip;

use crate::{
    circuit_builder::CircuitBuilder,
    error::ZKVMError,
    expression::{Expression, ToExpr, WitIn},
};

use super::UInt;

impl<const M: usize, const C: usize> UInt<M, C> {
    pub fn add_const<E: ExtensionField>(
        &self,
        _circuit_builder: &CircuitBuilder<E>,
        _constant: Expression<E>,
    ) -> Result<Self, ZKVMError> {
        // TODO
        Ok(self.clone())
    }

    /// Little-endian addition.
    pub fn add<E: ExtensionField>(
        &self,
        _circuit_builder: &mut CircuitBuilder<E>,
        _addend_1: &UInt<M, C>,
    ) -> Result<UInt<M, C>, ZKVMError> {
        // TODO
        Ok(self.clone())
    }

    /// Little-endian addition.
    pub fn eq<E: ExtensionField>(
        &self,
        circuit_builder: &mut CircuitBuilder<E>,
        rhs: &UInt<M, C>,
    ) -> Result<(), ZKVMError> {
        izip!(self.expr(), rhs.expr())
            .try_for_each(|(lhs, rhs)| circuit_builder.require_equal(lhs, rhs))
    }

    pub fn lt<E: ExtensionField>(
        &self,
        _circuit_builder: &mut CircuitBuilder<E>,
        _rhs: &UInt<M, C>,
    ) -> Result<Expression<E>, ZKVMError> {
        Ok(self.expr().remove(0) + 1.into())
    }

    /// borrow*(1<<shift) + a - b = diff
    /// return borrow
    pub fn sub_with_borrow<E: ExtensionField>(
        &self,
        circuit_builder: &mut CircuitBuilder<E>,
        _rhs: &UInt<M, C>,
    ) -> Result<WitIn, ZKVMError> {
        // TODO
        let borrow = circuit_builder.create_witin();
        circuit_builder.assert_bit(borrow.expr())?;
        Ok(borrow)
    }
}
