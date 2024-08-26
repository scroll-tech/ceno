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

    // when flag is true, return lhs
    // otherwise return rhs
    pub fn select_if<E: ExtensionField>(
        _circuit_builder: &mut CircuitBuilder<E>,
        _flag: Expression<E>,
        _lhs: UInt<M, C>,
        _rhs: UInt<M, C>,
    ) -> Result<UInt<M, C>, ZKVMError> {
        // we need represent UInt limb as expression
        todo!()
    }

    /// return the most significant bit
    pub fn msb<E: ExtensionField>(
        &self,
        _circuit_builder: &mut CircuitBuilder<E>,
    ) -> Result<Expression<E>, ZKVMError> {
        todo!()
    }
}
