use ff_ext::ExtensionField;
use goldilocks::SmallField;
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

    /// decompose x = (x_s, x_{<s})
    /// where x_s is highest bit, x_{<s} is the rest
    pub fn msb_decompose<F: SmallField, E: ExtensionField<BaseField = F>>(
        &self,
        circuit_builder: &mut CircuitBuilder<E>,
    ) -> Result<(Expression<E>, Expression<E>), ZKVMError> {
        let l = circuit_builder.create_witin();
        let h = circuit_builder.create_witin();
        let h_mask = circuit_builder.create_witin();
        let high_limb = self.values[Self::N_OPERAND_CELLS - 1].expr();

        circuit_builder.assert_byte(l.expr())?;
        circuit_builder.assert_byte(h.expr())?;
        circuit_builder
            .require_zero(l.expr() + h.expr() * Expression::from(1 << 8) - high_limb.clone())?;
        circuit_builder.lookup_and_byte(h_mask.expr(), h.expr(), Expression::from(1 << 7))?;

        let inv_128 = F::from(128).invert().unwrap();
        let msb = (h.expr() - h_mask.expr()) * Expression::Constant(inv_128);
        let high_limb_mask = l.expr() + h_mask.expr() * Expression::from(1 << 8);
        Ok((msb, high_limb_mask))
    }
}
