use ff_ext::ExtensionField;
use goldilocks::SmallField;
use itertools::{izip, Itertools};

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
    pub fn conditional_select<E: ExtensionField>(
        _circuit_builder: &mut CircuitBuilder<E>,
        _flag: Expression<E>,
        _lhs: UInt<M, C>,
        _rhs: UInt<M, C>,
    ) -> Result<UInt<M, C>, ZKVMError> {
        // we need represent UInt limb as expression
        todo!()
    }
}

impl<const M: usize> UInt<M, 8> {
    /// decompose x = (x_s, x_{<s})
    /// where x_s is highest bit, x_{<s} is the rest
    pub fn msb_decompose<F: SmallField, E: ExtensionField<BaseField = F>>(
        &self,
        circuit_builder: &mut CircuitBuilder<E>,
    ) -> Result<(Expression<E>, Expression<E>), ZKVMError> {
        let high_limb = self.values[Self::N_OPERAND_CELLS - 1].expr();
        let high_limb_mask = circuit_builder.create_witin().expr();

        circuit_builder.lookup_and_byte(
            high_limb_mask.clone(),
            high_limb.clone(),
            Expression::from(1 << 7),
        )?;

        let inv_128 = F::from(128).invert().unwrap();
        let msb = (high_limb - high_limb_mask.clone()) * Expression::Constant(inv_128);
        Ok((msb, high_limb_mask))
    }

    /// compare unsigned intergers a < b
    pub fn ltu<E: ExtensionField>(
        &self,
        circuit_builder: &mut CircuitBuilder<E>,
        rhs: &UInt<M, 8>,
    ) -> Result<Expression<E>, ZKVMError> {
        let n_bytes = Self::N_OPERAND_CELLS;
        let indexes: Vec<WitIn> = (0..n_bytes)
            .map(|_| circuit_builder.create_witin())
            .collect();

        // indicate the first non-zero byte index i_0 of a[i] - b[i]
        indexes
            .iter()
            .try_for_each(|idx| circuit_builder.assert_bit(idx.expr()))?;
        let index_sum = indexes
            .iter()
            .fold(Expression::from(0), |acc, idx| acc + idx.expr());
        circuit_builder.assert_bit(index_sum)?;

        // equal zero if a==b, otherwise equal (a[i_0]-b[i_0])^{-1}
        let byte_diff_inverse = circuit_builder.create_witin();

        // define accumulated index sum
        let si: Vec<Expression<E>> = indexes
            .iter()
            .scan(Expression::from(0), |acc, idx| {
                *acc = acc.clone() + idx.expr();
                Some(acc.clone())
            })
            .collect();

        // check byte diff that before the first non-zero i_0 equals zero
        si.iter()
            .zip(self.values.iter())
            .zip(rhs.values.iter())
            .try_for_each(|((flag, a), b)| {
                circuit_builder
                    .require_zero((Expression::from(1) - flag.clone()) * (a.expr() - b.expr()))
            })?;

        // define accumulated byte sum
        // when a!= b, the last item in sa should equal the first non-zero byte a[i_0]
        let sa: Vec<Expression<E>> = self
            .values
            .iter()
            .zip_eq(indexes.iter())
            .scan(Expression::from(0), |acc, (ai, idx)| {
                *acc = acc.clone() + ai.expr() * idx.expr();
                Some(acc.clone())
            })
            .collect();
        let sb: Vec<Expression<E>> = rhs
            .values
            .iter()
            .zip_eq(indexes.iter())
            .scan(Expression::from(0), |acc, (ai, idx)| {
                *acc = acc.clone() + ai.expr() * idx.expr();
                Some(acc.clone())
            })
            .collect();

        // check the first byte difference has a inverse
        // unwrap is safe because vector len > 0
        let lhs_ne_byte = sa.last().unwrap().clone();
        let rhs_ne_byte = sb.last().unwrap().clone();
        let index_ne = si.last().unwrap().clone();
        circuit_builder.require_zero(
            (lhs_ne_byte.clone() - rhs_ne_byte.clone()) * byte_diff_inverse.expr()
                - index_ne.clone(),
        )?;

        let is_ltu = circuit_builder.create_witin();
        // now we know the first non-equal byte pairs is  (lhs_ne_byte, rhs_ne_byte)
        circuit_builder.lookup_ltu_byte(is_ltu.expr(), lhs_ne_byte, rhs_ne_byte)?;
        Ok(is_ltu.expr())
    }
}
