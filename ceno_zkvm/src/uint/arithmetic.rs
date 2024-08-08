use std::ops::Mul;

use ff_ext::ExtensionField;
use itertools::{izip, Itertools};

use crate::{
    circuit_builder::CircuitBuilder,
    error::ZKVMError,
    expression::{Expression, ToExpr},
};

use super::{uint::UintLimb, UInt};

impl<const M: usize, const C: usize, E: ExtensionField> UInt<M, C, E> {
    pub fn add_const(
        &self,
        _circuit_builder: &CircuitBuilder<E>,
        _constant: Expression<E>,
    ) -> Result<Self, ZKVMError> {
        // TODO
        Ok(self.clone())
    }

    /// Little-endian addition.
    pub fn add(
        &self,
        circuit_builder: &mut CircuitBuilder<E>,
        addend: &UInt<M, C, E>,
    ) -> Result<UInt<M, C, E>, ZKVMError> {
        let mut c = UInt::<M, C, E>::new_expr(circuit_builder);

        // allocate witness cells for carries
        c.carries = (0..Self::NUM_CELLS)
            .map(|_| Some(circuit_builder.create_witin()))
            .collect();

        let a_limbs = self.expr();
        let b_limbs = addend.expr();
        // perform add operation
        c.limbs = UintLimb::Expression(
            a_limbs
                .iter()
                .zip(b_limbs.iter())
                .map(|(a, b)| a.clone() + b.clone())
                .collect_vec(),
        );

        // result check
        // a[i] + b[i] = c[i] + carry[i] * 2 ^ (i*C)
        c.expr()
            .iter()
            .enumerate()
            .map(|(i, expr)| {
                circuit_builder
                    .require_equal(
                        a_limbs[i].clone() + b_limbs[i].clone(),
                        expr.clone()
                            + c.carries.as_mut().unwrap()[i].expr()
                                * 2_usize.pow((i * C) as u32).into(),
                    )
                    .unwrap()
            })
            .collect_vec();

        Ok(c.clone())
    }

    pub fn mul(
        &self,
        circuit_builder: &mut CircuitBuilder<E>,
        multiplier: &UInt<M, C, E>,
    ) -> Result<UInt<M, C, E>, ZKVMError> {
        let mut c = UInt::<M, C, E>::new(circuit_builder);

        // allocate witness cells for carries
        c.carries = (0..Self::NUM_CELLS)
            .map(|_| Some(circuit_builder.create_witin()))
            .collect();

        let a_limbs = self.expr();
        let b_limbs = multiplier.expr();
        let c_limbs = c.expr();

        // perform mul operation
        let t0 = a_limbs[0].clone() * b_limbs[0].clone();
        let t1 = a_limbs[0].clone() * b_limbs[1].clone() + a_limbs[1].clone() * b_limbs[0].clone();
        let t2 = a_limbs[0].clone() * b_limbs[2].clone()
            + a_limbs[1].clone() * b_limbs[1].clone()
            + a_limbs[2].clone() * b_limbs[0].clone();
        let t3 = a_limbs[0].clone() * b_limbs[3].clone()
            + a_limbs[1].clone() * b_limbs[2].clone()
            + a_limbs[2].clone() * b_limbs[1].clone()
            + a_limbs[3].clone() * b_limbs[0].clone();

        // result check
        let pow_of_C = 2_usize.pow(C as u32);
        let pow_of_2C = 2_usize.pow(2 * C as u32);
        let c_carries = c.carries.as_ref().unwrap();
        circuit_builder
            .require_equal(
                t0 + t1 * pow_of_C.into(),
                c_limbs[0].clone()
                    + (c_carries[0].expr() + c_limbs[1].clone()) * pow_of_C.into()
                    + c_carries[1].expr() * pow_of_C.into(),
            )
            .unwrap();
        circuit_builder
            .require_equal(
                t2 + t3 * pow_of_C.into(),
                (c_limbs[2].clone() + c_carries[1].expr())
                    + (c_carries[2].expr() + c_limbs[3].clone()) * pow_of_C.into()
                    + c_carries[3].expr() * pow_of_2C.into(),
            )
            .unwrap();

        Ok(c.clone())
    }

    /// Little-endian addition.
    pub fn eq(
        &self,
        circuit_builder: &mut CircuitBuilder<E>,
        rhs: &UInt<M, C, E>,
    ) -> Result<(), ZKVMError> {
        izip!(self.expr(), rhs.expr())
            .try_for_each(|(lhs, rhs)| circuit_builder.require_equal(lhs, rhs))
    }

    pub fn lt(
        &self,
        circuit_builder: &mut CircuitBuilder<E>,
        rhs: &UInt<M, C, E>,
    ) -> Result<Expression<E>, ZKVMError> {
        Ok(self.expr().remove(0) + 1.into())
    }
}
