use std::ops::Mul;

use ark_std::iterable::Iterable;
use ff_ext::ExtensionField;
use goldilocks::{Goldilocks, SmallField};
use itertools::{izip, Itertools};
use rayon::iter;

use crate::{
    circuit_builder::CircuitBuilder,
    error::ZKVMError,
    expression::{Expression, ToExpr},
};

use super::{uint::UintLimb, UInt};

impl<const M: usize, const C: usize, E: ExtensionField> UInt<M, C, E> {
    fn internal_add(
        &self,
        circuit_builder: &mut CircuitBuilder<E>,
        addend1: &Vec<Expression<E>>,
        addend2: &Vec<Expression<E>>,
    ) -> Result<UInt<M, C, E>, ZKVMError> {
        let mut c = UInt::<M, C, E>::new_expr(circuit_builder);

        // allocate witness cells for carries
        c.carries = (0..Self::NUM_CELLS)
            .map(|_| Some(circuit_builder.create_witin()))
            .collect();

        // perform add operation
        // c[i] = a[i] + b[i] + carry[i-1] - carry[i] * 2 ^ C
        c.limbs = UintLimb::Expression(
            (*addend1)
                .iter()
                .zip((*addend2).iter())
                .enumerate()
                .map(|(i, (a, b))| {
                    let carry =
                        c.carries.as_ref().unwrap()[i].expr() * 2_usize.pow(C as u32).into();
                    if i != 0 {
                        a.clone() + b.clone() + c.carries.as_ref().unwrap()[i - 1].expr() - carry
                    } else {
                        a.clone() + b.clone() - carry
                    }
                })
                .collect_vec(),
        );

        // result check
        let c_expr = c.expr();
        (0..Self::NUM_CELLS)
            .map(|i| {
                circuit_builder
                    .require_equal(
                        (*addend1)[i].clone() + (*addend2)[i].clone(),
                        c_expr[i].clone(),
                    )
                    .unwrap()
            })
            .collect_vec();

        Ok(c.clone())
    }

    pub fn add_const(
        &self,
        circuit_builder: &mut CircuitBuilder<E>,
        constant: Expression<E>,
    ) -> Result<Self, ZKVMError> {
        let mut b: u64 = 0;
        if let Expression::Constant(c) = constant {
            b = c.to_canonical_u64();
        } else {
            assert!(false, "addend is not a constant type")
        }

        // convert Expression::Constant to limbs
        let b_limbs = (0..Self::NUM_CELLS)
            .map(|i| Expression::Constant(E::BaseField::from((b >> C * i) & 0xFFFF)))
            .collect_vec();

        self.internal_add(circuit_builder, &self.expr(), &b_limbs)
    }

    /// Little-endian addition.
    pub fn add(
        &self,
        circuit_builder: &mut CircuitBuilder<E>,
        addend: &UInt<M, C, E>,
    ) -> Result<UInt<M, C, E>, ZKVMError> {
        self.internal_add(circuit_builder, &self.expr(), &addend.expr())
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

#[cfg(test)]
mod tests {
    use crate::{
        circuit_builder::CircuitBuilder, expression::Expression, scheme::utils::eval_by_expr,
        uint::uint::UInt,
    };
    use ff::Field;
    use goldilocks::{Goldilocks, GoldilocksExt2};
    use itertools::Itertools;

    #[test]
    fn test_uint_add_no_carries() {
        type E = GoldilocksExt2;
        let mut circuit_builder = CircuitBuilder::<E>::new();

        // a = 1 + 1 * 2^16
        // b = 2 + 1 * 2^16
        // c = 3 + 2 * 2^16 with 0 carries
        let a = vec![1, 1, 0, 0];
        let b = vec![2, 1, 0, 0];
        let carries = vec![0; 4];
        let witness_values = [a, b, carries]
            .concat()
            .iter()
            .map(|&a| a.into())
            .collect_vec();
        let challenges = (0..witness_values.len()).map(|_| 1.into()).collect_vec();

        let a = UInt::<64, 16, E>::new(&mut circuit_builder);
        let b = UInt::<64, 16, E>::new(&mut circuit_builder);
        let c = a.add(&mut circuit_builder, &b).unwrap();

        // verify limb_c[] = limb_a[] + limb_b[]
        assert_eq!(
            eval_by_expr(&witness_values, &challenges, &c.expr()[0]),
            E::from(3)
        );
        assert_eq!(
            eval_by_expr(&witness_values, &challenges, &c.expr()[1]),
            E::from(2)
        );
        assert_eq!(
            eval_by_expr(&witness_values, &challenges, &c.expr()[2]),
            E::ZERO
        );
        assert_eq!(
            eval_by_expr(&witness_values, &challenges, &c.expr()[3]),
            E::ZERO
        );
    }

    #[test]
    fn test_uint_add_w_carries() {
        type E = GoldilocksExt2;
        let mut circuit_builder = CircuitBuilder::<E>::new();

        // a = 65535 + 1 * 2^16
        // b =   2   + 1 * 2^16
        // c =   1   + 3 * 2^16 with carries [1, 0, 0, 0]
        let a = vec![0xFFFF, 1, 0, 0];
        let b = vec![2, 1, 0, 0];
        let carries = vec![1, 0, 0, 0];
        let witness_values = [a, b, carries]
            .concat()
            .iter()
            .map(|&a| a.into())
            .collect_vec();
        let challenges = (0..witness_values.len()).map(|_| 1.into()).collect_vec();

        let a = UInt::<64, 16, E>::new(&mut circuit_builder);
        let b = UInt::<64, 16, E>::new(&mut circuit_builder);
        let c = a.add(&mut circuit_builder, &b).unwrap();

        // verify limb_c[] = limb_a[] + limb_b[]
        assert_eq!(
            eval_by_expr(&witness_values, &challenges, &c.expr()[0]),
            E::ONE
        );
        assert_eq!(
            eval_by_expr(&witness_values, &challenges, &c.expr()[1]),
            E::from(3)
        );
        assert_eq!(
            eval_by_expr(&witness_values, &challenges, &c.expr()[2]),
            E::ZERO
        );
        assert_eq!(
            eval_by_expr(&witness_values, &challenges, &c.expr()[3]),
            E::ZERO
        );
    }

    #[test]
    fn test_uint_add_w_carries2() {
        type E = GoldilocksExt2;
        let mut circuit_builder = CircuitBuilder::<E>::new();

        // a = 65535 + 65534 * 2^16
        // b =   2   +   1   * 2^16
        // c =   1   +   0   * 2^16 + 1 * 2^32 with carries [1, 1, 0, 0]
        let a = vec![0xFFFF, 0xFFFE, 0, 0];
        let b = vec![2, 1, 0, 0];
        let carries = vec![1, 1, 0, 0];
        let witness_values = [a, b, carries]
            .concat()
            .iter()
            .map(|&a| a.into())
            .collect_vec();
        let challenges = (0..witness_values.len()).map(|_| 1.into()).collect_vec();

        let a = UInt::<64, 16, E>::new(&mut circuit_builder);
        let b = UInt::<64, 16, E>::new(&mut circuit_builder);
        let c = a.add(&mut circuit_builder, &b).unwrap();

        // verify limb_c[] = limb_a[] + limb_b[]
        assert_eq!(
            eval_by_expr(&witness_values, &challenges, &c.expr()[0]),
            E::ONE
        );
        assert_eq!(
            eval_by_expr(&witness_values, &challenges, &c.expr()[1]),
            E::ZERO
        );
        assert_eq!(
            eval_by_expr(&witness_values, &challenges, &c.expr()[2]),
            E::ONE
        );
        assert_eq!(
            eval_by_expr(&witness_values, &challenges, &c.expr()[3]),
            E::ZERO
        );
    }

    #[test]
    fn test_uint_add_w_overflow() {
        type E = GoldilocksExt2;
        let mut circuit_builder = CircuitBuilder::<E>::new();

        // a = 1 + 1 * 2^16 + 0 + 65535 * 2^48
        // b = 2 + 1 * 2^16 + 0 +     2 * 2^48
        // c = 3 + 2 * 2^16 + 0 +     1 * 2^48 with carries [0, 0, 0, 1]
        let a = vec![1, 1, 0, 0xFFFF];
        let b = vec![2, 1, 0, 2];
        let carries = vec![0, 0, 0, 1];
        let witness_values = [a, b, carries]
            .concat()
            .iter()
            .map(|&a| a.into())
            .collect_vec();
        let challenges = (0..witness_values.len()).map(|_| 1.into()).collect_vec();

        let a = UInt::<64, 16, E>::new(&mut circuit_builder);
        let b = UInt::<64, 16, E>::new(&mut circuit_builder);
        let c = a.add(&mut circuit_builder, &b).unwrap();

        // verify limb_c[] = limb_a[] + limb_b[]
        assert_eq!(
            eval_by_expr(&witness_values, &challenges, &c.expr()[0]),
            E::from(3)
        );
        assert_eq!(
            eval_by_expr(&witness_values, &challenges, &c.expr()[1]),
            E::from(2)
        );
        assert_eq!(
            eval_by_expr(&witness_values, &challenges, &c.expr()[2]),
            E::ZERO
        );
        assert_eq!(
            eval_by_expr(&witness_values, &challenges, &c.expr()[3]),
            E::ONE
        );
    }

    #[test]
    fn test_uint_add_const_no_carries() {
        type E = GoldilocksExt2;
        let mut circuit_builder = CircuitBuilder::<E>::new();

        // a = 1 + 1 * 2^16
        // b = 2 + 1 * 2^16
        // c = 3 + 2 * 2^16 with 0 carries
        let a = vec![1, 1, 0, 0];
        // let b = vec![2, 1, 0, 0];
        let carries = vec![0; 4];
        let witness_values = [a, carries]
            .concat()
            .iter()
            .map(|&a| a.into())
            .collect_vec();
        let challenges = (0..witness_values.len()).map(|_| 1.into()).collect_vec();

        let a = UInt::<64, 16, E>::new(&mut circuit_builder);
        let b = Expression::Constant(2.into());
        let c = a.add_const(&mut circuit_builder, b).unwrap();

        // verify limb_c[] = limb_a[] + limb_b[]
        assert_eq!(
            eval_by_expr(&witness_values, &challenges, &c.expr()[0]),
            E::from(3)
        );
        assert_eq!(
            eval_by_expr(&witness_values, &challenges, &c.expr()[1]),
            E::ONE
        );
        assert_eq!(
            eval_by_expr(&witness_values, &challenges, &c.expr()[2]),
            E::ZERO
        );
        assert_eq!(
            eval_by_expr(&witness_values, &challenges, &c.expr()[3]),
            E::ZERO
        );
    }

    #[test]
    fn test_uint_add_const_w_carries() {
        type E = GoldilocksExt2;
        let mut circuit_builder = CircuitBuilder::<E>::new();

        // a = 65535 + 1 * 2^16
        // b =   2   + 1 * 2^16 = 65538
        // c =   1   + 3 * 2^16 with carries [1, 0, 0, 0]
        let a = vec![0xFFFF, 1, 0, 0];
        // let b = vec![2, 1, 0, 0];
        let carries = vec![1, 0, 0, 0];
        let witness_values = [a, carries]
            .concat()
            .iter()
            .map(|&a| a.into())
            .collect_vec();
        let challenges = (0..witness_values.len()).map(|_| 1.into()).collect_vec();

        let a = UInt::<64, 16, E>::new(&mut circuit_builder);
        let b = Expression::Constant(65538.into());
        let c = a.add_const(&mut circuit_builder, b).unwrap();

        // verify limb_c[] = limb_a[] + limb_b[]
        assert_eq!(
            eval_by_expr(&witness_values, &challenges, &c.expr()[0]),
            E::ONE
        );
        assert_eq!(
            eval_by_expr(&witness_values, &challenges, &c.expr()[1]),
            E::from(3)
        );
        assert_eq!(
            eval_by_expr(&witness_values, &challenges, &c.expr()[2]),
            E::ZERO
        );
        assert_eq!(
            eval_by_expr(&witness_values, &challenges, &c.expr()[3]),
            E::ZERO
        );
    }
}
