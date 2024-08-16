use std::ops::Mul;

use ark_std::iterable::Iterable;
use ff_ext::ExtensionField;
use goldilocks::SmallField;
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
                    let carries = c.carries.as_ref().unwrap();
                    let carry = carries[i].expr() * 2_usize.pow(C as u32).into();
                    if i > 0 {
                        a.clone() + b.clone() + carries[i - 1].expr() - carry
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
        let c_carries = c.carries.as_ref().unwrap();

        let a_expr = self.expr();
        let b_expr = multiplier.expr();
        let c_expr = c.expr();

        // perform mul operation
        let pow_of_C = 2_usize.pow(C as u32);
        let pow_of_2C = 2_usize.pow(2 * C as u32);
        let t0 = a_expr[0].clone() * b_expr[0].clone() - c_carries[0].expr() * pow_of_C.into();
        let t1 = a_expr[0].clone() * b_expr[1].clone() + a_expr[1].clone() * b_expr[0].clone()
            - c_carries[1].expr() * pow_of_C.into();
        let t2 = a_expr[0].clone() * b_expr[2].clone()
            + a_expr[1].clone() * b_expr[1].clone()
            + a_expr[2].clone() * b_expr[0].clone()
            - c_carries[2].expr() * pow_of_C.into();
        let t3 = a_expr[0].clone() * b_expr[3].clone()
            + a_expr[1].clone() * b_expr[2].clone()
            + a_expr[2].clone() * b_expr[1].clone()
            + a_expr[3].clone() * b_expr[0].clone()
            - c_carries[3].expr() * pow_of_C.into();

        // t0 - t4 are degree 2, but we only support monomial form now.
        // So, we do a small trick here, constrain that intermediate witness equals the expression (t1 - t4)
        // And then using the intermediate witness for the following computations.
        let inter_wits = UInt::<M, C, E>::new(circuit_builder).expr();
        circuit_builder
            .require_equal(inter_wits[0].clone(), t0)
            .unwrap();
        circuit_builder
            .require_equal(inter_wits[1].clone(), t1)
            .unwrap();
        circuit_builder
            .require_equal(inter_wits[2].clone(), t2)
            .unwrap();
        circuit_builder
            .require_equal(inter_wits[3].clone(), t3)
            .unwrap();

        // result check
        circuit_builder
            .require_equal(
                c_expr[0].clone() + c_expr[1].clone() * pow_of_C.into(),
                inter_wits[0].clone()
                    + (c_carries[0].expr() + inter_wits[1].clone()) * pow_of_C.into()
                    - c_carries[1].expr() * pow_of_2C.into(),
            )
            .unwrap();
        circuit_builder
            .require_equal(
                c_expr[2].clone() + c_expr[3].clone() * pow_of_C.into(),
                inter_wits[2].clone()
                    + (c_carries[2].expr() + inter_wits[3].clone()) * pow_of_C.into()
                    - c_carries[3].expr() * pow_of_2C.into(),
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

    mod add {
        use crate::{
            circuit_builder::CircuitBuilder, expression::Expression, scheme::utils::eval_by_expr,
            uint::uint::UInt,
        };
        use ff::Field;
        use goldilocks::GoldilocksExt2;
        use itertools::Itertools;

        type E = GoldilocksExt2;
        #[test]
        fn test_add_no_carries() {
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
        fn test_add_w_carry() {
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
        fn test_add_w_carries() {
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
        fn test_add_w_overflow() {
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
        fn test_add_const_no_carries() {
            let mut circuit_builder = CircuitBuilder::<E>::new();

            // a = 1 + 1 * 2^16
            // b = 2 + 1 * 2^16
            // c = 3 + 2 * 2^16 with 0 carries
            let a = vec![1, 1, 0, 0];
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
        fn test_add_const_w_carries() {
            let mut circuit_builder = CircuitBuilder::<E>::new();

            // a = 65535 + 65534 * 2^16
            // b =   2   +   1   * 2^16
            // c =   1   +   0   * 2^16 + 1 * 2^32 with carries [1, 1, 0, 0]
            let a = vec![0xFFFF, 0xFFFE, 0, 0];
            let carries = vec![1, 1, 0, 0];
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
    }

    mod mul {
        use crate::{
            circuit_builder::CircuitBuilder, expression::Expression, scheme::utils::eval_by_expr,
            uint::uint::UInt,
        };
        use ff_ext::ExtensionField;
        use goldilocks::GoldilocksExt2;
        use itertools::Itertools;

        type E = GoldilocksExt2;
        // 18446744069414584321

        #[test]
        fn test_mul_no_carries() {
            // a = 1 + 1 * 2^16
            // b = 2 + 1 * 2^16
            // c = 2 + 3 * 2^16 + 1 * 2^32 = 4,295,163,906
            let wit_a = vec![1, 1, 0, 0];
            let wit_b = vec![2, 1, 0, 0];
            let wit_c = vec![2, 3, 1, 0];
            let wit_carries = vec![0, 0, 0, 0];
            let wit_inter_values = vec![2, 3, 1, 0];
            let witness_values: Vec<E> = [
                wit_a,
                wit_b,
                wit_c.clone(),
                wit_carries.clone(),
                wit_inter_values.clone(),
            ]
            .concat()
            .iter()
            .map(|&a| a.into())
            .collect_vec();

            verify(witness_values, wit_c, wit_carries, wit_inter_values);
        }

        #[test]
        fn test_mul_w_carry() {
            // a = 256 + 1 * 2^16
            // b = 257 + 1 * 2^16
            // c = 256 + 514 * 2^16 + 1 * 2^32 = 4,328,653,056
            let wit_a = vec![256, 1, 0, 0];
            let wit_b = vec![257, 1, 0, 0];
            let wit_c = vec![256, 513, 1, 0];
            let wit_carries = vec![1, 0, 0, 0];
            let wit_inter_values = vec![256, 513, 1, 0];
            let witness_values: Vec<E> = [
                wit_a,
                wit_b,
                wit_c.clone(),
                wit_carries.clone(),
                wit_inter_values.clone(),
            ]
            .concat()
            .iter()
            .map(|&a| a.into())
            .collect_vec();

            verify(witness_values, wit_c, wit_carries, wit_inter_values);
        }

        #[test]
        fn test_mul_w_carries() {
            // a = 256 + 256 * 2^16 = 16,777,472
            // b = 257 + 256 * 2^16 = 16,777,473
            // c = 256 + 257 * 2^16 + 2 * 2^32 + 1 * 2^48 = 281,483,583,488,256
            let wit_a = vec![256, 256, 0, 0];
            let wit_b = vec![257, 256, 0, 0];
            // result = [256 * 257, 256*256 + 256*257, 256*256, 0]
            // ==> [256 + 1 * (2^16), 256 + 2 * (2^16), 0 + 1 * (2^16), 0]
            // so we get wit_c = [256, 256, 0, 0] and carries = [1, 2, 1, 0]
            let wit_c = vec![256, 256, 0, 0];
            let wit_carries = vec![1, 2, 1, 0];
            let wit_inter_values = vec![256, 256, 0, 0];
            let witness_values: Vec<E> = [
                wit_a,
                wit_b,
                wit_c.clone(),
                wit_carries.clone(),
                wit_inter_values.clone(),
            ]
            .concat()
            .iter()
            .map(|&a| a.into())
            .collect_vec();

            verify(witness_values, wit_c, wit_carries, wit_inter_values);
        }

        fn verify<E: ExtensionField>(
            witness_values: Vec<E>,
            wit_c: Vec<u64>,
            wit_carries: Vec<u64>,
            wit_inter_values: Vec<u64>,
        ) {
            let mut circuit_builder = CircuitBuilder::<E>::new();
            let challenges = (0..witness_values.len()).map(|_| 1.into()).collect_vec();

            let uint_a = UInt::<64, 16, E>::new(&mut circuit_builder);
            let uint_b = UInt::<64, 16, E>::new(&mut circuit_builder);
            let uint_c = uint_a.mul(&mut circuit_builder, &uint_b).unwrap();

            let a = uint_a.expr();
            let b = uint_b.expr();
            let c = uint_c.expr();
            assert_eq!(
                eval_by_expr(&witness_values, &challenges, &c[0]),
                E::from(wit_c.clone()[0])
            );
            assert_eq!(
                eval_by_expr(&witness_values, &challenges, &c[1]),
                E::from(wit_c.clone()[1] + wit_carries[0])
            );
            assert_eq!(
                eval_by_expr(&witness_values, &challenges, &c[2]),
                E::from(wit_c.clone()[2] + wit_carries[1])
            );
            assert_eq!(
                eval_by_expr(&witness_values, &challenges, &c[3]),
                E::from(wit_c[3] + wit_carries[2])
            );

            // verify the intermediate witness constraints
            let pow_of_C = 2_usize.pow(16 as u32) as u64;
            let t0 = a[0].clone() * b[0].clone()
                - Expression::Constant((wit_carries.clone()[0] * pow_of_C).into());
            let t1 = a[0].clone() * b[1].clone() + a[1].clone() * b[0].clone()
                - Expression::Constant((wit_carries.clone()[1] * pow_of_C).into());
            let t2 = a[0].clone() * b[2].clone()
                + a[1].clone() * b[1].clone()
                + a[2].clone() * b[0].clone()
                - Expression::Constant((wit_carries.clone()[2] * pow_of_C).into());
            let t3 = a[0].clone() * b[3].clone()
                + a[1].clone() * b[2].clone()
                + a[2].clone() * b[1].clone()
                + a[3].clone() * b[0].clone()
                - Expression::Constant((wit_carries.clone()[3] * pow_of_C).into());
            assert_eq!(
                eval_by_expr(&witness_values, &challenges, &t0),
                E::from(wit_inter_values[0])
            );
            assert_eq!(
                eval_by_expr(&witness_values, &challenges, &t1),
                E::from(wit_inter_values[1])
            );
            assert_eq!(
                eval_by_expr(&witness_values, &challenges, &t2),
                E::from(wit_inter_values[2])
            );
            assert_eq!(
                eval_by_expr(&witness_values, &challenges, &t3),
                E::from(wit_inter_values[3])
            );
        }
    }
}
