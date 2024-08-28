use ff_ext::ExtensionField;
use goldilocks::SmallField;
use itertools::{izip, Itertools};

use crate::{
    circuit_builder::CircuitBuilder,
    error::ZKVMError,
    expression::{Expression, ToExpr},
};

use super::{UInt, UintLimb};

impl<const M: usize, const C: usize, E: ExtensionField> UInt<M, C, E> {
    const POW_OF_C: usize = 2_usize.pow(C as u32);
    const LIMB_BIT_MASK: u64 = (1 << C) - 1;

    fn internal_add(
        &self,
        circuit_builder: &mut CircuitBuilder<E>,
        addend1: &Vec<Expression<E>>,
        addend2: &Vec<Expression<E>>,
        check_overflow: bool,
    ) -> Result<UInt<M, C, E>, ZKVMError> {
        let mut c = UInt::<M, C, E>::new_limb_as_expr();

        // allocate witness cells and do range checks for carries
        c.create_carry_witin(circuit_builder);

        // perform add operation
        // c[i] = a[i] + b[i] + carry[i-1] - carry[i] * 2 ^ C
        c.limbs = UintLimb::Expression(
            (*addend1)
                .iter()
                .zip((*addend2).iter())
                .enumerate()
                .map(|(i, (a, b))| {
                    let carries = c.carries.as_ref().unwrap();
                    let carry = carries[i].expr() * Self::POW_OF_C.into();
                    if i > 0 {
                        a.clone() + b.clone() + carries[i - 1].expr() - carry
                    } else {
                        a.clone() + b.clone() - carry
                    }
                })
                .collect_vec(),
        );

        // overflow check
        if check_overflow {
            circuit_builder.require_zero(c.carries.as_ref().unwrap().last().unwrap().expr())?;
        }

        Ok(c)
    }

    pub fn add_const(
        &self,
        circuit_builder: &mut CircuitBuilder<E>,
        constant: Expression<E>,
    ) -> Result<Self, ZKVMError> {
        let Expression::Constant(c) = constant else {
            panic!("addend is not a constant type");
        };
        let b = c.to_canonical_u64();

        // convert Expression::Constant to limbs
        let b_limbs = (0..Self::NUM_CELLS)
            .map(|i| Expression::Constant(E::BaseField::from((b >> (C * i)) & Self::LIMB_BIT_MASK)))
            .collect_vec();

        self.internal_add(circuit_builder, &self.expr(), &b_limbs, true)
    }

    /// Little-endian addition.
    pub fn add(
        &self,
        circuit_builder: &mut CircuitBuilder<E>,
        addend: &UInt<M, C, E>,
    ) -> Result<UInt<M, C, E>, ZKVMError> {
        self.internal_add(circuit_builder, &self.expr(), &addend.expr(), true)
    }

    /// Little-endian addition without overflow check
    pub fn add_unsafe(
        &self,
        circuit_builder: &mut CircuitBuilder<E>,
        addend: &UInt<M, C, E>,
    ) -> Result<UInt<M, C, E>, ZKVMError> {
        self.internal_add(circuit_builder, &self.expr(), &addend.expr(), false)
    }

    fn internal_mul(
        &mut self,
        circuit_builder: &mut CircuitBuilder<E>,
        multiplier: &mut UInt<M, C, E>,
        check_overflow: bool,
    ) -> Result<UInt<M, C, E>, ZKVMError> {
        let mut c = UInt::<M, C, E>::new(circuit_builder);
        // allocate witness cells and do range checks for carries
        c.create_carry_witin(circuit_builder);

        // We only allow expressions are in monomial form
        // if any of a or b is in Expression term, it would cause error.
        // So a small trick here, creating a witness and constrain the witness and the expression is equal
        let mut create_expr = |u: &mut UInt<M, C, E>| {
            if u.is_expr() {
                let existing_expr = u.expr();
                // this will overwrite existing expressions
                u.replace_limbs_with_witin(circuit_builder);
                // check if the new witness equals the existing expression
                izip!(u.expr(), existing_expr)
                    .try_for_each(|(lhs, rhs)| circuit_builder.require_equal(lhs, rhs))
                    .unwrap();
            }
            u.expr()
        };

        let a_expr = create_expr(self);
        let b_expr = create_expr(multiplier);

        // result check
        let c_expr = c.expr();
        let c_carries = c.carries.as_ref().unwrap();

        // a_expr[0] * b_expr[0] - c_carry[0] * 2^C = c_expr[0]
        circuit_builder.require_equal(
            a_expr[0].clone() * b_expr[0].clone() - c_carries[0].expr() * Self::POW_OF_C.into(),
            c_expr[0].clone(),
        )?;
        // a_expr[0] * b_expr[1] + a_expr[1] * b_expr[0] -  c_carry[1] * 2^C + c_carry[0] = c_expr[1]
        circuit_builder.require_equal(
            a_expr[0].clone() * b_expr[0].clone() - c_carries[1].expr() * Self::POW_OF_C.into()
                + c_carries[0].expr(),
            c_expr[1].clone(),
        )?;
        // a_expr[0] * b_expr[2] + a_expr[1] * b_expr[1] + a_expr[2] * b_expr[0] -
        // c_carry[2] * 2^C + c_carry[1] = c_expr[2]
        circuit_builder.require_equal(
            a_expr[0].clone() * b_expr[2].clone()
                + a_expr[1].clone() * b_expr[1].clone()
                + a_expr[2].clone() * b_expr[0].clone()
                - c_carries[2].expr() * Self::POW_OF_C.into()
                + c_carries[1].expr(),
            c_expr[2].clone(),
        )?;
        // a_expr[0] * b_expr[3] + a_expr[1] * b_expr[2] + a_expr[2] * b_expr[1] +
        // a_expr[3] * b_expr[0] - c_carry[3] * 2^C + c_carry[2] = c_expr[3]
        circuit_builder.require_equal(
            a_expr[0].clone() * b_expr[3].clone()
                + a_expr[1].clone() * b_expr[2].clone()
                + a_expr[2].clone() * b_expr[1].clone()
                + a_expr[3].clone() * b_expr[0].clone()
                - c_carries[3].expr() * Self::POW_OF_C.into()
                + c_carries[2].expr(),
            c_expr[3].clone(),
        )?;

        // overflow check
        if check_overflow {
            circuit_builder.require_zero(c.carries.as_ref().unwrap().last().unwrap().expr())?;
        }

        Ok(c)
    }

    pub fn mul(
        &mut self,
        circuit_builder: &mut CircuitBuilder<E>,
        multiplier: &mut UInt<M, C, E>,
    ) -> Result<UInt<M, C, E>, ZKVMError> {
        self.internal_mul(circuit_builder, multiplier, true)
    }

    pub fn mul_unsafe(
        &mut self,
        circuit_builder: &mut CircuitBuilder<E>,
        multiplier: &mut UInt<M, C, E>,
    ) -> Result<UInt<M, C, E>, ZKVMError> {
        self.internal_mul(circuit_builder, multiplier, true)
    }

    /// Check two UInt are equal
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
        _circuit_builder: &mut CircuitBuilder<E>,
        _rhs: &UInt<M, C, E>,
    ) -> Result<Expression<E>, ZKVMError> {
        Ok(self.expr().remove(0) + 1.into())
    }
}

#[cfg(test)]
mod tests {

    mod add {
        use crate::{
            circuit_builder::CircuitBuilder,
            expression::{Expression, ToExpr},
            scheme::utils::eval_by_expr,
            uint::UInt,
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
            // const b = 2
            // c = 3 + 1 * 2^16 with 0 carries
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
            circuit_builder::CircuitBuilder, expression::ToExpr, scheme::utils::eval_by_expr,
            uint::UInt,
        };
        use ff_ext::ExtensionField;
        use goldilocks::GoldilocksExt2;
        use itertools::Itertools;

        type E = GoldilocksExt2; // 18446744069414584321
        const POW_OF_C: u64 = 2_usize.pow(16u32) as u64;
        #[test]
        fn test_mul_no_carries() {
            // a = 1 + 1 * 2^16
            // b = 2 + 1 * 2^16
            // c = 2 + 3 * 2^16 + 1 * 2^32 = 4,295,163,906
            let wit_a = vec![1, 1, 0, 0];
            let wit_b = vec![2, 1, 0, 0];
            let wit_c = vec![2, 3, 1, 0];
            let wit_carries = vec![0, 0, 0, 0];
            let witness_values = [wit_a, wit_b, wit_c, wit_carries].concat();
            verify::<E>(witness_values);
        }

        #[test]
        fn test_mul_w_carry() {
            // a = 256 + 1 * 2^16
            // b = 257 + 1 * 2^16
            // c = 256 + 514 * 2^16 + 1 * 2^32 = 4,328,653,056
            let wit_a = vec![256, 1, 0, 0];
            let wit_b = vec![257, 1, 0, 0];
            let wit_c = vec![256, 514, 1, 0];
            let wit_carries = vec![1, 0, 0, 0];
            let witness_values = [wit_a, wit_b, wit_c, wit_carries].concat();
            verify::<E>(witness_values);
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
            let wit_c = vec![256, 257, 2, 1];
            let wit_carries = vec![1, 2, 1, 0];
            let witness_values = [wit_a, wit_b, wit_c, wit_carries].concat();
            verify::<E>(witness_values);
        }

        fn verify<E: ExtensionField>(witness_values: Vec<u64>) {
            let mut circuit_builder = CircuitBuilder::<E>::new();
            let challenges = (0..witness_values.len()).map(|_| 1.into()).collect_vec();

            let mut uint_a = UInt::<64, 16, E>::new(&mut circuit_builder);
            let mut uint_b = UInt::<64, 16, E>::new(&mut circuit_builder);
            let uint_c = uint_a.mul(&mut circuit_builder, &mut uint_b).unwrap();

            let a = &witness_values[0..4];
            let b = &witness_values[4..8];
            let c_carries = &witness_values[12..16];

            // limbs cal.
            let t0 = a[0] * b[0] - c_carries[0] * POW_OF_C;
            let t1 = a[0] * b[1] + a[1] * b[0] - c_carries[1] * POW_OF_C + c_carries[0];
            let t2 =
                a[0] * b[2] + a[1] * b[1] + a[2] * b[0] - c_carries[2] * POW_OF_C + c_carries[1];
            let t3 = a[0] * b[3] + a[1] * b[2] + a[2] * b[1] + a[3] * b[0]
                - c_carries[3] * POW_OF_C
                + c_carries[2];

            // verify
            let c_expr = uint_c.expr();
            let w: Vec<E> = witness_values.iter().map(|&a| a.into()).collect_vec();
            assert_eq!(eval_by_expr(&w, &challenges, &c_expr[0]), E::from(t0));
            assert_eq!(eval_by_expr(&w, &challenges, &c_expr[1]), E::from(t1));
            assert_eq!(eval_by_expr(&w, &challenges, &c_expr[2]), E::from(t2));
            assert_eq!(eval_by_expr(&w, &challenges, &c_expr[3]), E::from(t3));
        }
    }

    mod mul_add {
        use crate::{
            circuit_builder::CircuitBuilder, expression::ToExpr, scheme::utils::eval_by_expr,
            uint::UInt,
        };
        use goldilocks::GoldilocksExt2;
        use itertools::Itertools;

        type E = GoldilocksExt2; // 18446744069414584321
        #[test]
        fn test_add_mul() {
            // c = a + b
            // e = c * d

            // a = 1 + 1 * 2^16
            // b = 2 + 1 * 2^16
            // ==> c = 3 + 2 * 2^16 with 0 carries
            // d = 1 + 1 * 2^16
            // ==> e = 3 + 5 * 2^16 + 2 * 2^32 = 8,590,262,275
            let a = vec![1, 1, 0, 0];
            let b = vec![2, 1, 0, 0];
            let c_carries = vec![0; 4];
            // witness of e = c * d
            let new_c = vec![3, 2, 0, 0];
            let new_c_carries = c_carries.clone();
            let d = vec![1, 1, 0, 0];
            let e = vec![3, 5, 2, 0];
            let e_carries = vec![0; 4];

            let witness_values: Vec<E> = [
                a,
                b,
                c_carries.clone(),
                // e = c * d
                d,
                e.clone(),
                e_carries.clone(),
                new_c,
                new_c_carries,
            ]
            .concat()
            .iter()
            .map(|&a| a.into())
            .collect_vec();

            let mut circuit_builder = CircuitBuilder::<E>::new();
            let challenges = (0..witness_values.len()).map(|_| 1.into()).collect_vec();

            let uint_a = UInt::<64, 16, E>::new(&mut circuit_builder);
            let uint_b = UInt::<64, 16, E>::new(&mut circuit_builder);
            let mut uint_c = uint_a.add(&mut circuit_builder, &uint_b).unwrap();
            let mut uint_d = UInt::<64, 16, E>::new(&mut circuit_builder);
            let uint_e = uint_c.mul(&mut circuit_builder, &mut uint_d).unwrap();

            uint_e.expr().iter().enumerate().for_each(|(i, ret)| {
                // limbs check
                assert_eq!(
                    eval_by_expr(&witness_values, &challenges, ret),
                    E::from(e.clone()[i])
                );
            });
        }

        #[test]
        fn test_add_mul2() {
            // c = a + b
            // f = d + e
            // g = c * f

            // a = 1 + 1 * 2^16
            // b = 2 + 1 * 2^16
            // ==> c = 3 + 2 * 2^16 with 0 carries
            // d = 1 + 1 * 2^16
            // e = 2 + 1 * 2^16
            // ==> f = 3 + 2 * 2^16 with 0 carries
            // ==> e = 9 + 12 * 2^16 + 4 * 2^32 = 17,180,655,625
            let a = vec![1, 1, 0, 0];
            let b = vec![2, 1, 0, 0];
            let c_carries = vec![0; 4];
            // witness of g = c * f
            let new_c = vec![3, 2, 0, 0];
            let new_c_carries = c_carries.clone();
            let g = vec![9, 12, 4, 0];
            let g_carries = vec![0; 4];

            let witness_values: Vec<E> = [
                // c = a + b
                a.clone(),
                b.clone(),
                c_carries.clone(),
                // f = d + e
                a,
                b,
                c_carries.clone(),
                // g = c * f
                g.clone(),
                g_carries,
                new_c.clone(),
                new_c_carries.clone(),
                new_c,
                new_c_carries,
            ]
            .concat()
            .iter()
            .map(|&a| a.into())
            .collect_vec();

            let mut circuit_builder = CircuitBuilder::<E>::new();
            let challenges = (0..witness_values.len()).map(|_| 1.into()).collect_vec();

            let uint_a = UInt::<64, 16, E>::new(&mut circuit_builder);
            let uint_b = UInt::<64, 16, E>::new(&mut circuit_builder);
            let mut uint_c = uint_a.add(&mut circuit_builder, &uint_b).unwrap();
            let uint_d = UInt::<64, 16, E>::new(&mut circuit_builder);
            let uint_e = UInt::<64, 16, E>::new(&mut circuit_builder);
            let mut uint_f = uint_d.add(&mut circuit_builder, &uint_e).unwrap();
            let uint_g = uint_c.mul(&mut circuit_builder, &mut uint_f).unwrap();

            uint_g.expr().iter().enumerate().for_each(|(i, ret)| {
                // limbs check
                assert_eq!(
                    eval_by_expr(&witness_values, &challenges, ret),
                    E::from(g.clone()[i])
                );
            });
        }

        #[test]
        fn test_mul_add() {
            // c = a * b
            // e = c + d

            // a = 1 + 1 * 2^16
            // b = 2 + 1 * 2^16
            // ==> c = 2 + 3 * 2^16 + 1 * 2^32
            // d = 1 + 1 * 2^16
            // ==> e = 3 + 4 * 2^16 + 1 * 2^32
            let a = vec![1, 1, 0, 0];
            let b = vec![2, 1, 0, 0];
            let c = vec![2, 3, 1, 0];
            let c_carries = vec![0; 4];
            // e = c + d
            let d = vec![1, 1, 0, 0];
            let e = vec![3, 4, 1, 0];
            let e_carries = vec![0; 4];

            let witness_values: Vec<E> = [a, b, c, c_carries, d, e_carries]
                .concat()
                .iter()
                .map(|&a| a.into())
                .collect_vec();

            let mut circuit_builder = CircuitBuilder::<E>::new();
            let challenges = (0..witness_values.len()).map(|_| 1.into()).collect_vec();

            let mut uint_a = UInt::<64, 16, E>::new(&mut circuit_builder);
            let mut uint_b = UInt::<64, 16, E>::new(&mut circuit_builder);
            let uint_c = uint_a.mul(&mut circuit_builder, &mut uint_b).unwrap();
            let uint_d = UInt::<64, 16, E>::new(&mut circuit_builder);
            let uint_e = uint_c.add(&mut circuit_builder, &uint_d).unwrap();

            uint_e.expr().iter().enumerate().for_each(|(i, ret)| {
                // limbs check
                assert_eq!(
                    eval_by_expr(&witness_values, &challenges, ret),
                    E::from(e.clone()[i])
                );
            });
        }
    }
}
