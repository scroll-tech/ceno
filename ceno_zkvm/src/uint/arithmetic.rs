use ff_ext::ExtensionField;
use goldilocks::SmallField;
use itertools::{izip, Itertools};

use super::{UInt, UintLimb};
use crate::{
    circuit_builder::CircuitBuilder,
    create_witin_from_expr,
    error::ZKVMError,
    expression::{Expression, ToExpr, WitIn},
    instructions::riscv::config::{IsEqualConfig, LtConfig, LtuConfig, MsbConfig},
};

impl<const M: usize, const C: usize, E: ExtensionField> UInt<M, C, E> {
    const POW_OF_C: usize = 2_usize.pow(C as u32);
    const LIMB_BIT_MASK: u64 = (1 << C) - 1;

    fn internal_add(
        &self,
        circuit_builder: &mut CircuitBuilder<E>,
        addend1: &Vec<Expression<E>>,
        addend2: &Vec<Expression<E>>,
        with_overflow: bool,
    ) -> Result<UInt<M, C, E>, ZKVMError> {
        let mut c = UInt::<M, C, E>::new_as_empty();

        // allocate witness cells and do range checks for carries
        c.create_carry_witin(|| "carry", circuit_builder, with_overflow)?;

        // perform add operation
        // c[i] = a[i] + b[i] + carry[i-1] - carry[i] * 2 ^ C
        c.limbs = UintLimb::Expression(
            (*addend1)
                .iter()
                .zip((*addend2).iter())
                .enumerate()
                .map(|(i, (a, b))| {
                    let carries = c.carries.as_ref().unwrap();
                    let limb_expr = match (
                        if i > 0 { carries.get(i - 1) } else { None },
                        carries.get(i),
                    ) {
                        // first limb
                        (None, Some(next_carry)) => {
                            a.clone() + b.clone() - next_carry.expr() * Self::POW_OF_C.into()
                        }
                        // assert no overflow
                        (Some(carry), None) => {
                            debug_assert!(!with_overflow);
                            a.clone() + b.clone() + carry.expr()
                        }
                        (Some(carry), Some(next_carry)) => {
                            a.clone() + b.clone() + carry.expr()
                                - next_carry.expr() * Self::POW_OF_C.into()
                        }
                        (None, None) => unreachable!(),
                    };
                    circuit_builder
                        .assert_ux::<_, _, C>(|| format!("limb_{i}_in_{C}"), limb_expr.clone())?;
                    Ok(limb_expr)
                })
                .collect::<Result<Vec<Expression<E>>, ZKVMError>>()?,
        );

        Ok(c)
    }

    pub fn add_const<NR: Into<String>, N: FnOnce() -> NR>(
        &self,
        name_fn: N,
        circuit_builder: &mut CircuitBuilder<E>,
        constant: Expression<E>,
        with_overflow: bool,
    ) -> Result<Self, ZKVMError> {
        circuit_builder.namespace(name_fn, |cb| {
            let Expression::Constant(c) = constant else {
                panic!("addend is not a constant type");
            };
            let b = c.to_canonical_u64();

            // convert Expression::Constant to limbs
            let b_limbs = (0..Self::NUM_CELLS)
                .map(|i| {
                    Expression::Constant(E::BaseField::from((b >> (C * i)) & Self::LIMB_BIT_MASK))
                })
                .collect_vec();

            self.internal_add(cb, &self.expr(), &b_limbs, with_overflow)
        })
    }

    /// Little-endian addition.
    pub fn add<NR: Into<String>, N: FnOnce() -> NR>(
        &self,
        name_fn: N,
        circuit_builder: &mut CircuitBuilder<E>,
        addend: &UInt<M, C, E>,
        with_overflow: bool,
    ) -> Result<UInt<M, C, E>, ZKVMError> {
        circuit_builder.namespace(name_fn, |cb| {
            self.internal_add(cb, &self.expr(), &addend.expr(), with_overflow)
        })
    }

    fn internal_mul(
        &mut self,
        circuit_builder: &mut CircuitBuilder<E>,
        multiplier: &mut UInt<M, C, E>,
        with_overflow: bool,
    ) -> Result<UInt<M, C, E>, ZKVMError> {
        let mut c = UInt::<M, C, E>::new(|| "c", circuit_builder)?;
        // allocate witness cells and do range checks for carries
        c.create_carry_witin(|| "carry", circuit_builder, with_overflow)?;

        // We only allow expressions are in monomial form
        // if any of a or b is in Expression term, it would cause error.
        // So a small trick here, creating a witness and constrain the witness and the expression is equal
        let mut create_expr = |u: &mut UInt<M, C, E>| -> Result<Vec<Expression<E>>, ZKVMError> {
            if u.is_expr() {
                let existing_expr = u.expr();
                // this will overwrite existing expressions
                u.replace_limbs_with_witin(|| "replace_limbs_with_witin", circuit_builder)?;
                // check if the new witness equals the existing expression
                izip!(u.expr(), existing_expr).try_for_each(|(lhs, rhs)| {
                    circuit_builder.require_equal(|| "new_witin_equal_expr", lhs, rhs)
                })?;
            }
            Ok(u.expr())
        };

        let a_expr = create_expr(self)?;
        let b_expr = create_expr(multiplier)?;

        // result check
        let c_expr = c.expr();
        let c_carries = c.carries.as_ref().unwrap();

        // TODO #174
        // a_expr[0] * b_expr[0] - c_carry[0] * 2^C = c_expr[0]
        circuit_builder.require_equal(
            || "c_expr[0]",
            a_expr[0].clone() * b_expr[0].clone() - c_carries[0].expr() * Self::POW_OF_C.into(),
            c_expr[0].clone(),
        )?;
        // a_expr[0] * b_expr[1] + a_expr[1] * b_expr[0] -  c_carry[1] * 2^C + c_carry[0] = c_expr[1]
        circuit_builder.require_equal(
            || "c_expr[1]",
            a_expr[0].clone() * b_expr[0].clone() - c_carries[1].expr() * Self::POW_OF_C.into()
                + c_carries[0].expr(),
            c_expr[1].clone(),
        )?;
        // a_expr[0] * b_expr[2] + a_expr[1] * b_expr[1] + a_expr[2] * b_expr[0] -
        // c_carry[2] * 2^C + c_carry[1] = c_expr[2]
        circuit_builder.require_equal(
            || "c_expr[2]",
            a_expr[0].clone() * b_expr[2].clone()
                + a_expr[1].clone() * b_expr[1].clone()
                + a_expr[2].clone() * b_expr[0].clone()
                - c_carries[2].expr() * Self::POW_OF_C.into()
                + c_carries[1].expr(),
            c_expr[2].clone(),
        )?;
        // a_expr[0] * b_expr[3] + a_expr[1] * b_expr[2] + a_expr[2] * b_expr[1] +
        // a_expr[3] * b_expr[0] - c_carry[3] * 2^C + c_carry[2] = c_expr[3]
        let mut target = a_expr[0].clone() * b_expr[3].clone()
            + a_expr[1].clone() * b_expr[2].clone()
            + a_expr[2].clone() * b_expr[1].clone()
            + a_expr[3].clone() * b_expr[0].clone()
            + c_carries[2].expr();
        if let Some(overflow) = c_carries.get(3) {
            target = target - overflow.expr() * Self::POW_OF_C.into();
        }
        circuit_builder.require_equal(|| "c_expr[3]", target, c_expr[3].clone())?;
        Ok(c)
    }

    pub fn mul<NR: Into<String>, N: FnOnce() -> NR>(
        &mut self,
        name_fn: N,
        circuit_builder: &mut CircuitBuilder<E>,
        multiplier: &mut UInt<M, C, E>,
        with_overflow: bool,
    ) -> Result<UInt<M, C, E>, ZKVMError> {
        circuit_builder.namespace(name_fn, |cb| {
            self.internal_mul(cb, multiplier, with_overflow)
        })
    }

    /// Check two UInt are equal
    pub fn eq<NR: Into<String>, N: FnOnce() -> NR>(
        &self,
        name_fn: N,
        circuit_builder: &mut CircuitBuilder<E>,
        rhs: &UInt<M, C, E>,
    ) -> Result<(), ZKVMError> {
        circuit_builder.namespace(name_fn, |cb| {
            izip!(self.expr(), rhs.expr())
                .try_for_each(|(lhs, rhs)| cb.require_equal(|| "uint_eq", lhs, rhs))
        })
    }

    pub fn lt(
        &self,
        _circuit_builder: &mut CircuitBuilder<E>,
        _rhs: &UInt<M, C, E>,
    ) -> Result<Expression<E>, ZKVMError> {
        Ok(self.expr().remove(0) + 1.into())
    }

    pub fn is_equal(
        &self,
        circuit_builder: &mut CircuitBuilder<E>,
        rhs: &UInt<M, C, E>,
    ) -> Result<IsEqualConfig, ZKVMError> {
        let n_limbs = Self::NUM_CELLS;
        let (is_equal_per_limb, diff_inv_per_limb): (Vec<WitIn>, Vec<WitIn>) = self
            .limbs
            .iter()
            .zip_eq(rhs.limbs.iter())
            .map(|(a, b)| circuit_builder.is_equal(a.expr(), b.expr()))
            .collect::<Result<Vec<(WitIn, WitIn)>, ZKVMError>>()?
            .into_iter()
            .unzip();

        let sum_expr = is_equal_per_limb
            .iter()
            .fold(Expression::from(0), |acc, flag| acc.clone() + flag.expr());

        let sum_flag = create_witin_from_expr!(circuit_builder, false, sum_expr)?;
        let (is_equal, diff_inv) =
            circuit_builder.is_equal(sum_flag.expr(), Expression::from(n_limbs))?;
        Ok(IsEqualConfig {
            is_equal_per_limb,
            diff_inv_per_limb,
            is_equal,
            diff_inv,
        })
    }
}

impl<const M: usize, E: ExtensionField> UInt<M, 8, E> {
    /// decompose x = (x_s, x_{<s})
    /// where x_s is highest bit, x_{<s} is the rest
    pub fn msb_decompose<F: SmallField>(
        &self,
        circuit_builder: &mut CircuitBuilder<E>,
    ) -> Result<MsbConfig, ZKVMError>
    where
        E: ExtensionField<BaseField = F>,
    {
        let high_limb_no_msb = circuit_builder.create_witin(|| "high_limb_mask")?;
        let high_limb = self.limbs[Self::NUM_CELLS - 1].expr();

        circuit_builder.lookup_and_byte(
            high_limb_no_msb.expr(),
            high_limb.clone(),
            Expression::from(1 << 7),
        )?;

        let inv_128 = F::from(128).invert().unwrap();
        let msb = (high_limb - high_limb_no_msb.expr()) * Expression::Constant(inv_128);
        let msb = create_witin_from_expr!(circuit_builder, false, msb)?;
        Ok(MsbConfig {
            msb,
            high_limb_no_msb,
        })
    }

    /// compare unsigned intergers a < b
    pub fn ltu_limb8(
        &self,
        circuit_builder: &mut CircuitBuilder<E>,
        rhs: &UInt<M, 8, E>,
    ) -> Result<LtuConfig, ZKVMError> {
        let n_bytes = Self::NUM_CELLS;
        let indexes: Vec<WitIn> = (0..n_bytes)
            .map(|_| circuit_builder.create_witin(|| "index"))
            .collect::<Result<_, ZKVMError>>()?;

        // indicate the first non-zero byte index i_0 of a[i] - b[i]
        // from high to low
        indexes
            .iter()
            .try_for_each(|idx| circuit_builder.assert_bit(|| "bit assert", idx.expr()))?;
        let index_sum = indexes
            .iter()
            .fold(Expression::from(0), |acc, idx| acc + idx.expr());
        circuit_builder.assert_bit(|| "bit assert", index_sum)?;

        // equal zero if a==b, otherwise equal (a[i_0]-b[i_0])^{-1}
        let byte_diff_inv = circuit_builder.create_witin(|| "byte_diff_inverse")?;

        // define accumulated index sum from high to low
        let si_expr: Vec<Expression<E>> = indexes
            .iter()
            .rev()
            .scan(Expression::from(0), |state, idx| {
                *state = state.clone() + idx.expr();
                Some(state.clone())
            })
            .collect();
        let si = si_expr
            .into_iter()
            .rev()
            .map(|expr| create_witin_from_expr!(circuit_builder, false, expr))
            .collect::<Result<Vec<WitIn>, ZKVMError>>()?;

        // check byte diff that before the first non-zero i_0 equals zero
        si.iter()
            .zip(self.limbs.iter())
            .zip(rhs.limbs.iter())
            .try_for_each(|((flag, a), b)| {
                circuit_builder.require_zero(
                    || "byte diff zero check",
                    a.expr() - b.expr() - flag.expr() * a.expr() + flag.expr() * b.expr(),
                )
            })?;

        // define accumulated byte sum
        // when a!= b, sa should equal the first non-zero byte a[i_0]
        let sa = self
            .limbs
            .iter()
            .zip_eq(indexes.iter())
            .fold(Expression::from(0), |acc, (ai, idx)| {
                acc.clone() + ai.expr() * idx.expr()
            });
        let sb = rhs
            .limbs
            .iter()
            .zip_eq(indexes.iter())
            .fold(Expression::from(0), |acc, (bi, idx)| {
                acc.clone() + bi.expr() * idx.expr()
            });

        // check the first byte difference has a inverse
        // unwrap is safe because vector len > 0
        let lhs_ne_byte = create_witin_from_expr!(circuit_builder, false, sa.clone())?;
        let rhs_ne_byte = create_witin_from_expr!(circuit_builder, false, sb.clone())?;
        let index_ne = si.first().unwrap();
        circuit_builder.require_zero(
            || "byte inverse check",
            lhs_ne_byte.expr() * byte_diff_inv.expr()
                - rhs_ne_byte.expr() * byte_diff_inv.expr()
                - index_ne.expr(),
        )?;

        let is_ltu = circuit_builder.create_witin(|| "is_ltu")?;
        // circuit_builder.assert_bit(is_ltu.expr())?; // lookup ensure it is bit
        // now we know the first non-equal byte pairs is  (lhs_ne_byte, rhs_ne_byte)
        circuit_builder.lookup_ltu_limb8(is_ltu.expr(), lhs_ne_byte.expr(), rhs_ne_byte.expr())?;
        Ok(LtuConfig {
            byte_diff_inv,
            indexes,
            acc_indexes: si,
            lhs_ne_byte,
            rhs_ne_byte,
            is_ltu,
        })
    }

    pub fn lt_limb8(
        &self,
        circuit_builder: &mut CircuitBuilder<E>,
        rhs: &UInt<M, 8, E>,
    ) -> Result<LtConfig, ZKVMError> {
        let is_lt = circuit_builder.create_witin(|| "is_lt")?;
        circuit_builder.assert_bit(|| "assert_bit", is_lt.expr())?;

        let lhs_msb = self.msb_decompose(circuit_builder)?;
        let rhs_msb = rhs.msb_decompose(circuit_builder)?;

        let mut lhs_limbs = self.limbs.iter().copied().collect_vec();
        lhs_limbs[Self::NUM_CELLS - 1] = lhs_msb.high_limb_no_msb;
        let lhs_no_msb = Self::new_from_limbs(&lhs_limbs);
        let mut rhs_limbs = rhs.limbs.iter().copied().collect_vec();
        rhs_limbs[Self::NUM_CELLS - 1] = rhs_msb.high_limb_no_msb;
        let rhs_no_msb = Self::new_from_limbs(&rhs_limbs);

        // (1) compute ltu(a_{<s},b_{<s})
        let is_ltu = lhs_no_msb.ltu_limb8(circuit_builder, &rhs_no_msb)?;
        // (2) compute $lt(a,b)=a_s\cdot (1-b_s)+eq(a_s,b_s)\cdot ltu(a_{<s},b_{<s})$
        // Refer Jolt 5.3: Set Less Than (https://people.cs.georgetown.edu/jthaler/Jolt-paper.pdf)
        let (msb_is_equal, msb_diff_inv) =
            circuit_builder.is_equal(lhs_msb.msb.expr(), rhs_msb.msb.expr())?;
        circuit_builder.require_zero(
            || "is lt zero check",
            lhs_msb.msb.expr() - lhs_msb.msb.expr() * rhs_msb.msb.expr()
                + msb_is_equal.expr() * is_ltu.is_ltu.expr()
                - is_lt.expr(),
        )?;
        Ok(LtConfig {
            lhs_msb,
            rhs_msb,
            msb_is_equal,
            msb_diff_inv,
            is_ltu,
            is_lt,
        })
    }
}

#[cfg(test)]
mod tests {

    mod add {
        use crate::{
            circuit_builder::{CircuitBuilder, ConstraintSystem},
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
            let mut cs = ConstraintSystem::new(|| "test");
            let mut circuit_builder = CircuitBuilder::<E>::new(&mut cs);

            // a = 1 + 1 * 2^16
            // b = 2 + 1 * 2^16
            // c = 3 + 2 * 2^16 with 0 carries
            let a = vec![1, 1, 0, 0];
            let b = vec![2, 1, 0, 0];
            let carries = vec![0; 3]; // no overflow
            let witness_values = [a, b, carries]
                .concat()
                .iter()
                .map(|&a| a.into())
                .collect_vec();
            let challenges = (0..witness_values.len()).map(|_| 1.into()).collect_vec();

            let a = UInt::<64, 16, E>::new(|| "a", &mut circuit_builder).unwrap();
            let b = UInt::<64, 16, E>::new(|| "b", &mut circuit_builder).unwrap();
            let c = a.add(|| "c", &mut circuit_builder, &b, false).unwrap();

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
            // overflow
            assert_eq!(
                eval_by_expr(
                    &witness_values,
                    &challenges,
                    &c.carries.unwrap().last().unwrap().expr()
                ),
                E::ZERO
            );
        }

        #[test]
        fn test_add_w_carry() {
            type E = GoldilocksExt2;
            let mut cs = ConstraintSystem::new(|| "test");
            let mut circuit_builder = CircuitBuilder::<E>::new(&mut cs);

            // a = 65535 + 1 * 2^16
            // b =   2   + 1 * 2^16
            // c =   1   + 3 * 2^16 with carries [1, 0, 0, 0]
            let a = vec![0xFFFF, 1, 0, 0];
            let b = vec![2, 1, 0, 0];
            let carries = vec![1, 0, 0]; // no overflow
            let witness_values = [a, b, carries]
                .concat()
                .iter()
                .map(|&a| a.into())
                .collect_vec();
            let challenges = (0..witness_values.len()).map(|_| 1.into()).collect_vec();

            let a = UInt::<64, 16, E>::new(|| "a", &mut circuit_builder).unwrap();
            let b = UInt::<64, 16, E>::new(|| "b", &mut circuit_builder).unwrap();
            let c = a.add(|| "c", &mut circuit_builder, &b, false).unwrap();

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
            // overflow
            assert_eq!(
                eval_by_expr(
                    &witness_values,
                    &challenges,
                    &c.carries.unwrap().last().unwrap().expr()
                ),
                E::ZERO
            );
        }

        #[test]
        fn test_add_w_carries() {
            let mut cs = ConstraintSystem::new(|| "test");
            let mut circuit_builder = CircuitBuilder::<E>::new(&mut cs);

            // a = 65535 + 65534 * 2^16
            // b =   2   +   1   * 2^16
            // c =   1   +   0   * 2^16 + 1 * 2^32 with carries [1, 1, 0, 0]
            let a = vec![0xFFFF, 0xFFFE, 0, 0];
            let b = vec![2, 1, 0, 0];
            let carries = vec![1, 1, 0]; // no overflow
            let witness_values = [a, b, carries]
                .concat()
                .iter()
                .map(|&a| a.into())
                .collect_vec();
            let challenges = (0..witness_values.len()).map(|_| 1.into()).collect_vec();

            let a = UInt::<64, 16, E>::new(|| "a", &mut circuit_builder).unwrap();
            let b = UInt::<64, 16, E>::new(|| "b", &mut circuit_builder).unwrap();
            let c = a.add(|| "c", &mut circuit_builder, &b, false).unwrap();

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
            // overflow
            assert_eq!(
                eval_by_expr(
                    &witness_values,
                    &challenges,
                    &c.carries.unwrap().last().unwrap().expr()
                ),
                E::ZERO
            );
        }

        #[test]
        fn test_add_w_overflow() {
            let mut cs = ConstraintSystem::new(|| "test");
            let mut circuit_builder = CircuitBuilder::<E>::new(&mut cs);

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

            let a = UInt::<64, 16, E>::new(|| "a", &mut circuit_builder).unwrap();
            let b = UInt::<64, 16, E>::new(|| "b", &mut circuit_builder).unwrap();
            let c = a.add(|| "c", &mut circuit_builder, &b, true).unwrap();

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
            // overflow
            assert_eq!(
                eval_by_expr(
                    &witness_values,
                    &challenges,
                    &c.carries.unwrap().last().unwrap().expr()
                ),
                E::ONE
            );
        }

        #[test]
        fn test_add_const_no_carries() {
            let mut cs = ConstraintSystem::new(|| "test");
            let mut circuit_builder = CircuitBuilder::<E>::new(&mut cs);

            // a = 1 + 1 * 2^16
            // const b = 2
            // c = 3 + 1 * 2^16 with 0 carries
            let a = vec![1, 1, 0, 0];
            let carries = vec![0; 3]; // no overflow
            let witness_values = [a, carries]
                .concat()
                .iter()
                .map(|&a| a.into())
                .collect_vec();
            let challenges = (0..witness_values.len()).map(|_| 1.into()).collect_vec();

            let a = UInt::<64, 16, E>::new(|| "a", &mut circuit_builder).unwrap();
            let b = Expression::Constant(2.into());
            let c = a.add_const(|| "c", &mut circuit_builder, b, false).unwrap();

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
            let mut cs = ConstraintSystem::new(|| "test");
            let mut circuit_builder = CircuitBuilder::<E>::new(&mut cs);

            // a = 65535 + 65534 * 2^16
            // b =   2   +   1   * 2^16
            // c =   1   +   0   * 2^16 + 1 * 2^32 with carries [1, 1, 0, 0]
            let a = vec![0xFFFF, 0xFFFE, 0, 0];
            let carries = vec![1, 1, 0]; // no overflow
            let witness_values = [a, carries]
                .concat()
                .iter()
                .map(|&a| a.into())
                .collect_vec();
            let challenges = (0..witness_values.len()).map(|_| 1.into()).collect_vec();

            let a = UInt::<64, 16, E>::new(|| "a", &mut circuit_builder).unwrap();
            let b = Expression::Constant(65538.into());
            let c = a.add_const(|| "c", &mut circuit_builder, b, false).unwrap();

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
            circuit_builder::{CircuitBuilder, ConstraintSystem},
            expression::ToExpr,
            scheme::utils::eval_by_expr,
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
            verify::<E>(witness_values, false);
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
            verify::<E>(witness_values, false);
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
            verify::<E>(witness_values, true);
        }

        fn verify<E: ExtensionField>(witness_values: Vec<u64>, overflow: bool) {
            let mut cs = ConstraintSystem::new(|| "test");
            let mut circuit_builder = CircuitBuilder::<E>::new(&mut cs);
            let challenges = (0..witness_values.len()).map(|_| 1.into()).collect_vec();

            let mut uint_a = UInt::<64, 16, E>::new(|| "uint_a", &mut circuit_builder).unwrap();
            let mut uint_b = UInt::<64, 16, E>::new(|| "uint_b", &mut circuit_builder).unwrap();
            let uint_c = uint_a
                .mul(|| "uint_c", &mut circuit_builder, &mut uint_b, false)
                .unwrap();

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
            // overflow
            assert_eq!(
                eval_by_expr(
                    &w,
                    &challenges,
                    &uint_c.carries.unwrap().last().unwrap().expr()
                ),
                if overflow { E::ONE } else { E::ZERO }
            );
        }
    }

    mod mul_add {
        use crate::{
            circuit_builder::{CircuitBuilder, ConstraintSystem},
            expression::ToExpr,
            scheme::utils::eval_by_expr,
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
            let c_carries = vec![0; 3]; // no overflow bit
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

            let mut cs = ConstraintSystem::new(|| "test");
            let mut circuit_builder = CircuitBuilder::<E>::new(&mut cs);
            let challenges = (0..witness_values.len()).map(|_| 1.into()).collect_vec();

            let uint_a = UInt::<64, 16, E>::new(|| "uint_a", &mut circuit_builder).unwrap();
            let uint_b = UInt::<64, 16, E>::new(|| "uint_b", &mut circuit_builder).unwrap();
            let mut uint_c = uint_a
                .add(|| "uint_c", &mut circuit_builder, &uint_b, false)
                .unwrap();
            let mut uint_d = UInt::<64, 16, E>::new(|| "uint_d", &mut circuit_builder).unwrap();
            let uint_e = uint_c
                .mul(|| "uint_e", &mut circuit_builder, &mut uint_d, false)
                .unwrap();

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
            let c_carries = vec![0; 3]; // no overflow
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

            let mut cs = ConstraintSystem::new(|| "test");
            let mut circuit_builder = CircuitBuilder::<E>::new(&mut cs);
            let challenges = (0..witness_values.len()).map(|_| 1.into()).collect_vec();

            let uint_a = UInt::<64, 16, E>::new(|| "uint_a", &mut circuit_builder).unwrap();
            let uint_b = UInt::<64, 16, E>::new(|| "uint_b", &mut circuit_builder).unwrap();
            let mut uint_c = uint_a
                .add(|| "uint_c", &mut circuit_builder, &uint_b, false)
                .unwrap();
            let uint_d = UInt::<64, 16, E>::new(|| "uint_d", &mut circuit_builder).unwrap();
            let uint_e = UInt::<64, 16, E>::new(|| "uint_e", &mut circuit_builder).unwrap();
            let mut uint_f = uint_d
                .add(|| "uint_f", &mut circuit_builder, &uint_e, false)
                .unwrap();
            let uint_g = uint_c
                .mul(|| "unit_g", &mut circuit_builder, &mut uint_f, false)
                .unwrap();

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
            let c_carries = vec![0; 3];
            // e = c + d
            let d = vec![1, 1, 0, 0];
            let e = vec![3, 4, 1, 0];
            let e_carries = vec![0; 3];

            let witness_values: Vec<E> = [a, b, c, c_carries, d, e_carries]
                .concat()
                .iter()
                .map(|&a| a.into())
                .collect_vec();

            let mut cs = ConstraintSystem::new(|| "test");
            let mut circuit_builder = CircuitBuilder::<E>::new(&mut cs);
            let challenges = (0..witness_values.len()).map(|_| 1.into()).collect_vec();

            let mut uint_a = UInt::<64, 16, E>::new(|| "uint_a", &mut circuit_builder).unwrap();
            let mut uint_b = UInt::<64, 16, E>::new(|| "uint_b", &mut circuit_builder).unwrap();
            let uint_c = uint_a
                .mul(|| "uint_c", &mut circuit_builder, &mut uint_b, false)
                .unwrap();
            let uint_d = UInt::<64, 16, E>::new(|| "uint_d", &mut circuit_builder).unwrap();
            let uint_e = uint_c
                .add(|| "uint_e", &mut circuit_builder, &uint_d, false)
                .unwrap();

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
