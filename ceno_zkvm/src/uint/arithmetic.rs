use ff_ext::ExtensionField;
use goldilocks::SmallField;
use itertools::{Itertools, izip};

use super::{UIntLimbs, UintLimb};
use crate::{
    circuit_builder::CircuitBuilder,
    error::ZKVMError,
    expression::{Expression, ToExpr, WitIn},
    gadgets::AssertLTConfig,
    instructions::riscv::config::{IsEqualConfig, MsbConfig, UIntLtConfig, UIntLtuConfig},
};

impl<const M: usize, const C: usize, E: ExtensionField> UIntLimbs<M, C, E> {
    const POW_OF_C: usize = 2_usize.pow(C as u32);
    const LIMB_BIT_MASK: u64 = (1 << C) - 1;

    fn internal_add(
        &self,
        circuit_builder: &mut CircuitBuilder<E>,
        addend: &Vec<Expression<E>>,
        with_overflow: bool,
    ) -> Result<UIntLimbs<M, C, E>, ZKVMError> {
        let mut c = UIntLimbs::<M, C, E>::new_as_empty();

        // allocate witness cells and do range checks for carries
        c.alloc_carry_unchecked("add_carry", circuit_builder, with_overflow, Self::NUM_LIMBS)?;
        let Some(carries) = &c.carries else {
            return Err(ZKVMError::CircuitError);
        };
        carries.iter().enumerate().try_for_each(|(i, carry)| {
            circuit_builder.assert_bit(format!("carry_{i}_in_as_bit"), carry.expr())
        })?;

        // perform add operation
        // c[i] = a[i] + b[i] + carry[i-1] - carry[i] * 2 ^ C
        c.limbs = UintLimb::Expression(
            (self.expr())
                .iter()
                .zip((*addend).iter())
                .enumerate()
                .map(|(i, (a, b))| {
                    let carries = c.carries.as_ref().unwrap();
                    let carry = if i > 0 { carries.get(i - 1) } else { None };
                    let next_carry = carries.get(i);

                    let mut limb_expr = a.clone() + b.clone();
                    if carry.is_some() {
                        limb_expr = limb_expr.clone() + carry.unwrap().expr();
                    }
                    if next_carry.is_some() {
                        limb_expr = limb_expr.clone() - next_carry.unwrap().expr() * Self::POW_OF_C;
                    }

                    circuit_builder
                        .assert_ux::<_, C>(format!("limb_{i}_in_{C}"), limb_expr.clone())?;
                    Ok(limb_expr)
                })
                .collect::<Result<Vec<Expression<E>>, ZKVMError>>()?,
        );

        Ok(c)
    }

    pub fn add_const<Name: Into<String>>(
        &self,
        name: Name,
        circuit_builder: &mut CircuitBuilder<E>,
        constant: Expression<E>,
        with_overflow: bool,
    ) -> Result<Self, ZKVMError> {
        circuit_builder.namespace(name, |cb| {
            let Expression::Constant(c) = constant else {
                panic!("addend is not a constant type");
            };
            let b = c.to_canonical_u64();

            // convert Expression::Constant to limbs
            let b_limbs = (0..Self::NUM_LIMBS)
                .map(|i| {
                    Expression::Constant(E::BaseField::from((b >> (C * i)) & Self::LIMB_BIT_MASK))
                })
                .collect_vec();

            self.internal_add(cb, &b_limbs, with_overflow)
        })
    }

    /// Little-endian addition.
    pub fn add<Name: Into<String>>(
        &self,
        name: Name,
        circuit_builder: &mut CircuitBuilder<E>,
        addend: &UIntLimbs<M, C, E>,
        with_overflow: bool,
    ) -> Result<UIntLimbs<M, C, E>, ZKVMError> {
        circuit_builder.namespace(name, |cb| {
            self.internal_add(cb, &addend.expr(), with_overflow)
        })
    }

    fn internal_mul<const M2: usize>(
        &mut self,
        circuit_builder: &mut CircuitBuilder<E>,
        multiplier: &mut UIntLimbs<M, C, E>,
        with_overflow: bool,
    ) -> Result<UIntLimbs<M2, C, E>, ZKVMError> {
        debug_assert!(M2 == M || M2 == 2 * M, "illegal M2 {M2} and M {M}");
        let is_hi_limb = M2 == 2 * M;
        let num_limbs = if is_hi_limb {
            2 * Self::NUM_LIMBS
        } else {
            Self::NUM_LIMBS
        };
        // with high limb, overall cell will be double
        let c_limbs: Vec<WitIn> = (0..num_limbs).try_fold(vec![], |mut c_limbs, i| {
            let limb = circuit_builder.create_witin(format!("limb_{i}"))?;
            circuit_builder.assert_ux::<_, C>(format!("limb_{i}_in_{C}"), limb.expr())?;
            c_limbs.push(limb);
            Result::<Vec<WitIn>, ZKVMError>::Ok(c_limbs)
        })?;
        let c_carries: Vec<WitIn> = (0..num_limbs).try_fold(vec![], |mut c_carries, i| {
            // skip last carry if with_overflow == false
            if i != num_limbs - 1 || with_overflow {
                let carry = circuit_builder.create_witin(format!("carry_{i}"))?;
                c_carries.push(carry);
            }
            Result::<Vec<WitIn>, ZKVMError>::Ok(c_carries)
        })?;
        // assert carry range less than max carry value constant
        let carries_auxiliary_lt_config = c_carries
            .iter()
            .enumerate()
            .map(|(i, carry)| {
                AssertLTConfig::construct_circuit(
                    circuit_builder,
                    format!("carry_{i}_in_less_than"),
                    carry.expr(),
                    (Self::MAX_DEGREE_2_MUL_CARRY_VALUE as usize).into(),
                    Self::MAX_DEGREE_2_MUL_CARRY_U16_LIMB,
                )
            })
            .collect::<Result<Vec<AssertLTConfig>, ZKVMError>>()?;

        // creating a witness constrained as expression to reduce overall degree
        let mut swap_witin =
            |name: &str, u: &mut UIntLimbs<M, C, E>| -> Result<Vec<Expression<E>>, ZKVMError> {
                if u.is_expr() {
                    circuit_builder.namespace(name.to_owned(), |cb| {
                        let existing_expr = u.expr();
                        // this will overwrite existing expressions
                        u.replace_limbs_with_witin("replace_limbs_with_witin".to_string(), cb)?;
                        // check if the new witness equals the existing expression
                        izip!(u.expr(), existing_expr).try_for_each(|(lhs, rhs)| {
                            cb.require_equal("new_witin_equal_expr".to_string(), lhs, rhs)
                        })?;
                        Ok(())
                    })?;
                }
                Ok(u.expr())
            };

        let a_expr = swap_witin("lhs", self)?;
        let b_expr = swap_witin("rhs", multiplier)?;

        // compute the result
        let mut result_c: Vec<Expression<E>> = Vec::<Expression<E>>::with_capacity(c_limbs.len());
        a_expr.iter().enumerate().for_each(|(i, a)| {
            b_expr.iter().enumerate().for_each(|(j, b)| {
                let idx = i + j;
                if idx < c_limbs.len() {
                    if result_c.get(idx).is_none() {
                        result_c.push(a.clone() * b.clone());
                    } else {
                        result_c[idx] = result_c[idx].clone() + a.clone() * b.clone();
                    }
                }
            });
        });
        result_c.resize(c_limbs.len(), Expression::ZERO);

        // constrain each limb with carry
        c_limbs.iter().enumerate().try_for_each(|(i, c_limb)| {
            let carry = if i > 0 { c_carries.get(i - 1) } else { None };
            let next_carry = c_carries.get(i);
            result_c[i] = result_c[i].clone() - c_limb.expr();
            if carry.is_some() {
                result_c[i] = result_c[i].clone() + carry.unwrap().expr();
            }
            if next_carry.is_some() {
                result_c[i] = result_c[i].clone() - next_carry.unwrap().expr() * Self::POW_OF_C;
            }
            circuit_builder.require_zero(format!("mul_zero_{i}"), result_c[i].clone())?;
            Ok::<(), ZKVMError>(())
        })?;

        Ok(UIntLimbs::from_witins_unchecked(
            c_limbs,
            Some(c_carries),
            Some(carries_auxiliary_lt_config),
        ))
    }

    pub fn mul<const M2: usize, Name: Into<String>>(
        &mut self,
        name: Name,
        circuit_builder: &mut CircuitBuilder<E>,
        multiplier: &mut UIntLimbs<M, C, E>,
        with_overflow: bool,
    ) -> Result<UIntLimbs<M2, C, E>, ZKVMError> {
        circuit_builder.namespace(name, |cb| self.internal_mul(cb, multiplier, with_overflow))
    }

    pub fn mul_add<const M2: usize, Name: Into<String>>(
        &mut self,
        name: Name,
        circuit_builder: &mut CircuitBuilder<E>,
        multiplier: &mut UIntLimbs<M, C, E>,
        addend: &UIntLimbs<M, C, E>,
        with_overflow: bool,
    ) -> Result<(UIntLimbs<M, C, E>, UIntLimbs<M2, C, E>), ZKVMError> {
        circuit_builder.namespace(name, |cb| {
            let mul = cb.namespace("mul", |cb| {
                self.internal_mul::<M2>(cb, multiplier, with_overflow)
            })?;
            let mul_lo_or_hi = if M2 == 2 * M {
                // hi limb
                let (_, mul_hi) = mul.as_lo_hi()?;
                mul_hi
            } else {
                // lo limb
                UIntLimbs::from_exprs_unchecked(mul.expr())?
            };
            let add = cb.namespace("add", |cb| {
                mul_lo_or_hi.internal_add(cb, &addend.expr(), with_overflow)
            })?;
            Ok((add, mul))
        })
    }

    /// Check two UIntLimbs are equal
    pub fn require_equal<Name: Into<String>>(
        &self,
        name: Name,
        circuit_builder: &mut CircuitBuilder<E>,
        rhs: &UIntLimbs<M, C, E>,
    ) -> Result<(), ZKVMError> {
        circuit_builder.require_equal(name, self.value(), rhs.value())
    }

    pub fn is_equal(
        &self,
        circuit_builder: &mut CircuitBuilder<E>,
        rhs: &UIntLimbs<M, C, E>,
    ) -> Result<IsEqualConfig, ZKVMError> {
        let n_limbs = Self::NUM_LIMBS;
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
            .fold(Expression::ZERO, |acc, flag| acc.clone() + flag.expr());

        let sum_flag = WitIn::from_expr("sum_flag", circuit_builder, sum_expr, false)?;
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

impl<const M: usize, E: ExtensionField> UIntLimbs<M, 8, E> {
    /// decompose x = (x_s, x_{<s})
    /// where x_s is highest bit, x_{<s} is the rest
    pub fn msb_decompose<F: SmallField>(
        &self,
        circuit_builder: &mut CircuitBuilder<E>,
    ) -> Result<MsbConfig, ZKVMError>
    where
        E: ExtensionField<BaseField = F>,
    {
        let high_limb_no_msb = circuit_builder.create_witin("high_limb_mask")?;
        let high_limb = self.limbs[Self::NUM_LIMBS - 1].expr();

        circuit_builder.lookup_and_byte(
            high_limb.clone(),
            Expression::from(0b0111_1111),
            high_limb_no_msb.expr(),
        )?;

        let inv_128 = F::from(128).invert().unwrap();
        let msb = (high_limb - high_limb_no_msb.expr()) * Expression::Constant(inv_128);
        let msb = WitIn::from_expr("msb", circuit_builder, msb, false)?;
        Ok(MsbConfig {
            msb,
            high_limb_no_msb,
        })
    }

    /// compare unsigned intergers a < b
    pub fn ltu_limb8(
        &self,
        circuit_builder: &mut CircuitBuilder<E>,
        rhs: &UIntLimbs<M, 8, E>,
    ) -> Result<UIntLtuConfig, ZKVMError> {
        let n_bytes = Self::NUM_LIMBS;
        let indexes: Vec<WitIn> = (0..n_bytes)
            .map(|_| circuit_builder.create_witin("index"))
            .collect::<Result<_, ZKVMError>>()?;

        // indicate the first non-zero byte index i_0 of a[i] - b[i]
        // from high to low
        //        indexes
        //            .iter()
        //            .try_for_each(|idx| circuit_builder.assert_bit("bit assert", idx.expr()))?;
        //        let index_sum = indexes
        //            .iter()
        //            .fold(Expression::from(0), |acc, idx| acc + idx.expr());
        // circuit_builder.assert_bit("bit assert", index_sum)?;

        // equal zero if a==b, otherwise equal (a[i_0]-b[i_0])^{-1}
        let byte_diff_inv = circuit_builder.create_witin("byte_diff_inverse")?;

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
            .enumerate()
            .map(|(i, expr)| WitIn::from_expr(format!("si_expr_{i}"), circuit_builder, expr, false))
            .collect::<Result<Vec<WitIn>, ZKVMError>>()?;

        // check byte diff that before the first non-zero i_0 equals zero
        si.iter()
            .zip(self.limbs.iter())
            .zip(rhs.limbs.iter())
            .enumerate()
            .try_for_each(|(i, ((flag, a), b))| {
                circuit_builder.require_zero(
                    format!("byte diff {i} zero check"),
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
        let lhs_ne_byte = WitIn::from_expr("lhs_ne_byte", circuit_builder, sa.clone(), false)?;
        let rhs_ne_byte = WitIn::from_expr("rhs_ne_byte", circuit_builder, sb.clone(), false)?;
        let index_ne = si.first().unwrap();
        circuit_builder.require_zero(
            "byte inverse check",
            lhs_ne_byte.expr() * byte_diff_inv.expr()
                - rhs_ne_byte.expr() * byte_diff_inv.expr()
                - index_ne.expr(),
        )?;

        let is_ltu = circuit_builder.create_witin("is_ltu")?;
        // now we know the first non-equal byte pairs is  (lhs_ne_byte, rhs_ne_byte)
        circuit_builder.lookup_ltu_byte(lhs_ne_byte.expr(), rhs_ne_byte.expr(), is_ltu.expr())?;
        Ok(UIntLtuConfig {
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
        rhs: &UIntLimbs<M, 8, E>,
    ) -> Result<UIntLtConfig, ZKVMError> {
        let is_lt = circuit_builder.create_witin("is_lt")?;
        // circuit_builder.assert_bit("assert_bit", is_lt.expr())?;

        let lhs_msb = self.msb_decompose(circuit_builder)?;
        let rhs_msb = rhs.msb_decompose(circuit_builder)?;

        let mut lhs_limbs = self.limbs.iter().copied().collect_vec();
        lhs_limbs[Self::NUM_LIMBS - 1] = lhs_msb.high_limb_no_msb;
        let lhs_no_msb = Self::from_witins_unchecked(lhs_limbs, None, None);
        let mut rhs_limbs = rhs.limbs.iter().copied().collect_vec();
        rhs_limbs[Self::NUM_LIMBS - 1] = rhs_msb.high_limb_no_msb;
        let rhs_no_msb = Self::from_witins_unchecked(rhs_limbs, None, None);

        // (1) compute ltu(a_{<s},b_{<s})
        let is_ltu = lhs_no_msb.ltu_limb8(circuit_builder, &rhs_no_msb)?;
        // (2) compute $lt(a,b)=a_s\cdot (1-b_s)+eq(a_s,b_s)\cdot ltu(a_{<s},b_{<s})$
        // Refer Jolt 5.3: Set Less Than (https://people.cs.georgetown.edu/jthaler/Jolt-paper.pdf)
        let (msb_is_equal, msb_diff_inv) =
            circuit_builder.is_equal(lhs_msb.msb.expr(), rhs_msb.msb.expr())?;
        circuit_builder.require_zero(
            "is lt zero check",
            lhs_msb.msb.expr() - lhs_msb.msb.expr() * rhs_msb.msb.expr()
                + msb_is_equal.expr() * is_ltu.is_ltu.expr()
                - is_lt.expr(),
        )?;
        Ok(UIntLtConfig {
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
            uint::UIntLimbs,
        };
        use ff_ext::ExtensionField;
        use goldilocks::GoldilocksExt2;
        use itertools::Itertools;

        type E = GoldilocksExt2;
        #[test]
        fn test_add64_16_no_carries() {
            // a = 1 + 1 * 2^16
            // b = 2 + 1 * 2^16
            // c = 3 + 2 * 2^16 with 0 carries
            let a = vec![1, 1, 0, 0];
            let b = vec![2, 1, 0, 0];
            let carries = vec![0; 3]; // no overflow
            let witness_values = [a, b, carries].concat();
            verify::<64, 16, E>(witness_values, None, false);
        }

        #[test]
        fn test_add64_16_w_carry() {
            // a = 65535 + 1 * 2^16
            // b =   2   + 1 * 2^16
            // c =   1   + 3 * 2^16 with carries [1, 0, 0, 0]
            let a = vec![0xFFFF, 1, 0, 0];
            let b = vec![2, 1, 0, 0];
            let carries = vec![1, 0, 0]; // no overflow
            let witness_values = [a, b, carries].concat();
            verify::<64, 16, E>(witness_values, None, false);
        }

        #[test]
        fn test_add64_16_w_carries() {
            // a = 65535 + 65534 * 2^16
            // b =   2   +   1   * 2^16
            // c =   1   +   0   * 2^16 + 1 * 2^32 with carries [1, 1, 0, 0]
            let a = vec![0xFFFF, 0xFFFE, 0, 0];
            let b = vec![2, 1, 0, 0];
            let carries = vec![1, 1, 0]; // no overflow
            let witness_values = [a, b, carries].concat();
            verify::<64, 16, E>(witness_values, None, false);
        }

        #[test]
        fn test_add64_16_w_overflow() {
            // a = 1 + 1 * 2^16 + 0 + 65535 * 2^48
            // b = 2 + 1 * 2^16 + 0 +     2 * 2^48
            // c = 3 + 2 * 2^16 + 0 +     1 * 2^48 with carries [0, 0, 0, 1]
            let a = vec![1, 1, 0, 0xFFFF];
            let b = vec![2, 1, 0, 2];
            let carries = vec![0, 0, 0, 1];
            let witness_values = [a, b, carries].concat();
            verify::<64, 16, E>(witness_values, None, false);
        }

        #[test]
        fn test_add32_16_w_carry() {
            // a = 65535 + 1 * 2^16
            // b =   2   + 1 * 2^16
            // c =   1   + 3 * 2^16 with carries [1]
            let a = vec![0xFFFF, 1];
            let b = vec![2, 1];
            let carries = vec![1]; // no overflow
            let witness_values = [a, b, carries].concat();
            verify::<32, 16, E>(witness_values, None, false);
        }

        #[test]
        fn test_add32_5_w_carry() {
            // a = 31
            // b = 2 + 1 * 2^5
            // c = 1 + 1 * 2^5 with carries [1, 0, 0, 0]
            let a = vec![31, 1, 0, 0, 0, 0, 0];
            let b = vec![2, 1, 0, 0, 0, 0, 0];
            let carries = vec![1, 0, 0, 0, 0, 0]; // no overflow
            let witness_values = [a, b, carries].concat();
            verify::<32, 5, E>(witness_values, None, false);
        }

        #[test]
        fn test_add_const64_16_no_carries() {
            // a = 1 + 1 * 2^16
            // const b = 2
            // c = 3 + 1 * 2^16 with 0 carries
            let a = vec![1, 1, 0, 0];
            let carries = vec![0; 3]; // no overflow
            let witness_values = [a, carries].concat();
            verify::<64, 16, E>(witness_values, Some(2), false);
        }

        #[test]
        fn test_add_const64_16_w_carries() {
            // a = 65535 + 65534 * 2^16
            // const b =   2   +   1   * 2^16 = 65,538
            // c =   1   +   0   * 2^16 + 1 * 2^32 with carries [1, 1, 0, 0]
            let a = vec![0xFFFF, 0xFFFE, 0, 0];
            let carries = vec![1, 1, 0]; // no overflow
            let witness_values = [a, carries].concat();
            verify::<64, 16, E>(witness_values, Some(65538), false);
        }

        #[test]
        fn test_add_const32_16_w_carry() {
            // a = 65535 + 1 * 2^16
            // const b =   2   + 1 * 2^16 = 65,538
            // c =   1   + 3 * 2^16 with carries [1]
            let a = vec![0xFFFF, 1];
            let carries = vec![1]; // no overflow
            let witness_values = [a, carries].concat();
            verify::<32, 16, E>(witness_values, Some(65538), false);
        }

        #[test]
        fn test_add_const32_5_w_carry() {
            // a = 31
            // const b = 2 + 1 * 2^5 = 34
            // c = 1 + 1 * 2^5 with carries [1, 0, 0, 0]
            let a = vec![31, 1, 0, 0, 0, 0, 0];
            let carries = vec![1, 0, 0, 0, 0, 0]; // no overflow
            let witness_values = [a, carries].concat();
            verify::<32, 5, E>(witness_values, Some(34), false);
        }

        fn verify<const M: usize, const C: usize, E: ExtensionField>(
            witness_values: Vec<u64>,
            const_b: Option<u64>,
            overflow: bool,
        ) {
            let mut cs = ConstraintSystem::new("test_add");
            let mut cb = CircuitBuilder::<E>::new(&mut cs);
            let challenges = (0..witness_values.len()).map(|_| 1.into()).collect_vec();

            let uint_a = UIntLimbs::<M, C, E>::new("uint_a", &mut cb).unwrap();
            let uint_c = if const_b.is_none() {
                let uint_b = UIntLimbs::<M, C, E>::new("uint_b", &mut cb).unwrap();
                uint_a.add("uint_c", &mut cb, &uint_b, overflow).unwrap()
            } else {
                let const_b = Expression::Constant(const_b.unwrap().into());
                uint_a
                    .add_const("uint_c", &mut cb, const_b, overflow)
                    .unwrap()
            };

            let pow_of_c: u64 = 2_usize.pow(UIntLimbs::<M, C, E>::MAX_LIMB_BIT_WIDTH as u32) as u64;
            let single_wit_size = UIntLimbs::<M, C, E>::NUM_LIMBS;

            let a = &witness_values[0..single_wit_size];
            let mut const_b_pre_allocated = vec![0u64; single_wit_size];
            let b = if const_b.is_none() {
                &witness_values[single_wit_size..2 * single_wit_size]
            } else {
                let b = const_b.unwrap();
                let limb_bit_mask: u64 = (1 << C) - 1;
                const_b_pre_allocated
                    .iter_mut()
                    .enumerate()
                    .for_each(|(i, limb)| *limb = (b >> (C * i)) & limb_bit_mask);
                &const_b_pre_allocated
            };

            // the num of witness is 3, a, b and c_carries if it's a `add`
            // only the num is 2 if it's a `add_const` bcs there is no `b`
            let num_witness = if const_b.is_none() { 3 } else { 2 };
            let wit_end_idx = if overflow {
                num_witness * single_wit_size
            } else {
                num_witness * single_wit_size - 1
            };
            let carries = &witness_values[(num_witness - 1) * single_wit_size..wit_end_idx];

            // limbs cal.
            let mut result = vec![0u64; single_wit_size];
            a.iter()
                .zip(b)
                .enumerate()
                .for_each(|(i, (&limb_a, &limb_b))| {
                    let carry = carries.get(i);
                    result[i] = limb_a + limb_b;
                    if i != 0 {
                        result[i] += carries[i - 1];
                    }
                    if !overflow && carry.is_some() {
                        result[i] -= carry.unwrap() * pow_of_c;
                    }
                });

            // verify
            let wit: Vec<E> = witness_values.iter().map(|&w| w.into()).collect_vec();
            uint_c.expr().iter().zip(result).for_each(|(c, ret)| {
                assert_eq!(eval_by_expr(&wit, &challenges, c), E::from(ret));
            });

            // overflow
            if overflow {
                let carries = uint_c.carries.unwrap().last().unwrap().expr();
                assert_eq!(eval_by_expr(&wit, &challenges, &carries), E::ONE);
            } else {
                // non-overflow case, the len of carries should be (NUM_CELLS - 1)
                assert_eq!(uint_c.carries.unwrap().len(), single_wit_size - 1)
            }
        }
    }

    mod mul {
        use crate::{
            circuit_builder::{CircuitBuilder, ConstraintSystem},
            expression::ToExpr,
            scheme::utils::eval_by_expr,
            uint::UIntLimbs,
        };
        use ff_ext::ExtensionField;
        use goldilocks::GoldilocksExt2;
        use itertools::Itertools;

        type E = GoldilocksExt2; // 18446744069414584321
        #[test]
        fn test_mul64_16_no_carries() {
            // a = 1 + 1 * 2^16
            // b = 2 + 1 * 2^16
            // c = 2 + 3 * 2^16 + 1 * 2^32 = 4,295,163,906
            let wit_a = vec![1, 1, 0, 0];
            let wit_b = vec![2, 1, 0, 0];
            let wit_c = vec![2, 3, 1, 0];
            let wit_carries = vec![0, 0, 0];
            let witness_values = [wit_a, wit_b, wit_c, wit_carries].concat();
            verify::<64, 16, E>(witness_values, false);
        }

        #[test]
        fn test_mul64_16_w_carry() {
            // a = 256 + 1 * 2^16
            // b = 257 + 1 * 2^16
            // c = 256 + 514 * 2^16 + 1 * 2^32 = 4,328,653,056
            let wit_a = vec![256, 1, 0, 0];
            let wit_b = vec![257, 1, 0, 0];
            let wit_c = vec![256, 514, 1, 0];
            let wit_carries = vec![1, 0, 0];
            let witness_values = [wit_a, wit_b, wit_c, wit_carries].concat();
            verify::<64, 16, E>(witness_values, false);
        }

        #[test]
        fn test_mul64_16_w_carries() {
            // a = 256 + 256 * 2^16 = 16,777,472
            // b = 257 + 256 * 2^16 = 16,777,473
            // c = 256 + 257 * 2^16 + 2 * 2^32 + 1 * 2^48 = 281,483,583,488,256
            let wit_a = vec![256, 256, 0, 0];
            let wit_b = vec![257, 256, 0, 0];
            // result = [256 * 257, 256*256 + 256*257, 256*256, 0]
            // ==> [256 + 1 * (2^16), 256 + 2 * (2^16), 0 + 1 * (2^16), 0]
            // so we get wit_c = [256, 256, 0, 0] and carries = [1, 2, 1, 0]
            let wit_c = vec![256, 257, 2, 1];
            let wit_carries = vec![1, 2, 1];
            let witness_values = [wit_a, wit_b, wit_c, wit_carries].concat();
            verify::<64, 16, E>(witness_values, false);
        }

        #[test]
        fn test_mul64_16_w_overflow() {
            // 18,446,744,073,709,551,616
            // a = 1 * 2^16 + 1 * 2^32 = 4,295,032,832
            // b =            1 * 2^32 = 4,294,967,296
            // c = 1 * 2^48 + 1 * 2^64 = 18,447,025,548,686,262,272
            let wit_a = vec![0, 1, 1, 0];
            let wit_b = vec![0, 0, 1, 0];
            let wit_c = vec![0, 0, 0, 1];
            let wit_carries = vec![0, 0, 0, 1];
            let witness_values = [wit_a, wit_b, wit_c, wit_carries].concat();
            verify::<64, 16, E>(witness_values, true);
        }

        #[test]
        fn test_mul64_8_w_carries() {
            // a = 256
            // b = 257
            // c = 254 + 1 * 2^16 = 510
            let wit_a = vec![255, 0, 0, 0, 0, 0, 0, 0];
            let wit_b = vec![2, 0, 0, 0, 0, 0, 0, 0];
            let wit_c = vec![254, 1, 0, 0, 0, 0, 0, 0];
            let wit_carries = vec![1, 0, 0, 0, 0, 0, 0];
            let witness_values = [wit_a, wit_b, wit_c, wit_carries].concat();
            verify::<64, 8, E>(witness_values, false);
        }

        #[test]
        fn test_mul32_16_w_carries() {
            let wit_a = vec![48683, 2621];
            let wit_b = vec![7, 0];
            let wit_c = vec![13101, 18352];
            let wit_carries = vec![5, 0];
            let witness_values = [wit_a, wit_b, wit_c, wit_carries].concat();
            verify::<32, 16, E>(witness_values, false);
        }

        #[test]
        fn test_mul32_5_w_carries() {
            // a = 31
            // b = 2
            // c = 30 + 1 * 2^8 = 62
            let wit_a = vec![31, 0, 0, 0, 0, 0, 0];
            let wit_b = vec![2, 0, 0, 0, 0, 0, 0];
            let wit_c = vec![30, 1, 0, 0, 0, 0, 0];
            let wit_carries = vec![1, 0, 0, 0, 0, 0];
            let witness_values = [wit_a, wit_b, wit_c, wit_carries].concat();
            verify::<32, 5, E>(witness_values, false);
        }

        fn verify<const M: usize, const C: usize, E: ExtensionField>(
            witness_values: Vec<u64>,
            overflow: bool,
        ) {
            let pow_of_c: u64 = 2_usize.pow(UIntLimbs::<M, C, E>::MAX_LIMB_BIT_WIDTH as u32) as u64;
            let single_wit_size = UIntLimbs::<M, C, E>::NUM_LIMBS;
            if overflow {
                assert_eq!(
                    witness_values.len() % single_wit_size,
                    0,
                    "witness len is incorrect"
                )
            }

            let mut cs = ConstraintSystem::new("test_mul");
            let mut cb = CircuitBuilder::<E>::new(&mut cs);
            let challenges = (0..witness_values.len()).map(|_| 1.into()).collect_vec();

            let mut uint_a = UIntLimbs::<M, C, E>::new("uint_a", &mut cb).unwrap();
            let mut uint_b = UIntLimbs::<M, C, E>::new("uint_b", &mut cb).unwrap();
            let uint_c: UIntLimbs<M, C, E> = uint_a
                .mul("uint_c", &mut cb, &mut uint_b, overflow)
                .unwrap();

            let wit_end_idx = if overflow {
                4 * single_wit_size
            } else {
                4 * single_wit_size - 1
            };
            let a = &witness_values[0..single_wit_size];
            let b = &witness_values[single_wit_size..2 * single_wit_size];
            let carries = &witness_values[3 * single_wit_size..wit_end_idx];

            // limbs cal.
            let mut result = vec![0u64; single_wit_size];
            a.iter().enumerate().for_each(|(i, a_limb)| {
                b.iter().enumerate().for_each(|(j, b_limb)| {
                    let idx = i + j;
                    if idx < single_wit_size {
                        result[idx] += a_limb * b_limb;
                    }
                });
            });

            // take care carries
            result.iter_mut().enumerate().for_each(|(i, ret)| {
                if i != 0 {
                    *ret += carries[i - 1];
                }
                if !overflow && carries.get(i).is_some() {
                    *ret -= carries[i] * pow_of_c;
                }
            });

            // verify
            let wit: Vec<E> = witness_values.iter().map(|&w| w.into()).collect_vec();
            uint_c.expr().iter().zip(result).for_each(|(c, ret)| {
                assert_eq!(eval_by_expr(&wit, &challenges, c), E::from(ret));
            });

            // overflow
            if overflow {
                let overflow = uint_c.carries.unwrap().last().unwrap().expr();
                assert_eq!(eval_by_expr(&wit, &challenges, &overflow), E::ONE);
            } else {
                // non-overflow case, the len of carries should be (NUM_CELLS - 1)
                assert_eq!(uint_c.carries.unwrap().len(), single_wit_size - 1)
            }
        }
    }

    mod mul_add {
        use crate::{
            Value,
            circuit_builder::{CircuitBuilder, ConstraintSystem},
            gadgets::cal_lt_diff,
            scheme::mock_prover::MockProver,
            uint::UIntLimbs,
            witness::LkMultiplicity,
        };
        use ff_ext::ExtensionField;
        use goldilocks::GoldilocksExt2;
        use itertools::Itertools;
        use multilinear_extensions::{
            mle::DenseMultilinearExtension, virtual_poly_v2::ArcMultilinearExtension,
        };

        type E = GoldilocksExt2; // 18446744069414584321

        trait ValueToArcMle<E: ExtensionField> {
            #[allow(clippy::wrong_self_convention)]
            fn into_arc_mle<'a>(&self) -> Vec<ArcMultilinearExtension<'a, E>>;
        }

        impl<E: ExtensionField> ValueToArcMle<E> for Vec<u64> {
            fn into_arc_mle<'a>(&self) -> Vec<ArcMultilinearExtension<'a, E>> {
                self.iter()
                    .map(|a| {
                        let mle: ArcMultilinearExtension<E> =
                            DenseMultilinearExtension::from_evaluation_vec_smart(0, vec![
                                E::BaseField::from(*a),
                            ])
                            .into();
                        mle
                    })
                    .collect_vec()
            }
        }

        fn calculate_carry_diff<const M: usize, const C: usize>(carries: Vec<u64>) -> Vec<u64> {
            carries
                .into_iter()
                .flat_map(|carry| {
                    let max_carry_value = UIntLimbs::<M, C, E>::MAX_DEGREE_2_MUL_CARRY_VALUE;
                    let max_carry_u16_limb = UIntLimbs::<M, C, E>::MAX_DEGREE_2_MUL_CARRY_U16_LIMB;
                    let diff = cal_lt_diff(true, max_carry_u16_limb, carry, max_carry_value);
                    let mut diff_u16_limb = Value::new_unchecked(diff).as_u16_limbs().to_vec();
                    diff_u16_limb.resize(max_carry_u16_limb, 0);
                    diff_u16_limb.iter().map(|v| *v as u64).collect_vec()
                })
                .collect_vec()
        }
        #[test]
        fn test_add_mul() {
            let witness_values: Vec<ArcMultilinearExtension<E>> = [
                vec![1, 1, 0, 0],
                // alloc b = 2 + 1 * 2^16
                vec![2, 1, 0, 0],
                // c = a + b = 3 + 2 * 2^16 with 0 carries, no overflow bit,
                vec![0; 3],
                // alloc d
                vec![1, 1, 0, 0],
                // e = c * d
                // alloc e
                vec![3, 5, 2, 0],
                // alloc e carry
                vec![0; 3],
                // each carry alloc with diff
                calculate_carry_diff::<64, 16>(vec![0; 3]),
                // alloc c limb
                vec![3, 2, 0, 0],
            ]
            .concat()
            .into_arc_mle();

            let mut cs = ConstraintSystem::new("test_add_mul");
            let mut cb = CircuitBuilder::<E>::new(&mut cs);

            let uint_a = UIntLimbs::<64, 16, E>::new("uint_a", &mut cb).unwrap();
            let uint_b = UIntLimbs::<64, 16, E>::new("uint_b", &mut cb).unwrap();
            let mut uint_c = uint_a.add("uint_c", &mut cb, &uint_b, false).unwrap();
            let mut uint_d = UIntLimbs::<64, 16, E>::new("uint_d", &mut cb).unwrap();
            let uint_e: UIntLimbs<64, 16, E> =
                uint_c.mul("uint_e", &mut cb, &mut uint_d, false).unwrap();
            let expected_e = UIntLimbs::<64, 16, E>::from_const_unchecked(vec![3u64, 5, 2, 0]);
            expected_e
                .require_equal("assert_g", &mut cb, &uint_e)
                .unwrap();

            MockProver::assert_satisfied(&cb, &witness_values, &[], None, None);
        }

        #[test]
        fn test_add_mul2() {
            let witness_values: Vec<ArcMultilinearExtension<E>> = vec![
                // alloc a = 1 + 1 * 2^16
                vec![1, 1, 0, 0],
                // alloc b = 2 + 1 * 2^16
                vec![2, 1, 0, 0],
                // c = a + b = 3 + 2 * 2^16 with 0 carries, no overflow bit
                vec![0; 3],
                // alloc d
                vec![1, 1, 0, 0],
                // alloc e
                vec![2, 1, 0, 0],
                // f = d + e = 3 + 2 * 2^16 with 0 carries, no overflow bit
                vec![0; 3],
                // g = c * f
                // alloc g
                vec![9, 12, 4, 0],
                // alloc g carry
                vec![0; 3],
                // each carry alloc with diff
                calculate_carry_diff::<64, 16>(vec![0; 3]),
                // alloc c limb
                vec![3, 2, 0, 0],
                // alloc f limb
                vec![3, 2, 0, 0],
            ]
            .concat()
            .into_arc_mle();

            let mut cs = ConstraintSystem::new("test_add_mul2");
            let mut cb = CircuitBuilder::<E>::new(&mut cs);

            let uint_a = UIntLimbs::<64, 16, E>::new("uint_a", &mut cb).unwrap();
            let uint_b = UIntLimbs::<64, 16, E>::new("uint_b", &mut cb).unwrap();
            let mut uint_c = uint_a.add("uint_c", &mut cb, &uint_b, false).unwrap();
            let uint_d = UIntLimbs::<64, 16, E>::new("uint_d", &mut cb).unwrap();
            let uint_e = UIntLimbs::<64, 16, E>::new("uint_e", &mut cb).unwrap();
            let mut uint_f = uint_d.add("uint_f", &mut cb, &uint_e, false).unwrap();
            let uint_g: UIntLimbs<64, 16, E> =
                uint_c.mul("unit_g", &mut cb, &mut uint_f, false).unwrap();
            let expected_g = UIntLimbs::<64, 16, E>::from_const_unchecked(vec![9u64, 12, 4, 0]);
            expected_g
                .require_equal("assert_g", &mut cb, &uint_g)
                .unwrap();

            MockProver::assert_satisfied(&cb, &witness_values, &[], None, None);
        }

        #[test]
        fn test_mul_add() {
            let witness_values: Vec<ArcMultilinearExtension<E>> = [
                vec![1, 1, 0, 0],
                // alloc b = 2 + 1 * 2^16
                vec![2, 1, 0, 0],
                // alloc mul_c = a * b = [2, 3, 1]
                vec![2, 3, 1, 0],
                // alloc mul_c carry
                vec![0; 3],
                // each carry alloc with diff
                calculate_carry_diff::<64, 16>(vec![0; 3]),
                // alloc d
                vec![1, 1, 0, 0],
                // e = c + d, carry only
                vec![0; 3],
            ]
            .concat()
            .into_arc_mle();

            let mut cs = ConstraintSystem::new("test_mul_add");
            let mut cb = CircuitBuilder::<E>::new(&mut cs);

            let mut uint_a = UIntLimbs::<64, 16, E>::new("uint_a", &mut cb).unwrap();
            let mut uint_b = UIntLimbs::<64, 16, E>::new("uint_b", &mut cb).unwrap();
            let uint_c = uint_a.mul("uint_c", &mut cb, &mut uint_b, false).unwrap();
            let uint_d = UIntLimbs::<64, 16, E>::new("uint_d", &mut cb).unwrap();
            let uint_e = uint_c.add("uint_e", &mut cb, &uint_d, false).unwrap();

            let expected_e = UIntLimbs::<64, 16, E>::from_const_unchecked(vec![3u64, 4, 1, 0]);
            expected_e
                .require_equal("assert_e", &mut cb, &uint_e)
                .unwrap();

            MockProver::assert_satisfied(&cb, &witness_values, &[], None, None);
        }

        #[test]
        fn test_mul_add2() {
            let witness_values: Vec<ArcMultilinearExtension<E>> = [
                vec![1, 1, 0, 0],
                // alloc b = 2 + 1 * 2^16
                vec![2, 1, 0, 0],
                // alloc d
                vec![1, 1, 0, 0],
                // e = a * b + d,
                // tmp = a * b = [2, 3, 1, 0]
                vec![2, 3, 1, 0],
                // tmp carry
                vec![0; 3],
                // each carry alloc with diff
                calculate_carry_diff::<64, 16>(vec![0; 3]),
                // e carry
                vec![0; 3],
            ]
            .concat()
            .into_arc_mle();

            let mut cs = ConstraintSystem::new("test_mul_add");
            let mut cb = CircuitBuilder::<E>::new(&mut cs);

            let mut uint_a = UIntLimbs::<64, 16, E>::new("uint_a", &mut cb).unwrap();
            let mut uint_b = UIntLimbs::<64, 16, E>::new("uint_b", &mut cb).unwrap();
            let uint_d = UIntLimbs::<64, 16, E>::new("uint_d", &mut cb).unwrap();
            let (uint_e, _): (_, UIntLimbs<64, 16, E>) = uint_a
                .mul_add("uint_e", &mut cb, &mut uint_b, &uint_d, false)
                .unwrap();

            let expected_e = UIntLimbs::<64, 16, E>::from_const_unchecked(vec![3u64, 4, 1, 0]);
            expected_e
                .require_equal("assert_e", &mut cb, &uint_e)
                .unwrap();

            MockProver::assert_satisfied(&cb, &witness_values, &[], None, None);
        }

        #[test]
        fn test_mul_overflow() {
            let a = Value::<'_, u32>::new_unchecked(u32::MAX);
            let b = Value::<'_, u32>::new_unchecked(u32::MAX);
            let ret = a.mul(&b, &mut LkMultiplicity::default(), true);
            let witness_values: Vec<ArcMultilinearExtension<E>> = [
                vec![u16::MAX as u64, u16::MAX as u64],
                // alloc b = 2^16 + (2^16 - 1) * 2^16
                vec![u16::MAX as u64, u16::MAX as u64],
                // mul_c = a * b,
                // alloc c [1, 0xfffe, 0xffff, 0] with lo part only
                ret.limbs.iter().map(|v| *v as u64).collect_vec(),
                // c carry
                ret.carries.iter().copied().collect_vec(),
                // each carry alloc with diff
                calculate_carry_diff::<32, 16>(ret.carries.to_vec()),
            ]
            .concat()
            .into_arc_mle();

            let mut cs = ConstraintSystem::new("test_mul_add");
            let mut cb = CircuitBuilder::<E>::new(&mut cs);

            let mut uint_a = UIntLimbs::<32, 16, E>::new("uint_a", &mut cb).unwrap();
            let mut uint_b = UIntLimbs::<32, 16, E>::new("uint_b", &mut cb).unwrap();
            let uint_c: UIntLimbs<32, 16, E> =
                uint_a.mul("mul_add", &mut cb, &mut uint_b, true).unwrap();

            let expected_c = UIntLimbs::<32, 16, E>::from_const_unchecked(ret.limbs.to_vec());
            expected_c
                .require_equal("assert_g", &mut cb, &uint_c)
                .unwrap();

            MockProver::assert_satisfied(&cb, &witness_values, &[], None, None);
        }
    }
}
