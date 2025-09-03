use ff_ext::ExtensionField;
use generic_array::{GenericArray, sequence::GenericSequence, typenum::Unsigned};
use gkr_iop::{circuit_builder::CircuitBuilder, error::CircuitBuilderError};
use multilinear_extensions::{Expression, ToExpr, WitIn};
use num::BigUint;
use p3_field::PrimeField32;
use sp1_curves::{
    params::{FieldParameters, Limbs},
    polynomial::Polynomial,
};
use std::fmt::Debug;

use crate::{
    gadgets::{
        field::FieldOperation,
        util::{compute_root_quotient_and_shift, split_u16_limbs_to_u8_limbs},
        util_expr::eval_field_operation,
    },
    witness::LkMultiplicity,
};

/// A set of columns to compute an emulated modular arithmetic operation.
///
/// *Safety* The input operands (a, b) (not included in the operation columns) are assumed to be
/// elements within the range `[0, 2^{P::nb_bits()})`. the result is also assumed to be within the
/// same range. Let `M = P:modulus()`. The constraints of the function [`FieldOpCols::eval`] assert
/// that:
/// * When `op` is `FieldOperation::Add`, then `result = a + b mod M`.
/// * When `op` is `FieldOperation::Mul`, then `result = a * b mod M`.
/// * When `op` is `FieldOperation::Sub`, then `result = a - b mod M`.
/// * When `op` is `FieldOperation::Div`, then `result * b = a mod M`.
///
/// **Warning**: The constraints do not check for division by zero. The caller is responsible for
/// ensuring that the division operation is valid.
#[derive(Debug, Clone)]
#[repr(C)]
pub struct FieldOpCols<T, P: FieldParameters> {
    /// The result of `a op b`, where a, b are field elements
    pub result: Limbs<T, P::Limbs>,
    pub carry: Limbs<T, P::Limbs>,
    pub(crate) witness_low: Limbs<T, P::Witness>,
    pub(crate) witness_high: Limbs<T, P::Witness>,
}

impl<P: FieldParameters> FieldOpCols<WitIn, P> {
    pub fn create<E: ExtensionField, NR, N>(cb: &mut CircuitBuilder<E>, name_fn: N) -> Self
    where
        NR: Into<String>,
        N: FnOnce() -> NR,
    {
        let name: String = name_fn().into();
        Self {
            result: Limbs(GenericArray::generate(|_| {
                cb.create_witin(|| format!("{}_result", name))
            })),
            carry: Limbs(GenericArray::generate(|_| {
                cb.create_witin(|| format!("{}_carry", name))
            })),
            witness_low: Limbs(GenericArray::generate(|_| {
                cb.create_witin(|| format!("{}_witness_low", name))
            })),
            witness_high: Limbs(GenericArray::generate(|_| {
                cb.create_witin(|| format!("{}_witness_high", name))
            })),
        }
    }
}

impl<F: PrimeField32, P: FieldParameters> FieldOpCols<F, P> {
    #[allow(clippy::too_many_arguments)]
    /// Populate result and carry columns from the equation (a*b + c) % modulus
    pub fn populate_mul_and_carry(
        &mut self,
        record: &mut LkMultiplicity,
        a: &BigUint,
        b: &BigUint,
        c: &BigUint,
        modulus: &BigUint,
    ) -> (BigUint, BigUint) {
        let p_a: Polynomial<F> = P::to_limbs_field::<F, _>(a).into();
        let p_b: Polynomial<F> = P::to_limbs_field::<F, _>(b).into();
        let p_c: Polynomial<F> = P::to_limbs_field::<F, _>(c).into();

        let mul_add = a * b + c;
        let result = &mul_add % modulus;
        let carry = (mul_add - &result) / modulus;
        debug_assert!(&result < modulus);
        debug_assert!(&carry < modulus);
        debug_assert_eq!(&carry * modulus, a * b + c - &result);

        let p_modulus_limbs = modulus
            .to_bytes_le()
            .iter()
            .map(|x| F::from_canonical_u8(*x))
            .collect::<Vec<F>>();
        let p_modulus: Polynomial<F> = p_modulus_limbs.iter().into();
        let p_result: Polynomial<F> = P::to_limbs_field::<F, _>(&result).into();
        let p_carry: Polynomial<F> = P::to_limbs_field::<F, _>(&carry).into();

        let p_op = &p_a * &p_b + &p_c;
        let p_vanishing = &p_op - &p_result - &p_carry * &p_modulus;

        let p_witness = compute_root_quotient_and_shift(
            &p_vanishing,
            P::WITNESS_OFFSET,
            P::NB_BITS_PER_LIMB as u32,
            P::NB_WITNESS_LIMBS,
        );

        let (mut p_witness_low, mut p_witness_high) = split_u16_limbs_to_u8_limbs(&p_witness);

        self.result = p_result.into();
        self.carry = p_carry.into();

        p_witness_low.resize(P::Witness::USIZE, F::ZERO);
        p_witness_high.resize(P::Witness::USIZE, F::ZERO);
        self.witness_low = Limbs(p_witness_low.try_into().unwrap());
        self.witness_high = Limbs(p_witness_high.try_into().unwrap());

        record.assert_ux_slice_fields::<8, _>(&self.result.0);
        record.assert_ux_slice_fields::<8, _>(&self.carry.0);
        record.assert_ux_slice_fields::<8, _>(&self.witness_low.0);
        record.assert_ux_slice_fields::<8, _>(&self.witness_high.0);

        (result, carry)
    }

    pub fn populate_carry_and_witness(
        &mut self,
        a: &BigUint,
        b: &BigUint,
        op: FieldOperation,
        modulus: &BigUint,
    ) -> BigUint {
        let p_a: Polynomial<F> = P::to_limbs_field::<F, _>(a).into();
        let p_b: Polynomial<F> = P::to_limbs_field::<F, _>(b).into();
        let (result, carry) = match op {
            FieldOperation::Add => ((a + b) % modulus, (a + b - (a + b) % modulus) / modulus),
            FieldOperation::Mul => ((a * b) % modulus, (a * b - (a * b) % modulus) / modulus),
            FieldOperation::Sub | FieldOperation::Div => unreachable!(),
        };
        debug_assert!(&result < modulus);
        debug_assert!(&carry < modulus);
        match op {
            FieldOperation::Add => debug_assert_eq!(&carry * modulus, a + b - &result),
            FieldOperation::Mul => debug_assert_eq!(&carry * modulus, a * b - &result),
            FieldOperation::Sub | FieldOperation::Div => unreachable!(),
        }

        // Here we have special logic for p_modulus because to_limbs_field only works for numbers in
        // the field, but modulus can == the field modulus so it can have 1 extra limb (ex.
        // uint256).
        let p_modulus_limbs = modulus
            .to_bytes_le()
            .iter()
            .map(|x| F::from_canonical_u8(*x))
            .collect::<Vec<F>>();
        let p_modulus: Polynomial<F> = p_modulus_limbs.iter().into();
        let p_result: Polynomial<F> = P::to_limbs_field::<F, _>(&result).into();
        let p_carry: Polynomial<F> = P::to_limbs_field::<F, _>(&carry).into();

        // Compute the vanishing polynomial.
        let p_op = match op {
            FieldOperation::Add => &p_a + &p_b,
            FieldOperation::Mul => &p_a * &p_b,
            FieldOperation::Sub | FieldOperation::Div => unreachable!(),
        };
        let p_vanishing: Polynomial<F> = &p_op - &p_result - &p_carry * &p_modulus;

        let p_witness = compute_root_quotient_and_shift(
            &p_vanishing,
            P::WITNESS_OFFSET,
            P::NB_BITS_PER_LIMB as u32,
            P::NB_WITNESS_LIMBS,
        );
        let (mut p_witness_low, mut p_witness_high) = split_u16_limbs_to_u8_limbs(&p_witness);

        self.result = p_result.into();
        self.carry = p_carry.into();

        p_witness_low.resize(P::Witness::USIZE, F::ZERO);
        p_witness_high.resize(P::Witness::USIZE, F::ZERO);
        self.witness_low = Limbs(p_witness_low.try_into().unwrap());
        self.witness_high = Limbs(p_witness_high.try_into().unwrap());

        result
    }

    /// Populate these columns with a specified modulus. This is useful in the `mulmod` precompile
    /// as an example.
    #[allow(clippy::too_many_arguments)]
    pub fn populate_with_modulus(
        &mut self,
        record: &mut LkMultiplicity,
        a: &BigUint,
        b: &BigUint,
        modulus: &BigUint,
        op: FieldOperation,
    ) -> BigUint {
        if b == &BigUint::ZERO && op == FieldOperation::Div {
            // Division by 0 is allowed only when dividing 0 so that padded rows can be all 0.
            assert_eq!(
                *a,
                BigUint::ZERO,
                "division by zero is allowed only when dividing zero"
            );
        }

        let result = match op {
            // If doing the subtraction operation, a - b = result, equivalent to a = result + b.
            FieldOperation::Sub => {
                let result = (modulus.clone() + a - b) % modulus;
                // We populate the carry, witness_low, witness_high as if we were doing an addition
                // with result + b. But we populate `result` with the actual result
                // of the subtraction because those columns are expected to contain
                // the result by the user. Note that this reversal means we have to
                // flip result, a correspondingly in the `eval` function.
                self.populate_carry_and_witness(&result, b, FieldOperation::Add, modulus);
                self.result = P::to_limbs_field::<F, _>(&result);
                result
            }
            // a / b = result is equivalent to a = result * b.
            FieldOperation::Div => {
                // As modulus is prime, we can use Fermat's little theorem to compute the
                // inverse.
                cfg_if::cfg_if! {
                    if #[cfg(feature = "bigint-rug")] {
                        use sp1_curves::utils::{biguint_to_rug, rug_to_biguint};
                        let rug_a = biguint_to_rug(a);
                        let rug_b = biguint_to_rug(b);
                        let rug_modulus = biguint_to_rug(modulus);
                        let rug_result = (rug_a
                            * rug_b.pow_mod(&(rug_modulus.clone() - 2u32), &rug_modulus.clone()).unwrap())
                            % rug_modulus.clone();
                        let result = rug_to_biguint(&rug_result);
                    } else {
                        let result =
                            (a * b.modpow(&(modulus.clone() - 2u32), &modulus.clone())) % modulus.clone();
                    }
                }
                // We populate the carry, witness_low, witness_high as if we were doing a
                // multiplication with result * b. But we populate `result` with the
                // actual result of the multiplication because those columns are
                // expected to contain the result by the user. Note that this
                // reversal means we have to flip result, a correspondingly in the `eval`
                // function.
                self.populate_carry_and_witness(&result, b, FieldOperation::Mul, modulus);
                self.result = P::to_limbs_field::<F, _>(&result);
                result
            }
            _ => self.populate_carry_and_witness(a, b, op, modulus),
        };

        // Range checks
        record.assert_ux_slice_fields::<8, _>(&self.result.0);
        record.assert_ux_slice_fields::<8, _>(&self.carry.0);
        record.assert_ux_slice_fields::<8, _>(&self.witness_low.0);
        record.assert_ux_slice_fields::<8, _>(&self.witness_high.0);

        result
    }

    /// Populate these columns without a specified modulus (will use the modulus of the field
    /// parameters).
    pub fn populate(
        &mut self,
        record: &mut LkMultiplicity,
        a: &BigUint,
        b: &BigUint,
        op: FieldOperation,
    ) -> BigUint {
        self.populate_with_modulus(record, a, b, &P::modulus(), op)
    }
}

impl<Expr: Clone, P: FieldParameters> FieldOpCols<Expr, P> {
    /// Allows an evaluation over opetations specified by boolean flags.
    #[allow(clippy::too_many_arguments)]
    pub fn eval_variable<E>(
        &self,
        builder: &mut CircuitBuilder<E>,
        a: &(impl Into<Polynomial<Expression<E>>> + Clone),
        b: &(impl Into<Polynomial<Expression<E>>> + Clone),
        modulus: &(impl Into<Polynomial<Expression<E>>> + Clone),
        is_add: impl ToExpr<E, Output = Expression<E>> + Clone,
        is_sub: impl ToExpr<E, Output = Expression<E>> + Clone,
        is_mul: impl ToExpr<E, Output = Expression<E>> + Clone,
        is_div: impl ToExpr<E, Output = Expression<E>> + Clone,
    ) -> Result<(), CircuitBuilderError>
    where
        E: ExtensionField,
        Expr: ToExpr<E, Output = Expression<E>>,
        Expression<E>: From<Expr>,
    {
        let p_a_param: Polynomial<Expression<E>> = (a).clone().into();
        let p_b: Polynomial<Expression<E>> = (b).clone().into();
        let p_res_param: Polynomial<Expression<E>> = self.result.clone().into();

        let is_add: Expression<E> = is_add.expr();
        let is_sub: Expression<E> = is_sub.expr();
        let is_mul: Expression<E> = is_mul.expr();
        let is_div: Expression<E> = is_div.expr();

        let p_result = p_res_param.clone() * (is_add.clone() + is_mul.clone())
            + p_a_param.clone() * (is_sub.clone() + is_div.clone());

        let p_add = p_a_param.clone() + p_b.clone();
        let p_sub = p_res_param.clone() + p_b.clone();
        let p_mul = p_a_param.clone() * p_b.clone();
        let p_div = p_res_param * p_b.clone();
        let p_op = p_add * is_add + p_sub * is_sub + p_mul * is_mul + p_div * is_div;

        self.eval_with_polynomials(builder, p_op, modulus.clone(), p_result)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn build_mul_and_carry<E>(
        &self,
        builder: &mut CircuitBuilder<E>,
        a: &(impl Into<Polynomial<Expression<E>>> + Clone),
        b: &(impl Into<Polynomial<Expression<E>>> + Clone),
        c: &(impl Into<Polynomial<Expression<E>>> + Clone),
        modulus: &(impl Into<Polynomial<Expression<E>>> + Clone),
    ) -> Result<(), CircuitBuilderError>
    where
        E: ExtensionField,
        Expr: ToExpr<E, Output = Expression<E>>,
        Expression<E>: From<Expr>,
    {
        let p_a: Polynomial<Expression<E>> = (a).clone().into();
        let p_b: Polynomial<Expression<E>> = (b).clone().into();
        let p_c: Polynomial<Expression<E>> = (c).clone().into();

        let p_result: Polynomial<_> = self.result.clone().into();
        let p_op = p_a * p_b + p_c;

        self.eval_with_polynomials(builder, p_op, modulus.clone(), p_result)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn eval_with_modulus<E>(
        &self,
        builder: &mut CircuitBuilder<E>,
        a: &(impl Into<Polynomial<Expression<E>>> + Clone),
        b: &(impl Into<Polynomial<Expression<E>>> + Clone),
        modulus: &(impl Into<Polynomial<Expression<E>>> + Clone),
        op: FieldOperation,
    ) -> Result<(), CircuitBuilderError>
    where
        E: ExtensionField,
        Expr: ToExpr<E, Output = Expression<E>>,
        Expression<E>: From<Expr>,
    {
        let p_a_param: Polynomial<Expression<E>> = (a).clone().into();
        let p_b: Polynomial<Expression<E>> = (b).clone().into();

        let (p_a, p_result): (Polynomial<_>, Polynomial<_>) = match op {
            FieldOperation::Add | FieldOperation::Mul => (p_a_param, self.result.clone().into()),
            FieldOperation::Sub | FieldOperation::Div => (self.result.clone().into(), p_a_param),
        };
        let p_op: Polynomial<Expression<E>> = match op {
            FieldOperation::Add | FieldOperation::Sub => p_a + p_b,
            FieldOperation::Mul | FieldOperation::Div => p_a * p_b,
        };
        self.eval_with_polynomials(builder, p_op, modulus.clone(), p_result)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn eval_with_polynomials<E>(
        &self,
        builder: &mut CircuitBuilder<E>,
        op: impl Into<Polynomial<Expression<E>>>,
        modulus: impl Into<Polynomial<Expression<E>>>,
        result: impl Into<Polynomial<Expression<E>>>,
    ) -> Result<(), CircuitBuilderError>
    where
        E: ExtensionField,
        Expr: ToExpr<E, Output = Expression<E>>,
        Expression<E>: From<Expr>,
    {
        let p_op: Polynomial<Expression<E>> = op.into();
        let p_result: Polynomial<Expression<E>> = result.into();
        let p_modulus: Polynomial<Expression<E>> = modulus.into();
        let p_carry: Polynomial<Expression<E>> = self.carry.clone().into();
        let p_op_minus_result: Polynomial<Expression<E>> = p_op - &p_result;
        let p_vanishing = p_op_minus_result - &(&p_carry * &p_modulus);
        let p_witness_low = self.witness_low.0.iter().into();
        let p_witness_high = self.witness_high.0.iter().into();
        eval_field_operation::<E, P>(builder, &p_vanishing, &p_witness_low, &p_witness_high)?;

        // Range checks for the result, carry, and witness columns.assert_ux<const C: usize>
        builder.assert_bytes(|| "field_op result", &self.result.0)?;
        builder.assert_bytes(|| "field_op carry", &self.carry.0)?;
        builder.assert_bytes(|| "field_op p_witness_low", p_witness_low.coefficients())?;
        builder.assert_bytes(|| "field_op p_witness_high", p_witness_high.coefficients())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn eval<E>(
        &self,
        builder: &mut CircuitBuilder<E>,
        a: &(impl Into<Polynomial<Expression<E>>> + Clone),
        b: &(impl Into<Polynomial<Expression<E>>> + Clone),
        op: FieldOperation,
    ) -> Result<(), CircuitBuilderError>
    where
        E: ExtensionField,
        Expr: ToExpr<E, Output = Expression<E>>,
        Expression<E>: From<Expr>,
    {
        let p_limbs =
            Polynomial::from_iter(P::modulus_field_iter::<E::BaseField>().map(|x| x.expr()));
        self.eval_with_modulus(builder, a, b, &p_limbs, op)
    }
}
