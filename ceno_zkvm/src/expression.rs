use std::{
    cmp::max,
    mem::MaybeUninit,
    ops::{Add, Deref, Mul, Neg, Sub},
};

use ff::Field;
use ff_ext::ExtensionField;
use goldilocks::SmallField;

use crate::{
    circuit_builder::CircuitBuilder,
    error::ZKVMError,
    structs::{ChallengeId, WitnessId},
};

#[derive(Clone, Debug, PartialEq)]
pub enum Expression<E: ExtensionField> {
    /// WitIn(Id)
    WitIn(WitnessId),
    /// Fixed
    Fixed(Fixed),
    /// Constant poly
    Constant(E::BaseField),
    /// This is the sum of two expression
    Sum(Box<Expression<E>>, Box<Expression<E>>),
    /// This is the product of two polynomials
    Product(Box<Expression<E>>, Box<Expression<E>>),
    /// This is x, a, b expr to represent ax + b polynomial
    ScaledSum(Box<Expression<E>>, Box<Expression<E>>, Box<Expression<E>>),
    Challenge(ChallengeId, usize, E, E), // (challenge_id, power, scalar, offset)
}

/// this is used as finite state machine state
/// for differentiate an expression is in monomial form or not
enum MonomialState {
    SumTerm,
    ProductTerm,
}

impl<E: ExtensionField> Expression<E> {
    pub const ZERO: Expression<E> = Expression::Constant(E::BaseField::ZERO);
    pub const ONE: Expression<E> = Expression::Constant(E::BaseField::ONE);

    pub fn degree(&self) -> usize {
        match self {
            Expression::Fixed(_) => 1,
            Expression::WitIn(_) => 1,
            Expression::Constant(_) => 0,
            Expression::Sum(a_expr, b_expr) => max(a_expr.degree(), b_expr.degree()),
            Expression::Product(a_expr, b_expr) => a_expr.degree() + b_expr.degree(),
            Expression::ScaledSum(_, _, _) => 1,
            Expression::Challenge(_, _, _, _) => 0,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn evaluate<T>(
        &self,
        fixed_in: &impl Fn(&Fixed) -> T,
        wit_in: &impl Fn(WitnessId) -> T, // witin id
        constant: &impl Fn(E::BaseField) -> T,
        challenge: &impl Fn(ChallengeId, usize, E, E) -> T,
        sum: &impl Fn(T, T) -> T,
        product: &impl Fn(T, T) -> T,
        scaled: &impl Fn(T, T, T) -> T,
    ) -> T {
        match self {
            Expression::Fixed(f) => fixed_in(f),
            Expression::WitIn(witness_id) => wit_in(*witness_id),
            Expression::Constant(scalar) => constant(*scalar),
            Expression::Sum(a, b) => {
                let a = a.evaluate(fixed_in, wit_in, constant, challenge, sum, product, scaled);
                let b = b.evaluate(fixed_in, wit_in, constant, challenge, sum, product, scaled);
                sum(a, b)
            }
            Expression::Product(a, b) => {
                let a = a.evaluate(fixed_in, wit_in, constant, challenge, sum, product, scaled);
                let b = b.evaluate(fixed_in, wit_in, constant, challenge, sum, product, scaled);
                product(a, b)
            }
            Expression::ScaledSum(x, a, b) => {
                let x = x.evaluate(fixed_in, wit_in, constant, challenge, sum, product, scaled);
                let a = a.evaluate(fixed_in, wit_in, constant, challenge, sum, product, scaled);
                let b = b.evaluate(fixed_in, wit_in, constant, challenge, sum, product, scaled);
                scaled(x, a, b)
            }
            Expression::Challenge(challenge_id, pow, scalar, offset) => {
                challenge(*challenge_id, *pow, *scalar, *offset)
            }
        }
    }

    pub fn is_monomial_form(&self) -> bool {
        Self::is_monomial_form_inner(MonomialState::SumTerm, self)
    }

    pub fn unpack_sum(&self) -> Option<(Expression<E>, Expression<E>)> {
        match self {
            Expression::Sum(a, b) => Some((a.deref().clone(), b.deref().clone())),
            _ => None,
        }
    }

    fn is_zero_expr(expr: &Expression<E>) -> bool {
        match expr {
            Expression::Fixed(_) => false,
            Expression::WitIn(_) => false,
            Expression::Constant(c) => *c == E::BaseField::ZERO,
            Expression::Sum(a, b) => Self::is_zero_expr(a) && Self::is_zero_expr(b),
            Expression::Product(a, b) => Self::is_zero_expr(a) || Self::is_zero_expr(b),
            Expression::ScaledSum(_, _, _) => false,
            Expression::Challenge(_, _, _, _) => false,
        }
    }

    fn is_monomial_form_inner(s: MonomialState, expr: &Expression<E>) -> bool {
        match (expr, s) {
            (
                Expression::Fixed(_)
                | Expression::WitIn(_)
                | Expression::Challenge(..)
                | Expression::Constant(_),
                _,
            ) => true,
            (Expression::Sum(a, b), MonomialState::SumTerm) => {
                Self::is_monomial_form_inner(MonomialState::SumTerm, a)
                    && Self::is_monomial_form_inner(MonomialState::SumTerm, b)
            }
            (Expression::Sum(_, _), MonomialState::ProductTerm) => false,
            (Expression::Product(a, b), MonomialState::SumTerm) => {
                Self::is_monomial_form_inner(MonomialState::ProductTerm, a)
                    && Self::is_monomial_form_inner(MonomialState::ProductTerm, b)
            }
            (Expression::Product(a, b), MonomialState::ProductTerm) => {
                Self::is_monomial_form_inner(MonomialState::ProductTerm, a)
                    && Self::is_monomial_form_inner(MonomialState::ProductTerm, b)
            }
            (Expression::ScaledSum(_, _, _), MonomialState::SumTerm) => true,
            (Expression::ScaledSum(_, _, b), MonomialState::ProductTerm) => Self::is_zero_expr(b),
        }
    }

    #[allow(dead_code)]
    fn to_monomial_form(&self) -> Expression<E> {
        fn expand<E: ExtensionField>(expr: Expression<E>) -> Vec<Vec<Expression<E>>> {
            match expr {
                Expression::Sum(a, b) => {
                    let mut expansion = expand(*a);
                    expansion.extend(expand(*b));
                    expansion
                }
                Expression::Product(a, b) => product_expand(*a, *b),
                Expression::ScaledSum(a, x, b) => {
                    let mut expansion = product_expand(*a, *x);

                    let expand_b = expand(*b);
                    expansion.extend(expand_b);

                    expansion
                }
                _ => vec![vec![expr]],
            }
        }

        fn product_expand<E: ExtensionField>(
            a: Expression<E>,
            b: Expression<E>,
        ) -> Vec<Vec<Expression<E>>> {
            let expand_a = expand(a);
            let expand_b = expand(b);

            let mut expansion = Vec::new();

            for a_element_prod in expand_a {
                for b_element_prod in expand_b.clone() {
                    let mut prod = a_element_prod.clone();
                    prod.extend(b_element_prod.clone());
                    expansion.push(prod);
                }
            }
            expansion
        }

        let sum = expand(self.clone());

        // TODO combine duplicate terms in the sum

        sum.into_iter()
            .fold(Expression::Constant(0.into()), |acc, prod| {
                let prod_expr = prod.into_iter().reduce(|acc, x| acc * x).unwrap();
                acc + prod_expr
            })
    }
}

impl<E: ExtensionField> Neg for Expression<E> {
    type Output = Expression<E>;
    fn neg(self) -> Self::Output {
        match self {
            Expression::Fixed(_) | Expression::WitIn(_) => Expression::ScaledSum(
                Box::new(self),
                Box::new(Expression::Constant(E::BaseField::ONE.neg())),
                Box::new(Expression::Constant(E::BaseField::ZERO)),
            ),
            Expression::Constant(c1) => Expression::Constant(c1.neg()),
            Expression::Sum(a, b) => {
                Expression::Sum(Box::new(-a.deref().clone()), Box::new(-b.deref().clone()))
            }
            Expression::Product(a, b) => {
                Expression::Product(Box::new(-a.deref().clone()), Box::new(b.deref().clone()))
            }
            Expression::ScaledSum(x, a, b) => Expression::ScaledSum(
                x,
                Box::new(-a.deref().clone()),
                Box::new(-b.deref().clone()),
            ),
            Expression::Challenge(challenge_id, pow, scalar, offset) => {
                Expression::Challenge(challenge_id, pow, scalar.neg(), offset.neg())
            }
        }
    }
}

impl<E: ExtensionField> Add for Expression<E> {
    type Output = Expression<E>;
    fn add(self, rhs: Expression<E>) -> Expression<E> {
        match (&self, &rhs) {
            // constant + challenge
            (
                Expression::Constant(c1),
                Expression::Challenge(challenge_id, pow, scalar, offset),
            )
            | (
                Expression::Challenge(challenge_id, pow, scalar, offset),
                Expression::Constant(c1),
            ) => Expression::Challenge(*challenge_id, *pow, *scalar, *offset + c1),

            // challenge + challenge
            (
                Expression::Challenge(challenge_id1, pow1, scalar1, offset1),
                Expression::Challenge(challenge_id2, pow2, scalar2, offset2),
            ) => {
                if challenge_id1 == challenge_id2 && pow1 == pow2 {
                    Expression::Challenge(
                        *challenge_id1,
                        *pow1,
                        *scalar1 + scalar2,
                        *offset1 + offset2,
                    )
                } else {
                    Expression::Sum(Box::new(self), Box::new(rhs))
                }
            }

            // constant + constant
            (Expression::Constant(c1), Expression::Constant(c2)) => Expression::Constant(*c1 + c2),

            // constant + scaledsum
            (c1 @ Expression::Constant(_), Expression::ScaledSum(x, a, b))
            | (Expression::ScaledSum(x, a, b), c1 @ Expression::Constant(_)) => {
                Expression::ScaledSum(
                    x.clone(),
                    a.clone(),
                    Box::new(b.deref().clone() + c1.clone()),
                )
            }

            // challenge + scaledsum
            (c1 @ Expression::Challenge(..), Expression::ScaledSum(x, a, b))
            | (Expression::ScaledSum(x, a, b), c1 @ Expression::Challenge(..)) => {
                Expression::ScaledSum(
                    x.clone(),
                    a.clone(),
                    Box::new(b.deref().clone() + c1.clone()),
                )
            }

            _ => Expression::Sum(Box::new(self), Box::new(rhs)),
        }
    }
}

impl<E: ExtensionField> Sub for Expression<E> {
    type Output = Expression<E>;
    fn sub(self, rhs: Expression<E>) -> Expression<E> {
        match (&self, &rhs) {
            // constant - challenge
            (
                Expression::Constant(c1),
                Expression::Challenge(challenge_id, pow, scalar, offset),
            ) => Expression::Challenge(*challenge_id, *pow, *scalar, offset.neg() + c1),

            // challenge - constant
            (
                Expression::Challenge(challenge_id, pow, scalar, offset),
                Expression::Constant(c1),
            ) => Expression::Challenge(*challenge_id, *pow, *scalar, *offset - c1),

            // challenge - challenge
            (
                Expression::Challenge(challenge_id1, pow1, scalar1, offset1),
                Expression::Challenge(challenge_id2, pow2, scalar2, offset2),
            ) => {
                if challenge_id1 == challenge_id2 && pow1 == pow2 {
                    Expression::Challenge(
                        *challenge_id1,
                        *pow1,
                        *scalar1 - scalar2,
                        *offset1 - offset2,
                    )
                } else {
                    Expression::Sum(Box::new(self), Box::new(-rhs))
                }
            }

            // constant - constant
            (Expression::Constant(c1), Expression::Constant(c2)) => Expression::Constant(*c1 - c2),

            // constant - scalesum
            (c1 @ Expression::Constant(_), Expression::ScaledSum(x, a, b)) => {
                Expression::ScaledSum(
                    x.clone(),
                    Box::new(-a.deref().clone()),
                    Box::new(c1.clone() - b.deref().clone()),
                )
            }

            // scalesum - constant
            (Expression::ScaledSum(x, a, b), c1 @ Expression::Constant(_)) => {
                Expression::ScaledSum(
                    x.clone(),
                    a.clone(),
                    Box::new(b.deref().clone() - c1.clone()),
                )
            }

            // challenge - scalesum
            (c1 @ Expression::Challenge(..), Expression::ScaledSum(x, a, b)) => {
                Expression::ScaledSum(
                    x.clone(),
                    Box::new(-a.deref().clone()),
                    Box::new(c1.clone() - b.deref().clone()),
                )
            }

            // scalesum - challenge
            (Expression::ScaledSum(x, a, b), c1 @ Expression::Challenge(..)) => {
                Expression::ScaledSum(
                    x.clone(),
                    a.clone(),
                    Box::new(b.deref().clone() - c1.clone()),
                )
            }

            _ => Expression::Sum(Box::new(self), Box::new(-rhs)),
        }
    }
}

impl<E: ExtensionField> Mul for Expression<E> {
    type Output = Expression<E>;
    fn mul(self, rhs: Expression<E>) -> Expression<E> {
        match (&self, &rhs) {
            // constant * witin
            (c @ Expression::Constant(_), w @ Expression::WitIn(..))
            | (w @ Expression::WitIn(..), c @ Expression::Constant(_)) => Expression::ScaledSum(
                Box::new(w.clone()),
                Box::new(c.clone()),
                Box::new(Expression::Constant(E::BaseField::ZERO)),
            ),
            // challenge * witin
            (c @ Expression::Challenge(..), w @ Expression::WitIn(..))
            | (w @ Expression::WitIn(..), c @ Expression::Challenge(..)) => Expression::ScaledSum(
                Box::new(w.clone()),
                Box::new(c.clone()),
                Box::new(Expression::Constant(E::BaseField::ZERO)),
            ),
            // constant * challenge
            (
                Expression::Constant(c1),
                Expression::Challenge(challenge_id, pow, scalar, offset),
            )
            | (
                Expression::Challenge(challenge_id, pow, scalar, offset),
                Expression::Constant(c1),
            ) => Expression::Challenge(*challenge_id, *pow, *scalar * c1, *offset * c1),
            // challenge * challenge
            (
                Expression::Challenge(challenge_id1, pow1, s1, offset1),
                Expression::Challenge(challenge_id2, pow2, s2, offset2),
            ) => {
                if challenge_id1 == challenge_id2 {
                    // (s1 * s2 * c1^(pow1 + pow2) + offset2 * s1 * c1^(pow1) + offset1 * s2 * c2^(pow2))
                    // + offset1 * offset2

                    // (s1 * s2 * c1^(pow1 + pow2) + offset1 * offset2
                    let mut result = Expression::Challenge(
                        *challenge_id1,
                        pow1 + pow2,
                        *s1 * s2,
                        *offset1 * offset2,
                    );

                    // offset2 * s1 * c1^(pow1)
                    if *s1 != E::ZERO && *offset2 != E::ZERO {
                        result = Expression::Sum(
                            Box::new(result),
                            Box::new(Expression::Challenge(
                                *challenge_id1,
                                *pow1,
                                *offset2 * *s1,
                                E::ZERO,
                            )),
                        );
                    }

                    // offset1 * s2 * c2^(pow2))
                    if *s2 != E::ZERO && *offset1 != E::ZERO {
                        result = Expression::Sum(
                            Box::new(result),
                            Box::new(Expression::Challenge(
                                *challenge_id1,
                                *pow2,
                                *offset1 * *s2,
                                E::ZERO,
                            )),
                        );
                    }

                    result
                } else {
                    Expression::Product(Box::new(self), Box::new(rhs))
                }
            }

            // constant * constant
            (Expression::Constant(c1), Expression::Constant(c2)) => Expression::Constant(*c1 * c2),
            // scaledsum * constant
            (Expression::ScaledSum(x, a, b), c2 @ Expression::Constant(_))
            | (c2 @ Expression::Constant(_), Expression::ScaledSum(x, a, b)) => {
                Expression::ScaledSum(
                    x.clone(),
                    Box::new(a.deref().clone() * c2.clone()),
                    Box::new(b.deref().clone() * c2.clone()),
                )
            }
            // scaled * challenge => scaled
            (Expression::ScaledSum(x, a, b), c2 @ Expression::Challenge(..))
            | (c2 @ Expression::Challenge(..), Expression::ScaledSum(x, a, b)) => {
                Expression::ScaledSum(
                    x.clone(),
                    Box::new(a.deref().clone() * c2.clone()),
                    Box::new(b.deref().clone() * c2.clone()),
                )
            }
            _ => Expression::Product(Box::new(self), Box::new(rhs)),
        }
    }
}

#[derive(Clone, Debug, Copy)]
pub struct WitIn {
    pub id: WitnessId,
}

#[derive(Clone, Debug, Ord, PartialOrd, Eq, PartialEq)]
pub struct Fixed(pub usize);

impl WitIn {
    pub fn from_expr<E: ExtensionField, N, NR>(
        name: N,
        circuit_builder: &mut CircuitBuilder<E>,
        input: Expression<E>,
        debug: bool,
    ) -> Result<Self, ZKVMError>
    where
        NR: Into<String> + Clone,
        N: FnOnce() -> NR,
    {
        circuit_builder.namespace(
            || "from_expr",
            |cb| {
                let name = name().into();
                let wit = cb.create_witin(|| name.clone())?;
                if !debug {
                    cb.require_zero(|| name.clone(), wit.expr() - input)?;
                }
                Ok(wit)
            },
        )
    }

    pub fn assign<E: ExtensionField>(
        &self,
        instance: &mut [MaybeUninit<E::BaseField>],
        value: E::BaseField,
    ) {
        instance[self.id as usize] = MaybeUninit::new(value);
    }
}

#[macro_export]
/// this is to avoid non-monomial expression
macro_rules! create_witin_from_expr {
    // Handle the case for a single expression
    ($name:expr, $builder:expr, $debug:expr, $e:expr) => {
        WitIn::from_expr($name, $builder, $e, $debug)
    };
    // Recursively handle multiple expressions and create a flat tuple with error handling
    ($name:expr, $builder:expr, $debug:expr, $e:expr, $($rest:expr),+) => {
        {
            // Return a Result tuple, handling errors
            Ok::<_, ZKVMError>((WitIn::from_expr($name, $builder, $e, $debug)?, $(WitIn::from_expr($name, $builder, $rest)?),*))
        }
    };
}

pub trait ToExpr<E: ExtensionField> {
    type Output;
    fn expr(&self) -> Self::Output;
}

impl<E: ExtensionField> ToExpr<E> for WitIn {
    type Output = Expression<E>;
    fn expr(&self) -> Expression<E> {
        Expression::WitIn(self.id)
    }
}

impl<F: SmallField, E: ExtensionField<BaseField = F>> ToExpr<E> for F {
    type Output = Expression<E>;
    fn expr(&self) -> Expression<E> {
        Expression::Constant(*self)
    }
}

impl<F: SmallField, E: ExtensionField<BaseField = F>> From<usize> for Expression<E> {
    fn from(value: usize) -> Self {
        Expression::Constant(F::from(value as u64))
    }
}

#[cfg(test)]
mod tests {
    use goldilocks::GoldilocksExt2;

    use crate::{
        circuit_builder::{CircuitBuilder, ConstraintSystem},
        scheme::{mock_prover::fmt_expr_2 as fmt_expr, utils::eval_by_expr},
    };

    use super::{Expression, ToExpr};
    use ff::Field;

    #[test]
    fn test_expression_arithmetics() {
        type E = GoldilocksExt2;
        let mut cs = ConstraintSystem::new(|| "test_root");
        let mut cb = CircuitBuilder::<E>::new(&mut cs);
        let x = cb.create_witin(|| "x").unwrap();

        // scaledsum * challenge
        // 3 * x + 2
        let expr: Expression<E> =
            Into::<Expression<E>>::into(3usize) * x.expr() + Into::<Expression<E>>::into(2usize);
        // c^3 + 1
        let c = Expression::Challenge(0, 3, 1.into(), 1.into());
        // res
        // x* (c^3*3 + 3) + 2c^3 + 2
        assert_eq!(
            c * expr,
            Expression::ScaledSum(
                Box::new(x.expr()),
                Box::new(Expression::Challenge(0, 3, 3.into(), 3.into())),
                Box::new(Expression::Challenge(0, 3, 2.into(), 2.into()))
            )
        );

        // constant * witin
        // 3 * x
        let expr: Expression<E> = Into::<Expression<E>>::into(3usize) * x.expr();
        assert_eq!(
            expr,
            Expression::ScaledSum(
                Box::new(x.expr()),
                Box::new(Expression::Constant(3.into())),
                Box::new(Expression::Constant(0.into()))
            )
        );

        // constant * challenge
        // 3 * (c^3 + 1)
        let expr: Expression<E> = Expression::Constant(3.into());
        let c = Expression::Challenge(0, 3, 1.into(), 1.into());
        assert_eq!(expr * c, Expression::Challenge(0, 3, 3.into(), 3.into()));

        // challenge * challenge
        // (2c^3 + 1) * (2c^2 + 1) = 4c^5 + 2c^3 + 2c^2 + 1
        let res: Expression<E> = Expression::Challenge(0, 3, 2.into(), 1.into())
            * Expression::Challenge(0, 2, 2.into(), 1.into());
        assert_eq!(
            res,
            Expression::Sum(
                Box::new(Expression::Sum(
                    // (s1 * s2 * c1^(pow1 + pow2) + offset1 * offset2
                    Box::new(Expression::Challenge(
                        0,
                        3 + 2,
                        (2 * 2).into(),
                        E::ONE * E::ONE,
                    )),
                    // offset2 * s1 * c1^(pow1)
                    Box::new(Expression::Challenge(0, 3, 2.into(), E::ZERO)),
                )),
                // offset1 * s2 * c2^(pow2))
                Box::new(Expression::Challenge(0, 2, 2.into(), E::ZERO)),
            )
        );
    }

    #[test]
    fn test_is_monomial_form() {
        type E = GoldilocksExt2;
        let mut cs = ConstraintSystem::new(|| "test_root");
        let mut cb = CircuitBuilder::<E>::new(&mut cs);
        let x = cb.create_witin(|| "x").unwrap();
        let y = cb.create_witin(|| "y").unwrap();
        let z = cb.create_witin(|| "z").unwrap();
        // scaledsum * challenge
        // 3 * x + 2
        let expr: Expression<E> =
            Into::<Expression<E>>::into(3usize) * x.expr() + Into::<Expression<E>>::into(2usize);
        assert!(expr.is_monomial_form());

        // 2 product term
        let expr: Expression<E> = Into::<Expression<E>>::into(3usize) * x.expr() * y.expr()
            + Into::<Expression<E>>::into(2usize) * x.expr();
        assert!(expr.is_monomial_form());

        // complex linear operation
        // (2c + 3) * x * y - 6z
        let expr: Expression<E> =
            Expression::Challenge(0, 1, 2.into(), 3.into()) * x.expr() * y.expr()
                - Into::<Expression<E>>::into(6usize) * z.expr();
        assert!(expr.is_monomial_form());

        // complex linear operation
        // (2c + 3) * x * y - 6z
        let expr: Expression<E> =
            Expression::Challenge(0, 1, 2.into(), 3.into()) * x.expr() * y.expr()
                - Into::<Expression<E>>::into(6usize) * z.expr();
        assert!(expr.is_monomial_form());

        // complex linear operation
        // (2 * x + 3) * 3 + 6 * 8
        let expr: Expression<E> = (Into::<Expression<E>>::into(2usize) * x.expr()
            + Into::<Expression<E>>::into(3usize))
            * Into::<Expression<E>>::into(3usize)
            + Into::<Expression<E>>::into(6usize) * Into::<Expression<E>>::into(8usize);
        assert!(expr.is_monomial_form());
    }

    #[test]
    fn test_not_monomial_form() {
        type E = GoldilocksExt2;
        let mut cs = ConstraintSystem::new(|| "test_root");
        let mut cb = CircuitBuilder::<E>::new(&mut cs);
        let x = cb.create_witin(|| "x").unwrap();
        let y = cb.create_witin(|| "y").unwrap();
        // scaledsum * challenge
        // (x + 1) * (y + 1)
        let expr: Expression<E> = (Into::<Expression<E>>::into(1usize) + x.expr())
            * (Into::<Expression<E>>::into(2usize) + y.expr());
        assert!(!expr.is_monomial_form());
    }

    #[test]
    fn test_to_monomial_form_1() {
        let w_0 = Expression::<GoldilocksExt2>::WitIn(0);
        let w_1 = Expression::<GoldilocksExt2>::WitIn(1);

        let expr = (w_0.clone() + w_1.clone()) * (w_0 + w_1);

        assert!(!expr.is_monomial_form(), "expr is not in monomial form");
        assert_eq!(
            fmt_expr(&expr),
            "(WitIn(0) + WitIn(1)) * (WitIn(0) + WitIn(1))"
        );
        let result_1 = eval_by_expr(&[1.into(), 10000.into()], &[], &expr);

        let expr = expr.to_monomial_form();
        assert!(expr.is_monomial_form(), "expr must now be monomial form");
        assert_eq!(
            fmt_expr(&expr),
            "0 + WitIn(0) * WitIn(0) + WitIn(0) * WitIn(1) + WitIn(1) * WitIn(0) + WitIn(1) * WitIn(1)"
        );

        let result_2 = eval_by_expr(&[1.into(), 10000.into()], &[], &expr);
        assert_eq!(
            result_1, result_2,
            "evaluation before and after must be equal"
        );
    }

    #[test]
    fn test_to_monomial_form_2() {
        let w_0 = Expression::<GoldilocksExt2>::WitIn(0);
        let w_1 = Expression::<GoldilocksExt2>::WitIn(1);
        let c_4 = Expression::<GoldilocksExt2>::Constant(4.into());
        let c_7 = Expression::<GoldilocksExt2>::Constant(7.into());

        let expr = (w_0.clone() + w_1.clone() + c_4) * (w_0 + w_1 + c_7);

        assert!(!expr.is_monomial_form(), "expr is not in monomial form");
        assert_eq!(
            fmt_expr(&expr),
            "(WitIn(0) + WitIn(1) + 4) * (WitIn(0) + WitIn(1) + 7)"
        );
        let result_1 = eval_by_expr(&[1.into(), 10000.into()], &[], &expr);

        let expr = expr.to_monomial_form();
        assert!(expr.is_monomial_form(), "expr must now be monomial form");
        assert_eq!(
            fmt_expr(&expr),
            "0 + WitIn(0) * WitIn(0) + WitIn(0) * WitIn(1) + 7 * WitIn(0) + 0 + WitIn(1) * WitIn(0) + WitIn(1) * WitIn(1) + 7 * WitIn(1) + 0 + 4 * WitIn(0) + 0 + 4 * WitIn(1) + 0 + 28"
        );

        let result_2 = eval_by_expr(&[1.into(), 10000.into()], &[], &expr);
        assert_eq!(
            result_1, result_2,
            "evaluation before and after must be equal"
        );
    }
}
