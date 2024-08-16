use std::{
    cmp::max,
    ops::{Add, Deref, Mul, Neg, Sub},
};

use ff::Field;
use ff_ext::ExtensionField;
use goldilocks::SmallField;

use crate::structs::{ChallengeId, WitnessId};

#[derive(Clone, Debug, PartialEq)]
pub enum Expression<E: ExtensionField> {
    /// WitIn(Id)
    WitIn(WitnessId),
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
/// for differentiate a expression is in monomial form or not
enum MonomialState {
    SumTerm,
    ProductTerm,
}

impl<E: ExtensionField> Expression<E> {
    pub fn degree(&self) -> usize {
        match self {
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
        wit_in: &impl Fn(WitnessId) -> T, // witin id
        constant: &impl Fn(E::BaseField) -> T,
        challenge: &impl Fn(ChallengeId, usize, E, E) -> T,
        sum: &impl Fn(T, T) -> T,
        product: &impl Fn(T, T) -> T,
        scaled: &impl Fn(T, T, T) -> T,
    ) -> T {
        match self {
            Expression::WitIn(witness_id) => wit_in(*witness_id),
            Expression::Constant(scalar) => constant(*scalar),
            Expression::Sum(a, b) => {
                let a = a.evaluate(wit_in, constant, challenge, sum, product, scaled);
                let b = b.evaluate(wit_in, constant, challenge, sum, product, scaled);
                sum(a, b)
            }
            Expression::Product(a, b) => {
                let a = a.evaluate(wit_in, constant, challenge, sum, product, scaled);
                let b = b.evaluate(wit_in, constant, challenge, sum, product, scaled);
                product(a, b)
            }
            Expression::ScaledSum(x, a, b) => {
                let x = x.evaluate(wit_in, constant, challenge, sum, product, scaled);
                let a = a.evaluate(wit_in, constant, challenge, sum, product, scaled);
                let b = b.evaluate(wit_in, constant, challenge, sum, product, scaled);
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

    fn is_zero_expr(expr: &Expression<E>) -> bool {
        match expr {
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
            (Expression::WitIn(_), MonomialState::SumTerm) => true,
            (Expression::WitIn(_), MonomialState::ProductTerm) => true,
            (Expression::Constant(_), MonomialState::SumTerm) => true,
            (Expression::Constant(_), MonomialState::ProductTerm) => true,
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
            (Expression::Challenge(_, _, _, _), MonomialState::SumTerm) => true,
            (Expression::Challenge(_, _, _, _), MonomialState::ProductTerm) => true,
        }
    }
}

impl<E: ExtensionField> Neg for Expression<E> {
    type Output = Expression<E>;
    fn neg(self) -> Self::Output {
        match self {
            Expression::WitIn(_) => Expression::ScaledSum(
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
                    Expression::Sum(
                        Box::new(Expression::Sum(
                            // (s1 * s2 * c1^(pow1 + pow2) + offset1 * offset2
                            Box::new(Expression::Challenge(
                                *challenge_id1,
                                pow1 + pow2,
                                *s1 * s2,
                                *offset1 * offset2,
                            )),
                            // offset2 * s1 * c1^(pow1)
                            Box::new(Expression::Challenge(
                                *challenge_id1,
                                *pow1,
                                *offset2,
                                E::ZERO,
                            )),
                        )),
                        // offset1 * s2 * c2^(pow2))
                        Box::new(Expression::Challenge(
                            *challenge_id1,
                            *pow2,
                            *offset1,
                            E::ZERO,
                        )),
                    )
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

pub trait ToExpr<E: ExtensionField> {
    fn expr(&self) -> Expression<E>;
}

impl<E: ExtensionField> ToExpr<E> for WitIn {
    fn expr(&self) -> Expression<E> {
        Expression::WitIn(self.id)
    }
}

impl<F: SmallField, E: ExtensionField<BaseField = F>> ToExpr<E> for F {
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

    use crate::circuit_builder::CircuitBuilder;

    use super::{Expression, ToExpr};
    use ff::Field;

    #[test]
    fn test_expression_arithmetics() {
        type E = GoldilocksExt2;
        let mut cb = CircuitBuilder::<E>::new();
        let x = cb.create_witin();

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
                    Box::new(Expression::Challenge(0, 3, E::ONE, E::ZERO,)),
                )),
                // offset1 * s2 * c2^(pow2))
                Box::new(Expression::Challenge(0, 2, E::ONE, E::ZERO,)),
            )
        );
    }

    #[test]
    fn test_is_monomial_form() {
        type E = GoldilocksExt2;
        let mut cb = CircuitBuilder::<E>::new();
        let x = cb.create_witin();
        let y = cb.create_witin();
        let z = cb.create_witin();
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
        let mut cb = CircuitBuilder::<E>::new();
        let x = cb.create_witin();
        let y = cb.create_witin();
        // scaledsum * challenge
        // (x + 1) * (y + 1)
        let expr: Expression<E> = (Into::<Expression<E>>::into(1usize) + x.expr())
            * (Into::<Expression<E>>::into(2usize) + y.expr());
        assert!(!expr.is_monomial_form());
    }
}
