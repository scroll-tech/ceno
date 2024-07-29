use std::ops::{Add, Mul, Neg, Sub};

use ff_ext::ExtensionField;
use goldilocks::SmallField;
use simple_frontend::structs::{ChallengeId, WitnessId};
use std::cmp::max;

use crate::{constants::OpcodeType, error::UtilError, structs_v2::CircuitBuilderV2};

#[derive(Debug)]
pub enum ZKVMV2Error {
    CircuitError(&'static str),
    UtilError(UtilError),
    VerifyError,
}

impl From<UtilError> for ZKVMV2Error {
    fn from(error: UtilError) -> Self {
        Self::UtilError(error)
    }
}
pub trait InstructionV2<E: ExtensionField> {
    const OPCODE: OpcodeType;
    const NAME: &'static str;
    type InstructionConfig;
    fn construct_circuit(
        circuit_builder: &mut CircuitBuilderV2<E>,
    ) -> Result<Self::InstructionConfig, ZKVMV2Error>;
}

#[derive(Clone, Debug)]
pub enum Expression<E: ExtensionField> {
    /// WitIn(Id)
    WitIn(WitnessId),
    /// Constant poly
    Constant(E::BaseField),
    /// This is the sum of two expression
    Sum(Box<Expression<E>>, Box<Expression<E>>),
    /// This is the product of two polynomials
    Product(Box<Expression<E>>, Box<Expression<E>>),
    /// This is a scaled polynomial
    Scaled(Box<Expression<E>>, E),
    Challenge(ChallengeId, usize, E, E), // (challenge_id, power, scalar, offset)
}

impl<E: ExtensionField> Expression<E> {
    pub fn degree(&self) -> usize {
        match self {
            Expression::WitIn(_) => 1,
            Expression::Constant(_) => 0,
            Expression::Sum(a_expr, b_expr) => max(a_expr.degree(), b_expr.degree()),
            Expression::Product(a_expr, b_expr) => a_expr.degree() + b_expr.degree(),
            Expression::Scaled(expr, _) => expr.degree(),
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
        scaled: &impl Fn(T, E) -> T,
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
            Expression::Scaled(a, scalar) => {
                let a = a.evaluate(wit_in, constant, challenge, sum, product, scaled);
                scaled(a, *scalar)
            }
            Expression::Challenge(challenge_id, pow, scalar, offset) => {
                challenge(*challenge_id, *pow, *scalar, *offset)
            }
        }
    }
}

impl<E: ExtensionField> Neg for Expression<E> {
    type Output = Expression<E>;
    fn neg(self) -> Self::Output {
        Expression::Scaled(Box::new(self), E::ONE.neg())
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
            _ => Expression::Sum(Box::new(self), Box::new(-rhs)),
        }
    }
}

impl<E: ExtensionField> Mul for Expression<E> {
    type Output = Expression<E>;
    fn mul(self, rhs: Expression<E>) -> Expression<E> {
        match (&self, &rhs) {
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
                Expression::Challenge(challenge_id1, pow1, scalar1, offset1),
                Expression::Challenge(challenge_id2, pow2, scalar2, offset2),
            ) => {
                if challenge_id1 == challenge_id2 && (offset1, offset2) == (&E::ZERO, &E::ZERO) {
                    Expression::Challenge(*challenge_id1, pow1 + pow2, *scalar1 * scalar2, E::ZERO)
                } else {
                    Expression::Product(Box::new(self), Box::new(rhs))
                }
            }

            // constant * constant
            (Expression::Constant(c1), Expression::Constant(c2)) => Expression::Constant(*c1 * c2),
            // scaled * constant => scaled
            (Expression::Scaled(a_expr, c1), Expression::Constant(c2)) => {
                Expression::Scaled(a_expr.clone(), *c1 * c2)
            }
            (Expression::Constant(c2), Expression::Scaled(a_expr, c1)) => {
                Expression::Scaled(a_expr.clone(), *c1 * c2)
            }
            _ => Expression::Product(Box::new(self), Box::new(rhs)),
        }
    }
}

#[derive(Clone, Debug)]
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
        Expression::Constant(self.clone())
    }
}

impl<F: SmallField, E: ExtensionField<BaseField = F>> From<usize> for Expression<E> {
    fn from(value: usize) -> Self {
        Expression::Constant(F::from(value as u64))
    }
}
