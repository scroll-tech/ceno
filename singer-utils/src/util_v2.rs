use std::ops::{Add, Mul, Neg, Sub};

use ff_ext::ExtensionField;
use goldilocks::SmallField;
use simple_frontend::structs::ChallengeId;
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
pub enum ExpressionV2<E: ExtensionField> {
    /// WitIn(Id)
    WitIn(usize),
    /// Constant poly
    Constant(E::BaseField),
    Negated(Box<ExpressionV2<E>>),
    /// This is the sum of two expression
    Sum(Box<ExpressionV2<E>>, Box<ExpressionV2<E>>),
    /// This is the product of two polynomials
    Product(Box<ExpressionV2<E>>, Box<ExpressionV2<E>>),
    /// This is a scaled polynomial
    Scaled(Box<ExpressionV2<E>>, E),
    Challenge(ChallengeId),
}

impl<E: ExtensionField> ExpressionV2<E> {
    pub fn degree(&self) -> usize {
        match self {
            ExpressionV2::WitIn(_) => 1,
            ExpressionV2::Constant(_) => 0,
            ExpressionV2::Negated(expr) => expr.degree(),
            ExpressionV2::Sum(a_expr, b_expr) => max(a_expr.degree(), b_expr.degree()),
            ExpressionV2::Product(a_expr, b_expr) => a_expr.degree() + b_expr.degree(),
            ExpressionV2::Scaled(expr, _) => expr.degree(),
            ExpressionV2::Challenge(_) => 0,
        }
    }
}

impl<E: ExtensionField> Neg for ExpressionV2<E> {
    type Output = ExpressionV2<E>;
    fn neg(self) -> Self::Output {
        ExpressionV2::Negated(Box::new(self))
    }
}

impl<E: ExtensionField> Add for ExpressionV2<E> {
    type Output = ExpressionV2<E>;
    fn add(self, rhs: ExpressionV2<E>) -> ExpressionV2<E> {
        ExpressionV2::Sum(Box::new(self), Box::new(rhs))
    }
}

impl<E: ExtensionField> Sub for ExpressionV2<E> {
    type Output = ExpressionV2<E>;
    fn sub(self, rhs: ExpressionV2<E>) -> ExpressionV2<E> {
        ExpressionV2::Sum(Box::new(self), Box::new(-rhs))
    }
}

impl<E: ExtensionField> Mul for ExpressionV2<E> {
    type Output = ExpressionV2<E>;
    fn mul(self, rhs: ExpressionV2<E>) -> ExpressionV2<E> {
        match (&self, &rhs) {
            // scaled * constant => scaled
            (ExpressionV2::Scaled(a_expr, c1), ExpressionV2::Constant(c2)) => {
                ExpressionV2::Scaled(a_expr.clone(), *c1 * c2)
            }
            (ExpressionV2::Constant(c2), ExpressionV2::Scaled(a_expr, c1)) => {
                ExpressionV2::Scaled(a_expr.clone(), *c1 * c2)
            }
            _ => ExpressionV2::Product(Box::new(self), Box::new(rhs)),
        }
    }
}

#[derive(Clone, Debug)]
pub struct WitIn {
    pub id: usize,
}

pub trait ToExpr<E: ExtensionField> {
    fn expr(&self) -> ExpressionV2<E>;
}

impl<E: ExtensionField> ToExpr<E> for WitIn {
    fn expr(&self) -> ExpressionV2<E> {
        ExpressionV2::WitIn(self.id)
    }
}

impl<F: SmallField, E: ExtensionField<BaseField = F>> ToExpr<E> for F {
    fn expr(&self) -> ExpressionV2<E> {
        ExpressionV2::Constant(self.clone())
    }
}

impl<F: SmallField, E: ExtensionField<BaseField = F>> From<usize> for ExpressionV2<E> {
    fn from(value: usize) -> Self {
        ExpressionV2::Constant(F::from(value as u64))
    }
}
