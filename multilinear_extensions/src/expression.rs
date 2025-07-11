pub mod monomial;
pub mod utils;

use crate::{
    commutative_op_mle_pair,
    mle::{ArcMultilinearExtension, MultilinearExtension},
    op_mle_xa_b, op_mle3_range,
    util::ceil_log2,
};
use ff_ext::{ExtensionField, SmallField};
use itertools::{Either, izip};
use p3::field::FieldAlgebra;
use rayon::iter::{IndexedParallelIterator, IntoParallelRefIterator, ParallelIterator};
use serde::de::DeserializeOwned;
use std::{
    cmp::max,
    fmt::{Debug, Display},
    iter::{Product, Sum, successors},
    ops::{Add, AddAssign, Deref, Mul, MulAssign, Neg, Shl, ShlAssign, Sub, SubAssign},
};

pub type WitnessId = u16;
pub type ChallengeId = u16;
pub const MIN_PAR_SIZE: usize = 64;

#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
#[serde(bound = "E: ExtensionField + DeserializeOwned")]
pub enum Expression<E: ExtensionField> {
    /// WitIn(Id)
    WitIn(WitnessId),
    /// StructuralWitIn is similar with WitIn, but it is structured.
    /// These witnesses in StructuralWitIn allow succinct verification directly during the verification processing, rather than requiring a commitment.
    /// StructuralWitIn(Id, max_len, offset, multi_factor)
    StructuralWitIn(WitnessId, usize, u32, usize),
    /// This multi-linear polynomial is known at the setup/keygen phase.
    Fixed(Fixed),
    /// Public Values
    Instance(Instance),
    /// Constant poly
    Constant(Either<E::BaseField, E>),
    /// This is the sum of two expressions
    Sum(Box<Expression<E>>, Box<Expression<E>>),
    /// This is the product of two expressions
    Product(Box<Expression<E>>, Box<Expression<E>>),
    /// ScaledSum(x, a, b) represents a * x + b
    /// where x is one of wit / fixed / instance, a and b are either constants or challenges
    ScaledSum(Box<Expression<E>>, Box<Expression<E>>, Box<Expression<E>>),
    /// Challenge(challenge_id, power, scalar, offset)
    Challenge(ChallengeId, usize, E, E),
}

impl<E: ExtensionField> Debug for Expression<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Expression::WitIn(id) => write!(f, "W[{}]", id),
            Expression::StructuralWitIn(id, _max_len, _offset, _multi_factor) => {
                write!(f, "S[{}]", id)
            }
            Expression::Fixed(fixed) => write!(f, "F[{}]", fixed.0),
            Expression::Instance(instance) => write!(f, "I[{}]", instance.0),
            Expression::Constant(c) => write!(f, "C[{}]", c),
            Expression::Sum(a, b) => write!(f, "({} + {})", a, b),
            Expression::Product(a, b) => write!(f, "({} * {})", a, b),
            Expression::ScaledSum(x, a, b) => write!(f, "{} * {} + {}", x, a, b),
            Expression::Challenge(challenge_id, pow, scalar, offset) => {
                write!(
                    f,
                    "C({})^{} * {:?} + {:?}",
                    challenge_id,
                    pow,
                    scalar.to_canonical_u64_vec(),
                    offset.to_canonical_u64_vec(),
                )
            }
        }
    }
}

/// this is used as finite state machine state
/// for differentiate an expression is in monomial form or not
enum MonomialState {
    SumTerm,
    ProductTerm,
}

#[macro_export]
macro_rules! combine_cumulative_either {
    ($a:expr, $b:expr, $op:expr) => {
        match ($a, $b) {
            (Either::Left(c1), Either::Left(c2)) => Either::Left($op(c1, c2)),
            (Either::Left(c1), Either::Right(c2)) => Either::Right($op(c2, c1)),
            (Either::Right(c1), Either::Left(c2)) => Either::Right($op(c1, c2)),
            (Either::Right(c1), Either::Right(c2)) => Either::Right($op(c2, c1)),
        }
    };
}

impl<E: ExtensionField> Expression<E> {
    pub const ZERO: Expression<E> = Expression::Constant(Either::Left(E::BaseField::ZERO));
    pub const ONE: Expression<E> = Expression::Constant(Either::Left(E::BaseField::ONE));

    pub fn degree(&self) -> usize {
        match self {
            Expression::Fixed(_) => 1,
            Expression::WitIn(_) => 1,
            Expression::StructuralWitIn(..) => 1,
            Expression::Instance(_) => 0,
            Expression::Constant(_) => 0,
            Expression::Sum(a_expr, b_expr) => max(a_expr.degree(), b_expr.degree()),
            Expression::Product(a_expr, b_expr) => a_expr.degree() + b_expr.degree(),
            Expression::ScaledSum(x, _, _) => x.degree(),
            Expression::Challenge(_, _, _, _) => 0,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn evaluate<T>(
        &self,
        fixed_in: &impl Fn(&Fixed) -> T,
        wit_in: &impl Fn(WitnessId) -> T, // witin id
        structural_wit_in: &impl Fn(WitnessId, usize, u32, usize) -> T,
        constant: &impl Fn(Either<E::BaseField, E>) -> T,
        challenge: &impl Fn(ChallengeId, usize, E, E) -> T,
        sum: &impl Fn(T, T) -> T,
        product: &impl Fn(T, T) -> T,
        scaled: &impl Fn(T, T, T) -> T,
    ) -> T {
        self.evaluate_with_instance(
            fixed_in,
            wit_in,
            structural_wit_in,
            &|_| unreachable!(),
            constant,
            challenge,
            sum,
            product,
            scaled,
        )
    }

    pub fn evaluate_constant<T>(
        &self,
        constant: &impl Fn(Either<E::BaseField, E>) -> T,
        challenge: &impl Fn(ChallengeId, usize, E, E) -> T,
    ) -> T {
        match self {
            Expression::Constant(either) => constant(*either),
            Expression::Challenge(challenge_id, pow, scalar, offset) => {
                challenge(*challenge_id, *pow, *scalar, *offset)
            }
            _ => unimplemented!("unsupported"),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn evaluate_with_instance<T>(
        &self,
        fixed_in: &impl Fn(&Fixed) -> T,
        wit_in: &impl Fn(WitnessId) -> T, // witin id
        structural_wit_in: &impl Fn(WitnessId, usize, u32, usize) -> T,
        instance: &impl Fn(Instance) -> T,
        constant: &impl Fn(Either<E::BaseField, E>) -> T,
        challenge: &impl Fn(ChallengeId, usize, E, E) -> T,
        sum: &impl Fn(T, T) -> T,
        product: &impl Fn(T, T) -> T,
        scaled: &impl Fn(T, T, T) -> T,
    ) -> T {
        match self {
            Expression::Fixed(f) => fixed_in(f),
            Expression::WitIn(witness_id) => wit_in(*witness_id),
            Expression::StructuralWitIn(witness_id, max_len, offset, multi_factor) => {
                structural_wit_in(*witness_id, *max_len, *offset, *multi_factor)
            }
            Expression::Instance(i) => instance(*i),
            Expression::Constant(scalar) => constant(*scalar),
            Expression::Sum(a, b) => {
                let a = a.evaluate_with_instance(
                    fixed_in,
                    wit_in,
                    structural_wit_in,
                    instance,
                    constant,
                    challenge,
                    sum,
                    product,
                    scaled,
                );
                let b = b.evaluate_with_instance(
                    fixed_in,
                    wit_in,
                    structural_wit_in,
                    instance,
                    constant,
                    challenge,
                    sum,
                    product,
                    scaled,
                );
                sum(a, b)
            }
            Expression::Product(a, b) => {
                let a = a.evaluate_with_instance(
                    fixed_in,
                    wit_in,
                    structural_wit_in,
                    instance,
                    constant,
                    challenge,
                    sum,
                    product,
                    scaled,
                );
                let b = b.evaluate_with_instance(
                    fixed_in,
                    wit_in,
                    structural_wit_in,
                    instance,
                    constant,
                    challenge,
                    sum,
                    product,
                    scaled,
                );
                product(a, b)
            }
            Expression::ScaledSum(x, a, b) => {
                let x = x.evaluate_with_instance(
                    fixed_in,
                    wit_in,
                    structural_wit_in,
                    instance,
                    constant,
                    challenge,
                    sum,
                    product,
                    scaled,
                );
                let a = a.evaluate_with_instance(
                    fixed_in,
                    wit_in,
                    structural_wit_in,
                    instance,
                    constant,
                    challenge,
                    sum,
                    product,
                    scaled,
                );
                let b = b.evaluate_with_instance(
                    fixed_in,
                    wit_in,
                    structural_wit_in,
                    instance,
                    constant,
                    challenge,
                    sum,
                    product,
                    scaled,
                );
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

    pub fn get_monomial_form(&self) -> Self {
        self.get_monomial_terms().into_iter().sum()
    }

    pub fn is_constant(&self) -> bool {
        matches!(self, Expression::Constant(_))
    }

    pub fn is_linear(&self) -> bool {
        self.degree() <= 1
    }

    fn is_zero_expr(expr: &Expression<E>) -> bool {
        match expr {
            Expression::Fixed(_) => false,
            Expression::WitIn(_) => false,
            Expression::StructuralWitIn(..) => false,
            Expression::Instance(_) => false,
            Expression::Constant(c) => c
                .map_either(|c| c == E::BaseField::ZERO, |c| c == E::ZERO)
                .into_inner(),
            Expression::Sum(a, b) => Self::is_zero_expr(a) && Self::is_zero_expr(b),
            Expression::Product(a, b) => Self::is_zero_expr(a) || Self::is_zero_expr(b),
            Expression::ScaledSum(x, a, b) => {
                (Self::is_zero_expr(x) || Self::is_zero_expr(a)) && Self::is_zero_expr(b)
            }
            Expression::Challenge(_, _, scalar, offset) => *scalar == E::ZERO && *offset == E::ZERO,
        }
    }

    fn is_monomial_form_inner(s: MonomialState, expr: &Expression<E>) -> bool {
        match (expr, s) {
            (
                Expression::Fixed(_)
                | Expression::WitIn(_)
                | Expression::StructuralWitIn(..)
                | Expression::Challenge(..)
                | Expression::Constant(_)
                | Expression::Instance(_),
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
            (Expression::ScaledSum(x, a, b), MonomialState::ProductTerm) => {
                Self::is_zero_expr(x) || Self::is_zero_expr(a) || Self::is_zero_expr(b)
            }
        }
    }

    /// recursively transforms an expression tree by allowing custom handlers for each leaf variant.
    /// this allows rewriting any part of the tree (e.g., replacing `Fixed` with `WitIn`, etc.).
    /// each closure corresponds to the rewrite a specific leaf node.
    pub fn transform_all<TF, TW, TS, TI, TC, CH>(
        &self,
        fixed_fn: &TF,
        wit_fn: &TW,
        struct_wit_fn: &TS,
        instance_fn: &TI,
        constant_fn: &TC,
        challenge_fn: &CH,
    ) -> Expression<E>
    where
        TF: Fn(&Fixed) -> Expression<E>,
        TW: Fn(WitnessId) -> Expression<E>,
        TS: Fn(WitnessId, usize, u32, usize) -> Expression<E>,
        TI: Fn(Instance) -> Expression<E>,
        TC: Fn(Either<E::BaseField, E>) -> Expression<E>,
        CH: Fn(ChallengeId, usize, E, E) -> Expression<E>,
    {
        match self {
            Expression::WitIn(id) => wit_fn(*id),
            Expression::StructuralWitIn(id, len, offset, multi_factor) => {
                struct_wit_fn(*id, *len, *offset, *multi_factor)
            }
            Expression::Fixed(f) => fixed_fn(f),
            Expression::Instance(i) => instance_fn(*i),
            Expression::Constant(c) => constant_fn(*c),
            Expression::Challenge(id, pow, scalar, offset) => {
                challenge_fn(*id, *pow, *scalar, *offset)
            }
            Expression::Sum(a, b) => Expression::Sum(
                Box::new(a.transform_all(
                    fixed_fn,
                    wit_fn,
                    struct_wit_fn,
                    instance_fn,
                    constant_fn,
                    challenge_fn,
                )),
                Box::new(b.transform_all(
                    fixed_fn,
                    wit_fn,
                    struct_wit_fn,
                    instance_fn,
                    constant_fn,
                    challenge_fn,
                )),
            ),
            Expression::Product(a, b) => Expression::Product(
                Box::new(a.transform_all(
                    fixed_fn,
                    wit_fn,
                    struct_wit_fn,
                    instance_fn,
                    constant_fn,
                    challenge_fn,
                )),
                Box::new(b.transform_all(
                    fixed_fn,
                    wit_fn,
                    struct_wit_fn,
                    instance_fn,
                    constant_fn,
                    challenge_fn,
                )),
            ),
            Expression::ScaledSum(x, a, b) => Expression::ScaledSum(
                Box::new(x.transform_all(
                    fixed_fn,
                    wit_fn,
                    struct_wit_fn,
                    instance_fn,
                    constant_fn,
                    challenge_fn,
                )),
                Box::new(a.transform_all(
                    fixed_fn,
                    wit_fn,
                    struct_wit_fn,
                    instance_fn,
                    constant_fn,
                    challenge_fn,
                )),
                Box::new(b.transform_all(
                    fixed_fn,
                    wit_fn,
                    struct_wit_fn,
                    instance_fn,
                    constant_fn,
                    challenge_fn,
                )),
            ),
        }
    }
}

impl<E: ExtensionField> Neg for Expression<E> {
    type Output = Expression<E>;
    fn neg(self) -> Self::Output {
        match self {
            Expression::Fixed(_)
            | Expression::WitIn(_)
            | Expression::StructuralWitIn(..)
            | Expression::Instance(_) => Expression::ScaledSum(
                Box::new(self),
                Box::new(Expression::Constant(Either::Left(-E::BaseField::ONE))),
                Box::new(Expression::Constant(Either::Left(E::BaseField::ZERO))),
            ),
            Expression::Constant(c1) => Expression::Constant(c1.map_either(|c| -c, |c| -c)),
            Expression::Sum(a, b) => Expression::Sum(-a, -b),
            Expression::Product(a, b) => Expression::Product(-a, b.clone()),
            Expression::ScaledSum(x, a, b) => Expression::ScaledSum(x, -a, -b),
            Expression::Challenge(challenge_id, pow, scalar, offset) => {
                Expression::Challenge(challenge_id, pow, scalar.neg(), offset.neg())
            }
        }
    }
}

impl<E: ExtensionField> Neg for &Expression<E> {
    type Output = Expression<E>;
    fn neg(self) -> Self::Output {
        self.clone().neg()
    }
}

impl<E: ExtensionField> Neg for Box<Expression<E>> {
    type Output = Box<Expression<E>>;
    fn neg(self) -> Self::Output {
        self.deref().clone().neg().into()
    }
}

impl<E: ExtensionField> Neg for &Box<Expression<E>> {
    type Output = Box<Expression<E>>;
    fn neg(self) -> Self::Output {
        self.clone().neg()
    }
}

impl<E: ExtensionField> Add for Expression<E> {
    type Output = Expression<E>;
    fn add(self, rhs: Expression<E>) -> Expression<E> {
        match (&self, &rhs) {
            // constant + witness
            // constant + fixed
            // constant + instance
            (Expression::WitIn(_), Expression::Constant(_))
            | (Expression::Fixed(_), Expression::Constant(_))
            | (Expression::Instance(_), Expression::Constant(_)) => Expression::ScaledSum(
                Box::new(self),
                Box::new(Expression::Constant(Either::Left(E::BaseField::ONE))),
                Box::new(rhs),
            ),
            (Expression::Constant(_), Expression::WitIn(_))
            | (Expression::Constant(_), Expression::Fixed(_))
            | (Expression::Constant(_), Expression::Instance(_)) => Expression::ScaledSum(
                Box::new(rhs),
                Box::new(Expression::Constant(Either::Left(E::BaseField::ONE))),
                Box::new(self),
            ),
            // challenge + witness
            // challenge + fixed
            // challenge + instance
            (Expression::WitIn(_), Expression::Challenge(..))
            | (Expression::Fixed(_), Expression::Challenge(..))
            | (Expression::Instance(_), Expression::Challenge(..)) => Expression::ScaledSum(
                Box::new(self),
                Box::new(Expression::Constant(Either::Left(E::BaseField::ONE))),
                Box::new(rhs),
            ),
            (Expression::Challenge(..), Expression::WitIn(_))
            | (Expression::Challenge(..), Expression::Fixed(_))
            | (Expression::Challenge(..), Expression::Instance(_)) => Expression::ScaledSum(
                Box::new(rhs),
                Box::new(Expression::Constant(Either::Left(E::BaseField::ONE))),
                Box::new(self),
            ),
            // constant + challenge
            (
                Expression::Constant(c1),
                Expression::Challenge(challenge_id, pow, scalar, offset),
            )
            | (
                Expression::Challenge(challenge_id, pow, scalar, offset),
                Expression::Constant(c1),
            ) => Expression::Challenge(
                *challenge_id,
                *pow,
                *scalar,
                either::for_both!(*c1, c1 => *offset + c1),
            ),

            // challenge + challenge
            (
                Expression::Challenge(challenge_id1, pow1, scalar1, offset1),
                Expression::Challenge(challenge_id2, pow2, scalar2, offset2),
            ) => {
                if challenge_id1 == challenge_id2 && pow1 == pow2 {
                    Expression::Challenge(
                        *challenge_id1,
                        *pow1,
                        *scalar1 + *scalar2,
                        *offset1 + *offset2,
                    )
                } else {
                    Expression::Sum(Box::new(self), Box::new(rhs))
                }
            }

            // constant + constant
            (Expression::Constant(c1), Expression::Constant(c2)) => {
                Expression::Constant(combine_cumulative_either!(*c1, *c2, |c1, c2| c1 + c2))
            }

            // constant + scaled sum
            (c1 @ Expression::Constant(_), Expression::ScaledSum(x, a, b))
            | (Expression::ScaledSum(x, a, b), c1 @ Expression::Constant(_)) => {
                Expression::ScaledSum(x.clone(), a.clone(), Box::new(b.deref() + c1))
            }

            _ => Expression::Sum(Box::new(self), Box::new(rhs)),
        }
    }
}

macro_rules! binop_assign_instances {
    ($op_assign: ident, $fun_assign: ident, $op: ident, $fun: ident) => {
        impl<E: ExtensionField, Rhs> $op_assign<Rhs> for Expression<E>
        where
            Expression<E>: $op<Rhs, Output = Expression<E>>,
        {
            fn $fun_assign(&mut self, rhs: Rhs) {
                // TODO: consider in-place?
                *self = self.clone().$fun(rhs);
            }
        }
    };
}

binop_assign_instances!(AddAssign, add_assign, Add, add);
binop_assign_instances!(SubAssign, sub_assign, Sub, sub);
binop_assign_instances!(MulAssign, mul_assign, Mul, mul);

impl<E: ExtensionField> Shl<usize> for Expression<E> {
    type Output = Expression<E>;
    fn shl(self, rhs: usize) -> Expression<E> {
        self * (1_usize << rhs)
    }
}

impl<E: ExtensionField> Shl<usize> for &Expression<E> {
    type Output = Expression<E>;
    fn shl(self, rhs: usize) -> Expression<E> {
        self.clone() << rhs
    }
}

impl<E: ExtensionField> Shl<usize> for &mut Expression<E> {
    type Output = Expression<E>;
    fn shl(self, rhs: usize) -> Expression<E> {
        self.clone() << rhs
    }
}

impl<E: ExtensionField> ShlAssign<usize> for Expression<E> {
    fn shl_assign(&mut self, rhs: usize) {
        *self = self.clone() << rhs;
    }
}

impl<E: ExtensionField> Sum for Expression<E> {
    fn sum<I: Iterator<Item = Expression<E>>>(iter: I) -> Expression<E> {
        iter.fold(Expression::ZERO, |acc, x| acc + x)
    }
}

impl<E: ExtensionField> Product for Expression<E> {
    fn product<I: Iterator<Item = Expression<E>>>(iter: I) -> Self {
        iter.fold(Expression::ONE, |acc, x| acc * x)
    }
}

impl<E: ExtensionField> Sub for Expression<E> {
    type Output = Expression<E>;
    fn sub(self, rhs: Expression<E>) -> Expression<E> {
        match (&self, &rhs) {
            // witness - constant
            // fixed - constant
            // instance - constant
            (Expression::WitIn(_), Expression::Constant(_))
            | (Expression::Fixed(_), Expression::Constant(_))
            | (Expression::Instance(_), Expression::Constant(_)) => Expression::ScaledSum(
                Box::new(self),
                Box::new(Expression::Constant(Either::Left(E::BaseField::ONE))),
                Box::new(rhs.neg()),
            ),

            // constant - witness
            // constant - fixed
            // constant - instance
            (Expression::Constant(_), Expression::WitIn(_))
            | (Expression::Constant(_), Expression::Fixed(_))
            | (Expression::Constant(_), Expression::Instance(_)) => Expression::ScaledSum(
                Box::new(rhs),
                Box::new(Expression::Constant(Either::Left(E::BaseField::ONE.neg()))),
                Box::new(self),
            ),

            // witness - challenge
            // fixed - challenge
            // instance - challenge
            (Expression::WitIn(_), Expression::Challenge(..))
            | (Expression::Fixed(_), Expression::Challenge(..))
            | (Expression::Instance(_), Expression::Challenge(..)) => Expression::ScaledSum(
                Box::new(self),
                Box::new(Expression::Constant(Either::Left(E::BaseField::ONE))),
                Box::new(rhs.neg()),
            ),

            // challenge - witness
            // challenge - fixed
            // challenge - instance
            (Expression::Challenge(..), Expression::WitIn(_))
            | (Expression::Challenge(..), Expression::Fixed(_))
            | (Expression::Challenge(..), Expression::Instance(_)) => Expression::ScaledSum(
                Box::new(rhs),
                Box::new(Expression::Constant(Either::Left(E::BaseField::ONE.neg()))),
                Box::new(self),
            ),

            // constant - challenge
            (
                Expression::Constant(c1),
                Expression::Challenge(challenge_id, pow, scalar, offset),
            ) => Expression::Challenge(
                *challenge_id,
                *pow,
                *scalar,
                either::for_both!(*c1, c1 => offset.neg() + c1),
            ),

            // challenge - constant
            (
                Expression::Challenge(challenge_id, pow, scalar, offset),
                Expression::Constant(c1),
            ) => Expression::Challenge(
                *challenge_id,
                *pow,
                *scalar,
                either::for_both!(*c1, c1 => *offset - c1),
            ),

            // challenge - challenge
            (
                Expression::Challenge(challenge_id1, pow1, scalar1, offset1),
                Expression::Challenge(challenge_id2, pow2, scalar2, offset2),
            ) => {
                if challenge_id1 == challenge_id2 && pow1 == pow2 {
                    Expression::Challenge(
                        *challenge_id1,
                        *pow1,
                        *scalar1 - *scalar2,
                        *offset1 - *offset2,
                    )
                } else {
                    Expression::Sum(Box::new(self), Box::new(-rhs))
                }
            }

            // constant - constant
            (Expression::Constant(c1), Expression::Constant(c2)) => {
                Expression::Constant(match (c1, c2) {
                    (Either::Left(c1), Either::Left(c2)) => Either::Left(*c1 - *c2),
                    (Either::Left(c1), Either::Right(c2)) => Either::Right(c2.neg() + *c1),
                    (Either::Right(c1), Either::Left(c2)) => Either::Right(*c1 - *c2),
                    (Either::Right(c1), Either::Right(c2)) => Either::Right(*c1 - *c2),
                })
            }

            // constant - scalesum
            (c1 @ Expression::Constant(_), Expression::ScaledSum(x, a, b)) => {
                Expression::ScaledSum(x.clone(), -a, Box::new(c1 - b.deref()))
            }

            // scalesum - constant
            (Expression::ScaledSum(x, a, b), c1 @ Expression::Constant(_)) => {
                Expression::ScaledSum(x.clone(), a.clone(), Box::new(b.deref() - c1))
            }

            // challenge - scalesum
            (c1 @ Expression::Challenge(..), Expression::ScaledSum(x, a, b)) => {
                Expression::ScaledSum(x.clone(), -a, Box::new(c1 - b.deref()))
            }

            // scalesum - challenge
            (Expression::ScaledSum(x, a, b), c1 @ Expression::Challenge(..)) => {
                Expression::ScaledSum(x.clone(), a.clone(), Box::new(b.deref() - c1))
            }

            _ => Expression::Sum(Box::new(self), Box::new(-rhs)),
        }
    }
}

/// Instances for binary operations that mix Expression and &Expression
macro_rules! ref_binop_instances {
    ($op: ident, $fun: ident) => {
        impl<E: ExtensionField> $op<&Expression<E>> for Expression<E> {
            type Output = Expression<E>;

            fn $fun(self, rhs: &Expression<E>) -> Expression<E> {
                self.$fun(rhs.clone())
            }
        }

        impl<E: ExtensionField> $op<Expression<E>> for &Expression<E> {
            type Output = Expression<E>;

            fn $fun(self, rhs: Expression<E>) -> Expression<E> {
                self.clone().$fun(rhs)
            }
        }

        impl<E: ExtensionField> $op<&Expression<E>> for &Expression<E> {
            type Output = Expression<E>;

            fn $fun(self, rhs: &Expression<E>) -> Expression<E> {
                self.clone().$fun(rhs.clone())
            }
        }

        // for mutable references
        impl<E: ExtensionField> $op<&mut Expression<E>> for Expression<E> {
            type Output = Expression<E>;

            fn $fun(self, rhs: &mut Expression<E>) -> Expression<E> {
                self.$fun(rhs.clone())
            }
        }

        impl<E: ExtensionField> $op<Expression<E>> for &mut Expression<E> {
            type Output = Expression<E>;

            fn $fun(self, rhs: Expression<E>) -> Expression<E> {
                self.clone().$fun(rhs)
            }
        }

        impl<E: ExtensionField> $op<&mut Expression<E>> for &mut Expression<E> {
            type Output = Expression<E>;

            fn $fun(self, rhs: &mut Expression<E>) -> Expression<E> {
                self.clone().$fun(rhs.clone())
            }
        }
    };
}
ref_binop_instances!(Add, add);
ref_binop_instances!(Sub, sub);
ref_binop_instances!(Mul, mul);

macro_rules! mixed_binop_instances {
    ($op: ident, $fun: ident, ($($t:ty),*)) => {
        $(impl<E: ExtensionField> $op<Expression<E>> for $t {
            type Output = Expression<E>;

            fn $fun(self, rhs: Expression<E>) -> Expression<E> {
                Expression::<E>::from(self).$fun(rhs)
            }
        }

        impl<E: ExtensionField> $op<$t> for Expression<E> {
            type Output = Expression<E>;

            fn $fun(self, rhs: $t) -> Expression<E> {
                self.$fun(Expression::<E>::from(rhs))
            }
        }

        impl<E: ExtensionField> $op<&Expression<E>> for $t {
            type Output = Expression<E>;

            fn $fun(self, rhs: &Expression<E>) -> Expression<E> {
                Expression::<E>::from(self).$fun(rhs)
            }
        }

        impl<E: ExtensionField> $op<$t> for &Expression<E> {
            type Output = Expression<E>;

            fn $fun(self, rhs: $t) -> Expression<E> {
                self.$fun(Expression::<E>::from(rhs))
            }
        }
    )*
    };
}

mixed_binop_instances!(
    Add,
    add,
    (u8, u16, u32, u64, usize, i8, i16, i32, i64, isize)
);
mixed_binop_instances!(
    Sub,
    sub,
    (u8, u16, u32, u64, usize, i8, i16, i32, i64, isize)
);
mixed_binop_instances!(
    Mul,
    mul,
    (u8, u16, u32, u64, usize, i8, i16, i32, i64, isize)
);

impl<E: ExtensionField> Mul for Expression<E> {
    type Output = Expression<E>;
    fn mul(self, rhs: Expression<E>) -> Expression<E> {
        match (&self, &rhs) {
            // constant * witin
            // constant * fixed
            (c @ Expression::Constant(_), w @ Expression::WitIn(..))
            | (w @ Expression::WitIn(..), c @ Expression::Constant(_))
            | (c @ Expression::Constant(_), w @ Expression::Fixed(..))
            | (w @ Expression::Fixed(..), c @ Expression::Constant(_)) => Expression::ScaledSum(
                Box::new(w.clone()),
                Box::new(c.clone()),
                Box::new(Expression::Constant(Either::Left(E::BaseField::ZERO))),
            ),
            // challenge * witin
            // challenge * fixed
            (c @ Expression::Challenge(..), w @ Expression::WitIn(..))
            | (w @ Expression::WitIn(..), c @ Expression::Challenge(..))
            | (c @ Expression::Challenge(..), w @ Expression::Fixed(..))
            | (w @ Expression::Fixed(..), c @ Expression::Challenge(..)) => Expression::ScaledSum(
                Box::new(w.clone()),
                Box::new(c.clone()),
                Box::new(Expression::Constant(Either::Left(E::BaseField::ZERO))),
            ),
            // instance * witin
            // instance * fixed
            (c @ Expression::Instance(..), w @ Expression::WitIn(..))
            | (w @ Expression::WitIn(..), c @ Expression::Instance(..))
            | (c @ Expression::Instance(..), w @ Expression::Fixed(..))
            | (w @ Expression::Fixed(..), c @ Expression::Instance(..)) => Expression::ScaledSum(
                Box::new(w.clone()),
                Box::new(c.clone()),
                Box::new(Expression::Constant(Either::Left(E::BaseField::ZERO))),
            ),
            // constant * challenge
            (
                Expression::Constant(c1),
                Expression::Challenge(challenge_id, pow, scalar, offset),
            )
            | (
                Expression::Challenge(challenge_id, pow, scalar, offset),
                Expression::Constant(c1),
            ) => Expression::Challenge(
                *challenge_id,
                *pow,
                either::for_both!(*c1, c1 => *scalar * c1),
                either::for_both!(*c1, c1 => *offset * c1),
            ),
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
                        *s1 * *s2,
                        *offset1 * *offset2,
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
            (Expression::Constant(c1), Expression::Constant(c2)) => {
                Expression::Constant(combine_cumulative_either!(*c1, *c2, |c1, c2| c1 * c2))
            }
            // scaledsum * constant
            (Expression::ScaledSum(x, a, b), c2 @ Expression::Constant(_))
            | (c2 @ Expression::Constant(_), Expression::ScaledSum(x, a, b)) => {
                Expression::ScaledSum(
                    x.clone(),
                    Box::new(a.deref() * c2),
                    Box::new(b.deref() * c2),
                )
            }
            // scaled * challenge => scaled
            (Expression::ScaledSum(x, a, b), c2 @ Expression::Challenge(..))
            | (c2 @ Expression::Challenge(..), Expression::ScaledSum(x, a, b)) => {
                Expression::ScaledSum(
                    x.clone(),
                    Box::new(a.deref() * c2),
                    Box::new(b.deref() * c2),
                )
            }
            _ => Expression::Product(Box::new(self), Box::new(rhs)),
        }
    }
}

#[derive(Clone, Debug, Copy)]
#[repr(C)]
pub struct WitIn {
    pub id: WitnessId,
}

#[derive(Clone, Debug, Copy, serde::Serialize, serde::Deserialize)]
#[repr(C)]
pub struct StructuralWitIn {
    pub id: WitnessId,
    pub max_len: usize,
    pub offset: u32,
    pub multi_factor: usize,
    pub descending: bool,
}

#[derive(
    Copy, Clone, Debug, Ord, PartialOrd, Eq, PartialEq, Hash, serde::Serialize, serde::Deserialize,
)]
#[repr(C)]
pub struct Fixed(pub usize);

#[derive(
    Copy, Clone, Debug, Ord, PartialOrd, Eq, PartialEq, Hash, serde::Serialize, serde::Deserialize,
)]
#[repr(C)]
pub struct Instance(pub usize);

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

impl<E: ExtensionField> ToExpr<E> for &WitIn {
    type Output = Expression<E>;
    fn expr(&self) -> Expression<E> {
        Expression::WitIn(self.id)
    }
}

impl<E: ExtensionField> ToExpr<E> for StructuralWitIn {
    type Output = Expression<E>;
    fn expr(&self) -> Expression<E> {
        Expression::StructuralWitIn(self.id, self.max_len, self.offset, self.multi_factor)
    }
}

impl<E: ExtensionField> ToExpr<E> for &StructuralWitIn {
    type Output = Expression<E>;
    fn expr(&self) -> Expression<E> {
        Expression::StructuralWitIn(self.id, self.max_len, self.offset, self.multi_factor)
    }
}

impl<E: ExtensionField> ToExpr<E> for Fixed {
    type Output = Expression<E>;
    fn expr(&self) -> Expression<E> {
        Expression::Fixed(*self)
    }
}

impl<E: ExtensionField> ToExpr<E> for &Fixed {
    type Output = Expression<E>;
    fn expr(&self) -> Expression<E> {
        Expression::Fixed(**self)
    }
}

impl<E: ExtensionField> ToExpr<E> for Instance {
    type Output = Expression<E>;
    fn expr(&self) -> Expression<E> {
        Expression::Instance(*self)
    }
}

impl<F: SmallField, E: ExtensionField<BaseField = F>> ToExpr<E> for F {
    type Output = Expression<E>;
    fn expr(&self) -> Expression<E> {
        Expression::Constant(Either::Left(*self))
    }
}

impl<E: ExtensionField> ToExpr<E> for Expression<E> {
    type Output = Expression<E>;
    fn expr(&self) -> Self::Output {
        self.clone()
    }
}

pub fn wit_infer_by_expr<'a, E: ExtensionField>(
    fixed: &[ArcMultilinearExtension<'a, E>],
    witnesses: &[ArcMultilinearExtension<'a, E>],
    structual_witnesses: &[ArcMultilinearExtension<'a, E>],
    instance: &[ArcMultilinearExtension<'a, E>],
    challenges: &[E],
    expr: &Expression<E>,
) -> ArcMultilinearExtension<'a, E> {
    expr.evaluate_with_instance::<ArcMultilinearExtension<'a, E>>(
        &|f| fixed[f.0].clone(),
        &|witness_id| witnesses[witness_id as usize].clone(),
        &|witness_id, _, _, _| structual_witnesses[witness_id as usize].clone(),
        &|i| instance[i.0].clone(),
        &|scalar| {
            let scalar: ArcMultilinearExtension<E> = MultilinearExtension::from_evaluations_vec(
                0,
                vec![scalar.left().expect("do not support extension field")],
            )
            .into();
            scalar
        },
        &|challenge_id, pow, scalar, offset| {
            // TODO cache challenge power to be acquired once for each power
            let challenge = challenges[challenge_id as usize];
            let challenge: ArcMultilinearExtension<E> =
                MultilinearExtension::from_evaluations_ext_vec(
                    0,
                    vec![challenge.exp_u64(pow as u64) * scalar + offset],
                )
                .into();
            challenge
        },
        &|a, b| {
            commutative_op_mle_pair!(|a, b| {
                match (a.len(), b.len()) {
                    (1, 1) => {
                        MultilinearExtension::from_evaluation_vec_smart(0, vec![a[0] + b[0]]).into()
                    }
                    (1, _) => MultilinearExtension::from_evaluation_vec_smart(
                        ceil_log2(b.len()),
                        b.par_iter()
                            .with_min_len(MIN_PAR_SIZE)
                            .map(|b| a[0] + *b)
                            .collect(),
                    )
                    .into(),
                    (_, 1) => MultilinearExtension::from_evaluation_vec_smart(
                        ceil_log2(a.len()),
                        a.par_iter()
                            .with_min_len(MIN_PAR_SIZE)
                            .map(|a| *a + b[0])
                            .collect(),
                    )
                    .into(),
                    (_, _) => MultilinearExtension::from_evaluation_vec_smart(
                        ceil_log2(a.len()),
                        a.par_iter()
                            .zip(b.par_iter())
                            .with_min_len(MIN_PAR_SIZE)
                            .map(|(a, b)| *a + *b)
                            .collect(),
                    )
                    .into(),
                }
            })
        },
        &|a, b| {
            commutative_op_mle_pair!(|a, b| {
                match (a.len(), b.len()) {
                    (1, 1) => {
                        MultilinearExtension::from_evaluation_vec_smart(0, vec![a[0] * b[0]]).into()
                    }
                    (1, _) => MultilinearExtension::from_evaluation_vec_smart(
                        ceil_log2(b.len()),
                        b.par_iter()
                            .with_min_len(MIN_PAR_SIZE)
                            .map(|b| a[0] * *b)
                            .collect(),
                    )
                    .into(),
                    (_, 1) => MultilinearExtension::from_evaluation_vec_smart(
                        ceil_log2(a.len()),
                        a.par_iter()
                            .with_min_len(MIN_PAR_SIZE)
                            .map(|a| *a * b[0])
                            .collect(),
                    )
                    .into(),
                    (_, _) => {
                        assert_eq!(a.len(), b.len());
                        // we do the pointwise evaluation multiplication here without involving FFT
                        // the evaluations outside of range will be checked via sumcheck + identity polynomial
                        MultilinearExtension::from_evaluation_vec_smart(
                            ceil_log2(a.len()),
                            a.par_iter()
                                .zip(b.par_iter())
                                .with_min_len(MIN_PAR_SIZE)
                                .map(|(a, b)| *a * *b)
                                .collect(),
                        )
                        .into()
                    }
                }
            })
        },
        &|x, a, b| {
            op_mle_xa_b!(|x, a, b| {
                match (x.len(), a.len(), b.len()) {
                    (_, 1, 1) => MultilinearExtension::from_evaluation_vec_smart(
                        ceil_log2(x.len()),
                        x.par_iter()
                            .with_min_len(MIN_PAR_SIZE)
                            .map(|x| a[0] * *x + b[0])
                            .collect(),
                    )
                    .into(),
                    (1, _, 1) => MultilinearExtension::from_evaluation_vec_smart(
                        ceil_log2(a.len()),
                        a.par_iter()
                            .with_min_len(MIN_PAR_SIZE)
                            .map(|a| *a * x[0] + b[0])
                            .collect(),
                    )
                    .into(),
                    lefted => panic!("unknown combination {:?}", lefted),
                }
            })
        },
    )
}

pub fn rlc_chip_record<E: ExtensionField>(
    records: Vec<Expression<E>>,
    chip_record_alpha: Expression<E>,
    chip_record_beta: Expression<E>,
) -> Expression<E> {
    assert!(!records.is_empty());
    let beta_pows = power_sequence(chip_record_beta);

    let item_rlc = izip!(records, beta_pows)
        .map(|(record, beta)| record * beta)
        .sum::<Expression<E>>();

    item_rlc + chip_record_alpha.clone()
}

/// derive power sequence [1, base, base^2, ..., base^(len-1)] of base expression
pub fn power_sequence<E: ExtensionField>(
    base: Expression<E>,
) -> impl Iterator<Item = Expression<E>> {
    assert!(
        matches!(
            base,
            Expression::Constant { .. } | Expression::Challenge { .. }
        ),
        "expression must be constant or challenge"
    );
    successors(Some(E::BaseField::ONE.expr()), move |prev| {
        Some(prev.clone() * base.clone())
    })
}

macro_rules! impl_from_via_ToExpr {
    ($($t:ty),*) => {
        $(
            impl<E: ExtensionField> From<$t> for Expression<E> {
                fn from(value: $t) -> Self {
                    value.expr()
                }
            }
        )*
    };
}
impl_from_via_ToExpr!(WitIn, Fixed, StructuralWitIn, Instance);
impl_from_via_ToExpr!(&WitIn, &Fixed, &StructuralWitIn, &Instance);

// Implement From trait for unsigned types of at most 64 bits
#[macro_export]
macro_rules! impl_expr_from_unsigned {
    ($($t:ty),*) => {
        $(
            impl<F: ff_ext::SmallField, E: ExtensionField<BaseField = F>> From<$t> for Expression<E> {
                fn from(value: $t) -> Self {
                    Expression::Constant(Either::Left(F::from_canonical_u64(value as u64)))
                }
            }
        )*
    };
}
impl_expr_from_unsigned!(u8, u16, u32, u64, usize);

// Implement From trait for signed types
macro_rules! impl_from_signed {
    ($($t:ty),*) => {
        $(
            impl<F: SmallField, E: ExtensionField<BaseField = F>> From<$t> for Expression<E> {
                fn from(value: $t) -> Self {
                    let reduced = (value as i128).rem_euclid(F::MODULUS_U64 as i128) as u64;
                    Expression::Constant(Either::Left(F::from_canonical_u64(reduced)))
                }
            }
        )*
    };
}
impl_from_signed!(i8, i16, i32, i64, isize);

impl<E: ExtensionField> Display for Expression<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut wtns = vec![];
        write!(f, "{}", fmt::expr(self, &mut wtns, false))
    }
}

pub mod fmt {
    use super::*;
    use std::fmt::Write;

    pub fn expr<E: ExtensionField>(
        expression: &Expression<E>,
        wtns: &mut Vec<WitnessId>,
        add_parens_sum: bool,
    ) -> String {
        match expression {
            Expression::WitIn(wit_in) => {
                if !wtns.contains(wit_in) {
                    wtns.push(*wit_in);
                }
                format!("WitIn({})", wit_in)
            }
            Expression::StructuralWitIn(wit_in, max_len, offset, multi_factor) => {
                format!(
                    "StructuralWitIn({}, {}, {}, {})",
                    wit_in, max_len, offset, multi_factor
                )
            }
            Expression::Challenge(id, pow, scaler, offset) => {
                if *pow == 1 && *scaler == E::ONE && *offset == E::ZERO {
                    format!("Challenge({})", id)
                } else {
                    let mut s = String::new();
                    if *scaler != E::ONE {
                        write!(s, "{}*", field(scaler)).unwrap();
                    }
                    write!(s, "Challenge({})", id,).unwrap();
                    if *pow > 1 {
                        write!(s, "^{}", pow).unwrap();
                    }
                    if *offset != E::ZERO {
                        write!(s, "+{}", field(offset)).unwrap();
                    }
                    s
                }
            }
            Expression::Constant(constant) => constant
                .as_ref()
                .map_either(
                    |constant| base_field::<E::BaseField>(constant, true).to_string(),
                    |constant| field(constant).to_string(),
                )
                .into_inner(),
            Expression::Fixed(fixed) => format!("{:?}", fixed),
            Expression::Instance(i) => format!("{:?}", i),
            Expression::Sum(left, right) => {
                let s = format!("{} + {}", expr(left, wtns, false), expr(right, wtns, false));
                if add_parens_sum {
                    format!("({})", s)
                } else {
                    s
                }
            }
            Expression::Product(left, right) => {
                format!("{} * {}", expr(left, wtns, true), expr(right, wtns, true))
            }
            Expression::ScaledSum(x, a, b) => {
                let s = format!(
                    "{} * {} + {}",
                    expr(a, wtns, true),
                    expr(x, wtns, true),
                    expr(b, wtns, false)
                );
                if add_parens_sum {
                    format!("({})", s)
                } else {
                    s
                }
            }
        }
    }

    pub fn field<E: ExtensionField>(field: &E) -> String {
        let data = field
            .as_bases()
            .iter()
            .map(|b| base_field::<E::BaseField>(b, false))
            .collect::<Vec<String>>();
        let only_one_limb = field.as_bases()[1..]
            .iter()
            .all(|&x| x == E::BaseField::ZERO);

        if only_one_limb {
            data[0].to_string()
        } else {
            format!("[{}]", data.join(","))
        }
    }

    pub fn base_field<F: SmallField>(base_field: &F, add_parens: bool) -> String {
        let value = base_field.to_canonical_u64();

        if value > F::MODULUS_U64 - u16::MAX as u64 {
            // beautiful format for negative number > -65536
            parens(format!("-{}", F::MODULUS_U64 - value), add_parens)
        } else if value < u16::MAX as u64 {
            format!("{value}")
        } else {
            // hex
            if value > F::MODULUS_U64 - (u32::MAX as u64 + u16::MAX as u64) {
                parens(format!("-{}", F::MODULUS_U64 - value), add_parens)
            } else {
                format!("{value}")
            }
        }
    }

    pub fn parens(s: String, add_parens: bool) -> String {
        if add_parens { format!("({})", s) } else { s }
    }

    pub fn wtns<E: ExtensionField>(
        wtns: &[WitnessId],
        wits_in: &[ArcMultilinearExtension<E>],
        inst_id: usize,
        wits_in_name: &[String],
    ) -> String {
        use crate::mle::FieldType;
        use itertools::Itertools;

        wtns.iter()
            .sorted()
            .map(|wt_id| {
                let wit = &wits_in[*wt_id as usize];
                let name = &wits_in_name[*wt_id as usize];
                let value_fmt = match wit.evaluations() {
                    FieldType::Base(vec) => base_field::<E::BaseField>(&vec[inst_id], true),
                    FieldType::Ext(vec) => field(&vec[inst_id]),
                    FieldType::Unreachable => unreachable!(),
                };
                format!("  WitIn({wt_id})={value_fmt} {name:?}")
            })
            .join("\n")
    }
}

#[cfg(test)]
mod tests {

    use super::{Expression, ToExpr, fmt};
    use crate::{expression::WitIn, mle::IntoMLE, wit_infer_by_expr};
    use either::Either;
    use ff_ext::{FieldInto, GoldilocksExt2};
    use p3::field::FieldAlgebra;

    #[test]
    fn test_expression_arithmetics() {
        type E = GoldilocksExt2;
        let x = WitIn { id: 0 };

        // scaledsum * challenge
        // 3 * x + 2
        let expr: Expression<E> = 3 * x.expr() + 2;
        // c^3 + 1
        let c = Expression::Challenge(0, 3, 1.into_f(), 1.into_f());
        // res
        // x* (c^3*3 + 3) + 2c^3 + 2
        assert_eq!(
            c * expr,
            Expression::ScaledSum(
                Box::new(x.expr()),
                Box::new(Expression::Challenge(0, 3, 3.into_f(), 3.into_f())),
                Box::new(Expression::Challenge(0, 3, 2.into_f(), 2.into_f()))
            )
        );

        // constant * witin
        // 3 * x
        let expr: Expression<E> = 3 * x.expr();
        assert_eq!(
            expr,
            Expression::ScaledSum(
                Box::new(x.expr()),
                Box::new(Expression::Constant(Either::Left(3.into_f()))),
                Box::new(Expression::Constant(Either::Left(0.into_f())))
            )
        );

        // constant * challenge
        // 3 * (c^3 + 1)
        let expr: Expression<E> = Expression::Constant(Either::Left(3.into_f()));
        let c = Expression::Challenge(0, 3, 1.into_f(), 1.into_f());
        assert_eq!(
            expr * c,
            Expression::Challenge(0, 3, 3.into_f(), 3.into_f())
        );

        // challenge * challenge
        // (2c^3 + 1) * (2c^2 + 1) = 4c^5 + 2c^3 + 2c^2 + 1
        let res: Expression<E> = Expression::Challenge(0, 3, 2.into_f(), 1.into_f())
            * Expression::Challenge(0, 2, 2.into_f(), 1.into_f());
        assert_eq!(
            res,
            Expression::Sum(
                Box::new(Expression::Sum(
                    // (s1 * s2 * c1^(pow1 + pow2) + offset1 * offset2
                    Box::new(Expression::Challenge(
                        0,
                        3 + 2,
                        (2 * 2).into_f(),
                        E::ONE * E::ONE,
                    )),
                    // offset2 * s1 * c1^(pow1)
                    Box::new(Expression::Challenge(0, 3, 2.into_f(), E::ZERO)),
                )),
                // offset1 * s2 * c2^(pow2))
                Box::new(Expression::Challenge(0, 2, 2.into_f(), E::ZERO)),
            )
        );
    }

    #[test]
    fn test_is_monomial_form() {
        type E = GoldilocksExt2;
        let x = WitIn { id: 0 };
        let y = WitIn { id: 1 };
        let z = WitIn { id: 2 };
        // scaledsum * challenge
        // 3 * x + 2
        let expr: Expression<E> = 3 * x.expr() + 2;
        assert!(expr.is_monomial_form());

        // 2 product term
        let expr: Expression<E> = 3 * x.expr() * y.expr() + 2 * x.expr();
        assert!(expr.is_monomial_form());

        // complex linear operation
        // (2c + 3) * x * y - 6z
        let expr: Expression<E> =
            Expression::Challenge(0, 1, 2_u64.into_f(), 3_u64.into_f()) * x.expr() * y.expr()
                - 6 * z.expr();
        assert!(expr.is_monomial_form());

        // complex linear operation
        // (2c + 3) * x * y - 6z
        let expr: Expression<E> =
            Expression::Challenge(0, 1, 2_u64.into_f(), 3_u64.into_f()) * x.expr() * y.expr()
                - 6 * z.expr();
        assert!(expr.is_monomial_form());

        // complex linear operation
        // (2 * x + 3) * 3 + 6 * 8
        let expr: Expression<E> = (2 * x.expr() + 3) * 3 + 6 * 8;
        assert!(expr.is_monomial_form());
    }

    #[test]
    fn test_not_monomial_form() {
        type E = GoldilocksExt2;
        let x = WitIn { id: 0 };
        let y = WitIn { id: 1 };
        // scaledsum * challenge
        // (x + 1) * (y + 1)
        let expr: Expression<E> = (1 + x.expr()) * (2 + y.expr());
        assert!(!expr.is_monomial_form());
    }

    #[test]
    fn test_fmt_expr_challenge_1() {
        let a = Expression::<GoldilocksExt2>::Challenge(0, 2, 3.into_f(), 4.into_f());
        let b = Expression::<GoldilocksExt2>::Challenge(0, 5, 6.into_f(), 7.into_f());

        let mut wtns_acc = vec![];
        let s = fmt::expr(&(a * b), &mut wtns_acc, false);

        assert_eq!(
            s,
            "18*Challenge(0)^7+28 + 21*Challenge(0)^2 + 24*Challenge(0)^5"
        );
    }

    #[test]
    fn test_fmt_expr_challenge_2() {
        let a = Expression::<GoldilocksExt2>::Challenge(0, 1, 1.into_f(), 0.into_f());
        let b = Expression::<GoldilocksExt2>::Challenge(0, 1, 1.into_f(), 0.into_f());

        let mut wtns_acc = vec![];
        let s = fmt::expr(&(a * b), &mut wtns_acc, false);

        assert_eq!(s, "Challenge(0)^2");
    }

    #[test]
    fn test_fmt_expr_wtns_acc_1() {
        let expr = Expression::<GoldilocksExt2>::WitIn(0);
        let mut wtns_acc = vec![];
        let s = fmt::expr(&expr, &mut wtns_acc, false);
        assert_eq!(s, "WitIn(0)");
        assert_eq!(wtns_acc, vec![0]);
    }

    #[test]
    fn test_wit_infer_by_expr_base_field() {
        type E = ff_ext::GoldilocksExt2;
        type B = p3::goldilocks::Goldilocks;
        let a = WitIn { id: 0 };
        let b = WitIn { id: 1 };
        let c = WitIn { id: 2 };

        let expr: Expression<E> = a.expr() + b.expr() + a.expr() * b.expr() + (c.expr() * 3 + 2);

        let res = wit_infer_by_expr(
            &[],
            &[
                vec![B::from_canonical_u64(1)].into_mle().into(),
                vec![B::from_canonical_u64(2)].into_mle().into(),
                vec![B::from_canonical_u64(3)].into_mle().into(),
            ],
            &[],
            &[],
            &[],
            &expr,
        );
        res.get_base_field_vec();
    }

    #[test]
    fn test_wit_infer_by_expr_ext_field() {
        type E = ff_ext::GoldilocksExt2;
        type B = p3::goldilocks::Goldilocks;
        let a = WitIn { id: 0 };
        let b = WitIn { id: 1 };
        let c = WitIn { id: 2 };

        let expr: Expression<E> = a.expr()
            + b.expr()
            + a.expr() * b.expr()
            + (c.expr() * 3 + 2)
            + Expression::Challenge(0, 1, E::ONE, E::ONE);

        let res = wit_infer_by_expr(
            &[],
            &[
                vec![B::from_canonical_u64(1)].into_mle().into(),
                vec![B::from_canonical_u64(2)].into_mle().into(),
                vec![B::from_canonical_u64(3)].into_mle().into(),
            ],
            &[],
            &[],
            &[E::ONE],
            &expr,
        );
        res.get_ext_field_vec();
    }
}
