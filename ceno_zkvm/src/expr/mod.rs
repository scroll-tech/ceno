use crate::{
    expression::{Fixed, Instance},
    structs::{ChallengeId, WitnessId},
};
use bumpalo::Bump;
use ff_ext::ExtensionField;
use goldilocks::SmallField;
use std::ops::Add;
pub mod compat;

// This test serves as a little demo of the prototype so far:
#[test]
fn test_expr() {
    type E = goldilocks::GoldilocksExt2;

    // We generally need a 'builder' for complex expressions.
    // The same context that already tracks fixed, witnesses and instances can also track the builder.
    let builder = ExprBuilder::default();

    // We can do consts without a builder:

    let a = Expr::<'_, E>::from(1);
    let b = 2;
    let c = a + b;
    println!("{:?}", c);

    // TODO: implement support for witin, fixed, instance
    // Here we just create one out of thin air for the demonstration.
    let x = builder.wit_in(5);
    println!("{:?}", a);
    let y = x + c;
    println!("{:?}", y);

    // Notice how we can use `x` and `y` multiple times without worrying about cloning, and we can also use literals like `10`:
    let z = x + 10 + y + y;
    println!("{:?}", z);
}

/// Contains a reference to [`ExprTree`] that is managed by [`ExprBuilder`].
#[derive(Clone, Copy, Debug)]
pub enum Expr<'a, E: ExtensionField> {
    Constant(E::BaseField),
    Compound {
        expr: CompoundExpr<'a, E>,
        builder: &'a ExprBuilder,
    },
}

#[derive(Clone, Copy, Debug)]
pub struct CompoundExpr<'a, E: ExtensionField>(&'a ExprTree<'a, E>);

/// Internal type to represent the Expr trees
#[derive(Debug)]
pub enum ExprTree<'a, E: ExtensionField> {
    /// WitIn(Id)
    WitIn(WitnessId),
    /// Fixed
    Fixed(Fixed),
    /// Public Values
    Instance(Instance),
    /// Constant poly
    Constant(E::BaseField),
    /// This is the sum of two Expr
    Sum(CompoundExpr<'a, E>, CompoundExpr<'a, E>),
    /// This is the product of two polynomials
    Product(CompoundExpr<'a, E>, CompoundExpr<'a, E>),
    // TODO(Matthias): Why is this one special, instead of build from `Sum` and `Product`?
    /// This is x, a, b expr to represent ax + b polynomial
    /// and x is one of wit / fixed / instance, a and b are either constant or challenge
    ScaledSum(
        CompoundExpr<'a, E>,
        CompoundExpr<'a, E>,
        CompoundExpr<'a, E>,
    ),
    Challenge(ChallengeId, usize, E, E), // (challenge_id, power, scalar, offset)
}

use ff::Field;

impl<E: ExtensionField> ExprTree<'_, E> {
    pub const ZERO: ExprTree<'static, E> = ExprTree::<'static, E>::Constant(E::BaseField::ZERO);
    pub const ONE: ExprTree<'static, E> = ExprTree::<'static, E>::Constant(E::BaseField::ONE);
    // pub fn add(&self, other: &Self) -> Self {
    //     ExprTree::Sum(CompoundExpr(self), CompoundExpr(other))
    // }
}

/// Expr Builder.  Contains a [`Bump`] memory arena that will allocate and
/// store all the [`ExprTree`]s.
#[derive(Debug, Default)]
pub struct ExprBuilder {
    bump: Bump,
}

impl<'a, E: ExtensionField> From<&'a ExprTree<'a, E>> for CompoundExpr<'a, E> {
    fn from(value: &'a ExprTree<'a, E>) -> Self {
        CompoundExpr(value)
    }
}

impl<'a, E: ExtensionField> From<&'a mut ExprTree<'a, E>> for CompoundExpr<'a, E> {
    fn from(value: &'a mut ExprTree<'a, E>) -> Self {
        CompoundExpr(value)
    }
}

// Implement From trait for unsigned types of at most 64 bits
macro_rules! impl_from_unsigned {
    ($($t:ty),*) => {
        $(
            impl<F: SmallField, E: ExtensionField<BaseField = F>> From<$t> for Expr<'_, E> {
                fn from(value: $t) -> Self {
                    Expr::Constant(F::from(value as u64))
                }
            }
        )*
    };
}
impl_from_unsigned!(u8, u16, u32, u64, usize);

// Implement From trait for u128 separately since it requires explicit reduction
impl<F: SmallField, E: ExtensionField<BaseField = F>> From<u128> for Expr<'_, E> {
    fn from(value: u128) -> Self {
        let reduced = value.rem_euclid(F::MODULUS_U64 as u128) as u64;
        Expr::Constant(F::from(reduced))
    }
}

// Implement From trait for signed types
macro_rules! impl_from_signed {
    ($($t:ty),*) => {
        $(
            impl<F: SmallField, E: ExtensionField<BaseField = F>> From<$t> for Expr<'_, E> {
                fn from(value: $t) -> Self {
                    let reduced = (value as i128).rem_euclid(F::MODULUS_U64 as i128) as u64;
                    Expr::Constant(F::from(reduced))
                }
            }
        )*
    };
}
impl_from_signed!(i8, i16, i32, i64, i128, isize);

impl ExprBuilder {
    /// Internalise an [`ExprTree`] by moving it to memory allocated by the
    /// [`Bump`] arena owned by [`ExprBuilder`].
    fn intern<'a, E: ExtensionField>(&'a self, expr_tree: ExprTree<'a, E>) -> CompoundExpr<'a, E> {
        self.bump.alloc(expr_tree).into()
    }

    fn ensure_interned<'a, E: ExtensionField>(&'a self, expr: Expr<'a, E>) -> CompoundExpr<'a, E> {
        match expr {
            Expr::Compound { expr, .. } => expr,
            Expr::Constant(value) => self.constant_tree(value),
        }
    }

    /// Wrap [`ExprTree`] reference with an [`Expr`] wrapper
    fn wrap<'a, E: ExtensionField>(&'a self, expr: CompoundExpr<'a, E>) -> Expr<'a, E> {
        Expr::Compound {
            expr,
            builder: self,
        }
    }

    /// Allocate Constant Expr Tree in the Expr Builder
    fn constant_tree<E: ExtensionField>(&self, constant: E::BaseField) -> CompoundExpr<'_, E> {
        self.intern(ExprTree::Constant(constant))
    }

    /// Create a `Constant` Expr
    pub fn constant<E: ExtensionField>(&self, value: E::BaseField) -> Expr<'_, E> {
        self.wrap(self.constant_tree(value))
    }

    /// Create a `Fixed` Expr
    ///
    /// TODO: don't just create these out of thin air, hook it up with whatever hands out witness ids already.
    /// TODO: implement support for witin, fixed, instance
    pub fn wit_in<E: ExtensionField>(&self, id: WitnessId) -> Expr<'_, E> {
        self.wrap(self.intern(ExprTree::WitIn(id)))
    }
}

impl<'a, E: ExtensionField> Add for Expr<'a, E> {
    type Output = Self;
    fn add(self, rhs: Expr<'a, E>) -> Expr<'a, E> {
        let builder = match (self, rhs) {
            (Expr::Constant(c), Expr::Constant(d)) => return Expr::Constant(c + d),
            (Expr::Compound { builder, .. }, _) | (_, Expr::Compound { builder, .. }) => builder,
        };
        let lhs = builder.ensure_interned(self).0;
        let rhs = builder.ensure_interned(rhs).0;

        // TODO(Matthias): perhaps move this to a method on ExprTree or so?
        let one = || builder.ensure_interned(Self::from(1));
        let result = match (lhs, rhs) {
            // constant + witness
            // constant + fixed
            // constant + instance
            (ExprTree::WitIn(_), ExprTree::Constant(_))
            | (ExprTree::Fixed(_), ExprTree::Constant(_))
            | (ExprTree::Instance(_), ExprTree::Constant(_)) => {
                ExprTree::ScaledSum(CompoundExpr(lhs), one(), CompoundExpr(rhs))
            }
            (ExprTree::Constant(_), ExprTree::WitIn(_))
            | (ExprTree::Constant(_), ExprTree::Fixed(_))
            | (ExprTree::Constant(_), ExprTree::Instance(_)) => {
                ExprTree::ScaledSum(CompoundExpr(rhs), one(), CompoundExpr(lhs))
            }
            // challenge + witness
            // challenge + fixed
            // challenge + instance
            (ExprTree::WitIn(_), ExprTree::Challenge(..))
            | (ExprTree::Fixed(_), ExprTree::Challenge(..))
            | (ExprTree::Instance(_), ExprTree::Challenge(..)) => {
                ExprTree::ScaledSum(CompoundExpr(lhs), one(), CompoundExpr(rhs))
            }
            (ExprTree::Challenge(..), ExprTree::WitIn(_))
            | (ExprTree::Challenge(..), ExprTree::Fixed(_))
            | (ExprTree::Challenge(..), ExprTree::Instance(_)) => {
                ExprTree::ScaledSum(CompoundExpr(rhs), one(), CompoundExpr(lhs))
            }
            // constant + challenge
            (ExprTree::Constant(c1), ExprTree::Challenge(challenge_id, pow, scalar, offset))
            | (ExprTree::Challenge(challenge_id, pow, scalar, offset), ExprTree::Constant(c1)) => {
                ExprTree::Challenge(*challenge_id, *pow, *scalar, *offset + c1)
            }

            // challenge + challenge
            (
                ExprTree::Challenge(challenge_id1, pow1, scalar1, offset1),
                ExprTree::Challenge(challenge_id2, pow2, scalar2, offset2),
            ) if challenge_id1 == challenge_id2 && pow1 == pow2 => ExprTree::Challenge(
                *challenge_id1,
                *pow1,
                *scalar1 + scalar2,
                *offset1 + offset2,
            ),

            // constant + constant
            (ExprTree::Constant(c1), ExprTree::Constant(c2)) => ExprTree::Constant(*c1 + c2),

            // constant + scaled sum
            (ExprTree::Constant(c), ExprTree::ScaledSum(x, a, b))
            | (ExprTree::ScaledSum(x, a, b), ExprTree::Constant(c)) => ExprTree::ScaledSum(
                *x,
                *a,
                builder.ensure_interned(builder.wrap(*b) + Expr::Constant(*c)),
            ),

            _ => ExprTree::Sum(CompoundExpr(lhs), CompoundExpr(rhs)),
        };
        builder.wrap(builder.intern(result))
    }
}

macro_rules! binop_instances {
    ($op: ident, $fun: ident, ($($t:ty),*)) => {
        $(impl<'a, E: ExtensionField> $op<Expr<'a, E>> for $t {
            type Output = Expr<'a, E>;

            fn $fun(self, rhs: Expr<'a, E>) -> Expr<'a, E> {
                Expr::<'a, E>::from(self).$fun(rhs)
            }
        }

        impl<'a, E: ExtensionField> $op<$t> for Expr<'a, E> {
            type Output = Expr<'a, E>;

            fn $fun(self, rhs: $t) -> Expr<'a, E> {
                self.$fun(Expr::<'a, E>::from(rhs))
            }
        })*
    };
}

binop_instances!(
    Add,
    add,
    (u8, u16, u32, u64, usize, i8, i16, i32, i64, i128, isize)
);