use std::ops::Add;

use crate::{
    expression::{Fixed, Instance},
    structs::{ChallengeId, WitnessId},
};
use bumpalo::Bump;
use ff_ext::ExtensionField;

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

    // /// Convenience method for creating `BinOp` nodes
    // fn bin_op<'a, E: ExtensionField>(
    //     &'a self,
    //     op: BinOp,
    //     left: CompoundExpr<'a, E>,
    //     right: CompoundExpr<'a, E>,
    // ) -> CompoundExpr<'a, E> {
    //     let expr_tree = ExprTree::BinOp { op, left, right };
    //     self.intern(expr_tree)
    // }

    // /// Convenience method for creating `UnaOp` nodes
    // fn una_op<'a, V>(&'a self, op: UnaOp, expr: CompoundExpr<'a, V>) -> CompoundExpr<'a, V> {
    //     let expr_tree = ExprTree::UnaOp { op, expr };
    //     self.intern(expr_tree)
    // }

    /// Allocate Constant Expr Tree in the Expr Builder
    fn constant_tree<E: ExtensionField>(&self, constant: E::BaseField ) -> CompoundExpr<'_, E> {
        self.intern(ExprTree::Constant(constant))
    }

    // fn lit_tree<V>(&self, value: V) -> CompoundExpr<'_, V> {
    //     self.intern(ExprTree::Literal { value })
    // }

    // /// Create a `Constant` Expr
    // pub fn constant<V>(&self, value: i64) -> Expr<'_, V> { self.wrap(self.constant_tree(value)) }

    // /// Create a `Literal` Expr
    // pub fn lit<V>(&self, value: V) -> Expr<'_, V> { self.wrap(self.lit_tree(value)) }
}

impl<'a, E: ExtensionField> Add for Expr<'a, E> {
    type Output = Self;
    fn add(self, rhs: Expr<E>) -> Expr<E> {
        let builder = match (self, rhs) {
            (Expr::Constant(c), Expr::Constant(d)) => return Expr::Constant(c + d),
            (Expr::Compound { builder, .. }, _) | (_, Expr::Compound { builder, .. }) => builder,
        };
        todo!()
        // match (&self, &rhs) {
        //     // constant + witness
        //     // constant + fixed
        //     // constant + instance
        //     (Expr::WitIn(_), Expr::Constant(_))
        //     | (Expr::Fixed(_), Expr::Constant(_))
        //     | (Expr::Instance(_), Expr::Constant(_)) => Expr::ScaledSum(
        //         Box::new(self),
        //         Box::new(Expr::Constant(E::BaseField::ONE)),
        //         Box::new(rhs),
        //     ),
        //     (Expr::Constant(_), Expr::WitIn(_))
        //     | (Expr::Constant(_), Expr::Fixed(_))
        //     | (Expr::Constant(_), Expr::Instance(_)) => Expr::ScaledSum(
        //         Box::new(rhs),
        //         Box::new(Expr::Constant(E::BaseField::ONE)),
        //         Box::new(self),
        //     ),
        //     // challenge + witness
        //     // challenge + fixed
        //     // challenge + instance
        //     (Expr::WitIn(_), Expr::Challenge(..))
        //     | (Expr::Fixed(_), Expr::Challenge(..))
        //     | (Expr::Instance(_), Expr::Challenge(..)) => Expr::ScaledSum(
        //         Box::new(self),
        //         Box::new(Expr::Constant(E::BaseField::ONE)),
        //         Box::new(rhs),
        //     ),
        //     (Expr::Challenge(..), Expr::WitIn(_))
        //     | (Expr::Challenge(..), Expr::Fixed(_))
        //     | (Expr::Challenge(..), Expr::Instance(_)) => Expr::ScaledSum(
        //         Box::new(rhs),
        //         Box::new(Expr::Constant(E::BaseField::ONE)),
        //         Box::new(self),
        //     ),
        //     // constant + challenge
        //     (
        //         Expr::Constant(c1),
        //         Expr::Challenge(challenge_id, pow, scalar, offset),
        //     )
        //     | (
        //         Expr::Challenge(challenge_id, pow, scalar, offset),
        //         Expr::Constant(c1),
        //     ) => Expr::Challenge(*challenge_id, *pow, *scalar, *offset + c1),

        //     // challenge + challenge
        //     (
        //         Expr::Challenge(challenge_id1, pow1, scalar1, offset1),
        //         Expr::Challenge(challenge_id2, pow2, scalar2, offset2),
        //     ) => {
        //         if challenge_id1 == challenge_id2 && pow1 == pow2 {
        //             Expr::Challenge(
        //                 *challenge_id1,
        //                 *pow1,
        //                 *scalar1 + scalar2,
        //                 *offset1 + offset2,
        //             )
        //         } else {
        //             Expr::Sum(Box::new(self), Box::new(rhs))
        //         }
        //     }

        //     // constant + constant
        //     (Expr::Constant(c1), Expr::Constant(c2)) => Expr::Constant(*c1 + c2),

        //     // constant + scaled sum
        //     (c1 @ Expr::Constant(_), Expr::ScaledSum(x, a, b))
        //     | (Expr::ScaledSum(x, a, b), c1 @ Expr::Constant(_)) => {
        //         Expr::ScaledSum(
        //             x.clone(),
        //             a.clone(),
        //             Box::new(b.deref().clone() + c1.clone()),
        //         )
        //     }

        //     _ => Expr::Sum(Box::new(self), Box::new(rhs)),
        }
}

#[test]
fn test_expr() {
    use goldilocks::Goldilocks;
    use goldilocks::GoldilocksExt2;
    type E = GoldilocksExt2;
    let builder = ExprBuilder::default();
    let expr: CompoundExpr<'_, E> = builder.constant_tree(Goldilocks::from(1));
    let a = builder.wrap(expr);
    println!("{:?}", a);
    // let b = a + a;
    // println!("{:?}", b);
}
